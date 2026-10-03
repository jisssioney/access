"""IPv6 前缀迁移（“前缀迁移”会话操作）：在线双栈会话在 IPv4 租约不变的
前提下把委派前缀原子迁到指定前缀池。覆盖取值规则、错误次序、原子性、
幂等重放、分族老化、检查点/服务恢复与 session-run 端到端。"""

import json
import subprocess
import sys
import unittest

from access import (
    AuthError,
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
    StateError,
)


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def pool_entry(pool_id, cidr, reserved=(), static=()):
    return {
        "标识": pool_id,
        "CIDR": cidr,
        "保留": list(reserved),
        "静态": [[user, ip] for user, ip in static],
    }


def template_entry(template_id, limit=0):
    return {
        "标识": template_id,
        "限速": 1,
        "突发": 0,
        "配额": 10 ** 9,
        "周期毫秒": 0,
        "会话上限": limit,
        "排队优先级": 0,
        "超限": "拒绝",
    }


def v6_entry(pool_id, agg, deleg, reserved=(), static=()):
    return {
        "标识": pool_id,
        "聚合前缀": agg,
        "委派长度": deleg,
        "保留": list(reserved),
        "静态": [[user, prefix] for user, prefix in static],
    }


USERS = ("alice", "bob", "carol", "dave")


def base_config(v6_pools=(), template_v6=(), user_templates=USERS):
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                "租期毫秒": 1000},
        "地址池": [
            pool_entry("default", "10.0.0.0/28"),
            pool_entry("p2", "10.1.0.0/28"),
        ],
        "模板": [template_entry("dual")],
        "用户模板": [[user, "dual"] for user in user_templates],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 100, "重试上限毫秒": 1600},
        "模板地址池": [],
        "IPv6 前缀池": [v6_entry(*args) for args in v6_pools],
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


TWO_POOLS = (
    ("v6a", "2001:db8::/48", 56, (),
     (("bob", "2001:db8:0:200::/56"),)),
    ("v6b", "2001:db8:1::/48", 56, (),
     (("alice", "2001:db8:1:500::/56"),)),
)


def make_sessions(v6_pools=TWO_POOLS, seq=("v6a", "v6b"),
                  users=USERS, bound_users=("alice", "bob", "carol"),
                  retry_base=0, retry_cap=0):
    auth = Authenticator(3, 10 ** 9, retry_base_ms=retry_base,
                         retry_cap_ms=retry_cap)
    for user in users:
        auth.add(user, "pw")
    sessions = Sessions(
        auth, 100, 10, 50000,
        pool=("10.0.0.0/30", (), ()), lease_ms=1000,
    )
    sessions.load_config(compact(base_config(
        v6_pools=v6_pools,
        template_v6=(("dual", seq),),
        user_templates=bound_users,
    )))
    return sessions


V6_KEY = "IPv6 前缀池"
MIG_KEYS = [
    "会话", "状态", "时刻", "期限", "池", "地址", "租期",
    "原IPv6池", "原IPv6前缀", "目标IPv6池", "目标IPv6前缀", "IPv6租期",
]


def waterline(sessions, now_ms=0):
    stats = json.loads(sessions.pool_stats(now_ms))
    return {row[0]: row[:] for row in stats[V6_KEY]}


class PrefixMigrateTest(unittest.TestCase):
    def setUp(self):
        self.s = make_sessions(retry_base=100, retry_cap=1600)
        self.est = json.loads(
            self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        )

    def migrate(self, *args):
        return json.loads(self.s.do(*args))

    def test_dynamic_smallest_prefix_and_unchanged_v4(self):
        out = self.migrate("k2", "前缀迁移", "s1", ("v6b", "pw"), 500)
        self.assertEqual(list(out), MIG_KEYS)
        # alice 在 v6b 有专属静态前缀，静态优先。
        self.assertEqual(out["原IPv6池"], "v6a")
        self.assertEqual(out["原IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["目标IPv6池"], "v6b")
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1:500::/56")
        self.assertEqual(out["IPv6租期"], 1500)
        # IPv4 池/地址/租期与空闲期限不变。
        self.assertEqual(out["池"], "default")
        self.assertEqual(out["地址"], "10.0.0.1")
        self.assertEqual(out["租期"], 1000)
        self.assertEqual(out["期限"], 50000)
        self.assertEqual(out["状态"], "在线")
        # 迁移后查询视图呈现目标池前缀与新租期。
        view = json.loads(self.s.sessions(500))
        row = view["项目"][0]
        self.assertEqual(row["IPv6池"], "v6b")
        self.assertEqual(row["IPv6前缀"], "2001:db8:1:500::/56")
        self.assertEqual(row["IPv6租期"], 1500)
        # LF 结尾。
        raw = self.s.do("k9", "前缀迁移", "s1", ("v6a", "pw"), 600)
        self.assertTrue(raw.endswith("\n"))

    def test_dynamic_smallest_when_no_static(self):
        # carol 在两池均无静态：目标池取数值最小可用动态前缀。
        self.s.do("kc", "建立", "sc", ("carol", "pw"), 10)
        out = self.migrate("km", "前缀迁移", "sc", ("v6b", "pw"), 20)
        self.assertEqual(out["目标IPv6池"], "v6b")
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1::/56")
        # alice 已取走 ::（动态最小），bob 静态 0:200，carol 得 0:100。
        self.assertEqual(out["原IPv6前缀"], "2001:db8:0:100::/56")

    def test_waterline_moves_exactly_one_lease(self):
        before = waterline(self.s, 0)
        self.assertEqual(before["v6a"][4], 1)
        self.assertEqual(before["v6b"][4], 0)
        self.migrate("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        after = waterline(self.s, 100)
        # 原池少一个在租（静态配置数不变）、目标池恰多一个。
        self.assertEqual(after["v6a"][4], 0)
        self.assertEqual(after["v6b"][4], 1)
        # 动态归还块进入原池空闲：v6a 空闲数回到无动态占用值。
        self.assertEqual(after["v6a"][5], 255)
        self.assertEqual(after["v6b"][5], 254)

    def test_static_occupied_is_resource_error_without_change(self):
        # alice 迁入 v6b 取得其静态前缀；其另一会话再迁 v6b 时静态被占用。
        self.migrate("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        self.s.do("k3", "建立", "s2", ("alice", "pw"), 200)
        before = waterline(self.s, 200)
        with self.assertRaises(ResourceError):
            self.s.do("k4", "前缀迁移", "s2", ("v6b", "pw"), 300)
        self.assertEqual(waterline(self.s, 300), before)
        # s2 仍在原池持原前缀（s1 迁出 v6a 后 :: 已归还，s2 建立重取 ::）。
        row = next(
            r for r in json.loads(self.s.sessions(300))["项目"]
            if r["会话"] == "s2"
        )
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")

    def test_exhausted_target_no_dynamic_prefix(self):
        # tiny /128 单块池：被 q2 持有后，q3 迁入即 ResourceError。
        s = make_sessions(
            v6_pools=(
                ("v6a", "2001:db8::/48", 56),
                ("tiny", "2001:db8:9::/128", 128),
            ),
            seq=("v6a",),
            users=("alice",),
            bound_users=("alice",),
        )
        s.do("a1", "建立", "q2", ("alice", "pw"), 40)
        s.do("a2", "前缀迁移", "q2", ("tiny", "pw"), 50)
        s.do("a3", "建立", "q3", ("alice", "pw"), 60)
        before = waterline(s, 60)
        with self.assertRaises(ResourceError):
            s.do("a4", "前缀迁移", "q3", ("tiny", "pw"), 70)
        # 原前缀租约与目标池水位不变；q2 仍持 tiny 唯一前缀。
        self.assertEqual(waterline(s, 70), before)
        self.assertEqual(waterline(s, 70)["tiny"], ["tiny", 1, 0, 0, 1, 0])

    def test_unknown_sid_and_pool(self):
        with self.assertRaises(KeyError):
            self.s.do("k2", "前缀迁移", "nope", ("v6b", "pw"), 100)
        with self.assertRaises(KeyError):
            self.s.do("k3", "前缀迁移", "s1", ("ghost", "pw"), 100)

    def test_state_errors(self):
        # 目标等于原池。
        with self.assertRaises(StateError):
            self.s.do("k2", "前缀迁移", "s1", ("v6a", "pw"), 100)
        # 挂起会话。
        self.s.do("ks", "挂起", "s1", None, 200)
        with self.assertRaises(StateError):
            self.s.do("k3", "前缀迁移", "s1", ("v6b", "pw"), 300)
        # 下线墓碑。
        self.s.do("ko", "下线", "s1", None, 400)
        with self.assertRaises(StateError):
            self.s.do("k4", "前缀迁移", "s1", ("v6b", "pw"), 500)

    def test_pure_v4_session_state_error(self):
        # dave 未绑定模板：纯 IPv4 建立，迁移拒绝。
        self.s.do("kd", "建立", "sd", ("dave", "pw"), 0)
        with self.assertRaises(StateError):
            self.s.do("kx", "前缀迁移", "sd", ("v6a", "pw"), 100)

    def test_no_prefix_after_v6_aging_state_error(self):
        # 两族租约同刻到期（1000）；老化释放后会话仍在线但已无前缀。
        self.s.pool_stats(1000)
        with self.assertRaises(StateError):
            self.s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 1001)
        # IPv4 仍在租（同刻亦释），状态在线。
        row = json.loads(self.s.sessions(1001))["项目"][0]
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["IPv6前缀"], "")

    def test_bad_password_auth_error_keeps_state(self):
        before = waterline(self.s, 0)
        with self.assertRaises(AuthError):
            self.s.do("k2", "前缀迁移", "s1", ("v6b", "nope"), 100)
        self.assertEqual(waterline(self.s, 100), before)
        # 认证失败计数保留（再错两次即锁定，由最大失败=3）。
        with self.assertRaises(AuthError):
            self.s.do("k3", "前缀迁移", "s1", ("v6b", "nope"), 100)
        stats = json.loads(self.s.user_stats("alice", 100))
        fail = {item["类型"]: item["次数"] for item in stats["失败"]}
        self.assertEqual(fail["认证"], 2)

    def test_backend_error_precedes_target_and_is_retried(self):
        # 故障期：目标池即便不存在也先抛 BackendError；退避计数保留。
        self.s.fault("f1", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            self.s.do("k2", "前缀迁移", "s1", ("ghost", "pw"), 10)
        # 退避未到期再调用：n 不变，仍 BackendError。
        with self.assertRaises(BackendError):
            self.s.do("k3", "前缀迁移", "s1", ("ghost", "pw"), 20)
        stats = json.loads(self.s.fault_stats(20))
        # 两次失败计入（故障一次、退避一次），原租约与池水位不动。
        counts = {item["类型"]: item["次数"] for item in stats["失败"]}
        self.assertEqual(counts["故障"], 1)
        self.assertEqual(counts["退避"], 1)
        self.assertEqual(waterline(self.s, 20)["v6a"][4], 1)
        # 恢复后同刻未知目标池才暴露 KeyError。
        self.s.fault("f2", "恢复", None, 100000)
        with self.assertRaises(KeyError):
            self.s.do("k4", "前缀迁移", "s1", ("ghost", "pw"), 100000)

    def test_aging_runs_before_migrate(self):
        # bob 的会话时刻 0 建立、租期 1000 到期；先在 900 为 alice 续租
        # （两族租期顺延至 1900），时刻 1000 的迁移须先完成老化：bob 的
        # 静态前缀退租，alice 的迁移照常成功。
        self.s.do("kb", "建立", "sb", ("bob", "pw"), 0)
        self.s.do("kr", "续租", "s1", None, 900)
        self.s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 1000)
        rows = {
            r["会话"]: r for r in json.loads(self.s.sessions(1000))["项目"]
        }
        self.assertEqual(rows["sb"]["状态"], "在线")
        self.assertEqual(rows["sb"]["IPv6前缀"], "")
        self.assertEqual(rows["s1"]["IPv6池"], "v6b")
        # bob 静态前缀退租后仍属其专属，不回动态空闲；v6a 在租为 0。
        self.assertEqual(waterline(self.s, 1000)["v6a"][4], 0)

    def test_replay_same_params_no_second_migration(self):
        first = self.s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        # 迁回 v6a 的状态变化必须不发生：重放返回首果字节。
        second = self.s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        self.assertEqual(second, first)
        before = waterline(self.s, 100)
        self.s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        self.assertEqual(waterline(self.s, 100), before)
        row = json.loads(self.s.sessions(100))["项目"][0]
        self.assertEqual(row["IPv6池"], "v6b")
        # 同 key 异参：ValueError。
        with self.assertRaises(ValueError):
            self.s.do("k2", "前缀迁移", "s1", ("v6a", "pw"), 100)
        # 失败首果亦重放：先对 s2 造认证失败，再同参重放同异常。
        self.s.do("k3", "建立", "s2", ("carol", "pw"), 0)
        with self.assertRaises(AuthError):
            self.s.do("ke", "前缀迁移", "s2", ("v6b", "bad"), 50)
        with self.assertRaises(AuthError):
            self.s.do("ke", "前缀迁移", "s2", ("v6b", "bad"), 50)

    def test_failure_replay_result_and_chain(self):
        # 未知 sid 首果入防篡改链，重放沿用首果并指认首次序号。
        with self.assertRaises(KeyError):
            self.s.do("kz", "前缀迁移", "zz", ("v6b", "pw"), 10)
        with self.assertRaises(KeyError):
            self.s.do("kz", "前缀迁移", "zz", ("v6b", "pw"), 10)
        events = json.loads(self.s.audit(limit=1000))["事件"]
        entries = [e for e in events if e["操作"] == "前缀迁移"]
        self.assertEqual([e["结果"] for e in entries], ["KeyError", "KeyError"])
        self.assertEqual(entries[0]["原序号"], 0)
        self.assertEqual(entries[1]["原序号"], entries[0]["序号"])
        self.assertTrue(self.s.verify_audit())

    def test_param_type_and_value_errors(self):
        cases = [
            (("v6b", "pw", "x"), ValueError),       # 参数数量
            ((123, "pw"), TypeError),               # 目标类型
            (("v6b", 9), TypeError),                # 口令类型
            (("", "pw"), ValueError),               # 空目标
            (("v6b", "a\x00b"), ValueError),        # 口令含 NUL
        ]
        for args, exc in cases:
            with self.assertRaises(exc):
                self.s.do("kp%d" % cases.index((args, exc)),
                          "前缀迁移", "s1", args, 0)
        with self.assertRaises(ValueError):
            self.s.do("kn", "前缀迁移", "s1", ("v6b", "pw"), -1)
        with self.assertRaises(TypeError):
            self.s.do("kn2", "前缀迁移", "s1", ["v6b", "pw"], 0)

    def test_v4_lease_can_expire_while_v6_renewed(self):
        # 迁移把 v6 租期重置为 1500，v4 租期仍为 1000：时刻 1001 仅 IPv4
        # 释出，会话在线且仅持前缀；再迁移渲染空 IPv4 字段并成功。
        self.migrate("k2", "前缀迁移", "s1", ("v6b", "pw"), 500)
        self.s.pool_stats(1001)
        row = next(
            r for r in json.loads(self.s.sessions(1001))["项目"]
            if r["会话"] == "s1"
        )
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["池"], "")
        self.assertEqual(row["地址"], "")
        self.assertEqual(row["租期"], 0)
        self.assertEqual(row["IPv6池"], "v6b")
        self.assertEqual(row["IPv6租期"], 1500)
        out = self.migrate("k3", "前缀迁移", "s1", ("v6a", "pw"), 1100)
        self.assertEqual(out["池"], "")
        self.assertEqual(out["地址"], "")
        self.assertEqual(out["租期"], 0)
        self.assertEqual(out["目标IPv6池"], "v6a")
        self.assertEqual(out["IPv6租期"], 2100)

    def test_deterministic_bytes(self):
        def run(seed):
            s = make_sessions(retry_base=100, retry_cap=1600)
            out = []
            out.append(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
            out.append(s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100))
            out.append(s.pool_stats(200))
            return b"".join(part.encode() for part in out)
        self.assertEqual(run(0), run(1))


class PrefixMigrateCheckpointTest(unittest.TestCase):
    def _loaded(self):
        return make_sessions()

    def test_capacity_checkpoint_roundtrip(self):
        s = self._loaded()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        text = s.clog(200)
        target = self._loaded()
        target.creplay(text)
        self.assertEqual(target.clog(200), text)
        rows = {r["会话"]: r for r in json.loads(text)["会话"]}
        self.assertEqual(rows["s1"]["IPv6池"], "v6b")
        self.assertEqual(rows["s1"]["IPv6前缀"], "2001:db8:1:500::/56")
        self.assertEqual(rows["s1"]["IPv6租期"], 1100)
        stats = json.loads(target.pool_stats(200))
        by_id = {r[0]: r for r in stats[V6_KEY]}
        self.assertEqual(by_id["v6a"][4], 0)
        self.assertEqual(by_id["v6b"][4], 1)

    def test_capacity_checkpoint_roundtrip_v6_only_online(self):
        # v4 租期先到期、仅持前缀的在线会话亦可保存恢复。
        s = self._loaded()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 500)
        s.pool_stats(1001)
        text = s.clog(1100)
        target = self._loaded()
        target.creplay(text)
        self.assertEqual(target.clog(1100), text)

    def test_runtime_and_service_restore(self):
        s = self._loaded()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        runtime = s.runtime_checkpoint(200)
        t1 = self._loaded()
        self.assertEqual(t1.runtime_restore("rk", runtime), runtime)
        service = s.service_checkpoint(200)
        t2 = self._loaded()
        self.assertEqual(t2.service_restore("sk", service), service)
        self.assertEqual(t2.service_checkpoint(200), service)


class CliSessionRunPrefixMigrateTest(unittest.TestCase):
    def _request(self, requests, users=USERS):
        return {
            "users": [[user, "pw"] for user in users],
            "config": base_config(
                v6_pools=TWO_POOLS,
                template_v6=(("dual", ("v6a", "v6b")),),
                user_templates=users,
            ),
            "requests": requests,
            "query_ms": 1000,
        }

    def _run(self, request):
        return subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=compact(request).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_business_outcomes_continue_and_contract(self):
        request = self._request([
            {"key": "r1", "op": "建立", "sid": "s1",
             "args": ["alice", "pw"], "now_ms": 0},
            {"key": "r2", "op": "前缀迁移", "sid": "s1",
             "args": ["v6b", "pw"], "now_ms": 100},
            {"key": "r2", "op": "前缀迁移", "sid": "s1",
             "args": ["v6b", "pw"], "now_ms": 100},
            {"key": "r3", "op": "前缀迁移", "sid": "s1",
             "args": ["v6a", "bad"], "now_ms": 200},
            {"key": "r4", "op": "前缀迁移", "sid": "s1",
             "args": ["ghost", "pw"], "now_ms": 300},
            {"key": "r5", "op": "前缀迁移", "sid": "zz",
             "args": ["v6b", "pw"], "now_ms": 400},
            {"key": "r6", "op": "续租", "sid": "s1",
             "args": None, "now_ms": 500},
        ])
        proc = self._run(request)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = json.loads(proc.stdout.decode())
        self.assertEqual(
            list(out), ["版本", "项目", "会话", "地址池", "摘要"]
        )
        types = [item["类型"] for item in out["项目"]]
        self.assertEqual(
            types, ["", "", "", "AuthError", "KeyError", "KeyError", ""]
        )
        self.assertEqual([item["序号"] for item in out["项目"]],
                         list(range(7)))
        migrated = out["项目"][1]["输出"]
        self.assertEqual(list(migrated), MIG_KEYS)
        self.assertEqual(migrated["目标IPv6池"], "v6b")
        # 重放项输出与首果逐字节（解析后）一致。
        self.assertEqual(out["项目"][2]["输出"], migrated)
        # 最终会话视图：v6b 静态前缀，续租顺延两族租期。
        row = next(r for r in out["会话"]["项目"] if r["会话"] == "s1")
        self.assertEqual(row["IPv6池"], "v6b")
        self.assertEqual(row["IPv6前缀"], "2001:db8:1:500::/56")
        self.assertEqual(row["IPv6租期"], 1500)
        by_id = {r[0]: r for r in out["地址池"][V6_KEY]}
        self.assertEqual(by_id["v6a"][4], 0)
        self.assertEqual(by_id["v6b"][4], 1)
        # 摘要盖前四键。
        import hashlib
        head = {key: out[key]
                for key in ("版本", "项目", "会话", "地址池")}
        expect = hashlib.sha256(
            compact(head).encode("utf-8")
        ).hexdigest()
        self.assertEqual(out["摘要"], expect)
        # 确定性：同输入逐字节。
        again = self._run(request)
        self.assertEqual(again.stdout, proc.stdout)

    def test_static_validation_rejects_bad_shapes(self):
        good = {
            "key": "r2", "op": "前缀迁移", "sid": "s1",
            "args": ["v6b", "pw"], "now_ms": 100,
        }

        def with_request(req):
            request = self._request([
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
                req,
            ])
            return self._run(request)

        bad_args_len = dict(good, args=["v6b"])
        proc = with_request(bad_args_len)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(json.loads(proc.stderr.decode())["类型"],
                         "ValueError")
        bad_args_type = dict(good, args=[5, "pw"])
        proc = with_request(bad_args_type)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stderr.decode())["类型"],
                         "TypeError")
        bad_time = dict(good, now_ms=-3)
        proc = with_request(bad_time)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stderr.decode())["类型"],
                         "ValueError")

    def test_pure_v4_config_byte_shape_unchanged(self):
        request = self._request([
            {"key": "r1", "op": "建立", "sid": "sd",
             "args": ["dave", "pw"], "now_ms": 0},
            {"key": "r2", "op": "迁移", "sid": "sd",
             "args": ["p2", "pw"], "now_ms": 100},
        ])
        request["config"]["IPv6 前缀池"] = []
        request["config"]["模板 IPv6 池"] = []
        proc = self._run(request)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertNotIn("IPv6", proc.stdout.decode())
        self.assertNotIn("前缀迁移", proc.stdout.decode())


if __name__ == "__main__":
    unittest.main()
