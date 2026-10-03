"""前缀迁移（"前缀迁移" 操作）：在线双栈会话在 IPv4 租约不变的前提下把
委派前缀原子迁到指定 IPv6 前缀池。覆盖成功形态与键序、静态优先与最小
动态、状态/认证/资源/后端失败的不改态、幂等重放、分族老化、检查点
（clog/runtime/service）往返、session-run 接入与逐字节确定性。"""

import hashlib
import json
import subprocess
import sys
import unittest

import access
from access import (
    AuthError,
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
    StateError,
)

V6_KEY = "IPv6 前缀池"


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
# 默认仅前三人绑定双栈模板，dave 未绑定（纯 IPv4 用户）。
BOUND_USERS = ("alice", "bob", "carol")


def base_config(v6_pools=(), template_v6=(), user_templates=BOUND_USERS):
    bound = (
        [(user, "dual") for user in user_templates]
        if isinstance(user_templates, (list, tuple))
        else list(user_templates)
    )
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                "租期毫秒": 1000},
        "地址池": [
            pool_entry("default", "10.0.0.0/28"),
            pool_entry("p2", "10.1.0.0/28"),
        ],
        "模板": [template_entry("dual")],
        "用户模板": [list(pair) for pair in bound],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [],
        "IPv6 前缀池": [
            v6_entry(*args) if isinstance(args, tuple) else args
            for args in v6_pools
        ],
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


def make_sessions():
    auth = Authenticator(3, 10 ** 9)
    for user in USERS:
        auth.add(user, "pw")
    return Sessions(
        auth, 100, 10, 50000,
        pool=("10.0.0.0/30", (), ()), lease_ms=1000,
    )


def load(s, **kwargs):
    return s.load_config(compact(base_config(**kwargs)))


TWO_POOLS = dict(
    v6_pools=(
        v6_entry("v6a", "2001:db8::/48", 56,
                 reserved=["2001:db8:0:100::/56"],
                 static=[["bob", "2001:db8:0:200::/56"]]),
        v6_entry("v6b", "2001:db8:1::/48", 56,
                 static=[["bob", "2001:db8:1:500::/56"]]),
    ),
    template_v6=(("dual", ("v6a", "v6b")),),
)


def loaded_two_pools():
    s = make_sessions()
    load(s, **TWO_POOLS)
    return s


class PrefixMigrationSuccessTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.est = json.loads(
            self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        )

    def migrate(self, key="k9", target="v6b", now_ms=500, password="pw"):
        return json.loads(
            self.s.do(
                key, "前缀迁移", "s1", (target, password), now_ms
            )
        )

    def test_output_key_order_and_values(self):
        out = self.migrate(now_ms=500)
        self.assertEqual(
            list(out),
            [
                "会话", "状态", "时刻", "期限", "池", "地址", "租期",
                "原IPv6池", "原IPv6前缀", "目标IPv6池", "目标IPv6前缀",
                "IPv6租期",
            ],
        )
        self.assertEqual(out["会话"], "s1")
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(out["时刻"], 500)
        # 空闲期限不变。
        self.assertEqual(out["期限"], 50000)
        # IPv4 池、地址、租期全部保持迁移前值。
        self.assertEqual(out["池"], "default")
        self.assertEqual(out["地址"], "10.0.0.1")
        self.assertEqual(out["租期"], 1000)
        self.assertEqual(out["原IPv6池"], "v6a")
        self.assertEqual(out["原IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["目标IPv6池"], "v6b")
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1::/56")
        self.assertEqual(out["IPv6租期"], 1500)

    def test_lf_terminated_compact_json(self):
        text = self.s.do("k9", "前缀迁移", "s1", ("v6b", "pw"), 500)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, compact(json.loads(text)) + "\n")

    def test_waterline_moves_atomically(self):
        self.migrate()
        stats = json.loads(self.s.pool_stats(500))
        rows = {row[0]: row for row in stats[V6_KEY]}
        # 原池动态前缀已归还，目标池恰持一个新租约。
        self.assertEqual(rows["v6a"][4], 0)
        self.assertEqual(rows["v6b"][4], 1)
        view = json.loads(self.s.sessions(500))["项目"][0]
        self.assertEqual(view["IPv6池"], "v6b")
        self.assertEqual(view["IPv6前缀"], "2001:db8:1::/56")
        self.assertEqual(view["IPv6租期"], 1500)
        # IPv4 仍在原池。
        self.assertEqual(view["池"], "default")
        self.assertEqual(view["地址"], "10.0.0.1")

    def test_static_prefix_preferred_in_target(self):
        s = loaded_two_pools()
        s.do("kb", "建立", "sb", ("bob", "pw"), 0)
        out = json.loads(s.do("km", "前缀迁移", "sb", ("v6b", "pw"), 100))
        # bob 在 v6b 的专属静态前缀优先于动态首块。
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1:500::/56")

    def test_smallest_dynamic_is_returned_heap_then_cursor(self):
        s = loaded_two_pools()
        s.do("ka", "建立", "sa", ("alice", "pw"), 0)   # v6a ::/56
        s.do("kc", "建立", "sc", ("carol", "pw"), 0)  # v6a 0:300::/56
        s.do("ko", "下线", "sa", None, 10)            # ::/56 回归还堆
        # carol 迁到空的 v6b：取数值最小动态块（游标首块 1::/56）。
        out = json.loads(
            s.do("km1", "前缀迁移", "sc", ("v6b", "pw"), 20)
        )
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1::/56")
        # carol 再迁回 v6a：归还堆顶 ::/56 小于游标，优先复用。
        back = json.loads(
            s.do("km2", "前缀迁移", "sc", ("v6a", "pw"), 30)
        )
        self.assertEqual(back["目标IPv6前缀"], "2001:db8::/56")

    def test_same_session_view_after_query_consistent(self):
        self.migrate()
        # 查询不老化；两次同刻视图逐字节一致。
        self.assertEqual(
            self.s.sessions(500), self.s.sessions(500)
        )


class PrefixMigrationFailureTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.s.do("k2", "建立", "s2", ("bob", "pw"), 0)

    def waterline(self, now_ms):
        stats = json.loads(self.s.pool_stats(now_ms))
        return {
            row[0]: row[4] for row in stats[V6_KEY]
        }

    def test_unknown_sid_key_error(self):
        with self.assertRaises(KeyError):
            self.s.do("kx", "前缀迁移", "nope", ("v6b", "pw"), 100)

    def test_unknown_target_pool_key_error(self):
        with self.assertRaises(KeyError):
            self.s.do("kx", "前缀迁移", "s1", ("nope", "pw"), 100)

    def test_same_pool_state_error(self):
        with self.assertRaises(StateError):
            self.s.do("kx", "前缀迁移", "s1", ("v6a", "pw"), 100)

    def test_pure_v4_session_state_error(self):
        # dave 不绑定模板，建立为纯 IPv4 会话。
        self.s.do("kd", "建立", "sd", ("dave", "pw"), 0)
        with self.assertRaises(StateError):
            self.s.do("kx", "前缀迁移", "sd", ("v6b", "pw"), 100)

    def test_suspended_and_offline_state_error(self):
        self.s.do("ks", "挂起", "s1", None, 100)
        with self.assertRaises(StateError):
            self.s.do("kx", "前缀迁移", "s1", ("v6b", "pw"), 200)
        self.s.do("ko", "下线", "s2", None, 100)
        with self.assertRaises(StateError):
            self.s.do("ky", "前缀迁移", "s2", ("v6b", "pw"), 200)

    def test_dual_session_without_prefix_state_error(self):
        # IPv6 租期先到期单独老化释出后，双栈在线会话已无在租前缀。
        view = json.loads(self.s.sessions(1000))
        self.assertEqual(view["项目"][0]["IPv6前缀"], "")
        with self.assertRaises(StateError):
            self.s.do("kx", "前缀迁移", "s1", ("v6b", "pw"), 1000)

    def test_bad_auth_auth_error_keeps_lease(self):
        before = self.waterline(100)
        with self.assertRaises(AuthError):
            self.s.do("kx", "前缀迁移", "s1", ("v6b", "nope"), 100)
        self.assertEqual(self.waterline(100), before)
        row = [
            r for r in json.loads(self.s.sessions(100))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")

    def test_static_prefix_occupied_resource_error(self):
        # s2（bob）已在 v6a 持有动态块；先令 bob 的另一会话占住其 v6b 静态
        # 前缀：s2 迁 v6b 成功后，s3（同为 bob）再迁 v6b 即静态被占用。
        self.s.do("km2", "前缀迁移", "s2", ("v6b", "pw"), 50)
        self.s.do("k3", "建立", "s3", ("bob", "pw"), 60)
        before = self.waterline(100)
        with self.assertRaises(ResourceError):
            self.s.do("kx", "前缀迁移", "s3", ("v6b", "pw"), 100)
        # 失败不动两池水位，s3 仍在 v6a。
        self.assertEqual(self.waterline(100), before)
        row = [
            r for r in json.loads(self.s.sessions(100))["项目"]
            if r["会话"] == "s3"
        ][0]
        self.assertEqual(row["IPv6池"], "v6a")

    def test_no_dynamic_prefix_resource_error(self):
        s = make_sessions()
        load(
            s,
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48", 56),
                v6_entry("tiny", "2001:db8:9::/128", 128),
            ),
            template_v6=(("dual", ("v6a", "tiny")),),
        )
        s.do("ka", "建立", "sa", ("alice", "pw"), 0)
        s.do("kb", "建立", "sb", ("bob", "pw"), 0)
        s.do("km", "前缀迁移", "sa", ("tiny", "pw"), 100)
        stats_before = json.loads(s.pool_stats(200))[V6_KEY]
        with self.assertRaises(ResourceError):
            s.do("kx", "前缀迁移", "sb", ("tiny", "pw"), 200)
        stats_after = json.loads(s.pool_stats(200))[V6_KEY]
        self.assertEqual(stats_after, stats_before)

    def test_backend_failure_backend_error_before_state(self):
        # 后端故障先于状态/目标池/认证：未知 sid 仍为 KeyError，定位成功后
        # BackendError 先于其余业务校验，且不老化、不迁移。
        self.s.fault("f1", "注入", 10000, 0)
        before = self.waterline(250)
        with self.assertRaises(BackendError):
            self.s.do("kb", "前缀迁移", "s1", ("v6b", "pw"), 250)
        self.assertEqual(self.waterline(250), before)
        row = [
            r for r in json.loads(self.s.sessions(250))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["IPv6池"], "v6a")
        # 退避予以保留：同刻（retry_at 未到）重放为缓存结果，新 key 仍
        # BackendError。
        with self.assertRaises(BackendError):
            self.s.do("kb2", "前缀迁移", "s1", ("v6b", "pw"), 250)

    def test_unknown_sid_backend_order_key_error(self):
        self.s.fault("f1", "注入", 10000, 0)
        with self.assertRaises(KeyError):
            self.s.do("kx", "前缀迁移", "missing", ("v6b", "pw"), 0)

    def test_aging_before_migrate_is_kept(self):
        # 迁移在老化之后执行：IPv6 租期已到（1000）的前缀先被老化释出，
        # 迁移随即 StateError，老化不回滚。
        with self.assertRaises(StateError):
            self.s.do("kx", "前缀迁移", "s1", ("v6b", "pw"), 1000)


class PrefixMigrationParamTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def call(self, args, now_ms=100, key="kx"):
        self.s.do(key, "前缀迁移", "s1", args, now_ms)

    def test_args_wrong_type(self):
        for bad in (["v6b", "pw"], "v6b", 42, {"a": 1}):
            with self.assertRaises(TypeError):
                self.call(bad, key="kt%r" % (bad,))

    def test_args_wrong_arity(self):
        for bad in (("v6b",), ("v6b", "pw", "x"), ()):
            with self.assertRaises(ValueError):
                self.call(bad, key="ka%r" % (bad,))

    def test_field_types(self):
        with self.assertRaises(TypeError):
            self.call((123, "pw"), key="kt1")
        with self.assertRaises(TypeError):
            self.call(("v6b", 9), key="kt2")

    def test_field_values_and_negative_now(self):
        with self.assertRaises(ValueError):
            self.call(("v6b", ""), key="kv1")
        with self.assertRaises(ValueError):
            self.call(("", "pw"), key="kv2")
        with self.assertRaises(ValueError):
            self.s.do("kn", "前缀迁移", "s1", ("v6b", "pw"), -1)

    def test_bad_op_still_value_error(self):
        with self.assertRaises(ValueError):
            self.s.do("ko", "不存在", "s1", ("v6b", "pw"), 0)


class PrefixMigrationReplayTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def test_same_key_same_params_replays_first_result(self):
        first = self.s.do("k9", "前缀迁移", "s1", ("v6b", "pw"), 500)
        replay = self.s.do("k9", "前缀迁移", "s1", ("v6b", "pw"), 500)
        self.assertEqual(replay, first)
        # 重放不再次迁移：v6b 仅一个租约。
        stats = json.loads(self.s.pool_stats(500))
        rows = {row[0]: row for row in stats[V6_KEY]}
        self.assertEqual(rows["v6a"][4], 0)
        self.assertEqual(rows["v6b"][4], 1)

    def test_same_key_different_params_value_error(self):
        self.s.do("k9", "前缀迁移", "s1", ("v6b", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", "前缀迁移", "s1", ("v6a", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", "前缀迁移", "s1", ("v6b", "pw"), 501)

    def test_failure_result_is_replayed_too(self):
        # 同池 StateError 首次入缓存，重放同结果。
        with self.assertRaises(StateError):
            self.s.do("ke", "前缀迁移", "s1", ("v6a", "pw"), 100)
        with self.assertRaises(StateError):
            self.s.do("ke", "前缀迁移", "s1", ("v6a", "pw"), 100)


class IndependentAgingAndLeaseTest(unittest.TestCase):
    def test_v6_lease_can_outlive_v4_and_vice_versa(self):
        s = loaded_two_pools()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 500 时迁到 v6b：v6 租期 1500、v4 租期仍 1000。
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 500)
        view = json.loads(s.sessions(1100))["项目"][0]
        self.assertEqual(view["状态"], "在线")
        self.assertEqual(view["池"], "")
        self.assertEqual(view["地址"], "")
        self.assertEqual(view["租期"], 0)
        self.assertEqual(view["IPv6池"], "v6b")
        self.assertEqual(view["IPv6租期"], 1500)
        # 到 1500 IPv6 租期亦到期（含同刻），视图无任何址。
        view = json.loads(s.sessions(1500))["项目"][0]
        self.assertEqual(view["IPv6前缀"], "")
        self.assertEqual(view["IPv6池"], "")
        # 空闲到期（50000）才挂起。
        view = json.loads(s.sessions(50000))["项目"][0]
        self.assertEqual(view["状态"], "挂起")

    def test_migration_then_renew_only_extends_when_prefix_held(self):
        s = loaded_two_pools()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        out = json.loads(s.do("k3", "续租", "s1", None, 200))
        # 续租同步顺延两类租期。
        self.assertEqual(out["租期"], 1200)
        self.assertEqual(out["IPv6租期"], 1200)

    def test_explicit_ipv4_migrate_keeps_migrated_prefix(self):
        # 前缀迁移后再做 IPv4 迁移：只换 IPv4，前缀与前缀池保持、租期不顺延。
        s = loaded_two_pools()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 100)
        out = json.loads(s.do("k3", "迁移", "s1", ("p2", "pw"), 200))
        self.assertEqual(out["目标池"], "p2")
        self.assertEqual(out["IPv6池"], "v6b")
        self.assertEqual(out["IPv6前缀"], "2001:db8:1::/56")
        # 前缀迁移给的 v6 租期 1100 不被 IPv4 迁移顺延。
        self.assertEqual(out["IPv6租期"], 1100)
        self.assertEqual(out["租期"], 1200)


class CheckpointRoundtripTest(unittest.TestCase):
    def _state(self):
        s = loaded_two_pools()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 500)
        return s

    def test_capacity_checkpoint_roundtrip_with_v6_after_v4_aging(self):
        s = self._state()
        # 1100：v4 已老化、v6b 前缀仍在租（v6 租期 1500）。
        before = s.sessions(1100)
        text = s.clog(1100)
        target = loaded_two_pools()
        target.creplay(text)
        self.assertEqual(target.sessions(1100), before)
        stats = json.loads(target.pool_stats(1100))
        rows = {row[0]: row for row in stats[V6_KEY]}
        self.assertEqual(rows["v6a"][4], 0)
        self.assertEqual(rows["v6b"][4], 1)
        # 再检查点逐字节一致。
        self.assertEqual(target.clog(1100), text)

    def test_runtime_checkpoint_roundtrip(self):
        s = self._state()
        text = s.runtime_checkpoint(1100)
        target = loaded_two_pools()
        restored = target.runtime_restore("rk", text)
        self.assertEqual(restored, text)
        self.assertEqual(target.sessions(1100), s.sessions(1100))

    def test_service_checkpoint_roundtrip(self):
        s = self._state()
        text = s.service_checkpoint(1100)
        target = loaded_two_pools()
        target.service_restore("sk", text)
        self.assertEqual(target.sessions(1100), s.sessions(1100))
        stats_a = json.loads(target.pool_stats(1100))[V6_KEY]
        stats_b = json.loads(s.pool_stats(1100))[V6_KEY]
        self.assertEqual(stats_a, stats_b)


class DeterminismTest(unittest.TestCase):
    def test_byte_identical_runs(self):
        def run():
            s = loaded_two_pools()
            out = []
            out.append(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
            out.append(s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 500))
            out.append(s.sessions(600))
            out.append(s.pool_stats(600))
            return out
        self.assertEqual(run(), run())


class SessionRunCliTest(unittest.TestCase):
    def _request(self):
        doc = base_config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48", 56),
                v6_entry("v6b", "2001:db8:1::/48", 56),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        return {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
                {"key": "r2", "op": "前缀迁移", "sid": "s1",
                 "args": ["v6b", "pw"], "now_ms": 200},
                # 业务失败：同池 StateError，仅记类名继续。
                {"key": "r3", "op": "前缀迁移", "sid": "s1",
                 "args": ["v6b", "pw"], "now_ms": 300},
                # 业务失败：未知 sid KeyError。
                {"key": "r4", "op": "前缀迁移", "sid": "nope",
                 "args": ["v6b", "pw"], "now_ms": 300},
                # 迁回成功。
                {"key": "r5", "op": "前缀迁移", "sid": "s1",
                 "args": ["v6a", "pw"], "now_ms": 400},
            ],
            "query_ms": 500,
        }

    def _run(self, request):
        return subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=compact(request).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_session_run_accepts_prefix_migration(self):
        proc = self._run(self._request())
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = json.loads(proc.stdout.decode())
        types = [(it["结果"], it["类型"]) for it in out["项目"]]
        self.assertEqual(
            types,
            [(True, ""), (True, ""), (False, "StateError"),
             (False, "KeyError"), (True, "")],
        )
        migrated = out["项目"][1]["输出"]
        self.assertEqual(
            list(migrated),
            [
                "会话", "状态", "时刻", "期限", "池", "地址", "租期",
                "原IPv6池", "原IPv6前缀", "目标IPv6池", "目标IPv6前缀",
                "IPv6租期",
            ],
        )
        row = [r for r in out["会话"]["项目"] if r["会话"] == "s1"][0]
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(row["IPv6租期"], 1400)
        water = {r[0]: r[4] for r in out["地址池"][V6_KEY]}
        self.assertEqual(water, {"v6a": 1, "v6b": 0})
        head = {
            "版本": out["版本"],
            "项目": out["项目"],
            "会话": out["会话"],
            "地址池": out["地址池"],
        }
        self.assertEqual(
            out["摘要"],
            hashlib.sha256(compact(head).encode()).hexdigest(),
        )

    def test_byte_identical_outputs(self):
        request = self._request()
        first = self._run(request).stdout
        second = self._run(request).stdout
        self.assertEqual(first, second)

    def test_static_validation_rejects_bad_shape(self):
        bad = self._request()
        bad["requests"][1]["args"] = ["v6b"]
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        envelope = json.loads(proc.stderr.decode())
        self.assertEqual(
            envelope, {"错误": "session-run", "类型": "ValueError"}
        )

        bad = self._request()
        bad["requests"][1]["args"] = [123, "pw"]
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr.decode())["类型"], "TypeError"
        )

        bad = self._request()
        bad["requests"][1]["op"] = "前缀迁移x"
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)

    def test_pure_v4_config_byte_compatible(self):
        # 纯 IPv4 配置（无前缀池）下，含前缀迁移业务失败的合法请求输出不含
        # 任何 IPv6 键，且与无该操作的请求结构兼容。
        doc = base_config()
        doc["IPv6 前缀池"] = []
        doc["模板 IPv6 池"] = []
        request = {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["dave", "pw"], "now_ms": 0},
                # 纯 IPv4 会话上前缀迁移：目标池未知，KeyError 业务失败。
                {"key": "r2", "op": "前缀迁移", "sid": "s1",
                 "args": ["v6b", "pw"], "now_ms": 100},
            ],
            "query_ms": 200,
        }
        proc = self._run(request)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        raw = proc.stdout.decode()
        self.assertNotIn("IPv6", raw)
        out = json.loads(raw)
        self.assertEqual(
            [(it["结果"], it["类型"]) for it in out["项目"]],
            [(True, ""), (False, "KeyError")],
        )


if __name__ == "__main__":
    unittest.main()
