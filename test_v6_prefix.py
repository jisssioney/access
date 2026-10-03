"""版本 12 可选 IPv6 前缀委派（双栈）测试。"""

import io
import json
import sys
import unittest

import access
from access import Authenticator, ResourceError, Sessions, StateError


def v12_config(v6_pools, template_v6, pools=None, user_templates=None,
               template_pools=None):
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 100000,
                 "租期毫秒": 1000},
        "地址池": (
            [dict(p, 保留=list(p["保留"]), 静态=[list(x) for x in p["静态"]])
             for p in pools]
            if pools is not None
            else [
                {"标识": "default", "CIDR": "10.0.0.0/28",
                 "保留": [], "静态": []},
            ]
        ),
        "模板": [
            {"标识": "gold", "限速": 1, "突发": 0, "配额": 1,
             "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
             "超限": "拒绝"},
            {"标识": "silver", "限速": 1, "突发": 0, "配额": 1,
             "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
             "超限": "拒绝"},
        ],
        "用户模板": (
            [list(x) for x in user_templates]
            if user_templates is not None
            else [["alice", "gold"], ["bob", "gold"], ["carol", "silver"]]
        ),
        "容量": {"队列上限": 1024, "最大等待毫秒": 0,
                 "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 1000,
                 "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [list(x) if not isinstance(x, dict) else x
                      for x in (template_pools or [])],
        "IPv6前缀池": [
            dict(p, 保留前缀=list(p["保留前缀"]),
                 静态绑定=[list(x) for x in p["静态绑定"]])
            for p in v6_pools
        ],
        "模板IPv6池": [[a, list(b)] for a, b in template_v6],
    }


POOL_A = {
    "标识": "a", "聚合前缀": "2001:db8::/55", "委派长度": 56,
    "保留前缀": ["2001:db8:0:100::/56"],
    "静态绑定": [["alice", "2001:db8::/56"]],
}
POOL_B = {
    "标识": "b", "聚合前缀": "2001:db9::/48", "委派长度": 56,
    "保留前缀": [], "静态绑定": [],
}


def make_sessions(doc, users=None):
    auth = Authenticator(3, 10 ** 9)
    if users is None:
        users = [u for u, _t in doc["用户模板"]]
    for user in users:
        auth.add(user, "pw")
    sessions = Sessions(auth, 100, 10, 100000, lease_ms=1000)
    sessions.load_config(json.dumps(doc, ensure_ascii=False))
    return sessions


def dual_config():
    return v12_config([POOL_A, POOL_B], [["gold", ["a", "b"]]])


class V6ConfigTest(unittest.TestCase):
    def test_export_v12_key_order_and_empty_sections(self):
        doc = v12_config([], [])
        sessions = make_sessions(doc)
        out = json.loads(sessions.export_config())
        self.assertEqual(out["版本"], 12)
        self.assertEqual(
            list(out),
            ["版本", "会话", "地址池", "模板", "用户模板", "容量", "认证",
             "模板地址池", "IPv6前缀池", "模板IPv6池"],
        )
        self.assertEqual(out["IPv6前缀池"], [])
        self.assertEqual(out["模板IPv6池"], [])

    def test_export_roundtrip_byte_stable(self):
        sessions = make_sessions(dual_config())
        first = sessions.export_config()
        self.assertEqual(sessions.load_config(first), first)

    def test_v11_upgrade_fills_empty_v6_sections(self):
        sessions = make_sessions(v12_config([], []))
        v11 = json.loads(sessions.export_config())
        v11["版本"] = 11
        del v11["IPv6前缀池"]
        del v11["模板IPv6池"]
        envelope = json.loads(
            sessions.upgrade_config(json.dumps(v11, ensure_ascii=False))
        )
        self.assertEqual(envelope["源版本"], 11)
        self.assertEqual(envelope["目标版本"], 12)
        self.assertIs(envelope["改变"], True)
        self.assertEqual(envelope["配置"]["版本"], 12)
        self.assertEqual(envelope["配置"]["IPv6前缀池"], [])
        self.assertEqual(envelope["配置"]["模板IPv6池"], [])
        out = sessions.load_config(json.dumps(envelope, ensure_ascii=False))
        self.assertEqual(out, sessions.export_config())

    def test_v12_upgrade_changed_false(self):
        sessions = make_sessions(dual_config())
        envelope = json.loads(sessions.upgrade_config(sessions.export_config()))
        self.assertIs(envelope["改变"], False)
        self.assertEqual(envelope["目标版本"], 12)

    def test_delegated_length_errors(self):
        for mutate in (
            lambda d: d["IPv6前缀池"][0].__setitem__("委派长度", 47),
            lambda d: d["IPv6前缀池"][0].__setitem__("委派长度", 129),
            lambda d: d["IPv6前缀池"][0].__setitem__("委派长度", "56"),
            lambda d: d["IPv6前缀池"][0].__setitem__("委派长度", True),
        ):
            doc = dual_config()
            mutate(doc)
            with self.assertRaises(ValueError):
                make_sessions(doc)

    def test_prefix_alignment_and_containment_errors(self):
        for field, bad in (
            ("聚合前缀", "2001:db8::1/48"),
            ("保留前缀_item", "2001:db8::1/56"),
            ("保留前缀_outside", "2001:db9::/56"),
            ("静态绑定_item", ["alice", "2001:db8::1/56"]),
            ("静态绑定_outside", ["alice", "2001:ffff::/56"]),
        ):
            doc = dual_config()
            pool = doc["IPv6前缀池"][0]
            if field == "聚合前缀":
                pool["聚合前缀"] = bad
            elif field.startswith("保留前缀"):
                pool["保留前缀"] = [bad]
            else:
                pool["静态绑定"] = [bad]
            with self.assertRaises(ValueError, msg=field):
                make_sessions(doc)

    def test_conflicts_and_duplicates(self):
        cases = {
            "reserved dup": ["2001:db8:0:200::/56", "2001:db8:0:200::/56"],
        }
        doc = dual_config()
        doc["IPv6前缀池"][0]["保留前缀"] = cases["reserved dup"]
        with self.assertRaises(ValueError):
            make_sessions(doc)
        # 静态与保留冲突
        doc = dual_config()
        doc["IPv6前缀池"][0]["保留前缀"] = ["2001:db8:0:200::/56"]
        doc["IPv6前缀池"][0]["静态绑定"] = [
            ["alice", "2001:db8:0:200::/56"]
        ]
        with self.assertRaises(ValueError):
            make_sessions(doc)
        # 静态用户重复
        doc = dual_config()
        doc["IPv6前缀池"][0]["静态绑定"] = [
            ["alice", "2001:db8::/56"],
            ["alice", "2001:db8:0:200::/56"],
        ]
        with self.assertRaises(ValueError):
            make_sessions(doc)
        # 静态前缀重复
        doc = dual_config()
        doc["IPv6前缀池"][0]["静态绑定"] = [
            ["alice", "2001:db8:0:200::/56"],
            ["bob", "2001:db8:0:200::/56"],
        ]
        with self.assertRaises(ValueError):
            make_sessions(doc)

    def test_template_v6_section_errors(self):
        for mutate, label in (
            (lambda d: d.__setitem__("模板IPv6池", [["gold", ["zzz"]]]),
             "unknown pool"),
            (lambda d: d.__setitem__("模板IPv6池", [["zzz", ["a"]]]),
             "unknown template"),
            (lambda d: d.__setitem__("模板IPv6池", [["gold", ["a", "a"]]]),
             "duplicate pool"),
            (lambda d: d.__setitem__("模板IPv6池", [["gold", ["a"] * 33]]),
             "33 pools"),
            (lambda d: d.__setitem__(
                "模板IPv6池",
                [["silver", ["a"]], ["gold", ["a"]]]), "unsorted"),
            (lambda d: d.__setitem__(
                "模板IPv6池",
                [["gold", ["a"]], ["gold", ["b"]]]), "duplicate template"),
        ):
            doc = dual_config()
            mutate(doc)
            with self.assertRaises(ValueError, msg=label):
                make_sessions(doc)

    def test_missing_or_extra_section_rejected(self):
        doc = dual_config()
        del doc["IPv6前缀池"]
        with self.assertRaises(ValueError):
            make_sessions(doc)
        doc = dual_config()
        doc["版本"] = 11
        with self.assertRaises(ValueError):
            make_sessions(doc)


class V6SessionTest(unittest.TestCase):
    def test_dual_stack_establish_static_first(self):
        sessions = make_sessions(dual_config())
        out = json.loads(sessions.do(
            "k1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(out["前缀池"], "a")
        self.assertEqual(out["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["前缀租期"], 1000)
        # 键序：前缀三字段紧随租期。
        self.assertEqual(
            list(out)[-3:], ["前缀池", "IPv6前缀", "前缀租期"])

    def test_dynamic_smallest_and_fallback(self):
        # alice 取 a 的静态；bob 无静态，a 仅剩的动态序号（被 alice 静态与
        # 保留占满两个 /56）不可得 -> 回退 b 取最小空闲前缀。
        sessions = make_sessions(dual_config())
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = json.loads(sessions.do(
            "k2", "建立", "s2", ("bob", "pw"), 0))
        self.assertEqual(out["前缀池"], "b")
        self.assertEqual(out["IPv6前缀"], "2001:db9::/56")

    def test_exhaustion_rolls_back_v4(self):
        # 仅一个前缀池、只有一条动态委派：建立占用后第二条双栈建立必须整体
        # 失败，且撤销 v4（不留半分配租约、不建会话）。
        doc = v12_config(
            [{"标识": "a", "聚合前缀": "2001:db8::/55", "委派长度": 56,
              "保留前缀": ["2001:db8:0:100::/56"], "静态绑定": []}],
            [["gold", ["a"]]],
        )
        sessions = make_sessions(doc)
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        v4_before = dict(sessions._pools["default"].leases)
        v6_before = dict(sessions._v6_pools["a"].leases)
        with self.assertRaises(ResourceError):
            sessions.do("k2", "建立", "s2", ("bob", "pw"), 0)
        self.assertNotIn("s2", sessions._sessions)
        self.assertEqual(sessions._pools["default"].leases, v4_before)
        self.assertEqual(sessions._v6_pools["a"].leases, v6_before)

    def test_renew_extends_both_leases(self):
        sessions = make_sessions(dual_config())
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = json.loads(sessions.do("kr", "续租", "s1", None, 100))
        self.assertEqual(out["租期"], 1100)
        self.assertEqual(out["前缀租期"], 1100)

    def test_suspend_and_resume_dual_stack(self):
        sessions = make_sessions(dual_config())
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        suspended = json.loads(
            sessions.do("ks", "挂起", "s1", None, 200))
        self.assertEqual(suspended["IPv6前缀"], "")
        self.assertEqual(suspended["前缀池"], "")
        self.assertEqual(suspended["前缀租期"], 0)
        resumed = json.loads(
            sessions.do("kr2", "恢复", "s1", ("default", "pw"), 300))
        self.assertEqual(resumed["前缀池"], "a")
        self.assertEqual(resumed["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(resumed["前缀租期"], 1300)

    def test_takeover_transfers_prefix_atomically(self):
        sessions = make_sessions(dual_config())
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = json.loads(sessions.do(
            "kt", "接管", "t1", ("s1", "pw"), 400))
        self.assertEqual(out["前缀池"], "a")
        self.assertEqual(out["IPv6前缀"], "2001:db8::/56")
        # 旧会话转为下线墓碑（仍在表中但已清址），前缀转移给新会话。
        self.assertEqual(sessions._sessions["s1"]["state"], "下线")
        self.assertIsNone(sessions._sessions["s1"]["v6"])
        v6_leases = sessions._v6_pools["a"].leases
        self.assertEqual(len(v6_leases), 1)
        self.assertEqual(list(v6_leases.values()), ["t1"])

    def test_takeover_replay_same_params(self):
        sessions = make_sessions(dual_config())
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        first = sessions.do("kt", "接管", "t1", ("s1", "pw"), 400)
        # 同 key 同参重放返回缓存原结果（幂等语义）。
        replay = sessions.do("kt", "接管", "t1", ("s1", "pw"), 400)
        self.assertEqual(replay, first)
        with self.assertRaises(ValueError):
            sessions.do("kt", "接管", "t2", ("s1", "pw"), 400)

    def test_migrate_keeps_v6_prefix(self):
        doc = v12_config(
            [POOL_A, POOL_B], [["gold", ["a", "b"]]],
            pools=[
                {"标识": "default", "CIDR": "10.0.0.0/28",
                 "保留": [], "静态": []},
                {"标识": "p2", "CIDR": "10.1.0.0/28",
                 "保留": [], "静态": []},
            ],
        )
        sessions = make_sessions(doc)
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before = json.loads(sessions.sessions(0))["项目"][0]
        out = json.loads(sessions.do(
            "km", "迁移", "s1", ("p2", "pw"), 100))
        self.assertEqual(out["目标地址"], "10.1.0.1")
        self.assertEqual(out["目标池"], "p2")
        self.assertEqual(out["前缀池"], "a")
        self.assertEqual(out["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["前缀租期"], before["前缀租期"])

    def test_unbound_template_stays_pure_ipv4(self):
        doc = dual_config()
        sessions = make_sessions(
            doc, users=("alice", "bob", "carol", "erin"))
        # erin 未绑定模板：建立为纯 IPv4，但因功能已启用仍输出空 v6 三键。
        out = json.loads(sessions.do(
            "ku", "建立", "u1", ("erin", "pw"), 0))
        self.assertEqual(out["前缀池"], "")
        self.assertEqual(out["IPv6前缀"], "")
        self.assertEqual(out["前缀租期"], 0)

    def test_offline_releases_both(self):
        sessions = make_sessions(dual_config())
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = json.loads(sessions.do("ko", "下线", "s1", None, 50))
        self.assertEqual(out["IPv6前缀"], "")
        self.assertEqual(sessions._v6_pools["a"].leases, {})
        # alice 重新建立可取回静态前缀。
        out = json.loads(sessions.do("k2", "建立", "s2", ("alice", "pw"), 60))
        self.assertEqual(out["IPv6前缀"], "2001:db8::/56")


class V6CapacityTest(unittest.TestCase):
    def test_queue_and_promotion_dual_stack(self):
        doc = v12_config(
            [{"标识": "a", "聚合前缀": "2001:db8::/55", "委派长度": 56,
              "保留前缀": ["2001:db8:0:100::/56"], "静态绑定": []}],
            [["gold", ["a"]]],
        )
        sessions = make_sessions(doc)
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        queued = json.loads(sessions.capacity(
            "q1", "申请", "qb", ("bob", "pw", 100000), 0))
        self.assertEqual(queued["结果"], "排队")
        # 挂起 s1 释放前缀后推进晋升。
        sessions.do("su", "挂起", "s1", None, 1)
        advanced = json.loads(sessions.capacity(
            "adv", "推进", "", None, 1))
        self.assertEqual(advanced["排队"], 0)
        self.assertEqual(advanced["变更"], [1])
        row = [r for r in json.loads(sessions.sessions(1))["项目"]
               if r["会话"] == "qb"][0]
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")


class V6StatsAndCheckpointTest(unittest.TestCase):
    def setUp(self):
        self.sessions = make_sessions(dual_config())
        self.sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.sessions.do("k2", "建立", "s2", ("bob", "pw"), 0)

    def test_pool_stats_v6_watermark(self):
        stats = json.loads(self.sessions.pool_stats(0))
        self.assertIn("IPv6前缀池", stats)
        by_id = {row[0]: row for row in stats["IPv6前缀池"]}
        # a: /55 -> 2 个委派，1 保留 1 静态，alice 持静态 -> 动态空闲 0。
        self.assertEqual(by_id["a"], ["a", 56, 0, 1, 1, 1, 0])
        # b: /48 -> 256 个委派，bob 持一条动态 -> 空闲 255。
        self.assertEqual(by_id["b"][0], "b")
        self.assertEqual(by_id["b"][2], 256)
        self.assertEqual(by_id["b"][5], 1)
        self.assertEqual(by_id["b"][6], 255)

    def test_sessions_page_has_v6_fields(self):
        rows = json.loads(self.sessions.sessions(0))["项目"]
        s1 = [r for r in rows if r["会话"] == "s1"][0]
        self.assertEqual(s1["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(s1["前缀池"], "a")
        self.assertEqual(s1["前缀租期"], 1000)
        self.assertEqual(
            list(s1)[-4:-1], ["前缀池", "IPv6前缀", "前缀租期"])

    def test_clog_creplay_roundtrip(self):
        checkpoint = self.sessions.clog(0)
        target = make_sessions(dual_config())
        target.creplay(checkpoint)
        row = [r for r in json.loads(target.sessions(0))["项目"]
               if r["会话"] == "s1"][0]
        self.assertEqual(row["前缀池"], "a")
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(row["前缀租期"], 1000)

    def test_runtime_checkpoint_roundtrip(self):
        checkpoint = self.sessions.runtime_checkpoint(0)
        target = make_sessions(dual_config())
        target.runtime_restore("rk", checkpoint)
        row = [r for r in json.loads(target.sessions(0))["项目"]
               if r["会话"] == "s1"][0]
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")

    def test_service_checkpoint_roundtrip(self):
        checkpoint = self.sessions.service_checkpoint(0)
        target = make_sessions(dual_config())
        target.service_restore("sk", checkpoint)
        rows = {r["会话"]: r for r in json.loads(target.sessions(0))["项目"]}
        self.assertEqual(rows["s1"]["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(rows["s2"]["IPv6前缀"], "2001:db9::/56")

    def test_restore_rejects_tampered_prefix(self):
        checkpoint = self.sessions.clog(0)
        doc = json.loads(checkpoint)
        doc["会话"][0]["IPv6前缀"] = "2001:db8:0:999::/56"
        target = make_sessions(dual_config())
        with self.assertRaises(ValueError):
            target.creplay(json.dumps(doc, ensure_ascii=False))


class PureIPv4ByteIdentityTest(unittest.TestCase):
    """无 v6 配置（前缀池为空）时，会话类输出不含任何 v6 键。"""

    def test_no_v6_keys_when_pool_section_empty(self):
        doc = v12_config([], [])
        sessions = make_sessions(doc, users=("alice", "bob", "carol"))
        sessions.do("k1", "建立", "s1", ("alice", "pw"), 0)
        outputs = [
            sessions.do("k2", "建立", "s2", ("bob", "pw"), 0),
            sessions.sessions(0),
            sessions.pool_stats(0),
            sessions.runtime_stats(0),
            sessions.clog(0),
            sessions.capacity_stats(0),
        ]
        for text in outputs:
            self.assertNotIn("IPv6前缀", text)
            self.assertNotIn("前缀池", text)
            self.assertNotIn("前缀租期", text)


class SessionRunCliV12Test(unittest.TestCase):
    def _run(self, document):
        raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv = ["access.py", "session-run"]
        sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        sys.stdout, sys.stderr = out, err
        try:
            code = access.main(sys.argv)
        finally:
            out.flush()
            err.flush()
            stdout, stderr = out.buffer.getvalue(), err.buffer.getvalue()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        return code, stdout, stderr

    def test_session_run_v12_dual_stack(self):
        config = v12_config(
            [{"标识": "a", "聚合前缀": "2001:db8::/48", "委派长度": 56,
              "保留前缀": [], "静态绑定": []}],
            [["gold", ["a"]]],
            user_templates=[["alice", "gold"]],
        )
        document = {
            "users": [["alice", "pw"]],
            "config": config,
            "requests": [
                {"key": "k1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
            ],
            "query_ms": 0,
        }
        code, stdout, stderr = self._run(document)
        self.assertEqual(code, 0, stderr.decode())
        result = json.loads(stdout)
        session = [r for r in result["会话"]["项目"]
                   if r["会话"] == "s1"][0]
        self.assertEqual(session["前缀池"], "a")
        self.assertEqual(session["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(session["前缀租期"], 1000)


if __name__ == "__main__":
    unittest.main()
