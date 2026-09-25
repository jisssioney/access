"""runtime_stats 只读快照测试。"""

import json
import unittest

from access import (
    Authenticator,
    AuthError,
    BackendError,
    ResourceError,
    Sessions,
    StateError,
)

POOL = ("10.0.0.0/24", ("10.0.0.2",), ())


def make(total=2, per=2, idle_ms=100, lease_ms=50, users=("alice", "bob")):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=POOL, lease_ms=lease_ms)


class RuntimeStatsValidationTest(unittest.TestCase):
    def test_now_ms_type_and_value_errors(self):
        _auth, s = make()
        for bad in (True, 1.0, "0", None):
            with self.assertRaises(TypeError):
                s.runtime_stats(bad)
        with self.assertRaises(ValueError):
            s.runtime_stats(-1)

    def test_pool_type_value_and_unknown(self):
        _auth, s = make()
        for bad in (1, True, b"default"):
            with self.assertRaises(TypeError):
                s.runtime_stats(0, bad)
        with self.assertRaises(ValueError):
            s.runtime_stats(0, "")
        with self.assertRaises(ValueError):
            s.runtime_stats(0, "a\0b")
        with self.assertRaises(KeyError):
            s.runtime_stats(0, "nope")

    def test_empty_snapshot_bytes(self):
        _auth, s = make()
        self.assertEqual(
            s.runtime_stats(0),
            '{"时刻":0,'
            '"会话":{"在线":0,"挂起":0,"下线":0,"排队":0},'
            '"建立":{"总数":0,"成功":0,"成功率万分比":0},'
            '"失败":['
            '{"类型":"认证","次数":0},'
            '{"类型":"资源","次数":0},'
            '{"类型":"状态","次数":0},'
            '{"类型":"后端","次数":0}],'
            '"池":[{"标识":"default","总量":254,"占用":0,"可用":253,"保留":1}]}\n',
        )

    def test_no_pool_lists_empty(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 2, 2, 100, lease_ms=50)
        out = json.loads(s.runtime_stats(0))
        self.assertEqual(out["池"], [])


class RuntimeStatsViewTest(unittest.TestCase):
    def test_session_view_and_pool_occupancy(self):
        _auth, s = make(idle_ms=100, lease_ms=50)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = json.loads(s.runtime_stats(10))
        self.assertEqual(out["会话"], {"在线": 1, "挂起": 0, "下线": 0, "排队": 0})
        self.assertEqual(
            out["池"],
            [{"标识": "default", "总量": 254, "占用": 1, "可用": 252, "保留": 1}],
        )
        # 租期到（含同刻）不计占用，仍计在线。
        out = json.loads(s.runtime_stats(50))
        self.assertEqual(out["会话"]["在线"], 1)
        self.assertEqual(out["池"][0]["占用"], 0)
        self.assertEqual(out["池"][0]["可用"], 253)
        # 期限到（含同刻）视图为挂起。
        out = json.loads(s.runtime_stats(100))
        self.assertEqual(out["会话"], {"在线": 0, "挂起": 1, "下线": 0, "排队": 0})

    def test_query_does_not_age(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.runtime_stats(1000)
        session = s._sessions["s1"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])
        self.assertEqual(len(s._pools["default"].leases), 1)

    def test_tombstone_and_queue_view(self):
        auth, s = make(per=2, idle_ms=1000)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        # total=2 满，carol 申请入队，截止=20+500=520。
        auth.add("carol", "pw")
        s.capacity("c1", "申请", "q1", ("carol", "pw", 500), 20)
        s.do("k3", "下线", "s1", None, 30)
        out = json.loads(s.runtime_stats(519))
        self.assertEqual(out["会话"], {"在线": 1, "挂起": 0, "下线": 1, "排队": 1})
        out = json.loads(s.runtime_stats(520))
        self.assertEqual(out["会话"]["排队"], 0)
        # 视图不摘队项。
        self.assertIn("q1", s._capacity_queue)

    def test_pool_filter_and_unicode_order(self):
        auth, s = make()
        s.add_pool("b池", ("10.1.0.0/24", (), ()))
        s.add_pool("a池", ("10.2.0.0/24", ("10.2.0.1",), ()))
        out = json.loads(s.runtime_stats(0))
        self.assertEqual([row["标识"] for row in out["池"]], ["a池", "b池", "default"])
        out = json.loads(s.runtime_stats(0, "b池"))
        self.assertEqual(
            out["池"],
            [{"标识": "b池", "总量": 254, "占用": 0, "可用": 254, "保留": 0}],
        )
        out = json.loads(s.runtime_stats(0, "a池"))
        self.assertEqual(out["池"][0]["保留"], 1)
        self.assertEqual(out["池"][0]["可用"], 253)


class RuntimeStatsEstablishTest(unittest.TestCase):
    def test_total_and_success_counting(self):
        _auth, s = make(per=1)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # 重放不计
        with self.assertRaises(AuthError):  # 认证失败：计总数不计成功
            s.do("k2", "建立", "s2", ("alice", "bad"), 0)
        with self.assertRaises(ResourceError):  # per 满：计总数不计成功
            s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        with self.assertRaises(KeyError):  # 未知用户：不计
            s.do("k4", "建立", "s4", ("carol", "pw"), 0)
        with self.assertRaises(ValueError):  # 参数错：不计
            s.do("k5", "建立", "s5", ("alice",), 0)
        s.do("k6", "续租", "s1", None, 10)  # 非建立：不计
        out = json.loads(s.runtime_stats(10))
        self.assertEqual(out["建立"], {"总数": 3, "成功": 1, "成功率万分比": 3333})

    def test_backend_failure_counts_total_not_success(self):
        _auth, s = make()
        s.fault("f1", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("k1", "建立", "s1", ("alice", "pw"), 10)
        with self.assertRaises(BackendError):  # 重放不计
            s.do("k1", "建立", "s1", ("alice", "pw"), 10)
        out = json.loads(s.runtime_stats(10))
        self.assertEqual(out["建立"], {"总数": 1, "成功": 0, "成功率万分比": 0})

    def test_config_change_keeps_counters(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        doc = json.loads(s.export_config())
        doc["容量"] = {"队列上限": 8, "最大等待毫秒": 0}
        s.load_config(json.dumps(doc, ensure_ascii=False))
        s.rollback_config()
        out = json.loads(s.runtime_stats(0))
        self.assertEqual(out["建立"], {"总数": 1, "成功": 1, "成功率万分比": 10000})


class RuntimeStatsFailureTest(unittest.TestCase):
    def test_failures_aggregate_across_users(self):
        _auth, s = make(per=1)
        with self.assertRaises(AuthError):
            s.do("k1", "建立", "s1", ("alice", "bad"), 0)
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        with self.assertRaises(ResourceError):
            s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        with self.assertRaises(StateError):  # 重复 sid，计 bob 状态
            s.do("k4", "建立", "s2", ("bob", "pw"), 0)
        s.fault("f1", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("k5", "建立", "s9", ("bob", "pw"), 10)
        out = json.loads(s.runtime_stats(10))
        self.assertEqual(
            [(f["类型"], f["次数"]) for f in out["失败"]],
            [("认证", 1), ("资源", 1), ("状态", 1), ("后端", 1)],
        )

    def test_query_is_readonly(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        snapshot = (
            dict(s._user_fail),
            list(s._establish_stats),
            dict(s._backoff),
            len(s._capacity_events),
            len(s._chain_events),
            len(s._audit_events),
            len(s._cache),
        )
        s.runtime_stats(999)
        s.runtime_stats(999, "default")
        self.assertEqual(
            (
                s._user_fail,
                s._establish_stats,
                s._backoff,
                len(s._capacity_events),
                len(s._chain_events),
                len(s._audit_events),
                len(s._cache),
            ),
            snapshot,
        )


if __name__ == "__main__":
    unittest.main()
