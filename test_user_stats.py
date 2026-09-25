"""user_stats 只读快照测试。"""

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

POOL = ("10.0.0.0/24", (), ())


def make(total=2, per=2, idle_ms=100, lease_ms=50, users=("alice", "bob")):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=POOL, lease_ms=lease_ms)


class UserStatsValidationTest(unittest.TestCase):
    def test_type_and_value_errors(self):
        _auth, s = make()
        for bad in (1, True, None, b"alice"):
            with self.assertRaises(TypeError):
                s.user_stats(bad, 0)
        with self.assertRaises(ValueError):
            s.user_stats("", 0)
        with self.assertRaises(ValueError):
            s.user_stats("alice\0", 0)
        with self.assertRaises(TypeError):
            s.user_stats("alice", True)
        with self.assertRaises(TypeError):
            s.user_stats("alice", 1.0)
        with self.assertRaises(ValueError):
            s.user_stats("alice", -1)

    def test_unknown_user_key_error(self):
        _auth, s = make()
        with self.assertRaises(KeyError):
            s.user_stats("carol", 0)

    def test_empty_snapshot_bytes(self):
        _auth, s = make()
        self.assertEqual(
            s.user_stats("alice", 0),
            '{"时刻":0,"用户":"alice",'
            '"会话":{"在线":0,"挂起":0,"下线":0,"排队":0},'
            '"租约":{"占用":0,"最早到期":0},'
            '"失败":['
            '{"类型":"认证","次数":0},'
            '{"类型":"资源","次数":0},'
            '{"类型":"状态","次数":0},'
            '{"类型":"后端","次数":0}]}\n',
        )


class UserStatsViewTest(unittest.TestCase):
    def test_online_lease_and_deadline_view(self):
        _auth, s = make(idle_ms=100, lease_ms=50)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 期限 100、租期 50。
        out = json.loads(s.user_stats("alice", 10))
        self.assertEqual(out["会话"], {"在线": 1, "挂起": 0, "下线": 0, "排队": 0})
        self.assertEqual(out["租约"], {"占用": 1, "最早到期": 50})
        # 租期到（含同刻）不计占用，仍计在线。
        out = json.loads(s.user_stats("alice", 50))
        self.assertEqual(out["会话"]["在线"], 1)
        self.assertEqual(out["租约"], {"占用": 0, "最早到期": 0})
        # 期限到（含同刻）视图为挂起。
        out = json.loads(s.user_stats("alice", 100))
        self.assertEqual(out["会话"], {"在线": 0, "挂起": 1, "下线": 0, "排队": 0})
        self.assertEqual(out["租约"], {"占用": 0, "最早到期": 0})

    def test_query_does_not_age_or_change_lease(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.user_stats("alice", 1000)
        # 查询不老化：会话仍在线且持址。
        session = s._sessions["s1"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])
        self.assertEqual(len(s._pools["default"].leases), 1)

    def test_tombstone_counts_offline(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "下线", "s1", None, 10)
        out = json.loads(s.user_stats("alice", 0))
        self.assertEqual(out["会话"], {"在线": 0, "挂起": 0, "下线": 1, "排队": 0})

    def test_suspended_counts_suspended_not_online(self):
        _auth, s = make(idle_ms=10, lease_ms=100)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.capacity("c0", "推进", "", None, 10)  # 老化：s1 挂起释址
        out = json.loads(s.user_stats("alice", 20))
        self.assertEqual(out["会话"], {"在线": 0, "挂起": 1, "下线": 0, "排队": 0})
        self.assertEqual(out["租约"], {"占用": 0, "最早到期": 0})

    def test_queue_deadline_view(self):
        auth, s = make(per=2)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        # total=2 满，carol 申请入队，截止=20+500=520。
        auth.add("carol", "pw")
        s.capacity("c1", "申请", "q1", ("carol", "pw", 500), 20)
        self.assertEqual(json.loads(s.user_stats("carol", 519))["会话"]["排队"], 1)
        self.assertEqual(json.loads(s.user_stats("carol", 520))["会话"]["排队"], 0)
        # 视图不摘队项。
        self.assertIn("q1", s._capacity_queue)
        # 队项不计入其他用户。
        self.assertEqual(json.loads(s.user_stats("alice", 20))["会话"]["排队"], 0)

    def test_earliest_lease_is_minimum(self):
        auth, s = make(total=5, per=5, lease_ms=50)
        auth.add("carol", "pw")
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("alice", "pw"), 10)
        out = json.loads(s.user_stats("alice", 5))
        self.assertEqual(out["租约"]["占用"], 2)
        self.assertEqual(out["租约"]["最早到期"], 50)


class UserStatsFailureTest(unittest.TestCase):
    def test_do_auth_resource_state_and_replay(self):
        _auth, s = make(per=1)
        with self.assertRaises(AuthError):
            s.do("k1", "建立", "s1", ("alice", "bad"), 0)
        with self.assertRaises(AuthError):  # 同参重放不重复计数
            s.do("k1", "建立", "s1", ("alice", "bad"), 0)
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        with self.assertRaises(ResourceError):  # per 满
            s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        with self.assertRaises(StateError):  # 重复 sid 计状态（bob 名下）
            s.do("k4", "建立", "s2", ("bob", "pw"), 0)
        with self.assertRaises(KeyError):  # KeyError 不计
            s.do("k5", "续租", "nope", None, 0)
        with self.assertRaises(ValueError):  # 参数错不计
            s.do("k6", "建立", "s6", ("alice",), 0)
        self.assertEqual(
            [f["次数"] for f in json.loads(s.user_stats("alice", 0))["失败"]],
            [1, 1, 0, 0],
        )
        self.assertEqual(
            [f["次数"] for f in json.loads(s.user_stats("bob", 0))["失败"]],
            [0, 0, 1, 0],
        )

    def test_backend_failures_from_do_and_capacity(self):
        _auth, s = make()
        s.fault("f1", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("k1", "建立", "s1", ("alice", "pw"), 10)
        with self.assertRaises(BackendError):  # 重放不计
            s.do("k1", "建立", "s1", ("alice", "pw"), 10)
        with self.assertRaises(BackendError):  # capacity 申请同用户，计第二次
            s.capacity("c1", "申请", "q1", ("alice", "pw", 100), 20)
        s.fault("f2", "恢复", None, 30)
        self.assertEqual(
            [f["次数"] for f in json.loads(s.user_stats("alice", 30))["失败"]],
            [0, 0, 0, 2],
        )

    def test_meter_failures(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):  # 未绑模板
            s.meter("m1", "s1", 10, 10)
        with self.assertRaises(KeyError):  # 未知 sid 不计
            s.meter("m2", "nope", 10, 10)
        self.assertEqual(
            [f["次数"] for f in json.loads(s.user_stats("alice", 10))["失败"]],
            [0, 0, 1, 0],
        )

    def test_capacity_cancel_state_and_queue_full_resource(self):
        _auth, s = make(total=1, per=1)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):  # 取消非排队项，计 alice 状态失败
            s.capacity("c1", "取消", "s1", None, 10)
        # 队满：队列上限 1，per 满使申请入队，第二项队满计资源（bob 名下）。
        doc = json.loads(s.export_config())
        doc["容量"] = {"队列上限": 1, "最大等待毫秒": 0}
        s.load_config(json.dumps(doc, ensure_ascii=False))
        s.capacity("c2", "申请", "q1", ("bob", "pw", 100), 20)
        with self.assertRaises(ResourceError):
            s.capacity("c3", "申请", "q2", ("bob", "pw", 100), 20)
        self.assertEqual(
            [f["次数"] for f in json.loads(s.user_stats("alice", 20))["失败"]],
            [0, 0, 1, 0],
        )
        self.assertEqual(
            [f["次数"] for f in json.loads(s.user_stats("bob", 20))["失败"]],
            [0, 1, 0, 0],
        )

    def test_query_is_readonly(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        snapshot = (
            dict(s._user_fail),
            dict(s._backoff),
            len(s._capacity_events),
            len(s._chain_events),
            len(s._audit_events),
            len(s._cache),
        )
        s.user_stats("alice", 999)
        self.assertEqual(
            (
                s._user_fail,
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
