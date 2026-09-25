import json
import unittest

from access import (
    AuthError,
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def make(users=("alice", "bob", "carol", "dave"), total=2, per=2,
         pool=("10.0.0.0/30", (), ()), idle_ms=100000, lease_ms=100000):
    """total=2、/30 动态池恰两址（.1/.2），默认占满即触发排队。"""
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


class ParamValidationTest(unittest.TestCase):
    def test_types_and_ranges(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.capacity(bad, "申请", "x", ("alice", "pw", 1), 0)
        for i, bad in enumerate((True, 1, None, [])):
            with self.assertRaises(TypeError):
                s.capacity(f"kop{i}", bad, "x", ("alice", "pw", 1), 0)
        for bad in ("建立", "续租", "下线", "迁移", "接管", ""):
            with self.assertRaises(ValueError):
                s.capacity("k" + bad, bad, "x", ("alice", "pw", 1), 0)
        for bad in (True, 1.5, "1", None):
            with self.assertRaises(TypeError):
                s.capacity("n1" + str(bad), "申请", "x", ("alice", "pw", bad), 0)
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                s.capacity("n2" + str(bad), "申请", "x", ("alice", "pw", bad), 0)
        for i, bad in enumerate((False, 1.5, -1, None)):
            with self.assertRaises((TypeError, ValueError)):
                s.capacity(f"n3{i}", "推进", "", None, bad)

    def test_args_shape(self):
        _auth, s = make()
        for bad in (["alice", "pw", 1], None, ("alice", "pw"),
                    ("alice", "pw", 1, 2)):
            with self.assertRaises((TypeError, ValueError)):
                s.capacity("a" + str(type(bad)), "申请", "x", bad, 0)
        with self.assertRaises(TypeError):
            s.capacity("c1", "申请", "x", (1, "pw", 1), 0)
        with self.assertRaises(ValueError):
            s.capacity("c2", "申请", "x", ("alice", "", 1), 0)
        with self.assertRaises(ValueError):
            s.capacity("c3", "取消", "x", ("x",), 0)
        with self.assertRaises(ValueError):
            s.capacity("c4", "推进", "x", None, 0)
        with self.assertRaises(TypeError):
            s.capacity("c5", "推进", 1, None, 0)
        with self.assertRaises(ValueError):
            s.capacity("c6", "推进", "", 0, 0)
        with self.assertRaises(ValueError):
            s.capacity("c7", "取消", "", None, 0)

    def test_param_error_is_cached(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.capacity("z", "推进", "", None, -1)
        # 同参重放重抛同型异常；异参抛 ValueError。
        with self.assertRaises(ValueError):
            s.capacity("z", "推进", "", None, -1)
        with self.assertRaises(ValueError):
            s.capacity("z", "推进", "", None, 0)


class ApplyTest(unittest.TestCase):
    def test_immediate_online_bytes(self):
        _auth, s = make(total=4, per=4)
        out = s.capacity("k1", "申请", "s1", ("alice", "pw", 500), 10)
        self.assertEqual(out, wire({"会话": "s1", "结果": "在线",
                                   "时刻": 10, "截止": 510}))
        self.assertEqual(list(json.loads(out)), ["会话", "结果", "时刻", "截止"])

    def test_queued_when_total_full(self):
        _auth, s = make()
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        out = s.capacity("k3", "申请", "q1", ("carol", "pw", 20), 5)
        self.assertEqual(out, wire({"会话": "q1", "结果": "排队",
                                   "时刻": 5, "截止": 25}))
        self.assertEqual(len(s._queue_order), 1)

    def test_queued_when_per_user_full(self):
        _auth, s = make(total=4, per=1)
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        out = s.capacity("k2", "申请", "q1", ("alice", "pw", 100), 0)
        self.assertEqual(json.loads(out)["结果"], "排队")

    def test_queued_when_pool_exhausted(self):
        _auth, s = make(total=10, per=10)
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        out = s.capacity("k3", "申请", "q1", ("carol", "pw", 100), 0)
        self.assertEqual(json.loads(out)["结果"], "排队")

    def test_aging_frees_address_before_apply(self):
        _auth, s = make(total=10, per=10, idle_ms=100)
        s.capacity("k1", "申请", "s1", ("alice", "pw", 500), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 500), 0)
        # 两址占满；同刻到期挂起并释址，申请先老化，carol 立即在线。
        out = s.capacity("k3", "申请", "q1", ("carol", "pw", 500), 100)
        self.assertEqual(json.loads(out)["结果"], "在线")

    def test_auth_failure_no_allocation(self):
        _auth, s = make(total=4, per=4)
        with self.assertRaises(AuthError):
            s.capacity("k1", "申请", "s1", ("alice", "bad", 10), 0)
        with self.assertRaises(AuthError):  # 同参重放，认证器失败计数不重复累加
            s.capacity("k1", "申请", "s1", ("alice", "bad", 10), 0)
        # 正确口令仍可建立（重放未产生副作用）。
        out = s.capacity("k2", "申请", "s1", ("alice", "pw", 10), 0)
        self.assertEqual(json.loads(out)["结果"], "在线")

    def test_duplicate_sid(self):
        _auth, s = make(total=4, per=4)
        s.capacity("k1", "申请", "s1", ("alice", "pw", 10), 0)
        with self.assertRaises(StateError):
            s.capacity("k2", "申请", "s1", ("alice", "pw", 10), 0)
        # 排队中 sid 同样冲突。
        _auth2, s2 = make()
        s2.capacity("a1", "申请", "x1", ("alice", "pw", 100), 0)
        s2.capacity("a2", "申请", "x2", ("bob", "pw", 100), 0)
        s2.capacity("a3", "申请", "q1", ("carol", "pw", 100), 0)
        with self.assertRaises(StateError):
            s2.capacity("a4", "申请", "q1", ("dave", "pw", 100), 0)

    def test_queue_full_at_1024(self):
        auth = Authenticator(3, 1000)
        for i in range(1030):
            auth.add(f"u{i}", "pw")
        s = Sessions(auth, 1, 1100, 100000,
                     pool=("10.0.0.0/30", (), ()), lease_ms=100000)
        s.capacity("q0", "申请", "q0", ("u0", "pw", 100), 0)
        for i in range(1, 1025):
            s.capacity(f"q{i}", "申请", f"q{i}", (f"u{i}", "pw", 100), 0)
        self.assertEqual(len(s._queue_order), 1024)
        with self.assertRaises(ResourceError):
            s.capacity("qfull", "申请", "qfull", ("u1025", "pw", 100), 0)
        # 失败不留队项；取消一项后可再入队。
        self.assertNotIn("qfull", s._capacity_queue)
        s.capacity("qx", "取消", "q1024", None, 0)
        out = s.capacity("qagain", "申请", "q1024", ("u1024", "pw", 100), 0)
        self.assertEqual(json.loads(out)["结果"], "排队")


class CancelTest(unittest.TestCase):
    def test_cancel_queued_bytes(self):
        _auth, s = make()
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        s.capacity("k3", "申请", "q1", ("carol", "pw", 20), 5)
        out = s.capacity("k4", "取消", "q1", None, 9)
        self.assertEqual(out, wire({"会话": "q1", "结果": "取消",
                                   "时刻": 9, "截止": 25}))
        self.assertEqual(s._queue_order, [])
        # 取消后同 sid 可重新申请（入队序继续递增）。
        out = s.capacity("k5", "申请", "q1", ("carol", "pw", 1), 9)
        self.assertEqual(json.loads(out)["结果"], "排队")

    def test_cancel_unknown_keyerror(self):
        _auth, s = make()
        with self.assertRaises(KeyError):
            s.capacity("k1", "取消", "nope", None, 0)

    def test_cancel_non_queued_stateerror(self):
        _auth, s = make(total=4, per=4)
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        with self.assertRaises(StateError):
            s.capacity("k2", "取消", "s1", None, 0)
        s.do("o1", "下线", "s1", None, 0)
        with self.assertRaises(StateError):
            s.capacity("k3", "取消", "s1", None, 0)

    def test_cancel_does_not_age(self):
        _auth, s = make(total=1, per=1, idle_ms=50)
        s.capacity("k1", "申请", "s1", ("alice", "pw", 1000), 0)
        s.capacity("k2", "申请", "q1", ("bob", "pw", 1000), 1)
        # t=100 已过空闲期限，取消不老化，s1 仍持址在线。
        s.capacity("k3", "取消", "q1", None, 100)
        doc = json.loads(s.pool_stats(100))
        self.assertEqual(doc["池"][0][4], 0)  # 统计时才老化释址


class AdvanceTest(unittest.TestCase):
    def test_empty_advance(self):
        _auth, s = make(total=4, per=4)
        self.assertEqual(s.capacity("k1", "推进", "", None, 7),
                         wire({"时刻": 7, "在线": 0, "排队": 0, "变更": []}))

    def test_timeout_inclusive_and_promotion(self):
        _auth, s = make(total=1, per=10)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("a2", "申请", "q1", ("bob", "pw", 5), 1)   # seq1 截止6
        s.capacity("a3", "申请", "q2", ("carol", "pw", 50), 1)  # seq2 截止51
        out = s.capacity("v1", "推进", "", None, 6)
        self.assertEqual(out, wire({"时刻": 6, "在线": 1,
                                   "排队": 1, "变更": [1]}))
        s.do("o1", "下线", "s1", None, 7)
        out = s.capacity("v2", "推进", "", None, 8)
        self.assertEqual(json.loads(out), {"时刻": 8, "在线": 1,
                                           "排队": 0, "变更": [2]})

    def test_fifo_with_per_user_gate(self):
        _auth, s = make(total=2, per=1)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("a2", "申请", "s2", ("bob", "pw", 100), 0)
        s.capacity("a3", "申请", "q1", ("carol", "pw", 100), 1)  # seq1
        s.capacity("a4", "申请", "q2", ("alice", "pw", 100), 1)  # seq2
        s.do("o1", "下线", "s2", None, 2)
        # 仅一个空位：seq1 先晋升，seq2 因全局再满留队。
        doc = json.loads(s.capacity("v1", "推进", "", None, 3))
        self.assertEqual(doc["变更"], [1])
        self.assertEqual((doc["在线"], doc["排队"]), (2, 1))
        s.do("o2", "下线", "s1", None, 4)
        doc = json.loads(s.capacity("v2", "推进", "", None, 5))
        self.assertEqual(doc["变更"], [2])
        self.assertEqual((doc["在线"], doc["排队"]), (2, 0))

    def test_timeout_then_promotion_one_pass(self):
        _auth, s = make(total=1, per=10)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("a2", "申请", "q1", ("bob", "pw", 10), 1)   # seq1 截止11
        s.capacity("a3", "申请", "q2", ("carol", "pw", 10), 1)  # seq2 截止11
        s.capacity("a4", "申请", "q3", ("dave", "pw", 100), 1)  # seq3
        s.do("o1", "下线", "s1", None, 11)
        # 超时按入队序 [1,2]，随后 seq3 晋升：变更为超时序接晋升序。
        doc = json.loads(s.capacity("v1", "推进", "", None, 11))
        self.assertEqual(doc, {"时刻": 11, "在线": 1,
                               "排队": 0, "变更": [1, 2, 3]})

    def test_static_address_gate(self):
        pool = ("10.0.0.0/30", (), (("alice", "10.0.0.1"),))
        _auth, s = make(total=2, per=2, pool=pool)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)  # 静态址
        s.capacity("a2", "申请", "s2", ("bob", "pw", 100), 0)    # 动态址
        s.capacity("a3", "申请", "qa", ("alice", "pw", 100), 1)  # seq1
        s.capacity("a4", "申请", "qb", ("bob", "pw", 100), 1)    # seq2
        s.do("o1", "下线", "s2", None, 5)
        # alice 静态址仍被 s1 占用，不可晋升；bob 可取动态址晋升。
        doc = json.loads(s.capacity("v1", "推进", "", None, 6))
        self.assertEqual(doc["变更"], [2])
        self.assertEqual(doc["排队"], 1)

    def test_aging_suspends_then_promotes(self):
        _auth, s = make(total=10, per=10, idle_ms=100)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 1000), 0)
        s.capacity("a2", "申请", "s2", ("bob", "pw", 1000), 0)
        s.capacity("a3", "申请", "q1", ("carol", "pw", 1000), 1)  # 因池耗尽排队
        # 同刻到期 s1/s2 挂起释址；挂起会话仍计上限但 total 有余，q1 晋升。
        doc = json.loads(s.capacity("v1", "推进", "", None, 100))
        self.assertEqual(doc, {"时刻": 100, "在线": 3,
                               "排队": 0, "变更": [1]})

    def test_lease_expiry_frees_address(self):
        _auth, s = make(total=10, per=10, lease_ms=10)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 1000), 0)
        s.capacity("a2", "申请", "s2", ("bob", "pw", 1000), 0)
        s.capacity("a3", "申请", "q1", ("carol", "pw", 1000), 1)
        # t=10 租约同刻到期释址，会话仍在线（空闲未到），q1 取址晋升。
        doc = json.loads(s.capacity("v1", "推进", "", None, 10))
        self.assertEqual(doc["在线"], 3)
        self.assertEqual(doc["变更"], [1])


class ReplayTest(unittest.TestCase):
    def test_apply_replay_no_side_effect(self):
        _auth, s = make(total=1, per=10)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)
        out = s.capacity("a2", "申请", "q1", ("bob", "pw", 100), 1)
        self.assertEqual(json.loads(out)["结果"], "排队")
        s.do("o1", "下线", "s1", None, 2)
        s.capacity("v1", "推进", "", None, 3)  # q1 已晋升
        # 同参重放仍返回首次“排队”结果，无任何副作用。
        self.assertEqual(s.capacity("a2", "申请", "q1", ("bob", "pw", 100), 1),
                         out)

    def test_advance_replay_byte_identical(self):
        _auth, s = make(total=1, per=10)
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("a2", "申请", "q1", ("bob", "pw", 50), 1)
        first = s.capacity("v1", "推进", "", None, 10)
        self.assertEqual(json.loads(first)["变更"], [])
        # 重放不老化、不推进：返回逐字节一致。
        self.assertEqual(s.capacity("v1", "推进", "", None, 10), first)

    def test_different_params_valueerror(self):
        _auth, s = make()
        s.capacity("k1", "申请", "s1", ("alice", "pw", 10), 0)
        with self.assertRaises(ValueError):
            s.capacity("k1", "申请", "s1", ("alice", "pw", 11), 0)
        with self.assertRaises(ValueError):
            s.capacity("k1", "申请", "s1", ("alice", "pw", 10), 1)
        with self.assertRaises(ValueError):
            s.capacity("k1", "取消", "s1", None, 0)

    def test_exception_replay(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(KeyError):
                s.capacity("k1", "取消", "nope", None, 0)

    def test_cache_domains_separate(self):
        _auth, s = make(total=4, per=4)
        # do 与 capacity 同 key 不同域，互不视为重放。
        out_do = s.do("same", "建立", "s1", ("alice", "pw"), 0)
        out_cap = s.capacity("same", "申请", "s2", ("bob", "pw", 10), 0)
        self.assertIn("状态", out_do)
        self.assertEqual(json.loads(out_cap)["结果"], "在线")


class NoPoolAndDoTest(unittest.TestCase):
    def test_apply_queues_without_default_pool(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 4, 100000, lease_ms=100000)
        out = s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        self.assertEqual(json.loads(out)["结果"], "排队")
        s.add_pool("default", ("10.0.0.0/30", (), ()))
        doc = json.loads(s.capacity("v1", "推进", "", None, 5))
        self.assertEqual(doc, {"时刻": 5, "在线": 1,
                               "排队": 0, "变更": [1]})

    def test_do_establish_still_rejects(self):
        _auth, s = make(total=1, per=10)
        s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(ResourceError):
            s.do("d2", "建立", "s2", ("bob", "pw"), 0)
        # do 建立不入队：取消 s2 为未知 sid。
        with self.assertRaises(KeyError):
            s.capacity("c1", "取消", "s2", None, 0)


if __name__ == "__main__":
    unittest.main()
