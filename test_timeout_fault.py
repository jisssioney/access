import json
import unittest

from access import (
    Authenticator,
    Sessions,
)


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


class TimeoutFaultParamTest(unittest.TestCase):
    def test_types_and_ranges(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.timeout_fault(bad, "注入", 1, 0)
        with self.assertRaises(ValueError):
            s.timeout_fault("", "注入", 1, 0)
        for i, bad in enumerate((True, 1, None, [])):
            with self.assertRaises(TypeError):
                s.timeout_fault(f"op{i}", bad, 1, 0)
        for bad in ("建立", "", "inject"):
            with self.assertRaises(ValueError):
                s.timeout_fault("ov" + bad, bad, 1, 0)
        for i, bad in enumerate((True, 1.5, "1", None)):
            with self.assertRaises(TypeError):
                s.timeout_fault(f"at{i}", "注入", bad, 0)
        with self.assertRaises(ValueError):
            s.timeout_fault("av", "注入", -1, 0)
        with self.assertRaises(ValueError):
            s.timeout_fault("av2", "注入", 4, 5)
        with self.assertRaises(ValueError):
            s.timeout_fault("r1", "恢复", 0, 0)
        with self.assertRaises(ValueError):
            s.timeout_fault("r2", "恢复", 5, 0)
        for i, bad in enumerate((True, 1.5, -1, None)):
            with self.assertRaises((TypeError, ValueError)):
                s.timeout_fault(f"n{i}", "注入", 1, bad)

    def test_type_error_precedes_value_error(self):
        _auth, s = make()
        # 类型错先于值错：op 既非 str 又非法、at_ms 既非 int 又小于 now。
        with self.assertRaises(TypeError):
            s.timeout_fault("a", 1, True, 1.5)
        with self.assertRaises(TypeError):
            s.timeout_fault("b", "注入", None, -1)

    def test_output_shape(self):
        _auth, s = make()
        out = s.timeout_fault("f1", "注入", 500, 10)
        self.assertEqual(
            out, wire({"状态": "等待", "时刻": 10, "触发": 500})
        )
        self.assertEqual(list(json.loads(out)), ["状态", "时刻", "触发"])
        # at_ms == now_ms 合法。
        out = s.timeout_fault("f0", "注入", 10, 10)
        self.assertEqual(json.loads(out)["触发"], 10)
        out = s.timeout_fault("f2", "恢复", None, 20)
        self.assertEqual(
            out, wire({"状态": "正常", "时刻": 20, "触发": 0})
        )

    def test_replay_cache(self):
        _auth, s = make()
        out = s.timeout_fault("f1", "注入", 500, 10)
        # 恢复后同参重放不改待触发值，仍返回首次输出。
        s.timeout_fault("g", "恢复", None, 20)
        self.assertIsNone(s._timeout_at)
        self.assertEqual(s.timeout_fault("f1", "注入", 500, 10), out)
        self.assertIsNone(s._timeout_at)
        with self.assertRaises(ValueError):
            s.timeout_fault("f1", "注入", 501, 10)
        with self.assertRaises(ValueError):
            s.timeout_fault("f1", "注入", 500, 11)
        with self.assertRaises(ValueError):
            s.timeout_fault("f1", "恢复", None, 10)

    def test_error_first_result_is_cached(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.timeout_fault("p", "注入", 0, 1)
        with self.assertRaises(ValueError):
            s.timeout_fault("p", "注入", 0, 1)
        with self.assertRaises(ValueError):
            s.timeout_fault("p", "注入", 1, 1)

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("dk", "建立", "s1", ("alice", "pw"), 0)
        s.fault("dk", "注入", 100, 0)
        s.pool_fault("dk", "注入", "default", 100, 0)
        out = s.timeout_fault("dk", "注入", 100, 0)
        self.assertEqual(json.loads(out)["状态"], "等待")

    def test_override_and_recover(self):
        _auth, s = make()
        s.timeout_fault("o1", "注入", 100, 0)
        self.assertEqual(s._timeout_at, 100)
        s.timeout_fault("o2", "注入", 250, 200)
        self.assertEqual(s._timeout_at, 250)
        s.timeout_fault("o3", "恢复", None, 300)
        self.assertIsNone(s._timeout_at)

    def test_audited_first_and_replay_only(self):
        _auth, s = make()
        s.timeout_fault("a1", "注入", 100, 0)
        s.timeout_fault("a1", "注入", 100, 0)
        s.timeout_fault("a2", "恢复", None, 5)
        s.timeout_fault("a2", "恢复", None, 5)
        events = json.loads(s.audit(limit=1000))["事件"]
        self.assertEqual(
            [(e["操作"], e["会话"], e["结果"], e["原序号"]) for e in events],
            [
                ("超时注入", "", "成功", 0),
                ("超时注入", "", "重放", 1),
                ("超时恢复", "", "成功", 0),
                ("超时恢复", "", "重放", 3),
            ],
        )
        self.assertTrue(s.verify_audit())
        # 异常不记。
        with self.assertRaises(ValueError):
            s.timeout_fault("a3", "注入", 0, 1)
        self.assertEqual(len(json.loads(s.audit(limit=1000))["事件"]), 4)
        # 不混入接管审计。
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_chain_origin_index_separate_across_domains(self):
        _auth, s = make()
        s.do("k", "建立", "s1", ("alice", "pw"), 0)
        s.timeout_fault("k", "注入", 100, 0)
        s.do("k", "建立", "s1", ("alice", "pw"), 0)
        s.timeout_fault("k", "注入", 100, 0)
        events = json.loads(s.audit(limit=100))["事件"]
        self.assertEqual(
            [(e["操作"], e["结果"], e["原序号"]) for e in events],
            [
                ("建立", "成功", 0),
                ("超时注入", "成功", 0),
                ("建立", "成功", 1),
                ("超时注入", "重放", 2),
            ],
        )
        self.assertTrue(s.verify_audit())


class TimeoutFaultFireTest(unittest.TestCase):
    def test_fire_suspends_sessions_and_times_out_queue(self):
        _auth, s = make(total=2, per=2)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.capacity("c3", "申请", "s3", ("bob", "pw", 1000), 0)
        s.capacity("c1", "申请", "q1", ("carol", "pw", 500), 10)
        s.capacity("c2", "申请", "q2", ("carol", "pw", 500), 10)
        s.timeout_fault("tf", "注入", 100, 20)
        # 未到刻的普通推进不引爆。
        doc = json.loads(s.capacity("b1", "推进", "", None, 50))
        self.assertEqual((doc["在线"], doc["排队"], doc["变更"]), (2, 2, []))
        self.assertEqual(s._timeout_at, 100)
        # 同刻引爆：全部在线挂起、全部队项按入队序超时，触发清除。
        doc = json.loads(s.capacity("go", "推进", "", None, 100))
        self.assertEqual((doc["在线"], doc["排队"], doc["变更"]), (0, 0, [1, 2]))
        self.assertIsNone(s._timeout_at)
        self.assertEqual(s._sessions["s0"]["state"], "挂起")
        self.assertEqual(s._sessions["s0"]["deadline"], 0)
        self.assertIsNone(s._sessions["s0"]["ip"])
        self.assertEqual(s._sessions["s3"]["state"], "挂起")
        self.assertEqual(len(s._capacity_queue), 0)
        self.assertEqual(len(s._pools["default"].leases), 0)
        events = json.loads(s.capacity_events(limit=100))["事件"]
        self.assertEqual(
            [(e["结果"], e["入队序"], e["会话"]) for e in events[-2:]],
            [("超时", 1, "q1"), ("超时", 2, "q2")],
        )

    def test_only_due_advance_fires(self):
        _auth, s = make(total=1, per=1)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.timeout_fault("tf", "注入", 100, 0)
        # 申请与取消不引爆。
        self.assertEqual(
            json.loads(s.capacity("a1", "申请", "q1", ("bob", "pw", 1000), 10))["结果"],
            "排队",
        )
        self.assertEqual(
            json.loads(s.capacity("x1", "取消", "q1", None, 20))["结果"], "取消"
        )
        # 只读统计不引爆。
        s.capacity_stats(100)
        s.clog(100)
        s.pool_stats(100)
        s.runtime_stats(100)
        self.assertEqual(s._timeout_at, 100)
        doc = json.loads(s.capacity("go", "推进", "", None, 100))
        self.assertEqual((doc["在线"], doc["排队"]), (0, 0))
        self.assertIsNone(s._timeout_at)

    def test_no_promotion_or_half_release_in_firing_batch(self):
        _auth, s = make(total=2, per=2, pool=("10.0.0.0/31", (), ()))
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.capacity("c1", "申请", "s1", ("bob", "pw", 1000), 0)
        s.capacity("c2", "申请", "q9", ("carol", "pw", 1000), 0)
        s.timeout_fault("tf", "注入", 50, 10)
        # 挂起释址后本可晋升 q9，但触发批只超时、不晋升。
        doc = json.loads(s.capacity("go", "推进", "", None, 50))
        self.assertEqual((doc["在线"], doc["排队"], doc["变更"]), (0, 0, [1]))
        self.assertNotIn("q9", s._sessions)
        pool = s._pools["default"]
        self.assertEqual(len(pool.leases), 0)
        self.assertEqual(len(pool.free), 2)

    def test_fire_without_prior_aging(self):
        _auth, s = make(total=2, per=2)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.capacity("c1", "申请", "s1", ("bob", "pw", 1000), 0)
        s.timeout_fault("tf", "注入", 50, 0)
        doc = json.loads(s.capacity("go", "推进", "", None, 99999))
        self.assertEqual(doc["在线"], 0)
        self.assertTrue(
            all(v["state"] == "挂起" for v in s._sessions.values())
        )

    def test_advance_replay_does_not_refire(self):
        _auth, s = make(total=1, per=1)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.timeout_fault("tf", "注入", 100, 0)
        out = s.capacity("go", "推进", "", None, 100)
        self.assertEqual(json.loads(out)["变更"], [])
        s.timeout_fault("tf2", "注入", 500, 200)
        # 同参重放直接返回缓存，不引爆新触发、不老化。
        self.assertEqual(s.capacity("go", "推进", "", None, 100), out)
        self.assertEqual(s._timeout_at, 500)
        self.assertEqual(s._sessions["s0"]["state"], "挂起")

    def test_normal_timeout_then_trigger(self):
        _auth, s = make(total=1, per=1)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.capacity("c1", "申请", "q1", ("bob", "pw", 100), 0)
        s.timeout_fault("tf", "注入", 500, 0)
        doc = json.loads(s.capacity("p1", "推进", "", None, 100))
        self.assertEqual((doc["在线"], doc["排队"], doc["变更"]), (1, 0, [1]))
        self.assertEqual(s._timeout_at, 500)
        doc = json.loads(s.capacity("p2", "推进", "", None, 500))
        self.assertEqual((doc["在线"], doc["排队"], doc["变更"]), (0, 0, []))

    def test_static_address_released_not_returned_to_heap(self):
        _auth, s = make(pool=("10.0.0.0/24", (), (("alice", "10.0.0.5"),)))
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        pool = s._pools["default"]
        self.assertEqual(len(pool.leases), 1)
        s.timeout_fault("tf", "注入", 100, 0)
        s.capacity("go", "推进", "", None, 100)
        self.assertEqual(len(pool.leases), 0)
        self.assertNotIn(0x0A000005, pool.free)
        out = s.capacity("n1", "申请", "s1", ("alice", "pw", 1000), 200)
        self.assertEqual(json.loads(out)["结果"], "在线")

    def test_checkpoint_consistent_after_fire(self):
        _auth, s = make(total=2, per=2)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.capacity("c3", "申请", "s3", ("bob", "pw", 1000), 0)
        s.capacity("c1", "申请", "q1", ("carol", "pw", 1000), 10)
        s.timeout_fault("tf", "注入", 100, 20)
        s.capacity("go", "推进", "", None, 100)
        self.assertTrue(s.cverify())
        stats = json.loads(s.creplay(s.clog(100)))
        self.assertEqual((stats["在线"], stats["挂起"], stats["排队"]), (0, 2, 0))


class TimeoutFaultConfigTest(unittest.TestCase):
    def test_load_and_rollback_keep_trigger(self):
        _auth, s = make()
        s.timeout_fault("tf", "注入", 500, 0)
        doc = json.loads(s.export_config())
        doc["会话"]["空闲毫秒"] = 200000
        s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(s._timeout_at, 500)
        s.rollback_config()
        self.assertEqual(s._timeout_at, 500)

    def test_failed_load_keeps_trigger(self):
        _auth, s = make()
        s.timeout_fault("tf", "注入", 500, 0)
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 0
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(s._timeout_at, 500)

    def test_independent_from_pool_fault(self):
        _auth, s = make()
        s.pool_fault("pf", "注入", "default", 1000, 0)
        s.timeout_fault("tf", "注入", 100, 0)
        s.capacity("go", "推进", "", None, 100)
        # 超时演练触发不影响池耗尽演练。
        self.assertEqual(s._pool_fault, {"default": 1000})
        self.assertTrue(s.verify_audit())


if __name__ == "__main__":
    unittest.main()
