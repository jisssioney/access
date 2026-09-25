import json
import unittest

from access import (
    AuthError,
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
    StateError,
)


def make(users=("alice", "bob", "carol", "dave"), total=8, per=8,
         pool=("10.0.0.0/28", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


class FaultParamTest(unittest.TestCase):
    def test_inject_bytes(self):
        _auth, s = make()
        out = s.fault("alice", "注入", 500, 10)
        self.assertEqual(out, wire({"状态": "故障", "时刻": 10, "截至": 510}))
        self.assertEqual(list(json.loads(out)), ["状态", "时刻", "截至"])
        doc = json.loads(out)
        self.assertIs(type(doc["状态"]), str)
        self.assertIs(type(doc["时刻"]), int)
        self.assertIs(type(doc["截至"]), int)
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(s._faults, {"alice": 510})

    def test_recover_bytes(self):
        _auth, s = make()
        out = s.fault("bob", "恢复", None, 10)
        self.assertEqual(out, wire({"状态": "正常", "时刻": 10, "截至": 0}))
        self.assertEqual(s._faults, {})

    def test_key_validation(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k", 1.5):
            with self.assertRaises(TypeError):
                s.fault(bad, "注入", 1, 0)
        for bad in ("", "a\0b"):
            with self.assertRaises(ValueError):
                s.fault(bad, "注入", 1, 0)

    def test_op_validation(self):
        _auth, s = make()
        for bad in (True, 1, None, [], 1.5):
            with self.assertRaises(TypeError):
                s.fault("k" + str(type(bad)), bad, 1, 0)
        for i, bad in enumerate(("建立", "故障", "恢复 ", "")):
            with self.assertRaises(ValueError):
                s.fault(f"badop{i}", bad, 1, 0)

    def test_ms_validation(self):
        _auth, s = make()
        # 注入：ms 为非 bool 正 int。
        for i, bad in enumerate((True, False, 1.5, "1", None)):
            with self.assertRaises(TypeError):
                s.fault(f"t{i}", "注入", bad, 0)
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                s.fault(f"v{bad}", "注入", bad, 0)
        # 恢复：ms 必须为 None（非 None 一律 ValueError，含 bool/int）。
        for i, bad in enumerate((1, 0, True, False, 1.5)):
            with self.assertRaises(ValueError):
                s.fault(f"r{i}", "恢复", bad, 0)

    def test_now_ms_validation(self):
        _auth, s = make()
        for i, bad in enumerate((True, False, 1.5, "1", None)):
            with self.assertRaises(TypeError):
                s.fault(f"n{i}", "注入", 1, bad)
        with self.assertRaises(ValueError):
            s.fault("nneg", "注入", 1, -1)

    def test_replay_and_different_params(self):
        _auth, s = make()
        first = s.fault("alice", "注入", 500, 10)
        # 同参重放逐字节一致、无副作用。
        self.assertEqual(s.fault("alice", "注入", 500, 10), first)
        for params in (("注入", 501, 10), ("注入", 500, 11),
                       ("恢复", None, 10), ("恢复", None, 11)):
            with self.assertRaises(ValueError):
                s.fault("alice", *params)
        # 恢复首果亦永久缓存。
        rec = s.fault("bob", "恢复", None, 3)
        self.assertEqual(s.fault("bob", "恢复", None, 3), rec)
        with self.assertRaises(ValueError):
            s.fault("bob", "注入", 1, 3)

    def test_param_error_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.fault("z", "注入", 0, 0)
        # 异参（即便改为合法值）仍为重放冲突 ValueError。
        with self.assertRaises(ValueError):
            s.fault("z", "注入", 1, 0)

    def test_inject_and_recover_clear_backoff(self):
        _auth, s = make()
        s.fault("alice", "注入", 5000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(s._backoff["alice"], [1, 100])
        # 无故障用户的恢复仅清其退避（此时本无条目）并返回正常，不影响他人。
        self.assertEqual(json.loads(s.fault("bob", "恢复", None, 0))["状态"], "正常")
        self.assertIn("alice", s._backoff)

    def test_cache_domain_separate(self):
        _auth, s = make()
        out_fault = s.fault("same", "恢复", None, 0)
        out_do = s.do("same", "建立", "s1", ("alice", "pw"), 0)
        out_cap = s.capacity("same", "申请", "s2", ("bob", "pw", 10), 0)
        self.assertEqual(json.loads(out_fault)["状态"], "正常")
        self.assertIn("状态", out_do)
        self.assertEqual(json.loads(out_cap)["结果"], "在线")


class BackoffSequenceTest(unittest.TestCase):
    def _probe(self, s, key, sid, t):
        with self.assertRaises(BackendError) as ctx:
            s.do(key, "建立", sid, ("alice", "pw"), t)
        return ctx.exception.args[0]

    def test_delays_100_200_400_800_cap_1600(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        self.assertEqual(self._probe(s, "d1", "s1", 0), 100)
        self.assertEqual(s._backoff["alice"], [1, 100])
        self.assertEqual(self._probe(s, "d2", "s2", 100), 300)
        self.assertEqual(s._backoff["alice"], [2, 300])
        self.assertEqual(self._probe(s, "d3", "s3", 300), 700)
        self.assertEqual(s._backoff["alice"], [3, 700])
        self.assertEqual(self._probe(s, "d4", "s4", 700), 1500)
        self.assertEqual(s._backoff["alice"], [4, 1500])
        # 100*2**4=1600 封顶。
        self.assertEqual(self._probe(s, "d5", "s5", 1500), 3100)
        self.assertEqual(s._backoff["alice"], [5, 3100])
        self.assertEqual(self._probe(s, "d6", "s6", 3100), 4700)
        self.assertEqual(s._backoff["alice"], [6, 4700])
        # 退避窗口内：n 不变、retry_at 沿用。
        self.assertEqual(self._probe(s, "d7", "s7", 3150), 4700)
        self.assertEqual(s._backoff["alice"], [6, 4700])

    def test_until_and_retry_both_arrive_inclusive(self):
        _auth, s = make()
        # 截至 50：首探 t=0 得 r=100；t=50 时截至已到但 r 未到，仍拒且 n 不变；
        # t=100 两者均到（含同刻）才认证。
        s.fault("alice", "注入", 50, 0)
        self.assertEqual(self._probe(s, "d1", "s1", 0), 100)
        self.assertEqual(self._probe(s, "d2", "s2", 50), 100)
        self.assertEqual(s._backoff["alice"], [1, 100])
        out = s.do("d3", "建立", "s3", ("alice", "pw"), 100)
        self.assertEqual(json.loads(out)["状态"], "在线")
        self.assertEqual(s._backoff, {})
        self.assertEqual(s._faults, {})

    def test_until_arrived_before_first_probe(self):
        _auth, s = make()
        # 首次探测时截至已过（含同刻）、retry_at 视同 0：直接放行，不产生退避。
        s.fault("alice", "注入", 100, 0)
        out = s.do("d1", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(json.loads(out)["状态"], "在线")
        self.assertEqual(s._backoff, {})
        self.assertEqual(s._faults, {})

    def test_retry_at_is_call_arg(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 500)
        with self.assertRaises(BackendError) as ctx:
            s.do("d1", "建立", "s1", ("alice", "pw"), 500)
        self.assertEqual(ctx.exception.args, (600,))

    def test_backoff_per_user_independent(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        # bob 健康：照常建立。
        out = s.do("d2", "建立", "s2", ("bob", "pw"), 0)
        self.assertEqual(json.loads(out)["状态"], "在线")
        self.assertNotIn("bob", s._backoff)

    def test_backend_error_cached_and_replay_no_increment(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(BackendError) as first:
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        # 同参重放：同样的 BackendError(100)，退避不重复累加。
        for _ in range(3):
            with self.assertRaises(BackendError) as again:
                s.do("d1", "建立", "s1", ("alice", "pw"), 0)
            self.assertEqual(again.exception.args, first.exception.args)
        self.assertEqual(s._backoff["alice"], [1, 100])
        # 异参 key 重放抛 ValueError。
        with self.assertRaises(ValueError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 1)


class GateOrderingTest(unittest.TestCase):
    def test_establish_backend_precedes_auth_and_unknown_user(self):
        _auth, s = make()
        # 认证器中不存在的用户亦可被注入；故障期间 BackendError 先于认证。
        s.fault("ghost", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("ghost", "wrong"), 0)
        # 窗口过后才由认证器抛未知用户 KeyError。
        with self.assertRaises(KeyError):
            s.do("d2", "建立", "s2", ("ghost", "wrong"), 100001)

    def test_establish_backend_precedes_no_pool_state(self):
        # 零池模式：缺 default 的 StateError 也让位于 BackendError。
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 4, 100000, lease_ms=100000)
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)

    def test_migrate_locates_by_sid_backend_first(self):
        _auth, s = make()
        s.add_pool("other", ("10.1.0.0/28", (), ()))
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("alice", "注入", 100000, 0)
        # 故障先于认证：错口令也只抛 BackendError。
        with self.assertRaises(BackendError):
            s.do("m1", "迁移", "s1", ("other", "wrong"), 0)
        # 故障先于同池/目标池状态错误（迁回 default）。
        with self.assertRaises(BackendError):
            s.do("m2", "迁移", "s1", ("default", "pw"), 0)

    def test_migrate_unknown_sid_keyerror_no_backoff(self):
        _auth, s = make()
        s.add_pool("other", ("10.1.0.0/28", (), ()))
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "ghost", ("other", "pw"), 0)
        # 未知 sid 不定位到任何用户，退避表无新增。
        self.assertEqual(s._backoff, {})

    def test_migrate_unknown_sid_precedes_no_pool(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 4, 100000, lease_ms=100000)
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "ghost", ("other", "pw"), 0)

    def test_migrate_healthy_keeps_old_order(self):
        _auth, s = make()
        s.add_pool("other", ("10.1.0.0/28", (), ()))
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        # 健康用户：目标池未知仍为 KeyError（认证前）。
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "s1", ("nope", "pw"), 0)
        # 同池 StateError。
        with self.assertRaises(StateError):
            s.do("m2", "迁移", "s1", ("default", "pw"), 0)
        # 错口令 AuthError。
        with self.assertRaises(AuthError):
            s.do("m3", "迁移", "s1", ("other", "wrong"), 0)

    def test_takeover_backend_precedes_dup_sid_and_state(self):
        _auth, s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.do("e2", "建立", "s2", ("bob", "pw"), 0)
        s.fault("alice", "注入", 100000, 0)
        # sid=s2 已存在本应 StateError，但旧会话用户故障，BackendError 在先；
        # 错口令同样不触认证。
        with self.assertRaises(BackendError):
            s.do("t1", "接管", "s2", ("s1", "wrong"), 0)
        # 旧会话已下线的 StateError 同样让位于 BackendError（只读定位不看状态）。
        s.do("o1", "下线", "s1", None, 1)
        with self.assertRaises(BackendError):
            s.do("t2", "接管", "s3", ("s1", "pw"), 1)

    def test_takeover_unknown_old_keyerror_no_backoff(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(KeyError):
            s.do("t1", "接管", "s9", ("ghost", "pw"), 0)
        self.assertEqual(s._backoff, {})

    def test_takeover_healthy_keeps_old_order(self):
        _auth, s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(AuthError):
            s.do("t1", "接管", "s2", ("s1", "wrong"), 0)
        out = s.do("t2", "接管", "s3", ("s1", "pw"), 1)
        self.assertEqual(json.loads(out)["状态"], "在线")


class CapacityGateTest(unittest.TestCase):
    def test_apply_backend_error_no_event_no_queue(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.capacity("c1", "申请", "s1", ("alice", "pw", 100), 0)
        # 同参重放。
        with self.assertRaises(BackendError):
            s.capacity("c1", "申请", "s1", ("alice", "pw", 100), 0)
        self.assertEqual(s._queue_order, [])
        self.assertEqual(json.loads(s.capacity_events(0, 100))["事件"], [])
        self.assertEqual(s._backoff["alice"], [1, 100])

    def test_apply_unknown_faulted_user_then_keyerror_event(self):
        _auth, s = make()
        s.fault("ghost", "注入", 100, 0)
        with self.assertRaises(BackendError):
            s.capacity("c1", "申请", "s1", ("ghost", "pw", 100), 0)
        # 窗口过后走认证：未知用户 KeyError，并照常记“未知”事件。
        with self.assertRaises(KeyError):
            s.capacity("c2", "申请", "s1", ("ghost", "pw", 100), 100)
        results = [e["结果"]
                   for e in json.loads(s.capacity_events(0, 100))["事件"]]
        self.assertEqual(results, ["未知"])

    def test_cancel_and_advance_not_gated(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        # 推进不查后端。
        out = s.capacity("v1", "推进", "", None, 0)
        self.assertEqual(json.loads(out),
                         {"时刻": 0, "在线": 0, "排队": 0, "变更": []})
        # 取消不查后端：未知 sid 直接 KeyError。
        with self.assertRaises(KeyError):
            s.capacity("x1", "取消", "nope", None, 0)

    def test_healthy_apply_during_other_outage(self):
        _auth, s = make()
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.capacity("c1", "申请", "s1", ("alice", "pw", 100), 0)
        out = s.capacity("c2", "申请", "s2", ("bob", "pw", 100), 0)
        self.assertEqual(json.loads(out)["结果"], "在线")


class IsolationTest(unittest.TestCase):
    def test_backend_failure_does_not_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("alice", "注入", 100000, 0)
        # t=100 已过空闲期限；BackendError 不老化，s1 仍持址在线。
        with self.assertRaises(BackendError):
            s.do("d2", "建立", "s2", ("alice", "pw"), 100)
        session = s._sessions["s1"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])

    def test_authenticator_untouched_during_outage(self):
        auth, s = make()
        s.fault("alice", "注入", 1000, 0)
        # 故障期错口令不触认证：连续尝试均为 BackendError。
        for key in ("d1", "d2", "d3"):
            with self.assertRaises(BackendError):
                s.do(key, "建立", key, ("alice", "wrong"), 0)
        # 窗口过后第一次错口令才 denied（失败计数恰为 1，未锁定）。
        with self.assertRaises(AuthError):
            s.do("d4", "建立", "s4", ("alice", "wrong"), 1000)
        # 正确口令立即成功（认证失败计数已清零）。
        out = s.do("d5", "建立", "s5", ("alice", "pw"), 1000)
        self.assertEqual(json.loads(out)["状态"], "在线")

    def test_sessions_leases_queue_unchanged(self):
        _auth, s = make()
        s.do("e1", "建立", "s1", ("bob", "pw"), 0)
        leased_before = dict(s._pools["default"].leases)
        s.fault("alice", "注入", 100000, 0)
        for key in ("d1", "d2"):
            with self.assertRaises(BackendError):
                s.do(key, "建立", key, ("alice", "pw"), 0)
        self.assertEqual(s._pools["default"].leases, leased_before)
        self.assertEqual(sorted(s._sessions), ["s1"])
        self.assertEqual(s._queue_order, [])

    def test_backend_error_not_audited(self):
        _auth, s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("alice", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("t1", "接管", "s2", ("s1", "pw"), 0)
        # 防篡改链与接管审计均无 BackendError 项，链仍可校验。
        chain = json.loads(s.audit(0, 100))["事件"]
        self.assertEqual([e["结果"] for e in chain], ["成功"])
        self.assertTrue(s.verify_audit())
        self.assertEqual(json.loads(s.takeover_audit(0, 100))["事件"], [])
        # fault 本身不入任何审计。
        s.fault("bob", "恢复", None, 0)
        self.assertEqual(len(json.loads(s.audit(0, 100))["事件"]), 1)
        self.assertEqual(json.loads(s.capacity_events(0, 100))["事件"], [])

    def test_locating_keyerror_still_chained(self):
        _auth, s = make()
        s.add_pool("other", ("10.1.0.0/28", (), ()))
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "ghost", ("other", "pw"), 0)
        chain = json.loads(s.audit(0, 100))["事件"]
        self.assertEqual([e["结果"] for e in chain], ["KeyError"])
        self.assertTrue(s.verify_audit())
        # 同参重放沿用首次结果入链并指认原序号。
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "ghost", ("other", "pw"), 0)
        chain = json.loads(s.audit(0, 100))["事件"]
        self.assertEqual([e["结果"] for e in chain], ["KeyError", "KeyError"])
        self.assertEqual([e["原序号"] for e in chain], [0, 1])

    def test_renew_offline_meter_not_gated(self):
        auth, s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("alice", "注入", 100000, 0)
        # 续租与下线不查后端。
        self.assertIn("租期", s.do("r1", "续租", "s1", None, 5))
        self.assertEqual(json.loads(s.do("o1", "下线", "s1", None, 6))["状态"],
                         "下线")
        # pool_stats 等查询亦不受影响。
        self.assertEqual(json.loads(s.pool_stats(7))["时刻"], 7)

    def test_recovery_then_replay_byte_identical(self):
        _auth, s = make()
        out = s.fault("alice", "注入", 100, 0)
        self.assertEqual(s.fault("alice", "注入", 100, 0), out)
        # 故障窗口随成功探测结束后，同参 fault 重放仍逐字节返回首果（仅缓存）。
        s.do("d1", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(s.fault("alice", "注入", 100, 0), out)


if __name__ == "__main__":
    unittest.main()
