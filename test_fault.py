import json
import unittest

from access import (
    Authenticator,
    BackendError,
    Sessions,
    StateError,
)


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


class FaultParamTest(unittest.TestCase):
    def test_types_and_ranges(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.fault(bad, "注入", 1, 0)
        with self.assertRaises(ValueError):
            s.fault("", "注入", 1, 0)
        for i, bad in enumerate((True, 1, None, [])):
            with self.assertRaises(TypeError):
                s.fault(f"op{i}", bad, 1, 0)
        for bad in ("建立", "申请", "", "inject"):
            with self.assertRaises(ValueError):
                s.fault("opv" + bad, bad, 1, 0)
        for i, bad in enumerate((True, 1.5, "1")):
            with self.assertRaises(TypeError):
                s.fault(f"ms{i}", "注入", bad, 0)
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                s.fault("msv" + str(bad), "注入", bad, 0)
        with self.assertRaises(ValueError):
            s.fault("r1", "恢复", 5, 0)
        with self.assertRaises(ValueError):
            s.fault("r2", "恢复", True, 0)
        for i, bad in enumerate((True, 1.5, -1, None)):
            with self.assertRaises((TypeError, ValueError)):
                s.fault(f"n{i}", "注入", 1, bad)

    def test_output_shape(self):
        _auth, s = make()
        out = s.fault("f1", "注入", 500, 10)
        self.assertEqual(out, wire({"状态": "故障", "时刻": 10, "截至": 510}))
        self.assertEqual(list(json.loads(out)), ["状态", "时刻", "截至"])
        out = s.fault("f2", "恢复", None, 20)
        self.assertEqual(out, wire({"状态": "正常", "时刻": 20, "截至": 0}))

    def test_replay_cache(self):
        _auth, s = make()
        out = s.fault("f1", "注入", 500, 10)
        self.assertEqual(s.fault("f1", "注入", 500, 10), out)
        with self.assertRaises(ValueError):
            s.fault("f1", "注入", 500, 11)
        with self.assertRaises(ValueError):
            s.fault("f1", "注入", 501, 10)
        with self.assertRaises(ValueError):
            s.fault("f1", "恢复", None, 10)

    def test_param_error_is_cached(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault("z", "注入", 0, 0)
        with self.assertRaises(ValueError):
            s.fault("z", "注入", 0, 0)
        with self.assertRaises(ValueError):
            s.fault("z", "注入", 1, 0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("dk", "建立", "s1", ("alice", "pw"), 0)
        out = s.fault("dk", "注入", 100, 0)
        self.assertEqual(json.loads(out)["状态"], "故障")

    def test_fault_not_audited(self):
        _auth, s = make()
        s.fault("f1", "注入", 1000, 0)
        s.fault("f2", "恢复", None, 10)
        self.assertEqual(len(s._chain_events), 0)
        self.assertEqual(len(s._audit_events), 0)
        self.assertEqual(len(s._capacity_events), 0)


class BackoffTest(unittest.TestCase):
    def test_backoff_progression_and_cap(self):
        _auth, s = make()
        s.fault("fi", "注入", 100000, 0)
        now = 0
        deltas = []
        for i in range(7):
            with self.assertRaises(BackendError) as ctx:
                s.do(f"b{i}", "建立", "s1", ("alice", "pw"), now)
            deltas.append(ctx.exception.args[0] - now)
            now = ctx.exception.args[0]
        self.assertEqual(deltas, [100, 200, 400, 800, 1600, 1600, 1600])

    def test_retry_at_not_reached_keeps_n(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError) as ctx:
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(ctx.exception.args[0], 100)
        with self.assertRaises(BackendError) as ctx:
            s.do("d2", "建立", "s1", ("alice", "pw"), 50)
        self.assertEqual(ctx.exception.args[0], 100)
        self.assertEqual(s._backoff["alice"], (1, 100))

    def test_backoff_outlives_fault_until_retry_at(self):
        _auth, s = make()
        s.fault("fi", "注入", 50, 0)
        with self.assertRaises(BackendError) as ctx:
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(ctx.exception.args[0], 100)
        # 截至 50 已过但 retry_at=100 未到：仍退避且 n 不变。
        with self.assertRaises(BackendError) as ctx:
            s.do("d2", "建立", "s1", ("alice", "pw"), 75)
        self.assertEqual(ctx.exception.args[0], 100)
        self.assertEqual(s._backoff["alice"], (1, 100))
        # 截至与 retry_at 均到：认证并清退避。
        out = s.do("d3", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(json.loads(out)["状态"], "在线")
        self.assertNotIn("alice", s._backoff)

    def test_per_user_backoff(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("p1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(BackendError) as ctx:
            s.do("p2", "建立", "s2", ("bob", "pw"), 50)
        self.assertEqual(ctx.exception.args[0], 150)
        self.assertEqual(s._backoff["alice"], (1, 100))
        self.assertEqual(s._backoff["bob"], (1, 150))

    def test_inject_and_recover_clear_backoff(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("x1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi2", "注入", 500, 100)
        self.assertEqual(s._backoff, {})
        with self.assertRaises(BackendError) as ctx:
            s.do("x2", "建立", "s1", ("alice", "pw"), 200)
        self.assertEqual(ctx.exception.args[0], 300)
        s.fault("fr", "恢复", None, 300)
        self.assertEqual(s._backoff, {})
        out = s.do("x3", "建立", "s1", ("alice", "pw"), 300)
        self.assertEqual(json.loads(out)["状态"], "在线")

    def test_failure_side_effects(self):
        auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 10)
        before = {u: list(r) for u, r in auth._users.items()}
        with self.assertRaises(BackendError):
            s.do("e2", "建立", "s2", ("bob", "pw"), 100)
        self.assertEqual({u: list(r) for u, r in auth._users.items()}, before)
        # 不老化：s1 期限 50 已过但仍在线；不建会话、不入链、不记事件。
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertEqual(len(s._sessions), 1)
        n_chain = len(s._chain_events)
        with self.assertRaises(BackendError):
            s.do("e3", "建立", "s3", ("carol", "pw"), 100)
        self.assertEqual(len(s._chain_events), n_chain)
        self.assertEqual(len(s._capacity_events), 0)

    def test_backend_error_cached(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError) as ctx:
            s.do("r1", "建立", "s1", ("alice", "pw"), 0)
        first = ctx.exception.args[0]
        with self.assertRaises(BackendError) as ctx:
            s.do("r1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(ctx.exception.args[0], first)
        self.assertEqual(s._backoff["alice"], (1, 100))
        with self.assertRaises(ValueError):
            s.do("r1", "建立", "s1", ("alice", "pw"), 1)


class DoBackendCheckTest(unittest.TestCase):
    def test_renew_offline_unaffected(self):
        _auth, s = make()
        s.do("a1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        out = s.do("a2", "续租", "s1", None, 10)
        self.assertEqual(json.loads(out)["状态"], "在线")
        out = s.do("a3", "下线", "s1", None, 20)
        self.assertEqual(json.loads(out)["状态"], "下线")

    def test_establish_backend_error_precedes_state_error(self):
        _auth, s = make()
        s.do("b0", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("b1", "建立", "s1", ("alice", "pw"), 10)
        s.fault("fr", "恢复", None, 20)
        with self.assertRaises(StateError):
            s.do("b2", "建立", "s1", ("alice", "pw"), 30)

    def test_migrate_unknown_sid_keyerror_no_backoff(self):
        _auth, s = make(idle_ms=50)
        s.do("m0", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 10)
        n_chain = len(s._chain_events)
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "nosuch", ("pool2", "pw"), 100)
        self.assertEqual(s._backoff, {})
        self.assertEqual(len(s._chain_events), n_chain + 1)
        # 定位在老化前：s1 期限 50 已过但未被老化。
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        with self.assertRaises(KeyError):
            s.do("m1", "迁移", "nosuch", ("pool2", "pw"), 100)

    def test_migrate_backend_error_precedes_target_pool_error(self):
        _auth, s = make()
        s.add_pool("pool2", ("10.1.0.0/24", (), ()))
        s.do("m0", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError) as ctx:
            s.do("m1", "迁移", "s1", ("nosuchpool", "pw"), 10)
        self.assertEqual(ctx.exception.args[0], 110)
        s.fault("fr", "恢复", None, 20)
        with self.assertRaises(KeyError):
            s.do("m2", "迁移", "s1", ("nosuchpool", "pw"), 30)
        out = s.do("m3", "迁移", "s1", ("pool2", "pw"), 40)
        self.assertEqual(json.loads(out)["目标池"], "pool2")

    def test_takeover_unknown_old_keyerror_no_backoff(self):
        _auth, s = make()
        s.do("t0", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(KeyError):
            s.do("t1", "接管", "s2", ("nosuch", "pw"), 10)
        self.assertEqual(s._backoff, {})

    def test_takeover_backend_error_precedes_new_sid_error(self):
        _auth, s = make()
        s.do("t0", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError) as ctx:
            s.do("t1", "接管", "s1", ("s1", "pw"), 10)
        self.assertEqual(ctx.exception.args[0], 110)
        s.fault("fr", "恢复", None, 20)
        with self.assertRaises(StateError):
            s.do("t2", "接管", "s1", ("s1", "pw"), 30)
        out = s.do("t3", "接管", "s2", ("s1", "pw"), 40)
        self.assertEqual(json.loads(out)["新会话"], "s2")


class CapacityBackendCheckTest(unittest.TestCase):
    def test_apply_backend_error(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError) as ctx:
            s.capacity("c1", "申请", "s1", ("alice", "pw", 500), 10)
        self.assertEqual(ctx.exception.args[0], 110)
        self.assertEqual(len(s._capacity_events), 0)
        self.assertEqual(len(s._capacity_queue), 0)
        self.assertEqual(len(s._sessions), 0)

    def test_apply_backend_error_cached(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.capacity("c1", "申请", "s1", ("alice", "pw", 500), 10)
        with self.assertRaises(BackendError) as ctx:
            s.capacity("c1", "申请", "s1", ("alice", "pw", 500), 10)
        self.assertEqual(ctx.exception.args[0], 110)
        self.assertEqual(s._backoff["alice"], (1, 110))
        with self.assertRaises(ValueError):
            s.capacity("c1", "申请", "s1", ("alice", "pw", 500), 11)

    def test_cancel_advance_unaffected(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        out = s.capacity("c1", "推进", "", None, 20)
        self.assertEqual(json.loads(out)["在线"], 0)
        with self.assertRaises(KeyError):
            s.capacity("c2", "取消", "s1", None, 20)

    def test_apply_after_recovery(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.capacity("c1", "申请", "s1", ("alice", "pw", 500), 10)
        s.fault("fr", "恢复", None, 20)
        out = s.capacity("c2", "申请", "s1", ("alice", "pw", 500), 30)
        self.assertEqual(json.loads(out)["结果"], "在线")

    def test_max_wait_error_precedes_backend_check(self):
        _auth, s = make()
        doc = json.loads(s.export_config())
        doc["容量"] = {"队列上限": 1024, "最大等待毫秒": 100}
        s.load_config(json.dumps(doc, ensure_ascii=False))
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(ValueError):
            s.capacity("w1", "申请", "s1", ("alice", "pw", 200), 10)
        self.assertEqual(s._backoff, {})


if __name__ == "__main__":
    unittest.main()
