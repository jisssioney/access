import json
import unittest

from access import (
    AuthError,
    Authenticator,
    ResourceError,
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


class PoolFaultParamTest(unittest.TestCase):
    def test_types_and_ranges(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.pool_fault(bad, "注入", "default", 1, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("", "注入", "default", 1, 0)
        for i, bad in enumerate((True, 1, None, [])):
            with self.assertRaises(TypeError):
                s.pool_fault(f"op{i}", bad, "default", 1, 0)
        for bad in ("建立", "", "inject"):
            with self.assertRaises(ValueError):
                s.pool_fault("ov" + bad, bad, "default", 1, 0)
        for i, bad in enumerate((True, 1, None, ())):
            with self.assertRaises(TypeError):
                s.pool_fault(f"pl{i}", "注入", bad, 1, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("pv", "注入", "", 1, 0)
        for i, bad in enumerate((True, 1.5, "1", None)):
            with self.assertRaises(TypeError):
                s.pool_fault(f"ms{i}", "注入", "default", bad, 0)
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                s.pool_fault("msv" + str(bad), "注入", "default", bad, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("r1", "恢复", "default", 5, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("r2", "恢复", "default", 0, 0)
        for i, bad in enumerate((True, 1.5, -1, None)):
            with self.assertRaises((TypeError, ValueError)):
                s.pool_fault(f"n{i}", "注入", "default", 1, bad)

    def test_error_order_type_value_unknown_pool(self):
        _auth, s = make()
        # 类型错先于值错。
        with self.assertRaises(TypeError):
            s.pool_fault("a", "怪op", "default", 1, 1.5)
        # 值错先于未知池错。
        with self.assertRaises(ValueError):
            s.pool_fault("b", "怪op", "nosuch", 1, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("c", "注入", "nosuch", 0, 0)
        # 全合规则未知池才 KeyError。
        with self.assertRaises(KeyError):
            s.pool_fault("d", "注入", "nosuch", 1, 0)
        with self.assertRaises(KeyError):
            s.pool_fault("e", "恢复", "nosuch", None, 0)

    def test_output_shape(self):
        _auth, s = make()
        out = s.pool_fault("f1", "注入", "default", 500, 10)
        self.assertEqual(
            out, wire({"池": "default", "状态": "耗尽", "时刻": 10, "截至": 510})
        )
        self.assertEqual(list(json.loads(out)), ["池", "状态", "时刻", "截至"])
        out = s.pool_fault("f2", "恢复", "default", None, 20)
        self.assertEqual(
            out, wire({"池": "default", "状态": "正常", "时刻": 20, "截至": 0})
        )

    def test_replay_cache(self):
        _auth, s = make()
        out = s.pool_fault("f1", "注入", "default", 500, 10)
        # 同参重放不改状态：把截至恢复后重放仍返回首次输出，故障态不动。
        s.pool_fault("g", "恢复", "default", None, 20)
        self.assertEqual(s.pool_fault("f1", "注入", "default", 500, 10), out)
        self.assertNotIn("default", s._pool_fault)
        with self.assertRaises(ValueError):
            s.pool_fault("f1", "注入", "default", 500, 11)
        with self.assertRaises(ValueError):
            s.pool_fault("f1", "注入", "default", 501, 10)
        with self.assertRaises(ValueError):
            s.pool_fault("f1", "注入", "pool2", 500, 10)
        with self.assertRaises(ValueError):
            s.pool_fault("f1", "恢复", "default", None, 10)

    def test_error_first_result_is_cached(self):
        _auth, s = make()
        with self.assertRaises(KeyError):
            s.pool_fault("z", "注入", "nosuch", 1, 0)
        with self.assertRaises(KeyError):
            s.pool_fault("z", "注入", "nosuch", 1, 0)
        # 异参复用即使首果为未知池仍 ValueError。
        with self.assertRaises(ValueError):
            s.pool_fault("z", "注入", "default", 1, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("p", "注入", "default", 0, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("p", "注入", "default", 0, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("p", "注入", "default", 1, 0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("dk", "建立", "s1", ("alice", "pw"), 0)
        out = s.pool_fault("dk", "注入", "default", 100, 0)
        self.assertEqual(json.loads(out)["状态"], "耗尽")
        # fault 域同样独立。
        out = s.fault("dk", "注入", 100, 0)
        self.assertEqual(json.loads(out)["状态"], "故障")

    def test_chain_origin_index_separate_across_domains(self):
        # 同名字符串 key 跨 do/pool_fault 两域时，原序号各自指认本域首次事件。
        _auth, s = make()
        s.do("k", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("k", "注入", "default", 100, 0)
        s.do("k", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("k", "注入", "default", 100, 0)
        events = json.loads(s.audit(limit=100))["事件"]
        self.assertEqual(
            [(e["操作"], e["结果"], e["原序号"]) for e in events],
            [
                ("建立", "成功", 0),
                ("池注入", "成功", 0),
                ("建立", "成功", 1),
                ("池注入", "重放", 2),
            ],
        )
        self.assertTrue(s.verify_audit())

    def test_override(self):
        _auth, s = make()
        s.pool_fault("o1", "注入", "default", 100, 0)
        self.assertEqual(s._pool_fault, {"default": 100})
        s.pool_fault("o2", "注入", "default", 50, 200)
        self.assertEqual(s._pool_fault, {"default": 250})
        s.pool_fault("o3", "恢复", "default", None, 300)
        self.assertEqual(s._pool_fault, {})

    def test_audited_first_and_replay_only(self):
        _auth, s = make()
        s.pool_fault("a1", "注入", "default", 100, 0)
        s.pool_fault("a1", "注入", "default", 100, 0)
        s.pool_fault("a2", "恢复", "default", None, 5)
        s.pool_fault("a2", "恢复", "default", None, 5)
        events = json.loads(s.audit(limit=1000))["事件"]
        self.assertEqual(
            [(e["操作"], e["会话"], e["结果"], e["原序号"]) for e in events],
            [
                ("池注入", "default", "成功", 0),
                ("池注入", "default", "重放", 1),
                ("池恢复", "default", "成功", 0),
                ("池恢复", "default", "重放", 3),
            ],
        )
        self.assertTrue(s.verify_audit())
        # 异常不记。
        with self.assertRaises(KeyError):
            s.pool_fault("a3", "注入", "nosuch", 1, 0)
        with self.assertRaises(ValueError):
            s.pool_fault("a4", "注入", "default", 0, 0)
        self.assertEqual(len(json.loads(s.audit(limit=1000))["事件"]), 4)
        # 与 do 共用现有防篡改链，但不混入接管审计。
        s.do("d0", "建立", "s9", ("alice", "pw"), 0)
        self.assertEqual(
            json.loads(s.audit(limit=1000))["事件"][-1]["操作"], "建立"
        )
        self.assertTrue(s.verify_audit())
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])


class PoolFaultEffectTest(unittest.TestCase):
    def test_establish_blocked_auth_precedes(self):
        _auth, s = make()
        s.pool_fault("fi", "注入", "default", 1000, 0)
        with self.assertRaises(ResourceError):
            s.do("e1", "建立", "s1", ("alice", "pw"), 10)
        # 认证在资源之前：错密仍 AuthError。
        with self.assertRaises(AuthError):
            s.do("e2", "建立", "s2", ("carol", "bad"), 10)
        # 无半分配。
        self.assertEqual(len(s._sessions), 0)

    def test_static_user_blocked_while_injected(self):
        _auth, s = make(pool=("10.0.0.0/24", (), (("alice", "10.0.0.5"),)))
        s.pool_fault("fi", "注入", "default", 100, 0)
        with self.assertRaises(ResourceError):
            s.do("e1", "建立", "s1", ("alice", "pw"), 10)
        # 到刻（含同刻）自动正常，静态用户取专属址。
        out = s.do("e2", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(json.loads(out)["地址"], "10.0.0.5")

    def test_renew_offline_migrate_out_unaffected(self):
        _auth, s = make()
        s.add_pool("pool2", ("10.1.0.0/24", (), ()))
        s.do("a1", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("fi", "注入", "default", 1000, 10)
        out = s.do("a2", "续租", "s1", None, 20)
        self.assertEqual(json.loads(out)["状态"], "在线")
        out = s.do("m1", "迁移", "s1", ("pool2", "pw"), 30)
        self.assertEqual(json.loads(out)["目标池"], "pool2")
        out = s.do("a3", "下线", "s1", None, 40)
        self.assertEqual(json.loads(out)["状态"], "下线")

    def test_migrate_in_blocked_no_half_swap(self):
        _auth, s = make()
        s.add_pool("pool2", ("10.1.0.0/24", (), ()))
        s.do("m0", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("fi", "注入", "pool2", 100, 0)
        with self.assertRaises(ResourceError):
            s.do("m1", "迁移", "s1", ("pool2", "pw"), 50)
        self.assertEqual(s._sessions["s1"]["pool"], "default")
        # 到刻同刻即可迁入。
        out = s.do("m2", "迁移", "s1", ("pool2", "pw"), 100)
        self.assertEqual(json.loads(out)["目标池"], "pool2")
        # default 未注入，建立不受影响。
        out = s.do("b1", "建立", "s2", ("bob", "pw"), 100)
        self.assertEqual(json.loads(out)["状态"], "在线")

    def test_lease_real_exhaustion_unchanged(self):
        # /32 仅一个可用动态址：无注入时真实耗尽仍为 ResourceError。
        _auth, s = make(pool=("10.0.0.0/32", (), ()))
        s.do("x1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(ResourceError):
            s.do("x2", "建立", "s2", ("bob", "pw"), 0)

    def test_takeover_without_address_blocked_after_aging(self):
        _auth, s = make(idle_ms=50, lease_ms=1000)
        s.do("t0", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("fi", "注入", "default", 1000, 0)
        with self.assertRaises(ResourceError):
            s.do("t1", "接管", "s2", ("s1", "pw"), 100)
        # 老化结果保留：旧会话挂起释址，未建新会话。
        self.assertEqual(s._sessions["s1"]["state"], "挂起")
        self.assertNotIn("s2", s._sessions)

    def test_takeover_with_address_unaffected(self):
        _auth, s = make(idle_ms=100000, lease_ms=100000)
        s.do("t0", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("fi", "注入", "default", 1000, 0)
        # 旧会话持址，新会话直接继承，无需从故障池取址。
        out = s.do("t1", "接管", "s2", ("s1", "pw"), 10)
        self.assertEqual(json.loads(out)["新会话"], "s2")


class PoolFaultCapacityTest(unittest.TestCase):
    def test_apply_queues_and_advance_skips(self):
        _auth, s = make(total=2, per=2)
        s.capacity("c0", "申请", "s0", ("alice", "pw", 1000), 0)
        s.pool_fault("fi", "注入", "default", 100, 0)
        out = s.capacity("c1", "申请", "q1", ("bob", "pw", 1000), 10)
        self.assertEqual(json.loads(out)["结果"], "排队")
        out = s.capacity("c2", "推进", "", None, 20)
        doc = json.loads(out)
        self.assertEqual((doc["在线"], doc["排队"], doc["变更"]), (1, 1, []))
        # 跳过项不产生超时/晋升事件。
        events = json.loads(s.capacity_events(after=0, limit=100))["事件"]
        self.assertEqual([e["结果"] for e in events], ["在线", "排队"])
        # 到刻推进晋升。
        out = s.capacity("c3", "推进", "", None, 100)
        doc = json.loads(out)
        self.assertEqual((doc["在线"], doc["排队"]), (2, 0))
        self.assertEqual(doc["变更"], [1])
        events = json.loads(s.capacity_events(after=0, limit=100))["事件"]
        self.assertEqual([e["结果"] for e in events], ["在线", "排队", "晋升"])

    def test_apply_queues_during_injection(self):
        _auth, s = make()
        s.pool_fault("fi", "注入", "default", 100, 0)
        # 申请在注入期排队（非队满），不建立、不半分配。
        out = s.capacity("c1", "申请", "s1", ("alice", "pw", 1000), 10)
        self.assertEqual(json.loads(out)["结果"], "排队")
        self.assertEqual(len(s._sessions), 0)
        self.assertEqual(len(s._capacity_queue), 1)
        # 恢复后推进晋升。
        s.pool_fault("fr", "恢复", "default", None, 20)
        out = s.capacity("c2", "推进", "", None, 30)
        doc = json.loads(out)
        self.assertEqual((doc["在线"], doc["排队"]), (1, 0))

    def test_queue_full_still_resource_error(self):
        _auth, s = make()
        doc = json.loads(s.export_config())
        doc["容量"] = {"队列上限": 1, "最大等待毫秒": 0}
        s.load_config(json.dumps(doc, ensure_ascii=False))
        s.pool_fault("fi", "注入", "default", 1000, 0)
        s.capacity("q0", "申请", "q1", ("alice", "pw", 1000), 0)
        # 注入致排队且队长已达上限：真实队满仍 ResourceError，不半分配。
        with self.assertRaises(ResourceError):
            s.capacity("q1", "申请", "q2", ("bob", "pw", 1000), 0)
        self.assertEqual(len(s._capacity_queue), 1)
        self.assertEqual(len(s._sessions), 0)

    def test_wait_limit_value_error_precedes(self):
        _auth, s = make()
        doc = json.loads(s.export_config())
        doc["容量"] = {"队列上限": 1024, "最大等待毫秒": 100}
        s.load_config(json.dumps(doc, ensure_ascii=False))
        s.pool_fault("fi", "注入", "default", 1000, 0)
        # 等待超最大等待：验参即 ValueError，先于资源，不入队。
        with self.assertRaises(ValueError):
            s.capacity("w1", "申请", "s1", ("alice", "pw", 200), 10)
        self.assertEqual(len(s._capacity_queue), 0)


class PoolFaultConfigTest(unittest.TestCase):
    def _drop_pool(self, s, pool_id):
        doc = json.loads(s.export_config())
        doc["地址池"] = [p for p in doc["地址池"] if p["标识"] != pool_id]
        return json.dumps(doc, ensure_ascii=False)

    def test_load_keeps_same_name_drops_deleted(self):
        _auth, s = make()
        s.add_pool("pool2", ("10.1.0.0/24", (), ()))
        s.pool_fault("g1", "注入", "default", 1000, 0)
        s.pool_fault("g2", "注入", "pool2", 1000, 0)
        s.load_config(self._drop_pool(s, "pool2"))
        self.assertEqual(s._pool_fault, {"default": 1000})
        # 回滚恢复 pool2，但已删池故障不复活。
        s.rollback_config()
        self.assertEqual(s._pool_fault, {"default": 1000})

    def test_failed_load_keeps_faults(self):
        _auth, s = make()
        s.pool_fault("g1", "注入", "default", 1000, 0)
        s.pool_fault("g9", "恢复", "default", None, 0)
        s.do("n1", "建立", "sx", ("alice", "pw"), 0)
        s.do("n2", "建立", "sy", ("bob", "pw"), 1)
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 1  # 现有 2 个非下线会话，承载失败
        before = dict(s._pool_fault)
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(dict(s._pool_fault), before)


if __name__ == "__main__":
    unittest.main()
