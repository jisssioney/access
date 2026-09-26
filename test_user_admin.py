import json
import unittest

from access import AuthError, Authenticator, Sessions, StateError


def make(pool=("10.0.0.0/28", ("10.0.0.9",), ())):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def chain(s):
    return [(e[3], e[4], e[5], e[6]) for e in s._chain_events]


class UserAdminValidationTest(unittest.TestCase):
    def test_key_validated_first_and_not_cached(self):
        s = make()
        for bad in (1, True, None):
            with self.assertRaises(TypeError):
                s.user_admin(bad, "停用", "alice", 0)
        with self.assertRaises(ValueError):
            s.user_admin("", "停用", "alice", 0)
        self.assertEqual(s._user_admin_cache, {})
        self.assertEqual(chain(s), [])

    def test_op_types(self):
        s = make()
        for i, bad in enumerate((1, True, None, ("停用",))):
            with self.assertRaises(TypeError):
                s.user_admin(f"k{i}", bad, "alice", 0)

    def test_user_types(self):
        s = make()
        for i, bad in enumerate((1, True, None, ("a",))):
            with self.assertRaises(TypeError):
                s.user_admin(f"k{i}", "停用", bad, 0)

    def test_now_ms_types(self):
        s = make()
        for i, bad in enumerate((True, 1.5, "0", None)):
            with self.assertRaises(TypeError):
                s.user_admin(f"k{i}", "停用", "alice", bad)

    def test_force_types(self):
        s = make()
        for i, bad in enumerate((1, 0, "true", None)):
            with self.assertRaises(TypeError):
                s.user_admin(f"k{i}", "停用", "alice", 0, bad)

    def test_type_errors_precede_value_errors(self):
        s = make()
        with self.assertRaises(TypeError):
            s.user_admin("k1", 1, "x", True)
        with self.assertRaises(TypeError):
            s.user_admin("k2", "停用", 1, True)

    def test_value_errors(self):
        s = make()
        with self.assertRaises(ValueError):
            s.user_admin("k1", "冻结", "alice", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k2", "停用", "", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k3", "停用", "a\0b", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k4", "停用", "alice", -1)
        # 启用限 force=False
        with self.assertRaises(ValueError):
            s.user_admin("k5", "启用", "alice", 0, True)
        self.assertEqual(chain(s), [])

    def test_unknown_user_keyerror(self):
        s = make()
        with self.assertRaises(KeyError):
            s.user_admin("k1", "停用", "ghost", 0)
        with self.assertRaises(KeyError):
            s.user_admin("k2", "启用", "ghost", 0)
        # 业务异常不审计
        self.assertEqual(chain(s), [])


class UserAdminSuccessTest(unittest.TestCase):
    def test_disable_json_shape_and_bytes(self):
        auth = Authenticator(3, 1000)
        auth.add("张三", "pw")
        s = Sessions(auth, 4, 2, 5000)
        out = s.user_admin("k", "停用", "张三", 42)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        self.assertIn("张三", out)
        self.assertEqual(
            out, '{"用户":"张三","状态":"停用","时刻":42,"下线":0,"取消":0}\n'
        )
        doc = json.loads(out)
        self.assertEqual(list(doc), ["用户", "状态", "时刻", "下线", "取消"])
        self.assertEqual(type(doc["用户"]), str)
        self.assertEqual(type(doc["状态"]), str)
        self.assertEqual(type(doc["时刻"]), int)
        self.assertEqual(type(doc["下线"]), int)
        self.assertEqual(type(doc["取消"]), int)

    def test_enable_json_shape(self):
        s = make()
        out = s.user_admin("k", "启用", "alice", 7)
        self.assertEqual(
            out, '{"用户":"alice","状态":"启用","时刻":7,"下线":0,"取消":0}\n'
        )

    def test_homomorphic_repeated_ops_counts_zero(self):
        s = make()
        for i, (op, force) in enumerate(
            (("停用", False), ("停用", True), ("启用", False),
             ("停用", False), ("启用", False))
        ):
            doc = json.loads(s.user_admin(f"k{i}", op, "bob", i, force))
            self.assertEqual(doc["下线"], 0)
            self.assertEqual(doc["取消"], 0)
            self.assertEqual(doc["状态"], op)

    def test_disable_marks_user_and_enable_restores(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        self.assertIn("alice", s._disabled_users)
        s.user_admin("e", "启用", "alice", 0)
        self.assertNotIn("alice", s._disabled_users)


class UserAdminStateErrorTest(unittest.TestCase):
    def test_active_session_blocks_without_force(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 100)
        # 状态不变：用户未停用，会话仍在线
        self.assertNotIn("alice", s._disabled_users)
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertIsNotNone(s._sessions["s1"]["ip"])
        # 其他用户操作不受影响
        self.assertEqual(
            json.loads(s.do("e2", "建立", "s2", ("bob", "pw"), 100))["状态"],
            "在线",
        )

    def test_suspended_session_blocks(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        # 老化后挂起（无址、非下线），仍算非下线会话
        s.pool_stats(90000)
        self.assertEqual(s._sessions["s1"]["state"], "挂起")
        with self.assertRaises(StateError):
            s.user_admin("d2", "停用", "alice", 90000)
        # force=True 可强制下线挂起会话
        doc = json.loads(s.user_admin("f", "停用", "alice", 90000, force=True))
        self.assertEqual(doc["下线"], 1)
        self.assertIsNone(s._sessions["s1"]["ip"])

    def test_queued_item_blocks_without_force(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 1, 1, 50000, pool=("10.0.0.0/28", (), ()), lease_ms=1000)
        s.do("e0", "建立", "occ", ("alice", "pw"), 0)
        self.assertEqual(
            json.loads(s.capacity("q", "申请", "q1", ("alice", "pw", 1000), 0))["结果"],
            "排队",
        )
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 0)
        self.assertEqual(s._queue_order, ["q1"])
        self.assertNotIn("alice", s._disabled_users)

    def test_offline_tombstone_does_not_block(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.do("o1", "下线", "s1", None, 10)
        doc = json.loads(s.user_admin("d", "停用", "alice", 20))
        self.assertEqual((doc["下线"], doc["取消"]), (0, 0))

    def test_stateerror_cached_replayed_not_audited(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 100)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 100)
        # 异参 ValueError
        with self.assertRaises(ValueError):
            s.user_admin("d", "停用", "alice", 101)
        # StateError 不审计（仅此前 do 建立成功一条）
        self.assertEqual([c[0] for c in chain(s)], ["建立"])
        # 会话仍在
        self.assertEqual(s._sessions["s1"]["state"], "在线")


class UserAdminForceTest(unittest.TestCase):
    def test_force_offlines_sessions_and_cancels_queue(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(auth, 1, 4, 50000, pool=("10.0.0.0/28", (), ()), lease_ms=100000)
        s.do("occ", "建立", "occ", ("alice", "pw"), 0)
        s.capacity("qa", "申请", "qa1", ("alice", "pw", 1000), 0)
        s.capacity("qb", "申请", "qb1", ("bob", "pw", 1000), 0)
        s.capacity("qa2", "申请", "qa2", ("alice", "pw", 1000), 0)
        events_before = json.loads(s.capacity_events())["事件"]
        out = s.user_admin("adm", "停用", "alice", 5, force=True)
        doc = json.loads(out)
        self.assertEqual(doc["状态"], "停用")
        self.assertEqual(doc["下线"], 1)
        self.assertEqual(doc["取消"], 2)
        # 会话下线、期限清零、租约释放
        self.assertEqual(s._sessions["occ"]["state"], "下线")
        self.assertEqual(s._sessions["occ"]["deadline"], 0)
        self.assertIsNone(s._sessions["occ"]["ip"])
        self.assertEqual(s._sessions["occ"]["lease"], 0)
        self.assertTrue(s._pools["default"].free)
        # 仅删 alice 的队项，bob 保留且入队序不乱
        self.assertEqual(s._queue_order, ["qb1"])
        self.assertNotIn("qa1", s._capacity_queue)
        self.assertNotIn("qa2", s._capacity_queue)
        self.assertIn("qb1", s._capacity_queue)
        # 无 capacity 事件
        self.assertEqual(
            json.loads(s.capacity_events())["事件"], events_before
        )
        self.assertIn("alice", s._disabled_users)

    def test_force_no_active_items_counts_zero(self):
        s = make()
        doc = json.loads(s.user_admin("d", "停用", "alice", 0, force=True))
        self.assertEqual((doc["下线"], doc["取消"]), (0, 0))

    def test_force_keeps_other_users_sessions(self):
        s = make()
        s.do("a", "建立", "as", ("alice", "pw"), 0)
        s.do("b", "建立", "bs", ("bob", "pw"), 0)
        s.user_admin("d", "停用", "alice", 0, force=True)
        self.assertEqual(s._sessions["as"]["state"], "下线")
        self.assertEqual(s._sessions["bs"]["state"], "在线")


class UserAdminCacheTest(unittest.TestCase):
    def test_param_errors_cached_and_replayed(self):
        s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.user_admin("k", "启用", "alice", 0, True)
        with self.assertRaises(ValueError):
            s.user_admin("k", "启用", "alice", 1, True)
        self.assertIn("k", s._user_admin_cache)
        self.assertEqual(chain(s), [])

    def test_keyerror_cached_and_replayed(self):
        s = make()
        for _ in range(2):
            with self.assertRaises(KeyError):
                s.user_admin("k", "停用", "ghost", 5)
        with self.assertRaises(ValueError):
            s.user_admin("k", "停用", "ghost", 6)

    def test_success_replay_returns_same_bytes_without_effect(self):
        s = make()
        s.do("a", "建立", "as", ("alice", "pw"), 0)
        first = s.user_admin("k", "停用", "alice", 10, force=True)
        self.assertEqual(json.loads(first)["下线"], 1)
        # 启用并新建会话后，旧 key 同参重放返回缓存结果且不再下线
        s.user_admin("e", "启用", "alice", 20)
        s.do("a2", "建立", "as2", ("alice", "pw"), 20)
        replay = s.user_admin("k", "停用", "alice", 10, force=True)
        self.assertEqual(replay, first)
        self.assertEqual(json.loads(replay)["下线"], 1)
        self.assertEqual(s._sessions["as2"]["state"], "在线")
        self.assertNotIn("alice", s._disabled_users)

    def test_different_params_value_error(self):
        s = make()
        s.user_admin("k", "停用", "alice", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k", "启用", "alice", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k", "停用", "bob", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k", "停用", "alice", 1)
        with self.assertRaises(ValueError):
            s.user_admin("k", "停用", "alice", 0, True)

    def test_cache_domain_isolated(self):
        s = make()
        s.user_admin("same", "停用", "alice", 0)
        # 与 do 等同名 key 不冲突
        out = s.do("same", "建立", "s1", ("bob", "pw"), 0)
        self.assertEqual(json.loads(out)["状态"], "在线")


class UserAdminAuditTest(unittest.TestCase):
    def test_success_and_replay_audited(self):
        s = make()
        s.user_admin("L", "停用", "bob", 100, force=True)
        s.user_admin("L", "停用", "bob", 100, force=True)
        self.assertEqual(
            chain(s),
            [("用户停用", "bob", "成功", 0),
             ("用户停用", "bob", "重放", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_enable_audit_op_name(self):
        s = make()
        s.user_admin("d", "停用", "bob", 0)
        s.user_admin("e", "启用", "bob", 1)
        self.assertEqual(
            [c[0] for c in chain(s)], ["用户停用", "用户启用"]
        )
        self.assertTrue(s.verify_audit())

    def test_business_errors_not_audited(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 0)
        with self.assertRaises(KeyError):
            s.user_admin("u", "停用", "ghost", 0)
        # 仅 do 建立一条链事件
        self.assertEqual([c[0] for c in chain(s)], ["建立"])


class DisabledGateTest(unittest.TestCase):
    def test_do_establish_gate_before_auth(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        with self.assertRaises(AuthError):
            s.do("g", "建立", "s9", ("alice", "wrong"), 100)
        # 认证失败计数不变（先于认证拒绝）
        self.assertEqual(s._auth._users["alice"][1], 0)

    def test_do_migrate_and_takeover_gate(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.user_admin("d", "停用", "alice", 100, force=True)
        # 迁移：定位用户后先于状态/池错误拒绝
        with self.assertRaises(AuthError):
            s.do("g1", "迁移", "s1", ("default", "x"), 200)
        # 接管：旧会话已下线，停用拒绝先于 StateError
        with self.assertRaises(AuthError):
            s.do("g2", "接管", "s8", ("s1", "x"), 200)
        # 未知 sid/old 仍为 KeyError（定位先于停用判定）
        with self.assertRaises(KeyError):
            s.do("g3", "迁移", "zzz", ("default", "x"), 200)
        with self.assertRaises(KeyError):
            s.do("g4", "接管", "s8", ("zzz", "x"), 200)

    def test_capacity_apply_gate_no_event(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        with self.assertRaises(AuthError):
            s.capacity("g", "申请", "s9", ("alice", "x", 10), 0)
        self.assertEqual(json.loads(s.capacity_events())["事件"], [])
        self.assertNotIn("s9", s._capacity_queue)

    def test_batch_online_gate_non_atomic_and_atomic(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        out = json.loads(
            s.batch_online("b1", (("s1", "alice", "x"), ("s2", "bob", "pw")), 0)
        )
        self.assertEqual(out["结果"], "部分")
        self.assertEqual(
            {i["会话"]: i["结果"] for i in out["项目"]},
            {"s1": "AuthError", "s2": "上线"},
        )
        # 原子批：停用项失败整批回滚
        out2 = json.loads(
            s.batch_online(
                "b2", (("s3", "alice", "x"), ("s4", "bob", "pw")), 0, atomic=True
            )
        )
        self.assertEqual(out2["结果"], "回滚")
        self.assertNotIn("s3", s._sessions)
        self.assertNotIn("s4", s._sessions)
        # 认证失败计数不变
        self.assertEqual(s._auth._users["alice"][1], 0)

    def test_credential_change_gate(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        with self.assertRaises(AuthError):
            s.credential_change("c", "alice", "pw", "new", 0)
        with self.assertRaises(AuthError):
            s.credential_change("c", "alice", "pw", "new", 0)
        # 失败计数不变、密码未换
        self.assertEqual(s._auth._users["alice"][1], 0)
        self.assertEqual(s._auth.authenticate("alice", "pw", 0)[1], "ok")

    def test_gate_before_backend_fault(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        s.fault("f", "注入", 10000, 0)
        with self.assertRaises(AuthError):
            s.do("g", "建立", "s9", ("alice", "x"), 100)
        # 未触发后端退避
        self.assertNotIn("alice", s._backoff)
        self.assertEqual(
            json.loads(s.fault_stats(100))["失败"],
            [{"类型": "故障", "次数": 0}, {"类型": "退避", "次数": 0}],
        )

    def test_gate_no_aging_no_failure_counts(self):
        s = make()
        s.do("e1", "建立", "b1", ("bob", "pw"), 0)  # 期限 5000
        s.user_admin("d", "停用", "alice", 6000)
        # alice 的停用不应老化 bob：b1 仍在线持址
        self.assertEqual(s._sessions["b1"]["state"], "在线")
        self.assertIsNotNone(s._sessions["b1"]["ip"])
        # 停用拒绝不入用户失败统计
        with self.assertRaises(AuthError):
            s.do("g", "建立", "s9", ("alice", "x"), 7000)
        stats = json.loads(s.user_stats("alice", 8000))
        self.assertEqual(
            stats["失败"],
            [{"类型": "认证", "次数": 0}, {"类型": "资源", "次数": 0},
             {"类型": "状态", "次数": 0}, {"类型": "后端", "次数": 0}],
        )

    def test_enable_restores(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        with self.assertRaises(AuthError):
            s.do("g", "建立", "s9", ("alice", "pw"), 0)
        s.user_admin("e", "启用", "alice", 10)
        self.assertEqual(
            json.loads(s.do("ok", "建立", "s1", ("alice", "pw"), 10))["状态"],
            "在线",
        )
        out = s.credential_change("c", "alice", "pw", "new", 20)
        self.assertEqual(json.loads(out)["结果"], "已轮换")


class DisabledPersistenceTest(unittest.TestCase):
    def test_disabled_survives_config_load(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        s.config_change("cfg", "加载", s.export_config(), 0)
        with self.assertRaises(AuthError):
            s.do("g", "建立", "s9", ("alice", "pw"), 0)

    def test_queued_other_users_promote_after_force_disable(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(auth, 1, 4, 50000, pool=("10.0.0.0/28", (), ()), lease_ms=100000)
        s.do("occ", "建立", "occ", ("alice", "pw"), 0)
        s.capacity("qa", "申请", "qa1", ("alice", "pw", 1000), 0)
        s.capacity("qb", "申请", "qb1", ("bob", "pw", 1000), 0)
        s.user_admin("adm", "停用", "alice", 0, force=True)
        adv = json.loads(s.capacity("adv", "推进", "", None, 1))
        self.assertEqual(adv["在线"], 1)
        self.assertEqual(s._sessions["qb1"]["user"], "bob")
        verdicts = [e["结果"] for e in json.loads(s.capacity_events())["事件"]]
        self.assertNotIn("超时", verdicts)


if __name__ == "__main__":
    unittest.main()
