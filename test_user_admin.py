import json
import unittest

from access import AuthError, Authenticator, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def ops(s):
    return [(e[0], e[3], e[4], e[5], e[6]) for e in s._chain_events]


class UserAdminValidationTest(unittest.TestCase):
    def test_key_validated_first_and_not_cached(self):
        s = make()
        for bad in (1, True, None):
            with self.assertRaises(TypeError):
                s.user_admin(bad, "停用", "alice", 0)
        with self.assertRaises(ValueError):
            s.user_admin("", "停用", "alice", 0)
        self.assertEqual(s._user_admin_cache, {})
        self.assertEqual(ops(s), [])

    def test_param_types(self):
        s = make()
        with self.assertRaises(TypeError):
            s.user_admin("o", 1, "alice", 0)
        with self.assertRaises(TypeError):
            s.user_admin("u", "停用", 1, 0)
        for i, bad in enumerate((True, 1.5, "0", None)):
            with self.assertRaises(TypeError):
                s.user_admin(f"t{i}", "停用", "alice", bad)
        for i, bad in enumerate((1, 0, "x", None)):
            with self.assertRaises(TypeError):
                s.user_admin(f"f{i}", "停用", "alice", 0, bad)

    def test_type_errors_precede_value_errors(self):
        s = make()
        # op 类型错先于非法取值
        with self.assertRaises(TypeError):
            s.user_admin("k", 1, "alice", True, True)
        # now_ms 类型错先于负值与 force 取值错
        with self.assertRaises(TypeError):
            s.user_admin("k2", "启用", "alice", True, True)

    def test_op_and_user_value_errors(self):
        s = make()
        with self.assertRaises(ValueError):
            s.user_admin("k", "冻结", "alice", 0)
        for bad in ("", "a" * 257, "a\0b"):
            with self.assertRaises(ValueError):
                s.user_admin(f"u-{bad!r}", "停用", bad, 0)
        with self.assertRaises(ValueError):
            s.user_admin("n", "停用", "alice", -1)

    def test_enable_force_must_be_false(self):
        s = make()
        with self.assertRaises(ValueError):
            s.user_admin("k", "启用", "alice", 0, force=True)
        # 停用允许 force=True
        out = s.user_admin("k2", "停用", "alice", 0, force=True)
        self.assertEqual(json.loads(out)["状态"], "停用")

    def test_param_errors_cached_not_audited(self):
        s = make()
        with self.assertRaises(ValueError):
            s.user_admin("k", "冻结", "alice", 0)
        with self.assertRaises(ValueError):
            s.user_admin("k", "冻结", "alice", 0)
        self.assertEqual(ops(s), [])
        with self.assertRaises(ValueError):
            s.user_admin("k", "停用", "alice", 0)
        self.assertEqual(ops(s), [])
        # 参数错 key 永久首果，仍重放参数错
        with self.assertRaises(ValueError):
            s.user_admin("k", "冻结", "alice", 0)
        self.assertEqual(ops(s), [])


class UserAdminUnknownUserTest(unittest.TestCase):
    def test_unknown_user_key_error_audited_replayed(self):
        s = make()
        with self.assertRaises(KeyError) as cm:
            s.user_admin("k", "停用", "ghost", 5)
        self.assertEqual(cm.exception.args, ("unknown user: 'ghost'",))
        # 未知用户不审计（异常仍缓存、可重放）
        self.assertEqual(ops(s), [])
        with self.assertRaises(KeyError) as cm2:
            s.user_admin("k", "停用", "ghost", 5)
        self.assertEqual(cm2.exception.args, cm.exception.args)
        self.assertEqual(ops(s), [])
        self.assertTrue(s.verify_audit())
        # 未知用户不进入停用集合
        self.assertNotIn("ghost", s._disabled_users)


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
        self.assertNotIn("alice", s._disabled_users)

    def test_disable_then_enable_toggles_set(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        self.assertIn("alice", s._disabled_users)
        s.user_admin("e", "启用", "alice", 1)
        self.assertNotIn("alice", s._disabled_users)

    def test_idempotent_same_state_counts_zero(self):
        s = make()
        first = s.user_admin("d1", "停用", "alice", 0)
        second = s.user_admin("d2", "停用", "alice", 1)
        self.assertEqual(json.loads(first)["下线"], 0)
        doc = json.loads(second)
        self.assertEqual(doc["状态"], "停用")
        self.assertEqual((doc["下线"], doc["取消"]), (0, 0))
        # 未停用过直接启用同样成功、二数 0
        out = json.loads(s.user_admin("e1", "启用", "bob", 2))
        self.assertEqual(out["状态"], "启用")
        self.assertEqual((out["下线"], out["取消"]), (0, 0))


class UserAdminForceTest(unittest.TestCase):
    def test_state_error_with_active_session(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 5)
        # 状态不变；StateError 缓存但不审计（仅 do 建立入链）
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertNotIn("alice", s._disabled_users)
        self.assertEqual(
            ops(s), [(1, "建立", "s1", "成功", 0)]
        )

    def test_state_error_with_suspended_session(self):
        # 挂起（无址）仍属非下线会话，拒绝停用。
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        # idle=5000：6000 时老化把 s1 挂起
        s.pool_stats(6000)
        self.assertEqual(s._sessions["s1"]["state"], "挂起")
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 6000)
        self.assertNotIn("alice", s._disabled_users)

    def test_state_error_with_queued_item(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 1, 2, 5000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(
            json.loads(s.capacity("q", "申请", "s2", ("alice", "pw", 100000), 0))[
                "结果"
            ],
            "排队",
        )
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 1)
        self.assertEqual(len(s._capacity_queue), 1)

    def test_offline_tombstone_does_not_block(self):
        # 下线墓碑不计非下线：可直接停用，下线数 0。
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.do("o1", "下线", "s1", None, 1)
        out = json.loads(s.user_admin("d", "停用", "alice", 1))
        self.assertEqual(out["状态"], "停用")
        self.assertEqual((out["下线"], out["取消"]), (0, 0))

    def test_force_offlines_sessions_and_releases_lease(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.do("e2", "建立", "s2", ("bob", "pw"), 0)
        out = json.loads(s.user_admin("d", "停用", "alice", 5, force=True))
        self.assertEqual(out["状态"], "停用")
        self.assertEqual(out["下线"], 1)
        self.assertEqual(out["取消"], 0)
        alice = s._sessions["s1"]
        self.assertEqual(alice["state"], "下线")
        self.assertEqual(alice["deadline"], 0)
        self.assertIsNone(alice["ip"])
        # 仅 alice 被清场，bob 保留；alice 静态址退租
        self.assertEqual(s._sessions["s2"]["state"], "在线")
        self.assertEqual(len(s._pools["default"].leases), 1)
        self.assertIn("alice", s._disabled_users)

    def test_force_removes_queued_items_without_capacity_events(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(auth, 1, 4, 5000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.capacity("qa", "申请", "s2", ("alice", "pw", 100000), 0)
        s.capacity("qb", "申请", "s3", ("bob", "pw", 100000), 0)
        out = json.loads(s.user_admin("d", "停用", "alice", 5, force=True))
        self.assertEqual(out["下线"], 1)
        self.assertEqual(out["取消"], 1)
        # alice 在线与排队项皆清，bob 队项保留
        self.assertNotIn("s2", s._capacity_queue)
        self.assertIn("s3", s._capacity_queue)
        self.assertEqual([q for q in s._queue_order], ["s3"])
        # 停用清场不记 capacity 事件（do 建立无事件；仅有两条排队事件，
        # 清场不补取消/超时事件）
        verdicts = [e["结果"] for e in
                    json.loads(s.capacity_events(limit=100))["事件"]]
        self.assertEqual(verdicts, ["排队", "排队"])

    def test_force_failure_is_impossible_and_state_error_replays(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 5)
        # 同参重放仍 StateError，且不改态（会话仍在线、未停用）
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 5)
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertNotIn("alice", s._disabled_users)
        # 异参 ValueError
        with self.assertRaises(ValueError):
            s.user_admin("d", "停用", "alice", 5, force=True)


class UserAdminGateTest(unittest.TestCase):
    def setUp(self):
        self.s = make(pool=("10.0.0.0/28", (), ()))
        self.s.user_admin("dis", "停用", "alice", 0, force=True)

    def test_do_establish_rejected_before_auth(self):
        s = self.s
        with self.assertRaises(AuthError):
            s.do("e", "建立", "sx", ("alice", "WRONG"), 10)
        # 错误密码也未触达认证：失败计数不变
        self.assertEqual(s._auth._users["alice"][1], 0)
        self.assertNotIn("sx", s._sessions)
        # 早退不写 do 审计（仅停用本身入链），重放也不写
        with self.assertRaises(AuthError):
            s.do("e", "建立", "sx", ("alice", "WRONG"), 10)
        self.assertEqual(
            [e[1] for e in ops(s)], ["用户停用"]
        )

    def test_do_migrate_and_takeover_rejected(self):
        s = make(pool=("10.0.0.0/28", (), ()))
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.add_pool("p2", ("10.0.2.0/28", (), ()))
        s.user_admin("dis", "停用", "alice", 1, force=True)
        with self.assertRaises(AuthError):
            s.do("m", "迁移", "s1", ("p2", "WRONG"), 2)
        with self.assertRaises(AuthError):
            s.do("t", "接管", "new", ("s1", "WRONG"), 2)
        # 失败计数与退避不变
        self.assertNotIn("alice", s._backoff)
        self.assertEqual(s._user_fail.get("alice"), None)

    def test_capacity_apply_rejected_no_event_no_queue(self):
        s = self.s
        with self.assertRaises(AuthError):
            s.capacity("q", "申请", "sq", ("alice", "WRONG", 1000), 10)
        self.assertNotIn("sq", s._capacity_queue)
        self.assertEqual(
            json.loads(s.capacity_events(limit=100))["事件"], []
        )

    def test_batch_online_item_records_auth_error(self):
        s = self.s
        out = json.loads(
            s.batch_online(
                "b",
                (("z1", "alice", "WRONG"), ("z2", "bob", "pw")),
                10,
            )
        )
        self.assertEqual(out["结果"], "部分")
        self.assertEqual(
            out["项目"],
            [{"会话": "z1", "结果": "AuthError"},
             {"会话": "z2", "结果": "上线"}],
        )
        self.assertNotIn("z1", s._sessions)
        self.assertIn("z2", s._sessions)
        self.assertEqual(s._auth._users["alice"][1], 0)

    def test_batch_online_atomic_rolls_back_when_disabled(self):
        s = self.s
        out = json.loads(
            s.batch_online(
                "b",
                (("z2", "bob", "pw"), ("z1", "alice", "pw")),
                10,
                atomic=True,
            )
        )
        self.assertEqual(out["结果"], "回滚")
        self.assertEqual(
            out["项目"],
            [{"会话": "z2", "结果": "回滚"},
             {"会话": "z1", "结果": "AuthError"}],
        )
        self.assertNotIn("z2", s._sessions)

    def test_credential_change_rejected(self):
        s = self.s
        with self.assertRaises(AuthError):
            s.credential_change("c", "alice", "pw", "pw2", 10)
        # 旧密码仍可认证（未轮换）
        self.assertEqual(s._auth.authenticate("alice", "pw", 10)[1], "ok")
        self.assertEqual(s._auth._users["alice"][1], 0)
        # 早退不写凭据轮换审计（仅停用本身入链）
        self.assertEqual([e[1] for e in ops(s)], ["用户停用"])

    def test_backend_fault_skipped_and_no_backoff(self):
        s = self.s
        s.fault("inj", "注入", 1000, 0)
        # 停用先于后端：不产生退避记录
        with self.assertRaises(AuthError):
            s.do("e", "建立", "sx", ("alice", "pw"), 5)
        self.assertNotIn("alice", s._backoff)

    def test_enable_restores(self):
        s = self.s
        s.user_admin("en", "启用", "alice", 20)
        out = json.loads(s.do("e", "建立", "sx", ("alice", "pw"), 20))
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(
            json.loads(
                s.capacity("q", "申请", "sq", ("alice", "pw", 1000), 20)
            )["结果"],
            "在线",
        )
        self.assertEqual(
            json.loads(s.credential_change("c", "alice", "pw", "pw2", 20))[
                "结果"
            ],
            "已轮换",
        )


class UserAdminChainTest(unittest.TestCase):
    def test_success_audited_and_replayed(self):
        s = make()
        out = s.user_admin("L", "停用", "alice", 100)
        self.assertEqual(ops(s), [(1, "用户停用", "alice", "成功", 0)])
        out2 = s.user_admin("L", "停用", "alice", 100)
        self.assertEqual(out2, out)
        self.assertEqual(
            ops(s),
            [(1, "用户停用", "alice", "成功", 0),
             (2, "用户停用", "alice", "重放", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_enable_chain_op_name(self):
        s = make()
        s.user_admin("E", "启用", "alice", 1)
        self.assertEqual(ops(s), [(1, "用户启用", "alice", "成功", 0)])

    def test_state_error_replay_cached_not_audited(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 5)
        with self.assertRaises(StateError):
            s.user_admin("d", "停用", "alice", 5)
        # StateError 缓存可重放但不入审计链（仅 do 建立一项）
        self.assertEqual(ops(s), [(1, "建立", "s1", "成功", 0)])
        self.assertTrue(s.verify_audit())
        # 之后 force 成功才入链，原序号 0
        out = json.loads(s.user_admin("f", "停用", "alice", 5, force=True))
        self.assertEqual(out["下线"], 1)
        self.assertEqual(ops(s)[-1], (2, "用户停用", "alice", "成功", 0))

    def test_independent_cache_domain(self):
        s = make()
        s.do("dup", "建立", "s1", ("alice", "pw"), 0)
        # 同名 key 在 user_admin 域独立
        s.user_admin("dup", "停用", "alice", 1, force=True)
        # do 域重放不受影响，返回建立首果（同参重放）
        r = json.loads(s.do("dup", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["状态"], "在线")
        user_events = [e for e in ops(s) if e[1] in ("用户停用", "用户启用")]
        self.assertEqual(user_events, [(2, "用户停用", "alice", "成功", 0)])

    def test_audit_json_shape(self):
        s = make()
        s.user_admin("L", "停用", "alice", 42)
        e = json.loads(s.audit(limit=1000))["事件"][0]
        self.assertEqual(
            list(e),
            ["序号", "时刻", "键", "操作", "会话", "结果", "原序号",
             "前哈希", "哈希"],
        )
        self.assertEqual(e["操作"], "用户停用")
        self.assertEqual(e["会话"], "alice")
        self.assertEqual(e["结果"], "成功")
        self.assertEqual(e["前哈希"], "0" * 64)
        self.assertEqual(len(e["哈希"]), 64)

    def test_deterministic_byte_output(self):
        def run():
            auth = Authenticator(3, 1000)
            auth.add("alice", "pw")
            s = Sessions(auth, 4, 2, 5000)
            parts = [s.user_admin("L", "停用", "alice", 100)]
            s.user_admin("L", "停用", "alice", 100)
            parts.append(s.audit(limit=1000))
            return "".join(parts)
        self.assertEqual(run(), run())


if __name__ == "__main__":
    unittest.main()
