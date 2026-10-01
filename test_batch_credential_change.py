import json
import unittest

from access import AuthError, Authenticator, Sessions


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000,
         max_fail=3, lock_ms=1000, retry_base_ms=0, retry_cap_ms=0):
    auth = Authenticator(max_fail, lock_ms, retry_base_ms, retry_cap_ms)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool,
                          lease_ms=lease_ms)


def item(user, old, new):
    return (user, old, new)


def rows(output):
    return [(it["用户"], it["结果"]) for it in json.loads(output)["项目"]]


def batch_events(s, limit=1000):
    return json.loads(s.batch_audit(limit=limit))["事件"]


class BatchCredentialParamTest(unittest.TestCase):
    def test_key_checked_first_no_cache(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.batch_credential_change(bad, (("alice", "pw", "a"),), 0)
        # 空串 key 为取值错，先于 items 容器类型错。
        with self.assertRaises(ValueError):
            s.batch_credential_change("", [("alice", "pw", "a")], 0)
        self.assertEqual(s._batch_credential_cache, {})
        self.assertEqual(batch_events(s), [])

    def test_container_types(self):
        _auth, s = make()
        for bad in ([("alice", "pw", "a")], {"a"}, "x", None,
                    (x for x in (("alice", "pw", "a"),))):
            with self.assertRaises(TypeError):
                s.batch_credential_change("k" + type(bad).__name__, bad, 0)

    def test_item_and_field_types(self):
        _auth, s = make()
        # 元素必须是 tuple。
        with self.assertRaises(TypeError):
            s.batch_credential_change("t1", (["alice", "pw", "a"],), 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t2", ("alice",), 0)
        # 字段必须为 str。
        with self.assertRaises(TypeError):
            s.batch_credential_change("t3", (("alice", 1, "a"),), 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t4", (("alice", "pw", None),), 0)

    def test_now_ms_and_atomic_types(self):
        _auth, s = make()
        for bad in (True, False, 1.5, "0", None):
            with self.assertRaises(TypeError):
                s.batch_credential_change("n" + type(bad).__name__,
                                          (("alice", "pw", "a"),), bad)
        for bad in (0, 1, "false", None):
            with self.assertRaises(TypeError):
                s.batch_credential_change(
                    "a" + type(bad).__name__,
                    (("alice", "pw", "a"),), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        with self.assertRaises(TypeError):
            s.batch_credential_change("o1", [("alice", "pw", "pw")],
                                      True, atomic="x")
        with self.assertRaises(TypeError):
            s.batch_credential_change("o2", (("alice", 1, "x"),), -1)
        with self.assertRaises(TypeError):
            s.batch_credential_change(
                "o3", (("alice", "pw", "a"),), 1.5, atomic=0)

    def test_value_errors(self):
        _auth, s = make()
        with self.assertRaises(ValueError):  # 空批
            s.batch_credential_change("e0", (), 0)
        with self.assertRaises(ValueError):  # 项长度 2
            s.batch_credential_change("e1", (("alice", "pw"),), 0)
        with self.assertRaises(ValueError):  # 项长度 4
            s.batch_credential_change(
                "e2", (("alice", "pw", "a", "b"),), 0)
        with self.assertRaises(ValueError):  # 空 user
            s.batch_credential_change("e3", (("", "pw", "a"),), 0)
        with self.assertRaises(ValueError):  # NUL
            s.batch_credential_change("e4", (("a\0b", "pw", "a"),), 0)
        with self.assertRaises(ValueError):  # 超长
            s.batch_credential_change(
                "e5", (("alice", "pw", "a" * 257),), 0)
        with self.assertRaises(ValueError):  # 旧新相同
            s.batch_credential_change(
                "e6", (("alice", "same", "same"),), 0)
        with self.assertRaises(ValueError):  # 负时刻
            s.batch_credential_change("e7", (("alice", "pw", "a"),), -1)
        with self.assertRaises(ValueError):  # 重复用户
            s.batch_credential_change(
                "e8",
                (("alice", "pw", "a"), ("alice", "x", "b")), 0)

    def test_over_1000_items(self):
        _auth, s = make()
        items = tuple((f"u{i}", "pw", f"n{i}") for i in range(1001))
        with self.assertRaises(ValueError):
            s.batch_credential_change("big", items, 0)
        self.assertEqual(s._batch_credential_cache, {})

    def test_param_errors_do_not_authenticate_or_audit(self):
        auth, s = make()
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "k", (("alice", "same", "same"),), 0)
        # 无失败计数（未认证）、无审计。
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertEqual(batch_events(s), [])
        self.assertEqual(s._chain_events, [])

    def test_param_errors_do_not_occupy_key(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "k", (("alice", "same", "same"),), 0)
        # 同 key 的合法调用正常进行，证明参数错未占 key。
        out = s.batch_credential_change(
            "k", (("alice", "pw", "a"),), 0)
        self.assertEqual(rows(out), [("alice", "轮换")])


class BatchCredentialSequentialTest(unittest.TestCase):
    def test_all_success(self):
        auth, s = make()
        out = s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("bob", "pw", "b2")), 10)
        doc = json.loads(out)
        self.assertEqual(list(doc), ["时刻", "原子", "结果", "项目"])
        self.assertEqual(doc["时刻"], 10)
        self.assertIs(doc["原子"], False)
        self.assertEqual(doc["结果"], "成功")
        self.assertEqual(
            rows(out), [("alice", "轮换"), ("bob", "轮换")])
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        self.assertEqual(
            auth.authenticate("alice", "a2", 10)[1], "ok")
        self.assertEqual(
            auth.authenticate("bob", "b2", 10)[1], "ok")
        self.assertEqual(
            auth.authenticate("alice", "pw", 10)[1], "denied")

    def test_partial_success(self):
        auth, s = make()
        out = s.batch_credential_change(
            "k",
            (("alice", "pw", "a2"), ("ghost", "x", "y"),
             ("bob", "pw", "b2")), 5)
        self.assertEqual(json.loads(out)["结果"], "部分成功")
        self.assertEqual(
            rows(out),
            [("alice", "轮换"), ("ghost", "KeyError"),
             ("bob", "轮换")])
        # 前项失败不影响后项提交。
        self.assertEqual(auth.authenticate("bob", "b2", 5)[1], "ok")

    def test_all_failed(self):
        auth, s = make()
        out = s.batch_credential_change(
            "k", (("ghost", "x", "y"), ("alice", "BAD", "z")), 5)
        self.assertEqual(json.loads(out)["结果"], "失败")
        self.assertEqual(
            rows(out), [("ghost", "KeyError"), ("alice", "AuthError")])
        # 失败计数保留，口令未换。
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(auth.authenticate("alice", "pw", 6)[1], "ok")

    def test_unknown_user_is_keyerror_item(self):
        _auth, s = make()
        out = s.batch_credential_change(
            "k", (("ghost", "x", "y"),), 5)
        self.assertEqual(rows(out), [("ghost", "KeyError")])
        # 入口不抛。
        self.assertNotIn("ghost", s._auth._users)

    def test_disabled_user_is_autherror_item(self):
        auth, s = make()
        s.user_admin("d", "停用", "alice", 0)
        out = s.batch_credential_change(
            "k", (("alice", "pw", "a2"),), 5)
        self.assertEqual(rows(out), [("alice", "AuthError")])
        # 停用先于认证：失败计数不变，口令未换。
        self.assertEqual(auth._users["alice"][1], 0)
        s.user_admin("e", "启用", "alice", 6)
        self.assertEqual(auth.authenticate("alice", "pw", 6)[1], "ok")

    def test_wrong_password_retains_failed_count(self):
        auth, s = make()
        out = s.batch_credential_change(
            "k", (("alice", "WRONG", "a2"),), 100)
        self.assertEqual(rows(out), [("alice", "AuthError")])
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(auth.authenticate("alice", "pw", 100)[1], "ok")

    def test_lockout_retained(self):
        auth, s = make(max_fail=2, lock_ms=1000)
        s.batch_credential_change(
            "d1", (("alice", "BAD", "a2"),), 100)
        out = s.batch_credential_change(
            "d2", (("alice", "BAD2", "a3"),), 100)
        self.assertEqual(rows(out), [("alice", "AuthError")])
        self.assertEqual(auth._users["alice"][1], 2)
        self.assertEqual(auth._users["alice"][2], 1100)
        # 锁定期内正确口令也不换。
        out = s.batch_credential_change(
            "dL", (("alice", "pw", "a4"),), 100)
        self.assertEqual(rows(out), [("alice", "AuthError")])
        self.assertEqual(auth._users["alice"][2], 1100)
        # 锁到期（含同刻）后成功轮换并清零。
        out = s.batch_credential_change(
            "dOK", (("alice", "pw", "a5"),), 1100)
        self.assertEqual(rows(out), [("alice", "轮换")])
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])
        self.assertEqual(auth.authenticate("alice", "a5", 1100)[1], "ok")

    def test_success_clears_existing_failures(self):
        auth, s = make()
        auth.authenticate("alice", "bad", 0)
        self.assertEqual(auth._users["alice"][1], 1)
        s.batch_credential_change(
            "k", (("alice", "pw", "a2"),), 0)
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])
        self.assertEqual(auth._users["alice"][3], 0)

    def test_does_not_touch_sessions_or_disabled_state(self):
        _auth, s = make()
        r = json.loads(s.do("e1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["状态"], "在线")
        s.user_admin("d", "停用", "bob", 0)
        s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("bob", "x", "b2")), 100)
        # 会话仍在线、可续租；停用态不变（bob 仍停用）。
        self.assertEqual(
            json.loads(s.do("r", "续租", "s1", None, 100))["状态"], "在线")
        self.assertIn("bob", s._disabled_users)

    def test_no_aging_at_future_now_ms(self):
        _auth, s = make(idle_ms=10, lease_ms=100000)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        # now_ms 远超空闲期限：批量凭据轮换不老化，会话仍在线。
        s.batch_credential_change(
            "k", (("bob", "pw", "b2"),), 5000)
        self.assertEqual(s._sessions["s1"]["state"], "在线")


class BatchCredentialAtomicTest(unittest.TestCase):
    def test_all_success_commits(self):
        auth, s = make()
        out = s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("bob", "pw", "b2")), 10,
            atomic=True)
        doc = json.loads(out)
        self.assertIs(doc["原子"], True)
        self.assertEqual(doc["结果"], "成功")
        self.assertEqual(
            rows(out), [("alice", "轮换"), ("bob", "轮换")])
        self.assertEqual(auth.authenticate("alice", "a2", 10)[1], "ok")
        self.assertEqual(auth.authenticate("bob", "b2", 10)[1], "ok")

    def test_rollback_marks_verified_items_and_keeps_old_digests(self):
        auth, s = make()
        before_a = auth._users["alice"][0]
        before_c = auth._users["carol"][0]
        out = s.batch_credential_change(
            "k",
            (("alice", "pw", "a2"), ("carol", "BAD", "c2"),
             ("ghost", "x", "y")), 20, atomic=True)
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(
            rows(out),
            [("alice", "回滚"), ("carol", "AuthError"),
             ("ghost", "KeyError")])
        # 全部凭据保持批次前值：alice 旧口令仍可认证、新口令失败。
        self.assertEqual(auth._users["alice"][0], before_a)
        self.assertEqual(auth._users["carol"][0], before_c)
        self.assertEqual(auth.authenticate("alice", "pw", 20)[1], "ok")
        self.assertEqual(auth.authenticate("alice", "a2", 20)[1], "denied")

    def test_rollback_keeps_auth_failure_counts_and_clears(self):
        auth, s = make()
        # carol 错口令留下失败计数；alice 认证成功造成限制清零。回滚后两者
        # 均保留：carol failed=1，alice 批次前已有的一次失败被成功清零。
        auth.authenticate("alice", "bad", 0)
        self.assertEqual(auth._users["alice"][1], 1)
        s.batch_credential_change(
            "k",
            (("alice", "pw", "a2"), ("carol", "BAD", "c2")), 0,
            atomic=True)
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])
        self.assertEqual(auth._users["carol"][1], 1)
        self.assertIsNone(auth._users["carol"][2])

    def test_rollback_keeps_lock_and_backoff(self):
        auth, s = make(max_fail=2, lock_ms=1000,
                       retry_base_ms=10, retry_cap_ms=100)
        # carol 首次错口令：failed=1，退避至 110。
        s.batch_credential_change(
            "l1", (("carol", "BAD", "c2"),), 100, atomic=True)
        self.assertEqual(auth._users["carol"][1], 1)
        self.assertEqual(auth._users["carol"][3], 110)
        # 同刻再试落退避窗（不增失败、不锁定）；退避窗不影响本断言之外的项。
        out = s.batch_credential_change(
            "lw", (("carol", "BAD9", "c9"),), 100, atomic=True)
        self.assertEqual(rows(out), [("carol", "AuthError")])
        self.assertEqual(auth._users["carol"][1], 1)
        # 退避到刻（110）再错：第二次失败，锁定至 1110；bob 首次错留退避。
        out = s.batch_credential_change(
            "l2",
            (("alice", "pw", "a2"), ("carol", "BAD2", "c3"),
             ("bob", "BAD", "b2")), 110, atomic=True)
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(
            rows(out),
            [("alice", "回滚"), ("carol", "AuthError"),
             ("bob", "AuthError")])
        self.assertEqual(auth._users["carol"][1], 2)
        self.assertEqual(auth._users["carol"][2], 1110)
        self.assertEqual(auth._users["carol"][3], 0)
        self.assertEqual(auth._users["bob"][1], 1)
        self.assertEqual(auth._users["bob"][3], 120)
        # 全部口令未换。
        self.assertEqual(auth.authenticate("alice", "pw", 110)[1], "ok")
        # 回滚后可整体重提成功（bob 在退避到刻 120 以旧口令认证）。
        out2 = s.batch_credential_change(
            "k2", (("alice", "pw", "a2"), ("bob", "pw", "b2")), 120,
            atomic=True)
        self.assertEqual(json.loads(out2)["结果"], "成功")

    def test_all_fail_atomic_is_rollback_without_rollback_items(self):
        _auth, s = make()
        out = s.batch_credential_change(
            "k", (("ghost", "x", "y"), ("alice", "BAD", "z")), 5,
            atomic=True)
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(
            rows(out), [("ghost", "KeyError"), ("alice", "AuthError")])

    def test_disabled_does_not_authenticate_in_atomic(self):
        auth, s = make()
        s.user_admin("d", "停用", "bob", 0)
        out = s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("bob", "x", "b2")), 0,
            atomic=True)
        self.assertEqual(
            rows(out), [("alice", "回滚"), ("bob", "AuthError")])
        # bob 未认证：失败计数为 0。
        self.assertEqual(auth._users["bob"][1], 0)
        # 回滚：alice 旧口令仍有效。
        self.assertEqual(auth.authenticate("alice", "pw", 0)[1], "ok")

    def test_all_success_after_rollback(self):
        auth, s = make()
        s.batch_credential_change(
            "r", (("alice", "pw", "x"), ("carol", "BAD", "y")), 0,
            atomic=True)
        out = s.batch_credential_change(
            "ok", (("alice", "pw", "a2"), ("carol", "pw", "c2")), 1,
            atomic=True)
        self.assertEqual(json.loads(out)["结果"], "成功")
        self.assertEqual(auth.authenticate("alice", "a2", 1)[1], "ok")
        self.assertEqual(auth.authenticate("carol", "c2", 1)[1], "ok")

    def test_does_not_touch_sessions(self):
        _auth, s = make(idle_ms=10, lease_ms=100000)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.batch_credential_change(
            "k", (("bob", "pw", "b2"), ("ghost", "x", "y")), 5000,
            atomic=True)
        # 不老化、会话与租约不变。
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertIsNotNone(s._sessions["s1"]["ip"])


class BatchCredentialReplayTest(unittest.TestCase):
    def test_same_params_replay_byte_identical(self):
        _auth, s = make()
        items = (("alice", "pw", "a2"), ("bob", "BAD", "b2"))
        first = s.batch_credential_change("k", items, 10)
        second = s.batch_credential_change("k", items, 10)
        self.assertEqual(second, first)

    def test_replay_does_not_authenticate_or_rotate(self):
        auth, s = make(max_fail=2, lock_ms=1000)
        items = (("alice", "BAD", "a2"),)
        first = s.batch_credential_change("k", items, 100)
        self.assertEqual(auth._users["alice"][1], 1)
        # 多次重放不再认证，失败计数不增长。
        for _ in range(3):
            out = s.batch_credential_change("k", items, 100)
            self.assertEqual(out, first)
        self.assertEqual(auth._users["alice"][1], 1)
        # 重放逐字节返回首果（首果 JSON 时刻为 100）。
        self.assertIn('"时刻":100', first)

    def test_replay_after_state_change_returns_first_result(self):
        auth, s = make()
        items = (("alice", "pw", "a2"),)
        first = s.batch_credential_change("k", items, 0)
        # 此后密码再变；重放仍返首果且不轮换。
        s.credential_change("c", "alice", "a2", "a3", 0)
        replay = s.batch_credential_change("k", items, 0)
        self.assertEqual(replay, first)
        self.assertEqual(auth.authenticate("alice", "a3", 0)[1], "ok")

    def test_different_params_value_error(self):
        _auth, s = make()
        s.batch_credential_change(
            "k", (("alice", "pw", "a2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "k", (("alice", "pw", "a3"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "k", (("alice", "pw", "a2"),), 1)
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "k", (("bob", "pw", "b2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "k", (("alice", "pw", "a2"),), 0, atomic=True)

    def test_atomic_rollback_replay_byte_identical(self):
        auth, s = make()
        items = (("alice", "pw", "a2"), ("carol", "BAD", "c2"))
        first = s.batch_credential_change(
            "k", items, 0, atomic=True)
        before = auth._users["alice"][0]
        replay = s.batch_credential_change(
            "k", items, 0, atomic=True)
        self.assertEqual(replay, first)
        self.assertEqual(auth._users["alice"][0], before)
        # 重放不再认证：carol 失败计数仍为 1。
        self.assertEqual(auth._users["carol"][1], 1)

    def test_domains_independent_from_single_credential_change(self):
        _auth, s = make()
        # 同名字符串 key 在两域各为首次。
        out1 = s.batch_credential_change(
            "dup", (("alice", "pw", "a2"),), 0)
        out2 = s.credential_change("dup", "alice", "a2", "a3", 0)
        self.assertEqual(json.loads(out1)["结果"], "成功")
        self.assertEqual(json.loads(out2)["结果"], "已轮换")


class BatchCredentialAuditTest(unittest.TestCase):
    def _op_events(self, s, key=None):
        return [
            e for e in batch_events(s)
            if e["操作"] == "批量凭据轮换"
            and (key is None or e["键"] == key)
        ]

    def test_first_call_records_item_results(self):
        _auth, s = make()
        s.batch_credential_change(
            "k",
            (("alice", "pw", "a2"), ("ghost", "x", "y"),
             ("bob", "BAD", "b2")), 42)
        events = self._op_events(s, "k")
        self.assertEqual(
            [(e["会话"], e["结果"], e["原序号"]) for e in events],
            [("alice", "轮换", 0), ("ghost", "KeyError", 0),
             ("bob", "AuthError", 0)])
        self.assertTrue(all(e["时刻"] == 42 for e in events))
        self.assertFalse(any(e["原子"] for e in events))
        self.assertEqual(events[0]["前哈希"], "0" * 64)
        self.assertEqual(events[1]["前哈希"], events[0]["哈希"])
        self.assertEqual(events[2]["前哈希"], events[1]["哈希"])

    def test_replay_points_to_first_items(self):
        _auth, s = make()
        items = (("alice", "pw", "a2"), ("bob", "BAD", "b2"))
        s.batch_credential_change("k", items, 7)
        s.batch_credential_change("k", items, 7)
        events = self._op_events(s, "k")
        self.assertEqual(len(events), 4)
        first_seqs = [events[0]["序号"], events[1]["序号"]]
        for replay, origin in zip(events[2:], first_seqs):
            self.assertEqual(replay["结果"], "重放")
            self.assertEqual(replay["原序号"], origin)
        self.assertEqual(events[2]["前哈希"], events[1]["哈希"])

    def test_atomic_audit_fields(self):
        _auth, s = make()
        s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("ghost", "x", "y")), 3,
            atomic=True)
        events = self._op_events(s, "k")
        self.assertTrue(all(e["原子"] for e in events))
        self.assertEqual(
            [(e["会话"], e["结果"]) for e in events],
            [("alice", "回滚"), ("ghost", "KeyError")])

    def test_not_written_to_single_audit_chain(self):
        _auth, s = make()
        s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("ghost", "x", "y")), 0)
        self.assertEqual(s._chain_events, [])
        audit = json.loads(s.audit(limit=1000))["事件"]
        self.assertEqual(audit, [])

    def test_projects_to_compliance_chain(self):
        _auth, s = make()
        s.batch_credential_change(
            "k", (("alice", "pw", "a2"), ("bob", "BAD", "b2")), 0)
        comp = json.loads(s.compliance_events(limit=1000))["事件"]
        batch = [e for e in comp if e["来源"] == "批量"]
        self.assertEqual(len(batch), 2)
        payload = json.loads(batch[0]["载荷"])
        self.assertEqual(payload["操作"], "批量凭据轮换")
        self.assertEqual(payload["会话"], "alice")
        self.assertEqual(payload["结果"], "轮换")
        # 来源序号与批量链序号一致。
        self.assertEqual(batch[0]["来源序号"], payload["序号"])

    def test_deterministic_bytes(self):
        def run():
            auth = Authenticator(2, 1000)
            auth.add("alice", "pw")
            auth.add("bob", "pw")
            s = Sessions(auth, 4, 2, 5000)
            parts = [s.batch_credential_change(
                "k", (("alice", "pw", "a2"), ("bob", "BAD", "b2")), 100)]
            s.batch_credential_change(
                "k", (("alice", "pw", "a2"), ("bob", "BAD", "b2")), 100)
            parts.append(s.batch_audit(limit=1000))
            return "".join(parts)
        self.assertEqual(run(), run())


if __name__ == "__main__":
    unittest.main()
