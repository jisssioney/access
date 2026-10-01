import json
import unittest

from access import AuthError, Authenticator, Sessions


def make(users=("alice", "bob", "carol"), pool=("10.0.0.0/24", (), ())):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def item(user="alice", old="pw", new="pw2"):
    return (user, old, new)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def batch_rows(s):
    return [
        (e[0], e[3], e[5], e[6], e[7])
        for e in s._batch_chain_events
    ]


class BatchCredentialParamTest(unittest.TestCase):
    def test_key_checked_first(self):
        _auth, s = make()
        for bad in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.batch_credential_change(bad, (item(),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("", (item(),), 0)
        # key 非法不占任何域
        self.assertEqual(s._batch_credential_change_cache, {})
        self.assertEqual(batch_rows(s), [])

    def test_container_and_element_types(self):
        _auth, s = make()
        for bad in ([item()], {item()}, "x", None, (x for x in (item(),))):
            with self.assertRaises(TypeError):
                s.batch_credential_change("k" + type(bad).__name__, bad, 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t1", (["alice", "pw", "pw2"],), 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t2", ((1, "pw", "pw2"),), 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t3", (("alice", None, "pw2"),), 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t4", (("alice", "pw", b"pw2"),), 0)

    def test_now_ms_atomic_types(self):
        _auth, s = make()
        for bad in (True, 1.5, "0", None):
            with self.assertRaises(TypeError):
                s.batch_credential_change(f"n{type(bad).__name__}", (item(),), bad)
        for bad in (0, 1, "false", None):
            with self.assertRaises(TypeError):
                s.batch_credential_change(
                    f"a{type(bad).__name__}", (item(),), 0, atomic=bad
                )

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        with self.assertRaises(TypeError):
            s.batch_credential_change(
                "o1", [item(), item()], 1.5, atomic="x"
            )
        with self.assertRaises(TypeError):
            s.batch_credential_change("o2", (("alice", "pw"),), True)
        with self.assertRaises(TypeError):
            s.batch_credential_change("o3", ((1, "x", "x"),), True)

    def test_value_errors(self):
        _auth, s = make()
        long_s = "a" * 257
        with self.assertRaises(ValueError):
            s.batch_credential_change("e0", (), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("e2a", (("alice", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "e4", (("alice", "pw", "pw2", "x"),), 0
            )
        with self.assertRaises(ValueError):
            s.batch_credential_change("v1", (("", "pw", "pw2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("v2", (("alice", long_s, "pw2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("v3", (("alice", "pw\0", "pw2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("v4", (("alice", "pw", ""),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("same", (item("alice", "x", "x"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("neg", (item(),), -1)
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "dup", (item("alice"), item("alice", "a", "b")), 0
            )
        with self.assertRaises(ValueError):
            s.batch_credential_change(
                "dup2", (item("alice"), item("bob"), item("alice")), 0
            )

    def test_length_bounds(self):
        _auth, s = make()
        one = tuple(item(f"u{i:04d}", "pw", "pw2") for i in range(1))
        thousand = tuple(item(f"u{i:04d}", "pw", "pw2") for i in range(1000))
        thousand_one = tuple(
            item(f"u{i:04d}", "pw", "pw2") for i in range(1001)
        )
        # 全未知用户为业务失败项，不抛；1000 合法。
        self.assertEqual(
            json.loads(s.batch_credential_change("b1", one, 0))["结果"], "失败"
        )
        self.assertEqual(
            json.loads(s.batch_credential_change("b1000", thousand, 0))["结果"],
            "失败",
        )
        with self.assertRaises(ValueError):
            s.batch_credential_change("b1001", thousand_one, 0)

    def test_param_errors_do_not_occupy_key_or_audit(self):
        _auth, s = make()
        # 参数错首调不占 key：同 key 合法参数随后按首次处理并成功。
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", (item("alice", "x", "x"),), 0)
        self.assertNotIn("k", s._batch_credential_change_cache)
        self.assertEqual(batch_rows(s), [])
        out = s.batch_credential_change("k", (item(),), 0)
        self.assertEqual(json.loads(out)["结果"], "成功")
        self.assertIn("k", s._batch_credential_change_cache)


class BatchCredentialNonAtomicTest(unittest.TestCase):
    def test_all_success_bytes(self):
        _auth, s = make()
        items = (item("bob", "pw", "nb"), item("alice", "pw", "na"))
        out = s.batch_credential_change("k", items, 42)
        self.assertEqual(
            out,
            wire({
                "时刻": 42,
                "原子": False,
                "结果": "成功",
                "项目": [
                    {"用户": "bob", "结果": "轮换"},
                    {"用户": "alice", "结果": "轮换"},
                ],
            }),
        )
        doc = json.loads(out)
        self.assertEqual(list(doc), ["时刻", "原子", "结果", "项目"])
        self.assertEqual(type(doc["时刻"]), int)
        self.assertEqual(type(doc["原子"]), bool)

    def test_new_passwords_effective(self):
        auth, s = make()
        s.batch_credential_change(
            "k", (item("alice", "pw", "a2"), item("bob", "pw", "b2")), 10
        )
        self.assertEqual(auth.authenticate("alice", "a2", 10)[1], "ok")
        self.assertEqual(auth.authenticate("bob", "b2", 10)[1], "ok")
        self.assertEqual(auth.authenticate("alice", "pw", 10)[1], "denied")

    def test_partial_success_result_and_order(self):
        auth, s = make()
        items = (
            item("alice", "WRONG", "na"),
            item("bob", "pw", "nb"),
            ("ghost", "pw", "ng"),
        )
        doc = json.loads(s.batch_credential_change("k", items, 100))
        self.assertEqual(doc["结果"], "部分成功")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            doc["项目"],
            [
                {"用户": "alice", "结果": "AuthError"},
                {"用户": "bob", "结果": "轮换"},
                {"用户": "ghost", "结果": "KeyError"},
            ],
        )
        # 失败项不换密，成功项已换；失败计数保留
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(auth.authenticate("alice", "pw", 100)[1], "ok")
        self.assertEqual(auth.authenticate("bob", "pw", 100)[1], "denied")
        self.assertNotIn("ghost", auth._users)

    def test_all_failure_result(self):
        _auth, s = make()
        items = (item("alice", "WRONG", "na"), ("ghost", "x", "y"))
        doc = json.loads(s.batch_credential_change("k", items, 0))
        self.assertEqual(doc["结果"], "失败")
        self.assertEqual(
            doc["项目"],
            [
                {"用户": "alice", "结果": "AuthError"},
                {"用户": "ghost", "结果": "KeyError"},
            ],
        )

    def test_sequential_commit_independence(self):
        # 用户互异，逐项提交：先成功换密不影响后项失败项。
        auth, s = make()
        items = (item("alice", "pw", "a2"), item("bob", "BAD", "b2"))
        doc = json.loads(s.batch_credential_change("k", items, 5))
        self.assertEqual(doc["结果"], "部分成功")
        self.assertEqual(auth.authenticate("alice", "a2", 5)[1], "ok")
        # 失败项失败计数保留（成功认证会清零，故先断言）
        self.assertEqual(auth._users["bob"][1], 1)
        self.assertEqual(auth.authenticate("bob", "pw", 5)[1], "ok")
        self.assertEqual(auth._users["bob"][1], 0)

    def test_success_clears_failed_and_lock(self):
        auth, s = make()
        auth.authenticate("alice", "bad", 0)
        self.assertEqual(auth._users["alice"][1], 1)
        s.batch_credential_change("k", (item("alice"),), 0)
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])
        self.assertEqual(auth._users["alice"][3], 0)

    def test_locked_recorded(self):
        auth = Authenticator(2, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        auth.add("carol", "pw")
        s = Sessions(auth, 4, 2, 5000)
        # max_fail=2：两次错口即锁定至 1100
        auth.authenticate("alice", "bad1", 100)
        auth.authenticate("alice", "bad2", 100)
        self.assertEqual(auth._users["alice"][2], 1100)
        doc = json.loads(
            s.batch_credential_change(
                "k",
                (
                    ("alice", "pw", "new"),
                    ("bob", "bad", "bnew"),
                    ("carol", "pw", "cnew"),
                ),
                100,
            )
        )
        self.assertEqual(doc["结果"], "部分成功")
        self.assertEqual(doc["项目"][0]["结果"], "AuthError")
        self.assertEqual(doc["项目"][1]["结果"], "AuthError")
        self.assertEqual(doc["项目"][2]["结果"], "轮换")
        # 锁定保持，且锁定期项未再认证、失败计数不增
        self.assertEqual(auth._users["alice"][1], 2)
        self.assertEqual(auth._users["alice"][2], 1100)

    def test_disabled_user_rejected_before_auth(self):
        auth, s = make()
        s.user_admin("d", "停用", "alice", 0)
        doc = json.loads(
            s.batch_credential_change("k", (item("alice"), item("bob")), 0)
        )
        self.assertEqual(doc["结果"], "部分成功")
        self.assertEqual(doc["项目"][0]["结果"], "AuthError")
        self.assertEqual(doc["项目"][1]["结果"], "轮换")
        # 停用项未认证：失败计数不变，密码未换
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertEqual(auth.authenticate("alice", "pw", 0)[1], "ok")
        # 停用状态保留
        self.assertIn("alice", s._disabled_users)


class BatchCredentialAtomicTest(unittest.TestCase):
    def test_all_success_single_commit(self):
        auth, s = make()
        items = (item("alice", "pw", "a2"), item("bob", "pw", "b2"))
        out = s.batch_credential_change("k", items, 7, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 7,
                "原子": True,
                "结果": "成功",
                "项目": [
                    {"用户": "alice", "结果": "轮换"},
                    {"用户": "bob", "结果": "轮换"},
                ],
            }),
        )
        self.assertEqual(auth.authenticate("alice", "a2", 7)[1], "ok")
        self.assertEqual(auth.authenticate("bob", "b2", 7)[1], "ok")

    def test_rollback_keeps_pre_batch_credentials(self):
        auth, s = make()
        old_alice = auth._users["alice"][0]
        old_bob = auth._users["bob"][0]
        doc = json.loads(
            s.batch_credential_change(
                "k",
                (
                    item("alice", "pw", "a2"),
                    item("bob", "BAD", "b2"),
                    ("ghost", "x", "g2"),
                ),
                50,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            doc["项目"],
            [
                {"用户": "alice", "结果": "回滚"},
                {"用户": "bob", "结果": "AuthError"},
                {"用户": "ghost", "结果": "KeyError"},
            ],
        )
        # 全部凭据保持批次前值
        self.assertEqual(auth._users["alice"][0], old_alice)
        self.assertEqual(auth._users["bob"][0], old_bob)
        self.assertEqual(auth.authenticate("alice", "pw", 50)[1], "ok")
        self.assertEqual(auth.authenticate("alice", "a2", 50)[1], "denied")

    def test_rollback_keeps_auth_side_effects_and_clears_limits(self):
        auth, s = make()
        # alice 带一次失败计数；原子批中 alice 验证成功（清零保留），bob 错口
        # （失败计数保留），ghost 未知，全部回滚凭据。
        auth.authenticate("alice", "bad", 0)
        self.assertEqual(auth._users["alice"][1], 1)
        s.batch_credential_change(
            "k",
            (
                item("alice", "pw", "a2"),
                item("bob", "BAD", "b2"),
                ("ghost", "x", "g2"),
            ),
            30,
            atomic=True,
        )
        # 成功验证的清零保留
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])
        self.assertEqual(auth._users["alice"][3], 0)
        # 失败项的失败计数保留
        self.assertEqual(auth._users["bob"][1], 1)

    def test_rollback_disabled_keeps_disabled_set(self):
        auth, s = make()
        s.user_admin("d", "停用", "bob", 0)
        doc = json.loads(
            s.batch_credential_change(
                "k",
                (item("alice", "pw", "a2"), item("bob", "pw", "b2")),
                0,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            doc["项目"],
            [
                {"用户": "alice", "结果": "回滚"},
                {"用户": "bob", "结果": "AuthError"},
            ],
        )
        self.assertIn("bob", s._disabled_users)
        self.assertEqual(auth.authenticate("alice", "pw", 0)[1], "ok")
        self.assertEqual(auth.authenticate("bob", "pw", 0)[1], "ok")
        # 停用项不认证，失败计数不变
        self.assertEqual(auth._users["bob"][1], 0)

    def test_all_fail_atomic(self):
        _auth, s = make()
        doc = json.loads(
            s.batch_credential_change(
                "k",
                (item("alice", "BAD", "a2"), ("ghost", "x", "y")),
                0,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            doc["项目"],
            [
                {"用户": "alice", "结果": "AuthError"},
                {"用户": "ghost", "结果": "KeyError"},
            ],
        )

    def test_later_items_judged_after_earlier_success(self):
        # 原子批：后项失败不阻止前项判定，且前项成功验证的清零对后项无影响
        # （用户互异）；回滚后仅凭据复原。
        auth, s = make()
        doc = json.loads(
            s.batch_credential_change(
                "k",
                (item("alice", "pw", "a2"), item("bob", "BAD", "b2")),
                0,
                atomic=True,
            )
        )
        self.assertEqual(doc["项目"][0]["结果"], "回滚")
        self.assertEqual(auth._users["bob"][1], 1)


class BatchCredentialNoSideEffectsTest(unittest.TestCase):
    def test_sessions_leases_queue_quota_disabled_unchanged(self):
        auth, s = make(pool=("10.0.0.0/24", (), ()))
        s = Sessions(auth, 1, 2, 5000, pool=("10.0.0.0/24", (), ()))
        r = json.loads(s.do("e1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["地址"], "10.0.0.1")
        ip_before = s._sessions["s1"]["ip"]
        pool_before = s._sessions["s1"]["pool"]
        q = json.loads(s.capacity("q", "申请", "s2", ("bob", "pw", 100000), 0))
        self.assertEqual(q["结果"], "排队")
        queue_before = list(s._queue_order)
        leases_before = {
            pool_id: dict(pool.leases) for pool_id, pool in s._pools.items()
        }
        account_before = len(s._account_events)
        # 原子回滚批
        s.batch_credential_change(
            "rb",
            (item("alice", "pw", "a2"), item("carol", "BAD", "c2")),
            100,
            atomic=True,
        )
        # 非原子部分成功批
        s.batch_credential_change(
            "nr",
            (item("bob", "pw", "b2"), item("carol", "BAD", "c3")),
            100,
        )
        self.assertEqual(s._sessions["s1"]["ip"], ip_before)
        self.assertEqual(s._sessions["s1"]["pool"], pool_before)
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertEqual(list(s._queue_order), queue_before)
        for pool_id, pool in s._pools.items():
            self.assertEqual(dict(pool.leases), leases_before[pool_id])
        self.assertEqual(len(s._account_events), account_before)
        self.assertEqual(s._disabled_users, set())

    def test_does_not_age(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        # idle_ms=10：s1 在时刻 0 建立，期限为 10；now_ms=100 的批量
        # 轮换不应触发老化（会话仍在线、期限不变）。
        s = Sessions(auth, 4, 2, 10, pool=("10.0.0.0/24", (), ()))
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        deadline_before = s._sessions["s1"]["deadline"]
        s.batch_credential_change("k", (item("bob"),), 100)
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertEqual(s._sessions["s1"]["deadline"], deadline_before)


class BatchCredentialCacheTest(unittest.TestCase):
    def test_replay_byte_identical_no_reauth(self):
        auth, s = make()
        items = (item("alice", "BAD", "a2"), item("bob", "pw", "b2"))
        out = s.batch_credential_change("k", items, 100)
        failed_after_first = auth._users["alice"][1]
        self.assertEqual(failed_after_first, 1)
        # 同参重放：逐字节相同，不再认证（失败计数不增）、不轮换
        out2 = s.batch_credential_change("k", items, 100)
        self.assertEqual(out2, out)
        self.assertEqual(auth._users["alice"][1], 1)
        # bob 仍只能用首调后的新口令
        self.assertEqual(auth.authenticate("bob", "b2", 100)[1], "ok")

    def test_replay_different_now_ms_still_replays(self):
        _auth, s = make()
        items = (item(),)
        out = s.batch_credential_change("k", items, 1)
        # now_ms 属于缓存参数；同参须包含相同时刻
        self.assertEqual(s.batch_credential_change("k", items, 1), out)
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", items, 2)

    def test_different_params_value_error(self):
        _auth, s = make()
        s.batch_credential_change("k", (item("alice"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", (item("bob"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", (item("alice", "pw", "zz"),), 0)
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", (item("alice"),), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", (item("alice"),), 1)
        # 异参不审计：再以原参重放仍为首果
        out = s.batch_credential_change("k", (item("alice"),), 0)
        self.assertEqual(json.loads(out)["结果"], "成功")

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("same", "建立", "sid", ("alice", "pw"), 0)
        out = s.batch_credential_change("same", (item("alice", "pw", "x"),), 0)
        self.assertEqual(json.loads(out)["结果"], "成功")
        # do 域不受影响
        r = json.loads(s.do("same", "建立", "sid", ("alice", "pw"), 0))
        self.assertEqual(r["状态"], "在线")
        # 单操作 credential_change 域独立
        with self.assertRaises(AuthError):
            s.credential_change("same", "alice", "pw", "y", 0)

    def test_atomic_replay_after_external_change_returns_first_bytes(self):
        auth, s = make()
        items = (item("alice", "pw", "a2"), item("bob", "pw", "b2"))
        out = s.batch_credential_change("k", items, 0, atomic=True)
        # 此后密码再被改掉，重放仍逐字节返回首果且不改密
        s.credential_change("c1", "alice", "a2", "a3", 0)
        out2 = s.batch_credential_change("k", items, 0, atomic=True)
        self.assertEqual(out2, out)
        self.assertEqual(auth.authenticate("alice", "a3", 0)[1], "ok")


class BatchCredentialAuditTest(unittest.TestCase):
    def test_first_call_records_item_results(self):
        _auth, s = make()
        items = (
            item("alice", "BAD", "a2"),
            item("bob", "pw", "b2"),
            ("ghost", "x", "g2"),
        )
        s.batch_credential_change("k", items, 55)
        self.assertEqual(
            batch_rows(s),
            [
                (1, "批量凭据轮换", "alice", "AuthError", 0),
                (2, "批量凭据轮换", "bob", "轮换", 0),
                (3, "批量凭据轮换", "ghost", "KeyError", 0),
            ],
        )

    def test_replay_points_to_first_items(self):
        _auth, s = make()
        items = (item("alice", "pw", "a2"), item("bob", "pw", "b2"))
        s.batch_credential_change("k", items, 0)
        s.batch_credential_change("k", items, 0)
        self.assertEqual(
            batch_rows(s),
            [
                (1, "批量凭据轮换", "alice", "轮换", 0),
                (2, "批量凭据轮换", "bob", "轮换", 0),
                (3, "批量凭据轮换", "alice", "重放", 1),
                (4, "批量凭据轮换", "bob", "重放", 2),
            ],
        )

    def test_atomic_flag_in_chain(self):
        _auth, s = make()
        s.batch_credential_change(
            "k", (item("alice", "pw", "a2"), item("bob", "BAD", "b2")),
            0, atomic=True,
        )
        events = s._batch_chain_events
        self.assertTrue(all(e[4] is True for e in events))
        self.assertEqual(
            [(e[5], e[6]) for e in events],
            [("alice", "回滚"), ("bob", "AuthError")],
        )

    def test_batch_audit_json_and_linking(self):
        _auth, s = make()
        s.batch_credential_change("k", (item("alice"),), 42)
        page = json.loads(s.batch_audit(limit=1000))
        self.assertEqual(list(page), ["下个序号", "事件"])
        e = page["事件"][0]
        self.assertEqual(
            list(e),
            ["序号", "时刻", "键", "操作", "原子", "会话", "结果",
             "原序号", "前哈希", "哈希"],
        )
        self.assertEqual(e["操作"], "批量凭据轮换")
        self.assertEqual(e["会话"], "alice")
        self.assertEqual(e["前哈希"], "0" * 64)
        self.assertEqual(len(e["哈希"]), 64)

    def test_not_written_to_single_audit_chain(self):
        _auth, s = make()
        s.credential_change("c", "carol", "pw", "c2", 0)
        s.batch_credential_change("k", (item("alice"),), 0)
        single_ops = [e[3] for e in s._chain_events]
        self.assertEqual(single_ops, ["凭据轮换"])
        batch_ops = [e[3] for e in s._batch_chain_events]
        self.assertEqual(batch_ops, ["批量凭据轮换"])

    def test_compliance_projection(self):
        _auth, s = make()
        s.batch_credential_change(
            "k", (item("alice"), item("bob", "pw", "b2")), 0
        )
        comp = json.loads(s.compliance_events(limit=1000))["事件"]
        self.assertEqual(len(comp), 2)
        for row in comp:
            self.assertEqual(row["来源"], "批量")
            payload = json.loads(row["载荷"])
            self.assertEqual(payload["操作"], "批量凭据轮换")
            self.assertEqual(list(payload)[0:6],
                             ["序号", "时刻", "键", "操作", "原子", "会话"])
        self.assertEqual(
            json.loads(comp[0]["载荷"])["会话"], "alice"
        )
        self.assertEqual(
            json.loads(comp[1]["载荷"])["会话"], "bob"
        )

    def test_param_errors_not_audited(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.batch_credential_change("k", (item("x", "a", "a"),), 0)
        with self.assertRaises(TypeError):
            s.batch_credential_change("t", 1, 0)
        self.assertEqual(batch_rows(s), [])
        self.assertEqual(json.loads(s.compliance_events(limit=10))["事件"], [])

    def test_deterministic_bytes(self):
        def run():
            auth = Authenticator(3, 1000)
            auth.add("alice", "pw")
            auth.add("bob", "pw")
            s = Sessions(auth, 4, 2, 5000)
            parts = [
                s.batch_credential_change(
                    "k",
                    (item("alice", "BAD", "a2"), item("bob", "pw", "b2")),
                    100,
                ),
                s.batch_credential_change(
                    "k",
                    (item("alice", "BAD", "a2"), item("bob", "pw", "b2")),
                    100,
                ),
                s.batch_audit(limit=1000),
            ]
            return "".join(parts)
        self.assertEqual(run(), run())


if __name__ == "__main__":
    unittest.main()
