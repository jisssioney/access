import json
import unittest

from access import Sessions, Authenticator, StateError, AuthError


def make(pool=("10.0.0.0/28", ("10.0.0.9",), ())):
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob", "carol"):
        auth.add(user, "pw")
    return Sessions(auth, 8, 4, 5000, pool=pool, lease_ms=1000)


def queued_pool():
    return ("10.0.0.0/28", (), ())


class BatchUserAdminValidationTest(unittest.TestCase):
    def call(self, s, *args, **kwargs):
        with self.assertRaises(TypeError):
            s.batch_user_admin(*args, **kwargs)

    def test_container_and_item_types(self):
        s = make()
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", [("停用", "alice", False)], 0)
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", (["停用", "alice", False],), 0)
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", ((1, "alice", False),), 0)
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", (("停用", 1, False),), 0)
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", (("停用", "alice", 0),), 0)
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", (("停用", "alice", False),), True)
        with self.assertRaises(TypeError):
            s.batch_user_admin("k", (("停用", "alice", False),), 0, 0)
        # 短元组只报取值错（长度），不越界。
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("停用", "alice"),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("停用", "alice", False, 1),), 0)

    def test_value_errors(self):
        s = make()
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (), 0)
        big = tuple(("停用", f"u{i:04d}", False) for i in range(1001))
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", big, 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("冻结", "alice", False),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("停用", "", False),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("停用", "a\0b", False),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin(
                "k",
                (("停用", "alice", False), ("启用", "alice", False)),
                0,
            )
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("启用", "alice", True),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("k", (("停用", "alice", False),), -1)
        self.assertEqual(s._batch_chain_events, [])
        self.assertEqual(s._disabled_users, set())

    def test_param_errors_do_not_occupy_key(self):
        s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.batch_user_admin("z", (), 0)
        out = json.loads(
            s.batch_user_admin("z", (("启用", "alice", False),), 0)
        )
        self.assertEqual(out["结果"], "成功")
        self.assertEqual(len(s._batch_chain_events), 1)


class BatchUserAdminResultTest(unittest.TestCase):
    def test_shape_and_key_order(self):
        s = make()
        out = s.batch_user_admin(
            "k", (("停用", "alice", False), ("启用", "bob", False)), 42
        )
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        doc = json.loads(out)
        self.assertEqual(list(doc), ["时刻", "原子", "结果", "项目"])
        self.assertEqual(
            (doc["时刻"], doc["原子"], doc["结果"]), (42, False, "成功")
        )
        for item in doc["项目"]:
            self.assertEqual(list(item), ["操作", "用户", "结果", "下线", "取消"])
        self.assertEqual(
            doc["项目"],
            [
                {"操作": "停用", "用户": "alice", "结果": "成功", "下线": 0, "取消": 0},
                {"操作": "启用", "用户": "bob", "结果": "成功", "下线": 0, "取消": 0},
            ],
        )
        self.assertIn("alice", s._disabled_users)

    def test_partial_unknown_and_stateerror_continue(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        doc = json.loads(
            s.batch_user_admin(
                "b",
                (
                    ("停用", "ghost", False),
                    ("停用", "alice", False),
                    ("停用", "carol", False),
                    ("启用", "bob", False),
                ),
                100,
            )
        )
        self.assertEqual(doc["结果"], "部分成功")
        self.assertEqual(
            [(i["用户"], i["结果"], i["下线"], i["取消"]) for i in doc["项目"]],
            [
                ("ghost", "KeyError", 0, 0),
                ("alice", "StateError", 0, 0),
                ("carol", "成功", 0, 0),
                ("bob", "成功", 0, 0),
            ],
        )
        self.assertNotIn("alice", s._disabled_users)
        self.assertIn("carol", s._disabled_users)
        self.assertEqual(s._sessions["s1"]["state"], "在线")

    def test_all_failed(self):
        s = make()
        doc = json.loads(
            s.batch_user_admin("b", (("停用", "ghost", False),), 0)
        )
        self.assertEqual(doc["结果"], "失败")

    def test_suspended_session_blocks_non_force(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.pool_stats(90000)
        doc = json.loads(
            s.batch_user_admin("sus", (("停用", "alice", False),), 90000)
        )
        self.assertEqual(doc["项目"][0]["结果"], "StateError")
        self.assertEqual(s._sessions["s1"]["state"], "挂起")

    def test_no_aging(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.batch_user_admin("ag", (("启用", "bob", False),), 999999)
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        self.assertIsNotNone(s._sessions["s1"]["ip"])


class BatchUserAdminForceTest(unittest.TestCase):
    def make_two(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(
            auth, 8, 8, 50000, pool=("10.0.0.0/28", (), ()), lease_ms=100000
        )
        s.do("e1", "建立", "z1", ("alice", "pw"), 0)
        s.do("e2", "建立", "a2", ("alice", "pw"), 0)
        s.do("e3", "建立", "m3", ("bob", "pw"), 0)
        return s

    def test_force_counts_and_ordering(self):
        s = self.make_two()
        doc = json.loads(
            s.batch_user_admin(
                "f",
                (("停用", "bob", True), ("停用", "alice", True)),
                50,
            )
        )
        self.assertEqual(doc["结果"], "成功")
        self.assertEqual(
            (doc["项目"][0]["下线"], doc["项目"][0]["取消"]), (1, 0)
        )
        self.assertEqual(
            (doc["项目"][1]["下线"], doc["项目"][1]["取消"]), (2, 0)
        )
        for sid in ("z1", "a2", "m3"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "下线")
            self.assertEqual(session["deadline"], 0)
            self.assertIsNone(session["ip"])
            self.assertEqual(session["lease"], 0)
            self.assertIsNone(session["pool"])
        self.assertEqual(s._disabled_users, {"alice", "bob"})
        self.assertEqual(s._pools["default"].leases, {})
        self.assertEqual(len(s._pools["default"].free), 14)

    def test_stop_events_ordered_by_item_then_sid(self):
        s = self.make_two()
        s.batch_user_admin(
            "f",
            (("停用", "bob", True), ("停用", "alice", True)),
            50,
        )
        events = json.loads(s.accounting_events())["事件"]
        stops = [(e["会话"], e["原因"]) for e in events if e["类型"] == "停止"]
        self.assertEqual(
            stops,
            [("m3", "停用"), ("a2", "停用"), ("z1", "停用")],
        )

    def test_queue_cancellation_keeps_other_users(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(
            auth, 1, 4, 50000, pool=queued_pool(), lease_ms=100000
        )
        s.do("occ", "建立", "occ", ("alice", "pw"), 0)
        s.capacity("qa", "申请", "qa1", ("alice", "pw", 1000), 0)
        s.capacity("qb", "申请", "qb1", ("bob", "pw", 1000), 0)
        s.capacity("qa2", "申请", "qa2", ("alice", "pw", 1000), 0)
        doc = json.loads(
            s.batch_user_admin("fq", (("停用", "alice", True),), 5)
        )
        self.assertEqual(
            doc["项目"][0],
            {"操作": "停用", "用户": "alice", "结果": "成功", "下线": 1, "取消": 2},
        )
        self.assertEqual(s._queue_order, ["qb1"])
        self.assertEqual(list(s._capacity_queue), ["qb1"])

    def test_homomorphic_zero(self):
        s = make()
        s.user_admin("d", "停用", "alice", 0)
        doc = json.loads(
            s.batch_user_admin("h", (("停用", "alice", True),), 1)
        )
        self.assertEqual(
            (doc["项目"][0]["下线"], doc["项目"][0]["取消"]), (0, 0)
        )


class BatchUserAdminAtomicTest(unittest.TestCase):
    def test_rollback_preserves_everything(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(
            auth, 1, 4, 50000, pool=queued_pool(), lease_ms=100000
        )
        s.do("occ", "建立", "occ", ("alice", "pw"), 0)
        s.capacity("qa", "申请", "qa1", ("alice", "pw", 1000), 0)
        s.capacity("qb", "申请", "qb1", ("bob", "pw", 1000), 0)
        sessions_snapshot = {k: dict(v) for k, v in s._sessions.items()}
        queue_snapshot = list(s._queue_order)
        qmap_snapshot = dict(s._capacity_queue)
        account_n = len(s._account_events)
        account_tail = s._account_tail
        leases_snapshot = dict(s._pools["default"].leases)
        free_snapshot = list(s._pools["default"].free)
        doc = json.loads(
            s.batch_user_admin(
                "atom",
                (
                    ("停用", "alice", True),
                    ("停用", "ghost", False),
                    ("停用", "bob", False),
                ),
                5,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(i["用户"], i["结果"], i["下线"], i["取消"]) for i in doc["项目"]],
            [
                ("alice", "回滚", 0, 0),
                ("ghost", "KeyError", 0, 0),
                ("bob", "StateError", 0, 0),
            ],
        )
        self.assertEqual(set(s._sessions), set(sessions_snapshot))
        for sid, snapshot in sessions_snapshot.items():
            self.assertEqual(dict(s._sessions[sid]), snapshot)
        self.assertEqual(s._queue_order, queue_snapshot)
        self.assertEqual(dict(s._capacity_queue), qmap_snapshot)
        self.assertEqual(len(s._account_events), account_n)
        self.assertEqual(s._account_tail, account_tail)
        self.assertEqual(s._disabled_users, set())
        self.assertEqual(dict(s._pools["default"].leases), leases_snapshot)
        self.assertEqual(list(s._pools["default"].free), free_snapshot)

    def test_rollback_appends_no_account_events(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(
            auth, 8, 8, 50000, pool=queued_pool(), lease_ms=100000
        )
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.do("e2", "建立", "s2", ("alice", "pw"), 0)
        before = len(s._account_events)
        s.batch_user_admin(
            "rb",
            (("停用", "alice", True), ("停用", "ghost", True)),
            5,
            atomic=True,
        )
        self.assertEqual(len(s._account_events), before)
        for sid in ("s1", "s2"):
            self.assertEqual(s._sessions[sid]["state"], "在线")
            self.assertIsNotNone(s._sessions[sid]["ip"])

    def test_all_success_commits(self):
        s = make()
        doc = json.loads(
            s.batch_user_admin(
                "ok",
                (("启用", "bob", False), ("停用", "carol", False)),
                0,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "成功")
        self.assertIn("carol", s._disabled_users)


class BatchUserAdminCacheTest(unittest.TestCase):
    def test_replay_byte_identical_and_no_effect(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        first = s.batch_user_admin("K", (("停用", "alice", True),), 10)
        self.assertEqual(
            s.batch_user_admin("K", (("停用", "alice", True),), 10), first
        )
        s.batch_user_admin("en", (("启用", "alice", False),), 20)
        s.do("e2", "建立", "s9", ("alice", "pw"), 20)
        replay = s.batch_user_admin("K", (("停用", "alice", True),), 10)
        self.assertEqual(replay, first)
        self.assertEqual(s._sessions["s9"]["state"], "在线")
        self.assertNotIn("alice", s._disabled_users)

    def test_replay_audit_events(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.batch_user_admin("K", (("停用", "alice", True),), 10)
        s.batch_user_admin("K", (("停用", "alice", True),), 10)
        rows = [
            (e[3], e[5], e[6], e[7])
            for e in s._batch_chain_events
            if e[2] == "K"
        ]
        self.assertEqual(
            rows,
            [
                ("批量用户管理", "alice", "成功", 0),
                ("批量用户管理", "alice", "重放", 1),
            ],
        )
        # 不写单操作审计链。
        self.assertTrue(
            all(
                e[3] not in ("用户停用", "用户启用")
                for e in s._chain_events
            )
        )
        # 合规链投影批量事件。
        comp = json.loads(s.compliance_events())["事件"]
        projected = [
            e for e in comp if e["来源"] == "批量" and '"键":"K"' in e["载荷"]
        ]
        self.assertEqual(len(projected), 2)

    def test_partial_first_call_cached_and_replayed(self):
        s = make()
        args = (("停用", "ghost", False),)
        first = s.batch_user_admin("P", args, 0)
        self.assertEqual(s.batch_user_admin("P", args, 0), first)
        rows = [
            (e[6], e[7])
            for e in s._batch_chain_events
            if e[2] == "P"
        ]
        self.assertEqual(rows, [("KeyError", 0), ("重放", 1)])

    def test_different_params_value_error(self):
        s = make()
        s.batch_user_admin("K", (("停用", "alice", False),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("K", (("启用", "alice", False),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("K", (("停用", "bob", False),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin("K", (("停用", "alice", False),), 1)
        with self.assertRaises(ValueError):
            s.batch_user_admin("K", (("停用", "alice", True),), 0)
        with self.assertRaises(ValueError):
            s.batch_user_admin(
                "K", (("停用", "alice", False),), 0, atomic=True
            )

    def test_domain_isolated_from_user_admin(self):
        s = make()
        s.batch_user_admin("same", (("停用", "alice", False),), 0)
        out = json.loads(s.user_admin("same", "启用", "alice", 1))
        self.assertEqual(out["状态"], "启用")


class BatchUserAdminGateTest(unittest.TestCase):
    def test_disabled_gate_after_batch(self):
        s = make()
        s.batch_user_admin("g", (("停用", "alice", False),), 0)
        with self.assertRaises(AuthError):
            s.do("x", "建立", "sx", ("alice", "x"), 100)
        self.assertEqual(s._auth._users["alice"][1], 0)


if __name__ == "__main__":
    unittest.main()
