import ipaddress
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


def add_p2(s, cidr="10.0.1.0/30", reserved=(), static=()):
    s.add_pool("p2", (cidr, reserved, static))


def ip(value):
    return int(ipaddress.IPv4Address(value))


def item(sid, target="p2", password="pw"):
    return (sid, target, password)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


class BatchMigrateParamTest(unittest.TestCase):
    def test_key_credential_rule_checked_first(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.batch_migrate(bad, (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("", [item("a")], 0)
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate("good", (item("a"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_types(self):
        _auth, s = make()
        for bad in ([item("a")], {item("a")}, "a", None,
                    (x for x in (item("a"),))):
            with self.assertRaises(TypeError):
                s.batch_migrate("k" + str(type(bad)), bad, 0)
        with self.assertRaises(TypeError):
            s.batch_migrate("t1", (["a", "p2", "pw"],), 0)
        with self.assertRaises(TypeError):
            s.batch_migrate("t2", ((1, "p2", "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_migrate("t3", (("a", None, "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_migrate("t4", (("a", "p2", b"pw"),), 0)
        for i, bad in enumerate((1.5, "0", None, True, False)):
            with self.assertRaises(TypeError):
                s.batch_migrate(f"n{i}", (item("a"),), bad)
        for i, bad in enumerate((0, 1, "false", None)):
            with self.assertRaises(TypeError):
                s.batch_migrate(f"at{i}", (item("a"),), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        with self.assertRaises(TypeError):
            s.batch_migrate("o1", [item("a"), item("a")], 1.5, atomic="x")
        with self.assertRaises(TypeError):
            s.batch_migrate("o2", (["a", "p2", "pw"],), "x")
        with self.assertRaises(TypeError):
            s.batch_migrate("o3", ((1, "p2"),), "x")
        with self.assertRaises(TypeError):
            s.batch_migrate("o4", (item("a"),), 1.5, atomic=0)

    def test_values_length_duplicates(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.batch_migrate("e0", (), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("e1", (("a", "p2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("e2", (("a", "p2", "pw", "x"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("v1", (("", "p2", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("v2", (("a", "p2\0", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("v3", (("a", "p2", ""),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("v4", (item("a"),), -1)
        with self.assertRaises(ValueError):
            s.batch_migrate("dup", (item("a"), item("a", "default")), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate(
                "dup2", (item("x"), item("y", "default"), item("x")), 0
            )

    def test_length_bounds(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        one = tuple(item(f"s{i:04d}") for i in range(1))
        thousand = tuple(item(f"s{i:04d}") for i in range(1000))
        thousand_one = tuple(item(f"s{i:04d}") for i in range(1001))
        # 全部未知 sid 为 KeyError 项结果，不抛异常。
        self.assertEqual(
            json.loads(s.batch_migrate("b1", one, 0))["结果"], "部分"
        )
        self.assertEqual(
            json.loads(s.batch_migrate("b1000", thousand, 0))["结果"], "部分"
        )
        with self.assertRaises(ValueError):
            s.batch_migrate("b1001", thousand_one, 0)


class BatchMigrateCacheTest(unittest.TestCase):
    def test_param_exception_is_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.batch_migrate("p", (item("a"), item("a")), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("p", (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("p", (item("a"), item("a")), 1)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        items = (item("a"),)
        out = s.batch_migrate("k", items, 10)
        self.assertEqual(s.batch_migrate("k", items, 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.batch_migrate("k", (item("a"),), 0)
        self.assertEqual(s._sessions["a"]["pool"], "p2")
        # 同参重放不再迁移，也不老化。
        s.batch_migrate("k", (item("a"),), 0)
        self.assertEqual(s._sessions["a"]["pool"], "p2")
        self.assertEqual(s._sessions["a"]["state"], "在线")

    def test_different_params_value_error(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.batch_migrate("k", (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a"),), 1)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("b"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a", "default"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a"),), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a"),), 0, atomic=0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        add_p2(s)
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        out = s.batch_migrate("same", (item("d"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        # do 域同 key 重放仍返回首次建立结果。
        replay = s.do("same", "建立", "d", ("alice", "pw"), 0)
        self.assertEqual(json.loads(replay)["状态"], "在线")
        # 与其余各域独立。
        self.assertEqual(
            json.loads(s.batch_online("same", (("e", "bob", "pw"),), 0))["结果"],
            "提交",
        )
        self.assertEqual(
            json.loads(s.batch_offline("same", ("d",), 0))["结果"], "提交"
        )
        self.assertEqual(
            json.loads(s.fault("same", "注入", 100, 0))["状态"], "故障"
        )
        # 同参重放逐字节相同；d 虽已被 batch_offline 下线，重放不改态。
        self.assertEqual(s.batch_migrate("same", (item("d"),), 0), out)


class BatchMigrateNonAtomicTest(unittest.TestCase):
    def test_all_commit_bytes(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        out = s.batch_migrate("k", (item("b"), item("a")), 10)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "迁移"},
                    {"会话": "a", "结果": "迁移"},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid in ("a", "b"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "在线")
            self.assertEqual(session["pool"], "p2")
            self.assertEqual(session["lease"], 10 + 100000)
        self.assertEqual(set(s._pools["p2"].leases.values()), {"a", "b"})
        self.assertEqual(s._pools["default"].leases, {})
        # 动态旧址回 default 堆。
        self.assertEqual(len(s._pools["default"].free),
                         s._pools["default"].capacity)

    def test_business_failures_per_item(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        s.do("e3", "建立", "c", ("carol", "pw"), 0)
        s.do("e4", "建立", "d", ("alice", "pw"), 0)
        items = (
            item("x"),                    # 未知 sid KeyError
            item("a"),                    # 迁移
            ("b", "nope", "pw"),          # 未知 target KeyError
            ("c", "p2", "bad"),           # 密码错 AuthError
            item("d"),                    # 迁移（不被前项失败阻断）
        )
        out = s.batch_migrate("k", items, 10)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("x", "KeyError"),
                ("a", "迁移"),
                ("b", "KeyError"),
                ("c", "AuthError"),
                ("d", "迁移"),
            ],
        )
        # a、d 已落 p2；b/c 失败留在 default。
        self.assertEqual(s._sessions["a"]["pool"], "p2")
        self.assertEqual(s._sessions["d"]["pool"], "p2")
        self.assertEqual(s._sessions["b"]["pool"], "default")
        self.assertEqual(s._sessions["c"]["pool"], "default")
        self.assertNotIn("x", s._sessions)
        # a 已在 p2：第二批再迁同池为 StateError。
        out = s.batch_migrate("k2", (item("a"),), 10)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "StateError")],
        )
        self.assertEqual(s._sessions["a"]["pool"], "p2")

    def test_target_exhausted_resource_error(self):
        # p2 仅 2 个可用动态址：第三个迁入项 ResourceError。
        _auth, s = make()
        add_p2(s)
        for sid in ("a", "b", "c"):
            user = {"a": "alice", "b": "bob", "c": "carol"}[sid]
            s.do("e" + sid, "建立", sid, (user, "pw"), 0)
        out = s.batch_migrate("k", tuple(item(x) for x in ("a", "b", "c")), 0)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "迁移"), ("b", "迁移"), ("c", "ResourceError")],
        )
        self.assertEqual(set(s._pools["p2"].leases.values()), {"a", "b"})
        self.assertEqual(s._sessions["c"]["pool"], "default")

    def test_previous_freed_address_counts(self):
        # 前项迁入 p2 占址，后项可见占用；前项释出的 default 址回堆。
        _auth, s = make()
        add_p2(s)
        for sid, user in (("a", "alice"), ("b", "bob"), ("c", "carol")):
            s.do("e" + sid, "建立", sid, (user, "pw"), 0)
        default = s._pools["default"]
        old_a = s._sessions["a"]["ip"]
        s.batch_migrate("k", (item("a"), item("b")), 0)
        # a 的旧址已回 default 堆。
        self.assertIn(old_a, default.free)
        # p2 两址被占，c 再迁失败。
        out = s.batch_migrate("k2", (item("c"),), 0)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("c", "ResourceError")],
        )

    def test_pool_fault_target_exhausted(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.pool_fault("pf", "注入", "p2", 100, 0)
        out = s.batch_migrate("k", (item("a"),), 50)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "ResourceError")],
        )
        self.assertEqual(s._sessions["a"]["pool"], "default")

    def test_static_address_occupied(self):
        # alice 在 p2 的静态址被其既有会话占用：后项 ResourceError。
        _auth, s = make()
        add_p2(s, static=(("alice", "10.0.1.1"),))
        s.do("e1", "建立", "old", ("alice", "pw"), 0)
        # old 先以静态址入 p2。
        s.do("m1", "迁移", "old", ("p2", "pw"), 0)
        s.do("e2", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate("k", (item("a"),), 0)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "ResourceError")],
        )
        self.assertEqual(s._sessions["a"]["pool"], "default")

    def test_suspended_session_state_error(self):
        # idle=100：a 在 t=200 老化为挂起并释址，迁移为 StateError。
        _auth, s = make(idle_ms=100, lease_ms=100000)
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate("k", (item("a"),), 200)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "StateError")],
        )
        self.assertEqual(s._sessions["a"]["state"], "挂起")
        self.assertIsNone(s._sessions["a"]["ip"])


class BatchMigrateAtomicTest(unittest.TestCase):
    def test_all_commit(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate("k", (item("a"),), 10, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": True,
                "结果": "提交",
                "项目": [{"会话": "a", "结果": "迁移"}],
            }),
        )
        self.assertEqual(s._sessions["a"]["pool"], "p2")
        self.assertEqual(set(s._pools["p2"].leases.values()), {"a"})

    def test_failure_rolls_back_sessions_pools_leases(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        a_before = dict(s._sessions["a"])
        out = s.batch_migrate(
            "k", (item("a"), item("x"), item("b")), 10, atomic=True
        )
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "回滚"), ("x", "KeyError"), ("b", "回滚")],
        )
        # 会话恢复至老化后快照。
        for sid, before in (("a", a_before),):
            session = s._sessions[sid]
            self.assertEqual(session["state"], before["state"])
            self.assertEqual(session["ip"], before["ip"])
            self.assertEqual(session["pool"], before["pool"])
            self.assertEqual(session["lease"], before["lease"])
        self.assertEqual(s._sessions["b"]["pool"], "default")
        # 池与租约恢复：p2 全空，default 两租约。
        self.assertEqual(s._pools["p2"].leases, {})
        self.assertEqual(len(s._pools["p2"].free), s._pools["p2"].capacity)
        self.assertEqual(set(s._pools["default"].leases.values()), {"a", "b"})

    def test_multiple_failures_first_recorded_rest_rollback(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate(
            "k",
            (item("x"), item("a"), item("y")),
            0,
            atomic=True,
        )
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("x", "KeyError"), ("a", "回滚"), ("y", "回滚")],
        )
        self.assertEqual(s._sessions["a"]["pool"], "default")
        self.assertEqual(s._pools["p2"].leases, {})

    def test_rollback_preserves_aging(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        add_p2(s)
        s.do("e1", "建立", "old", ("alice", "pw"), 0)
        out = s.batch_migrate(
            "k", (item("old"), item("x")), 200, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        session = s._sessions["old"]
        self.assertEqual(session["state"], "挂起")
        self.assertIsNone(session["ip"])
        self.assertIsNone(session["pool"])

    def test_rollback_preserves_auth_counts(self):
        auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        before = auth._users["alice"][1]
        out = s.batch_migrate(
            "k", (item("a", "p2", "bad"), item("x")), 0, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(auth._users["alice"][1], before + 1)  # 失败计数保留
        self.assertEqual(s._sessions["a"]["pool"], "default")

    def test_rollback_preserves_backoff(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.fault("f", "注入", 100, 0)
        out = s.batch_migrate("k", (item("a"), item("x")), 0, atomic=True)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "BackendError"), ("x", "回滚")],
        )
        self.assertEqual(s._backoff["alice"], (1, 100))
        self.assertEqual(s._sessions["a"]["pool"], "default")
        self.assertEqual(s._pools["p2"].leases, {})
        # 不计 fault_stats。
        stats = json.loads(s.fault_stats(0))
        self.assertEqual(stats["失败"], [
            {"类型": "故障", "次数": 0},
            {"类型": "退避", "次数": 0},
        ])

    def test_rollback_static_lease_released_not_heaped(self):
        _auth, s = make()
        add_p2(s, static=(("alice", "10.0.1.1"),))
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate(
            "k", (item("a"), item("x")), 0, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        p2 = s._pools["p2"]
        static_ip = next(iter(p2.static_ips))
        self.assertNotIn(static_ip, p2.leases)
        self.assertNotIn(static_ip, p2.free)
        # a 回到 default 原态。
        self.assertEqual(s._sessions["a"]["pool"], "default")
        # 回滚后静态址可再迁。
        out = s.batch_migrate("k2", (item("a"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        self.assertEqual(s._sessions["a"]["ip"], static_ip)

    def test_rollback_replay_does_not_mutate(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        items = (item("a"), item("x"))
        first = s.batch_migrate("k", items, 10, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        self.assertEqual(
            s.batch_migrate("k", items, 10, atomic=True), first
        )
        self.assertEqual(s._sessions["a"]["pool"], "default")
        self.assertEqual(s._pools["p2"].leases, {})


def _bounce_setup():
    """default=/29、p2=/30；a,b 持 default .1/.2，c 持 p2 .1。"""
    _auth, s = make(pool=("10.0.0.0/29", (), ()))
    add_p2(s)
    s.do("ea", "建立", "a", ("alice", "pw"), 0)
    s.do("eb", "建立", "b", ("bob", "pw"), 0)
    s.do("ec", "建立", "c", ("carol", "pw"), 0)
    s.do("mc", "迁移", "c", ("p2", "pw"), 0)
    return s


_BOUNCE_ITEMS = (
    ("c", "default", "pw"),  # c 出 p2（p2.1 入 reclaimed）入 default
    ("a", "p2", "pw"),       # a 取 reclaimed 中更小的 p2.1
    ("b", "p2", "pw"),       # b 取原 p2 堆的 p2.2
)


class BatchMigrateReclaimedTest(unittest.TestCase):
    def test_atomic_matches_sequential_when_all_commit(self):
        seq = _bounce_setup()
        seq.batch_migrate("ks", _BOUNCE_ITEMS, 0, atomic=False)
        atm = _bounce_setup()
        atm.batch_migrate("ka", _BOUNCE_ITEMS, 0, atomic=True)
        # 两种模式全部成功后会话落点、租约与各池空闲堆逐址一致。
        self.assertEqual(
            {k: (v["pool"], v["ip"]) for k, v in seq._sessions.items()},
            {k: (v["pool"], v["ip"]) for k, v in atm._sessions.items()},
        )
        for pool_id in ("default", "p2"):
            sp, ap = seq._pools[pool_id], atm._pools[pool_id]
            self.assertEqual(sp.leases, ap.leases, pool_id)
            self.assertEqual(sorted(sp.free), sorted(ap.free), pool_id)
        # 落点：c 回 default，a/b 占 p2 两址。
        self.assertEqual(seq._sessions["c"]["pool"], "default")
        self.assertEqual(
            {seq._sessions["a"]["ip"], seq._sessions["b"]["ip"]},
            {ip("10.0.1.1"), ip("10.0.1.2")},
        )

    def test_rollback_after_reclaimed_reuse_restores_snapshot(self):
        s = _bounce_setup()
        default = s._pools["default"]
        p2 = s._pools["p2"]
        before = {
            "sessions": {k: dict(v) for k, v in s._sessions.items()},
            "default_leases": dict(default.leases),
            "p2_leases": dict(p2.leases),
            "default_free": sorted(default.free),
            "p2_free": sorted(p2.free),
        }
        out = s.batch_migrate(
            "k", _BOUNCE_ITEMS + (("x", "p2", "pw"),), 0, atomic=True
        )
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("c", "回滚"), ("a", "回滚"), ("b", "回滚"), ("x", "KeyError")],
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        # 会话逐字段回到老化后快照。
        for sid, old in before["sessions"].items():
            self.assertEqual(dict(s._sessions[sid]), old, sid)
        self.assertEqual(dict(default.leases), before["default_leases"])
        self.assertEqual(dict(p2.leases), before["p2_leases"])
        self.assertEqual(sorted(default.free), before["default_free"])
        self.assertEqual(sorted(p2.free), before["p2_free"])
        # 回滚后可整体成功再提交，落点与逐址同非原子。
        s.batch_migrate("k2", _BOUNCE_ITEMS, 0, atomic=True)
        ref = _bounce_setup()
        ref.batch_migrate("kr", _BOUNCE_ITEMS, 0, atomic=False)
        self.assertEqual(
            {k: (v["pool"], v["ip"]) for k, v in s._sessions.items()},
            {k: (v["pool"], v["ip"]) for k, v in ref._sessions.items()},
        )


class BatchMigrateNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        s.batch_migrate("n1", (item("a"), item("x")), 10)
        s.batch_migrate("n1", (item("a"), item("x")), 10)
        s.batch_migrate("r1", (item("a"), item("y")), 10, atomic=True)
        s.batch_migrate("r1", (item("a"), item("y")), 10, atomic=True)
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        self.assertEqual(len(after_chain), before_chain)
        self.assertEqual(len(after_cap), before_cap)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_no_user_runtime_stats_on_business_failures(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "c", ("carol", "pw"), 0)
        # 非原子：未知 sid、错误密码各一，c 正常迁入（认证失败计数保留但
        # 不入 user_stats/runtime_stats）。
        s.batch_migrate(
            "n1", (item("x"), ("a", "p2", "bad"), item("c")), 0
        )
        # 原子回滚（未知 target）。
        s.batch_migrate("r1", (item("a"), ("c", "nope", "pw")), 0, atomic=True)
        runtime = json.loads(s.runtime_stats(0))
        self.assertEqual(runtime["失败"], [
            {"类型": "认证", "次数": 0},
            {"类型": "资源", "次数": 0},
            {"类型": "状态", "次数": 0},
            {"类型": "后端", "次数": 0},
        ])
        user = json.loads(s.user_stats("alice", 0))
        self.assertEqual(user["失败"], [
            {"类型": "认证", "次数": 0},
            {"类型": "资源", "次数": 0},
            {"类型": "状态", "次数": 0},
            {"类型": "后端", "次数": 0},
        ])

    def test_backend_failure_not_counted_in_fault_stats(self):
        _auth, s = make()
        add_p2(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.fault("f", "注入", 100, 0)
        s.batch_migrate("n1", (item("a"),), 0)
        s.batch_migrate("r1", (item("a"), item("x")), 0, atomic=True)
        # 退避保留。
        self.assertEqual(s._backoff["alice"], (1, 100))
        # 不计 fault_stats（其口径仅 do 与 capacity）。
        fault = json.loads(s.fault_stats(0))
        self.assertEqual(fault["失败"], [
            {"类型": "故障", "次数": 0},
            {"类型": "退避", "次数": 0},
        ])


if __name__ == "__main__":
    unittest.main()
