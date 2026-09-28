import ipaddress
import json
import unittest

from access import (
    Authenticator,
    BackendError,
    Sessions,
)


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def add_pool(s, pool_id="p2", cidr="10.1.0.0/24", reserved=(), static=()):
    s.add_pool(pool_id, (cidr, tuple(reserved), tuple(static)))


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def item(sid, target="p2", password="pw"):
    return (sid, target, password)


def snapshot(s):
    """老化后可变态快照：会话表与各池 free 堆（逐格）、租用表。"""
    sessions = {sid: dict(session) for sid, session in s._sessions.items()}
    pools = {
        pool_id: (list(pool.free), dict(pool.leases))
        for pool_id, pool in s._pools.items()
    }
    return sessions, pools


class BatchMigrateParamTest(unittest.TestCase):
    def test_key_credential_rule_checked_first(self):
        _auth, s = make()
        add_pool(s)
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.batch_migrate(bad, (item("a"),), 0)
        # 空串 key 为取值错，先于 items 容器类型错。
        with self.assertRaises(ValueError):
            s.batch_migrate("", [item("a")], 0)
        # key 非法在缓存查表之前抛出，故不留缓存、不影响任何合法 key。
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_migrate("good", (item("a"),), 1)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_types(self):
        _auth, s = make()
        # items 必须是 tuple：list/set/str/None/生成器均 TypeError。
        for bad in ([item("a")], {item("a")}, "a", None,
                    (x for x in (item("a"),))):
            with self.assertRaises(TypeError):
                s.batch_migrate("k" + str(type(bad)), bad, 0)
        # 每个 item 必须是 tuple。
        with self.assertRaises(TypeError):
            s.batch_migrate("t1", (["a", "p2", "pw"],), 0)
        # 三项串必须是 str。
        with self.assertRaises(TypeError):
            s.batch_migrate("t2", ((1, "p2", "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_migrate("t3", (("a", None, "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_migrate("t4", (("a", "p2", b"pw"),), 0)
        # now_ms 为非 bool int。
        for i, bad in enumerate((1.5, "0", None, True, False)):
            with self.assertRaises(TypeError):
                s.batch_migrate(f"n{i}", (item("a"),), bad)
        # atomic 为 bool。
        for i, bad in enumerate((0, 1, "false", None)):
            with self.assertRaises(TypeError):
                s.batch_migrate(f"at{i}", (item("a"),), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        # 容器类型错先于 now_ms 类型/取值与重复。
        with self.assertRaises(TypeError):
            s.batch_migrate("o1", [item("a"), item("a")], 1.5, atomic="x")
        # 项类型错先于 now_ms 类型错。
        with self.assertRaises(TypeError):
            s.batch_migrate("o2", (["a", "p2", "pw"],), "x")
        # 串类型错先于项长度取值错与 now_ms 类型错。
        with self.assertRaises(TypeError):
            s.batch_migrate("o3", ((1, "p2"),), "x")
        # now_ms 类型错先于 atomic 类型错。
        with self.assertRaises(TypeError):
            s.batch_migrate("o4", (item("a"),), 1.5, atomic=0)

    def test_values_length_duplicates(self):
        _auth, s = make()
        # 空批 ValueError。
        with self.assertRaises(ValueError):
            s.batch_migrate("e0", (), 0)
        # 项须为三元组。
        with self.assertRaises(ValueError):
            s.batch_migrate("e1", (("a", "p2"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("e2", (("a", "p2", "pw", "x"),), 0)
        # 三项串沿用凭据约束。
        with self.assertRaises(ValueError):
            s.batch_migrate("v1", (("", "p2", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("v2", (("a", "p2\x00", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("v3", (("a", "p2", ""),), 0)
        # now_ms 非负。
        with self.assertRaises(ValueError):
            s.batch_migrate("v4", (item("a"),), -1)
        # 重复 sid ValueError（即使 target/password 不同）。
        with self.assertRaises(ValueError):
            s.batch_migrate("dup", (item("a"), ("a", "p3", "pw")), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate(
                "dup2",
                (item("x"), item("y", "p3"), item("x", "p4")),
                0,
            )

    def test_length_bounds(self):
        _auth, s = make()
        add_pool(s)
        one = tuple(item(f"s{i:04d}") for i in range(1))
        thousand = tuple(item(f"s{i:04d}") for i in range(1000))
        thousand_one = tuple(item(f"s{i:04d}") for i in range(1001))
        self.assertEqual(len(one), 1)
        self.assertEqual(len(thousand), 1000)
        self.assertEqual(len(thousand_one), 1001)
        # 单项存在则提交；不存在的千项全部 KeyError，非原子记“部分”。
        s.do("e0", "建立", "s0000", ("alice", "pw"), 0)
        self.assertEqual(json.loads(s.batch_migrate("b1", one, 0))["结果"],
                         "提交")
        self.assertEqual(
            json.loads(s.batch_migrate("b1000", thousand, 0))["结果"], "部分"
        )
        with self.assertRaises(ValueError):
            s.batch_migrate("b1001", thousand_one, 0)

    def test_zero_pool_state_error(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 10, 10, 100000)
        out = s.batch_migrate("k", (("a", "p2", "pw"),), 0)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "StateError")],
        )


class BatchMigrateCacheTest(unittest.TestCase):
    def test_param_exception_is_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.batch_migrate("p", (item("a"), item("a")), 0)
        # 首果为异常：异参复用仍 ValueError。
        with self.assertRaises(ValueError):
            s.batch_migrate("p", (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("p", (item("a"), item("a")), 1)

    def test_type_exception_is_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(TypeError):
                s.batch_migrate("p", [item("a")], 0)
        # 同型同参重放仍 TypeError；异参 ValueError。
        with self.assertRaises(TypeError):
            s.batch_migrate("p", [item("a")], 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("p", (item("a"),), 0)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        items = (item("a"), item("b"))
        out = s.batch_migrate("k", items, 10)
        self.assertEqual(s.batch_migrate("k", items, 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)  # a 在 default
        s.batch_migrate("k", (item("a"),), 0)  # a 迁至 p2，缓存 now=0
        self.assertEqual(s._sessions["a"]["pool"], "p2")
        # 此后以晚于 a 期限的时刻重放旧 key（同参 now 仍 0），不得老化 a。
        s.batch_migrate("k", (item("a"),), 0)
        session = s._sessions["a"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])
        self.assertEqual(session["pool"], "p2")
        # 重放不重复迁移：两池租约总数仍为 1。
        total_leases = sum(len(p.leases) for p in s._pools.values())
        self.assertEqual(total_leases, 1)
        self.assertEqual(len(s._pools["default"].leases), 0)
        self.assertEqual(len(s._pools["p2"].leases), 1)

    def test_different_params_value_error(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.batch_migrate("k", (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a"),), 1)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("b"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (("a", "p2", "bad"),), 0)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (("a", "p3", "pw"),), 0)
        # atomic 标志不同亦为异参；类型差异同样归 ValueError。
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a"),), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.batch_migrate("k", (item("a"),), 0, atomic=0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        add_pool(s)
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        # batch_migrate 与 do 同名字符串 key 互不指认。
        out = s.batch_migrate("same", (item("d"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        # do 域同 key 重放仍返回首次建立结果。
        replay = s.do("same", "建立", "d", ("alice", "pw"), 0)
        self.assertEqual(json.loads(replay)["状态"], "在线")
        # 与各批量/故障域独立。
        self.assertEqual(
            json.loads(s.batch_offline("same", ("d",), 0))["结果"], "提交"
        )
        self.assertEqual(
            json.loads(s.batch_online(
                "same", (("e", "bob", "pw"),), 0))["结果"],
            "提交",
        )
        self.assertEqual(
            json.loads(s.fault("same", "注入", 100, 0))["状态"], "故障"
        )
        self.assertEqual(
            json.loads(s.pool_fault("same", "注入", "default", 100, 0))["状态"],
            "耗尽",
        )
        self.assertEqual(
            json.loads(s.timeout_fault("same", "注入", 0, 0))["状态"], "等待"
        )
        out2 = s.batch_migrate("same", (item("d"),), 0)
        self.assertEqual(out2, out)


class BatchMigrateNonAtomicTest(unittest.TestCase):
    def test_all_commit(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        out = s.batch_migrate(
            "k", (("a", "p2", "pw"), ("b", "p2", "pw")), 10
        )
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "a", "结果": "迁移"},
                    {"会话": "b", "结果": "迁移"},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid in ("a", "b"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "在线")
            self.assertEqual(session["pool"], "p2")
            self.assertEqual(session["deadline"], 100000)  # 期限不变
            self.assertEqual(session["lease"], 10 + 100000)  # 租期重置
            self.assertIsNotNone(session["ip"])
        self.assertEqual(len(s._pools["default"].leases), 0)
        self.assertEqual(len(s._pools["p2"].leases), 2)
        # 动态旧址回本池堆：/24 可用址 254 个，两址全部退回。
        self.assertEqual(len(s._pools["default"].free), 254)

    def test_failure_classes_dont_block_later(self):
        _auth, s = make()
        add_pool(s)
        for sid in ("a", "b", "c", "d", "e"):
            s.do("e" + sid, "建立", sid, ("alice", "pw"), 0)
        s.do("off", "下线", "c", None, 0)  # 下线墓碑，无址
        items = (
            ("z", "p2", "pw"),       # 未知 sid KeyError
            ("a", "nope", "pw"),     # 未知目标池 KeyError
            ("b", "default", "pw"),  # 同池 StateError
            ("c", "p2", "pw"),       # 下线无址 StateError
            ("d", "p2", "bad"),      # 密码错 AuthError
            ("e", "p2", "pw"),       # 迁移成功
        )
        out = s.batch_migrate("k", items, 10)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("z", "KeyError"),
                ("a", "KeyError"),
                ("b", "StateError"),
                ("c", "StateError"),
                ("d", "AuthError"),
                ("e", "迁移"),
            ],
        )
        # 仅 e 迁至 p2；失败项不留变更。
        self.assertEqual(s._sessions["e"]["pool"], "p2")
        self.assertEqual(s._sessions["a"]["pool"], "default")
        self.assertEqual(s._sessions["b"]["pool"], "default")
        self.assertEqual(s._sessions["d"]["pool"], "default")
        self.assertEqual(s._sessions["c"]["pool"], None)
        self.assertEqual(s._sessions["c"]["state"], "下线")
        self.assertEqual(len(s._pools["p2"].leases), 1)
        self.assertEqual(len(s._pools["default"].leases), 3)

    def test_earlier_release_affects_later_target(self):
        # 目标池仅一址：前项占用后后项 ResourceError。
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        add_pool(s, pool_id="tiny", cidr="10.1.0.0/32")
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        out = s.batch_migrate("k", (("a", "tiny", "pw"), ("b", "tiny", "pw")), 0)
        self.assertEqual(
            [it["结果"] for it in json.loads(out)["项目"]],
            ["迁移", "ResourceError"],
        )
        self.assertEqual(s._sessions["a"]["pool"], "tiny")
        self.assertEqual(s._sessions["b"]["pool"], "default")

    def test_released_addresses_can_be_reacquired(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        add_pool(s, cidr="10.1.0.0/30")
        s.do("e1", "建立", "a", ("alice", "pw"), 0)  # .1
        s.do("e2", "建立", "b", ("bob", "pw"), 0)    # .2
        s.batch_migrate(
            "k", (("a", "p2", "pw"), ("b", "p2", "pw")), 0
        )
        # 前一批释出的 default 动态址，后一批按最小址重新取得。
        out = s.batch_migrate(
            "k2", (("a", "default", "pw"), ("b", "default", "pw")), 0
        )
        self.assertEqual(json.loads(out)["结果"], "提交")
        self.assertEqual(
            s._sessions["a"]["ip"], int(ipaddress.IPv4Address("10.0.0.1"))
        )
        self.assertEqual(
            s._sessions["b"]["ip"], int(ipaddress.IPv4Address("10.0.0.2"))
        )

    def test_target_pool_exhausted_injection(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.pool_fault("pf", "注入", "p2", 100, 0)
        out = s.batch_migrate("k", (("a", "p2", "pw"),), 50)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "ResourceError")],
        )
        self.assertEqual(s._sessions["a"]["pool"], "default")

    def test_static_address_occupied(self):
        # alice 仅在 p2 有静态址；两个 alice 会话先以动态址落在 default。
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        add_pool(s, cidr="10.1.0.0/30", static=(("alice", "10.1.0.1"),))
        s.do("e1", "建立", "a", ("alice", "pw"), 0)  # default .1
        s.do("e2", "建立", "c", ("alice", "pw"), 0)  # default .2
        # 先把 a 迁至 p2 占用 alice 在 p2 的静态址；c 再迁 p2 即静态占用。
        out = s.batch_migrate(
            "k",
            (("a", "p2", "pw"), ("c", "p2", "pw")),
            0,
        )
        self.assertEqual(
            [it["结果"] for it in json.loads(out)["项目"]],
            ["迁移", "ResourceError"],
        )
        self.assertEqual(s._sessions["a"]["ip"],
                         int(ipaddress.IPv4Address("10.1.0.1")))
        self.assertEqual(s._sessions["c"]["pool"], "default")

    def test_aging_runs_before_processing(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()),
                        idle_ms=100, lease_ms=100000)
        add_pool(s)
        s.do("e1", "建立", "old", ("alice", "pw"), 0)
        # t=100：old 期限到（含同刻）老化为挂起释址，迁移记 StateError。
        out = s.batch_migrate("k", (("old", "p2", "pw"),), 100)
        self.assertEqual(
            [it["结果"] for it in json.loads(out)["项目"]],
            ["StateError"],
        )
        self.assertEqual(s._sessions["old"]["state"], "挂起")
        self.assertIsNone(s._sessions["old"]["ip"])

    def test_failure_counts_untouched(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "d", ("bob", "pw"), 0)
        s.batch_migrate(
            "k",
            (("a", "p2", "bad"), ("z", "p2", "pw"), ("d", "nope", "pw")),
            0,
        )
        stats = json.loads(s.runtime_stats(0))
        self.assertEqual(stats["失败"], [
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


class BatchMigrateAtomicTest(unittest.TestCase):
    def test_all_commit(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        out = s.batch_migrate(
            "k", (("b", "p2", "pw"), ("a", "p2", "pw")), 10, atomic=True
        )
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": True,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "迁移"},
                    {"会话": "a", "结果": "迁移"},
                ],
            }),
        )
        self.assertEqual(s._sessions["a"]["pool"], "p2")
        self.assertEqual(s._sessions["b"]["pool"], "p2")
        self.assertEqual(len(s._pools["p2"].leases), 2)
        self.assertEqual(len(s._pools["default"].leases), 0)

    def test_failure_rolls_back_entire_batch_exactly(self):
        _auth, s = make(pool=("10.0.0.0/28", (), ()))
        add_pool(s, cidr="10.1.0.0/28")
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        before = snapshot(s)
        out = s.batch_migrate(
            "k",
            (("a", "p2", "pw"), ("x", "p2", "pw"), ("b", "p2", "bad")),
            10,
            atomic=True,
        )
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "回滚"), ("x", "KeyError"), ("b", "AuthError")],
        )
        # 会话、各池 free 堆（逐格）与租约表精确恢复至老化后快照。
        self.assertEqual(snapshot(s), before)
        self.assertEqual(s._sessions["a"]["pool"], "default")
        self.assertEqual(s._sessions["b"]["pool"], "default")

    def test_multiple_failures_each_recorded(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        before = snapshot(s)
        out = s.batch_migrate(
            "k",
            (("z", "p2", "pw"), ("a", "p2", "pw"),
             ("b", "default", "pw"), ("w", "nope", "pw")),
            0,
            atomic=True,
        )
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("z", "KeyError"), ("a", "回滚"),
             ("b", "StateError"), ("w", "KeyError")],
        )
        self.assertEqual(snapshot(s), before)

    def test_rollback_exact_after_repeated_cross_pool_ops(self):
        # 两池间往返演算：同址在多堆 push/pop 间流转，回滚须逐格复原。
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        add_pool(s, cidr="10.1.0.0/30")
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("bob", "pw"), 0)
        # 批前先把 a 经 do 迁至 p2（持 p2 .1）。
        s.do("m1", "迁移", "a", ("p2", "pw"), 0)
        before = snapshot(s)
        # b default->p2（取 p2 .2、释 default .2），a p2->default（取 default
        # .1、释 p2 .1），z 未知失败：跨两池多堆流转后整批回滚。
        out = s.batch_migrate(
            "k",
            (("b", "p2", "pw"), ("a", "default", "pw"), ("z", "p2", "pw")),
            7,
            atomic=True,
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("b", "回滚"), ("a", "回滚"), ("z", "KeyError")],
        )
        self.assertEqual(snapshot(s), before)

    def test_rollback_preserves_aging(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        add_pool(s)
        s.do("e1", "建立", "old", ("alice", "pw"), 0)
        # keep 在 t=150 建立，期限 100150，故 t=200 批老化时仍在线；old 已挂起。
        s.do("e2", "建立", "keep", ("bob", "pw"), 150)
        out = s.batch_migrate(
            "k", (("keep", "p2", "pw"), ("z", "p2", "pw")), 200, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        old = s._sessions["old"]
        self.assertEqual(old["state"], "挂起")
        self.assertEqual(old["deadline"], 0)
        self.assertIsNone(old["ip"])
        # 演算成功项一并回滚：keep 留在 default 持址。
        self.assertEqual(s._sessions["keep"]["pool"], "default")
        self.assertIsNotNone(s._sessions["keep"]["ip"])

    def test_rollback_preserves_auth_counts_and_lock(self):
        auth = Authenticator(2, 1000)  # 两次失败即锁定
        for user in ("alice",):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 10, 100000, pool=("10.0.0.0/24", (), ()))
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        before = snapshot(s)
        out = s.batch_migrate(
            "k",
            (("a", "p2", "bad"), ("b", "p2", "bad")),
            0,
            atomic=True,
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        # 两次认证失败均保留并锁定；回滚不清零。
        self.assertEqual(auth._users["alice"][1], 2)
        self.assertEqual(auth._users["alice"][2], 1000)
        self.assertEqual(snapshot(s), before)

    def test_rollback_static_lease_not_in_heap(self):
        _auth, s = make(
            pool=("10.0.0.0/30", (), (("alice", "10.0.0.1"),))
        )
        add_pool(s, cidr="10.1.0.0/30", static=(("alice", "10.1.0.1"),))
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        before = snapshot(s)
        out = s.batch_migrate(
            "k", (("a", "p2", "pw"), ("z", "p2", "pw")), 0, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(snapshot(s), before)
        p2 = s._pools["p2"]
        static_ip = next(iter(p2.static_ips))
        self.assertNotIn(static_ip, p2.leases)
        self.assertNotIn(static_ip, p2.free)
        default = s._pools["default"]
        default_static = next(iter(default.static_ips))
        self.assertEqual(default.leases[default_static], "a")

    def test_rollback_replay_does_not_mutate(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        items = (("a", "p2", "pw"), ("z", "p2", "pw"))
        first = s.batch_migrate("k", items, 10, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        self.assertEqual(
            s.batch_migrate("k", items, 10, atomic=True), first
        )
        self.assertEqual(s._sessions["a"]["pool"], "default")
        self.assertEqual(len(s._pools["default"].leases), 1)
        self.assertEqual(len(s._pools["p2"].leases), 0)


class BatchMigrateNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "d", ("alice", "pw"), 0)
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        s.batch_migrate("n1", (("d", "p2", "pw"), ("z", "p2", "pw")), 10)
        s.batch_migrate("n1", (("d", "p2", "pw"), ("z", "p2", "pw")), 10)
        s.batch_migrate("r1", (("d", "default", "pw"), ("w", "p2", "pw")),
                        10, atomic=True)
        s.batch_migrate("r1", (("d", "default", "pw"), ("w", "p2", "pw")),
                        10, atomic=True)
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        self.assertEqual(len(after_chain), before_chain)
        self.assertEqual([e["操作"] for e in after_chain], ["建立"])
        self.assertEqual(len(after_cap), before_cap)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())

    def test_backoff_and_fault_stats_preserved(self):
        _auth, s = make()
        add_pool(s)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        # 预置后端故障与 alice 退避；批量迁移不查后端，回滚亦不动退避。
        s.fault("f", "注入", 100, 0)
        try:
            s.do("be", "建立", "probe", ("alice", "pw"), 0)  # 触发退避
        except BackendError:
            pass
        backoff_before = dict(s._backoff)
        fault_before = json.loads(s.fault_stats(0))
        s.batch_migrate(
            "k", (("a", "p2", "pw"), ("z", "p2", "pw")), 0, atomic=True
        )
        self.assertEqual(dict(s._backoff), backoff_before)
        self.assertEqual(json.loads(s.fault_stats(0)), fault_before)

    def test_unicode_wire_and_lf_tail(self):
        _auth, s = make(pool=("10.0.0.0/24", (), ()))
        add_pool(s, pool_id="池β")
        s.do("e1", "建立", "会话α", ("alice", "pw"), 0)
        out = s.batch_migrate("k", (("会话α", "池β", "pw"),), 0)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)
        self.assertIn("会话α", out)
        self.assertIn("迁移", out)
        doc = json.loads(out)
        self.assertEqual(doc["项目"][0]["结果"], "迁移")
        self.assertEqual(s._sessions["会话α"]["pool"], "池β")


if __name__ == "__main__":
    unittest.main()
