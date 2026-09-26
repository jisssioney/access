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


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def item(sid, user="alice", password="pw"):
    return (sid, user, password)


class BatchOnlineParamTest(unittest.TestCase):
    def test_key_credential_rule_checked_first(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.batch_online(bad, (item("a"),), 0)
        # 空串 key 为取值错，先于 items 容器类型错。
        with self.assertRaises(ValueError):
            s.batch_online("", [item("a")], 0)
        # key 非法在缓存查表之前抛出，故不留缓存、不影响任何合法 key。
        out = s.batch_online("good", (item("a"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_types(self):
        _auth, s = make()
        # items 必须是 tuple：list/set/str/None/生成器均 TypeError。
        for bad in ([item("a")], {item("a")}, "a", None, (x for x in (item("a"),))):
            with self.assertRaises(TypeError):
                s.batch_online("k" + str(type(bad)), bad, 0)
        # 每个 item 必须是 tuple。
        with self.assertRaises(TypeError):
            s.batch_online("t1", (["a", "alice", "pw"],), 0)
        # 三项串必须是 str。
        with self.assertRaises(TypeError):
            s.batch_online("t2", ((1, "alice", "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_online("t3", (("a", None, "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_online("t4", (("a", "alice", b"pw"),), 0)
        # now_ms 为非 bool int。
        for i, bad in enumerate((1.5, "0", None, True, False)):
            with self.assertRaises(TypeError):
                s.batch_online(f"n{i}", (item("a"),), bad)
        # atomic 为 bool。
        for i, bad in enumerate((0, 1, "false", None)):
            with self.assertRaises(TypeError):
                s.batch_online(f"at{i}", (item("a"),), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        # 容器类型错先于 now_ms 类型/取值与重复。
        with self.assertRaises(TypeError):
            s.batch_online("o1", [item("a"), item("a")], 1.5, atomic="x")
        # 项类型错先于 now_ms 类型错。
        with self.assertRaises(TypeError):
            s.batch_online("o2", (["a", "alice", "pw"],), "x")
        # 串类型错先于项长度取值错与 now_ms 类型错。
        with self.assertRaises(TypeError):
            s.batch_online("o3", ((1, "alice"),), "x")
        # now_ms 类型错先于 atomic 类型错。
        with self.assertRaises(TypeError):
            s.batch_online("o4", (item("a"),), 1.5, atomic=0)

    def test_values_length_duplicates(self):
        _auth, s = make()
        # 空批 ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("e0", (), 0)
        # 项须为三元组。
        with self.assertRaises(ValueError):
            s.batch_online("e1", (("a", "alice"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("e2", (("a", "alice", "pw", "x"),), 0)
        # 三项串沿用凭据约束。
        with self.assertRaises(ValueError):
            s.batch_online("v1", (("", "alice", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("v2", (("a", "ali\0ce", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("v3", (("a", "alice", ""),), 0)
        # now_ms 非负。
        with self.assertRaises(ValueError):
            s.batch_online("v4", (item("a"),), -1)
        # 重复 sid ValueError（即使其余项非法用户）。
        with self.assertRaises(ValueError):
            s.batch_online("dup", (item("a"), item("a", "bob")), 0)
        with self.assertRaises(ValueError):
            s.batch_online(
                "dup2", (item("x"), item("y", "bob"), item("x", "carol")), 0
            )

    def test_length_bounds(self):
        _auth, s = make()
        one = tuple(item(f"s{i:04d}") for i in range(1))
        thousand = tuple(item(f"s{i:04d}") for i in range(1000))
        thousand_one = tuple(item(f"s{i:04d}") for i in range(1001))
        self.assertEqual(len(one), 1)
        self.assertEqual(len(thousand), 1000)
        self.assertEqual(len(thousand_one), 1001)
        self.assertEqual(
            json.loads(s.batch_online("b1", one, 0))["结果"], "提交"
        )
        # 总数上限 10：前 10 项上线、余下 ResourceError，故上界批返回“部分”。
        self.assertEqual(
            json.loads(s.batch_online("b1000", thousand, 0))["结果"], "部分"
        )
        with self.assertRaises(ValueError):
            s.batch_online("b1001", thousand_one, 0)


class BatchOnlineCacheTest(unittest.TestCase):
    def test_param_exception_is_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.batch_online("p", (item("a"), item("a")), 0)
        # 首果为异常：异参复用仍 ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("p", (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("p", (item("a"), item("a")), 1)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make()
        items = (item("a"), item("b", "bob"))
        out = s.batch_online("k", items, 10)
        self.assertEqual(s.batch_online("k", items, 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.batch_online("k", (item("a"),), 0)  # a 上线，缓存 now=0
        # 此后以晚于 a 期限的时刻重放旧 key（同参 now 仍 0），不得老化 a。
        s.batch_online("k", (item("a"),), 0)
        session = s._sessions["a"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])
        # 重放不重复建立：会话数与租约数仍为 1。
        self.assertEqual(len(s._sessions), 1)
        self.assertEqual(len(s._pools["default"].leases), 1)

    def test_different_params_value_error(self):
        _auth, s = make()
        s.batch_online("k", (item("a"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("k", (item("a"),), 1)
        with self.assertRaises(ValueError):
            s.batch_online("k", (item("b"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("k", (item("a", "bob"),), 0)
        # atomic 标志不同亦为异参；类型差异同样归 ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("k", (item("a"),), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.batch_online("k", (item("a"),), 0, atomic=0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        # 与 do 同名字符串 key 互不指认。
        out = s.batch_online("same", (item("e", "bob"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        # do 域同 key 重放仍返回首次建立结果。
        replay = s.do("same", "建立", "d", ("alice", "pw"), 0)
        self.assertEqual(json.loads(replay)["状态"], "在线")
        # 与 batch_offline/fault/pool_fault/timeout_fault 各域独立。
        self.assertEqual(
            json.loads(s.batch_offline("same", ("d",), 0))["结果"], "提交"
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
        # 同参重放仍逐字节相同（各域互不指认）。
        out2 = s.batch_online("same", (item("e", "bob"),), 0)
        self.assertEqual(out2, out)


class BatchOnlineNonAtomicTest(unittest.TestCase):
    def test_all_commit(self):
        _auth, s = make()
        out = s.batch_online("k", (item("a"), item("b", "bob")), 10)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "a", "结果": "上线"},
                    {"会话": "b", "结果": "上线"},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid, user in (("a", "alice"), ("b", "bob")):
            session = s._sessions[sid]
            self.assertEqual(session["user"], user)
            self.assertEqual(session["state"], "在线")
            self.assertEqual(session["deadline"], 10 + 100000)
            self.assertEqual(session["lease"], 10 + 100000)
            self.assertIsNotNone(session["ip"])
        self.assertEqual(len(s._pools["default"].leases), 2)

    def test_failure_does_not_block_later_items(self):
        _auth, s = make()
        s.do("e1", "建立", "dup", ("carol", "pw"), 0)
        items = (
            item("x", "nobody", "pw"),      # 未知用户 KeyError
            item("a"),                       # 上线
            item("y", "bob", "bad"),        # 密码错 AuthError
            item("b", "bob"),                # 上线
            ("dup", "carol", "pw"),         # sid 已存在 StateError
            item("c", "carol"),              # 上线
        )
        out = s.batch_online("k", items, 10)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("x", "KeyError"),
                ("a", "上线"),
                ("y", "AuthError"),
                ("b", "上线"),
                ("dup", "StateError"),
                ("c", "上线"),
            ],
        )
        # 成功项确已建立，失败项不留痕。
        for sid in ("a", "b", "c"):
            self.assertEqual(s._sessions[sid]["state"], "在线")
        for sid in ("x", "y"):
            self.assertNotIn(sid, s._sessions)
        # 既有会话不受影响。
        self.assertEqual(s._sessions["dup"]["user"], "carol")

    def test_capacity_limits_per_item(self):
        _auth, s = make(total=2, per=1)
        items = (
            item("a"),                       # 上线（alice 1/1）
            item("b"),                       # alice 超每用户 ResourceError
            item("c", "bob"),                # 上线（总数 2/2）
            item("d", "carol"),              # 超总数 ResourceError
        )
        out = s.batch_online("k", items, 0)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("a", "上线"),
                ("b", "ResourceError"),
                ("c", "上线"),
                ("d", "ResourceError"),
            ],
        )
        self.assertEqual(set(s._sessions), {"a", "c"})

    def test_static_address_rules(self):
        _auth, s = make(pool=("10.0.0.0/30", (), (("alice", "10.0.0.1"),)))
        # alice 静态址被既有会话占用：ResourceError；bob 取动态址。
        s.do("e1", "建立", "old", ("alice", "pw"), 0)
        out = s.batch_online("k", (item("a"), item("b", "bob")), 0)
        doc = json.loads(out)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "ResourceError"), ("b", "上线")],
        )
        self.assertEqual(s._sessions["b"]["ip"], int(
            __import__("ipaddress").IPv4Address("10.0.0.2")
        ))

    def test_pool_fault_and_no_default_pool(self):
        # 池耗尽演练期：建立项 ResourceError。
        _auth, s = make()
        s.pool_fault("pf", "注入", "default", 100, 0)
        out = s.batch_online("k", (item("a"),), 50)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "ResourceError")],
        )
        self.assertNotIn("a", s._sessions)
        # 缺 default 池：StateError。
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s2 = Sessions(auth, 10, 10, 100000)
        out = s2.batch_online("k", (item("a"),), 0)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in json.loads(out)["项目"]],
            [("a", "StateError")],
        )

    def test_backend_fault_per_item(self):
        _auth, s = make()
        s.fault("f", "注入", 100, 0)
        out = s.batch_online("k", (item("a"), item("b", "bob")), 0)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "BackendError"), ("b", "BackendError")],
        )
        self.assertEqual(len(s._sessions), 0)
        # 退避保留：两用户各进一格退避；同刻重查仍退避未到期。
        self.assertEqual(s._backoff["alice"], (1, 100))
        self.assertEqual(s._backoff["bob"], (1, 100))
        # 不计 fault_stats（其口径仅 do 与 capacity）。
        stats = json.loads(s.fault_stats(0))
        self.assertEqual(stats["失败"], [
            {"类型": "故障", "次数": 0},
            {"类型": "退避", "次数": 0},
        ])
        # 恢复后同 key 异参 ValueError；新 key 正常建立。
        s.fault("f2", "恢复", None, 0)
        out = s.batch_online("k2", (item("a"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_aging_runs_before_processing(self):
        # 既有会话占满动态址；老化先释址，批内新会话方能取址。
        _auth, s = make(pool=("10.0.0.0/30", (), ()), idle_ms=100,
                        lease_ms=100000)
        s.do("e1", "建立", "old1", ("alice", "pw"), 0)
        s.do("e2", "建立", "old2", ("bob", "pw"), 0)
        out = s.batch_online("k", (item("a", "carol"), item("b", "carol")), 100)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "提交")
        self.assertEqual(s._sessions["old1"]["state"], "挂起")
        self.assertEqual(s._sessions["a"]["state"], "在线")


class BatchOnlineAtomicTest(unittest.TestCase):
    def test_all_commit(self):
        _auth, s = make()
        out = s.batch_online("k", (item("b", "bob"), item("a")), 10, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": True,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "上线"},
                    {"会话": "a", "结果": "上线"},
                ],
            }),
        )
        self.assertEqual(set(s._sessions), {"a", "b"})
        self.assertEqual(len(s._pools["default"].leases), 2)

    def test_failure_rolls_back_entire_batch(self):
        _auth, s = make()
        out = s.batch_online(
            "k",
            (item("a"), item("x", "nobody", "pw"), item("b", "bob")),
            10,
            atomic=True,
        )
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "回滚"), ("x", "KeyError"), ("b", "回滚")],
        )
        # 批内不建会话/租约。
        self.assertEqual(len(s._sessions), 0)
        pool = s._pools["default"]
        self.assertEqual(pool.leases, {})
        self.assertEqual(len(pool.free), pool.capacity)

    def test_multiple_failures_each_recorded(self):
        _auth, s = make()
        out = s.batch_online(
            "k",
            (item("x", "nobody", "pw"), item("a"), item("y", "bob", "bad")),
            0,
            atomic=True,
        )
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("x", "KeyError"), ("a", "回滚"), ("y", "AuthError")],
        )
        self.assertEqual(len(s._sessions), 0)

    def test_rollback_preserves_aging(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "old", ("alice", "pw"), 0)
        # old 在 t=200 老化为挂起并释址；批因失败项回滚但保留老化。
        out = s.batch_online(
            "k", (item("a", "bob"), item("x", "nobody", "pw")), 200, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        session = s._sessions["old"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])
        # 批内会话未建立。
        self.assertNotIn("a", s._sessions)

    def test_rollback_preserves_auth_counts(self):
        auth, s = make()
        # max_fail=3：两次错误密码不锁定，失败计数保留。
        out = s.batch_online(
            "k",
            (item("a"), item("y", "bob", "bad")),
            0,
            atomic=True,
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        self.assertEqual(auth._users["bob"][1], 1)  # failed 计数保留
        # 批内成功项已回滚，可再次建立。
        out = s.batch_online("k2", (item("a"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_rollback_preserves_backoff(self):
        _auth, s = make()
        s.fault("f", "注入", 100, 0)
        out = s.batch_online("k", (item("a"), item("b", "bob")), 0, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "BackendError"), ("b", "BackendError")],
        )
        self.assertEqual(len(s._sessions), 0)
        # 退避保留。
        self.assertEqual(s._backoff["alice"], (1, 100))
        self.assertEqual(s._backoff["bob"], (1, 100))

    def test_rollback_releases_static_lease(self):
        _auth, s = make(pool=("10.0.0.0/30", (), (("alice", "10.0.0.1"),)))
        out = s.batch_online(
            "k", (item("a"), item("x", "nobody", "pw")), 0, atomic=True
        )
        self.assertEqual(json.loads(out)["结果"], "回滚")
        pool = s._pools["default"]
        static_ip = next(iter(pool.static_ips))
        # 静态址退租但不回动态堆；批内会话不存在。
        self.assertNotIn(static_ip, pool.leases)
        self.assertNotIn(static_ip, pool.free)
        self.assertNotIn("a", s._sessions)
        # 回滚后静态址可再租。
        out = s.batch_online("k2", (item("a"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        self.assertEqual(s._sessions["a"]["ip"], static_ip)

    def test_rollback_replay_does_not_mutate(self):
        _auth, s = make()
        items = (item("a"), item("x", "nobody", "pw"))
        first = s.batch_online("k", items, 10, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        # 同参重放返回逐字节相同结果，仍不建立。
        self.assertEqual(s.batch_online("k", items, 10, atomic=True), first)
        self.assertEqual(len(s._sessions), 0)
        self.assertEqual(len(s._pools["default"].leases), 0)


class BatchOnlineNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events(self):
        _auth, s = make()
        s.do("e1", "建立", "d", ("alice", "pw"), 0)
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        s.batch_online("n1", (item("a"), item("x", "nobody", "pw")), 10)
        s.batch_online("n1", (item("a"), item("x", "nobody", "pw")), 10)  # 重放
        s.batch_online("r1", (item("b"), item("y", "nobody", "pw")), 10,
                       atomic=True)
        s.batch_online("r1", (item("b"), item("y", "nobody", "pw")), 10,
                       atomic=True)  # 重放
        s.batch_online("n2", (item("c", "bob"),), 30)
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        # 仅 e1 一条建立事件，批量建立不入链。
        self.assertEqual(len(after_chain), before_chain)
        self.assertEqual([e["操作"] for e in after_chain], ["建立"])
        self.assertEqual(len(after_cap), before_cap)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_no_failure_or_establish_stats(self):
        _auth, s = make()
        s.batch_online("n1", (item("a"), item("x", "nobody", "pw"),
                              item("y", "bob", "bad")), 10)
        s.batch_online("r1", (item("b"), item("z", "nobody", "pw")), 10,
                       atomic=True)
        stats = json.loads(s.runtime_stats(0))
        # 建立统计仅计 do 建立。
        self.assertEqual(stats["建立"], {"总数": 0, "成功": 0, "成功率万分比": 0})
        # 失败统计仅计 do/meter/capacity。
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


if __name__ == "__main__":
    unittest.main()
