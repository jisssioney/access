import json
import unittest

from access import (
    Authenticator,
    Sessions,
)


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000,
         max_fail=3):
    auth = Authenticator(max_fail, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


class BatchOnlineParamTest(unittest.TestCase):
    def test_key_credential_rule_checked_first(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.batch_online(bad, (("a", "alice", "pw"),), 0)
        # 空串 key 为取值错，先于 items 容器类型错。
        with self.assertRaises(ValueError):
            s.batch_online("", [("a", "alice", "pw")], 0)
        # key 非法在缓存查表之前抛出，故不留缓存、不影响任何合法 key。
        out = s.batch_online("good", (("a", "alice", "pw"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_types(self):
        _auth, s = make()
        # items 必须是 tuple：list/set/str/None/生成器均 TypeError。
        for bad in (
            [("a", "alice", "pw")],
            {("a", "alice", "pw")},
            "abc",
            None,
            (x for x in (("a", "alice", "pw"),)),
        ):
            with self.assertRaises(TypeError):
                s.batch_online("k" + str(type(bad)), bad, 0)
        # 每项必须是 tuple。
        for j, bad in enumerate((
            [["a", "alice", "pw"]],
            (["a", "alice", "pw"],),
            (1,),
        )):
            with self.assertRaises(TypeError):
                s.batch_online(f"it{j}", bad, 0)
        # sid/user/password 必须是 str（长度恰为 3 时按位定位）。
        with self.assertRaises(TypeError):
            s.batch_online("t1", ((1, "alice", "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_online("t2", (("a", 1, "pw"),), 0)
        with self.assertRaises(TypeError):
            s.batch_online("t3", (("a", "alice", 1),), 0)
        # now_ms 为非 bool int。
        for i, bad in enumerate((1.5, "0", None, True, False)):
            with self.assertRaises(TypeError):
                s.batch_online(f"n{i}", (("a", "alice", "pw"),), bad)
        # atomic 为 bool。
        for i, bad in enumerate((0, 1, "false", None)):
            with self.assertRaises(TypeError):
                s.batch_online(f"at{i}", (("a", "alice", "pw"),), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        # 容器类型错先于元素取值、now_ms 类型/取值与重复。
        with self.assertRaises(TypeError):
            s.batch_online("o1", [("a", "alice", "pw"), ("a", "bob", "pw")],
                           1.5, atomic="x")
        # 元素非 tuple 的类型错先于三元组长度取值错。
        with self.assertRaises(TypeError):
            s.batch_online("o2", (["a", "alice"],), 0)
        # 元素类型错先于 now_ms 类型错。
        with self.assertRaises(TypeError):
            s.batch_online("o3", (("a", "alice", 1),), "x")
        # now_ms 类型错先于 atomic 类型错。
        with self.assertRaises(TypeError):
            s.batch_online("o4", (("a", "alice", "pw"),), 1.5, atomic=0)

    def test_values_length_duplicates(self):
        _auth, s = make()
        # 空批 ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("e0", (), 0)
        # 三元组长度取值错。
        with self.assertRaises(ValueError):
            s.batch_online("l2", (("a", "alice"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("l4", (("a", "alice", "pw", "x"),), 0)
        # 各串沿用凭据约束。
        with self.assertRaises(ValueError):
            s.batch_online("v1", (("", "alice", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("v2", (("a", "", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("v3", (("a", "alice", ""),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("v4", (("a\0", "alice", "pw"),), 0)
        # now_ms 非负。
        with self.assertRaises(ValueError):
            s.batch_online("v5", (("a", "alice", "pw"),), -1)
        # 重复 sid ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("dup",
                           (("a", "alice", "pw"), ("a", "bob", "pw")), 0)
        with self.assertRaises(ValueError):
            s.batch_online("dup2",
                           (("x", "alice", "pw"),
                            ("y", "bob", "pw"),
                            ("x", "carol", "pw")), 0)

    def test_length_bounds(self):
        _auth, s = make()
        one = (("s0000", "nobody", "pw"),)
        thousand = tuple((f"s{i:04d}", "nobody", "pw") for i in range(1000))
        thousand_one = tuple(
            (f"s{i:04d}", "nobody", "pw") for i in range(1001)
        )
        # 全部未知用户不抛异常（记 KeyError），故边界批正常返回“部分”。
        self.assertEqual(
            json.loads(s.batch_online("b1", one, 0))["结果"], "部分"
        )
        doc = json.loads(s.batch_online("b1000", thousand, 0))
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(len(doc["项目"]), 1000)
        with self.assertRaises(ValueError):
            s.batch_online("b1001", thousand_one, 0)


class BatchOnlineCacheTest(unittest.TestCase):
    def test_param_exception_is_cached(self):
        _auth, s = make()
        dup = (("a", "alice", "pw"), ("a", "bob", "pw"))
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.batch_online("p", dup, 0)
        # 首果为异常：异参复用仍 ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("p", (("a", "alice", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("p", dup, 1)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make()
        items = (("a", "alice", "pw"), ("b", "bob", "pw"))
        out = s.batch_online("k", items, 10)
        self.assertEqual(s.batch_online("k", items, 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.batch_online("k", (("a", "alice", "pw"),), 0)
        # 此后新建 c，期限 100；以同参（now 仍 0）重放旧 key，不得老化 c。
        s.do("e2", "建立", "c", ("alice", "pw"), 0)
        s.batch_online("k", (("a", "alice", "pw"),), 0)
        self.assertEqual(s._sessions["c"]["state"], "在线")
        self.assertIsNotNone(s._sessions["c"]["ip"])

    def test_different_params_value_error(self):
        _auth, s = make()
        s.batch_online("k", (("a", "alice", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("k", (("b", "alice", "pw"),), 0)
        with self.assertRaises(ValueError):
            s.batch_online("k", (("a", "alice", "pw"),), 1)
        with self.assertRaises(ValueError):
            s.batch_online("k", (("a", "alice", "other"),), 0)
        # atomic 标志不同亦为异参；类型差异同样归 ValueError。
        with self.assertRaises(ValueError):
            s.batch_online("k", (("a", "alice", "pw"),), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.batch_online("k", (("a", "alice", "pw"),), 0, atomic=0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        # 与 do/batch_offline 同名字符串 key 互不指认。
        out = s.batch_online("same", (("e", "bob", "pw"),), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        offline = s.batch_offline("same", ("d",), 0)
        self.assertEqual(json.loads(offline)["结果"], "提交")
        # 与 fault/pool_fault/timeout_fault 各域独立。
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
        # 各域重放不报错且不改 batch_online 缓存。
        replay = s.batch_online("same", (("e", "bob", "pw"),), 0)
        self.assertEqual(json.loads(replay)["结果"], "提交")


class BatchOnlineNonAtomicTest(unittest.TestCase):
    def test_all_online_commit(self):
        _auth, s = make()
        items = (("a", "alice", "pw"), ("b", "bob", "pw"))
        out = s.batch_online("k", items, 10)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "a", "结果": "在线"},
                    {"会话": "b", "结果": "在线"},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid in ("a", "b"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "在线")
            self.assertEqual(session["deadline"], 100010)
            self.assertEqual(session["lease"], 100010)
            self.assertIsNotNone(session["ip"])

    def test_business_exceptions_record_class_name_and_continue(self):
        _auth, s = make(per=1)
        items = (
            ("s1", "alice", "pw"),     # 成功，占 alice 唯一 per 名额
            ("s2", "alice", "pw"),     # ResourceError（单用户上限）
            ("s3", "dave", "pw"),      # KeyError（未知用户）
            ("s4", "alice", "bad"),    # AuthError（密码错）
            ("s5", "bob", "pw"),       # 成功，不受前项影响
        )
        doc = json.loads(s.batch_online("k", items, 0))
        self.assertEqual(doc["结果"], "部分")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("s1", "在线"),
                ("s2", "ResourceError"),
                ("s3", "KeyError"),
                ("s4", "AuthError"),
                ("s5", "在线"),
            ],
        )
        # 成功项落库，失败项不留会话或租约。
        self.assertEqual(sorted(s._sessions), ["s1", "s5"])
        self.assertEqual(len(s._pools["default"].leases), 2)
        # 认证失败计数保留（一次错误密码）。
        self.assertEqual(s._auth._users["alice"][1], 1)

    def test_total_limit_resource_error(self):
        _auth, s = make(total=2, per=10)
        s.do("e1", "建立", "x", ("carol", "pw"), 0)
        s.do("e2", "建立", "y", ("carol", "pw"), 0)
        doc = json.loads(
            s.batch_online("k", (("a", "alice", "pw"), ("b", "bob", "pw")), 0)
        )
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "ResourceError"), ("b", "ResourceError")],
        )

    def test_duplicate_sid_state_error(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("carol", "pw"), 0)
        doc = json.loads(
            s.batch_online("k", (("a", "alice", "pw"), ("b", "bob", "pw")), 0)
        )
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "StateError"), ("b", "在线")],
        )

    def test_no_default_pool_state_error(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 10, 10, 100000)
        doc = json.loads(
            s.batch_online("k", (("a", "alice", "pw"), ("b", "alice", "pw")), 0)
        )
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "StateError"), ("b", "StateError")],
        )
        self.assertEqual(s._sessions, {})

    def test_pool_exhaustion_resource_error(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        s.pool_fault("pf", "注入", "default", 1000, 0)
        doc = json.loads(
            s.batch_online("k", (("a", "alice", "pw"), ("b", "bob", "pw")), 0)
        )
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "ResourceError"), ("b", "ResourceError")],
        )
        # 失败不半分配。
        self.assertEqual(s._pools["default"].leases, {})
        self.assertEqual(s._sessions, {})

    def test_small_dynamic_pool_partial(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        items = tuple((f"s{i}", u, "pw")
                      for i, u in enumerate(("alice", "bob", "carol")))
        doc = json.loads(s.batch_online("k", items, 0))
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("s0", "在线"), ("s1", "在线"), ("s2", "ResourceError")],
        )
        self.assertEqual(len(s._pools["default"].leases), 2)

    def test_aging_runs_once_before_items(self):
        # 租期到期但未到空闲期限：批开始先老化释址，再逐项建立。
        _auth, s = make(idle_ms=100000, lease_ms=50)
        s.do("e1", "建立", "old", ("carol", "pw"), 0)
        doc = json.loads(
            s.batch_online("k", (("a", "alice", "pw"),), 50)
        )
        self.assertEqual(doc["结果"], "提交")
        # 老化已释放 old 的租约但仍在线，新建 a 成功取址。
        self.assertIsNone(s._sessions["old"]["ip"])
        self.assertEqual(s._sessions["old"]["state"], "在线")
        self.assertEqual(s._sessions["a"]["state"], "在线")
        self.assertIsNotNone(s._sessions["a"]["ip"])


class BatchOnlineAtomicTest(unittest.TestCase):
    def test_all_online_commit(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        items = (("b", "bob", "pw"), ("a", "alice", "pw"))
        out = s.batch_online("k", items, 10, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": True,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "在线"},
                    {"会话": "a", "结果": "在线"},
                ],
            }),
        )
        self.assertEqual(len(s._pools["default"].leases), 2)
        self.assertEqual(s._sessions["a"]["deadline"], 100010)

    def test_failure_rolls_back_entire_batch(self):
        _auth, s = make(per=1, pool=("10.0.0.0/24", (), ()))
        items = (
            ("s1", "alice", "pw"),   # 演算成功
            ("s2", "alice", "pw"),   # ResourceError：失败点
            ("s3", "bob", "pw"),     # 不再演算
        )
        out = s.batch_online("k", items, 0, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("s1", "回滚"), ("s2", "ResourceError"), ("s3", "回滚")],
        )
        # 批内不留任何会话、墓碑或租约。
        self.assertEqual(s._sessions, {})
        self.assertEqual(s._pools["default"].leases, {})
        self.assertEqual(len(s._pools["default"].free),
                         s._pools["default"].capacity)

    def test_failure_on_first_item(self):
        _auth, s = make()
        items = (
            ("s1", "dave", "pw"),    # KeyError：首项即失败
            ("s2", "bob", "pw"),
        )
        doc = json.loads(s.batch_online("k", items, 0, atomic=True))
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("s1", "KeyError"), ("s2", "回滚")],
        )
        self.assertEqual(s._sessions, {})
        self.assertEqual(s._pools["default"].leases, {})

    def test_evaluates_all_items_multiple_failures_recorded(self):
        # 原子演算全部：首个失败不停止，后续失败仍记其异常类名，
        # 其间与其后暂建成功项一律回滚。
        _auth, s = make(per=1)
        items = (
            ("s1", "alice", "pw"),   # 暂建成功（alice 占唯一名额）
            ("s2", "alice", "pw"),   # ResourceError（单用户上限）
            ("s3", "dave", "pw"),    # KeyError（未知用户，不停止演算）
            ("s4", "bob", "pw"),     # 暂建成功
        )
        doc = json.loads(s.batch_online("k", items, 0, atomic=True))
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("s1", "回滚"),
                ("s2", "ResourceError"),
                ("s3", "KeyError"),
                ("s4", "回滚"),
            ],
        )
        # 两个失败点之后仍演算到 s4；整批回滚后无会话、租约、墓碑。
        self.assertEqual(s._sessions, {})
        self.assertEqual(s._pools["default"].leases, {})

    def test_rollback_releases_static_lease_not_dynamic_heap(self):
        import ipaddress
        _auth, s = make(per=1,
                        pool=("10.0.0.0/30", (), (("alice", "10.0.0.1"),)))
        pool = s._pools["default"]
        static_ip = int(ipaddress.IPv4Address("10.0.0.1"))
        free_before = list(pool.free)
        # s1 静态址演算成功，s2 因 per=1 失败，整批回滚。
        items = (("s1", "alice", "pw"), ("s2", "alice", "pw"))
        doc = json.loads(s.batch_online("k", items, 0, atomic=True))
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("s1", "回滚"), ("s2", "ResourceError")],
        )
        self.assertEqual(pool.leases, {})
        self.assertEqual(list(pool.free), free_before)
        self.assertNotIn(static_ip, pool.free)
        self.assertEqual(s._sessions, {})

    def test_rollback_preserves_aging(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "old", ("carol", "pw"), 0)
        # old 在 t=200 老化为挂起并释址；批因认证失败回滚但保留老化。
        doc = json.loads(
            s.batch_online(
                "k",
                (("a", "alice", "bad"), ("b", "bob", "pw")),
                200,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "AuthError"), ("b", "回滚")],
        )
        self.assertEqual(s._sessions["old"]["state"], "挂起")
        self.assertEqual(s._sessions["old"]["deadline"], 0)
        self.assertIsNone(s._sessions["old"]["ip"])
        # 批内新建项均不留存。
        self.assertNotIn("a", s._sessions)
        self.assertNotIn("b", s._sessions)

    def test_auth_failure_count_retained_after_rollback(self):
        auth, s = make()
        # 连续三个原子批各含一次错误密码：失败计数累加，第三次触发锁定。
        s.batch_online("k1", (("x1", "alice", "bad"),), 0, atomic=True)
        self.assertEqual(auth._users["alice"][1], 1)
        s.batch_online("k2", (("x2", "alice", "bad"),), 0, atomic=True)
        self.assertEqual(auth._users["alice"][1], 2)
        self.assertIsNone(auth._users["alice"][2])
        s.batch_online("k3", (("x3", "alice", "bad"),), 0, atomic=True)
        self.assertEqual(auth._users["alice"][1], 3)
        self.assertEqual(auth._users["alice"][2], 1000)
        # 锁定后即使密码正确仍 AuthError，且不留任何批内会话。
        doc = json.loads(
            s.batch_online("k4", (("x4", "alice", "pw"),), 0, atomic=True)
        )
        self.assertEqual(doc["项目"][0]["结果"], "AuthError")
        self.assertEqual(s._sessions, {})

    def test_rollback_replay_byte_identical_and_clean(self):
        _auth, s = make(per=1)
        items = (("s1", "alice", "pw"), ("s2", "alice", "pw"))
        first = s.batch_online("k", items, 0, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        self.assertEqual(s._sessions, {})
        second = s.batch_online("k", items, 0, atomic=True)
        self.assertEqual(second, first)
        # 重放无副作用：仍无会话、租约，动态池全量空闲。
        self.assertEqual(s._sessions, {})
        self.assertEqual(s._pools["default"].leases, {})


class BatchOnlineBackendTest(unittest.TestCase):
    def test_backend_checked_after_aging(self):
        # 批开始先老化：old 租期到点释址；随后各项后端检查均失败。
        _auth, s = make(idle_ms=100000, lease_ms=50)
        s.do("e1", "建立", "old", ("carol", "pw"), 0)
        s.fault("f", "注入", 1000, 0)
        doc = json.loads(
            s.batch_online(
                "k",
                (("a", "alice", "pw"), ("b", "bob", "pw")),
                50,
                atomic=True,
            )
        )
        self.assertEqual(doc["结果"], "回滚")
        # 原子演算全部：两项都做后端检查，各自 BackendError，不提前停止。
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "BackendError"), ("b", "BackendError")],
        )
        # 老化结果保留（old 释址仍在线），批内不留会话。
        self.assertIsNone(s._sessions["old"]["ip"])
        self.assertNotIn("a", s._sessions)
        self.assertNotIn("b", s._sessions)
        # 两个用户各演进一次退避并保留（retry_at = 50 + 100*2**0 = 150）。
        self.assertEqual(s._backoff["alice"], (1, 150))
        self.assertEqual(s._backoff["bob"], (1, 150))

    def test_backoff_mutates_and_is_retained(self):
        _auth, s = make()
        s.fault("f", "注入", 1000, 0)
        # 首次失败：n=1，retry_at=0+100。
        s.batch_online("k1", (("a", "alice", "pw"),), 0, atomic=True)
        self.assertEqual(s._backoff["alice"], (1, 100))
        # 非原子同刻两项：退避未到期 n 不变，两项均 BackendError，退避保留。
        doc = json.loads(
            s.batch_online("k2", (("b", "alice", "pw"), ("c", "alice", "pw")), 0)
        )
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("b", "BackendError"), ("c", "BackendError")],
        )
        self.assertEqual(s._backoff["alice"], (1, 100))
        # 原子回滚后仍无会话/租约，但退避保留。
        self.assertEqual(s._sessions, {})

    def test_backend_failures_not_counted_in_fault_stats(self):
        _auth, s = make()
        before = json.loads(s.fault_stats(0))["失败"]
        s.fault("f", "注入", 1000, 0)
        s.batch_online("k1", (("a", "alice", "pw"),), 0, atomic=True)
        s.batch_online("k2", (("b", "alice", "pw"), ("c", "bob", "pw")), 0)
        after = json.loads(s.fault_stats(0))["失败"]
        self.assertEqual(after, before)
        self.assertEqual([x["次数"] for x in after], [0, 0])

    def test_recovery_clears_backoff_then_commit(self):
        _auth, s = make()
        s.fault("f", "注入", 1000, 0)
        s.batch_online("k1", (("a", "alice", "pw"),), 0, atomic=True)
        self.assertIn("alice", s._backoff)
        # 截至与退避均到刻后恢复，健康检查清退避并成功建立。
        s.fault("r", "恢复", None, 100)
        doc = json.loads(s.batch_online("k2", (("a", "alice", "pw"),), 100))
        self.assertEqual(doc["结果"], "提交")
        self.assertNotIn("alice", s._backoff)
        self.assertEqual(s._sessions["a"]["state"], "在线")


class BatchOnlineNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events(self):
        _auth, s = make()
        s.do("e0", "建立", "seed", ("carol", "pw"), 0)
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        # 非原子部分成功、原子回滚及各自重放均不入链/不记事件。
        s.batch_online("n1", (("a", "alice", "pw"), ("x", "dave", "pw")), 10)
        s.batch_online("n1", (("a", "alice", "pw"), ("x", "dave", "pw")), 10)
        s.batch_online("r1",
                       (("b", "bob", "pw"), ("y", "alice", "bad")),
                       10, atomic=True)
        s.batch_online("r1",
                       (("b", "bob", "pw"), ("y", "alice", "bad")),
                       10, atomic=True)
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        self.assertEqual(len(after_chain), before_chain)
        self.assertEqual(len(after_cap), before_cap)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        # 接管审计亦为空。
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_no_business_stats_changes(self):
        _auth, s = make()
        s.fault("f", "注入", 1000, 0)
        before_rt = json.loads(s.runtime_stats(0))
        before_user = json.loads(s.user_stats("alice", 0))["失败"]
        # 覆盖成功、认证失败、容量失败、未知用户、后端失败的混合批。
        s.batch_online(
            "n1",
            (
                ("a", "alice", "pw"),
                ("b", "alice", "bad"),
                ("c", "dave", "pw"),
            ),
            0,
        )
        s.batch_online(
            "r1",
            (("d", "bob", "pw"), ("e", "alice", "pw")),
            0,
            atomic=True,
        )
        after_rt = json.loads(s.runtime_stats(0))
        after_user = json.loads(s.user_stats("alice", 0))["失败"]
        self.assertEqual(after_rt["建立"], before_rt["建立"])
        self.assertEqual(after_rt["失败"], before_rt["失败"])
        self.assertEqual(after_user, before_user)
        # 故障注入本身不计失败；批量建立的后端失败亦不计。
        self.assertEqual(
            [x["次数"] for x in json.loads(s.fault_stats(0))["失败"]], [0, 0]
        )


if __name__ == "__main__":
    unittest.main()
