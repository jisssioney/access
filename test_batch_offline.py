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


class BatchOfflineParamTest(unittest.TestCase):
    def test_key_credential_rule_checked_first(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.batch_offline(bad, ("a",), 0)
        # 空串 key 为取值错，先于 sids 容器类型错。
        with self.assertRaises(ValueError):
            s.batch_offline("", ["a"], 0)
        # key 非法在缓存查表之前抛出，故不留缓存、不影响任何合法 key。
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_offline("good", ("a",), 1)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_types(self):
        _auth, s = make()
        # sids 必须是 tuple：str/list/set/None 均 TypeError。
        for bad in (["a"], {"a"}, "a", None, (x for x in ("a",))):
            with self.assertRaises(TypeError):
                s.batch_offline("k" + str(type(bad)), bad, 0)
        # 每个 sid 必须是 str。
        with self.assertRaises(TypeError):
            s.batch_offline("t1", (1,), 0)
        with self.assertRaises(TypeError):
            s.batch_offline("t2", ("a", None), 0)
        # now_ms 为非 bool int。
        for i, bad in enumerate((1.5, "0", None, True, False)):
            with self.assertRaises(TypeError):
                s.batch_offline(f"n{i}", ("a",), bad)
        # atomic 为 bool。
        for i, bad in enumerate((0, 1, "false", None)):
            with self.assertRaises(TypeError):
                s.batch_offline(f"at{i}", ("a",), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        # 容器类型错先于 now_ms 类型/取值与重复。
        with self.assertRaises(TypeError):
            s.batch_offline("o1", ["a", "a"], 1.5, atomic="x")
        # 元素类型错先于 now_ms 类型错与重复。
        with self.assertRaises(TypeError):
            s.batch_offline("o2", ("a", 1), "x")
        # now_ms 类型错先于 atomic 类型错。
        with self.assertRaises(TypeError):
            s.batch_offline("o3", ("a",), 1.5, atomic=0)

    def test_values_length_duplicates(self):
        _auth, s = make()
        # 空批 ValueError。
        with self.assertRaises(ValueError):
            s.batch_offline("e0", (), 0)
        # sid 沿用凭据约束。
        with self.assertRaises(ValueError):
            s.batch_offline("v1", ("",), 0)
        with self.assertRaises(ValueError):
            s.batch_offline("v2", ("a\0",), 0)
        # now_ms 非负。
        with self.assertRaises(ValueError):
            s.batch_offline("v3", ("a",), -1)
        # 重复 sid ValueError（即使其中有未知项）。
        with self.assertRaises(ValueError):
            s.batch_offline("dup", ("a", "a"), 0)
        with self.assertRaises(ValueError):
            s.batch_offline("dup2", ("x", "y", "x"), 0)

    def test_length_bounds(self):
        _auth, s = make()
        one = tuple(f"s{i:04d}" for i in range(1))
        thousand = tuple(f"s{i:04d}" for i in range(1000))
        thousand_one = tuple(f"s{i:04d}" for i in range(1001))
        self.assertEqual(len(one), 1)
        self.assertEqual(len(thousand), 1000)
        self.assertEqual(len(thousand_one), 1001)
        # 全部未知不抛异常，故上界批正常返回“部分”。
        self.assertEqual(
            json.loads(s.batch_offline("b1", one, 0))["结果"], "部分"
        )
        self.assertEqual(
            json.loads(s.batch_offline("b1000", thousand, 0))["结果"], "部分"
        )
        with self.assertRaises(ValueError):
            s.batch_offline("b1001", thousand_one, 0)


class BatchOfflineCacheTest(unittest.TestCase):
    def test_param_exception_is_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.batch_offline("p", ("a", "a"), 0)
        # 首果为异常：异参复用仍 ValueError。
        with self.assertRaises(ValueError):
            s.batch_offline("p", ("a",), 0)
        with self.assertRaises(ValueError):
            s.batch_offline("p", ("a", "a"), 1)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_offline("k", ("a", "z"), 10)
        self.assertEqual(s.batch_offline("k", ("a", "z"), 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.batch_offline("k", ("a",), 0)  # a 下线，缓存 now=0
        # 此后新建 c，期限 100；以晚于期限的时刻重放旧 key（同参 now 仍 0），
        # 不得老化 c。
        s.do("e2", "建立", "c", ("alice", "pw"), 0)
        s.batch_offline("k", ("a",), 0)
        self.assertEqual(s._sessions["c"]["state"], "在线")
        self.assertIsNotNone(s._sessions["c"]["ip"])

    def test_different_params_value_error(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.batch_offline("k", ("a",), 0)
        with self.assertRaises(ValueError):
            s.batch_offline("k", ("a",), 1)
        with self.assertRaises(ValueError):
            s.batch_offline("k", ("b",), 0)
        # atomic 标志不同亦为异参；类型差异同样归 ValueError。
        with self.assertRaises(ValueError):
            s.batch_offline("k", ("a",), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.batch_offline("k", ("a",), 0, atomic=0)

    def test_cache_domain_separate(self):
        _auth, s = make()
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        # 与 do 同名字符串 key 互不指认。
        out = s.batch_offline("same", ("d",), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        # do 域同 key 重放仍返回首次建立结果（会话已下线，重放不老化、不改态）。
        replay = s.do("same", "建立", "d", ("alice", "pw"), 0)
        self.assertEqual(json.loads(replay)["状态"], "在线")
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
        out = s.batch_offline("same", ("d",), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")


class BatchOfflineNonAtomicTest(unittest.TestCase):
    def test_all_existing_commit(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.batch_offline("k", ("a", "b"), 10)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "a", "结果": "下线"},
                    {"会话": "b", "结果": "下线"},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid in ("a", "b"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "下线")
            self.assertEqual(session["deadline"], 0)
            self.assertIsNone(session["ip"])

    def test_unknown_does_not_block_later_items(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.batch_offline("k", ("x", "a", "y", "b", "z"), 10)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [
                ("x", "未知"),
                ("a", "下线"),
                ("y", "未知"),
                ("b", "下线"),
                ("z", "未知"),
            ],
        )
        # 现存项确已下线，未知项不留痕。
        self.assertEqual(s._sessions["a"]["state"], "下线")
        self.assertEqual(s._sessions["b"]["state"], "下线")
        self.assertNotIn("x", s._sessions)

    def test_tombstone_and_suspended_count_as_existing(self):
        # idle=100：b 在 t=200 已老化为挂起，但仍是现存项。
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        s.do("e3", "下线", "a", None, 0)  # a 下线墓碑
        self.assertEqual(s._sessions["b"]["state"], "在线")
        out = s.batch_offline("k", ("a", "b", "q"), 200)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "下线"), ("b", "下线"), ("q", "未知")],
        )
        self.assertEqual(s._sessions["a"]["state"], "下线")
        self.assertEqual(s._sessions["b"]["state"], "下线")
        self.assertEqual(s._sessions["b"]["deadline"], 0)
        self.assertIsNone(s._sessions["b"]["ip"])

    def test_leases_released_back_to_pool(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        pool = s._pools["default"]
        self.assertEqual(len(pool.leases), 2)
        s.batch_offline("k", ("a", "b"), 0)
        self.assertEqual(pool.leases, {})
        self.assertEqual(len(pool.free), pool.capacity)
        stats = json.loads(s.pool_stats(0))["池"][0]
        self.assertEqual(stats[4], 0)  # 租用 0

    def test_static_lease_released_but_not_returned_to_dynamic(self):
        _auth, s = make(pool=("10.0.0.0/30", (), (("alice", "10.0.0.1"),)))
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        pool = s._pools["default"]
        static_ip = next(iter(pool.static_ips))
        self.assertIn(static_ip, pool.leases)
        s.batch_offline("k", ("a",), 0)
        self.assertNotIn(static_ip, pool.leases)
        # 静态址不回动态堆。
        self.assertNotIn(static_ip, pool.free)

    def test_aging_runs_before_processing(self):
        # 租期到期但未到空闲期限：老化先释址，下线项再清期限。
        _auth, s = make(idle_ms=100000, lease_ms=50)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.batch_offline("k", ("a",), 50)
        self.assertEqual(json.loads(out)["结果"], "提交")
        session = s._sessions["a"]
        self.assertEqual(session["state"], "下线")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])
        self.assertIsNone(session["pool"])


class BatchOfflineAtomicTest(unittest.TestCase):
    def test_all_existing_commit(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.batch_offline("k", ("b", "a"), 10, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": True,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "下线"},
                    {"会话": "a", "结果": "下线"},
                ],
            }),
        )
        for sid in ("a", "b"):
            self.assertEqual(s._sessions[sid]["state"], "下线")

    def test_some_unknown_rolls_back_entire_batch(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        a_before = dict(s._sessions["a"])
        b_before = dict(s._sessions["b"])
        out = s.batch_offline("k", ("a", "x", "b"), 10, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "回滚"), ("x", "未知"), ("b", "回滚")],
        )
        # 整批不执行：现存会话状态、期限、地址、租期保持老化后快照。
        for sid, before in (("a", a_before), ("b", b_before)):
            session = s._sessions[sid]
            self.assertEqual(session["state"], before["state"])
            self.assertEqual(session["deadline"], before["deadline"])
            self.assertEqual(session["ip"], before["ip"])
            self.assertEqual(session["lease"], before["lease"])
        # 租约未释放。
        self.assertEqual(len(s._pools["default"].leases), 2)

    def test_all_unknown_rollback(self):
        _auth, s = make()
        out = s.batch_offline("k", ("p", "q"), 10, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("p", "未知"), ("q", "未知")],
        )
        self.assertEqual(len(s._sessions), 0)

    def test_rollback_preserves_aging(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        # a 在 t=200 老化为挂起并释址；批因未知项回滚但保留老化。
        out = s.batch_offline("k", ("a", "z"), 200, atomic=True)
        self.assertEqual(json.loads(out)["结果"], "回滚")
        session = s._sessions["a"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])

    def test_commit_releases_leases(self):
        _auth, s = make(pool=("10.0.0.0/30", (), ()))
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.batch_offline("k", ("a", "b"), 0, atomic=True)
        self.assertEqual(json.loads(out)["结果"], "提交")
        self.assertEqual(s._pools["default"].leases, {})

    def test_rollback_replay_does_not_mutate(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        first = s.batch_offline("k", ("a", "z"), 10, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        self.assertEqual(s._sessions["a"]["state"], "在线")
        # 同参重放返回逐字节相同结果，仍不执行下线。
        self.assertEqual(
            s.batch_offline("k", ("a", "z"), 10, atomic=True), first
        )
        self.assertEqual(s._sessions["a"]["state"], "在线")
        self.assertIsNotNone(s._sessions["a"]["ip"])


class BatchOfflineNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        # 建立会写防篡改链；记录其后链长。
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        s.batch_offline("n1", ("a", "x"), 10)                       # 部分
        s.batch_offline("n1", ("a", "x"), 10)                       # 重放
        s.batch_offline("r1", ("a", "q"), 10, atomic=True)         # 回滚
        s.batch_offline("r1", ("a", "q"), 10, atomic=True)         # 重放
        s.do("e2", "建立", "c", ("alice", "pw"), 20)
        s.batch_offline("n2", ("c",), 30)                            # 提交
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        # 仅 e1/e2 两条建立事件，批量下线不入链。
        self.assertEqual(len(after_chain), before_chain + 1)
        self.assertEqual([e["操作"] for e in after_chain], ["建立", "建立"])
        self.assertEqual(len(after_cap), before_cap)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        # 接管审计亦为空。
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_unknown_does_not_count_failure(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        before = json.loads(s.runtime_stats(0))["失败"]
        s.batch_offline("n1", ("a", "x"), 10)
        s.batch_offline("r1", ("y",), 10, atomic=True)
        after = json.loads(s.runtime_stats(0))["失败"]
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
