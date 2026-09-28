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


class KeepaliveParamTest(unittest.TestCase):
    def test_key_credential_rule_checked_first(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.keepalive(bad, ("a",), 0)
        # 空串 key 为取值错，先于 sids 容器类型错。
        with self.assertRaises(ValueError):
            s.keepalive("", ["a"], 0)
        # key 非法在缓存查表之前抛出，故不留缓存、不影响任何合法 key。
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.keepalive("good", ("a",), 1)
        self.assertEqual(json.loads(out)["结果"], "提交")

    def test_types(self):
        _auth, s = make()
        # sids 必须是 tuple：str/list/set/None 均 TypeError。
        for bad in (["a"], {"a"}, "a", None, (x for x in ("a",))):
            with self.assertRaises(TypeError):
                s.keepalive("k" + str(type(bad)), bad, 0)
        # 每个 sid 必须是 str。
        with self.assertRaises(TypeError):
            s.keepalive("t1", (1,), 0)
        with self.assertRaises(TypeError):
            s.keepalive("t2", ("a", None), 0)
        # now_ms 为非 bool int。
        for i, bad in enumerate((1.5, "0", None, True, False)):
            with self.assertRaises(TypeError):
                s.keepalive(f"n{i}", ("a",), bad)
        # atomic 为 bool。
        for i, bad in enumerate((0, 1, "false", None)):
            with self.assertRaises(TypeError):
                s.keepalive(f"at{i}", ("a",), 0, atomic=bad)

    def test_type_errors_precede_value_errors(self):
        _auth, s = make()
        # 容器类型错先于 now_ms 类型/取值与重复。
        with self.assertRaises(TypeError):
            s.keepalive("o1", ["a", "a"], 1.5, atomic="x")
        # 元素类型错先于 now_ms 类型错与重复。
        with self.assertRaises(TypeError):
            s.keepalive("o2", ("a", 1), "x")
        # now_ms 类型错先于 atomic 类型错。
        with self.assertRaises(TypeError):
            s.keepalive("o3", ("a",), 1.5, atomic=0)

    def test_values_length_duplicates(self):
        _auth, s = make()
        # 空批 ValueError。
        with self.assertRaises(ValueError):
            s.keepalive("e0", (), 0)
        # sid 沿用凭据约束。
        with self.assertRaises(ValueError):
            s.keepalive("v1", ("",), 0)
        with self.assertRaises(ValueError):
            s.keepalive("v2", ("a\0",), 0)
        # now_ms 非负。
        with self.assertRaises(ValueError):
            s.keepalive("v3", ("a",), -1)
        # 重复 sid ValueError（即使其中有未知项）。
        with self.assertRaises(ValueError):
            s.keepalive("dup", ("a", "a"), 0)
        with self.assertRaises(ValueError):
            s.keepalive("dup2", ("x", "y", "x"), 0)

    def test_length_bounds(self):
        _auth, s = make(idle_ms=100)
        one = tuple(f"s{i:04d}" for i in range(1))
        thousand = tuple(f"s{i:04d}" for i in range(1000))
        thousand_one = tuple(f"s{i:04d}" for i in range(1001))
        self.assertEqual(len(one), 1)
        self.assertEqual(len(thousand), 1000)
        self.assertEqual(len(thousand_one), 1001)
        # 全部未知不抛异常，故上界批正常返回“部分”。
        self.assertEqual(json.loads(s.keepalive("b1", one, 0))["结果"], "部分")
        self.assertEqual(
            json.loads(s.keepalive("b1000", thousand, 0))["结果"], "部分"
        )
        with self.assertRaises(ValueError):
            s.keepalive("b1001", thousand_one, 0)


class KeepaliveCacheTest(unittest.TestCase):
    def test_param_exception_is_cached(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(ValueError):
                s.keepalive("p", ("a", "a"), 0)
        # 首果为异常：异参复用仍 ValueError。
        with self.assertRaises(ValueError):
            s.keepalive("p", ("a",), 0)
        with self.assertRaises(ValueError):
            s.keepalive("p", ("a", "a"), 1)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.keepalive("k", ("a", "z"), 10)
        self.assertEqual(s.keepalive("k", ("a", "z"), 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.keepalive("k", ("a",), 0)  # a 保活，缓存 now=0（新期限 100）
        # 此后新建 c，期限 100；以晚于期限的时刻重放旧 key（同参 now 仍 0），
        # 不得老化 c，也不得再次延长 a。
        s.do("e2", "建立", "c", ("alice", "pw"), 0)
        s.keepalive("k", ("a",), 0)
        self.assertEqual(s._sessions["c"]["state"], "在线")
        self.assertIsNotNone(s._sessions["c"]["ip"])
        self.assertEqual(s._sessions["a"]["deadline"], 100)

    def test_different_params_value_error(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.keepalive("k", ("a",), 0)
        with self.assertRaises(ValueError):
            s.keepalive("k", ("a",), 1)
        with self.assertRaises(ValueError):
            s.keepalive("k", ("b",), 0)
        # atomic 标志不同亦为异参；类型差异同样归 ValueError。
        with self.assertRaises(ValueError):
            s.keepalive("k", ("a",), 0, atomic=True)
        with self.assertRaises(ValueError):
            s.keepalive("k", ("a",), 0, atomic=0)

    def test_cache_domain_separate(self):
        _auth, s = make(idle_ms=100)
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        # 与 do 同名字符串 key 互不指认。
        out = s.keepalive("same", ("d",), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        # do 域同 key 重放仍返回首次建立结果（重放不老化、不改态）。
        replay = s.do("same", "建立", "d", ("alice", "pw"), 0)
        self.assertEqual(json.loads(replay)["状态"], "在线")
        # 与 fault/pool_fault/timeout_fault/batch_offline/batch_online 各域独立。
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
        self.assertEqual(
            json.loads(s.batch_offline("same", ("d",), 0))["结果"], "提交"
        )


class KeepaliveNonAtomicTest(unittest.TestCase):
    def test_all_online_commit_extends_deadline_only(self):
        _auth, s = make(lease_ms=50)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.keepalive("k", ("b", "a"), 10)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "保活", "期限": 100010},
                    {"会话": "a", "结果": "保活", "期限": 100010},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid in ("a", "b"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "在线")
            self.assertEqual(session["deadline"], 100010)
            # 保活只改期限：租期不续租（仍为建立时的 50），地址不变。
            self.assertEqual(session["lease"], 50)
            self.assertIsNotNone(session["ip"])

    def test_unknown_does_not_block_later_items(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.keepalive("k", ("x", "a", "y", "b", "z"), 10)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertFalse(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [
                ("x", "未知", 0),
                ("a", "保活", 100010),
                ("y", "未知", 0),
                ("b", "保活", 100010),
                ("z", "未知", 0),
            ],
        )
        self.assertEqual(s._sessions["a"]["deadline"], 100010)
        self.assertEqual(s._sessions["b"]["deadline"], 100010)
        self.assertNotIn("x", s._sessions)

    def test_suspended_and_tombstone_record_state(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        s.do("e3", "建立", "c", ("alice", "pw"), 0)
        s.do("g1", "挂起", "a", None, 0)   # a 挂起
        s.do("o1", "下线", "c", None, 0)  # c 下线墓碑
        out = s.keepalive("k", ("a", "b", "c", "q"), 10)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [
                ("a", "状态", 0),
                ("b", "保活", 110),
                ("c", "状态", 0),
                ("q", "未知", 0),
            ],
        )
        self.assertEqual(s._sessions["a"]["state"], "挂起")
        self.assertEqual(s._sessions["a"]["deadline"], 0)
        self.assertEqual(s._sessions["c"]["state"], "下线")
        self.assertEqual(s._sessions["c"]["deadline"], 0)
        self.assertEqual(s._sessions["b"]["deadline"], 110)

    def test_aging_suspends_expired_online_before_keepalive(self):
        # idle=100：a 在 t=100（含同刻）老化为挂起并释址，再记“状态”。
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.keepalive("k", ("a",), 100)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [("a", "状态", 0)],
        )
        session = s._sessions["a"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])
        self.assertIsNone(session["pool"])

    def test_keptalive_session_ages_by_new_deadline(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.keepalive("k", ("a",), 50)          # 期限 50 -> 150
        self.assertEqual(s._sessions["a"]["deadline"], 150)
        # 旧期限已过但新期限未到：另一写接口的老化不应挂起 a。
        s.do("q1", "建立", "z", ("alice", "pw"), 120)
        self.assertEqual(s._sessions["a"]["state"], "在线")
        self.assertIsNotNone(s._sessions["a"]["ip"])


class KeepaliveAtomicTest(unittest.TestCase):
    def test_all_online_commit(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.keepalive("k", ("b", "a"), 10, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 10,
                "原子": True,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "保活", "期限": 100010},
                    {"会话": "a", "结果": "保活", "期限": 100010},
                ],
            }),
        )
        for sid in ("a", "b"):
            self.assertEqual(s._sessions[sid]["state"], "在线")
            self.assertEqual(s._sessions[sid]["deadline"], 100010)

    def test_some_failed_rolls_back_entire_batch(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        s.do("g1", "挂起", "b", None, 0)  # b 挂起
        a_before = dict(s._sessions["a"])
        out = s.keepalive("k", ("a", "x", "b"), 10, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [
                ("a", "回滚", 0),
                ("x", "未知", 0),
                ("b", "状态", 0),
            ],
        )
        # 在线项期限不延长、租期/地址不变；挂起项保持挂起。
        a = s._sessions["a"]
        self.assertEqual(a["state"], a_before["state"])
        self.assertEqual(a["deadline"], a_before["deadline"])
        self.assertEqual(a["ip"], a_before["ip"])
        self.assertEqual(a["lease"], a_before["lease"])
        self.assertEqual(s._sessions["b"]["state"], "挂起")
        self.assertEqual(len(s._pools["default"].leases), 1)

    def test_all_unknown_rollback(self):
        _auth, s = make()
        out = s.keepalive("k", ("p", "q"), 10, atomic=True)
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
        # a 在 t=100 老化为挂起并释址；批因未知项回滚但保留老化，a 归“状态”。
        out = s.keepalive("k", ("a", "z"), 100, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in doc["项目"]],
            [("a", "状态"), ("z", "未知")],
        )
        session = s._sessions["a"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])

    def test_rollback_replay_does_not_mutate(self):
        _auth, s = make(idle_ms=100)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        first = s.keepalive("k", ("a", "z"), 10, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        self.assertEqual(s._sessions["a"]["deadline"], 100)
        # 同参重放逐字节相同，仍不延长期限。
        self.assertEqual(
            s.keepalive("k", ("a", "z"), 10, atomic=True), first
        )
        self.assertEqual(s._sessions["a"]["deadline"], 100)
        self.assertIsNotNone(s._sessions["a"]["ip"])


class KeepaliveNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        s.keepalive("n1", ("a", "x"), 10)                    # 部分
        s.keepalive("n1", ("a", "x"), 10)                    # 重放
        s.keepalive("r1", ("a", "q"), 10, atomic=True)      # 回滚
        s.keepalive("r1", ("a", "q"), 10, atomic=True)      # 重放
        s.do("e2", "建立", "c", ("alice", "pw"), 20)
        s.keepalive("n2", ("c",), 30)                        # 提交
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        # 仅 e1/e2 两条建立事件，批量保活不入链。
        self.assertEqual(len(after_chain), before_chain + 1)
        self.assertEqual([e["操作"] for e in after_chain], ["建立", "建立"])
        self.assertEqual(len(after_cap), before_cap)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_no_failure_or_establish_counts(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        before = json.loads(s.runtime_stats(0))["失败"]
        s.keepalive("n1", ("a", "x"), 10)
        s.keepalive("r1", ("y",), 10, atomic=True)
        after = json.loads(s.runtime_stats(0))["失败"]
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
