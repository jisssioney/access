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
        _auth, s = make()
        one = tuple(f"s{i:04d}" for i in range(1))
        thousand = tuple(f"s{i:04d}" for i in range(1000))
        thousand_one = tuple(f"s{i:04d}" for i in range(1001))
        # 全部未知不抛异常，故上界批正常返回“部分”。
        self.assertEqual(
            json.loads(s.keepalive("b1", one, 0))["结果"], "部分"
        )
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

    def test_type_exception_is_cached_same_class(self):
        _auth, s = make()
        for _ in range(2):
            with self.assertRaises(TypeError):
                s.keepalive("t", (1,), 0)

    def test_same_params_byte_identical_replay(self):
        _auth, s = make(idle_ms=1000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.keepalive("k", ("a", "z"), 10)
        self.assertEqual(s.keepalive("k", ("a", "z"), 10), out)

    def test_replay_does_not_age_or_mutate(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.keepalive("k", ("a",), 0)  # a 期限保活为 100，缓存 now=0
        # 此后新建 c，期限 100；以晚于期限的时刻重放旧 key（同参 now 仍 0），
        # 不得老化 c，也不得再改 a。
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
        _auth, s = make()
        s.do("same", "建立", "d", ("alice", "pw"), 0)
        # 与 do 同名字符串 key 互不指认。
        out = s.keepalive("same", ("d",), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")
        # do 域同 key 重放仍返回首次建立结果（重放不老化、不改态）。
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
        out = s.keepalive("same", ("d",), 0)
        self.assertEqual(json.loads(out)["结果"], "提交")


class KeepaliveNonAtomicTest(unittest.TestCase):
    def test_all_online_commit_extends_deadline_only(self):
        _auth, s = make(idle_ms=1000, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        lease_a = s._sessions["a"]["lease"]
        ip_a = s._sessions["a"]["ip"]
        out = s.keepalive("k", ("a", "b"), 500)
        self.assertEqual(
            out,
            wire({
                "时刻": 500,
                "原子": False,
                "结果": "提交",
                "项目": [
                    {"会话": "a", "结果": "保活", "期限": 1500},
                    {"会话": "b", "结果": "保活", "期限": 1500},
                ],
            }),
        )
        self.assertEqual(list(json.loads(out)), ["时刻", "原子", "结果", "项目"])
        for sid in ("a", "b"):
            session = s._sessions[sid]
            self.assertEqual(session["state"], "在线")
            self.assertEqual(session["deadline"], 1500)
        # 保活只改期限：租期、地址不变。
        self.assertEqual(s._sessions["a"]["lease"], lease_a)
        self.assertEqual(s._sessions["a"]["ip"], ip_a)

    def test_unknown_does_not_block_later_items(self):
        _auth, s = make(idle_ms=1000)
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
                ("a", "保活", 1010),
                ("y", "未知", 0),
                ("b", "保活", 1010),
                ("z", "未知", 0),
            ],
        )
        self.assertNotIn("x", s._sessions)

    def test_suspended_and_tombstone_count_as_state(self):
        # idle=100：b 在 t=200 已老化为挂起；a 为下线墓碑，二者记“状态”。
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        s.do("e3", "建立", "c", ("alice", "pw"), 150)  # c 期限 250
        s.do("off1", "下线", "a", None, 0)
        out = s.keepalive("k", ("x", "a", "b", "c"), 200)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [
                ("x", "未知", 0),
                ("a", "状态", 0),
                ("b", "状态", 0),
                ("c", "保活", 300),
            ],
        )
        # 挂起会话不持址；保活的 c 租期与地址不变。
        self.assertEqual(s._sessions["b"]["state"], "挂起")
        self.assertIsNone(s._sessions["b"]["ip"])
        self.assertEqual(s._sessions["c"]["deadline"], 300)
        self.assertEqual(s._sessions["c"]["lease"], 100150)
        self.assertIsNotNone(s._sessions["c"]["ip"])
        # 墓碑保持下线、期限 0。
        self.assertEqual(s._sessions["a"]["state"], "下线")
        self.assertEqual(s._sessions["a"]["deadline"], 0)

    def test_aging_runs_before_processing_inclusive_boundary(self):
        # 期限 <= now_ms 的在线项先挂起、退租，故记“状态”而非“保活”。
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.keepalive("k", ("a",), 100)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "部分")
        self.assertEqual(
            [(it["结果"], it["期限"]) for it in doc["项目"]], [("状态", 0)]
        )
        session = s._sessions["a"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])
        self.assertIsNone(session["pool"])

    def test_lease_expired_address_released_but_still_kept_alive(self):
        # 租期到期但未到空闲期限：老化退租释址，会话仍在线，保活仅改期限，
        # 不重新分址、不续租。
        _auth, s = make(idle_ms=100000, lease_ms=50)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        out = s.keepalive("k", ("a",), 50)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "提交")
        session = s._sessions["a"]
        self.assertEqual(session["state"], "在线")
        self.assertEqual(session["deadline"], 100050)
        self.assertIsNone(session["ip"])
        self.assertEqual(session["lease"], 0)
        self.assertEqual(doc["项目"][0]["期限"], 100050)


class KeepaliveAtomicTest(unittest.TestCase):
    def test_all_online_commit(self):
        _auth, s = make(idle_ms=1000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        out = s.keepalive("k", ("b", "a"), 100, atomic=True)
        self.assertEqual(
            out,
            wire({
                "时刻": 100,
                "原子": True,
                "结果": "提交",
                "项目": [
                    {"会话": "b", "结果": "保活", "期限": 1100},
                    {"会话": "a", "结果": "保活", "期限": 1100},
                ],
            }),
        )
        self.assertEqual(s._sessions["a"]["deadline"], 1100)
        self.assertEqual(s._sessions["b"]["deadline"], 1100)

    def test_some_unknown_rolls_back_entire_batch(self):
        _auth, s = make(idle_ms=1000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        deadline_a = s._sessions["a"]["deadline"]
        lease_a = s._sessions["a"]["lease"]
        ip_a = s._sessions["a"]["ip"]
        out = s.keepalive("k", ("a", "x", "b"), 100, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertTrue(doc["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [("a", "回滚", 0), ("x", "未知", 0), ("b", "回滚", 0)],
        )
        # 整批不延长：在线项状态、期限、地址、租期保持老化后快照。
        self.assertEqual(s._sessions["a"]["deadline"], deadline_a)
        self.assertEqual(s._sessions["a"]["lease"], lease_a)
        self.assertEqual(s._sessions["a"]["ip"], ip_a)
        self.assertEqual(s._sessions["b"]["deadline"], deadline_a)
        self.assertEqual(len(s._pools["default"].leases), 2)

    def test_suspended_or_tombstone_marks_state_and_rolls_back_online(self):
        _auth, s = make(idle_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "b", ("alice", "pw"), 0)
        s.do("sus", "挂起", "b", None, 0)
        out = s.keepalive("k", ("a", "b", "x"), 50, atomic=True)
        doc = json.loads(out)
        self.assertEqual(doc["结果"], "回滚")
        self.assertEqual(
            [(it["会话"], it["结果"], it["期限"]) for it in doc["项目"]],
            [("a", "回滚", 0), ("b", "状态", 0), ("x", "未知", 0)],
        )
        # 在线项不延长，挂起项不改。
        self.assertEqual(s._sessions["a"]["deadline"], 100000)
        self.assertEqual(s._sessions["b"]["state"], "挂起")
        self.assertEqual(s._sessions["b"]["deadline"], 0)

    def test_rollback_preserves_aging(self):
        _auth, s = make(idle_ms=100, lease_ms=100000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        # a 在 t=200 老化为挂起并释址；批因未知项回滚但保留老化。
        out = s.keepalive("k", ("a", "z"), 200, atomic=True)
        self.assertEqual(json.loads(out)["结果"], "回滚")
        session = s._sessions["a"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])

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

    def test_rollback_replay_does_not_mutate(self):
        _auth, s = make(idle_ms=1000)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        first = s.keepalive("k", ("a", "z"), 100, atomic=True)
        self.assertEqual(json.loads(first)["结果"], "回滚")
        self.assertEqual(s._sessions["a"]["deadline"], 1000)
        # 同参重放逐字节相同，仍不延长。
        self.assertEqual(
            s.keepalive("k", ("a", "z"), 100, atomic=True), first
        )
        self.assertEqual(s._sessions["a"]["deadline"], 1000)
        self.assertIsNotNone(s._sessions["a"]["ip"])


class KeepaliveNoSideEffectsTest(unittest.TestCase):
    def test_no_audit_or_capacity_events_or_stats(self):
        _auth, s = make()
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        s.do("e2", "建立", "c", ("alice", "pw"), 20)
        # 在两次建立之后取基线：保活本身不得再动建立/失败统计。
        before_chain = len(json.loads(s.audit(limit=1000))["事件"])
        before_cap = len(json.loads(s.capacity_events(limit=1000))["事件"])
        before_est = json.loads(s.runtime_stats(0))["建立"]
        before_fail = json.loads(s.runtime_stats(0))["失败"]
        s.keepalive("n1", ("a", "x"), 10)                       # 部分
        s.keepalive("n1", ("a", "x"), 10)                       # 重放
        s.keepalive("r1", ("a", "q"), 10, atomic=True)         # 回滚
        s.keepalive("r1", ("a", "q"), 10, atomic=True)         # 重放
        s.keepalive("n2", ("c",), 30)                            # 提交
        after_chain = json.loads(s.audit(limit=1000))["事件"]
        after_cap = json.loads(s.capacity_events(limit=1000))["事件"]
        after_est = json.loads(s.runtime_stats(0))["建立"]
        after_fail = json.loads(s.runtime_stats(0))["失败"]
        # 批量保活不入链、不记容量事件、不动建立/失败统计。
        self.assertEqual(len(after_chain), before_chain)
        self.assertEqual([e["操作"] for e in after_chain], ["建立", "建立"])
        self.assertEqual(len(after_cap), before_cap)
        self.assertEqual(after_est, before_est)
        self.assertEqual(after_fail, before_fail)
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        self.assertEqual(json.loads(s.takeover_audit())["事件"], [])

    def test_does_not_renew_lease_or_reassign_address(self):
        # 保活只改空闲期限：地址仍持有时租期保持原值。
        _auth, s = make(idle_ms=100000, lease_ms=80)
        s.do("e1", "建立", "a", ("alice", "pw"), 0)
        pool = s._pools["default"]
        self.assertEqual(len(pool.leases), 1)
        s.keepalive("k", ("a",), 50)
        session = s._sessions["a"]
        self.assertEqual(session["deadline"], 100050)  # 期限顺延
        self.assertEqual(session["lease"], 80)         # 租期不顺延
        self.assertIsNotNone(session["ip"])
        self.assertEqual(len(pool.leases), 1)


if __name__ == "__main__":
    unittest.main()
