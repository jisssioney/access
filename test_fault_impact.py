import copy
import hashlib
import json
import unittest

from access import (
    Authenticator,
    Sessions,
)


def make(users=("alice", "bob", "carol", "dave"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def expected_digest(doc):
    """摘要 = 前三键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写值。"""
    head = {"时刻": doc["时刻"], "域": doc["域"], "合计": doc["合计"]}
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


BACKEND = ("后端", "", "注入", 100)
TIMEOUT = ("超时", "", "注入", 50)


class ParamTest(unittest.TestCase):
    def test_steps_type_errors(self):
        _auth, s = make()
        for bad in ([], "x", 1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.fault_impact(bad, 0)
        # 步项非 tuple。
        with self.assertRaises(TypeError):
            s.fault_impact((["后端", "", "注入", 1],), 0)
        # 前三字段非 str（bool 亦非 str）。
        for bad in (1, True, None, ()):
            with self.assertRaises(TypeError):
                s.fault_impact(((bad, "", "注入", 1),), 0)
        # 注入 value 非 int 或 bool。
        for bad in (True, 1.5, "1", None):
            with self.assertRaises(TypeError):
                s.fault_impact((("后端", "", "注入", bad),), 0)

    def test_now_ms_type_errors(self):
        _auth, s = make()
        for bad in (True, 1.5, "5", None, []):
            with self.assertRaises(TypeError):
                s.fault_impact((BACKEND,), bad)

    def test_type_error_precedes_value_error(self):
        _auth, s = make()
        # steps 容器类型错先于 now_ms 类型/取值错。
        with self.assertRaises(TypeError):
            s.fault_impact([], True)
        with self.assertRaises(TypeError):
            s.fault_impact(1, -1)

    def test_structure_and_value_errors(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault_impact((), 0)
        for bad in (
            ("后端", "", "注入"),               # 3 元组
            ("后端", "", "注入", 1, 2),         # 5 元组
        ):
            with self.assertRaises(ValueError):
                s.fault_impact((bad,), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("怪域", "", "注入", 1),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("后端", "", "怪op", 1),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("后端", "x", "注入", 1),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("超时", "x", "注入", 1),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("池", "", "注入", 1),), 0)
        # 后端/超时项各域唯一；池项互异。
        with self.assertRaises(ValueError):
            s.fault_impact(
                (("后端", "", "注入", 1), ("后端", "", "恢复", None)), 0
            )
        with self.assertRaises(ValueError):
            s.fault_impact(
                (("超时", "", "注入", 0), ("超时", "", "恢复", None)), 0
            )
        with self.assertRaises(ValueError):
            s.fault_impact(
                (("池", "default", "注入", 1),
                 ("池", "default", "注入", 2)), 0
            )
        # 注入取值：后端/池须正 int；超时注入 >= now_ms。
        with self.assertRaises(ValueError):
            s.fault_impact((("后端", "", "注入", 0),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("池", "default", "注入", -1),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("超时", "", "注入", -1),), 0)
        # 恢复 value 须 None（bool 归取值错，类型阶段不可判定）。
        with self.assertRaises(ValueError):
            s.fault_impact((("后端", "", "恢复", 0),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("后端", "", "恢复", True),), 0)

    def test_now_ms_negative(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault_impact((BACKEND,), -1)

    def test_step_count_bounds(self):
        _auth, s = make()
        # 1001 项（同池重复目标）即取值错。
        with self.assertRaises(ValueError):
            s.fault_impact(
                tuple(("池", "default", "注入", 1) for _ in range(1001)), 0
            )
        # 1000 个互异现存池注入合法。
        for i in range(1000):
            s.add_pool(f"p{i:04d}", (f"10.{4 + i // 256}.{i % 256}.0/24", (), ()))
        steps = tuple(("池", f"p{i:04d}", "注入", 1) for i in range(1000))
        doc = json.loads(s.fault_impact(steps, 0))
        self.assertEqual(len(doc["域"]), 1002)

    def test_unknown_pool_keyerror(self):
        _auth, s = make()
        with self.assertRaises(KeyError):
            s.fault_impact((("池", "nosuch", "注入", 1),), 0)
        with self.assertRaises(KeyError):
            s.fault_impact((("池", "nosuch", "恢复", None),), 0)
        # 值错先于未知池。
        with self.assertRaises(ValueError):
            s.fault_impact((("池", "nosuch", "注入", 0),), 0)
        with self.assertRaises(ValueError):
            s.fault_impact((("池", "nosuch", "怪op", None),), 0)


class ShapeTest(unittest.TestCase):
    def test_top_level_and_row_key_order(self):
        _auth, s = make()
        out = s.fault_impact((BACKEND,), 0)
        self.assertTrue(out.endswith("\n") and not out.endswith("\n\n"))
        doc = json.loads(out)
        self.assertEqual(list(doc), ["时刻", "域", "合计", "摘要"])
        self.assertEqual(list(doc["合计"]), ["在线", "挂起", "排队", "租约"])
        for row in doc["域"]:
            self.assertEqual(
                list(row), ["域", "目标", "生效", "在线", "挂起", "排队", "租约"]
            )

    def test_empty_state_rows(self):
        _auth, s = make()
        # 无会话无队列：后端与超时两行恒在；本计划无注入池故无池行。
        doc = json.loads(s.fault_impact((BACKEND, TIMEOUT), 50))
        self.assertEqual(
            [(r["域"], r["目标"]) for r in doc["域"]],
            [("后端", ""), ("超时", "")],
        )
        backend, timeout = doc["域"]
        self.assertEqual(
            backend,
            {"域": "后端", "目标": "", "生效": True,
             "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertEqual(
            timeout,
            {"域": "超时", "目标": "", "生效": True,
             "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0})
        self.assertEqual(doc["摘要"], expected_digest(doc))


class BackendRowTest(unittest.TestCase):
    def test_active_counts_global_four(self):
        _auth, s = make(total=2)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "挂起", "s1", None, 5)       # 真挂起（仍占全局上限）
        # 非下线会话 s1(挂起)+s2(在线)=2 达上限，dave 入队。
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 0)  # 排队
        doc = json.loads(s.fault_impact((BACKEND,), 50))
        (row,) = [r for r in doc["域"] if r["域"] == "后端"]
        self.assertEqual(
            row,
            {"域": "后端", "目标": "", "生效": True,
             "在线": 1, "挂起": 1, "排队": 1, "租约": 1},
        )
        self.assertEqual(doc["合计"], {"在线": 1, "挂起": 1, "排队": 1, "租约": 1})
        self.assertEqual(doc["摘要"], expected_digest(doc))

    def test_recover_step_inactive_zero_row(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        doc = json.loads(s.fault_impact((("后端", "", "恢复", None),), 50))
        self.assertEqual(doc["域"][0]["生效"], False)
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0})

    def test_existing_expired_fault_row_inactive(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fx", "注入", 10, 0)             # 截至 10
        # 计划不列后端（未列域不变）：截至已过，行不生效。
        doc = json.loads(s.fault_impact((TIMEOUT,), 50))
        self.assertEqual(doc["域"][0]["目标"], "")
        self.assertFalse(doc["域"][0]["生效"])
        self.assertEqual(doc["域"][0]["在线"], 0)
        self.assertEqual(s._fault_until, 10)     # 只读：实例态不变

    def test_existing_active_fault_row_active_when_unlisted(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fx", "注入", 1000, 0)           # 截至 1000
        doc = json.loads(s.fault_impact((TIMEOUT,), 50))
        self.assertTrue(doc["域"][0]["生效"])
        self.assertEqual(doc["域"][0]["在线"], 1)


class ViewTest(unittest.TestCase):
    def test_deadline_equality_means_suspended(self):
        _auth, s = make(idle_ms=100)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)   # 期限 100
        # 同刻：在线归挂起。
        doc = json.loads(s.fault_impact((BACKEND,), 100))
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 1, "排队": 0, "租约": 0})
        # 存储态未被老化改写。
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        # 前一刻仍在线。
        doc = json.loads(s.fault_impact((BACKEND,), 99))
        self.assertEqual(doc["合计"], {"在线": 1, "挂起": 0, "排队": 0, "租约": 1})

    def test_lease_equality_not_counted(self):
        _auth, s = make(idle_ms=100000, lease_ms=100)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)   # 期限大、租期 100
        doc = json.loads(s.fault_impact((BACKEND,), 100))
        # 期限未到计在线，租期同刻不计租约。
        self.assertEqual(doc["合计"], {"在线": 1, "挂起": 0, "排队": 0, "租约": 0})
        doc = json.loads(s.fault_impact((BACKEND,), 99))
        self.assertEqual(doc["合计"], {"在线": 1, "挂起": 0, "排队": 0, "租约": 1})

    def test_queue_deadline_equality_not_counted(self):
        _auth, s = make(total=2, per=2, pool=("10.0.0.0/30", (), ()))
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        out = s.capacity("q0", "申请", "q1", ("dave", "pw", 100), 0)
        self.assertEqual(json.loads(out)["结果"], "排队")  # 截止 100
        doc = json.loads(s.fault_impact((BACKEND,), 100))
        self.assertEqual(doc["域"][0]["排队"], 0)
        doc = json.loads(s.fault_impact((BACKEND,), 99))
        self.assertEqual(doc["域"][0]["排队"], 1)

    def test_offline_tombstones_never_counted(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "下线", "s1", None, 10)
        doc = json.loads(s.fault_impact((BACKEND,), 50))
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0})


class PoolRowTest(unittest.TestCase):
    def test_pool_rows_sorted_and_scoped(self):
        _auth, s = make(total=2)
        s.add_pool("pz", ("10.2.0.0/24", (), ()))
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "迁移", "s1", ("pa", "pw"), 10)   # s1 -> pa
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)  # 满，排队
        steps = (
            ("池", "pz", "注入", 100),
            ("池", "pa", "注入", 100),
            ("池", "default", "注入", 100),
        )
        doc = json.loads(s.fault_impact(steps, 50))
        names = [(r["域"], r["目标"]) for r in doc["域"]]
        # 后端、池按标识 Unicode 升序（default < pa < pz）、超时。
        self.assertEqual(
            names,
            [("后端", ""), ("池", "default"), ("池", "pa"),
             ("池", "pz"), ("超时", "")],
        )
        by_target = {r["目标"]: r for r in doc["域"] if r["域"] == "池"}
        self.assertFalse(by_target["default"]["生效"] is False)
        self.assertEqual(
            (by_target["default"]["在线"], by_target["default"]["挂起"],
             by_target["default"]["排队"], by_target["default"]["租约"]),
            (1, 0, 1, 1),
        )
        self.assertEqual(
            (by_target["pa"]["在线"], by_target["pa"]["挂起"],
             by_target["pa"]["排队"], by_target["pa"]["租约"]),
            (1, 0, 0, 1),
        )
        self.assertEqual(
            (by_target["pz"]["在线"], by_target["pz"]["排队"],
             by_target["pz"]["租约"]),
            (0, 0, 0),
        )

    def test_existing_expired_pool_fault_inactive_zero_row(self):
        _auth, s = make()
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "迁移", "s1", ("pa", "pw"), 10)
        s.pool_fault("pf", "注入", "pa", 10, 0)     # 截至 10
        # 计划不列该池：行保留但不生效，全 0。
        doc = json.loads(s.fault_impact((("后端", "", "恢复", None),), 50))
        rows = [(r["域"], r["目标"], r["生效"]) for r in doc["域"]]
        self.assertEqual(
            rows, [("后端", "", False), ("池", "pa", False), ("超时", "", False)]
        )
        pa = next(r for r in doc["域"] if r["目标"] == "pa")
        self.assertEqual(
            pa, {"域": "池", "目标": "pa", "生效": False,
                 "在线": 0, "挂起": 0, "排队": 0, "租约": 0}
        )

    def test_recover_step_removes_pool_row(self):
        _auth, s = make()
        s.pool_fault("pf", "注入", "default", 1000, 0)
        doc = json.loads(s.fault_impact((("池", "default", "恢复", None),), 50))
        self.assertEqual(
            [(r["域"], r["目标"]) for r in doc["域"]],
            [("后端", ""), ("超时", "")],
        )

    def test_non_default_pool_never_counts_queue(self):
        _auth, s = make(total=2, per=2, pool=("10.0.0.0/30", (), ()))
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 0)
        doc = json.loads(s.fault_impact((("池", "pa", "注入", 100),), 50))
        pa = next(r for r in doc["域"] if r["目标"] == "pa")
        self.assertEqual(pa["排队"], 0)
        self.assertEqual(pa["挂起"], 0)


class TimeoutRowTest(unittest.TestCase):
    def test_trigger_boundary(self):
        _auth, s = make(total=1)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 0)
        # 触发时刻恰为 now：生效（含同刻）。
        doc = json.loads(s.fault_impact((("超时", "", "注入", 50),), 50))
        row = doc["域"][-1]
        self.assertEqual(
            row,
            {"域": "超时", "目标": "", "生效": True,
             "在线": 1, "挂起": 0, "排队": 1, "租约": 1},
        )
        # 未到：不生效、全 0（挂起恒 0）。
        doc = json.loads(s.fault_impact((("超时", "", "注入", 51),), 50))
        self.assertFalse(doc["域"][-1]["生效"])
        self.assertEqual(doc["域"][-1]["挂起"], 0)
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0})

    def test_active_row_suspended_always_zero(self):
        _auth, s = make(idle_ms=100)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "挂起", "s2", None, 5)
        # t=100：s1 期限到（视图挂起），s2 真挂起；超时行挂起恒 0，
        # 在线/租约/排队按视图、不含挂起。
        doc = json.loads(s.fault_impact((("超时", "", "注入", 100),), 100))
        self.assertEqual(
            doc["域"][-1],
            {"域": "超时", "目标": "", "生效": True,
             "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )

    def test_recover_step_and_existing_state(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 恢复步骤：不等待，行不生效。
        doc = json.loads(s.fault_impact((("超时", "", "恢复", None),), 50))
        self.assertFalse(doc["域"][-1]["生效"])
        # 既有待触发且已到刻、计划不列超时：演算不触发清场，行生效。
        s.timeout_fault("t1", "注入", 20, 0)
        doc = json.loads(s.fault_impact((("后端", "", "恢复", None),), 50))
        self.assertTrue(doc["域"][-1]["生效"])
        self.assertEqual(doc["域"][-1]["在线"], 1)
        self.assertIsNotNone(s._timeout_at)       # 只读：未被触发清除


class TotalsAndDigestTest(unittest.TestCase):
    def test_totals_sum_rows_with_double_counting(self):
        _auth, s = make(total=2)
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "迁移", "s1", ("pa", "pw"), 10)
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)  # 满，排队
        steps = (
            ("后端", "", "注入", 100),
            ("池", "default", "注入", 100),
            ("池", "pa", "注入", 100),
            ("超时", "", "注入", 50),
        )
        doc = json.loads(s.fault_impact(steps, 50))
        # 后端：在线2 挂起0 排队1 租约2；default：在线1 排队1 租约1；
        # pa：在线1 租约1；超时：在线2 排队1 租约2。
        self.assertEqual(
            doc["合计"], {"在线": 6, "挂起": 0, "排队": 3, "租约": 6}
        )
        self.assertEqual(doc["摘要"], expected_digest(doc))

    def test_digest_and_byte_stability(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        steps = (BACKEND, TIMEOUT)
        first = s.fault_impact(steps, 50)
        self.assertEqual(first, s.fault_impact(steps, 50))
        doc = json.loads(first)
        self.assertEqual(doc["摘要"], expected_digest(doc))
        # 异时刻（顶层“时刻”不同）摘要不同。
        other = s.fault_impact(
            (("后端", "", "注入", 100), ("超时", "", "注入", 51)), 51
        )
        self.assertNotEqual(json.loads(other)["摘要"], doc["摘要"])

    def test_unicode_target_utf8_digest_no_ascii_escaping(self):
        _auth, s = make()
        s.add_pool("池γ", ("10.1.0.0/24", (), ()))
        raw = s.fault_impact((("池", "池γ", "注入", 100),), 50)
        self.assertIn("池γ", raw)
        self.assertNotIn("\\u", raw)
        self.assertTrue(raw.endswith("\n"))
        doc = json.loads(raw)
        self.assertEqual(doc["摘要"], expected_digest(doc))


class ReadOnlyTest(unittest.TestCase):
    def _snapshot(self, s):
        return (
            s._fault_until,
            copy.deepcopy(s._pool_fault),
            s._timeout_at,
            copy.deepcopy(s._sessions),
            copy.deepcopy(s._capacity_queue),
            list(s._queue_order),
            len(s._chain_events),
            len(s._capacity_events),
            len(s._audit_events),
            copy.deepcopy(s._fault_plan_cache),
        )

    def test_success_changes_nothing(self):
        _auth, s = make(total=1)
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "迁移", "s1", ("pa", "pw"), 10)
        # s1 占满唯一容量，dave 入队（此时后端健康）。
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)
        # 故障在排队之后注入：评估不得受演算之外的任何副作用影响。
        s.fault("f0", "注入", 1000, 30)
        s.pool_fault("p0", "注入", "default", 1000, 30)
        s.timeout_fault("t0", "注入", 80, 30)
        before = self._snapshot(s)
        steps = (
            ("后端", "", "恢复", None),
            ("池", "pa", "注入", 100),
            ("池", "default", "恢复", None),
            ("超时", "", "注入", 50),
        )
        s.fault_impact(steps, 50)
        s.fault_impact(steps, 50)
        self.assertEqual(self._snapshot(s), before)

    def test_keyerror_changes_nothing(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before = self._snapshot(s)
        with self.assertRaises(KeyError):
            s.fault_impact((("池", "nosuch", "注入", 10),), 50)
        self.assertEqual(self._snapshot(s), before)

    def test_param_error_changes_nothing(self):
        _auth, s = make()
        before = self._snapshot(s)
        with self.assertRaises(ValueError):
            s.fault_impact((), 50)
        with self.assertRaises(TypeError):
            s.fault_impact([], 50)
        self.assertEqual(self._snapshot(s), before)

    def test_no_effect_on_fault_plan_cache_domain(self):
        _auth, s = make()
        s.fault_impact((BACKEND,), 50)
        # fault_impact 不占 fault_plan 的 key 缓存：同 key 执行正常首果。
        out = s.fault_plan("k1", "执行", (BACKEND,), 50)
        again = s.fault_plan("k1", "执行", (BACKEND,), 50)
        self.assertEqual(out, again)
        self.assertIn("k1", s._fault_plan_cache)


if __name__ == "__main__":
    unittest.main()
