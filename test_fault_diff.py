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
                s.fault_diff(bad, (BACKEND,), 0)
            with self.assertRaises(TypeError):
                s.fault_diff((BACKEND,), bad, 0)
        # 步项非 tuple。
        with self.assertRaises(TypeError):
            s.fault_diff((["后端", "", "注入", 1],), (BACKEND,), 0)
        # 前三字段非 str（bool 亦非 str）。
        for bad in (1, True, None, ()):
            with self.assertRaises(TypeError):
                s.fault_diff(((bad, "", "注入", 1),), (BACKEND,), 0)
        # 注入 value 非 int 或 bool。
        for bad in (True, 1.5, "1", None):
            with self.assertRaises(TypeError):
                s.fault_diff((("后端", "", "注入", bad),), (BACKEND,), 0)
            with self.assertRaises(TypeError):
                s.fault_diff((BACKEND,), (("后端", "", "注入", bad),), 0)

    def test_now_ms_type_errors(self):
        _auth, s = make()
        for bad in (True, 1.5, "5", None, []):
            with self.assertRaises(TypeError):
                s.fault_diff((BACKEND,), (BACKEND,), bad)

    def test_type_error_precedes_value_error(self):
        _auth, s = make()
        # 容器类型错先于另一侧取值错与 now_ms 类型/取值错。
        with self.assertRaises(TypeError):
            s.fault_diff([], (), True)
        with self.assertRaises(TypeError):
            s.fault_diff((), 1, -1)

    def test_structure_and_value_errors(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault_diff((), (BACKEND,), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((BACKEND,), (), 0)
        for bad in (
            ("后端", "", "注入"),               # 3 元组
            ("后端", "", "注入", 1, 2),         # 5 元组
        ):
            with self.assertRaises(ValueError):
                s.fault_diff((bad,), (BACKEND,), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((("怪域", "", "注入", 1),), (BACKEND,), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((BACKEND,), (("后端", "", "怪op", 1),), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((("后端", "x", "注入", 1),), (BACKEND,), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((("超时", "x", "注入", 1),), (BACKEND,), 0)
        # 后端/超时项各域唯一；池项互异。
        with self.assertRaises(ValueError):
            s.fault_diff(
                (("后端", "", "注入", 1), ("后端", "", "恢复", None)),
                (BACKEND,), 0,
            )
        with self.assertRaises(ValueError):
            s.fault_diff(
                (BACKEND,),
                (("超时", "", "注入", 0), ("超时", "", "恢复", None)), 0,
            )
        with self.assertRaises(ValueError):
            s.fault_diff(
                (BACKEND,),
                (("池", "default", "注入", 1),
                 ("池", "default", "注入", 2)), 0,
            )
        # 注入取值：后端/池须正 int；超时注入 >= now_ms。
        with self.assertRaises(ValueError):
            s.fault_diff((("后端", "", "注入", 0),), (BACKEND,), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((BACKEND,), (("池", "default", "注入", -1),), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((("超时", "", "注入", -1),), (BACKEND,), 0)
        # 恢复 value 须 None（bool 归取值错，类型阶段不可判定）。
        with self.assertRaises(ValueError):
            s.fault_diff((BACKEND,), (("后端", "", "恢复", 0),), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((("后端", "", "恢复", True),), (BACKEND,), 0)

    def test_now_ms_negative(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault_diff((BACKEND,), (BACKEND,), -1)

    def test_step_count_bounds(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault_diff(
                tuple(("池", "default", "注入", 1) for _ in range(1001)),
                (BACKEND,), 0,
            )
        for i in range(1000):
            s.add_pool(f"p{i:04d}", (f"10.{4 + i // 256}.{i % 256}.0/24", (), ()))
        left = tuple(("池", f"p{i:04d}", "注入", 1) for i in range(1000))
        doc = json.loads(s.fault_diff(left, (BACKEND,), 0))
        # 后端 + 1000 池（右侧无在册池）+ 超时。
        self.assertEqual(len(doc["域"]), 1002)

    def test_unknown_pool_keyerror(self):
        _auth, s = make()
        with self.assertRaises(KeyError):
            s.fault_diff((("池", "nosuch", "注入", 1),), (BACKEND,), 0)
        with self.assertRaises(KeyError):
            s.fault_diff((BACKEND,), (("池", "nosuch", "注入", 1),), 0)
        with self.assertRaises(KeyError):
            s.fault_diff((("池", "nosuch", "恢复", None),), (BACKEND,), 0)
        # 值错先于未知池（两侧结构均全量校验后才演算）。
        with self.assertRaises(ValueError):
            s.fault_diff((("池", "nosuch", "注入", 1),), (), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((("池", "nosuch", "注入", 0),), (BACKEND,), 0)
        with self.assertRaises(ValueError):
            s.fault_diff((BACKEND,), (("池", "nosuch", "怪op", None),), 0)
        # 两侧均未知池：先演算 left，左侧池先抛。
        with self.assertRaisesRegex(KeyError, "zzz"):
            s.fault_diff(
                (("池", "zzz", "注入", 1),),
                (("池", "aaa", "注入", 1),), 0,
            )


class ShapeTest(unittest.TestCase):
    def test_top_level_and_row_key_order(self):
        _auth, s = make()
        out = s.fault_diff((BACKEND,), (TIMEOUT,), 50)
        self.assertTrue(out.endswith("\n") and not out.endswith("\n\n"))
        doc = json.loads(out)
        self.assertEqual(list(doc), ["时刻", "域", "合计", "摘要"])
        self.assertEqual(list(doc["合计"]), ["在线", "挂起", "排队", "租约"])
        for row in doc["域"]:
            self.assertEqual(list(row), ["域", "目标", "左", "右", "增减"])
            self.assertEqual(
                list(row["左"]), ["生效", "在线", "挂起", "排队", "租约"]
            )
            self.assertEqual(
                list(row["右"]), ["生效", "在线", "挂起", "排队", "租约"]
            )
            self.assertEqual(list(row["增减"]), ["在线", "挂起", "排队", "租约"])

    def test_empty_state_rows(self):
        _auth, s = make()
        # 无会话无队列无池注入：仅后端与超时两行；两侧均无池行。
        doc = json.loads(s.fault_diff((BACKEND,), (TIMEOUT,), 50))
        self.assertEqual(
            [(r["域"], r["目标"]) for r in doc["域"]],
            [("后端", ""), ("超时", "")],
        )
        backend, timeout = doc["域"]
        self.assertEqual(
            backend["左"],
            {"生效": True, "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        # 右侧未列后端（未列域不变且无既有故障）：不生效、四项 0。
        self.assertEqual(
            backend["右"],
            {"生效": False, "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertEqual(
            timeout["右"],
            {"生效": True, "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertEqual(
            timeout["左"],
            {"生效": False, "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0})
        self.assertEqual(doc["摘要"], expected_digest(doc))


class PoolUnionTest(unittest.TestCase):
    def test_union_sorted_with_missing_side_zero(self):
        _auth, s = make(total=2)
        s.add_pool("pz", ("10.2.0.0/24", (), ()))
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "迁移", "s1", ("pa", "pw"), 10)
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)
        # 左仅 pa，右 pa/default（pz 两侧均不注入故不出现）。
        left = (("池", "pa", "注入", 100),)
        right = (
            ("池", "pa", "注入", 100),
            ("池", "default", "注入", 100),
        )
        doc = json.loads(s.fault_diff(left, right, 50))
        self.assertEqual(
            [(r["域"], r["目标"]) for r in doc["域"]],
            [("后端", ""), ("池", "default"), ("池", "pa"), ("超时", "")],
        )
        rows = {(r["域"], r["目标"]): r for r in doc["域"]}
        default = rows[("池", "default")]
        self.assertEqual(
            default["左"],
            {"生效": False, "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertEqual(
            default["右"],
            {"生效": True, "在线": 1, "挂起": 0, "排队": 1, "租约": 1},
        )
        self.assertEqual(
            default["增减"],
            {"在线": 1, "挂起": 0, "排队": 1, "租约": 1},
        )
        pa = rows[("池", "pa")]
        self.assertTrue(pa["左"]["生效"] and pa["右"]["生效"])
        self.assertEqual(
            pa["增减"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0}
        )

    def test_expired_side_is_inactive_zero(self):
        _auth, s = make()
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "迁移", "s1", ("pa", "pw"), 10)
        # 既有 pa 故障截至 10（已过视图 100）：左不列 pa 沿用不生效，右
        # 重新注入（截至 100+200）生效。
        s.pool_fault("pf", "注入", "pa", 10, 0)
        doc = json.loads(
            s.fault_diff(
                (BACKEND,),
                (("池", "pa", "注入", 200),),
                100,
            )
        )
        (pa,) = [r for r in doc["域"] if r["目标"] == "pa"]
        self.assertFalse(pa["左"]["生效"])
        self.assertEqual(
            pa["左"],
            {"生效": False, "在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        self.assertTrue(pa["右"]["生效"])
        self.assertEqual(
            pa["右"],
            {"生效": True, "在线": 1, "挂起": 0, "排队": 0, "租约": 1},
        )
        self.assertEqual(
            pa["增减"], {"在线": 1, "挂起": 0, "排队": 0, "租约": 1}
        )

    def test_recover_removes_side_row(self):
        _auth, s = make()
        s.pool_fault("pf", "注入", "default", 1000, 0)
        # 左恢复移除唯一在册池，右无池步骤沿用在册：仅右有 default 行。
        doc = json.loads(
            s.fault_diff(
                (("池", "default", "恢复", None),), (BACKEND,), 50
            )
        )
        (row,) = [r for r in doc["域"] if r["域"] == "池"]
        self.assertEqual(row["目标"], "default")
        self.assertFalse(row["左"]["生效"])
        self.assertTrue(row["右"]["生效"])


class DeltaAndTotalsTest(unittest.TestCase):
    def test_delta_right_minus_left_and_totals(self):
        _auth, s = make(total=2)
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "迁移", "s1", ("pa", "pw"), 10)
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)
        left = (
            ("后端", "", "注入", 100),
            ("池", "default", "注入", 100),
            ("池", "pa", "注入", 100),
            ("超时", "", "注入", 50),
        )
        # 右：后端恢复、default 不注入、pa 仍注入、超时不注入。
        right = (
            ("后端", "", "恢复", None),
            ("池", "pa", "注入", 100),
            ("超时", "", "恢复", None),
        )
        doc = json.loads(s.fault_diff(left, right, 50))
        rows = {(r["域"], r["目标"]): r for r in doc["域"]}
        # 左后端全局四类 (2,0,1,2)，右后端不生效全 0。
        self.assertEqual(
            rows[("后端", "")]["增减"],
            {"在线": -2, "挂起": 0, "排队": -1, "租约": -2},
        )
        # default：左 (1,0,1,1)，右缺省不生效全 0。
        self.assertEqual(
            rows[("池", "default")]["增减"],
            {"在线": -1, "挂起": 0, "排队": -1, "租约": -1},
        )
        # pa 两侧相同。
        self.assertEqual(
            rows[("池", "pa")]["增减"],
            {"在线": 0, "挂起": 0, "排队": 0, "租约": 0},
        )
        # 超时：左 (2,0,1,2)，右不生效全 0。
        self.assertEqual(
            rows[("超时", "")]["增减"],
            {"在线": -2, "挂起": 0, "排队": -1, "租约": -2},
        )
        # 合计为各行增减逐项和。
        totals = {"在线": 0, "挂起": 0, "排队": 0, "租约": 0}
        for row in doc["域"]:
            for name in totals:
                totals[name] += row["增减"][name]
        self.assertEqual(doc["合计"], totals)
        self.assertEqual(
            doc["合计"], {"在线": -5, "挂起": 0, "排队": -3, "租约": -5}
        )
        self.assertEqual(doc["摘要"], expected_digest(doc))

    def test_matches_fault_impact_per_side(self):
        _auth, s = make(total=2)
        s.add_pool("pa", ("10.1.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "迁移", "s1", ("pa", "pw"), 10)
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)
        left = (("池", "pa", "注入", 100), ("超时", "", "注入", 50))
        right = (("后端", "", "注入", 100), ("池", "default", "注入", 100))
        diff = json.loads(s.fault_diff(left, right, 50))
        li = {
            (r["域"], r["目标"]): r
            for r in json.loads(s.fault_impact(left, 50))["域"]
        }
        ri = {
            (r["域"], r["目标"]): r
            for r in json.loads(s.fault_impact(right, 50))["域"]
        }
        for row in diff["域"]:
            key = (row["域"], row["目标"])
            for side, impact in (("左", li), ("右", ri)):
                # fault_impact 仅列该侧在册池；缺侧在 diff 中为不生效全 0。
                if key in impact:
                    for name in ("生效", "在线", "挂起", "排队", "租约"):
                        self.assertEqual(row[side][name], impact[key][name])
                else:
                    self.assertEqual(
                        row[side],
                        {"生效": False, "在线": 0, "挂起": 0,
                         "排队": 0, "租约": 0},
                    )

    def test_identical_plans_zero_delta(self):
        _auth, s = make(total=2)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        steps = (BACKEND, TIMEOUT)
        doc = json.loads(s.fault_diff(steps, steps, 50))
        for row in doc["域"]:
            self.assertEqual(
                row["增减"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0}
            )
        self.assertEqual(doc["合计"], {"在线": 0, "挂起": 0, "排队": 0, "租约": 0})


class DigestTest(unittest.TestCase):
    def test_digest_and_byte_stability(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        first = s.fault_diff((BACKEND,), (TIMEOUT,), 50)
        self.assertEqual(first, s.fault_diff((BACKEND,), (TIMEOUT,), 50))
        doc = json.loads(first)
        self.assertEqual(doc["摘要"], expected_digest(doc))
        other = s.fault_diff(
            (("后端", "", "注入", 200),), (("超时", "", "注入", 51),), 51
        )
        self.assertNotEqual(json.loads(other)["摘要"], doc["摘要"])

    def test_unicode_target_utf8_digest_no_ascii_escaping(self):
        _auth, s = make()
        s.add_pool("池γ", ("10.1.0.0/24", (), ()))
        raw = s.fault_diff(
            (("池", "池γ", "注入", 100),), (BACKEND,), 50
        )
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
        s.capacity("q1", "申请", "q1", ("dave", "pw", 100), 20)
        s.fault("f0", "注入", 1000, 30)
        s.pool_fault("p0", "注入", "default", 1000, 30)
        s.timeout_fault("t0", "注入", 80, 30)
        before = self._snapshot(s)
        left = (
            ("后端", "", "恢复", None),
            ("池", "pa", "注入", 100),
            ("池", "default", "恢复", None),
        )
        right = (
            ("后端", "", "注入", 5),
            ("池", "default", "注入", 100),
            ("超时", "", "注入", 50),
        )
        s.fault_diff(left, right, 50)
        s.fault_diff(left, right, 50)
        self.assertEqual(self._snapshot(s), before)

    def test_keyerror_changes_nothing(self):
        _auth, s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before = self._snapshot(s)
        with self.assertRaises(KeyError):
            s.fault_diff(
                (("池", "nosuch", "注入", 10),), (BACKEND,), 50
            )
        with self.assertRaises(KeyError):
            s.fault_diff(
                (BACKEND,), (("池", "nosuch", "注入", 10),), 50
            )
        self.assertEqual(self._snapshot(s), before)

    def test_param_error_changes_nothing(self):
        _auth, s = make()
        before = self._snapshot(s)
        with self.assertRaises(ValueError):
            s.fault_diff((), (BACKEND,), 50)
        with self.assertRaises(TypeError):
            s.fault_diff((BACKEND,), [], 50)
        self.assertEqual(self._snapshot(s), before)

    def test_no_effect_on_fault_plan_cache_domain(self):
        _auth, s = make()
        s.fault_diff((BACKEND,), (TIMEOUT,), 50)
        # fault_diff 不占 fault_plan 的 key 缓存：同 key 执行正常首果。
        out = s.fault_plan("k1", "执行", (BACKEND,), 50)
        again = s.fault_plan("k1", "执行", (BACKEND,), 50)
        self.assertEqual(out, again)
        self.assertIn("k1", s._fault_plan_cache)


if __name__ == "__main__":
    unittest.main()
