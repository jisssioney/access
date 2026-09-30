"""全局合规链 compliance_events/compliance_snapshot/compliance_restore 测试。"""
import copy
import hashlib
import json
import unittest

from access import (
    Authenticator,
    Sessions,
    StateError,
)

ZERO = "0" * 64
AUDIT = "审计"
BATCH = "批量"
CAP = "容量"


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def parse(text):
    return json.loads(text)


def make(users=("alice", "bob", "carol", "dave"), total=2, per=2,
         pool=("10.0.0.0/30", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool,
                          lease_ms=lease_ms)


def seal(doc):
    """按前六键重算摘要，返回规范 LF 尾紧凑合规快照文本。"""
    head = {
        key: doc[key]
        for key in ("版本", "锚序号", "锚哈希", "上限", "下个序号", "事件")
    }
    doc["摘要"] = digest(head)
    return compact(doc) + "\n"


def rehash(doc):
    """从锚哈希起重算全部合规事件前哈希/哈希、游标与摘要。"""
    prev = doc["锚哈希"]
    for ev in doc["事件"]:
        ev["前哈希"] = prev
        ev["哈希"] = Sessions._compliance_hash(
            ev["全局序号"], ev["来源"], ev["来源序号"], ev["载荷"], prev,
        )
        prev = ev["哈希"]
    doc["下个序号"] = (
        doc["事件"][-1]["全局序号"] if doc["事件"] else doc["锚序号"]
    )
    return seal(doc)


def audit_payload(event):
    return compact({
        "序号": event["序号"],
        "时刻": event["时刻"],
        "键": event["键"],
        "操作": event["操作"],
        "会话": event["会话"],
        "结果": event["结果"],
        "原序号": event["原序号"],
        "前哈希": event["前哈希"],
        "哈希": event["哈希"],
    })


def batch_payload(event):
    return compact({
        "序号": event["序号"],
        "时刻": event["时刻"],
        "键": event["键"],
        "操作": event["操作"],
        "原子": event["原子"],
        "会话": event["会话"],
        "结果": event["结果"],
        "原序号": event["原序号"],
        "前哈希": event["前哈希"],
        "哈希": event["哈希"],
    })


def cap_payload(event):
    return compact({
        "序号": event["序号"],
        "时刻": event["时刻"],
        "会话": event["会话"],
        "结果": event["结果"],
        "入队序": event["入队序"],
    })


class EmptyChainTest(unittest.TestCase):
    def test_empty_events_page(self):
        _auth, s = make()
        out = parse(s.compliance_events(0, 100))
        self.assertEqual(list(out), ["下个序号", "事件"])
        self.assertEqual(out["下个序号"], 0)
        self.assertEqual(out["事件"], [])

    def test_empty_snapshot(self):
        _auth, s = make()
        text = s.compliance_snapshot(0, 100)
        self.assertTrue(text.endswith("\n"))
        doc = parse(text)
        self.assertEqual(
            list(doc),
            ["版本", "锚序号", "锚哈希", "上限", "下个序号", "事件", "摘要"],
        )
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["锚序号"], 0)
        self.assertEqual(doc["锚哈希"], ZERO)
        self.assertEqual(doc["上限"], 100)
        self.assertEqual(doc["下个序号"], 0)
        self.assertEqual(doc["事件"], [])
        head = {
            "版本": 1, "锚序号": 0, "锚哈希": ZERO, "上限": 100,
            "下个序号": 0, "事件": [],
        }
        self.assertEqual(doc["摘要"], digest(head))

    def test_after_beyond_tail_is_key_error(self):
        _auth, s = make()
        with self.assertRaises(KeyError):
            s.compliance_snapshot(1, 100)


class ParamValidationTest(unittest.TestCase):
    def test_after_limit_types_and_ranges(self):
        _auth, s = make()
        for fn in (s.compliance_events, s.compliance_snapshot):
            for bad in ("0", 1.0, None, False, True):
                with self.assertRaises(TypeError, msg=repr(bad)):
                    fn(bad, 100)
                with self.assertRaises(TypeError, msg=repr(bad)):
                    fn(0, bad)
            for bad in (-1,):
                with self.assertRaises(ValueError):
                    fn(bad, 100)
            for bad in (0, 1001):
                with self.assertRaises(ValueError):
                    fn(0, bad)

    def test_events_empty_page_keeps_cursor(self):
        _auth, s = make()
        s.do("k", "建立", "s1", ("alice", "pw"), 0)
        out = parse(s.compliance_events(5, 100))
        self.assertEqual(out["下个序号"], 5)
        self.assertEqual(out["事件"], [])


class ProjectionOrderingTest(unittest.TestCase):
    def test_audit_event_projected_atomically(self):
        _auth, s = make(pool=("10.0.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = parse(s.compliance_events(0, 100))
        self.assertEqual(len(out["事件"]), 1)
        ev = out["事件"][0]
        self.assertEqual(list(ev),
                         ["全局序号", "来源", "来源序号", "载荷", "前哈希", "哈希"])
        self.assertEqual(ev["全局序号"], 1)
        self.assertEqual(ev["来源"], AUDIT)
        self.assertEqual(ev["来源序号"], 1)
        self.assertEqual(ev["前哈希"], ZERO)
        src = parse(s.audit(0, 100))["事件"][0]
        self.assertEqual(ev["载荷"], audit_payload(src))
        self.assertEqual(
            ev["哈希"],
            Sessions._compliance_hash(1, AUDIT, 1, ev["载荷"], ZERO),
        )

    def test_three_sources_interleave_in_append_order(self):
        _auth, s = make(pool=("10.0.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)       # 审计
        s.batch_offline("b1", ("s1",), 0, atomic=False)    # 批量
        # s1 已下线，址空闲：申请立即在线 -> 容量“在线”
        s.capacity("c1", "申请", "q1", ("bob", "pw", 9000), 5)
        out = parse(s.compliance_events(0, 100))["事件"]
        self.assertEqual(
            [(e["来源"], e["来源序号"]) for e in out],
            [(AUDIT, 1), (BATCH, 1), (CAP, 1)],
        )
        self.assertEqual([e["全局序号"] for e in out], [1, 2, 3])
        # 前哈希逐项衔接。
        self.assertEqual(out[0]["前哈希"], ZERO)
        self.assertEqual(out[1]["前哈希"], out[0]["哈希"])
        self.assertEqual(out[2]["前哈希"], out[1]["哈希"])

    def test_payloads_match_public_source_events(self):
        _auth, s = make(pool=("10.0.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)       # 同参重放
        s.batch_offline("b1", ("s1", "zz"), 2, atomic=True)
        s.capacity("c1", "申请", "q1", ("bob", "pw", 9000), 3)
        events = parse(s.compliance_events(0, 100))["事件"]
        audit_rows = parse(s.audit(0, 100))["事件"]
        batch_rows = parse(s.batch_audit(0, 100))["事件"]
        cap_rows = parse(s.capacity_events(0, 100))["事件"]
        by_source = {AUDIT: [], BATCH: [], CAP: []}
        for ev in events:
            by_source[ev["来源"]].append(ev)
        self.assertEqual(
            [e["载荷"] for e in by_source[AUDIT]],
            [audit_payload(r) for r in audit_rows],
        )
        self.assertEqual(
            [e["载荷"] for e in by_source[BATCH]],
            [batch_payload(r) for r in batch_rows],
        )
        self.assertEqual(
            [e["载荷"] for e in by_source[CAP]],
            [cap_payload(r) for r in cap_rows],
        )
        # 批量项目保持输入顺序：s1 在前、zz 在后（原子批，结果 下线/回滚）。
        self.assertEqual(
            [json.loads(e["载荷"])["会话"] for e in by_source[BATCH]],
            ["s1", "zz"],
        )

    def test_capacity_advance_timeouts_then_promotions(self):
        # total=1：s1 立即在线；q1/q2 短等待先超时，q3 长等待在 s1 下线后晋升。
        _auth, s = make(total=1, per=10, pool=("10.0.0.0/30", (), ()))
        s.capacity("a1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("a2", "申请", "q1", ("bob", "pw", 10), 1)
        s.capacity("a3", "申请", "q2", ("carol", "pw", 10), 1)
        s.capacity("a4", "申请", "q3", ("dave", "pw", 100), 1)
        s.do("o1", "下线", "s1", None, 11)
        s.capacity("v1", "推进", "", None, 11)
        cap_rows = parse(s.capacity_events(0, 100))["事件"]
        verdicts = [(r["结果"], r["会话"]) for r in cap_rows]
        self.assertEqual(
            verdicts,
            [("在线", "s1"), ("排队", "q1"), ("排队", "q2"), ("排队", "q3"),
             ("超时", "q1"), ("超时", "q2"), ("晋升", "q3")],
        )
        events = parse(s.compliance_events(0, 100))["事件"]
        cap_events = [e for e in events if e["来源"] == CAP]
        self.assertEqual(
            [(json.loads(e["载荷"])["结果"], json.loads(e["载荷"])["会话"])
             for e in cap_events],
            verdicts,
        )
        # 合规投影中同一批先超时后晋升（全局序单调）。
        order = [json.loads(e["载荷"])["结果"] for e in cap_events]
        self.assertLess(order.index("超时"), order.index("晋升"))
        self.assertEqual(order.count("超时"), 2)

    def test_param_errors_append_nothing(self):
        _auth, s = make(pool=("10.0.0.0/24", (), ()))
        with self.assertRaises(TypeError):
            s.do(123, "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(ValueError):
            s.capacity("c", "申请", "s1", ("alice", "pw", 0), 0)
        with self.assertRaises(ValueError):
            s.batch_offline("b", (), 0)
        self.assertEqual(parse(s.compliance_events())["事件"], [])

    def test_deterministic_bytes(self):
        _a, s1 = make(pool=("10.0.0.0/24", (), ()))
        _b, s2 = make(pool=("10.0.0.0/24", (), ()))
        for s in (s1, s2):
            s.do("k1", "建立", "s1", ("alice", "pw"), 0)
            s.batch_offline("b1", ("s1",), 0)
        self.assertEqual(s1.compliance_events(0, 100),
                         s2.compliance_events(0, 100))
        self.assertEqual(s1.compliance_snapshot(0, 100),
                         s2.compliance_snapshot(0, 100))
        self.assertEqual(s1.compliance_events(0, 100),
                         s1.compliance_events(0, 100))


class SnapshotOfflineVerifyTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make(pool=("10.0.0.0/24", (), ()))
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.s.batch_offline("b1", ("s1",), 0)
        self.s.capacity("c1", "申请", "q1", ("bob", "pw", 9000), 5)

    def verify_offline(self, text):
        """纯从文本离线校验锚点、顺序、逐项哈希与摘要。"""
        doc = parse(text)
        head = {
            key: doc[key]
            for key in ("版本", "锚序号", "锚哈希", "上限", "下个序号", "事件")
        }
        self.assertEqual(digest(head), doc["摘要"])
        prev = doc["锚哈希"]
        expect = doc["锚序号"] + 1
        for ev in doc["事件"]:
            self.assertEqual(ev["全局序号"], expect)
            self.assertEqual(ev["前哈希"], prev)
            self.assertEqual(
                ev["哈希"],
                Sessions._compliance_hash(
                    ev["全局序号"], ev["来源"], ev["来源序号"],
                    ev["载荷"], prev,
                ),
            )
            prev = ev["哈希"]
            expect += 1
        self.assertEqual(doc["下个序号"],
                         doc["事件"][-1]["全局序号"] if doc["事件"]
                         else doc["锚序号"])

    def test_window_from_zero(self):
        text = self.s.compliance_snapshot(0, 2)
        doc = parse(text)
        self.assertEqual(doc["锚序号"], 0)
        self.assertEqual(doc["锚哈希"], ZERO)
        self.assertEqual(doc["上限"], 2)
        self.assertEqual(len(doc["事件"]), 2)
        self.assertEqual(doc["下个序号"], 2)
        self.verify_offline(text)

    def test_paged_anchors(self):
        first = parse(self.s.compliance_snapshot(0, 2))
        second_text = self.s.compliance_snapshot(2, 2)
        second = parse(second_text)
        self.assertEqual(second["锚序号"], 2)
        self.assertEqual(second["锚哈希"], first["事件"][-1]["哈希"])
        self.assertEqual(second["事件"][0]["前哈希"], second["锚哈希"])
        self.verify_offline(second_text)
        # 尾上空页。
        tail = parse(self.s.compliance_snapshot(3, 2))
        self.assertEqual(tail["事件"], [])
        self.assertEqual(tail["下个序号"], 3)
        self.assertEqual(tail["锚哈希"], second["事件"][-1]["哈希"])
        self.verify_offline(self.s.compliance_snapshot(3, 2))


class ComplianceRestoreSuccessTest(unittest.TestCase):
    def setUp(self):
        _auth, self.src = make(pool=("10.0.0.0/24", (), ()))
        self.src.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.src.batch_offline("b1", ("s1",), 0)
        self.src.capacity("c1", "申请", "q1", ("bob", "pw", 9000), 5)
        self.src.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def fresh(self):
        _auth, d = make(pool=("10.0.0.0/24", (), ()))
        return d

    def test_full_restore_onto_empty_chain(self):
        d = self.fresh()
        snap = self.src.compliance_snapshot(0, 100)
        out = parse(d.compliance_restore("rk", snap))
        self.assertEqual(list(out), ["追加", "末序号", "末哈希", "摘要"])
        self.assertEqual(out["追加"], 4)
        self.assertEqual(out["末序号"], 4)
        self.assertEqual(out["末哈希"], self.src._compliance_tail)
        head = {"追加": 4, "末序号": 4, "末哈希": out["末哈希"]}
        self.assertEqual(out["摘要"], digest(head))
        # 六元组逐字接入，查询全窗逐字节一致。
        self.assertEqual(d._compliance_events, self.src._compliance_events)
        self.assertEqual(d.compliance_events(0, 100),
                         self.src.compliance_events(0, 100))

    def test_paged_restore(self):
        d = self.fresh()
        for after, limit, n, total in ((0, 2, 2, 2), (2, 1, 1, 3),
                                      (3, 10, 1, 4)):
            out = parse(
                d.compliance_restore(
                    f"rk{after}", self.src.compliance_snapshot(after, limit)
                )
            )
            self.assertEqual(out["追加"], n)
            self.assertEqual(out["末序号"], total)
        self.assertEqual(d._compliance_events, self.src._compliance_events)
        self.assertEqual(d._compliance_tail, self.src._compliance_tail)

    def test_empty_page_appends_nothing(self):
        d = self.fresh()
        out = parse(d.compliance_restore("rk", d.compliance_snapshot(0, 100)))
        self.assertEqual(out["追加"], 0)
        self.assertEqual(out["末序号"], 0)
        self.assertEqual(out["末哈希"], ZERO)
        self.assertEqual(d._compliance_events, [])

    def test_empty_page_at_tail(self):
        d = self.fresh()
        d.compliance_restore("a", self.src.compliance_snapshot(0, 100))
        out = parse(
            d.compliance_restore("b", self.src.compliance_snapshot(4, 100))
        )
        self.assertEqual(out["追加"], 0)
        self.assertEqual(out["末序号"], 4)
        self.assertEqual(len(d._compliance_events), 4)

    def test_replay_same_bytes_no_duplicate(self):
        d = self.fresh()
        snap = self.src.compliance_snapshot(0, 100)
        first = d.compliance_restore("rk", snap)
        second = d.compliance_restore("rk", snap)
        self.assertEqual(second, first)
        self.assertEqual(len(d._compliance_events), 4)

    def test_different_text_same_key_is_value_error(self):
        d = self.fresh()
        d.compliance_restore("rk", self.src.compliance_snapshot(0, 100))
        with self.assertRaises(ValueError):
            d.compliance_restore("rk", self.src.compliance_snapshot(0, 10))
        self.assertEqual(len(d._compliance_events), 4)

    def test_restore_generates_no_own_event_and_touches_no_source(self):
        d = self.fresh()
        d.compliance_restore("rk", self.src.compliance_snapshot(0, 100))
        self.assertEqual(len(d._compliance_events), 4)
        # 只恢复合规事件：三条源链与业务态均不动。
        self.assertEqual(d._chain_events, [])
        self.assertEqual(d._batch_chain_events, [])
        self.assertEqual(d._capacity_events, [])
        self.assertEqual(d._sessions, {})
        self.assertEqual(d._capacity_queue, {})
        self.assertIn("rk", d._compliance_restore_cache)

    def test_restore_does_not_age_or_authenticate_or_stats(self):
        d = self.fresh()
        d.do("k", "建立", "s1", ("alice", "pw"), 0)
        deadline_before = d._sessions["s1"]["deadline"]
        d.compliance_restore("rk", d.compliance_snapshot(1, 100))
        self.assertEqual(d._sessions["s1"]["deadline"], deadline_before)
        self.assertEqual(d._establish_total, 1)


class ComplianceRestoreAnchorTest(unittest.TestCase):
    def setUp(self):
        _auth, self.src = make(pool=("10.0.0.0/24", (), ()))
        self.src.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.src.batch_offline("b1", ("s1",), 0)

    def fresh(self):
        _auth, d = make(pool=("10.0.0.0/24", (), ()))
        return d

    def test_anchor_behind_tail_state_error(self):
        d = self.fresh()
        d.do("x", "建立", "z1", ("alice", "pw"), 0)      # d 末序号 1
        with self.assertRaises(StateError) as cm:
            d.compliance_restore("rk", self.src.compliance_snapshot(0, 100))
        self.assertEqual(cm.exception.args, (0, 1))
        self.assertEqual(len(d._compliance_events), 1)

    def test_anchor_ahead_of_tail_state_error(self):
        d = self.fresh()
        with self.assertRaises(StateError) as cm:
            d.compliance_restore("rk", self.src.compliance_snapshot(2, 100))
        self.assertEqual(cm.exception.args, (2, 0))
        self.assertEqual(d._compliance_events, [])

    def test_same_seq_different_anchor_hash(self):
        d = self.fresh()
        d.do("x", "建立", "z1", ("alice", "pw"), 0)      # 末序号同为 1、哈希不同
        with self.assertRaises(StateError) as cm:
            d.compliance_restore("rk", self.src.compliance_snapshot(1, 100))
        self.assertEqual(cm.exception.args, (1, 1))

    def test_state_error_does_not_occupy_key(self):
        d = self.fresh()
        d.do("x", "建立", "z1", ("alice", "pw"), 0)
        with self.assertRaises(StateError):
            d.compliance_restore("rk", self.src.compliance_snapshot(0, 100))
        self.assertNotIn("rk", d._compliance_restore_cache)
        # 同 key 随后用匹配尾锚的空页可成功。
        out = parse(d.compliance_restore("rk", d.compliance_snapshot(1, 100)))
        self.assertEqual(out["追加"], 0)


class ComplianceRestoreParamTest(unittest.TestCase):
    def test_text_non_str_type_error(self):
        _auth, s = make()
        for bad in (None, 123, 1.5, b"x", [], {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                s.compliance_restore("rk", bad)

    def test_key_type_and_value(self):
        _auth, s = make()
        for bad in (None, 1, b"k", 1.5):
            with self.assertRaises(TypeError):
                s.compliance_restore(bad, "x")
        for bad in ("", "k\0"):
            with self.assertRaises(ValueError):
                s.compliance_restore(bad, "x")

    def test_non_str_replay_is_value_error(self):
        _auth, s = make()
        s.compliance_restore("rk", s.compliance_snapshot(0, 100))
        with self.assertRaises(ValueError):
            s.compliance_restore("rk", 123)


class ComplianceSnapshotValueErrorTest(unittest.TestCase):
    def setUp(self):
        _auth, self.src = make(pool=("10.0.0.0/24", (), ()))
        self.src.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.src.batch_offline("b1", ("s1",), 0)
        self.src.capacity("c1", "申请", "q1", ("bob", "pw", 9000), 5)

    def fresh(self):
        _auth, d = make(pool=("10.0.0.0/24", (), ()))
        return d

    def reject(self, text):
        d = self.fresh()
        with self.assertRaises(ValueError, msg=text[:80]):
            d.compliance_restore("rk", text)
        self.assertEqual(d._compliance_events, [])
        self.assertEqual(d._compliance_tail, ZERO)
        self.assertNotIn("rk", d._compliance_restore_cache)

    def doc(self, after=0, limit=100):
        return parse(self.src.compliance_snapshot(after, limit))

    def test_not_json(self):
        self.reject("{")
        self.reject("[]")
        self.reject("null")

    def test_duplicate_top_key(self):
        raw = self.src.compliance_snapshot(0, 100)
        self.reject(raw.replace('"版本":1', '"版本":1,"版本":1', 1))

    def test_top_keys(self):
        doc = self.doc()
        missing = copy.deepcopy(doc)
        del missing["锚哈希"]
        self.reject(compact(missing) + "\n")
        extra = copy.deepcopy(doc)
        extra["x"] = 1
        self.reject(compact(extra) + "\n")
        reordered = {"锚序号": doc["锚序号"]}
        for k in doc:
            if k != "锚序号":
                reordered[k] = doc[k]
        self.reject(seal(reordered))

    def test_version(self):
        for bad in (2, 0, "1", True):
            doc = self.doc()
            doc["版本"] = bad
            self.reject(compact(doc) + "\n")

    def test_int_ranges(self):
        cases = [("锚序号", -1), ("锚序号", "0"), ("上限", 0),
                 ("上限", 1001), ("下个序号", -1), ("下个序号", 1.0)]
        for field, value in cases:
            doc = self.doc()
            doc[field] = value
            self.reject(seal(doc))

    def test_hex_fields(self):
        for field in ("锚哈希", "摘要"):
            for value in ("", "g" * 64, "A" * 64, 123):
                doc = self.doc()
                doc[field] = value
                self.reject(compact(doc) + "\n")

    def test_event_keys_and_types(self):
        doc = self.doc()
        doc["事件"][0]["多余"] = 1
        self.reject(rehash(doc))
        doc = self.doc()
        ev = doc["事件"][0]
        reordered = {"来源": ev.pop("来源"), **ev}
        doc["事件"][0] = reordered
        self.reject(rehash(doc))
        for field, value in (("全局序号", 0), ("全局序号", "1"),
                             ("来源序号", 0), ("来源序号", "2"),
                             ("载荷", 1)):
            doc = self.doc()
            doc["事件"][0][field] = value
            self.reject(rehash(doc))
        # 前哈希非法（不经过会重写它的 rehash）。
        doc = self.doc()
        doc["事件"][0]["前哈希"] = 1
        self.reject(seal(doc))
        doc = self.doc()
        doc["事件"][1]["前哈希"] = "f" * 64
        self.reject(seal(doc))

    def test_bad_source(self):
        doc = self.doc()
        doc["事件"][0]["来源"] = "接管"
        self.reject(rehash(doc))

    def test_non_contiguous_global_seq(self):
        doc = self.doc()
        doc["事件"][1]["全局序号"] = 9
        self.reject(rehash(doc))

    def test_broken_hashes_and_summary(self):
        doc = self.doc()
        doc["事件"][0]["前哈希"] = "b" * 64
        self.reject(seal(doc))
        doc = self.doc()
        doc["事件"][0]["哈希"] = "c" * 64
        self.reject(compact(doc) + "\n")
        doc = self.doc()
        doc["摘要"] = "d" * 64
        self.reject(compact(doc) + "\n")

    def test_cursor_mismatch(self):
        doc = self.doc()
        doc["下个序号"] = 1
        self.reject(seal(doc))

    def test_count_exceeds_limit(self):
        doc = self.doc()
        doc["上限"] = 1
        self.reject(seal(doc))

    def test_noncanonical_encoding(self):
        snap = self.src.compliance_snapshot(0, 100)
        doc = parse(snap)
        self.reject(compact(doc))                  # 无 LF
        self.reject(snap + "\n")                   # 多余 LF
        self.reject(json.dumps(doc, indent=2) + "\n")
        self.reject(json.dumps(doc, ensure_ascii=True,
                               separators=(",", ":")) + "\n")

    def test_payload_must_be_source_shape(self):
        # 载荷不是合法 JSON。
        doc = self.doc()
        doc["事件"][0]["载荷"] = "{"
        self.reject(rehash(doc))
        # 载荷键序/键集非法。
        doc = self.doc()
        p = json.loads(doc["事件"][0]["载荷"])
        del p["哈希"]
        doc["事件"][0]["载荷"] = compact(p)
        self.reject(rehash(doc))
        # 审计载荷伪装为容量键序。
        doc = self.doc()
        audit_ev = json.loads(doc["事件"][0]["载荷"])
        doc["事件"][0]["载荷"] = compact({
            "序号": audit_ev["序号"], "时刻": audit_ev["时刻"],
            "会话": audit_ev["会话"], "结果": "在线", "入队序": 0,
        })
        self.reject(rehash(doc))
        # 容量载荷结果非法。
        doc = self.doc()
        cap_ev = next(e for e in doc["事件"] if e["来源"] == CAP)
        p = json.loads(cap_ev["载荷"])
        p["结果"] = "不存在"
        cap_ev["载荷"] = compact(p)
        self.reject(rehash(doc))
        # 容量载荷入队序与判定不符（在线携带正入队序）。
        doc = self.doc()
        cap_ev = next(e for e in doc["事件"] if e["来源"] == CAP)
        p = json.loads(cap_ev["载荷"])
        p["入队序"] = 7
        cap_ev["载荷"] = compact(p)
        self.reject(rehash(doc))

    def test_payload_seq_must_equal_source_seq(self):
        doc = self.doc()
        p = json.loads(doc["事件"][0]["载荷"])
        p["序号"] = 99
        # 保持载荷内部审计哈希自洽（改序号后重算源哈希）。
        p["哈希"] = Sessions._chain_hash(
            p["序号"], p["时刻"], p["键"], p["操作"], p["会话"], p["结果"],
            p["原序号"], p["前哈希"],
        )
        doc["事件"][0]["载荷"] = compact(p)
        self.reject(rehash(doc))

    def test_payload_noncanonical(self):
        # 载荷为同值但非紧凑编码：外层重哈希后仍须拒绝。
        doc = self.doc()
        p = json.loads(doc["事件"][0]["载荷"])
        doc["事件"][0]["载荷"] = json.dumps(p, ensure_ascii=False)
        self.reject(rehash(doc))


class NoBackfillFromSourceRestoreTest(unittest.TestCase):
    def test_audit_restore_does_not_backfill_compliance(self):
        _auth, src = make(pool=("10.0.0.0/24", (), ()))
        src.do("k1", "建立", "s1", ("alice", "pw"), 0)
        src.do("k2", "建立", "s2", ("bob", "pw"), 0)
        _a2, dst = make(pool=("10.0.0.0/24", (), ()))
        dst.audit_restore("rk", src.audit_snapshot(0, 100))
        self.assertEqual(len(dst._chain_events), 2)
        self.assertEqual(dst._compliance_events, [])
        self.assertEqual(dst._compliance_tail, ZERO)

    def test_batch_audit_restore_does_not_backfill_compliance(self):
        _auth, src = make(pool=("10.0.0.0/24", (), ()))
        src.batch_offline("b1", ("s1", "s2"), 0, atomic=False)
        _a2, dst = make(pool=("10.0.0.0/24", (), ()))
        dst.batch_audit_restore("rk", src.batch_audit(0, 100))
        self.assertEqual(len(dst._batch_chain_events), 2)
        self.assertEqual(dst._compliance_events, [])

    def test_creplay_does_not_backfill_compliance(self):
        _auth, src = make(pool=("10.0.0.0/24", (), ()))
        src.capacity("c1", "申请", "q1", ("alice", "pw", 9000), 0)
        cp = src.clog(0)
        _a2, dst = make(pool=("10.0.0.0/24", (), ()))
        dst.creplay(cp)
        self.assertEqual(len(dst._capacity_events), 1)
        self.assertEqual(dst._compliance_events, [])
        # 此后新事件照常投影，序号自 1 起（不补历史）。
        dst.capacity("c2", "申请", "q2", ("bob", "pw", 9000), 1)
        events = parse(dst.compliance_events(0, 100))["事件"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["来源"], CAP)
        self.assertEqual(events[0]["来源序号"], 2)

    def test_runtime_restore_does_not_backfill_compliance(self):
        _auth, src = make(pool=("10.0.0.0/24", (), ())
        )
        src.capacity("c1", "申请", "q1", ("alice", "pw", 9000), 0)
        cp = src.runtime_checkpoint(0)
        _a2, dst = make(pool=("10.0.0.0/24", (), ()))
        dst.runtime_restore("rk", cp)
        self.assertEqual(len(dst._capacity_events), 1)
        self.assertEqual(dst._compliance_events, [])


if __name__ == "__main__":
    unittest.main()
