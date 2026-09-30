"""compliance_events/compliance_snapshot/compliance_restore 合规全局链测试。"""

import hashlib
import json
import unittest

from access import (
    Authenticator,
    Sessions,
    StateError,
)

ZERO = "0" * 64
AUDIT_KEYS = ("序号", "时刻", "键", "操作", "会话", "结果", "原序号",
              "前哈希", "哈希")
BATCH_KEYS = ("序号", "时刻", "键", "操作", "原子", "会话", "结果",
              "原序号", "前哈希", "哈希")
CAPACITY_KEYS = ("序号", "时刻", "会话", "结果", "入队序")
COMPLIANCE_KEYS = ("全局序号", "来源", "来源序号", "载荷", "前哈希", "哈希")


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def wire(obj):
    return compact(obj) + "\n"


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def event_hash(ev):
    head = {key: ev[key] for key in COMPLIANCE_KEYS[:5]}
    return digest(head)


def snapshot_digest(doc):
    head = {key: doc[key] for key in
            ("版本", "锚序号", "锚哈希", "上限", "下个序号", "事件")}
    return digest(head)


def reseal(doc):
    """重算合规快照的逐项前哈希/哈希、游标与摘要，返回规范 LF 尾文本。"""
    prev = doc["锚哈希"]
    for ev in doc["事件"]:
        ev["前哈希"] = prev
        ev["哈希"] = event_hash(ev)
        prev = ev["哈希"]
    doc["下个序号"] = (
        doc["事件"][-1]["全局序号"] if doc["事件"] else doc["锚序号"]
    )
    doc["摘要"] = snapshot_digest(doc)
    return wire(doc)


def audit_payload(seq, now_ms, key, op, sid, result, origin, prev_hash):
    ev = {
        "序号": seq, "时刻": now_ms, "键": key, "操作": op, "会话": sid,
        "结果": result, "原序号": origin, "前哈希": prev_hash,
    }
    ev["哈希"] = Sessions._chain_hash(
        seq, now_ms, key, op, sid, result, origin, prev_hash
    )
    return ev, compact(ev)


class ProjectionTest(unittest.TestCase):
    def build(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 1000)       # 审计1
        s.capacity("q1", "申请", "s2", ("bob", "pw", 5000), 2000)  # 容量1 排队
        s.batch_offline("kb", ("s2",), 3000)                  # 批量1
        s.do("k2", "建立", "s3", ("carol", "pw"), 4000)       # 审计2
        return s

    def test_ordering_and_linkage(self):
        s = self.build()
        doc = json.loads(s.compliance_events(0, 1000))
        self.assertEqual(doc["下个序号"], 4)
        self.assertEqual(
            [(e["来源"], e["来源序号"]) for e in doc["事件"]],
            [("审计", 1), ("容量", 1), ("批量", 1), ("审计", 2)],
        )
        prev = ZERO
        for index, ev in enumerate(doc["事件"], start=1):
            self.assertEqual(ev["全局序号"], index)
            self.assertEqual(ev["前哈希"], prev)
            self.assertEqual(ev["哈希"], event_hash(ev))
            prev = ev["哈希"]

    def test_payload_equals_public_source_event(self):
        s = self.build()
        pages = {
            "审计": json.loads(s.audit(0, 1000))["事件"],
            "批量": json.loads(s.batch_audit(0, 1000))["事件"],
            "容量": json.loads(s.capacity_events(0, 1000))["事件"],
        }
        for ev in json.loads(s.compliance_events(0, 1000))["事件"]:
            source_event = pages[ev["来源"]][ev["来源序号"] - 1]
            # 载荷串即公开源事件行的紧凑 JSON（无 LF）。
            self.assertEqual(ev["载荷"], compact(source_event))
            self.assertFalse(ev["载荷"].endswith("\n"))
            payload = json.loads(ev["载荷"])
            if ev["来源"] == "审计":
                self.assertEqual(list(payload), list(AUDIT_KEYS))
            elif ev["来源"] == "批量":
                self.assertEqual(list(payload), list(BATCH_KEYS))
            else:
                self.assertEqual(list(payload), list(CAPACITY_KEYS))

    def test_fixed_key_order_and_lf_and_determinism(self):
        s = self.build()
        text = s.compliance_events(0, 100)
        self.assertTrue(text.endswith("\n"))
        self.assertTrue(text.startswith('{"下个序号":4,'))
        doc = json.loads(text)
        self.assertEqual(list(doc), ["下个序号", "事件"])
        for ev in doc["事件"]:
            self.assertEqual(list(ev), list(COMPLIANCE_KEYS))
        self.assertEqual(text, s.compliance_events(0, 100))

    def test_source_event_not_produced_is_not_projected(self):
        s = make()
        # 验参错：源审计链与全局链均不产生。
        with self.assertRaises(TypeError):
            s.do("bad", "建立", "x", ("alice", "pw"), None)
        # capacity 后端故障之前无事件；停用用户亦不产生容量事件。
        s.fault("f", "注入", 10000, 0)  # audit 链记一条（后端注入）
        before = json.loads(s.compliance_events(0, 1000))["下个序号"]
        with self.assertRaises(Exception):
            s.capacity("q", "申请", "z", ("alice", "pw", 10), 5000)
        # capacity 同参重放不产生容量源事件，故无新容量投影。
        s2 = make()
        s2.capacity("qq", "申请", "z1", ("alice", "pw", 10), 1000)
        n = json.loads(s2.compliance_events(0, 1000))["下个序号"]
        with self.assertRaises(Exception):
            s2.capacity("qq", "申请", "z1", ("alice", "pw", 10), 9999)
        self.assertEqual(
            json.loads(s2.compliance_events(0, 1000))["下个序号"], n
        )
        self.assertGreaterEqual(
            json.loads(s.compliance_events(0, 1000))["下个序号"], before
        )

    def test_batch_items_keep_input_order(self):
        s = make()
        s.batch_offline("kb", ("b1", "b2", "b3"), 1000)
        events = json.loads(s.compliance_events(0, 1000))["事件"]
        batch = [e for e in events if e["来源"] == "批量"]
        self.assertEqual(
            [json.loads(e["载荷"])["会话"] for e in batch],
            ["b1", "b2", "b3"],
        )
        self.assertEqual([e["来源序号"] for e in batch], [1, 2, 3])

    def test_advance_timeout_before_promote(self):
        # 总容量 1：s1 在线，s2 短等排队（将超时），s3 长等排队（将晋升）。
        s = make(users=("alice", "bob"), total=1, per=10)
        s.capacity("c1", "申请", "s1", ("alice", "pw", 100), 0)     # 容量1 在线
        s.capacity("c2", "申请", "s2", ("bob", "pw", 100), 10)     # 容量2 排队
        s.capacity("c3", "申请", "s3", ("bob", "pw", 10000), 20)   # 容量3 排队
        s.do("off", "下线", "s1", None, 300)                       # 释放容量
        s.capacity("adv", "推进", "", None, 500)                   # 超时 s2、晋升 s3
        cap = json.loads(s.capacity_events(0, 1000))["事件"]
        self.assertEqual(
            [(e["结果"], e["会话"]) for e in cap[3:]],
            [("超时", "s2"), ("晋升", "s3")],
        )
        comp = json.loads(s.compliance_events(0, 1000))["事件"]
        tail = [(e["来源"], json.loads(e["载荷"])["结果"])
                for e in comp[-2:]]
        self.assertEqual(tail, [("容量", "超时"), ("容量", "晋升")])

    def test_do_replay_is_projected_with_origin(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        s.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        events = json.loads(s.compliance_events(0, 1000))["事件"]
        self.assertEqual(len(events), 2)
        payload = json.loads(events[1]["载荷"])
        self.assertEqual(payload["原序号"], 1)


class EventsQueryTest(unittest.TestCase):
    def test_paging_after_limit(self):
        s = make()
        for i in range(5):
            s.do(f"k{i}", "建立", f"s{i}", ("alice", "pw"), 1000 + i)
        page1 = json.loads(s.compliance_events(0, 2))
        self.assertEqual([e["全局序号"] for e in page1["事件"]], [1, 2])
        self.assertEqual(page1["下个序号"], 2)
        page2 = json.loads(s.compliance_events(2, 2))
        self.assertEqual([e["全局序号"] for e in page2["事件"]], [3, 4])
        self.assertEqual(page2["下个序号"], 4)
        page3 = json.loads(s.compliance_events(4, 2))
        self.assertEqual([e["全局序号"] for e in page3["事件"]], [5])
        self.assertEqual(page3["下个序号"], 5)

    def test_empty_page_keeps_cursor(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        self.assertEqual(
            s.compliance_events(9, 10), wire({"下个序号": 9, "事件": []})
        )
        fresh = make()
        self.assertEqual(
            fresh.compliance_events(0, 10), wire({"下个序号": 0, "事件": []})
        )

    def test_param_rules(self):
        s = make()
        with self.assertRaises(TypeError):
            s.compliance_events(after=True)
        with self.assertRaises(TypeError):
            s.compliance_events(limit=False)
        with self.assertRaises(TypeError):
            s.compliance_events(after="1")
        with self.assertRaises(ValueError):
            s.compliance_events(after=-1)
        with self.assertRaises(ValueError):
            s.compliance_events(limit=0)
        with self.assertRaises(ValueError):
            s.compliance_events(limit=1001)
        # 边界合法。
        s.compliance_events(0, 1)
        s.compliance_events(0, 1000)


class SnapshotTest(unittest.TestCase):
    def test_snapshot_shape_and_summary(self):
        s = make()
        for i in range(3):
            s.do(f"k{i}", "建立", f"s{i}", ("alice", "pw"), 1000 + i)
        text = s.compliance_snapshot(0, 2)
        doc = json.loads(text)
        self.assertEqual(
            list(doc),
            ["版本", "锚序号", "锚哈希", "上限", "下个序号", "事件", "摘要"],
        )
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["锚序号"], 0)
        self.assertEqual(doc["锚哈希"], ZERO)
        self.assertEqual(doc["上限"], 2)
        self.assertEqual(doc["下个序号"], 2)
        self.assertEqual(len(doc["事件"]), 2)
        self.assertEqual(doc["摘要"], snapshot_digest(doc))
        self.assertTrue(text.endswith("\n"))

    def test_anchor_is_prior_event_hash(self):
        s = make()
        for i in range(3):
            s.do(f"k{i}", "建立", f"s{i}", ("alice", "pw"), 1000 + i)
        full = json.loads(s.compliance_events(0, 100))
        doc = json.loads(s.compliance_snapshot(2, 10))
        self.assertEqual(doc["锚序号"], 2)
        self.assertEqual(doc["锚哈希"], full["事件"][1]["哈希"])
        self.assertEqual([e["全局序号"] for e in doc["事件"]], [3])
        # 空窗锚取第 after 项哈希，游标保持锚。
        empty = json.loads(s.compliance_snapshot(3, 10))
        self.assertEqual(empty["锚哈希"], full["事件"][2]["哈希"])
        self.assertEqual(empty["下个序号"], 3)
        self.assertEqual(empty["事件"], [])

    def test_after_beyond_tail_raises_keyerror(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        with self.assertRaises(KeyError):
            s.compliance_snapshot(2, 10)
        fresh = make()
        with self.assertRaises(KeyError):
            fresh.compliance_snapshot(1, 10)

    def test_param_rules(self):
        s = make()
        with self.assertRaises(TypeError):
            s.compliance_snapshot(after=True)
        with self.assertRaises(ValueError):
            s.compliance_snapshot(limit=0)
        with self.assertRaises(ValueError):
            s.compliance_snapshot(limit=1001)


class RestoreTest(unittest.TestCase):
    def test_append_and_only_restores_compliance(self):
        src = make()
        for i in range(3):
            src.do(f"k{i}", "建立", f"s{i}", ("alice", "pw"), 1000 + i)
        text = src.compliance_snapshot(0, 1000)
        dst = make()
        result = json.loads(dst.compliance_restore("rk", text))
        self.assertEqual(result["追加"], 3)
        self.assertEqual(result["末序号"], 3)
        # 结果四键序与摘要。
        self.assertEqual(list(result), ["追加", "末序号", "末哈希", "摘要"])
        head = {k: result[k] for k in ("追加", "末序号", "末哈希")}
        self.assertEqual(result["摘要"], digest(head))
        # 只恢复合规事件：三条源链保持空。
        self.assertEqual(json.loads(dst.audit(0, 10))["下个序号"], 0)
        self.assertEqual(json.loads(dst.batch_audit(0, 10))["下个序号"], 0)
        self.assertEqual(json.loads(dst.capacity_events(0, 10))["下个序号"], 0)
        # 全局链逐字节一致。
        self.assertEqual(
            dst.compliance_events(0, 1000), src.compliance_events(0, 1000)
        )
        # 恢复不生成自身事件。
        self.assertEqual(
            json.loads(dst.compliance_events(0, 1000))["下个序号"], 3
        )

    def test_continuable_after_restore(self):
        # 目标链已有实时投影，快照锚在链尾，接入后新源事件继续投影。
        src = make()
        src.do("k0", "建立", "x0", ("alice", "pw"), 500)
        src.do("k1", "建立", "x1", ("alice", "pw"), 600)
        dst = make()
        dst.do("k0", "建立", "x0", ("alice", "pw"), 500)
        page = src.compliance_snapshot(1, 10)
        result = json.loads(dst.compliance_restore("rk", page))
        self.assertEqual(result["追加"], 1)
        dst.do("k2", "建立", "x2", ("alice", "pw"), 700)
        doc = json.loads(dst.compliance_events(0, 100))
        self.assertEqual([e["全局序号"] for e in doc["事件"]], [1, 2, 3])
        self.assertEqual(doc["事件"][2]["来源"], "审计")
        self.assertEqual(doc["事件"][2]["来源序号"], 2)

    def test_multi_page_restore(self):
        src = make()
        for i in range(5):
            src.do(f"k{i}", "建立", f"s{i}", ("alice", "pw"), 1000 + i)
        dst = make()
        r1 = json.loads(dst.compliance_restore("p1", src.compliance_snapshot(0, 2)))
        self.assertEqual((r1["追加"], r1["末序号"]), (2, 2))
        r2 = json.loads(dst.compliance_restore("p2", src.compliance_snapshot(2, 2)))
        self.assertEqual((r2["追加"], r2["末序号"]), (2, 4))
        r3 = json.loads(dst.compliance_restore("p3", src.compliance_snapshot(4, 2)))
        self.assertEqual((r3["追加"], r3["末序号"]), (1, 5))
        # 空页接入：追加 0，仍占该 key。
        r4 = json.loads(dst.compliance_restore("p4", src.compliance_snapshot(5, 2)))
        self.assertEqual(r4["追加"], 0)
        self.assertEqual(
            dst.compliance_events(0, 1000), src.compliance_events(0, 1000)
        )

    def test_idempotent_replay_returns_same_bytes_no_reappend(self):
        src = make()
        src.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        text = src.compliance_snapshot(0, 1000)
        dst = make()
        first = dst.compliance_restore("rk", text)
        second = dst.compliance_restore("rk", text)
        self.assertIsInstance(first, str)
        self.assertEqual(second, first)
        self.assertEqual(json.loads(dst.compliance_events(0, 100))["下个序号"], 1)

    def test_same_key_different_text_raises(self):
        src = make()
        src.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        dst = make()
        dst.compliance_restore("rk", src.compliance_snapshot(0, 1000))
        src.do("k2", "建立", "s2", ("alice", "pw"), 2000)
        with self.assertRaises(ValueError):
            dst.compliance_restore("rk", src.compliance_snapshot(0, 1000))
        # 异参不改变链。
        self.assertEqual(json.loads(dst.compliance_events(0, 100))["下个序号"], 1)

    def test_text_type_and_key_rules(self):
        s = make()
        with self.assertRaises(TypeError):
            s.compliance_restore("rk", 123)
        with self.assertRaises(TypeError):
            s.compliance_restore(123, "{}")
        with self.assertRaises(ValueError):
            s.compliance_restore("", "{}")

    def test_anchor_mismatch_raises_stateerror(self):
        src = make()
        for i in range(3):
            src.do(f"k{i}", "建立", f"s{i}", ("alice", "pw"), 1000 + i)
        dst = make()
        # 目标空链（尾 0/zeros），快照锚在 2 -> StateError(锚序号, 尾序号)。
        with self.assertRaises(StateError) as ctx:
            dst.compliance_restore("rk", src.compliance_snapshot(2, 10))
        self.assertEqual(ctx.exception.args, (2, 0))
        self.assertEqual(json.loads(dst.compliance_events(0, 10))["下个序号"], 0)

    def test_failure_does_not_occupy_key(self):
        src = make()
        src.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        dst = make()
        # 锚点失败不占 key。
        with self.assertRaises(StateError):
            dst.compliance_restore("rk", src.compliance_snapshot(1, 10))
        # 同一 key 随后可用（空链接全量）。
        result = json.loads(
            dst.compliance_restore("rk", src.compliance_snapshot(0, 1000))
        )
        self.assertEqual(result["追加"], 1)

    def _one_event_snapshot_text(self):
        src = make()
        src.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        return json.loads(src.compliance_snapshot(0, 1000))

    def test_reject_malformed(self):
        dst = make()
        base = self._one_event_snapshot_text()
        cases = {}

        # 非 JSON。
        cases["json"] = "not json\n"
        # 顶层键序错。
        d = json.loads(reseal(json.loads(json.dumps(base))))
        d = {"版本": d["版本"], "锚序号": d["锚序号"], "锚哈希": d["锚哈希"],
             "上限": d["上限"], "摘要": d["摘要"], "下个序号": d["下个序号"],
             "事件": d["事件"]}
        cases["top_order"] = wire(d)
        # 版本错。
        d = json.loads(reseal(json.loads(json.dumps(base)))); d["版本"] = 2
        cases["version"] = wire(d)
        # 越界。
        d = json.loads(reseal(json.loads(json.dumps(base)))); d["上限"] = 0
        cases["limit_zero"] = wire(d)
        d = json.loads(reseal(json.loads(json.dumps(base)))); d["上限"] = 1001
        cases["limit_big"] = wire(d)
        # 事件数超上限。
        d = json.loads(json.dumps(base)); d["上限"] = 0
        cases["too_many"] = reseal(d)
        # 全局序号不连续。
        d = json.loads(json.dumps(base)); d["事件"][0]["全局序号"] = 2
        cases["seq_gap"] = reseal(d)
        # 非法来源。
        d = json.loads(json.dumps(base)); d["事件"][0]["来源"] = "其他"
        cases["source"] = reseal(d)
        # 来源序号与载荷序号不符。
        d = json.loads(json.dumps(base)); d["事件"][0]["来源序号"] = 7
        cases["source_seq"] = reseal(d)
        # 载荷非 JSON。
        d = json.loads(json.dumps(base)); d["事件"][0]["载荷"] = "{"
        cases["payload_json"] = reseal(d)
        # 载荷键序错（审计九键换序）。
        d = json.loads(json.dumps(base))
        p = json.loads(d["事件"][0]["载荷"])
        p = {k: p[k] for k in list(AUDIT_KEYS)[::-1]}
        d["事件"][0]["载荷"] = compact(p)
        cases["payload_order"] = reseal(d)
        # 载荷内哈希不匹配（篡改结果串）。
        d = json.loads(json.dumps(base))
        p = json.loads(d["事件"][0]["载荷"]); p["结果"] = "StateError"
        d["事件"][0]["载荷"] = compact(p)
        cases["payload_hash"] = reseal(d)
        # 载荷非规范（多余空白）。
        d = json.loads(json.dumps(base))
        d["事件"][0]["载荷"] = d["事件"][0]["载荷"].replace("{", "{ ", 1)
        cases["payload_canonical"] = reseal(d)
        # 容量载荷使用非法结果值。
        d = json.loads(json.dumps(base))
        ev = d["事件"][0]; ev["来源"] = "容量"
        ev["载荷"] = compact({"序号": 1, "时刻": 1, "会话": "s",
                              "结果": "不存在", "入队序": 0})
        cases["cap_verdict"] = reseal(d)
        # 合规层哈希错（不重算）。
        d = json.loads(json.dumps(base))
        d["事件"][0]["哈希"] = "a" * 64
        cases["event_hash"] = wire(d)
        # 摘要错（不重算）。
        d = json.loads(json.dumps(base))
        d["摘要"] = "b" * 64
        cases["summary"] = wire(d)
        # 非规范整体编码（无 LF）。
        cases["no_lf"] = reseal(json.loads(json.dumps(base)))[:-1]
        # 游标错。
        d = json.loads(json.dumps(base)); d["下个序号"] = 9
        d["摘要"] = snapshot_digest(d)
        cases["next_seq"] = wire(d)

        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    dst.compliance_restore(f"k-{name}", text)
                # 失败不改变链、不占 key（同名 key 之后可成功）。
                self.assertEqual(
                    json.loads(dst.compliance_events(0, 10))["下个序号"], 0
                )

    def test_empty_page_anchor_must_match_tail(self):
        src = make()
        src.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        dst = make()
        # 空页锚序号 1，目标尾 0 -> StateError。
        with self.assertRaises(StateError):
            dst.compliance_restore("rk", src.compliance_snapshot(1, 10))


class NoBackfillTest(unittest.TestCase):
    def test_audit_restore_does_not_project(self):
        src = make()
        src.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        src.do("k2", "建立", "s2", ("alice", "pw"), 1001)
        src.do("k3", "建立", "s3", ("alice", "pw"), 1002)
        page = src.audit_snapshot(2, 1)   # 审计源序号 3，锚 2
        dst = make()
        dst.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        dst.do("k2", "建立", "s2", ("alice", "pw"), 1001)
        self.assertEqual(
            json.loads(dst.audit_restore("rk", page))["追加"], 1
        )
        # 源链到 3，全局链仍只含实时投影的 2 条。
        self.assertEqual(json.loads(dst.audit(0, 10))["下个序号"], 3)
        self.assertEqual(
            json.loads(dst.compliance_events(0, 10))["下个序号"], 2
        )

    def test_batch_audit_restore_does_not_project(self):
        src = make()
        src.batch_offline("kb", ("b1", "b2"), 1000)
        page = src.batch_audit(0, 100)
        dst = make()
        result = json.loads(dst.batch_audit_restore("rk", page))
        self.assertEqual(result["追加"], 2)
        self.assertEqual(
            json.loads(dst.compliance_events(0, 10))["下个序号"], 0
        )

    def test_creplay_does_not_project(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        src = Sessions(auth, 2, 10, 100000,
                       pool=("10.0.0.0/24", (), ()), lease_ms=100000)
        src.capacity("q1", "申请", "s1", ("alice", "pw", 5000), 1000)
        src.capacity("q2", "申请", "s2", ("bob", "pw", 5000), 1100)
        checkpoint = src.clog(2000)

        auth2 = Authenticator(3, 1000)
        auth2.add("alice", "pw")
        auth2.add("bob", "pw")
        dst = Sessions(auth2, 2, 10, 100000,
                       pool=("10.0.0.0/24", (), ()), lease_ms=100000)
        dst.creplay(checkpoint)
        self.assertEqual(json.loads(dst.capacity_events(0, 10))["下个序号"], 2)
        self.assertEqual(
            json.loads(dst.compliance_events(0, 10))["下个序号"], 0
        )

    def test_synthetic_payload_restores_compliance_only(self):
        # 合规恢复不查源链：自造一份来源审计载荷（自洽即可），可接入空链。
        payload_ev, payload = audit_payload(
            1, 1234, "k", "建立", "sid", "成功", 0, ZERO
        )
        ev = {
            "全局序号": 1, "来源": "审计", "来源序号": 1, "载荷": payload,
            "前哈希": ZERO,
        }
        ev["哈希"] = event_hash(ev)
        doc = {
            "版本": 1, "锚序号": 0, "锚哈希": ZERO, "上限": 100,
            "下个序号": 1, "事件": [ev],
        }
        doc["摘要"] = snapshot_digest(doc)
        text = wire(doc)
        dst = make()
        result = json.loads(dst.compliance_restore("rk", text))
        self.assertEqual(result["追加"], 1)
        # 源审计链依旧为空，仅全局链有此投影。
        self.assertEqual(json.loads(dst.audit(0, 10))["下个序号"], 0)
        got = json.loads(dst.compliance_events(0, 10))["事件"][0]
        self.assertEqual(json.loads(got["载荷"]), payload_ev)


class SourceChainsUnchangedTest(unittest.TestCase):
    def test_source_queries_and_projection_consistent(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 1000)
        s.capacity("q1", "申请", "s2", ("bob", "pw", 5000), 2000)
        s.batch_offline("kb", ("s2",), 3000)
        # 三条源链查询仍可独立校验（哈希链形态不变）。
        self.assertTrue(s.verify_audit())
        self.assertTrue(s.cverify())
        audit = json.loads(s.audit(0, 10))["事件"]
        self.assertEqual(len(audit), 1)
        batch = json.loads(s.batch_audit(0, 10))["事件"]
        self.assertEqual(len(batch), 1)
        cap = json.loads(s.capacity_events(0, 10))["事件"]
        self.assertEqual(len(cap), 1)


if __name__ == "__main__":
    unittest.main()
