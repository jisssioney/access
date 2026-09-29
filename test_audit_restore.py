import copy
import hashlib
import json
import unittest

from access import Authenticator, Sessions, StateError

ZERO = "0" * 64


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def make():
    auth = Authenticator(3, 10000)
    for user in ("alice", "bob", "carol"):
        auth.add(user, "pw")
    return Sessions(
        auth, 10, 10, 100000,
        pool=("10.0.0.0/24", (), ()), lease_ms=100000,
    )


def empty_sessions():
    return Sessions(Authenticator(3, 10000), 10, 10, 100000)


def seal(doc):
    """按前六键重算摘要，返回规范 LF 尾紧凑快照文本。"""
    head = {
        key: doc[key]
        for key in ("版本", "锚序号", "锚哈希", "上限", "下个序号", "事件")
    }
    doc["摘要"] = digest(head)
    return compact(doc) + "\n"


def rehash(doc):
    """从锚哈希起重算全部事件前哈希/哈希、游标与摘要，返回规范文本。

    供在结构自洽的前提下定向篡改单一字段（序号、原序号、上限等）。
    """
    prev = doc["锚哈希"]
    for ev in doc["事件"]:
        ev["前哈希"] = prev
        ev["哈希"] = Sessions._chain_hash(
            ev["序号"], ev["时刻"], ev["键"], ev["操作"], ev["会话"],
            ev["结果"], ev["原序号"], prev,
        )
        prev = ev["哈希"]
    doc["下个序号"] = doc["事件"][-1]["序号"] if doc["事件"] else doc["锚序号"]
    return seal(doc)


def snapshot_doc(s, after=0, limit=100):
    return json.loads(s.audit_snapshot(after, limit))


def build_chain(s, n):
    """在 s 上产生 n 条防篡改审计事件：同参 do 两次（建立+重放）交替，
    故每对 key/sid/now_ms 完全一致。"""
    for i in range(n):
        index = i // 2
        s.do(f"k{index}", "建立", f"s{index}", ("alice", "pw"), index)


class AuditRestoreSuccessTest(unittest.TestCase):
    def test_empty_snapshot_onto_empty_chain_appends_nothing(self):
        s = empty_sessions()
        out = s.audit_restore("rk", s.audit_snapshot(0, 100))
        self.assertTrue(out.endswith("\n"))
        doc = json.loads(out)
        self.assertEqual(list(doc), ["追加", "末序号", "末哈希", "摘要"])
        self.assertEqual(doc["追加"], 0)
        self.assertEqual(doc["末序号"], 0)
        self.assertEqual(doc["末哈希"], ZERO)
        head = {"追加": 0, "末序号": 0, "末哈希": ZERO}
        self.assertEqual(doc["摘要"], digest(head))
        self.assertEqual(len(s._chain_events), 0)
        self.assertEqual(s._chain_tail, ZERO)

    def test_full_snapshot_onto_empty_chain(self):
        src = make()
        build_chain(src, 4)
        snap = src.audit_snapshot(0, 100)

        dst = empty_sessions()
        out = json.loads(dst.audit_restore("rk", snap))
        self.assertEqual(out["追加"], 4)
        self.assertEqual(out["末序号"], 4)
        self.assertEqual(out["末哈希"], src._chain_tail)
        # 九元组逐字接入，链校验通过；audit 全窗输出逐字节一致。
        self.assertEqual(dst._chain_events, src._chain_events)
        self.assertTrue(dst.verify_audit())
        self.assertEqual(dst.audit(0, 100), src.audit(0, 100))

    def test_paged_restore_chain_pagination(self):
        src = make()
        build_chain(src, 5)
        dst = empty_sessions()
        for after, limit, n, total in (
            (0, 2, 2, 2),
            (2, 2, 2, 4),
            (4, 10, 1, 5),
        ):
            out = json.loads(
                dst.audit_restore(f"rk{after}", src.audit_snapshot(after, limit))
            )
            self.assertEqual(out["追加"], n)
            self.assertEqual(out["末序号"], total)
        self.assertEqual(dst._chain_events, src._chain_events)
        self.assertEqual(dst._chain_tail, src._chain_tail)
        self.assertTrue(dst.verify_audit())

    def test_empty_window_at_nonzero_anchor(self):
        src = make()
        build_chain(src, 3)
        dst = empty_sessions()
        dst.audit_restore("rk", src.audit_snapshot(0, 100))
        # 锚在链尾的空页：追加 0，末序号/末哈希不动。
        out = json.loads(dst.audit_restore("rk2", src.audit_snapshot(3, 100)))
        self.assertEqual(out["追加"], 0)
        self.assertEqual(out["末序号"], 3)
        self.assertEqual(out["末哈希"], src._chain_tail)
        self.assertEqual(len(dst._chain_events), 3)

    def test_non_ascii_payload_roundtrips_utf8_bytes(self):
        src = make()
        src.do("ké1", "建立", "sé", ("alice", "pw"), 0)
        snap = src.audit_snapshot(0, 100)
        self.assertIn("sé", snap)          # ensure_ascii=False 原文保留
        self.assertNotIn("\\u", snap)
        dst = empty_sessions()
        out = dst.audit_restore("rk", snap)
        self.assertEqual(json.loads(out)["追加"], 1)
        self.assertEqual(dst.audit(0, 10), src.audit(0, 10))

    def test_event_count_at_limit_accepted(self):
        src = make()
        build_chain(src, 5)
        dst = empty_sessions()
        out = json.loads(dst.audit_restore("rk", src.audit_snapshot(0, 5)))
        self.assertEqual(out["追加"], 5)

    def test_origin_below_seq_is_accepted(self):
        # 原序号为 [0, 本项序号) 内的引用合法；重算哈希后可接入且链校验通过。
        src = make()
        build_chain(src, 3)
        doc = snapshot_doc(src, 0, 100)
        doc["事件"][1]["原序号"] = 1
        dst = empty_sessions()
        out = json.loads(dst.audit_restore("rk", rehash(doc)))
        self.assertEqual(out["追加"], 3)
        self.assertTrue(dst.verify_audit())
        self.assertEqual(dst._chain_events[1][6], 1)


class AuditRestoreCacheTest(unittest.TestCase):
    def test_replay_returns_identical_bytes_without_append(self):
        src = make()
        build_chain(src, 2)
        snap = src.audit_snapshot(0, 100)
        dst = empty_sessions()
        first = dst.audit_restore("rk", snap)
        second = dst.audit_restore("rk", snap)
        self.assertEqual(second, first)
        self.assertEqual(len(dst._chain_events), 2)
        self.assertEqual(dst._chain_tail, src._chain_tail)

    def test_restore_and_replay_write_no_chain_index(self):
        src = make()
        build_chain(src, 2)
        dst = empty_sessions()
        dst.audit_restore("rk", src.audit_snapshot(0, 100))
        dst.audit_restore("rk", src.audit_snapshot(0, 100))
        # 恢复与重放均不登记任何原序号（操作幂等）索引。
        self.assertEqual(dst._chain_index, {})
        self.assertNotIn("rk", dst._audit_index)

    def test_different_text_raises_and_keeps_cache(self):
        src = make()
        build_chain(src, 3)
        dst = empty_sessions()
        snap = src.audit_snapshot(0, 100)
        first = dst.audit_restore("rk", snap)
        other = src.audit_snapshot(0, 10)
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", other)
        # 异参不追加，原缓存仍可重放原字节。
        self.assertEqual(len(dst._chain_events), 3)
        self.assertEqual(dst.audit_restore("rk", snap), first)

    def test_failure_does_not_occupy_key(self):
        dst = empty_sessions()
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", "{not json")
        # 同 key 随后可成功（空页）。
        out = json.loads(dst.audit_restore("rk", dst.audit_snapshot(0, 100)))
        self.assertEqual(out["追加"], 0)

    def test_state_error_does_not_occupy_key(self):
        src = make()
        build_chain(src, 2)
        dst = make()
        build_chain(dst, 1)               # 目标末项与源锚不一致
        with self.assertRaises(StateError):
            dst.audit_restore("rk", src.audit_snapshot(0, 100))
        # 同 key 对一份匹配目标当前尾的快照可成功。
        out = json.loads(dst.audit_restore("rk", dst.audit_snapshot(1, 100)))
        self.assertEqual(out["追加"], 0)
        self.assertEqual(out["末序号"], 1)

    def test_cache_domain_independent_from_do(self):
        # 同名字符串 key 已用于 do 幂等缓存：audit_restore 不读它，接入照常。
        src = make()
        first_do = src.do("shared", "建立", "sx", ("alice", "pw"), 0)
        src.do("other", "建立", "sy", ("alice", "pw"), 1)
        dst = make()
        self.assertEqual(
            dst.do("shared", "建立", "sx", ("alice", "pw"), 0), first_do
        )
        self.assertEqual(dst._chain_tail, src._chain_events[0][8])
        # do 缓存中已有 "shared"：若域共用，此处会命中 do 元组而异参 ValueError；
        # 域独立故接入成功，从 seq1 锚接入源 seq2。
        out = json.loads(
            dst.audit_restore("shared", src.audit_snapshot(1, 100))
        )
        self.assertEqual(out["追加"], 1)
        self.assertEqual(out["末序号"], 2)
        self.assertTrue(dst.verify_audit())
        # do 域缓存原封不动：同参 do 重放仍返回首次 JSON（其入链语义不变）。
        self.assertEqual(
            dst.do("shared", "建立", "sx", ("alice", "pw"), 0), first_do
        )
        self.assertIn("shared", dst._cache)
        self.assertIn("shared", dst._audit_restore_cache)


class AuditRestoreAnchorTest(unittest.TestCase):
    def test_anchor_seq_behind_tail(self):
        src = make()
        build_chain(src, 1)
        dst = make()
        build_chain(dst, 2)
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("rk", src.audit_snapshot(0, 100))
        self.assertEqual(cm.exception.args, (0, 2))
        self.assertEqual(len(dst._chain_events), 2)

    def test_anchor_seq_ahead_of_tail(self):
        src = make()
        build_chain(src, 3)
        dst = make()
        build_chain(dst, 1)
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("rk", src.audit_snapshot(2, 100))
        self.assertEqual(cm.exception.args, (2, 1))
        self.assertEqual(len(dst._chain_events), 1)

    def test_same_seq_but_different_anchor_hash(self):
        src = make()
        src.do("first", "建立", "s1", ("alice", "pw"), 0)
        src.do("second", "建立", "s2", ("bob", "pw"), 5)
        dst = make()
        dst.do("other", "建立", "z9", ("carol", "pw"), 9)
        # 双方末序号皆 1，但末哈希不同。
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("rk", src.audit_snapshot(1, 100))
        self.assertEqual(cm.exception.args, (1, 1))
        self.assertEqual(dst._chain_tail, dst._chain_events[0][8])

    def test_empty_window_nonzero_anchor_hash_mismatch(self):
        # 空窗锚序号 0、锚哈希非零：结构合法，对空链抛 StateError(0,0)。
        dst = empty_sessions()
        doc = {
            "版本": 1,
            "锚序号": 0,
            "锚哈希": "a" * 64,
            "上限": 100,
            "下个序号": 0,
            "事件": [],
        }
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("rk", seal(doc))
        self.assertEqual(cm.exception.args, (0, 0))
        self.assertEqual(len(dst._chain_events), 0)


class AuditRestoreParamTypeTest(unittest.TestCase):
    def test_text_non_str_is_type_error(self):
        s = empty_sessions()
        for bad in (None, 123, 1.5, b"x", [], {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                s.audit_restore("rk", bad)

    def test_key_type_error(self):
        s = empty_sessions()
        for bad in (None, 1, b"k", 1.5, ["k"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                s.audit_restore(bad, "x")

    def test_key_value_error(self):
        s = empty_sessions()
        for bad in ("", "k\0", "é" * 200):
            with self.assertRaises(ValueError, msg=repr(bad)):
                s.audit_restore(bad, "x")

    def test_key_checked_before_text(self):
        s = empty_sessions()
        with self.assertRaises(TypeError):
            s.audit_restore(123, 456)
        with self.assertRaises(ValueError):
            s.audit_restore("", 456)

    def test_non_str_replay_is_value_error_not_type_error(self):
        # 沿用各 restore 域先例：缓存命中后仅按异参 ValueError，不再查类型。
        s = empty_sessions()
        snap = s.audit_snapshot(0, 100)
        s.audit_restore("rk", snap)
        with self.assertRaises(ValueError):
            s.audit_restore("rk", 123)


class AuditRestoreSnapshotValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.src = make()
        build_chain(self.src, 3)
        self.dst = empty_sessions()

    def reject(self, text):
        with self.assertRaises(ValueError, msg=text[:80]):
            self.dst.audit_restore("rk", text)
        # 任何失败不追加、不占缓存键。
        self.assertEqual(len(self.dst._chain_events), 0)
        self.assertEqual(self.dst._chain_tail, ZERO)
        self.assertNotIn("rk", self.dst._audit_restore_cache)

    def test_not_json(self):
        self.reject("{")
        self.reject("[1,2]")
        self.reject("null")
        self.reject("1")

    def test_duplicate_top_key(self):
        raw = self.src.audit_snapshot(0, 10)
        raw = raw.replace('"版本":1', '"版本":1,"版本":1', 1)
        self.reject(raw)

    def test_top_level_key_set_and_order(self):
        doc = snapshot_doc(self.src, 0, 100)
        missing = copy.deepcopy(doc)
        del missing["锚序号"]
        self.reject(compact(missing) + "\n")
        extra = copy.deepcopy(doc)
        extra["多余"] = 1
        self.reject(compact(extra) + "\n")
        reordered = {"锚序号": doc["锚序号"]}
        for k in doc:
            if k != "锚序号":
                reordered[k] = doc[k]
        self.reject(seal(reordered))

    def test_version(self):
        for bad in (2, 0, "1", True, 1.0):
            doc = snapshot_doc(self.src, 0, 100)
            doc["版本"] = bad
            self.reject(compact(doc) + "\n")

    def test_int_ranges_and_types(self):
        cases = [
            ("锚序号", -1), ("锚序号", "0"), ("锚序号", True),
            ("上限", 0), ("上限", 1001), ("上限", "1"), ("上限", False),
            ("下个序号", -1), ("下个序号", 1.0),
        ]
        for field, value in cases:
            doc = snapshot_doc(self.src, 0, 100)
            doc[field] = value
            self.reject(seal(doc))

    def test_hex_fields(self):
        for field in ("锚哈希", "摘要"):
            for value in ("", "g" * 64, "A" * 64, "a" * 63, 123):
                doc = snapshot_doc(self.src, 0, 100)
                doc[field] = value
                self.reject(compact(doc) + "\n")

    def test_events_not_list_and_event_keys(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["事件"] = {}
        self.reject(seal(doc))
        doc = snapshot_doc(self.src, 0, 100)
        doc["事件"][0]["多余"] = 1
        self.reject(rehash(doc))
        doc = snapshot_doc(self.src, 0, 100)
        del doc["事件"][0]["哈希"]
        self.reject(compact(doc) + "\n")
        doc = snapshot_doc(self.src, 0, 100)
        ev = doc["事件"][0]
        reordered = {"时刻": ev.pop("时刻"), **ev}
        doc["事件"][0] = reordered
        self.reject(compact(doc) + "\n")

    def test_event_field_types(self):
        bad_values = [
            ("序号", 0), ("序号", -1), ("序号", "1"), ("序号", True),
            ("时刻", -1), ("时刻", "0"),
            ("原序号", -1), ("原序号", "0"),
            ("键", 1), ("操作", None), ("会话", 1.5), ("结果", []),
        ]
        for field, value in bad_values:
            doc = snapshot_doc(self.src, 0, 100)
            doc["事件"][1][field] = value
            self.reject(rehash(doc))

    def test_event_count_exceeds_limit(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["上限"] = 2
        self.reject(seal(doc))

    def test_first_seq_must_follow_anchor(self):
        doc = snapshot_doc(self.src, 2, 100)   # 事件自 seq3 起
        doc["锚序号"] = 1                      # 锚改 1：首项应为 seq2
        self.reject(rehash(doc))

    def test_non_contiguous_seq(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["事件"][1]["序号"] = 5             # seq2 位置跳到 5
        self.reject(rehash(doc))

    def test_origin_must_be_zero_or_below_seq(self):
        for bad_origin in (2, 99):
            doc = snapshot_doc(self.src, 0, 100)
            doc["事件"][1]["原序号"] = bad_origin
            self.reject(rehash(doc))

    def test_broken_prev_hash(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["事件"][0]["前哈希"] = "b" * 64
        self.reject(seal(doc))

    def test_broken_event_hash(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["事件"][0]["哈希"] = "c" * 64
        self.reject(compact(doc) + "\n")

    def test_cursor_mismatch(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["下个序号"] = 2                   # 实际末项 seq3
        self.reject(seal(doc))
        doc = snapshot_doc(self.src, 3, 100)  # 空窗游标须等于锚 3
        doc["下个序号"] = 4
        self.reject(seal(doc))

    def test_bad_summary(self):
        doc = snapshot_doc(self.src, 0, 100)
        doc["摘要"] = "f" * 64
        self.reject(compact(doc) + "\n")

    def test_non_canonical_encoding(self):
        snap = self.src.audit_snapshot(0, 100)
        doc = json.loads(snap)
        self.reject(compact(doc))                  # 无 LF
        self.reject(snap + "\n")                   # 多余 LF
        self.reject(snap + " ")                    # 尾随空白
        self.reject(json.dumps(doc, ensure_ascii=False) + "\n")        # 空白
        self.reject(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")

    def test_non_ascii_escape_is_noncanonical(self):
        self.src.do("ké9", "建立", "sé9", ("alice", "pw"), 9)
        snap = self.src.audit_snapshot(0, 100)
        doc = json.loads(snap)
        self.assertIn("sé9", snap)
        self.reject(
            json.dumps(doc, ensure_ascii=True, separators=(",", ":")) + "\n"
        )


class AuditRestoreIsolationTest(unittest.TestCase):
    def test_restores_only_chain_events_and_tail(self):
        src = make()
        build_chain(src, 3)
        dst = empty_sessions()
        dst.audit_restore("rk", src.audit_snapshot(0, 100))
        # 除审计链序列与末哈希外，会话、各业务/幂等缓存、接管审计均不动。
        self.assertEqual(dst._sessions, {})
        self.assertEqual(dst._cache, {})
        self.assertEqual(dst._capacity_cache, {})
        self.assertEqual(dst._audit_events, [])
        self.assertEqual(dst._audit_index, {})
        self.assertEqual(dst._chain_index, {})
        self.assertEqual(
            list(dst._config_history), [0]
        )

    def test_repeated_same_page_with_new_key_is_state_error(self):
        src = make()
        build_chain(src, 2)
        dst = empty_sessions()
        dst.audit_restore("a", src.audit_snapshot(0, 100))
        tail_before = dst._chain_tail
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("b", src.audit_snapshot(0, 100))
        self.assertEqual(cm.exception.args, (0, 2))
        self.assertEqual(len(dst._chain_events), 2)
        self.assertEqual(dst._chain_tail, tail_before)

    def test_state_error_leaves_instance_untouched(self):
        src = make()
        build_chain(src, 2)
        dst = make()
        build_chain(dst, 1)
        before = list(dst._chain_events)
        with self.assertRaises(StateError):
            dst.audit_restore("rk", src.audit_snapshot(0, 100))
        self.assertEqual(dst._chain_events, before)
        self.assertTrue(dst.verify_audit())
        self.assertNotIn("rk", dst._audit_restore_cache)


if __name__ == "__main__":
    unittest.main()
