import hashlib
import json
import unittest

from access import Authenticator, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def text(s, lease):
    doc = json.loads(s.export_config())
    doc["会话"]["租期毫秒"] = lease
    return json.dumps(doc, ensure_ascii=False)


def digest(spec_text):
    return hashlib.sha256(spec_text[:-1].encode("utf-8")).hexdigest()


def rec(s):
    return json.loads(s.config_audit_reconcile())


KEYS = ["锚修订", "检查", "完整", "断点修订", "断点审计", "原因",
        "末修订", "末审计"]
REASONS = {"历史", "审计", "来源", "关联", "操作", "结果", "重放", ""}


def assert_shape(test, s):
    raw = s.config_audit_reconcile()
    test.assertIsInstance(raw, str)
    test.assertTrue(raw.endswith("\n"))
    test.assertNotIn(" ", raw.strip())
    payload = json.loads(raw)
    test.assertEqual(list(payload), KEYS)
    test.assertIn(payload["原因"], REASONS)
    for name in ("锚修订", "检查", "断点修订", "断点审计",
                 "末修订", "末审计"):
        test.assertIsInstance(payload[name], int, name)
    test.assertIsInstance(payload["完整"], bool)
    return payload


def rehash(s):
    """篡改链后重算全部哈希，使链校验本身通过，从而进入来源阶段。"""
    new = []
    for event in s._chain_events:
        seq, now, key, op, sid, result, origin = event[:7]
        prev = new[-1][8] if new else "0" * 64
        h = Sessions._chain_hash(seq, now, key, op, sid, result, origin, prev)
        new.append((seq, now, key, op, sid, result, origin, prev, h))
    s._chain_events = new
    if new:
        s._chain_tail = new[-1][8]


def swap_first_events(s, i, j):
    """交换两条首事件的全部载荷字段（保留位置序号），并同步域索引。"""
    events = s._chain_events
    p, q = events[i], events[j]
    events[i] = (p[0], q[1], q[2], q[3], q[4], q[5], q[6], p[7], p[8])
    events[j] = (q[0], p[1], p[2], p[3], p[4], p[5], p[6], q[7], q[8])
    s._config_change_chain_index[p[2]] = q[0]
    s._config_change_chain_index[q[2]] = p[0]
    rehash(s)


class ConfigAuditReconcileCleanTest(unittest.TestCase):
    def test_shape_on_construction(self):
        s = make()
        p = assert_shape(self, s)
        self.assertEqual(p, {
            "锚修订": -1, "检查": 1, "完整": True,
            "断点修订": -1, "断点审计": -1, "原因": "",
            "末修订": 0, "末审计": 0,
        })

    def test_two_transaction_loads(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 10)
        s.config_change("B", "加载", text(s, 3003), 20)
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual(p["原因"], "")
        self.assertEqual((p["锚修订"], p["检查"], p["末修订"], p["末审计"]),
                         (-1, 3, 2, 2))

    def test_direct_revisions_interleaved_with_transactions(self):
        s = make()
        s.load_config(text(s, 111))                       # rev1 直接加载
        s.config_change("T", "加载", text(s, 222), 5)    # rev2 事务加载
        s.config_cas("c", text(s, 333), 2, 0)            # rev3 直接 CAS
        s.config_revert("r", 1, 3, 0)                    # rev4 直接回退
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual((p["检查"], p["末修订"], p["末审计"]), (5, 4, 1))

    def test_transaction_load_then_transaction_rollback(self):
        s = make()
        s.config_change("L", "加载", text(s, 9), 1)
        s.config_change("R", "回滚", None, 2)
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual(p["检查"], 3)

    def test_identical_summary_direct_and_transaction(self):
        s = make()
        same = text(s, 777)
        s.load_config(same)                  # rev1 直接，摘要 X
        s.config_change("K", "加载", same, 1)  # rev2 事务，同摘要 X
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual(p["检查"], 3)

    def test_rollback_rebuilds_earlier_in_window_summary(self):
        s = make()
        d1 = text(s, 1001)
        s.config_change("T1", "加载", d1, 1)     # rev1 事务摘要 X
        s.load_config(text(s, 2002))             # rev2 直接摘要 Y
        s.config_change("R", "回滚", None, 3)    # rev3 事务回滚摘要 X
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual(p["检查"], 4)

    def test_failures_upgrades_and_replays_do_not_pair(self):
        s = make()
        with self.assertRaises(ValueError):
            s.config_change("bad", "加载", "{not json", 1)
        s.config_change("U", "升级", s.export_config(), 2)
        ok = text(s, 5)
        s.config_change("ok", "加载", ok, 3)
        s.config_change("ok", "加载", ok, 3)   # 同参重放
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual((p["检查"], p["末审计"]), (2, 4))
        self.assertTrue(s.verify_audit())

    def test_failed_rollback_state_error(self):
        s = make()
        with self.assertRaises(StateError):
            s.config_change("rb", "回滚", None, 7)
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], True)
        self.assertEqual((p["检查"], p["末修订"], p["末审计"]), (1, 0, 1))

    def test_read_only_and_deterministic(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 10)
        before_rev = s.config_revision()
        before_audit = s.audit(limit=1000)
        out1 = s.config_audit_reconcile()
        out2 = s.config_audit_reconcile()
        self.assertEqual(out1, out2)
        self.assertEqual(s.config_revision(), before_rev)
        self.assertEqual(s.audit(limit=1000), before_audit)


class ConfigAuditReconcileSwapTest(unittest.TestCase):
    def test_swap_two_distinct_summary_first_events_still_source(self):
        """两个不同配置摘要的事务首次事件互换并同步调整索引，
        旧的分组最晚贪心会跨序换配而漏检；现在须在首个分歧归“来源”。"""
        s = make()
        tA = text(s, 1001)
        s.config_change("A", "加载", tA, 10)
        tB = text(s, 3003)
        s.config_change("B", "加载", tB, 20)
        self.assertTrue(rec(s)["完整"])

        swap_first_events(s, 0, 1)
        self.assertTrue(s.verify_audit())  # 链本身自洽
        p = assert_shape(self, s)
        self.assertEqual(p["完整"], False)
        self.assertEqual(p["原因"], "来源")
        # 首个分歧：rev1 记录与被换入的 seq1 事件冲突；rev0 已通过。
        self.assertEqual(p["断点修订"], 1)
        self.assertEqual(p["断点审计"], 1)
        self.assertEqual(p["检查"], 1)
        self.assertEqual((p["末修订"], p["末审计"]), (0, 2))

    def test_swap_without_index_sync_also_fails(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 10)
        s.config_change("B", "加载", text(s, 3003), 20)
        # 仅互换事件载荷、不同步索引：必在来源/关联阶段失败。
        events = s._chain_events
        p, q = events[0], events[1]
        events[0] = (p[0], q[1], q[2], q[3], q[4], q[5], q[6], p[7], p[8])
        events[1] = (q[0], p[1], p[2], p[3], p[4], p[5], p[6], q[7], q[8])
        rehash(s)
        out = assert_shape(self, s)
        self.assertFalse(out["完整"])
        self.assertIn(out["原因"], {"来源", "关联"})

    def test_swap_adjacent_among_many_transactions(self):
        s = make()
        s.config_change("a", "加载", text(s, 11), 1)
        t2 = text(s, 22)
        s.config_change("b", "加载", t2, 2)
        t3 = text(s, 33)
        s.config_change("c", "加载", t3, 3)
        s.config_change("d", "加载", text(s, 44), 4)
        self.assertTrue(rec(s)["完整"])
        # 互换中间两个不同摘要事务的首事件并同步索引。
        swap_first_events(s, 1, 2)
        p = assert_shape(self, s)
        self.assertFalse(p["完整"])
        self.assertEqual(p["原因"], "来源")
        # rev0、rev1 已通过，分歧落在 rev2；冲突事件为换入的 seq2。
        self.assertEqual((p["检查"], p["断点修订"], p["断点审计"]),
                         (2, 2, 2))

    def test_swap_load_and_rollback_distinct_summary(self):
        s = make()
        # rev1 事务加载 X（非构造态），rev2 另一事务加载 Y，
        # rev3 事务回滚到 rev2 前态（=X），三类摘要可分。
        s.config_change("L1", "加载", text(s, 1001), 1)
        s.config_change("L2", "加载", text(s, 2002), 2)
        s.config_change("RB", "回滚", None, 3)
        self.assertTrue(rec(s)["完整"])
        # 互换 L2 加载事件(seq2,摘要X2)与回滚事件(seq3,摘要X1)。
        swap_first_events(s, 1, 2)
        p = assert_shape(self, s)
        self.assertFalse(p["完整"])
        self.assertEqual(p["原因"], "来源")


class ConfigAuditReconcileWindowTest(unittest.TestCase):
    def test_evicted_transaction_is_trusted_boundary(self):
        s = make()
        s.config_change("T", "加载", text(s, 1001), 0)  # rev1 事务
        base = json.loads(s.export_config())
        for i in range(2, 260):                        # 258 次直接加载
            base["会话"]["租期毫秒"] = 2000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertEqual(s._config_history_log[0][0], 4)
        p = assert_shape(self, s)
        self.assertTrue(p["完整"])
        self.assertEqual(p["锚修订"], 4)
        self.assertEqual(p["检查"], 255)
        self.assertEqual(p["末修订"], 259)
        self.assertEqual(p["末审计"], 1)

    def test_rollback_after_eviction_still_pairs(self):
        s = make()
        s.config_change("T", "加载", text(s, 1001), 0)
        base = json.loads(s.export_config())
        for i in range(2, 259):
            base["会话"]["租期毫秒"] = 3000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))  # rev2..258
        s.config_change("R", "回滚", None, 50)        # rev259 事务回滚
        p = assert_shape(self, s)
        self.assertTrue(p["完整"])
        self.assertEqual(p["末审计"], 2)

    def test_revert_record_outlives_its_evicted_target(self):
        s = make()
        s.config_change("T", "加载", text(s, 1001), 0)
        base = json.loads(s.export_config())
        for i in range(2, 260):                       # 直接加载至 rev259
            base["会话"]["租期毫秒"] = 4000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertEqual(s._config_history_log[0][0], 4)
        # rev260 回退到当时在册修订 44（直接来源，快照等于 rev44 配置）。
        out = json.loads(s.config_revert("rv", 44, 259, 0))
        self.assertEqual(out["修订"], 260)
        # 再提交 44 个直接加载：窗口滑到 rev49..304，目标 rev44 已淘汰，
        # 但回退记录 rev260 仍在册——对账按可信边界信任其快照，不判“回退”。
        base = json.loads(s.export_config())
        for i in range(261, 305):
            base["会话"]["租期毫秒"] = 5000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertNotIn(44, s._config_history)
        self.assertIn(260, s._config_history)
        p = assert_shape(self, s)
        self.assertTrue(p["完整"])
        self.assertEqual(p["锚修订"], 49)
        self.assertEqual(p["末审计"], 1)


class ConfigAuditReconcileTamperTest(unittest.TestCase):
    def test_forged_trailing_success_candidate_is_extra(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 0)  # rev1/seq1
        # 内部伪造一个新键的成功首事件及其缓存，但其配置从未提交。
        fake = text(s, 9999)
        s._config_change_cache["C"] = (
            "加载", fake, 5, ("ok", fake + "\n")
        )
        s._chain_append(
            "C", "配置加载", "", "成功", 5,
            index=s._config_change_chain_index,
        )
        p = assert_shape(self, s)
        self.assertFalse(p["完整"])
        self.assertEqual(p["原因"], "来源")
        self.assertEqual(p["断点修订"], -1)
        self.assertEqual(p["断点审计"], 2)
        self.assertEqual(p["检查"], 2)

    def test_corrupted_chain_hash_is_audit(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 0)
        event = list(s._chain_events[0])
        event[5] = "ResourceError"          # 篡改结果名，不重算哈希
        s._chain_events[0] = tuple(event)
        p = assert_shape(self, s)
        self.assertFalse(p["完整"])
        self.assertEqual(p["原因"], "审计")
        self.assertEqual(p["断点审计"], 1)
        self.assertEqual(p["末审计"], 0)

    def test_corrupted_history_is_history_and_audit_unknown(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 0)
        record = list(s._config_history_log[1])
        record[4] = "f" * 64                # 篡改历史摘要
        s._config_history_log[1] = tuple(record)
        p = assert_shape(self, s)
        self.assertFalse(p["完整"])
        self.assertEqual(p["原因"], "历史")
        self.assertEqual(p["断点修订"], 1)
        self.assertEqual(p["断点审计"], -1)

    def test_corrupted_internal_state_never_raises(self):
        s = make()
        s.config_change("A", "加载", text(s, 1001), 0)
        s.config_change("B", "加载", text(s, 2002), 1)
        # 直接破坏内部结构：缓存改成非元组、索引指向越界序号。
        s._config_change_cache["A"] = object()
        s._config_change_chain_index["B"] = 999
        # 总入口兜底，任何损坏都只返回结构化失败 JSON 而不抛异常。
        raw = s.config_audit_reconcile()
        payload = json.loads(raw)
        self.assertFalse(payload["完整"])
        self.assertIn(payload["原因"], REASONS)


if __name__ == "__main__":
    unittest.main()
