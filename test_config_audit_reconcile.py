import hashlib
import json
import unittest

from access import Authenticator, Sessions


def make():
    auth = Authenticator(3, 10000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(
        auth, 4, 2, 5000,
        pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),)),
        lease_ms=1000,
    )


def config(s, lease):
    """一份与导出同形、仅租期毫秒不同的合法 v6 配置紧凑 JSON。"""
    doc = json.loads(s.export_config())
    doc["会话"]["租期毫秒"] = lease
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def reconcile(s):
    return json.loads(s.config_audit_reconcile())


def rehash_chain(s):
    """按当前事件负载重算全部前哈希/哈希，使审计链二阶段保持通过。"""
    prev = "0" * 64
    rebuilt = []
    for event in s._chain_events:
        seq, now, key, op, sid, result, origin, _old_prev, _old_digest = event
        digest = s._chain_hash(seq, now, key, op, sid, result, origin, prev)
        rebuilt.append((seq, now, key, op, sid, result, origin, prev, digest))
        prev = digest
    s._chain_events = rebuilt
    s._chain_tail = prev


def swap_first_events(s, seq_a, seq_b):
    """互换两个原序号 0 首事件的负载（保留序号位），同步改指键索引并重哈希。"""
    events = s._chain_events
    a = events[seq_a - 1]
    b = events[seq_b - 1]

    def keep_seq(seq_holder, payload):
        return (
            seq_holder[0],  # 序号保留原位
            payload[1], payload[2], payload[3], payload[4],
            payload[5], payload[6],
            seq_holder[7], seq_holder[8],
        )

    events[seq_a - 1] = keep_seq(a, b)
    events[seq_b - 1] = keep_seq(b, a)
    # 同键索引同步指认互换后的位置（否则 3.3 先归“关联”，掩盖来源问题）。
    index = s._config_change_chain_index
    index[a[2]] = seq_b
    index[b[2]] = seq_a
    rehash_chain(s)


class ReconcileHealthyTest(unittest.TestCase):
    def test_direct_revisions_interleave_between_transactions(self):
        # 事务加载、直接加载、事务加载交错：直接记录须判直接来源、不被占用。
        s = make()
        s.config_change("kA", "加载", config(s, 1000), 10)   # rev1 事务
        s.load_config(config(s, 3000))                        # rev2 直接
        s.config_change("kB", "加载", config(s, 2000), 20)   # rev3 事务
        out = reconcile(s)
        self.assertTrue(out["完整"], out)
        self.assertEqual(out["原因"], "")
        self.assertEqual((out["检查"], out["末修订"], out["末审计"]), (4, 3, 2))
        self.assertEqual((out["断点修订"], out["断点审计"]), (-1, -1))

    def test_two_transactions_same_digest_pair_in_order(self):
        # 两个事务产生相同配置摘要（不同键、不同时刻）仍须保序配对且通过。
        s = make()
        text = config(s, 1000)
        s.config_change("kA", "加载", text, 10)
        s.config_change("kB", "加载", text, 20)
        out = reconcile(s)
        self.assertTrue(out["完整"], out)
        self.assertEqual((out["末修订"], out["末审计"]), (2, 2))

    def test_revert_recreating_earlier_digest_is_direct(self):
        # 回退重建早前摘要：回退是直接来源，不应与事务候选换配。
        s = make()
        s.config_change("kA", "加载", config(s, 1000), 1)   # rev1 事务 A
        s.config_change("kB", "加载", config(s, 2000), 2)   # rev2 事务 B
        s.config_revert("rv", 1, 2, 3)                      # rev3 回退=A 摘要
        out = reconcile(s)
        self.assertTrue(out["完整"], out)
        self.assertEqual(out["末修订"], 3)

    def test_failure_upgrade_and_replay_are_not_candidates(self):
        # 失败首调、升级（首果异常）与同参重放不产生修订、不入事务候选。
        s = make()
        text = config(s, 1000)
        s.config_change("kA", "加载", text, 10)
        with self.assertRaises(ValueError):
            s.config_change("kF", "加载", "{bad", 11)
        with self.assertRaises(ValueError):
            s.config_change("kU", "升级", "{bad", 12)
        s.config_change("kA", "加载", text, 10)             # 同参重放
        out = reconcile(s)
        self.assertTrue(out["完整"], out)
        # 仅构造 rev0 与事务 rev1 两修订；末审计取全链（含失败/重放事件）。
        self.assertEqual(out["检查"], 2)
        self.assertEqual(out["末修订"], 1)

    def test_transaction_rollback_after_window_eviction(self):
        # 回滚点规格随对象保留而不随 256 项历史淘汰：越窗后的事务回滚合法。
        s = make()
        s.config_change("first", "加载", config(s, 1500), 1)  # rev1，回滚点=rev0
        for i in range(258):
            s.load_config(config(s, 2000 + i))               # rev2..rev259 越窗
        s.config_change("lateRb", "回滚", None, 500)         # rev260=rev0 摘要
        out = reconcile(s)
        self.assertTrue(out["完整"], out)
        self.assertEqual(out["锚修订"], 5)
        self.assertEqual(out["检查"], 255)
        self.assertEqual(out["末修订"], 260)


class ReconcileSourceSwapRegressionTest(unittest.TestCase):
    def test_swapped_distinct_digest_first_events_detected_as_source(self):
        # 核心回归：两个不同配置摘要的事务首次事件互换、索引同步改指后，
        # 旧的分组最晚贪心会把逆序伪装成合法配对；新口径须判“来源”。
        s = make()
        s.config_change("kA", "加载", config(s, 1000), 10)  # seq1 -> rev1 (HA)
        s.load_config(config(s, 3000))                       # rev2 直接 (HD)
        s.config_change("kB", "加载", config(s, 2000), 20)  # seq2 -> rev3 (HB)
        self.assertTrue(reconcile(s)["完整"])

        swap_first_events(s, 1, 2)
        out = reconcile(s)
        self.assertFalse(out["完整"])
        self.assertEqual(out["原因"], "来源")
        # 首处分歧：冲突记录为 rev1、冲突事件为 seq1；此前仅构造 rev0 通过。
        self.assertEqual(out["断点修订"], 1)
        self.assertEqual(out["断点审计"], 1)
        self.assertEqual(out["检查"], 1)
        self.assertEqual(out["末修订"], 0)
        self.assertEqual(out["末审计"], 2)

    def test_swapped_same_digest_first_events_stay_complete(self):
        # 对照：相同配置摘要的两事务互换首事件不可区分（配置逐字节相同），
        # 属合法重配，不得误报“来源”。
        s = make()
        text = config(s, 1000)
        s.config_change("kA", "加载", text, 10)
        s.config_change("kB", "加载", text, 20)
        swap_first_events(s, 1, 2)
        out = reconcile(s)
        self.assertTrue(out["完整"], out)
        self.assertEqual(out["原因"], "")

    def test_swapped_distinct_detectected_after_window_rotation(self):
        # 越窗（修订 0 已淘汰、存在可信淘汰前缀）后互换在册事务首事件，仍须
        # 检出“来源”，而非把多丢的候选吞进淘汰边界。
        s = make()
        for i in range(300):
            s.config_change(f"k{i}", "加载", config(s, 1000 + i), i)
        self.assertEqual(s._config_history_log[0][0], 45)
        self.assertTrue(reconcile(s)["完整"])

        index = s._config_change_chain_index
        ordered = sorted(((seq, key) for key, seq in index.items()))
        seq_hi, key_hi = ordered[-1]      # seq 300
        seq_lo, key_lo = ordered[-2]      # seq 299
        swap_first_events(s, seq_lo, seq_hi)
        out = reconcile(s)
        self.assertFalse(out["完整"])
        self.assertEqual(out["原因"], "来源")
        # 分歧落在在册窗口内首个失配记录/事件（锚 45 之后）。
        self.assertNotEqual(out["断点修订"], -1)
        self.assertNotEqual(out["断点审计"], -1)
        self.assertGreaterEqual(out["断点修订"], out["锚修订"])

    def test_output_is_lf_terminated_compact_json(self):
        s = make()
        s.config_change("kA", "加载", config(s, 1000), 10)
        raw = s.config_audit_reconcile()
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw.strip())
        self.assertEqual(
            list(json.loads(raw)),
            ["锚修订", "检查", "完整", "断点修订", "断点审计",
             "原因", "末修订", "末审计"],
        )

    def test_corrupt_internal_state_never_raises(self):
        s = make()
        s.config_change("kA", "加载", config(s, 1000), 10)
        s._config_history_log = "garbage"
        raw = s.config_audit_reconcile()
        out = json.loads(raw)
        self.assertFalse(out["完整"])
        self.assertTrue(raw.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
