import hashlib
import json
import unittest

from access import Sessions, _compact_config, Authenticator


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def load(s, lease=None):
    doc = json.loads(s.export_config())
    if lease is not None:
        doc["会话"]["租期毫秒"] = lease
    return s.load_config(json.dumps(doc, ensure_ascii=False))


def build(s):
    load(s, 1001)  # 1 加载
    s.rollback_config()  # 2 回滚
    doc = json.loads(s.export_config())
    doc["会话"]["租期毫秒"] = 7
    s.config_cas("c", json.dumps(doc, ensure_ascii=False), 2, 0)  # 3 CAS
    s.config_revert("r", 0, 3, 0)  # 4 回退


def verify(s, **kw):
    return json.loads(s.config_history_verify(**kw))


def rows(s, **kw):
    return json.loads(s.config_history(limit=1000, **kw))["项目"]


def corrupt(s, index, field, value):
    cols = {
        "修订": 0, "父修订": 1, "操作": 2, "目标": 3,
        "摘要": 4, "前哈希": 5, "哈希": 6,
    }
    rec = list(s._config_history_log[index])
    rec[cols[field]] = value
    s._config_history_log[index] = tuple(rec)


def recompute(s, index):
    rec = s._config_history_log[index]
    corrupt(s, index, "哈希", Sessions._config_history_hash(*rec[:6]))


class ConfigHistoryVerifyCleanTest(unittest.TestCase):
    def test_full_chain_from_genesis_anchor(self):
        s = make()
        build(s)
        out = verify(s, limit=1000)
        self.assertEqual(
            list(out),
            ["锚修订", "锚哈希", "检查", "完整", "断点", "原因", "末哈希"],
        )
        self.assertEqual(out["锚修订"], -1)
        self.assertEqual(out["锚哈希"], "0" * 64)
        self.assertEqual(out["检查"], 5)
        self.assertIs(out["完整"], True)
        self.assertEqual(out["断点"], -1)
        self.assertEqual(out["原因"], "")
        self.assertEqual(out["末哈希"], rows(s)[-1]["哈希"])
        raw = s.config_history_verify()
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw.strip())

    def test_each_summary_matches_retained_snapshot(self):
        s = make()
        build(s)
        for r in rows(s):
            spec = s._config_history[r["修订"]]
            expect = hashlib.sha256(
                _compact_config(spec).encode("utf-8")
            ).hexdigest()
            self.assertEqual(r["摘要"], expect)
        self.assertTrue(verify(s, limit=1000)["完整"])

    def test_anchor_at_retained_revision(self):
        s = make()
        build(s)
        anchor2 = next(r for r in rows(s) if r["修订"] == 2)
        out = verify(s, after=2, limit=1000)
        self.assertEqual(out["锚修订"], 2)
        self.assertEqual(out["锚哈希"], anchor2["哈希"])
        self.assertEqual(out["检查"], 2)  # 仅修订 3、4
        self.assertTrue(out["完整"])
        self.assertEqual(out["末哈希"], rows(s)[-1]["哈希"])

    def test_pagination_counts_only_window(self):
        s = make()
        build(s)
        out = verify(s, after=0, limit=2)  # 修订 1、2
        self.assertEqual(out["检查"], 2)
        self.assertTrue(out["完整"])
        window = json.loads(s.config_history(after=0, limit=2))["项目"]
        self.assertEqual(out["锚哈希"], rows(s)[0]["哈希"])  # 锚为修订 0
        self.assertEqual(out["末哈希"], window[-1]["哈希"])

    def test_empty_window_reports_anchor_only(self):
        s = make()
        build(s)
        last = rows(s)[-1]
        out = verify(s, after=4, limit=10)
        self.assertEqual(out["锚修订"], 4)
        self.assertEqual(out["锚哈希"], last["哈希"])
        self.assertEqual(out["检查"], 0)
        self.assertTrue(out["完整"])
        self.assertEqual(out["断点"], -1)
        self.assertEqual(out["原因"], "")
        self.assertEqual(out["末哈希"], last["哈希"])

    def test_read_only(self):
        s = make()
        build(s)
        before = s.config_revision()
        log_before = list(s._config_history_log)
        s.config_history_verify()
        s.config_history_verify(2, 1)
        self.assertEqual(s.config_revision(), before)
        self.assertEqual(s._config_history_log, log_before)


class ConfigHistoryVerifyParamTest(unittest.TestCase):
    def setUp(self):
        self.s = make()
        build(self.s)

    def test_param_types(self):
        for kw in (
            {"after": True}, {"after": 1.0}, {"after": "0"},
            {"limit": True}, {"limit": 1.0}, {"limit": "10"},
        ):
            with self.assertRaises(TypeError):
                self.s.config_history_verify(**kw)

    def test_param_values(self):
        for bad in (-2, -100):
            with self.assertRaises(ValueError):
                self.s.config_history_verify(after=bad)
        for bad in (0, -1, 1001):
            with self.assertRaises(ValueError):
                self.s.config_history_verify(limit=bad)
        json.loads(self.s.config_history_verify(after=-1, limit=1))
        json.loads(self.s.config_history_verify(limit=1000))

    def test_unretained_after_raises_key_error(self):
        with self.assertRaises(KeyError) as cm:
            self.s.config_history_verify(after=5)
        self.assertEqual(cm.exception.args, (5,))


class ConfigHistoryVerifyEvictionTest(unittest.TestCase):
    def test_anchor_uses_oldest_minus_one_and_prev_hash(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 300):
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        log = s._config_history_log
        self.assertEqual(log[0][0], 44)
        out = verify(s, limit=1000)
        self.assertEqual(out["锚修订"], 43)
        self.assertEqual(out["锚哈希"], log[0][5])
        self.assertEqual(out["检查"], 256)
        self.assertTrue(out["完整"])
        self.assertEqual(out["末哈希"], log[-1][6])
        with self.assertRaises(KeyError):
            s.config_history_verify(after=43)
        out2 = verify(s, after=44, limit=1000)
        self.assertEqual(out2["锚修订"], 44)
        self.assertEqual(out2["锚哈希"], log[0][6])
        self.assertEqual(out2["检查"], 255)
        self.assertTrue(out2["完整"])


class ConfigHistoryVerifyCorruptionTest(unittest.TestCase):
    def setUp(self):
        self.s = make()
        build(self.s)

    def assert_failure(self, index, field, value, reason, checked, tail_index):
        corrupt(self.s, index, field, value)
        out = verify(self.s, limit=1000)
        self.assertFalse(out["完整"])
        self.assertEqual(out["原因"], reason)
        self.assertEqual(out["检查"], checked)
        self.assertEqual(out["断点"], self.s._config_history_log[index][0])
        log = self.s._config_history_log
        self.assertEqual(out["末哈希"], log[tail_index][6] if tail_index >= 0
                         else out["锚哈希"])
        # 恢复后完整。
        corrupt(self.s, index, field, self._originals[index][field])
        if field in ("父修订", "目标", "操作", "摘要", "前哈希"):
            recompute(self.s, index)
        self.assertTrue(verify(self.s, limit=1000)["完整"])

    def _snapshot(self):
        self._originals = {}
        recs = self.s._config_history_log
        for i, r in enumerate(recs):
            self._originals[i] = {
                "修订": r[0], "父修订": r[1], "操作": r[2], "目标": r[3],
                "摘要": r[4], "前哈希": r[5], "哈希": r[6],
            }

    def test_revision_gap(self):
        self._snapshot()
        self.assert_failure(2, "修订", 99, "修订", 2, 1)

    def test_bad_parent(self):
        self._snapshot()
        self.assert_failure(3, "父修订", 0, "父修订", 3, 2)

    def test_bad_operation(self):
        self._snapshot()
        self.assert_failure(2, "操作", "黑", "操作", 2, 1)

    def test_bad_target_on_load(self):
        self._snapshot()
        self.assert_failure(1, "目标", 0, "目标", 1, 0)

    def test_revert_target_must_be_below_parent(self):
        self._snapshot()
        # 修订 4 为回退、父修订 3、目标 0；目标等于父修订非法。
        self.assert_failure(4, "目标", 3, "目标", 4, 3)

    def test_revert_negative_target(self):
        self._snapshot()
        self.assert_failure(4, "目标", -1, "目标", 4, 3)

    def test_missing_snapshot(self):
        self._snapshot()
        saved = self.s._config_history.pop(2)
        out = verify(self.s, limit=1000)
        self.assertEqual((out["原因"], out["断点"], out["检查"]),
                         ("快照", 2, 2))
        self.s._config_history[2] = saved
        self.assertTrue(verify(self.s, limit=1000)["完整"])

    def test_bad_summary(self):
        self._snapshot()
        self.assert_failure(2, "摘要", "f" * 64, "摘要", 2, 1)

    def test_bad_prev_hash(self):
        self._snapshot()
        self.assert_failure(3, "前哈希", "a" * 64, "前哈希", 3, 2)

    def test_bad_digest(self):
        self._snapshot()
        self.assert_failure(3, "哈希", "b" * 64, "哈希", 3, 2)

    def test_first_error_stops_and_anchor_tail_when_none_pass(self):
        s = self.s
        # 构造记录目标被改：首项即败，检查 0、末哈希取锚（64 个 0）。
        corrupt(s, 0, "目标", 0)
        recompute(s, 0)
        out = verify(s, limit=1000)
        self.assertEqual(
            (out["完整"], out["检查"], out["断点"], out["原因"]),
            (False, 0, 0, "目标"),
        )
        self.assertEqual(out["锚哈希"], "0" * 64)
        self.assertEqual(out["末哈希"], "0" * 64)


if __name__ == "__main__":
    unittest.main()
