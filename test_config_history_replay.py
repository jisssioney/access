import hashlib
import json
import unittest

from access import (
    Authenticator,
    Sessions,
)


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def load(s, mutate=None):
    doc = json.loads(s.export_config())
    if mutate is not None:
        mutate(doc)
    return s.load_config(json.dumps(doc, ensure_ascii=False))


def record_hash(r):
    head = {
        "修订": r["修订"],
        "父修订": r["父修订"],
        "操作": r["操作"],
        "目标": r["目标"],
        "摘要": r["摘要"],
        "前哈希": r["前哈希"],
    }
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def fix_hashes(s, start=0):
    """自 start 起重算链：前哈希衔接前项哈希，哈希按前六键重算。"""
    log = s._config_history_log
    keys = ["修订", "父修订", "操作", "目标", "摘要", "前哈希", "哈希"]
    for i in range(start, len(log)):
        r = log[i]
        prev = log[i - 1][6] if i else "0" * 64
        r = (r[0], r[1], r[2], r[3], r[4], prev, None)
        r = r[:6] + (record_hash(dict(zip(keys, r))),)
        log[i] = r


def tamper(s, index, **fields):
    """改写第 index 条记录的字段（位置：修订0/父1/操作2/目标3/摘要4/前哈希5/
    哈希6），默认随后重算哈希链以隔离被测检查项。"""
    pos = {"修订": 0, "父修订": 1, "操作": 2, "目标": 3, "摘要": 4,
           "前哈希": 5, "哈希": 6}
    r = list(s._config_history_log[index])
    for k, v in fields.items():
        r[pos[k]] = v
    s._config_history_log[index] = tuple(r)


def replay(s):
    return json.loads(s.config_history_replay())


class ReplayHonestTest(unittest.TestCase):
    def test_construction_only(self):
        s = make()
        out = replay(s)
        self.assertEqual(
            list(out),
            ["锚修订", "锚哈希", "检查", "完整", "断点", "原因", "末修订", "末摘要"],
        )
        rev = json.loads(s.config_revision())
        self.assertEqual(out["锚修订"], -1)
        self.assertEqual(out["锚哈希"], "0" * 64)
        self.assertEqual(out["检查"], 1)
        self.assertTrue(out["完整"])
        self.assertEqual(out["断点"], -1)
        self.assertEqual(out["原因"], "")
        self.assertEqual(out["末修订"], rev["修订"])
        self.assertEqual(out["末摘要"], rev["摘要"])

    def test_four_operations_complete(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1 加载
        s.rollback_config()  # 2 回滚
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 7
        s.config_cas("c", json.dumps(doc, ensure_ascii=False), 2, 0)  # 3 CAS
        s.config_revert("r", 0, 3, 0)  # 4 回退
        out = replay(s)
        rev = json.loads(s.config_revision())
        self.assertTrue(out["完整"])
        self.assertEqual(out["检查"], 5)
        self.assertEqual((out["断点"], out["原因"]), (-1, ""))
        self.assertEqual(out["末修订"], rev["修订"])
        self.assertEqual(out["末摘要"], rev["摘要"])

    def test_read_only_and_stable(self):
        s = make()
        load(s)
        s.rollback_config()
        first = s.config_history_replay()
        rev = s.config_revision()
        for _ in range(3):
            self.assertEqual(s.config_history_replay(), first)
        self.assertEqual(s.config_revision(), rev)
        raw = first
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw.strip())

    def test_evicted_anchor(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 300):
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertNotIn(0, s._config_history)
        out = replay(s)
        log = s._config_history_log
        self.assertEqual(out["锚修订"], log[0][0] - 1)
        self.assertEqual(out["锚哈希"], log[0][5])
        self.assertTrue(out["完整"])
        self.assertEqual(out["检查"], 256)
        rev = json.loads(s.config_revision())
        self.assertEqual(out["末修订"], rev["修订"])
        self.assertEqual(out["末摘要"], rev["摘要"])


class ReplayVerifyContractTest(unittest.TestCase):
    def setUp(self):
        self.s = make()
        load(self.s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1
        load(self.s, lambda d: d["会话"].__setitem__("租期毫秒", 1002))  # 2

    def test_revision_broken(self):
        tamper(self.s, 2, 修订=5)
        fix_hashes(self.s, 2)
        out = replay(self.s)
        self.assertEqual(
            (out["完整"], out["断点"], out["原因"], out["检查"]),
            (False, 5, "修订", 2),
        )
        self.assertEqual(out["末修订"], 1)

    def test_revision_unreadable_breakpoint_minus_one(self):
        tamper(self.s, 2, 修订="2")
        fix_hashes(self.s, 2)
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (-1, "修订"))

    def test_parent_broken(self):
        tamper(self.s, 2, 父修订=9)
        fix_hashes(self.s, 2)
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (2, "父修订"))

    def test_op_broken(self):
        tamper(self.s, 1, 操作="升级")
        fix_hashes(self.s, 1)
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (1, "操作"))

    def test_target_broken(self):
        tamper(self.s, 1, 目标=0)
        fix_hashes(self.s, 1)
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (1, "目标"))

    def test_snapshot_missing(self):
        del self.s._config_history[2]
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"], out["检查"]), (2, "快照", 2))

    def test_summary_broken(self):
        tamper(self.s, 2, 摘要="0" * 64)
        fix_hashes(self.s, 2)
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (2, "摘要"))

    def test_prev_hash_broken(self):
        r = list(self.s._config_history_log[2])
        r[5] = "1" * 64
        self.s._config_history_log[2] = tuple(r)  # 不重算：前哈希不衔接
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (2, "前哈希"))

    def test_hash_broken(self):
        tamper(self.s, 2, 哈希="f" * 64)
        out = replay(self.s)
        self.assertEqual((out["断点"], out["原因"]), (2, "哈希"))

    def test_last_values_from_last_passed(self):
        tamper(self.s, 2, 摘要="0" * 64)
        fix_hashes(self.s, 2)
        out = replay(self.s)
        rows = json.loads(self.s.config_history())["项目"]
        self.assertEqual(out["末修订"], rows[1]["修订"])
        self.assertEqual(out["末摘要"], rows[1]["摘要"])


class ReplaySimulationTest(unittest.TestCase):
    def test_rollback_point_unknown(self):
        s = make()
        tamper(s, 0, 操作="回滚")  # 构造改回滚：回滚点未知
        fix_hashes(s, 0)
        out = replay(s)
        self.assertEqual(
            (out["完整"], out["断点"], out["原因"], out["检查"]),
            (False, 0, "回滚", 0),
        )
        self.assertEqual((out["末修订"], out["末摘要"]), (-1, "0" * 64))

    def test_rollback_snapshot_mismatch(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1
        s.rollback_config()  # 2 回滚：快照应同修订 0
        # 篡改修订 2 快照为另一份合法配置并同步摘要/哈希
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 42
        spec = s._parse_config_text(json.dumps(doc, ensure_ascii=False))[0]
        s._config_history[2] = spec
        from access import _compact_config
        summary = hashlib.sha256(
            _compact_config(spec).encode("utf-8")
        ).hexdigest()
        tamper(s, 2, 摘要=summary)
        fix_hashes(s, 2)
        out = replay(s)
        self.assertEqual((out["断点"], out["原因"]), (2, "回滚"))

    def test_revert_snapshot_mismatch(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1
        s.config_revert("r", 0, 1, 0)  # 2 回退到 0
        # 篡改修订 2 快照使之不等于目标快照，并同步摘要/哈希
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 42
        spec = s._parse_config_text(json.dumps(doc, ensure_ascii=False))[0]
        s._config_history[2] = spec
        from access import _compact_config
        summary = hashlib.sha256(
            _compact_config(spec).encode("utf-8")
        ).hexdigest()
        tamper(s, 2, 摘要=summary)
        fix_hashes(s, 2)
        out = replay(s)
        self.assertEqual((out["断点"], out["原因"]), (2, "回退"))

    def test_revert_target_evicted_is_boundary(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 11):  # 修订 1..10
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        s.config_revert("r", 0, 10, 0)  # 修订 11 回退到 0
        for i in range(245):  # 再提交 245 次：窗口 [1, 256]，目标 0 被淘汰
            base["会话"]["租期毫秒"] = 2000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertNotIn(0, s._config_history)
        self.assertIn(11, s._config_history)
        out = replay(s)
        self.assertEqual((out["完整"], out["断点"], out["原因"]), (False, 11, "边界"))

    def test_truncated_rollback_unknown_point(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1 加载
        s.rollback_config()  # 2 回滚
        base = json.loads(s.export_config())
        for i in range(254):  # 再提交 254 次：窗口 [1, 256]
            base["会话"]["租期毫秒"] = 3000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertEqual(s._config_history_log[0][0], 1)
        out = replay(s)
        # 最老项（修订 1 加载）被信任，修订 2 回滚的回滚点未知
        self.assertEqual(
            (out["完整"], out["断点"], out["原因"], out["检查"]),
            (False, 2, "回滚", 1),
        )
        self.assertEqual(out["末修订"], 1)


if __name__ == "__main__":
    unittest.main()
