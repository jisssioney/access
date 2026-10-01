import hashlib
import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def digest(text):
    return hashlib.sha256(text[:-1].encode("utf-8")).hexdigest()


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


def load(s, mutate=None):
    doc = json.loads(s.export_config())
    if mutate is not None:
        mutate(doc)
    return s.load_config(json.dumps(doc, ensure_ascii=False))


def items(s, **kw):
    return json.loads(s.config_history(**kw))["项目"]


class ConfigHistoryConstructionTest(unittest.TestCase):
    def test_construction_record_shape(self):
        s = make()
        out = json.loads(s.config_history())
        self.assertEqual(list(out), ["下个修订", "项目"])
        self.assertEqual(out["下个修订"], 0)
        self.assertEqual(len(out["项目"]), 1)
        r = out["项目"][0]
        self.assertEqual(
            list(r), ["修订", "父修订", "操作", "目标", "摘要", "前哈希", "哈希"]
        )
        self.assertEqual((r["修订"], r["父修订"], r["目标"]), (0, -1, -1))
        self.assertEqual(r["操作"], "构造")
        self.assertEqual(r["前哈希"], "0" * 64)
        self.assertEqual(
            r["摘要"], json.loads(s.config_revision())["摘要"]
        )
        self.assertEqual(r["摘要"], digest(s.export_config()))
        self.assertEqual(record_hash(r), r["哈希"])
        # 输出为 LF 尾紧凑 JSON，无空白
        raw = s.config_history()
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw.strip())


class ConfigHistoryAppendTest(unittest.TestCase):
    def test_four_operations_append_in_order(self):
        s = make()
        v1 = load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1 加载
        v2 = s.rollback_config()  # 2 回滚
        doc = json.loads(v2)
        doc["会话"]["租期毫秒"] = 7
        text = json.dumps(doc, ensure_ascii=False)
        cas = json.loads(s.config_cas("c", text, 2, 0))  # 3 CAS
        rv = json.loads(s.config_revert("r", 0, 3, 0))  # 4 回退
        rows = items(s, limit=1000)
        self.assertEqual(
            [(r["修订"], r["父修订"], r["操作"], r["目标"]) for r in rows],
            [(0, -1, "构造", -1),
             (1, 0, "加载", -1),
             (2, 1, "回滚", -1),
             (3, 2, "CAS", -1),
             (4, 3, "回退", 0)],
        )
        # 链接：后项前哈希取前项哈希；各项摘要同 config_revision 口径；哈希可重算。
        zero = "0" * 64
        summaries = {
            1: digest(v1), 2: digest(v2), 3: cas["后摘要"], 4: rv["后摘要"],
        }
        prev_hash = zero
        for r in rows:
            self.assertEqual(r["前哈希"], prev_hash)
            self.assertEqual(record_hash(r), r["哈希"])
            if r["修订"] in summaries:
                self.assertEqual(r["摘要"], summaries[r["修订"]])
            prev_hash = r["哈希"]

    def test_failures_and_replays_do_not_append(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # rev1
        # 无回滚点的失败回滚不追加（另起实例，加载成功会设回滚点）
        fresh = make()
        with self.assertRaises(StateError):
            fresh.rollback_config()
        self.assertEqual(
            [(r["修订"], r["操作"]) for r in items(fresh, limit=1000)],
            [(0, "构造")],
        )
        before = items(s, limit=1000)
        # 失败加载不追加
        bad = json.loads(s.export_config())
        bad["会话"]["租期毫秒"] = 0
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(bad, ensure_ascii=False))
        # CAS 修订不符失败不追加
        with self.assertRaises(StateError):
            s.config_cas("x", s.export_config(), 99, 0)
        # 回退修订不符失败不追加
        with self.assertRaises(StateError):
            s.config_revert("y", 0, 99, 0)
        # 只读升级不追加
        s.upgrade_config(s.export_config(), 10)
        self.assertEqual(items(s, limit=1000), before)

        # CAS / 回退成功后的同参重放不追加
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 7
        text = json.dumps(doc, ensure_ascii=False)
        first = s.config_cas("c", text, 1, 0)  # rev2 CAS
        self.assertEqual(s.config_cas("c", text, 1, 0), first)
        s.config_revert("r", 0, 2, 0)  # rev3 回退
        s.config_revert("r", 0, 2, 0)  # 重放
        rows = items(s, limit=1000)
        self.assertEqual(
            [(r["修订"], r["操作"]) for r in rows],
            [(0, "构造"), (1, "加载"), (2, "CAS"), (3, "回退")],
        )

    def test_config_change_first_success_append_replays_and_upgrade_not(self):
        s = make()
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 900
        text = json.dumps(doc, ensure_ascii=False)
        s.config_change("L", "加载", text, 0)
        s.config_change("L", "加载", text, 0)  # 重放不追加
        s.config_change("R", "回滚", None, 1)
        s.config_change("R", "回滚", None, 1)  # 重放不追加
        s.config_change("U", "升级", s.export_config(), 0)  # 只读不追加
        self.assertEqual(
            [(r["修订"], r["操作"]) for r in items(s, limit=1000)],
            [(0, "构造"), (1, "加载"), (2, "回滚")],
        )


class ConfigHistoryQueryTest(unittest.TestCase):
    def setUp(self):
        self.s = make()
        for _ in range(5):
            load(self.s)  # rev 1..5

    def test_defaults_and_order(self):
        out = json.loads(self.s.config_history())
        self.assertEqual(out["下个修订"], 5)
        self.assertEqual([r["修订"] for r in out["项目"]], [0, 1, 2, 3, 4, 5])

    def test_pagination(self):
        o1 = json.loads(self.s.config_history(after=-1, limit=2))
        self.assertEqual([r["修订"] for r in o1["项目"]], [0, 1])
        self.assertEqual(o1["下个修订"], 1)
        o2 = json.loads(self.s.config_history(after=1, limit=2))
        self.assertEqual([r["修订"] for r in o2["项目"]], [2, 3])
        self.assertEqual(o2["下个修订"], 3)

    def test_empty_window_cursor_is_after(self):
        o = json.loads(self.s.config_history(after=5, limit=2))
        self.assertEqual(o["项目"], [])
        self.assertEqual(o["下个修订"], 5)

    def test_limit_bounds_take_at_most_limit(self):
        o = json.loads(self.s.config_history(after=0))  # 默认 limit 100
        self.assertEqual([r["修订"] for r in o["项目"]], [1, 2, 3, 4, 5])
        o = json.loads(self.s.config_history(after=4, limit=1))
        self.assertEqual([r["修订"] for r in o["项目"]], [5])
        self.assertEqual(o["下个修订"], 5)

    def test_param_types(self):
        for kw in (
            {"after": True}, {"after": 1.0}, {"after": "0"},
            {"limit": True}, {"limit": 1.0}, {"limit": "10"},
        ):
            with self.assertRaises(TypeError):
                self.s.config_history(**kw)

    def test_param_values(self):
        for bad in (-2, -100):
            with self.assertRaises(ValueError):
                self.s.config_history(after=bad)
        for bad in (0, -1, 1001):
            with self.assertRaises(ValueError):
                self.s.config_history(limit=bad)
        # 边界合法
        json.loads(self.s.config_history(after=-1, limit=1))
        json.loads(self.s.config_history(limit=1000))

    def test_unretained_after_raises_key_error(self):
        with self.assertRaises(KeyError) as cm:
            self.s.config_history(after=6)
        self.assertEqual(cm.exception.args, (6,))
        with self.assertRaises(KeyError):
            self.s.config_history(after=999)

    def test_query_is_read_only(self):
        rev = self.s.config_revision()
        for _ in range(3):
            self.s.config_history(0, 2)
        self.assertEqual(self.s.config_revision(), rev)


class ConfigHistoryEvictionTest(unittest.TestCase):
    def test_log_tracks_snapshots_without_resewing_hashes(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 300):
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertEqual(s._revision, 299)
        self.assertEqual(len(s._config_history), 256)
        log = s._config_history_log
        self.assertEqual(len(log), 256)
        self.assertEqual(log[0][0], 44)
        self.assertEqual(log[-1][0], 299)
        self.assertEqual(set(s._config_history), {r[0] for r in log})
        # 链不缝合：最旧在册记录的前哈希不是 0，而是已淘汰前项的哈希；
        # 留存各项前哈希仍衔前项、哈希可重算。
        self.assertNotEqual(log[0][5], "0" * 64)
        for prev, cur in zip(log, log[1:]):
            self.assertEqual(cur[1], prev[0])
            self.assertEqual(cur[5], prev[6])
            keys = ["修订", "父修订", "操作", "目标", "摘要", "前哈希", "哈希"]
            self.assertEqual(
                record_hash(dict(zip(keys, cur))), cur[6]
            )
        # 被淘汰修订查询抛 KeyError(after)；-1 自最旧在册项起。
        with self.assertRaises(KeyError) as cm:
            s.config_history(after=43)
        self.assertEqual(cm.exception.args, (43,))
        o = json.loads(s.config_history(limit=1000))
        self.assertEqual(len(o["项目"]), 256)
        self.assertEqual(o["项目"][0]["修订"], 44)

    def test_eviction_at_revert_keeps_current(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 300):
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        out = json.loads(s.config_revert("e", 44, 299, 0))
        self.assertEqual((out["修订"], out["目标"]), (300, 44))
        log = s._config_history_log
        self.assertEqual(len(log), 256)
        self.assertEqual(log[0][0], 45)
        self.assertEqual(log[-1][0], 300)
        last = log[-1]
        self.assertEqual((last[0], last[1], last[2], last[3]),
                         (300, 299, "回退", 44))
        self.assertNotIn(44, s._config_history)
        self.assertIn(300, s._config_history)


if __name__ == "__main__":
    unittest.main()
