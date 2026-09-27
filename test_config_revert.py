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


def load(s, mutate=None):
    doc = json.loads(s.export_config())
    if mutate is not None:
        mutate(doc)
    return s.load_config(json.dumps(doc, ensure_ascii=False))


class ConfigHistoryTest(unittest.TestCase):
    def test_construction_is_revision_zero(self):
        s = make()
        out = json.loads(s.config_revision())
        self.assertEqual(list(out), ["修订", "摘要"])
        self.assertEqual(out["修订"], 0)
        self.assertEqual(set(s._config_history), {0})
        self.assertEqual(s._config_history[0], s._current_spec())

    def test_commits_record_history_failures_and_upgrade_do_not(self):
        s = make()
        v0 = s.export_config()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))  # rev1
        self.assertEqual(json.loads(s.config_revision())["修订"], 1)
        self.assertEqual(set(s._config_history), {0, 1})
        # rollback 成功保存新修订
        self.assertIn('"租期毫秒":9', s.export_config())
        s.rollback_config()  # rev2
        self.assertEqual(set(s._config_history), {0, 1, 2})
        self.assertEqual(s.export_config(), v0)
        # config_cas 成功保存新修订
        doc = json.loads(v0)
        doc["会话"]["租期毫秒"] = 5
        text = json.dumps(doc, ensure_ascii=False)
        cas = json.loads(s.config_cas("c", text, 2, 0))
        self.assertEqual(cas["修订"], 3)
        self.assertEqual(set(s._config_history), {0, 1, 2, 3})
        # CAS 修订不符失败不保存
        with self.assertRaises(StateError):
            s.config_cas("c2", text, 99, 0)
        self.assertEqual(set(s._config_history), {0, 1, 2, 3})
        # 只读升级不保存
        s.upgrade_config(v0, 6)
        self.assertEqual(set(s._config_history), {0, 1, 2, 3})
        # 失败加载不保存
        bad = json.loads(s.export_config())
        bad["会话"]["租期毫秒"] = 0
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(bad, ensure_ascii=False))
        self.assertEqual(set(s._config_history), {0, 1, 2, 3})
        # config_change 同参重放不再次保存
        s.config_change("L", "加载", text, 0)  # rev4
        self.assertEqual(set(s._config_history), {0, 1, 2, 3, 4})
        s.config_change("L", "加载", text, 0)
        self.assertEqual(set(s._config_history), {0, 1, 2, 3, 4})

    def test_history_keeps_256_most_recent_and_never_current(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 300):
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertEqual(s._revision, 299)
        hist = s._config_history
        self.assertEqual(len(hist), 256)
        self.assertEqual(min(hist), 44)
        self.assertEqual(max(hist), 299)
        self.assertNotIn(0, hist)  # 构造态也可被淘汰
        # 回退到最旧在册项：提交后该旧项淘汰、当前项保留
        out = json.loads(s.config_revert("e", 44, 299, 0))
        self.assertEqual((out["修订"], out["目标"]), (300, 44))
        self.assertEqual(len(s._config_history), 256)
        self.assertNotIn(44, s._config_history)
        self.assertIn(45, s._config_history)
        self.assertIn(300, s._config_history)


class ConfigRevertValidationTest(unittest.TestCase):
    def test_key_validated_first_and_not_cached(self):
        s = make()
        for bad in (1, True, None):
            with self.assertRaises(TypeError):
                s.config_revert(bad, 0, 0, 0)
        with self.assertRaises(ValueError):
            s.config_revert("", 0, 0, 0)
        self.assertEqual(s._config_revert_cache, {})

    def test_param_types_in_declaration_order(self):
        s = make()
        with self.assertRaises(TypeError) as cm:
            s.config_revert("k", True, True, True)
        self.assertIn("target", str(cm.exception))
        with self.assertRaises(TypeError) as cm:
            s.config_revert("k", 0, 1.5, True)
        self.assertIn("expected", str(cm.exception))
        with self.assertRaises(TypeError) as cm:
            s.config_revert("k", 0, 0, "0")
        self.assertIn("now_ms", str(cm.exception))
        for bad in (1.0, None, "0", (0,)):
            with self.assertRaises(TypeError):
                s.config_revert("k", bad, 0, 0)

    def test_negative_values_in_declaration_order(self):
        s = make()
        with self.assertRaises(ValueError) as cm:
            s.config_revert("k", -1, -1, -1)
        self.assertIn("target", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            s.config_revert("k", 0, -1, -1)
        self.assertIn("expected", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            s.config_revert("k", 0, 0, -1)
        self.assertIn("now_ms", str(cm.exception))

    def test_expected_mismatch_state_error_before_target_lookup(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))  # rev1
        # 目标 999 未保留，但修订比较先于目标查询
        with self.assertRaises(StateError) as cm:
            s.config_revert("k", 999, 5, 0)
        self.assertEqual(cm.exception.args, (5, 1))
        self.assertEqual(s._revision, 1)
        self.assertNotIn("k", s._config_revert_cache)

    def test_target_must_be_below_expected(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))  # rev1
        with self.assertRaises(ValueError):
            s.config_revert("a", 5, 1, 0)
        with self.assertRaises(ValueError):
            s.config_revert("b", 1, 1, 0)  # target == expected

    def test_evicted_target_raises_key_error_with_target(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 257):
            base["会话"]["租期毫秒"] = 1000 + i
            s.load_config(json.dumps(base, ensure_ascii=False))
        self.assertEqual(s._revision, 256)
        with self.assertRaises(KeyError) as cm:
            s.config_revert("k", 0, 256, 0)
        self.assertEqual(cm.exception.args, (0,))
        self.assertNotIn("k", s._config_revert_cache)
        self.assertEqual(s._revision, 256)


class ConfigRevertSuccessTest(unittest.TestCase):
    def test_revert_shape_summaries_and_snapshot(self):
        s = make()
        v0 = s.export_config()
        v1 = load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))
        raw = s.config_revert("r", 0, 1, 100)
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw.strip())
        out = json.loads(raw)
        self.assertEqual(list(out), ["修订", "目标", "前摘要", "后摘要"])
        self.assertEqual(out["修订"], 2)
        self.assertEqual(out["目标"], 0)
        self.assertEqual(out["前摘要"], digest(v1))
        self.assertEqual(out["后摘要"], digest(v0))
        # 当前配置逐字节回到目标快照，修订查询摘要一致
        self.assertEqual(s.export_config(), v0)
        self.assertEqual(json.loads(s.config_revision())["摘要"], digest(v0))
        self.assertEqual(set(s._config_history), {0, 1, 2})

    def test_revert_to_middle_revision_is_exact_snapshot(self):
        s = make()
        v0 = s.export_config()
        v1 = load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))
        load(s, lambda d: d["会话"].__setitem__("空闲毫秒", 7))  # rev2
        out = json.loads(s.config_revert("r", 1, 2, 0))
        self.assertEqual(out["修订"], 3)
        self.assertEqual(s.export_config(), v1)
        self.assertEqual(out["后摘要"], digest(v1))
        # 构造态修订 0 与 rev2 快照仍在册且未受回退影响
        self.assertIn(0, s._config_history)
        self.assertIn(2, s._config_history)
        self.assertNotEqual(s.export_config(), v0)

    def test_revert_overwrites_rollback_point_with_pre_revert_spec(self):
        s = make()
        v0 = s.export_config()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))  # rev1
        # 此前无回滚点；回退成功后回滚点指向回退前（rev1）配置
        s.config_revert("r", 0, 1, 0)  # rev2 = v0
        rolled = s.rollback_config()  # rev3 = rev1 spec
        self.assertIn('"租期毫秒":9', rolled)
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_resource_failure_changes_nothing_and_key_not_cached(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(auth, 1, 1, 5000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 4
        s.load_config(json.dumps(doc, ensure_ascii=False))  # rev1，回滚点 rev0(总1)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        with self.assertRaises(ResourceError):
            s.config_revert("x", 0, 1, 0)  # 目标总限 1 承载不了 2 个会话
        # 失败不改配置、历史、修订、回滚点、缓存与会话
        self.assertEqual(json.loads(s.export_config())["会话"]["总数"], 4)
        self.assertEqual(s._revision, 1)
        self.assertEqual(set(s._config_history), {0, 1})
        self.assertIsNotNone(s._rollback)
        self.assertNotIn("x", s._config_revert_cache)
        # 腾出会话后同一 key 首次成功
        s.do("k3", "下线", "s2", None, 1)
        out = json.loads(s.config_revert("x", 0, 1, 2))
        self.assertEqual((out["修订"], out["目标"]), (2, 0))
        self.assertEqual(json.loads(s.export_config())["会话"]["总数"], 1)


class ConfigRevertReplayTest(unittest.TestCase):
    def test_same_params_replay_original_bytes_without_revision_check(self):
        s = make()
        v1 = load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))
        first = s.config_revert("r", 0, 1, 7)
        self.assertEqual(json.loads(first)["修订"], 2)
        # 提交后修订已变，同参重放不再比较修订、不加载、原样返回首字节
        second = s.config_revert("r", 0, 1, 7)
        self.assertEqual(second, first)
        self.assertEqual(s._revision, 2)
        # 外部再改配置；重放仍返回首果且不回退
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 3))  # rev3
        third = s.config_revert("r", 0, 1, 7)
        self.assertEqual(third, first)
        self.assertEqual(s._revision, 3)
        self.assertEqual(
            json.loads(s.export_config())["会话"]["租期毫秒"], 3
        )

    def test_different_params_value_error(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))
        s.config_revert("r", 0, 1, 7)
        for args in ((0, 1, 8), (0, 0, 7), (1, 1, 7)):
            with self.assertRaises(ValueError):
                s.config_revert("r", *args)
        # 异参不占成功缓存之外的语义：原参数仍可重放
        self.assertEqual(
            s.config_revert("r", 0, 1, 7),
            s.config_revert("r", 0, 1, 7),
        )

    def test_keys_independent(self):
        s = make()
        v0 = s.export_config()
        v1 = load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))
        a = json.loads(s.config_revert("a", 0, 1, 0))  # rev2 = v0
        self.assertEqual((a["修订"], a["目标"]), (2, 0))
        b = json.loads(s.config_revert("b", 0, 2, 0))  # 独立 key，当前 rev2
        self.assertEqual((b["修订"], b["目标"]), (3, 0))
        self.assertEqual(s.export_config(), v0)
        # a 重放不受 b 推进影响
        self.assertEqual(
            json.loads(s.config_revert("a", 0, 1, 0))["修订"], 2
        )

    def test_failure_does_not_cache_even_with_same_key(self):
        s = make()
        with self.assertRaises(StateError):
            s.config_revert("k", 0, 5, 0)
        # 之后以同 key 做合法回退，应真正执行而非重放
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 9))
        out = json.loads(s.config_revert("k", 0, 1, 0))
        self.assertEqual(out["修订"], 2)


if __name__ == "__main__":
    unittest.main()
