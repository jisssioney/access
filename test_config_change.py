import json
import unittest

from access import Authenticator, ResourceError, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def ops(s):
    return [(e[0], e[3], e[4], e[5], e[6]) for e in s._chain_events]


class ConfigChangeValidationTest(unittest.TestCase):
    def test_key_validated_first_and_not_cached(self):
        s = make()
        for bad in (1, True, None):
            with self.assertRaises(TypeError):
                s.config_change(bad, "加载", "x", 0)
        with self.assertRaises(ValueError):
            s.config_change("", "加载", "x", 0)
        self.assertEqual(s._config_change_cache, {})
        self.assertEqual(ops(s), [])

    def test_op_type(self):
        s = make()
        for i, bad in enumerate((1, True, None, ("加载",))):
            with self.assertRaises(TypeError):
                s.config_change(f"k{i}", bad, None, 0)

    def test_op_value(self):
        s = make()
        with self.assertRaises(ValueError):
            s.config_change("k", "建立", None, 0)

    def test_text_mode(self):
        s = make()
        with self.assertRaises(TypeError):
            s.config_change("k1", "加载", 1, 0)
        with self.assertRaises(TypeError):
            s.config_change("k2", "加载", None, 0)
        # 回滚 text 非 None 为值/模式错
        with self.assertRaises(ValueError):
            s.config_change("k3", "回滚", "x", 0)

    def test_now_ms_type_and_value(self):
        s = make()
        for i, bad in enumerate((True, 1.5, "0", None)):
            with self.assertRaises(TypeError):
                s.config_change(f"k{i}", "回滚", None, bad)
        with self.assertRaises(ValueError):
            s.config_change("kz", "回滚", None, -1)

    def test_type_errors_precede_value_errors(self):
        s = make()
        # op 类型错先于 text/now_ms 错
        with self.assertRaises(TypeError):
            s.config_change("k", 1, "x", True)
        # now_ms 类型错先于回滚 text 值错
        with self.assertRaises(TypeError):
            s.config_change("k2", "回滚", "x", True)

    def test_param_errors_cached_not_audited(self):
        s = make()
        with self.assertRaises(TypeError):
            s.config_change("k", "加载", 1, 0)
        # 同参重放：重抛首果，不审计
        with self.assertRaises(TypeError):
            s.config_change("k", "加载", 1, 0)
        self.assertEqual(ops(s), [])
        # 异参 ValueError，仍不审计
        with self.assertRaises(ValueError):
            s.config_change("k", "加载", "{}", 0)
        self.assertEqual(ops(s), [])
        # 参数错 key 永不入业务：再来同参仍重抛参数错
        with self.assertRaises(TypeError):
            s.config_change("k", "加载", 1, 0)
        self.assertEqual(ops(s), [])


class ConfigChangeLoadTest(unittest.TestCase):
    def test_first_load_success_and_replay(self):
        s = make()
        text = s.export_config()
        out = s.config_change("L", "加载", text, 100)
        self.assertEqual(out, text)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        self.assertEqual(ops(s), [(1, "配置加载", "", "成功", 0)])
        self.assertTrue(s.verify_audit())
        # 同参重放返回同串，记重放成功，原序号指 1
        out2 = s.config_change("L", "加载", text, 100)
        self.assertEqual(out2, text)
        self.assertEqual(
            ops(s),
            [(1, "配置加载", "", "成功", 0),
             (2, "配置加载", "", "重放成功", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_replay_does_not_reload_or_age(self):
        s = make()
        text = s.export_config()
        s.config_change("L", "加载", text, 0)
        # 外部再加载改变配置；重放不重新加载、不老化，返回首果
        doc = json.loads(text)
        doc["会话"]["租期毫秒"] = 3
        s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(s.config_change("L", "加载", text, 0), text)
        self.assertEqual(json.loads(s.export_config())["会话"]["租期毫秒"], 3)

    def test_different_params_value_error_not_audited(self):
        s = make()
        text = s.export_config()
        s.config_change("L", "加载", text, 0)
        doc = json.loads(text)
        doc["会话"]["租期毫秒"] = 3
        other = json.dumps(doc, ensure_ascii=False)
        with self.assertRaises(ValueError):
            s.config_change("L", "加载", other, 0)
        with self.assertRaises(ValueError):
            s.config_change("L", "加载", text, 1)
        with self.assertRaises(ValueError):
            s.config_change("L", "回滚", None, 0)
        self.assertEqual(len(s._chain_events), 1)

    def test_invalid_config_value_error_audited_and_replayed(self):
        s = make()
        with self.assertRaises(ValueError):
            s.config_change("bad", "加载", "{not json", 5)
        self.assertEqual(ops(s)[0][:4], (1, "配置加载", "", "JSONDecodeError"))
        with self.assertRaises(ValueError) as cm:
            s.config_change("bad", "加载", "{not json", 5)
        self.assertEqual(type(cm.exception).__name__, "JSONDecodeError")
        self.assertEqual(
            ops(s)[1], (2, "配置加载", "", "重放JSONDecodeError", 1)
        )
        self.assertTrue(s.verify_audit())

    def test_structural_value_error_class_name(self):
        s = make()
        with self.assertRaises(ValueError) as cm:
            s.config_change("bad", "加载", "[1,2]", 0)
        self.assertIs(type(cm.exception), ValueError)
        self.assertEqual(ops(s), [(1, "配置加载", "", "ValueError", 0)])

    def test_resource_error_audited_replayed_and_state_unchanged(self):
        s = make(pool=("10.0.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 1
        small = json.dumps(doc, ensure_ascii=False)
        with self.assertRaises(ResourceError):
            s.config_change("rc", "加载", small, 50)
        self.assertEqual(ops(s)[-1][3:], ("ResourceError", 0))
        # 配置未改
        self.assertEqual(json.loads(s.export_config())["会话"]["总数"], 4)
        # 回滚点未被失败加载改动：此前无成功加载，故无回滚点
        with self.assertRaises(StateError):
            s.rollback_config()
        with self.assertRaises(ResourceError):
            s.config_change("rc", "加载", small, 50)
        self.assertEqual(
            ops(s)[-1], (4, "配置加载", "", "重放ResourceError", 3)
        )
        self.assertTrue(s.verify_audit())

    def test_failure_does_not_touch_sessions_or_fault_state(self):
        s = make()
        r = json.loads(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["地址"], "10.0.0.2")
        s.pool_fault("f", "注入", "default", 1000, 0)
        with self.assertRaises(ValueError):
            s.config_change("bad", "加载", "{", 1)
        # 会话、租约、故障态不变
        self.assertIn("default", s._pool_fault)
        self.assertEqual(json.loads(s.do("k2", "续租", "s1", None, 1))["地址"],
                         "10.0.0.2")


class ConfigChangeRollbackTest(unittest.TestCase):
    def test_rollback_no_point_state_error_audited(self):
        s = make()
        with self.assertRaises(StateError):
            s.config_change("rb", "回滚", None, 7)
        self.assertEqual(ops(s), [(1, "配置回滚", "", "StateError", 0)])
        with self.assertRaises(StateError):
            s.config_change("rb", "回滚", None, 7)
        self.assertEqual(ops(s)[1],
                         (2, "配置回滚", "", "重放StateError", 1))
        self.assertTrue(s.verify_audit())

    def test_load_then_rollback_success(self):
        s = make()
        before = s.export_config()
        doc = json.loads(before)
        doc["会话"]["租期毫秒"] = 9
        changed = json.dumps(doc, ensure_ascii=False)
        self.assertEqual(s.config_change("L", "加载", changed, 1),
                         s.export_config())
        self.assertIn('"租期毫秒":9', s.export_config())
        out = s.config_change("R", "回滚", None, 2)
        self.assertEqual(out, before)
        self.assertEqual(s.export_config(), before)
        self.assertEqual(
            ops(s),
            [(1, "配置加载", "", "成功", 0),
             (2, "配置回滚", "", "成功", 0)],
        )
        # 回滚点已清除
        with self.assertRaises(StateError):
            s.config_change("R2", "回滚", None, 3)
        self.assertTrue(s.verify_audit())

    def test_rollback_replay_after_point_consumed(self):
        s = make()
        before = s.export_config()
        doc = json.loads(before)
        doc["会话"]["租期毫秒"] = 9
        s.config_change("L", "加载", json.dumps(doc, ensure_ascii=False), 0)
        out1 = s.config_change("R", "回滚", None, 0)
        self.assertEqual(out1, before)
        # 回滚点已被首次消费；重放不重跑回滚，仍返回首果
        out2 = s.config_change("R", "回滚", None, 0)
        self.assertEqual(out2, before)
        self.assertEqual(
            [e[5] for e in s._chain_events],
            ["成功", "成功", "重放成功"],
        )

    def test_rollback_resource_error_keeps_point_and_audited(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(auth, 1, 1, 5000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 4
        s.config_change("L", "加载", json.dumps(doc, ensure_ascii=False), 0)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        with self.assertRaises(ResourceError):
            s.config_change("R", "回滚", None, 1)
        self.assertIn('"总数":4', s.export_config())
        # 回滚点保留：下线后回滚成功
        s.do("k3", "下线", "s2", None, 2)
        out = s.rollback_config()
        self.assertIn('"总数":1', out)

    def test_exception_args_preserved_on_replay(self):
        s = make()
        with self.assertRaises(StateError) as first:
            s.config_change("e", "回滚", None, 0)
        with self.assertRaises(StateError) as second:
            s.config_change("e", "回滚", None, 0)
        self.assertEqual(second.exception.args, first.exception.args)


class ConfigChangeUpgradeTest(unittest.TestCase):
    V1 = json.dumps({
        "版本": 1,
        "会话": {"总数": 3, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 7},
        "地址池": {"CIDR": "10.9.0.0/24", "保留": ["10.9.0.1"],
                   "静态": [["alice", "10.9.0.2"]]},
    }, ensure_ascii=False)

    def test_first_upgrade_returns_envelope_and_is_read_only(self):
        s = make()
        before = s.export_config()
        out = s.config_change("U", "升级", self.V1, 100)
        # 首调等同 upgrade_config(text, 5)，原字节返回升级包。
        self.assertEqual(out, s.upgrade_config(self.V1, 5))
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        doc = json.loads(out)
        self.assertEqual(
            list(doc), ["源版本", "目标版本", "改变", "摘要", "配置"]
        )
        self.assertEqual(doc["源版本"], 1)
        self.assertEqual(doc["目标版本"], 5)
        self.assertIs(doc["改变"], True)
        self.assertIsInstance(doc["摘要"], str)
        self.assertIsInstance(doc["配置"], dict)
        # 只读：配置、运行态不变。
        self.assertEqual(s.export_config(), before)
        self.assertEqual(
            ops(s), [(1, "配置升级", "", "成功", 0)]
        )
        self.assertTrue(s.verify_audit())
        # 不产生回滚点。
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_upgrade_replay_returns_same_bytes_and_links_origin(self):
        s = make()
        direct = s.upgrade_config(self.V1, 5)
        out1 = s.config_change("U", "升级", self.V1, 100)
        # 外部改变配置与认证策略；重放不预检、不重跑，仍返回首果原字节。
        loaded = json.loads(s.export_config())
        loaded["会话"]["租期毫秒"] = 3
        s.load_config(json.dumps(loaded, ensure_ascii=False))
        out2 = s.config_change("U", "升级", self.V1, 100)
        self.assertEqual(out1, direct)
        self.assertEqual(out2, direct)
        self.assertEqual(
            ops(s),
            [(1, "配置升级", "", "成功", 0),
             (2, "配置升级", "", "重放成功", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_upgrade_v5_changed_false(self):
        s = make()
        v5 = s.export_config()
        doc = json.loads(s.config_change("V", "升级", v5, 0))
        self.assertEqual(doc["源版本"], 5)
        self.assertIs(doc["改变"], False)
        self.assertEqual(ops(s), [(1, "配置升级", "", "成功", 0)])

    def test_upgrade_invalid_json_audited_and_replayed(self):
        s = make()
        with self.assertRaises(ValueError):
            s.config_change("bad", "升级", "{not json", 5)
        self.assertEqual(ops(s)[0][:4], (1, "配置升级", "", "JSONDecodeError"))
        with self.assertRaises(ValueError) as cm:
            s.config_change("bad", "升级", "{not json", 5)
        self.assertEqual(type(cm.exception).__name__, "JSONDecodeError")
        self.assertEqual(
            ops(s)[1], (2, "配置升级", "", "重放JSONDecodeError", 1)
        )
        self.assertTrue(s.verify_audit())

    def test_upgrade_structural_value_error_class_name(self):
        s = make()
        with self.assertRaises(ValueError) as cm:
            s.config_change("bad", "升级", "[1,2]", 0)
        self.assertIs(type(cm.exception), ValueError)
        self.assertEqual(ops(s), [(1, "配置升级", "", "ValueError", 0)])

    def test_upgrade_bad_version_and_dup_keys_value_error(self):
        s = make()
        for i, bad in enumerate((
            '{"版本":0}',
            '{"版本":6}',
            '{"版本":2,"版本":2}',
        )):
            with self.assertRaises(ValueError, msg=bad):
                s.config_change(f"k{i}", "升级", bad, 0)

    def test_upgrade_param_types(self):
        s = make()
        for i, bad in enumerate((1, True, None)):
            with self.assertRaises(TypeError):
                s.config_change(f"t{i}", "升级", bad, 0)
        for i, bad in enumerate((True, 1.5, "0", None)):
            with self.assertRaises(TypeError):
                s.config_change(f"n{i}", "升级", self.V1, bad)
        with self.assertRaises(TypeError):
            s.config_change("u", "升级", None, 0)

    def test_upgrade_op_value_and_negative_now(self):
        s = make()
        with self.assertRaises(ValueError):
            s.config_change("op", "建立", None, 0)
        with self.assertRaises(ValueError):
            s.config_change("neg", "升级", self.V1, -1)

    def test_upgrade_param_errors_cached_not_audited(self):
        s = make()
        with self.assertRaises(TypeError):
            s.config_change("k", "升级", 1, 0)
        with self.assertRaises(TypeError):
            s.config_change("k", "升级", 1, 0)
        self.assertEqual(ops(s), [])
        with self.assertRaises(ValueError):
            s.config_change("k", "升级", self.V1, 0)
        self.assertEqual(ops(s), [])

    def test_upgrade_different_params_value_error_not_audited(self):
        s = make()
        s.config_change("U", "升级", self.V1, 0)
        other = json.dumps({
            "版本": 2,
            "会话": {"总数": 4, "每用户": 2, "空闲毫秒": 5000,
                     "租期毫秒": 1000},
            "地址池": [],
        }, ensure_ascii=False)
        with self.assertRaises(ValueError):
            s.config_change("U", "升级", other, 0)
        with self.assertRaises(ValueError):
            s.config_change("U", "升级", self.V1, 1)
        with self.assertRaises(ValueError):
            s.config_change("U", "加载", self.V1, 0)
        with self.assertRaises(ValueError):
            s.config_change("U", "回滚", None, 0)
        self.assertEqual(len(s._chain_events), 1)

    def test_upgrade_exception_args_preserved_on_replay(self):
        s = make()
        with self.assertRaises(ValueError) as first:
            s.config_change("e", "升级", "{bad", 0)
        with self.assertRaises(ValueError) as second:
            s.config_change("e", "升级", "{bad", 0)
        self.assertEqual(second.exception.args, first.exception.args)

    def test_upgrade_does_not_touch_runtime(self):
        s = make()
        r = json.loads(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["地址"], "10.0.0.2")
        before = s.export_config()
        s.config_change("U", "升级", self.V1, 99999)
        self.assertEqual(
            json.loads(s.do("k2", "续租", "s1", None, 1))["地址"],
            "10.0.0.2",
        )
        self.assertEqual(s.export_config(), before)


class ConfigChangeChainIntegrationTest(unittest.TestCase):
    def test_separate_cache_and_index_domains(self):
        s = make()
        s.do("dup", "建立", "s1", ("alice", "pw"), 0)
        # 同名 key 在 config_change 域为首次调用（无回滚点）
        with self.assertRaises(StateError):
            s.config_change("dup", "回滚", None, 0)
        # do 域重放不受影响
        r = json.loads(s.do("dup", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["状态"], "在线")

    def test_audit_json_shape_and_linkage(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 42)
        out = json.loads(s.audit(limit=1000))
        self.assertEqual(list(out), ["下个序号", "事件"])
        e = out["事件"][0]
        self.assertEqual(
            list(e),
            ["序号", "时刻", "键", "操作", "会话", "结果", "原序号",
             "前哈希", "哈希"],
        )
        self.assertEqual(e["会话"], "")
        self.assertEqual(e["前哈希"], "0" * 64)
        self.assertEqual(len(e["哈希"]), 64)
        # 与 pool_fault 等共用同一条链：后续事件前哈希衔接
        s.pool_fault("p", "注入", "default", 10, 43)
        ev = json.loads(s.audit(limit=1000))["事件"]
        self.assertEqual(ev[1]["前哈希"], ev[0]["哈希"])
        self.assertTrue(s.verify_audit())

    def test_deterministic_byte_output(self):
        def run():
            s = make()
            text = s.export_config()
            parts = [s.config_change("L", "加载", text, 100)]
            s.config_change("L", "加载", text, 100)  # 重放成功
            s.config_change("R", "回滚", None, 100)  # 消费回滚点
            s.config_change("R", "回滚", None, 100)  # 重放成功
            parts.append(s.audit(limit=1000))
            return "".join(parts)
        self.assertEqual(run(), run())


if __name__ == "__main__":
    unittest.main()
