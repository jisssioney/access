import hashlib
import json
import re
import unittest

from access import Authenticator, ResourceError, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def canonical_config_bytes(envelope_text):
    doc = json.loads(envelope_text)
    return json.dumps(doc["配置"], ensure_ascii=False, separators=(",", ":"))


V1 = json.dumps({
    "版本": 1,
    "会话": {"总数": 3, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 7},
    "地址池": {"CIDR": "10.9.0.0/24", "保留": ["10.9.0.1"],
               "静态": [["alice", "10.9.0.2"]]},
}, ensure_ascii=False)

V2 = json.dumps({
    "版本": 2,
    "会话": {"总数": 4, "每用户": 2, "空闲毫秒": 5000, "租期毫秒": 1000},
    "地址池": [
        {"标识": "b", "CIDR": "192.168.0.0/24",
         "保留": ["192.168.0.5", "192.168.0.3"],
         "静态": [["zoe", "192.168.0.8"], ["amy", "192.168.0.9"]]},
        {"标识": "a", "CIDR": "10.0.0.0/24", "保留": [], "静态": []},
    ],
}, ensure_ascii=False)

V3 = json.dumps({
    "版本": 3,
    "会话": {"总数": 4, "每用户": 2, "空闲毫秒": 5000, "租期毫秒": 1000},
    "地址池": [],
    "模板": [
        {"标识": "gold", "限速": 1000, "突发": 500, "配额": 10000, "超限": "拒绝"},
        {"标识": "basic", "限速": 100, "突发": 0, "配额": 1, "超限": "下线"},
    ],
    "用户模板": [["alice", "gold"]],
}, ensure_ascii=False)


class UpgradeConfigTest(unittest.TestCase):
    def test_envelope_shape_and_digest_v1(self):
        s = make()
        out = s.upgrade_config(V1)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())  # 基线紧凑
        doc = json.loads(out)
        self.assertEqual(
            list(doc), ["源版本", "目标版本", "改变", "摘要", "配置"]
        )
        self.assertEqual(doc["源版本"], 1)
        self.assertEqual(doc["目标版本"], 4)
        self.assertIs(doc["改变"], True)
        self.assertIsInstance(doc["摘要"], str)
        # 迁移：v1 单池改 default；模板/用户模板补空；容量补 1024、0。
        cfg = doc["配置"]
        self.assertEqual(cfg["版本"], 4)
        self.assertEqual(
            list(cfg), ["版本", "会话", "地址池", "模板", "用户模板", "容量"]
        )
        self.assertEqual(len(cfg["地址池"]), 1)
        self.assertEqual(cfg["地址池"][0]["标识"], "default")
        self.assertEqual(cfg["地址池"][0]["CIDR"], "10.9.0.0/24")
        self.assertEqual(cfg["模板"], [])
        self.assertEqual(cfg["用户模板"], [])
        self.assertEqual(cfg["容量"], {"队列上限": 1024, "最大等待毫秒": 0})
        # 摘要 = 配置紧凑编码（无 LF）UTF-8 字节的 sha256 小写值。
        config_text = canonical_config_bytes(out)
        expect = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
        self.assertEqual(doc["摘要"], expect)
        self.assertRegex(doc["摘要"], r"^[0-9a-f]{64}$")

    def test_migrations_v2_v3_and_sorting(self):
        s = make()
        d2 = json.loads(s.upgrade_config(V2))
        self.assertEqual(d2["源版本"], 2)
        self.assertIs(d2["改变"], True)
        self.assertEqual(d2["目标版本"], 4)
        # 池按标识升序、保留按 IP 升序、静态按用户升序（同 export v4）。
        pools = d2["配置"]["地址池"]
        self.assertEqual([p["标识"] for p in pools], ["a", "b"])
        self.assertEqual(pools[1]["保留"], ["192.168.0.3", "192.168.0.5"])
        self.assertEqual(
            pools[1]["静态"],
            [["amy", "192.168.0.9"], ["zoe", "192.168.0.8"]],
        )
        self.assertEqual(d2["配置"]["模板"], [])
        self.assertEqual(d2["配置"]["用户模板"], [])
        self.assertEqual(d2["配置"]["容量"], {"队列上限": 1024, "最大等待毫秒": 0})

        d3 = json.loads(s.upgrade_config(V3))
        self.assertEqual(d3["源版本"], 3)
        self.assertIs(d3["改变"], True)
        # 模板按标识升序。
        self.assertEqual(
            [t["标识"] for t in d3["配置"]["模板"]], ["basic", "gold"]
        )
        self.assertEqual(d3["配置"]["用户模板"], [["alice", "gold"]])
        self.assertEqual(d3["配置"]["容量"], {"队列上限": 1024, "最大等待毫秒": 0})

    def test_v4_only_canonicalizes_and_changed_false(self):
        s = make()
        s.add_pool("bpool", ("192.168.0.0/24", (), ()))
        v4 = s.export_config()
        out = s.upgrade_config(v4)
        doc = json.loads(out)
        self.assertEqual(doc["源版本"], 4)
        self.assertEqual(doc["目标版本"], 4)
        self.assertIs(doc["改变"], False)
        # v4 只规范化：配置部分与 export 逐字节一致。
        self.assertEqual(
            json.dumps(doc["配置"], ensure_ascii=False, separators=(",", ":")),
            v4.rstrip("\n"),
        )
        # target 显式传 4（位置与关键字）。
        self.assertEqual(s.upgrade_config(v4, 4), out)
        self.assertEqual(s.upgrade_config(v4, target=4), out)

    def test_type_errors(self):
        s = make()
        with self.assertRaises(TypeError):
            s.upgrade_config(123)
        with self.assertRaises(TypeError):
            s.upgrade_config(None)
        with self.assertRaises(TypeError):
            s.upgrade_config(V1, "4")
        with self.assertRaises(TypeError):
            s.upgrade_config(V1, 4.0)
        for bad_target in (True, False):
            with self.assertRaises(TypeError):
                s.upgrade_config(V1, bad_target)

    def test_target_must_be_4(self):
        s = make()
        for bad_target in (0, 1, 2, 3, 5, -1):
            with self.assertRaises(ValueError):
                s.upgrade_config(V1, bad_target)

    def test_value_errors(self):
        s = make()
        bad_texts = [
            "{not json",                       # JSON 解析错
            "[1, 2]",                          # 非对象
            '{"版本":2,"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}',  # 重键
            '{"版本":0,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}',  # 版本非法
            '{"版本":5,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}',
            '{"版本":true,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}',
            '{"版本":"4","会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}',
            # 缺失/未知键
            '{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1}}',
            '{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[],"多":1}',
            # v4 缺容量
            '{"版本":4,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
            '"地址池":[],"模板":[],"用户模板":[]}',
            # 池规则错
            '{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
            '"地址池":[{"标识":"p","CIDR":"10.0.0.1/24","保留":[],"静态":[]}]}',
            # 模板引用未知标识
            '{"版本":3,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
            '"地址池":[],"模板":[],"用户模板":[["alice","nosuch"]]}',
        ]
        for text in bad_texts:
            with self.assertRaises(ValueError, msg=text):
                s.upgrade_config(text)

    def test_upgrade_is_read_only(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before = s.export_config()
        # 合法升级
        s.upgrade_config(V1)
        s.upgrade_config(V2)
        s.upgrade_config(V3)
        s.upgrade_config(before)
        # 非法升级
        with self.assertRaises(ValueError):
            s.upgrade_config("{bad")
        with self.assertRaises(TypeError):
            s.upgrade_config(1)
        self.assertEqual(s.export_config(), before)
        # 会话、租约不受影响
        r = json.loads(s.do("k2", "续租", "s1", None, 1))
        self.assertEqual(r["地址"], "10.0.0.2")
        self.assertTrue(s.verify_audit())
        # 不产生回滚点
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_upgrade_does_not_check_authenticator_users(self):
        # 升级只读：用户模板用户不在认证器中不属升级的引用校验（加载才校验）。
        s = make()
        doc = json.loads(V3)
        doc["用户模板"] = [["carol", "gold"]]
        out = s.upgrade_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(json.loads(out)["配置"]["用户模板"], [["carol", "gold"]])


class LoadUpgradeEnvelopeTest(unittest.TestCase):
    def test_load_envelope_v1_migrates(self):
        s = make()
        before = s.export_config()
        envelope = s.upgrade_config(V1)
        out = s.load_config(envelope)
        cfg = json.loads(envelope)["配置"]
        expect = json.dumps(cfg, ensure_ascii=False, separators=(",", ":")) + "\n"
        self.assertEqual(out, expect)
        self.assertEqual(s.export_config(), expect)
        # 唯一回滚点指向加载前配置
        self.assertEqual(s.rollback_config(), before)

    def test_load_envelope_roundtrips_all_versions(self):
        s = make()
        for text in (V1, V2, V3, s.export_config()):
            envelope = s.upgrade_config(text)
            out = s.load_config(envelope)
            self.assertEqual(out, s.export_config())
            self.assertEqual(
                json.loads(out), json.loads(envelope)["配置"]
            )

    def test_tampered_envelope_value_error(self):
        s = make()
        raw = s.upgrade_config(V2)

        def reload(mutated):
            with self.assertRaises(ValueError, msg=mutated):
                s.load_config(mutated)

        # 摘要与配置不符
        doc = json.loads(raw)
        bad = json.loads(json.dumps(doc))
        bad["摘要"] = "0" * 64
        reload(json.dumps(bad, ensure_ascii=False))
        # 改变与源版本矛盾
        bad = json.loads(json.dumps(doc))
        bad["改变"] = False
        reload(json.dumps(bad, ensure_ascii=False))
        # 目标版本非 4
        bad = json.loads(json.dumps(doc))
        bad["目标版本"] = 3
        reload(json.dumps(bad, ensure_ascii=False))
        # 源版本越界
        bad = json.loads(json.dumps(doc))
        bad["源版本"] = 5
        reload(json.dumps(bad, ensure_ascii=False))
        # 摘要类型错
        bad = json.loads(json.dumps(doc))
        bad["摘要"] = 1
        reload(json.dumps(bad, ensure_ascii=False))
        # 改变类型错
        bad = json.loads(json.dumps(doc))
        bad["改变"] = 1
        reload(json.dumps(bad, ensure_ascii=False))
        # 缺键 / 多键
        bad = json.loads(json.dumps(doc))
        del bad["摘要"]
        reload(json.dumps(bad, ensure_ascii=False))
        bad = json.loads(json.dumps(doc))
        bad["多"] = 1
        reload(json.dumps(bad, ensure_ascii=False))
        # 键序错（内容不变）
        m = re.match(r'^\{"源版本":\d+,"目标版本":4,', raw)
        self.assertIsNotNone(m)
        head = m.group(0)
        new_head = '{"目标版本":4,"源版本":' + str(doc["源版本"]) + ","
        reload(new_head + raw[len(head):])
        # 配置非规范形态：键序错（顶层 版本/会话 对调须整体重排，改测容量键序）
        bad = json.loads(json.dumps(doc))
        bad["配置"]["容量"] = {
            "最大等待毫秒": bad["配置"]["容量"]["最大等待毫秒"],
            "队列上限": bad["配置"]["容量"]["队列上限"],
        }
        bad["摘要"] = hashlib.sha256(
            json.dumps(bad["配置"], ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        reload(json.dumps(bad, ensure_ascii=False))
        # 配置非规范形态：池未按标识升序（摘要按该字节算出也须拒）
        bad = json.loads(json.dumps(doc))
        bad["配置"]["地址池"] = list(reversed(bad["配置"]["地址池"]))
        bad["摘要"] = hashlib.sha256(
            json.dumps(bad["配置"], ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        reload(json.dumps(bad, ensure_ascii=False))
        # 配置版本非 4
        bad = json.loads(json.dumps(doc))
        bad["配置"]["版本"] = 3
        reload(json.dumps(bad, ensure_ascii=False))
        # 配置不是对象
        bad = json.loads(json.dumps(doc))
        bad["配置"] = []
        reload(json.dumps(bad, ensure_ascii=False))
        # 全部失败：状态不变
        self.assertEqual(json.loads(s.export_config())["会话"]["租期毫秒"], 1000)

    def test_envelope_reference_error(self):
        s = make()
        # 升级包自身合法（升级不查认证器），加载时引用校验抛 ValueError。
        doc = json.loads(s.upgrade_config(V3))
        doc["配置"]["用户模板"] = [["carol", "gold"]]
        # 须重算摘要才能越过摘要校验、到达引用校验
        doc["摘要"] = hashlib.sha256(
            json.dumps(doc["配置"], ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        before = s.export_config()
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(s.export_config(), before)

    def test_envelope_capacity_resource_error(self):
        s = make(pool=("10.0.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        doc = json.loads(s.export_config())
        # 构造 v2 源文本并把总数降到 1，先升级成包再加载：承载冲突 ResourceError。
        source = {
            "版本": 2,
            "会话": {"总数": 1, "每用户": 2, "空闲毫秒": 5000, "租期毫秒": 1000},
            "地址池": doc["地址池"],
        }
        envelope = s.upgrade_config(json.dumps(source, ensure_ascii=False))
        before = s.export_config()
        with self.assertRaises(ResourceError):
            s.load_config(envelope)
        # 任一失败保持全部实例状态
        self.assertEqual(s.export_config(), before)
        r = json.loads(s.do("k3", "续租", "s1", None, 1))
        self.assertEqual(r["地址"], "10.0.0.1")
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_direct_load_still_accepts_v1_to_v4(self):
        s = make()
        # 直载（既有行为）：v1 迁移
        out = json.loads(s.load_config(V1))
        self.assertEqual(out["版本"], 4)
        self.assertEqual(out["地址池"][0]["标识"], "default")
        # 直载 v2/v3 迁移
        self.assertEqual(json.loads(s.load_config(V2))["版本"], 4)
        self.assertEqual(json.loads(s.load_config(V3))["版本"], 4)
        # 直载 v4
        self.assertEqual(s.load_config(s.export_config()), s.export_config())

    def test_load_envelope_type_error_and_bad_json(self):
        s = make()
        with self.assertRaises(TypeError):
            s.load_config(123)
        with self.assertRaises(ValueError):
            s.load_config("{not json")


if __name__ == "__main__":
    unittest.main()
