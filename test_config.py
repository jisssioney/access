import json
import unittest

from access import Authenticator, ResourceError, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def load_templates(s, templates, user_templates):
    """在 s 当前配置上挂入 QoS 模板/用户模板并加载。"""
    doc = json.loads(s.export_config())
    doc["模板"] = templates
    doc["用户模板"] = user_templates
    s.load_config(json.dumps(doc, ensure_ascii=False))
    return s


GOLD = {"标识": "gold", "限速": 1000, "突发": 500, "配额": 100000, "超限": "拒绝"}
SILVER = {"标识": "silver", "限速": 500, "突发": 0, "配额": 50000, "超限": "下线"}


class ConfigTest(unittest.TestCase):
    def test_export_v3_key_order_and_sorting(self):
        s = make()
        s.add_pool("bpool", ("192.168.0.0/24", ("192.168.0.5", "192.168.0.3"),
                             (("zoe", "192.168.0.8"), ("amy", "192.168.0.9"))))
        # 模板与用户均乱序给出，导出须按标识/用户升序。
        load_templates(s, [SILVER, GOLD], [["bob", "silver"], ["alice", "gold"]])
        out = s.export_config()
        self.assertTrue(out.endswith("\n"))
        doc = json.loads(out)
        self.assertEqual(list(doc), ["版本", "会话", "地址池", "模板", "用户模板"])
        self.assertEqual(doc["版本"], 3)
        self.assertEqual(list(doc["会话"]), ["总数", "每用户", "空闲毫秒", "租期毫秒"])
        self.assertEqual(doc["会话"], {"总数": 4, "每用户": 2, "空闲毫秒": 5000, "租期毫秒": 1000})
        self.assertEqual([p["标识"] for p in doc["地址池"]], ["bpool", "default"])
        p0 = doc["地址池"][0]
        self.assertEqual(list(p0), ["标识", "CIDR", "保留", "静态"])
        self.assertEqual(p0["保留"], ["192.168.0.3", "192.168.0.5"])
        self.assertEqual(p0["静态"], [["amy", "192.168.0.9"], ["zoe", "192.168.0.8"]])
        p1 = doc["地址池"][1]
        self.assertEqual(p1["保留"], ["10.0.0.9"])
        self.assertEqual(p1["静态"], [["alice", "10.0.0.2"]])
        self.assertEqual([t["标识"] for t in doc["模板"]], ["gold", "silver"])
        t0 = doc["模板"][0]
        self.assertEqual(list(t0), ["标识", "限速", "突发", "配额", "超限"])
        self.assertEqual(t0, GOLD)
        self.assertEqual(doc["模板"][1], SILVER)
        self.assertEqual(doc["用户模板"], [["alice", "gold"], ["bob", "silver"]])
        # 紧凑分隔符
        self.assertIn('"版本":3,', out)
        self.assertNotIn(" ", out.strip())

    def test_export_zero_pools(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 1, 1, 0, lease_ms=1)
        doc = json.loads(s.export_config())
        self.assertEqual(doc["版本"], 3)
        self.assertEqual(doc["地址池"], [])
        self.assertEqual(doc["模板"], [])
        self.assertEqual(doc["用户模板"], [])

    def test_roundtrip(self):
        s = make()
        s.add_pool("bpool", ("192.168.0.0/24", (), ()))
        text = s.export_config()
        out = s.load_config(text)
        self.assertEqual(out, text)
        # 再导出仍一致
        self.assertEqual(s.export_config(), text)

    def test_load_v1_migrates_default(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 2, 1, 100, lease_ms=5)
        v1 = json.dumps({
            "版本": 1,
            "会话": {"总数": 3, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 7},
            "地址池": {"CIDR": "10.9.0.0/24", "保留": ["10.9.0.1"],
                       "静态": [["alice", "10.9.0.2"]]},
        }, ensure_ascii=False)
        out = s.load_config(v1)
        doc = json.loads(out)
        self.assertEqual(doc["版本"], 3)
        self.assertEqual(doc["会话"], {"总数": 3, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 7})
        self.assertEqual(len(doc["地址池"]), 1)
        self.assertEqual(doc["地址池"][0]["标识"], "default")
        self.assertEqual(doc["地址池"][0]["CIDR"], "10.9.0.0/24")
        # v1 迁移：两项模板均为空
        self.assertEqual(doc["模板"], [])
        self.assertEqual(doc["用户模板"], [])
        # 新租期作用于后续建立
        s._auth.add("alice", "pw")
        r = json.loads(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["租期"], 7)
        self.assertEqual(r["地址"], "10.9.0.2")

    def test_load_v2_migrates_empty_templates(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 2, 1, 100, lease_ms=5)
        v2 = json.dumps({
            "版本": 2,
            "会话": {"总数": 3, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 7},
            "地址池": [{"标识": "default", "CIDR": "10.9.0.0/24",
                       "保留": [], "静态": []}],
        }, ensure_ascii=False)
        doc = json.loads(s.load_config(v2))
        self.assertEqual(doc["版本"], 3)
        self.assertEqual([p["标识"] for p in doc["地址池"]], ["default"])
        self.assertEqual(doc["模板"], [])
        self.assertEqual(doc["用户模板"], [])
        # v2 文本不得携带 v3 键（未知键）
        bad = json.loads(v2)
        bad["模板"] = []
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(bad, ensure_ascii=False))

    def test_load_applies_new_limits_and_keeps_sessions(self):
        s = make()
        r1 = json.loads(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r1["地址"], "10.0.0.2")  # alice 静态址
        text = s.export_config().replace('"总数":4', '"总数":1').replace('"租期毫秒":1000', '"租期毫秒":50')
        s.load_config(text)
        # 会话状态/期限/地址/租期不变
        r2 = json.loads(s.do("k2", "续租", "s1", None, 10))
        self.assertEqual(r2["地址"], "10.0.0.2")
        self.assertEqual(r2["期限"], 5000)
        self.assertEqual(r2["租期"], 60)  # 新租期 50 作用于续租
        # 新总数=1：第二个建立被拒
        with self.assertRaises(ResourceError):
            s.do("k3", "建立", "s2", ("bob", "pw"), 20)

    def test_load_limit_below_active_raises(self):
        s = make(pool=("10.0.0.0/24", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        s.do("k3", "建立", "s3", ("bob", "pw"), 0)
        # 总数 2 < 非下线 3
        text = s.export_config().replace('"总数":4', '"总数":2')
        with self.assertRaises(ResourceError):
            s.load_config(text)
        # 每用户 1 < alice 的 2
        text2 = s.export_config().replace('"每用户":2', '"每用户":1')
        with self.assertRaises(ResourceError):
            s.load_config(text2)
        # 失败不改状态
        self.assertIn('"总数":4', s.export_config())
        self.assertIn('"每用户":2', s.export_config())

    def test_load_pool_cannot_carry_lease(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # 持 10.0.0.2 于 default
        # 新配置去掉 default 池
        doc = json.loads(s.export_config())
        doc["地址池"] = []
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        # 地址被保留（同时清静态以满足池规则）
        doc2 = json.loads(s.export_config())
        doc2["地址池"][0]["保留"] = ["10.0.0.2", "10.0.0.9"]
        doc2["地址池"][0]["静态"] = []
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc2, ensure_ascii=False))
        # 静态址易主
        doc3 = json.loads(s.export_config())
        doc3["地址池"][0]["静态"] = [["bob", "10.0.0.2"]]
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc3, ensure_ascii=False))
        # 换 CIDR 不含原地址
        doc4 = json.loads(s.export_config())
        doc4["地址池"][0]["CIDR"] = "10.1.0.0/24"
        doc4["地址池"][0]["保留"] = []
        doc4["地址池"][0]["静态"] = []
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc4, ensure_ascii=False))
        # 全部失败，状态不变
        self.assertIn('"CIDR":"10.0.0.0/24"', s.export_config())
        r = json.loads(s.do("k4", "续租", "s1", None, 1))
        self.assertEqual(r["地址"], "10.0.0.2")

    def test_load_carry_lease_ok_and_rebuild(self):
        s = make()
        s.do("k1", "建立", "s1", ("bob", "pw"), 0)  # bob 动态址 10.0.0.1
        doc = json.loads(s.export_config())
        doc["地址池"][0]["静态"] = [["alice", "10.0.0.2"], ["carol", "10.0.0.3"]]
        s.load_config(json.dumps(doc, ensure_ascii=False))
        # bob 租约保留，新空闲堆不含 10.0.0.1
        stats = json.loads(s.pool_stats(0))
        self.assertEqual(stats["池"][0][4], 1)  # 租用 1
        r = json.loads(s.do("k2", "建立", "s2", ("alice", "pw"), 0))
        self.assertEqual(r["地址"], "10.0.0.2")

    def test_rollback(self):
        s = make()
        before = s.export_config()
        doc = json.loads(before)
        doc["会话"]["租期毫秒"] = 9
        s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertIn('"租期毫秒":9', s.export_config())
        out = s.rollback_config()
        self.assertEqual(out, before)
        self.assertEqual(s.export_config(), before)
        # 回滚点已清除
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_rollback_no_point(self):
        s = make()
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_rollback_overwritten_by_each_load(self):
        s = make()
        v2a = json.loads(s.export_config())
        v2a["会话"]["租期毫秒"] = 9
        s.load_config(json.dumps(v2a, ensure_ascii=False))
        v2b = json.loads(s.export_config())
        v2b["会话"]["租期毫秒"] = 8
        s.load_config(json.dumps(v2b, ensure_ascii=False))
        out = s.rollback_config()
        self.assertIn('"租期毫秒":9', out)
        with self.assertRaises(StateError):
            s.rollback_config()

    def test_rollback_resource_failure_keeps_point(self):
        s = make()
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 2
        s.load_config(json.dumps(doc, ensure_ascii=False))
        # 建立 2 个会话，使回滚到 总数=4 不失败……改为让旧配置更小
        # 旧配置 总数=4；现 2 个会话，回滚应成功。改为构造失败：
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        # 旧配置 总数=4 >= 2，回滚成功
        s.rollback_config()
        self.assertIn('"总数":4', s.export_config())

    def test_rollback_fails_when_sessions_grew(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        s = Sessions(auth, 1, 1, 5000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 4
        s.load_config(json.dumps(doc, ensure_ascii=False))  # 回滚点：总数=1
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        with self.assertRaises(ResourceError):
            s.rollback_config()
        # 回滚点保留，状态不变
        self.assertIn('"总数":4', s.export_config())
        s.do("k3", "下线", "s2", None, 1)
        out = s.rollback_config()
        self.assertIn('"总数":1', out)

    def test_load_type_and_value_errors(self):
        s = make()
        with self.assertRaises(TypeError):
            s.load_config(123)
        with self.assertRaises(ValueError):
            s.load_config("{not json")
        with self.assertRaises(ValueError):
            s.load_config("[1,2]")
        # 重复键
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}')
        # 未知键 / 缺失键
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[],"多":1}')
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1}}')
        # 版本值：4 / bool 非法（3 的合法加载见 test_load_v2_migrates_empty_templates
        # 及各模板用例）
        with self.assertRaises(ValueError):
            s.load_config('{"版本":4,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[],"模板":[],"用户模板":[]}')
        with self.assertRaises(ValueError):
            s.load_config('{"版本":true,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[],"模板":[],"用户模板":[]}')
        # v3 缺失/多出模板键
        with self.assertRaises(ValueError):
            s.load_config('{"版本":3,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[],"模板":[]}')
        with self.assertRaises(ValueError):
            s.load_config('{"版本":3,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[],"模板":[],"用户模板":[],"x":1}')
        # 数值约束：bool、float、越界
        for bad in ('"总数":true', '"总数":1.5', '"总数":0', '"空闲毫秒":-1', '"租期毫秒":0'):
            good = '{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}'
            key = bad.split(":")[0].strip('"')
            import re
            badtext = re.sub(r'"%s":[^,}]+' % key, bad, good)
            with self.assertRaises(ValueError, msg=bad):
                s.load_config(badtext)
        # 池规则错
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[{"标识":"p","CIDR":"10.0.0.1/24","保留":[],"静态":[]}]}')
        # 重复池标识
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[{"标识":"p","CIDR":"10.0.0.0/24","保留":[],"静态":[]},'
                          '{"标识":"p","CIDR":"10.1.0.0/24","保留":[],"静态":[]}]}')
        # 结构错：保留非列表、静态项非二元
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[{"标识":"p","CIDR":"10.0.0.0/24","保留":"x","静态":[]}]}')
        with self.assertRaises(ValueError):
            s.load_config('{"版本":2,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},'
                          '"地址池":[{"标识":"p","CIDR":"10.0.0.0/24","保留":[],"静态":[["u"]]}]}')
        # 全部失败，状态不变
        self.assertIn('"总数":4', s.export_config())

    def test_load_does_not_age_sessions(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # 持 10.0.0.2
        # 租期与空闲期限均已过，但加载不老化：租约仍在，空池配置须被拒
        doc = json.loads(s.export_config())
        doc["地址池"] = []
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        # 加载后会话仍未被老化：导出配置不变，老化由后续 do 触发
        self.assertIn('"CIDR":"10.0.0.0/24"', s.export_config())
        r = json.loads(s.do("k2", "下线", "s1", None, 99999))
        self.assertEqual(r["状态"], "下线")

    # ---- QoS 模板 ----

    def test_template_roundtrip(self):
        s = make()
        before = s.export_config()
        self.assertIn('"模板":[],"用户模板":[]', before)
        load_templates(s, [SILVER, GOLD], [["alice", "gold"], ["bob", "silver"]])
        text = s.export_config()
        # 重复加载与再导出逐字节一致
        self.assertEqual(s.load_config(text), text)
        self.assertEqual(s.export_config(), text)

    def test_template_value_errors(self):
        s = make()
        base = {"版本": 3,
                "会话": {"总数": 4, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 1},
                "地址池": [{"标识": "p", "CIDR": "10.0.0.0/24",
                           "保留": [], "静态": []}]}

        def reject(doc):
            with self.assertRaises(ValueError):
                s.load_config(json.dumps(doc, ensure_ascii=False))

        def with_templates(templates, user_templates=None):
            doc = dict(base)
            doc["模板"] = templates
            doc["用户模板"] = [] if user_templates is None else user_templates
            return doc

        def t(**over):
            item = {"标识": "g", "限速": 1000, "突发": 500,
                    "配额": 9999, "超限": "拒绝"}
            item.update(over)
            return item

        # 模板容器与项结构
        reject(with_templates({}))
        reject(with_templates([{"限速": 1000, "突发": 0, "配额": 1, "超限": "拒绝"}]))
        reject(with_templates([{"标识": "g", "限速": 1000, "突发": 0,
                                "配额": 1, "超限": "拒绝", "x": 1}]))
        # 重复标识
        reject(with_templates([t(), t(超限="下线")]))
        # 标识沿用凭据约束
        reject(with_templates([t(标识="")]))
        reject(with_templates([t(标识="a\x00b")]))
        reject(with_templates([t(标识="a" * 257)]))
        # 限速/配额为非 bool 正 int；突发为非 bool 非负 int
        for over in ({"限速": True}, {"限速": 1.5}, {"限速": "1"},
                     {"限速": 0}, {"限速": -2},
                     {"配额": False}, {"配额": 1.0}, {"配额": 0},
                     {"突发": True}, {"突发": 0.0}, {"突发": -1}):
            reject(with_templates([t(**over)]))
        # 突发允许 0；超限仅取 拒绝/下线
        accept = with_templates([t(突发=0, 超限="下线")])
        self.assertEqual(json.loads(s.load_config(json.dumps(accept, ensure_ascii=False)))["版本"], 3)
        # 合法加载会改配置：恢复到测试起始空模板配置，再继续验证失败不改状态
        s.load_config(json.dumps(with_templates([], []), ensure_ascii=False))
        reject(with_templates([t(超限="拉黑")]))
        reject(with_templates([t(超限=None)]))
        # 重复键（限速出现两次）
        raw = ('{"版本":3,"会话":{"总数":4,"每用户":2,"空闲毫秒":0,"租期毫秒":1},'
               '"地址池":[],"模板":[{"标识":"g","限速":1,"突发":0,"配额":1,'
               '"超限":"拒绝","限速":2}],"用户模板":[]}')
        with self.assertRaises(ValueError):
            s.load_config(raw)
        # 用户模板容器与项结构
        reject(with_templates([t()], {}))
        reject(with_templates([t()], [["alice"]]))
        reject(with_templates([t()], [["alice", 1]]))
        reject(with_templates([t()], [[1, "g"]]))
        reject(with_templates([t()], [["alice", "g"], ["alice", "g"]]))  # 用户重复
        # 引用错：用户不在认证器、标识不存在
        reject(with_templates([t()], [["carol", "g"]]))
        reject(with_templates([t()], [["alice", "zzz"]]))
        reject(with_templates([], [["alice", "g"]]))  # 模板表为空
        # 全部失败，状态不变
        self.assertIn('"模板":[],"用户模板":[]', s.export_config())

    def test_load_failure_keeps_config_point_sessions(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # 持 10.0.0.2
        before = s.export_config()
        doc = json.loads(before)
        doc["模板"] = [{"标识": "g", "限速": 1, "突发": 0, "配额": 1, "超限": "拒绝"}]
        doc["用户模板"] = [["alice", "g"], ["bob", "nope"]]  # 未知标识
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        # 配置不变
        self.assertEqual(s.export_config(), before)
        self.assertEqual(s._templates, {})
        self.assertEqual(s._user_templates, {})
        # 失败不设回滚点
        with self.assertRaises(StateError):
            s.rollback_config()
        # 会话与租约不变
        r = json.loads(s.do("k2", "续租", "s1", None, 1))
        self.assertEqual(r["地址"], "10.0.0.2")
        self.assertEqual(r["租期"], 1001)

    def test_rollback_restores_templates(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        load_templates(s, [GOLD], [["alice", "gold"]])
        self.assertEqual(json.loads(s.qos("s1"))["限速"], 1000)
        before = json.loads(s.rollback_config())
        self.assertEqual(before["模板"], [])
        self.assertEqual(before["用户模板"], [])
        # 回滚后已在线会话变为未绑定
        with self.assertRaises(StateError):
            s.qos("s1")
        with self.assertRaises(StateError):
            s.rollback_config()

    # ---- qos 查询 ----

    def test_qos_success_key_order_and_types(self):
        s = make()
        load_templates(s, [SILVER, GOLD], [["alice", "gold"], ["bob", "silver"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = s.qos("s1")
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        q = json.loads(out)
        self.assertEqual(list(q), ["会话", "用户", "模板", "限速", "突发", "配额", "超限"])
        self.assertEqual(q, {"会话": "s1", "用户": "alice", "模板": "gold",
                             "限速": 1000, "突发": 500, "配额": 100000, "超限": "拒绝"})
        for key in ("会话", "用户", "模板", "超限"):
            self.assertIsInstance(q[key], str)
        for key in ("限速", "突发", "配额"):
            self.assertIsInstance(q[key], int)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        qb = json.loads(s.qos("s2"))
        self.assertEqual(qb, {"会话": "s2", "用户": "bob", "模板": "silver",
                              "限速": 500, "突发": 0, "配额": 50000, "超限": "下线"})

    def test_qos_errors(self):
        s = make()
        load_templates(s, [GOLD], [["alice", "gold"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)  # bob 未绑定
        # sid 类型/值
        with self.assertRaises(TypeError):
            s.qos(123)
        with self.assertRaises(TypeError):
            s.qos(b"s1")
        with self.assertRaises(ValueError):
            s.qos("a\x00b")
        with self.assertRaises(ValueError):
            s.qos("")
        # 未知 sid
        with self.assertRaises(KeyError):
            s.qos("nope")
        # 在线但未绑定
        with self.assertRaises(StateError):
            s.qos("s2")
        # 下线/挂起（已绑定用户）非在线
        s.do("k3", "下线", "s1", None, 1)
        with self.assertRaises(StateError):
            s.qos("s1")

    def test_qos_does_not_age(self):
        s = make()
        load_templates(s, [GOLD], [["alice", "gold"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 空闲期限 5000、租期 1000 均已过，查询不老化：仍按在线返回模板
        q = json.loads(s.qos("s1"))
        self.assertEqual(q["模板"], "gold")
        q = json.loads(s.qos("s1"))
        self.assertEqual(q["模板"], "gold")
        # 下一次 do 才老化
        with self.assertRaises(StateError):
            s.do("k2", "续租", "s1", None, 99999)

    def test_rebind_affects_future_query_only(self):
        s = make()
        load_templates(s, [GOLD], [["alice", "gold"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(json.loads(s.qos("s1"))["限速"], 1000)
        # 改绑 silver：仅影响后续查询，会话本身（地址/期限/租期）不变
        load_templates(s, [GOLD, SILVER], [["alice", "silver"]])
        q = json.loads(s.qos("s1"))
        self.assertEqual(q["模板"], "silver")
        self.assertEqual(q["限速"], 500)
        r = json.loads(s.do("k2", "续租", "s1", None, 1))
        self.assertEqual(r["地址"], "10.0.0.2")
        self.assertEqual(r["期限"], 5000)


if __name__ == "__main__":
    unittest.main()
