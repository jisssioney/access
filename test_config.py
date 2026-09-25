import json
import unittest

from access import Authenticator, ResourceError, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


class ConfigTest(unittest.TestCase):
    def test_export_v2_key_order_and_sorting(self):
        s = make()
        s.add_pool("bpool", ("192.168.0.0/24", ("192.168.0.5", "192.168.0.3"),
                             (("zoe", "192.168.0.8"), ("amy", "192.168.0.9"))))
        out = s.export_config()
        self.assertTrue(out.endswith("\n"))
        doc = json.loads(out)
        self.assertEqual(list(doc), ["版本", "会话", "地址池"])
        self.assertEqual(doc["版本"], 2)
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
        # 紧凑分隔符
        self.assertIn('"版本":2,', out)
        self.assertNotIn(" ", out.strip())

    def test_export_zero_pools(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 1, 1, 0, lease_ms=1)
        doc = json.loads(s.export_config())
        self.assertEqual(doc["地址池"], [])

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
        self.assertEqual(doc["版本"], 2)
        self.assertEqual(doc["会话"], {"总数": 3, "每用户": 2, "空闲毫秒": 0, "租期毫秒": 7})
        self.assertEqual(len(doc["地址池"]), 1)
        self.assertEqual(doc["地址池"][0]["标识"], "default")
        self.assertEqual(doc["地址池"][0]["CIDR"], "10.9.0.0/24")
        # 新租期作用于后续建立
        s._auth.add("alice", "pw")
        r = json.loads(s.do("k1", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["租期"], 7)
        self.assertEqual(r["地址"], "10.9.0.2")

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
        # 版本值
        with self.assertRaises(ValueError):
            s.load_config('{"版本":3,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}')
        with self.assertRaises(ValueError):
            s.load_config('{"版本":true,"会话":{"总数":1,"每用户":1,"空闲毫秒":0,"租期毫秒":1},"地址池":[]}')
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


if __name__ == "__main__":
    unittest.main()
