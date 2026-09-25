import json
import unittest

from access import Authenticator, Sessions, StateError


def make():
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob", "carol"):
        auth.add(user, "pw")
    s = Sessions(auth, 10, 5, 100000, lease_ms=100000)
    config = {
        "版本": 3,
        "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 100000, "租期毫秒": 100000},
        "地址池": [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
        ],
        "模板": [
            {"标识": "gold", "限速": 1000000, "突发": 0, "配额": 1000, "超限": "拒绝"},
            {"标识": "kill", "限速": 1000000, "突发": 0, "配额": 10, "超限": "下线"},
        ],
        "用户模板": [["alice", "gold"], ["bob", "kill"]],
    }
    s.load_config(json.dumps(config, ensure_ascii=False))
    return s


class MeterStatsTest(unittest.TestCase):
    def test_param_validation(self):
        s = make()
        for bad in (True, 1.5, "0", None):
            with self.assertRaises(TypeError):
                s.meter_stats(bad)
        with self.assertRaises(ValueError):
            s.meter_stats(-1)
        for bad in (1, True, None, b"x"):
            with self.assertRaises(TypeError):
                s.meter_stats(0, bad)
        with self.assertRaises(ValueError):
            s.meter_stats(0, "会话")
        # 验参失败不老化：先建会话再让非法调用越过空闲期限
        s.do("k0", "建立", "s0", ("carol", "pw"), 0)
        with self.assertRaises(ValueError):
            s.meter_stats(200000, "bad")
        out = json.loads(s.meter_stats(0))
        self.assertEqual(out["汇总"], [{"标识": "carol", "在线": 1, "通过": 0,
                                       "拒绝": 0, "下线": 0, "通过字节": 0}])

    def test_empty(self):
        s = make()
        self.assertEqual(s.meter_stats(0), '{"时刻":0,"分组":"用户","汇总":[]}\n')
        self.assertEqual(s.meter_stats(5, "模板"),
                         '{"时刻":5,"分组":"模板","汇总":[]}\n')

    def test_online_grouping_and_key_order(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        s.do("k3", "建立", "s3", ("carol", "pw"), 0)  # 未绑定模板
        out = s.meter_stats(10)
        self.assertTrue(out.endswith("\n"))
        doc = json.loads(out)
        self.assertEqual(list(doc), ["时刻", "分组", "汇总"])
        self.assertEqual(doc["时刻"], 10)
        self.assertEqual(doc["分组"], "用户")
        self.assertEqual([list(item) for item in doc["汇总"]],
                         [["标识", "在线", "通过", "拒绝", "下线", "通过字节"]] * 2)
        self.assertEqual(doc["汇总"], [
            {"标识": "alice", "在线": 2, "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0},
            {"标识": "carol", "在线": 1, "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0},
        ])
        doc = json.loads(s.meter_stats(10, "模板"))
        self.assertEqual(doc["汇总"], [
            {"标识": "", "在线": 1, "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0},
            {"标识": "gold", "在线": 2, "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0},
        ])

    def test_aging_excludes_suspended(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 2, 100, pool=("10.0.0.0/24", (), ()), lease_ms=50)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        doc = json.loads(s.meter_stats(100))  # 同刻到期挂起
        self.assertEqual(doc["汇总"], [])

    def test_meter_events_recorded_once(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.meter("m1", "s1", 100, 0)   # 通过
        s.meter("m2", "s1", 50, 1)    # 通过
        s.meter("m3", "s2", 11, 2)    # 超配额 -> 下线（kill 模板）
        # 同参重放不重复计数
        self.assertEqual(s.meter("m1", "s1", 100, 0),
                         '{"会话":"s1","时刻":0,"字节":100,"结果":"通过","累计":100}\n')
        # 异参 key 复用不记
        with self.assertRaises(ValueError):
            s.meter("m1", "s1", 101, 0)
        # 异常不记（未知 sid）
        with self.assertRaises(KeyError):
            s.meter("m4", "nope", 1, 3)
        # 下线后会话已离线、地址已释放
        with self.assertRaises(StateError):
            s.meter("m5", "s2", 1, 4)
        doc = json.loads(s.meter_stats(10))
        self.assertEqual(doc["汇总"], [
            {"标识": "alice", "在线": 1, "通过": 2, "拒绝": 0, "下线": 0,
             "通过字节": 150},
            {"标识": "bob", "在线": 0, "通过": 0, "拒绝": 0, "下线": 1,
             "通过字节": 0},
        ])
        doc = json.loads(s.meter_stats(10, "模板"))
        self.assertEqual(doc["汇总"], [
            {"标识": "gold", "在线": 1, "通过": 2, "拒绝": 0, "下线": 0,
             "通过字节": 150},
            {"标识": "kill", "在线": 0, "通过": 0, "拒绝": 0, "下线": 1,
             "通过字节": 0},
        ])

    def test_deny_counts_without_bytes(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 900, 0)   # 通过，配额余 100
        s.meter("m2", "s1", 200, 1)   # 超配额 -> 拒绝（gold 模板）
        doc = json.loads(s.meter_stats(2))
        self.assertEqual(doc["汇总"], [
            {"标识": "alice", "在线": 1, "通过": 1, "拒绝": 1, "下线": 0,
             "通过字节": 900},
        ])

    def test_config_reload_does_not_migrate_counts(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        # 热加载：alice 改绑 kill，gold 删除
        config = json.loads(s.export_config())
        config["模板"] = [
            {"标识": "kill", "限速": 1000000, "突发": 0, "配额": 10, "超限": "下线"}
        ]
        config["用户模板"] = [["alice", "kill"]]
        s.load_config(json.dumps(config, ensure_ascii=False))
        doc = json.loads(s.meter_stats(1, "模板"))
        # 历史计数留在 gold，在线按新绑定归 kill
        self.assertEqual(doc["汇总"], [
            {"标识": "gold", "在线": 0, "通过": 1, "拒绝": 0, "下线": 0,
             "通过字节": 100},
            {"标识": "kill", "在线": 1, "通过": 0, "拒绝": 0, "下线": 0,
             "通过字节": 0},
        ])
        # 回滚亦不迁移；kill 无历史计数且回滚后无在线会话绑定，不再出现
        s.rollback_config()
        doc = json.loads(s.meter_stats(2, "模板"))
        self.assertEqual(doc["汇总"], [
            {"标识": "gold", "在线": 1, "通过": 1, "拒绝": 0, "下线": 0,
             "通过字节": 100},
        ])

    def test_sorted_by_codepoint(self):
        s = make()
        s.do("k1", "建立", "s1", ("carol", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        doc = json.loads(s.meter_stats(0))
        self.assertEqual([i["标识"] for i in doc["汇总"]], ["alice", "bob", "carol"])


if __name__ == "__main__":
    unittest.main()
