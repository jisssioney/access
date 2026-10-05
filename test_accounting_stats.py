import hashlib
import json
import unittest

from access import Authenticator, Sessions


def make():
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob"):
        auth.add(user, "pw")
    s = Sessions(auth, 10, 5, 100000, lease_ms=100000)
    config = {
        "版本": 3,
        "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 100000, "租期毫秒": 100000},
        "地址池": [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
        ],
        "模板": [
            {"标识": "gold", "限速": 1000000, "突发": 0, "配额": 10000, "超限": "拒绝"},
        ],
        "用户模板": [["alice", "gold"], ["bob", "gold"]],
    }
    s.load_config(json.dumps(config, ensure_ascii=False))
    return s


def digest_of(doc_without_summary):
    blob = json.dumps(doc_without_summary, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AccountingStatsTest(unittest.TestCase):
    def test_validation(self):
        s = make()
        for bad in (True, 1, 1.5, None, b"alice"):
            with self.assertRaises(TypeError):
                s.accounting_stats(bad)
        for bad in ("", "a\0b", "x" * 257):
            with self.assertRaises(ValueError):
                s.accounting_stats(bad)
        with self.assertRaises(KeyError):
            s.accounting_stats("carol")
        # 任何失败不产生输出状态：注册用户空账结果不受影响。
        out = json.loads(s.accounting_stats("alice"))
        self.assertEqual(out["会话"], {"总数": 0, "活动": 0, "停止": 0})
        self.assertEqual(out["事件"], {"开始": 0, "中间": 0, "停止": 0})
        self.assertEqual(out["累计字节"], 0)
        self.assertEqual(out["最近时刻"], 0)

    def test_empty_chain_layout_and_digest(self):
        s = make()
        text = s.accounting_stats("alice")
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(
            list(json.loads(text)),
            ["版本", "用户", "会话", "事件", "累计字节", "最近时刻",
             "尾序号", "尾哈希", "摘要"],
        )
        doc = json.loads(text)
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["用户"], "alice")
        self.assertEqual(list(doc["会话"]), ["总数", "活动", "停止"])
        self.assertEqual(list(doc["事件"]), ["开始", "中间", "停止"])
        self.assertEqual(doc["尾序号"], 0)
        self.assertEqual(doc["尾哈希"], "0" * 64)
        body = {k: v for k, v in doc.items() if k != "摘要"}
        self.assertEqual(doc["摘要"], digest_of(body))

    def test_lifecycle_folding(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 1)
        s.accounting_interim("i1", "s1", 2)
        s.do("k2", "建立", "s2", ("bob", "pw"), 3)
        s.meter("m2", "s2", 700, 4)
        s.do("k3", "建立", "s3", ("alice", "pw"), 5)
        s.meter("m3", "s1", 50, 6)
        s.accounting_interim("i2", "s1", 7)   # 累计 150
        s.do("k4", "下线", "s1", None, 8)     # alice s1 停止，末条累计 150
        s.accounting_interim("i3", "s2", 9)   # bob 中间累计 700

        doc = json.loads(s.accounting_stats("alice"))
        # 会话：s1 停止、s3 活动（仅开始、累计 0）。
        self.assertEqual(doc["会话"], {"总数": 2, "活动": 1, "停止": 1})
        # s1：开始+中间2+停止；s3：开始。
        self.assertEqual(doc["事件"], {"开始": 2, "中间": 2, "停止": 1})
        # 只取每会话末条累计：s1 停止事件 150，s3 开始事件 0。
        self.assertEqual(doc["累计字节"], 150)
        self.assertEqual(doc["最近时刻"], 8)
        # 尾序号/尾哈希是全局链尾（含 bob 的事件），不是 alice 的末事件。
        chain = json.loads(s.accounting_events(0, 100))
        self.assertEqual(doc["尾序号"], chain["尾序号"])
        self.assertEqual(doc["尾哈希"], chain["尾哈希"])
        self.assertEqual(doc["尾序号"], 7)
        self.assertEqual(doc["摘要"], digest_of(
            {k: v for k, v in doc.items() if k != "摘要"}))

        doc = json.loads(s.accounting_stats("bob"))
        self.assertEqual(doc["会话"], {"总数": 1, "活动": 1, "停止": 0})
        self.assertEqual(doc["事件"], {"开始": 1, "中间": 1, "停止": 0})
        self.assertEqual(doc["累计字节"], 700)
        self.assertEqual(doc["最近时刻"], 9)
        self.assertEqual(doc["尾序号"], 7)

    def test_deterministic_and_readonly(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 1)
        s.accounting_interim("i1", "s1", 2)
        before = {
            "events": s.accounting_events(0, 100),
            "user_stats": s.user_stats("alice", 0),
            "meter_stats": s.meter_stats(0),
        }
        first = s.accounting_stats("alice")
        second = s.accounting_stats("alice")
        self.assertEqual(first, second)
        self.assertEqual(s.accounting_events(0, 100), before["events"])
        self.assertEqual(s.user_stats("alice", 0), before["user_stats"])
        self.assertEqual(s.meter_stats(0), before["meter_stats"])

    def test_non_clock_driven(self):
        # 查询不接收时钟：同一状态无论何时调用，最近时刻只取链上事件时刻。
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 42)
        self.assertEqual(
            json.loads(s.accounting_stats("alice"))["最近时刻"], 42
        )
        self.assertEqual(
            json.loads(s.accounting_stats("alice"))["最近时刻"], 42
        )


if __name__ == "__main__":
    unittest.main()
