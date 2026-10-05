import hashlib
import json
import unittest

from access import Authenticator, Sessions


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


def parse(out):
    return json.loads(out)


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def fold(events):
    """从全量计费事件折叠出 accounting_stats 口径的期望结果。"""
    last = {}
    counts = {"开始": 0, "中间": 0, "停止": 0}
    latest = 0
    for event in events:
        last[event["会话"]] = (event["类型"], event["累计字节"])
        counts[event["类型"]] += 1
        latest = max(latest, event["时刻"])
    stopped = sum(1 for kind, _total in last.values() if kind == "停止")
    return {
        "会话": {"总数": len(last), "活动": len(last) - stopped, "停止": stopped},
        "事件": counts,
        "累计字节": sum(total for _kind, total in last.values()),
        "最近时刻": latest,
    }


TOP_KEYS = ["版本", "用户", "会话", "事件", "累计字节", "最近时刻",
            "尾序号", "尾哈希", "摘要"]


class AccountingStatsTest(unittest.TestCase):
    def test_empty_user_zeroes_and_global_empty_tail(self):
        s = make()
        out = s.accounting_stats("carol")
        self.assertTrue(out.endswith("\n"))
        doc = parse(out)
        self.assertEqual(list(doc), TOP_KEYS)
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["用户"], "carol")
        self.assertEqual(doc["会话"], {"总数": 0, "活动": 0, "停止": 0})
        self.assertEqual(list(doc["会话"]), ["总数", "活动", "停止"])
        self.assertEqual(doc["事件"], {"开始": 0, "中间": 0, "停止": 0})
        self.assertEqual(list(doc["事件"]), ["开始", "中间", "停止"])
        self.assertEqual(doc["累计字节"], 0)
        self.assertEqual(doc["最近时刻"], 0)
        self.assertEqual(doc["尾序号"], 0)
        self.assertEqual(doc["尾哈希"], "0" * 64)
        head = {key: doc[key] for key in TOP_KEYS[:-1]}
        self.assertEqual(
            doc["摘要"], hashlib.sha256(compact(head).encode("utf-8")).hexdigest()
        )

    def test_full_stop_lifecycle(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 1)
        s.accounting_interim("i1", "s1", 2)
        s.meter("m2", "s1", 50, 3)
        s.do("k2", "下线", "s1", None, 4)
        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["会话"], {"总数": 1, "活动": 0, "停止": 1})
        self.assertEqual(doc["事件"], {"开始": 1, "中间": 1, "停止": 1})
        self.assertEqual(doc["累计字节"], 150)
        self.assertEqual(doc["最近时刻"], 4)
        # 链上恰为开始/中间/停止三条。
        self.assertEqual(doc["尾序号"], 3)
        self.assertEqual(
            doc["尾哈希"], parse(s.accounting_events(0, 1000))["尾哈希"]
        )

    def test_active_session_only_last_total_sums(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 1)
        s.accounting_interim("i1", "s1", 2)   # 中间累计 100
        s.meter("m2", "s1", 50, 3)
        s.accounting_interim("i2", "s1", 4)   # 中间累计 150
        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["会话"], {"总数": 1, "活动": 1, "停止": 0})
        self.assertEqual(doc["事件"], {"开始": 1, "中间": 2, "停止": 0})
        # 不得把 0/100/150 重复相加。
        self.assertEqual(doc["累计字节"], 150)
        self.assertEqual(doc["最近时刻"], 4)
        self.assertEqual(doc["尾序号"], 3)

    def test_quota_stop_total_zero(self):
        s = make()
        s.do("k1", "建立", "sb", ("bob", "pw"), 0)
        # kill 模板配额 10：11 字节超限即下线，该笔不累计。
        s.meter("m1", "sb", 11, 2)
        doc = parse(s.accounting_stats("bob"))
        self.assertEqual(doc["会话"], {"总数": 1, "活动": 0, "停止": 1})
        self.assertEqual(doc["事件"], {"开始": 1, "中间": 0, "停止": 1})
        self.assertEqual(doc["累计字节"], 0)
        self.assertEqual(doc["最近时刻"], 2)
        self.assertEqual(doc["尾序号"], 2)

    def test_takeover_counts_old_stop_and_new_start(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 60, 1)
        s.do("k2", "接管", "s2", ("s1", "pw"), 5)
        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["会话"], {"总数": 2, "活动": 1, "停止": 1})
        self.assertEqual(doc["事件"], {"开始": 2, "中间": 0, "停止": 1})
        # 旧会话末条停止累计 60，新会话开始累计 0。
        self.assertEqual(doc["累计字节"], 60)
        self.assertEqual(doc["最近时刻"], 5)
        self.assertEqual(doc["尾序号"], 3)

    def test_multiple_sessions_and_global_tail(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # seq1 alice
        s.do("k2", "建立", "sb", ("bob", "pw"), 1)    # seq2 bob
        s.do("k3", "建立", "s2", ("alice", "pw"), 2)  # seq3 alice
        s.meter("m1", "s1", 70, 3)                    # 不产生事件
        s.do("k4", "下线", "s1", None, 4)             # seq4 alice 停止 70
        chain = parse(s.accounting_events(0, 1000))

        alice = parse(s.accounting_stats("alice"))
        self.assertEqual(alice["会话"], {"总数": 2, "活动": 1, "停止": 1})
        self.assertEqual(alice["事件"], {"开始": 2, "中间": 0, "停止": 1})
        self.assertEqual(alice["累计字节"], 70)
        self.assertEqual(alice["最近时刻"], 4)

        bob = parse(s.accounting_stats("bob"))
        self.assertEqual(bob["会话"], {"总数": 1, "活动": 1, "停止": 0})
        self.assertEqual(bob["事件"], {"开始": 1, "中间": 0, "停止": 0})
        self.assertEqual(bob["累计字节"], 0)
        self.assertEqual(bob["最近时刻"], 1)

        carol = parse(s.accounting_stats("carol"))
        self.assertEqual(carol["会话"], {"总数": 0, "活动": 0, "停止": 0})
        self.assertEqual(carol["事件"], {"开始": 0, "中间": 0, "停止": 0})
        self.assertEqual(carol["累计字节"], 0)
        self.assertEqual(carol["最近时刻"], 0)

        # 尾序号/尾哈希始终是查询时的全局链尾，与查询用户无关。
        for doc in (alice, bob, carol):
            self.assertEqual(doc["尾序号"], chain["尾序号"])
            self.assertEqual(doc["尾哈希"], chain["尾哈希"])

    def test_latest_time_is_max_not_last_event_time(self):
        s = make()
        # 事件时刻允许回拨：开始于 10、停止于 5。
        s.do("k1", "建立", "s1", ("alice", "pw"), 10)
        s.do("k2", "下线", "s1", None, 5)
        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["最近时刻"], 10)

    def test_matches_fold_of_all_paginated_events(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "sb", ("bob", "pw"), 1)
        s.do("k3", "建立", "s2", ("alice", "pw"), 2)
        s.do("k4", "建立", "s3", ("alice", "pw"), 3)
        s.meter("ma1", "s1", 10, 4)
        s.accounting_interim("ia1", "s1", 4)
        s.meter("mb1", "s2", 5, 5)
        s.accounting_interim("ib1", "s2", 6)
        for index, now_ms in enumerate((8, 12), start=2):
            s.meter(f"ma{index}", "s1", 10, now_ms)
            s.accounting_interim(f"ia{index}", "s1", now_ms)
        s.do("k5", "下线", "s1", None, 20)

        # 以小页拉全链后自行折叠，逐字段比对。
        gathered = []
        after = 0
        while True:
            page = parse(s.accounting_events(after, 4))
            rows = page["事件"]
            if not rows:
                break
            gathered.extend(rows)
            after = page["下页"]
        self.assertEqual(len(gathered), 9)
        expected = fold([e for e in gathered if e["用户"] == "alice"])

        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["会话"], expected["会话"])
        self.assertEqual(doc["事件"], expected["事件"])
        self.assertEqual(doc["累计字节"], expected["累计字节"])
        self.assertEqual(doc["最近时刻"], expected["最近时刻"])

    def test_digest_determinism_and_compact_encoding(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 1)
        first = s.accounting_stats("alice")
        second = s.accounting_stats("alice")
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))
        self.assertNotIn(", ", first)
        self.assertNotIn(": ", first)
        doc = parse(first)
        head = {key: doc[key] for key in TOP_KEYS[:-1]}
        self.assertEqual(
            doc["摘要"], hashlib.sha256(compact(head).encode("utf-8")).hexdigest()
        )

    def test_unicode_user_not_escaped(self):
        s = make()
        s._auth.add("张三", "pw")
        s.do("k1", "建立", "s1", ("张三", "pw"), 0)
        out = s.accounting_stats("张三")
        self.assertIn("张三", out)
        self.assertNotIn("\\u", out)
        self.assertEqual(parse(out)["用户"], "张三")

    def test_param_validation(self):
        s = make()
        for bad in (123, None, True, b"alice", 1.5):
            with self.assertRaises(TypeError):
                s.accounting_stats(bad)
        for bad in ("", "a\0b", "é" * 129):  # 末者 UTF-8 为 258 字节
            with self.assertRaises(ValueError):
                s.accounting_stats(bad)
        # 凭据合法但未注册。
        with self.assertRaises(KeyError):
            s.accounting_stats("dave")
        # UTF-8 恰好 256 字节通过取值校验，落到未注册判定。
        with self.assertRaises(KeyError):
            s.accounting_stats("é" * 128)
        # 类型判定先于注册判定，取值判定先于注册判定。
        with self.assertRaises(TypeError):
            s.accounting_stats(123)
        with self.assertRaises(ValueError):
            s.accounting_stats("")

    def test_failures_have_no_side_effects(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before = s.accounting_events(0, 1000)
        for bad in (123, "", "a\0b", "dave", "é" * 129):
            with self.assertRaises((TypeError, ValueError, KeyError)):
                s.accounting_stats(bad)
        self.assertEqual(s.accounting_events(0, 1000), before)
        # 失败不影响后续正常查询。
        self.assertEqual(
            parse(s.accounting_stats("alice"))["事件"],
            {"开始": 1, "中间": 0, "停止": 0},
        )

    def test_success_changes_no_observable_state(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 1)
        s.accounting_interim("i1", "s1", 2)
        s.do("k2", "建立", "sb", ("bob", "pw"), 0)

        before = (
            s.accounting_events(0, 1000),
            s.meter_stats(0),
            s.user_stats("alice", 0),
            s.user_stats("bob", 0),
            s.user_stats("carol", 0),
            s.service_checkpoint(0),
            s.sessions(0),
            s.audit(),
        )
        for user in ("alice", "bob", "carol"):
            s.accounting_stats(user)
            s.accounting_stats(user)
        after = (
            s.accounting_events(0, 1000),
            s.meter_stats(0),
            s.user_stats("alice", 0),
            s.user_stats("bob", 0),
            s.user_stats("carol", 0),
            s.service_checkpoint(0),
            s.sessions(0),
            s.audit(),
        )
        self.assertEqual(before, after)
        # 幂等缓存内容不变：interim 同参仍原样重放。
        self.assertEqual(
            s.accounting_interim("i1", "s1", 2),
            s.accounting_interim("i1", "s1", 2),
        )

    def test_query_does_not_age(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 同刻即到期：若查询内部老化，s1 会被挂起并释址；只读查询不得如此。
        s.accounting_stats("alice")
        s.accounting_stats("bob")
        session = s._sessions["s1"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])
        # 链尾依旧只有开始事件。
        self.assertEqual(parse(s.accounting_stats("alice"))["尾序号"], 1)

    def test_legacy_restored_session_without_events_not_counted(self):
        donor = make()
        donor.do("k1", "建立", "s1", ("alice", "pw"), 0)
        donor.meter("m1", "s1", 100, 1)
        cp = donor.runtime_checkpoint(10)

        s = make()
        s.runtime_restore("r1", cp)
        # 运行态恢复会话，但计费链不恢复：s1 在线却无任何计费事件。
        self.assertEqual(parse(s.accounting_events(0, 1000))["事件"], [])
        self.assertEqual(s._sessions["s1"]["state"], "在线")

        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["会话"], {"总数": 0, "活动": 0, "停止": 0})
        self.assertEqual(doc["事件"], {"开始": 0, "中间": 0, "停止": 0})
        self.assertEqual(doc["累计字节"], 0)
        self.assertEqual(doc["最近时刻"], 0)
        self.assertEqual(doc["尾序号"], 0)
        self.assertEqual(doc["尾哈希"], "0" * 64)

        # meter 仅惰性建账、不产生事件，汇总仍为空。
        s.meter("m2", "s1", 100, 20)
        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["事件"], {"开始": 0, "中间": 0, "停止": 0})
        self.assertEqual(doc["尾序号"], 0)

        # 首次中间计费惰性开账，仅落中间事件（累计自本次 100 起，不补开始）。
        s.accounting_interim("i1", "s1", 30)
        doc = parse(s.accounting_stats("alice"))
        self.assertEqual(doc["会话"], {"总数": 1, "活动": 1, "停止": 0})
        self.assertEqual(doc["事件"], {"开始": 0, "中间": 1, "停止": 0})
        self.assertEqual(doc["累计字节"], 100)
        self.assertEqual(doc["最近时刻"], 30)
        self.assertEqual(doc["尾序号"], 1)


if __name__ == "__main__":
    unittest.main()
