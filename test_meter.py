import json
import unittest

from access import Authenticator, Sessions, StateError


def make(templates=None, user_templates=None, idle_ms=5000, lease_ms=1000):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    s = Sessions(
        auth,
        4,
        2,
        idle_ms,
        pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),)),
        lease_ms=lease_ms,
    )
    if templates is not None:
        doc = json.loads(s.export_config())
        doc["模板"] = templates
        doc["用户模板"] = user_templates or []
        s.load_config(json.dumps(doc, ensure_ascii=False))
    return s


# 限速 100 字节/秒、无突发、配额 10000、超限拒绝：C=(100+0)*1000=100000。
REJECT_TPL = [{"标识": "t", "限速": 100, "突发": 0, "配额": 10000, "超限": "拒绝"}]
OFFLINE_TPL = [{"标识": "t", "限速": 100, "突发": 0, "配额": 10000, "超限": "下线"}]


class MeterTest(unittest.TestCase):
    def test_pass_and_json_format(self):
        s = make(REJECT_TPL, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = s.meter("m1", "s1", 100, 0)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        doc = json.loads(out)
        self.assertEqual(list(doc), ["会话", "时刻", "字节", "结果", "累计"])
        self.assertEqual(
            doc, {"会话": "s1", "时刻": 0, "字节": 100, "结果": "通过", "累计": 100}
        )
        self.assertIsInstance(doc["会话"], str)
        self.assertIsInstance(doc["结果"], str)
        for name in ("时刻", "字节", "累计"):
            self.assertIsInstance(doc[name], int)
            self.assertNotIsInstance(doc[name], bool)

    def test_token_bucket_refill(self):
        s = make(REJECT_TPL, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 初始 c=C=100000（即 100 字节），size=100 恰好耗尽。
        r = json.loads(s.meter("m1", "s1", 100, 0))
        self.assertEqual(r["结果"], "通过")
        # 同刻无补充，1 字节也不足。
        r = json.loads(s.meter("m2", "s1", 1, 0))
        self.assertEqual(r["结果"], "拒绝")
        self.assertEqual(r["累计"], 100)  # 拒绝不提交
        # 500ms 补充 100*500=50000（50 字节），恰好通过。
        r = json.loads(s.meter("m3", "s1", 50, 500))
        self.assertEqual(r["结果"], "通过")
        self.assertEqual(r["累计"], 150)
        # 令牌不超额累积：长时间后 c 截顶于 C（仍在空闲期限内）。
        r = json.loads(s.meter("m4", "s1", 100, 4000))
        self.assertEqual(r["结果"], "通过")
        r = json.loads(s.meter("m5", "s1", 1, 4000))
        self.assertEqual(r["结果"], "拒绝")

    def test_quota_exceeded(self):
        tpl = [{"标识": "t", "限速": 1000, "突发": 0, "配额": 100, "超限": "拒绝"}]
        s = make(tpl, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        r = json.loads(s.meter("m1", "s1", 60, 0))
        self.assertEqual(r["结果"], "通过")
        # 令牌充足但 u+size=110>100：拒绝且不提交（令牌也不扣）。
        r = json.loads(s.meter("m2", "s1", 50, 0))
        self.assertEqual(r["结果"], "拒绝")
        self.assertEqual(r["累计"], 60)
        r = json.loads(s.meter("m3", "s1", 40, 0))
        self.assertEqual(r["结果"], "通过")
        self.assertEqual(r["累计"], 100)

    def test_offline_action(self):
        s = make(OFFLINE_TPL, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        r = json.loads(s.meter("m1", "s1", 100, 0))
        self.assertEqual(r["结果"], "通过")
        # 令牌耗尽，超限动作为下线：不累计并原子下线、清期限、释址退租。
        out = s.meter("m2", "s1", 1, 0)
        r = json.loads(out)
        self.assertEqual(r["结果"], "下线")
        self.assertEqual(r["累计"], 100)
        stats = json.loads(s.pool_stats(0))
        self.assertEqual(stats["池"][0][4], 0)  # 租用 0：地址已释放
        # 已下线：qos 与后续 meter 均抛 StateError。
        with self.assertRaises(StateError):
            s.qos("s1")
        with self.assertRaises(StateError):
            s.meter("m3", "s1", 1, 0)
        # 下线结果已缓存：同参重放仍返回原 JSON。
        self.assertEqual(s.meter("m2", "s1", 1, 0), out)

    def test_unknown_sid_and_state_errors(self):
        s = make(REJECT_TPL, [["alice", "t"]])
        with self.assertRaises(KeyError):
            s.meter("m1", "nope", 1, 0)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        # bob 未绑模板
        with self.assertRaises(StateError):
            s.meter("m2", "s2", 1, 0)
        # 非在线（下线后）
        s.do("k3", "下线", "s1", None, 1)
        with self.assertRaises(StateError):
            s.meter("m3", "s1", 1, 2)
        # now_ms < t（上次通过时刻）
        s.do("k4", "建立", "s3", ("alice", "pw"), 100)
        s.meter("m4", "s3", 1, 200)
        with self.assertRaises(StateError):
            s.meter("m5", "s3", 1, 199)

    def test_first_call_ages_and_exception_keeps_aging(self):
        s = make(REJECT_TPL, [["alice", "t"]], idle_ms=5000)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 未知 sid 抛 KeyError，但老化已发生：s1 空闲到期被挂起。
        with self.assertRaises(KeyError):
            s.meter("m1", "nope", 1, 6000)
        with self.assertRaises(StateError):
            s.meter("m2", "s1", 1, 6000)

    def test_replay_cache(self):
        s = make(REJECT_TPL, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        out = s.meter("m1", "s1", 10, 0)
        # 同型同参重放：逐字节相同，不重复扣令牌。
        self.assertEqual(s.meter("m1", "s1", 10, 0), out)
        self.assertEqual(json.loads(s.meter("m2", "s1", 90, 0))["结果"], "通过")
        # 异参重放抛 ValueError
        with self.assertRaises(ValueError):
            s.meter("m1", "s1", 11, 0)
        with self.assertRaises(ValueError):
            s.meter("m1", "s1", 10, 1)
        with self.assertRaises(ValueError):
            s.meter("m1", "s2", 10, 0)
        with self.assertRaises(ValueError):
            s.meter("m1", "s1", True, 0)  # 同值异型亦为异参
        # 异常结果亦缓存：重抛同类异常，异参抛 ValueError
        with self.assertRaises(KeyError):
            s.meter("m9", "nope", 1, 0)
        with self.assertRaises(KeyError):
            s.meter("m9", "nope", 1, 0)
        with self.assertRaises(ValueError):
            s.meter("m9", "nope", 1, 1)

    def test_key_domain_separate_from_do(self):
        s = make(REJECT_TPL, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 同一 key 在 do 与 meter 各自独立。
        out = s.meter("k1", "s1", 10, 0)
        self.assertEqual(json.loads(out)["结果"], "通过")
        self.assertEqual(s.meter("k1", "s1", 10, 0), out)
        # do 侧缓存不受 meter 影响。
        self.assertEqual(s.do("k1", "建立", "s1", ("alice", "pw"), 0),
                         s.do("k1", "建立", "s1", ("alice", "pw"), 0))

    def test_param_validation(self):
        s = make(REJECT_TPL, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(TypeError):
            s.meter(1, "s1", 1, 0)
        with self.assertRaises(ValueError):
            s.meter("", "s1", 1, 0)
        with self.assertRaises(TypeError):
            s.meter("ms1", 1, 1, 0)
        with self.assertRaises(ValueError):
            s.meter("ms2", "", 1, 0)
        for i, bad_size in enumerate((0, -1)):
            with self.assertRaises(ValueError):
                s.meter(f"mv{i}", "s1", bad_size, 0)
        for i, bad_size in enumerate((True, 1.5, "1")):
            with self.assertRaises(TypeError):
                s.meter(f"mt{i}", "s1", bad_size, 0)
        with self.assertRaises(ValueError):
            s.meter("m4", "s1", 1, -1)
        for i, bad_now in enumerate((False, 0.5, "0")):
            with self.assertRaises(TypeError):
                s.meter(f"mn{i}", "s1", 1, bad_now)
        # 校验异常同样入缓存：同参重抛、异参重放抛 ValueError。
        with self.assertRaises(ValueError):
            s.meter("mv0", "s1", 0, 0)
        with self.assertRaises(ValueError):
            s.meter("mv0", "s1", 1, 0)

    def test_config_change_caps_tokens_keeps_used_and_last(self):
        tpl = [{"标识": "t", "限速": 1000, "突发": 0, "配额": 10000, "超限": "拒绝"}]
        s = make(tpl, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # C=(1000+0)*1000=1000000；通过 500 字节后 c=500000。
        r = json.loads(s.meter("m1", "s1", 500, 0))
        self.assertEqual(r["结果"], "通过")
        # 换模板：限速 100 → 新 C=100000，c 截顶为 100000；u/t 续存。
        doc = json.loads(s.export_config())
        doc["模板"] = [
            {"标识": "t", "限速": 100, "突发": 0, "配额": 10000, "超限": "拒绝"}
        ]
        s.load_config(json.dumps(doc, ensure_ascii=False))
        # 150 字节 > 截顶后的 100 字节：拒绝（未截顶则为 500000 可通过）。
        r = json.loads(s.meter("m2", "s1", 150, 0))
        self.assertEqual(r["结果"], "拒绝")
        self.assertEqual(r["累计"], 500)  # u 续存
        # t 续存：now_ms < 上次通过时刻仍 StateError。
        s.meter("m3", "s1", 100, 100)
        with self.assertRaises(StateError):
            s.meter("m4", "s1", 1, 99)

    def test_burst_and_rebind(self):
        # 突发 50：C=(10+50)*1000=60000（60 字节）。
        tpl = [{"标识": "t", "限速": 10, "突发": 50, "配额": 1000, "超限": "拒绝"}]
        s = make(tpl, [["alice", "t"]])
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        r = json.loads(s.meter("m1", "s1", 60, 0))
        self.assertEqual(r["结果"], "通过")
        r = json.loads(s.meter("m2", "s1", 1, 0))
        self.assertEqual(r["结果"], "拒绝")
        # 改绑更大模板后按新模板计量。
        doc = json.loads(s.export_config())
        doc["模板"].append(
            {"标识": "big", "限速": 10, "突发": 90, "配额": 1000, "超限": "拒绝"}
        )
        doc["用户模板"] = [["alice", "big"]]
        s.load_config(json.dumps(doc, ensure_ascii=False))
        # 新 C=100000；旧 c=0 截顶不变，1 秒补充 10*1000=10000 → 10 字节。
        r = json.loads(s.meter("m3", "s1", 10, 1000))
        self.assertEqual(r["结果"], "通过")
        self.assertEqual(r["累计"], 70)


if __name__ == "__main__":
    unittest.main()
