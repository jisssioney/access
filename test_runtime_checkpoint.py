import hashlib
import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def make():
    """总数 2、每用户 2、default 池 /24；alice/bob 绑 gold 模板。"""
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob", "carol"):
        auth.add(user, "pw")
    s = Sessions(auth, 2, 2, 100000, lease_ms=100000)
    config = {
        "版本": 4,
        "会话": {"总数": 2, "每用户": 2, "空闲毫秒": 100000, "租期毫秒": 100000},
        "地址池": [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
        ],
        "模板": [
            {"标识": "gold", "限速": 1000000, "突发": 0, "配额": 1000, "超限": "拒绝"},
        ],
        "用户模板": [["alice", "gold"], ["bob", "gold"]],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0},
    }
    s.load_config(json.dumps(config, ensure_ascii=False))
    return s


def populate(s):
    """s1/s2 在线占满总数，q1 排队（产生事件），s2 下线成墓碑，s1 计量建账。"""
    s.do("k1", "建立", "s1", ("alice", "pw"), 0)
    s.do("k2", "建立", "s2", ("bob", "pw"), 0)
    s.capacity("c1", "申请", "q1", ("carol", "pw", 500), 1)
    s.do("k3", "下线", "s2", None, 2)
    s.meter("m1", "s1", 100, 3)
    return s


def parse(out):
    return json.loads(out)


def reseal(doc):
    """按规范化前四键重算顶层摘要，返回 LF 尾紧凑文本。"""
    head = {key: doc[key] for key in ("版本", "时刻", "容量", "配额")}
    doc["摘要"] = digest(head)
    return compact(doc) + "\n"


def reseal_capacity(cap):
    """按规范化前四键重算容量状态哈希。"""
    state = {key: cap[key] for key in ("时刻", "事件", "会话", "排队")}
    cap["状态哈希"] = digest(state)


class RuntimeCheckpointTest(unittest.TestCase):
    def test_empty_format_and_digest(self):
        s = make()
        out = s.runtime_checkpoint(0)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)
        doc = parse(out)
        self.assertEqual(list(doc), ["版本", "时刻", "容量", "配额", "摘要"])
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["时刻"], 0)
        self.assertEqual(
            list(doc["容量"]), ["时刻", "事件", "会话", "排队", "状态哈希"]
        )
        self.assertEqual(doc["容量"]["时刻"], 0)
        self.assertEqual(doc["容量"]["事件"], [])
        self.assertEqual(doc["容量"]["会话"], [])
        self.assertEqual(doc["容量"]["排队"], [])
        self.assertEqual(doc["配额"], {"版本": 1, "账本": []})
        head = {key: doc[key] for key in ("版本", "时刻", "容量", "配额")}
        self.assertEqual(doc["摘要"], digest(head))
        # 容量/配额与同刻 clog/quota_checkpoint 对象一致。
        self.assertEqual(doc["容量"], parse(s.clog(0)))
        self.assertEqual(doc["配额"], parse(s.quota_checkpoint()))

    def test_param_validation(self):
        s = make()
        for bad in (True, "0", 1.5, None, b"0", []):
            with self.assertRaises(TypeError):
                s.runtime_checkpoint(bad)
        for bad in (-1, -100):
            with self.assertRaises(ValueError):
                s.runtime_checkpoint(bad)

    def test_ages_once_before_snapshot(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 越过空闲期限：检查点先老化，s1 挂起释址。
        doc = parse(s.runtime_checkpoint(100000))
        rows = {row["会话"]: row for row in doc["容量"]["会话"]}
        self.assertEqual(rows["s1"]["状态"], "挂起")
        self.assertEqual(rows["s1"]["池"], "")
        self.assertEqual(rows["s1"]["地址"], "")
        self.assertEqual(rows["s1"]["租期"], 0)
        # 同刻再取逐字节相同（老化幂等）。
        self.assertEqual(s.runtime_checkpoint(100000), s.runtime_checkpoint(100000))

    def test_checkpoint_covers_sessions_queue_events_ledgers(self):
        s = populate(make())
        doc = parse(s.runtime_checkpoint(10))
        sids = [row["会话"] for row in doc["容量"]["会话"]]
        self.assertEqual(sids, ["s1", "s2"])
        states = {row["会话"]: row["状态"] for row in doc["容量"]["会话"]}
        self.assertEqual(states, {"s1": "在线", "s2": "下线"})
        self.assertEqual([row["会话"] for row in doc["容量"]["排队"]], ["q1"])
        self.assertEqual(len(doc["容量"]["事件"]), 1)
        self.assertEqual(doc["容量"]["事件"][0]["结果"], "排队")
        self.assertEqual(
            doc["配额"]["账本"], [["alice", "gold", 100, 3, 999900000]]
        )
        self.assertEqual(doc["容量"]["时刻"], 10)

    def test_unicode_not_escaped(self):
        auth = Authenticator(3, 1000)
        auth.add("张三", "pw")
        s = Sessions(auth, 2, 2, 100000)
        config = json.loads(make().export_config())
        config["用户模板"] = [["张三", "gold"]]
        s.load_config(json.dumps(config, ensure_ascii=False))
        s.do("k1", "建立", "s1", ("张三", "pw"), 0)
        s.meter("m1", "s1", 1, 0)
        out = s.runtime_checkpoint(0)
        self.assertIn("张三", out)
        self.assertNotIn("\\u", out)


class RuntimeRestoreTest(unittest.TestCase):
    def test_roundtrip_byte_stable(self):
        s = populate(make())
        cp = s.runtime_checkpoint(10)
        out = s.runtime_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(s.runtime_checkpoint(10), cp)

    def test_restore_onto_fresh_instance(self):
        donor = populate(make())
        cp = donor.runtime_checkpoint(10)
        s = make()
        out = s.runtime_restore("r1", cp)
        self.assertEqual(out, cp)
        # 会话/租约、队列/事件与账本一致恢复。
        self.assertEqual(s.clog(10), donor.clog(10))
        self.assertEqual(s.quota_checkpoint(), donor.quota_checkpoint())
        self.assertEqual(s.runtime_checkpoint(10), cp)
        # 续租一致恢复：s1 在线持址可续租。
        renewed = parse(s.do("k9", "续租", "s1", None, 20))
        self.assertEqual(renewed["状态"], "在线")
        self.assertEqual(renewed["租期"], 20 + 100000)
        # 计量一致恢复：沿用恢复的共享账本累计。
        metered = parse(s.meter("m9", "s1", 50, 20))
        self.assertEqual(metered["结果"], "通过")
        self.assertEqual(metered["累计"], 150)
        # 推进一致恢复：墓碑不占容量，q1 晋升上线。
        advanced = parse(s.capacity("c9", "推进", "", None, 20))
        self.assertEqual(advanced["在线"], 2)
        self.assertEqual(advanced["排队"], 0)
        states = {
            row["会话"]: row["状态"] for row in parse(s.clog(20))["会话"]
        }
        self.assertEqual(states["q1"], "在线")

    def test_restore_empty_checkpoint_on_fresh(self):
        donor = make()
        cp = donor.runtime_checkpoint(0)
        s = make()
        self.assertEqual(s.runtime_restore("r1", cp), cp)
        self.assertEqual(s.runtime_checkpoint(0), cp)

    def test_noop_when_same_digest(self):
        s = populate(make())
        cp = s.runtime_checkpoint(10)
        # 不同 key 同刻同态：空操作成功，不改态。
        self.assertEqual(s.runtime_restore("r1", cp), cp)
        self.assertEqual(s.runtime_restore("r2", cp), cp)
        self.assertEqual(s.runtime_checkpoint(10), cp)

    def test_state_error_on_divergent_state(self):
        s = populate(make())
        cp = s.runtime_checkpoint(10)
        # 状态推进后（新会话），异摘要覆盖状态抛 StateError。
        s.do("k8", "建立", "s3", ("bob", "pw"), 20)
        before_clog = s.clog(30)
        before_quota = s.quota_checkpoint()
        with self.assertRaises(StateError):
            s.runtime_restore("r9", cp)
        # 失败不改运行态。
        self.assertEqual(s.clog(30), before_clog)
        self.assertEqual(s.quota_checkpoint(), before_quota)

    def test_state_error_from_ledger_only_divergence(self):
        donor = populate(make())
        cp = donor.runtime_checkpoint(10)
        s = make()
        s.do("k1", "建立", "sx", ("alice", "pw"), 0)
        s.meter("m1", "sx", 1, 0)
        s.do("k2", "下线", "sx", None, 1)
        # 仅账本分歧（无会话/队列/事件外的覆盖状态差异）亦为覆盖状态。
        with self.assertRaises(StateError):
            s.runtime_restore("r1", cp)

    def test_type_errors(self):
        s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.runtime_restore(bad_key, "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.runtime_restore("k", bad_text)

    def test_value_errors(self):
        s = make()
        good = parse(make().runtime_checkpoint(0))
        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            '"x"',
            # 键集/键序。
            '{"版本":1}',
            compact({k: good[k] for k in ("时刻", "版本", "容量", "配额", "摘要")}),
            compact(dict(list(good.items()) + [("x", 1)])),
            # 版本。
            compact({**good, "版本": 0}),
            compact({**good, "版本": 2}),
            compact({**good, "版本": "1"}),
            compact({**good, "版本": True}),
            # 时刻。
            compact({**good, "时刻": -1}),
            compact({**good, "时刻": True}),
            compact({**good, "时刻": "0"}),
            # 摘要形态。
            compact({**good, "摘要": 0}),
            compact({**good, "摘要": "0" * 64}),
            compact({**good, "摘要": "A" * 64}),
            compact({**good, "摘要": "0" * 63}),
            # 容量/配额非对象。
            compact({**good, "容量": []}),
            compact({**good, "配额": []}),
            # 容量时刻不等于顶层。
            reseal({**good, "容量": {**good["容量"], "时刻": 1}}),
            # 配额版本错。
            reseal({**good, "配额": {"版本": 2, "账本": []}}),
            # 配额账本乱序。
            reseal(
                {
                    **good,
                    "配额": {
                        "版本": 1,
                        "账本": [["bob", "gold", 0, 0, 0], ["alice", "gold", 0, 0, 0]],
                    },
                }
            ),
            # 容量状态哈希错。
            reseal({**good, "容量": {**good["容量"], "状态哈希": "0" * 64}}),
            # 摘要与内容不符。
            compact({**good, "摘要": "1" * 64}),
            # 重复键。
            '{"版本":1,"版本":1,"时刻":0,"容量":{},"配额":{},"摘要":"0"}',
        ]
        for text in bad_texts:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.runtime_restore("k", text)

    def test_capacity_subdocument_validated(self):
        s = make()
        doc = parse(populate(make()).runtime_checkpoint(10))
        # 事件哈希链断裂。
        broken = parse(compact(doc))
        broken["容量"]["事件"][0]["哈希"] = "0" * 64
        reseal_capacity(broken["容量"])
        with self.assertRaises(ValueError):
            s.runtime_restore("k1", reseal(broken))
        # 会话行乱序。
        broken = parse(compact(doc))
        broken["容量"]["会话"] = list(reversed(broken["容量"]["会话"]))
        reseal_capacity(broken["容量"])
        with self.assertRaises(ValueError):
            s.runtime_restore("k2", reseal(broken))
        # 排队行与事件账本的入队序不符。
        broken = parse(compact(doc))
        broken["容量"]["排队"] = []
        reseal_capacity(broken["容量"])
        with self.assertRaises(ValueError):
            s.runtime_restore("k3", reseal(broken))

    def test_resource_errors(self):
        donor = populate(make())
        base = parse(donor.runtime_checkpoint(10))
        s = make()
        # 账本引用未注册用户。
        doc = parse(compact(base))
        doc["配额"]["账本"] = [["nobody", "gold", 0, 0, 0]]
        with self.assertRaises(ResourceError):
            s.runtime_restore("r1", reseal(doc))
        # 账本引用未知模板。
        doc = parse(compact(base))
        doc["配额"]["账本"] = [["alice", "bronze", 0, 0, 0]]
        with self.assertRaises(ResourceError):
            s.runtime_restore("r2", reseal(doc))
        # 令牌超桶容（gold 桶容 (1000000+0)*1000）。
        doc = parse(compact(base))
        doc["配额"]["账本"] = [["alice", "gold", 0, 0, 1000000001]]
        with self.assertRaises(ResourceError):
            s.runtime_restore("r3", reseal(doc))
        # 会话行引用未注册用户。
        doc = parse(compact(base))
        doc["容量"]["会话"][0]["用户"] = "nobody"
        reseal_capacity(doc["容量"])
        with self.assertRaises(ResourceError):
            s.runtime_restore("r4", reseal(doc))
        # 会话行引用未知池。
        doc = parse(compact(base))
        doc["容量"]["会话"][0]["池"] = "nosuch"
        reseal_capacity(doc["容量"])
        with self.assertRaises(ResourceError):
            s.runtime_restore("r5", reseal(doc))
        # 非下线会话数超总数上限（总数 2，三在线）。
        doc = parse(compact(base))
        doc["容量"]["会话"] = [
            {"会话": "s1", "用户": "alice", "状态": "在线", "期限": 100000,
             "池": "default", "地址": "10.0.0.1", "租期": 100000},
            {"会话": "s2", "用户": "bob", "状态": "在线", "期限": 100000,
             "池": "default", "地址": "10.0.0.2", "租期": 100000},
            {"会话": "s3", "用户": "carol", "状态": "在线", "期限": 100000,
             "池": "default", "地址": "10.0.0.3", "租期": 100000},
        ]
        reseal_capacity(doc["容量"])
        with self.assertRaises(ResourceError):
            s.runtime_restore("r6", reseal(doc))
        # 全部失败不改运行态。
        self.assertEqual(s.runtime_checkpoint(0), make().runtime_checkpoint(0))

    def test_failure_does_not_change_instance_or_occupy_key(self):
        s = populate(make())
        before = s.runtime_checkpoint(10)
        before_config = s.export_config()
        before_audit = parse(s.audit())["事件"]
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", "not json")
        with self.assertRaises(TypeError):
            s.runtime_restore("r1", None)
        doc = parse(make().runtime_checkpoint(0))
        doc["配额"]["账本"] = [["nobody", "gold", 0, 0, 0]]
        with self.assertRaises(ResourceError):
            s.runtime_restore("r1", reseal(doc))
        # 失败不占 key：同 key 换合法文本（同态空操作）成功。
        self.assertEqual(s.runtime_restore("r1", before), before)
        # 运行态、配置、审计均未变。
        self.assertEqual(s.runtime_checkpoint(10), before)
        self.assertEqual(s.export_config(), before_config)
        self.assertEqual(parse(s.audit())["事件"], before_audit)
        self.assertEqual(parse(s.takeover_audit())["事件"], [])

    def test_replay_cache_semantics(self):
        donor = populate(make())
        cp = donor.runtime_checkpoint(10)
        s = make()
        self.assertEqual(s.runtime_restore("r1", cp), cp)
        # 同 key 同型同 text 重放无副作用：状态已推进仍返回缓存规范包。
        s.do("k9", "建立", "s9", ("bob", "pw"), 20)
        self.assertEqual(s.runtime_restore("r1", cp), cp)
        # 异参 ValueError。
        other = make().runtime_checkpoint(0)
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", other)
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", cp.rstrip("\n"))
        # 异 key 同 text 在状态分歧后抛 StateError（不走缓存）。
        with self.assertRaises(StateError):
            s.runtime_restore("r2", cp)

    def test_cache_domain_independent(self):
        s = populate(make())
        # do/meter/quota_restore 域用过的 key 在本域可首次使用。
        s.meter("shared", "s1", 1, 4)
        s.quota_restore("shared2", s.quota_checkpoint())
        cp = s.runtime_checkpoint(10)
        out = s.runtime_restore("shared", cp)
        self.assertEqual(out, cp)
        self.assertEqual(s.runtime_checkpoint(10), cp)

    def test_restore_does_not_audit(self):
        donor = populate(make())
        cp = donor.runtime_checkpoint(10)
        s = make()
        s.runtime_restore("r1", cp)
        self.assertEqual(parse(s.audit())["事件"], [])
        self.assertEqual(parse(s.takeover_audit())["事件"], [])
        self.assertTrue(s.verify_audit())

    def test_restore_preserves_config_and_fault_state(self):
        donor = populate(make())
        cp = donor.runtime_checkpoint(10)
        s = make()
        before_config = s.export_config()
        s.fault("f1", "注入", 500, 0)
        s.runtime_restore("r1", cp)
        # 配置与后端故障状态不属于运行态检查点，原样保留。
        self.assertEqual(s.export_config(), before_config)
        stats = parse(s.fault_stats(0))
        self.assertEqual(stats["故障"], True)

    def test_restore_event_chain_and_queue_sequence(self):
        donor = make()
        donor.do("k1", "建立", "s1", ("alice", "pw"), 0)
        donor.do("k2", "建立", "s2", ("bob", "pw"), 0)
        donor.capacity("c1", "申请", "q1", ("carol", "pw", 500), 1)
        donor.capacity("c2", "申请", "q2", ("carol", "pw", 500), 2)
        donor.capacity("c3", "取消", "q2", None, 3)
        cp = donor.runtime_checkpoint(10)
        s = make()
        s.runtime_restore("r1", cp)
        # 事件哈希链恢复后可校验、可查询。
        self.assertTrue(s.cverify())
        events = parse(s.capacity_events())["事件"]
        self.assertEqual([e["结果"] for e in events], ["排队", "排队", "取消"])
        # 入队序游标延续：取消不回收序号，新排队项取序 3。
        out = parse(s.capacity("c9", "申请", "q3", ("carol", "pw", 500), 25))
        self.assertEqual(out["结果"], "排队")
        events = parse(s.capacity_events())["事件"]
        self.assertEqual(events[-1]["入队序"], 3)
        self.assertTrue(s.cverify())


if __name__ == "__main__":
    unittest.main()
