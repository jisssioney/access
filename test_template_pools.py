"""v11 模板地址池：配置解析/迁移与有序后备选池规则测试。"""

import json
import unittest

from access import (
    AuthError,
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
    StateError,
)


def make(users=("alice", "bob"), default_cidr="10.0.0.0/30",
         default_static=(), backup_cidrs=("10.1.0.0/30",),
         backup_static=(), total=10, per=10):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(
        auth, total, per, 50000,
        pool=(default_cidr, (), tuple(default_static)), lease_ms=50000,
    )
    for index, cidr in enumerate(backup_cidrs):
        pool_id = f"bak{index}" if len(backup_cidrs) > 1 else "bak"
        static = (
            backup_static.get(cidr, ())
            if isinstance(backup_static, dict)
            else backup_static
        )
        s.add_pool(pool_id, (cidr, (), tuple(static)))
    return auth, s


def config_doc(seq=None, templates=("gold",), bindings=(("alice", "gold"),),
               pools=("default", "bak"), cidrs=None, statics=None):
    """构造规范 v11 配置对象；seq 为 模板地址池 原始值。"""
    if cidrs is None:
        cidrs = {"default": "10.0.0.0/30", "bak": "10.1.0.0/30",
                 "bak0": "10.1.0.0/30", "bak1": "10.2.0.0/30"}
    if statics is None:
        statics = {}
    pool_entries = [
        {
            "标识": pool_id,
            "CIDR": cidrs[pool_id],
            "保留": [],
            "静态": [list(pair) for pair in statics.get(pool_id, ())],
        }
        for pool_id in pools
    ]
    template_entries = [
        {"标识": tid, "限速": 100, "突发": 0, "配额": 1000, "周期毫秒": 0,
         "会话上限": 0, "排队优先级": 0, "超限": "拒绝"}
        for tid in templates
    ]
    doc = {
        "版本": 11,
        "会话": {"总数": 10, "每用户": 10, "空闲毫秒": 50000, "租期毫秒": 50000},
        "地址池": pool_entries,
        "模板": template_entries,
        "用户模板": [list(pair) for pair in bindings],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 1000,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [] if seq is None else seq,
    }
    return doc


def load(s, doc):
    if isinstance(doc, str):
        return s.load_config(doc)
    return s.load_config(json.dumps(doc, ensure_ascii=False))


def pool_of(sessions, sid, now=40000):
    for item in json.loads(sessions.sessions(now))["项目"]:
        if item["会话"] == sid:
            return item["池"], item["地址"]
    return None


class TemplatePoolConfigTest(unittest.TestCase):
    def test_export_shape_and_empty_default(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        doc = json.loads(s.export_config())
        self.assertEqual(doc["版本"], 11)
        self.assertEqual(
            list(doc),
            ["版本", "会话", "地址池", "模板", "用户模板", "容量", "认证",
             "模板地址池"],
        )
        self.assertEqual(doc["模板地址池"], [])

    def test_roundtrip_preserves_sequence_order(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        doc = config_doc(seq=[["gold", ["bak", "default"]]])
        out = json.loads(load(s, doc))
        self.assertEqual(out["模板地址池"], [["gold", ["bak", "default"]]])
        # 再导出与重复加载稳定。
        self.assertEqual(s.export_config(), load(s, json.dumps(out)))

    def test_outer_order_must_be_sorted(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        doc = config_doc(
            templates=("gold", "silver"),
            seq=[["silver", ["default"]], ["gold", ["bak"]]],
        )
        with self.assertRaises(ValueError):
            load(s, doc)
        # 升序合法。
        doc["模板地址池"] = [["gold", ["bak"]], ["silver", ["default"]]]
        self.assertEqual(
            json.loads(load(s, doc))["模板地址池"],
            [["gold", ["bak"]], ["silver", ["default"]]],
        )

    def test_value_errors(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        bad_sections = (
            {},                                       # 缺键（顶层键集）
        )
        for section in bad_sections:
            with self.assertRaises(ValueError):
                load(s, section)
        bad_seq = [
            (42, "not list"),
            ([["gold"]], "entry not pair"),
            ([["gold", ["default"], 9]], "triple entry"),
            ([["gold", "default"]], "seq not list"),
            ([["gold", []]], "empty seq"),
            ([["gold", ["default", "default"]]], "dup pool in seq"),
            ([["gold", ["nope"]]], "unknown pool"),
            ([["nope", ["default"]]], "unknown template"),
            ([["gold", ["default"]], ["gold", ["bak"]]], "dup template"),
            ([["gold", [1]]], "pool id not str"),
            ([[8, ["default"]]], "template id not str"),
        ]
        for seq, label in bad_seq:
            doc = config_doc(seq=seq)
            with self.assertRaises(ValueError, msg=label):
                load(s, doc)

    def test_sequence_length_bounds(self):
        _auth, s = make()
        for index in range(34):
            s.add_pool(f"p{index}", (f"10.{50 + index}.0.0/24", (), ()))
        pools = ["default"] + [f"p{i}" for i in range(34)]
        cidrs = {f"p{i}": f"10.{50 + i}.0.0/24" for i in range(34)}
        cidrs["default"] = "10.0.0.0/30"
        seq33 = ["p" + str(i) for i in range(32)]
        doc = config_doc(seq=[["gold", seq33]], pools=pools[:33], cidrs=cidrs)
        # 32 个池合法。
        load(s, doc)
        seq33_names = ["default"] + [f"p{i}" for i in range(32)]
        doc = config_doc(seq=[["gold", seq33_names]], pools=pools[:33],
                         cidrs=cidrs)
        # 33 个池非法。
        with self.assertRaises(ValueError):
            load(s, doc)

    def test_failed_commit_changes_nothing(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        good = config_doc(seq=[["gold", ["default", "bak"]]])
        load(s, good)
        before = s.export_config()
        # 引用未知池：提交失败，配置与序列不变。
        bad = config_doc(seq=[["gold", ["default", "ghost"]]])
        with self.assertRaises(ValueError):
            load(s, bad)
        self.assertEqual(s.export_config(), before)
        self.assertEqual(s._template_pools, {"gold": ("default", "bak")})

    def test_v10_loads_with_empty_template_pools(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        v10 = config_doc()
        v10["版本"] = 10
        del v10["模板地址池"]
        out = json.loads(load(s, json.dumps(v10, ensure_ascii=False)))
        self.assertEqual(out["版本"], 11)
        self.assertEqual(out["模板地址池"], [])

    def test_upgrade_v10_envelope(self):
        import hashlib
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        v10 = config_doc(seq=[["gold", ["bak"]]])
        v10["版本"] = 10
        del v10["模板地址池"]
        env = json.loads(s.upgrade_config(json.dumps(v10, ensure_ascii=False)))
        self.assertEqual((env["源版本"], env["目标版本"], env["改变"]),
                         (10, 11, True))
        self.assertEqual(env["配置"]["模板地址池"], [])
        canonical = json.dumps(env["配置"], ensure_ascii=False,
                               separators=(",", ":"))
        self.assertEqual(
            env["摘要"], hashlib.sha256(canonical.encode()).hexdigest()
        )
        # v11 自升级改变为 False。
        env2 = json.loads(s.upgrade_config(load(s, config_doc())))
        self.assertFalse(env2["改变"])

    def test_history_diff_and_preflight_include_field(self):
        _auth, s = make(backup_cidrs=("10.1.0.0/30",))
        load(s, config_doc(seq=[["gold", ["default", "bak"]]]))   # rev 1
        load(s, config_doc(seq=[["gold", ["bak", "default"]]]))   # rev 2
        diff = json.loads(s.config_history_diff(1, 2))
        self.assertTrue(diff["改变"])
        self.assertTrue(
            any("模板地址池" in item["路径"] for item in diff["变更"])
        )
        pre = json.loads(s.config_preflight(
            json.dumps(config_doc(seq=[["gold", ["default", "bak"]]]),
                       ensure_ascii=False)
        ))
        self.assertTrue(
            any("模板地址池" in item["路径"] for item in pre["变更"])
        )


class OrderedSelectionTest(unittest.TestCase):
    def doc(self, seq):
        return config_doc(seq=seq)

    def test_dynamic_exhaustion_falls_back(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        # /30 恰两动态址；占满 default 后落 bak。
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s1"), ("default", "10.0.0.1"))
        self.assertEqual(pool_of(s, "s2"), ("default", "10.0.0.2"))
        s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s3"), ("bak", "10.1.0.1"))

    def test_pool_fault_falls_back(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        s.pool_fault("f", "注入", "default", 100000, 0)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s1"), ("bak", "10.1.0.1"))

    def test_static_occupied_falls_back_without_dynamic_downgrade(self):
        _auth, s = make(
            default_static=(("alice", "10.0.0.2"),),
            backup_static={"10.1.0.0/30": (("alice", "10.1.0.2"),)},
        )
        doc = self.doc([["gold", ["default", "bak"]]])
        doc["地址池"][0]["静态"] = [["alice", "10.1.0.2"]]
        doc["地址池"][1]["静态"] = [["alice", "10.0.0.2"]]
        # 标识升序：bak 在 default 前，上面两池按字母赋值后需按标识对齐。
        pools_by_id = {p["标识"]: p for p in doc["地址池"]}
        pools_by_id["bak"]["静态"] = [["alice", "10.1.0.2"]]
        pools_by_id["default"]["静态"] = [["alice", "10.0.0.2"]]
        load(s, doc)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s1"), ("default", "10.0.0.2"))
        # default 静态址被同用户占用，不回落 default 动态，转 bak 静态。
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s2"), ("bak", "10.1.0.2"))
        # 两池静态均占用：继续转下一池，无下一池则 ResourceError。
        with self.assertRaises(ResourceError):
            s.do("k3", "建立", "s3", ("alice", "pw"), 0)

    def test_unbound_and_unlisted_users_use_default_only(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["bak"]]]))
        # bob 未绑定模板：只用 default（bak 不在其候选中）。
        s.pool_fault("f", "注入", "default", 100000, 0)
        with self.assertRaises(ResourceError):
            s.do("k1", "建立", "b1", ("bob", "pw"), 0)
        s.pool_fault("r", "恢复", "default", None, 0)
        s.do("k2", "建立", "b2", ("bob", "pw"), 0)
        self.assertEqual(pool_of(s, "b2"), ("default", "10.0.0.1"))
        # 模板存在但未列入模板地址池：alice 仍只走 default；default 故障时
        # 不回落到任何其他池。
        load(s, self.doc([]))
        s.pool_fault("f2", "注入", "default", 100000, 1)
        with self.assertRaises(ResourceError):
            s.do("k3", "建立", "a0", ("alice", "pw"), 1)

    def test_all_unavailable_resource_error(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        s.pool_fault("d", "注入", "default", 100000, 0)
        s.pool_fault("b", "注入", "bak", 100000, 0)
        with self.assertRaises(ResourceError):
            s.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def test_replay_returns_first_result_without_reselecting(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        # 占满 default，首建立落 bak。
        s.do("a1", "建立", "x1", ("alice", "pw"), 0)
        s.do("a2", "建立", "x2", ("alice", "pw"), 0)
        first = s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s3"), ("bak", "10.1.0.1"))
        # 改变故障态后重放同键：返回首次结果，不重新选址、不重复建会话。
        s.pool_fault("f", "注入", "bak", 100000, 0)
        replay = s.do("k3", "建立", "s3", ("alice", "pw"), 0)
        self.assertEqual(replay, first)
        self.assertEqual(pool_of(s, "s3"), ("bak", "10.1.0.1"))

    def test_failure_leaves_no_partial_state(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        # 认证失败：无会话、无租约、无计费开始事件。
        with self.assertRaises(AuthError):
            s.do("bad", "建立", "s1", ("alice", "nope"), 0)
        self.assertNotIn("s1", s._sessions)
        self.assertEqual(
            [e for e in json.loads(s.accounting_events())["事件"]
             if e["类型"] == "开始"],
            [],
        )
        # 全部池不可用：default/bak 租约表均无残留。
        s.pool_fault("d", "注入", "default", 100000, 0)
        s.pool_fault("b", "注入", "bak", 100000, 0)
        with self.assertRaises(ResourceError):
            s.do("full", "建立", "s2", ("alice", "pw"), 0)
        self.assertNotIn("s2", s._sessions)
        self.assertEqual(s._pools["default"].leases, {})
        self.assertEqual(s._pools["bak"].leases, {})

    def test_batch_atomic_rollback_across_pools(self):
        _auth, s = make(per=10)
        load(s, self.doc([["gold", ["default", "bak"]]]))
        # 首项占 default，次项落 bak，第三项错误口令：原子整批回滚两池租约。
        items = (
            ("s1", "alice", "pw"),
            ("s2", "alice", "pw"),
            ("s3", "alice", "pw"),
            ("s4", "alice", "bad"),
        )
        out = json.loads(s.batch_online("k", items, 0, atomic=True))
        self.assertEqual(out["结果"], "回滚")
        self.assertEqual([i["结果"] for i in out["项目"]],
                         ["回滚", "回滚", "回滚", "AuthError"])
        self.assertEqual(s._pools["default"].leases, {})
        self.assertEqual(s._pools["bak"].leases, {})
        # 回滚截断计费链：无开始事件。
        self.assertFalse(
            [e for e in json.loads(s.accounting_events())["事件"]
             if e["类型"] == "开始"]
        )

    def test_fault_recovery_at_deadline_picks_first_pool(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        s.pool_fault("f", "注入", "default", 100, 0)  # 截至 100
        # 故障中落 bak。
        s.do("k1", "建立", "s1", ("alice", "pw"), 50)
        self.assertEqual(pool_of(s, "s1", 60), ("bak", "10.1.0.1"))
        # 恢复（含同刻）后新建立回首选 default。
        s.do("k2", "建立", "s2", ("alice", "pw"), 100)
        self.assertEqual(pool_of(s, "s2", 110), ("default", "10.0.0.1"))


class CapacitySelectionTest(unittest.TestCase):
    def doc(self, wait=100000):
        doc = config_doc(seq=[["gold", ["default", "bak"]]])
        doc["容量"] = {"队列上限": 1024, "最大等待毫秒": wait,
                       "队满策略": "拒绝"}
        return doc

    def test_immediate_apply_uses_fallback(self):
        _auth, s = make()
        load(s, self.doc())
        s.do("a1", "建立", "x1", ("alice", "pw"), 0)
        s.do("a2", "建立", "x2", ("alice", "pw"), 0)
        out = json.loads(
            s.capacity("c", "申请", "q1", ("alice", "pw", 100000), 0)
        )
        self.assertEqual(out["结果"], "在线")
        self.assertEqual(pool_of(s, "q1"), ("bak", "10.1.0.1"))

    def test_all_unavailable_enqueues_and_promotes_later(self):
        _auth, s = make()
        load(s, self.doc())
        s.pool_fault("d", "注入", "default", 100000, 0)
        s.pool_fault("b", "注入", "bak", 100, 0)
        out = json.loads(
            s.capacity("c1", "申请", "q1", ("alice", "pw", 100000), 0)
        )
        self.assertEqual(out["结果"], "排队")
        # 恢复 bak（default 仍故障）：推进晋升落 bak。
        s.pool_fault("r", "恢复", "bak", None, 100)
        adv = json.loads(s.capacity("c2", "推进", "", None, 100))
        self.assertEqual(adv["变更"], [1])
        self.assertEqual(pool_of(s, "q1", 200), ("bak", "10.1.0.1"))

    def test_still_unavailable_kept_and_does_not_block_later(self):
        # alice 序列 [default, bak]：default 动态耗尽、bak 故障 -> 留队；
        # carol 序列 [third]：third 可用，正常晋升，不被前项阻挡。
        auth = Authenticator(3, 1000)
        for user in ("alice", "bob", "carol"):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 10, 50000,
                     pool=("10.0.0.0/30", (), ()), lease_ms=50000)
        s.add_pool("bak", ("10.1.0.0/30", (), ()))
        s.add_pool("third", ("10.2.0.0/30", (), ()))
        doc = config_doc(
            templates=("gold", "silver"),
            bindings=(("alice", "gold"), ("carol", "silver")),
            pools=("bak", "default", "third"),
            cidrs={"default": "10.0.0.0/30", "bak": "10.1.0.0/30",
                   "third": "10.2.0.0/30"},
            seq=[["gold", ["default", "bak"]], ["silver", ["third"]]],
        )
        doc["容量"] = {"队列上限": 1024, "最大等待毫秒": 100000,
                       "队满策略": "拒绝"}
        load(s, doc)
        # 未绑定用户 bob 占满 default 两动态址。
        s.do("o1", "建立", "o1", ("bob", "pw"), 0)
        s.do("o2", "建立", "o2", ("bob", "pw"), 0)
        s.pool_fault("bf", "注入", "bak", 100000, 0)
        # 两申请入队。
        s.capacity("ca", "申请", "qa", ("alice", "pw", 100000), 0)
        s.capacity("cc", "申请", "qc", ("carol", "pw", 100000), 0)
        adv = json.loads(s.capacity("adv", "推进", "", None, 50))
        # carol 晋升（third），alice 留队。
        self.assertEqual(adv["在线"], 3)
        self.assertEqual(adv["排队"], 1)
        self.assertEqual(pool_of(s, "qc", 60), ("third", "10.2.0.1"))
        # forecast 同口径：alice 等待（首个受阻池 default 为地址耗尽）。
        fc = {i["会话"]: (i["结果"], i["原因"])
              for i in json.loads(s.capacity_forecast(60))["项目"]}
        self.assertEqual(fc["qa"], ("等待", "地址"))

    def test_forecast_fallback_and_reasons(self):
        _auth, s = make()
        load(s, self.doc())
        # 全故障：原因取序列首个受阻池（池故障）。
        s.pool_fault("d", "注入", "default", 100000, 0)
        s.pool_fault("b", "注入", "bak", 100000, 0)
        s.capacity("c1", "申请", "q1", ("alice", "pw", 100000), 0)
        fc = json.loads(s.capacity_forecast(50))
        self.assertEqual(
            [(i["结果"], i["原因"]) for i in fc["项目"]],
            [("等待", "池故障")],
        )
        # default 故障、bak 正常：预测晋升。
        s.pool_fault("r", "恢复", "bak", None, 50)
        fc = json.loads(s.capacity_forecast(50))
        self.assertEqual(
            [(i["结果"], i["原因"]) for i in fc["项目"]],
            [("晋升", "")],
        )

    def test_rebalance_precheck_and_execute_fallback(self):
        _auth, s = make()
        load(s, self.doc())
        s.pool_fault("d", "注入", "default", 100000, 0)
        s.pool_fault("b", "注入", "bak", 100000, 0)
        s.capacity("c1", "申请", "q1", ("alice", "pw", 100000), 0)
        # 恢复 bak（default 仍故障）：预演晋升落 bak。
        s.pool_fault("r", "恢复", "bak", None, 50)
        changes = (("优先级", "gold", 7),)
        pre = json.loads(s.capacity_rebalance("pk", "预检", changes, 50))
        self.assertEqual(pre["晋升"], ["q1"])
        # 预检不改队列。
        self.assertEqual(
            json.loads(s.capacity_stats(50))["排队"], 1
        )
        first = s.capacity_rebalance("ek", "执行", changes, 50)
        exe = json.loads(first)
        self.assertEqual(exe["晋升"], ["q1"])
        self.assertEqual(pool_of(s, "q1", 60), ("bak", "10.1.0.1"))
        # 执行同参重放原字节。
        self.assertEqual(
            s.capacity_rebalance("ek", "执行", changes, 50), first
        )


class HotReloadSemanticsTest(unittest.TestCase):
    def doc(self, seq):
        return config_doc(seq=seq)

    def test_existing_sessions_keep_pool_new_selection_uses_new_seq(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s1"), ("default", "10.0.0.1"))
        load(s, self.doc([["gold", ["bak", "default"]]]))
        s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(pool_of(s, "s1"), ("default", "10.0.0.1"))
        self.assertEqual(pool_of(s, "s2"), ("bak", "10.1.0.1"))

    def test_queued_item_uses_new_sequence_on_advance(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        s.pool_fault("d", "注入", "default", 100000, 0)
        s.pool_fault("b", "注入", "bak", 100000, 0)
        s.capacity("c1", "申请", "q1", ("alice", "pw", 100000), 0)
        # 热加载反转优先序，恢复 bak（default 仍故障）。
        load(s, self.doc([["gold", ["bak", "default"]]]))
        s.pool_fault("r", "恢复", "bak", None, 50)
        s.capacity("adv", "推进", "", None, 50)
        self.assertEqual(pool_of(s, "q1", 60), ("bak", "10.1.0.1"))

    def test_delete_leased_pool_rejected(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        s.do("a1", "建立", "x1", ("alice", "pw"), 0)
        s.do("a2", "建立", "x2", ("alice", "pw"), 0)
        s.do("a3", "建立", "x3", ("alice", "pw"), 0)  # 落 bak
        before = s.export_config()
        doc = self.doc([])
        doc["地址池"] = [
            p for p in doc["地址池"] if p["标识"] != "bak"
        ]
        with self.assertRaises(ResourceError):
            load(s, doc)
        self.assertEqual(s.export_config(), before)

    def test_rollback_restores_sequence(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["default", "bak"]]]))
        load(s, self.doc([["gold", ["bak", "default"]]]))
        out = json.loads(s.rollback_config())
        self.assertEqual(
            out["模板地址池"], [["gold", ["default", "bak"]]]
        )

    def test_explicit_migrate_ignores_fallback_sequence(self):
        _auth, s = make()
        load(s, self.doc([["gold", ["bak", "default"]]]))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 即使序列首选 bak，显式迁移到指定池仍以调用方目标为准。
        out = json.loads(
            s.do("m", "迁移", "s1", ("default", "pw"), 100)
        )
        self.assertEqual(out["新池"] if "新池" in out else out.get("目标池"),
                         "default")
        self.assertEqual(pool_of(s, "s1", 200)[0], "default")


class ObservabilityTest(unittest.TestCase):
    def test_chosen_pool_in_query_stats_accounting_and_checkpoint(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = make(users=("alice",))[1]
        load(s, config_doc(seq=[["gold", ["default", "bak"]]],
                          bindings=(("alice", "gold"),)))
        s.do("a1", "建立", "x1", ("alice", "pw"), 0)
        s.do("a2", "建立", "x2", ("alice", "pw"), 0)
        s.do("a3", "建立", "x3", ("alice", "pw"), 0)   # bak
        # 会话查询。
        self.assertEqual(pool_of(s, "x3"), ("bak", "10.1.0.1"))
        # 池统计：bak 有一租。
        stats = json.loads(s.pool_stats(100))
        leased = {row[0]: row[4] for row in stats["池"]}
        self.assertEqual(leased["bak"], 1)
        # 计费开始事件记实际池。
        events = json.loads(s.accounting_events())["事件"]
        start = {e["会话"]: (e["地址池"], e["地址"])
                 for e in events if e["类型"] == "开始"}
        self.assertEqual(start["x3"], ("bak", "10.1.0.1"))
        # 运行态检查点（clog）与恢复保留池。
        cp = s.clog(100)
        auth2 = Authenticator(3, 1000)
        auth2.add("alice", "pw")
        s2 = Sessions(auth2, 10, 10, 50000,
                      pool=("10.0.0.0/30", (), ()), lease_ms=50000)
        s2.add_pool("bak", ("10.1.0.0/30", (), ()))
        load(s2, config_doc(seq=[["gold", ["default", "bak"]]],
                            bindings=(("alice", "gold"),)))
        s2.creplay(cp)
        self.assertEqual(pool_of(s2, "x3", 200), ("bak", "10.1.0.1"))

    def test_deterministic_bytes(self):
        import subprocess
        doc = config_doc(seq=[["gold", ["default", "bak"]]])
        doc["容量"] = {"队列上限": 1024, "最大等待毫秒": 100000,
                       "队满策略": "拒绝"}
        request = {
            "users": [["alice", "pw"], ["bob", "pw"]],
            "config": doc,
            "requests": [
                {"key": f"k{i}", "op": "建立", "sid": f"s{i}",
                 "args": ["alice", "pw"], "now_ms": 0}
                for i in range(3)
            ],
            "query_ms": 100,
        }
        payload = json.dumps(request, ensure_ascii=False)
        run = lambda: subprocess.run(
            ["python", "access.py", "session-run"], input=payload,
            capture_output=True, text=True,
        )
        r1, r2 = run(), run()
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(r1.stdout, r2.stdout)
        out = json.loads(r1.stdout)
        pools = {item["会话"]: item["池"]
                 for item in out["会话"]["项目"]}
        self.assertEqual(pools, {"s0": "default", "s1": "default",
                                 "s2": "bak"})


if __name__ == "__main__":
    unittest.main()
