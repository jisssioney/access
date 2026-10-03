"""模板地址池：有序候选池选择与后备切换的端到端测试。"""

import hashlib
import io
import json
import sys
import unittest

import access
from access import (
    AuthError,
    Authenticator,
    ResourceError,
    Sessions,
)


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


POOL_CIDR = {
    "default": "10.0.0.0/30",
    "p1": "10.1.0.0/30",
    "p2": "10.2.0.0/30",
    "st": "10.3.0.0/30",
}


def pool_entry(pool_id, cidr=None, reserved=(), static=()):
    return {
        "标识": pool_id,
        "CIDR": cidr if cidr is not None else POOL_CIDR[pool_id],
        "保留": list(reserved),
        "静态": [[user, ip] for user, ip in static],
    }


def template_entry(template_id, limit=0, priority=0):
    return {
        "标识": template_id,
        "限速": 1,
        "突发": 0,
        "配额": 1,
        "周期毫秒": 0,
        "会话上限": limit,
        "排队优先级": priority,
        "超限": "拒绝",
    }


def base_config(pools, templates=(), user_templates=(), template_pools=(),
                total=100, per=10):
    return {
        "版本": 12,
        "IPv6 前缀池": [],
        "模板 IPv6 池": [],
        "会话": {"总数": total, "每用户": per, "空闲毫秒": 100000,
                "租期毫秒": 100000},
        "地址池": pools,
        "模板": [template_entry(t) if isinstance(t, str) else t
                for t in templates],
        "用户模板": [list(pair) for pair in user_templates],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 1000,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [[tid, list(seq)] for tid, seq in template_pools],
    }


USERS = ("alice", "bob", "carol", "dave", "erin", "frank")


def make_sessions(users=USERS):
    auth = Authenticator(3, 10 ** 9)
    for user in users:
        auth.add(user, "pw")
    # /30 每池恰两动态址 .1/.2。
    return Sessions(auth, 100, 10, 100000,
                    pool=("10.0.0.0/30", (), ()), lease_ms=100000)


def load(s, doc):
    s.load_config(compact(doc))


def loc(s, sid):
    session = s._sessions[sid]
    return session["pool"], session["ip"]


def add_backup_pools(s, static=()):
    s.add_pool("p1", ("10.1.0.0/30", (), ()))
    s.add_pool("p2", ("10.2.0.0/30", (), ()))
    s.add_pool("st", ("10.3.0.0/30", (), tuple(static)))


def four_pool_config(static=(), sequence=("st", "p1", "p2", "default")):
    return base_config(
        pools=[
            pool_entry("default"),
            pool_entry("p1"),
            pool_entry("p2"),
            pool_entry("st", static=static),
        ],
        templates=("gold",),
        user_templates=(("alice", "gold"),),
        template_pools=(("gold", sequence),),
    )


# /30 可用址 .1/.2；alice 在 st 的专属静态址取 .1，此时 st 动态仅剩 .2。
ST_STATIC_IP = "10.3.0.1"
ST_STATIC_INT = 0x0A030001


class ConfigV11ModelTest(unittest.TestCase):
    def test_export_shape_key_order_and_empty_default(self):
        s = make_sessions()
        doc = json.loads(s.export_config())
        self.assertEqual(doc["版本"], 12)
        self.assertEqual(
            list(doc),
            ["版本", "会话", "地址池", "模板", "用户模板", "容量", "认证",
             "模板地址池", "IPv6 前缀池", "模板 IPv6 池"],
        )
        self.assertEqual(doc["模板地址池"], [])

    def test_roundtrip_preserves_section(self):
        s = make_sessions()
        add_backup_pools(s)
        load(s, four_pool_config())
        out = s.export_config()
        self.assertEqual(s.load_config(out), out)
        self.assertEqual(
            json.loads(out)["模板地址池"],
            [["gold", ["st", "p1", "p2", "default"]]],
        )

    def test_section_sorting_and_sequence_order(self):
        s = make_sessions()
        add_backup_pools(s)
        doc = four_pool_config()
        doc["模板"].append(template_entry("silver"))
        # 未按模板标识升序即非法。
        doc["模板地址池"] = [["silver", ["p2"]], ["gold", ["p1"]]]
        with self.assertRaises(ValueError):
            load(s, doc)
        # 升序后可加载；池序列的内部次序原样保留（不排序）。
        doc["模板地址池"] = [["gold", ["p2", "p1"]], ["silver", ["p2"]]]
        load(s, doc)
        self.assertEqual(
            json.loads(s.export_config())["模板地址池"],
            [["gold", ["p2", "p1"]], ["silver", ["p2"]]],
        )

    def test_value_errors(self):
        s = make_sessions()
        add_backup_pools(s)

        def bad(mutate):
            doc = four_pool_config()
            mutate(doc)
            with self.assertRaises(ValueError, msg=compact(doc)):
                load(s, doc)

        bad(lambda d: d.update({"模板地址池": {}}))
        bad(lambda d: d.update({"模板地址池": None}))
        bad(lambda d: d.update({"模板地址池": [["gold"]]}))
        bad(lambda d: d.update({"模板地址池": [["gold", ["p1"], 1]]}))
        bad(lambda d: d.update({"模板地址池": [[1, ["p1"]]]}))
        bad(lambda d: d.update({"模板地址池": [["go\x00ld", ["p1"]]]}))
        bad(lambda d: d.update({"模板地址池": [["nosuch", ["p1"]]]}))
        bad(lambda d: d.update({
            "模板地址池": [["gold", ["p1"]], ["gold", ["p2"]]]}))
        bad(lambda d: d.update({"模板地址池": [["gold", []]]}))
        bad(lambda d: d.update({"模板地址池": [["gold", ["p1"] * 33]]}))
        bad(lambda d: d.update({"模板地址池": [["gold", [1]]]}))
        bad(lambda d: d.update({"模板地址池": [["gold", ["p1", "p1"]]]}))
        bad(lambda d: d.update({"模板地址池": [["gold", ["nosuch"]]]}))

    def test_tuple_entry_rejected_by_parser(self):
        # 直接以 Python tuple 喂解析器（JSON 路径只会产生 list）。
        from access import _parse_config_doc
        doc = four_pool_config()
        doc["模板地址池"] = [("gold", ["p1"])]
        with self.assertRaises(ValueError):
            _parse_config_doc(doc, None)

    def test_sequence_of_32_pools_allowed(self):
        s = make_sessions()
        ids = []
        for i in range(32):
            pid = f"q{i:02d}"
            ids.append(pid)
            s.add_pool(pid, (f"10.{i}.0.0/30", (), ()))
        doc = four_pool_config()
        doc["地址池"] = [pool_entry("default")] + [
            pool_entry(pid, f"10.{i}.0.0/30") for i, pid in enumerate(ids)
        ]
        doc["模板地址池"] = [["gold", ids]]
        load(s, doc)
        self.assertEqual(
            len(json.loads(s.export_config())["模板地址池"][0][1]), 32
        )

    def test_v11_requires_exact_keys(self):
        s = make_sessions()
        doc = base_config(pools=[pool_entry("default")])
        del doc["模板地址池"]
        with self.assertRaises(ValueError):
            load(s, doc)
        doc2 = base_config(pools=[pool_entry("default")])
        doc2["多余"] = 1
        with self.assertRaises(ValueError):
            load(s, doc2)
        # v12 要求恰含两个新节；缺一节即键集不符。
        doc3 = base_config(pools=[pool_entry("default")])
        del doc3["IPv6 前缀池"]
        with self.assertRaises(ValueError):
            load(s, doc3)
        doc4 = base_config(pools=[pool_entry("default")])
        doc4["版本"] = 13
        with self.assertRaises(ValueError):
            load(s, doc4)

    def test_upgrade_v1_to_v11_fills_empty_section(self):
        s = make_sessions()
        v1 = json.dumps({
            "版本": 1,
            "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 100000,
                     "租期毫秒": 100000},
            "地址池": {"CIDR": "10.0.0.0/30", "保留": [], "静态": []},
        }, ensure_ascii=False)
        envelope = json.loads(s.upgrade_config(v1))
        self.assertEqual(
            (envelope["源版本"], envelope["目标版本"], envelope["改变"]),
            (1, 12, True),
        )
        cfg = envelope["配置"]
        self.assertEqual(cfg["版本"], 12)
        self.assertEqual(cfg["模板地址池"], [])
        self.assertEqual(list(cfg)[-1], "模板 IPv6 池")
        canonical = compact(cfg)
        self.assertEqual(
            envelope["摘要"],
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    def test_upgrade_v10_to_v11_fills_empty(self):
        s = make_sessions()
        doc = json.loads(s.export_config())
        doc["版本"] = 10
        del doc["模板地址池"]
        del doc["IPv6 前缀池"]
        del doc["模板 IPv6 池"]
        envelope = json.loads(s.upgrade_config(compact(doc)))
        self.assertEqual(envelope["目标版本"], 12)
        self.assertIs(envelope["改变"], True)
        self.assertEqual(envelope["配置"]["模板地址池"], [])
        self.assertEqual(envelope["配置"]["IPv6 前缀池"], [])

    def test_canonical_encoding_required_in_envelope(self):
        s = make_sessions()
        add_backup_pools(s)
        doc = four_pool_config()
        doc["模板"].append(template_entry("silver"))
        doc["模板地址池"] = [
            ["gold", ["p1", "p2"]], ["silver", ["p2"]],
        ]
        envelope = json.loads(s.upgrade_config(compact(doc)))
        # 模板地址池外层须按模板标识升序；颠倒即非规范，升级包复核须拒绝
        # （解析会按 gold/silver 重排，与文档原编码不一致）。
        bad = json.loads(json.dumps(envelope))
        bad["配置"]["模板地址池"] = list(reversed(bad["配置"]["模板地址池"]))
        bad["摘要"] = hashlib.sha256(
            compact(bad["配置"]).encode("utf-8")
        ).hexdigest()
        with self.assertRaises(ValueError):
            s.load_config(compact(bad))

    def test_failed_commit_changes_nothing(self):
        s = make_sessions()
        add_backup_pools(s)
        load(s, four_pool_config(static=(("alice", ST_STATIC_IP),)))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before = s.export_config()
        doc = json.loads(before)
        doc["模板地址池"] = [["gold", ["nosuch"]]]
        with self.assertRaises(ValueError):
            load(s, doc)
        self.assertEqual(s.export_config(), before)
        self.assertEqual(loc(s, "s1")[0], "st")


class OrderedSelectionTest(unittest.TestCase):
    def setUp(self):
        self.s = make_sessions()
        add_backup_pools(self.s, static=(("alice", ST_STATIC_IP),))
        load(self.s, four_pool_config(static=(("alice", ST_STATIC_IP),)))

    def test_first_pool_static_preferred(self):
        # 首选 st：取 alice 专属静态址 .1，而非其他池的更小动态址。
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(loc(self.s, "s1"), ("st", ST_STATIC_INT))

    def test_fallback_when_static_occupied(self):
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # st 静态址被同用户另一会话占用，静态占用不回落同池动态址 → p1。
        self.s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(loc(self.s, "s2"), ("p1", 0x0A010001))

    def test_fallback_skips_dynamic_exhausted_pools(self):
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # st 静态
        self.s.do("k2", "建立", "s2", ("alice", "pw"), 0)  # p1 .1
        self.s.do("k3", "建立", "s3", ("alice", "pw"), 0)  # p1 .2
        self.s.do("k4", "建立", "s4", ("alice", "pw"), 0)  # p2 .1
        self.assertEqual(loc(self.s, "s4"), ("p2", 0x0A020001))
        self.s.do("k5", "建立", "s5", ("alice", "pw"), 0)  # p2 .2
        self.s.do("k6", "建立", "s6", ("alice", "pw"), 0)  # default .1
        self.assertEqual(loc(self.s, "s6"), ("default", 0x0A000001))

    def test_fallback_skips_pool_fault_drill(self):
        self.s.pool_fault("f1", "注入", "st", 10 ** 9, 0)
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(loc(self.s, "s1"), ("p1", 0x0A010001))
        self.s.pool_fault("f2", "注入", "p1", 10 ** 9, 0)
        self.s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(loc(self.s, "s2"), ("p2", 0x0A020001))

    def test_all_candidates_unavailable_raises(self):
        # st 静态址占用；st 动态 .2 因静态占用不可回落；占满 p1/p2/default。
        self.s.do("a", "建立", "s0", ("alice", "pw"), 0)   # st 静态
        for i, sid in enumerate(("p", "q", "r", "t", "u", "v")):
            self.s.do(f"k{i}", "建立", sid, ("alice", "pw"), 0)
        # 依次用掉 p1.1 p1.2 p2.1 p2.2 default.1 default.2。
        self.assertEqual(loc(self.s, "v"), ("default", 0x0A000002))
        with self.assertRaises(ResourceError):
            self.s.do("kz", "建立", "sz", ("alice", "pw"), 0)

    def test_unbound_user_uses_default_only(self):
        # bob 未绑定：default 两址占满即失败，不切换。
        self.s.do("b1", "建立", "b1", ("bob", "pw"), 0)
        self.s.do("b2", "建立", "b2", ("carol", "pw"), 0)
        with self.assertRaises(ResourceError):
            self.s.do("b3", "建立", "b3", ("dave", "pw"), 0)

    def test_bound_template_without_sequence_uses_default(self):
        doc = json.loads(self.s.export_config())
        doc["模板"].append(template_entry("silver"))
        doc["用户模板"].append(["carol", "silver"])
        load(self.s, doc)
        self.s.do("c1", "建立", "c1", ("carol", "pw"), 0)
        self.assertEqual(loc(self.s, "c1")[0], "default")

    def test_failure_leaves_nothing(self):
        accounts_before = len(self.s._account_events)
        leases_before = {
            pid: dict(pool.leases) for pid, pool in self.s._pools.items()
        }
        with self.assertRaises(AuthError):
            self.s.do("bad", "建立", "x9", ("alice", "wrong"), 0)
        self.assertNotIn("x9", self.s._sessions)
        self.assertEqual(len(self.s._account_events), accounts_before)
        for pid, pool in self.s._pools.items():
            self.assertEqual(pool.leases, leases_before[pid])

    def test_idempotent_replay_does_not_reselect(self):
        self.s.pool_fault("f1", "注入", "st", 10 ** 9, 0)
        first = self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # p1
        self.assertEqual(loc(self.s, "s1"), ("p1", 0x0A010001))
        # 恢复 st 并令 p1 耗尽，重放仍返回首果、不重选。
        self.s.pool_fault("f2", "恢复", "st", None, 1)
        self.s.pool_fault("f3", "注入", "p1", 10 ** 9, 1)
        replay = self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(replay, first)
        self.assertEqual(loc(self.s, "s1"), ("p1", 0x0A010001))


class BatchAndCapacitySelectionTest(unittest.TestCase):
    def setUp(self):
        self.s = make_sessions()
        add_backup_pools(self.s)
        load(self.s, four_pool_config())

    def fill(self, pool_id, key_prefix, sid_prefix, n):
        """以 alice 会话占满指定池的前 n 个动态址。"""
        for i in range(n):
            sid = f"{sid_prefix}{i}"
            self.s.do(f"{key_prefix}{i}", "建立", sid, ("alice", "pw"), 0)
            self.assertEqual(loc(self.s, sid)[0], pool_id)

    def test_batch_online_fallback(self):
        self.fill("st", "a", "a", 2)
        out = json.loads(self.s.batch_online(
            "bk",
            (("n1", "alice", "pw"), ("n2", "alice", "pw"),
             ("n3", "alice", "pw")),
            0,
        ))
        self.assertEqual(out["结果"], "提交")
        self.assertEqual(loc(self.s, "n1")[0], "p1")
        self.assertEqual(loc(self.s, "n2")[0], "p1")
        self.assertEqual(loc(self.s, "n3")[0], "p2")

    def test_batch_online_atomic_rollback(self):
        # 占满全部 4 池共 8 动态址。
        self.fill("st", "s", "s", 2)
        self.fill("p1", "p", "p", 2)
        self.fill("p2", "q", "q", 2)
        self.fill("default", "d", "d", 2)
        bad = json.loads(self.s.batch_online(
            "roll",
            (("y1", "alice", "pw"), ("y2", "bob", "pw")),
            0, atomic=True,
        ))
        self.assertEqual(bad["结果"], "回滚")
        self.assertNotIn("y1", self.s._sessions)
        self.assertNotIn("y2", self.s._sessions)

    def test_capacity_apply_immediate_fallback(self):
        self.fill("st", "a", "a", 2)
        out = json.loads(self.s.capacity(
            "cap1", "申请", "q0", ("alice", "pw", 10000), 0))
        self.assertEqual(out["结果"], "在线")
        self.assertEqual(loc(self.s, "q0")[0], "p1")

    def test_advance_promotes_into_newly_available_preferred_pool(self):
        self.fill("st", "e", "e", 2)
        self.fill("p1", "f", "f", 2)
        self.fill("p2", "g", "g", 2)
        # st/p1/p2 满；default 有空但序列含它。先占 default 令 qa 排队。
        self.fill("default", "h", "h", 2)
        qa = json.loads(self.s.capacity(
            "qa", "申请", "qa", ("alice", "pw", 10000), 0))
        self.assertEqual(qa["结果"], "排队")
        # 释放首选 st 的一址，推进应把 qa 晋升回 st（确定性首选）。
        self.s.do("off0", "下线", "e0", None, 1)
        adv = json.loads(self.s.capacity("adv", "推进", "", None, 1))
        self.assertEqual(adv["排队"], 0)
        self.assertEqual(loc(self.s, "qa"), ("st", 0x0A030001))

    def test_advance_skips_unavailable_item_without_blocking_next(self):
        # 占满 st/p1/p2/default，使 alice 无址可排队；bob 未绑定，仅 default。
        self.fill("st", "e", "e", 2)
        self.fill("p1", "f", "f", 2)
        self.fill("p2", "g", "g", 2)
        self.s.do("h0", "建立", "h0", ("carol", "pw"), 0)  # default .1
        # qa(alice)：四候选池此刻 default 仅剩 .2，实际可取 → 直接在线，先占掉。
        self.s.capacity("qa", "申请", "qa", ("alice", "pw", 10000), 0)
        self.assertEqual(loc(self.s, "qa"), ("default", 0x0A000002))
        # 现在四池全满：alice 再申请排队；bob 申请也排队（default 满）。
        self.s.capacity("qa2", "申请", "qa2", ("alice", "pw", 10000), 0)
        self.s.capacity("qb", "申请", "qb", ("bob", "pw", 10000), 0)
        # 释放 default 一址：两个队项都以 default 为候选（bob 仅 default；
        # alice 序列含 default）。按有效优先级/入队序，qa2 先入队先晋升，
        # qb 仍留队——不被前项阻塞规则反向影响（顺序确定）。
        self.s.do("offh", "下线", "h0", None, 1)
        adv = json.loads(self.s.capacity("adv", "推进", "", None, 1))
        self.assertEqual(adv["排队"], 1)
        self.assertIn("qa2", self.s._sessions)
        self.assertEqual(loc(self.s, "qa2")[0], "default")
        self.assertIn("qb", self.s._capacity_queue)

    def test_queue_item_stays_when_all_unavailable(self):
        self.fill("st", "e", "e", 2)
        self.fill("p1", "f", "f", 2)
        self.fill("p2", "g", "g", 2)
        self.fill("default", "h", "h", 2)
        qa = json.loads(self.s.capacity(
            "qa", "申请", "qa", ("alice", "pw", 10000), 0))
        self.assertEqual(qa["结果"], "排队")
        adv = json.loads(self.s.capacity("adv", "推进", "", None, 1))
        self.assertEqual(adv["排队"], 1)
        self.assertIn("qa", self.s._capacity_queue)
        self.assertNotIn("qa", self.s._account_active)

    def test_forecast_promotes_into_backup_pool(self):
        # 占满全部四池后 qa 只能排队；预测时刻取租期/期限同刻到期（100000），
        # 老化释放占位址，qa 应预测晋升回首选 st。
        self.fill("st", "e", "e", 2)
        self.fill("p1", "f", "f", 2)
        self.fill("p2", "g", "g", 2)
        self.fill("default", "h", "h", 2)
        self.s.capacity("qa", "申请", "qa", ("alice", "pw", 10 ** 9), 0)
        forecast = json.loads(self.s.capacity_forecast(100000))
        item = forecast["项目"][0]
        self.assertEqual(item["会话"], "qa")
        self.assertEqual(item["结果"], "晋升")
        self.assertEqual(item["原因"], "")
        # 预测只读，不真的建立。
        self.assertNotIn("qa", self.s._sessions)

    def test_forecast_wait_reason_address(self):
        self.fill("st", "e", "e", 2)
        self.fill("p1", "f", "f", 2)
        self.fill("p2", "g", "g", 2)
        self.fill("default", "h", "h", 2)
        self.s.capacity("qa", "申请", "qa", ("alice", "pw", 10000), 0)
        forecast = json.loads(self.s.capacity_forecast(0))
        self.assertEqual(forecast["项目"][0]["结果"], "等待")
        self.assertEqual(forecast["项目"][0]["原因"], "地址")

    def test_rebalance_preview_and_execute(self):
        # carol 未绑定模板，仅能用 default；占满 default 后其申请排队。
        self.s.do("c0", "建立", "c0", ("carol", "pw"), 0)
        self.s.do("c1", "建立", "c1", ("carol", "pw"), 0)
        self.assertEqual(loc(self.s, "c0")[0], "default")
        queued = json.loads(self.s.capacity(
            "qa", "申请", "qa", ("carol", "pw", 10000), 0))
        self.assertEqual(queued["结果"], "排队")
        changes = (("绑定", "carol", "gold"),)
        # 预检：候选绑定下 carol 按 gold 序列（st 首选）可晋升到 st，不改态。
        pre = json.loads(self.s.capacity_rebalance(
            "pre", "预检", changes, 0))
        self.assertEqual(pre["晋升"], ["qa"])
        self.assertIn("qa", self.s._capacity_queue)
        # 执行：原子绑定并把 qa 晋升落库到 st。
        exe = json.loads(self.s.capacity_rebalance(
            "exe", "执行", changes, 0))
        self.assertEqual(exe["晋升"], ["qa"])
        self.assertEqual(loc(self.s, "qa"), ("st", 0x0A030001))
        self.assertEqual(self.s._user_templates.get("carol"), "gold")


class HotReloadAndExplicitOpsTest(unittest.TestCase):
    def setUp(self):
        self.s = make_sessions()
        add_backup_pools(self.s)
        load(self.s, four_pool_config())

    def test_hot_reload_keeps_existing_session_pool(self):
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # st .1
        doc = json.loads(self.s.export_config())
        doc["模板地址池"] = [["gold", ["p2"]]]
        load(self.s, doc)
        self.assertEqual(loc(self.s, "s1"), ("st", 0x0A030001))
        self.s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(loc(self.s, "s2"), ("p2", 0x0A020001))

    def test_rollback_restores_sequence(self):
        doc = json.loads(self.s.export_config())
        doc["模板地址池"] = [["gold", ["p2"]]]
        load(self.s, doc)
        rolled = json.loads(self.s.rollback_config())
        self.assertEqual(
            rolled["模板地址池"], [["gold", ["st", "p1", "p2", "default"]]]
        )
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(loc(self.s, "s1")[0], "st")

    def test_reload_applies_to_unpromoted_queue_items(self):
        for pid, pre in (("st", "e"), ("p1", "f"), ("p2", "g"),
                        ("default", "h")):
            for i in range(2):
                sid = f"{pre}{i}"
                self.s.do(f"{pre}k{i}", "建立", sid, ("alice", "pw"), 0)
                assert loc(self.s, sid)[0] == pid
        self.s.capacity("qa", "申请", "qa", ("alice", "pw", 10000), 0)
        # 热加载把序列缩为仅剩 default（仍满），再释放 default 一址后推进。
        doc = json.loads(self.s.export_config())
        doc["模板地址池"] = [["gold", ["default"]]]
        load(self.s, doc)
        self.s.do("offh", "下线", "h0", None, 1)
        self.s.capacity("adv", "推进", "", None, 1)
        self.assertEqual(loc(self.s, "qa"), ("default", 0x0A000001))

    def test_explicit_migrate_ignores_sequence(self):
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # st
        out = json.loads(self.s.do("m1", "迁移", "s1", ("p2", "pw"), 0))
        self.assertEqual(out["目标池"], "p2")
        self.assertEqual(loc(self.s, "s1")[0], "p2")

    def test_resume_uses_only_specified_pool(self):
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.s.do("su", "挂起", "s1", None, 0)
        out = json.loads(self.s.do(
            "r1", "恢复", "s1", ("default", "pw"), 1))
        self.assertEqual(out["池"], "default")
        self.assertEqual(loc(self.s, "s1")[0], "default")

    def test_delete_pool_with_lease_rejected(self):
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        doc = json.loads(self.s.export_config())
        doc["地址池"] = [p for p in doc["地址池"] if p["标识"] != "st"]
        doc["模板地址池"] = [["gold", ["p1"]]]
        before = self.s.export_config()
        with self.assertRaises(ResourceError):
            load(self.s, doc)
        self.assertEqual(self.s.export_config(), before)
        self.assertEqual(loc(self.s, "s1")[0], "st")


class ObservabilityAndDeterminismTest(unittest.TestCase):
    def _build(self, with_static=False):
        s = make_sessions()
        static = (("alice", ST_STATIC_IP),) if with_static else ()
        add_backup_pools(s, static=static)
        load(s, four_pool_config(static=static))
        return s

    def test_pool_stats_report_selected_pool(self):
        s = self._build()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        rows = {row[0]: row for row in json.loads(s.pool_stats(0))["池"]}
        # 行序：标识、容量、保留、静态、租用、动态空闲；s1 在 st。
        self.assertEqual(rows["st"][4], 1)
        self.assertEqual(rows["p1"][4], 0)

    def test_session_query_reports_selected_pool(self):
        s = self._build()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        row = next(r for r in json.loads(s.sessions(0))["项目"]
                   if r["会话"] == "s1")
        self.assertEqual(row["池"], "st")

    def test_accounting_start_event_carries_pool(self):
        s = self._build()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        start = next(e for e in
                     json.loads(s.accounting_events())["事件"]
                     if e["会话"] == "s1")
        self.assertEqual(start["地址池"], "st")

    def test_service_checkpoint_roundtrip(self):
        s = self._build()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # st .1
        checkpoint = s.service_checkpoint(0)
        # 目标实例须加载同一配置（配置摘要一致）。
        fresh = make_sessions()
        add_backup_pools(fresh)
        load(fresh, four_pool_config())
        fresh.service_restore("restore-1", checkpoint)
        self.assertEqual(loc(fresh, "s1"), ("st", 0x0A030001))
        # 恢复后选择行为一致：st 下一动态址 .2。
        fresh.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(loc(fresh, "s2"), ("st", 0x0A030002))

    def test_byte_identical_outputs(self):
        a, b = self._build(), self._build()
        for s in (a, b):
            s.do("k1", "建立", "s1", ("alice", "pw"), 0)
            s.do("k2", "建立", "s2", ("alice", "pw"), 0)
        self.assertEqual(a.export_config(), b.export_config())
        self.assertEqual(a.pool_stats(0), b.pool_stats(0))
        self.assertEqual(a.service_checkpoint(0), b.service_checkpoint(0))


class SessionRunCliTest(unittest.TestCase):
    def _run(self, doc):
        raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv = ["access.py", "session-run"]
        sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        sys.stdout, sys.stderr = out, err
        try:
            code = access.main(sys.argv)
        finally:
            out.flush()
            err.flush()
            stdout, stderr = out.buffer.getvalue(), err.buffer.getvalue()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        return code, stdout, stderr

    def test_session_run_v11_template_pool_selection(self):
        config = base_config(
            pools=[pool_entry("default"), pool_entry("p1")],
            templates=("gold",),
            user_templates=(("alice", "gold"),),
            template_pools=(("gold", ("p1", "default")),),
        )
        doc = {
            "users": [["alice", "pw"], ["bob", "pw"]],
            "config": config,
            "requests": [
                {"key": "k1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
            ],
            "query_ms": 0,
        }
        code, stdout, stderr = self._run(doc)
        self.assertEqual(code, 0, stderr)
        result = json.loads(stdout)
        self.assertTrue(result["项目"][0]["结果"])
        session = next(r for r in result["会话"]["项目"]
                       if r["会话"] == "s1")
        self.assertEqual(session["池"], "p1")
        self.assertEqual(session["地址"], "10.1.0.1")

    def test_session_run_rejects_bad_template_pool_section(self):
        config = base_config(
            pools=[pool_entry("default"), pool_entry("p1")],
            templates=("gold",),
            user_templates=(("alice", "gold"),),
            template_pools=(("gold", ("nosuch",)),),
        )
        doc = {
            "users": [["alice", "pw"], ["bob", "pw"]],
            "config": config,
            "requests": [
                {"key": "k1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
            ],
            "query_ms": 0,
        }
        code, _stdout, stderr = self._run(doc)
        self.assertEqual(code, 2)
        envelope = json.loads(stderr)
        self.assertEqual(envelope["类型"], "ValueError")


if __name__ == "__main__":
    unittest.main()
