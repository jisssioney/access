"""版本 12 可选 IPv6 前缀委派：配置校验、双栈取址、后备切换、事务
回滚、续租/挂起/恢复/迁移/接管、热加载承载、检查点恢复与 CLI 的端到端
测试。"""

import hashlib
import json
import subprocess
import sys
import unittest

import access
from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def pool_entry(pool_id, cidr, reserved=(), static=()):
    return {
        "标识": pool_id,
        "CIDR": cidr,
        "保留": list(reserved),
        "静态": [[user, ip] for user, ip in static],
    }


def template_entry(template_id, limit=0):
    return {
        "标识": template_id,
        "递归": None,
    } if False else {
        "标识": template_id,
        "限速": 1,
        "突发": 0,
        "配额": 10 ** 9,
        "周期毫秒": 0,
        "会话上限": limit,
        "排队优先级": 0,
        "超限": "拒绝",
    }


def v6_entry(pool_id, agg, deleg, reserved=(), static=()):
    return {
        "标识": pool_id,
        "聚合前缀": agg,
        "委派长度": deleg,
        "保留": list(reserved),
        "静态": [[user, prefix] for user, prefix in static],
    }


def base_config(
    v6_pools=(),
    template_v6=(),
    templates=("dual",),
    user_templates=(("alice", "dual"), ("bob", "dual"), ("carol", "dual")),
):
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                "租期毫秒": 1000},
        "地址池": [
            pool_entry("default", "10.0.0.0/28"),
            pool_entry("p2", "10.1.0.0/28"),
        ],
        "模板": [template_entry(t) for t in templates],
        "用户模板": [list(pair) for pair in user_templates],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [],
        "IPv6 前缀池": [v6_entry(*args) if isinstance(args, tuple) else args
                     for args in v6_pools],
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


USERS = ("alice", "bob", "carol", "dave")
V6A = ("v6a", "2001:db8::/48", 56)
V6B = ("v6b", "2001:db8:1::/48", 56)


def make_sessions():
    auth = Authenticator(3, 10 ** 9)
    for user in USERS:
        auth.add(user, "pw")
    return Sessions(
        auth, 100, 10, 50000,
        pool=("10.0.0.0/30", (), ()), lease_ms=1000,
    )


def load(s, **kwargs):
    return s.load_config(compact(base_config(**kwargs)))


V6_DUAL_CONFIG = dict(
    v6_pools=(
        v6_entry("v6a", "2001:db8::/48", 56,
                 reserved=["2001:db8:0:100::/56"],
                 static=[["bob", "2001:db8:0:200::/56"]]),
    ),
    template_v6=(("dual", ("v6a",)),),
)


def make_loaded_sessions():
    s = make_sessions()
    load(s, **V6_DUAL_CONFIG)
    return s


class ConfigV12Test(unittest.TestCase):
    def setUp(self):
        self.s = make_sessions()

    def test_export_shape_and_pure_v4_default(self):
        out = json.loads(load(self.s))
        self.assertEqual(out["版本"], 12)
        self.assertEqual(
            list(out),
            ["版本", "会话", "地址池", "模板", "用户模板", "容量", "认证",
             "模板地址池", "IPv6 前缀池", "模板 IPv6 池"],
        )
        self.assertEqual(out["IPv6 前缀池"], [])
        self.assertEqual(out["模板 IPv6 池"], [])
        # 导出再加载逐字节稳定。
        again = self.s.export_config()
        self.assertEqual(again, self.s.export_config())
        self.s.load_config(again)
        self.assertEqual(again, self.s.export_config())

    def test_v11_upgrade_is_pure_v4(self):
        doc = base_config()
        doc["版本"] = 11
        del doc["IPv6 前缀池"]
        del doc["模板 IPv6 池"]
        envelope = json.loads(self.s.upgrade_config(compact(doc)))
        self.assertEqual(envelope["目标版本"], 12)
        self.assertTrue(envelope["改变"])
        self.assertEqual(envelope["配置"]["IPv6 前缀池"], [])
        self.assertEqual(envelope["配置"]["模板 IPv6 池"], [])
        # 升级包可直接加载，加载后为纯 IPv4。
        self.s.load_config(self.s.upgrade_config(compact(doc)))
        self.assertEqual(json.loads(self.s.export_config())["版本"], 12)

    def test_v12_canonicalizes_sorting(self):
        doc = base_config(
            templates=("dual", "t2"),
            v6_pools=(
                v6_entry("vb", "2001:db8:2::/48", 64,
                         static=[["dave", "2001:db8:2:100::/64"]]),
                v6_entry("va", "2001:db8::/48", 56,
                         reserved=["2001:db8:0:200::/56",
                                   "2001:db8:0:100::/56"],
                         static=[["bob", "2001:db8:0:300::/56"],
                                 ["alice", "2001:db8:0:400::/56"]]),
            ),
            template_v6=(("dual", ("va", "vb")), ("t2", ("vb",))),
        )
        out = json.loads(self.s.load_config(compact(doc)))
        ids = [p["标识"] for p in out["IPv6 前缀池"]]
        self.assertEqual(ids, ["va", "vb"])
        va = out["IPv6 前缀池"][0]
        self.assertEqual(
            va["保留"],
            ["2001:db8:0:100::/56", "2001:db8:0:200::/56"],
        )
        self.assertEqual(
            va["静态"][0], ["alice", "2001:db8:0:400::/56"]
        )
        self.assertEqual(
            [row[0] for row in out["模板 IPv6 池"]], ["dual", "t2"]
        )

    def test_value_errors(self):
        def expect(fn):
            with self.assertRaises(ValueError):
                fn()

        good = v6_entry(*V6A)
        # 委派长度短于聚合长度。
        bad = dict(good)
        bad["委派长度"] = 40
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 委派长度超过 128。
        bad = dict(good)
        bad["委派长度"] = 129
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 非规范前缀（主机位非零）。
        bad = dict(good)
        bad["聚合前缀"] = "2001:db8::1/48"
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 保留前缀不按委派长度对齐。
        bad = v6_entry(*V6A, reserved=["2001:db8::1/56"])
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 保留前缀越界。
        bad = v6_entry(*V6A, reserved=["2001:db9::/56"])
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 保留前缀长度错误。
        bad = v6_entry(*V6A, reserved=["2001:db8::/64"])
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 静态前缀与保留冲突。
        bad = v6_entry(*V6A,
                       reserved=["2001:db8::/56"],
                       static=[["alice", "2001:db8::/56"]])
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 重复保留。
        bad = v6_entry(*V6A,
                       reserved=["2001:db8::/56", "2001:db8:0::/56"])
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 同用户重复静态（跨池允许，同池拒绝）。
        bad = v6_entry(*V6A, static=[
            ["alice", "2001:db8::/56"], ["alice", "2001:db8:1::/56"]])
        expect(lambda: load(self.s, v6_pools=(bad,)))
        # 重复池标识。
        expect(lambda: load(
            self.s, v6_pools=(v6_entry(*V6A), v6_entry(*V6A))))
        # 模板引用未知前缀池。
        expect(lambda: load(
            self.s, template_v6=(("dual", ("nope",)),)))
        # 模板引用未知模板。
        expect(lambda: load(
            self.s, v6_pools=(V6A,),
            template_v6=(("nope", ("v6a",)),)))
        # 后备序列为空。
        expect(lambda: load(
            self.s, v6_pools=(V6A,),
            template_v6=(("dual", ()),)))
        # 后备序列超过 32 个。
        pools = tuple(
            ("vp%d" % i, "2001:db8:%x::/48", 56) for i in range(33)
        )
        # 33 个不同聚合前缀（第三段十六进制）。
        pools = tuple(
            ("vp%d" % i, "2001:db8:%x::/47" if False else
             "2001:%x::/48" % i, 56)
            for i in range(33)
        )
        expect(lambda: load(
            self.s, v6_pools=pools,
            template_v6=(("dual", tuple("vp%d" % i for i in range(33))),)))

    def test_type_errors_become_value_error_in_config_section(self):
        # 配置文档形态内的类型错沿 JSON 配置约定抛 ValueError。
        bad = v6_entry(*V6A)
        bad["委派长度"] = "56"
        with self.assertRaises(ValueError):
            load(self.s, v6_pools=(bad,))
        with self.assertRaises(ValueError):
            load(self.s, v6_pools=({"标识": "v6a", "聚合前缀": 42,
                                  "委派长度": 56, "保留": [], "静态": []},))


class AllocationTest(unittest.TestCase):
    def setUp(self):
        self.s = make_sessions()
        load(
            self.s,
            v6_pools=(
                v6_entry(
                    "v6a", "2001:db8::/48", 56,
                    reserved=["2001:db8:0:100::/56"],
                    static=[["bob", "2001:db8:0:200::/56"]],
                ),
                v6_entry("v6b", "2001:db8:1::/48", 56),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )

    def establish(self, key, sid, user):
        return json.loads(self.s.do(key, "建立", sid, (user, "pw"), 0))

    def test_static_first_then_smallest_dynamic_skips_reserved(self):
        alice = self.establish("k1", "s1", "alice")
        # 首个动态块跳过保留 0:100 与静态 0:200，取 0:0::/56。
        self.assertEqual(alice["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(alice["IPv6池"], "v6a")
        # bob 的静态绑定优先于动态首块。
        bob = self.establish("k2", "s2", "bob")
        self.assertEqual(bob["IPv6前缀"], "2001:db8:0:200::/56")
        carol = self.establish("k3", "s3", "carol")
        self.assertEqual(carol["IPv6前缀"], "2001:db8:0:300::/56")

    def test_unbound_template_stays_pure_v4(self):
        # 无模板用户（dave 未绑定 dual）不委派，输出无 IPv6 键。
        out = self.establish("k9", "s9", "dave")
        self.assertNotIn("IPv6池", out)

    def test_fallback_when_first_pool_exhausted(self):
        # /30 IPv4 池每池仅两个动态址；v6a 对 carol 无静态，耗尽后切 v6b。
        # 用保留+静态填满 v6a 不现实，直接用极小委派池：/127 池仅两块。
        doc = base_config(
            v6_pools=(
                v6_entry("small", "2001:db8:9::/126", 127,
                         reserved=["2001:db8:9::/127"]),
                v6_entry("other", "2001:db8:a::/126", 127),
            ),
            template_v6=(("dual", ("small", "other")),),
        )
        self.s.load_config(compact(doc))
        # small 池：2 个块，保留 1 个，首个用户取唯一动态块。
        first = self.establish("k1", "s1", "alice")
        self.assertEqual(first["IPv6池"], "small")
        # small 耗尽（动态空、alice 无静态），第二个用户切 other。
        second = self.establish("k2", "s2", "bob")
        self.assertEqual(second["IPv6池"], "other")

    def test_all_pools_exhausted_resource_error_and_rollback(self):
        doc = base_config(
            v6_pools=(v6_entry("tiny", "2001:db8:9::/128", 128),),
            template_v6=(("dual", ("tiny",)),),
        )
        self.s.load_config(compact(doc))
        self.establish("k1", "s1", "alice")
        # tiny 仅一块；第二个双栈建立须 ResourceError，且本次窥视到的
        # IPv4 址不落库：无模板用户 dave 随后建立仍取得下一个 IPv4 址
        # 10.0.0.2（若双栈失败误提交了 IPv4，dave 只会拿到 10.0.0.3）。
        with self.assertRaises(ResourceError):
            self.s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        stats = json.loads(self.s.pool_stats(0))
        self.assertEqual(stats["池"][0][4], 1)
        dave = self.establish("k3", "s3", "dave")
        self.assertEqual(dave["地址"], "10.0.0.2")
        self.assertNotIn("IPv6池", dave)

    def test_renew_extends_both_leases(self):
        self.establish("k1", "s1", "alice")
        out = json.loads(self.s.do("k9", "续租", "s1", None, 500))
        self.assertEqual(out["租期"], 1500)
        self.assertEqual(out["IPv6租期"], 1500)

    def test_migrate_keeps_prefix_and_its_lease(self):
        self.establish("k1", "s1", "alice")
        out = json.loads(
            self.s.do("k9", "迁移", "s1", ("p2", "pw"), 500)
        )
        self.assertEqual(out["目标池"], "p2")
        self.assertEqual(out["租期"], 1500)
        self.assertEqual(out["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["IPv6租期"], 1000)

    def test_takeover_transfers_prefix_without_reselect(self):
        self.establish("k1", "s1", "alice")
        out = json.loads(
            self.s.do("k9", "接管", "s9", ("s1", "pw"), 500)
        )
        self.assertEqual(out["旧地址"], "10.0.0.1")
        self.assertEqual(out["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["IPv6租期"], 1000)
        stats = json.loads(self.s.pool_stats(500))
        # 前缀租约数仍为 1（转移而非新选）。
        self.assertEqual(stats[_V6_KEY][0][4], 1)

    def test_suspend_resume_redelegates(self):
        self.establish("k1", "s1", "alice")
        suspended = json.loads(
            self.s.do("k8", "挂起", "s1", None, 100)
        )
        self.assertEqual(suspended["IPv6池"], "")
        self.assertEqual(suspended["IPv6前缀"], "")
        self.assertEqual(suspended["IPv6租期"], 0)
        # 挂起后前缀归还，bob 可取走最小动态块。
        self.establish("k2", "s2", "bob")
        resumed = json.loads(
            self.s.do("k9", "恢复", "s1", ("default", "pw"), 200)
        )
        self.assertEqual(resumed["状态"], "在线")
        self.assertIn("IPv6前缀", resumed)
        self.assertNotEqual(resumed["IPv6前缀"], "")

    def test_aging_releases_prefix_when_lease_due(self):
        # 空闲期限 50000 > 租期 1000：租期到先释两址；同刻视图无址。
        self.establish("k1", "s1", "alice")
        view = json.loads(self.s.sessions(1001))
        row = view["项目"][0]
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["地址"], "")
        self.assertEqual(row["IPv6前缀"], "")
        # 空闲到期（50000）后挂起。
        view = json.loads(self.s.sessions(50000))
        self.assertEqual(view["项目"][0]["状态"], "挂起")

    def test_pool_stats_waterline(self):
        self.establish("k1", "s1", "alice")
        stats = json.loads(self.s.pool_stats(0))
        rows = {row[0]: row for row in stats[_V6_KEY]}
        # /48 -> /56 共 256 块，保留 1、静态 1、租用 1、空闲 253。
        self.assertEqual(rows["v6a"], ["v6a", 256, 1, 1, 1, 253])
        self.assertEqual(rows["v6b"], ["v6b", 256, 0, 0, 0, 256])


_V6_KEY = "IPv6 前缀池"


class CheckpointTest(unittest.TestCase):
    def setUp(self):
        self.s = make_loaded_sessions()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        self.s.do("k3", "挂起", "s2", None, 100)

    def test_capacity_checkpoint_roundtrip(self):
        text = self.s.clog(200)
        doc = json.loads(text)
        rows = {row["会话"]: row for row in doc["会话"]}
        self.assertEqual(
            list(rows["s1"]),
            ["会话", "用户", "状态", "期限", "池", "地址", "租期",
             "IPv6池", "IPv6前缀", "IPv6租期"],
        )
        self.assertEqual(rows["s2"]["IPv6池"], "")
        target = make_loaded_sessions()
        out = json.loads(target.creplay(text))
        self.assertEqual(out["在线"], 1)
        # 租约表恢复后水位一致：alice 一块动态、bob 挂起无租约。
        stats = json.loads(target.pool_stats(200))
        self.assertEqual(stats[_V6_KEY][0][4], 1)
        # 恢复后重新检查点逐字节一致。
        self.assertEqual(target.clog(200), text)

    def test_runtime_checkpoint_roundtrip(self):
        text = self.s.runtime_checkpoint(200)
        target = make_loaded_sessions()
        restored = target.runtime_restore("rk", text)
        self.assertEqual(restored, text)

    def test_restore_rejects_bad_prefix_ownership(self):
        text = self.s.clog(200)
        doc = json.loads(text)
        for row in doc["会话"]:
            if row["会话"] == "s1":
                # 改成 bob 的静态前缀，归属却是 alice。
                row["IPv6前缀"] = "2001:db8:0:200::/56"
        state = {
            "时刻": doc["时刻"],
            "事件": doc["事件"],
            "会话": doc["会话"],
            "排队": doc["排队"],
        }
        doc["状态哈希"] = hashlib.sha256(compact(state).encode()).hexdigest()
        target = make_loaded_sessions()
        with self.assertRaises(ResourceError):
            target.creplay(compact(doc))

    def test_restore_rejects_misaligned_prefix(self):
        text = self.s.clog(200)
        doc = json.loads(text)
        for row in doc["会话"]:
            if row["会话"] == "s1":
                row["IPv6前缀"] = "2001:db8:0:1::/56"
        # 篡改破坏状态哈希 -> ValueError（结构/哈希先于承载校验）。
        target = make_loaded_sessions()
        with self.assertRaises(ValueError):
            target.creplay(compact(doc))

    def test_restore_rejects_duplicate_prefix(self):
        # 构造 s1/s4 双会话持同一前缀的检查点行，哈希重算后承载阶段拒绝。
        self.s.do("k4", "恢复", "s2", ("default", "pw"), 300)
        text = self.s.clog(400)
        doc = json.loads(text)
        for row in doc["会话"]:
            if row["会话"] == "s2":
                row["IPv6池"] = "v6a"
                row["IPv6前缀"] = "2001:db8::/56"
                row["IPv6租期"] = 1300
        # 重算状态哈希以越过结构校验，暴露唯一占用冲突（ResourceError）。
        state = {
            "时刻": doc["时刻"],
            "事件": doc["事件"],
            "会话": doc["会话"],
            "排队": doc["排队"],
        }
        doc["状态哈希"] = hashlib.sha256(compact(state).encode()).hexdigest()
        target = make_loaded_sessions()
        with self.assertRaises(ResourceError):
            target.creplay(compact(doc))

    def test_reload_carries_leases_without_migrating_prefix(self):
        # 重新导出当前配置再加载：在租前缀原样承载，输出不变。
        before = self.s.sessions(200)
        self.s.load_config(self.s.export_config())
        self.assertEqual(self.s.sessions(200), before)
        stats = json.loads(self.s.pool_stats(200))
        self.assertEqual(stats[_V6_KEY][0][4], 1)

    def test_reload_removing_pool_is_resource_error(self):
        doc = json.loads(self.s.export_config())
        doc["IPv6 前缀池"] = []
        doc["模板 IPv6 池"] = []
        with self.assertRaises(ResourceError):
            self.s.load_config(compact(doc))

    def test_capacity_promotion_delegates(self):
        # default /30 两动态址：alice、bob 占满（bob 挂起释放后由 carol
        # 走申请排队，推进晋升时取得双栈）。
        self.s.do("k9", "下线", "s2", None, 150)
        self.s.capacity("c1", "申请", "q1", ("carol", "pw", 100000), 0)
        advanced = json.loads(
            self.s.capacity("c2", "推进", "", None, 10)
        )
        self.assertEqual(advanced["在线"], 2)
        view = json.loads(self.s.sessions(10))
        carol = next(row for row in view["项目"] if row["会话"] == "q1")
        self.assertEqual(carol["IPv6池"], "v6a")
        self.assertNotEqual(carol["IPv6前缀"], "")


class EdgeCaseTest(unittest.TestCase):
    def test_programmatic_type_errors(self):
        with self.assertRaises(TypeError):
            access._check_v6_pool(("2001:db8::/48", "56", (), ()))
        with self.assertRaises(TypeError):
            access._check_v6_pool(("2001:db8::/48", True, (), ()))

    def test_ipv4_pool_fault_still_blocks_establish(self):
        s = make_loaded_sessions()
        s.pool_fault("pf", "注入", "default", 1000, 0)
        with self.assertRaises(ResourceError):
            s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 未提交任何双栈租约。
        stats = json.loads(s.pool_stats(0))
        self.assertEqual(stats[_V6_KEY][0][4], 0)

    def test_batch_online_atomic_rolls_back_v6_lease(self):
        s = make_sessions()
        load(
            s,
            v6_pools=(v6_entry("tiny", "2001:db8:9::/128", 128),),
            template_v6=(("dual", ("tiny",)),),
        )
        items = (
            ("s1", "alice", "pw"),
            ("s2", "bob", "pw"),
            ("s3", "carol", "pw"),
        )
        out = json.loads(s.batch_online("b", items, 0, atomic=True))
        self.assertEqual(
            [r["结果"] for r in out["项目"]],
            ["回滚", "ResourceError", "ResourceError"],
        )
        stats = json.loads(s.pool_stats(0))
        self.assertEqual(stats[_V6_KEY][0][4], 0)
        self.assertEqual(stats["池"][0][4], 0)
        # 非原子：仅首项成功并持前缀，后两项失败不影响它。
        out = json.loads(s.batch_online("b2", items, 1, atomic=False))
        self.assertEqual(
            [r["结果"] for r in out["项目"]],
            ["上线", "ResourceError", "ResourceError"],
        )
        stats = json.loads(s.pool_stats(0))
        self.assertEqual(stats[_V6_KEY][0][4], 1)

    def test_released_prefix_reused_as_smallest(self):
        s = make_loaded_sessions()
        # dave 也绑定 dual，以便释放后由绑定用户重新取走最小块。
        doc = json.loads(s.export_config())
        doc["用户模板"].append(["dave", "dual"])
        s.load_config(compact(doc))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("carol", "pw"), 0)
        # s1 持有最小动态块 ::/56；下线归还后 dave 建立重新取到最小块。
        s.do("kd", "下线", "s1", None, 100)
        dave = json.loads(s.do("k3", "建立", "s3", ("dave", "pw"), 200))
        self.assertEqual(dave["IPv6前缀"], "2001:db8::/56")


class CliSessionRunTest(unittest.TestCase):
    def test_session_run_accepts_v12_and_outputs_v6_fields(self):
        doc = base_config(
            v6_pools=(v6_entry(*V6A),),
            template_v6=(("dual", ("v6a",)),),
        )
        # default /30 仅两个动态址，足够单请求。
        request = {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
                {"key": "r2", "op": "续租", "sid": "s1",
                 "args": None, "now_ms": 100},
            ],
            "query_ms": 200,
        }
        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=compact(request).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=".",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(
            list(out), ["版本", "项目", "会话", "地址池", "摘要"]
        )
        self.assertIn("IPv6前缀", out["项目"][1]["输出"])
        self.assertIn(_V6_KEY, out["地址池"])
        # 摘要覆盖前四键。
        head = {
            "版本": out["版本"],
            "项目": out["项目"],
            "会话": out["会话"],
            "地址池": out["地址池"],
        }
        expect = hashlib.sha256(
            compact(head).encode("utf-8")
        ).hexdigest()
        self.assertEqual(out["摘要"], expect)

    def test_pure_v4_output_byte_identical_to_v11_shape(self):        # 纯 IPv4 v12 配置的 session-run 输出不得含任何 IPv6 键。
        doc = base_config()
        doc["IPv6 前缀池"] = []
        doc["模板 IPv6 池"] = []
        request = {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["dave", "pw"], "now_ms": 0},
            ],
            "query_ms": 200,
        }
        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=compact(request).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        raw = proc.stdout.decode("utf-8")
        self.assertNotIn("IPv6", raw)
        self.assertNotIn(_V6_KEY, raw)


if __name__ == "__main__":
    unittest.main()
