"""可恢复 IPv6 前缀池排空 prefix_pool_drain / prefix_pool_drain_status 的测试。

覆盖：参数校验与异常次序（TypeError/ValueError/KeyError/StateError）、开始
幂等与目标顺序冲突、推进的老化/码点序/limit/静态优先/保留不可动态/最小动态
前缀/目标后备/排空目标跳过/ResourceError 项/原子换前缀/仅重置 IPv6 租期
（IPv4 池址租期、空闲期限、QoS 账本与计费累计不变）、取消不迁回、只读状态、
同键同参逐字节重放与异参 ValueError、批量审计链（操作“前缀池排空”）与合规
链投影、源池在建立/恢复/容量晋升/显式前缀迁移各通道的新委派阻断、配置删池
ResourceError 原子保持、运行态/服务检查点（无 v6 排空逐字节一致、含排空
往返、IPv4+IPv6 双节、旧检查点无 v6 节视为空、恢复失败原子）。"""

import json
import unittest

from access import (
    Authenticator,
    Sessions,
    ResourceError,
    StateError,
)

V6_KEY = "IPv6 前缀池"


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def pool_entry(pool_id, cidr):
    return {"标识": pool_id, "CIDR": cidr, "保留": [], "静态": []}


def template_entry(template_id):
    return {
        "标识": template_id,
        "限速": 1,
        "突发": 0,
        "配额": 10 ** 9,
        "周期毫秒": 0,
        "会话上限": 0,
        "排队优先级": 0,
        "超限": "拒绝",
    }


def v6_entry(pool_id, agg, deleg=56, reserved=(), static=()):
    return {
        "标识": pool_id,
        "聚合前缀": agg,
        "委派长度": deleg,
        "保留": list(reserved),
        "静态": [[user, prefix] for user, prefix in static],
    }


USERS = ("alice", "bob", "carol")


def config(v6_pools, template_v6, bound=USERS, idle_ms=50000, lease_ms=1000):
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": idle_ms,
                "租期毫秒": lease_ms},
        "地址池": [pool_entry("default", "10.0.0.0/28")],
        "模板": [template_entry("dual")],
        "用户模板": [[user, "dual"] for user in bound],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [],
        V6_KEY: list(v6_pools),
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


def make():
    auth = Authenticator(3, 10 ** 9)
    for user in USERS:
        auth.add(user, "pw")
    s = Sessions(
        auth, 100, 10, 50000,
        pool=("10.0.0.0/30", (), ()), lease_ms=1000,
    )
    return auth, s


TWO = dict(
    v6_pools=(
        v6_entry("v6a", "2001:db8::/48"),
        v6_entry("v6b", "2001:db8:1::/48"),
    ),
    template_v6=(("dual", ("v6a", "v6b")),),
)


def load(s, **kwargs):
    cfg = config(**kwargs) if kwargs else config(**TWO)
    s.load_config(compact(cfg))


def parse(text):
    return json.loads(text)


def establish(s, key, sid, user="alice", now=0):
    return s.do(key, "建立", sid, (user, "pw"), now)


def loaded_session(s, sid="a"):
    return parse(s.sessions(0))["项目"][0] if sid == "a" else {
        r["会话"]: r for r in parse(s.sessions(0))["项目"]
    }[sid]


class PrefixDrainParamTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        load(self.s)

    def test_key_credential_checked_first(self):
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                self.s.prefix_pool_drain(
                    bad, "开始", "v6a", ("v6b",), 0, 10
                )
        with self.assertRaises(ValueError):
            self.s.prefix_pool_drain(
                "", "开始", "v6a", ("v6b",), 0, 10
            )

    def test_type_errors(self):
        s = self.s
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", 5, "v6a", ("v6b",), 0, 10)
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", "开始", 9, ("v6b",), 0, 10)
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", "开始", "v6a", ["v6b"], 0, 10)
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", "开始", "v6a", (9,), 0, 10)
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6b",), "x", 10)
        for bad_now in (1.5, "0", None, True, False):
            with self.assertRaises(TypeError):
                s.prefix_pool_drain(
                    "kn" + str(bad_now), "开始", "v6a", ("v6b",),
                    bad_now, 10,
                )
        for bad_limit in (1.5, "5", None, True, False):
            with self.assertRaises(TypeError):
                s.prefix_pool_drain(
                    "kl" + str(bad_limit), "开始", "v6a", ("v6b",),
                    0, bad_limit,
                )

    def test_value_errors(self):
        s = self.s
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "冻结", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", (), 0, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6b", "v6b"), 0, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6a",), 0, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6b",), -1, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6b",), 0, 0)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6b",), 0, 1001)

    def test_unknown_pools(self):
        s = self.s
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "nope", ("v6b",), 0, 10)
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "v6a", ("nope",), 0, 10)
        # 未知 IPv4 池名同样 KeyError（域为前缀池）。
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "default", ("v6b",), 0, 10)
        # 源池先于目标池判定。
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "nope", ("alsonope",), 0, 10)

    def test_param_failure_does_not_cache_or_drain(self):
        s = self.s
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "开始", "v6a", (), 0, 10)
        self.assertEqual(parse(s.batch_audit(0, 1000))["事件"], [])
        with self.assertRaises(StateError):
            s.prefix_pool_drain_status("v6a", 0)
        # 参数错不占 key：同 key 改正参数后成功。
        out = s.prefix_pool_drain("k", "开始", "v6a", ("v6b",), 0, 10)
        self.assertEqual(parse(out)["状态"], "排空中")

    def test_status_validation(self):
        s = self.s
        with self.assertRaises(TypeError):
            s.prefix_pool_drain_status("v6a", True)
        with self.assertRaises(KeyError):
            s.prefix_pool_drain_status("nope", 0)
        with self.assertRaises(StateError):
            s.prefix_pool_drain_status("v6b", 0)


class PrefixDrainStartTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        load(self.s)

    def test_start_shape_and_block_establish(self):
        s = self.s
        establish(s, "e1", "a", "alice")
        out = parse(s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10))
        self.assertEqual(list(out), ["时刻", "源池", "状态", "剩余", "项目"])
        self.assertEqual(
            out,
            {"时刻": 0, "源池": "v6a", "状态": "排空中", "剩余": 1, "项目": []},
        )
        raw = s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw)
        # 源池不再承接建立：后备序 [v6a,v6b] 跳过 v6a，新会话落在 v6b。
        out2 = parse(establish(s, "e2", "b", "bob"))
        self.assertEqual(out2["IPv6池"], "v6b")

    def test_start_idempotent_same_order_any_key(self):
        s = self.s
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b",), 0, 10)
        out2 = s.prefix_pool_drain("d2", "开始", "v6a", ("v6b",), 5, 10)
        self.assertEqual(parse(out2)["状态"], "排空中")

    def test_start_different_order_state_error(self):
        s = self.s
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
                v6_entry("v6c", "2001:db8:2::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
        )
        s.load_config(compact(cfg))
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("d2", "开始", "v6a", ("v6c", "v6b"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("d3", "开始", "v6a", ("v6b",), 0, 10)

    def test_start_preserves_sessions(self):
        s = self.s
        establish(s, "e1", "a", "alice")
        before = s.sessions(0)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        self.assertEqual(s.sessions(0), before)


class PrefixDrainAdvanceTest(unittest.TestCase):
    def test_codepoint_order_limit_and_lease_reset(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "z", "alice")
        establish(s, "e2", "a", "bob")
        establish(s, "e3", "m", "carol")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 500, 2))
        self.assertEqual(
            [(i["会话"], i["目标池"], i["结果"]) for i in out["项目"]],
            [("a", "v6b", "迁移"), ("m", "v6b", "迁移")],
        )
        self.assertEqual(out["状态"], "排空中")
        self.assertEqual(out["剩余"], 1)
        rows = {r["会话"]: r for r in parse(s.sessions(500))["项目"]}
        # 已迁：仅换 v6 池/前缀、IPv6 租期重置为 500+1000。
        self.assertEqual(rows["a"]["IPv6池"], "v6b")
        self.assertEqual(rows["a"]["IPv6租期"], 1500)
        self.assertEqual(rows["m"]["IPv6池"], "v6b")
        # IPv4 池/地址/租期与空闲期限不变。
        self.assertEqual(rows["a"]["池"], "default")
        self.assertEqual(rows["a"]["租期"], 1000)
        self.assertEqual(rows["a"]["期限"], 50000)
        # 未处理项保持源池与原 v6 租期。
        self.assertEqual(rows["z"]["IPv6池"], "v6a")
        self.assertEqual(rows["z"]["IPv6租期"], 1000)
        # 第二批排空剩余 z。
        out2 = parse(s.prefix_pool_drain("k2", "推进", "v6a", ("v6b",), 500, 10))
        self.assertEqual([i["会话"] for i in out2["项目"]], ["z"])
        self.assertEqual(out2["状态"], "已排空")
        self.assertEqual(out2["剩余"], 0)

    def test_drained_still_blocks_new_delegations(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "已排空"
        )
        out = parse(establish(s, "e2", "b", "bob"))
        self.assertEqual(out["IPv6池"], "v6b")

    def test_advance_without_start_state_error(self):
        _auth, s = make()
        load(s)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)

    def test_advance_wrong_target_order_state_error(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
                v6_entry("v6c", "2001:db8:2::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
        )
        s.load_config(compact(cfg))
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6c", "v6b"), 0, 10)

    def test_static_binding_priority(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry(
                    "v6b", "2001:db8:1::/48",
                    static=(("alice", "2001:db8:1:700::/56"),),
                ),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10))
        self.assertEqual(
            {i["会话"]: i["目标池"] for i in out["项目"]},
            {"a": "v6b", "b": "v6b"},
        )
        sess = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        # a(alice) 取按 /56 对齐的静态块 7，b(bob) 取最小动态块 0。
        self.assertEqual(sess["a"]["IPv6前缀"], "2001:db8:1:700::/56")
        self.assertEqual(sess["b"]["IPv6前缀"], "2001:db8:1::/56")

    def test_reserved_prefix_never_dynamically_allocated(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry(
                    "v6b", "2001:db8:1::/48",
                    reserved=("2001:db8:1::/56",),
                ),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        row = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}["a"]
        # 最小可派动态前缀跳过保留块 ::/56，取 0:100::/56 之后的更小者——
        # 保留 ::/56 后首个为 2001:db8:1:100::/56? 实际次块为
        # 2001:db8:1:100::/56（块步长 0x100）。
        self.assertEqual(row["IPv6前缀"], "2001:db8:1:100::/56")

    def test_target_fallback_order(self):
        _auth, s = make()
        # v6c 仅一个可委派块（/48 委派 /48），v6b 充裕；目标序 v6c 优先。
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6c", "2001:db8:2::/48", deleg=48),
                v6_entry("v6b", "2001:db8:1::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6c", "v6b"), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6c", "v6b"), 0, 10))
        mapping = {i["会话"]: i["目标池"] for i in out["项目"]}
        # 码点序 a 先占 v6c 独块，b 回退 v6b。
        self.assertEqual(mapping["a"], "v6c")
        self.assertEqual(mapping["b"], "v6b")

    def test_draining_target_skipped(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
                v6_entry("v6c", "2001:db8:2::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        # v6b 自身排空中：v6a->[v6b,v6c] 跳过 v6b 取 v6c。
        s.prefix_pool_drain("d2", "开始", "v6b", ("v6c",), 0, 10)
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b", "v6c"), 0, 10))
        self.assertEqual(out["项目"][0]["目标池"], "v6c")

    def test_no_double_lease_after_success(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        # 源池租用清空、目标池唯一租用；无双重占用。
        self.assertEqual(len(s._v6_pools["v6a"].leases), 0)
        self.assertEqual(len(s._v6_pools["v6b"].leases), 1)
        for pool in s._v6_pools.values():
            self.assertEqual(len(pool.leases), len(set(pool.leases)))
        row = parse(s.sessions(0))["项目"][0]
        self.assertEqual(row["IPv6池"], "v6b")
        # IPv4 租约不受影响。
        self.assertEqual(len(s._pools["default"].leases), 1)

    def test_advance_ages_first(self):
        # v6 租期 1000、空闲 50000：t=2000 推进时老化先释 v6 前缀（会话仍
        # 在线），无有效承载会话 -> 已排空，不迁移。
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 2000, 10))
        self.assertEqual(out["项目"], [])
        self.assertEqual(out["状态"], "已排空")
        row = parse(s.sessions(2000))["项目"][0]
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["IPv6池"], "")
        self.assertEqual(row["IPv6前缀"], "")
        # IPv4 未到期（租期同为 1000，亦到期单独释出），地址同样空。
        self.assertEqual(row["池"], "")

    def test_item_failure_does_not_block_others(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6c", "2001:db8:2::/48", deleg=48),
                v6_entry("v6b", "2001:db8:1::/48", deleg=48),
            ),
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        establish(s, "e3", "m", "carol")
        # 两目标各一块，第三项无承载 -> ResourceError，前两项成功。
        s.prefix_pool_drain("d", "开始", "v6a", ("v6c", "v6b"), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6c", "v6b"), 0, 10))
        results = [i["结果"] for i in out["项目"]]
        self.assertEqual(results.count("迁移"), 2)
        self.assertEqual(results.count("ResourceError"), 1)
        failed = [i for i in out["项目"] if i["结果"] == "ResourceError"][0]
        self.assertEqual(failed["目标池"], "")
        self.assertEqual(out["剩余"], 1)
        self.assertEqual(out["状态"], "排空中")
        # 失败项前缀与租期不变。
        rows = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        self.assertEqual(rows["m"]["IPv6池"], "v6a")
        self.assertEqual(rows["m"]["IPv6租期"], 1000)

    def test_ipv4_and_billing_untouched(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        # 限速 1（千分字节令牌桶容 1000）：1 字节在 t=0 必然通过、累计 1。
        self.assertEqual(parse(s.meter("m", "a", 1, 0))["结果"], "通过")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 500, 10)
        row = parse(s.sessions(500))["项目"][0]
        # IPv4 池/地址/租期不变。
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["地址"], "10.0.0.1")
        self.assertEqual(row["租期"], 1000)
        # 计费不切分、累计保持（仅建立的开始，中间累计 1）。
        types = [e["类型"] for e in parse(s.accounting_events(0, 100))["事件"]]
        self.assertEqual(types, ["开始"])
        interim = parse(s.accounting_interim("i", "a", 600))
        self.assertEqual(interim["累计字节"], 1)


class PrefixDrainCancelTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        load(self.s)
        establish(self.s, "e1", "a", "alice")

    def test_cancel_restores_selection_no_moveback(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10))
        self.assertEqual(out["状态"], "已取消")
        # 取消后 v6a 恢复承接新委派（后备序首选 v6a）。
        new = parse(establish(s, "e2", "b", "bob"))
        self.assertEqual(new["IPv6池"], "v6a")
        # 已迁出会话不迁回。
        rows = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        self.assertEqual(rows["a"]["IPv6池"], "v6b")
        with self.assertRaises(StateError):
            s.prefix_pool_drain_status("v6a", 0)

    def test_cancel_without_start_state_error(self):
        with self.assertRaises(StateError):
            self.s.prefix_pool_drain("c", "取消", "v6b", ("v6a",), 0, 10)

    def test_cancel_wrong_targets_state_error(self):
        s = self.s
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
                v6_entry("v6c", "2001:db8:2::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
        )
        s.load_config(compact(cfg))
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("c", "取消", "v6a", ("v6c", "v6b"), 0, 10)


class PrefixDrainStatusTest(unittest.TestCase):
    def test_status_read_only_does_not_age(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        # v6 租期 1000，t=2000 只读：不老化、按 now_ms 视图计有效承载 -> 0，
        # 但租约表保持原状。
        out = parse(s.prefix_pool_drain_status("v6a", 2000))
        self.assertEqual(out, {"源池": "v6a", "状态": "排空中", "剩余": 0})
        self.assertEqual(parse(s.prefix_pool_drain_status("v6a", 0))["剩余"], 1)
        self.assertEqual(len(s._v6_pools["v6a"].leases), 1)


class PrefixDrainReplayTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        load(self.s)
        establish(self.s, "e1", "a", "alice")
        establish(self.s, "e2", "b", "bob")

    def test_same_key_same_params_byte_identical(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        first = s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        replay = s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        self.assertEqual(replay, first)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 9999, 10)

    def test_diff_params_value_error(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "取消", "v6a", ("v6b",), 0, 10)

    def test_replay_does_not_change_state(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        # a 已迁出，b 仍在 v6a；同参重放不得再迁 b。
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        rows = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        self.assertEqual(rows["a"]["IPv6池"], "v6b")
        self.assertEqual(rows["b"]["IPv6池"], "v6a")


class PrefixDrainAuditTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        load(self.s)
        establish(self.s, "e1", "a", "alice")
        establish(self.s, "e2", "b", "bob")

    def test_batch_chain_and_replay(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)  # 重放
        events = parse(s.batch_audit(0, 1000))["事件"]
        # 开始 1 条，首调 2 条、重放 2 条。
        self.assertEqual(len(events), 5)
        ops = {(e["操作"], e["原子"]) for e in events}
        self.assertEqual(ops, {("前缀池排空", False)})
        self.assertEqual(events[0]["会话"], "v6a")
        self.assertEqual(events[0]["结果"], "排空中")
        self.assertEqual(events[0]["原序号"], 0)
        first_seqs = {e["会话"]: e["序号"] for e in events[1:3]}
        for ev in events[3:]:
            self.assertEqual(ev["结果"], "重放")
            self.assertEqual(ev["原序号"], first_seqs[ev["会话"]])
        prev = "0" * 64
        for ev in events:
            self.assertEqual(ev["前哈希"], prev)
            prev = ev["哈希"]

    def test_projected_to_compliance_chain(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        events = parse(s.compliance_events(0, 1000))["事件"]
        batch = [e for e in events if e["来源"] == "批量"]
        self.assertTrue(batch)
        payload = parse(batch[0]["载荷"])
        self.assertEqual(payload["操作"], "前缀池排空")

    def test_cancel_event(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10)
        events = parse(s.batch_audit(0, 1000))["事件"]
        self.assertEqual([e["结果"] for e in events], ["排空中", "已取消"])
        self.assertTrue(all(e["会话"] == "v6a" for e in events))

    def test_batch_audit_restore_accepts_events(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        page = s.batch_audit(0, 1000)
        _auth2, s2 = make()
        load(s2)
        res = parse(s2.batch_audit_restore("r", page))
        self.assertEqual(res["追加"], 3)
        self.assertEqual(
            parse(s2.batch_audit_restore("r", page))["追加"], 3
        )


class PrefixDrainBlockTest(unittest.TestCase):
    def test_resume_skips_draining_source(self):
        _auth, s = make()
        # 两前缀池但模板后备仅 v6a：v6a 排空中后恢复取不到前缀（不回落未配置
        # 的 v6b）-> ResourceError。
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
            ),
            template_v6=(("dual", ("v6a",)),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        s.do("su", "挂起", "a", None, 0)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ResourceError):
            s.do("r", "恢复", "a", ("default", "pw"), 0)
        # 取消后恢复成功（仍仅委派 v6a）。
        s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10)
        out = parse(s.do("r2", "恢复", "a", ("default", "pw"), 0))
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(out["IPv6池"], "v6a")

    def test_explicit_v6_migrate_into_draining_blocked(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")  # 落在 v6a
        # 目标 v6b 进入排空（源 v6b 无承载会话亦可开始）。
        s.prefix_pool_drain("d", "开始", "v6b", ("v6a",), 0, 10)
        with self.assertRaises(ResourceError):
            s.do("mv", "前缀迁移", "a", ("v6b", "pw"), 0)
        # 取消后迁移成功（前缀迁移返回键为 目标IPv6池）。
        s.prefix_pool_drain("c", "取消", "v6b", ("v6a",), 0, 10)
        out = parse(s.do("mv2", "前缀迁移", "a", ("v6b", "pw"), 0))
        self.assertEqual(out["目标IPv6池"], "v6b")

    def test_capacity_promotion_skips_draining(self):
        _auth, s = make()
        # v6a 仅一个可委派块（/48 委派 /48），模板后备仅 v6a；a 占着该块，
        # v6a 排空中后 b 既无空闲块又不能取 v6a，推进不得晋升。
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48", deleg=48),
                v6_entry("v6b", "2001:db8:1::/48"),
            ),
            template_v6=(("dual", ("v6a",)),),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.capacity("q", "申请", "b", ("bob", "pw", 1000000), 0)
        s.do("off", "下线", "a", None, 0)
        out = parse(s.capacity("adv", "推进", "", None, 0))
        self.assertEqual(out["在线"], 0)
        self.assertEqual(out["排队"], 1)


class PrefixDrainConfigGuardTest(unittest.TestCase):
    def _cfg_without(self, s, pool_id):
        cfg = json.loads(s.export_config())
        cfg[V6_KEY] = [p for p in cfg[V6_KEY] if p["标识"] != pool_id]
        # 模板 IPv6 池引用须同步摘除，否则先触发引用 ValueError。
        cfg["模板 IPv6 池"] = [
            [tid, [pid for pid in seq if pid != pool_id]]
            for tid, seq in cfg["模板 IPv6 池"]
        ]
        return compact(cfg)

    def test_delete_target_pool_resource_error_atomic(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        rev_before = s.config_revision()
        with self.assertRaises(ResourceError):
            s.load_config(self._cfg_without(s, "v6b"))
        self.assertIn("v6b", s._v6_pools)
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )
        self.assertEqual(s.config_revision(), rev_before)

    def test_delete_source_pool_resource_error(self):
        _auth, s = make()
        load(s)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ResourceError):
            s.load_config(self._cfg_without(s, "v6a"))
        self.assertIn("v6a", s._v6_pools)

    def test_delete_unrelated_pool_ok(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
                v6_entry("v6x", "2001:db8:9::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        s.load_config(compact(cfg))
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cfg = json.loads(s.export_config())
        cfg[V6_KEY] = [p for p in cfg[V6_KEY] if p["标识"] != "v6x"]
        s.load_config(compact(cfg))
        self.assertNotIn("v6x", s._v6_pools)
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )


class PrefixDrainCheckpointTest(unittest.TestCase):
    def _fresh(self, s):
        _auth2, s2 = make()
        s2.load_config(s.export_config())
        return s2

    def test_no_drain_byte_identical_and_restore_as_none(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)), ["版本", "时刻", "容量", "配额", "摘要"]
        )
        s2 = self._fresh(s)
        s2.runtime_restore("r", cp)
        with self.assertRaises(StateError):
            s2.prefix_pool_drain_status("v6a", 0)

    def test_v6_drain_roundtrip(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)),
            ["版本", "时刻", "容量", "配额", "IPv6排空", "摘要"],
        )
        s2 = self._fresh(s)
        out = json.loads(s2.runtime_restore("r", cp))
        self.assertEqual(
            out["IPv6排空"],
            [{"源池": "v6a", "状态": "排空中", "目标": ["v6b"]}],
        )
        status = parse(s2.prefix_pool_drain_status("v6a", 0))
        self.assertEqual(status["状态"], "排空中")
        self.assertEqual(status["剩余"], 1)
        adv = parse(s2.prefix_pool_drain("k2", "推进", "v6a", ("v6b",), 0, 10))
        self.assertEqual(adv["状态"], "已排空")

    def test_both_drains_roundtrip_key_order(self):
        _auth, s = make()
        cfg = config(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48"),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        # 追加第二 IPv4 池以承载 IPv4 排空目标。
        cfg["地址池"].append(pool_entry("p2", "10.1.0.0/28"))
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        s.pool_drain("d4", "开始", "default", ("p2",), 0, 10)
        s.prefix_pool_drain("d6", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)),
            ["版本", "时刻", "容量", "配额", "排空", "IPv6排空", "摘要"],
        )
        s2 = self._fresh(s)  # export_config 已含 p2
        out = json.loads(s2.runtime_restore("r", cp))
        self.assertEqual(out["排空"][0]["源池"], "default")
        self.assertEqual(out["IPv6排空"][0]["源池"], "v6a")
        self.assertEqual(
            parse(s2.pool_drain_status("default", 0))["状态"], "排空中"
        )
        self.assertEqual(
            parse(s2.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )

    def test_drained_state_roundtrip(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        s2 = self._fresh(s)
        s2.runtime_restore("r", cp)
        self.assertEqual(
            parse(s2.prefix_pool_drain_status("v6a", 0))["状态"], "已排空"
        )

    def test_restore_unknown_v6_target_resource_error(self):
        _auth, s = make()
        load(s)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        # 目标实例配置删除 v6b。
        cfg = json.loads(s.export_config())
        cfg[V6_KEY] = [p for p in cfg[V6_KEY] if p["标识"] != "v6b"]
        cfg["模板 IPv6 池"] = [
            [tid, [pid for pid in seq if pid != "v6b"]]
            for tid, seq in cfg["模板 IPv6 池"]
        ]
        _auth2, s2 = make()
        s2.load_config(compact(cfg))
        with self.assertRaises(ResourceError):
            s2.runtime_restore("r", cp)
        with self.assertRaises(StateError):
            s2.prefix_pool_drain_status("v6a", 0)

    def test_restore_malformed_v6_drain_value_error(self):
        _auth, s = make()
        load(s)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = json.loads(s.runtime_checkpoint(0))
        cp["IPv6排空"][0]["状态"] = "非法"
        text = compact(cp)
        s2 = self._fresh(s)
        with self.assertRaises(ValueError):
            s2.runtime_restore("r", text)

    def test_old_checkpoint_without_v6_section_restored_as_none(self):
        # 无 IPv6 排空的基线包恢复后 v6 排平行为空（旧检查点视为无 IPv6
        # 排空），且不影响同实例后续操作。
        _auth, s = make()
        load(s)
        cp = s.runtime_checkpoint(0)
        s2 = self._fresh(s)
        s2.runtime_restore("r", cp)
        self.assertEqual(s2._prefix_drains, {})
        with self.assertRaises(StateError):
            s2.prefix_pool_drain_status("v6a", 0)

    def test_service_checkpoint_carries_v6_drain(self):
        _auth, s = make()
        load(s)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.service_checkpoint(0)
        s2 = self._fresh(s)
        out = s2.service_restore("r", cp)
        self.assertEqual(
            json.loads(out)["运行态"]["IPv6排空"],
            [{"源池": "v6a", "状态": "排空中", "目标": ["v6b"]}],
        )
        self.assertEqual(
            parse(s2.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )


if __name__ == "__main__":
    unittest.main()
