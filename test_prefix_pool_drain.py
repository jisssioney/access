"""可恢复 IPv6 前缀池排空 prefix_pool_drain / prefix_pool_drain_status 的测试。

覆盖：参数校验与异常次序（TypeError/ValueError/KeyError/StateError）、开始
幂等与目标顺序冲突、推进的老化/码点序/limit/静态优先/保留不可动态/目标后备/
排空目标跳过/ResourceError 项/原子换前缀/仅重置 IPv6 租期语义、取消不迁回、
只读状态、同键同参逐字节重放与异参 ValueError、批量审计链（操作“前缀池
排空”）与合规链投影、源前缀池在建立/恢复/容量晋升/显式前缀迁移各通道的新
委派阻断、配置删池 ResourceError 原子保持、运行态与服务检查点（无 IPv6
排空逐字节一致、含排空往返、旧键序形态、恢复失败原子）、与 IPv4 排空并存。
"""

import json
import unittest

from access import (
    Authenticator,
    Sessions,
    AuthError,
    ResourceError,
    StateError,
)


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def v6_entry(pool_id, agg, deleg=56, reserved=(), static=()):
    return {
        "标识": pool_id,
        "聚合前缀": agg,
        "委派长度": deleg,
        "保留": list(reserved),
        "静态": [[user, prefix] for user, prefix in static],
    }


def pool_entry(pool_id, cidr, reserved=(), static=()):
    return {
        "标识": pool_id,
        "CIDR": cidr,
        "保留": list(reserved),
        "静态": [[user, ip] for user, ip in static],
    }


def make_config(v6_pools, template_v6, *, users=("alice", "bob", "carol"),
                total=100, per=10, idle_ms=50000, lease_ms=1000,
                v4_pools=("default", "p2")):
    return {
        "版本": 12,
        "会话": {"总数": total, "每用户": per, "空闲毫秒": idle_ms,
                "租期毫秒": lease_ms},
        "地址池": [
            pool_entry("default", "10.0.0.0/28") if p == "default"
            else pool_entry(p, f"10.{i + 1}.0.0/28")
            for i, p in enumerate(v4_pools)
        ],
        "模板": [{"标识": "dual", "限速": 1, "突发": 0,
                  "配额": 10 ** 9, "周期毫秒": 0, "会话上限": 0,
                  "排队优先级": 0, "超限": "拒绝"}],
        "用户模板": [[u, "dual"] for u in users],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [],
        "IPv6 前缀池": list(v6_pools),
        "模板 IPv6 池": [["dual", list(template_v6)]],
    }


def make(v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                   v6_entry("v6b", "2001:db8:1::/48")),
         template_v6=("v6a", "v6b"), *, total=100, per=10,
         idle_ms=50000, lease_ms=1000, v4_pool=("10.0.0.0/28", (), ())):
    auth = Authenticator(3, 10 ** 9)
    for user in ("alice", "bob", "carol", "dave"):
        auth.add(user, "pw")
    s = Sessions(auth, total, per, idle_ms, pool=v4_pool, lease_ms=lease_ms)
    cfg = make_config(
        v6_pools, template_v6, total=total, per=per,
        idle_ms=idle_ms, lease_ms=lease_ms,
    )
    s.load_config(compact(cfg))
    return auth, s


def parse(text):
    return json.loads(text)


def establish(s, key, sid, user="alice", now=0):
    return s.do(key, "建立", sid, (user, "pw"), now)


def session_rows(s, now=0):
    return {r["会话"]: r for r in parse(s.sessions(now))["项目"]}


class V6DrainParamTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()

    def test_key_credential_checked_first(self):
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                self.s.prefix_pool_drain(
                    bad, "开始", "v6a", ("v6b",), 0, 10
                )
        with self.assertRaises(ValueError):
            self.s.prefix_pool_drain("", "开始", "v6a", ("v6b",), 0, 10)

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
                s.prefix_pool_drain("kn" + str(bad_now), "开始", "v6a",
                                    ("v6b",), bad_now, 10)
        for bad_limit in (1.5, "5", None, True, False):
            with self.assertRaises(TypeError):
                s.prefix_pool_drain("kl" + str(bad_limit), "开始", "v6a",
                                    ("v6b",), 0, bad_limit)

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

    def test_type_precedes_value(self):
        s = self.s
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", "冻结", "v6a", [], 0, 0)
        with self.assertRaises(TypeError):
            s.prefix_pool_drain("k", "开始", 9, (), "x", 0)

    def test_unknown_pools(self):
        s = self.s
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "nope", ("v6b",), 0, 10)
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "v6a", ("nope",), 0, 10)
        # 源池先于目标池判定；IPv4 池标识不等于前缀池标识。
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "nope", ("alsonope",), 0, 10)
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "default", ("v6b",), 0, 10)

    def test_v6_disabled_unknown_pool(self):
        auth = Authenticator(3, 10 ** 9)
        auth.add("alice", "pw")
        s = Sessions(auth, 100, 10, 50000, pool=("10.0.0.0/28", (), ()))
        with self.assertRaises(KeyError):
            s.prefix_pool_drain("k", "开始", "v6a", ("v6b",), 0, 10)

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

    def test_state_failure_does_not_cache(self):
        s = self.s
        with self.assertRaises(StateError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        # 未占 key：取消（亦 StateError）后同 key 开始成功。
        with self.assertRaises(StateError):
            s.prefix_pool_drain("k", "取消", "v6a", ("v6b",), 0, 10)
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


class V6DrainStartTest(unittest.TestCase):
    def test_start_shape_and_block_establish_with_fallback(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        out = parse(s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10))
        self.assertEqual(list(out), ["时刻", "源池", "状态", "剩余", "项目"])
        self.assertEqual(
            out, {"时刻": 0, "源池": "v6a", "状态": "排空中",
                  "剩余": 1, "项目": []}
        )
        raw = s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw)
        # 建立的后备序 [v6a,v6b]：v6a 排空中，回落 v6b 取前缀。
        new = parse(establish(s, "e2", "b", "bob"))
        self.assertEqual(new["IPv6池"], "v6b")

    def test_start_blocks_establish_when_all_pools_draining(self):
        _auth, s = make()
        s.prefix_pool_drain("d2", "开始", "v6b", ("v6a",), 0, 10)
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ResourceError):
            establish(s, "e1", "a", "alice")

    def test_start_idempotent_same_order_any_key(self):
        _auth, s = make()
        out1 = s.prefix_pool_drain("d1", "开始", "v6a", ("v6b",), 0, 10)
        out2 = s.prefix_pool_drain("d2", "开始", "v6a", ("v6b",), 5, 10)
        self.assertEqual(parse(out2)["状态"], "排空中")
        self.assertEqual(parse(out1)["剩余"], parse(out2)["剩余"])

    def test_start_different_order_state_error(self):
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/48"),
                      v6_entry("v6c", "2001:db8:2::/48")),
            template_v6=("v6a", "v6b", "v6c"),
        )
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("d2", "开始", "v6a", ("v6c", "v6b"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("d3", "开始", "v6a", ("v6b",), 0, 10)

    def test_start_preserves_sessions(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        before = s.sessions(0)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        self.assertEqual(s.sessions(0), before)


class V6DrainAdvanceTest(unittest.TestCase):
    def test_codepoint_order_limit_and_lease_reset(self):
        _auth, s = make()
        establish(s, "e1", "z", "alice")
        establish(s, "e2", "a", "bob")
        establish(s, "e3", "m", "carol")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 500, 2))
        self.assertEqual(
            [(i["会话"], i["目标池"], i["结果"]) for i in out["项目"]],
            [("a", "v6b", "前缀迁移"), ("m", "v6b", "前缀迁移")],
        )
        self.assertEqual(out["状态"], "排空中")
        self.assertEqual(out["剩余"], 1)
        rows = session_rows(s, 500)
        # 已迁：换前缀池、仅 IPv6 租期重置为 500+1000。
        self.assertEqual(rows["a"]["IPv6池"], "v6b")
        self.assertEqual(rows["a"]["IPv6租期"], 1500)
        self.assertEqual(rows["a"]["租期"], 1000)      # IPv4 租期不变
        self.assertEqual(rows["a"]["池"], "default")  # IPv4 池不变
        self.assertEqual(rows["a"]["期限"], 50000)    # 空闲期限不变
        self.assertEqual(rows["m"]["IPv6池"], "v6b")
        # 未处理项保持源池与原租期。
        self.assertEqual(rows["z"]["IPv6池"], "v6a")
        self.assertEqual(rows["z"]["IPv6租期"], 1000)
        out2 = parse(s.prefix_pool_drain("k2", "推进", "v6a", ("v6b",), 500, 10))
        self.assertEqual([i["会话"] for i in out2["项目"]], ["z"])
        self.assertEqual(out2["状态"], "已排空")
        self.assertEqual(out2["剩余"], 0)

    def test_drained_still_blocks_new_delegations(self):
        # 模板后备仅 v6a：开始并推进至已排空（前缀已迁去 v6b），未取消前
        # 新建立无可用后备池 -> ResourceError。
        _auth, s = make()
        cfg = make_config(
            (v6_entry("v6a", "2001:db8::/48"),
             v6_entry("v6b", "2001:db8:1::/48")),
            ("v6a",),
        )
        s.load_config(compact(cfg))
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "已排空"
        )
        with self.assertRaises(ResourceError):
            establish(s, "e2", "b", "bob")

    def test_advance_without_start_state_error(self):
        _auth, s = make()
        with self.assertRaises(StateError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)

    def test_advance_wrong_target_order_state_error(self):
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/48"),
                      v6_entry("v6c", "2001:db8:2::/48")),
            template_v6=("v6a", "v6b", "v6c"),
        )
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6c", "v6b"), 0, 10)

    def test_static_binding_priority(self):
        _auth, s = make(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48",
                         static=(("alice", "2001:db8:1::/56"),)),
            ),
        )
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10))
        self.assertEqual(
            [(i["会话"], i["目标池"]) for i in out["项目"]],
            [("a", "v6b"), ("b", "v6b")],
        )
        rows = session_rows(s, 0)
        # a(alice) 取专属静态前缀；b(bob) 取数值最小动态前缀（静态块从不入动态）。
        self.assertEqual(rows["a"]["IPv6前缀"], "2001:db8:1::/56")
        self.assertEqual(rows["b"]["IPv6前缀"], "2001:db8:1:100::/56")

    def test_reserved_prefix_not_dynamic(self):
        # v6b 首个委派块被保留：动态用户须取数值次小前缀。
        _auth, s = make(
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48"),
                v6_entry("v6b", "2001:db8:1::/48",
                         reserved=("2001:db8:1::/56",)),
            ),
        )
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        rows = session_rows(s, 0)
        self.assertEqual(rows["a"]["IPv6前缀"], "2001:db8:1:100::/56")

    def test_target_fallback_order(self):
        # v6b 仅一个可委派前缀（/127 聚合、/128 委派），v6c 充裕；目标序
        # v6b 优先：码点序 a 先占 v6b 独前缀，b 回退 v6c。
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/128", deleg=128),
                      v6_entry("v6c", "2001:db8:2::/48")),
            template_v6=("v6a", "v6b", "v6c"),
        )
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b", "v6c"), 0, 10))
        mapping = {i["会话"]: i["目标池"] for i in out["项目"]}
        self.assertEqual(mapping["a"], "v6b")
        self.assertEqual(mapping["b"], "v6c")

    def test_draining_target_skipped(self):
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/48"),
                      v6_entry("v6c", "2001:db8:2::/48")),
            template_v6=("v6a", "v6b", "v6c"),
        )
        establish(s, "e1", "a", "alice")
        # v6b 自身排空中：v6a->[v6b,v6c] 应跳过 v6b 取 v6c。
        s.prefix_pool_drain("d2", "开始", "v6b", ("v6c",), 0, 10)
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b", "v6c"), 0, 10))
        self.assertEqual(out["项目"][0]["目标池"], "v6c")

    def test_no_double_lease_after_success(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        stats = {row[0]: row for row in parse(s.pool_stats(0))["IPv6 前缀池"]}
        # v6a 租用 0；v6b 租用 1。
        self.assertEqual(stats["v6a"][4], 0)
        self.assertEqual(stats["v6b"][4], 1)
        for pool in s._v6_pools.values():
            self.assertEqual(len(pool.leases), len(set(pool.leases)))

    def test_advance_ages_first(self):
        # IPv6 租期先于 IPv4 到期的形态：t=500 做一次 IPv4 迁移（仅重置
        # IPv4 租期为 1500，v6 租期仍为 1000），t=1200 推进时先老化——前缀
        # 已单独释出（会话仍在线、IPv4 在 p2），无有效持前缀会话 -> 已排空。
        _auth, s = make(lease_ms=1000, idle_ms=50000)
        establish(s, "e1", "a", "alice")
        s.do("mig", "迁移", "a", ("p2", "pw"), 500)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 500, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 1200, 10))
        self.assertEqual(out["项目"], [])
        self.assertEqual(out["状态"], "已排空")
        row = session_rows(s, 1200)["a"]
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["IPv6池"], "")
        self.assertEqual(row["IPv6前缀"], "")
        self.assertEqual(row["池"], "p2")  # IPv4 未受影响

    def test_item_failure_does_not_block_others_or_release(self):
        # v6b 与 v6c 各仅一个可委派前缀，第三项无承载 -> ResourceError，
        # 前两项成功，失败项原前缀与租期不变，其他项继续。
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/128", deleg=128),
                      v6_entry("v6c", "2001:db8:2::/128", deleg=128)),
            template_v6=("v6a", "v6b", "v6c"),
        )
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        establish(s, "e3", "c", "carol")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        out = parse(s.prefix_pool_drain("k", "推进", "v6a", ("v6b", "v6c"), 0, 10))
        results = [i["结果"] for i in out["项目"]]
        self.assertEqual(results.count("前缀迁移"), 2)
        self.assertEqual(results.count("ResourceError"), 1)
        failed = [i for i in out["项目"] if i["结果"] == "ResourceError"][0]
        self.assertEqual(failed["目标池"], "")
        self.assertEqual(out["剩余"], 1)
        self.assertEqual(out["状态"], "排空中")
        # 失败项原前缀与租期不变。
        rows = session_rows(s, 0)
        self.assertEqual(rows["c"]["IPv6池"], "v6a")
        self.assertEqual(rows["c"]["IPv6租期"], 1000)
        self.assertEqual(
            len(s._v6_pools["v6a"].leases), 1
        )  # 失败未半释放

    def test_ipv4_and_qos_billing_untouched(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        # 计费不切分：仅有建立的“开始”。
        types = [e["类型"] for e in parse(s.accounting_events(0, 100))["事件"]]
        self.assertEqual(types, ["开始"])
        # meter 仍可计量且账内累计照常（限速 1、突发 0：桶容 1000 千分字节，
        # size=1 即 1000，t=100 补至 1100 可通过）。
        m1 = parse(s.meter("m1", "a", 1, 100))
        self.assertEqual(m1["结果"], "通过")
        self.assertEqual(m1["累计"], 1)


class V6DrainCancelTest(unittest.TestCase):
    def test_cancel_restores_selection_no_moveback(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        out = parse(s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10))
        self.assertEqual(out["状态"], "已取消")
        # 取消后 v6a 恢复承接新委派。
        new = parse(establish(s, "e2", "b", "bob"))
        self.assertEqual(new["IPv6池"], "v6a")
        # 已迁出前缀不迁回。
        self.assertEqual(session_rows(s, 0)["a"]["IPv6池"], "v6b")
        with self.assertRaises(StateError):
            s.prefix_pool_drain_status("v6a", 0)

    def test_cancel_without_start_state_error(self):
        _auth, s = make()
        with self.assertRaises(StateError):
            s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10)

    def test_cancel_wrong_targets_state_error(self):
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/48"),
                      v6_entry("v6c", "2001:db8:2::/48")),
            template_v6=("v6a", "v6b", "v6c"),
        )
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b", "v6c"), 0, 10)
        with self.assertRaises(StateError):
            s.prefix_pool_drain("c", "取消", "v6a", ("v6c", "v6b"), 0, 10)
        # 取消失败不移除记录。
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )


class V6DrainStatusTest(unittest.TestCase):
    def test_status_read_only_does_not_age(self):
        _auth, s = make(lease_ms=1000)
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        # t=2000 只读：不老化、按 now_ms 视图计有效（v6_lease<=now_ms 不计）。
        out = parse(s.prefix_pool_drain_status("v6a", 2000))
        self.assertEqual(out, {"源池": "v6a", "状态": "排空中", "剩余": 0})
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["剩余"], 1
        )
        # 租约表未被只读查询改动。
        self.assertIn("v6a", session_rows(s, 0)["a"]["IPv6池"])


class V6DrainReplayTest(unittest.TestCase):
    def test_same_key_same_params_byte_identical(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        first = s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        replay = s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        self.assertEqual(replay, first)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 9999, 10)

    def test_diff_params_value_error(self):
        _auth, s = make()
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        with self.assertRaises(ValueError):
            s.prefix_pool_drain("k", "取消", "v6a", ("v6b",), 0, 10)

    def test_replay_does_not_change_state(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        # a 已迁出，b 仍在 v6a；同参重放不得再迁 b。
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        rows = session_rows(s, 0)
        self.assertEqual(rows["a"]["IPv6池"], "v6b")
        self.assertEqual(rows["b"]["IPv6池"], "v6a")


class V6DrainAuditTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        establish(self.s, "e1", "a", "alice")
        establish(self.s, "e2", "b", "bob")

    def test_batch_chain_and_replay(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)  # 重放
        events = parse(s.batch_audit(0, 1000))["事件"]
        # 开始 1 条（会话=源池、结果=状态），首调 2 条、重放 2 条。
        self.assertEqual(len(events), 5)
        self.assertEqual({(e["操作"], e["原子"]) for e in events},
                         {("前缀池排空", False)})
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
        self.assertEqual(
            list(payload),
            ["序号", "时刻", "键", "操作", "原子", "会话", "结果",
             "原序号", "前哈希", "哈希"],
        )
        self.assertEqual(payload["操作"], "前缀池排空")

    def test_cancel_event(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10)
        events = parse(s.batch_audit(0, 1000))["事件"]
        self.assertEqual([e["结果"] for e in events], ["排空中", "已取消"])
        self.assertTrue(all(e["会话"] == "v6a" for e in events))

    def test_batch_audit_restore_accepts_v6_drain_events(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        page = s.batch_audit(0, 1000)
        _auth2, s2 = make()
        res = parse(s2.batch_audit_restore("r", page))
        self.assertEqual(res["追加"], 3)
        self.assertEqual(
            parse(s2.batch_audit_restore("r", page))["追加"], 3
        )
        self.assertEqual(len(parse(s2.batch_audit(0, 1000))["事件"]), 3)

    def test_compliance_restore_accepts_projection(self):
        s = self.s
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 1)
        snapshot = s.compliance_snapshot(0, 1000)
        _auth2, s2 = make()
        s2.compliance_restore("cr", snapshot)
        events = parse(s2.compliance_events(0, 1000))["事件"]
        drain = [
            e for e in events
            if json.loads(e["载荷"])["操作"] == "前缀池排空"
        ]
        self.assertTrue(drain)


class V6DrainAllocationBlockTest(unittest.TestCase):
    def test_explicit_v6_migrate_into_draining_blocked(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        # a 已在 v6b；显式迁回仍在排空的 v6a -> ResourceError。
        with self.assertRaises(ResourceError):
            s.do("m", "前缀迁移", "a", ("v6a", "pw"), 100)
        # 失败不改前缀。
        self.assertEqual(session_rows(s, 100)["a"]["IPv6池"], "v6b")

    def test_resume_blocked_when_only_pool_draining(self):
        # 模板后备仅 v6a，挂起后排空 v6a（目标 v6b 不在模板后备中不影响
        # 恢复选池），恢复时唯一后备池排空中 -> ResourceError，不留半分配。
        _auth, s = make(template_v6=("v6a",))
        establish(s, "e1", "a", "alice")
        s.do("su", "挂起", "a", None, 0)
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        with self.assertRaises(ResourceError):
            s.do("r", "恢复", "a", ("default", "pw"), 0)
        # 取消后恢复成功。
        s.prefix_pool_drain("c", "取消", "v6a", ("v6b",), 0, 10)
        out = parse(s.do("r2", "恢复", "a", ("default", "pw"), 0))
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(out["IPv6池"], "v6a")

    def test_capacity_promotion_skips_draining(self):
        _auth, s = make(total=1, per=1)
        establish(s, "e1", "a", "alice")
        # 两个前缀池互排空：无任何可承接新委派的池。
        s.prefix_pool_drain("d2", "开始", "v6b", ("v6a",), 0, 10)
        s.prefix_pool_drain("d1", "开始", "v6a", ("v6b",), 0, 10)
        # 全局上限 1、a 占着；b 先排队，下线 a 后推进但无可用前缀池，
        # b 不能晋升仍留队。
        s.capacity("q", "申请", "b", ("bob", "pw", 1000000), 0)
        s.do("off", "下线", "a", None, 0)
        out = parse(s.capacity("adv", "推进", "", None, 0))
        self.assertEqual(out["在线"], 0)
        self.assertEqual(out["排队"], 1)

    def test_migrating_out_of_draining_source_allowed(self):
        # 显式前缀迁移从排空源池迁出（到未排空池）不受阻断。
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        out = parse(s.do("m", "前缀迁移", "a", ("v6b", "pw"), 100))
        self.assertEqual(out["目标IPv6池"], "v6b")


class V6DrainConfigGuardTest(unittest.TestCase):
    def _cfg_without_v6(self, s, pool_id):
        # 删池的同时从模板 IPv6 引用中摘除该池（否则配置解析自身即以引用未知
        # 池报 ValueError，无法到达 _build_pools 的排空承载判定）。
        cfg = json.loads(s.export_config())
        cfg["IPv6 前缀池"] = [
            p for p in cfg["IPv6 前缀池"] if p["标识"] != pool_id
        ]
        cfg["模板 IPv6 池"] = [
            [tid, [pid for pid in refs if pid != pool_id]]
            for tid, refs in cfg["模板 IPv6 池"]
        ]
        return compact(cfg)

    def test_delete_target_pool_resource_error_atomic(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        rev_before = s.config_revision()
        with self.assertRaises(ResourceError):
            s.load_config(self._cfg_without_v6(s, "v6b"))
        self.assertIn("v6b", s._v6_pools)
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )
        self.assertEqual(s.config_revision(), rev_before)
        self.assertEqual(session_rows(s, 0)["a"]["IPv6池"], "v6a")

    def test_delete_source_pool_resource_error(self):
        _auth, s = make()
        s.prefix_pool_drain("d", "开始", "v6b", ("v6a",), 0, 10)
        with self.assertRaises(ResourceError):
            s.load_config(self._cfg_without_v6(s, "v6b"))
        self.assertIn("v6b", s._v6_pools)

    def test_delete_unrelated_pool_ok(self):
        _auth, s = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),
                      v6_entry("v6b", "2001:db8:1::/48"),
                      v6_entry("v6c", "2001:db8:2::/48")),
            template_v6=("v6a", "v6b", "v6c"),
        )
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.load_config(self._cfg_without_v6(s, "v6c"))
        self.assertNotIn("v6c", s._v6_pools)
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )


class V6DrainCheckpointTest(unittest.TestCase):
    def test_no_v6_drain_byte_compatible_and_restore_as_none(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)), ["版本", "时刻", "容量", "配额", "摘要"]
        )
        _auth2, s2 = make()
        s2.runtime_restore("r", cp)
        with self.assertRaises(StateError):
            s2.prefix_pool_drain_status("v6a", 0)

    def test_v4_drain_without_v6_drain_has_no_v6_key(self):
        # 仅 IPv4 排空时检查点键序为基线六键，不含 IPv6排空。
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        cp = json.loads(s.runtime_checkpoint(0))
        self.assertEqual(
            list(cp), ["版本", "时刻", "容量", "配额", "排空", "摘要"]
        )

    def test_v6_drain_roundtrip(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)),
            ["版本", "时刻", "容量", "配额", "IPv6排空", "摘要"],
        )
        _auth2, s2 = make()
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

    def test_both_drains_key_order_and_roundtrip(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.pool_drain("d4", "开始", "default", ("p2",), 0, 10)
        s.prefix_pool_drain("d6", "开始", "v6a", ("v6b",), 0, 10)
        cp = json.loads(s.runtime_checkpoint(0))
        self.assertEqual(
            list(cp),
            ["版本", "时刻", "容量", "配额", "排空", "IPv6排空", "摘要"],
        )
        _auth2, s2 = make()
        out = json.loads(s2.runtime_restore("r", s.runtime_checkpoint(0)))
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
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        s.prefix_pool_drain("k", "推进", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        _auth2, s2 = make()
        s2.runtime_restore("r", cp)
        self.assertEqual(
            parse(s2.prefix_pool_drain_status("v6a", 0))["状态"], "已排空"
        )

    def test_restore_unknown_drain_pool_resource_error(self):
        _auth, s = make()
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.runtime_checkpoint(0)
        # 目标实例配置只有 v6a，缺目标池 v6b -> ResourceError。
        _auth2, s2 = make(
            v6_pools=(v6_entry("v6a", "2001:db8::/48"),),
            template_v6=("v6a",),
        )
        with self.assertRaises(ResourceError):
            s2.runtime_restore("r", cp)
        with self.assertRaises(StateError):
            s2.prefix_pool_drain_status("v6a", 0)

    def test_restore_malformed_section_value_error(self):
        _auth, s = make()
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = json.loads(s.runtime_checkpoint(0))
        cp["IPv6排空"][0]["状态"] = "非法"
        text = compact(cp)
        _auth2, s2 = make()
        with self.assertRaises(ValueError):
            s2.runtime_restore("r", text)

    def test_service_checkpoint_carries_v6_drain(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        s.prefix_pool_drain("d", "开始", "v6a", ("v6b",), 0, 10)
        cp = s.service_checkpoint(0)
        _auth2, s2 = make()
        s2.load_config(s.export_config())
        out = json.loads(s2.service_restore("r", cp))
        self.assertEqual(
            out["运行态"]["IPv6排空"],
            [{"源池": "v6a", "状态": "排空中", "目标": ["v6b"]}],
        )
        self.assertEqual(
            parse(s2.prefix_pool_drain_status("v6a", 0))["状态"], "排空中"
        )


class V6AndV4DrainCoexistTest(unittest.TestCase):
    def test_independent_drains_advance(self):
        _auth, s = make()
        establish(s, "e1", "a", "alice")
        # IPv4：default -> p2；IPv6：v6a -> v6b，互不干扰。
        s.pool_drain("d4", "开始", "default", ("p2",), 0, 10)
        s.prefix_pool_drain("d6", "开始", "v6a", ("v6b",), 0, 10)
        s.pool_drain("k4", "推进", "default", ("p2",), 0, 10)
        s.prefix_pool_drain("k6", "推进", "v6a", ("v6b",), 0, 10)
        row = session_rows(s, 0)["a"]
        self.assertEqual(row["池"], "p2")
        self.assertEqual(row["IPv6池"], "v6b")
        # 两类排空各自完成且彼此不产生 KeyError/目标跳过误判。
        self.assertEqual(
            parse(s.pool_drain_status("default", 0))["状态"], "已排空"
        )
        self.assertEqual(
            parse(s.prefix_pool_drain_status("v6a", 0))["状态"], "已排空"
        )
        # 两条链操作名各自正确。
        ops = {e["操作"] for e in parse(s.batch_audit(0, 1000))["事件"]}
        self.assertEqual(ops, {"地址池排空", "前缀池排空"})


if __name__ == "__main__":
    unittest.main()
