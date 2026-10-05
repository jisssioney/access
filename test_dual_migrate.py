"""双栈迁移（"双栈迁移" 操作）：在线双栈会话一次请求同时迁移 IPv4 地址与
IPv6 委派前缀。覆盖成功形态与键序、两族静态优先与最小动态、状态/认证/
资源/后端/停用失败的两族均不改态、显式老化保留、幂等重放、无计费切分、
用户失败统计与防篡改审计链、session-run 接入（含信封整体校验与逐字节
确定性）及纯 IPv4 配置逐字节兼容。"""

import hashlib
import json
import subprocess
import sys
import unittest

import access
from access import (
    AuthError,
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
    StateError,
)

V6_KEY = "IPv6 前缀池"
DUAL_OP = "双栈迁移"
DUAL_KEYS = [
    "会话", "状态", "时刻", "期限", "原池", "原地址", "目标池", "目标地址",
    "租期", "原IPv6池", "原IPv6前缀", "目标IPv6池", "目标IPv6前缀",
    "IPv6租期",
]


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


USERS = ("alice", "bob", "carol", "dave")
# 前三人为双栈模板用户，dave 不绑定模板（纯 IPv4 用户）。
BOUND_USERS = ("alice", "bob", "carol")


def base_config(
    v4_pools=("default", "p2"),
    v6_pools=(),
    v6_specs=None,
    template_v6=(),
    user_templates=BOUND_USERS,
    static4=(),
    static6=(),
    cidrs=None,
):
    default_cidrs = {"default": "10.0.0.0/28", "p2": "10.1.0.0/28"}
    if cidrs is not None:
        default_cidrs.update(cidrs)
    static4_map = {}
    for user, pool_id, ip in static4:
        static4_map.setdefault(pool_id, []).append((user, ip))
    static6_map = {}
    for user, pool_id, prefix in static6:
        static6_map.setdefault(pool_id, []).append((user, prefix))
    # v6_specs: {pool_id: (聚合前缀, 委派长度)}，缺省取 v6a/v6b 的 /48->/56。
    v6_specs = v6_specs or {}
    bound = (
        [(user, "dual") for user in user_templates]
        if isinstance(user_templates, (list, tuple))
        else list(user_templates)
    )
    v6_entries = []
    for pool_id in v6_pools:
        spec = v6_specs.get(pool_id) or _DEFAULT_V6_SPEC.get(pool_id)
        if spec is None:
            raise KeyError(f"v6 spec required for pool {pool_id!r}")
        agg, deleg = spec
        v6_entries.append(
            v6_entry(pool_id, agg, deleg, static=static6_map.get(pool_id, ()))
        )
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                "租期毫秒": 1000},
        "地址池": [
            pool_entry(pool_id, default_cidrs[pool_id],
                       static=static4_map.get(pool_id, ()))
            for pool_id in v4_pools
        ],
        "模板": [template_entry("dual")],
        "用户模板": [list(pair) for pair in bound],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [],
        "IPv6 前缀池": v6_entries,
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


_DEFAULT_V6_SPEC = {
    "v6a": ("2001:db8::/48", 56),
    "v6b": ("2001:db8:1::/48", 56),
}


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


TWO_POOLS = dict(
    v4_pools=("default", "p2"),
    v6_pools=("v6a", "v6b"),
    template_v6=(("dual", ("v6a", "v6b")),),
    static4=(("bob", "p2", "10.1.0.5"),),
    static6=(("bob", "v6b", "2001:db8:1:500::/56"),),
)


def loaded_two_pools():
    s = make_sessions()
    load(s, **TWO_POOLS)
    return s


def v4_waterline(s, now_ms):
    stats = json.loads(s.pool_stats(now_ms))
    return {row[0]: (row[4], row[5]) for row in stats["池"]}


def v6_waterline(s, now_ms):
    stats = json.loads(s.pool_stats(now_ms))
    return {row[0]: (row[4], row[5]) for row in stats[V6_KEY]}


class DualMigrationSuccessTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def dual(self, key="k9", target4="p2", target6="v6b", now_ms=500,
             password="pw"):
        return json.loads(
            self.s.do(
                key, DUAL_OP, "s1", (target4, target6, password), now_ms
            )
        )

    def test_output_key_order_and_values(self):
        out = self.dual(now_ms=500)
        self.assertEqual(list(out), DUAL_KEYS)
        self.assertEqual(out["会话"], "s1")
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(out["时刻"], 500)
        # 空闲期限不变。
        self.assertEqual(out["期限"], 50000)
        self.assertEqual(out["原池"], "default")
        self.assertEqual(out["原地址"], "10.0.0.1")
        self.assertEqual(out["目标池"], "p2")
        self.assertEqual(out["目标地址"], "10.1.0.1")
        self.assertEqual(out["租期"], 1500)
        self.assertEqual(out["原IPv6池"], "v6a")
        self.assertEqual(out["原IPv6前缀"], "2001:db8::/56")
        self.assertEqual(out["目标IPv6池"], "v6b")
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1::/56")
        self.assertEqual(out["IPv6租期"], 1500)

    def test_lf_terminated_compact_json(self):
        text = self.s.do(
            "k9", DUAL_OP, "s1", ("p2", "v6b", "pw"), 500
        )
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, compact(json.loads(text)) + "\n")

    def test_both_waterlines_move_atomically(self):
        self.dual()
        stats = json.loads(self.s.pool_stats(500))
        v4 = {row[0]: row[4] for row in stats["池"]}
        v6 = {row[0]: row[4] for row in stats[V6_KEY]}
        # 旧池各 0 租约，目标池各 1 租约。
        self.assertEqual(v4, {"default": 0, "p2": 1})
        self.assertEqual(v6, {"v6a": 0, "v6b": 1})
        view = json.loads(self.s.sessions(500))["项目"][0]
        self.assertEqual(view["池"], "p2")
        self.assertEqual(view["地址"], "10.1.0.1")
        self.assertEqual(view["租期"], 1500)
        self.assertEqual(view["IPv6池"], "v6b")
        self.assertEqual(view["IPv6前缀"], "2001:db8:1::/56")
        self.assertEqual(view["IPv6租期"], 1500)
        # 空闲期限不变。
        self.assertEqual(view["期限"], 50000)

    def test_static_preferred_in_both_families(self):
        s = loaded_two_pools()
        s.do("kb", "建立", "sb", ("bob", "pw"), 0)
        out = json.loads(
            s.do("km", DUAL_OP, "sb", ("p2", "v6b", "pw"), 100)
        )
        # bob 在 p2 的专属静态址与 v6b 的专属静态前缀同时优先。
        self.assertEqual(out["目标地址"], "10.1.0.5")
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1:500::/56")

    def test_smallest_dynamic_after_released_resources(self):
        s = loaded_two_pools()
        s.do("ka", "建立", "sa", ("alice", "pw"), 0)
        s.do("kc", "建立", "sc", ("carol", "pw"), 0)
        s.do("ko", "下线", "sa", None, 10)  # 10.0.0.1 与 ::/56 归还
        # carol 双栈迁到空目标：p2 最小动态 10.1.0.1，v6b 游标首块 1::/56。
        out = json.loads(
            s.do("km1", DUAL_OP, "sc", ("p2", "v6b", "pw"), 20)
        )
        self.assertEqual(out["目标地址"], "10.1.0.1")
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1::/56")
        # 再迁回原池：IPv4 取归还堆顶 10.0.0.1，IPv6 取归还堆顶 ::/56。
        back = json.loads(
            s.do("km2", DUAL_OP, "sc", ("default", "v6a", "pw"), 30)
        )
        self.assertEqual(back["目标地址"], "10.0.0.1")
        self.assertEqual(back["目标IPv6前缀"], "2001:db8::/56")

    def test_both_leases_reset_but_deadline_kept(self):
        # 先各自单迁使两族租期错开，再双栈迁移：两类租期同刻重置。
        self.s.do("km", "迁移", "s1", ("p2", "pw"), 100)
        self.s.do("kv", "前缀迁移", "s1", ("v6b", "pw"), 200)
        out = self.dual(
            key="kd", target4="default", target6="v6a", now_ms=300
        )
        self.assertEqual(out["租期"], 1300)
        self.assertEqual(out["IPv6租期"], 1300)
        self.assertEqual(out["期限"], 50000)

    def test_no_accounting_start_or_stop_events(self):
        # 模板限速 1、突发 0，单字节计量恰好通过（初始千分令牌桶 1000）。
        self.s.meter("m1", "s1", 1, 100)
        # 迁移前出一条中间事件：累计 1，位置为原池原址。
        interim_before = json.loads(
            self.s.accounting_interim("i1", "s1", 200)
        )
        self.assertEqual(interim_before["累计字节"], 1)
        self.assertEqual(interim_before["地址池"], "default")
        self.dual()
        # 迁移本身不产生任何计费事件：仍只有开始与一条中间。
        events = json.loads(self.s.accounting_events(0, 100))["事件"]
        self.assertEqual(
            [event["类型"] for event in events], ["开始", "中间"]
        )
        # 限速 1 字节/毫秒：距上次通过 1000 毫秒恰补足一个字节，活动账延续。
        self.s.meter("m2", "s1", 1, 1100)
        interim_after = json.loads(
            self.s.accounting_interim("i2", "s1", 1200)
        )
        # 累计连续不重新开账；中间事件位置已为新池新址，且无停止/开始事件。
        self.assertEqual(interim_after["累计字节"], 2)
        self.assertEqual(interim_after["地址池"], "p2")
        self.assertEqual(interim_after["地址"], "10.1.0.1")
        events = json.loads(self.s.accounting_events(0, 100))["事件"]
        self.assertEqual(
            [event["类型"] for event in events],
            ["开始", "中间", "中间"],
        )


class DualMigrationFailureTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        self.s.do("k2", "建立", "s2", ("bob", "pw"), 0)

    def snapshot(self, now_ms=100):
        return (
            self.s.sessions(now_ms),
            v4_waterline(self.s, now_ms),
            v6_waterline(self.s, now_ms),
        )

    def assert_unchanged(self, before, now_ms=100):
        after = self.snapshot(now_ms)
        self.assertEqual(after, before)

    def test_unknown_sid_key_error(self):
        with self.assertRaises(KeyError):
            self.s.do("kx", DUAL_OP, "nope", ("p2", "v6b", "pw"), 100)

    def test_unknown_target_pools_key_error(self):
        with self.assertRaises(KeyError):
            self.s.do("kx", DUAL_OP, "s1", ("nope", "v6b", "pw"), 100)
        with self.assertRaises(KeyError):
            self.s.do("ky", DUAL_OP, "s1", ("p2", "nope", "pw"), 100)

    def test_same_family_pool_state_error(self):
        self.s.do("km", DUAL_OP, "s1", ("p2", "v6b", "pw"), 50)
        # 任一族目标与当前同族池相同即 StateError。
        for args in (
            ("p2", "v6a", "pw"),
            ("default", "v6b", "pw"),
            ("p2", "v6b", "pw"),
        ):
            with self.assertRaises(StateError):
                self.s.do("k%s" % (args,), DUAL_OP, "s1", args, 100)

    def test_pure_v4_session_state_error(self):
        # dave 不绑定双栈模板，建立为纯 IPv4 会话。
        self.s.do("kd", "建立", "sd", ("dave", "pw"), 0)
        with self.assertRaises(StateError):
            self.s.do("kx", DUAL_OP, "sd", ("p2", "v6b", "pw"), 100)

    def test_suspended_and_offline_state_error(self):
        self.s.do("ks", "挂起", "s1", None, 100)
        with self.assertRaises(StateError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 200)
        self.s.do("ko", "下线", "s2", None, 100)
        with self.assertRaises(StateError):
            self.s.do("ky", DUAL_OP, "s2", ("p2", "v6b", "pw"), 200)

    def test_missing_either_lease_after_aging_state_error(self):
        # IPv6 租期先到期单独释出：双栈在线会话已无委派前缀。
        with self.assertRaises(StateError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 1000)
        # 先前缀迁移把 IPv6 租期延到 1500，则 1100 时仅 IPv4 老化释出。
        s = loaded_two_pools()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "前缀迁移", "s1", ("v6b", "pw"), 500)
        with self.assertRaises(StateError):
            s.do("k3", DUAL_OP, "s1", ("p2", "v6a", "pw"), 1100)
        row = [
            r for r in json.loads(s.sessions(1100))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["地址"], "")
        self.assertEqual(row["IPv6池"], "v6b")

    def test_aging_results_are_kept_on_failure(self):
        # now_ms=1000：老化先释两类到期租约，随后双栈迁移 StateError，
        # 老化结果不回滚。
        before = v4_waterline(self.s, 0)
        self.assertEqual(before["default"][0], 2)
        with self.assertRaises(StateError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 1000)
        self.assertEqual(v4_waterline(self.s, 1000)["default"][0], 0)
        self.assertEqual(v6_waterline(self.s, 1000)["v6a"][0], 0)
        row = [
            r for r in json.loads(self.s.sessions(1000))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["地址"], "")
        self.assertEqual(row["IPv6前缀"], "")

    def test_bad_auth_keeps_both_leases(self):
        before = self.snapshot()
        with self.assertRaises(AuthError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "nope"), 100)
        self.assert_unchanged(before)

    def test_ipv4_target_exhausted_fault_resource_error(self):
        before = self.snapshot()
        self.s.pool_fault("pf", "注入", "p2", 5000, 0)
        with self.assertRaises(ResourceError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 100)
        self.assert_unchanged(before)

    def test_ipv4_target_draining_resource_error(self):
        before = self.snapshot()
        # 反向排水使 p2 成为排水源（目标序不含 p2）：任何在排空的池都不承接
        # 新 IPv4 分配。
        self.s.pool_drain("d1", "开始", "p2", ("default",), 0, 10)
        with self.assertRaises(ResourceError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 100)
        self.assert_unchanged(before)

    def test_ipv6_target_draining_resource_error(self):
        before = self.snapshot()
        # 反向排水使 v6b 进入排空中（源不能在目标序中）。
        self.s.prefix_pool_drain(
            "d1", "开始", "v6b", ("v6a",), 0, 10
        )
        with self.assertRaises(ResourceError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 100)
        self.assert_unchanged(before)

    def test_ipv4_static_occupied_resource_error(self):
        # bob 的 p2 静态址先由 sb 占住；s2（同为 bob）双栈迁入 p2 即静态占用。
        # 增设第三前缀池 v6c 保证 IPv6 侧可承载，从而单独由 IPv4 静态占用触发。
        s = make_sessions()
        load(
            s,
            v4_pools=("default", "p2"),
            v6_pools=("v6a", "v6b", "v6c"),
            v6_specs={"v6c": ("2001:db8:2::/48", 56)},
            template_v6=(("dual", ("v6a", "v6b", "v6c")),),
            static4=(("bob", "p2", "10.1.0.5"),),
            static6=(("bob", "v6b", "2001:db8:1:500::/56"),),
        )
        s.do("k0", "建立", "s2", ("bob", "pw"), 0)
        s.do("kb", "建立", "sb", ("bob", "pw"), 5)
        s.do("km", DUAL_OP, "sb", ("p2", "v6b", "pw"), 10)
        before = (s.sessions(50), v4_waterline(s, 50), v6_waterline(s, 50))
        with self.assertRaises(ResourceError):
            s.do("kx", DUAL_OP, "s2", ("p2", "v6c", "pw"), 50)
        after = (s.sessions(50), v4_waterline(s, 50), v6_waterline(s, 50))
        self.assertEqual(after, before)
        row = [
            r for r in json.loads(s.sessions(50))["项目"]
            if r["会话"] == "s2"
        ][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"], "v6a")

    def test_ipv6_static_occupied_resource_error(self):
        # bob 的 v6b 静态前缀先由 sb 占住（sb 的 IPv4 落在第三池 p3，故 p2
        # 静态址仍空闲）；s2 双栈迁入 (p2, v6b) 时 IPv4 侧可选、IPv6 侧静态
        # 被占用，单独由 IPv6 静态占用触发，两族水位均不改。
        s = make_sessions()
        load(
            s,
            v4_pools=("default", "p2", "p3"),
            v6_pools=("v6a", "v6b"),
            template_v6=(("dual", ("v6a", "v6b")),),
            static4=(("bob", "p2", "10.1.0.5"),),
            static6=(("bob", "v6b", "2001:db8:1:500::/56"),),
            cidrs={"p3": "10.2.0.0/28"},
        )
        s.do("k0", "建立", "s2", ("bob", "pw"), 0)
        s.do("kb", "建立", "sb", ("bob", "pw"), 5)
        s.do("km4", "迁移", "sb", ("p3", "pw"), 8)
        s.do("km6", "前缀迁移", "sb", ("v6b", "pw"), 10)
        before = (s.sessions(50), v4_waterline(s, 50), v6_waterline(s, 50))
        with self.assertRaises(ResourceError):
            s.do("kx", DUAL_OP, "s2", ("p2", "v6b", "pw"), 50)
        after = (s.sessions(50), v4_waterline(s, 50), v6_waterline(s, 50))
        self.assertEqual(after, before)

    def test_ipv4_dynamic_exhausted_resource_error(self):
        s = make_sessions()
        load(
            s,
            v4_pools=("default", "p2", "tiny4"),
            v6_pools=("v6a", "v6b"),
            template_v6=(("dual", ("v6a", "v6b")),),
            cidrs={"tiny4": "10.9.0.0/32"},
        )
        s.do("ka", "建立", "sa", ("alice", "pw"), 0)
        s.do("kt", DUAL_OP, "sa", ("tiny4", "v6b", "pw"), 10)
        s.do("kb", "建立", "sb", ("bob", "pw"), 20)
        stats_before = json.loads(s.pool_stats(30))
        with self.assertRaises(ResourceError):
            s.do("kx", DUAL_OP, "sb", ("tiny4", "v6b", "pw"), 30)
        self.assertEqual(json.loads(s.pool_stats(30)), stats_before)

    def test_ipv6_dynamic_exhausted_resource_error(self):
        s = make_sessions()
        load(
            s,
            v6_pools=("v6a", "tiny6"),
            v6_specs={"tiny6": ("2001:db8:9::/128", 128)},
            template_v6=(("dual", ("v6a", "tiny6")),),
        )
        s.do("ka", "建立", "sa", ("alice", "pw"), 0)
        s.do("kt", DUAL_OP, "sa", ("p2", "tiny6", "pw"), 10)
        s.do("kb", "建立", "sb", ("bob", "pw"), 20)
        before = json.loads(s.pool_stats(30))
        with self.assertRaises(ResourceError):
            s.do("kx", DUAL_OP, "sb", ("p2", "tiny6", "pw"), 30)
        self.assertEqual(json.loads(s.pool_stats(30)), before)

    def test_backend_failure_before_state_and_targets(self):
        self.s.fault("f1", "注入", 10000, 0)
        before = self.snapshot(250)
        with self.assertRaises(BackendError):
            self.s.do("kb", DUAL_OP, "s1", ("p2", "v6b", "pw"), 250)
        self.assert_unchanged(before, 250)
        # 退避保留：同刻新 key 仍 BackendError，且未知 sid 仍优先 KeyError。
        with self.assertRaises(BackendError):
            self.s.do("kb2", DUAL_OP, "s1", ("p2", "v6b", "pw"), 250)
        with self.assertRaises(KeyError):
            self.s.do("kb3", DUAL_OP, "missing", ("p2", "v6b", "pw"), 250)

    def test_disabled_user_auth_error_before_backend(self):
        self.s.user_admin("u1", "停用", "alice", 0, force=True)
        self.s.fault("f1", "注入", 10000, 0)
        with self.assertRaises(AuthError):
            self.s.do("kx", DUAL_OP, "s1", ("p2", "v6b", "pw"), 100)
        before = self.snapshot(100)
        with self.assertRaises(AuthError):
            self.s.do("ky", DUAL_OP, "s1", ("p2", "v6b", "pw"), 100)
        self.assert_unchanged(before, 100)


class DualMigrationParamTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def call(self, args, now_ms=100, key="kx"):
        self.s.do(key, DUAL_OP, "s1", args, now_ms)

    def test_args_wrong_type(self):
        for bad in (["p2", "v6b", "pw"], "x", 42, {"a": 1}, None):
            with self.assertRaises(TypeError):
                self.call(bad, key="kt%r" % (bad,))

    def test_args_wrong_arity(self):
        for bad in (
            ("p2", "v6b"),
            ("p2",),
            (),
            ("p2", "v6b", "pw", "x"),
        ):
            with self.assertRaises(ValueError):
                self.call(bad, key="ka%r" % (bad,))

    def test_field_types(self):
        for bad in ((1, "v6b", "pw"), ("p2", 2, "pw"), ("p2", "v6b", 3)):
            with self.assertRaises(TypeError):
                self.call(bad, key="ki%r" % (bad,))

    def test_field_values_and_negative_now(self):
        for bad in (
            ("", "v6b", "pw"),
            ("p2", "", "pw"),
            ("p2", "v6b", ""),
        ):
            with self.assertRaises(ValueError):
                self.call(bad, key="kv%r" % (bad,))
        with self.assertRaises(ValueError):
            self.s.do("kn", DUAL_OP, "s1", ("p2", "v6b", "pw"), -1)

    def test_bad_op_still_value_error(self):
        with self.assertRaises(ValueError):
            self.s.do("ko", "双栈迁移x", "s1", ("p2", "v6b", "pw"), 0)


class DualMigrationReplayTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        self.s.do("k1", "建立", "s1", ("alice", "pw"), 0)

    def test_same_key_same_params_replays_first_result(self):
        first = self.s.do("k9", DUAL_OP, "s1", ("p2", "v6b", "pw"), 500)
        replay = self.s.do("k9", DUAL_OP, "s1", ("p2", "v6b", "pw"), 500)
        self.assertEqual(replay, first)
        # 重放不再次迁移：目标池各恰一个租约。
        stats = json.loads(self.s.pool_stats(500))
        self.assertEqual(
            {row[0]: row[4] for row in stats["池"]},
            {"default": 0, "p2": 1},
        )
        self.assertEqual(
            {row[0]: row[4] for row in stats[V6_KEY]},
            {"v6a": 0, "v6b": 1},
        )

    def test_same_key_different_params_value_error(self):
        self.s.do("k9", DUAL_OP, "s1", ("p2", "v6b", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", DUAL_OP, "s1", ("default", "v6b", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", DUAL_OP, "s1", ("p2", "v6a", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", DUAL_OP, "s1", ("p2", "v6b", "x"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", DUAL_OP, "s1", ("p2", "v6b", "pw"), 501)

    def test_failure_result_is_replayed_too(self):
        # 同池 StateError 首次入缓存，重放同结果且不重复计失败。
        with self.assertRaises(StateError):
            self.s.do("ke", DUAL_OP, "s1", ("default", "v6a", "pw"), 100)
        with self.assertRaises(StateError):
            self.s.do("ke", DUAL_OP, "s1", ("default", "v6a", "pw"), 100)
        stats = json.loads(self.s.user_stats("alice", 100))
        # 认证/资源/状态/后端：状态失败仅首果计一次（重放不重复计）。
        state_fail = [
            row for row in stats["失败"] if row["类型"] == "状态"
        ][0]["次数"]
        self.assertEqual(state_fail, 1)

    def test_bad_auth_replayed_without_reauth(self):
        with self.assertRaises(AuthError):
            self.s.do("ka", DUAL_OP, "s1", ("p2", "v6b", "nope"), 100)
        with self.assertRaises(AuthError):
            self.s.do("ka", DUAL_OP, "s1", ("p2", "v6b", "nope"), 100)
        stats = json.loads(self.s.user_stats("alice", 100))
        auth_fail = [
            row for row in stats["失败"] if row["类型"] == "认证"
        ][0]["次数"]
        self.assertEqual(auth_fail, 1)

    def test_success_and_failure_on_audit_chain(self):
        self.s.do("k9", DUAL_OP, "s1", ("p2", "v6b", "pw"), 500)
        with self.assertRaises(StateError):
            self.s.do("ke", DUAL_OP, "s1", ("p2", "v6b", "pw"), 600)
        chain = json.loads(self.s.audit(0, 100))["事件"]
        dual_events = [e for e in chain if e["操作"] == DUAL_OP]
        self.assertEqual([e["结果"] for e in dual_events], ["成功", "StateError"])
        self.assertTrue(self.s.verify_audit())


class SessionRunCliTest(unittest.TestCase):
    def _request(self):
        doc = base_config(
            v4_pools=("default", "p2"),
            v6_pools=("v6a", "v6b"),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        return {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
                {"key": "r2", "op": DUAL_OP, "sid": "s1",
                 "args": ["p2", "v6b", "pw"], "now_ms": 200},
                # 业务失败：两族皆同池 StateError，仅记类名继续。
                {"key": "r3", "op": DUAL_OP, "sid": "s1",
                 "args": ["p2", "v6b", "pw"], "now_ms": 300},
                # 业务失败：未知 IPv6 目标池 KeyError。
                {"key": "r4", "op": DUAL_OP, "sid": "s1",
                 "args": ["default", "nope", "pw"], "now_ms": 300},
                # 迁回成功。
                {"key": "r5", "op": DUAL_OP, "sid": "s1",
                 "args": ["default", "v6a", "pw"], "now_ms": 400},
            ],
            "query_ms": 500,
        }

    def _run(self, request):
        return subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=compact(request).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_session_run_accepts_dual_migration(self):
        proc = self._run(self._request())
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = json.loads(proc.stdout.decode())
        types = [(it["结果"], it["类型"]) for it in out["项目"]]
        self.assertEqual(
            types,
            [(True, ""), (True, ""), (False, "StateError"),
             (False, "KeyError"), (True, "")],
        )
        migrated = out["项目"][1]["输出"]
        self.assertEqual(list(migrated), DUAL_KEYS)
        row = [r for r in out["会话"]["项目"] if r["会话"] == "s1"][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["地址"], "10.0.0.1")
        self.assertEqual(row["租期"], 1400)
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertEqual(row["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(row["IPv6租期"], 1400)
        # 最终查询反映原子结果：迁回后两族原池各恰一个租约。
        self.assertEqual(
            {r[0]: r[4] for r in out["地址池"]["池"]},
            {"default": 1, "p2": 0},
        )
        self.assertEqual(
            {r[0]: r[4] for r in out["地址池"][V6_KEY]},
            {"v6a": 1, "v6b": 0},
        )
        head = {
            "版本": out["版本"],
            "项目": out["项目"],
            "会话": out["会话"],
            "地址池": out["地址池"],
        }
        self.assertEqual(
            out["摘要"],
            hashlib.sha256(compact(head).encode()).hexdigest(),
        )

    def test_byte_identical_outputs(self):
        request = self._request()
        first = self._run(request).stdout
        second = self._run(request).stdout
        self.assertEqual(first, second)

    def test_static_validation_rejects_bad_shape(self):
        # 长度错误：ValueError，执行前整体校验，无任何副作用。
        bad = self._request()
        bad["requests"][1]["args"] = ["p2", "v6b"]
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            json.loads(proc.stderr.decode()),
            {"错误": "session-run", "类型": "ValueError"},
        )

        bad = self._request()
        bad["requests"][1]["args"] = ["p2", "v6b", "pw", "x"]
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr.decode())["类型"], "ValueError"
        )

        # 字段类型错误：TypeError。
        bad = self._request()
        bad["requests"][1]["args"] = [123, "v6b", "pw"]
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr.decode())["类型"], "TypeError"
        )

        # args 标量：TypeError。
        bad = self._request()
        bad["requests"][1]["args"] = "x"
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr.decode())["类型"], "TypeError"
        )

        # 未知 op：ValueError。
        bad = self._request()
        bad["requests"][1]["op"] = "双栈迁移x"
        proc = self._run(bad)
        self.assertEqual(proc.returncode, 2)

    def test_pure_v4_config_byte_compatible(self):
        # 纯 IPv4 配置（无前缀池）下，双栈迁移为业务失败（未知 IPv6 目标
        # 池 KeyError），整体输出不含任何 IPv6 键。
        doc = base_config()
        doc["IPv6 前缀池"] = []
        doc["模板 IPv6 池"] = []
        request = {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["dave", "pw"], "now_ms": 0},
                {"key": "r2", "op": DUAL_OP, "sid": "s1",
                 "args": ["p2", "v6b", "pw"], "now_ms": 100},
            ],
            "query_ms": 200,
        }
        proc = self._run(request)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        raw = proc.stdout.decode()
        self.assertNotIn("IPv6", raw)
        out = json.loads(raw)
        self.assertEqual(
            [(it["结果"], it["类型"]) for it in out["项目"]],
            [(True, ""), (False, "KeyError")],
        )


if __name__ == "__main__":
    unittest.main()
