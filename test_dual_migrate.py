"""双栈迁移（"双栈迁移" 操作）：持有 IPv4 地址与 IPv6 委派前缀的在线会话在
一次请求中把两类资源原子迁到目标 IPv4 池与目标 IPv6 前缀池。覆盖成功形态
与键序、两族静态优先与最小动态、状态/认证/资源/后端/停用失败的两族不改
态、幂等重放、显式时钟老化保留、计费不切分、两类租期重置、检查点
（clog/runtime/service）往返、session-run 接入（含整体形态校验）与逐字节
确定性。"""

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
BOUND_USERS = ("alice", "bob", "carol")


def base_config(v4_pools=None, v6_pools=(), template_v6=(),
                user_templates=BOUND_USERS):
    if v4_pools is None:
        v4_pools = (
            pool_entry("default", "10.0.0.0/28"),
            pool_entry("p2", "10.1.0.0/28"),
        )
    bound = (
        [(user, "dual") for user in user_templates]
        if isinstance(user_templates, (list, tuple))
        else list(user_templates)
    )
    return {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                "租期毫秒": 1000},
        "地址池": list(v4_pools),
        "模板": [template_entry("dual")],
        "用户模板": [list(pair) for pair in bound],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [],
        "IPv6 前缀池": [
            v6_entry(*args) if isinstance(args, tuple) else args
            for args in v6_pools
        ],
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


TWO_POOLS = dict(
    v6_pools=(
        v6_entry("v6a", "2001:db8::/48", 56,
                 reserved=["2001:db8:0:100::/56"],
                 static=[["bob", "2001:db8:0:200::/56"]]),
        v6_entry("v6b", "2001:db8:1::/48", 56,
                 static=[["bob", "2001:db8:1:500::/56"]]),
    ),
    template_v6=(("dual", ("v6a", "v6b")),),
)


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


def loaded_two_pools(v4_pools=None):
    s = make_sessions()
    kw = dict(TWO_POOLS)
    if v4_pools is not None:
        kw["v4_pools"] = v4_pools
    load(s, **kw)
    return s


def establish(s, sid, user, now_ms=0, key=None):
    return s.do(key or ("k_" + sid), "建立", sid, (user, "pw"), now_ms)


def waterline(s, now_ms):
    stats = json.loads(s.pool_stats(now_ms))
    return (
        {row[0]: row[4] for row in stats["池"]},
        {row[0]: row[4] for row in stats[V6_KEY]},
    )


KEYS = [
    "会话", "状态", "时刻", "期限",
    "原池", "原地址", "目标池", "目标地址", "租期",
    "原IPv6池", "原IPv6前缀", "目标IPv6池", "目标IPv6前缀", "IPv6租期",
]


class DualMigrationSuccessTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        establish(self.s, "s1", "alice")

    def migrate(self, key="k9", v4="p2", v6="v6b", now_ms=500, password="pw"):
        return json.loads(
            self.s.do(key, "双栈迁移", "s1", (v4, v6, password), now_ms)
        )

    def test_output_key_order_and_values(self):
        out = self.migrate(now_ms=500)
        self.assertEqual(list(out), KEYS)
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
        text = self.s.do("k9", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, compact(json.loads(text)) + "\n")

    def test_waterline_moves_both_families_atomically(self):
        self.migrate()
        v4, v6 = waterline(self.s, 500)
        self.assertEqual(v4, {"default": 0, "p2": 1})
        self.assertEqual(v6, {"v6a": 0, "v6b": 1})
        row = json.loads(self.s.sessions(500))["项目"][0]
        self.assertEqual(row["池"], "p2")
        self.assertEqual(row["地址"], "10.1.0.1")
        self.assertEqual(row["租期"], 1500)
        self.assertEqual(row["IPv6池"], "v6b")
        self.assertEqual(row["IPv6前缀"], "2001:db8:1::/56")
        self.assertEqual(row["IPv6租期"], 1500)

    def test_deadline_unchanged_and_no_billing_events(self):
        self.migrate(now_ms=500)
        events = json.loads(self.s.accounting_events(0, 100))["事件"]
        self.assertEqual(
            [(e["类型"], e["会话"]) for e in events], [("开始", "s1")]
        )

    def test_static_preferred_in_both_targets(self):
        s = loaded_two_pools()
        establish(s, "sb", "bob")
        out = json.loads(
            s.do("km", "双栈迁移", "sb", ("p2", "v6b", "pw"), 100)
        )
        # bob 在 v6b 的专属静态前缀优先于动态首块；p2 无静态绑定取最小动态。
        self.assertEqual(out["目标IPv6前缀"], "2001:db8:1:500::/56")
        self.assertEqual(out["目标地址"], "10.1.0.1")

    def test_ipv4_static_preferred_in_target(self):
        pools = (
            pool_entry("default", "10.0.0.0/28"),
            pool_entry(
                "p2", "10.1.0.0/28",
                static=[("alice", "10.1.0.9")],
            ),
        )
        s = loaded_two_pools(v4_pools=pools)
        establish(s, "s1", "alice")
        out = json.loads(
            s.do("km", "双栈迁移", "s1", ("p2", "v6b", "pw"), 100)
        )
        self.assertEqual(out["目标地址"], "10.1.0.9")

    def test_smallest_dynamic_returned_heap_reused(self):
        s = loaded_two_pools()
        establish(s, "sa", "alice")
        establish(s, "sc", "carol")
        self.s_do_offline(s, "sa", 10)
        # 先 default/v6a -> p2/v6b，再 p2/v6b -> default/v6a：
        # v6a 归还堆顶 ::/56 小于游标，优先复用；IPv4 复用归还的 10.0.0.1。
        s.do("km1", "双栈迁移", "sc", ("p2", "v6b", "pw"), 20)
        back = json.loads(
            s.do("km2", "双栈迁移", "sc", ("default", "v6a", "pw"), 30)
        )
        self.assertEqual(back["目标IPv6前缀"], "2001:db8::/56")
        self.assertEqual(back["目标地址"], "10.0.0.1")
        self.assertEqual(back["租期"], 1030)
        self.assertEqual(back["IPv6租期"], 1030)

    @staticmethod
    def s_do_offline(s, sid, now_ms):
        s.do("ko_" + sid, "下线", sid, None, now_ms)

    def test_renew_after_migration_extends_both_leases(self):
        self.migrate(now_ms=100)
        out = json.loads(self.s.do("kr", "续租", "s1", None, 200))
        self.assertEqual(out["租期"], 1200)
        self.assertEqual(out["IPv6租期"], 1200)


class DualMigrationFailureTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        establish(self.s, "s1", "alice")
        establish(self.s, "s2", "bob")

    def test_unknown_sid_key_error(self):
        with self.assertRaises(KeyError):
            self.s.do("kx", "双栈迁移", "nope", ("p2", "v6b", "pw"), 100)

    def test_unknown_target_pools_key_error(self):
        with self.assertRaises(KeyError):
            self.s.do("kx", "双栈迁移", "s1", ("nope", "v6b", "pw"), 100)
        with self.assertRaises(KeyError):
            self.s.do("ky", "双栈迁移", "s1", ("p2", "nope", "pw"), 100)

    def test_same_v4_pool_state_error(self):
        with self.assertRaises(StateError):
            self.s.do("kx", "双栈迁移", "s1", ("default", "v6b", "pw"), 100)

    def test_same_v6_pool_state_error(self):
        with self.assertRaises(StateError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6a", "pw"), 100)

    def test_pure_v4_session_state_error(self):
        establish(self.s, "sd", "dave")
        with self.assertRaises(StateError):
            self.s.do("kx", "双栈迁移", "sd", ("p2", "v6b", "pw"), 100)

    def test_suspended_and_offline_state_error(self):
        self.s.do("ks", "挂起", "s1", None, 100)
        with self.assertRaises(StateError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "pw"), 200)
        self.s.do("ko", "下线", "s2", None, 100)
        with self.assertRaises(StateError):
            self.s.do("ky", "双栈迁移", "s2", ("p2", "v6b", "pw"), 200)

    def test_missing_v6_lease_after_aging_state_error(self):
        # IPv6 租期先到期单独老化释出后，双栈会话缺前缀：StateError，老化保留。
        view = json.loads(self.s.sessions(1000))
        self.assertEqual(view["项目"][0]["IPv6前缀"], "")
        with self.assertRaises(StateError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "pw"), 1000)

    def test_missing_v4_lease_after_aging_state_error(self):
        # IPv4 先到期单独释出（双栈迁移/前缀迁移只重置 v6 租期的形态）：
        # 先双栈迁移使两租期同为 1500，无法构造 v4 先到期；改用前缀迁移把
        # v6 租期顺延，再令 v4 先到期，双栈迁移缺 IPv4 址 StateError。
        s = loaded_two_pools()
        establish(s, "s1", "alice")
        s.do("k2", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500)
        s.do("k3", "前缀迁移", "s1", ("v6a", "pw"), 1400)
        view = json.loads(s.sessions(1600))
        row = [r for r in view["项目"] if r["会话"] == "s1"][0]
        self.assertEqual(row["地址"], "")
        self.assertNotEqual(row["IPv6前缀"], "")
        with self.assertRaises(StateError):
            s.do("kx", "双栈迁移", "s1", ("default", "v6b", "pw"), 1600)

    def test_bad_auth_keeps_both_leases(self):
        before = waterline(self.s, 100)
        with self.assertRaises(AuthError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "nope"), 100)
        self.assertEqual(waterline(self.s, 100), before)
        row = [
            r for r in json.loads(self.s.sessions(100))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"], "v6a")

    def test_target_v4_fault_resource_error_keeps_state(self):
        before = waterline(self.s, 200)
        self.s.pool_fault("pf1", "注入", "p2", 5000, 200)
        with self.assertRaises(ResourceError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "pw"), 200)
        self.assertEqual(waterline(self.s, 200), before)

    def test_target_v4_draining_resource_error_keeps_state(self):
        before = waterline(self.s, 200)
        self.s.pool_drain("pd", "开始", "p2", ("default",), 0, 100)
        with self.assertRaises(ResourceError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "pw"), 200)
        self.assertEqual(waterline(self.s, 200), before)

    def test_target_v6_draining_resource_error_keeps_state(self):
        before = waterline(self.s, 200)
        self.s.prefix_pool_drain("pd", "开始", "v6b", ("v6a",), 0, 100)
        with self.assertRaises(ResourceError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "pw"), 200)
        self.assertEqual(waterline(self.s, 200), before)
        row = [
            r for r in json.loads(self.s.sessions(200))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"]=="v6a", True)

    def test_target_v6_exhausted_resource_error_keeps_both_families(self):
        s = make_sessions()
        load(
            s,
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48", 56),
                v6_entry("tiny", "2001:db8:9::/128", 128),
            ),
            template_v6=(("dual", ("v6a", "tiny")),),
        )
        establish(s, "sa", "alice")
        establish(s, "sb", "bob")
        s.do("km", "前缀迁移", "sa", ("tiny", "pw"), 100)
        before = waterline(s, 200)
        with self.assertRaises(ResourceError):
            s.do("kx", "双栈迁移", "sb", ("p2", "tiny", "pw"), 200)
        # v6 失败不得已先迁走 IPv4。
        self.assertEqual(waterline(s, 200), before)
        row = [
            r for r in json.loads(s.sessions(200))["项目"]
            if r["会话"] == "sb"
        ][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"], "v6a")

    def test_target_v4_static_occupied_resource_error(self):
        # 第三个前缀池 v6c 供 s2 在绕开 bob 的 v6a/v6b 静态后落脚，隔离 IPv4
        # 静态占用失败（v6 目标 v6b 的窥视先不被触及，IPv4 校验先失败）。
        pools = (
            pool_entry("default", "10.0.0.0/28"),
            pool_entry("p2", "10.1.0.0/28",
                       static=[("bob", "10.1.0.9")]),
        )
        v6_pools = (
            v6_entry("v6a", "2001:db8::/48", 56,
                     static=[["bob", "2001:db8:0:200::/56"]]),
            v6_entry("v6b", "2001:db8:1::/48", 56,
                     static=[["bob", "2001:db8:1:500::/56"]]),
            v6_entry("v6c", "2001:db8:2::/48", 56),
        )
        s = make_sessions()
        load(s, v4_pools=pools, v6_pools=v6_pools,
             template_v6=(("dual", ("v6a", "v6b", "v6c")),))
        establish(s, "s1", "bob", 0)   # v6a 静态 0:200
        establish(s, "s2", "bob", 10)  # v6b 静态 1:500
        # s1 占住 bob 在 p2 的专属 IPv4 静态址（v6 不动）。
        s.do("km0", "迁移", "s1", ("p2", "pw"), 20)
        # s2 先把前缀挪到 v6c，使 v6 目标 v6b 与当前池不同。
        s.do("km1", "前缀迁移", "s2", ("v6c", "pw"), 25)
        before = waterline(s, 30)
        with self.assertRaises(ResourceError):
            s.do("kx", "双栈迁移", "s2", ("p2", "v6b", "pw"), 30)
        self.assertEqual(waterline(s, 30), before)
        row = [
            r for r in json.loads(s.sessions(30))["项目"]
            if r["会话"] == "s2"
        ][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"], "v6c")

    def test_target_v6_static_occupied_resource_error(self):
        s = loaded_two_pools()
        establish(s, "s1", "bob")
        # s1 先迁到 v6b 占住 bob 的专属静态前缀，同时释出 v6a 静态。
        s.do("km0", "前缀迁移", "s1", ("v6b", "pw"), 20)
        # s2 建立：v6a 静态已释故取得 0:200。
        establish(s, "s2", "bob", 30)
        before = waterline(s, 40)
        with self.assertRaises(ResourceError):
            s.do("kx", "双栈迁移", "s2", ("p2", "v6b", "pw"), 40)
        self.assertEqual(waterline(s, 40), before)
        row = [
            r for r in json.loads(s.sessions(40))["项目"]
            if r["会话"] == "s2"
        ][0]
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertEqual(row["池"], "default")

    def test_backend_failure_before_state_and_no_aging(self):
        before = waterline(self.s, 250)
        self.s.fault("f1", "注入", 10000, 0)
        with self.assertRaises(BackendError):
            self.s.do("kb", "双栈迁移", "s1", ("p2", "v6b", "pw"), 250)
        self.assertEqual(waterline(self.s, 250), before)
        # 退避保留：同刻新 key 仍 BackendError。
        with self.assertRaises(BackendError):
            self.s.do("kb2", "双栈迁移", "s1", ("p2", "v6b", "pw"), 250)

    def test_unknown_sid_backend_order_key_error(self):
        self.s.fault("f1", "注入", 10000, 0)
        with self.assertRaises(KeyError):
            self.s.do("kx", "双栈迁移", "missing",
                      ("p2", "v6b", "pw"), 0)

    def test_disabled_user_auth_error_without_change(self):
        self.s.user_admin("ua", "停用", "alice", 0, True)
        with self.assertRaises(AuthError):
            self.s.do("kd", "双栈迁移", "s1", ("p2", "v6b", "pw"), 100)
        # 停用拒绝路径不入审计链。
        chain = json.loads(self.s.audit(0, 100))
        self.assertFalse(any(e["键"] == "kd" for e in chain["事件"]))

    def test_explicit_aging_result_is_kept_on_failure(self):
        # now_ms=1000：IPv6 租期已到先老化释出，双栈迁移随 StateError，
        # 老化结果保留不回滚。
        with self.assertRaises(StateError):
            self.s.do("kx", "双栈迁移", "s1", ("p2", "v6b", "pw"), 1000)
        row = [
            r for r in json.loads(self.s.sessions(1000))["项目"]
            if r["会话"] == "s1"
        ][0]
        self.assertEqual(row["IPv6前缀"], "")


class DualMigrationParamTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        establish(self.s, "s1", "alice")

    def call(self, args, now_ms=100, key="kx"):
        self.s.do(key, "双栈迁移", "s1", args, now_ms)

    def test_args_wrong_type(self):
        for bad in (["p2", "v6b", "pw"], "p2", 42, {"a": 1}, None):
            with self.assertRaises(TypeError):
                self.call(bad, key="kt%r" % (bad,))

    def test_args_wrong_arity(self):
        for bad in (("p2", "v6b"), ("p2", "v6b", "pw", "x"), ()):
            with self.assertRaises(ValueError):
                self.call(bad, key="ka%r" % (bad,))

    def test_field_types(self):
        with self.assertRaises(TypeError):
            self.call((123, "v6b", "pw"), key="kt1")
        with self.assertRaises(TypeError):
            self.call(("p2", 9, "pw"), key="kt2")
        with self.assertRaises(TypeError):
            self.call(("p2", "v6b", 7), key="kt3")

    def test_field_values_and_negative_now(self):
        with self.assertRaises(ValueError):
            self.call(("", "v6b", "pw"), key="kv1")
        with self.assertRaises(ValueError):
            self.call(("p2", "", "pw"), key="kv2")
        with self.assertRaises(ValueError):
            self.call(("p2", "v6b", ""), key="kv3")
        with self.assertRaises(ValueError):
            self.s.do("kn", "双栈迁移", "s1",
                      ("p2", "v6b", "pw"), -1)

    def test_bad_op_still_value_error(self):
        with self.assertRaises(ValueError):
            self.s.do("ko", "不存在", "s1",
                      ("p2", "v6b", "pw"), 0)


class DualMigrationReplayTest(unittest.TestCase):
    def setUp(self):
        self.s = loaded_two_pools()
        establish(self.s, "s1", "alice")

    def test_same_key_same_params_replays_first_result(self):
        first = self.s.do(
            "k9", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500
        )
        replay = self.s.do(
            "k9", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500
        )
        self.assertEqual(replay, first)
        v4, v6 = waterline(self.s, 500)
        self.assertEqual(v4, {"default": 0, "p2": 1})
        self.assertEqual(v6, {"v6a": 0, "v6b": 1})

    def test_same_key_different_params_value_error(self):
        self.s.do("k9", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", "双栈迁移", "s1", ("default", "v6b", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", "双栈迁移", "s1", ("p2", "v6a", "pw"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", "双栈迁移", "s1", ("p2", "v6b", "x"), 500)
        with self.assertRaises(ValueError):
            self.s.do("k9", "双栈迁移", "s1", ("p2", "v6b", "pw"), 501)

    def test_failure_result_is_replayed_and_not_reauthenticated(self):
        # 同池 StateError 首次入缓存，重放同结果。
        for _ in range(2):
            with self.assertRaises(StateError):
                self.s.do("ke", "双栈迁移", "s1",
                          ("default", "v6b", "pw"), 100)
        # 认证失败同样重放，不再次认证（不累计额外失败计数）。
        for _ in range(3):
            with self.assertRaises(AuthError):
                self.s.do("ka", "双栈迁移", "s1",
                          ("p2", "v6b", "nope"), 200)
        stats = json.loads(self.s.user_stats("alice", 200))
        failures = {row["类型"]: row["次数"] for row in stats["失败"]}
        self.assertEqual(failures.get("认证"), 1)


class IndependentLeaseTest(unittest.TestCase):
    def test_dual_migration_resets_both_leases_together(self):
        s = loaded_two_pools()
        establish(s, "s1", "alice")
        s.do("k2", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500)
        view = json.loads(s.sessions(500))["项目"][0]
        self.assertEqual(view["租期"], 1500)
        self.assertEqual(view["IPv6租期"], 1500)
        # 两租期同刻到期（1500）：同时释出，到 1500 两族皆无址；空闲期限
        # 仍是建立时刻 0+50000。
        view = json.loads(s.sessions(1500))["项目"][0]
        self.assertEqual(view["池"], "")
        self.assertEqual(view["IPv6池"], "")
        view = json.loads(s.sessions(4999))["项目"][0]
        self.assertEqual(view["状态"], "在线")


class CheckpointRoundtripTest(unittest.TestCase):
    def _state(self):
        s = loaded_two_pools()
        establish(s, "s1", "alice")
        s.do("k2", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500)
        return s

    def test_clog_roundtrip(self):
        s = self._state()
        before = s.sessions(600)
        text = s.clog(600)
        target = loaded_two_pools()
        target.creplay(text)
        self.assertEqual(target.sessions(600), before)
        self.assertEqual(target.pool_stats(600), s.pool_stats(600))
        self.assertEqual(target.clog(600), text)

    def test_runtime_checkpoint_roundtrip(self):
        s = self._state()
        text = s.runtime_checkpoint(600)
        target = loaded_two_pools()
        self.assertEqual(target.runtime_restore("rk", text), text)
        self.assertEqual(target.sessions(600), s.sessions(600))

    def test_service_checkpoint_roundtrip(self):
        s = self._state()
        text = s.service_checkpoint(600)
        target = loaded_two_pools()
        target.service_restore("sk", text)
        self.assertEqual(target.sessions(600), s.sessions(600))
        self.assertEqual(target.pool_stats(600), s.pool_stats(600))


class DeterminismTest(unittest.TestCase):
    def test_byte_identical_runs(self):
        def run():
            s = loaded_two_pools()
            out = [
                s.do("k1", "建立", "s1", ("alice", "pw"), 0),
                s.do("k2", "双栈迁移", "s1", ("p2", "v6b", "pw"), 500),
                s.sessions(600),
                s.pool_stats(600),
            ]
            return out

        self.assertEqual(run(), run())


class SessionRunCliTest(unittest.TestCase):
    def _request(self):
        doc = base_config(
            v4_pools=(
                pool_entry("default", "10.0.0.0/28"),
                pool_entry("p2", "10.1.0.0/28"),
            ),
            v6_pools=(
                v6_entry("v6a", "2001:db8::/48", 56),
                v6_entry("v6b", "2001:db8:1::/48", 56),
            ),
            template_v6=(("dual", ("v6a", "v6b")),),
        )
        return {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["alice", "pw"], "now_ms": 0},
                {"key": "r2", "op": "双栈迁移", "sid": "s1",
                 "args": ["p2", "v6b", "pw"], "now_ms": 200},
                # 业务失败：两族同池 StateError，仅记类名继续。
                {"key": "r3", "op": "双栈迁移", "sid": "s1",
                 "args": ["p2", "v6b", "pw"], "now_ms": 300},
                # 业务失败：未知 sid KeyError。
                {"key": "r4", "op": "双栈迁移", "sid": "nope",
                 "args": ["p2", "v6b", "pw"], "now_ms": 300},
                # 迁回成功：最终查询反映原子结果。
                {"key": "r5", "op": "双栈迁移", "sid": "s1",
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
        self.assertEqual(
            [(it["结果"], it["类型"]) for it in out["项目"]],
            [(True, ""), (True, ""), (False, "StateError"),
             (False, "KeyError"), (True, "")],
        )
        migrated = out["项目"][1]["输出"]
        self.assertEqual(list(migrated), KEYS)
        row = [r for r in out["会话"]["项目"] if r["会话"] == "s1"][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertEqual(row["租期"], 1400)
        self.assertEqual(row["IPv6租期"], 1400)
        v4 = {r[0]: r[4] for r in out["地址池"]["池"]}
        v6 = {r[0]: r[4] for r in out["地址池"][V6_KEY]}
        self.assertEqual(v4, {"default": 1, "p2": 0})
        self.assertEqual(v6, {"v6a": 1, "v6b": 0})
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

    def test_business_failure_unknown_target_pool_recorded(self):
        request = self._request()
        request["requests"][2]["args"] = ["zzz", "v6b", "pw"]
        proc = self._run(request)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = json.loads(proc.stdout.decode())
        self.assertEqual(
            (out["项目"][2]["结果"], out["项目"][2]["类型"]),
            (False, "KeyError"),
        )
        row = [r for r in out["会话"]["项目"] if r["会话"] == "s1"][0]
        # r2 已迁至 p2/v6b，r3 失败不改，r5 迁回 default/v6a。
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["IPv6池"], "v6a")

    def test_auth_failure_recorded_and_continue(self):
        request = self._request()
        request["requests"][1]["args"] = ["p2", "v6b", "nope"]
        proc = self._run(request)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = json.loads(proc.stdout.decode())
        self.assertEqual(
            (out["项目"][1]["结果"], out["项目"][1]["类型"]),
            (False, "AuthError"),
        )
        # r3 此刻同池检测不再成立（s1 仍在 default/v6a），迁移成功。
        self.assertEqual(
            (out["项目"][2]["结果"], out["项目"][2]["类型"]),
            (True, ""),
        )

    def test_byte_identical_outputs(self):
        request = self._request()
        self.assertEqual(
            self._run(request).stdout, self._run(request).stdout
        )

    def test_static_validation_rejects_bad_shape(self):
        def expect(mutate, type_name):
            bad = self._request()
            mutate(bad)
            proc = self._run(bad)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, b"")
            envelope = json.loads(proc.stderr.decode())
            self.assertEqual(envelope, {
                "错误": "session-run", "类型": type_name
            })

        expect(lambda b: b["requests"][1].__setitem__(
            "args", ["p2", "v6b"]), "ValueError")
        expect(lambda b: b["requests"][1].__setitem__(
            "args", ["p2", "v6b", "pw", "x"]), "ValueError")
        expect(lambda b: b["requests"][1].__setitem__(
            "args", [123, "v6b", "pw"]), "TypeError")
        expect(lambda b: b["requests"][1].__setitem__(
            "args", ["p2", 9, "pw"]), "TypeError")
        expect(lambda b: b["requests"][1].__setitem__(
            "args", ["p2", "v6b", 7]), "TypeError")
        expect(lambda b: b["requests"][1].__setitem__(
            "args", None), "TypeError")
        expect(lambda b: b["requests"][1].__setitem__(
            "args", "p2"), "TypeError")
        expect(lambda b: b["requests"][1].__setitem__(
            "op", "双栈迁移x"), "ValueError")

    def test_pure_v4_config_business_failure(self):
        doc = base_config()
        doc["IPv6 前缀池"] = []
        doc["模板 IPv6 池"] = []
        request = {
            "users": [[u, "pw"] for u in USERS],
            "config": doc,
            "requests": [
                {"key": "r1", "op": "建立", "sid": "s1",
                 "args": ["dave", "pw"], "now_ms": 0},
                {"key": "r2", "op": "双栈迁移", "sid": "s1",
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
