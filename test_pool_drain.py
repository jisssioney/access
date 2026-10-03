"""可恢复地址池排空 pool_drain / pool_drain_status 的测试。

覆盖：参数校验与异常次序（TypeError/ValueError/KeyError/StateError）、开始
幂等与目标顺序冲突、推进的老化/码点序/limit/静态优先/目标后备/池故障/排空
目标跳过/ResourceError 项/原子换址/租期与期限语义、取消不迁回、只读状态、
同键同参逐字节重放与异参 ValueError、批量审计链与合规链投影、源池在建立/
恢复/接管/容量晋升/模板后备各通道的新分配阻断、配置删池 ResourceError
原子保持、运行态检查点（无排空逐字节一致、含排空往返、旧版本无排空键、
恢复失败原子）。"""

import ipaddress
import json
import unittest

from access import (
    Authenticator,
    Sessions,
    AuthError,
    ResourceError,
    StateError,
)


def make(users=("alice", "bob", "carol"), total=100, per=100,
         pool=("10.0.0.0/29", (), ()), idle_ms=100000, lease_ms=1000):
    auth = Authenticator(3, 100000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(
        auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms
    )


def add_pool(s, pool_id="p2", cidr="10.0.2.0/29", reserved=(), static=()):
    s.add_pool(pool_id, (cidr, reserved, static))


def parse(text):
    return json.loads(text)


def establish(s, key, sid, user="alice", now=0):
    return s.do(key, "建立", sid, (user, "pw"), now)


class DrainParamTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        add_pool(self.s)

    def test_key_credential_checked_first(self):
        for bad in (True, 1, None, b"k", ()):
            with self.assertRaises(TypeError):
                self.s.pool_drain(bad, "开始", "default", ("p2",), 0, 10)
        with self.assertRaises(ValueError):
            self.s.pool_drain("", "开始", "default", ("p2",), 0, 10)

    def test_type_errors(self):
        s = self.s
        with self.assertRaises(TypeError):
            s.pool_drain("k", 5, "default", ("p2",), 0, 10)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", 9, ("p2",), 0, 10)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "default", ["p2"], 0, 10)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "default", (9,), 0, 10)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "default", ("p2",), "x", 10)
        for bad_now in (1.5, "0", None, True, False):
            with self.assertRaises(TypeError):
                s.pool_drain("kn" + str(bad_now), "开始", "default", ("p2",),
                             bad_now, 10)
        for bad_limit in (1.5, "5", None, True, False):
            with self.assertRaises(TypeError):
                s.pool_drain("kl" + str(bad_limit), "开始", "default", ("p2",),
                             0, bad_limit)

    def test_value_errors(self):
        s = self.s
        with self.assertRaises(ValueError):
            s.pool_drain("k", "冻结", "default", ("p2",), 0, 10)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", (), 0, 10)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("p2", "p2"), 0, 10)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("default",), 0, 10)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("p2",), -1, 10)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("p2",), 0, 0)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("p2",), 0, 1001)

    def test_type_precedes_value(self):
        s = self.s
        # 类型错先于空列表/重复/非法操作。
        with self.assertRaises(TypeError):
            s.pool_drain("k", "冻结", "default", [], 0, 0)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", 9, (), "x", 0)

    def test_unknown_pools(self):
        s = self.s
        with self.assertRaises(KeyError):
            s.pool_drain("k", "开始", "nope", ("p2",), 0, 10)
        with self.assertRaises(KeyError):
            s.pool_drain("k", "开始", "default", ("nope",), 0, 10)
        # 源池先于目标池判定。
        with self.assertRaises(KeyError):
            s.pool_drain("k", "开始", "nope", ("alsonope",), 0, 10)

    def test_param_failure_does_not_cache_or_drain(self):
        s = self.s
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", (), 0, 10)
        # 失败不写批量审计链、不建排空态。
        self.assertEqual(parse(s.batch_audit(0, 1000))["事件"], [])
        with self.assertRaises(StateError):
            s.pool_drain_status("default", 0)
        # 参数错不占 key：同 key 改正参数后成功。
        out = s.pool_drain("k", "开始", "default", ("p2",), 0, 10)
        self.assertEqual(parse(out)["状态"], "排空中")

    def test_status_validation(self):
        s = self.s
        with self.assertRaises(TypeError):
            s.pool_drain_status("default", True)
        with self.assertRaises(KeyError):
            s.pool_drain_status("nope", 0)
        with self.assertRaises(StateError):
            s.pool_drain_status("p2", 0)


class DrainStartTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        add_pool(self.s)

    def test_start_shape_and_block_establish(self):
        s = self.s
        establish(s, "e1", "a")
        out = parse(s.pool_drain("d", "开始", "default", ("p2",), 0, 10))
        self.assertEqual(
            list(out), ["时刻", "源池", "状态", "剩余", "项目"]
        )
        self.assertEqual(
            out, {"时刻": 0, "源池": "default", "状态": "排空中",
                  "剩余": 1, "项目": []}
        )
        # LF 结尾紧凑 JSON。
        raw = s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw)
        # 建立被阻断（未绑定模板仅候选 default）。
        with self.assertRaises(ResourceError):
            establish(s, "e2", "b")

    def test_start_idempotent_same_order_any_key(self):
        s = self.s
        out1 = s.pool_drain("d1", "开始", "default", ("p2",), 0, 10)
        # 同序同集再次开始（即使不同 key）为空操作成功。
        out2 = s.pool_drain("d2", "开始", "default", ("p2",), 5, 10)
        self.assertEqual(parse(out2)["状态"], "排空中")

    def test_start_different_order_state_error(self):
        s = self.s
        add_pool(self.s, "p3", "10.0.3.0/29")
        s.pool_drain("d1", "开始", "default", ("p2", "p3"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("d2", "开始", "default", ("p3", "p2"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("d3", "开始", "default", ("p2",), 0, 10)

    def test_start_preserves_sessions_prefixes_queue(self):
        s = self.s
        establish(s, "e1", "a")
        before = s.sessions(0)
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        self.assertEqual(s.sessions(0), before)


class DrainAdvanceTest(unittest.TestCase):
    def test_codepoint_order_limit_and_lease_reset(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "z", "alice")
        establish(s, "e2", "a", "bob")
        establish(s, "e3", "m", "carol")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p2",), 500, 2))
        self.assertEqual(
            [(i["会话"], i["目标池"], i["结果"]) for i in out["项目"]],
            [("a", "p2", "迁移"), ("m", "p2", "迁移")],
        )
        self.assertEqual(out["状态"], "排空中")
        self.assertEqual(out["剩余"], 1)
        rows = {r["会话"]: r for r in parse(s.sessions(500))["项目"]}
        # 已迁：换池址、IPv4 租期重置为 500+1000、空闲期限不变。
        self.assertEqual(rows["a"]["池"], "p2")
        self.assertEqual(rows["a"]["租期"], 1500)
        self.assertEqual(rows["a"]["期限"], 100000)
        self.assertEqual(rows["m"]["池"], "p2")
        # 未处理项保持源池与原租期。
        self.assertEqual(rows["z"]["池"], "default")
        self.assertEqual(rows["z"]["租期"], 1000)
        # 第二批排空剩余 z。
        out2 = parse(s.pool_drain("k2", "推进", "default", ("p2",), 500, 10))
        self.assertEqual(
            [i["会话"] for i in out2["项目"]], ["z"]
        )
        self.assertEqual(out2["状态"], "已排空")
        self.assertEqual(out2["剩余"], 0)

    def test_drained_still_blocks_new_allocations(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        self.assertEqual(
            parse(s.pool_drain_status("default", 0))["状态"], "已排空"
        )
        with self.assertRaises(ResourceError):
            establish(s, "e2", "b")

    def test_advance_without_start_state_error(self):
        _auth, s = make()
        add_pool(s)
        with self.assertRaises(StateError):
            s.pool_drain("k", "推进", "default", ("p2",), 0, 10)

    def test_advance_wrong_target_order_state_error(self):
        _auth, s = make()
        add_pool(s)
        add_pool(s, "p3", "10.0.3.0/29")
        s.pool_drain("d", "开始", "default", ("p2", "p3"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("k", "推进", "default", ("p3", "p2"), 0, 10)

    def test_static_binding_priority(self):
        _auth, s = make()
        # p2 中 alice 有专属静态址 10.0.2.6。
        add_pool(s, static=(("alice", "10.0.2.6"),))
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p2",), 0, 10))
        rows = {i["会话"]: i for i in out["项目"]}
        # a(alice) 取静态，b(bob) 取最小动态 10.0.2.1。
        sess = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        self.assertEqual(sess["a"]["地址"], "10.0.2.6")
        self.assertEqual(sess["b"]["地址"], "10.0.2.1")

    def test_target_fallback_order(self):
        _auth, s = make()
        # p3 仅一个可用地址（/32），p2 充裕；目标序 p3 优先。
        add_pool(s, "p3", "10.0.3.0/32")
        add_pool(s, "p2", "10.0.2.0/29")
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        s.pool_drain("d", "开始", "default", ("p3", "p2"), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p3", "p2"), 0, 10))
        mapping = {i["会话"]: i["目标池"] for i in out["项目"]}
        # 码点序 a 先占 p3 独址，b 回退 p2。
        self.assertEqual(mapping["a"], "p3")
        self.assertEqual(mapping["b"], "p2")

    def test_pool_fault_target_skipped(self):
        _auth, s = make(lease_ms=100000)
        add_pool(s)
        establish(s, "e1", "a", "alice")
        # p2 耗尽演练：无目标可承载 -> ResourceError，原址不变。
        s.pool_fault("pf", "注入", "p2", 5000, 0)
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p2",), 0, 10))
        self.assertEqual(
            out["项目"],
            [{"会话": "a", "目标池": "", "结果": "ResourceError"}],
        )
        self.assertEqual(out["剩余"], 1)
        self.assertEqual(out["状态"], "排空中")
        row = parse(s.sessions(0))["项目"][0]
        self.assertEqual(row["池"], "default")
        self.assertEqual(row["地址"], "10.0.0.1")
        # 到刻恢复后推进成功（租期 100000 未到）。
        out2 = parse(s.pool_drain("k2", "推进", "default", ("p2",), 6000, 10))
        self.assertEqual(out2["项目"][0]["结果"], "迁移")

    def test_draining_target_skipped(self):
        _auth, s = make()
        add_pool(s, "p2", "10.0.2.0/29")
        add_pool(s, "p3", "10.0.3.0/29")
        establish(s, "e1", "a", "alice")
        # p2 自身排空中：default->[p2,p3] 应跳过 p2 取 p3。
        s.pool_drain("d2", "开始", "p2", ("p3",), 0, 10)
        s.pool_drain("d1", "开始", "default", ("p2", "p3"), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p2", "p3"), 0, 10))
        self.assertEqual(out["项目"][0]["目标池"], "p3")

    def test_no_double_occupancy_after_success(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        stats = {row[0]: row for row in parse(s.pool_stats(0))["池"]}
        # default 租用 0、动态空闲全回收；p2 租用 1。
        self.assertEqual(stats["default"][4], 0)
        self.assertEqual(stats["default"][5], stats["default"][1])
        self.assertEqual(stats["p2"][4], 1)
        # 每个池租约表内地址唯一（无重复占用）。
        for pool in s._pools.values():
            self.assertEqual(len(pool.leases), len(set(pool.leases)))

    def test_advance_ages_first(self):
        # 租期 1000、空闲 100000：t=2000 推进时老化先释址（仅租期到期 ->
        # 释 IPv4、会话仍在线无址），无有效持址会话 -> 已排空，不迁移。
        _auth, s = make(lease_ms=1000)
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p2",), 2000, 10))
        self.assertEqual(out["项目"], [])
        self.assertEqual(out["状态"], "已排空")
        row = parse(s.sessions(2000))["项目"][0]
        self.assertEqual(row["状态"], "在线")
        self.assertEqual(row["池"], "")
        self.assertEqual(row["地址"], "")

    def test_item_failure_does_not_block_others(self):
        _auth, s = make()
        add_pool(s, "p3", "10.0.3.0/32")  # 一址
        add_pool(s, "p2", "10.0.2.0/32")  # 一址
        establish(s, "e1", "a", "alice")
        establish(s, "e2", "b", "bob")
        establish(s, "e3", "c", "carol")
        # 两目标各一址，第三项无承载 -> ResourceError，前两项成功。
        s.pool_drain("d", "开始", "default", ("p3", "p2"), 0, 10)
        out = parse(s.pool_drain("k", "推进", "default", ("p3", "p2"), 0, 10))
        results = [i["结果"] for i in out["项目"]]
        self.assertEqual(results.count("迁移"), 2)
        self.assertEqual(results.count("ResourceError"), 1)
        self.assertEqual(out["剩余"], 1)
        self.assertEqual(out["状态"], "排空中")

    def test_dual_stack_ipv6_preserved(self):
        _auth, s = make()
        add_pool(s, "p2", "10.1.0.0/28")
        self._configure_dual(s)
        before = parse(s.do("e1", "建立", "a", ("alice", "pw"), 0))
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 500, 10)
        after = parse(s.sessions(500))["项目"][0]
        self.assertEqual(after["池"], "p2")
        self.assertEqual(after["IPv6池"], "v6a")
        self.assertEqual(after["IPv6前缀"], before["IPv6前缀"])
        self.assertEqual(after["租期"], 1500)       # IPv4 重置
        self.assertEqual(after["IPv6租期"], 1000)  # IPv6 不变
        self.assertEqual(after["期限"], 50000)     # 空闲期限不变

    @staticmethod
    def _configure_dual(s):
        cfg = {
            "版本": 12,
            "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                    "租期毫秒": 1000},
            "地址池": [
                {"标识": "default", "CIDR": "10.0.0.0/28", "保留": [],
                 "静态": []},
                {"标识": "p2", "CIDR": "10.1.0.0/28", "保留": [],
                 "静态": []},
            ],
            "模板": [{"标识": "dual", "限速": 1, "突发": 0,
                      "配额": 10 ** 9, "周期毫秒": 0, "会话上限": 0,
                      "排队优先级": 0, "超限": "拒绝"}],
            "用户模板": [["alice", "dual"]],
            "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
            "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                    "重试基数毫秒": 0, "重试上限毫秒": 0},
            "模板地址池": [],
            "IPv6 前缀池": [
                {"标识": "v6a", "聚合前缀": "2001:db8::/48", "委派长度": 56,
                 "保留": [], "静态": []}
            ],
            "模板 IPv6 池": [["dual", ["v6a"]]],
        }
        s.load_config(json.dumps(cfg, ensure_ascii=False, separators=(",", ":")))

    def test_billing_not_split_by_drain(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        types = [e["类型"] for e in parse(s.accounting_events(0, 100))["事件"]]
        # 迁移不切分计费：仅有建立的“开始”。
        self.assertEqual(types, ["开始"])


class DrainCancelTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        add_pool(self.s)
        establish(self.s, "e1", "a", "alice")

    def test_cancel_restores_selection_no_moveback(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        out = parse(s.pool_drain("c", "取消", "default", ("p2",), 0, 10))
        self.assertEqual(out["状态"], "已取消")
        # 取消后 default 恢复承接新分配。
        new = parse(establish(s, "e2", "b", "bob"))
        self.assertEqual(new["地址"], "10.0.0.1")
        # 已迁出会话不迁回。
        rows = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        self.assertEqual(rows["a"]["池"], "p2")
        # 取消后状态查询为无排空。
        with self.assertRaises(StateError):
            s.pool_drain_status("default", 0)

    def test_cancel_without_start_state_error(self):
        with self.assertRaises(StateError):
            self.s.pool_drain("c", "取消", "p2", ("default",), 0, 10)

    def test_cancel_wrong_targets_state_error(self):
        s = self.s
        add_pool(s, "p3", "10.0.3.0/29")
        s.pool_drain("d", "开始", "default", ("p2", "p3"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("c", "取消", "default", ("p3", "p2"), 0, 10)


class DrainStatusTest(unittest.TestCase):
    def test_status_read_only_does_not_age(self):
        _auth, s = make(lease_ms=1000)
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        # 租期 1000，t=2000 只读查询：不老化、按 now_ms 视图计有效持址
        # （租期 <= now_ms 不计）-> 剩余 0，但会话与租约表保持原状。
        out = parse(s.pool_drain_status("default", 2000))
        self.assertEqual(out, {"源池": "default", "状态": "排空中", "剩余": 0})
        # 查询未改态、未释放：t=0 视图仍剩余 1。
        self.assertEqual(
            parse(s.pool_drain_status("default", 0))["剩余"], 1
        )
        row = parse(s.sessions(0))["项目"][0]
        self.assertEqual(row["池"], "default")


class DrainReplayTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        add_pool(self.s)
        establish(self.s, "e1", "a", "alice")
        establish(self.s, "e2", "b", "bob")

    def test_same_key_same_params_byte_identical(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        first = s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        # 同参重放（含相同 now_ms）不老化、不改态，逐字节相同。
        replay = s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        self.assertEqual(replay, first)
        # 异 now_ms 即异参 -> ValueError。
        with self.assertRaises(ValueError):
            s.pool_drain("k", "推进", "default", ("p2",), 9999, 10)

    def test_diff_params_value_error(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "推进", "default", ("p2",), 0, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "取消", "default", ("p2",), 0, 10)

    def test_replay_does_not_change_state(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 1)
        # a 已迁出，b 仍在 default；同参重放不得再迁 b。
        s.pool_drain("k", "推进", "default", ("p2",), 0, 1)
        rows = {r["会话"]: r for r in parse(s.sessions(0))["项目"]}
        self.assertEqual(rows["a"]["池"], "p2")
        self.assertEqual(rows["b"]["池"], "default")


class DrainAuditTest(unittest.TestCase):
    def setUp(self):
        _auth, self.s = make()
        add_pool(self.s)
        establish(self.s, "e1", "a", "alice")
        establish(self.s, "e2", "b", "bob")

    def test_batch_chain_and_replay(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)  # 重放
        events = parse(s.batch_audit(0, 1000))["事件"]
        # 开始 1 条（会话=源池、结果=状态），首调 2 条、重放 2 条。
        self.assertEqual(len(events), 5)
        ops = {(e["操作"], e["原子"]) for e in events}
        self.assertEqual(ops, {("地址池排空", False)})
        self.assertEqual(events[0]["会话"], "default")
        self.assertEqual(events[0]["结果"], "排空中")
        self.assertEqual(events[0]["原序号"], 0)
        first_seqs = {e["会话"]: e["序号"] for e in events[1:3]}
        for ev in events[3:]:
            self.assertEqual(ev["结果"], "重放")
            self.assertEqual(ev["原序号"], first_seqs[ev["会话"]])
        # 链哈希衔接。
        prev = "0" * 64
        for ev in events:
            self.assertEqual(ev["前哈希"], prev)
            prev = ev["哈希"]

    def test_projected_to_compliance_chain(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 1)
        events = parse(s.compliance_events(0, 1000))["事件"]
        batch = [e for e in events if e["来源"] == "批量"]
        self.assertTrue(batch)
        # 载荷为 batch_audit 十键。
        payload = parse(batch[0]["载荷"])
        self.assertEqual(
            list(payload),
            ["序号", "时刻", "键", "操作", "原子", "会话", "结果",
             "原序号", "前哈希", "哈希"],
        )

    def test_cancel_event(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("c", "取消", "default", ("p2",), 0, 10)
        events = parse(s.batch_audit(0, 1000))["事件"]
        self.assertEqual([e["结果"] for e in events], ["排空中", "已取消"])
        self.assertTrue(all(e["会话"] == "default" for e in events))

    def test_batch_audit_restore_accepts_drain_events(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        page = s.batch_audit(0, 1000)
        _auth2, s2 = make()
        add_pool(s2)
        res = parse(s2.batch_audit_restore("r", page))
        self.assertEqual(res["追加"], 3)
        # 重放空操作（不重复追加），返回缓存结果。
        self.assertEqual(
            parse(s2.batch_audit_restore("r", page))["追加"], 3
        )
        self.assertEqual(
            len(parse(s2.batch_audit(0, 1000))["事件"]), 3
        )

    def test_compliance_restore_accepts_drain_projection(self):
        s = self.s
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 1)
        snapshot = s.compliance_snapshot(0, 1000)
        _auth2, s2 = make()
        add_pool(s2)
        s2.compliance_restore("cr", snapshot)
        events = parse(s2.compliance_events(0, 1000))["事件"]
        drain = [
            e for e in events
            if json.loads(e["载荷"])["操作"] == "地址池排空"
        ]
        self.assertTrue(drain)


class DrainAllocationBlockTest(unittest.TestCase):
    def test_resume_blocked(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.do("su", "挂起", "a", None, 0)
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        with self.assertRaises(ResourceError):
            s.do("r", "恢复", "a", ("default", "pw"), 0)
        # 取消后恢复成功。
        s.pool_drain("c", "取消", "default", ("p2",), 0, 10)
        out = parse(s.do("r2", "恢复", "a", ("default", "pw"), 0))
        self.assertEqual(out["状态"], "在线")

    def test_takeover_new_alloc_blocked(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.do("su", "挂起", "a", None, 0)
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        # 挂起旧会话无址，接管需自 default 新分配 -> ResourceError。
        with self.assertRaises(ResourceError):
            s.do("t", "接管", "a2", ("a", "pw"), 0)

    def test_capacity_promotion_skips_draining(self):
        _auth, s = make(total=1, per=1)
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        # 全局上限 1、a 占着；先排队 b（无可用址亦排队），下线 a 后推进，
        # 但 default 排空中、无其他候选，b 不能晋升仍留队。
        s.capacity("q", "申请", "b", ("bob", "pw", 1000000), 0)
        s.do("off", "下线", "a", None, 0)
        out = parse(s.capacity("adv", "推进", "", None, 0))
        self.assertEqual(out["在线"], 0)
        self.assertEqual(out["排队"], 1)

    def test_template_fallback_skips_draining(self):
        # 模板候选序 [p2, default]，p2 排空中时建立回退 default。
        _auth, s = make()
        add_pool(s, "p2", "10.0.2.0/29")
        s.load_config(_template_cfg())
        s.pool_drain("d", "开始", "p2", ("default",), 0, 10)
        out = parse(establish(s, "e1", "a", "alice"))
        self.assertEqual(out["地址"], "10.0.0.1")


def _template_cfg():
    cfg = {
        "版本": 12,
        "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 100000,
                "租期毫秒": 1000},
        "地址池": [
            {"标识": "default", "CIDR": "10.0.0.0/29", "保留": [],
             "静态": []},
            {"标识": "p2", "CIDR": "10.0.2.0/29", "保留": [], "静态": []},
        ],
        "模板": [{"标识": "t", "限速": 1, "突发": 0, "配额": 10 ** 9,
                  "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
                  "超限": "拒绝"}],
        "用户模板": [["alice", "t"], ["bob", "t"], ["carol", "t"]],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                "重试基数毫秒": 0, "重试上限毫秒": 0},
        "模板地址池": [["t", ["p2", "default"]]],
        "IPv6 前缀池": [],
        "模板 IPv6 池": [],
    }
    return json.dumps(cfg, ensure_ascii=False, separators=(",", ":"))


class DrainConfigGuardTest(unittest.TestCase):
    def _cfg_without(self, s, pool_id):
        cfg = json.loads(s.export_config())
        cfg["地址池"] = [p for p in cfg["地址池"] if p["标识"] != pool_id]
        return json.dumps(cfg, ensure_ascii=False, separators=(",", ":"))

    def test_delete_target_pool_resource_error_atomic(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        rev_before = s.config_revision()
        with self.assertRaises(ResourceError):
            s.load_config(self._cfg_without(s, "p2"))
        # 原子保持：池、排空态、会话与修订均不变。
        self.assertIn("p2", s._pools)
        self.assertEqual(
            parse(s.pool_drain_status("default", 0))["状态"], "排空中"
        )
        self.assertEqual(s.config_revision(), rev_before)
        self.assertEqual(parse(s.sessions(0))["项目"][0]["池"], "default")

    def test_delete_source_pool_resource_error(self):
        _auth, s = make()
        add_pool(s)
        s.pool_drain("d", "开始", "p2", ("default",), 0, 10)
        with self.assertRaises(ResourceError):
            s.load_config(self._cfg_without(s, "p2"))
        self.assertIn("p2", s._pools)

    def test_delete_unrelated_pool_ok(self):
        _auth, s = make()
        add_pool(s)
        add_pool(s, "p3", "10.0.3.0/29")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        # 删除不相关的 p3 成功，排空态保留。
        s.load_config(self._cfg_without(s, "p3"))
        self.assertNotIn("p3", s._pools)
        self.assertEqual(
            parse(s.pool_drain_status("default", 0))["状态"], "排空中"
        )


class DrainCheckpointTest(unittest.TestCase):
    def test_no_drain_byte_identical_and_restore_as_none(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)), ["版本", "时刻", "容量", "配额", "摘要"]
        )
        # 恢复到空实例后视为无排空池。
        _auth2, s2 = make()
        add_pool(s2)
        s2.runtime_restore("r", cp)
        with self.assertRaises(StateError):
            s2.pool_drain_status("default", 0)

    def test_drain_roundtrip(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        cp = s.runtime_checkpoint(0)
        self.assertEqual(
            list(json.loads(cp)),
            ["版本", "时刻", "容量", "配额", "排空", "摘要"],
        )
        _auth2, s2 = make()
        add_pool(s2)
        out = json.loads(s2.runtime_restore("r", cp))
        self.assertEqual(
            out["排空"],
            [{"源池": "default", "状态": "排空中", "目标": ["p2"]}],
        )
        status = parse(s2.pool_drain_status("default", 0))
        self.assertEqual(status["状态"], "排空中")
        self.assertEqual(status["剩余"], 1)
        # 恢复后可继续推进至已排空。
        adv = parse(s2.pool_drain("k2", "推进", "default", ("p2",), 0, 10))
        self.assertEqual(adv["状态"], "已排空")

    def test_drained_state_roundtrip(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        s.pool_drain("k", "推进", "default", ("p2",), 0, 10)
        cp = s.runtime_checkpoint(0)
        _auth2, s2 = make()
        add_pool(s2)
        s2.runtime_restore("r", cp)
        self.assertEqual(
            parse(s2.pool_drain_status("default", 0))["状态"], "已排空"
        )

    def test_restore_unknown_drain_pool_resource_error(self):
        _auth, s = make()
        add_pool(s)
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        cp = s.runtime_checkpoint(0)
        # 目标实例只有 default，缺目标池 p2 -> ResourceError。
        _auth2, s2 = make()
        with self.assertRaises(ResourceError):
            s2.runtime_restore("r", cp)
        # 失败原子：实例仍无排空态。
        with self.assertRaises(StateError):
            s2.pool_drain_status("default", 0)

    def test_restore_malformed_drain_value_error(self):
        _auth, s = make()
        add_pool(s)
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        cp = json.loads(s.runtime_checkpoint(0))
        cp["排空"][0]["状态"] = "非法"
        text = json.dumps(cp, ensure_ascii=False, separators=(",", ":"))
        _auth2, s2 = make()
        add_pool(s2)
        with self.assertRaises(ValueError):
            s2.runtime_restore("r", text)

    def test_service_checkpoint_carries_drain(self):
        _auth, s = make()
        add_pool(s)
        establish(s, "e1", "a", "alice")
        s.pool_drain("d", "开始", "default", ("p2",), 0, 10)
        cp = s.service_checkpoint(0)
        _auth2, s2 = make()
        add_pool(s2)
        # service_restore 要求配置摘要一致：先加载同形配置。
        s2.load_config(s.export_config())
        out = s2.service_restore("r", cp)
        self.assertEqual(
            json.loads(out)["运行态"]["排空"],
            [{"源池": "default", "状态": "排空中", "目标": ["p2"]}],
        )
        self.assertEqual(
            parse(s2.pool_drain_status("default", 0))["状态"], "排空中"
        )


if __name__ == "__main__":
    unittest.main()
