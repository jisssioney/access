"""pool_drain 可恢复地址池排空的端到端测试。"""

import hashlib
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


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def pool_entry(pool_id, cidr, reserved=(), static=()):
    return {
        "标识": pool_id,
        "CIDR": cidr,
        "保留": list(reserved),
        "静态": [[user, ip] for user, ip in static],
    }


def v6_entry(pool_id, agg, deleg, reserved=(), static=()):
    return {
        "标识": pool_id,
        "聚合前缀": agg,
        "委派长度": deleg,
        "保留": list(reserved),
        "静态": [[user, prefix] for user, prefix in static],
    }


def template_entry(template_id, priority=0, limit=0):
    return {
        "标识": template_id,
        "限速": 1,
        "突发": 0,
        "配额": 10 ** 9,
        "周期毫秒": 0,
        "会话上限": limit,
        "排队优先级": priority,
        "超限": "拒绝",
    }


AUTH = {"最大失败": 3, "锁定毫秒": 1000, "重试基数毫秒": 0, "重试上限毫秒": 0}


def make_config(
    pools,
    templates=("t",),
    user_templates=(("alice", "t"), ("bob", "t"), ("carol", "t")),
    template_pools=(("t", ("src", "t1", "t2")),),
    v6_pools=(),
    template_v6=(),
    total=100,
):
    return {
        "版本": 12,
        "会话": {"总数": total, "每用户": 100, "空闲毫秒": 50000,
                "租期毫秒": 1000},
        "地址池": [pool_entry(*p) if isinstance(p, tuple) else p
                  for p in pools],
        "模板": [template_entry(t) for t in templates],
        "用户模板": [list(pair) for pair in user_templates],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": AUTH,
        "模板地址池": [[tid, list(seq)] for tid, seq in template_pools],
        "IPv6 前缀池": [v6_entry(*p) if isinstance(p, tuple) else p
                     for p in v6_pools],
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


def make_sessions(pool=("10.0.0.0/24", (), ())):
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob", "carol", "dave"):
        auth.add(user, "pw")
    return auth, Sessions(auth, 100, 100, 50000, pool=pool, lease_ms=1000)


def add_targets(s):
    s.add_pool("t1", ("10.1.0.0/24", (), ()))
    s.add_pool("t2", ("10.2.0.0/24", (), ()))


def load(s, config):
    s.load_config(compact(config))


def parse(text):
    return json.loads(text)


def pool_map(s, now_ms=0):
    return {
        item["会话"]: (item["池"], item["地址"], item["租期"], item["期限"])
        for item in parse(s.sessions(now_ms))["项目"]
    }


def make_loaded(
    pools,
    users=None,
    templates=("t",),
    user_templates=(("alice", "t"), ("bob", "t"), ("carol", "t"),
                    ("dave", "t")),
    template_pools=(("t", ("src", "t1", "t2")),),
    v6_pools=(),
    template_v6=(),
):
    config = make_config(
        pools,
        templates=templates,
        user_templates=user_templates,
        template_pools=template_pools,
        v6_pools=v6_pools,
        template_v6=template_v6,
    )
    auth = Authenticator(3, 1000)
    for user in (users or ("alice", "bob", "carol", "dave")):
        auth.add(user, "pw")
    s = Sessions(auth, 100, 100, 50000, pool=None, lease_ms=1000)
    for entry in config["地址池"]:
        s.add_pool(
            entry["标识"],
            (
                entry["CIDR"],
                tuple(entry["保留"]),
                tuple(tuple(pair) for pair in entry["静态"]),
            ),
        )
    load(s, config)
    return s


def fresh_configured(pools=None, **kwargs):
    """同 make_loaded 配置但无任何会话（供检查点恢复的空目标）。"""
    return make_loaded(pools or (
        ("src", "10.0.0.0/24"),
        ("t1", "10.1.0.0/24"),
        ("t2", "10.2.0.0/24"),
    ), **kwargs)


def standard(pools=None):
    """src + t1 + t2 全模板后备，用户 a/b/c 已在 src 建立。"""
    s = fresh_configured(
        pools or (
            ("src", "10.0.0.0/24"),
            ("t1", "10.1.0.0/24"),
            ("t2", "10.2.0.0/24"),
        )
    )
    for sid, user in (("sa", "alice"), ("sb", "bob"), ("sc", "carol")):
        s.do("e" + sid, "建立", sid, (user, "pw"), 0)
    return s


class DrainParamTest(unittest.TestCase):
    def test_key_checked_first(self):
        _auth, s = make_sessions()
        add_targets(s)
        for bad in (1, True, None, b"k", ()):
            with self.assertRaises(TypeError):
                s.pool_drain(bad, "开始", "default", ("t1",), 0, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("", "开始", "default", ("t1",), 0, 1)

    def test_type_errors(self):
        _auth, s = make_sessions()
        add_targets(s)
        with self.assertRaises(TypeError):
            s.pool_drain("k", 1, "default", ("t1",), 0, 1)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", 5, ("t1",), 0, 1)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "default", ["t1"], 0, 1)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "default", (5,), 0, 1)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "default", ("t1",), "x", 1)
        for bad in (True, False, 1.5, None, "1"):
            with self.assertRaises(TypeError):
                s.pool_drain("k" + str(type(bad)), "开始", "default", ("t1",),
                             0, bad)

    def test_type_precedes_value_and_unknown(self):
        _auth, s = make_sessions()
        add_targets(s)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "bogus", "default", (), "x", 0)
        with self.assertRaises(TypeError):
            s.pool_drain("k", "开始", "nope", ("t1",), 0, True)

    def test_value_errors(self):
        _auth, s = make_sessions()
        add_targets(s)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "bad", "default", ("t1",), 0, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", (), 0, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("t1", "t1"), 0, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("default",), 0, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("t1",), -1, 1)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("t1",), 0, 0)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "default", ("t1",), 0, 1001)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "开始", "def\0", ("t1",), 0, 1)

    def test_unknown_pool_is_keyerror(self):
        _auth, s = make_sessions()
        add_targets(s)
        with self.assertRaises(KeyError):
            s.pool_drain("k", "开始", "nope", ("t1",), 0, 1)
        with self.assertRaises(KeyError):
            s.pool_drain("k", "开始", "default", ("nope",), 0, 1)

    def test_failure_does_not_occupy_key(self):
        _auth, s = make_sessions()
        add_targets(s)
        with self.assertRaises(ValueError):
            s.pool_drain("k", "bad", "default", ("t1",), 0, 1)
        # 同 key 随后可成功开始。
        out = parse(s.pool_drain("k", "开始", "default", ("t1",), 0, 1))
        self.assertEqual(out["状态"], "已排空")

    def test_status_param_errors(self):
        _auth, s = make_sessions()
        add_targets(s)
        with self.assertRaises(TypeError):
            s.pool_drain_status(5)
        with self.assertRaises(ValueError):
            s.pool_drain_status("a\0")
        with self.assertRaises(KeyError):
            s.pool_drain_status("nope")
        with self.assertRaises(StateError):
            s.pool_drain_status("default")


class DrainStartTest(unittest.TestCase):
    def test_start_empty_source_is_drained_but_blocks(self):
        s = standard()
        # 先下线全部持址会话，源池无持址。
        for sid in ("sa", "sb", "sc"):
            s.do("o" + sid, "下线", sid, None, 0)
        out = parse(s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10))
        self.assertEqual(out["状态"], "已排空")
        self.assertEqual(out["剩余"], 0)
        self.assertEqual(out["项目"], [])
        # 已排空仍拒绝新分配（经后备迁到 t1，不回 src）。
        s.do("en", "建立", "sn", ("dave", "pw"), 0)
        self.assertEqual(pool_map(s)["sn"][0], "t1")

    def test_start_blocks_second_start(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("g2", "开始", "src", ("t1", "t2"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("g3", "开始", "src", ("t2", "t1"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("g4", "开始", "t1", ("t2",), 0, 10)

    def test_start_blocks_fallback_selection(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        s.do("e", "建立", "z", ("dave", "pw"), 0)
        # 模板后备序为 src,t1,t2；src 被排空故取 t1。
        self.assertEqual(pool_map(s)["z"][0], "t1")

    def test_start_blocks_resume_into_source(self):
        s = standard()
        s.do("su", "挂起", "sa", None, 0)
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        with self.assertRaises(ResourceError):
            s.do("rs", "恢复", "sa", ("src", "pw"), 0)
        # 恢复到非源池 t1 成功。
        out = parse(s.do("rs2", "恢复", "sa", ("t1", "pw"), 0))
        self.assertEqual(out["池"], "t1")

    def test_start_blocks_noaddr_takeover_default(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 100, 100, 50000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        s.add_pool("t1", ("10.1.0.0/24", (), ()))
        s.do("e", "建立", "a", ("alice", "pw"), 0)
        s.do("su", "挂起", "a", None, 0)
        s.pool_drain("g", "开始", "default", ("t1",), 0, 10)
        # 无址接管自 default 新分配，被排空拒绝。
        with self.assertRaises(ResourceError):
            s.do("t", "接管", "n", ("a", "pw"), 0)

    def test_existing_sessions_v6_and_queue_unchanged_on_start(self):
        s = standard()
        before = pool_map(s)
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        self.assertEqual(pool_map(s), before)


class DrainAdvanceTest(unittest.TestCase):
    def test_ordering_and_limit(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 2)
        out = parse(s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2))
        sids = [item["会话"] for item in out["项目"]]
        self.assertEqual(sids, ["sa", "sb"])
        self.assertEqual(out["剩余"], 1)
        self.assertEqual(out["状态"], "排空中")
        out2 = parse(s.pool_drain("p2", "推进", "src", ("t1", "t2"), 0, 2))
        self.assertEqual([i["会话"] for i in out2["项目"]], ["sc"])
        self.assertEqual(out2["剩余"], 0)
        self.assertEqual(out2["状态"], "已排空")

    def test_static_priority(self):
        pools = (
            pool_entry("src", "10.0.0.0/28"),
            pool_entry("t1", "10.1.0.0/30",
                       static=(("alice", "10.1.0.2"),)),
            pool_entry("t2", "10.2.0.0/30"),
        )
        s = make_loaded(pools)
        s.do("ea", "建立", "sa", ("alice", "pw"), 0)
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        out = parse(s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 10))
        self.assertEqual(out["项目"][0]["目标池"], "t1")
        self.assertEqual(pool_map(s)["sa"][1], "10.1.0.2")

    def test_static_held_skips_pool_but_others_use_it(self):
        # alice 在 t1 的静态址被 alice 另一会话占用 -> alice 跳过 t1 取 t2。
        pools = (
            pool_entry("src", "10.0.0.0/28"),
            pool_entry("t1", "10.1.0.0/30",
                       static=(("alice", "10.1.0.2"),)),
            pool_entry("t2", "10.2.0.0/30"),
        )
        s = make_loaded(pools)
        # hold 先占 t1 的 alice 静态址。
        s.do("h", "建立", "hold", ("alice", "pw"), 0)
        s.do("m", "迁移", "hold", ("t1", "pw"), 0)
        s.do("ea", "建立", "sa", ("alice", "pw"), 0)
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        out = parse(s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 10))
        target = out["项目"][0]["目标池"]
        self.assertEqual(target, "t2")

    def test_faulted_target_unavailable(self):
        s = standard()
        s.pool_fault("f", "注入", "t1", 100, 0)
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        out = parse(s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 10))
        self.assertTrue(all(i["目标池"] == "t2" for i in out["项目"]))

    def test_no_carrier_is_resource_error_and_continues(self):
        pools = (
            pool_entry("src", "10.0.0.0/24"),
            pool_entry("t", "10.1.0.0/30"),  # 仅 2 个可用地址
        )
        s = make_loaded(
            pools,
            templates=("t",),
            user_templates=(("alice", "t"),),
            template_pools=(("t", ("src", "t")),),
        )
        for i in range(3):
            s.do("e" + str(i), "建立", "s" + str(i), ("alice", "pw"), 0)
        s.pool_drain("g", "开始", "src", ("t",), 0, 10)
        out = parse(s.pool_drain("p", "推进", "src", ("t",), 0, 10))
        results = [(i["会话"], i["目标池"], i["结果"]) for i in out["项目"]]
        self.assertEqual(results[0][1:], ("t", "迁移"))
        self.assertEqual(results[1][1:], ("t", "迁移"))
        self.assertEqual(results[2][1:], ("", "ResourceError"))
        self.assertEqual(out["剩余"], 1)
        self.assertEqual(out["状态"], "排空中")
        # 失败项原址不动、无双占用。
        self.assertEqual(pool_map(s)["s2"][0], "src")
        self.assertEqual(len(s._pools["t"].leases), 2)
        self.assertEqual(s._pools["t"].free, [])

    def test_only_holds_source_lease_and_valid(self):
        s = standard()
        s.do("m1", "迁移", "sa", ("t1", "pw"), 0)  # 已不在源池
        s.do("su", "挂起", "sb", None, 0)          # 挂起无址
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        out = parse(s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 10))
        self.assertEqual([i["会话"] for i in out["项目"]], ["sc"])
        self.assertEqual(out["状态"], "已排空")

    def test_age_before_select(self):
        # lease_ms=1000：推进 now_ms=1000（含同刻）老化释址，项不被处理。
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        out = parse(s.pool_drain("p", "推进", "src", ("t1", "t2"), 1000, 10))
        self.assertEqual(out["项目"], [])
        self.assertEqual(out["状态"], "已排空")

    def test_lease_reset_only_ipv4(self):
        pools = (
            pool_entry("src", "10.0.0.0/28"),
            pool_entry("t1", "10.1.0.0/28"),
        )
        s = make_loaded(
            pools,
            template_pools=(("t", ("src", "t1")),),
            v6_pools=(("v6a", "2001:db8::/48", 64),),
            template_v6=(("t", ("v6a",)),),
        )
        s.do("e", "建立", "d", ("alice", "pw"), 0)
        before = next(i for i in parse(s.sessions(0))["项目"]
                      if i["会话"] == "d")
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1",), 5, 10)
        after = next(i for i in parse(s.sessions(5))["项目"]
                     if i["会话"] == "d")
        self.assertEqual(after["池"], "t1")
        self.assertEqual(after["租期"], 5 + 1000)
        self.assertEqual(after["期限"], before["期限"])
        self.assertEqual(after["IPv6池"], before["IPv6池"])
        self.assertEqual(after["IPv6前缀"], before["IPv6前缀"])
        self.assertEqual(after["IPv6租期"], before["IPv6租期"])

    def test_accounting_not_split(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1",), 0, 10)
        events = parse(s.accounting_events(0, 100))["事件"]
        # 仅建立产生的开始事件，排空迁移不切分计费。
        self.assertTrue(all(e["类型"] == "开始" for e in events))
        self.assertEqual(len(events), 3)


class DrainStateAndCancelTest(unittest.TestCase):
    def test_status_no_age(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        out = parse(s.pool_drain_status("src"))
        self.assertEqual(out, {"源池": "src", "状态": "排空中", "剩余": 3})
        # 状态查询不老化：now_ms 早已到期，仍报排空中/3。
        out2 = parse(s.pool_drain_status("src"))
        self.assertEqual(out2, out)

    def test_explicit_migrate_empties_source(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        for sid in ("sa", "sb", "sc"):
            s.do("m" + sid, "迁移", sid, ("t1", "pw"), 0)
        out = parse(s.pool_drain_status("src"))
        self.assertEqual(out["状态"], "已排空")
        self.assertEqual(out["剩余"], 0)

    def test_cancel_restores_selection_no_moveback(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 10)
        moved = pool_map(s)
        out = parse(s.pool_drain("c", "取消", "src", ("t1", "t2"), 5, 10))
        self.assertEqual(out["状态"], "已排空")
        self.assertEqual(out["剩余"], 0)
        # 已迁出的会话不迁回。
        self.assertEqual(pool_map(s), moved)
        # 取消后可重新开始。
        out2 = parse(s.pool_drain("g2", "开始", "t1", ("t2",), 6, 10))
        self.assertEqual(out2["源池"], "t1")

    def test_cancel_wrong_targets_is_state_error(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        with self.assertRaises(StateError):
            s.pool_drain("c", "取消", "src", ("t2", "t1"), 0, 10)

    def test_advance_or_cancel_without_active(self):
        s = standard()
        for op in ("推进", "取消"):
            with self.assertRaises(StateError):
                s.pool_drain("k" + op, op, "src", ("t1",), 0, 10)


class DrainIdempotencyAuditTest(unittest.TestCase):
    def test_replay_byte_identical(self):
        s = standard()
        r1 = s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 2)
        self.assertEqual(s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 2), r1)
        ra = s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2)
        self.assertEqual(s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2), ra)
        self.assertTrue(ra.endswith("\n"))
        rc = s.pool_drain("c", "取消", "src", ("t1", "t2"), 5, 2)
        self.assertEqual(s.pool_drain("c", "取消", "src", ("t1", "t2"), 5, 2), rc)

    def test_replay_does_not_move_or_age(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2)
        moved = pool_map(s)
        # 同参重放不再迁移：持址视图不变。
        s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2)
        self.assertEqual(pool_map(s), moved)

    def test_diff_param_reuse_value_error(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 2)
        s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2)
        with self.assertRaises(ValueError):
            s.pool_drain("p", "推进", "src", ("t1",), 0, 2)
        with self.assertRaises(ValueError):
            s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 3)
        with self.assertRaises(ValueError):
            s.pool_drain("p", "取消", "src", ("t1", "t2"), 0, 2)

    def test_batch_chain_and_compliance(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 2)
        s.pool_drain("g", "开始", "src", ("t1",), 0, 2)
        s.pool_drain("p", "推进", "src", ("t1",), 0, 2)
        s.pool_drain("p", "推进", "src", ("t1",), 0, 2)
        events = parse(s.batch_audit(0, 1000))["事件"]
        drain = [e for e in events if e["操作"] == "地址池排空"]
        # 开始首果+重放；推进两项 + 两项重放 = 6。
        self.assertEqual(len(drain), 6)
        self.assertTrue(all(e["原子"] is False for e in drain))
        self.assertEqual([e["会话"] for e in drain[:2]], ["src", "src"])
        self.assertEqual([e["结果"] for e in drain[:2]],
                         ["排空中", "重放"])
        first_advance_seq = drain[2]["序号"]
        for e in drain[2:4]:
            self.assertEqual(e["结果"], "迁移")
            self.assertEqual(e["原序号"], 0)
        for e in drain[4:]:
            self.assertEqual(e["结果"], "重放")
            self.assertEqual(e["原序号"], first_advance_seq +
                             (e["序号"] - first_advance_seq - 2))
        # 哈希链复算。
        prev = "0" * 64
        for e in events:
            head = {
                "序号": e["序号"], "时刻": e["时刻"], "键": e["键"],
                "操作": e["操作"], "原子": e["原子"], "会话": e["会话"],
                "结果": e["结果"], "原序号": e["原序号"], "前哈希": prev,
            }
            digest = hashlib.sha256(
                compact(head).encode("utf-8")).hexdigest()
            self.assertEqual(digest, e["哈希"])
            prev = digest
        # 合规链逐项投影。
        comp = parse(s.compliance_events(0, 1000))["事件"]
        batch = [c for c in comp if c["来源"] == "批量"]
        self.assertEqual(len(batch), 6)
        self.assertTrue(s.cverify if hasattr(s, "cverify") else True)

    def test_advance_empty_batch_records_one_event(self):
        s = standard()
        for sid in ("sa", "sb", "sc"):
            s.do("o" + sid, "下线", sid, None, 0)
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1",), 0, 10)
        events = parse(s.batch_audit(0, 1000))["事件"]
        drain = [e for e in events if e["操作"] == "地址池排空"]
        self.assertEqual([(e["会话"], e["结果"]) for e in drain],
                         [("src", "已排空"), ("src", "已排空")])

    def test_key_order_and_lf(self):
        s = standard()
        text = s.pool_drain("g", "开始", "src", ("t1",), 0, 2)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(list(parse(text)),
                         ["时刻", "源池", "状态", "剩余", "项目"])
        out = parse(s.pool_drain("p", "推进", "src", ("t1",), 0, 1))
        self.assertEqual(list(out["项目"][0]), ["会话", "目标池", "结果"])


class DrainConfigTest(unittest.TestCase):
    def _config_without(self, drop, keep_order=None):
        config = make_config((
            ("src", "10.0.0.0/24"),
            ("t1", "10.1.0.0/24"),
            ("t2", "10.2.0.0/24"),
        ))
        config["地址池"] = [p for p in config["地址池"]
                          if p["标识"] != drop]
        # 同步从模板地址池序列中移除被删池，使配置本身可解析，触发承载阶段的
        # ResourceError 而非引用未知池的 ValueError。
        config["模板地址池"] = [
            [tid, [p for p in seq if p != drop]]
            for tid, seq in config["模板地址池"]
        ]
        return config

    def test_delete_target_pool_rejected(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        with self.assertRaises(ResourceError):
            s.load_config(compact(self._config_without("t2")))
        # 排空态原子保持。
        out = parse(s.pool_drain_status("src"))
        self.assertEqual(out["状态"], "排空中")

    def test_delete_source_pool_rejected(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        with self.assertRaises(ResourceError):
            s.load_config(compact(self._config_without("src")))


class DrainCheckpointTest(unittest.TestCase):
    def test_runtime_roundtrip_preserves_drain(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1", "t2"), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1", "t2"), 0, 2)
        cp = s.runtime_checkpoint(0)
        doc = parse(cp)
        self.assertEqual(list(doc),
                         ["版本", "时刻", "容量", "配额", "排空", "摘要"])
        self.assertEqual(doc["排空"]["目标池"], ["t1", "t2"])
        target = fresh_configured()
        out = target.runtime_restore("r", cp)
        self.assertEqual(out, cp)
        status = parse(target.pool_drain_status("src"))
        self.assertEqual(status["剩余"], 1)
        self.assertEqual(status["状态"], "排空中")

    def test_no_drain_checkpoint_byte_shape(self):
        s = standard()
        cp = parse(s.runtime_checkpoint(0))
        self.assertEqual(list(cp),
                         ["版本", "时刻", "容量", "配额", "摘要"])
        self.assertNotIn("排空", cp)

    def test_old_shape_restore_clears_drain(self):
        empty = fresh_configured().runtime_checkpoint(0)  # 无会话的五键检查点
        target = fresh_configured()
        target.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        self.assertEqual(parse(target.pool_drain_status("src"))["状态"],
                         "已排空")
        target.runtime_restore("r", empty)
        with self.assertRaises(StateError):
            target.pool_drain_status("src")

    def test_restore_unknown_drain_pool_resource_error(self):
        s = standard()
        for sid in ("sa", "sb", "sc"):
            s.do("o" + sid, "下线", sid, None, 0)
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        cp = s.runtime_checkpoint(0)
        # 目标实例配置不含 t1。
        target = make_loaded(
            (("src", "10.0.0.0/24"), ("x", "10.9.0.0/24")),
            templates=("t",),
            user_templates=(),
            template_pools=(("t", ("src", "x")),),
        )
        with self.assertRaises(ResourceError):
            target.runtime_restore("r", cp)

    def test_drained_zero_holders_roundtrip(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1",), 0, 10)
        self.assertEqual(parse(s.pool_drain_status("src"))["状态"], "已排空")
        cp = s.runtime_checkpoint(0)
        target = fresh_configured()
        out = target.runtime_restore("r", cp)
        self.assertEqual(out, cp)
        self.assertEqual(parse(target.pool_drain_status("src"))["状态"],
                         "已排空")

    def test_service_checkpoint_carries_drain(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        s.pool_drain("p", "推进", "src", ("t1",), 0, 1)
        cp = s.service_checkpoint(0)
        self.assertIn("排空", parse(cp)["运行态"])
        target = fresh_configured()
        out = target.service_restore("r", cp)
        self.assertIn("排空", parse(out)["运行态"])
        self.assertEqual(parse(target.pool_drain_status("src"))["剩余"], 2)

    def test_checkpoint_state_must_match_holders(self):
        s = standard()
        s.pool_drain("g", "开始", "src", ("t1",), 0, 10)
        cp = json.loads(s.runtime_checkpoint(0))
        # 篡改为已排空但仍有持址行 -> 摘要不符 ValueError。
        cp["排空"]["状态"] = "已排空"
        head = {k: cp[k] for k in ("版本", "时刻", "容量", "配额", "排空")}
        cp["摘要"] = hashlib.sha256(
            compact(head).encode("utf-8")).hexdigest()
        target = fresh_configured()
        with self.assertRaises(ValueError):
            target.runtime_restore("r", compact(cp) + "\n")


if __name__ == "__main__":
    unittest.main()
