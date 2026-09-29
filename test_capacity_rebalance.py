import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def make(users=("alice", "bob", "carol", "dave"), total=2, per=2,
         idle_ms=100000, pool=("10.0.0.0/30", (), ()), lease_ms=100000):
    """total=2、/30 动态池恰两址（.1/.2），默认占满即触发排队。"""
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def config(total, per, idle_ms, lease_ms, templates, binds,
           queue_limit=1024, max_wait=0, policy="拒绝",
           cidr="10.0.0.0/24", max_fail=3):
    return json.dumps(
        {
            "版本": 9,
            "会话": {"总数": total, "每用户": per, "空闲毫秒": idle_ms,
                    "租期毫秒": lease_ms},
            "地址池": [{"标识": "default", "CIDR": cidr, "保留": [],
                       "静态": []}],
            "模板": templates,
            "用户模板": binds,
            "容量": {"队列上限": queue_limit, "最大等待毫秒": max_wait,
                     "队满策略": policy},
            "认证": {"最大失败": max_fail, "锁定毫秒": 1000},
        },
        ensure_ascii=False,
    )


def tpl(tid, prio=0, limit=0, rate=1, burst=0, quota=100, period=0,
        exceed="拒绝"):
    return {"标识": tid, "限速": rate, "突发": burst, "配额": quota,
            "周期毫秒": period, "会话上限": limit, "排队优先级": prio,
            "超限": exceed}


def parse(out):
    return json.loads(out)


class ParamValidationTest(unittest.TestCase):
    def test_key(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.capacity_rebalance(bad, "预检", (("容量", "", (1, 0, "拒绝")),), 0)
        for bad in ("", "a\0b"):
            with self.assertRaises(ValueError):
                s.capacity_rebalance(bad, "预检", (("容量", "", (1, 0, "拒绝")),), 0)

    def test_mode(self):
        _auth, s = make()
        changes = (("容量", "", (1, 0, "拒绝")),)
        for bad in (True, 1, None, []):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("m", bad, changes, 0)
        for bad in ("", "执行 ", "预"):
            with self.assertRaises(ValueError):
                s.capacity_rebalance("m" + bad, bad, changes, 0)

    def test_now_ms(self):
        _auth, s = make()
        changes = (("容量", "", (1, 0, "拒绝")),)
        for bad in (True, 1.5, "1", None):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("n", "预检", changes, bad)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("n2", "预检", changes, -1)

    def test_changes_container_and_shape(self):
        _auth, s = make()
        for bad in (["容量"], None, "x", {}):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("c", "预检", bad, 0)
        for bad in ((),):
            with self.assertRaises(ValueError):
                s.capacity_rebalance("c0", "预检", bad, 0)
        for bad in (["容量", "", (1, 0, "拒绝")], None, "x"):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("c1", "预检", (bad,), 0)
        for bad in (("容量", "", (1, 0, "拒绝"), 1), ("容量", "")):
            with self.assertRaises(ValueError):
                s.capacity_rebalance("c2", "预检", (bad,), 0)

    def test_kind_and_target(self):
        _auth, s = make()
        for bad in ("", "别的", "优先"):
            with self.assertRaises(ValueError):
                s.capacity_rebalance("k" + bad, "预检",
                                     ((bad, "", (1, 0, "拒绝")),), 0)
        # 容量目标必须为空串。
        with self.assertRaises(ValueError):
            s.capacity_rebalance("t", "预检",
                                 (("容量", "x", (1, 0, "拒绝")),), 0)

    def test_kind_target_unique(self):
        _auth, s = make()
        changes = (
            ("容量", "", (1, 0, "拒绝")),
            ("容量", "", (2, 0, "拒绝")),
        )
        with self.assertRaises(ValueError):
            s.capacity_rebalance("u", "预检", changes, 0)

    def test_priority_value(self):
        _auth, s = make()
        for bad in (True, 1.0, "1", None):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("p" + str(type(bad)), "预检",
                                     (("优先级", "t", bad),), 0)
        for bad in (-1, 101):
            with self.assertRaises(ValueError):
                s.capacity_rebalance("p" + str(bad), "预检",
                                     (("优先级", "t", bad),), 0)

    def test_binding_value(self):
        _auth, s = make()
        for bad in (True, 1, None, []):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("b", "预检",
                                     (("绑定", "alice", bad),), 0)
        for bad in ("",):
            pass  # 空串解绑合法。

    def test_capacity_triplet(self):
        _auth, s = make()
        for bad in (True, 1, None, [], [1, 0, "拒绝"]):
            with self.assertRaises(TypeError):
                s.capacity_rebalance("q", "预检",
                                     (("容量", "", bad),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("q1", "预检",
                                 (("容量", "", (1, 0)),), 0)
        with self.assertRaises(TypeError):
            s.capacity_rebalance("q2", "预检",
                                 (("容量", "", ("x", 0, "拒绝")),), 0)
        with self.assertRaises(TypeError):
            s.capacity_rebalance("q3", "预检",
                                 (("容量", "", (1, False, "拒绝")),), 0)
        with self.assertRaises(TypeError):
            s.capacity_rebalance("q4", "预检",
                                 (("容量", "", (1, 0, 5)),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("q5", "预检",
                                 (("容量", "", (10001, 0, "拒绝")),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("q6", "预检",
                                 (("容量", "", (1, -1, "拒绝")),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("q7", "预检",
                                 (("容量", "", (1, 0, "替换 ")),), 0)

    def test_too_many_changes(self):
        _auth, s = make()
        changes = tuple(("优先级", f"t{i}", 0) for i in range(1001))
        with self.assertRaises(ValueError):
            s.capacity_rebalance("big", "预检", changes, 0)


class UnknownReferenceTest(unittest.TestCase):
    def test_unknown_template_priority(self):
        _auth, s = make()
        with self.assertRaises(ResourceError):
            s.capacity_rebalance("r", "预检",
                                 (("优先级", "nope", 5),), 0)

    def test_unknown_user_binding(self):
        _auth, s = make()
        with self.assertRaises(ResourceError):
            s.capacity_rebalance("r", "预检",
                                 (("绑定", "nobody", ""),), 0)

    def test_unknown_template_binding(self):
        _auth, s = make()
        with self.assertRaises(ResourceError):
            s.capacity_rebalance("r", "预检",
                                 (("绑定", "alice", "ghost"),), 0)


class ClockGuardTest(unittest.TestCase):
    def test_now_before_apply_raises(self):
        auth = Authenticator(3, 1000)
        auth.add("u", "pw")
        s = Sessions(auth, 1, 1, 100000,
                     pool=("10.0.0.0/30", (), ()), lease_ms=100000)
        s.capacity("a1", "申请", "s1", ("u", "pw", 100), 0)
        s.capacity("a2", "申请", "q1", ("u", "pw", 1000), 5000)
        with self.assertRaises(StateError):
            s.capacity_rebalance("r", "预检",
                                 (("容量", "", (1024, 0, "拒绝")),), 1000)
        # 执行同拒。
        with self.assertRaises(StateError):
            s.capacity_rebalance("r2", "执行",
                                 (("容量", "", (1024, 0, "拒绝")),), 1000)

    def test_empty_queue_no_guard(self):
        auth = Authenticator(3, 1000)
        auth.add("u", "pw")
        s = Sessions(auth, 1, 1, 100000,
                     pool=("10.0.0.0/30", (), ()), lease_ms=100000)
        out = parse(s.capacity_rebalance(
            "r", "预检", (("容量", "", (1024, 0, "拒绝")),), 1000))
        self.assertEqual(out["超时"], [])
        self.assertEqual(out["剩余"], 0)


class TimeoutTest(unittest.TestCase):
    def test_deadline_shortened_and_timeout_order(self):
        _auth, s = make()
        # q1 截止 100000，q2 同；缩短最大等待为 1000 后截止 = 0+1000。
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        s.capacity("k3", "申请", "q1", ("carol", "pw", 100000), 0)
        s.capacity("k4", "申请", "q2", ("dave", "pw", 100000), 0)
        out = parse(s.capacity_rebalance(
            "r", "预检", (("容量", "", (1024, 1000, "拒绝")),), 2000))
        self.assertEqual(out["超时"], ["q1", "q2"])
        self.assertEqual(out["淘汰"], [])
        self.assertEqual(out["晋升"], [])
        self.assertEqual(out["剩余"], 0)
        # 预检不改队列。
        self.assertEqual(s._queue_order, ["q1", "q2"])

    def test_max_wait_zero_leaves_deadline(self):
        _auth, s = make()
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        s.capacity("k3", "申请", "q1", ("carol", "pw", 100000), 0)
        out = parse(s.capacity_rebalance(
            "r", "预检", (("容量", "", (1024, 0, "拒绝")),), 50000))
        self.assertEqual(out["超时"], [])
        self.assertEqual(out["剩余"], 1)


class EvictionTest(unittest.TestCase):
    def _queued_two(self, s):
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        s.capacity("k3", "申请", "q1", ("carol", "pw", 100000), 0)
        s.capacity("k4", "申请", "q2", ("dave", "pw", 100000), 0)

    def test_tie_evicts_latest_enqueue(self):
        _auth, s = make()
        self._queued_two(s)
        out = parse(s.capacity_rebalance(
            "r", "预检", (("容量", "", (1, 0, "拒绝")),), 0))
        self.assertEqual(out["超时"], [])
        self.assertEqual(out["淘汰"], ["q2"])
        self.assertEqual(out["剩余"], 1)

    def test_lower_effective_evicted_first(self):
        auth = Authenticator(3, 1000)
        for u in ("alice", "bob", "carol", "dave"):
            auth.add(u, "pw")
        s = Sessions(auth, 2, 2, 100000,
                     pool=("10.0.0.0/30", (), ()), lease_ms=100000)
        s.load_config(config(
            2, 2, 100000, 100000, [tpl("vip", 100)],
            [["carol", "vip"]], cidr="10.0.0.0/30"))
        self._queued_two(s)
        # carol 基础优先级 100 高于 dave（未绑定，基础 0），now=0 时即 100 vs 0；
        # 收缩队限到 1 应淘汰有效值更低的 dave(q2)。
        out = parse(s.capacity_rebalance(
            "r", "预检", (("容量", "", (1, 0, "拒绝")),), 0))
        self.assertEqual(out["淘汰"], ["q2"])

    def test_execute_eviction_removes_items(self):
        _auth, s = make()
        self._queued_two(s)
        out = parse(s.capacity_rebalance(
            "r", "执行", (("容量", "", (1, 0, "拒绝")),), 0))
        self.assertEqual(out["淘汰"], ["q2"])
        self.assertEqual(s._queue_order, ["q1"])
        self.assertNotIn("q2", s._capacity_queue)


class PromotionTest(unittest.TestCase):
    def test_unbind_promotes(self):
        auth = Authenticator(3, 1000)
        for u in ("alice", "carol"):
            auth.add(u, "pw")
        s = Sessions(auth, 10, 10, 100000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=100000)
        s.load_config(config(
            10, 10, 100000, 100000, [tpl("gold", 0, 1)],
            [["alice", "gold"], ["carol", "gold"]]))
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "q1", ("carol", "pw", 100000), 0)
        self.assertEqual(s._queue_order, ["q1"])
        out = parse(s.capacity_rebalance(
            "r", "执行", (("绑定", "carol", ""),), 0))
        self.assertEqual(out["晋升"], ["q1"])
        self.assertEqual(out["剩余"], 0)
        self.assertEqual(s._sessions["q1"]["state"], "在线")
        self.assertIsNotNone(s._sessions["q1"]["ip"])
        self.assertEqual(s._queue_order, [])

    def test_priority_change_promotes_when_other_unbound(self):
        # 全局满额释放需绑定/模板闸开启；此处用会话上限验证优先级序。
        auth = Authenticator(3, 1000)
        for u in ("alice", "bob", "carol"):
            auth.add(u, "pw")
        s = Sessions(auth, 2, 2, 100000,
                     pool=("10.0.0.0/30", (), ()), lease_ms=100000)
        # gold 限 1：alice 在线占满；carol 排队。把 carol 改绑到 silver 即解除。
        s.load_config(config(
            2, 2, 100000, 100000,
            [tpl("gold", 0, 1), tpl("silver", 0, 0)],
            [["alice", "gold"], ["carol", "gold"]],
            cidr="10.0.0.0/30"))
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "q1", ("carol", "pw", 100000), 0)
        out = parse(s.capacity_rebalance(
            "r", "执行", (("绑定", "carol", "silver"),), 0))
        # 地址两址占一（s1），silver 无上限；carol 可取第二址晋升。
        self.assertEqual(out["晋升"], ["q1"])
        self.assertEqual(s._sessions["q1"]["state"], "在线")


class CommitTest(unittest.TestCase):
    def test_execute_commits_revision_snapshot_history(self):
        _auth, s = make()
        before = s.export_config()
        out = parse(s.capacity_rebalance(
            "r", "执行", (("容量", "", (8, 500, "替换")),), 0))
        self.assertEqual(out["模式"], "执行")
        self.assertEqual(out["修订"], 1)
        self.assertEqual(s._revision, 1)
        self.assertIn(1, s._config_history)
        record = s._config_history_log[-1]
        self.assertEqual(record[2], "加载")
        self.assertEqual(record[3], -1)
        # 回滚点为旧配置。
        self.assertEqual(s.export_config() != before, True)
        rolled = s.rollback_config()
        self.assertEqual(rolled, before)

    def test_precheck_does_not_commit(self):
        _auth, s = make()
        out = parse(s.capacity_rebalance(
            "r", "预检", (("容量", "", (8, 500, "替换")),), 0))
        self.assertEqual(out["修订"], 1)  # 预期新值
        self.assertEqual(s._revision, 0)
        self.assertEqual([r[2] for r in s._config_history_log], ["构造"])
        self.assertIsNone(s._rollback)

    def test_execute_writes_no_audit_or_capacity_events(self):
        _auth, s = make()
        s.capacity_rebalance("r", "执行",
                             (("容量", "", (8, 500, "替换")),), 0)
        self.assertEqual(s._chain_events, [])
        self.assertEqual(s._batch_chain_events, [])

    def test_carry_failure_is_atomic(self):
        auth = Authenticator(3, 1000)
        for u in ("alice", "bob"):
            auth.add(u, "pw")
        s = Sessions(auth, 10, 10, 100000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=100000)
        s.load_config(config(
            10, 10, 100000, 100000, [tpl("cap", 0, 1)],
            [["alice", "cap"]]))
        s.capacity("k1", "申请", "s1", ("alice", "pw", 100), 0)
        s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0)
        rev = s._revision
        with self.assertRaises(ResourceError):
            s.capacity_rebalance("r", "执行",
                                 (("绑定", "bob", "cap"),), 0)
        self.assertEqual(s._revision, rev)
        self.assertNotIn("bob", s._user_templates)
        self.assertEqual([r[2] for r in s._config_history_log],
                         ["构造", "加载"])


class CacheTest(unittest.TestCase):
    CHANGES = (("容量", "", (8, 500, "替换")),)

    def test_execute_success_cached_replay_bytes(self):
        _auth, s = make()
        first = s.capacity_rebalance("r", "执行", self.CHANGES, 0)
        again = s.capacity_rebalance("r", "执行", self.CHANGES, 0)
        self.assertEqual(first, again)
        # 重放不再提交：修订保持 1。
        self.assertEqual(s._revision, 1)
        self.assertEqual([r[2] for r in s._config_history_log],
                         ["构造", "加载"])

    def test_execute_replay_different_params_value_error(self):
        _auth, s = make()
        s.capacity_rebalance("r", "执行", self.CHANGES, 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("r", "执行",
                                 (("容量", "", (8, 500, "拒绝")),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("r", "预检", self.CHANGES, 0)

    def test_precheck_never_cached(self):
        _auth, s = make()
        a = s.capacity_rebalance("r", "预检",
                                 (("容量", "", (8, 0, "拒绝")),), 0)
        # 同 key 预检可换不同参数，不占 key。
        b = s.capacity_rebalance("r", "预检",
                                 (("容量", "", (9, 0, "拒绝")),), 0)
        self.assertNotIn("r", s._capacity_rebalance_cache)
        # 随后同 key 执行成功仍可占位。
        c = s.capacity_rebalance("r", "执行",
                                 (("容量", "", (7, 0, "拒绝")),), 0)
        self.assertIn("r", s._capacity_rebalance_cache)
        self.assertEqual(parse(c)["修订"], 1)

    def test_failure_not_cached(self):
        _auth, s = make()
        with self.assertRaises(ResourceError):
            s.capacity_rebalance("r", "预检",
                                 (("优先级", "ghost", 1),), 0)
        self.assertNotIn("r", s._capacity_rebalance_cache)
        # 参数错不占 key，修复后可复用。
        out = parse(s.capacity_rebalance(
            "r", "预检", self.CHANGES, 0))
        self.assertEqual(out["模式"], "预检")


class RenderTest(unittest.TestCase):
    def test_key_order_and_types(self):
        _auth, s = make()
        out = s.capacity_rebalance(
            "r", "预检", (("容量", "", (8, 0, "拒绝")),), 7)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        doc = json.loads(out)
        self.assertEqual(list(doc),
                         ["时刻", "模式", "修订", "超时", "淘汰",
                          "晋升", "剩余"])
        self.assertEqual(doc["时刻"], 7)
        self.assertEqual(doc["模式"], "预检")
        self.assertIsInstance(doc["修订"], int)
        self.assertIsInstance(doc["超时"], list)
        self.assertIsInstance(doc["淘汰"], list)
        self.assertIsInstance(doc["晋升"], list)
        self.assertIsInstance(doc["剩余"], int)
        self.assertEqual(out, wire(doc))


if __name__ == "__main__":
    unittest.main()
