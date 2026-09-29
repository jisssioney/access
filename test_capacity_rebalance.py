import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def make(users=("alice", "bob", "carol", "dave", "eve"), total=2, per=2,
         pool=("10.0.0.0/29", (), ()), idle_ms=100000, lease_ms=100000):
    """total=2、/29 动态池六址，占满两个在线位即触发排队。"""
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def v9(total=2, per=2, templates=(), bindings=(), queue_limit=10,
       max_wait=0, policy="拒绝"):
    """v9 配置文本：templates 为 (标识, 会话上限, 排队优先级) 三元组。"""
    doc = {
        "版本": 9,
        "会话": {"总数": total, "每用户": per, "空闲毫秒": 100000, "租期毫秒": 100000},
        "地址池": [{"标识": "default", "CIDR": "10.0.0.0/29", "保留": [], "静态": []}],
        "模板": [
            {"标识": tid, "限速": 1000, "突发": 0, "配额": 1000000, "周期毫秒": 0,
             "会话上限": slimit, "排队优先级": prio, "超限": "拒绝"}
            for tid, slimit, prio in templates
        ],
        "用户模板": [[user, tid] for user, tid in bindings],
        "容量": {"队列上限": queue_limit, "最大等待毫秒": max_wait, "队满策略": policy},
        "认证": {"最大失败": 3, "锁定毫秒": 1000},
    }
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def queued(s, n=2):
    """建满 total 个在线位后再排 n 项，返回 (在线 sids, 排队 sids)。"""
    online = []
    for i in range(2):
        sid = f"s{i + 1}"
        s.capacity(f"e{sid}", "申请", sid, (f"u{i}", "pw", 100000), 0)
        online.append(sid)
    waits = [5000, 60000, 70000, 80000, 90000]
    queued_sids = []
    for i in range(n):
        sid = f"q{i + 1}"
        s.capacity(f"e{sid}", "申请", sid, (f"u{10 + i}", "pw", waits[i]), 10 * (i + 1))
        queued_sids.append(sid)
    return online, queued_sids


USERS = ("alice", "bob", "carol", "dave", "eve",
         "u0", "u1", "u10", "u11", "u12", "u13", "u14")


def make_q(**kw):
    return make(users=USERS, **kw)


class ParamValidationTest(unittest.TestCase):
    def test_key_and_mode(self):
        _auth, s = make_q()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.capacity_rebalance(bad, "执行", (("容量", "", (5, 0, "拒绝")),), 0)
        for bad in ("", "k" * 300, "a\0b"):
            with self.assertRaises(ValueError):
                s.capacity_rebalance(bad, "执行", (("容量", "", (5, 0, "拒绝")),), 0)
        for i, bad in enumerate((True, 1, None, [])):
            with self.assertRaises(TypeError):
                s.capacity_rebalance(f"m{i}", bad, (("容量", "", (5, 0, "拒绝")),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("mx", "加载", (("容量", "", (5, 0, "拒绝")),), 0)

    def test_changes_shape(self):
        _auth, s = make_q()
        good = (("容量", "", (5, 0, "拒绝")),)
        for i, bad in enumerate(([good[0]], "x", 1, None)):
            with self.assertRaises(TypeError):
                s.capacity_rebalance(f"c{i}", "执行", bad, 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("ce", "执行", (), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("cf", "执行", good * 1001, 0)
        with self.assertRaises(TypeError):
            s.capacity_rebalance("cg", "执行", (["容量", "", (5, 0, "拒绝")],), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("ch", "执行", (("容量", ""),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("ci", "执行", (("容量", "", (5, 0, "拒绝"), 1),), 0)
        with self.assertRaises(TypeError):
            s.capacity_rebalance("cj", "执行", ((1, "", 5),), 0)
        with self.assertRaises(TypeError):
            s.capacity_rebalance("ck", "执行", (("容量", 1, (5, 0, "拒绝")),), 0)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("cl", "执行", (("未知", "", 5),), 0)

    def test_change_values(self):
        _auth, s = make_q()
        i = [0]

        def call(changes):
            i[0] += 1
            s.capacity_rebalance(f"v{i[0]}", "执行", changes, 0)

        # 优先级：值类型与取值。
        for bad in (True, "5", 1.5):
            with self.assertRaises(TypeError):
                call((("优先级", "t", bad),))
        for bad in (-1, 101):
            with self.assertRaises(ValueError):
                call((("优先级", "t", bad),))
        with self.assertRaises(ValueError):
            call((("优先级", "", 5),))
        # 绑定：值类型与凭据约束。
        with self.assertRaises(TypeError):
            call((("绑定", "alice", 1),))
        with self.assertRaises(ValueError):
            call((("绑定", "alice", "x" * 300),))
        # 容量：目标、三元组形状与各元素。
        with self.assertRaises(ValueError):
            call((("容量", "x", (5, 0, "拒绝")),))
        with self.assertRaises(TypeError):
            call((("容量", "", [5, 0, "拒绝"]),))
        with self.assertRaises(ValueError):
            call((("容量", "", (5, 0)),))
        with self.assertRaises(TypeError):
            call((("容量", "", (True, 0, "拒绝")),))
        with self.assertRaises(TypeError):
            call((("容量", "", (5, "0", "拒绝")),))
        with self.assertRaises(TypeError):
            call((("容量", "", (5, 0, 1)),))
        for bad in (-1, 10001):
            with self.assertRaises(ValueError):
                call((("容量", "", (bad, 0, "拒绝")),))
        with self.assertRaises(ValueError):
            call((("容量", "", (5, -1, "拒绝")),))
        with self.assertRaises(ValueError):
            call((("容量", "", (5, 0, "x")),))
        # (种类, 目标) 对互异。
        with self.assertRaises(ValueError):
            call((("优先级", "t", 5), ("优先级", "t", 6)))
        with self.assertRaises(ValueError):
            call((("容量", "", (5, 0, "拒绝")), ("容量", "", (6, 0, "拒绝"))))

    def test_now_ms(self):
        _auth, s = make_q()
        for i, bad in enumerate((True, "1", None, 1.5)):
            with self.assertRaises(TypeError):
                s.capacity_rebalance(f"n{i}", "执行", (("容量", "", (5, 0, "拒绝")),), bad)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("nn", "执行", (("容量", "", (5, 0, "拒绝")),), -1)

    def test_param_error_not_cached(self):
        _auth, s = make_q()
        with self.assertRaises(ValueError):
            s.capacity_rebalance("z", "执行", (), 0)
        # 参数错不占 key：同 key 合法调用照常执行。
        out = s.capacity_rebalance("z", "执行", (("容量", "", (5, 0, "拒绝")),), 0)
        self.assertEqual(json.loads(out)["模式"], "执行")


class GuardAndReferenceTest(unittest.TestCase):
    def test_clock_guard(self):
        _auth, s = make_q()
        queued(s, 1)  # q1 申请时刻 10
        with self.assertRaises(StateError):
            s.capacity_rebalance("g1", "执行", (("容量", "", (5, 0, "拒绝")),), 9)
        # 同刻不触发。
        s.capacity_rebalance("g1", "执行", (("容量", "", (5, 0, "拒绝")),), 10)

    def test_clock_guard_empty_queue(self):
        _auth, s = make_q()
        out = s.capacity_rebalance("g1", "预检", (("容量", "", (5, 0, "拒绝")),), 0)
        self.assertEqual(json.loads(out)["剩余"], 0)

    def test_unknown_references(self):
        _auth, s = make_q()
        s.load_config(v9(templates=(("gold", 0, 10),)))
        for i, changes in enumerate((
            (("优先级", "nosuch", 5),),
            (("绑定", "nosuch", "gold"),),
            (("绑定", "alice", "nosuch"),),
        )):
            with self.assertRaises(ResourceError):
                s.capacity_rebalance(f"r{i}", "预检", changes, 0)
        # 失败不占 key：同 key 修正后可用。
        out = s.capacity_rebalance("r0", "预检", (("优先级", "gold", 5),), 0)
        self.assertEqual(json.loads(out)["模式"], "预检")

    def test_carrying_failure(self):
        _auth, s = make_q()
        s.load_config(v9(templates=(("gold", 1, 10),)))
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.do("e2", "建立", "s2", ("bob", "pw"), 0)
        rev = json.loads(s.config_revision())["修订"]
        with self.assertRaises(ResourceError):
            # gold 会话上限 1，两个在线会话同绑不可承载。
            s.capacity_rebalance(
                "r1", "执行", (("绑定", "alice", "gold"), ("绑定", "bob", "gold")), 10)
        # 失败不变：修订与配置原样。
        self.assertEqual(json.loads(s.config_revision())["修订"], rev)
        self.assertEqual(json.loads(s.export_config())["用户模板"], [])
        out = s.capacity_rebalance("r1", "执行", (("绑定", "alice", "gold"),), 10)
        self.assertEqual(json.loads(out)["修订"], rev + 1)
        self.assertEqual(json.loads(s.export_config())["用户模板"], [["alice", "gold"]])


class RebalanceTest(unittest.TestCase):
    def test_result_shape_and_key_order(self):
        _auth, s = make_q()
        out = s.capacity_rebalance("k", "执行", (("容量", "", (5, 0, "拒绝")),), 7)
        self.assertTrue(out.endswith("\n"))
        doc = json.loads(out)
        self.assertEqual(
            list(doc), ["时刻", "模式", "修订", "超时", "淘汰", "晋升", "剩余"])
        self.assertEqual(doc["时刻"], 7)
        self.assertEqual(doc["模式"], "执行")
        self.assertIsInstance(doc["修订"], int)
        for name in ("超时", "淘汰", "晋升"):
            self.assertIsInstance(doc[name], list)
        self.assertIsInstance(doc["剩余"], int)

    def test_evict_to_limit(self):
        _auth, s = make_q()
        queued(s, 3)
        out = s.capacity_rebalance("r", "执行", (("容量", "", (1, 40000, "拒绝")),), 100)
        doc = json.loads(out)
        # 有效值全 0（未绑定），并列按入队序降序淘汰 q3、q2。
        self.assertEqual(doc["超时"], [])
        self.assertEqual(doc["淘汰"], ["q3", "q2"])
        self.assertEqual(doc["晋升"], [])
        self.assertEqual(doc["剩余"], 1)
        self.assertEqual(doc["修订"], 1)
        # 容量事件：两个淘汰各带原入队序。
        events = json.loads(s.capacity_events())["事件"]
        tail = [(e["会话"], e["结果"], e["入队序"]) for e in events[-2:]]
        self.assertEqual(tail, [("q3", "淘汰", 3), ("q2", "淘汰", 2)])
        self.assertEqual(len(s._capacity_queue), 1)

    def test_clamp_and_timeout(self):
        _auth, s = make_q()
        queued(s, 2)  # q1 截止 5010、q2 截止 60020
        out = s.capacity_rebalance("r", "执行", (("容量", "", (10, 100, "拒绝")),), 1000)
        doc = json.loads(out)
        # 新最大等待 100：截止钳为 110/120，均 <= 1000 按入队序超时。
        self.assertEqual(doc["超时"], ["q1", "q2"])
        self.assertEqual(doc["剩余"], 0)
        events = json.loads(s.capacity_events())["事件"]
        self.assertEqual([e["结果"] for e in events[-2:]], ["超时", "超时"])

    def test_no_clamp_without_capacity_change(self):
        _auth, s = make_q()
        queued(s, 1)  # q1 截止 5010
        out = s.capacity_rebalance("r", "执行", (("容量", "", (10, 0, "拒绝")),), 1000)
        doc = json.loads(out)
        # 新最大等待为 0（不限）：不钳制，截止 5010 > 1000 不超时。
        self.assertEqual(doc["超时"], [])
        self.assertEqual(doc["剩余"], 1)

    def test_promote_reverse_order(self):
        _auth, s = make_q()
        s.load_config(v9(templates=(("gold", 0, 10), ("silver", 0, 20))))
        queued(s, 3)
        # 绑定后有效值：u10->gold 10、u11->silver 20、u12 未绑定 0；淘汰至 2 去最低。
        out = s.capacity_rebalance("r1", "执行", (
            ("绑定", "u10", "gold"),
            ("绑定", "u11", "silver"),
            ("容量", "", (2, 0, "拒绝")),
        ), 100)
        doc = json.loads(out)
        self.assertEqual(doc["淘汰"], ["q3"])
        # 腾出在线位后晋升按反序（有效值降序）：q2 先于 q1。
        s.do("o1", "下线", "s1", None, 200)
        s.do("o2", "下线", "s2", None, 200)
        out = s.capacity_rebalance("r2", "执行", (("容量", "", (10, 0, "拒绝")),), 300)
        doc = json.loads(out)
        self.assertEqual(doc["晋升"], ["q2", "q1"])
        self.assertEqual(doc["剩余"], 0)
        events = json.loads(s.capacity_events())["事件"]
        self.assertEqual([e["结果"] for e in events[-2:]], ["晋升", "晋升"])

    def test_template_limit_gates_promotion(self):
        _auth, s = make_q(total=2, per=3)
        s.load_config(v9(total=2, per=3,
                         templates=(("gold", 1, 10),), bindings=(("u0", "gold"),)))
        queued(s, 1)
        s.do("o1", "下线", "s2", None, 30)  # 腾出一个全局位，gold 占用仍为 1
        # q1 用户 u10 绑 gold：占用已达上限 1，不可晋升。
        out = s.capacity_rebalance("r1", "执行", (("绑定", "u10", "gold"),), 100)
        doc = json.loads(out)
        self.assertEqual(doc["晋升"], [])
        self.assertEqual(doc["剩余"], 1)
        # 解绑后即可晋升。
        out = s.capacity_rebalance("r2", "执行", (("绑定", "u10", ""),), 200)
        self.assertEqual(json.loads(out)["晋升"], ["q1"])

    def test_config_commit(self):
        _auth, s = make_q()
        s.load_config(v9(templates=(("gold", 0, 10),)))
        before = s.export_config()
        rev = json.loads(s.config_revision())["修订"]
        out = s.capacity_rebalance("r", "执行", (
            ("优先级", "gold", 50),
            ("绑定", "alice", "gold"),
            ("容量", "", (7, 0, "替换")),
        ), 0)
        doc = json.loads(out)
        self.assertEqual(doc["修订"], rev + 1)
        cfg = json.loads(s.export_config())
        self.assertEqual(cfg["模板"][0]["排队优先级"], 50)
        self.assertEqual(cfg["用户模板"], [["alice", "gold"]])
        self.assertEqual(cfg["容量"], {"队列上限": 7, "最大等待毫秒": 0, "队满策略": "替换"})
        # config_history 追加“加载”、目标 -1。
        record = json.loads(s.config_history())["项目"][-1]
        self.assertEqual(record["操作"], "加载")
        self.assertEqual(record["目标"], -1)
        self.assertEqual(record["修订"], rev + 1)
        # 旧配置作回滚点。
        s.rollback_config()
        self.assertEqual(s.export_config(), before)
        # 不关联 audit。
        self.assertEqual(json.loads(s.audit())["事件"], [])


class PrecheckTest(unittest.TestCase):
    def test_precheck_readonly(self):
        _auth, s = make_q()
        s.load_config(v9(templates=(("gold", 0, 10),)))
        queued(s, 2)
        rev = json.loads(s.config_revision())["修订"]
        config = s.export_config()
        events = s.capacity_events()
        out = s.capacity_rebalance("p", "预检", (
            ("绑定", "u10", "gold"), ("容量", "", (1, 100, "拒绝"))), 1000)
        doc = json.loads(out)
        # 钳制后两均超时；修订为将产生的新值。
        self.assertEqual(doc["超时"], ["q1", "q2"])
        self.assertEqual(doc["修订"], rev + 1)
        self.assertEqual(doc["模式"], "预检")
        # 实例不变：配置、修订、队列、事件原样。
        self.assertEqual(s.export_config(), config)
        self.assertEqual(json.loads(s.config_revision())["修订"], rev)
        self.assertEqual(s.capacity_events(), events)
        self.assertEqual(len(s._capacity_queue), 2)
        for sid, entry in s._capacity_queue.items():
            self.assertEqual(entry[3], entry[1] + entry[2])

    def test_precheck_not_cached(self):
        _auth, s = make_q()
        changes = (("容量", "", (7, 0, "拒绝")),)
        out1 = s.capacity_rebalance("p", "预检", changes, 0)
        out2 = s.capacity_rebalance("p", "预检", changes, 0)
        self.assertEqual(out1, out2)
        # 预检不占 key：同 key 可执行。
        out3 = s.capacity_rebalance("p", "执行", changes, 0)
        self.assertEqual(json.loads(out3)["模式"], "执行")
        # 执行入缓存后异参（含异模式）重放抛 ValueError。
        with self.assertRaises(ValueError):
            s.capacity_rebalance("p", "预检", changes, 0)


class CacheTest(unittest.TestCase):
    def test_execute_success_cached(self):
        _auth, s = make_q()
        queued(s, 2)
        changes = (("容量", "", (1, 0, "拒绝")),)
        out = s.capacity_rebalance("k", "执行", changes, 100)
        rev = json.loads(s.config_revision())["修订"]
        events = s.capacity_events()
        # 同型同参重放返原字节，无副作用。
        self.assertEqual(s.capacity_rebalance("k", "执行", changes, 100), out)
        self.assertEqual(json.loads(s.config_revision())["修订"], rev)
        self.assertEqual(s.capacity_events(), events)
        # 异参 ValueError。
        with self.assertRaises(ValueError):
            s.capacity_rebalance("k", "执行", changes, 101)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("k", "预检", changes, 100)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("k", "执行", (("容量", "", (2, 0, "拒绝")),), 100)
        with self.assertRaises(ValueError):
            s.capacity_rebalance("k", "执行", changes, False)

    def test_failure_not_cached(self):
        _auth, s = make_q()
        with self.assertRaises(ResourceError):
            s.capacity_rebalance("k", "执行", (("优先级", "nosuch", 5),), 0)
        out = s.capacity_rebalance("k", "执行", (("容量", "", (5, 0, "拒绝")),), 0)
        self.assertEqual(json.loads(out)["修订"], 1)


if __name__ == "__main__":
    unittest.main()
