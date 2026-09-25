import copy
import hashlib
import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)

POOL = ("10.0.0.0/30", (), ())


def make(users=("alice", "bob", "carol", "dave"), total=2, per=2):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return Sessions(auth, total, per, 100000, pool=POOL, lease_ms=100000)


def reseal(doc):
    """重算状态哈希（事件链不动），返回重新序列化的检查点文本。"""
    state = {
        "时刻": doc["时刻"],
        "事件": doc["事件"],
        "会话": doc["会话"],
        "排队": doc["排队"],
    }
    blob = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    doc["状态哈希"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"


def checkpoint_with_tombstone():
    """s1 在线、s3 在线（晋升后持 .2）、s2 下线墓碑、队列空。"""
    s = make()
    s.capacity("a1", "申请", "s1", ("alice", "pw", 1000), 0)
    s.capacity("a2", "申请", "s2", ("bob", "pw", 1000), 0)
    s.capacity("a3", "申请", "s3", ("carol", "pw", 1000), 0)
    s.do("o1", "下线", "s2", None, 0)
    s.capacity("adv1", "推进", "", None, 0)
    return s, s.clog(0)


class TombstoneClogTest(unittest.TestCase):
    def test_clog_includes_offline_tombstone(self):
        _s, cp = checkpoint_with_tombstone()
        self.assertTrue(cp.endswith("\n"))
        doc = json.loads(cp)
        rows = doc["会话"]
        self.assertEqual([r["会话"] for r in rows], ["s1", "s2", "s3"])
        self.assertEqual(
            rows[1],
            {"会话": "s2", "用户": "bob", "状态": "下线",
             "期限": 0, "池": "", "地址": "", "租期": 0},
        )
        self.assertEqual(
            list(rows[1]), ["会话", "用户", "状态", "期限", "池", "地址", "租期"]
        )
        self.assertNotIn(": ", cp)
        self.assertNotIn(", ", cp)

    def test_clog_validates_before_aging(self):
        s = make()
        for bad in (True, 1.5, "0", None):
            with self.assertRaises(TypeError):
                s.clog(bad)
        with self.assertRaises(ValueError):
            s.clog(-1)

    def test_tombstone_only_roundtrip(self):
        s = make()
        s.capacity("k1", "申请", "x", ("alice", "pw", 5), 0)
        s.do("o1", "下线", "x", None, 0)
        cp = s.clog(0)
        self.assertEqual([r["状态"] for r in json.loads(cp)["会话"]], ["下线"])
        target = make()
        stats = target.creplay(cp)
        self.assertEqual(target.clog(0), cp)
        doc = json.loads(stats)
        self.assertEqual((doc["在线"], doc["挂起"], doc["排队"]), (0, 0, 0))


class TombstoneReplayTest(unittest.TestCase):
    def setUp(self):
        self.src, self.cp = checkpoint_with_tombstone()
        self.doc = json.loads(self.cp)

    def test_restore_into_fresh_target(self):
        target = make()
        target.creplay(self.cp)
        self.assertEqual(target._sessions["s2"]["state"], "下线")
        self.assertIsNone(target._sessions["s2"]["ip"])
        self.assertEqual(target._sessions["s3"]["state"], "在线")
        # 租约表不含墓碑，仅两条在线持址。
        leased = {
            ip for pool in target._pools.values() for ip in pool.leases
        }
        self.assertEqual(
            leased,
            {target._sessions["s1"]["ip"], target._sessions["s3"]["ip"]},
        )
        self.assertTrue(target.cverify())
        self.assertEqual(target.clog(0), self.cp)

    def test_same_state_hash_is_noop_keeps_tombstone(self):
        target = make()
        target.creplay(self.cp)
        events_before = len(target._capacity_events)
        stats = target.capacity_stats(0)
        self.assertEqual(target.creplay(self.cp), stats)
        self.assertEqual(target._sessions["s2"]["state"], "下线")
        self.assertEqual(len(target._capacity_events), events_before)

    def test_tombstone_does_not_count_capacity(self):
        doc = copy.deepcopy(self.doc)
        doc["会话"].insert(0, {
            "会话": "s0", "用户": "alice", "状态": "下线",
            "期限": 0, "池": "", "地址": "", "租期": 0,
        })
        text = reseal(doc)
        target = make(total=2)  # 四行会话中仅两条在线，total=2 仍可承载。
        target.creplay(text)
        self.assertEqual(target._sessions["s0"]["state"], "下线")

    def test_unregistered_tombstone_user_is_resource_error(self):
        auth = Authenticator(3, 1000)
        for user in ("alice", "carol", "dave"):
            auth.add(user, "pw")
        target = Sessions(auth, 2, 2, 100000, pool=POOL, lease_ms=100000)
        with self.assertRaises(ResourceError):
            target.creplay(self.cp)  # 墓碑用户 bob 未注册

    def test_undercarrying_pool_is_resource_error(self):
        auth = Authenticator(3, 1000)
        for user in ("alice", "bob", "carol", "dave"):
            auth.add(user, "pw")
        other = Sessions(auth, 2, 2, 100000,
                         pool=("10.0.1.0/30", (), ()), lease_ms=100000)
        with self.assertRaises(ResourceError):
            other.creplay(self.cp)

    def test_state_errors(self):
        # 同标识状态不同：目标在线，检查点列为墓碑。
        online = make()
        online.capacity("k1", "申请", "x", ("alice", "pw", 5), 0)
        tomb_src = make()
        tomb_src.capacity("k1", "申请", "x", ("alice", "pw", 5), 0)
        tomb_src.do("o1", "下线", "x", None, 0)
        with self.assertRaises(StateError):
            online.creplay(tomb_src.clog(0))

        # 包外墓碑：目标含一条检查点未列的墓碑。
        doc = copy.deepcopy(self.doc)
        doc["会话"].insert(0, {
            "会话": "s0", "用户": "alice", "状态": "下线",
            "期限": 0, "池": "", "地址": "", "租期": 0,
        })
        target = make()
        target.creplay(reseal(doc))
        with self.assertRaises(StateError):
            target.creplay(self.cp)

        # 包外排队项。
        target = make()
        target.creplay(self.cp)
        target.capacity("q", "申请", "sq", ("dave", "pw", 1000), 0)
        with self.assertRaises(StateError):
            target.creplay(self.cp)

    def test_malformed_tombstones_raise_value_error(self):
        def mutated(mut):
            doc = copy.deepcopy(self.doc)
            mut(doc)
            return reseal(doc)

        # 墓碑期限非零。
        with self.assertRaises(ValueError):
            make().creplay(mutated(lambda d: d["会话"][1].__setitem__("期限", 5)))
        # 墓碑带池址。
        with self.assertRaises(ValueError):
            make().creplay(mutated(lambda d: d["会话"][1].__setitem__("池", "default")))
        # 非法状态。
        with self.assertRaises(ValueError):
            make().creplay(mutated(lambda d: d["会话"][1].__setitem__("状态", "僵尸")))
        # 重复会话。
        with self.assertRaises(ValueError):
            make().creplay(
                mutated(lambda d: d["会话"].append(dict(d["会话"][1])))
            )
        # 乱序。
        with self.assertRaises(ValueError):
            make().creplay(
                mutated(lambda d: d["会话"].sort(
                    key=lambda r: r["会话"], reverse=True))
            )
        # JSON / 结构 / 类型 / 链 / 状态哈希错。
        with self.assertRaises(ValueError):
            make().creplay("{not json")
        doc = copy.deepcopy(self.doc)
        del doc["排队"]
        with self.assertRaises(ValueError):
            make().creplay(json.dumps(doc, ensure_ascii=False) + "\n")
        doc = copy.deepcopy(self.doc)
        doc["时刻"] = "0"
        with self.assertRaises(ValueError):
            make().creplay(json.dumps(doc, ensure_ascii=False) + "\n")
        doc = copy.deepcopy(self.doc)
        doc["事件"][0]["结果"] = "未知"  # 不重算哈希 -> 链哈希错
        with self.assertRaises(ValueError):
            make().creplay(json.dumps(doc, ensure_ascii=False) + "\n")
        doc = copy.deepcopy(self.doc)
        doc["会话"][0]["用户"] = "dave"  # 行合法但状态哈希不符
        with self.assertRaises(ValueError):
            make().creplay(json.dumps(doc, ensure_ascii=False) + "\n")

    def test_non_str_text_is_type_error(self):
        with self.assertRaises(TypeError):
            make().creplay(123)

    def test_failure_is_atomic(self):
        target = make()
        target.creplay(self.cp)
        snap = (
            copy.deepcopy(target._sessions),
            copy.deepcopy(target._capacity_queue),
            list(target._queue_order),
            list(target._capacity_events),
            target._capacity_tail,
        )
        with self.assertRaises(ValueError):
            target.creplay("{bad")
        self.assertEqual(
            snap,
            (
                copy.deepcopy(target._sessions),
                copy.deepcopy(target._capacity_queue),
                list(target._queue_order),
                list(target._capacity_events),
                target._capacity_tail,
            ),
        )


if __name__ == "__main__":
    unittest.main()
