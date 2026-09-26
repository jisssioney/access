import json
import unittest

from access import (
    Authenticator,
    Sessions,
)


def make(users=("alice", "bob", "carol"), total=1000, per=1000,
         pool=("10.0.0.0/22", (), ()), idle_ms=10, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool,
                          lease_ms=lease_ms)


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def chain_events(s):
    events = []
    after = 0
    while True:
        doc = json.loads(s.audit(after=after, limit=1000))
        window = doc["事件"]
        if not window:
            break
        events.extend(window)
        after = doc["下个序号"]
    return events


def establish(s, n, prefix="s", user="alice"):
    for i in range(n):
        s.do(f"k{prefix}{i}", "建立", f"{prefix}{i:04d}", (user, "pw"), 0)


class TimeoutStormParamTest(unittest.TestCase):
    def test_types_and_ranges(self):
        _auth, s = make()
        for bad in (True, 1, None, b"k"):
            with self.assertRaises(TypeError):
                s.timeout_storm(bad, 0)
        with self.assertRaises(ValueError):
            s.timeout_storm("", 0)
        for bad in (True, 1.5, "1", None, -1):
            with self.assertRaises((TypeError, ValueError)):
                s.timeout_storm(f"n{bad!r}", bad)
        for bad in (True, 1.5, "10", None):
            with self.assertRaises(TypeError):
                s.timeout_storm(f"b{bad!r}", 0, bad)
        for bad in (0, -1, 1001):
            with self.assertRaises(ValueError):
                s.timeout_storm(f"v{bad}", 0, bad)

    def test_default_batches_is_ten(self):
        _auth, s = make(total=2000, per=2000)
        establish(s, 1005)
        doc = json.loads(s.timeout_storm("d", 20))
        self.assertEqual(
            (doc["处理"], doc["剩余"], doc["完成"], len(doc["批次"])),
            (1000, 5, False, 10),
        )

    def test_empty_storm_shape(self):
        _auth, s = make()
        out = s.timeout_storm("e", 20)
        self.assertEqual(
            out,
            wire({"时刻": 20, "处理": 0, "剩余": 0, "完成": True, "批次": []}),
        )
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(
            list(json.loads(out)), ["时刻", "处理", "剩余", "完成", "批次"]
        )


class TimeoutStormBatchTest(unittest.TestCase):
    def test_batches_take_first_hundred_each(self):
        _auth, s = make()
        establish(s, 250)
        doc = json.loads(s.timeout_storm("b", 20, batches=2))
        self.assertEqual(doc["处理"], 200)
        self.assertEqual(doc["剩余"], 50)
        self.assertFalse(doc["完成"])
        self.assertEqual([b["序号"] for b in doc["批次"]], [1, 2])
        first, second = doc["批次"]
        self.assertEqual(
            (first["会话"], first["排队"], first["剩余"]), (100, 0, 150)
        )
        self.assertEqual(
            (second["会话"], second["排队"], second["剩余"]), (100, 0, 50)
        )
        # 处理为各批之和，完成恰为剩余 == 0。
        self.assertEqual(doc["处理"], sum(b["会话"] + b["排队"] for b in doc["批次"]))

    def test_final_batch_drains_and_completes(self):
        _auth, s = make()
        establish(s, 250)
        doc = json.loads(s.timeout_storm("b", 20, batches=3))
        self.assertEqual(doc["处理"], 250)
        self.assertEqual(doc["剩余"], 0)
        self.assertTrue(doc["完成"])
        self.assertEqual(len(doc["批次"]), 3)
        self.assertEqual(doc["批次"][-1]["剩余"], 0)

    def test_batch_item_key_order(self):
        _auth, s = make()
        establish(s, 1)
        doc = json.loads(s.timeout_storm("b", 20))
        batch = doc["批次"][0]
        self.assertEqual(
            list(batch), ["序号", "会话", "排队", "剩余", "池"]
        )
        self.assertEqual(
            list(batch["池"][0]), ["标识", "占用", "可用"]
        )

    def test_pool_watermark_after_each_batch(self):
        _auth, s = make(pool=("10.0.0.0/24", (), ()))
        establish(s, 250)
        doc = json.loads(s.timeout_storm("b", 20, batches=3))
        occupied = [b["池"][0]["占用"] for b in doc["批次"]]
        # 每批清扫 100，批后租约数递减；末批 50 全部清空。
        self.assertEqual(occupied, [150, 50, 0])
        # /24 可用主机 254，无保留；可用 = 254 - 占用。
        avail = [b["池"][0]["可用"] for b in doc["批次"]]
        self.assertEqual(avail, [104, 204, 254])

    def test_static_address_unrented_counts_as_available(self):
        _auth, s = make(
            users=("alice", "bob"),
            pool=("10.0.0.0/28", (), (("alice", "10.0.0.2"),)),
        )
        s.do("a", "建立", "sa", ("alice", "pw"), 0)
        s.do("b", "建立", "sb", ("bob", "pw"), 0)
        pool = s._pools["default"]
        # /28 可用主机 14；静态 .2 不入动态堆，故动态空闲 12。
        self.assertEqual((len(pool.leases), len(pool.free)), (2, 12))
        doc = json.loads(s.timeout_storm("b", 20))
        row = doc["批次"][0]["池"][0]
        # 静态退租不回动态堆；未租静态计入可用：13 动态 + 1 静态 = 14。
        self.assertEqual(row, {"标识": "default", "占用": 0, "可用": 14})
        self.assertNotIn(0x0A000002, pool.free)

    def test_pools_sorted_unicode_with_unaffected_pool(self):
        _auth, s = make(pool=("10.0.0.0/29", (), ()))
        s.add_pool("zz", ("10.1.0.0/30", (), ()))
        s.add_pool("aa", ("10.2.0.0/30", (), ()))
        establish(s, 2)
        doc = json.loads(s.timeout_storm("b", 20))
        ids = [p["标识"] for p in doc["批次"][0]["池"]]
        self.assertEqual(ids, ["aa", "default", "zz"])
        rows = {p["标识"]: p for p in doc["批次"][0]["池"]}
        # 未涉及的池占用恒 0，/30 可用主机 2。
        self.assertEqual(rows["aa"], {"标识": "aa", "占用": 0, "可用": 2})
        self.assertEqual(rows["default"]["占用"], 0)

    def test_sessions_precede_queued_at_same_deadline(self):
        _auth, s = make(total=2, per=2, pool=("10.0.0.0/24", (), ()))
        s.capacity("a", "申请", "zsid", ("alice", "pw", 1000), 0)
        s.capacity("b", "申请", "asid", ("bob", "pw", 1000), 0)
        s.capacity("c", "申请", "q1", ("carol", "pw", 10), 0)
        s.capacity("d", "申请", "q2", ("carol", "pw", 10), 0)
        doc = json.loads(s.timeout_storm("b", 10))
        batch = doc["批次"][0]
        self.assertEqual((batch["会话"], batch["排队"]), (2, 2))
        # 排队项按入队序追加既有超时事件。
        events = json.loads(s.capacity_events(limit=100))["事件"]
        timeouts = [(e["入队序"], e["会话"]) for e in events if e["结果"] == "超时"]
        self.assertEqual(timeouts, [(1, "q1"), (2, "q2")])

    def test_does_not_age_lease_only_expiry(self):
        _auth, s = make(idle_ms=100000, lease_ms=10)
        s.do("x", "建立", "h1", ("alice", "pw"), 0)
        doc = json.loads(s.timeout_storm("b", 50))
        self.assertEqual(doc["处理"], 0)
        self.assertEqual(doc["批次"], [])
        session = s._sessions["h1"]
        self.assertEqual(session["state"], "在线")
        self.assertIsNotNone(session["ip"])

    def test_sessions_suspended_and_released(self):
        _auth, s = make()
        establish(s, 1)
        s.timeout_storm("b", 20)
        session = s._sessions["s0000"]
        self.assertEqual(session["state"], "挂起")
        self.assertEqual(session["deadline"], 0)
        self.assertIsNone(session["ip"])
        self.assertIsNone(session["pool"])
        self.assertEqual(s._pools["default"].leases, {})


class TimeoutStormReplayTest(unittest.TestCase):
    def test_replay_returns_original_bytes_without_sweeping(self):
        _auth, s = make()
        establish(s, 1)
        out = s.timeout_storm("b", 20)
        # 重放前重建候选不可能（会话已挂起），重放只回原字节。
        self.assertEqual(s.timeout_storm("b", 20), out)
        self.assertEqual(s.timeout_storm("b", 20, batches=10), out)

    def test_different_params_raise_value_error(self):
        _auth, s = make()
        s.timeout_storm("b", 20, batches=2)
        with self.assertRaises(ValueError):
            s.timeout_storm("b", 21, batches=2)
        with self.assertRaises(ValueError):
            s.timeout_storm("b", 20, batches=3)

    def test_failures_do_not_occupy_key(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.timeout_storm("b", -1)
        with self.assertRaises(TypeError):
            s.timeout_storm("b", "x")
        # 此前失败不占 key：合法调用仍是首次成功。
        doc = json.loads(s.timeout_storm("b", 20))
        self.assertTrue(doc["完成"])

    def test_cache_domain_separate(self):
        _auth, s = make()
        establish(s, 1)
        s.do("k", "建立", "other", ("bob", "pw"), 0)
        s.timeout_sweep("k", 20)
        s.fault("k", "注入", 100, 0)
        # 同名字符串 key 跨域不冲突。
        doc = json.loads(s.timeout_storm("k", 20))
        self.assertEqual(doc["处理"], 0)


class TimeoutStormAuditTest(unittest.TestCase):
    def test_audit_first_and_replay(self):
        _auth, s = make()
        s.timeout_storm("a", 20)  # 完成
        s.timeout_storm("a", 20)
        events = json.loads(s.audit(limit=100))["事件"]
        self.assertEqual(
            [(e["操作"], e["会话"], e["结果"], e["原序号"]) for e in events],
            [
                ("超时风暴", "", "完成", 0),
                ("超时风暴", "", "重放", 1),
            ],
        )
        self.assertTrue(s.verify_audit())

    def test_audit_incomplete_result(self):
        _auth, s = make()
        establish(s, 250)
        s.timeout_storm("a", 20, batches=1)
        storm = [e for e in chain_events(s) if e["操作"] == "超时风暴"]
        self.assertEqual(len(storm), 1)
        self.assertEqual(
            (storm[0]["会话"], storm[0]["结果"], storm[0]["原序号"]),
            ("", "未完成", 0),
        )
        self.assertTrue(s.verify_audit())

    def test_param_error_not_audited(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.timeout_storm("a", -1)
        self.assertEqual(json.loads(s.audit(limit=100))["事件"], [])

    def test_separate_origin_index_across_domains(self):
        _auth, s = make()
        establish(s, 1)
        s.do("k", "建立", "other", ("bob", "pw"), 0)
        s.timeout_storm("k", 20)
        s.do("k", "建立", "other", ("bob", "pw"), 0)
        s.timeout_storm("k", 20)
        events = json.loads(s.audit(limit=100))["事件"]
        self.assertEqual(
            [(e["操作"], e["结果"], e["原序号"]) for e in events],
            [
                ("建立", "成功", 0),
                ("建立", "成功", 0),
                ("超时风暴", "完成", 0),
                ("建立", "成功", 2),
                ("超时风暴", "重放", 3),
            ],
        )
        self.assertTrue(s.verify_audit())


if __name__ == "__main__":
    unittest.main()
