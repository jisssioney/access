import hashlib
import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def make(pool_cidr="10.0.0.0/29", kill=False, per=5, idle=100000):
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob", "carol", "dave", "erin", "frank"):
        auth.add(user, "pw")
    s = Sessions(auth, 10, per, idle, lease_ms=100000)
    templates = [
        {"标识": "gold", "限速": 1000000, "突发": 0, "配额": 10000,
         "周期毫秒": 0, "会话上限": 0, "排队优先级": 0, "超限": "拒绝"},
    ]
    bindings = [["alice", "gold"], ["carol", "gold"], ["dave", "gold"],
                ["erin", "gold"], ["frank", "gold"]]
    if kill:
        templates.append(
            {"标识": "kill", "限速": 1000000, "突发": 0, "配额": 10,
             "周期毫秒": 0, "会话上限": 0, "排队优先级": 0, "超限": "下线"}
        )
        bindings.append(["bob", "kill"])
    config = {
        "版本": 10,
        "会话": {"总数": 10, "每用户": 5, "空闲毫秒": idle, "租期毫秒": 100000},
        "地址池": [{"标识": "default", "CIDR": pool_cidr, "保留": [], "静态": []}],
        "模板": templates,
        "用户模板": bindings,
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {"最大失败": 3, "锁定毫秒": 1000,
                 "重试基数毫秒": 0, "重试上限毫秒": 0},
    }
    s.load_config(json.dumps(config, ensure_ascii=False))
    return s


def events(s, after=0, limit=1000):
    return json.loads(s.accounting_events(after, limit))["事件"]


def verify_chain(rows):
    prev = "0" * 64
    for event in rows:
        head = {
            "序号": event["序号"], "类型": event["类型"], "时刻": event["时刻"],
            "会话": event["会话"], "用户": event["用户"],
            "地址池": event["地址池"], "地址": event["地址"],
            "累计字节": event["累计字节"], "原因": event["原因"],
            "前哈希": prev,
        }
        digest = hashlib.sha256(
            json.dumps(head, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        assert event["前哈希"] == prev
        assert event["哈希"] == digest
        prev = digest
    return prev


class AccountingStartStopTest(unittest.TestCase):
    def test_establish_and_explicit_offline(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "下线", "s1", None, 40)
        rows = events(s)
        self.assertEqual([(e["类型"], e["会话"], e["原因"]) for e in rows],
                         [("开始", "s1", ""), ("停止", "s1", "下线")])
        self.assertEqual(rows[0]["时刻"], 0)
        self.assertEqual(rows[1]["时刻"], 40)
        # 停止事件在清场前生成，仍携带会话当时持址；释址不回填事件。
        self.assertEqual(rows[0]["地址"], "10.0.0.1")
        self.assertEqual(rows[1]["地址"], "10.0.0.1")
        verify_chain(rows)

    def test_takeover_stop_and_start_same_moment(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "接管", "s2", ("s1", "pw"), 90)
        rows = events(s)
        self.assertEqual([e["类型"] for e in rows], ["开始", "停止", "开始"])
        stop, start = rows[1], rows[2]
        self.assertEqual(stop["原因"], "接管")
        self.assertEqual(stop["时刻"], 90)
        self.assertEqual(start["时刻"], 90)
        self.assertEqual(start["会话"], "s2")
        self.assertEqual(start["地址"], stop["地址"])
        verify_chain(rows)

    def test_migrate_renew_suspend_resume_do_not_split(self):
        s = make()
        s.add_pool("other", ("10.1.0.0/29", (), ()))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "续租", "s1", None, 5)
        s.do("k3", "迁移", "s1", ("other", "pw"), 6)
        s.do("k4", "挂起", "s1", None, 30)
        s.do("k5", "恢复", "s1", ("other", "pw"), 40)
        self.assertEqual([e["类型"] for e in events(s)], ["开始"])

    def test_timeout_aging_only_suspends_without_stop(self):
        s = make(idle=100)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # now_ms 越过空闲期限：老化仅挂起，不停止计费。
        try:
            s.meter("m1", "s1", 10, 200)
        except StateError:
            pass
        self.assertEqual([e["类型"] for e in events(s)], ["开始"])

    def test_batch_online_and_offline(self):
        s = make()
        s.batch_online(
            "b1", (("e1", "alice", "pw"), ("e2", "carol", "pw")), 100
        )
        s.batch_offline("b2", ("e1", "e2"), 110)
        rows = events(s)
        self.assertEqual([e["类型"] for e in rows],
                         ["开始", "开始", "停止", "停止"])
        self.assertTrue(all(e["原因"] == "批量下线" for e in rows[2:]))
        verify_chain(rows)

    def test_force_disable_reason(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.user_admin("u1", "停用", "alice", 130, force=True)
        rows = events(s)
        self.assertEqual(rows[-1]["类型"], "停止")
        self.assertEqual(rows[-1]["原因"], "停用")

    def test_quota_offline_reason_and_bytes(self):
        s = make(kill=True)
        s.do("k1", "建立", "q", ("bob", "pw"), 0)
        s.meter("m1", "q", 5, 5)
        try:
            s.meter("m2", "q", 100, 6)
        except Exception:
            pass
        rows = events(s)
        self.assertEqual(rows[-1]["原因"], "配额")
        self.assertEqual(rows[-1]["累计字节"], 5)

    def test_capacity_promotion_emits_start(self):
        s = make(pool_cidr="10.0.0.0/30")
        s.batch_online("pre", (("u0", "dave", "pw"), ("u1", "erin", "pw")), 0)
        self.assertEqual(json.loads(
            s.capacity("c1", "申请", "w", ("alice", "pw", 1000), 0)
        )["结果"], "排队")
        s.capacity("c2", "推进", "", None, 5)
        s.do("c3", "下线", "u0", None, 6)
        s.capacity("c4", "推进", "", None, 7)
        self.assertTrue(
            any(e["会话"] == "w" and e["类型"] == "开始" for e in events(s))
        )


class AccountingInterimTest(unittest.TestCase):
    def test_interim_accumulates_only_passed_bytes(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 10)
        s.meter("m2", "s1", 999999, 11)  # 拒绝：不计
        out = json.loads(s.accounting_interim("i1", "s1", 20))
        self.assertEqual(out["累计字节"], 100)
        self.assertEqual(out["类型"], "中间")
        self.assertEqual(out["原因"], "")
        self.assertEqual(out["序号"], 2)

    def test_unknown_sid_keyerror(self):
        s = make()
        with self.assertRaises(KeyError):
            s.accounting_interim("i1", "nope", 0)

    def test_non_online_state_error(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "挂起", "s1", None, 1)
        with self.assertRaises(StateError):
            s.accounting_interim("i1", "s1", 2)

    def test_earlier_than_last_accounting_state_error(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.accounting_interim("i1", "s1", 20)
        with self.assertRaises(StateError):
            s.accounting_interim("i2", "s1", 19)

    def test_replay_same_params_no_double_accounting(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 10)
        first = s.accounting_interim("i1", "s1", 20)
        second = s.accounting_interim("i1", "s1", 20)
        self.assertEqual(first, second)
        self.assertEqual(len(events(s)), 2)
        # meter 同参重放亦不多计。
        self.assertEqual(json.loads(s.meter("m1", "s1", 100, 10))["累计"], 100)
        with self.assertRaises(ValueError):
            s.accounting_interim("i1", "s1", 21)

    def test_param_validation(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        for i, bad_sid in enumerate((1, True)):
            with self.assertRaises(TypeError):
                s.accounting_interim(f"k{i}", bad_sid, 0)
        for i, bad_now in enumerate((True, 1.5, -1, "0")):
            with self.assertRaises((TypeError, ValueError)):
                s.accounting_interim(f"n{i}", "s1", bad_now)


class AccountingEventsPageTest(unittest.TestCase):
    def test_empty_and_tail(self):
        s = make()
        doc = json.loads(s.accounting_events())
        self.assertEqual(list(doc), ["版本", "起点", "下页", "事件", "尾序号", "尾哈希"])
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["起点"], 0)
        self.assertEqual(doc["下页"], 0)
        self.assertEqual(doc["事件"], [])
        self.assertEqual(doc["尾序号"], 0)
        self.assertEqual(doc["尾哈希"], "0" * 64)
        self.assertTrue(s.accounting_events().endswith("\n"))

    def test_paging(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "下线", "s1", None, 1)
        page1 = json.loads(s.accounting_events(0, 1))
        self.assertEqual(len(page1["事件"]), 1)
        self.assertEqual(page1["下页"], 1)
        self.assertEqual(page1["尾序号"], 2)
        page2 = json.loads(s.accounting_events(1, 1))
        self.assertEqual(page2["事件"][0]["序号"], 2)
        empty = json.loads(s.accounting_events(2, 10))
        self.assertEqual(empty["事件"], [])
        self.assertEqual(empty["下页"], 2)
        self.assertEqual(empty["尾哈希"], page2["事件"][0]["哈希"])

    def test_param_validation(self):
        s = make()
        for bad in (True, 1.5, "0", -1):
            with self.assertRaises((TypeError, ValueError)):
                s.accounting_events(bad)
        with self.assertRaises(TypeError):
            s.accounting_events(0, True)
        for bad_limit in (0, 1001):
            with self.assertRaises(ValueError):
                s.accounting_events(0, bad_limit)

    def test_determinism(self):
        def run():
            s = make()
            s.do("k1", "建立", "s1", ("alice", "pw"), 0)
            s.meter("m1", "s1", 100, 10)
            s.accounting_interim("i1", "s1", 20)
            s.do("k2", "下线", "s1", None, 30)
            return s.accounting_events()
        self.assertEqual(run(), run())


class AccountingBatchAtomicTest(unittest.TestCase):
    def test_atomic_rollback_leaves_no_events(self):
        s = make(pool_cidr="10.0.0.0/30")
        s.batch_online("pre", (("u0", "dave", "pw"), ("u1", "erin", "pw")), 0)
        before = len(events(s))
        out = json.loads(s.batch_online(
            "b2", (("p", "alice", "pw"), ("q", "carol", "pw")), 1, atomic=True
        ))
        self.assertEqual(out["结果"], "回滚")
        self.assertEqual(len(events(s)), before)

    def test_non_atomic_records_only_committed(self):
        s = make(pool_cidr="10.0.0.0/29")
        s.batch_online(
            "pre", (("v0", "alice", "pw"), ("v1", "bob", "pw"),
                    ("v2", "carol", "pw"), ("v3", "dave", "pw"),
                    ("v4", "erin", "pw")), 0
        )
        out = json.loads(s.batch_online(
            "b2", (("p", "frank", "pw"), ("q", "carol", "pw")), 1
        ))
        self.assertEqual([i["结果"] for i in out["项目"]],
                         ["上线", "ResourceError"])
        self.assertEqual(
            [e["会话"] for e in events(s) if e["类型"] == "开始"][-1], "p"
        )


class ServiceCheckpointAccountingTest(unittest.TestCase):
    def _populated(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 10)
        s.accounting_interim("i1", "s1", 20)
        s.do("k2", "建立", "s2", ("carol", "pw"), 40)
        return s

    def test_checkpoint_carries_accounting(self):
        s = self._populated()
        cp = json.loads(s.service_checkpoint(50))
        self.assertEqual(list(cp),
                         ["版本", "时刻", "配置摘要", "认证", "运行态",
                          "计费", "故障", "统计", "摘要"])
        self.assertEqual(cp["版本"], 2)
        acct = cp["计费"]
        self.assertEqual(list(acct), ["版本", "事件", "会话", "尾哈希", "摘要"])
        self.assertEqual([r["会话"] for r in acct["会话"]], ["s1", "s2"])
        self.assertEqual(acct["会话"][0]["累计字节"], 100)
        self.assertEqual(acct["会话"][0]["最近时刻"], 20)

    def test_restore_roundtrip(self):
        s = self._populated()
        cp = s.service_checkpoint(50)
        target = make()
        self.assertEqual(target.service_restore("r1", cp), cp)
        self.assertEqual(target.service_restore("r1", cp), cp)
        rows = events(target)
        self.assertEqual(len(rows), 3)
        # 恢复后链接继续，累计沿用。
        target.meter("m9", "s1", 50, 55)
        out = json.loads(target.accounting_interim("i9", "s1", 60))
        self.assertEqual(out["累计字节"], 150)
        self.assertEqual(out["前哈希"], rows[-1]["哈希"])

    def test_restore_accepts_v1_empty_accounting(self):
        s = self._populated()
        doc = json.loads(s.service_checkpoint(50))
        del doc["计费"]
        doc["版本"] = 1
        head = {k: doc[k] for k in
                ("版本", "时刻", "配置摘要", "认证", "运行态", "故障", "统计")}
        doc["摘要"] = hashlib.sha256(
            json.dumps(head, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        v1 = json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        target = make()
        out = json.loads(target.service_restore("r2", v1))
        self.assertEqual(out["版本"], 2)
        self.assertEqual(out["计费"]["事件"], [])

    def test_restore_divergent_accounting_state_error(self):
        s = self._populated()
        cp = s.service_checkpoint(50)
        # 运行态逐字段一致（含相同计量账本），仅计费链不同（中间计费时刻与
        # 累计不同）。
        target = make()
        target.do("j1", "建立", "s1", ("alice", "pw"), 0)
        target.accounting_interim("i0", "s1", 5)
        target.meter("m1", "s1", 100, 10)
        target.do("j2", "建立", "s2", ("carol", "pw"), 40)
        with self.assertRaises(StateError) as ctx:
            target.service_restore("r3", cp)
        self.assertEqual(ctx.exception.args[0], "计费")

    def test_restore_unknown_user_resource_error(self):
        s = self._populated()
        doc = json.loads(s.service_checkpoint(50))
        doc["计费"]["事件"][0]["用户"] = "ghost"
        self._reseal(doc, recompute_events=True)
        target = make()
        with self.assertRaises(ResourceError):
            target.service_restore("r4", json.dumps(
                doc, ensure_ascii=False, separators=(",", ":")) + "\n")

    def test_restore_bad_hash_value_error(self):
        s = self._populated()
        doc = json.loads(s.service_checkpoint(50))
        doc["计费"]["事件"][-1]["哈希"] = "f" * 64
        doc["计费"]["尾哈希"] = "f" * 64
        self._reseal(doc, recompute_events=False)
        target = make()
        with self.assertRaises(ValueError):
            target.service_restore("r5", json.dumps(
                doc, ensure_ascii=False, separators=(",", ":")) + "\n")

    def test_failure_changes_nothing(self):
        s = self._populated()
        doc = json.loads(s.service_checkpoint(50))
        doc["计费"]["事件"][-1]["哈希"] = "f" * 64
        doc["计费"]["尾哈希"] = "f" * 64
        self._reseal(doc, recompute_events=False)
        target = make()
        before = target.accounting_events()
        with self.assertRaises(ValueError):
            target.service_restore("r6", json.dumps(
                doc, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.assertEqual(target.accounting_events(), before)

    @staticmethod
    def _reseal(doc, recompute_events):
        if recompute_events:
            prev = "0" * 64
            for event in doc["计费"]["事件"]:
                event["前哈希"] = prev
                head = {k: event[k] for k in (
                    "序号", "类型", "时刻", "会话", "用户", "地址池", "地址",
                    "累计字节", "原因", "前哈希")}
                event["哈希"] = hashlib.sha256(
                    json.dumps(head, ensure_ascii=False,
                               separators=(",", ":")).encode()
                ).hexdigest()
                prev = event["哈希"]
            doc["计费"]["尾哈希"] = prev
        acct = doc["计费"]
        acct_head = {k: acct[k] for k in ("版本", "事件", "会话", "尾哈希")}
        acct["摘要"] = hashlib.sha256(
            json.dumps(acct_head, ensure_ascii=False,
                       separators=(",", ":")).encode()
        ).hexdigest()
        top = {k: doc[k] for k in (
            "版本", "时刻", "配置摘要", "认证", "运行态", "计费", "故障", "统计")}
        doc["摘要"] = hashlib.sha256(
            json.dumps(top, ensure_ascii=False,
                       separators=(",", ":")).encode()
        ).hexdigest()


if __name__ == "__main__":
    unittest.main()
