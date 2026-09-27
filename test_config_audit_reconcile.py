import hashlib
import json
import unittest

from access import Authenticator, ResourceError, Sessions, StateError


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def load(s, mutate=None):
    doc = json.loads(s.export_config())
    if mutate is not None:
        mutate(doc)
    return s.load_config(json.dumps(doc, ensure_ascii=False))


def recon(s):
    return json.loads(s.config_audit_reconcile())


def fix_chain(s):
    """重算全链前哈希/哈希（模拟篡改后缝合）。"""
    prev = "0" * 64
    events = []
    for e in s._chain_events:
        seq, now_ms, key, op, sid, result, origin, _p, _d = e
        digest = s._chain_hash(seq, now_ms, key, op, sid, result, origin, prev)
        events.append((seq, now_ms, key, op, sid, result, origin, prev, digest))
        prev = digest
    s._chain_events[:] = events
    s._chain_tail = prev


class ReconcileSuccessTest(unittest.TestCase):
    def test_fresh(self):
        s = make()
        self.assertEqual(
            recon(s),
            {"锚修订": -1, "检查": 1, "完整": True, "断点修订": -1,
             "断点审计": -1, "原因": "", "末修订": 0, "末审计": 0},
        )
        raw = s.config_audit_reconcile()
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn(" ", raw.strip())
        self.assertEqual(
            list(json.loads(raw)),
            ["锚修订", "检查", "完整", "断点修订", "断点审计", "原因",
             "末修订", "末审计"],
        )

    def test_mixed_sources(self):
        s = make()
        load(s, lambda d: d["会话"].__setitem__("租期毫秒", 1001))  # 1 直接
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 900
        text = json.dumps(doc, ensure_ascii=False)
        s.config_change("L", "加载", text, 10)   # 2 事务
        s.config_change("L", "加载", text, 10)   # 重放
        s.config_change("R", "回滚", None, 11)   # 3 事务
        s.config_change("R", "回滚", None, 11)   # 重放
        s.config_change("U", "升级", s.export_config(), 12)  # 升级
        with self.assertRaises(StateError):
            s.config_change("R2", "回滚", None, 13)  # 失败
        doc = json.loads(s.export_config())
        doc["会话"]["租期毫秒"] = 7
        cas_text = json.dumps(doc, ensure_ascii=False)
        s.config_cas("c", cas_text, 3, 0)        # 4 直接 CAS
        s.config_revert("r", 0, 4, 0)            # 5 直接 回退
        s.rollback_config()                      # 6 直接 回滚
        out = recon(s)
        self.assertEqual(
            out,
            {"锚修订": -1, "检查": 7, "完整": True, "断点修订": -1,
             "断点审计": -1, "原因": "", "末修订": 6,
             "末审计": len(s._chain_events)},
        )
        self.assertTrue(s.verify_audit())

    def test_read_only(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        before = (s.config_revision(), s.audit(limit=1000),
                  s.config_history(limit=1000), s.export_config())
        s.config_audit_reconcile()
        after = (s.config_revision(), s.audit(limit=1000),
                 s.config_history(limit=1000), s.export_config())
        self.assertEqual(before, after)

    def test_eviction_boundary(self):
        s = make()
        base = json.loads(s.export_config())
        for i in range(1, 300):
            base["会话"]["租期毫秒"] = 1000 + i
            if i % 2:
                s.config_change(f"L{i}", "加载",
                                json.dumps(base, ensure_ascii=False), i)
            else:
                s.load_config(json.dumps(base, ensure_ascii=False))
        out = recon(s)
        self.assertEqual(out["完整"], True)
        self.assertEqual(out["锚修订"], 44)
        self.assertEqual(out["检查"], 255)
        self.assertEqual(out["末修订"], 299)
        self.assertEqual(out["末审计"], len(s._chain_events))


class ReconcileHistoryFailureTest(unittest.TestCase):
    def test_tampered_history_record(self):
        s = make()
        load(s)
        r = list(s._config_history_log[1])
        r[2] = "回滚"  # 操作篡改
        s._config_history_log[1] = tuple(r)
        out = recon(s)
        self.assertEqual(out["完整"], False)
        self.assertEqual(out["原因"], "历史")
        self.assertEqual(out["断点修订"], 1)
        self.assertEqual(out["断点审计"], -1)
        self.assertEqual(out["末审计"], 0)


class ReconcileAuditFailureTest(unittest.TestCase):
    def test_tampered_chain_hash(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        e = list(s._chain_events[0])
        e[8] = "0" * 64  # 哈希篡改
        s._chain_events[0] = tuple(e)
        out = recon(s)
        self.assertEqual(out["完整"], False)
        self.assertEqual(out["原因"], "审计")
        self.assertEqual(out["断点审计"], 1)
        self.assertEqual(out["断点修订"], -1)
        self.assertEqual(out["检查"], 2)
        self.assertEqual(out["末审计"], 0)

    def test_tampered_prev_hash(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        s.config_change("L", "加载", s.export_config(), 5)
        e = list(s._chain_events[1])
        e[7] = "1" * 64
        s._chain_events[1] = tuple(e)
        out = recon(s)
        self.assertEqual(out["原因"], "审计")
        self.assertEqual(out["断点审计"], 2)
        self.assertEqual(out["末审计"], 1)


class ReconcileSourceFailureTest(unittest.TestCase):
    def test_missing_chain_index_is_source(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        del s._config_change_chain_index["L"]
        out = recon(s)
        self.assertEqual(out["原因"], "来源")
        self.assertEqual(out["断点审计"], -1)

    def test_missing_upgrade_index_is_association(self):
        s = make()
        s.config_change("U", "升级", s.export_config(), 5)
        del s._config_change_chain_index["U"]
        out = recon(s)
        self.assertEqual(out["原因"], "关联")

    def test_tampered_event_result(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        e = list(s._chain_events[0])
        e[5] = "重放成功"
        s._chain_events[0] = tuple(e)
        fix_chain(s)
        out = recon(s)
        self.assertEqual(out["原因"], "结果")
        self.assertEqual(out["断点审计"], 1)

    def test_tampered_event_op(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        e = list(s._chain_events[0])
        e[3] = "配置回滚"
        s._chain_events[0] = tuple(e)
        fix_chain(s)
        out = recon(s)
        self.assertEqual(out["原因"], "操作")
        self.assertEqual(out["断点审计"], 1)

    def test_tampered_event_time(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        e = list(s._chain_events[0])
        e[1] = 999
        s._chain_events[0] = tuple(e)
        fix_chain(s)
        out = recon(s)
        self.assertEqual(out["原因"], "关联")
        self.assertEqual(out["断点审计"], 1)

    def test_tampered_replay_origin(self):
        s = make()
        text = s.export_config()
        s.config_change("L", "加载", text, 5)
        s.config_change("L", "加载", text, 5)
        e = list(s._chain_events[1])
        e[6] = 2  # 原序号指向自身
        s._chain_events[1] = tuple(e)
        fix_chain(s)
        out = recon(s)
        self.assertEqual(out["原因"], "重放")
        self.assertEqual(out["断点审计"], 2)

    def test_unregistered_first_event(self):
        s = make()
        s.config_change("L", "加载", s.export_config(), 5)
        # 伪造一个未登记的首次事件
        s._chain_events.append(
            (2, 7, "zzz", "配置加载", "", "成功", 0, s._chain_tail, "")
        )
        fix_chain(s)
        out = recon(s)
        self.assertEqual(out["原因"], "关联")
        self.assertEqual(out["断点审计"], 2)


if __name__ == "__main__":
    unittest.main()
