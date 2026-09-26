import hashlib
import json
import unittest

from access import (
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
)


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def parse(out):
    return json.loads(out)


def make(users=("alice", "bob", "carol"), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(auth, 10, 10, idle_ms,
                 pool=("10.0.0.0/24", (), ()), lease_ms=lease_ms)
    s.add_pool("gold", ("10.1.0.0/24", (), ()))
    return auth, s


def seal(doc):
    head = {key: doc[key] for key in ("版本", "时刻", "后端", "池", "超时")}
    doc["摘要"] = digest(head)
    return compact(doc) + "\n"


def build(now_ms=0, until=0, backoff=(), fail=(0, 0), pools=(),
          waiting=False, trigger=0):
    return {
        "版本": 1,
        "时刻": now_ms,
        "后端": {
            "截至": until,
            "退避": [
                {"用户": u, "次数": n, "下次": r} for u, n, r in backoff
            ],
            "失败": {"故障": fail[0], "退避": fail[1]},
        },
        "池": [{"标识": p, "截至": u} for p, u in pools],
        "超时": {"等待": waiting, "触发": trigger},
    }


class FaultCheckpointTest(unittest.TestCase):
    def test_empty_format(self):
        _auth, s = make()
        out = s.fault_checkpoint(0)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)
        doc = parse(out)
        self.assertEqual(list(doc), ["版本", "时刻", "后端", "池", "超时", "摘要"])
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["时刻"], 0)
        self.assertEqual(list(doc["后端"]), ["截至", "退避", "失败"])
        self.assertEqual(doc["后端"]["截至"], 0)
        self.assertEqual(doc["后端"]["退避"], [])
        self.assertEqual(doc["后端"]["失败"], {"故障": 0, "退避": 0})
        self.assertEqual(list(doc["后端"]["失败"]), ["故障", "退避"])
        self.assertEqual(doc["池"], [])
        self.assertEqual(list(doc["超时"]), ["等待", "触发"])
        self.assertEqual(doc["超时"], {"等待": False, "触发": 0})
        head = {k: doc[k] for k in ("版本", "时刻", "后端", "池", "超时")}
        self.assertEqual(doc["摘要"], digest(head))

    def test_param_validation(self):
        _auth, s = make()
        for bad in (True, "0", 1.5, None, b"0", []):
            with self.assertRaises(TypeError):
                s.fault_checkpoint(bad)
        for bad in (-1, -100):
            with self.assertRaises(ValueError):
                s.fault_checkpoint(bad)

    def test_populated_full_shape(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        for key, sid, user, now in (
            ("d1", "s1", "alice", 0),
            ("d2", "s2", "bob", 0),
            ("d3", "s3", "alice", 50),
        ):
            with self.assertRaises(BackendError):
                s.do(key, "建立", sid, (user, "pw"), now)
        s.pool_fault("p1", "注入", "gold", 500, 10)
        s.pool_fault("p2", "注入", "default", 200, 10)
        s.timeout_fault("t1", "注入", 5000, 100)
        doc = parse(s.fault_checkpoint(60))
        self.assertEqual(doc["后端"]["截至"], 1000)
        self.assertEqual(
            doc["后端"]["退避"],
            [
                {"用户": "alice", "次数": 1, "下次": 100},
                {"用户": "bob", "次数": 1, "下次": 100},
            ],
        )
        self.assertEqual(doc["后端"]["失败"], {"故障": 2, "退避": 1})
        self.assertEqual(
            doc["池"],
            [{"标识": "default", "截至": 210},
             {"标识": "gold", "截至": 510}],
        )
        self.assertTrue(all(list(r) == ["标识", "截至"] for r in doc["池"]))
        self.assertEqual(doc["超时"], {"等待": True, "触发": 5000})
        head = {k: doc[k] for k in ("版本", "时刻", "后端", "池", "超时")}
        self.assertEqual(doc["摘要"], digest(head))

    def test_read_only_keeps_expired_and_does_not_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("e2", "建立", "s2", ("bob", "pw"), 0)
        s.pool_fault("p1", "注入", "gold", 10, 0)   # 截至 10
        s.timeout_fault("t1", "注入", 100, 0)       # 触发 100
        doc = parse(s.fault_checkpoint(100000))
        # 到期池演练与超时待触发值均原样保留，不清。
        self.assertEqual(
            doc["后端"]["退避"], [{"用户": "bob", "次数": 1, "下次": 100}]
        )
        self.assertEqual(doc["池"], [{"标识": "gold", "截至": 10}])
        self.assertEqual(doc["超时"], {"等待": True, "触发": 100})
        self.assertEqual(s._sessions["s1"]["state"], "在线")

    def test_byte_stable(self):
        _auth, s = make()
        self.assertEqual(s.fault_checkpoint(7), s.fault_checkpoint(7))
        self.assertNotEqual(s.fault_checkpoint(7), s.fault_checkpoint(8))

    def test_timeout_recovered_is_not_waiting(self):
        _auth, s = make()
        s.timeout_fault("t1", "注入", 100, 0)
        s.timeout_fault("t2", "恢复", None, 5)
        doc = parse(s.fault_checkpoint(0))
        self.assertEqual(doc["超时"], {"等待": False, "触发": 0})


class FaultRestoreTest(unittest.TestCase):
    def test_roundtrip_full(self):
        _auth, src = make()
        src.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            src.do("d1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(BackendError):
            src.do("d2", "建立", "s2", ("bob", "pw"), 0)
        with self.assertRaises(BackendError):
            src.do("d3", "建立", "s3", ("alice", "pw"), 50)
        src.pool_fault("p1", "注入", "gold", 500, 10)
        src.timeout_fault("t1", "注入", 9000, 100)
        cp = src.fault_checkpoint(60)

        _auth2, dst = make()
        out = dst.fault_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(dst.fault_checkpoint(60), cp)
        self.assertEqual(dst._fault_until, 1000)
        self.assertEqual(dst._backoff, {"alice": (1, 100), "bob": (1, 100)})
        self.assertEqual(dst._fault_fail, [2, 1])
        self.assertEqual(dst._pool_fault, {"gold": 510})
        self.assertEqual(dst._timeout_at, 9000)

    def test_roundtrip_empty_clears_all_three(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("p1", "注入", "gold", 500, 0)
        s.timeout_fault("t1", "注入", 100, 0)
        cp = seal(build(5))
        s.fault_restore("r1", cp)
        self.assertEqual(s._fault_until, 0)
        self.assertEqual(s._backoff, {})
        self.assertEqual(s._fault_fail, [0, 0])
        self.assertEqual(s._pool_fault, {})
        self.assertIsNone(s._timeout_at)
        self.assertEqual(s.fault_checkpoint(5), cp)

    def test_restored_domains_keep_working(self):
        _auth, s = make()
        cp = seal(build(60, 10000, [("alice", 1, 100)], (3, 2),
                        pools=[("gold", 5000)], waiting=True, trigger=7000))
        s.fault_restore("r1", cp)
        with self.assertRaises(BackendError) as ctx:
            s.do("d1", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(ctx.exception.args[0], 300)
        self.assertEqual(s._fault_fail, [4, 2])
        # 池演练表与超时待触发值沿用恢复值。
        self.assertEqual(s._pool_fault, {"gold": 5000})
        self.assertEqual(s._timeout_at, 7000)
        # 恢复后端后业务恢复正常；池/超时表仍保留。
        s.fault("fc", "恢复", None, 100)
        out = parse(s.do("d2", "建立", "s2", ("alice", "pw"), 100))
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(s._pool_fault, {"gold": 5000})
        self.assertEqual(s._timeout_at, 7000)

    def test_pretty_input_canonical(self):
        _auth, s = make()
        doc = build(10, 500, [("alice", 2, 300)], (1, 0),
                    pools=[("gold", 5)], waiting=True, trigger=42)
        doc["摘要"] = digest({k: doc[k] for k in
                              ("版本", "时刻", "后端", "池", "超时")})
        pretty = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
        out = s.fault_restore("r1", pretty)
        self.assertEqual(out, seal(json.loads(pretty)))
        self.assertEqual(s.fault_checkpoint(10), out)

    def test_type_errors(self):
        _auth, s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.fault_restore(bad_key, "x")
        with self.assertRaises(ValueError):
            s.fault_restore("", "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.fault_restore("k", bad_text)

    def test_value_errors(self):
        _auth, s = make()
        good = json.loads(seal(build(waiting=True, trigger=5)))
        bad_texts = [
            "", "{", "[]", "1", '"x"',
            compact({"版本": 1}),
            # 键集/键序。
            compact({k: good[k] for k in
                     ("摘要", "版本", "时刻", "后端", "池", "超时")}),
            compact({**good, "x": 1}),
            seal({**good, "版本": 0}),
            seal({**good, "版本": 2}),
            seal({**good, "版本": "1"}),
            seal({**good, "版本": True}),
            seal({**good, "时刻": -1}),
            seal({**good, "时刻": True}),
            # 后端键序/形态。
            seal({**good, "后端": []}),
            seal({**good, "后端": {"退避": [], "截至": 0,
                                   "失败": {"故障": 0, "退避": 0}}}),
            seal({**good, "后端": {"截至": 0, "退避": [],
                                   "失败": {"故障": 0, "退避": 0}, "x": 0}}),
            seal({**good, "后端": {**good["后端"], "截至": -1}}),
            # 退避项。
            seal({**good, "后端": {**good["后端"], "退避": [
                {"次数": 1, "用户": "alice", "下次": 1}]}}),
            seal({**good, "后端": {**good["后端"], "退避": [
                {"用户": "alice", "次数": 0, "下次": 1}]}}),
            seal({**good, "后端": {**good["后端"], "退避": [
                {"用户": "alice", "次数": 1, "下次": 1},
                {"用户": "alice", "次数": 2, "下次": 2}]}}),
            seal({**good, "后端": {**good["后端"], "退避": [
                {"用户": "bob", "次数": 1, "下次": 1},
                {"用户": "alice", "次数": 1, "下次": 1}]}}),
            # 失败键序/值。
            seal({**good, "后端": {**good["后端"],
                                   "失败": {"退避": 0, "故障": 0}}}),
            seal({**good, "后端": {**good["后端"],
                                   "失败": {"故障": -1, "退避": 0}}}),
            # 池形态。
            seal({**good, "池": {}}),
            seal({**good, "池": [{"截至": 1, "标识": "gold"}]}),
            seal({**good, "池": [{"标识": "gold"}]}),
            seal({**good, "池": [{"标识": "gold", "截至": -1}]}),
            seal({**good, "池": [{"标识": "", "截至": 1}]}),
            seal({**good, "池": [
                {"标识": "gold", "截至": 1},
                {"标识": "gold", "截至": 2}]}),
            seal({**good, "池": [
                {"标识": "gold", "截至": 1},
                {"标识": "default", "截至": 1}]}),
            # 超时。
            seal({**good, "超时": {"触发": 0, "等待": False}}),
            seal({**good, "超时": {"等待": "false", "触发": 0}}),
            seal({**good, "超时": {"等待": False, "触发": 1}}),
            seal({**good, "超时": {"等待": True, "触发": -1}}),
            seal({**good, "超时": {"等待": True, "触发": "1"}}),
            seal({**good, "超时": [True, 0]}),
            # 摘要。
            compact({**good, "摘要": 0}),
            compact({**good, "摘要": "0" * 64}),
        ]
        for text in bad_texts:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.fault_restore("k", text)

    def test_unknown_user_or_pool_resource_error(self):
        _auth, s = make()
        with self.assertRaises(ResourceError):
            s.fault_restore("r1", seal(build(0, 0, [("nobody", 1, 1)])))
        with self.assertRaises(ResourceError):
            s.fault_restore("r2", seal(build(pools=[("nope", 1)])))

    def test_failure_does_not_change_instance(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        s.pool_fault("p1", "注入", "gold", 500, 0)
        s.timeout_fault("t1", "注入", 100, 0)
        before = s.fault_checkpoint(0)
        for bad in ("not json", "[]",
                    seal(build(0, 0, [("x", 1, 1)])),
                    seal(build(pools=[("nope", 1)]))):
            with self.assertRaises((ValueError, ResourceError)):
                s.fault_restore("r9", bad)
        self.assertEqual(s.fault_checkpoint(0), before)
        self.assertEqual(s._fault_until, 1000)
        self.assertEqual(s._pool_fault, {"gold": 500})
        self.assertEqual(s._timeout_at, 100)

    def test_failure_does_not_occupy_key(self):
        _auth, s = make()
        good = seal(build())
        with self.assertRaises(ValueError):
            s.fault_restore("r1", "bad")
        with self.assertRaises(ResourceError):
            s.fault_restore("r1", seal(build(0, 0, [("x", 1, 1)])))
        self.assertEqual(s.fault_restore("r1", good),
                         s.fault_checkpoint(0))

    def test_replay_same_bytes(self):
        _auth, s = make()
        text = seal(build(0, 500, [("alice", 1, 100)], (1, 0),
                          pools=[("gold", 5)], waiting=True, trigger=9))
        first = s.fault_restore("r1", text)
        s.fault("fc", "恢复", None, 10)
        s.pool_fault("px", "恢复", "gold", None, 10)
        s.timeout_fault("tx", "恢复", None, 10)
        self.assertEqual(s.fault_restore("r1", text), first)
        # 重放不替换三域。
        self.assertEqual(s._fault_until, 0)
        self.assertEqual(s._pool_fault, {})
        self.assertIsNone(s._timeout_at)

    def test_replay_different_params_value_error(self):
        _auth, s = make()
        t1 = seal(build())
        t2 = seal(build(0, 1))
        s.fault_restore("r1", t1)
        with self.assertRaises(ValueError):
            s.fault_restore("r1", t2)
        with self.assertRaises(ValueError):
            s.fault_restore("r1", t1.rstrip("\n"))
        with self.assertRaises(ValueError):
            s.fault_restore("r1", None)
        self.assertEqual(s.fault_restore("r2", t1), t1)

    def test_audit_first_and_replay(self):
        _auth, s = make()
        cp = seal(build(77, 500, [("alice", 1, 100)], (2, 1),
                        pools=[("gold", 1)], waiting=True, trigger=88))
        s.fault_restore("r1", cp)
        s.fault_restore("r1", cp)
        events = parse(s.audit(limit=10))["事件"]
        self.assertEqual(
            [(e["操作"], e["会话"], e["结果"], e["时刻"], e["原序号"])
             for e in events],
            [
                ("故障恢复", "", "成功", 77, 0),
                ("故障恢复", "", "重放", 77, 1),
            ],
        )
        self.assertTrue(s.verify_audit())
        self.assertEqual(parse(s.takeover_audit())["事件"], [])

    def test_audit_origin_per_domain(self):
        _auth, s = make()
        out = s.do("shared", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(parse(out)["状态"], "在线")
        cp = seal(build())
        s.fault_restore("shared", cp)
        s.fault_restore("shared", cp)
        events = parse(s.audit(limit=10))["事件"]
        ops = [(e["操作"], e["结果"], e["原序号"]) for e in events]
        self.assertEqual(ops[0], ("建立", "成功", 0))
        self.assertEqual(ops[1], ("故障恢复", "成功", 0))
        self.assertEqual(ops[2], ("故障恢复", "重放", 2))
        self.assertTrue(s.verify_audit())

    def test_failures_not_audited(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.fault_restore("r1", "bad")
        with self.assertRaises(ResourceError):
            s.fault_restore("r2", seal(build(0, 0, [("x", 1, 1)])))
        with self.assertRaises(TypeError):
            s.fault_restore(1, seal(build()))
        self.assertEqual(parse(s.audit())["事件"], [])

    def test_cache_domain_independent(self):
        _auth, s = make()
        s.fault("shared", "注入", 1000, 0)
        # 与 fault/do/backend_restore 各域独立。
        cp = seal(build())
        self.assertEqual(s.fault_restore("shared", cp), cp)
        # 恢复已清故障；fault 域的 "shared" 首果仍可重放。
        out = s.fault("shared", "注入", 1000, 0)
        self.assertEqual(parse(out)["状态"], "故障")
        # backend_restore 域的同 key 也独立可用。
        backend_cp = (
            '{"版本":1,"时刻":0,"截至":0,"退避":[],'
            '"失败":{"故障":0,"退避":0},"摘要":"' + "0" * 64 + '"}\n'
        )
        # 摘要须真实：直接用 backend_checkpoint 生成空态包。
        backend_cp = s.backend_checkpoint(0)
        self.assertEqual(s.backend_restore("shared", backend_cp), backend_cp)

    def test_restore_does_not_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        cp = seal(build(100000))
        s.fault_restore("r1", cp)
        self.assertEqual(s._sessions["s1"]["state"], "在线")


if __name__ == "__main__":
    unittest.main()
