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


def make(users=("alice", "bob", "carol"), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(auth, 10, 10, idle_ms,
                 pool=("10.0.0.0/24", (), ()), lease_ms=lease_ms)
    return auth, s


def parse(out):
    return json.loads(out)


def seal(doc):
    """按前五键重算摘要，返回 LF 尾紧凑文本。"""
    head = {key: doc[key] for key in ("版本", "时刻", "截至", "退避", "失败")}
    doc["摘要"] = digest(head)
    return compact(doc) + "\n"


def build(now_ms=0, until=0, backoff=(), fail=(0, 0)):
    return {
        "版本": 1,
        "时刻": now_ms,
        "截至": until,
        "退避": [
            {"用户": user, "次数": n, "下次": retry_at}
            for user, n, retry_at in backoff
        ],
        "失败": {"故障": fail[0], "退避": fail[1]},
    }


class BackendCheckpointTest(unittest.TestCase):
    def test_empty_format(self):
        _auth, s = make()
        out = s.backend_checkpoint(0)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)
        self.assertEqual(
            out,
            '{"版本":1,"时刻":0,"截至":0,"退避":[],'
            '"失败":{"故障":0,"退避":0},'
            '"摘要":"7cb35a955921b141ac5c5a4a8d3942834fbac3d0'
            'ae1a6017949f3e4f528793b2"}\n',
        )
        doc = parse(out)
        self.assertEqual(
            list(doc), ["版本", "时刻", "截至", "退避", "失败", "摘要"]
        )
        self.assertEqual(list(doc["失败"]), ["故障", "退避"])
        head = {key: doc[key] for key in ("版本", "时刻", "截至", "退避", "失败")}
        self.assertEqual(doc["摘要"], digest(head))

    def test_param_validation(self):
        _auth, s = make()
        for bad in (True, "0", 1.5, None, b"0", []):
            with self.assertRaises(TypeError):
                s.backend_checkpoint(bad)
        for bad in (-1, -100):
            with self.assertRaises(ValueError):
                s.backend_checkpoint(bad)

    def test_populated_shape_order_and_digest(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        for key, sid, user, now in (
            ("d1", "s1", "alice", 0),
            ("d2", "s2", "bob", 0),
            ("d3", "s3", "alice", 50),   # retry_at 未到：计“退避”失败
        ):
            with self.assertRaises(BackendError):
                s.do(key, "建立", sid, (user, "pw"), now)
        out = s.backend_checkpoint(60)
        doc = parse(out)
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["时刻"], 60)
        self.assertEqual(doc["截至"], 1000)
        self.assertEqual(
            doc["退避"],
            [
                {"用户": "alice", "次数": 1, "下次": 100},
                {"用户": "bob", "次数": 1, "下次": 100},
            ],
        )
        self.assertEqual(doc["失败"], {"故障": 2, "退避": 1})
        self.assertTrue(all(list(row) == ["用户", "次数", "下次"]
                            for row in doc["退避"]))
        head = {key: doc[key] for key in ("版本", "时刻", "截至", "退避", "失败")}
        self.assertEqual(doc["摘要"], digest(head))

    def test_sorted_by_user_codepoint(self):
        auth = Authenticator(3, 1000)
        for user in ("alice", "zeb", "éve"):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 10, 100000)
        s.fault("fi", "注入", 100000, 0)
        for key, user in (("a", "alice"), ("z", "zeb"), ("e", "éve")):
            with self.assertRaises(BackendError):
                s.do(key, "建立", "s-" + user, (user, "pw"), 0)
        doc = parse(s.backend_checkpoint(0))
        self.assertEqual(
            [row["用户"] for row in doc["退避"]], ["alice", "zeb", "éve"]
        )

    def test_unicode_not_escaped(self):
        auth = Authenticator(3, 1000)
        auth.add("张三", "pw")
        s = Sessions(auth, 10, 10, 100000)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("张三", "pw"), 0)
        out = s.backend_checkpoint(0)
        self.assertIn("张三", out)
        self.assertNotIn("\\u", out)

    def test_read_only_does_not_clear_expired_backoff_or_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("e2", "建立", "s2", ("bob", "pw"), 0)
        # 远越过故障截至与退避时刻：检查点仍只读保留全部退避。
        doc = parse(s.backend_checkpoint(100000))
        self.assertEqual(doc["截至"], 1000)
        self.assertEqual(
            doc["退避"], [{"用户": "bob", "次数": 1, "下次": 100}]
        )
        self.assertEqual(s._fault_until, 1000)
        self.assertEqual(s._backoff["bob"], (1, 100))
        # 不老化：s1 期限 50 已过但仍在线。
        self.assertEqual(s._sessions["s1"]["state"], "在线")

    def test_byte_stable_same_now(self):
        _auth, s = make()
        self.assertEqual(s.backend_checkpoint(7), s.backend_checkpoint(7))
        self.assertNotEqual(s.backend_checkpoint(7), s.backend_checkpoint(8))


class BackendRestoreTest(unittest.TestCase):
    def test_roundtrip_onto_fresh_instance(self):
        _auth, src = make()
        src.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            src.do("d1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(BackendError):
            src.do("d2", "建立", "s2", ("bob", "pw"), 0)
        with self.assertRaises(BackendError):
            src.do("d3", "建立", "s3", ("alice", "pw"), 50)
        cp = src.backend_checkpoint(60)

        _auth2, dst = make()
        out = dst.backend_restore("r1", cp)
        self.assertEqual(out, cp)  # 返回规范包且与输入逐字节一致
        self.assertEqual(dst.backend_checkpoint(60), cp)
        self.assertEqual(dst._fault_until, 1000)
        self.assertEqual(dst._backoff, {"alice": (1, 100), "bob": (1, 100)})
        self.assertEqual(dst._fault_fail, [2, 1])
        stats = parse(dst.fault_stats(0))
        self.assertEqual(stats["故障"], True)
        self.assertEqual(stats["退避用户"], 2)
        self.assertEqual(stats["失败"],
                         [{"类型": "故障", "次数": 2},
                          {"类型": "退避", "次数": 1}])

    def test_restored_backoff_keeps_working(self):
        _auth, s = make()
        # 截至 10000，alice n=1/retry_at=100。
        cp = seal(build(60, 10000, [("alice", 1, 100)], (3, 2)))
        s.backend_restore("r1", cp)
        # now=100：故障中且退避到期 -> n 加一为 2，retry_at=300。
        with self.assertRaises(BackendError) as ctx:
            s.do("d1", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(ctx.exception.args[0], 300)
        self.assertEqual(s._backoff["alice"], (2, 300))
        # 失败计数沿恢复值继续累计。
        self.assertEqual(s._fault_fail, [4, 2])

    def test_empty_checkpoint_clears_fault_state(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        self.assertTrue(s._backoff)
        cp = seal(build(5, 0, [], (0, 0)))
        s.backend_restore("r1", cp)
        self.assertEqual(s._fault_until, 0)
        self.assertEqual(s._backoff, {})
        self.assertEqual(s._fault_fail, [0, 0])
        out = parse(s.do("d2", "建立", "s2", ("alice", "pw"), 10))
        self.assertEqual(out["状态"], "在线")

    def test_pretty_input_returns_canonical_package(self):
        _auth, s = make()
        doc = build(10, 500, [("alice", 2, 300)], (1, 0))
        head = {key: doc[key] for key in ("版本", "时刻", "截至", "退避", "失败")}
        doc["摘要"] = digest(head)
        pretty = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
        out = s.backend_restore("r1", pretty)
        self.assertEqual(out, seal(json.loads(pretty)))
        self.assertEqual(s.backend_checkpoint(10), out)

    def test_restored_state_independent_from_source(self):
        _auth, src = make()
        cp = seal(build(0, 1000, [("alice", 1, 100)], (1, 0)))
        _auth2, dst = make()
        dst.backend_restore("r1", cp)
        # 源实例随后变化，目标实例不受影响。
        src.fault("fx", "恢复", None, 5)
        self.assertEqual(dst._fault_until, 1000)
        self.assertEqual(dst.backend_checkpoint(0), cp)

    def test_type_errors(self):
        _auth, s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.backend_restore(bad_key, "x")
        with self.assertRaises(ValueError):
            s.backend_restore("", "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.backend_restore("k", bad_text)

    def test_value_errors(self):
        _auth, s = make()
        good = json.loads(seal(build()))
        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            '"x"',
            # 键集/键序。
            compact({"版本": 1}),
            compact({k: good[k] for k in
                     ("摘要", "版本", "时刻", "截至", "退避", "失败")}),
            compact({**good, "x": 1}),
            # 版本。
            seal({**good, "版本": 0}),
            seal({**good, "版本": 2}),
            seal({**good, "版本": "1"}),
            seal({**good, "版本": True}),
            # 时刻/截至。
            seal({**good, "时刻": -1}),
            seal({**good, "时刻": True}),
            seal({**good, "时刻": "0"}),
            seal({**good, "截至": -1}),
            seal({**good, "截至": 1.0}),
            # 退避整体形态。
            seal({**good, "退避": {}}),
            seal({**good, "退避": 1}),
            # 退避项键集/键序。
            seal({**good, "退避": [{"次数": 1, "用户": "alice", "下次": 1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": 1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": 1,
                                    "下次": 1, "x": 0}]}),
            seal({**good, "退避": [[]]}),
            # 次数 >0、非 bool int；下次 >=0。
            seal({**good, "退避": [{"用户": "alice", "次数": 0, "下次": 1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": -1, "下次": 1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": True,
                                    "下次": 1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": "1",
                                    "下次": 1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": 1,
                                    "下次": -1}]}),
            seal({**good, "退避": [{"用户": "alice", "次数": 1,
                                    "下次": True}]}),
            # 用户凭据约束。
            seal({**good, "退避": [{"用户": "", "次数": 1, "下次": 1}]}),
            seal({**good, "退避": [{"用户": 1, "次数": 1, "下次": 1}]}),
            seal({**good, "退避": [{"用户": "alice\u0000", "次数": 1,
                                    "下次": 1}]}),
            # 排序/重复。
            seal({**good, "退避": [
                {"用户": "bob", "次数": 1, "下次": 1},
                {"用户": "alice", "次数": 1, "下次": 1},
            ]}),
            seal({**good, "退避": [
                {"用户": "alice", "次数": 1, "下次": 1},
                {"用户": "alice", "次数": 2, "下次": 2},
            ]}),
            # 失败键集/键序/类型/范围。
            seal({**good, "失败": {"退避": 0, "故障": 0}}),
            seal({**good, "失败": {"故障": 0}}),
            seal({**good, "失败": {"故障": 0, "退避": 0, "x": 0}}),
            seal({**good, "失败": []}),
            seal({**good, "失败": {"故障": -1, "退避": 0}}),
            seal({**good, "失败": {"故障": 0, "退避": True}}),
            # 摘要形态与内容。
            compact({**good, "摘要": 0}),
            compact({**good, "摘要": "0" * 63}),
            compact({**good, "摘要": "g" * 64}),
            compact({**good, "摘要": "0" * 64}),  # 形态合法但内容不符
            # 重复顶层键。
            '{"版本":1,"版本":1,"时刻":0,"截至":0,"退避":[],'
            '"失败":{"故障":0,"退避":0},"摘要":"' + "0" * 64 + '"}',
        ]
        for text in bad_texts:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.backend_restore("k", text)

    def test_snapshot_allowances(self):
        """截至可小于时刻；次数>0 时下次可为 0（仅 >=0 约束）。"""
        _auth, s = make()
        cp = seal(build(100, 0, [("alice", 1, 0), ("bob", 9, 0)], (0, 0)))
        self.assertEqual(s.backend_restore("r1", cp), cp)
        self.assertEqual(s._backoff, {"alice": (1, 0), "bob": (9, 0)})

    def test_unknown_user_resource_error(self):
        _auth, s = make()
        cp = seal(build(0, 0, [("nobody", 1, 1)], (0, 0)))
        with self.assertRaises(ResourceError):
            s.backend_restore("r1", cp)

    def test_failure_does_not_change_instance(self):
        _auth, s = make()
        s.fault("fi", "注入", 1000, 0)
        with self.assertRaises(BackendError):
            s.do("d1", "建立", "s1", ("alice", "pw"), 0)
        before = s.backend_checkpoint(0)
        for bad in ("not json", "[]", seal(build(0, 0, [("x", 1, 1)]))):
            with self.assertRaises((ValueError, ResourceError)):
                s.backend_restore("r9", bad)
        # ResourceError 与 ValueError 均须不改实例。
        self.assertEqual(s.backend_checkpoint(0), before)
        self.assertEqual(s._fault_until, 1000)
        self.assertEqual(s._backoff, {"alice": (1, 100)})
        self.assertEqual(s._fault_fail, [1, 0])

    def test_failure_does_not_occupy_key(self):
        _auth, s = make()
        good = seal(build())
        with self.assertRaises(ValueError):
            s.backend_restore("r1", "bad")
        with self.assertRaises(TypeError):
            s.backend_restore("r1", None)
        with self.assertRaises(ResourceError):
            s.backend_restore("r1", seal(build(0, 0, [("x", 1, 1)])))
        # 同 key 此前失败不占位，合法文本首次成功。
        self.assertEqual(s.backend_restore("r1", good),
                         s.backend_checkpoint(0))

    def test_replay_same_bytes_no_revalidation(self):
        _auth, s = make()
        text = seal(build(0, 500, [("alice", 1, 100)], (1, 0)))
        first = s.backend_restore("r1", text)
        # 推进故障态后，同参重放不重验、不替换、返回原字节。
        s.fault("fc", "恢复", None, 10)
        self.assertEqual(s.backend_restore("r1", text), first)
        self.assertEqual(s._fault_until, 0)  # 重放未恢复检查点状态
        self.assertEqual(s._backoff, {})

    def test_replay_different_params_value_error(self):
        _auth, s = make()
        t1 = seal(build(0, 0, [], (0, 0)))
        t2 = seal(build(0, 1, [], (0, 0)))
        s.backend_restore("r1", t1)
        with self.assertRaises(ValueError):
            s.backend_restore("r1", t2)
        with self.assertRaises(ValueError):
            s.backend_restore("r1", t1.rstrip("\n"))
        # 已缓存 key 上 text 非 str：同型校验失败仍为 ValueError（非 TypeError）。
        with self.assertRaises(ValueError):
            s.backend_restore("r1", None)
        # 不同 key 同文本各自独立。
        self.assertEqual(s.backend_restore("r2", t1), t1)

    def test_audit_first_success_and_replay(self):
        _auth, s = make()
        cp = seal(build(77, 500, [("alice", 1, 100)], (2, 1)))
        s.backend_restore("r1", cp)
        s.backend_restore("r1", cp)
        s.backend_restore("r1", cp)
        events = parse(s.audit(limit=10))["事件"]
        self.assertEqual(
            [(e["操作"], e["会话"], e["结果"], e["时刻"], e["原序号"])
             for e in events],
            [
                ("后端恢复", "", "成功", 77, 0),
                ("后端恢复", "", "重放", 77, 1),
                ("后端恢复", "", "重放", 77, 1),
            ],
        )
        self.assertTrue(s.verify_audit())
        # 接管审计不混入。
        self.assertEqual(parse(s.takeover_audit())["事件"], [])

    def test_audit_origin_is_per_domain(self):
        _auth, s = make()
        # do 域先用同名字符串 key，其后端恢复域原序号须指认本域首次事件。
        out = s.do("shared", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(parse(out)["状态"], "在线")
        cp = seal(build(0, 0, [], (0, 0)))
        s.backend_restore("shared", cp)
        s.backend_restore("shared", cp)
        events = parse(s.audit(limit=10))["事件"]
        ops = [(e["操作"], e["结果"], e["原序号"]) for e in events]
        self.assertEqual(ops[0], ("建立", "成功", 0))
        self.assertEqual(ops[1], ("后端恢复", "成功", 0))
        self.assertEqual(ops[2], ("后端恢复", "重放", 2))
        self.assertTrue(s.verify_audit())

    def test_failures_not_audited(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.backend_restore("r1", "bad")
        with self.assertRaises(ResourceError):
            s.backend_restore("r2", seal(build(0, 0, [("x", 1, 1)])))
        with self.assertRaises(TypeError):
            s.backend_restore(1, seal(build()))
        self.assertEqual(parse(s.audit())["事件"], [])

    def test_cache_domain_independent(self):
        _auth, s = make()
        s.fault("shared", "注入", 1000, 0)
        # 与 fault/do/quota_restore/runtime_restore 各域独立。
        cp = seal(build(0, 0, [], (0, 0)))
        self.assertEqual(s.backend_restore("shared", cp), cp)
        # 恢复已清故障；fault 域的 "shared" 首果仍可重放。
        out = s.fault("shared", "注入", 1000, 0)
        self.assertEqual(parse(out)["状态"], "故障")

    def test_restore_does_not_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        cp = seal(build(100000, 0, [], (0, 0)))
        s.backend_restore("r1", cp)
        self.assertEqual(s._sessions["s1"]["state"], "在线")


if __name__ == "__main__":
    unittest.main()
