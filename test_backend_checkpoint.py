import hashlib
import json
import unittest

from access import (
    Authenticator,
    BackendError,
    ResourceError,
    Sessions,
)


def make(users=("alice", "bob", "carol"), total=10, per=10,
         pool=("10.0.0.0/24", (), ()), idle_ms=100000, lease_ms=100000):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    return auth, Sessions(auth, total, per, idle_ms, pool=pool, lease_ms=lease_ms)


def parse(out):
    return json.loads(out)


def head_digest(doc):
    """按基线重算前五键紧凑 JSON 的 sha256 摘要。"""
    head = {key: doc[key] for key in ("版本", "时刻", "截至", "退避", "失败")}
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def healthy_text(now_ms=0):
    return (
        f'{{"版本":1,"时刻":{now_ms},"截至":0,"退避":[],"失败":[0,0],'
        f'"摘要":""}}'
    )


def with_digest(text):
    """填入正确摘要，返回可直接恢复的检查点文本。"""
    doc = parse(text)
    doc["摘要"] = head_digest(doc)
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"


class BackendCheckpointTest(unittest.TestCase):
    def test_now_ms_types_and_ranges(self):
        _auth, s = make()
        for bad in (True, 1.5, None, "1", b"1", []):
            with self.assertRaises(TypeError):
                s.backend_checkpoint(bad)
        with self.assertRaises(ValueError):
            s.backend_checkpoint(-1)

    def test_empty_baseline(self):
        _auth, s = make()
        out = s.backend_checkpoint(0)
        doc = parse(out)
        self.assertEqual(
            list(doc), ["版本", "时刻", "截至", "退避", "失败", "摘要"]
        )
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["时刻"], 0)
        self.assertEqual(doc["截至"], 0)
        self.assertEqual(doc["退避"], [])
        self.assertEqual(doc["失败"], [0, 0])
        self.assertEqual(doc["摘要"], head_digest(doc))
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)

    def test_byte_stable_for_same_state(self):
        _auth, s = make()
        self.assertEqual(s.backend_checkpoint(7), s.backend_checkpoint(7))

    def test_records_fault_backoff_and_failures_sorted(self):
        _auth, s = make()
        s.fault("fi", "注入", 100000, 0)
        # alice：t=0 故障 n=1/retry=100；t=100 n=2/retry=300；t=300 n=3/700。
        for t in (0, 100, 300):
            with self.assertRaises(BackendError):
                s.do(f"a{t}", "建立", "sa", ("alice", "pw"), t)
        # bob：t=50 n=1/150（故障），t=60 退避未到（n 不变）。
        with self.assertRaises(BackendError):
            s.do("b0", "建立", "sb", ("bob", "pw"), 50)
        with self.assertRaises(BackendError):
            s.do("b1", "建立", "sb2", ("bob", "pw"), 60)
        out = s.backend_checkpoint(400)
        doc = parse(out)
        self.assertEqual(doc["截至"], 100000)
        self.assertEqual(
            doc["退避"],
            [["alice", 3, 700], ["bob", 1, 150]],
        )
        self.assertEqual(doc["失败"], [4, 1])
        self.assertEqual(doc["摘要"], head_digest(doc))

    def test_sorted_by_user_codepoint(self):
        auth = Authenticator(5, 1000)
        for user in ("alice", "zeb", "éve"):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 5, 100000)
        s.fault("fi", "注入", 100000, 0)
        for i, user in enumerate(("alice", "zeb", "éve")):
            with self.assertRaises(BackendError):
                s.do(f"k{i}", "建立", f"s{i}", (user, "pw"), 0)
        doc = parse(s.backend_checkpoint(0))
        self.assertEqual(
            [row[0] for row in doc["退避"]], ["alice", "zeb", "éve"]
        )

    def test_read_only_does_not_clear_expired_entries_or_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e0", "建立", "s1", ("alice", "pw"), 0)
        # 故障截至 50：alice 在 t=0 得退避 (1,100)。
        s.fault("fi", "注入", 50, 0)
        with self.assertRaises(BackendError):
            s.do("e1", "建立", "s2", ("alice", "pw"), 0)
        # 越过截至与下次、也越过会话空闲期限后取检查点：只读，照录到期项。
        doc = parse(s.backend_checkpoint(1000))
        self.assertEqual(doc["截至"], 50)
        self.assertEqual(doc["退避"], [["alice", 1, 100]])
        self.assertEqual(s._fault_until, 50)
        self.assertEqual(s._backoff["alice"], (1, 100))
        # 不老化：s1 仍在线。
        self.assertEqual(s._sessions["s1"]["state"], "在线")
        # 检查点本身不审计：链长度前后不变。
        chain_len = len(s._chain_events)
        s.backend_checkpoint(2000)
        self.assertEqual(len(s._chain_events), chain_len)

    def test_many_users_ordering(self):
        auth = Authenticator(5, 1000)
        users = [f"u{i:03d}" for i in range(50)]
        for user in users:
            auth.add(user, "pw")
        s = Sessions(auth, 1000, 100, 100000)
        s.fault("fi", "注入", 100000, 0)
        for i, user in enumerate(users):
            with self.assertRaises(BackendError):
                s.do(f"k{i}", "建立", f"s{i}", (user, "pw"), 0)
        doc = parse(s.backend_checkpoint(0))
        self.assertEqual([row[0] for row in doc["退避"]], sorted(users))
        self.assertTrue(all(row[1] == 1 and row[2] == 100 for row in doc["退避"]))


class BackendRestoreTest(unittest.TestCase):
    def test_type_errors(self):
        _auth, s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.backend_restore(bad_key, "x")
        with self.assertRaises(ValueError):
            s.backend_restore("", "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.backend_restore("r1", bad_text)

    def test_value_errors(self):
        _auth, s = make()
        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            "null",
            '"x"',
            '{"版本":1}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0]}',
            # 错序。
            '{"时刻":0,"版本":1,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"失败":[0,0],"退避":[],"摘要":"%s"}',
            # 多余/缺失键。
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0],'
            '"摘要":"%s","x":1}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"摘要":"%s"}',
            # 版本。
            '{"版本":"1","时刻":0,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":true,"时刻":0,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":0,"时刻":0,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":2,"时刻":0,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1.0,"时刻":0,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            # 时刻/截至。
            '{"版本":1,"时刻":-1,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":false,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":1.5,"截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":"0","截至":0,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":-1,"退避":[],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":true,"退避":[],"失败":[0,0],"摘要":"%s"}',
            # 退避结构。
            '{"版本":1,"时刻":0,"截至":0,"退避":{},"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[{}],"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",1]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",1,100,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            # 用户。
            '{"版本":1,"时刻":0,"截至":0,"退避":[[1,1,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["",1,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice\\u0000",1,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["\\ud800",1,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            # 次数：非 bool int 且 > 0；下次非负。
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",0,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",-1,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",true,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",1.5,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice","1",0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",1,-1]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[["alice",1,true]],'
            '"失败":[0,0],"摘要":"%s"}',
            # 排序/重复。
            '{"版本":1,"时刻":0,"截至":0,'
            '"退避":[["bob",1,0],["alice",1,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,'
            '"退避":[["alice",1,0],["alice",2,0]],'
            '"失败":[0,0],"摘要":"%s"}',
            # 失败结构与范围。
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":{},"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0,0],'
            '"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[-1,0],'
            '"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,true],'
            '"摘要":"%s"}',
            # 摘要形态。
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0],"摘要":""}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0],'
            '"摘要":"' + "0" * 63 + '"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0],'
            '"摘要":"' + ("A" * 64) + '"}',
            # 重复键。
            '{"版本":1,"版本":1,"时刻":0,"截至":0,"退避":[],'
            '"失败":[0,0],"摘要":"%s"}',
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[0,0],'
            '"摘要":"%s","摘要":"%s"}',
        ]
        # 含 "%s" 摘要占位的文本填入 64 个 0（结构错摘要不参与判定）。
        zero = "0" * 64
        for raw in bad_texts:
            text = raw % tuple([zero] * raw.count("%s")) if "%s" in raw else raw
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.backend_restore("k", text)

    def test_summary_mismatch_is_value_error(self):
        _auth, s = make()
        text = with_digest(healthy_text())
        doc = parse(text)
        doc["摘要"] = "0" * 64
        tampered = json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self.assertRaises(ValueError):
            s.backend_restore("r1", tampered)
        # 改前五键任一值而摘要照旧同样失配。
        doc2 = parse(with_digest(healthy_text()))
        doc2["截至"] = 1
        with self.assertRaises(ValueError):
            s.backend_restore(
                "r2",
                json.dumps(doc2, ensure_ascii=False, separators=(",", ":")) + "\n",
            )

    def test_unknown_user_is_resource_error(self):
        _auth, s = make()
        text = with_digest(
            '{"版本":1,"时刻":0,"截至":0,"退避":[["nobody",1,100]],'
            '"失败":[0,0],"摘要":""}'
        )
        with self.assertRaises(ResourceError):
            s.backend_restore("r1", text)

    def test_roundtrip_is_byte_identical(self):
        _auth, s = make()
        s.fault("fi", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("a0", "建立", "sa", ("alice", "pw"), 0)
        with self.assertRaises(BackendError):
            s.do("a1", "建立", "sa2", ("alice", "pw"), 100)
        cp = s.backend_checkpoint(77)
        _auth2, s2 = make()
        out = s2.backend_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(s2.backend_checkpoint(77), cp)

    def test_pretty_text_is_canonicalized(self):
        _auth, s = make()
        doc = {
            "版本": 1,
            "时刻": 5,
            "截至": 0,
            "退避": [],
            "失败": [0, 0],
        }
        blob = json.dumps(doc, ensure_ascii=False, indent=2)
        doc["摘要"] = hashlib.sha256(
            json.dumps(
                {k: doc[k] for k in ("版本", "时刻", "截至", "退避", "失败")},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        pretty = json.dumps(doc, ensure_ascii=False, indent=2)
        out = s.backend_restore("r1", pretty)
        self.assertEqual(
            out,
            json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n",
        )

    def test_restore_atomically_replaces_until_backoff_and_failures(self):
        _auth, s = make()
        # 先制造一整套故障态。
        s.fault("fi", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("a0", "建立", "sa", ("alice", "pw"), 0)
        with self.assertRaises(BackendError):
            s.do("b0", "建立", "sb", ("bob", "pw"), 50)
        self.assertEqual(s._fault_fail, [2, 0])
        # 用一个健康但带自定义失败计数的包原子替换。
        text = with_digest(
            '{"版本":1,"时刻":0,"截至":0,"退避":[],"失败":[7,8],"摘要":""}'
        )
        s.backend_restore("r1", text)
        self.assertEqual(s._fault_until, 0)
        self.assertEqual(s._backoff, {})
        self.assertEqual(s._fault_fail, [7, 8])
        stats = parse(s.fault_stats(0))
        self.assertFalse(stats["故障"])
        self.assertEqual(stats["退避用户"], 0)
        # do 建立恢复正常（故障已被替换清除）。
        out = s.do("e0", "建立", "s1", ("carol", "pw"), 0)
        self.assertEqual(parse(out)["状态"], "在线")

    def test_restore_sets_backoff_governing_backend_check(self):
        _auth, s = make()
        s.fault("fx", "注入", 10, 0)
        text = with_digest(
            '{"版本":1,"时刻":0,"截至":1000,'
            '"退避":[["alice",2,300]],"失败":[5,6],"摘要":""}'
        )
        s.backend_restore("r1", text)
        self.assertEqual(s._fault_until, 1000)
        self.assertEqual(s._backoff, {"alice": (2, 300)})
        # t=100 退避未到：n 不变，抛 300，且计一次“退避”失败。
        with self.assertRaises(BackendError) as ctx:
            s.do("d0", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(ctx.exception.args[0], 300)
        self.assertEqual(s._backoff["alice"], (2, 300))
        self.assertEqual(s._fault_fail, [5, 7])

    def test_restore_keeps_expired_entries_verbatim(self):
        _auth, s = make()
        # 包内截至与下次均已过期：不清理，照设；检查点只读照录。
        text = with_digest(
            '{"版本":1,"时刻":0,"截至":50,'
            '"退避":[["alice",1,100]],"失败":[0,0],"摘要":""}'
        )
        s.backend_restore("r1", text)
        self.assertEqual(s._fault_until, 50)
        self.assertEqual(s._backoff, {"alice": (1, 100)})
        doc = parse(s.backend_checkpoint(1000))
        self.assertEqual(doc["截至"], 50)
        self.assertEqual(doc["退避"], [["alice", 1, 100]])

    def test_restore_does_not_touch_other_state(self):
        _auth, s = make()
        s.do("e0", "建立", "s1", ("alice", "pw"), 0)
        s.backend_restore("r1", with_digest(healthy_text()))
        self.assertEqual(s._sessions["s1"]["state"], "在线")

    def test_failure_does_not_change_instance(self):
        _auth, s = make()
        s.fault("fi", "注入", 100000, 0)
        with self.assertRaises(BackendError):
            s.do("a0", "建立", "sa", ("alice", "pw"), 0)
        until, backoff, fail = s._fault_until, dict(s._backoff), list(s._fault_fail)
        with self.assertRaises(ValueError):
            s.backend_restore("r1", "not json")
        with self.assertRaises(ValueError):
            s.backend_restore("r2", with_digest(healthy_text()) + "x")
        with self.assertRaises(ResourceError):
            s.backend_restore(
                "r3",
                with_digest(
                    '{"版本":1,"时刻":0,"截至":0,"退避":[["x",1,0]],'
                    '"失败":[0,0],"摘要":""}'
                ),
            )
        self.assertEqual(s._fault_until, until)
        self.assertEqual(s._backoff, backoff)
        self.assertEqual(s._fault_fail, fail)

    def test_failure_does_not_occupy_key(self):
        _auth, s = make()
        good = with_digest(healthy_text())
        with self.assertRaises(ValueError):
            s.backend_restore("r1", "bad")
        with self.assertRaises(TypeError):
            s.backend_restore("r1", None)
        with self.assertRaises(ResourceError):
            s.backend_restore(
                "r1",
                with_digest(
                    '{"版本":1,"时刻":0,"截至":0,"退避":[["x",1,0]],'
                    '"失败":[0,0],"摘要":""}'
                ),
            )
        # 同 key 此前失败不占位，合法文本首次成功。
        self.assertEqual(s.backend_restore("r1", good), s.backend_checkpoint(0))

    def test_replay_same_bytes_without_revalidation_or_replace(self):
        _auth, s = make()
        text = with_digest(healthy_text())
        first = s.backend_restore("r1", text)
        # 此后故障态已变化，同参重放不重验、不替换，仍返回首次缓存原字节。
        s.fault("fi", "注入", 100000, 0)
        self.assertEqual(s.backend_restore("r1", text), first)
        self.assertEqual(s._fault_until, 100000)
        # 异参 ValueError。
        other = with_digest(healthy_text(1))
        with self.assertRaises(ValueError):
            s.backend_restore("r1", other)

    def test_replay_independent_domain(self):
        _auth, s = make()
        out = s.fault("shared", "注入", 100, 0)
        # 与 fault 域独立：同名 key 在本域首次使用。
        good = with_digest(healthy_text())
        self.assertEqual(s.backend_restore("shared", good), s.backend_checkpoint(0))
        # fault 域的重放不受影响。
        self.assertEqual(s.fault("shared", "注入", 100, 0), out)
        # 不同 key 同文本各自独立成功。
        self.assertEqual(s.backend_restore("r2", good), s.backend_checkpoint(0))

    def test_audit_first_success_and_replay(self):
        _auth, s = make()
        # 先放一条既有链接管事件，使首条恢复事件序号非 1。
        s.do("e0", "建立", "s1", ("alice", "pw"), 0)
        s.do("t0", "接管", "s2", ("s1", "pw"), 0)
        text = with_digest(healthy_text())
        s.backend_restore("r1", text)
        events = parse(s.audit())["事件"]
        first = events[-1]
        self.assertEqual(first["操作"], "后端恢复")
        self.assertEqual(first["会话"], "")
        self.assertEqual(first["结果"], "成功")
        self.assertEqual(first["原序号"], 0)
        self.assertEqual(first["时刻"], 0)
        seq = first["序号"]
        # 同参重放：结果“重放”，原序号指认首次。
        s.backend_restore("r1", text)
        replay = parse(s.audit())["事件"][-1]
        self.assertEqual(replay["结果"], "重放")
        self.assertEqual(replay["原序号"], seq)
        self.assertEqual(replay["序号"], seq + 1)
        self.assertTrue(s.verify_audit())
        # 旧接管审计不被写入。
        self.assertEqual(parse(s.takeover_audit())["事件"][-1]["新会话"], "s2")

    def test_failures_not_audited(self):
        _auth, s = make()
        with self.assertRaises(ValueError):
            s.backend_restore("r1", "bad")
        with self.assertRaises(ResourceError):
            s.backend_restore(
                "r2",
                with_digest(
                    '{"版本":1,"时刻":0,"截至":0,"退避":[["x",1,0]],'
                    '"失败":[0,0],"摘要":""}'
                ),
            )
        self.assertEqual(parse(s.audit())["事件"], [])

    def test_replay_after_state_change_keeps_cached_audit(self):
        _auth, s = make()
        text = with_digest(healthy_text())
        s.backend_restore("r1", text)
        # 重放审计始终写时刻 0（恢复无时钟参数）。
        s.backend_restore("r1", text)
        for ev in parse(s.audit())["事件"]:
            self.assertEqual(ev["时刻"], 0)
            self.assertEqual(ev["会话"], "")


if __name__ == "__main__":
    unittest.main()
