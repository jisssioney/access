import json
import unittest

from access import AuthError, Authenticator, Sessions


def make(pool=("10.0.0.0/24", ("10.0.0.9",), (("alice", "10.0.0.2"),))):
    auth = Authenticator(3, 1000)
    auth.add("alice", "pw")
    auth.add("bob", "pw")
    return Sessions(auth, 4, 2, 5000, pool=pool, lease_ms=1000)


def ops(s):
    return [(e[0], e[3], e[4], e[5], e[6]) for e in s._chain_events]


class CredentialChangeValidationTest(unittest.TestCase):
    def test_key_validated_first_and_not_cached(self):
        s = make()
        for bad in (1, True, None):
            with self.assertRaises(TypeError):
                s.credential_change(bad, "alice", "a", "b", 0)
        with self.assertRaises(ValueError):
            s.credential_change("", "alice", "a", "b", 0)
        self.assertEqual(s._credential_change_cache, {})
        self.assertEqual(ops(s), [])

    def test_string_param_types(self):
        s = make()
        for i, bad in enumerate((1, True, None, ("a",))):
            with self.assertRaises(TypeError):
                s.credential_change(f"u{i}", bad, "a", "b", 0)
            with self.assertRaises(TypeError):
                s.credential_change(f"o{i}", "alice", bad, "b", 0)
            with self.assertRaises(TypeError):
                s.credential_change(f"n{i}", "alice", "a", bad, 0)

    def test_now_ms_type(self):
        s = make()
        for i, bad in enumerate((True, 1.5, "0", None)):
            with self.assertRaises(TypeError):
                s.credential_change(f"t{i}", "alice", "a", "b", bad)

    def test_type_errors_precede_value_errors(self):
        s = make()
        # user 类型错先于旧新相同等取值错
        with self.assertRaises(TypeError):
            s.credential_change("k", 1, "x", "x", True)
        # now_ms 类型错先于负值错
        with self.assertRaises(TypeError):
            s.credential_change("k2", "alice", "x", "y", True)

    def test_credential_value_errors(self):
        s = make()
        # 空串、超 256 UTF-8 字节、U+0000 均为 ValueError
        long_pw = "a" * 257
        for i, bad in enumerate(("", long_pw, "a\0b")):
            with self.assertRaises(ValueError):
                s.credential_change(f"u{i}", bad, "a", "b", 0)
        for i, bad in enumerate(("", long_pw, "a\0b")):
            with self.assertRaises(ValueError):
                s.credential_change(f"o{i}", "alice", bad, "b", 0)
            with self.assertRaises(ValueError):
                s.credential_change(f"n{i}", "alice", "a", bad, 0)

    def test_same_password_value_error(self):
        s = make()
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "same", "same", 0)

    def test_now_ms_negative(self):
        s = make()
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "a", "b", -1)

    def test_param_errors_cached_not_audited(self):
        s = make()
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "same", "same", 0)
        # 同参重放：重抛首果，不审计
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "same", "same", 0)
        self.assertEqual(ops(s), [])
        # 异参 ValueError，仍不审计
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "pw", "new", 0)
        self.assertEqual(ops(s), [])
        # 参数错 key 永不入业务：再来同参仍重抛参数错
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "same", "same", 0)
        self.assertEqual(ops(s), [])


class CredentialChangeSuccessTest(unittest.TestCase):
    def test_success_json_shape_and_bytes(self):
        auth = Authenticator(3, 1000)
        auth.add("张三", "pw")
        s = Sessions(auth, 4, 2, 5000)
        out = s.credential_change("k", "张三", "pw", "新密码", 42)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn(" ", out.strip())
        # ensure_ascii=False：非 ASCII 原样
        self.assertIn("张三", out)
        self.assertIn("已轮换", out)
        self.assertEqual(
            out, '{"用户":"张三","时刻":42,"结果":"已轮换"}\n'
        )
        doc = json.loads(out)
        self.assertEqual(list(doc), ["用户", "时刻", "结果"])
        self.assertEqual(type(doc["用户"]), str)
        self.assertEqual(type(doc["时刻"]), int)
        self.assertEqual(type(doc["结果"]), str)
        self.assertEqual(doc, {"用户": "张三", "时刻": 42, "结果": "已轮换"})

    def test_only_new_password_authenticates_after(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 2, 5000)
        s.credential_change("k", "alice", "pw", "pw2", 0)
        self.assertEqual(auth.authenticate("alice", "pw2", 0)[1], "ok")
        self.assertEqual(auth.authenticate("alice", "pw", 0)[1], "denied")

    def test_success_clears_failed_and_lock(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        # 留一次失败计数，成功轮换应清零
        auth.authenticate("alice", "bad", 0)
        self.assertEqual(auth._users["alice"][1], 1)
        s = Sessions(auth, 4, 2, 5000)
        s.credential_change("k", "alice", "pw", "pw2", 0)
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])

    def test_sessions_preserved_and_new_password_usable(self):
        # 无静态址：s1、s2 均取动态址，避免静态址专属冲突。
        s = make(pool=("10.0.0.0/24", (), ()))
        r = json.loads(s.do("k0", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["地址"], "10.0.0.1")
        s.credential_change("rot", "alice", "pw", "pw2", 100)
        # 既有在线会话仍可续租
        self.assertEqual(
            json.loads(s.do("renew", "续租", "s1", None, 100))["状态"], "在线"
        )
        # 旧密码建立失败，新密码成功
        with self.assertRaises(AuthError):
            s.do("mig-old", "建立", "s2", ("alice", "pw"), 200)
        r2 = json.loads(s.do("mig-new", "建立", "s2", ("alice", "pw2"), 200))
        self.assertEqual(r2["状态"], "在线")

    def test_queued_items_preserved(self):
        # total=1：s1 在线，s2 排队；轮换后队项保留，推进凭用户直接晋升。
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 1, 2, 5000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=1000)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        r = json.loads(s.capacity("q", "申请", "s2", ("alice", "pw", 100000), 0))
        self.assertEqual(r["结果"], "排队")
        s.credential_change("rot", "alice", "pw", "pw2", 10)
        stats = json.loads(s.capacity_stats(10))
        self.assertEqual(stats["排队"], 1)
        # 下线 s1 后推进，队项（不携密码）正常晋升
        s.do("off", "下线", "s1", None, 20)
        adv = json.loads(s.capacity("adv", "推进", "", None, 20))
        self.assertEqual(adv["在线"], 1)
        self.assertIn("s2", s._sessions)

    def test_success_audited_once_and_replay_does_nothing(self):
        s = make()
        out = s.credential_change("L", "alice", "pw", "pw2", 100)
        self.assertEqual(ops(s), [(1, "凭据轮换", "alice", "成功", 0)])
        # 同参重放：不认证、不换密，原样返回首果；即便此后密码又变也照返回。
        s.credential_change("L2", "alice", "pw2", "pw3", 100)
        out2 = s.credential_change("L", "alice", "pw", "pw2", 100)
        self.assertEqual(out2, out)
        self.assertEqual(
            ops(s),
            [(1, "凭据轮换", "alice", "成功", 0),
             (2, "凭据轮换", "alice", "成功", 0),
             (3, "凭据轮换", "alice", "重放成功", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_different_params_value_error_not_audited(self):
        s = make()
        s.credential_change("L", "alice", "pw", "pw2", 0)
        with self.assertRaises(ValueError):
            s.credential_change("L", "alice", "pw", "pwX", 0)
        with self.assertRaises(ValueError):
            s.credential_change("L", "alice", "pw", "pw2", 1)
        with self.assertRaises(ValueError):
            s.credential_change("L", "bob", "pw", "pw2", 0)
        self.assertEqual(len(s._chain_events), 1)
        # 同型同参仍正常重放
        self.assertTrue(
            s.credential_change("L", "alice", "pw", "pw2", 0).endswith("\n")
        )
        self.assertEqual(len(s._chain_events), 2)


class CredentialChangeAuthFailureTest(unittest.TestCase):
    def test_denied_raises_and_retains_failed_count(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 2, 5000)
        with self.assertRaises(AuthError) as cm:
            s.credential_change("k", "alice", "WRONG", "new", 100)
        self.assertIn("denied", cm.exception.args[0])
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertIsNone(auth._users["alice"][2])
        # 密码未换：旧密码仍可认证
        self.assertEqual(auth.authenticate("alice", "pw", 100)[1], "ok")

    def test_denied_audited_and_replayed_without_reauth(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 2, 5000)
        with self.assertRaises(AuthError):
            s.credential_change("k", "alice", "WRONG", "new", 100)
        self.assertEqual(ops(s), [(1, "凭据轮换", "alice", "AuthError", 0)])
        with self.assertRaises(AuthError) as cm:
            s.credential_change("k", "alice", "WRONG", "new", 100)
        self.assertIn("denied", cm.exception.args[0])
        self.assertEqual(
            ops(s)[1], (2, "凭据轮换", "alice", "重放AuthError", 1)
        )
        # 重放不再认证：失败计数不增加
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertTrue(s.verify_audit())

    def test_locked_raises_and_retains_lock(self):
        auth = Authenticator(2, 1000)
        auth.add("bob", "old")
        s = Sessions(auth, 4, 2, 5000)
        for i in range(2):
            with self.assertRaises(AuthError):
                s.credential_change(f"d{i}", "bob", "WRONG", "new", 100)
        self.assertEqual(auth._users["bob"][1], 2)
        self.assertEqual(auth._users["bob"][2], 1100)
        # 锁定期内即便旧密码正确也 locked，失败计数与锁定不变
        with self.assertRaises(AuthError) as cm:
            s.credential_change("dL", "bob", "old", "new", 100)
        self.assertIn("locked", cm.exception.args[0])
        self.assertEqual(auth._users["bob"][1], 2)
        self.assertEqual(auth._users["bob"][2], 1100)
        self.assertEqual(
            ops(s)[-1], (3, "凭据轮换", "bob", "AuthError", 0)
        )
        # 锁到期（含同刻）后成功轮换并清零
        out = s.credential_change("dOK", "bob", "old", "new", 1100)
        self.assertEqual(json.loads(out)["结果"], "已轮换")
        self.assertEqual(auth._users["bob"][1], 0)
        self.assertIsNone(auth._users["bob"][2])

    def test_failure_does_not_change_other_state(self):
        s = make()
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(AuthError):
            s.credential_change("bad", "alice", "WRONG", "new", 100)
        # 会话仍在线且可续租；密码未变
        self.assertEqual(
            json.loads(s.do("r", "续租", "s1", None, 100))["状态"], "在线"
        )
        self.assertEqual(s._auth.authenticate("alice", "pw", 100)[1], "ok")


class CredentialChangeUnknownUserTest(unittest.TestCase):
    def test_unknown_user_key_error_audited_replayed(self):
        s = make()
        with self.assertRaises(KeyError) as cm:
            s.credential_change("k", "ghost", "a", "b", 5)
        self.assertEqual(cm.exception.args, ("unknown user: 'ghost'",))
        self.assertEqual(ops(s), [(1, "凭据轮换", "ghost", "KeyError", 0)])
        with self.assertRaises(KeyError) as cm2:
            s.credential_change("k", "ghost", "a", "b", 5)
        self.assertEqual(cm2.exception.args, cm.exception.args)
        self.assertEqual(
            ops(s)[1], (2, "凭据轮换", "ghost", "重放KeyError", 1)
        )
        # 未知用户认证侧无失败计数副作用
        self.assertNotIn("ghost", s._auth._users)
        self.assertTrue(s.verify_audit())


class CredentialChangeChainIntegrationTest(unittest.TestCase):
    def test_separate_cache_and_index_domains(self):
        s = make()
        s.do("dup", "建立", "s1", ("alice", "pw"), 0)
        # 同名 key 在 credential_change 域为首次调用
        out = s.credential_change("dup", "alice", "pw", "pw2", 0)
        self.assertEqual(json.loads(out)["结果"], "已轮换")
        # do 域重放不受影响（不重新认证），返回首果（建立时的在线 JSON）
        r = json.loads(s.do("dup", "建立", "s1", ("alice", "pw"), 0))
        self.assertEqual(r["状态"], "在线")
        # 凭据轮换重放原序号指认轮换事件而非 do 事件
        s.credential_change("dup", "alice", "pw", "pw2", 0)
        cred_events = [e for e in ops(s) if e[1] == "凭据轮换"]
        self.assertEqual(
            cred_events,
            [(2, "凭据轮换", "alice", "成功", 0),
             (4, "凭据轮换", "alice", "重放成功", 2)],
        )
        self.assertTrue(s.verify_audit())

    def test_audit_json_shape_and_linkage(self):
        s = make()
        s.credential_change("L", "alice", "pw", "pw2", 42)
        out = json.loads(s.audit(limit=1000))
        self.assertEqual(list(out), ["下个序号", "事件"])
        e = out["事件"][0]
        self.assertEqual(
            list(e),
            ["序号", "时刻", "键", "操作", "会话", "结果", "原序号",
             "前哈希", "哈希"],
        )
        self.assertEqual(e["操作"], "凭据轮换")
        self.assertEqual(e["会话"], "alice")
        self.assertEqual(e["前哈希"], "0" * 64)
        self.assertEqual(len(e["哈希"]), 64)
        # 与其余域共用同一条链：后续事件前哈希衔接
        s.pool_fault("p", "注入", "default", 10, 43)
        ev = json.loads(s.audit(limit=1000))["事件"]
        self.assertEqual(ev[1]["前哈希"], ev[0]["哈希"])
        self.assertTrue(s.verify_audit())

    def test_deterministic_byte_output(self):
        def run():
            auth = Authenticator(2, 1000)
            auth.add("alice", "pw")
            s = Sessions(auth, 4, 2, 5000)
            parts = [s.credential_change("L", "alice", "pw", "pw2", 100)]
            s.credential_change("L", "alice", "pw", "pw2", 100)  # 重放
            with self.assertRaises(AuthError):
                s.credential_change("d", "alice", "bad", "x", 100)
            parts.append(s.audit(limit=1000))
            return "".join(parts)
        self.assertEqual(run(), run())


if __name__ == "__main__":
    unittest.main()
