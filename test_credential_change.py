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
                s.credential_change(bad, "alice", "pw", "pw2", 0)
        with self.assertRaises(ValueError):
            s.credential_change("", "alice", "pw", "pw2", 0)
        self.assertEqual(s._credential_change_cache, {})
        self.assertEqual(ops(s), [])

    def test_user_type_and_value(self):
        s = make()
        for i, bad in enumerate((1, True, None, ("alice",))):
            with self.assertRaises(TypeError):
                s.credential_change(f"k{i}", bad, "pw", "pw2", 0)
        with self.assertRaises(ValueError):
            s.credential_change("kz", "", "pw", "pw2", 0)
        with self.assertRaises(ValueError):
            s.credential_change("kn", "a\0b", "pw", "pw2", 0)

    def test_password_type_and_value(self):
        s = make()
        for i, bad in enumerate((1, True, None)):
            with self.assertRaises(TypeError):
                s.credential_change(f"ko{i}", "alice", bad, "pw2", 0)
            with self.assertRaises(TypeError):
                s.credential_change(f"kn{i}", "alice", "pw", bad, 0)
        with self.assertRaises(ValueError):
            s.credential_change("ke", "alice", "", "pw2", 0)
        with self.assertRaises(ValueError):
            s.credential_change("kb", "alice", "pw", "x" * 300, 0)

    def test_now_ms_type_and_value(self):
        s = make()
        for i, bad in enumerate((True, 1.5, "0", None)):
            with self.assertRaises(TypeError):
                s.credential_change(f"k{i}", "alice", "pw", "pw2", bad)
        with self.assertRaises(ValueError):
            s.credential_change("kz", "alice", "pw", "pw2", -1)

    def test_same_old_new_value_error(self):
        s = make()
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "pw", "pw", 0)
        # 参数错入缓存但不审计
        self.assertIn("k", s._credential_change_cache)
        self.assertEqual(ops(s), [])

    def test_param_errors_cached_not_audited(self):
        s = make()
        with self.assertRaises(TypeError):
            s.credential_change("k", "alice", 1, "pw2", 0)
        # 同参重放：重抛首果，不审计
        with self.assertRaises(TypeError):
            s.credential_change("k", "alice", 1, "pw2", 0)
        self.assertEqual(ops(s), [])
        # 异参 ValueError，仍不审计
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "pw", "pw2", 0)
        self.assertEqual(ops(s), [])
        # 参数错 key 永不入业务：再来同参仍重抛参数错
        with self.assertRaises(TypeError):
            s.credential_change("k", "alice", 1, "pw2", 0)
        self.assertEqual(ops(s), [])


class CredentialChangeBusinessTest(unittest.TestCase):
    def test_unknown_user_key_error_audited(self):
        s = make()
        with self.assertRaises(KeyError):
            s.credential_change("k", "carol", "pw", "pw2", 0)
        self.assertEqual(ops(s), [(1, "凭据轮换", "carol", "KeyError", 0)])
        self.assertTrue(s.verify_audit())
        # 同参重放重抛 KeyError，记重放入链并指认首次事件
        with self.assertRaises(KeyError):
            s.credential_change("k", "carol", "pw", "pw2", 0)
        self.assertEqual(
            ops(s),
            [(1, "凭据轮换", "carol", "KeyError", 0),
             (2, "凭据轮换", "carol", "重放KeyError", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_wrong_old_password_auth_error_keeps_fail_count(self):
        s = make()
        with self.assertRaises(AuthError):
            s.credential_change("k", "alice", "bad", "pw2", 0)
        # 认证副作用：失败计数 +1；审计记 AuthError
        self.assertEqual(s._auth._users["alice"][1], 1)
        self.assertEqual(ops(s), [(1, "凭据轮换", "alice", "AuthError", 0)])
        # 同参重放不再认证：失败计数不变，记重放
        with self.assertRaises(AuthError):
            s.credential_change("k", "alice", "bad", "pw2", 0)
        self.assertEqual(s._auth._users["alice"][1], 1)
        self.assertEqual(
            ops(s),
            [(1, "凭据轮换", "alice", "AuthError", 0),
             (2, "凭据轮换", "alice", "重放AuthError", 1)],
        )
        self.assertTrue(s.verify_audit())
        # 密码未换：旧密码仍可认证
        self.assertEqual(s._auth.authenticate("alice", "pw", 10)[1], "ok")

    def test_locked_auth_error_keeps_lock(self):
        auth = Authenticator(1, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 4, 2, 5000)
        # 一次失败即锁定至 1000
        self.assertEqual(auth.authenticate("alice", "bad", 0)[1], "locked")
        with self.assertRaises(AuthError):
            s.credential_change("k", "alice", "pw", "pw2", 100)
        # 锁定保留，密码未换
        self.assertEqual(auth._users["alice"][2], 1000)
        self.assertEqual(ops(s), [(1, "凭据轮换", "alice", "AuthError", 0)])
        # 锁到期后可换密，且失败计数与锁定清零
        out = s.credential_change("k2", "alice", "pw", "pw2", 1000)
        self.assertEqual(json.loads(out)["结果"], "已轮换")
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertIsNone(auth._users["alice"][2])

    def test_success_output_and_audit(self):
        s = make()
        out = s.credential_change("k", "alice", "pw", "pw2", 100)
        self.assertEqual(
            out, '{"用户":"alice","时刻":100,"结果":"已轮换"}\n'
        )
        self.assertEqual(ops(s), [(1, "凭据轮换", "alice", "成功", 0)])
        self.assertTrue(s.verify_audit())
        # 此后仅新密码可认证
        self.assertEqual(s._auth.authenticate("alice", "pw", 200)[1], "denied")
        self.assertEqual(s._auth.authenticate("alice", "pw2", 200)[1], "ok")

    def test_success_clears_fail_count_and_lock(self):
        s = make()
        # 两次失败累计（未达锁定阈值）
        s._auth.authenticate("alice", "bad", 0)
        s._auth.authenticate("alice", "bad", 0)
        self.assertEqual(s._auth._users["alice"][1], 2)
        s.credential_change("k", "alice", "pw", "pw2", 10)
        self.assertEqual(s._auth._users["alice"][1], 0)
        self.assertIsNone(s._auth._users["alice"][2])

    def test_success_keeps_sessions_and_queue(self):
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        auth.add("bob", "pw")
        pool = ("10.0.0.0/24", (), ())
        s = Sessions(auth, 1, 1, 5000, pool=pool, lease_ms=1000)
        s.do("e1", "建立", "sid1", ("alice", "pw"), 0)
        # 总数已满，bob 的申请认证后入队
        s.capacity("c1", "申请", "sid2", ("bob", "pw", 100), 0)
        self.assertIn("sid2", s._capacity_queue)
        s.credential_change("k", "bob", "pw", "pw2", 10)
        # 会话与已认证队项保留
        self.assertIn("sid1", s._sessions)
        self.assertIn("sid2", s._capacity_queue)

    def test_success_replay_no_reauth_no_rechange(self):
        s = make()
        out = s.credential_change("k", "alice", "pw", "pw2", 0)
        # 换密后把 alice 锁定：重放不认证、不换密，仍返回首果
        auth = s._auth
        for _ in range(3):
            auth.authenticate("alice", "bad", 10)
        self.assertEqual(auth.authenticate("alice", "pw2", 20)[1], "locked")
        out2 = s.credential_change("k", "alice", "pw", "pw2", 0)
        self.assertEqual(out2, out)
        self.assertEqual(
            ops(s),
            [(1, "凭据轮换", "alice", "成功", 0),
             (2, "凭据轮换", "alice", "重放成功", 1)],
        )
        self.assertTrue(s.verify_audit())

    def test_different_params_value_error_not_audited(self):
        s = make()
        s.credential_change("k", "alice", "pw", "pw2", 0)
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "pw", "pw3", 0)
        with self.assertRaises(ValueError):
            s.credential_change("k", "alice", "pw", "pw2", 1)
        self.assertEqual(ops(s), [(1, "凭据轮换", "alice", "成功", 0)])
        # 首果仍可按原参重放
        out = s.credential_change("k", "alice", "pw", "pw2", 0)
        self.assertEqual(json.loads(out)["结果"], "已轮换")


if __name__ == "__main__":
    unittest.main()
