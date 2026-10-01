import json
import unittest

from access import AuthError, Authenticator, Sessions


def make(users=("alice", "bob", "carol"), max_fail=4, lock_ms=5000,
         base_ms=100, cap_ms=1000, idle_ms=100000, pool=("10.0.0.0/24", (), ())):
    auth = Authenticator(max_fail, lock_ms, base_ms, cap_ms)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(auth, 10, 10, idle_ms, pool=pool, lease_ms=100000)
    return auth, s


def parse(text):
    return json.loads(text)


class BackoffPolicyTest(unittest.TestCase):
    def test_constructor_validation(self):
        # 默认关闭退避。
        auth = Authenticator(3, 1000)
        self.assertEqual(auth.policy(), (3, 1000, 0, 0))
        auth = Authenticator(3, 1000, 0, 0)
        self.assertEqual(auth.policy(), (3, 1000, 0, 0))
        for args in (
            (1, 0, 0, 1),        # 0/正
            (1, 0, 1, 0),        # 正/0
            (1, 0, -1, 0),
            (1, 0, 0, -1),
            (1, 0, 100, 50),     # 上限小于基数
            (1, 0, True, 1),
            (1, 0, 1, True),
            (1, 0, 1.0, 1),
            (1, 0, 1, 1.0),
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(args)):
                Authenticator(*args)
        for args in ((1, 1, 1), (0, 0, 0, 0), (1, -1, 0, 0), (True, 0, 0, 0)):
            with self.assertRaises((TypeError, ValueError)):
                Authenticator(*args)

    def test_valid_policies(self):
        for base_ms, cap_ms in ((1, 1), (100, 100), (100, 1000),
                                (1, 10 ** 12)):
            auth = Authenticator(3, 1000, base_ms, cap_ms)
            self.assertEqual(
                auth.policy(), (3, 1000, base_ms, cap_ms)
            )

    def test_set_policy_validates_before_switch(self):
        auth = Authenticator(3, 1000, 100, 1000)
        with self.assertRaises(ValueError):
            auth.set_policy(3, 1000, 0, 1)
        self.assertEqual(auth.policy(), (3, 1000, 100, 1000))
        with self.assertRaises(TypeError):
            auth.set_policy(True, 1000)
        self.assertEqual(auth.policy(), (3, 1000, 100, 1000))
        auth.set_policy(5, 0)
        self.assertEqual(auth.policy(), (5, 0, 0, 0))
        auth.set_policy(5, 0, 200, 400)
        self.assertEqual(auth.policy(), (5, 0, 200, 400))


class BackoffAuthenticateTest(unittest.TestCase):
    def test_disabled_backoff_still_denied(self):
        auth = Authenticator(3, 1000)
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "denied", 0))
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "denied", 0))
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "locked", 1000))

    def test_exponential_schedule_and_cap(self):
        # base=100 cap=1000, max_fail=8：100,200,400,800,1000,1000,...
        auth = Authenticator(8, 0, 100, 1000)
        auth.add("u", "pw")
        schedule = [100, 300, 700, 1500, 2500, 3500, 4500]
        delays = [100, 200, 400, 800, 1000, 1000, 1000]
        for retry_at, delay in zip(schedule, delays):
            _user, status, value = auth.authenticate("u", "bad", retry_at - delay)
            self.assertEqual(status, "backoff")
            self.assertEqual(value, retry_at)
            self.assertEqual(auth._users["u"][3], retry_at)
        # 第 8 次失败锁定并清除下次可试。
        _user, status, until = auth.authenticate("u", "bad", 4500)
        self.assertEqual(status, "locked")
        self.assertEqual(until, 4500)  # lock_ms=0
        self.assertIsNone(auth._users["u"][3])
        self.assertEqual(auth._users["u"][1], 8)

    def test_cap_equal_base(self):
        auth = Authenticator(8, 0, 100, 100)
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "backoff", 100))
        self.assertEqual(auth.authenticate("u", "bad", 100), ("u", "backoff", 200))
        self.assertEqual(auth.authenticate("u", "bad", 200), ("u", "backoff", 300))

    def test_before_retry_time_no_check_no_failure_increment(self):
        auth = Authenticator(4, 5000, 100, 1000)
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "backoff", 100))
        # 未到时刻：错口令与正确口令均不验密、不增失败，返回原时刻。
        for password in ("bad", "pw"):
            for now_ms in (0, 50, 99):
                self.assertEqual(
                    auth.authenticate("u", password, now_ms),
                    ("u", "backoff", 100),
                )
        self.assertEqual(auth._users["u"][1], 1)
        # 等于时刻可重试。
        self.assertEqual(auth.authenticate("u", "bad", 100), ("u", "backoff", 300))
        self.assertEqual(auth._users["u"][1], 2)

    def test_correct_password_at_allowed_time_clears_all(self):
        auth = Authenticator(4, 5000, 100, 1000)
        auth.add("u", "pw")
        auth.authenticate("u", "bad", 0)
        self.assertEqual(auth.authenticate("u", "pw", 100), ("u", "ok", 0))
        self.assertEqual(auth._users["u"][1], 0)
        self.assertIsNone(auth._users["u"][2])
        self.assertIsNone(auth._users["u"][3])
        # 清零后失败计数从 1 重新起算。
        self.assertEqual(auth.authenticate("u", "bad", 100), ("u", "backoff", 200))

    def test_lock_takes_precedence_and_keeps_retry_at(self):
        auth = Authenticator(3, 1000, 100, 1000)
        auth.add("u", "pw")
        auth.authenticate("u", "bad", 0)  # retry 100
        auth.authenticate("u", "bad", 100)  # retry 300
        # 第三次失败：锁定，清除下次可试。
        self.assertEqual(auth.authenticate("u", "bad", 300), ("u", "locked", 1300))
        self.assertIsNone(auth._users["u"][3])
        # 锁定期间正确/错误口令均 locked 与锁定截止。
        for password in ("pw", "bad"):
            self.assertEqual(
                auth.authenticate("u", password, 1000), ("u", "locked", 1300)
            )
        self.assertEqual(auth._users["u"][1], 3)
        # 到期同刻：清零失败/锁定/退避后验密。
        self.assertEqual(auth.authenticate("u", "pw", 1300), ("u", "ok", 0))
        self.assertEqual(auth._users["u"][1:], [0, None, None])
        # 到期错口令按 failed=1 重新退避。
        self.assertEqual(auth.authenticate("u", "bad", 1300), ("u", "backoff", 1400))

    def test_zero_length_lock_expires_same_tick(self):
        auth = Authenticator(1, 0, 100, 1000)
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "locked", 0))
        self.assertEqual(auth.authenticate("u", "pw", 0), ("u", "ok", 0))

    def test_large_failed_from_restore_is_constant_time(self):
        # 恢复进来的超大失败数不得放大退避计算（封顶位移短路）。
        import time
        auth = Authenticator(3, 1000, 100, 1000)
        auth.add("u", "pw")
        auth._users["u"][1] = 10 ** 9  # failed 超大但未锁定
        start = time.perf_counter()
        _user, status, value = auth.authenticate("u", "bad", 0)
        elapsed = time.perf_counter() - start
        self.assertEqual((status, value), ("locked", 1000))
        self.assertLess(elapsed, 1.0)

    def test_param_errors(self):
        auth = Authenticator(3, 1000, 100, 1000)
        auth.add("u", "pw")
        with self.assertRaises(TypeError):
            auth.authenticate(1, "pw", 0)
        with self.assertRaises(TypeError):
            auth.authenticate("u", b"pw", 0)
        with self.assertRaises(TypeError):
            auth.authenticate("u", "pw", True)
        with self.assertRaises(ValueError):
            auth.authenticate("u", "pw", -1)
        with self.assertRaises(KeyError):
            auth.authenticate("nope", "pw", 0)


class BackoffEntriesTest(unittest.TestCase):
    """各认证入口复用 authenticate 的 backoff 结果：非 ok 抛 AuthError，
    失败不建会话、不占地址、不入队；同幂等键重放不推进认证状态。"""

    def test_establish_backoff_blocks_session_and_address(self):
        auth, s = make()
        with self.assertRaises(AuthError):
            s.do("b0", "建立", "s0", ("alice", "bad"), 0)
        self.assertEqual(auth._users["alice"][3], 100)
        # 退避未到：正确口令也拒绝，不建会话。
        with self.assertRaises(AuthError):
            s.do("b1", "建立", "s1", ("alice", "pw"), 50)
        self.assertNotIn("s1", s._sessions)
        # 同幂等键重放不推进认证状态。
        for _ in range(3):
            with self.assertRaises(AuthError):
                s.do("b0", "建立", "s0", ("alice", "bad"), 0)
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(auth._users["alice"][3], 100)
        # 到刻正确口令建立成功并清零。
        out = parse(s.do("ok", "建立", "s2", ("alice", "pw"), 100))
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(auth._users["alice"][1:], [0, None, None])

    def test_capacity_apply_backoff_does_not_queue(self):
        auth, s = make()
        with self.assertRaises(AuthError):
            s.capacity("c0", "申请", "q1", ("alice", "bad", 100), 0)
        with self.assertRaises(AuthError):
            s.capacity("c1", "申请", "q2", ("alice", "pw", 100), 50)
        self.assertNotIn("q1", s._capacity_queue)
        self.assertNotIn("q2", s._capacity_queue)
        self.assertEqual(auth._users["alice"][1], 1)
        out = parse(s.capacity("ok", "申请", "q3", ("alice", "pw", 100), 100))
        self.assertIn(out["结果"], ("在线", "排队"))

    def test_migrate_takeover_resume_backoff(self):
        auth, s = make(pool=("10.0.0.0/24", (), ()))
        s.add_pool("other", ("192.168.0.0/24", (), ()))
        # alice 先持一个在线会话，随后进入退避。
        s.do("k0", "建立", "s1", ("alice", "pw"), 0)
        with self.assertRaises(AuthError):
            s.do("b0", "建立", "x0", ("alice", "bad"), 0)
        self.assertEqual(auth._users["alice"][3], 100)
        # 迁移：认证会话属主 alice，退避未到拒绝、不换址。
        with self.assertRaises(AuthError):
            s.do("b1", "迁移", "s1", ("other", "pw"), 50)
        self.assertEqual(s._sessions["s1"]["pool"], "default")
        # 挂起后恢复同样认证 alice，退避未到拒绝。
        s.do("susp", "挂起", "s1", None, 60)
        with self.assertRaises(AuthError):
            s.do("r1", "恢复", "s1", ("default", "pw"), 70)
        # 接管以旧会话属主认证，退避未到拒绝。
        with self.assertRaises(AuthError):
            s.do("t1", "接管", "s2", ("s1", "pw"), 80)
        self.assertNotIn("s2", s._sessions)
        self.assertEqual(auth._users["alice"][1], 1)
        # 到刻恢复成功。
        out = parse(s.do("r2", "恢复", "s1", ("default", "pw"), 100))
        self.assertEqual(out["状态"], "在线")
        # 退避已随正确口令清零，迁移随后成功。
        out = parse(s.do("m2", "迁移", "s1", ("other", "pw"), 100))
        self.assertEqual(out["状态"], "在线")

    def test_batch_online_backoff_item_and_no_state(self):
        auth, s = make()
        out = parse(s.batch_online(
            "kb",
            (("s1", "alice", "bad"), ("s2", "bob", "pw")),
            0,
        ))
        self.assertEqual([i["结果"] for i in out["项目"]][:2],
                         ["AuthError", "上线"])
        self.assertNotIn("s1", s._sessions)
        self.assertEqual(auth._users["alice"][1], 1)

    def test_policy_switch_keeps_retry_schedule(self):
        auth, s = make()
        with self.assertRaises(AuthError):
            s.do("b0", "建立", "s0", ("alice", "bad"), 0)
        self.assertEqual(auth._users["alice"][3], 100)
        # 热加载仅改锁定毫秒：失败数与下次可试不重算。
        doc = parse(s.export_config())
        doc["认证"] = {"最大失败": 4, "锁定毫秒": 9000,
                       "重试基数毫秒": 100, "重试上限毫秒": 1000}
        s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(auth._users["alice"][3], 100)
        # 切换退避参数后，原时刻之前仍拒绝；到刻按新策略（failed=2 -> 200）。
        with self.assertRaises(AuthError):
            s.do("b1", "建立", "s1", ("alice", "pw"), 99)
        with self.assertRaises(AuthError):
            s.do("b2", "建立", "s2", ("alice", "bad"), 100)
        self.assertEqual(auth._users["alice"][3], 300)

    def test_credential_change_clears_retry_time(self):
        auth, s = make()
        with self.assertRaises(AuthError):
            s.do("b0", "建立", "s0", ("alice", "bad"), 0)
        self.assertEqual(auth._users["alice"][3], 100)
        # 退避未到：旧密码正确也过不了认证，故不能换密。
        with self.assertRaises(AuthError):
            s.credential_change("cc1", "alice", "pw", "newpw", 50)
        self.assertEqual(auth._users["alice"][3], 100)
        # 到刻换密成功：失败数、锁定、下次可试全清。
        out = parse(s.credential_change("cc2", "alice", "pw", "newpw", 100))
        self.assertEqual(out["结果"], "已轮换")
        self.assertEqual(auth._users["alice"][1:], [0, None, None])
        # 新密码立即可用（不受旧退避限制）。
        out = parse(s.do("ok", "建立", "s1", ("alice", "newpw"), 100))
        self.assertEqual(out["状态"], "在线")
        # 旧密码失败按全新计数起算。
        with self.assertRaises(AuthError):
            s.do("b3", "建立", "s2", ("alice", "pw"), 100)
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(auth._users["alice"][3], 200)


class CheckpointV1AcceptanceTest(unittest.TestCase):
    """恢复接受版本 1（下次可试补 None），导出恒为版本 2。"""

    @staticmethod
    def _cred_hex(user, password="pw"):
        import hashlib
        return hashlib.sha256((user + "\0" + password).encode()).digest().hex()

    def _v1_text(self, now_ms=0):
        import hashlib
        rows = []
        for user in ("alice", "bob", "carol"):
            rows.append({
                "用户": user,
                "凭据": self._cred_hex(user),
                "失败": 0,
                "锁定至": None,
                "停用": False,
            })
        head = {"版本": 1, "时刻": now_ms, "用户": rows}
        doc = dict(head)
        doc["摘要"] = hashlib.sha256(
            json.dumps(head, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"

    def test_v1_restore_fills_none_and_exports_v2(self):
        _auth, s = make()
        out = s.auth_restore("r1", self._v1_text(0))
        doc = parse(out)
        self.assertEqual(doc["版本"], 2)
        self.assertEqual(s.auth_checkpoint(0), out)
        for item in doc["用户"]:
            # 版本 1 恢复补 0（非 null）。
            self.assertEqual(item["下次可试"], 0)
            self.assertEqual(
                list(item),
                ["用户", "凭据", "失败", "锁定至", "下次可试", "停用"],
            )
        self.assertEqual(s._auth._users["alice"][3], 0)

    def test_v1_restore_then_backoff_works(self):
        auth, s = make()
        s.auth_restore("r1", self._v1_text(0))
        # 补 None 后第一次错口令即按当前退避策略起算。
        self.assertEqual(auth.authenticate("alice", "bad", 0), ("alice", "backoff", 100))

    def test_v1_with_until_roundtrips(self):
        import hashlib
        _auth, s = make()
        rows = [{
            "用户": "alice",
            "凭据": self._cred_hex("alice"),
            "失败": 2,
            "锁定至": 5000,
            "停用": False,
        }, {
            "用户": "bob",
            "凭据": self._cred_hex("bob"),
            "失败": 0,
            "锁定至": None,
            "停用": True,
        }, {
            "用户": "carol",
            "凭据": self._cred_hex("carol"),
            "失败": 0,
            "锁定至": None,
            "停用": False,
        }]
        head = {"版本": 1, "时刻": 7, "用户": rows}
        doc = dict(head)
        doc["摘要"] = hashlib.sha256(
            json.dumps(head, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
        text = json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        out = parse(s.auth_restore("r1", text))
        self.assertEqual(out["版本"], 2)
        self.assertEqual(out["时刻"], 7)
        self.assertEqual(out["用户"][0]["锁定至"], 5000)
        self.assertEqual(out["用户"][0]["下次可试"], 0)
        self.assertTrue(out["用户"][1]["停用"])
        self.assertEqual(s._disabled_users, {"bob"})


class CheckpointV2BackoffRoundTripTest(unittest.TestCase):
    def test_retry_at_roundtrips_and_is_in_digest(self):
        auth, s = make(max_fail=4)
        auth.authenticate("alice", "bad", 0)       # retry 100
        auth.authenticate("alice", "bad", 100)     # retry 300
        cp = parse(s.auth_checkpoint(200))
        rows = {r["用户"]: r for r in cp["用户"]}
        self.assertEqual(cp["版本"], 2)
        self.assertEqual(rows["alice"]["失败"], 2)
        self.assertEqual(rows["alice"]["下次可试"], 300)
        self.assertIsNone(rows["bob"]["下次可试"])

        # 恢复后状态一致。
        _auth2, d2 = make(max_fail=4)
        self.assertEqual(d2.auth_restore("r1", s.auth_checkpoint(200)),
                         s.auth_checkpoint(200))
        self.assertEqual(d2._auth._users["alice"][3], 300)
        # 下次可试纳入摘要：篡改即 ValueError。
        tampered = json.dumps(cp, ensure_ascii=False, separators=(",", ":"))
        tampered = tampered.replace('"下次可试":300', '"下次可试":301', 1)
        with self.assertRaises(ValueError):
            d2.auth_restore("r2", tampered + "\n")

    def test_checkpoint_does_not_clear_expired_retry(self):
        auth, s = make()
        auth.authenticate("alice", "bad", 0)  # retry 100
        # 只读检查点：越过时刻仍原样导出。
        doc = parse(s.auth_checkpoint(100000))
        self.assertEqual(doc["用户"][0]["下次可试"], 100)
        self.assertEqual(auth._users["alice"][3], 100)

    def test_byte_stable(self):
        _auth, s = make()
        s._auth.authenticate("alice", "bad", 0)
        self.assertEqual(s.auth_checkpoint(5), s.auth_checkpoint(5))
        self.assertNotEqual(s.auth_checkpoint(5), s.auth_checkpoint(6))


if __name__ == "__main__":
    unittest.main()
