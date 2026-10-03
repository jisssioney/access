import hashlib
import json
import unittest

from access import (
    AuthError,
    Authenticator,
    ResourceError,
    Sessions,
)


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def cred_hex(user, password="pw"):
    return hashlib.sha256((user + "\0" + password).encode("utf-8")).digest().hex()


def make_sessions(users=("alice", "bob"), max_fail=5, lock_ms=1000,
                  base=100, cap=800):
    auth = Authenticator(max_fail, lock_ms, base, cap)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(auth, 10, 10, 100000,
                 pool=("10.0.0.0/24", (), ()), lease_ms=100000)
    return auth, s


class BackoffPolicyTest(unittest.TestCase):
    def test_default_policy_is_no_backoff(self):
        auth = Authenticator(3, 1000)
        self.assertEqual(auth.policy(), (3, 1000, 0, 0))
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "denied", 0))
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "denied", 0))

    def test_constructor_rejects_invalid_pair(self):
        for kwargs in (
            dict(max_fail=1, lock_ms=0, retry_base_ms=1, retry_cap_ms=0),
            dict(max_fail=1, lock_ms=0, retry_base_ms=0, retry_cap_ms=1),
            dict(max_fail=1, lock_ms=0, retry_base_ms=10, retry_cap_ms=5),
            dict(max_fail=1, lock_ms=0, retry_base_ms=-1, retry_cap_ms=5),
        ):
            with self.assertRaises(ValueError):
                Authenticator(**kwargs)
        for bad in (True, 1.5, "1"):
            with self.assertRaises(TypeError):
                Authenticator(1, 0, bad, 1)
            with self.assertRaises(TypeError):
                Authenticator(1, 0, 1, bad)

    def test_exponential_schedule_with_cap(self):
        auth = Authenticator(10, 1000, 100, 800)
        auth.add("u", "pw")
        times = []
        for i in range(9):
            now = 0 if i == 0 else times[-1]
            _u, status, until = auth.authenticate("u", "bad", now)
            self.assertEqual(status, "backoff")
            times.append(until)
        # base*2**(failed-1)：100,200,400 截顶 800 后每步 +800。
        self.assertEqual(
            times, [100, 300, 700, 1500, 2300, 3100, 3900, 4700, 5500]
        )

    def test_cap_equals_base_fixed_delay(self):
        auth = Authenticator(5, 1000, 100, 100)
        auth.add("u", "pw")
        times = []
        for i in range(4):
            now = 0 if i == 0 else times[-1]
            times.append(auth.authenticate("u", "bad", now)[2])
        self.assertEqual(times, [100, 200, 300, 400])

    def test_window_blocks_without_incrementing_failed(self):
        auth = Authenticator(10, 1000, 100, 800)
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "backoff", 100))
        # now < 100：正确口令也不验密、失败数不增、时刻不变。
        before = list(auth._users["u"])
        self.assertEqual(auth.authenticate("u", "pw", 99), ("u", "backoff", 100))
        self.assertEqual(list(auth._users["u"]), before)
        # 等于时刻可重试，正确口令 ok 并清零。
        self.assertEqual(auth.authenticate("u", "pw", 100), ("u", "ok", 0))
        self.assertEqual(auth._users["u"][1], 0)
        self.assertEqual(auth._users["u"][3], 0)

    def test_lock_clears_next_retry_and_takes_priority(self):
        auth = Authenticator(3, 1000, 100, 800)
        auth.add("u", "pw")
        self.assertEqual(auth.authenticate("u", "bad", 0), ("u", "backoff", 100))
        self.assertEqual(auth.authenticate("u", "bad", 100), ("u", "backoff", 300))
        self.assertEqual(auth.authenticate("u", "bad", 300), ("u", "locked", 1300))
        record = auth._users["u"]
        self.assertEqual(record[1], 3)
        self.assertEqual(record[2], 1300)
        self.assertEqual(record[3], 0)
        # 锁定中不验密、不增失败，即使到了旧退避时刻。
        self.assertEqual(auth.authenticate("u", "pw", 500), ("u", "locked", 1300))
        self.assertEqual(record[1], 3)
        # 锁到期同刻：清零三项后验密。
        self.assertEqual(auth.authenticate("u", "pw", 1300), ("u", "ok", 0))
        self.assertEqual(record[1], 0)
        self.assertIsNone(record[2])
        self.assertEqual(record[3], 0)

    def test_after_lock_expiry_wrong_password_restarts_backoff(self):
        auth = Authenticator(2, 1000, 100, 800)
        auth.add("u", "pw")
        auth.authenticate("u", "bad", 0)
        self.assertEqual(auth.authenticate("u", "bad", 100), ("u", "locked", 1100))
        # 到期清零后错口令重新从 failed=1 起算退避。
        self.assertEqual(auth.authenticate("u", "bad", 1100), ("u", "backoff", 1200))

    def test_policy_switch_keeps_existing_limits(self):
        auth = Authenticator(5, 1000, 100, 800)
        auth.add("u", "pw")
        auth.authenticate("u", "bad", 0)  # failed=1, retry_at=100
        auth.set_policy(5, 5000, 0, 0)
        self.assertEqual(auth.policy(), (5, 5000, 0, 0))
        self.assertEqual(auth._users["u"][1], 1)
        self.assertEqual(auth._users["u"][3], 100)
        # 旧窗口仍执行；到刻后新策略生效（无退避 -> denied）。
        self.assertEqual(auth.authenticate("u", "bad", 50), ("u", "backoff", 100))
        self.assertEqual(auth.authenticate("u", "bad", 100), ("u", "denied", 0))
        self.assertEqual(auth._users["u"][1], 2)

    def test_huge_exponent_is_constant_time(self):
        # 恢复出极大失败数后再错：截顶路径不做超大整数移位。
        auth = Authenticator(10 ** 9, 1000, 1, 10 ** 18)
        auth.add("u", "pw")
        auth._users["u"][1] = 500000
        _u, status, until = auth.authenticate("u", "bad", 1)
        self.assertEqual(status, "backoff")
        self.assertEqual(until, 1 + 10 ** 18)


class ConfigV10Test(unittest.TestCase):
    def v10(self, s, **auth):
        doc = json.loads(s.export_config())
        doc["认证"] = {
            "最大失败": auth.get("max_fail", 5),
            "锁定毫秒": auth.get("lock_ms", 1000),
            "重试基数毫秒": auth.get("base", 100),
            "重试上限毫秒": auth.get("cap", 800),
        }
        return json.dumps(doc, ensure_ascii=False)

    def test_export_is_current_version_with_four_auth_fields(self):
        _auth, s = make_sessions()
        doc = json.loads(s.export_config())
        self.assertEqual(doc["版本"], 12)
        self.assertEqual(
            list(doc)[-1], "模板 IPv6 池"
        )
        self.assertEqual(doc["模板地址池"], [])
        self.assertEqual(doc["IPv6 前缀池"], [])
        self.assertEqual(
            list(doc["认证"]),
            ["最大失败", "锁定毫秒", "重试基数毫秒", "重试上限毫秒"],
        )
        self.assertEqual(doc["认证"], {
            "最大失败": 5, "锁定毫秒": 1000,
            "重试基数毫秒": 100, "重试上限毫秒": 800,
        })

    def test_load_applies_backoff_policy(self):
        auth, s = make_sessions()
        out = s.load_config(self.v10(s, max_fail=4, lock_ms=2000,
                                     base=50, cap=400))
        self.assertEqual(json.loads(out)["认证"], {
            "最大失败": 4, "锁定毫秒": 2000,
            "重试基数毫秒": 50, "重试上限毫秒": 400,
        })
        self.assertEqual(auth.policy(), (4, 2000, 50, 400))

    def test_invalid_auth_sections(self):
        _auth, s = make_sessions()
        for section in (
            {"最大失败": 1, "锁定毫秒": 0, "重试基数毫秒": 1, "重试上限毫秒": 0},
            {"最大失败": 1, "锁定毫秒": 0, "重试基数毫秒": 0, "重试上限毫秒": 1},
            {"最大失败": 1, "锁定毫秒": 0, "重试基数毫秒": 10, "重试上限毫秒": 5},
            {"最大失败": 1, "锁定毫秒": 0, "重试基数毫秒": -1, "重试上限毫秒": 5},
            {"最大失败": 1, "锁定毫秒": 0,
             "重试基数毫秒": True, "重试上限毫秒": 5},
            {"最大失败": 1, "锁定毫秒": 0, "重试基数毫秒": 1},
            {"最大失败": 1, "锁定毫秒": 0,
             "重试基数毫秒": 1, "重试上限毫秒": 5, "多余": 0},
            {"最大失败": 1, "锁定毫秒": 0},
        ):
            doc = json.loads(s.export_config())
            doc["认证"] = section
            with self.assertRaises(ValueError, msg=repr(section)):
                s.load_config(json.dumps(doc, ensure_ascii=False))

    def test_v9_loads_and_zero_fills_backoff(self):
        _auth, s = make_sessions()
        doc = json.loads(s.export_config())
        doc["版本"] = 9
        del doc["模板地址池"]
        del doc["IPv6 前缀池"]
        del doc["模板 IPv6 池"]
        doc["认证"] = {"最大失败": 2, "锁定毫秒": 500}
        loaded = json.loads(s.load_config(json.dumps(doc, ensure_ascii=False)))
        self.assertEqual(loaded["版本"], 12)
        self.assertEqual(loaded["模板地址池"], [])
        self.assertEqual(loaded["IPv6 前缀池"], [])
        self.assertEqual(loaded["认证"], {
            "最大失败": 2, "锁定毫秒": 500,
            "重试基数毫秒": 0, "重试上限毫秒": 0,
        })

    def test_v1_upgrade_zero_fills(self):
        # v1-v4 迁移以认证器当前四值补认证；默认认证器即无退避，补两项 0。
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s = Sessions(auth, 10, 10, 100000,
                     pool=("10.0.0.0/24", (), ()), lease_ms=100000)
        v1 = json.dumps({
            "版本": 1,
            "会话": {"总数": 10, "每用户": 10, "空闲毫秒": 100000,
                     "租期毫秒": 100000},
            "地址池": {"CIDR": "10.0.0.0/24", "保留": [], "静态": []},
        }, ensure_ascii=False)
        env = json.loads(s.upgrade_config(v1))
        self.assertEqual((env["源版本"], env["目标版本"], env["改变"]),
                         (1, 12, True))
        self.assertEqual(env["配置"]["版本"], 12)
        self.assertEqual(env["配置"]["模板地址池"], [])
        self.assertEqual(env["配置"]["IPv6 前缀池"], [])
        self.assertEqual(env["配置"]["认证"]["重试基数毫秒"], 0)
        self.assertEqual(env["配置"]["认证"]["重试上限毫秒"], 0)
        # 摘要是规范当前版本配置紧凑编码的 sha256。
        canonical = compact(env["配置"])
        self.assertEqual(
            env["摘要"],
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    def test_v10_upgrade_changed_false(self):
        _auth, s = make_sessions()
        text = s.export_config().rstrip("\n")
        env = json.loads(s.upgrade_config(text))
        self.assertFalse(env["改变"])
        self.assertEqual(env["配置"], json.loads(text))

    def test_upgrade_target_must_be_10(self):
        _auth, s = make_sessions()
        with self.assertRaises(ValueError):
            s.upgrade_config(s.export_config(), target=9)

    def test_failed_load_and_rollback_keep_policy_consistent(self):
        _auth, s = make_sessions()
        before = s.export_config()
        s.load_config(self.v10(s, max_fail=2, lock_ms=500, base=10, cap=20))
        # 承载冲突：失败加载不改策略。
        doc = json.loads(s.export_config())
        doc["会话"]["总数"] = 0  # 非法值在承载前即 ValueError
        with self.assertRaises(ValueError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(
            json.loads(s.export_config())["认证"]["重试基数毫秒"], 10
        )
        # 回滚恢复到加载前策略。
        rolled = json.loads(s.rollback_config())
        self.assertEqual(rolled, json.loads(before))


class AuthEntryIntegrationTest(unittest.TestCase):
    def test_establish_backoff_creates_nothing(self):
        auth, s = make_sessions()
        with self.assertRaises(AuthError):
            s.do("k1", "建立", "s1", ("alice", "bad"), 0)
        self.assertNotIn("s1", s._sessions)
        self.assertEqual(len(s._pools["default"].leases), 0)
        self.assertEqual(auth._users["alice"][1], 1)
        # 同幂等键重放不推进认证状态、不占地址。
        with self.assertRaises(AuthError):
            s.do("k1", "建立", "s1", ("alice", "bad"), 0)
        self.assertEqual(auth._users["alice"][1], 1)
        self.assertEqual(len(s._pools["default"].leases), 0)
        # 窗口内正确口令仍被拒；到刻成功。
        with self.assertRaises(AuthError):
            s.do("k2", "建立", "s2", ("alice", "pw"), 50)
        self.assertNotIn("s2", s._sessions)
        out = json.loads(s.do("k3", "建立", "s3", ("alice", "pw"), 100))
        self.assertEqual(out["状态"], "在线")
        self.assertEqual(auth._users["alice"][1], 0)
        self.assertEqual(auth._users["alice"][3], 0)

    def test_capacity_backoff_does_not_enqueue(self):
        auth, s = make_sessions()
        with self.assertRaises(AuthError):
            s.capacity("q1", "申请", "qs1", ("bob", "bad", 1), 0)
        self.assertNotIn("qs1", s._capacity_queue)
        before = auth._users["bob"][1]
        with self.assertRaises(AuthError):
            s.capacity("q1", "申请", "qs1", ("bob", "bad", 1), 0)
        self.assertEqual(auth._users["bob"][1], before)

    def test_credential_change_clears_three_limits(self):
        auth, s = make_sessions()
        auth.authenticate("bob", "bad", 0)
        auth.authenticate("bob", "bad", 100)
        self.assertEqual(
            (auth._users["bob"][1], auth._users["bob"][3]), (2, 300)
        )
        s.credential_change("cc1", "bob", "pw", "newpw", 300)
        record = auth._users["bob"]
        self.assertEqual(record[1], 0)
        self.assertIsNone(record[2])
        self.assertEqual(record[3], 0)
        self.assertEqual(auth.authenticate("bob", "newpw", 300)[1], "ok")

    def test_credential_change_blocked_in_window(self):
        auth, s = make_sessions()
        auth.authenticate("bob", "bad", 0)  # retry_at=100
        with self.assertRaises(AuthError):
            s.credential_change("cc2", "bob", "pw", "newpw", 50)
        self.assertEqual(auth._users["bob"][1], 1)
        # 重放不推进。
        with self.assertRaises(AuthError):
            s.credential_change("cc2", "bob", "pw", "newpw", 50)
        self.assertEqual(auth._users["bob"][1], 1)


def seal_v2(doc):
    doc["摘要"] = digest({k: doc[k] for k in ("版本", "时刻", "用户")})
    return compact(doc) + "\n"


def build_v2(now_ms=0, users=()):
    """users: (用户, 失败, 锁定至, 下次可试, 停用[, 密码])"""
    rows = []
    for item in users:
        user, failed, until, retry_at, disabled = item[:5]
        password = item[5] if len(item) > 5 else "pw"
        rows.append({
            "用户": user, "凭据": cred_hex(user, password), "失败": failed,
            "锁定至": until, "下次可试": retry_at, "停用": disabled,
        })
    return {"版本": 2, "时刻": now_ms, "用户": rows}


class AuthCheckpointV2Test(unittest.TestCase):
    def test_empty_v2_format(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 10, 10, 100000)
        out = s.auth_checkpoint(0)
        doc = json.loads(out)
        self.assertEqual(list(doc), ["版本", "时刻", "用户", "摘要"])
        self.assertEqual(doc["版本"], 2)
        self.assertEqual(doc["用户"], [])
        self.assertEqual(
            doc["摘要"],
            digest({"版本": 2, "时刻": 0, "用户": []}),
        )

    def test_populated_shape_and_retry_roundtrip(self):
        auth, s = make_sessions()
        auth.authenticate("alice", "bad", 0)  # failed=1 retry_at=100
        out = s.auth_checkpoint(60)
        doc = json.loads(out)
        self.assertEqual(doc["版本"], 2)
        self.assertEqual(
            [item["用户"] for item in doc["用户"]], ["alice", "bob"]
        )
        self.assertTrue(all(
            list(item) == ["用户", "凭据", "失败", "锁定至", "下次可试", "停用"]
            for item in doc["用户"]
        ))
        alice = next(item for item in doc["用户"] if item["用户"] == "alice")
        self.assertEqual(
            (alice["失败"], alice["锁定至"], alice["下次可试"]),
            (1, None, 100),
        )
        _a2, s2 = make_sessions()
        self.assertEqual(s2.auth_restore("r1", out), out)
        self.assertEqual(s2.auth_checkpoint(60), out)
        self.assertEqual(s2._auth._users["alice"][3], 100)

    def test_v1_input_accepted_and_zero_filled(self):
        auth, s = make_sessions()
        rows = []
        for user, failed, until, disabled in (
            ("alice", 2, 500, False),
            ("bob", 0, None, True),
        ):
            rows.append({
                "用户": user, "凭据": cred_hex(user), "失败": failed,
                "锁定至": until, "停用": disabled,
            })
        v1 = {"版本": 1, "时刻": 7, "用户": rows}
        v1["摘要"] = digest({k: v1[k] for k in ("版本", "时刻", "用户")})
        text = compact(v1) + "\n"
        out = json.loads(s.auth_restore("r1", text))
        self.assertEqual(out["版本"], 2)
        self.assertTrue(all(item["下次可试"] == 0 for item in out["用户"]))
        self.assertEqual(s._disabled_users, {"bob"})
        self.assertEqual(s._auth._users["alice"][2], 500)
        self.assertEqual(s._auth._users["alice"][3], 0)
        self.assertEqual(auth.policy(), (5, 1000, 100, 800))
        # 同参重放返回同一 v2 规范包。
        self.assertEqual(s.auth_restore("r1", text), compact(out) + "\n")

    def test_v2_strict_validation(self):
        _auth, s = make_sessions()
        good = build_v2(0, [
            ("alice", 0, None, 0, False),
            ("bob", 0, None, 0, False),
        ])
        bad_docs = []
        # 版本非 1/2。
        bad_docs.append(seal_v2({**good, "版本": 3}).rstrip("\n"))
        # v2 行缺下次可试。
        d = json.loads(json.dumps(good))
        d["用户"][0] = {"用户": "alice", "凭据": cred_hex("alice"),
                        "失败": 0, "锁定至": None, "停用": False}
        bad_docs.append(seal_v2(d).rstrip("\n"))
        # 下次可试负值/bool/浮点/字符串。
        for bad_value in (-1, True, 1.5, "0"):
            d = json.loads(json.dumps(good))
            d["用户"][0]["下次可试"] = bad_value
            bad_docs.append(seal_v2(d).rstrip("\n"))
        # 下次可试键序错位（在锁定至之前）。
        d = json.loads(json.dumps(good))
        d["用户"][0] = {
            "用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
            "下次可试": 0, "锁定至": None, "停用": False,
        }
        bad_docs.append(seal_v2(d).rstrip("\n"))
        # 摘要形态合法但内容不符。
        d = json.loads(json.dumps(good))
        d["摘要"] = "0" * 64
        bad_docs.append(compact(d))
        for text in bad_docs:
            with self.subTest(text=text[:60]):
                with self.assertRaises(ValueError):
                    s.auth_restore("k", text + "\n")

    def test_user_set_mismatch_resource_error(self):
        _auth, s = make_sessions(users=("alice", "bob"))
        cp = seal_v2(build_v2(0, [
            ("alice", 0, None, 0, False),
            ("bob", 0, None, 0, False),
        ]))
        other = Authenticator(5, 1000, 100, 800)
        other.add("alice", "pw")
        s_other = Sessions(other, 10, 10, 100000)
        with self.assertRaises(ResourceError):
            s_other.auth_restore("r1", cp)

    def test_failure_leaves_state_and_cache_untouched(self):
        _auth, s = make_sessions()
        s._auth.authenticate("alice", "bad", 0)
        before = s.auth_checkpoint(0)
        for bad in ("not json", "[]", seal_v2(build_v2(0, []))):
            with self.assertRaises((ValueError, ResourceError)):
                s.auth_restore("r9", bad)
        self.assertEqual(s.auth_checkpoint(0), before)
        # 失败不占 key：合法文本首次成功。
        good = s.auth_checkpoint(0)
        self.assertEqual(s.auth_restore("r9", good), good)

    def test_retry_at_followed_after_restore(self):
        auth, s = make_sessions()
        cp = seal_v2(build_v2(0, [
            ("alice", 0, None, 500, False),
            ("bob", 0, None, 0, False),
        ]))
        _a2, s2 = make_sessions()
        s2.auth_restore("r1", cp)
        # 恢复的下次可试时刻直接生效：窗口内不验密。
        self.assertEqual(
            s2._auth.authenticate("alice", "pw", 499), ("alice", "backoff", 500)
        )
        self.assertEqual(s2._auth._users["alice"][1], 0)
        self.assertEqual(
            s2._auth.authenticate("alice", "pw", 500), ("alice", "ok", 0)
        )


if __name__ == "__main__":
    unittest.main()
