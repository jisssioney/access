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


def make(users=("alice", "bob", "carol"), idle_ms=100000, lease_ms=100000,
         pool=("10.0.0.0/24", (), ())):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(auth, 10, 10, idle_ms, pool=pool, lease_ms=lease_ms)
    return auth, s


def parse(out):
    return json.loads(out)


def seal(doc):
    """按前三键重算摘要，返回 LF 尾紧凑文本。"""
    head = {key: doc[key] for key in ("版本", "时刻", "用户")}
    doc["摘要"] = digest(head)
    return compact(doc) + "\n"


def build(now_ms=0, users=(), version=2):
    """users 为 (用户, 失败, 锁定至, 下次可试, 停用[, 密码])；version 1 省略
    下次可试键（恢复时补 None）。"""
    rows = []
    for item in users:
        user, failed, until, retry_at, disabled = item[:5]
        password = item[5] if len(item) > 5 else "pw"
        row = {
            "用户": user,
            "凭据": cred_hex(user, password),
            "失败": failed,
            "锁定至": until,
        }
        if version == 2:
            row["下次可试"] = retry_at
        row["停用"] = disabled
        rows.append(row)
    return {"版本": version, "时刻": now_ms, "用户": rows}


def row(doc, user):
    return next(item for item in doc["用户"] if item["用户"] == user)


class AuthCheckpointTest(unittest.TestCase):
    def test_empty_format(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 10, 10, 100000)
        out = s.auth_checkpoint(0)
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)
        self.assertEqual(
            out,
            '{"版本":2,"时刻":0,"用户":[],'
            '"摘要":"279d29321d549c616d85737e38c11854'
            'a0f63216d9e4d862f8b2f3d9493d00a6"}\n',
        )
        doc = parse(out)
        self.assertEqual(list(doc), ["版本", "时刻", "用户", "摘要"])
        head = {key: doc[key] for key in ("版本", "时刻", "用户")}
        self.assertEqual(doc["摘要"], digest(head))

    def test_param_validation(self):
        _auth, s = make()
        for bad in (True, "0", 1.5, None, b"0", []):
            with self.assertRaises(TypeError):
                s.auth_checkpoint(bad)
        for bad in (-1, -100):
            with self.assertRaises(ValueError):
                s.auth_checkpoint(bad)

    def test_populated_shape_order_and_digest(self):
        auth, s = make()
        for _ in range(3):
            auth.authenticate("alice", "bad", 0)  # 第三次锁定至 1000
        s.user_admin("d", "停用", "bob", 0, force=True)
        out = s.auth_checkpoint(60)
        doc = parse(out)
        self.assertEqual(doc["版本"], 2)
        self.assertEqual(doc["时刻"], 60)
        self.assertEqual(
            [item["用户"] for item in doc["用户"]], ["alice", "bob", "carol"]
        )
        self.assertTrue(all(
            list(item) == ["用户", "凭据", "失败", "锁定至", "下次可试", "停用"]
            for item in doc["用户"]
        ))
        self.assertEqual(row(doc, "alice"), {
            "用户": "alice",
            "凭据": cred_hex("alice"),
            "失败": 3,
            "锁定至": 1000,
            "下次可试": None,
            "停用": False,
        })
        self.assertEqual(row(doc, "bob"), {
            "用户": "bob",
            "凭据": cred_hex("bob"),
            "失败": 0,
            "锁定至": None,
            "下次可试": None,
            "停用": True,
        })
        self.assertEqual(row(doc, "carol"), {
            "用户": "carol",
            "凭据": cred_hex("carol"),
            "失败": 0,
            "锁定至": None,
            "下次可试": None,
            "停用": False,
        })
        head = {key: doc[key] for key in ("版本", "时刻", "用户")}
        self.assertEqual(doc["摘要"], digest(head))

    def test_credential_is_digest_hex(self):
        auth, s = make()
        auth.add("dave", "s3cret!")
        doc = parse(s.auth_checkpoint(0))
        self.assertEqual(row(doc, "dave")["凭据"], cred_hex("dave", "s3cret!"))
        for item in doc["用户"]:
            self.assertRegex(item["凭据"], r"^[0-9a-f]{64}$")

    def test_sorted_by_user_codepoint(self):
        auth = Authenticator(3, 1000)
        for user in ("alice", "zeb", "éve"):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 10, 100000)
        doc = parse(s.auth_checkpoint(0))
        self.assertEqual(
            [item["用户"] for item in doc["用户"]], ["alice", "zeb", "éve"]
        )

    def test_unicode_not_escaped(self):
        auth = Authenticator(3, 1000)
        auth.add("张三", "pw")
        s = Sessions(auth, 10, 10, 100000)
        out = s.auth_checkpoint(0)
        self.assertIn("张三", out)
        self.assertNotIn("\\u", out)

    def test_read_only_does_not_clear_expired_lock_or_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        for _ in range(3):
            _auth.authenticate("bob", "bad", 0)  # 锁定至 1000
        # 远越过锁定时刻：检查点仍只读保留失败与锁定，且不老化会话。
        doc = parse(s.auth_checkpoint(100000))
        self.assertEqual(row(doc, "bob")["失败"], 3)
        self.assertEqual(row(doc, "bob")["锁定至"], 1000)
        self.assertEqual(_auth._users["bob"][1], 3)
        self.assertEqual(_auth._users["bob"][2], 1000)
        self.assertEqual(s._sessions["s1"]["state"], "在线")

    def test_byte_stable_same_now(self):
        _auth, s = make()
        self.assertEqual(s.auth_checkpoint(7), s.auth_checkpoint(7))
        self.assertNotEqual(s.auth_checkpoint(7), s.auth_checkpoint(8))


class AuthRestoreTest(unittest.TestCase):
    def test_roundtrip_onto_fresh_instance(self):
        src_auth, src = make()
        for _ in range(3):
            src_auth.authenticate("alice", "bad", 0)
        src.user_admin("d", "停用", "bob", 0, force=True)
        cp = src.auth_checkpoint(60)

        dst_auth, dst = make()
        out = dst.auth_restore("r1", cp)
        self.assertEqual(out, cp)  # 返回规范包且与输入逐字节一致
        self.assertEqual(dst.auth_checkpoint(60), cp)
        self.assertEqual(dst_auth._users["alice"][0], src_auth._users["alice"][0])
        self.assertEqual(dst_auth._users["alice"][1], 3)
        self.assertEqual(dst_auth._users["alice"][2], 1000)
        self.assertEqual(dst._disabled_users, {"bob"})
        # 认证策略不被恢复改写。
        self.assertEqual(dst_auth.policy(), (3, 1000, 0, 0))

    def test_policy_preserved_and_failed_until_verbatim(self):
        _auth, s = make()
        cp = seal(build(0, [
            ("alice", 99, None, None, False),     # 失败远超 max_fail=3，原样往返
            ("bob", 0, 0, None, False),           # 锁定至=0（非 null）原样往返
            ("carol", 5, 12345, None, True),      # 停用+未到期锁
        ]))
        dst_auth, dst = make()
        self.assertEqual(dst.auth_restore("r1", cp), cp)
        self.assertEqual(dst_auth.policy(), (3, 1000, 0, 0))
        self.assertEqual(dst_auth._users["alice"][1], 99)
        self.assertIsNone(dst_auth._users["alice"][2])
        self.assertEqual(dst_auth._users["bob"][1], 0)
        self.assertEqual(dst_auth._users["bob"][2], 0)
        self.assertEqual(dst_auth._users["carol"][1], 5)
        self.assertEqual(dst_auth._users["carol"][2], 12345)
        self.assertEqual(dst._disabled_users, {"carol"})

    def test_locked_state_follows_existing_rules_after_restore(self):
        _auth, s = make()
        # carol 锁定至 10000：后续认证先判锁，不验密、不清零。
        cp = seal(build(0, [
            ("alice", 0, None, None, False),
            ("bob", 0, None, None, False),
            ("carol", 2, 10000, None, False),
        ]))
        dst_auth, _dst = make()
        _dst.auth_restore("r1", cp)
        _user, status, until = dst_auth.authenticate("carol", "pw", 100)
        self.assertEqual(status, "locked")
        self.assertEqual(until, 10000)
        self.assertEqual(dst_auth._users["carol"][1], 2)
        # 锁到期（同刻）先清零再验密：正确密码 ok。
        self.assertEqual(dst_auth.authenticate("carol", "pw", 10000)[1], "ok")
        self.assertEqual(dst_auth._users["carol"][1], 0)
        self.assertIsNone(dst_auth._users["carol"][2])
        self.assertIsNone(dst_auth._users["carol"][3])

    def test_high_failed_count_keeps_existing_lock_rule(self):
        # 失败=99 原样恢复；下一次错密码按既有规则 failed>=max_fail 立即锁定。
        _auth, s = make()
        cp = seal(build(0, [
            ("alice", 99, None, None, False),
            ("bob", 0, None, None, False),
            ("carol", 0, None, None, False),
        ]))
        dst_auth, _dst = make()
        _dst.auth_restore("r1", cp)
        _user, status, until = dst_auth.authenticate("alice", "bad", 5)
        self.assertEqual(status, "locked")
        self.assertEqual(until, 1005)
        self.assertEqual(dst_auth._users["alice"][1], 100)

    def test_credential_replaced_and_old_password_rejected(self):
        _auth, s = make()
        cp = s.auth_checkpoint(0)  # 密码均为 pw
        dst_auth, dst = make()
        # 目标 alice 先换成另一密码；恢复后仅检查点密码可用。
        dst_auth._users["alice"][0] = hashlib.sha256(
            b"alice\0other"
        ).digest()
        self.assertEqual(dst.auth_restore("r1", cp), cp)
        self.assertEqual(dst_auth.authenticate("alice", "pw", 0)[1], "ok")
        # 恢复前的 other 密码不再可用：错密码计 denied。
        _user, status, _until = dst_auth.authenticate("alice", "other", 0)
        self.assertEqual(status, "denied")

    def test_disabled_user_blocks_establish_until_enabled(self):
        _auth, s = make()
        cp = seal(build(0, [
            ("alice", 0, None, None, True),
            ("bob", 0, None, None, False),
            ("carol", 0, None, None, False),
        ]))
        _a, dst = make()
        dst.auth_restore("r1", cp)
        with self.assertRaises(AuthError):
            dst.do("d1", "建立", "s1", ("alice", "pw"), 0)
        # 停用拒绝先于认证，失败计数不变。
        self.assertEqual(_a._users["alice"][1], 0)
        dst.user_admin("e", "启用", "alice", 0)
        self.assertEqual(
            parse(dst.do("d2", "建立", "s2", ("alice", "pw"), 0))["状态"], "在线"
        )

    def test_pretty_input_returns_canonical_package(self):
        _auth, s = make()
        doc = json.loads(s.auth_checkpoint(10))
        pretty = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
        _a2, dst = make()
        out = dst.auth_restore("r1", pretty)
        self.assertEqual(out, seal(json.loads(pretty)))
        self.assertEqual(dst.auth_checkpoint(10), out)

    def test_type_errors(self):
        _auth, s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.auth_restore(bad_key, "x")
        with self.assertRaises(ValueError):
            s.auth_restore("", "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.auth_restore("k", bad_text)

    def test_value_errors(self):
        _auth, s = make()
        good = json.loads(seal(build()))
        good3 = json.loads(seal(build(0, [
            ("alice", 0, None, None, False),
            ("bob", 0, None, None, False),
            ("carol", 0, None, None, False),
        ])))
        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            '"x"',
            # 键集/键序。
            compact({"版本": 2}),
            compact({k: good3[k] for k in
                     ("摘要", "版本", "时刻", "用户")}),
            compact({**good3, "x": 1}),
            compact({k: v for k, v in good3.items() if k != "用户"}),
            # 版本：1/2 合法，其余非法。
            seal({**good3, "版本": 0}),
            seal({**good3, "版本": 3}),
            seal({**good3, "版本": "1"}),
            seal({**good3, "版本": True}),
            # 时刻。
            seal({**good3, "时刻": -1}),
            seal({**good3, "时刻": True}),
            seal({**good3, "时刻": "0"}),
            seal({**good3, "时刻": 1.0}),
            # 用户整体形态。
            seal({**good3, "用户": {}}),
            seal({**good3, "用户": 1}),
            # 用户项键集/键序。
            seal({**good3, "用户": [
                {"凭据": cred_hex("alice"), "失败": 0, "锁定至": None,
                 "下次可试": None, "停用": False, "用户": "alice"}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None}
            ]}),
            # 版本 2 缺下次可试键。
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False, "x": 0}
            ]}),
            seal({**good3, "用户": [[]]}),
            # 用户凭据约束。
            seal({**good3, "用户": [
                {"用户": "", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": 1, "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "a\u0000", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            # 凭据：64 位小写十六进制。
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": 0, "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": "0" * 63, "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": "A" * 64, "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": "g" * 64, "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            # 失败：非 bool 非负 int。
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": -1,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": True,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": "1",
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 1.0,
                 "锁定至": None, "下次可试": None, "停用": False}
            ]}),
            # 锁定至：null 或非 bool 非负 int。
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": -1, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": True, "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": "1", "下次可试": None, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": 1.5, "下次可试": None, "停用": False}
            ]}),
            # 下次可试：null 或非 bool 非负 int。
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": -1, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": True, "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": "1", "停用": False}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": 1.5, "停用": False}
            ]}),
            # 停用：bool。
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": 0}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": "false"}
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": None}
            ]}),
            # 排序/重复。
            seal({**good3, "用户": [
                {"用户": "bob", "凭据": cred_hex("bob"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False},
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False},
            ]}),
            seal({**good3, "用户": [
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 0,
                 "锁定至": None, "下次可试": None, "停用": False},
                {"用户": "alice", "凭据": cred_hex("alice"), "失败": 1,
                 "锁定至": None, "下次可试": None, "停用": False},
            ]}),
            # 摘要形态与内容。
            compact({**good3, "摘要": 0}),
            compact({**good3, "摘要": "0" * 63}),
            compact({**good3, "摘要": "g" * 64}),
            compact({**good3, "摘要": "0" * 64}),  # 形态合法但内容不符
            # 重复顶层键。
            '{"版本":2,"版本":2,"时刻":0,"用户":[],"摘要":"' + "0" * 64 + '"}',
            # 重复用户项内键。
            '{"版本":2,"时刻":0,"用户":[{"用户":"alice","用户":"alice",'
            '"凭据":"' + cred_hex("alice") + '","失败":0,"锁定至":null,'
            '"下次可试":null,"停用":false}],"摘要":"' + "0" * 64 + '"}',
            # 版本 1 文档混入下次可试键（键集不符）。
            seal(build(0, [
                ("alice", 0, None, None, False),
                ("bob", 0, None, None, False),
                ("carol", 0, None, None, False),
            ], version=1)).replace('"停用":false', '"下次可试":null,"停用":false'),
        ]
        self.assertGreater(len(bad_texts), 30)  # 防止误删用例
        for text in bad_texts:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.auth_restore("k", text)

    def test_user_set_mismatch_resource_error(self):
        _auth, s = make()
        cp = seal(build(0, [
            ("alice", 0, None, None, False),
            ("bob", 0, None, None, False),
            ("carol", 0, None, None, False),
        ]))
        _a2, fewer = make(users=("alice", "bob"))
        with self.assertRaises(ResourceError):
            fewer.auth_restore("r1", cp)
        _a3, more = make(users=("alice", "bob", "carol", "dave"))
        with self.assertRaises(ResourceError):
            more.auth_restore("r1", cp)
        _a4, other = make(users=("alice", "bob", "xxx"))
        with self.assertRaises(ResourceError):
            other.auth_restore("r1", cp)

    def test_failure_does_not_change_instance(self):
        _auth, s = make()
        s.user_admin("u", "停用", "bob", 0, force=True)
        before = s.auth_checkpoint(0)
        _a4, s4 = make(users=("alice", "bob", "carol", "dave"))
        bad_set = s4.auth_checkpoint(0)
        for bad in ("not json", "[]", bad_set):
            with self.assertRaises((ValueError, ResourceError)):
                s.auth_restore("r9", bad)
        self.assertEqual(s.auth_checkpoint(0), before)
        self.assertEqual(s._disabled_users, {"bob"})

    def test_failure_does_not_occupy_key(self):
        _auth, s = make()
        _a4, s4 = make(users=("alice", "bob", "carol", "dave"))
        with self.assertRaises(ValueError):
            s.auth_restore("r1", "bad")
        with self.assertRaises(TypeError):
            s.auth_restore("r1", None)
        with self.assertRaises(ResourceError):
            s.auth_restore("r1", s4.auth_checkpoint(0))
        # 同 key 此前失败不占位，合法文本首次成功。
        good = s.auth_checkpoint(0)
        self.assertEqual(s.auth_restore("r1", good), good)

    def test_replay_same_bytes_no_revalidation(self):
        _auth, s = make()
        text = s.auth_checkpoint(0)
        first = s.auth_restore("r1", text)
        # 改动认证器后，同参重放不重验、不替换、返回原字节。
        for _ in range(2):
            _auth.authenticate("alice", "bad", 0)
        self.assertEqual(s.auth_restore("r1", text), first)
        self.assertEqual(_auth._users["alice"][1], 2)  # 重放未恢复检查点状态

    def test_replay_different_params_value_error(self):
        auth = Authenticator(3, 1000)
        s = Sessions(auth, 10, 10, 100000)
        t1 = seal(build(0))
        t2 = seal(build(1))
        s.auth_restore("r1", t1)
        with self.assertRaises(ValueError):
            s.auth_restore("r1", t2)
        with self.assertRaises(ValueError):
            s.auth_restore("r1", t1.rstrip("\n"))
        # 已缓存 key 上 text 非 str：同型校验失败仍为 ValueError（非 TypeError）。
        with self.assertRaises(ValueError):
            s.auth_restore("r1", None)
        # 不同 key 同文本各自独立。
        self.assertEqual(s.auth_restore("r2", t1), t1)

    def test_not_audited(self):
        _auth, s = make()
        cp = s.auth_checkpoint(77)
        s.auth_restore("r1", cp)
        s.auth_restore("r1", cp)
        self.assertEqual(parse(s.audit(limit=10))["事件"], [])
        self.assertEqual(parse(s.takeover_audit())["事件"], [])
        self.assertTrue(s.verify_audit())

    def test_cache_domain_independent(self):
        _auth, s = make()
        cp = s.auth_checkpoint(0)
        # 与 do/backend_restore 各域独立。
        self.assertEqual(s.auth_restore("shared", cp), cp)
        out = s.do("shared", "建立", "s1", ("alice", "pw"), 0)
        self.assertEqual(parse(out)["状态"], "在线")

    def test_restore_does_not_age(self):
        _auth, s = make(idle_ms=50)
        s.do("e1", "建立", "s1", ("alice", "pw"), 0)
        cp = seal(build(100000, [
            ("alice", 0, None, None, False),
            ("bob", 0, None, None, False),
            ("carol", 0, None, None, False),
        ]))
        s.auth_restore("r1", cp)
        self.assertEqual(s._sessions["s1"]["state"], "在线")

    def test_restored_state_independent_from_source(self):
        src_auth, src = make()
        cp = src.auth_checkpoint(0)
        _dst_auth, dst = make()
        dst.auth_restore("r1", cp)
        # 源实例随后变化（alice 错密码两次），目标实例不受影响。
        src_auth.authenticate("alice", "bad", 0)
        src_auth.authenticate("alice", "bad", 0)
        self.assertEqual(dst.auth_checkpoint(0), cp)


if __name__ == "__main__":
    unittest.main()
