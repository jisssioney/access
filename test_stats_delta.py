import hashlib
import json
import unittest

from access import (
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def make():
    auth = Authenticator(3, 1000)
    for user in ("alice", "bob", "carol"):
        auth.add(user, "pw")
    s = Sessions(auth, 10, 5, 100000, lease_ms=100000)
    config = {
        "版本": 3,
        "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 100000, "租期毫秒": 100000},
        "地址池": [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
        ],
        "模板": [
            {"标识": "gold", "限速": 1000000, "突发": 0, "配额": 1000, "超限": "拒绝"},
            {"标识": "kill", "限速": 1000000, "突发": 0, "配额": 10, "超限": "下线"},
        ],
        "用户模板": [["alice", "gold"], ["bob", "kill"]],
    }
    s.load_config(json.dumps(config, ensure_ascii=False))
    return s


def parse(out):
    return json.loads(out)


def digest(doc):
    head = {
        key: doc[key]
        for key in ("版本", "建立", "用户失败", "用户计量", "模板计量")
    }
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def wrap(doc, lf=True):
    doc = dict(doc)
    doc["摘要"] = digest(doc)
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + ("\n" if lf else "")


def doc(total=0, success=0, fails=(), users=(), templates=()):
    """构造版本 1 检查点 dict（未加摘要）。fails 为 (用户, 四计数) 序列，
    users/templates 为 (标识, 四计数) 序列，按码点升序给出。"""
    return {
        "版本": 1,
        "建立": {"总数": total, "成功": success},
        "用户失败": [
            {"用户": u, "认证": v[0], "资源": v[1], "状态": v[2], "后端": v[3]}
            for u, v in fails
        ],
        "用户计量": [
            {"标识": i, "通过": v[0], "拒绝": v[1], "下线": v[2], "通过字节": v[3]}
            for i, v in users
        ],
        "模板计量": [
            {"标识": i, "通过": v[0], "拒绝": v[1], "下线": v[2], "通过字节": v[3]}
            for i, v in templates
        ],
    }


def out_digest(doc):
    head = {
        key: doc[key]
        for key in (
            "基线摘要", "当前摘要", "建立", "用户失败", "用户计量", "模板计量"
        )
    }
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class StatsDeltaTest(unittest.TestCase):
    def test_basic_delta_arithmetic(self):
        s = make()
        base = wrap(doc(
            total=4, success=2,
            fails=(("alice", (1, 0, 0, 0)),),
            users=(("alice", (1, 1, 0, 100)),),
            templates=(("gold", (2, 0, 0, 200)),),
        ))
        current = wrap(doc(
            total=7, success=5,
            fails=(
                ("alice", (1, 2, 0, 0)),
                ("bob", (0, 0, 1, 3)),
            ),
            users=(
                ("alice", (4, 1, 1, 350)),
                ("carol", (1, 0, 0, 9)),
            ),
            templates=(
                ("gold", (2, 3, 0, 200)),
                ("zinc", (1, 0, 0, 7)),
            ),
        ))
        out = parse(s.stats_delta(base, current))
        self.assertEqual(
            list(out),
            ["基线摘要", "当前摘要", "建立", "用户失败", "用户计量", "模板计量", "摘要"],
        )
        self.assertEqual(out["基线摘要"], parse(base)["摘要"])
        self.assertEqual(out["当前摘要"], parse(current)["摘要"])
        self.assertEqual(
            out["建立"], {"总数": 3, "成功": 3, "成功率万分比": 10000}
        )
        self.assertEqual(
            out["用户失败"],
            [
                {"用户": "alice", "认证": 0, "资源": 2, "状态": 0, "后端": 0},
                {"用户": "bob", "认证": 0, "资源": 0, "状态": 1, "后端": 3},
            ],
        )
        self.assertEqual(
            out["用户计量"],
            [
                {"标识": "alice", "通过": 3, "拒绝": 0, "下线": 1, "通过字节": 250},
                {"标识": "carol", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 9},
            ],
        )
        self.assertEqual(
            out["模板计量"],
            [
                {"标识": "gold", "通过": 0, "拒绝": 3, "下线": 0, "通过字节": 0},
                {"标识": "zinc", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 7},
            ],
        )
        self.assertEqual(out["摘要"], out_digest(out))

    def test_missing_identifier_counts_as_zero(self):
        s = make()
        # 仅 current 新增 bob：base 缺失计 0，差即 current 值。
        out = parse(s.stats_delta(
            wrap(doc()), wrap(doc(
                total=1, success=1,
                users=(("bob", (1, 2, 3, 7)),),
                templates=(("gold", (1, 0, 0, 7)),),
            ))
        ))
        self.assertEqual(out["建立"], {"总数": 1, "成功": 1, "成功率万分比": 10000})
        self.assertEqual(
            out["用户计量"],
            [{"标识": "bob", "通过": 1, "拒绝": 2, "下线": 3, "通过字节": 7}],
        )
        self.assertEqual(
            out["模板计量"],
            [{"标识": "gold", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 7}],
        )

    def test_all_zero_rows_omitted_and_sorted_by_codepoint(self):
        auth = Authenticator(3, 1000)
        for user in ("alice", "z", "é", "a", "金牌"):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 5, 100000, lease_ms=100000)
        out = parse(s.stats_delta(
            wrap(doc()),
            wrap(doc(
                fails=(
                    ("alice", (1, 0, 0, 0)),
                    ("z", (0, 1, 0, 0)),
                    ("é", (0, 0, 1, 0)),
                ),
                users=(
                    ("a", (1, 0, 0, 0)),
                    ("金牌", (0, 0, 0, 1)),
                ),
            )),
        ))
        self.assertEqual([r["用户"] for r in out["用户失败"]], ["alice", "z", "é"])
        self.assertEqual([r["标识"] for r in out["用户计量"]], ["a", "金牌"])

    def test_identity_delta_is_zero(self):
        s = make()
        text = wrap(doc(
            total=3, success=1,
            fails=(("alice", (1, 1, 1, 1)),),
            users=(("alice", (1, 0, 0, 5)),),
            templates=(("gold", (1, 0, 0, 5)),),
        ))
        out = parse(s.stats_delta(text, text))
        self.assertEqual(out["建立"], {"总数": 0, "成功": 0, "成功率万分比": 0})
        self.assertEqual(out["用户失败"], [])
        self.assertEqual(out["用户计量"], [])
        self.assertEqual(out["模板计量"], [])
        self.assertEqual(out["摘要"], out_digest(out))

    def test_success_rate_is_floor_permyriad(self):
        s = make()
        cases = [(0, 0, 0), (3, 1, 3333), (3, 3, 10000), (7, 2, 2857)]
        for total, success, rate in cases:
            with self.subTest(total=total, success=success):
                out = parse(s.stats_delta(
                    wrap(doc()), wrap(doc(total=total, success=success))
                ))
                self.assertEqual(
                    out["建立"],
                    {"总数": total, "成功": success, "成功率万分比": rate},
                )

    def test_state_error_negative_and_overflow(self):
        s = make()
        cases = [
            # 总数回退。
            (doc(total=5, success=2), doc(total=4, success=2)),
            # 成功回退。
            (doc(total=5, success=3), doc(total=5, success=2)),
            # 成功增量大于总数增量。
            (doc(total=5, success=2), doc(total=6, success=5)),
            # base 有非零而 current 缺失：缺失计 0 即负差。
            (doc(users=(("bob", (1, 0, 0, 0)),)), doc()),
            # 失败单计数回退。
            (doc(fails=(("alice", (2, 0, 0, 0)),)),
             doc(fails=(("alice", (1, 0, 0, 0)),))),
            # 计量单计数回退（另一计数增长）。
            (doc(users=(("alice", (1, 1, 0, 0)),)),
             doc(users=(("alice", (2, 0, 0, 0)),))),
            # 模板计量回退。
            (doc(templates=(("gold", (1, 0, 0, 0)),)),
             doc(templates=(("gold", (0, 0, 0, 0)),))),
        ]
        for b, c in cases:
            with self.subTest():
                with self.assertRaises(StateError) as ctx:
                    s.stats_delta(wrap(b), wrap(c))
                self.assertEqual(str(ctx.exception), "current")

    def test_resource_error_unknown_users(self):
        s = make()
        good = wrap(doc())
        bad_fail = wrap(doc(fails=(("ghost", (1, 0, 0, 0)),)))
        bad_meter = wrap(doc(users=(("ghost", (1, 0, 0, 0)),)))
        with self.assertRaises(ResourceError):
            s.stats_delta(bad_fail, good)
        with self.assertRaises(ResourceError):
            s.stats_delta(good, bad_fail)
        with self.assertRaises(ResourceError):
            s.stats_delta(bad_meter, good)
        with self.assertRaises(ResourceError):
            s.stats_delta(good, bad_meter)
        # 模板计量不验引用。
        tmpl = wrap(doc(templates=(("bronze", (1, 2, 3, 4)),)))
        out = parse(s.stats_delta(good, tmpl))
        self.assertEqual(out["模板计量"][0]["标识"], "bronze")

    def test_value_errors_malformed_texts(self):
        s = make()
        good = wrap(doc())
        bad_texts = ["", "{", "[]", "1", '"x"', "null"]
        wrong = json.loads(good)
        wrong["摘要"] = "0" * 64
        bad_texts.append(json.dumps(wrong, ensure_ascii=False) + "\n")
        for idx in (0, 1):
            for bad in bad_texts:
                params = [good, good]
                params[idx] = bad
                with self.subTest(idx=idx, bad=bad):
                    with self.assertRaises(ValueError):
                        s.stats_delta(*params)

    def test_type_errors(self):
        s = make()
        good = wrap(doc())
        for bad in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.stats_delta(bad, good)
            with self.assertRaises(TypeError):
                s.stats_delta(good, bad)

    def test_error_precedence_parse_then_reference_then_state(self):
        s = make()
        # 解析错先于引用错。
        with self.assertRaises(ValueError):
            s.stats_delta("{", wrap(doc(fails=(("ghost", (1, 0, 0, 0)),))))
        # 引用错先于增量语义错（负差也同时存在）。
        with self.assertRaises(ResourceError):
            s.stats_delta(
                wrap(doc(fails=(("ghost", (9, 0, 0, 0)),))),
                wrap(doc(fails=(("ghost", (1, 0, 0, 0)),))),
            )

    def test_does_not_change_state_or_audit(self):
        s = make()
        before = s.stats_checkpoint()
        before_audit = len(parse(s.audit())["事件"])
        s.stats_delta(wrap(doc(total=1, success=1)), wrap(doc(total=2, success=2)))
        # 非法调用同样不改态。
        with self.assertRaises(StateError):
            s.stats_delta(wrap(doc(total=2, success=1)), wrap(doc(total=1, success=1)))
        self.assertEqual(s.stats_checkpoint(), before)
        self.assertEqual(len(parse(s.audit())["事件"]), before_audit)

    def test_deterministic_lf_terminated_compact_bytes(self):
        s = make()
        base = wrap(doc(total=1, success=1))
        current = wrap(doc(
            total=4, success=3,
            users=(("alice", (1, 0, 0, 5)),),
            templates=(("gold", (1, 0, 0, 5)),),
        ))
        first = s.stats_delta(base, current)
        self.assertTrue(first.endswith("\n"))
        self.assertEqual(first, s.stats_delta(base, current))
        self.assertEqual(first, s.stats_delta(base, current))
        # 紧凑：无 ", " / ": "；ensure_ascii=False 直出非 ASCII。
        self.assertNotIn(", ", first)
        self.assertNotIn(": ", first)
        cjk = s.stats_delta(
            wrap(doc()),
            wrap(doc(templates=(("金牌", (1, 0, 0, 1)),))),
        )
        self.assertIn("金牌", cjk)


if __name__ == "__main__":
    unittest.main()
