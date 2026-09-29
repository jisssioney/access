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


class StatsMergeTest(unittest.TestCase):
    def test_basic_three_way_arithmetic(self):
        s = make()
        base = wrap(doc(
            total=2, success=1,
            fails=(("alice", (1, 0, 0, 0)),),
            users=(("alice", (1, 0, 0, 100)),),
            templates=(("gold", (1, 0, 0, 100)),),
        ))
        left = wrap(doc(
            total=3, success=2,
            fails=(("alice", (1, 0, 0, 0)),),
            users=(("alice", (2, 0, 0, 200)),),
            templates=(("gold", (2, 0, 0, 200)),),
        ))
        right = wrap(doc(
            total=4, success=3,
            fails=(("alice", (1, 0, 0, 0)), ("bob", (0, 1, 0, 0))),
            users=(("alice", (1, 0, 0, 100)), ("bob", (1, 0, 0, 50))),
            templates=(("gold", (1, 0, 0, 100)), ("kill", (1, 0, 0, 10))),
        ))
        out = parse(s.stats_merge("mg", base, left, right))
        self.assertEqual(out["建立"], {"总数": 5, "成功": 4})
        self.assertEqual(
            out["用户失败"],
            [
                {"用户": "alice", "认证": 1, "资源": 0, "状态": 0, "后端": 0},
                {"用户": "bob", "认证": 0, "资源": 1, "状态": 0, "后端": 0},
            ],
        )
        self.assertEqual(
            out["用户计量"],
            [
                {"标识": "alice", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 200},
                {"标识": "bob", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 50},
            ],
        )
        self.assertEqual(
            out["模板计量"],
            [
                {"标识": "gold", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 200},
                {"标识": "kill", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 10},
            ],
        )
        # 返回值即合并后 stats_checkpoint()，LF 结尾。
        merged = s.stats_merge("mg2", base, left, right)
        self.assertEqual(merged, s.stats_checkpoint())
        self.assertTrue(merged.endswith("\n"))

    def test_independent_counter_growth_per_branch(self):
        s = make()
        # 左支增“通过”、右支增“拒绝”，结果两者皆有。
        base = wrap(doc(users=(("alice", (0, 0, 0, 0)),)))
        left = wrap(doc(total=1, success=1, users=(("alice", (1, 0, 0, 0)),)))
        right = wrap(doc(
            total=1, success=0,
            users=(("alice", (0, 1, 0, 0)),),
        ))
        out = parse(s.stats_merge("mg", base, left, right))
        self.assertEqual(out["建立"], {"总数": 2, "成功": 1})
        self.assertEqual(
            out["用户计量"],
            [{"标识": "alice", "通过": 1, "拒绝": 1, "下线": 0, "通过字节": 0}],
        )

    def test_missing_identifier_counts_as_zero(self):
        s = make()
        # bob 仅左支新增；base/right 缺失计 0，结果取左支值。
        base = wrap(doc())
        left = wrap(doc(
            total=1, success=1,
            users=(("bob", (1, 0, 0, 7)),),
            templates=(("gold", (1, 0, 0, 7)),),
        ))
        right = wrap(doc())
        out = parse(s.stats_merge("mg", base, left, right))
        self.assertEqual(
            out["用户计量"],
            [{"标识": "bob", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 7}],
        )
        self.assertEqual(
            out["模板计量"],
            [{"标识": "gold", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 7}],
        )

    def test_all_zero_rows_omitted_and_sorted_by_codepoint(self):
        s = make()
        # 显式全 0 行（解析契约允许）进入并集但结果全 0，须省略。
        base = wrap(doc(users=(
            ("alice", (0, 0, 0, 0)),
            ("carol", (1, 0, 0, 0)),
        )))
        # 左支新增 carol 推进与非 ASCII 模板行；éve 行全 0 须省略，zinc 与
        # 金牌行非零须按 Unicode 码点升序（z < é < 金，éve 省后剩 zinc/金牌）。
        left = wrap(doc(
            total=1, success=1,
            users=(
                ("alice", (0, 0, 0, 0)),
                ("carol", (1, 0, 0, 0)),
            ),
            templates=(
                ("zinc", (1, 0, 0, 3)),
                ("éve", (0, 0, 0, 0)),
                ("金牌", (1, 0, 0, 5)),
            ),
        ))
        right = wrap(doc(users=(
            ("alice", (0, 0, 0, 0)),
            ("carol", (2, 0, 0, 0)),
        )))
        out = parse(s.stats_merge("mg", base, left, right))
        self.assertEqual(out["用户失败"], [])
        self.assertEqual(
            [r["标识"] for r in out["用户计量"]], ["carol"]
        )
        self.assertEqual(
            out["用户计量"][0],
            {"标识": "carol", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 0},
        )
        self.assertEqual(
            [r["标识"] for r in out["模板计量"]], ["zinc", "金牌"]
        )
        self.assertEqual(
            out["模板计量"][1],
            {"标识": "金牌", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 5},
        )

    def test_full_atomic_replace_drops_unmentioned_stats(self):
        s = make()
        # 预置 carol 的失败与计量；合并结果不含 carol，须整体清除。
        preset = wrap(doc(
            total=3, success=3,
            fails=(("carol", (1, 1, 1, 1)),),
            users=(("carol", (5, 5, 5, 5)),),
        ))
        s.stats_restore("r0", preset)
        base = wrap(doc())
        left = wrap(doc(total=1, success=1, fails=(("alice", (0, 0, 0, 0)),)))
        right = wrap(doc())
        out = parse(s.stats_merge("mg", base, left, right))
        self.assertEqual(out["建立"], {"总数": 1, "成功": 1})
        self.assertEqual(out["用户失败"], [])
        self.assertEqual(out["用户计量"], [])
        self.assertEqual(out["模板计量"], [])
        self.assertEqual(parse(s.user_stats("carol", 0))["失败"], [
            {"类型": "认证", "次数": 0},
            {"类型": "资源", "次数": 0},
            {"类型": "状态", "次数": 0},
            {"类型": "后端", "次数": 0},
        ])

    def test_state_error_left_regressions(self):
        s = make()
        cases = [
            # 建立总数回退。
            (doc(total=2, success=1), doc(total=1, success=1), doc(total=2, success=1)),
            # 建立成功回退。
            (doc(total=2, success=1), doc(total=2, success=0), doc(total=2, success=1)),
            # 成功增量大于总数增量。
            (doc(total=2, success=0), doc(total=2, success=1), doc(total=2, success=0)),
            # 用户失败计数回退。
            (doc(fails=(("alice", (2, 0, 0, 0)),)),
             doc(fails=(("alice", (1, 0, 0, 0)),)),
             doc(fails=(("alice", (2, 0, 0, 0)),))),
            # 用户计量单计数回退（另一计数增长）。
            (doc(users=(("alice", (1, 1, 0, 0)),)),
             doc(users=(("alice", (2, 0, 0, 0)),)),
             doc(users=(("alice", (1, 1, 0, 0)),))),
            # 模板计量回退。
            (doc(templates=(("gold", (1, 0, 0, 0)),)),
             doc(templates=(("gold", (0, 0, 0, 0)),)),
             doc(templates=(("gold", (1, 0, 0, 0)),))),
            # 分支缺失标识按 0：base 有非零行而 left 缺失即回退。
            (doc(fails=(("bob", (1, 0, 0, 0)),)), doc(),
             doc(fails=(("bob", (1, 0, 0, 0)),))),
        ]
        for b, l, r in cases:
            with self.subTest(kind="left"):
                with self.assertRaises(StateError) as ctx:
                    s.stats_merge("mg", wrap(b), wrap(l), wrap(r))
                self.assertEqual(str(ctx.exception), "left")

    def test_state_error_right_regressions(self):
        s = make()
        base = wrap(doc(total=2, success=1, fails=(("alice", (1, 0, 0, 0)),)))
        # left 正常推进，right 回退。
        left = wrap(doc(total=3, success=2, fails=(("alice", (1, 0, 0, 0)),)))
        right_bad_total = wrap(doc(total=1, success=1, fails=(("alice", (1, 0, 0, 0)),)))
        with self.assertRaises(StateError) as ctx:
            s.stats_merge("mg1", base, left, right_bad_total)
        self.assertEqual(str(ctx.exception), "right")
        right_bad_fail = wrap(doc(total=3, success=2, fails=(("alice", (0, 0, 0, 0)),)))
        with self.assertRaises(StateError) as ctx:
            s.stats_merge("mg2", base, left, right_bad_fail)
        self.assertEqual(str(ctx.exception), "right")
        # 两侧皆回退时先报 left。
        with self.assertRaises(StateError) as ctx:
            s.stats_merge("mg3", base, right_bad_total, right_bad_fail)
        self.assertEqual(str(ctx.exception), "left")

    def test_resource_error_unknown_users(self):
        s = make()
        good = wrap(doc())
        bad_fail = wrap(doc(fails=(("ghost", (1, 0, 0, 0)),)))
        bad_meter = wrap(doc(users=(("ghost", (1, 0, 0, 0)),)))
        self._expect_resource(good, bad_fail, good)
        self._expect_resource(good, good, bad_fail)
        self._expect_resource(bad_fail, good, good)
        self._expect_resource(good, bad_meter, good)
        self._expect_resource(bad_meter, good, good)
        self._expect_resource(good, good, bad_meter)
        # 模板计量不验引用：三文本均可含未知模板。
        tmpl = wrap(doc(templates=(("bronze", (1, 2, 3, 4)),)))
        out = parse(s.stats_merge("ok", tmpl, tmpl, tmpl))
        self.assertEqual(out["模板计量"][0]["标识"], "bronze")

    def _expect_resource(self, base, left, right):
        s = make()
        with self.assertRaises(ResourceError):
            s.stats_merge("mg", base, left, right)

    def test_value_errors_malformed_texts(self):
        s = make()
        good = wrap(doc())
        bad_texts = ["", "{", "[]", "1", '"x"', "null"]
        # 错误摘要（合法排版但摘要对不上）。
        wrong = json.loads(good)
        wrong["摘要"] = "0" * 64
        bad_texts.append(json.dumps(wrong, ensure_ascii=False) + "\n")
        for name, idx in (("base", 0), ("left", 1), ("right", 2)):
            for bad in bad_texts:
                params = [good, good, good]
                params[idx] = bad
                with self.subTest(name=name, bad=bad):
                    with self.assertRaises(ValueError):
                        s.stats_merge("mg", *params)

    def test_type_errors(self):
        s = make()
        good = wrap(doc())
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.stats_merge(bad_key, good, good, good)
        # 空串 key 为取值错 ValueError。
        with self.assertRaises(ValueError):
            s.stats_merge("", good, good, good)
        for idx in range(3):
            for bad in (None, 1, True, b"x", [], {}):
                params = [good, good, good]
                params[idx] = bad
                with self.assertRaises(TypeError):
                    s.stats_merge("k", *params)

    def test_failure_changes_neither_stats_nor_cache(self):
        s = make()
        before = s.stats_checkpoint()
        good = wrap(doc())
        bad = wrap(doc(fails=(("ghost", (1, 0, 0, 0)),)))
        with self.assertRaises(ResourceError):
            s.stats_merge("mg", bad, good, good)
        with self.assertRaises(ValueError):
            s.stats_merge("mg", "{", good, good)
        with self.assertRaises(TypeError):
            s.stats_merge("mg", None, good, good)
        with self.assertRaises(StateError):
            s.stats_merge(
                "mg",
                wrap(doc(total=2, success=1)),
                wrap(doc(total=1, success=1)),
                good,
            )
        self.assertEqual(s.stats_checkpoint(), before)
        # 失败不占 key：同 key 首次合法合并成功。
        out = s.stats_merge("mg", good, good, good)
        self.assertEqual(out, before)

    def test_replay_same_params_returns_cached_bytes(self):
        s = make()
        base = wrap(doc())
        left = wrap(doc(total=1, success=1))
        right = wrap(doc(total=2, success=2))
        expected = wrap(doc(total=3, success=3))
        first = s.stats_merge("mg", base, left, right)
        self.assertEqual(first, expected)
        # 同型同四参重放不解析、不替换，逐字节相同。
        self.assertIs(s.stats_merge("mg", base, left, right), first)
        self.assertEqual(s.stats_merge("mg", base, left, right), first)
        # 随后实例统计被清空，重放仍返回首次缓存原字节。
        s.stats_restore("r1", wrap(doc()))
        self.assertEqual(s.stats_checkpoint(), wrap(doc()))
        self.assertEqual(s.stats_merge("mg", base, left, right), first)
        self.assertEqual(s.stats_checkpoint(), wrap(doc()))

    def test_replay_different_params_is_value_error(self):
        s = make()
        base = wrap(doc())
        left = wrap(doc(total=1, success=1))
        right = wrap(doc(total=2, success=2))
        s.stats_merge("mg", base, left, right)
        other = wrap(doc(total=9, success=9))
        with self.assertRaises(ValueError):
            s.stats_merge("mg", other, left, right)
        with self.assertRaises(ValueError):
            s.stats_merge("mg", base, other, right)
        with self.assertRaises(ValueError):
            s.stats_merge("mg", base, left, other)
        # 异型按异参 ValueError，而非 TypeError。
        with self.assertRaises(ValueError):
            s.stats_merge("mg", None, left, right)
        with self.assertRaises(ValueError):
            s.stats_merge("mg", base, left, 1)

    def test_cache_independent_from_restore_domain(self):
        s = make()
        empty = wrap(doc())
        left = wrap(doc(total=1, success=1))
        # 同名 key 在两域各首次使用、互不干扰。
        self.assertEqual(s.stats_merge("shared", empty, left, empty), left)
        self.assertEqual(s.stats_restore("shared", empty), empty)
        self.assertEqual(s.stats_merge("shared", empty, left, empty), left)
        self.assertEqual(s.stats_restore("shared", empty), empty)
        # 异参只影响各自域。
        with self.assertRaises(ValueError):
            s.stats_merge("shared", left, left, empty)
        with self.assertRaises(ValueError):
            s.stats_restore("shared", left)

    def test_distinct_keys_distinct_merges(self):
        s = make()
        base = wrap(doc())
        left = wrap(doc(total=1, success=1))
        right = wrap(doc(total=2, success=2))
        first = s.stats_merge("mg1", base, left, right)
        second = s.stats_merge("mg2", base, left, right)
        self.assertEqual(first, second)
        self.assertEqual(first, wrap(doc(total=3, success=3)))

    def test_noncanonical_formatting_accepted(self):
        s = make()
        d = doc(total=1, success=1)
        d["摘要"] = digest(d)
        pretty = json.dumps(d, ensure_ascii=False, indent=2)  # 宽松排版、无 LF
        canonical = json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n"
        out = s.stats_merge("mg", pretty, pretty, pretty)
        self.assertEqual(out, canonical)

    def test_no_aging_no_auth_no_audit(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before_audit = len(parse(s.audit())["事件"])
        before_takeover = len(parse(s.takeover_audit())["事件"])
        cp = s.stats_checkpoint()
        out = s.stats_merge("mg", cp, cp, cp)
        self.assertEqual(out, cp)
        # 不老化：既有会话仍在线。
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")
        # 合并不写任何审计链。
        self.assertEqual(len(parse(s.audit())["事件"]), before_audit)
        self.assertEqual(len(parse(s.takeover_audit())["事件"]), before_takeover)

    def test_identity_merge_against_self(self):
        s = make()
        cp = wrap(doc(
            total=4, success=3,
            fails=(("alice", (1, 0, 0, 0)),),
            users=(
                ("alice", (1, 0, 0, 100)),
                ("bob", (0, 0, 1, 0)),
            ),
            templates=(("gold", (1, 0, 0, 100)),),
        ))
        # base=left=right：结果计数 c+c-c=c。
        out = s.stats_merge("mg", cp, cp, cp)
        self.assertEqual(out, cp)


if __name__ == "__main__":
    unittest.main()
