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


EMPTY = wrap(
    {
        "版本": 1,
        "建立": {"总数": 0, "成功": 0},
        "用户失败": [],
        "用户计量": [],
        "模板计量": [],
    }
)

# 同源基线：alice 两次尝试一次成功、一次认证失败；alice 计量通过 1/100 字节；
# gold 模板计量通过 1/100 字节。
BASE = {
    "版本": 1,
    "建立": {"总数": 2, "成功": 1},
    "用户失败": [
        {"用户": "alice", "认证": 1, "资源": 0, "状态": 0, "后端": 0},
    ],
    "用户计量": [
        {"标识": "alice", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 100},
    ],
    "模板计量": [
        {"标识": "gold", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 100},
    ],
}
# left 支线：alice 新增一次成功（计量 +1/+50），bob 新增一次成功（1/10），
# gold 通过 2/160；建立 3/2。
LEFT = {
    "版本": 1,
    "建立": {"总数": 3, "成功": 2},
    "用户失败": [
        {"用户": "alice", "认证": 1, "资源": 0, "状态": 0, "后端": 0},
    ],
    "用户计量": [
        {"标识": "alice", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 150},
        {"标识": "bob", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 10},
    ],
    "模板计量": [
        {"标识": "gold", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 160},
    ],
}
# right 支线：alice 新增一次认证失败（建立 +1/成功不增），计量不变。
RIGHT = {
    "版本": 1,
    "建立": {"总数": 3, "成功": 1},
    "用户失败": [
        {"用户": "alice", "认证": 2, "资源": 0, "状态": 0, "后端": 0},
    ],
    "用户计量": [
        {"标识": "alice", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 100},
    ],
    "模板计量": [
        {"标识": "gold", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 100},
    ],
}


class StatsMergeTest(unittest.TestCase):
    def test_merge_counts_are_left_plus_right_minus_base(self):
        s = make()
        out = parse(s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(RIGHT)))
        # 建立：3 + 3 - 2 = 4；成功：2 + 1 - 1 = 2。
        self.assertEqual(out["建立"], {"总数": 4, "成功": 2})
        # alice 认证失败：1 + 2 - 1 = 2。
        self.assertEqual(
            out["用户失败"],
            [{"用户": "alice", "认证": 2, "资源": 0, "状态": 0, "后端": 0}],
        )
        # alice：2 + 1 - 1 = 2、150 + 100 - 100 = 150；bob 仅 left：1/10。
        self.assertEqual(
            out["用户计量"],
            [
                {"标识": "alice", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 150},
                {"标识": "bob", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 10},
            ],
        )
        # gold：2 + 1 - 1 = 2、160 + 100 - 100 = 160。
        self.assertEqual(
            out["模板计量"],
            [{"标识": "gold", "通过": 2, "拒绝": 0, "下线": 0, "通过字节": 160}],
        )
        self.assertEqual(out["摘要"], digest(out))

    def test_result_equals_canonical_checkpoint_and_is_replayable(self):
        s = make()
        result = s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(RIGHT))
        # 返回 stats_checkpoint() 的 LF 尾基线 JSON，实例统计即合并结果。
        self.assertTrue(result.endswith("\n"))
        self.assertEqual(result, s.stats_checkpoint())
        # 同型同四参重放返回首次规范包原字节。
        self.assertEqual(
            s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(RIGHT)), result
        )

    def test_identical_three_way_is_identity(self):
        s = make()
        text = wrap(BASE)
        self.assertEqual(s.stats_merge("m1", text, text, text), text)
        self.assertEqual(s.stats_checkpoint(), text)

    def test_empty_triple_yields_empty_checkpoint(self):
        s = make()
        self.assertEqual(s.stats_merge("m1", EMPTY, EMPTY, EMPTY), EMPTY)

    def test_missing_identifier_counts_as_zero(self):
        s = make()
        # carol 仅 right 有非零计数（base/left 缺行视 0）：合并为其原值。
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户计量"].append(
            {"标识": "carol", "通过": 3, "拒绝": 0, "下线": 0, "通过字节": 9}
        )
        out = parse(s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(right)))
        rows = {row["标识"]: row for row in out["用户计量"]}
        self.assertEqual(
            rows["carol"],
            {"标识": "carol", "通过": 3, "拒绝": 0, "下线": 0, "通过字节": 9},
        )
        # 标识仅出现在 left 同样保留：bob 合并后仍为 1/10。
        self.assertEqual(rows["bob"]["通过"], 1)

    def test_union_sorted_by_codepoint_with_zero_rows_omitted(self):
        s = make()
        # carol 行合并后全 0（仅 right 列出且全 0）须省略；bronze 模板仅
        # right 有非零下线，按码点与 gold 取并集升序。
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户计量"].append(
            {"标识": "carol", "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0}
        )
        right["模板计量"].insert(
            0,
            {"标识": "bronze", "通过": 0, "拒绝": 0, "下线": 1, "通过字节": 0},
        )
        out = parse(s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(right)))
        self.assertEqual(
            [row["标识"] for row in out["用户计量"]], ["alice", "bob"]
        )
        self.assertEqual(
            [row["标识"] for row in out["模板计量"]], ["bronze", "gold"]
        )

    def test_establish_regression_state_errors(self):
        s = make()
        cases = [
            ("left", "建立", {"总数": 1, "成功": 1}, dict(RIGHT["建立"])),
            ("right", "建立", dict(LEFT["建立"]), {"总数": 1, "成功": 1}),
            # 成功倒退：base 成功 1，支线成功 0。
            ("left", "建立", {"总数": 3, "成功": 0}, dict(RIGHT["建立"])),
            ("right", "建立", dict(LEFT["建立"]), {"总数": 3, "成功": 0}),
            # 成功增量 > 总数增量：支线总数 +1 而成功 +2（base 2/1 -> 3/3）。
            ("left", "建立", {"总数": 3, "成功": 3}, dict(RIGHT["建立"])),
            ("right", "建立", dict(LEFT["建立"]), {"总数": 3, "成功": 3}),
        ]
        for side, _field, l_est, r_est in cases:
            with self.subTest(side=side, l=l_est, r=r_est):
                s2 = make()
                left = json.loads(json.dumps(LEFT, ensure_ascii=False))
                right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
                left["建立"] = l_est
                right["建立"] = r_est
                with self.assertRaises(StateError) as ctx:
                    s2.stats_merge("m", wrap(BASE), wrap(left), wrap(right))
                self.assertEqual(ctx.exception.args, (side,))

    def test_row_regression_state_errors(self):
        s = make()
        # left 缺失 alice 失败行（0 < base 1）-> StateError("left")。
        left = json.loads(json.dumps(LEFT, ensure_ascii=False))
        left["用户失败"] = []
        with self.assertRaises(StateError) as ctx:
            s.stats_merge("m1", wrap(BASE), wrap(left), wrap(RIGHT))
        self.assertEqual(ctx.exception.args, ("left",))

        # right 的 alice 失败认证 0 < base 1 -> StateError("right")。
        s2 = make()
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户失败"][0]["认证"] = 0
        with self.assertRaises(StateError) as ctx:
            s2.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(right))
        self.assertEqual(ctx.exception.args, ("right",))

        # 计量分量倒退：right 通过字节 50 < base 100。
        s3 = make()
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户计量"][0]["通过字节"] = 50
        with self.assertRaises(StateError) as ctx:
            s3.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(right))
        self.assertEqual(ctx.exception.args, ("right",))

        # 模板计量倒退：left gold 通过 0 < base 1。
        s4 = make()
        left = json.loads(json.dumps(LEFT, ensure_ascii=False))
        left["模板计量"][0]["通过"] = 0
        with self.assertRaises(StateError) as ctx:
            s4.stats_merge("m1", wrap(BASE), wrap(left), wrap(RIGHT))
        self.assertEqual(ctx.exception.args, ("left",))

    def test_left_checked_before_right(self):
        s = make()
        # 两侧同时倒退：必须报 left。
        left = json.loads(json.dumps(LEFT, ensure_ascii=False))
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        left["建立"] = {"总数": 0, "成功": 0}
        right["建立"] = {"总数": 0, "成功": 0}
        with self.assertRaises(StateError) as ctx:
            s.stats_merge("m1", wrap(BASE), wrap(left), wrap(right))
        self.assertEqual(ctx.exception.args, ("left",))

    def test_unknown_users_are_resource_errors(self):
        s = make()
        # 用户失败含未知用户（base）。
        base = json.loads(json.dumps(BASE, ensure_ascii=False))
        base["用户失败"].append(
            {"用户": "zzz", "认证": 1, "资源": 0, "状态": 0, "后端": 0}
        )
        with self.assertRaises(ResourceError):
            s.stats_merge("m1", wrap(base), wrap(LEFT), wrap(RIGHT))

        # 用户计量含未知用户（left）。
        s2 = make()
        left = json.loads(json.dumps(LEFT, ensure_ascii=False))
        left["用户计量"].append(
            {"标识": "zzz", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 0}
        )
        with self.assertRaises(ResourceError):
            s2.stats_merge("m1", wrap(BASE), wrap(left), wrap(RIGHT))

        # 用户计量含未知用户（right），模板未知标识不验。
        s3 = make()
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户计量"].append(
            {"标识": "yyy", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 0}
        )
        right["模板计量"].insert(
            0,
            {"标识": "bronze", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 0},
        )
        with self.assertRaises(ResourceError):
            s3.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(right))

    def test_template_references_not_validated(self):
        s = make()
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["模板计量"].insert(
            0,
            {"标识": "bronze", "通过": 0, "拒绝": 0, "下线": 1, "通过字节": 0},
        )
        out = parse(s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(right)))
        self.assertEqual(
            [row["标识"] for row in out["模板计量"]], ["bronze", "gold"]
        )

    def test_malformed_checkpoint_texts_are_value_errors(self):
        s = make()
        good = wrap(BASE)
        wrong_digest = good[:-5] + "00000\n"
        bad_version = json.loads(good)
        bad_version["版本"] = 2
        bad_version = json.dumps(bad_version, ensure_ascii=False) + "\n"
        bad_cases = [
            ("", good, good),
            ("{", good, good),
            (good, "[]", good),
            (good, good, wrong_digest),
            (bad_version, good, good),
        ]
        for base, left, right in bad_cases:
            with self.subTest(base=base[:12], left=left[:12], right=right[:12]):
                with self.assertRaises(ValueError):
                    make().stats_merge("m", base, left, right)

    def test_parse_errors_precede_registration_and_divergence(self):
        s = make()
        # left 文本非法（ValueError）先于 right 的未知用户（ResourceError）。
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户计量"].append(
            {"标识": "zzz", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 0}
        )
        with self.assertRaises(ValueError):
            s.stats_merge("m1", wrap(BASE), "not json", wrap(right))
        # 注册校验（ResourceError）先于支线分歧（StateError）。
        s2 = make()
        base = json.loads(json.dumps(BASE, ensure_ascii=False))
        base["用户失败"].append(
            {"用户": "zzz", "认证": 1, "资源": 0, "状态": 0, "后端": 0}
        )
        left = json.loads(json.dumps(LEFT, ensure_ascii=False))
        left["建立"] = {"总数": 0, "成功": 0}
        with self.assertRaises(ResourceError):
            s2.stats_merge("m1", wrap(base), wrap(left), wrap(RIGHT))

    def test_type_errors(self):
        s = make()
        good = wrap(BASE)
        left = wrap(LEFT)
        right = wrap(RIGHT)
        for bad_key in (1, True, None, b"m1"):
            with self.assertRaises(TypeError):
                s.stats_merge(bad_key, good, left, right)
        for bad in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.stats_merge("m1", bad, left, right)
            with self.assertRaises(TypeError):
                s.stats_merge("m1", good, bad, right)
            with self.assertRaises(TypeError):
                s.stats_merge("m1", good, left, bad)

    def test_key_value_error_precedes_text_type_error(self):
        # key 取值错（空串）先于文本类型错抛 ValueError。
        with self.assertRaises(ValueError):
            make().stats_merge("", None, None, None)

    def test_failure_changes_neither_stats_nor_cache(self):
        s = make()
        before = s.stats_checkpoint()
        left = json.loads(json.dumps(LEFT, ensure_ascii=False))
        left["建立"] = {"总数": 0, "成功": 0}
        with self.assertRaises(StateError):
            s.stats_merge("m1", wrap(BASE), wrap(left), wrap(RIGHT))
        with self.assertRaises(ValueError):
            s.stats_merge("m2", "nope", wrap(LEFT), wrap(RIGHT))
        right = json.loads(json.dumps(RIGHT, ensure_ascii=False))
        right["用户计量"].append(
            {"标识": "zzz", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 0}
        )
        with self.assertRaises(ResourceError):
            s.stats_merge("m3", wrap(BASE), wrap(LEFT), wrap(right))
        self.assertEqual(s.stats_checkpoint(), before)
        # 失败不占 key：各 key 随即首次成功。
        self.assertEqual(s.stats_merge("m1", EMPTY, EMPTY, EMPTY), EMPTY)
        self.assertEqual(s.stats_merge("m2", EMPTY, EMPTY, EMPTY), EMPTY)
        self.assertEqual(s.stats_merge("m3", EMPTY, EMPTY, EMPTY), EMPTY)

    def test_replay_hetero_params_and_independent_domain(self):
        s = make()
        result = s.stats_merge("shared", wrap(BASE), wrap(LEFT), wrap(RIGHT))
        self.assertEqual(
            s.stats_merge("shared", wrap(BASE), wrap(LEFT), wrap(RIGHT)), result
        )
        # 异型先按异参 ValueError，而非 TypeError。
        with self.assertRaises(ValueError):
            s.stats_merge("shared", None, wrap(LEFT), wrap(RIGHT))
        # 任一参数不同即异参。
        with self.assertRaises(ValueError):
            s.stats_merge("shared", EMPTY, wrap(LEFT), wrap(RIGHT))
        with self.assertRaises(ValueError):
            s.stats_merge("shared", wrap(BASE), wrap(RIGHT), wrap(LEFT))
        # 与 stats_restore 域独立：同名 key 在两域各首次使用。
        s.stats_restore("shared", EMPTY)
        # restore 已把实例统计清空，merge 重放仍返回首次缓存原字节。
        self.assertEqual(s.stats_checkpoint(), EMPTY)
        self.assertEqual(
            s.stats_merge("shared", wrap(BASE), wrap(LEFT), wrap(RIGHT)), result
        )

    def test_merged_counts_feed_other_stats_without_touching_sessions(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(RIGHT))
        # 会话域不变：既有会话仍在线。
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")
        runtime = parse(s.runtime_stats(0))
        self.assertEqual(
            runtime["建立"], {"总数": 4, "成功": 2, "成功率万分比": 5000}
        )
        self.assertEqual(
            runtime["失败"],
            [
                {"类型": "认证", "次数": 2},
                {"类型": "资源", "次数": 0},
                {"类型": "状态", "次数": 0},
                {"类型": "后端", "次数": 0},
            ],
        )

    def test_no_aging_and_no_audit(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        before_audit = len(parse(s.audit())["事件"])
        before_takeover = len(parse(s.takeover_audit())["事件"])
        s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(RIGHT))
        # 重放亦不老化、不审计。
        s.stats_merge("m1", wrap(BASE), wrap(LEFT), wrap(RIGHT))
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")
        self.assertEqual(len(parse(s.audit())["事件"]), before_audit)
        self.assertEqual(len(parse(s.takeover_audit())["事件"]), before_takeover)


if __name__ == "__main__":
    unittest.main()
