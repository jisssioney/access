import hashlib
import json
import unittest

from access import Authenticator, ResourceError, Sessions


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


def populated():
    s = make()
    s.do("k1", "建立", "s1", ("alice", "pw"), 0)
    s.do("k2", "建立", "s2", ("bob", "pw"), 0)
    s.meter("m1", "s1", 100, 0)   # alice/gold 通过 100
    s.meter("m2", "s2", 11, 2)    # bob/kill 超配额 -> 下线
    try:
        s.do("k3", "建立", "s3", ("alice", "nope"), 0)  # 认证失败
    except Exception:
        pass
    return s


class StatsCheckpointTest(unittest.TestCase):
    def test_empty_baseline(self):
        s = make()
        out = s.stats_checkpoint()
        doc = parse(out)
        self.assertEqual(
            list(doc),
            ["版本", "建立", "用户失败", "用户计量", "模板计量", "摘要"],
        )
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["建立"], {"总数": 0, "成功": 0})
        self.assertEqual(doc["用户失败"], [])
        self.assertEqual(doc["用户计量"], [])
        self.assertEqual(doc["模板计量"], [])
        self.assertEqual(doc["摘要"], digest(doc))
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)

    def test_populated_format_order_and_digest(self):
        s = populated()
        out = s.stats_checkpoint()
        doc = parse(out)
        self.assertEqual(
            list(doc),
            ["版本", "建立", "用户失败", "用户计量", "模板计量", "摘要"],
        )
        self.assertEqual(list(doc["建立"]), ["总数", "成功"])
        self.assertEqual(doc["建立"], {"总数": 3, "成功": 2})
        # 用户失败按用户码点升序，项键序 用户/认证/资源/状态/后端。
        self.assertEqual(
            [list(row) for row in doc["用户失败"]],
            [["用户", "认证", "资源", "状态", "后端"]],
        )
        self.assertEqual(
            doc["用户失败"],
            [{"用户": "alice", "认证": 1, "资源": 0, "状态": 0, "后端": 0}],
        )
        # 计量项键序 标识/通过/拒绝/下线/通过字节，按标识码点升序。
        for rows in (doc["用户计量"], doc["模板计量"]):
            self.assertEqual(
                [list(row) for row in rows],
                [["标识", "通过", "拒绝", "下线", "通过字节"]] * len(rows),
            )
        self.assertEqual(
            doc["用户计量"],
            [
                {"标识": "alice", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 100},
                {"标识": "bob", "通过": 0, "拒绝": 0, "下线": 1, "通过字节": 0},
            ],
        )
        self.assertEqual(
            doc["模板计量"],
            [
                {"标识": "gold", "通过": 1, "拒绝": 0, "下线": 0, "通过字节": 100},
                {"标识": "kill", "通过": 0, "拒绝": 0, "下线": 1, "通过字节": 0},
            ],
        )
        self.assertEqual(doc["摘要"], digest(doc))

    def test_sorted_by_codepoint(self):
        auth = Authenticator(5, 1000)
        for user in ("alice", "zeb", "éve"):
            auth.add(user, "pw")
        s = Sessions(auth, 10, 5, 100000)
        config = {
            "版本": 3,
            "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 100000, "租期毫秒": 100000},
            "地址池": [
                {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
            ],
            "模板": [
                {"标识": "gold", "限速": 1, "突发": 0, "配额": 1000, "超限": "拒绝"}
            ],
            "用户模板": [["alice", "gold"], ["zeb", "gold"], ["éve", "gold"]],
        }
        s.load_config(json.dumps(config, ensure_ascii=False))
        for key, sid, user in (
            ("ka", "sa", "alice"),
            ("kz", "sz", "zeb"),
            ("ke", "se", "éve"),
        ):
            s.do(key, "建立", sid, (user, "pw"), 0)
            s.meter("m" + key, sid, 1, 0)
        doc = parse(s.stats_checkpoint())
        self.assertEqual(
            [r["标识"] for r in doc["用户计量"]], ["alice", "zeb", "éve"]
        )

    def test_unicode_not_escaped(self):
        auth = Authenticator(3, 1000)
        auth.add("张三", "pw")
        s = Sessions(auth, 10, 5, 100000)
        config = {
            "版本": 3,
            "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 100000, "租期毫秒": 100000},
            "地址池": [
                {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
            ],
            "模板": [
                {"标识": "金牌", "限速": 1, "突发": 0, "配额": 1000, "超限": "拒绝"}
            ],
            "用户模板": [["张三", "金牌"]],
        }
        s.load_config(json.dumps(config, ensure_ascii=False))
        s.do("k1", "建立", "s1", ("张三", "pw"), 0)
        s.meter("m1", "s1", 1, 0)
        out = s.stats_checkpoint()
        self.assertIn("张三", out)
        self.assertIn("金牌", out)
        self.assertNotIn("\\u", out)

    def test_byte_stable_and_does_not_age(self):
        s = populated()
        first = s.stats_checkpoint()
        self.assertEqual(s.stats_checkpoint(), first)
        # 只读：不老化，会话仍在线。
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")


class StatsRestoreTest(unittest.TestCase):
    EMPTY = wrap(
        {
            "版本": 1,
            "建立": {"总数": 0, "成功": 0},
            "用户失败": [],
            "用户计量": [],
            "模板计量": [],
        }
    )

    def test_roundtrip_and_byte_stable(self):
        s = populated()
        cp = s.stats_checkpoint()
        self.assertEqual(s.stats_restore("r1", cp), cp)
        self.assertEqual(s.stats_checkpoint(), cp)
        # 同型同 text 重放返回首次规范包原字节。
        self.assertEqual(s.stats_restore("r1", cp), cp)

    def test_restore_is_full_atomic_replace(self):
        s = populated()
        # 仅保留 alice 计量：bob 计量与失败、建立计数全部清除/覆盖。
        doc = {
            "版本": 1,
            "建立": {"总数": 5, "成功": 5},
            "用户失败": [],
            "用户计量": [
                {"标识": "alice", "通过": 9, "拒绝": 8, "下线": 7, "通过字节": 6}
            ],
            "模板计量": [],
        }
        out = parse(s.stats_restore("r1", wrap(doc)))
        self.assertEqual(out["建立"], {"总数": 5, "成功": 5})
        self.assertEqual(out["用户失败"], [])
        self.assertEqual(
            out["用户计量"],
            [{"标识": "alice", "通过": 9, "拒绝": 8, "下线": 7, "通过字节": 6}],
        )
        self.assertEqual(out["模板计量"], [])
        # 空快照清空全部五类统计。
        s.stats_restore("r2", self.EMPTY)
        self.assertEqual(s.stats_checkpoint(), self.EMPTY)

    def test_restored_counts_feed_other_stats(self):
        s = make()
        s.stats_restore("r1", populated().stats_checkpoint())
        runtime = parse(s.runtime_stats(0))
        self.assertEqual(
            runtime["建立"], {"总数": 3, "成功": 2, "成功率万分比": 6666}
        )
        self.assertEqual(
            runtime["失败"],
            [
                {"类型": "认证", "次数": 1},
                {"类型": "资源", "次数": 0},
                {"类型": "状态", "次数": 0},
                {"类型": "后端", "次数": 0},
            ],
        )
        alice = parse(s.user_stats("alice", 0))
        self.assertEqual(alice["失败"][0], {"类型": "认证", "次数": 1})
        user_rows = {r["标识"]: r for r in parse(s.meter_stats(0))["汇总"]}
        self.assertEqual(user_rows["alice"]["通过"], 1)
        self.assertEqual(user_rows["alice"]["通过字节"], 100)
        self.assertEqual(user_rows["bob"]["下线"], 1)
        template_rows = {
            r["标识"]: r for r in parse(s.meter_stats(0, "模板"))["汇总"]
        }
        self.assertEqual(template_rows["gold"]["通过字节"], 100)
        self.assertEqual(template_rows["kill"]["下线"], 1)

    def test_unknown_user_in_failures_is_resource_error(self):
        s = make()
        doc = {
            "版本": 1,
            "建立": {"总数": 0, "成功": 0},
            "用户失败": [
                {"用户": "nobody", "认证": 1, "资源": 0, "状态": 0, "后端": 0}
            ],
            "用户计量": [],
            "模板计量": [],
        }
        with self.assertRaises(ResourceError):
            s.stats_restore("r1", wrap(doc))

    def test_user_meter_unknown_user_is_resource_error(self):
        s = make()
        # 用户计量标识亦须为已注册用户；未知者抛 ResourceError，且统计与
        # 成功缓存均不变。
        doc = {
            "版本": 1,
            "建立": {"总数": 0, "成功": 0},
            "用户失败": [],
            "用户计量": [
                {"标识": "ghost", "通过": 1, "拒绝": 2, "下线": 3, "通过字节": 40}
            ],
            "模板计量": [],
        }
        with self.assertRaises(ResourceError):
            s.stats_restore("r1", wrap(doc))
        # 失败不占 key：同 key 随即首次成功。
        self.assertEqual(s.stats_restore("r1", self.EMPTY), self.EMPTY)

    def test_template_meter_rows_do_not_check_references(self):
        s = make()
        # 模板计量允许当前不存在（含已删）模板标识。
        doc = {
            "版本": 1,
            "建立": {"总数": 0, "成功": 0},
            "用户失败": [],
            "用户计量": [],
            "模板计量": [
                {"标识": "bronze", "通过": 0, "拒绝": 0, "下线": 1, "通过字节": 0}
            ],
        }
        out = parse(s.stats_restore("r1", wrap(doc)))
        self.assertEqual(out["模板计量"][0]["标识"], "bronze")

    def test_success_greater_than_total_is_value_error(self):
        s = make()
        doc = {
            "版本": 1,
            "建立": {"总数": 1, "成功": 2},
            "用户失败": [],
            "用户计量": [],
            "模板计量": [],
        }
        with self.assertRaises(ValueError):
            s.stats_restore("r1", wrap(doc))
        # 临界值合法。
        doc["建立"] = {"总数": 2, "成功": 2}
        s.stats_restore("r2", wrap(doc))

    def test_value_errors(self):
        s = make()

        def fail_doc(**over):
            doc = {
                "版本": 1,
                "建立": {"总数": 0, "成功": 0},
                "用户失败": [],
                "用户计量": [],
                "模板计量": [],
            }
            doc.update(over)
            return doc

        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            '"x"',
            '{"版本":1}',
            # 缺/多/乱序顶层键。
            '{"建立":{"总数":0,"成功":0},"用户失败":[],"用户计量":[],'
            '"模板计量":[],"摘要":"%s"}' % ("0" * 64),
            '{"版本":1,"建立":{"总数":0,"成功":0},"用户失败":[],'
            '"用户计量":[],"模板计量":[],"x":1,"摘要":"%s"}' % ("0" * 64),
            '{"版本":1,"用户失败":[],"建立":{"总数":0,"成功":0},'
            '"用户计量":[],"模板计量":[],"摘要":"%s"}' % ("0" * 64),
            # 版本。
            wrap(fail_doc(**{"版本": "1"})),
            wrap(fail_doc(**{"版本": True})),
            wrap(fail_doc(**{"版本": 0})),
            wrap(fail_doc(**{"版本": 2})),
            # 建立结构。
            wrap({"版本": 1, "建立": [], "用户失败": [], "用户计量": [],
                  "模板计量": []}),
            wrap({"版本": 1, "建立": {"成功": 0, "总数": 0}, "用户失败": [],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0, "成功": -1}, "用户失败": [],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": False, "成功": 0}, "用户失败": [],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0.5, "成功": 0}, "用户失败": [],
                  "用户计量": [], "模板计量": []}),
            # 列表非 list。
            wrap(fail_doc(**{"用户失败": {}})),
            wrap(fail_doc(**{"用户计量": {}})),
            wrap(fail_doc(**{"模板计量": {}})),
            # 失败项键集/键序/类型/值。
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [{"用户": "alice", "认证": 0, "资源": 0,
                              "状态": 0}],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [{"用户": "alice", "后端": 0, "认证": 0,
                              "资源": 0, "状态": 0}],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [{"用户": 1, "认证": 0, "资源": 0,
                              "状态": 0, "后端": 0}],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [{"用户": "alice", "认证": -1, "资源": 0,
                              "状态": 0, "后端": 0}],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [{"用户": "alice", "认证": True, "资源": 0,
                              "状态": 0, "后端": 0}],
                  "用户计量": [], "模板计量": []}),
            # U+0000 与孤代理：以转义写在原始 JSON 中，凭据约束归 ValueError
            # （行校验先于摘要校验，故摘要占位即可）。
            '{"版本":1,"建立":{"总数":0,"成功":0},"用户失败":['
            '{"用户":"a\\u0000","认证":0,"资源":0,"状态":0,"后端":0}],'
            '"用户计量":[],"模板计量":[],"摘要":"%s"}' % ("0" * 64),
            '{"版本":1,"建立":{"总数":0,"成功":0},"用户失败":['
            '{"用户":"\\ud800","认证":0,"资源":0,"状态":0,"后端":0}],'
            '"用户计量":[],"模板计量":[],"摘要":"%s"}' % ("0" * 64),
            # 计量项键集/键序/类型/值。
            wrap(fail_doc(**{"用户计量": [{"标识": "alice", "通过": 0,
                                          "拒绝": 0, "下线": 0}]})),
            wrap(fail_doc(**{"用户计量": [{"标识": "alice", "通过字节": 0,
                                          "通过": 0, "拒绝": 0, "下线": 0}]})),
            wrap(fail_doc(**{"模板计量": [{"标识": 1, "通过": 0, "拒绝": 0,
                                          "下线": 0, "通过字节": 0}]})),
            wrap(fail_doc(**{"模板计量": [{"标识": "gold", "通过": 0, "拒绝": 0,
                                          "下线": 0, "通过字节": -1}]})),
            wrap(fail_doc(**{"模板计量": [{"标识": "gold", "通过": 0.0,
                                          "拒绝": 0, "下线": 0,
                                          "通过字节": 0}]})),
            # 排序/重复。
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [
                      {"用户": "bob", "认证": 0, "资源": 0, "状态": 0, "后端": 0},
                      {"用户": "alice", "认证": 0, "资源": 0, "状态": 0, "后端": 0}],
                  "用户计量": [], "模板计量": []}),
            wrap({"版本": 1, "建立": {"总数": 0, "成功": 0},
                  "用户失败": [
                      {"用户": "alice", "认证": 0, "资源": 0, "状态": 0, "后端": 0},
                      {"用户": "alice", "认证": 0, "资源": 0, "状态": 0, "后端": 0}],
                  "用户计量": [], "模板计量": []}),
            wrap(fail_doc(**{"用户计量": [
                {"标识": "b", "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0},
                {"标识": "a", "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0}]})),
            wrap(fail_doc(**{"模板计量": [
                {"标识": "g", "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0},
                {"标识": "g", "通过": 0, "拒绝": 0, "下线": 0, "通过字节": 0}]})),
            # 重键。
            '{"版本":1,"版本":1,"建立":{"总数":0,"成功":0},"用户失败":[],'
            '"用户计量":[],"模板计量":[],"摘要":"%s"}' % ("0" * 64),
            '{"版本":1,"建立":{"总数":0,"成功":0},"建立":{"总数":0,"成功":0},'
            '"用户失败":[],"用户计量":[],"模板计量":[],"摘要":"%s"}' % ("0" * 64),
            # 摘要形态/值错。
            wrap(fail_doc())[:-65] + "0" * 63 + "\n",
        ]
        # 构造一个摘要长度合法但内容错的文本。
        wrong = json.loads(wrap(fail_doc()))
        wrong["摘要"] = "0" * 64
        bad_texts.append(json.dumps(wrong, ensure_ascii=False) + "\n")
        for text in bad_texts:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.stats_restore("k", text)

    def test_type_errors(self):
        s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.stats_restore(bad_key, "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.stats_restore("k", bad_text)

    def test_failure_does_not_change_instance_or_cache(self):
        s = populated()
        before = s.stats_checkpoint()
        with self.assertRaises(ValueError):
            s.stats_restore("r1", "not json")
        with self.assertRaises(TypeError):
            s.stats_restore("r1", None)
        with self.assertRaises(ResourceError):
            s.stats_restore(
                "r2",
                wrap({
                    "版本": 1,
                    "建立": {"总数": 0, "成功": 0},
                    "用户失败": [{"用户": "x", "认证": 0, "资源": 0,
                                "状态": 0, "后端": 0}],
                    "用户计量": [],
                    "模板计量": [],
                }),
            )
        self.assertEqual(s.stats_checkpoint(), before)
        # 失败不占 key：同 key 随即首次成功。
        self.assertEqual(s.stats_restore("r1", before), before)

    def test_replay_hetero_params_and_independent_domain(self):
        s = make()
        t1 = self.EMPTY
        t2 = wrap({
            "版本": 1,
            "建立": {"总数": 1, "成功": 1},
            "用户失败": [],
            "用户计量": [],
            "模板计量": [],
        })
        self.assertEqual(s.stats_restore("r1", t1), t1)
        self.assertEqual(s.stats_restore("r1", t1), t1)
        # 异型（text 非 str）先按异参 ValueError，而非 TypeError。
        with self.assertRaises(ValueError):
            s.stats_restore("r1", None)
        with self.assertRaises(ValueError):
            s.stats_restore("r1", t2)
        # 与 quota_restore 域独立：同名 key 在两域各首次使用。
        s.stats_restore("shared", t1)
        s.quota_restore("shared", '{"版本":1,"账本":[]}\n')
        # 不同 key 同文本各自成功。
        self.assertEqual(s.stats_restore("r2", t2), t2)

    def test_replay_returns_cached_bytes_after_state_changes(self):
        s = make()
        first = s.stats_restore("r1", populated().stats_checkpoint())
        # 实例统计随后被清空，同参重放仍返回首次缓存原字节（不重验、不替换）。
        s.stats_restore("r2", self.EMPTY)
        self.assertEqual(s.stats_checkpoint(), self.EMPTY)
        self.assertEqual(s.stats_restore("r1", first), first)
        self.assertEqual(s.stats_checkpoint(), self.EMPTY)

    def test_noncanonical_formatting_accepted_first_time(self):
        s = make()
        doc = {
            "版本": 1,
            "建立": {"总数": 2, "成功": 1},
            "用户失败": [],
            "用户计量": [],
            "模板计量": [],
        }
        doc["摘要"] = digest(doc)
        # 宽松排版（空格、无 LF）与 ensure_ascii=True 转义均按摘要重算接受。
        text = json.dumps(doc)
        out = s.stats_restore("r1", text)
        # 返回基线规范包（紧凑、LF 尾、不转义）。
        self.assertEqual(out, json.dumps(doc, ensure_ascii=False,
                                        separators=(",", ":")) + "\n")
        # 但重放须逐字节同 text：宽松文本与规范包异参。
        with self.assertRaises(ValueError):
            s.stats_restore("r1", out)

    def test_no_aging_and_no_audit(self):
        s = populated()
        # populated() 的建立操作本身写链；快照当前链长，恢复不得追加。
        before_audit = len(parse(s.audit())["事件"])
        before_takeover = len(parse(s.takeover_audit())["事件"])
        cp = s.stats_checkpoint()
        s.stats_restore("r1", cp)
        # 不老化：既有会话仍在线。
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")
        # 恢复不写任何审计链。
        self.assertEqual(len(parse(s.audit())["事件"]), before_audit)
        self.assertEqual(len(parse(s.takeover_audit())["事件"]), before_takeover)

    def test_credentials_constraint_on_identifiers(self):
        s = make()
        base = {
            "版本": 1,
            "建立": {"总数": 0, "成功": 0},
            "用户失败": [],
            "用户计量": [],
            "模板计量": [],
        }
        for field, label in (("用户失败", "用户"), ("用户计量", "标识"),
                             ("模板计量", "标识")):
            doc = json.loads(json.dumps(base))
            if field == "用户失败":
                doc[field] = [{"用户": "", "认证": 0, "资源": 0,
                               "状态": 0, "后端": 0}]
            else:
                doc[field] = [{"标识": "", "通过": 0, "拒绝": 0,
                               "下线": 0, "通过字节": 0}]
            with self.assertRaises(ValueError):
                s.stats_restore("k", wrap(doc))


if __name__ == "__main__":
    unittest.main()
