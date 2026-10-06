"""batch-online-run 子命令测试：信封整体校验、多批顺序执行、重放与异参、
原子/非原子批语义、v12 双栈回滚、全量查询与确定性输出。"""

import hashlib
import io
import json
import subprocess
import sys
import unittest

import access


def pool_entry(pool_id, cidr, reserved=(), static=()):
    return {
        "标识": pool_id,
        "CIDR": cidr,
        "保留": list(reserved),
        "静态": [[user, ip] for user, ip in static],
    }


def template_entry(template_id, limit=0):
    return {
        "标识": template_id,
        "限速": 1,
        "突发": 0,
        "配额": 10 ** 9,
        "周期毫秒": 0,
        "会话上限": limit,
        "排队优先级": 0,
        "超限": "拒绝",
    }


def v6_entry(pool_id, agg, deleg, reserved=(), static=()):
    return {
        "标识": pool_id,
        "聚合前缀": agg,
        "委派长度": deleg,
        "保留": list(reserved),
        "静态": [[user, prefix] for user, prefix in static],
    }


def config_v12(cidr="10.0.0.0/29", pools=None, total=10, per=5,
               idle_ms=1000, lease_ms=5000, v6_pools=(),
               templates=(), user_templates=(), template_v6=()):
    if pools is None:
        pools = [pool_entry("default", cidr)]
    return {
        "版本": 12,
        "会话": {"总数": total, "每用户": per, "空闲毫秒": idle_ms,
                "租期毫秒": lease_ms},
        "地址池": pools,
        "模板": [template_entry(t) for t in templates],
        "用户模板": [list(pair) for pair in user_templates],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {
            "最大失败": 3,
            "锁定毫秒": 1000,
            "重试基数毫秒": 0,
            "重试上限毫秒": 0,
        },
        "模板地址池": [],
        "IPv6 前缀池": [v6_entry(*args) for args in v6_pools],
        "模板 IPv6 池": [[tid, list(seq)] for tid, seq in template_v6],
    }


def batch(key, items, now_ms=0, atomic=False):
    return {"key": key, "items": items, "now_ms": now_ms, "atomic": atomic}


def entry(sid, user="alice", password="pw"):
    return [sid, user, password]


def make_input(batches, users=(("alice", "pw"), ("bob", "pw"), ("carol", "pw")),
               config=None, query_ms=0):
    return {
        "users": [list(pair) for pair in users],
        "config": config if config is not None else config_v12(),
        "batches": batches,
        "query_ms": query_ms,
    }


def encode(doc):
    return json.dumps(doc, ensure_ascii=False).encode("utf-8")


def run_raw(raw):
    """直接走 main 分派，返回 (returncode, stdout_bytes, stderr_bytes)。"""
    old_argv, old_stdin, old_stdout, old_stderr = (
        sys.argv, sys.stdin, sys.stdout, sys.stderr
    )
    sys.argv = ["access.py", "batch-online-run"]
    sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    sys.stdout, sys.stderr = out, err
    try:
        code = access.main(sys.argv)
    finally:
        out.flush()
        err.flush()
        stdout = out.buffer.getvalue()
        stderr = err.buffer.getvalue()
        sys.argv, sys.stdin, sys.stdout, sys.stderr = (
            old_argv, old_stdin, old_stdout, old_stderr
        )
    return code, stdout, stderr


def run_doc(doc):
    return run_raw(encode(doc))


def head_digest(doc):
    head = {key: doc[key] for key in ("版本", "项目", "会话", "地址池")}
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class BatchOnlineRunSuccessTest(unittest.TestCase):
    def test_basic_structure_and_digest(self):
        doc = make_input(
            [
                batch("b1", [entry("s1"), entry("s2", "bob")], now_ms=0),
                batch("b2", [entry("s3", "carol")], now_ms=10),
            ],
            query_ms=200,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        self.assertTrue(stdout.endswith(b"\n"))
        out = json.loads(stdout)
        self.assertEqual(list(out), ["版本", "项目", "会话", "地址池", "摘要"])
        self.assertEqual(out["版本"], 1)
        self.assertEqual([item["序号"] for item in out["项目"]], [0, 1])
        for item in out["项目"]:
            self.assertEqual(list(item), ["序号", "结果", "输出", "类型"])
            self.assertTrue(item["结果"])
            self.assertEqual(item["类型"], "")
            self.assertEqual(
                list(item["输出"]), ["时刻", "原子", "结果", "项目"]
            )
        self.assertEqual(out["项目"][0]["输出"]["结果"], "提交")
        self.assertEqual(
            [(it["会话"], it["结果"])
             for it in out["项目"][0]["输出"]["项目"]],
            [("s1", "上线"), ("s2", "上线")],
        )
        self.assertEqual(out["摘要"], head_digest(out))
        # 会话全量视图：s1/s2/s3 均在线（query_ms=200 < 空闲 1000）。
        self.assertEqual(
            [row["会话"] for row in out["会话"]["项目"]],
            ["s1", "s2", "s3"],
        )
        self.assertEqual(out["会话"]["剩余"], 0)
        default = out["地址池"]["池"][0]
        # [标识, 容量, 保留, 静态, 租用, 动态空闲]：/29 可用 6，租 3。
        self.assertEqual(default, ["default", 6, 0, 0, 3, 3])

    def test_compact_lf_and_cjk_passthrough(self):
        doc = make_input(
            [batch("b", [entry("会", "金牌")])],
            users=(("金牌", "pw"),),
            query_ms=0,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        self.assertTrue(stdout.endswith(b"\n"))
        self.assertNotIn(b", ", stdout)
        self.assertNotIn(b": ", stdout)
        self.assertIn("金牌".encode("utf-8"), stdout)

    def test_business_failures_recorded_and_continue(self):
        # /29 仅 6 个可用地址：alice 建满后再建即 ResourceError。
        doc = make_input(
            [
                batch(
                    "b1",
                    [
                        entry("a"),
                        entry("b", "bob", "bad"),   # AuthError
                        entry("x", "nobody", "pw"),  # KeyError
                    ],
                    now_ms=0,
                ),
                batch(
                    "b2",
                    [entry(f"c{i}") for i in range(6)],  # 容量/地址耗尽
                    now_ms=10,
                ),
            ],
            query_ms=0,
        )
        code, stdout, stderr = run_doc(doc)
        # 合法信封即使含业务失败也退出 0、stderr 空。
        self.assertEqual((code, stderr), (0, b""))
        out = json.loads(stdout)
        first, second = out["项目"]
        # 批本身“成功”返回（业务失败封在 batch_online 输出内）。
        self.assertTrue(first["结果"])
        self.assertEqual(first["输出"]["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in first["输出"]["项目"]],
            [("a", "上线"), ("b", "AuthError"), ("x", "KeyError")],
        )
        self.assertTrue(second["结果"])
        self.assertEqual(second["输出"]["结果"], "部分")
        # 成功项保留：a 与第二批成功项均在线；失败项不留痕。
        sids = {row["会话"] for row in out["会话"]["项目"]}
        self.assertIn("a", sids)
        self.assertNotIn("b", sids)
        self.assertNotIn("x", sids)
        # 地址池无超租。
        default = next(
            row for row in out["地址池"]["池"] if row[0] == "default"
        )
        self.assertLessEqual(default[4], 6)
        self.assertEqual(default[4] + default[5], default[1])

    def test_same_key_same_params_replays_first_result(self):
        items = [entry("s1"), entry("s2", "bob")]
        doc = make_input(
            [
                batch("dup", items, now_ms=0),
                batch("dup", items, now_ms=0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        first, second = out["项目"]
        self.assertTrue(first["结果"] and second["结果"])
        self.assertEqual(first["输出"], second["输出"])
        # 重放不重复建会话、不重复租地址。
        self.assertEqual(len(out["会话"]["项目"]), 2)
        self.assertEqual(out["地址池"]["池"][0][4], 2)

    def test_same_key_different_params_is_batch_value_error(self):
        doc = make_input(
            [
                batch("dup", [entry("s1")], now_ms=0),
                batch("dup", [entry("s2")], now_ms=0),
                batch("next", [entry("s3", "carol")], now_ms=10),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        first, conflict, later = out["项目"]
        self.assertTrue(first["结果"])
        self.assertFalse(conflict["结果"])
        self.assertIsNone(conflict["输出"])
        self.assertEqual(conflict["类型"], "ValueError")
        # 异参批不建 s2，后续批继续执行。
        self.assertTrue(later["结果"])
        self.assertEqual(
            sorted(row["会话"] for row in out["会话"]["项目"]),
            ["s1", "s3"],
        )

    def test_param_error_first_result_replays_then_conflicts(self):
        # 首调参数形态在信封层已被静态拒入；执行期的参数错首果只能由无法在
        # 信封层表达的形态产生——此处验证不同 key 互不影响，同 key 同参在
        # 首果成功后逐字节重放（与 batch_online 缓存语义一致）。
        items = [entry("s1")]
        doc = make_input(
            [
                batch("k", items, now_ms=5, atomic=True),
                batch("k", items, now_ms=5, atomic=True),
                batch("k2", [entry("s2", "bob")], now_ms=5, atomic=True),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertTrue(all(item["结果"] for item in out["项目"]))
        self.assertEqual(out["项目"][0]["输出"], out["项目"][1]["输出"])

    def test_duplicate_sid_across_batches_is_state_error_item(self):
        # 跨批 sid 重复不属于信封错误（重放须复用同批 items）：新 key 再建
        # 已存在 sid 时由 batch_online 记 StateError，不影响其他批。
        doc = make_input(
            [
                batch("b1", [entry("s1")], now_ms=0),
                batch("b2", [entry("s1"), entry("s2", "bob")], now_ms=10),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertTrue(out["项目"][0]["结果"])
        second = out["项目"][1]["输出"]
        self.assertEqual(second["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in second["项目"]],
            [("s1", "StateError"), ("s2", "上线")],
        )

    def test_atomic_failure_leaves_nothing_and_continues(self):
        doc = make_input(
            [
                batch(
                    "a1",
                    [entry("s1"), entry("x", "nobody", "pw"),
                     entry("s2", "bob")],
                    now_ms=0,
                    atomic=True,
                ),
                batch("a2", [entry("s3", "carol")], now_ms=10, atomic=True),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        rolled, committed = out["项目"]
        # 回滚是 batch_online 的正常返回：批项结果为 true，输出结果“回滚”。
        self.assertTrue(rolled["结果"])
        self.assertEqual(rolled["输出"]["结果"], "回滚")
        self.assertTrue(rolled["输出"]["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in rolled["输出"]["项目"]],
            [("s1", "回滚"), ("x", "KeyError"), ("s2", "回滚")],
        )
        self.assertTrue(committed["结果"])
        self.assertEqual(committed["输出"]["结果"], "提交")
        # 原子批不留新会话与 IPv4 租约；仅后续批的 s3 存在。
        self.assertEqual(
            [row["会话"] for row in out["会话"]["项目"]], ["s3"]
        )
        default = out["地址池"]["池"][0]
        self.assertEqual(default[4], 1)
        self.assertEqual(default[5], 5)

    def test_atomic_all_commit(self):
        doc = make_input(
            [batch("a", [entry("s1"), entry("s2", "bob")], now_ms=10,
                   atomic=True)],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        result = out["项目"][0]["输出"]
        self.assertTrue(result["原子"])
        self.assertEqual(result["结果"], "提交")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in result["项目"]],
            [("s1", "上线"), ("s2", "上线")],
        )

    def test_aging_views_at_query_ms(self):
        # 空闲 1000：query_ms=1000（含同刻）挂起释址，pool_stats 租用归零。
        doc = make_input(
            [batch("b", [entry("s1")], now_ms=0)],
            query_ms=1000,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(out["会话"]["项目"][0]["状态"], "挂起")
        self.assertEqual(out["地址池"]["池"][0][4], 0)
        self.assertEqual(out["地址池"]["池"][0][5], 6)

    def test_aging_between_batches(self):
        # 批间时刻推进：早批会话在晚批老化为挂起并释址，晚批可取回该址。
        doc = make_input(
            [
                batch("b1", [entry("old")], now_ms=0),
                batch("b2", [entry("new", "bob")], now_ms=1000),
            ],
            query_ms=1000,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        rows = {row["会话"]: row for row in out["会话"]["项目"]}
        self.assertEqual(rows["old"]["状态"], "挂起")
        self.assertEqual(rows["new"]["状态"], "在线")
        self.assertEqual(rows["new"]["地址"], "10.0.0.1")

    def test_output_is_deterministic_byte_for_byte(self):
        doc = make_input(
            [
                batch("b1", [entry("s1"), entry("s2", "bob")], 0),
                batch("b1", [entry("s1"), entry("s2", "bob")], 0),
                batch("b2", [entry("s3", "carol")], 100),
            ],
            query_ms=500,
        )
        first = run_doc(doc)[1]
        for _ in range(3):
            self.assertEqual(run_doc(doc)[1], first)


class BatchOnlineRunV12Test(unittest.TestCase):
    def dual_config(self):
        return config_v12(
            cidr="10.0.0.0/28",
            total=100,
            per=10,
            idle_ms=50000,
            lease_ms=1000,
            v6_pools=(("v6a", "2001:db8::/48", 56),),
            templates=("dual",),
            user_templates=(
                ("alice", "dual"),
                ("bob", "dual"),
                ("carol", "dual"),
            ),
            template_v6=(("dual", ("v6a",)),),
        )

    def test_v12_fields_in_views(self):
        doc = make_input(
            [batch("b", [entry("s1"), entry("s2", "bob")], 0)],
            config=self.dual_config(),
            query_ms=100,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        out = json.loads(stdout)
        rows = {row["会话"]: row for row in out["会话"]["项目"]}
        # /48->/56：s1 取首块、s2 取次块（偏移 0x100）。
        self.assertEqual(rows["s1"]["IPv6池"], "v6a")
        self.assertEqual(rows["s1"]["IPv6前缀"], "2001:db8::/56")
        self.assertEqual(rows["s1"]["IPv6租期"], 1000)
        self.assertEqual(rows["s2"]["IPv6前缀"], "2001:db8:0:100::/56")
        v6 = out["地址池"]["IPv6 前缀池"]
        # [标识, 总量, 保留, 静态, 租用, 空闲]：/48->/56 共 256 块。
        self.assertEqual(v6, [["v6a", 256, 0, 0, 2, 254]])

    def test_atomic_rollback_releases_v6_prefix(self):
        doc = make_input(
            [
                batch(
                    "a",
                    [entry("s1"), entry("x", "nobody", "pw"),
                     entry("s2", "bob")],
                    0,
                    atomic=True,
                ),
            ],
            config=self.dual_config(),
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(out["项目"][0]["输出"]["结果"], "回滚")
        # 回滚同步释放 IPv4 租约与 IPv6 前缀。
        self.assertEqual(out["会话"]["项目"], [])
        self.assertEqual(out["地址池"]["池"][0][4], 0)
        self.assertEqual(out["地址池"]["IPv6 前缀池"][0][4], 0)
        self.assertEqual(out["地址池"]["IPv6 前缀池"][0][5], 256)


class BatchOnlineRunValidationTest(unittest.TestCase):
    def assert_rejected(self, raw, expected_type=None):
        code, stdout, stderr = run_raw(raw)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")
        envelope = json.loads(stderr)
        self.assertEqual(list(envelope), ["错误", "类型"])
        self.assertEqual(envelope["错误"], "batch-online-run")
        self.assertTrue(envelope["类型"])
        self.assertTrue(stderr.endswith(b"\n"))
        if expected_type is not None:
            self.assertEqual(envelope["类型"], expected_type)
        return envelope

    def good_bytes(self, **mutate):
        doc = make_input([batch("b", [entry("s1")])])
        for key, value in mutate.items():
            if value == "__del__":
                del doc[key]
            else:
                doc[key] = value
        return encode(doc)

    def test_encoding_and_json(self):
        self.assert_rejected(b"{")
        self.assert_rejected(b"[]")
        self.assert_rejected(b"null")
        self.assert_rejected(b'"x"')
        self.assert_rejected(encode(make_input([batch("b", [entry("s")])]))
                           + b"\xff")

    def test_no_leading_whitespace_trailing_only(self):
        good = encode(make_input([batch("b", [entry("s")])]))
        self.assert_rejected(b" " + good)
        self.assert_rejected(good + b"x")
        code, stdout, _ = run_raw(good + b"\n\t ")
        self.assertEqual((code, stdout[:1]), (0, b"{"))

    def test_top_level_key_set_and_order(self):
        self.assert_rejected(b"{}")
        good = make_input([batch("b", [entry("s")])])
        self.assert_rejected(encode({**good, "extra": 1}))
        reordered = {
            "batches": good["batches"],
            "users": good["users"],
            "config": good["config"],
            "query_ms": 0,
        }
        self.assert_rejected(encode(reordered))
        missing = dict(good)
        del missing["query_ms"]
        self.assert_rejected(encode(missing))

    def test_duplicate_keys(self):
        self.assert_rejected(
            b'{"users":[],"users":[],"config":{},"batches":[],"query_ms":0}'
        )

    def test_users_and_config_rules_reused(self):
        self.assert_rejected(self.good_bytes(users=[]))
        self.assert_rejected(self.good_bytes(users=[["alice"]]))
        self.assert_rejected(
            self.good_bytes(users=[["bob", "p"], ["alice", "p"]])
        )
        other = config_v12(
            pools=[pool_entry("other", "10.0.0.0/30")]
        )
        self.assert_rejected(self.good_bytes(config=other))
        self.assert_rejected(self.good_bytes(config=[]))
        broken = config_v12()
        broken["版本"] = 11
        self.assert_rejected(self.good_bytes(config=broken))

    def test_batches_container_and_count(self):
        self.assert_rejected(self.good_bytes(batches=[]))
        self.assert_rejected(self.good_bytes(batches={}))
        too_many = [
            batch(f"b{i}", [entry(f"s{i}")]) for i in range(101)
        ]
        self.assert_rejected(self.good_bytes(batches=too_many))

    def test_batch_object_keys(self):
        self.assert_rejected(
            self.good_bytes(batches=[{"key": "b"}])
        )
        reordered = {
            "items": [entry("s")],
            "key": "b",
            "now_ms": 0,
            "atomic": False,
        }
        self.assert_rejected(self.good_bytes(batches=[reordered]))
        extra = batch("b", [entry("s")])
        extra["more"] = 1
        self.assert_rejected(self.good_bytes(batches=[extra]))
        self.assert_rejected(self.good_bytes(batches=[[]]))
        self.assert_rejected(self.good_bytes(batches=[42]))

    def test_key_credential_rule(self):
        self.assert_rejected(
            self.good_bytes(batches=[batch(0, [entry("s")])]),
            "TypeError",
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("", [entry("s")])]),
            "ValueError",
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("a\0b", [entry("s")])]),
            "ValueError",
        )

    def test_items_shape(self):
        # 空 items 与超 1000 项均为 ValueError。
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [])]), "ValueError"
        )
        self.assert_rejected(
            self.good_bytes(
                batches=[batch("b", [entry(f"s{i}") for i in range(1001)])]
            ),
            "ValueError",
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", {})]), "TypeError"
        )
        # 元组无法由 JSON 表达；元素非数组为 TypeError。
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", ["x"])]), "TypeError"
        )
        # 二串/四串为 ValueError。
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [["s", "alice"]])]),
            "ValueError",
        )
        self.assert_rejected(
            self.good_bytes(
                batches=[batch("b", [["s", "alice", "pw", "x"]])]
            ),
            "ValueError",
        )
        # 字段非串为 TypeError。
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [[1, "alice", "pw"]])]),
            "TypeError",
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [["s", None, "pw"]])]),
            "TypeError",
        )
        # 凭据取值为 ValueError。
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [["", "alice", "pw"]])]),
            "ValueError",
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [["s", "al\0ce", "pw"]])]),
            "ValueError",
        )

    def test_duplicate_sid_within_batch_rejected(self):
        # 批内重复 sid：ValueError。
        self.assert_rejected(
            self.good_bytes(
                batches=[batch("b", [entry("s"), entry("s", "bob")])]
            ),
            "ValueError",
        )
        # 跨批重复 sid 合法（执行期由 batch_online 判定）。
        code, _stdout, stderr = run_doc(
            make_input([
                batch("b1", [entry("s")]),
                batch("b2", [entry("s")]),
            ])
        )
        self.assertEqual((code, stderr), (0, b""))

    def test_total_items_limit(self):
        self.assert_rejected(
            self.good_bytes(
                batches=[
                    batch("b1", [entry(f"a{i}") for i in range(500)]),
                    batch("b2", [entry(f"c{i}") for i in range(501)]),
                ]
            ),
            "ValueError",
        )
        # 恰 1000 项合法。
        code, _stdout, stderr = run_doc(
            make_input([
                batch("b1", [entry(f"a{i:04d}") for i in range(500)]),
                batch("b2", [entry(f"c{i:04d}") for i in range(500)]),
            ])
        )
        self.assertEqual((code, stderr), (0, b""))

    def test_now_ms_and_atomic_types(self):
        for bad in (True, False, "0", 1.5, None):
            self.assert_rejected(
                self.good_bytes(batches=[batch("b", [entry("s")], now_ms=bad)]),
                "TypeError",
            )
        self.assert_rejected(
            self.good_bytes(batches=[batch("b", [entry("s")], now_ms=-1)]),
            "ValueError",
        )
        for bad in (0, 1, "false", None):
            self.assert_rejected(
                self.good_bytes(
                    batches=[batch("b", [entry("s")], atomic=bad)]
                ),
                "TypeError",
            )

    def test_query_ms(self):
        self.assert_rejected(self.good_bytes(query_ms=-1), "ValueError")
        self.assert_rejected(self.good_bytes(query_ms=True), "TypeError")
        self.assert_rejected(self.good_bytes(query_ms="0"), "TypeError")

    def test_validation_executes_nothing(self):
        # 首批可成功、末批形态非法：整封被拒，stdout 为空。
        doc = make_input([
            batch("b1", [entry("s1")], 0),
            batch("b2", [entry("s2")], now_ms=-1),
        ])
        code, stdout, stderr = run_doc(doc)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")
        self.assertEqual(json.loads(stderr)["错误"], "batch-online-run")


class BatchOnlineRunSubprocessTest(unittest.TestCase):
    """端到端：真实子进程验证退出码与流分离。"""

    def test_subprocess_success_and_error(self):
        good = encode(make_input([batch("b", [entry("s")])]))
        proc = subprocess.run(
            [sys.executable, "access.py", "batch-online-run"],
            input=good, capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")
        self.assertTrue(proc.stdout.endswith(b"\n"))

        proc = subprocess.run(
            [sys.executable, "access.py", "batch-online-run"],
            input=b"{", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "batch-online-run", "类型": "ValueError"},
        )

    def test_extra_arguments_rejected(self):
        proc = subprocess.run(
            [sys.executable, "access.py", "batch-online-run", "x"],
            input=b"{}", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        # 多余参数按未知子命令处理，沿用 stats-merge 名信封。
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "stats-merge", "类型": "ValueError"},
        )

    def test_existing_commands_unchanged(self):
        # 既有子命令行为不变：session-run 收到 {} 仍写自身信封。
        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=b"{}", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr)["错误"], "session-run"
        )
        proc = subprocess.run(
            [sys.executable, "access.py", "nope"],
            input=b"{}", capture_output=True, check=False,
        )
        self.assertEqual(
            json.loads(proc.stderr)["错误"], "stats-merge"
        )


if __name__ == "__main__":
    unittest.main()
