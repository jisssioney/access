"""batch-online-run 子命令测试：信封校验、多批顺序执行、批量原子语义、
幂等复用与确定性输出。"""

import hashlib
import io
import json
import subprocess
import sys
import unittest

import access


def config_v11(cidr="10.0.0.0/29", pools=None, templates=(), user_templates=(),
               template_pools=(), idle_ms=1000, lease_ms=5000, total=10, per=5):
    if pools is None:
        pools = [
            {"标识": "default", "CIDR": cidr, "保留": [], "静态": []}
        ]
    return {
        "版本": 11,
        "会话": {"总数": total, "每用户": per, "空闲毫秒": idle_ms,
                "租期毫秒": lease_ms},
        "地址池": pools,
        "模板": list(templates),
        "用户模板": [list(pair) for pair in user_templates],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
        "认证": {
            "最大失败": 3,
            "锁定毫秒": 1000,
            "重试基数毫秒": 0,
            "重试上限毫秒": 0,
        },
        "模板地址池": [[item[0], list(item[1])] for item in template_pools],
    }


def batch(key, items, now_ms=0, atomic=False):
    return {"key": key, "items": items, "now_ms": now_ms, "atomic": atomic}


def make_input(batches, users=(("alice", "pw"), ("bob", "pw"), ("carol", "pw")),
               config=None, query_ms=0):
    return {
        "users": [list(pair) for pair in users],
        "config": config if config is not None else config_v11(),
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
                batch("b1", [["s1", "alice", "pw"], ["s2", "bob", "pw"]], 0),
                batch("b2", [["s3", "carol", "pw"]], 100),
            ],
            query_ms=200,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, b"")
        self.assertTrue(stdout.endswith(b"\n"))
        out = json.loads(stdout)
        self.assertEqual(list(out), ["版本", "项目", "会话", "地址池", "摘要"])
        self.assertEqual(out["版本"], 1)
        self.assertEqual([item["序号"] for item in out["项目"]], [0, 1])
        for item in out["项目"]:
            self.assertEqual(list(item), ["序号", "结果", "输出", "类型"])
            self.assertTrue(item["结果"])
            self.assertEqual(item["类型"], "")
            self.assertIsNotNone(item["输出"])
        # 输出为 batch_online 原返回对象。
        self.assertEqual(
            list(out["项目"][0]["输出"]), ["时刻", "原子", "结果", "项目"]
        )
        self.assertEqual(out["项目"][0]["输出"]["结果"], "提交")
        self.assertFalse(out["项目"][0]["输出"]["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in out["项目"][0]["输出"]["项目"]],
            [("s1", "上线"), ("s2", "上线")],
        )
        self.assertEqual(out["项目"][1]["输出"]["时刻"], 100)
        self.assertEqual(out["摘要"], head_digest(out))
        sids = [row["会话"] for row in out["会话"]["项目"]]
        self.assertEqual(sorted(sids), ["s1", "s2", "s3"])
        self.assertEqual(out["会话"]["剩余"], 0)
        self.assertEqual(out["地址池"]["时刻"], 200)
        default = next(
            row for row in out["地址池"]["池"] if row[0] == "default"
        )
        # [标识, 容量, 保留, 静态, 租用, 动态空闲]：/29 可用 6，租 3。
        self.assertEqual(default, ["default", 6, 0, 0, 3, 3])

    def test_compact_lf_terminated_and_cjk_passthrough(self):
        doc = make_input(
            [batch("批一", [["会", "金牌", "pw"]], 0)],
            users=(("金牌", "pw"),),
            query_ms=0,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        self.assertTrue(stdout.endswith(b"\n"))
        self.assertNotIn(b", ", stdout)
        self.assertNotIn(b": ", stdout)
        self.assertIn("金牌".encode("utf-8"), stdout)

    def test_business_failures_recorded_per_item_and_continue_batches(self):
        cfg = config_v11(total=10, per=10)
        doc = make_input(
            [
                # 未知用户 KeyError + 错误口令 AuthError + 成功：非原子“部分”。
                batch("b1", [
                    ["x", "ghost", "pw"],
                    ["y", "bob", "bad"],
                    ["s1", "alice", "pw"],
                ], 0),
                # 后续批次照常执行。
                batch("b2", [["s2", "carol", "pw"]], 10),
            ],
            config=cfg,
            query_ms=10000,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        out = json.loads(stdout)
        self.assertTrue(all(item["结果"] for item in out["项目"]))
        self.assertEqual(out["项目"][0]["输出"]["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in out["项目"][0]["输出"]["项目"]],
            [("x", "KeyError"), ("y", "AuthError"), ("s1", "上线")],
        )
        self.assertEqual(out["项目"][1]["输出"]["结果"], "提交")
        # 失败不留会话，成功项保留。
        self.assertEqual(
            sorted(row["会话"] for row in out["会话"]["项目"]),
            ["s1", "s2"],
        )

    def test_resource_exhaustion_is_item_failure(self):
        # /30 仅 2 个可用地址。
        cfg = config_v11(cidr="10.0.0.0/30")
        doc = make_input(
            [batch("b", [
                ["a", "alice", "pw"],
                ["b", "bob", "pw"],
                ["c", "carol", "pw"],
            ], 0)],
            config=cfg,
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in out["项目"][0]["输出"]["项目"]],
            [("a", "上线"), ("b", "上线"), ("c", "ResourceError")],
        )
        self.assertEqual(len(out["会话"]["项目"]), 2)

    def test_atomic_batch_rolls_back_sessions_and_leases(self):
        cfg = config_v11(cidr="10.0.0.0/29")
        doc = make_input(
            [
                batch("r", [
                    ["a", "alice", "pw"],
                    ["x", "ghost", "pw"],
                    ["b", "bob", "pw"],
                ], 0, atomic=True),
                # 回滚不影响后续批次；s1 可取回批内曾尝试的地址。
                batch("ok", [["s1", "carol", "pw"]], 10),
            ],
            config=cfg,
            query_ms=100,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        first, second = out["项目"]
        self.assertTrue(first["结果"])
        self.assertEqual(first["输出"]["结果"], "回滚")
        self.assertTrue(first["输出"]["原子"])
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in first["输出"]["项目"]],
            [("a", "回滚"), ("x", "KeyError"), ("b", "回滚")],
        )
        self.assertEqual(second["输出"]["结果"], "提交")
        # 原子批不留新会话；只有后续批次的 s1。
        self.assertEqual(
            [row["会话"] for row in out["会话"]["项目"]], ["s1"]
        )
        default = next(
            row for row in out["地址池"]["池"] if row[0] == "default"
        )
        self.assertEqual(default[4], 1)  # 租用 1
        self.assertEqual(default[5], 5)  # 空闲 5

    def test_non_atomic_batch_keeps_successful_items(self):
        cfg = config_v11(cidr="10.0.0.0/30", total=2, per=10)
        doc = make_input(
            [batch("b", [
                ["a", "alice", "pw"],
                ["c", "carol", "pw"],
                ["x", "ghost", "pw"],
            ], 0)],
            config=cfg,
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(out["项目"][0]["输出"]["结果"], "部分")
        self.assertEqual(
            sorted(row["会话"] for row in out["会话"]["项目"]),
            ["a", "c"],
        )

    def test_same_key_same_params_replays_first_result(self):
        items = [["s1", "alice", "pw"], ["s2", "bob", "pw"]]
        doc = make_input(
            [
                batch("dup", items, 0),
                batch("dup", items, 0),
                batch("dup", items, 0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        outputs = [item["输出"] for item in out["项目"]]
        self.assertTrue(all(item["结果"] for item in out["项目"]))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])
        # 重放不重复建会话。
        self.assertEqual(len(out["会话"]["项目"]), 2)

    def test_same_key_different_params_is_value_error_item(self):
        doc = make_input(
            [
                batch("dup", [["s1", "alice", "pw"]], 0),
                batch("dup", [["s2", "alice", "pw"]], 0),       # 异 items
                batch("dup", [["s1", "alice", "pw"]], 1),       # 异 now_ms
                batch("dup", [["s1", "alice", "pw"]], 0, True),  # 异 atomic
                # 失败批次后继续：新 key 正常。
                batch("other", [["s3", "carol", "pw"]], 0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertTrue(out["项目"][0]["结果"])
        for index in (1, 2, 3):
            self.assertFalse(out["项目"][index]["结果"])
            self.assertIsNone(out["项目"][index]["输出"])
            self.assertEqual(out["项目"][index]["类型"], "ValueError")
        self.assertTrue(out["项目"][4]["结果"])
        # 异参复用不新建会话。
        self.assertEqual(
            sorted(row["会话"] for row in out["会话"]["项目"]),
            ["s1", "s3"],
        )

    def test_duplicate_sid_across_batches_is_business_state_error(self):
        # 互异约束仅在单批 items 内；跨批重复 sid 由 batch_online 判为
        # StateError 业务失败（非原子批结果“部分”，项目成功仍记）。
        doc = make_input(
            [
                batch("b1", [["s1", "alice", "pw"]], 0),
                batch("b2", [["s1", "bob", "pw"], ["s2", "carol", "pw"]], 0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(out["项目"][1]["输出"]["结果"], "部分")
        self.assertEqual(
            [(it["会话"], it["结果"]) for it in out["项目"][1]["输出"]["项目"]],
            [("s1", "StateError"), ("s2", "上线")],
        )

    def test_aging_views_at_query_ms(self):
        # 空闲 1000：query_ms=1000 视图挂起、池址回收；建立时刻均为 0。
        doc = make_input(
            [batch("b", [["s1", "alice", "pw"]], 0)],
            config=config_v11(idle_ms=1000),
            query_ms=1000,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        row = out["会话"]["项目"][0]
        self.assertEqual(row["状态"], "挂起")
        self.assertEqual(row["池"], "")
        self.assertEqual(row["地址"], "")
        default = out["地址池"]["池"][0]
        self.assertEqual(default[4], 0)
        self.assertEqual(default[5], 6)

    def test_batch_now_ms_drives_aging_between_batches(self):
        # 老会话在第二批的 now_ms 先老化释址，第二批方可取址。
        cfg = config_v11(cidr="10.0.0.0/30", idle_ms=100, lease_ms=100000)
        doc = make_input(
            [
                batch("old", [["o1", "alice", "pw"], ["o2", "bob", "pw"]], 0),
                batch("new", [["n1", "carol", "pw"]], 100),
            ],
            config=cfg,
            query_ms=100,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(out["项目"][1]["输出"]["结果"], "提交")
        states = {row["会话"]: row["状态"] for row in out["会话"]["项目"]}
        self.assertEqual(states["o1"], "挂起")
        self.assertEqual(states["n1"], "在线")

    def test_output_is_deterministic_byte_for_byte(self):
        doc = make_input(
            [
                batch("b1", [["s1", "alice", "pw"]], 0),
                batch("b2", [["s2", "bob", "pw"]], 100),
            ],
            query_ms=200,
        )
        first = run_doc(doc)[1]
        for _ in range(3):
            self.assertEqual(run_doc(doc)[1], first)


class BatchOnlineRunV12Test(unittest.TestCase):
    """v12 双栈：成功委派前缀，原子失败同步回滚 IPv4 租约与 IPv6 前缀。"""

    def base_config(self):
        return {
            "版本": 12,
            "会话": {"总数": 100, "每用户": 10, "空闲毫秒": 50000,
                    "租期毫秒": 1000},
            "地址池": [
                {"标识": "default", "CIDR": "10.0.0.0/28", "保留": [],
                 "静态": []},
            ],
            "模板": [{
                "标识": "dual", "限速": 1, "突发": 0, "配额": 10 ** 9,
                "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
                "超限": "拒绝",
            }],
            "用户模板": [["alice", "dual"]],
            "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
            "认证": {"最大失败": 3, "锁定毫秒": 10 ** 9,
                    "重试基数毫秒": 0, "重试上限毫秒": 0},
            "模板地址池": [],
            "IPv6 前缀池": [
                {"标识": "v6a", "聚合前缀": "2001:db8::/48", "委派长度": 56,
                 "保留": [], "静态": []},
            ],
            "模板 IPv6 池": [["dual", ["v6a"]]],
        }

    def test_v12_prefix_delegation_and_atomic_rollback(self):
        doc = make_input(
            [
                batch("ok", [["s1", "alice", "pw"]], 0),
                batch("roll", [
                    ["s2", "alice", "pw"],
                    ["x", "ghost", "pw"],
                ], 0, atomic=True),
            ],
            users=(("alice", "pw"),),
            config=self.base_config(),
            query_ms=0,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        out = json.loads(stdout)
        row = next(r for r in out["会话"]["项目"] if r["会话"] == "s1")
        self.assertEqual(row["IPv6池"], "v6a")
        self.assertTrue(row["IPv6前缀"])
        # 原子回滚不留 IPv4 租约或 IPv6 前缀。
        v6_pool = out["地址池"]["IPv6 前缀池"][0]
        v4_pool = next(r for r in out["地址池"]["池"] if r[0] == "default")
        # [标识, 容量, 保留, 静态, 租用, 空闲]：仅 s1 各占一个。
        self.assertEqual(v6_pool[4], 1)
        self.assertEqual(v4_pool[4], 1)
        self.assertNotIn("s2", [r["会话"] for r in out["会话"]["项目"]])


class BatchOnlineRunValidationTest(unittest.TestCase):
    def assert_rejected(self, raw, code=2):
        result, stdout, stderr = run_raw(raw)
        self.assertEqual(result, code)
        self.assertEqual(stdout, b"")
        envelope = json.loads(stderr)
        self.assertEqual(list(envelope), ["错误", "类型"])
        self.assertEqual(envelope["错误"], "batch-online-run")
        self.assertTrue(envelope["类型"])
        self.assertTrue(stderr.endswith(b"\n"))

    def good_bytes(self, **mutate):
        doc = make_input(
            [batch("k1", [["s1", "alice", "pw"]], 0)]
        )
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
        self.assert_rejected(
            encode(make_input([batch("k", [["s", "alice", "pw"]], 0)])) + b"\xff"
        )

    def test_no_leading_whitespace_trailing_only(self):
        good = encode(make_input([batch("k", [["s", "alice", "pw"]], 0)]))
        self.assert_rejected(b" " + good)
        self.assert_rejected(good + b"x")
        code, stdout, _ = run_raw(good + b"\n\t ")
        self.assertEqual((code, stdout[:1]), (0, b"{"))

    def test_top_level_key_set_and_order(self):
        self.assert_rejected(b"{}")
        self.assert_rejected(
            b'{"users":[],"config":{},"batches":[],"query_ms":0,"extra":1}'
        )
        doc = make_input([batch("k", [["s", "alice", "pw"]], 0)])
        reordered = {
            "config": doc["config"],
            "users": doc["users"],
            "batches": doc["batches"],
            "query_ms": 0,
        }
        self.assert_rejected(encode(reordered))
        # requests 信封不属于本子命令。
        self.assert_rejected(
            self.good_bytes()
            .replace(b'"batches"', b'"requests"', 1)
        )

    def test_duplicate_keys(self):
        self.assert_rejected(
            b'{"users":[],"config":{},"batches":[],"batches":[],"query_ms":0}'
        )

    def test_users_follow_session_run_rules(self):
        self.assert_rejected(self.good_bytes(users=[]))
        self.assert_rejected(self.good_bytes(users={}))
        self.assert_rejected(self.good_bytes(users=["alice"]))
        self.assert_rejected(self.good_bytes(users=[["alice"]]))
        self.assert_rejected(
            self.good_bytes(users=[["bob", "p"], ["alice", "p"]])
        )

    def test_config_must_be_v12_family_with_default_pool(self):
        cfg = config_v11()
        cfg["版本"] = 0
        self.assert_rejected(self.good_bytes(config=cfg))
        self.assert_rejected(self.good_bytes(config=[]))
        other = config_v11(
            pools=[
                {"标识": "other", "CIDR": "10.0.0.0/30", "保留": [], "静态": []}
            ]
        )
        self.assert_rejected(self.good_bytes(config=other))
        broken = config_v11()
        del broken["容量"]
        self.assert_rejected(self.good_bytes(config=broken))
        # 用户模板引用未注册用户。
        with_ref = config_v11(
            templates=[
                {"标识": "g", "限速": 1, "突发": 0, "配额": 1,
                 "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
                 "超限": "拒绝"}
            ],
            user_templates=(("ghost", "g"),),
        )
        self.assert_rejected(self.good_bytes(config=with_ref))

    def test_batches_container_and_count(self):
        self.assert_rejected(self.good_bytes(batches=[]))
        self.assert_rejected(self.good_bytes(batches={}))
        self.assert_rejected(self.good_bytes(batches="x"))
        # 101 批非法（每批 1 项共 101 项，先撞批次数 100 上界）。
        too_many = [
            batch(f"k{i:03d}", [[f"s{i:03d}", "alice", "pw"]], 0)
            for i in range(101)
        ]
        self.assert_rejected(self.good_bytes(batches=too_many))
        # 100 批、合计 1000 项（批内 sid 互异）合法。
        good = [
            batch(f"k{i:03d}", [
                [f"s{i:03d}-{j}", "alice", "pw"] for j in range(10)
            ], 0)
            for i in range(100)
        ]
        self.assertEqual(run_doc(self._doc_with(good))[0], 0)

    @staticmethod
    def _doc_with(batches):
        return make_input(batches)

    def test_batch_object_keys(self):
        self.assert_rejected(self.good_bytes(batches=[{"key": "k"}]))
        reordered = {
            "atomic": False,
            "key": "k",
            "items": [["s", "alice", "pw"]],
            "now_ms": 0,
        }
        self.assert_rejected(self.good_bytes(batches=[reordered]))
        # 多余/缺键。
        b = batch("k", [["s", "alice", "pw"]], 0)
        extra = dict(b)
        extra["more"] = 1
        self.assert_rejected(self.good_bytes(batches=[extra]))

    def test_key_credential_rule(self):
        for bad in (0, True, None, "", "a\0"):
            self.assert_rejected(
                self.good_bytes(batches=[batch(bad, [["s", "alice", "pw"]], 0)])
            )

    def test_items_shape(self):
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [], 0)])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", {}, 0)])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", "x", 0)])
        )
        # 项须为三串数组。
        for bad_items in (
            [["s", "alice"]],
            [["s", "alice", "pw", "x"]],
            [["s", 0, "pw"]],
            [["s", "alice", 1]],
            [[0, "alice", "pw"]],
            ["s", "alice", "pw"],
            [[["s"], "alice", "pw"]],
        ):
            self.assert_rejected(
                self.good_bytes(batches=[batch("k", bad_items, 0)])
            )
        # 凭据取值约束。
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["s", "al\0ce", "pw"]], 0)])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["", "alice", "pw"]], 0)])
        )

    def test_items_count_bounds(self):
        # 单批 1001 项非法。
        over = [[f"s{i:04d}", "alice", "pw"] for i in range(1001)]
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", over, 0)])
        )
        # 合计 1001 项非法（单批均不超 1000）。
        total_over = [
            batch("a", [[f"a{i:04d}", "alice", "pw"] for i in range(501)], 0),
            batch("b", [[f"b{i:04d}", "bob", "pw"] for i in range(500)], 0),
        ]
        self.assert_rejected(self.good_bytes(batches=total_over))
        # 合计恰 1000 项合法。
        total_full = [
            batch("a", [[f"a{i:04d}", "alice", "pw"] for i in range(500)], 0),
            batch("b", [[f"b{i:04d}", "bob", "pw"] for i in range(500)], 0),
        ]
        self.assertEqual(run_doc(self._doc_with(total_full))[0], 0)

    def test_duplicate_sid_within_batch_rejected(self):
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [
                ["s", "alice", "pw"],
                ["s", "bob", "pw"],
            ], 0)])
        )
        # 跨批重复合法（业务层判 StateError）。
        cross = [
            batch("a", [["s", "alice", "pw"]], 0),
            batch("b", [["s", "bob", "pw"]], 0),
        ]
        self.assertEqual(run_doc(self._doc_with(cross))[0], 0)

    def test_now_ms_and_atomic(self):
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["s", "alice", "pw"]], -1)])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["s", "alice", "pw"]], True)])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["s", "alice", "pw"]], "0")])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["s", "alice", "pw"]], 0,
                                           atomic=0)])
        )
        self.assert_rejected(
            self.good_bytes(batches=[batch("k", [["s", "alice", "pw"]], 0,
                                           atomic="true")])
        )

    def test_query_ms(self):
        self.assert_rejected(self.good_bytes(query_ms=-1))
        self.assert_rejected(self.good_bytes(query_ms=True))
        self.assert_rejected(self.good_bytes(query_ms="0"))
        self.assert_rejected(self.good_bytes(query_ms=1.5))

    def test_validation_failure_executes_no_batch(self):
        # 首批合法、末批形态非法：整体拒绝，stdout 为空，无任何批次执行。
        doc = make_input([
            batch("k1", [["s1", "alice", "pw"]], 0),
            batch("k2", [["s2", "alice", "pw"]], 0, atomic="x"),
        ])
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")


class BatchOnlineRunSubprocessTest(unittest.TestCase):
    """端到端：真实子进程验证退出码与流分离。"""

    def test_subprocess_success_and_error(self):
        good = encode(make_input(
            [batch("k", [["s", "alice", "pw"]], 0)]
        ))
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

    def test_type_error_exit_code(self):
        doc = make_input([
            {"key": "k", "items": [["s", "alice", "pw"]], "now_ms": 0,
             "atomic": 1},
        ])
        proc = subprocess.run(
            [sys.executable, "access.py", "batch-online-run"],
            input=encode(doc), capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr)["类型"], "TypeError"
        )

    def test_extra_args_rejected_as_unknown_subcommand(self):
        proc = subprocess.run(
            [sys.executable, "access.py", "batch-online-run", "extra"],
            input=b"{}", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "stats-merge", "类型": "ValueError"},
        )

    def test_existing_commands_unchanged(self):
        # session-run 信封不接受 batches 键。
        doc = make_input([batch("k", [["s", "alice", "pw"]], 0)])
        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=encode(doc), capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr)["错误"], "session-run"
        )
        # 未知子命令仍沿用 stats-merge 信封。
        proc = subprocess.run(
            [sys.executable, "access.py", "nope"],
            input=b"{}", capture_output=True, check=False,
        )
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "stats-merge", "类型": "ValueError"},
        )


if __name__ == "__main__":
    unittest.main()
