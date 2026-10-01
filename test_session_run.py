"""session-run 子命令测试：输入校验、全新实例执行、全量查询与确定性输出。"""

import hashlib
import io
import json
import subprocess
import sys
import unittest
from contextlib import contextmanager

import access


def config_v10(cidr="10.0.0.0/29", pools=None, templates=(), user_templates=()):
    if pools is None:
        pools = [
            {"标识": "default", "CIDR": cidr, "保留": [], "静态": []}
        ]
    return {
        "版本": 10,
        "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 1000, "租期毫秒": 5000},
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
    }


def request(key, op, sid, args, now_ms):
    return {"key": key, "op": op, "sid": sid, "args": args, "now_ms": now_ms}


def make_input(requests, users=(("alice", "pw"), ("bob", "pw")),
               config=None, query_ms=0):
    return {
        "users": [list(pair) for pair in users],
        "config": config if config is not None else config_v10(),
        "requests": requests,
        "query_ms": query_ms,
    }


def encode(doc):
    return json.dumps(doc, ensure_ascii=False).encode("utf-8")


def run_raw(raw):
    """直接走 main 分派，返回 (returncode, stdout_bytes, stderr_bytes)。"""
    old_argv, old_stdin, old_stdout, old_stderr = (
        sys.argv, sys.stdin, sys.stdout, sys.stderr
    )
    sys.argv = ["access.py", "session-run"]
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


class SessionRunSuccessTest(unittest.TestCase):
    def test_basic_run_structure_and_digest(self):
        doc = make_input(
            [
                request("k1", "建立", "s1", ["alice", "pw"], 0),
                request("k2", "建立", "s2", ["bob", "pw"], 0),
                request("k3", "续租", "s1", None, 100),
            ],
            query_ms=200,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, b"")
        self.assertTrue(stdout.endswith(b"\n"))
        out = json.loads(stdout)
        self.assertEqual(
            list(out), ["版本", "项目", "会话", "地址池", "摘要"]
        )
        self.assertEqual(out["版本"], 1)
        self.assertEqual([item["序号"] for item in out["项目"]], [0, 1, 2])
        for item in out["项目"]:
            self.assertEqual(
                list(item), ["序号", "结果", "输出", "类型"]
            )
            self.assertTrue(item["结果"])
            self.assertEqual(item["类型"], "")
            self.assertIsNotNone(item["输出"])
        # 建立输出为 do 原返回对象。
        self.assertEqual(out["项目"][0]["输出"]["会话"], "s1")
        self.assertEqual(out["项目"][0]["输出"]["状态"], "在线")
        self.assertEqual(out["项目"][0]["输出"]["地址"], "10.0.0.1")
        self.assertEqual(
            out["项目"][0]["输出"]["租期"], 5000
        )
        self.assertEqual(out["摘要"], head_digest(out))
        # 全量查询：s1/s2 均在线（query_ms=200 < 空闲 1000）。
        sids = [row["会话"] for row in out["会话"]["项目"]]
        self.assertEqual(sids, ["s1", "s2"])
        self.assertEqual(out["会话"]["剩余"], 0)
        self.assertEqual(out["地址池"]["时刻"], 200)
        default = next(
            row for row in out["地址池"]["池"] if row[0] == "default"
        )
        # [标识, 容量, 保留, 静态, 租用, 动态空闲]：/29 可用 6，租 2。
        self.assertEqual(default, ["default", 6, 0, 0, 2, 4])

    def test_compact_lf_terminated_and_cjk_passthrough(self):
        doc = make_input(
            [request("k1", "建立", "会", ["金牌", "pw"], 0)],
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
        # /29 仅 6 个可用地址：耗尽即 ResourceError。
        cfg = config_v10()
        cfg["会话"]["每用户"] = 10
        doc = make_input(
            [
                request("ka", "建立", "a", ["alice", "pw"], 0),
                request("kb", "建立", "b", ["bob", "bad"], 0),  # AuthError
                request("kc", "建立", "c", ["alice", "pw"], 10),
                request("kd", "建立", "d", ["alice", "pw"], 10),
                request("ke", "建立", "e", ["alice", "pw"], 10),
                request("kf", "建立", "f", ["alice", "pw"], 10),
                request("kg", "建立", "g", ["alice", "pw"], 10),
                request("kh", "建立", "h", ["alice", "pw"], 10),  # 耗尽
                request("ki", "下线", "ghost", None, 20),  # KeyError
                request("ka", "建立", "a", ["alice", "pw"], 0),  # 重放
            ],
            config=cfg,
            query_ms=10000,
        )
        code, stdout, stderr = run_doc(doc)
        # 合法输入即使含项目失败也退出 0。
        self.assertEqual((code, stderr), (0, b""))
        out = json.loads(stdout)
        results = [
            (item["结果"], item["类型"]) for item in out["项目"]
        ]
        self.assertEqual(
            results,
            [
                (True, ""),
                (False, "AuthError"),
                (True, ""),
                (True, ""),
                (True, ""),
                (True, ""),
                (True, ""),
                (False, "ResourceError"),
                (False, "KeyError"),
                (True, ""),
            ],
        )
        for item in out["项目"]:
            if item["结果"]:
                self.assertIsNotNone(item["输出"])
                self.assertEqual(item["类型"], "")
            else:
                self.assertIsNone(item["输出"])
                self.assertNotEqual(item["类型"], "")
        # 失败不留半分配：最终恰 6 个在线（重放不新增）。
        self.assertEqual(len(out["会话"]["项目"]), 6)

    def test_same_key_same_params_replays_original(self):
        doc = make_input(
            [
                request("dup", "建立", "s1", ["alice", "pw"], 0),
                # 同 key 同参重放原结果（即使 sid 已存在，也不二次建立）。
                request("dup", "建立", "s1", ["alice", "pw"], 0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        first, second = out["项目"]
        self.assertTrue(first["结果"])
        self.assertTrue(second["结果"])
        self.assertEqual(first["输出"], second["输出"])
        self.assertEqual(len(out["会话"]["项目"]), 1)

    def test_same_key_different_params_is_value_error_item(self):
        doc = make_input(
            [
                request("dup", "建立", "s1", ["alice", "pw"], 0),
                request("dup", "建立", "s2", ["alice", "pw"], 0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertTrue(out["项目"][0]["结果"])
        self.assertFalse(out["项目"][1]["结果"])
        self.assertEqual(out["项目"][1]["类型"], "ValueError")
        self.assertIsNone(out["项目"][1]["输出"])
        # 异参失败不建立 s2。
        self.assertEqual(
            [row["会话"] for row in out["会话"]["项目"]], ["s1"]
        )

    def test_state_error_duplicate_sid_recorded(self):
        doc = make_input(
            [
                request("k1", "建立", "s1", ["alice", "pw"], 0),
                request("k2", "建立", "s1", ["alice", "pw"], 0),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertFalse(out["项目"][1]["结果"])
        self.assertEqual(out["项目"][1]["类型"], "StateError")

    def test_aging_views_at_query_ms(self):
        # 空闲 1000：query_ms=1000（含同刻）视图挂起、池址空；pool_stats
        # 先老化，租用归零。
        doc = make_input(
            [request("k1", "建立", "s1", ["alice", "pw"], 0)],
            query_ms=1000,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        row = out["会话"]["项目"][0]
        self.assertEqual(row["状态"], "挂起")
        self.assertEqual(row["池"], "")
        self.assertEqual(row["地址"], "")
        self.assertEqual(row["租期"], 0)
        default = out["地址池"]["池"][0]
        self.assertEqual(default[4], 0)  # 租用 0
        self.assertEqual(default[5], 6)  # 空闲全回收

    def test_query_ms_view_does_not_mutate_and_can_rewind(self):
        # query_ms 早于操作时刻：会话视图按 query_ms 取（尚未建立则不影响
        # 已有行的期限判定）；sessions 查询不老化。
        doc = make_input(
            [
                request("k1", "建立", "s1", ["alice", "pw"], 100),
                request("k2", "下线", "s1", None, 500),
            ],
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        # 下线墓碑在任何 query_ms 均列出且清零。
        row = out["会话"]["项目"][0]
        self.assertEqual(row["状态"], "下线")
        self.assertEqual(row["期限"], 0)

    def test_full_ops_outputs_are_do_objects(self):
        pools = [
            {"标识": "default", "CIDR": "10.0.0.0/30", "保留": [], "静态": []},
            {"标识": "b", "CIDR": "192.168.0.0/30", "保留": [], "静态": []},
        ]
        doc = make_input(
            [
                request("k1", "建立", "s1", ["alice", "pw"], 0),
                request("k2", "迁移", "s1", ["b", "pw"], 100),
                request("k3", "挂起", "s1", None, 200),
                request("k4", "恢复", "s1", ["default", "pw"], 300),
                request("k5", "接管", "s2", ["s1", "pw"], 400),
                request("k6", "下线", "s1", None, 500),
            ],
            config=config_v10(pools=pools),
            query_ms=600,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual((code, stderr), (0, b""))
        out = json.loads(stdout)
        self.assertTrue(all(item["结果"] for item in out["项目"]))
        self.assertEqual(
            out["项目"][1]["输出"]["目标池"], "b"
        )
        self.assertEqual(out["项目"][2]["输出"]["状态"], "挂起")
        self.assertEqual(out["项目"][3]["输出"]["状态"], "在线")
        self.assertEqual(out["项目"][4]["输出"]["旧会话"], "s1")
        self.assertEqual(out["项目"][4]["输出"]["新会话"], "s2")

    def test_output_is_deterministic_byte_for_byte(self):
        doc = make_input(
            [
                request("k1", "建立", "s1", ["alice", "pw"], 0),
                request("k2", "建立", "s2", ["bob", "pw"], 0),
                request("k3", "续租", "s2", None, 100),
            ],
            query_ms=200,
        )
        first = run_doc(doc)[1]
        for _ in range(3):
            self.assertEqual(run_doc(doc)[1], first)


class SessionRunValidationTest(unittest.TestCase):
    def assert_rejected(self, raw):
        code, stdout, stderr = run_raw(raw)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")
        envelope = json.loads(stderr)
        self.assertEqual(list(envelope), ["错误", "类型"])
        self.assertEqual(envelope["错误"], "session-run")
        self.assertTrue(envelope["类型"])
        self.assertTrue(stderr.endswith(b"\n"))

    def good_bytes(self, **mutate):
        doc = make_input(
            [request("k1", "建立", "s1", ["alice", "pw"], 0)]
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
            encode(make_input([])) + b"\xff"
        )

    def test_no_leading_whitespace_trailing_only(self):
        good = encode(make_input([request("k", "建立", "s", ["alice", "pw"], 0)]))
        self.assert_rejected(b" " + good)
        self.assert_rejected(good + b"x")
        # 尾部仅许空白。
        code, stdout, _ = run_raw(good + b"\n\t ")
        self.assertEqual((code, stdout[:1]), (0, b"{"))

    def test_top_level_key_set_and_order(self):
        self.assert_rejected(b"{}")
        self.assert_rejected(
            b'{"users":[],"config":{},"requests":[],"query_ms":0,"extra":1}'
        )
        doc = make_input([request("k", "建立", "s", ["alice", "pw"], 0)])
        reordered = {
            "config": doc["config"],
            "users": doc["users"],
            "requests": doc["requests"],
            "query_ms": 0,
        }
        self.assert_rejected(encode(reordered))

    def test_duplicate_keys(self):
        self.assert_rejected(
            b'{"users":[],"users":[],"config":{},"requests":[],"query_ms":0}'
        )
        self.assert_rejected(
            b'{"users":[["a","p"],["a","q"]],"config":'
            + encode(config_v10())
            + b',"requests":[],"query_ms":0}'
        )

    def test_users_shape(self):
        self.assert_rejected(self.good_bytes(users=[]))
        self.assert_rejected(self.good_bytes(users={}))
        self.assert_rejected(self.good_bytes(users=["alice"]))
        self.assert_rejected(self.good_bytes(users=[["alice"]]))
        self.assert_rejected(self.good_bytes(users=[["alice", "pw", "x"]]))
        self.assert_rejected(self.good_bytes(users=[[1, "pw"]]))
        self.assert_rejected(self.good_bytes(users=[["alice", 1]]))
        self.assert_rejected(self.good_bytes(users=[["a\0", "pw"]]))
        # 未排序/重复。
        self.assert_rejected(
            self.good_bytes(users=[["bob", "p"], ["alice", "p"]])
        )
        self.assert_rejected(
            self.good_bytes(users=[["a", "p1"], ["a", "p2"]])
        )

    def test_config_must_be_v10_with_default_pool(self):
        cfg = config_v10()
        cfg["版本"] = 9
        self.assert_rejected(self.good_bytes(config=cfg))
        self.assert_rejected(self.good_bytes(config=[]))
        self.assert_rejected(self.good_bytes(config=None))
        other = config_v10(
            pools=[
                {"标识": "other", "CIDR": "10.0.0.0/30", "保留": [], "静态": []}
            ]
        )
        self.assert_rejected(self.good_bytes(config=other))
        # v10 键集：缺容量节即非法。
        broken = config_v10()
        del broken["容量"]
        self.assert_rejected(self.good_bytes(config=broken))
        # 字段类型错（配置内类型错统一 ValueError，退出 2）。
        broken = config_v10()
        broken["会话"]["总数"] = "10"
        self.assert_rejected(self.good_bytes(config=broken))
        # 用户模板引用未注册用户。
        with_ref = config_v10(
            templates=[
                {"标识": "g", "限速": 1, "突发": 0, "配额": 1,
                 "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
                 "超限": "拒绝"}
            ],
            user_templates=(("ghost", "g"),),
        )
        self.assert_rejected(self.good_bytes(config=with_ref))

    def test_requests_shape(self):
        self.assert_rejected(self.good_bytes(requests=[]))
        self.assert_rejected(self.good_bytes(requests={}))
        good_item = request("k", "建立", "s", ["alice", "pw"], 0)
        # 键集/键序。
        self.assert_rejected(
            self.good_bytes(requests=[{"key": "k"}])
        )
        reordered = {
            "now_ms": 0,
            "key": "k",
            "op": "建立",
            "sid": "s",
            "args": ["alice", "pw"],
        }
        self.assert_rejected(self.good_bytes(requests=[reordered]))
        # op 非法。
        bad = dict(good_item)
        bad["op"] = "炸"
        self.assert_rejected(self.good_bytes(requests=[bad]))
        bad = dict(good_item)
        bad["op"] = 0
        self.assert_rejected(self.good_bytes(requests=[bad]))
        # key/sid 类型与取值。
        bad = dict(good_item)
        bad["key"] = 0
        self.assert_rejected(self.good_bytes(requests=[bad]))
        bad = dict(good_item)
        bad["sid"] = ["x"]
        self.assert_rejected(self.good_bytes(requests=[bad]))
        # now_ms 类型与范围。
        bad = dict(good_item)
        bad["now_ms"] = -1
        self.assert_rejected(self.good_bytes(requests=[bad]))
        bad = dict(good_item)
        bad["now_ms"] = True
        self.assert_rejected(self.good_bytes(requests=[bad]))
        bad = dict(good_item)
        bad["now_ms"] = "0"
        self.assert_rejected(self.good_bytes(requests=[bad]))

    def test_args_forms(self):
        # 建立 args 须二元字符串数组。
        establish = request("k", "建立", "s", ["alice", "pw"], 0)
        for bad_args in (["alice"], ["alice", "pw", "x"], "x", 42, [0, "pw"]):
            bad = dict(establish)
            bad["args"] = bad_args
            self.assert_rejected(self.good_bytes(requests=[bad]))
        # 无参操作 args 须为 null。
        for op in ("续租", "挂起", "下线"):
            for bad_args in ([], 0, "x", False):
                item = request("k", op, "s", bad_args, 0)
                self.assert_rejected(self.good_bytes(requests=[item]))
        # 迁移/接管/恢复同建立形态。
        for op, first in (
            ("迁移", "b"), ("接管", "old"), ("恢复", "default")
        ):
            good = request("k", op, "s", [first, "pw"], 0)
            self.assertEqual(run_doc(self._with([good]))[0], 0)
            bad = request("k", op, "s", [first], 0)
            self.assert_rejected(
                self.good_bytes(requests=[bad])
            )

    @staticmethod
    def _with(items):
        pools = [
            {"标识": "default", "CIDR": "10.0.0.0/30", "保留": [], "静态": []},
            {"标识": "b", "CIDR": "192.168.0.0/30", "保留": [], "静态": []},
        ]
        return make_input(
            [request("base", "建立", "old", ["alice", "pw"], 0)] + items,
            config=config_v10(pools=pools),
            query_ms=0,
        )

    def test_query_ms(self):
        self.assert_rejected(self.good_bytes(query_ms=-1))
        self.assert_rejected(self.good_bytes(query_ms=True))
        self.assert_rejected(self.good_bytes(query_ms="0"))
        self.assert_rejected(self.good_bytes(query_ms=1.5))

    def test_requests_count_limit(self):
        items = [
            request(f"k{i}", "下线", f"s{i}", None, 0)
            for i in range(1001)
        ]
        self.assert_rejected(self.good_bytes(requests=items))

    def test_validation_failure_executes_nothing(self):
        # 非法输入时 stdout 必须为空（错误信封测试已覆盖），且不依赖任何
        # 请求顺序副作用——再以一个“首请求即可成功、末请求形态非法”的
        # 文档确认整体被拒。
        doc = make_input(
            [
                request("k1", "建立", "s1", ["alice", "pw"], 0),
                request("k2", "炸", "s2", None, 0),
            ]
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")


class SessionRunSubprocessTest(unittest.TestCase):
    """端到端：真实子进程验证退出码与流分离。"""

    def test_subprocess_success_and_error(self):
        good = encode(
            make_input([request("k", "建立", "s", ["alice", "pw"], 0)])
        )
        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=good, capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")
        self.assertTrue(proc.stdout.endswith(b"\n"))

        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=b"{", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "session-run", "类型": "ValueError"},
        )

    def test_unknown_subcommand_uses_stats_merge_envelope(self):
        proc = subprocess.run(
            [sys.executable, "access.py", "nope"],
            input=b"{}", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "stats-merge", "类型": "ValueError"},
        )

    def test_existing_commands_unchanged(self):
        proc = subprocess.run(
            [sys.executable, "access.py", "stats-delta"],
            input=b"{}", capture_output=True, check=False,
        )
        # stats-delta 收到 {} 仍为其原有 ValueError 信封。
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr)["错误"], "stats-delta"
        )


if __name__ == "__main__":
    unittest.main()
