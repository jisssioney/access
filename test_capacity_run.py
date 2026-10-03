"""capacity-run 子命令测试：信封校验、容量请求重放、容量水位与确定性输出。"""

import hashlib
import io
import json
import subprocess
import sys
import unittest

import access


def config_v11(cidr="10.0.0.0/29", pools=None, total=10, per=5,
               queue=1024, max_wait=0, policy="拒绝"):
    if pools is None:
        pools = [
            {"标识": "default", "CIDR": cidr, "保留": [], "静态": []}
        ]
    return {
        "版本": 11,
        "会话": {"总数": total, "每用户": per,
                 "空闲毫秒": 1000, "租期毫秒": 5000},
        "地址池": pools,
        "模板": [],
        "用户模板": [],
        "容量": {"队列上限": queue, "最大等待毫秒": max_wait,
                 "队满策略": policy},
        "认证": {
            "最大失败": 3,
            "锁定毫秒": 1000,
            "重试基数毫秒": 0,
            "重试上限毫秒": 0,
        },
        "模板地址池": [],
    }


def request(key, op, sid, args, now_ms):
    return {"key": key, "op": op, "sid": sid, "args": args,
            "now_ms": now_ms}


def make_input(requests, users=(("alice", "pw"), ("bob", "pw")),
               config=None, query_ms=0):
    return {
        "users": [list(pair) for pair in users],
        "config": config if config is not None else config_v11(),
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
    sys.argv = ["access.py", "capacity-run"]
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
    head = {key: doc[key] for key in ("版本", "项目", "会话", "容量")}
    blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def apply(key, sid, user, password, wait, now_ms):
    return request(key, "申请", sid, [user, password, wait], now_ms)


def cancel(key, sid, now_ms):
    return request(key, "取消", sid, None, now_ms)


def advance(key, now_ms):
    return request(key, "推进", "", None, now_ms)


class CapacityRunSuccessTest(unittest.TestCase):
    def test_basic_run_structure_and_digest(self):
        doc = make_input(
            [
                apply("k1", "s1", "alice", "pw", 500, 0),
                apply("k2", "s2", "bob", "pw", 500, 0),
            ],
            query_ms=200,
        )
        code, stdout, stderr = run_doc(doc)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, b"")
        self.assertTrue(stdout.endswith(b"\n"))
        out = json.loads(stdout)
        self.assertEqual(
            list(out), ["版本", "项目", "会话", "容量", "摘要"]
        )
        self.assertEqual(out["版本"], 1)
        self.assertEqual([item["序号"] for item in out["项目"]], [0, 1])
        for item in out["项目"]:
            self.assertEqual(list(item), ["序号", "结果", "输出", "类型"])
            self.assertTrue(item["结果"])
            self.assertEqual(item["类型"], "")
            self.assertIsNotNone(item["输出"])
        # 申请成功输出为 capacity 原返回对象。
        self.assertEqual(out["项目"][0]["输出"]["会话"], "s1")
        self.assertEqual(out["项目"][0]["输出"]["结果"], "在线")
        self.assertEqual(out["摘要"], head_digest(out))
        # 容量水位：capacity_stats 的固定键序。
        self.assertEqual(
            list(out["容量"]),
            ["时刻", "在线", "挂起", "排队", "可用", "水位",
             "最早截止", "用户", "池"],
        )
        self.assertEqual(out["容量"]["时刻"], 200)
        self.assertEqual(out["容量"]["在线"], 2)
        self.assertEqual(out["容量"]["排队"], 0)
        self.assertEqual(out["容量"]["水位"], 0)
        self.assertEqual(out["容量"]["最早截止"], 0)
        # 会话视图：sessions 全量第一页。
        self.assertEqual(
            list(out["会话"]), ["时刻", "下个", "剩余", "项目"]
        )
        self.assertEqual(
            [row["会话"] for row in out["会话"]["项目"]], ["s1", "s2"]
        )
        self.assertEqual(out["会话"]["剩余"], 0)

    def test_compact_lf_terminated_and_cjk_passthrough(self):
        doc = make_input(
            [apply("k1", "会", "金牌", "pw", 500, 0)],
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
        # /29 共 6 个可用地址：6 个 alice 在线后，第 7 个 alice 无址可取而
        # 入队等待（成功结果，非失败）。
        cfg = config_v11(per=10)
        doc = make_input(
            [
                apply("ka", "a", "alice", "pw", 500, 0),
                apply("kb", "b", "bob", "bad", 500, 0),  # AuthError
                apply("kc", "c", "alice", "pw", 500, 0),
                apply("kd", "d", "alice", "pw", 500, 0),
                apply("ke", "e", "alice", "pw", 500, 0),
                apply("kf", "f", "alice", "pw", 500, 0),
                apply("kg", "g", "alice", "pw", 500, 0),
                apply("kh", "h", "alice", "pw", 10000, 0),  # 排队
                cancel("ki", "ghost", 10),  # KeyError
                apply("ka", "a", "alice", "pw", 500, 0),  # 重放
            ],
            config=cfg,
            query_ms=100,
        )
        code, stdout, stderr = run_doc(doc)
        # 合法信封即使含业务失败也退出 0、stderr 空。
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
                (True, ""),
                (False, "KeyError"),
                (True, ""),
            ],
        )
        self.assertEqual(out["项目"][7]["输出"]["结果"], "排队")
        for item in out["项目"]:
            if item["结果"]:
                self.assertIsNotNone(item["输出"])
                self.assertEqual(item["类型"], "")
            else:
                self.assertIsNone(item["输出"])
                self.assertNotEqual(item["类型"], "")
        # 失败不留半分配：在线恰 6，排队 1；重放不新增。
        self.assertEqual(out["容量"]["在线"], 6)
        self.assertEqual(out["容量"]["排队"], 1)
        self.assertEqual(out["容量"]["水位"], 1)

    def test_same_key_same_params_replays_original(self):
        doc = make_input(
            [
                apply("dup", "s1", "alice", "pw", 500, 0),
                apply("dup", "s1", "alice", "pw", 500, 0),
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
        self.assertEqual(out["容量"]["在线"], 1)

    def test_same_key_different_params_is_value_error_item(self):
        doc = make_input(
            [
                apply("dup", "s1", "alice", "pw", 500, 0),
                apply("dup", "s2", "alice", "pw", 500, 0),
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
        self.assertEqual(out["容量"]["在线"], 1)

    def test_state_error_duplicate_sid_and_cancel_online(self):
        doc = make_input(
            [
                apply("k1", "s1", "alice", "pw", 500, 0),
                apply("k2", "s1", "alice", "pw", 500, 0),  # 重复 sid
                cancel("k3", "s1", 10),  # 取消在线项
            ],
            config=config_v11(per=10),
            query_ms=20,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(
            [item["类型"] for item in out["项目"]],
            ["", "StateError", "StateError"],
        )

    def test_resource_error_queue_full(self):
        # 总数 2、队限 1：2 在线、1 排队、再来即 ResourceError。
        cfg = config_v11(cidr="10.0.0.0/24", total=2, per=2, queue=1)
        doc = make_input(
            [
                apply("a0", "a0", "u0", "pw", 10000, 0),
                apply("a1", "a1", "u1", "pw", 10000, 0),
                apply("a2", "a2", "u2", "pw", 10000, 0),
                apply("a3", "a3", "u3", "pw", 10000, 0),
            ],
            users=(("u0", "pw"), ("u1", "pw"), ("u2", "pw"),
                   ("u3", "pw")),
            config=cfg,
            query_ms=0,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertEqual(
            [item["类型"] for item in out["项目"]],
            ["", "", "", "ResourceError"],
        )
        self.assertEqual(out["项目"][2]["输出"]["结果"], "排队")
        self.assertEqual(out["容量"]["在线"], 2)
        self.assertEqual(out["容量"]["水位"], 1)

    def test_cancel_queued_and_advance_outputs(self):
        cfg = config_v11(cidr="10.0.0.0/24", total=1, per=1)
        doc = make_input(
            [
                apply("q0", "a0", "u0", "pw", 10000, 0),
                apply("q1", "a1", "u1", "pw", 10000, 0),  # 排队
                cancel("q2", "a1", 100),                  # 取消排队
                apply("q3", "a2", "u1", "pw", 10000, 100),
                advance("q4", 200),                       # 仍排队
            ],
            users=(("u0", "pw"), ("u1", "pw")),
            config=cfg,
            query_ms=200,
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertTrue(all(item["结果"] for item in out["项目"]))
        self.assertEqual(
            [out["项目"][i]["输出"]["结果"] for i in range(3)],
            ["在线", "排队", "取消"],
        )
        self.assertEqual(
            list(out["项目"][4]["输出"]),
            ["时刻", "在线", "排队", "变更"],
        )
        self.assertEqual(out["项目"][4]["输出"]["在线"], 1)
        self.assertEqual(out["项目"][4]["输出"]["排队"], 1)
        # a0 仍在线占满总数 1，a2 无法晋升：变更为空。
        self.assertEqual(out["项目"][4]["输出"]["变更"], [])
        self.assertEqual(out["容量"]["在线"], 1)
        self.assertEqual(out["容量"]["排队"], 1)

    def test_advance_promotes_after_capacity_frees(self):
        # 仿既有容量语义：/29 六个可用址全部在线，第七项排队；空闲同刻到期
        # 六项老化挂起释址，推进令排队项按入队序晋升。
        cfg = config_v11(cidr="10.0.0.0/29", total=10, per=10)
        cfg["会话"]["空闲毫秒"] = 100
        users = tuple((f"u{i}", "pw") for i in range(7))
        requests = [
            apply(f"a{i}", f"s{i}", f"u{i}", "pw", 1000, 0)
            for i in range(6)
        ]
        requests.append(apply("a6", "q1", "u6", "pw", 1000, 1))
        requests.append(advance("v1", 100))
        doc = make_input(requests, users=users, config=cfg, query_ms=100)
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 0)
        out = json.loads(stdout)
        self.assertTrue(all(item["结果"] for item in out["项目"]))
        # 排队项入队序为 1，按入队序出现在变更中。
        self.assertEqual(out["项目"][7]["输出"]["变更"], [1])
        self.assertEqual(out["项目"][7]["输出"]["在线"], 1)
        self.assertEqual(out["项目"][7]["输出"]["排队"], 0)
        self.assertEqual(out["容量"]["在线"], 1)
        self.assertEqual(out["容量"]["挂起"], 6)
        self.assertEqual(out["容量"]["排队"], 0)

    def test_output_is_deterministic_byte_for_byte(self):
        doc = make_input(
            [
                apply("k1", "s1", "alice", "pw", 500, 0),
                apply("k2", "s2", "bob", "pw", 500, 0),
                advance("k3", 100),
            ],
            query_ms=200,
        )
        first = run_doc(doc)[1]
        for _ in range(3):
            self.assertEqual(run_doc(doc)[1], first)


class CapacityRunValidationTest(unittest.TestCase):
    def assert_rejected(self, raw, type_name=None):
        code, stdout, stderr = run_raw(raw)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")
        envelope = json.loads(stderr)
        self.assertEqual(list(envelope), ["错误", "类型"])
        self.assertEqual(envelope["错误"], "capacity-run")
        self.assertTrue(envelope["类型"])
        if type_name is not None:
            self.assertEqual(envelope["类型"], type_name)
        self.assertTrue(stderr.endswith(b"\n"))

    def good_bytes(self, **mutate):
        doc = make_input(
            [apply("k1", "s1", "alice", "pw", 500, 0)]
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
            encode(make_input([cancel("k", "s", 0)])) + b"\xff"
        )

    def test_no_leading_whitespace_trailing_only(self):
        good = encode(make_input([apply("k", "s", "alice", "pw", 1, 0)]))
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
        doc = make_input([apply("k", "s", "alice", "pw", 1, 0)])
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

    def test_users_shape(self):
        self.assert_rejected(self.good_bytes(users=[]))
        self.assert_rejected(self.good_bytes(users={}))
        self.assert_rejected(self.good_bytes(users=["alice"]))
        self.assert_rejected(self.good_bytes(users=[["alice"]]))
        self.assert_rejected(self.good_bytes(users=[["alice", "pw", "x"]]))
        self.assert_rejected(self.good_bytes(users=[[1, "pw"]]))
        self.assert_rejected(self.good_bytes(users=[["alice", 1]]))
        self.assert_rejected(self.good_bytes(users=[["a\0", "pw"]]))
        self.assert_rejected(
            self.good_bytes(users=[["bob", "p"], ["alice", "p"]])
        )
        self.assert_rejected(
            self.good_bytes(users=[["a", "p1"], ["a", "p2"]])
        )

    def test_config_must_be_v12_family_with_default_pool(self):
        cfg = config_v11()
        cfg["版本"] = 9
        self.assert_rejected(self.good_bytes(config=cfg))
        self.assert_rejected(self.good_bytes(config=[]))
        self.assert_rejected(self.good_bytes(config=None))
        other = config_v11(
            pools=[
                {"标识": "other", "CIDR": "10.0.0.0/30",
                 "保留": [], "静态": []}
            ]
        )
        self.assert_rejected(self.good_bytes(config=other))
        broken = config_v11()
        del broken["容量"]
        self.assert_rejected(self.good_bytes(config=broken))
        # 用户模板引用未注册用户。
        cfg_ref = config_v11()
        cfg_ref["模板"] = [
            {"标识": "g", "限速": 1, "突发": 0, "配额": 1,
             "周期毫秒": 0, "会话上限": 0, "排队优先级": 0,
             "超限": "拒绝"}
        ]
        cfg_ref["用户模板"] = [["ghost", "g"]]
        self.assert_rejected(self.good_bytes(config=cfg_ref))

    def test_requests_shape(self):
        self.assert_rejected(self.good_bytes(requests=[]))
        self.assert_rejected(self.good_bytes(requests={}))
        good_item = apply("k", "s", "alice", "pw", 1, 0)
        # 键集/键序。
        self.assert_rejected(self.good_bytes(requests=[{"key": "k"}]))
        reordered = {
            "now_ms": 0,
            "key": "k",
            "op": "申请",
            "sid": "s",
            "args": ["alice", "pw", 1],
        }
        self.assert_rejected(self.good_bytes(requests=[reordered]))
        # op 非法/类型错。
        bad = dict(good_item)
        bad["op"] = "建立"
        self.assert_rejected(self.good_bytes(requests=[bad]))
        bad = dict(good_item)
        bad["op"] = 0
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "TypeError"
        )
        # key/sid 类型。
        bad = dict(good_item)
        bad["key"] = 0
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "TypeError"
        )
        bad = dict(good_item)
        bad["sid"] = ["x"]
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "TypeError"
        )
        # now_ms 类型与范围。
        bad = dict(good_item)
        bad["now_ms"] = -1
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "ValueError"
        )
        bad = dict(good_item)
        bad["now_ms"] = True
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "TypeError"
        )
        bad = dict(good_item)
        bad["now_ms"] = "0"
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "TypeError"
        )

    def test_apply_args_forms(self):
        good = apply("k", "s", "alice", "pw", 1, 0)
        # 长度错。
        for bad_args in (
            ["alice", "pw"],
            ["alice", "pw", 1, 9],
        ):
            bad = dict(good)
            bad["args"] = bad_args
            self.assert_rejected(
                self.good_bytes(requests=[bad]), "ValueError"
            )
        # 等待须为非 bool 正 int。
        for wait, type_name in (
            (0, "ValueError"),
            (-1, "ValueError"),
            (True, "TypeError"),
            ("1", "TypeError"),
            (1.5, "TypeError"),
        ):
            bad = dict(good)
            bad["args"] = ["alice", "pw", wait]
            self.assert_rejected(
                self.good_bytes(requests=[bad]), type_name
            )
        # 凭据字段类型/取值。
        for bad_args, type_name in (
            ([0, "pw", 1], "TypeError"),
            (["alice", 0, 1], "TypeError"),
            (["a\0", "pw", 1], "ValueError"),
        ):
            bad = dict(good)
            bad["args"] = bad_args
            self.assert_rejected(
                self.good_bytes(requests=[bad]), type_name
            )
        # 非数组标量 TypeError、tuple 形态以 JSON 数组出现故为 ValueError
        # （长度不符），此处以 dict 标量验证 TypeError。
        bad = dict(good)
        bad["args"] = None
        self.assert_rejected(
            self.good_bytes(requests=[bad]), "TypeError"
        )

    def test_cancel_and_advance_args_forms(self):
        for op, sid in (("取消", "s"), ("推进", "")):
            for bad_args in ([], 0, "x", False, ["a"]):
                item = request("k", op, sid, bad_args, 0)
                self.assert_rejected(
                    self.good_bytes(requests=[item]),
                    "ValueError" if isinstance(bad_args, list)
                    else "TypeError",
                )
        # 推进 sid 必须为空串。
        self.assert_rejected(
            self.good_bytes(requests=[advance_item("s", 0)]),
            "ValueError",
        )
        self.assert_rejected(
            self.good_bytes(requests=[request("k", "推进", 0, None, 0)]),
            "TypeError",
        )
        # 取消 sid 沿凭据约束：空串非法。
        self.assert_rejected(
            self.good_bytes(requests=[cancel("k", "", 0)]),
            "ValueError",
        )

    def test_query_ms(self):
        self.assert_rejected(self.good_bytes(query_ms=-1))
        self.assert_rejected(self.good_bytes(query_ms=True), "TypeError")
        self.assert_rejected(self.good_bytes(query_ms="0"), "TypeError")
        self.assert_rejected(self.good_bytes(query_ms=1.5), "TypeError")

    def test_requests_count_limit(self):
        items = [cancel(f"k{i}", f"s{i}", 0) for i in range(1001)]
        self.assert_rejected(self.good_bytes(requests=items))

    def test_validation_failure_executes_nothing(self):
        # 首请求可成功、末请求形态非法：整体拒绝、stdout 空。
        doc = make_input(
            [
                apply("k1", "s1", "alice", "pw", 1, 0),
                apply("k2", "s2", "alice", "pw", 0, 0),
            ]
        )
        code, stdout, _ = run_doc(doc)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, b"")


def advance_item(sid, now_ms):
    return request("k", "推进", sid, None, now_ms)


class CapacityRunSubprocessTest(unittest.TestCase):
    """端到端：真实子进程验证退出码与流分离。"""

    def test_subprocess_success_and_error(self):
        good = encode(
            make_input([apply("k", "s", "alice", "pw", 1, 0)])
        )
        proc = subprocess.run(
            [sys.executable, "access.py", "capacity-run"],
            input=good, capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")
        self.assertTrue(proc.stdout.endswith(b"\n"))

        proc = subprocess.run(
            [sys.executable, "access.py", "capacity-run"],
            input=b"{", capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "capacity-run", "类型": "ValueError"},
        )

    def test_no_extra_arguments(self):
        good = encode(
            make_input([apply("k", "s", "alice", "pw", 1, 0)])
        )
        proc = subprocess.run(
            [sys.executable, "access.py", "capacity-run", "x"],
            input=good, capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        # 多余参数按未知子命令处理，沿用 stats-merge 名。
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "stats-merge", "类型": "ValueError"},
        )

    def test_existing_commands_unchanged(self):
        # session-run 信封不接受容量操作。
        doc = make_input([apply("k", "s", "alice", "pw", 1, 0)])
        proc = subprocess.run(
            [sys.executable, "access.py", "session-run"],
            input=encode(doc), capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            json.loads(proc.stderr),
            {"错误": "session-run", "类型": "ValueError"},
        )


if __name__ == "__main__":
    unittest.main()
