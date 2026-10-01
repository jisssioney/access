import hashlib
import json
import os
import subprocess
import sys
import unittest

ACCESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "access.py")


def config_doc(
    total=10,
    per=5,
    idle_ms=100000,
    lease_ms=100000,
    pools=None,
    templates=(),
    user_templates=(),
):
    if pools is None:
        pools = [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
        ]
    return {
        "版本": 10,
        "会话": {
            "总数": total,
            "每用户": per,
            "空闲毫秒": idle_ms,
            "租期毫秒": lease_ms,
        },
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


def req(key, op, sid, args, now_ms):
    return {"key": key, "op": op, "sid": sid, "args": args, "now_ms": now_ms}


def payload(users, config, requests, query_ms=0):
    return {
        "users": [list(pair) for pair in users],
        "config": config,
        "requests": requests,
        "query_ms": query_ms,
    }


def run_cli(obj=None, raw=None, args=("session-run",)):
    if raw is None:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    proc = subprocess.run(
        [sys.executable, ACCESS, *args],
        input=raw,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.returncode, proc.stdout, proc.stderr


def establish(key, sid, user, now_ms, password="pw"):
    return req(key, "建立", sid, [user, password], now_ms)


class SessionRunSuccessTest(unittest.TestCase):
    def test_basic_establish_and_output_envelope(self):
        body = payload(
            [("alice", "pw"), ("bob", "pw")],
            config_doc(),
            [establish("k1", "s1", "alice", 0)],
            query_ms=0,
        )
        rc, out, err = run_cli(body)
        self.assertEqual(rc, 0)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out)
        self.assertEqual(
            list(doc), ["版本", "项目", "会话", "地址池", "摘要"]
        )
        self.assertEqual(doc["版本"], 1)
        item = doc["项目"][0]
        self.assertEqual(list(item), ["序号", "结果", "输出", "类型"])
        self.assertEqual(item["序号"], 0)
        self.assertIs(item["结果"], True)
        self.assertEqual(item["类型"], "")
        self.assertEqual(
            item["输出"],
            {
                "会话": "s1",
                "状态": "在线",
                "时刻": 0,
                "期限": 100000,
                "地址": "10.0.0.1",
                "租期": 100000,
            },
        )
        self.assertEqual(doc["会话"][0]["用户"], "alice")
        self.assertEqual(doc["地址池"]["时刻"], 0)
        self.assertEqual(doc["地址池"]["池"][0][0], "default")

    def test_digest_covers_first_four_fields(self):
        body = payload([("alice", "pw")], config_doc(), [
            establish("k1", "s1", "alice", 0),
            req("k2", "续租", "s1", None, 10),
        ], query_ms=50)
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        head = {key: doc[key] for key in ("版本", "项目", "会话", "地址池")}
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(
            doc["摘要"], hashlib.sha256(blob.encode("utf-8")).hexdigest()
        )
        # 摘要为 64 位小写十六进制且为尾字段。
        self.assertEqual(len(doc["摘要"]), 64)
        self.assertEqual(doc["摘要"], doc["摘要"].lower())

    def test_items_keep_request_order_and_index(self):
        body = payload(
            [("alice", "pw"), ("bob", "pw")],
            config_doc(),
            [
                establish("k1", "s1", "alice", 0),
                req("k2", "建立", "s2", ["bob", "bad"], 1),
                req("k3", "续租", "s1", None, 2),
                req("k4", "建立", "s3", ["nobody", "pw"], 3),
            ],
            query_ms=10,
        )
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(
            [(i["序号"], i["结果"], i["类型"]) for i in doc["项目"]],
            [
                (0, True, ""),
                (1, False, "AuthError"),
                (2, True, ""),
                (3, False, "KeyError"),
            ],
        )
        failed = [i for i in doc["项目"] if not i["结果"]]
        self.assertTrue(all(i["输出"] is None for i in failed))

    def test_same_key_same_params_replays_original(self):
        body = payload([("alice", "pw")], config_doc(), [
            establish("k1", "s1", "alice", 5),
            establish("k1", "s1", "alice", 5),
        ], query_ms=0)
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        items = json.loads(out)["项目"]
        self.assertTrue(all(i["结果"] for i in items))
        self.assertEqual(items[0]["输出"], items[1]["输出"])

    def test_same_key_different_params_is_recorded_value_error(self):
        body = payload([("alice", "pw")], config_doc(), [
            establish("k1", "s1", "alice", 0),
            req("k1", "续租", "s1", None, 1),
        ], query_ms=0)
        rc, out, err = run_cli(body)
        # 异参复用是业务失败：记录 ValueError，命令仍退出 0。
        self.assertEqual(rc, 0)
        self.assertEqual(err, b"")
        items = json.loads(out)["项目"]
        self.assertEqual(items[1]["结果"], False)
        self.assertEqual(items[1]["类型"], "ValueError")
        self.assertIsNone(items[1]["输出"])

    def test_replay_of_failure_does_not_reauthenticate(self):
        # 首次错密致 AuthError；同参重放沿用缓存，不再次计数或锁定。
        body = payload([("alice", "pw")], config_doc(), [
            req("k1", "建立", "s1", ["alice", "bad"], 0),
            req("k1", "建立", "s1", ["alice", "bad"], 0),
            establish("k2", "s2", "alice", 1),
        ], query_ms=0)
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        items = json.loads(out)["项目"]
        self.assertEqual(
            [(i["结果"], i["类型"]) for i in items],
            [(False, "AuthError"), (False, "AuthError"), (True, "")],
        )

    def test_failed_establish_leaves_no_half_allocation(self):
        body = payload([("alice", "pw")], config_doc(), [
            req("k1", "建立", "s1", ["alice", "bad"], 0),
            establish("k2", "s2", "alice", 0),
        ], query_ms=0)
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        # 认证失败不占址：唯一成功会话取首地址，池租用为 1。
        self.assertEqual(doc["项目"][1]["输出"]["地址"], "10.0.0.1")
        default_pool = doc["地址池"]["池"][0]
        self.assertEqual(default_pool[4], 1)  # 租用数

    def test_all_seven_ops_shapes(self):
        pools = [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []},
            {"标识": "second", "CIDR": "10.1.0.0/24", "保留": [], "静态": []},
        ]
        body = payload(
            [("alice", "pw"), ("bob", "pw")],
            config_doc(idle_ms=1000000, lease_ms=1000000, pools=pools),
            [
                establish("e1", "s1", "alice", 0),
                req("n1", "续租", "s1", None, 10),
                establish("e2", "s2", "bob", 50),
                req("m1", "迁移", "s2", ["second", "pw"], 60),
                req("t1", "接管", "s3", ["s1", "pw"], 70),
                req("u1", "挂起", "s2", None, 80),
                req("r1", "恢复", "s2", ["default", "pw"], 90),
                req("o1", "下线", "s2", None, 100),
            ],
            query_ms=200,
        )
        rc, out, err = run_cli(body)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertTrue(all(i["结果"] for i in doc["项目"]), out)
        self.assertEqual(doc["项目"][3]["输出"]["原池"], "default")
        self.assertEqual(doc["项目"][3]["输出"]["目标池"], "second")
        self.assertEqual(doc["项目"][4]["输出"]["旧会话"], "s1")
        self.assertEqual(doc["项目"][4]["输出"]["新会话"], "s3")
        self.assertEqual(doc["项目"][5]["输出"]["状态"], "挂起")
        self.assertEqual(doc["项目"][6]["输出"]["状态"], "在线")
        self.assertEqual(doc["项目"][6]["输出"]["池"], "default")
        self.assertEqual(doc["项目"][7]["输出"]["状态"], "下线")

    def test_query_view_applies_idle_aging_without_mutation(self):
        body = payload([("alice", "pw")], config_doc(idle_ms=100, lease_ms=100), [
            establish("k1", "s1", "alice", 0),
        ], query_ms=100)  # 同刻到期：视图为挂起、清址。
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        row = doc["会话"][0]
        self.assertEqual(row["状态"], "挂起")
        self.assertEqual(row["池"], "")
        self.assertEqual(row["地址"], "")
        self.assertEqual(row["租期"], 0)
        # 全量查询含会话墓碑（下线后仍列出）。
        body["requests"].append(req("k2", "下线", "s1", None, 0))
        rc, out, _err = run_cli(body)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(doc["会话"][0]["状态"], "下线")

    def test_byte_identical_for_same_input(self):
        raw = json.dumps(
            payload([("alice", "pw")], config_doc(), [
                establish("k1", "s1", "alice", 0),
                req("k2", "建立", "s2", ["bob", "pw"], 0),
            ], query_ms=1000000),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        first = run_cli(raw=raw)[1]
        second = run_cli(raw=raw)[1]
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        # 紧凑：无 ", " / ": "。
        self.assertNotIn(b", ", first)
        self.assertNotIn(b": ", first)

    def test_cjk_usernames_pass_through(self):
        body = payload([("金牌用户", "口令")], config_doc(), [
            establish("键一", "会话一", "金牌用户", 0, password="口令"),
        ], query_ms=0)
        rc, out, err = run_cli(body)
        self.assertEqual(rc, 0)
        self.assertIn("金牌用户".encode("utf-8"), out)


class SessionRunInvalidInputTest(unittest.TestCase):
    def _base(self):
        return payload(
            [("alice", "pw")],
            config_doc(),
            [establish("k1", "s1", "alice", 0)],
            query_ms=0,
        )

    def _reject(self, mutate, raw=None):
        body = self._base()
        if mutate is not None:
            mutate(body)
        rc, out, err = run_cli(body, raw=raw)
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        env = json.loads(err)
        self.assertEqual(list(env), ["错误", "类型"])
        self.assertEqual(env["错误"], "session-run")
        self.assertTrue(err.endswith(b"\n"))
        return env["类型"]

    def test_encoding_and_json(self):
        self._reject(None, raw=b"{ not json")
        self._reject(None, raw=b'{"a":\xff}')
        # 对象前不得有空白；尾部空白允许。
        rc, out, err = run_cli(raw=b' {"a":1}')
        self.assertEqual((rc, out), (2, b""))
        good = json.dumps(self._base(), ensure_ascii=False).encode("utf-8")
        rc, out, err = run_cli(raw=good + b"  \n\t")
        self.assertEqual(rc, 0)

    def test_duplicate_top_key(self):
        raw = (
            b'{"users":[["a","p"]],"config":null,"requests":[]'
            b',"query_ms":0,"query_ms":1}'
        )
        self._reject(None, raw=raw)

    def test_top_level_key_set_and_order(self):
        def extra(b):
            b["other"] = 1

        def swap(b):
            b["users"], b["config"] = b["config"], b["users"]

        def missing(b):
            del b["query_ms"]

        self._reject(extra)
        self._reject(swap)
        self._reject(missing)

    def test_user_array_rules(self):
        self._reject(lambda b: b.update(users=[]))  # 数量下界
        self._reject(lambda b: b.update(users={}))  # 类型
        self._reject(lambda b: b.update(users=[["alice"]]))  # 非二元
        self._reject(lambda b: b.update(users=[["alice", 1]]))  # 元素类型
        self._reject(lambda b: b.update(users=[["", "pw"]]))  # 空用户名
        self._reject(lambda b: b.update(users=[["a\0", "pw"]]))  # 含 NUL
        self._reject(
            lambda b: b.update(users=[["bob", "p"], ["alice", "p"]])
        )  # 排序
        self._reject(
            lambda b: b.update(users=[["alice", "p"], ["alice", "q"]])
        )  # 互异

    def test_config_rules(self):
        self._reject(lambda b: b.update(config=[]))
        self._reject(lambda b: b["config"].update(版本=9))
        self._reject(
            lambda b: b["config"].update(
                地址池=[
                    {"标识": "other", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
                ]
            )
        )
        self._reject(
            lambda b: b["config"].update(
                模板=[
                    {
                        "标识": "g",
                        "限速": 1,
                        "突发": 0,
                        "配额": 1,
                        "周期毫秒": 0,
                        "会话上限": 0,
                        "排队优先级": 0,
                        "超限": "拒绝",
                    }
                ],
                用户模板=[["ghost", "g"]],
            )
        )
        self._reject(
            lambda b: b["config"]["会话"].update(总数=0)
        )
        self._reject(
            lambda b: b["config"]["地址池"][0].update(CIDR="10.0.0.0/9")
        )

    def test_request_array_rules(self):
        self._reject(lambda b: b.update(requests=[]))
        self._reject(lambda b: b.update(requests={}))

        def many(b):
            b["requests"] = [
                establish("k", "s", "alice", 0) for _ in range(1001)
            ]

        self._reject(many)
        self._reject(lambda b: b["requests"][0].update(op="申请"))
        self._reject(lambda b: b["requests"][0].update(op=7))
        self._reject(lambda b: b["requests"][0].update(sid=3))
        self._reject(lambda b: b["requests"][0].update(key=""))
        self._reject(lambda b: b["requests"][0].update(args=None))
        self._reject(lambda b: b["requests"][0].update(args=["alice"]))
        self._reject(lambda b: b["requests"][0].update(args=["alice", 9]))
        self._reject(lambda b: b["requests"][0].update(now_ms=-1))
        self._reject(lambda b: b["requests"][0].update(now_ms=True))
        self._reject(lambda b: b["requests"][0].pop("sid"))

        def renew_with_args(b):
            b["requests"] = [req("n", "续租", "s1", [], 0)]

        self._reject(renew_with_args)

    def test_query_ms_rules(self):
        for value in (-1, True, 1.0, "0", None):
            self._reject(lambda b, v=value: b.update(query_ms=v))

    def test_invalid_input_executes_no_requests(self):
        # 配置非法：建立请求虽形态合法也不得执行——stdout 必须为空。
        env_type = self._reject(lambda b: b["config"].update(版本=11))
        self.assertEqual(env_type, "ValueError")

    def test_type_errors_mapped_to_exit_2(self):
        # 明确的类型非法仍归退出 2，信封类型为 TypeError。
        self.assertEqual(
            self._reject(lambda b: b.update(users={})), "TypeError"
        )
        self.assertEqual(
            self._reject(lambda b: b.update(query_ms="0")), "TypeError"
        )
        self.assertEqual(
            self._reject(lambda b: b.update(config=[])), "TypeError"
        )


class SessionRunDispatchTest(unittest.TestCase):
    def test_unknown_and_extra_args_use_stats_merge_envelope(self):
        for args in (("frob",), ("session-run", "x"), ()):
            rc, out, err = run_cli(raw=b"{}", args=args)
            self.assertEqual(rc, 2)
            self.assertEqual(out, b"")
            self.assertEqual(
                json.loads(err),
                {"错误": "stats-merge", "类型": "ValueError"},
            )

    def test_existing_entries_unchanged(self):
        # stats-merge 未知子命令以外入口仍可用：缺字段按 stats-merge 名报错。
        rc, _out, err = run_cli(raw=b"{}", args=("stats-merge",))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["错误"], "stats-merge")
        rc, _out, err = run_cli(raw=b"{}", args=("stats-delta",))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["错误"], "stats-delta")


if __name__ == "__main__":
    unittest.main()
