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
        "版本": 4,
        "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 100000, "租期毫秒": 100000},
        "地址池": [
            {"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}
        ],
        "模板": [
            {"标识": "gold", "限速": 1000000, "突发": 0, "配额": 1000, "超限": "拒绝"},
        ],
        "用户模板": [["alice", "gold"], ["bob", "gold"]],
        "容量": {"队列上限": 1024, "最大等待毫秒": 0},
    }
    s.load_config(json.dumps(config, ensure_ascii=False))
    return s


def parse(out):
    return json.loads(out)


class RuntimeCheckpointTest(unittest.TestCase):
    def test_empty(self):
        s = make()
        out = s.runtime_checkpoint(0)
        self.assertTrue(out.endswith("\n"))
        doc = parse(out)
        self.assertEqual(list(doc), ["版本", "时刻", "容量", "配额", "摘要"])
        self.assertEqual(doc["版本"], 1)
        self.assertEqual(doc["时刻"], 0)
        self.assertEqual(list(doc["容量"]), ["时刻", "事件", "会话", "排队", "状态哈希"])
        self.assertEqual(doc["容量"]["时刻"], 0)
        self.assertEqual(doc["配额"], {"版本": 1, "账本": []})
        head = {k: doc[k] for k in ("版本", "时刻", "容量", "配额")}
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(
            doc["摘要"], hashlib.sha256(blob.encode("utf-8")).hexdigest()
        )

    def test_param_validation(self):
        s = make()
        for bad in (True, "0", None, 1.5):
            with self.assertRaises(TypeError):
                s.runtime_checkpoint(bad)
        with self.assertRaises(ValueError):
            s.runtime_checkpoint(-1)

    def test_ages_once_and_matches_clog_quota(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        # idle_ms=100000；在期限同刻后导出应先老化（挂起）。
        out = s.runtime_checkpoint(100000)
        doc = parse(out)
        self.assertEqual(doc["容量"], parse(s.clog(100000)))
        self.assertEqual(doc["配额"], parse(s.quota_checkpoint()))
        sessions = {r["会话"]: r["状态"] for r in doc["容量"]["会话"]}
        self.assertEqual(sessions["s1"], "挂起")

    def test_no_audit(self):
        s = make()
        s.runtime_checkpoint(0)
        self.assertEqual(parse(s.audit())["事件"], [])


class RuntimeRestoreTest(unittest.TestCase):
    def test_roundtrip_byte_stable(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        cp = s.runtime_checkpoint(0)
        out = s.runtime_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(s.runtime_checkpoint(0), cp)

    def test_cross_instance_restore(self):
        s1 = make()
        s1.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s1.meter("m1", "s1", 100, 0)
        cp = s1.runtime_checkpoint(0)
        s2 = make()
        out = s2.runtime_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(s2.runtime_checkpoint(0), cp)
        # 计量沿用恢复的账本。
        s2.do("k2", "建立", "s2", ("bob", "pw"), 0)
        stats = parse(s2.quota_stats("alice", 0))
        self.assertEqual(stats["累计"], 100)

    def test_restore_replaces_both_parts(self):
        s1 = make()
        s1.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s1.meter("m1", "s1", 100, 0)
        cp = s1.runtime_checkpoint(0)
        s2 = make()
        s2.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s2.meter("m2", "s2", 5, 0)
        # 目标已有包外会话 -> StateError（不同摘要的覆盖状态）。
        with self.assertRaises(StateError):
            s2.runtime_restore("r1", cp)
        # 同 key 失败不占位；空目标可恢复。
        s3 = make()
        self.assertEqual(s3.runtime_restore("r1", cp), cp)

    def test_quota_only_divergence_restores(self):
        s1 = make()
        s1.do("k1", "建立", "s1", ("alice", "pw"), 0)
        cp = s1.runtime_checkpoint(0)
        s2 = make()
        s2.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s2.meter("m1", "s1", 100, 0)  # 仅账本不同
        out = s2.runtime_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(parse(s2.quota_checkpoint())["账本"], [])

    def test_type_errors(self):
        s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.runtime_restore(bad_key, "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.runtime_restore("k", bad_text)

    def test_value_errors(self):
        s = make()
        good = parse(s.runtime_checkpoint(0))
        cap = json.dumps(good["容量"], ensure_ascii=False, separators=(",", ":"))
        quota = json.dumps(good["配额"], ensure_ascii=False, separators=(",", ":"))

        def pkg(**kw):
            d = {
                "版本": 1,
                "时刻": 0,
                "容量": json.loads(cap),
                "配额": json.loads(quota),
            }
            d.update(kw)
            head = {k: d[k] for k in ("版本", "时刻", "容量", "配额")}
            blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
            d["摘要"] = kw.get(
                "摘要", hashlib.sha256(blob.encode("utf-8")).hexdigest()
            )
            return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            '"x"',
            '{"版本":1}',
            pkg(版本=2),  # 版本错
            pkg(版本=True),
            pkg(时刻=-1),
            pkg(时刻=True),
            pkg(时刻=1),  # 容量时刻 != 顶层
            pkg(摘要="0" * 64),  # 摘要不符
            pkg(摘要="ABC"),
            pkg(摘要=123),
            # 键序错（时刻先于版本）。
            '{"时刻":0,"版本":1,"容量":%s,"配额":%s,"摘要":"%s"}'
            % (cap, quota, "0" * 64),
            # 重键。
            '{"版本":1,"版本":1,"时刻":0,"容量":%s,"配额":%s,"摘要":"%s"}'
            % (cap, quota, "0" * 64),
        ]
        for text in bad_texts:
            with self.subTest(text=text[:60]):
                with self.assertRaises(ValueError):
                    s.runtime_restore("k", text)

    def test_capacity_canonical_form_enforced(self):
        s = make()
        doc = parse(s.runtime_checkpoint(0))
        # 容量顶层键序打乱（重算摘要）-> ValueError。
        cap = doc["容量"]
        reordered = {
            "事件": cap["事件"],
            "时刻": cap["时刻"],
            "会话": cap["会话"],
            "排队": cap["排队"],
            "状态哈希": cap["状态哈希"],
        }
        head = {
            "版本": 1,
            "时刻": 0,
            "容量": reordered,
            "配额": doc["配额"],
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        pkg = dict(head)
        pkg["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        text = json.dumps(pkg, ensure_ascii=False, separators=(",", ":"))
        with self.assertRaises(ValueError):
            s.runtime_restore("k", text)

    def test_resource_errors(self):
        s = make()
        doc = parse(s.runtime_checkpoint(0))

        def pkg_with_quota(rows):
            d = {
                "版本": 1,
                "时刻": 0,
                "容量": doc["容量"],
                "配额": {"版本": 1, "账本": rows},
            }
            head = json.dumps(d, ensure_ascii=False, separators=(",", ":"))
            d["摘要"] = hashlib.sha256(head.encode("utf-8")).hexdigest()
            return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

        # 未注册用户。
        with self.assertRaises(ResourceError):
            s.runtime_restore("r1", pkg_with_quota([["nobody", "gold", 0, 0, 1]]))
        # 未知模板。
        with self.assertRaises(ResourceError):
            s.runtime_restore("r2", pkg_with_quota([["alice", "bronze", 0, 0, 1]]))
        # 令牌超桶容 (1000000+0)*1000。
        with self.assertRaises(ResourceError):
            s.runtime_restore(
                "r3", pkg_with_quota([["alice", "gold", 0, 0, 1000000001]])
            )
        # 失败不改运行态。
        self.assertEqual(s.quota_checkpoint(), '{"版本":1,"账本":[]}\n')

    def test_capacity_carry_resource_error(self):
        s1 = make()
        s1.do("k1", "建立", "s1", ("alice", "pw"), 0)
        cp = s1.runtime_checkpoint(0)
        # 无池目标：池址不承载。
        auth = Authenticator(3, 1000)
        auth.add("alice", "pw")
        s2 = Sessions(auth, 10, 5, 100000, lease_ms=100000)
        with self.assertRaises(ResourceError):
            s2.runtime_restore("r1", cp)

    def test_replay_semantics(self):
        s = make()
        t1 = s.runtime_checkpoint(0)
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        t2 = s.runtime_checkpoint(0)
        self.assertNotEqual(t1, t2)
        # 失败后不占 key。
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", "bad")
        out = s.runtime_restore("r1", t2)
        self.assertEqual(out, t2)
        # 同型同 text 重放无副作用，返回缓存。
        self.assertEqual(s.runtime_restore("r1", t2), t2)
        # 异参 ValueError。
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", t1)
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", None)
        # 与 quota_restore 域独立。
        s.runtime_restore("shared", t2)
        # 不审计：恢复前后审计链不变（do 建立本身入链）。
        self.assertEqual(len(parse(s.audit())["事件"]), 1)
        self.assertEqual(parse(s.takeover_audit())["事件"], [])

    def test_failure_does_not_change_instance(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        before = s.runtime_checkpoint(0)
        with self.assertRaises(ValueError):
            s.runtime_restore("r1", "not json")
        with self.assertRaises(TypeError):
            s.runtime_restore("r2", None)
        self.assertEqual(s.runtime_checkpoint(0), before)

    def test_restore_does_not_age(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        cp = s.runtime_checkpoint(0)
        # 越过空闲期限恢复：不老化，会话仍在线。
        s.runtime_restore("r1", cp)
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")


if __name__ == "__main__":
    unittest.main()
