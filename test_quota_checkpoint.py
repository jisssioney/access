import json
import unittest

from access import Authenticator, ResourceError, Sessions, StateError


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


class QuotaCheckpointTest(unittest.TestCase):
    def test_empty(self):
        s = make()
        self.assertEqual(s.quota_checkpoint(), '{"版本":1,"账本":[]}\n')

    def test_format_and_order(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        s.meter("m2", "s2", 1, 0)
        out = s.quota_checkpoint()
        self.assertTrue(out.endswith("\n"))
        self.assertNotIn("\\u", out)  # ensure_ascii=False
        # 精确基线：键序版本/账本，项为五元列表，按 (用户, 模板) 码点升序。
        self.assertEqual(
            out,
            '{"版本":1,"账本":[["alice","gold",100,0,999900000],'
            '["bob","kill",1,0,999999000]]}\n',
        )
        doc = parse(out)
        self.assertEqual(list(doc), ["版本", "账本"])
        self.assertTrue(all(len(row) == 5 for row in doc["账本"]))

    def test_sorted_by_user_then_template_codepoint(self):
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
                {"标识": "gold", "限速": 1000, "突发": 0, "配额": 1000, "超限": "拒绝"},
                {"标识": "kill", "限速": 1000, "突发": 0, "配额": 1000, "超限": "拒绝"},
            ],
            # 同一模板多用户；alice 先绑 gold 再改绑 kill，留下两本历史账。
            "用户模板": [["alice", "gold"], ["zeb", "gold"], ["éve", "gold"]],
        }
        s.load_config(json.dumps(config, ensure_ascii=False))
        s.do("a", "建立", "sa", ("alice", "pw"), 0)
        s.do("z", "建立", "sz", ("zeb", "pw"), 0)
        s.do("e", "建立", "se", ("éve", "pw"), 0)
        s.meter("ma", "sa", 1, 0)
        s.meter("mz", "sz", 1, 0)
        s.meter("me", "se", 1, 0)
        config["用户模板"] = [["alice", "kill"], ["zeb", "gold"], ["éve", "gold"]]
        s.load_config(json.dumps(config, ensure_ascii=False))
        s.meter("ma2", "sa", 1, 5)
        keys = [(row[0], row[1]) for row in parse(s.quota_checkpoint())["账本"]]
        # 码点序：'z'(122) < 'é'(233)；alice 的 gold < kill。
        self.assertEqual(
            keys,
            [("alice", "gold"), ("alice", "kill"), ("zeb", "gold"), ("éve", "gold")],
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
                {"标识": "金牌", "限速": 1000, "突发": 0, "配额": 1000, "超限": "拒绝"}
            ],
            "用户模板": [["张三", "金牌"]],
        }
        s.load_config(json.dumps(config, ensure_ascii=False))
        s.do("k1", "建立", "s1", ("张三", "pw"), 0)
        s.meter("m1", "s1", 1, 0)
        out = s.quota_checkpoint()
        self.assertIn("张三", out)
        self.assertIn("金牌", out)
        self.assertNotIn("\\u", out)

    def test_does_not_age(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 越过空闲期限后导出，会话仍须在线（导出不老化）。
        s.quota_checkpoint()
        s.quota_checkpoint()
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")


class QuotaRestoreTest(unittest.TestCase):
    def test_roundtrip_and_byte_stable(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        s.meter("m2", "s1", 50, 1)
        cp = s.quota_checkpoint()
        out = s.quota_restore("r1", cp)
        self.assertEqual(out, cp)
        self.assertEqual(s.quota_checkpoint(), cp)

    def test_restore_sets_triple_for_meter_and_stats(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # gold 容量 (1000000+0)*1000；令牌恢复为恰好 50*1000，时刻 10。
        text = '{"版本":1,"账本":[["alice","gold",500,10,50000]]}\n'
        out = s.quota_restore("r1", text)
        self.assertEqual(parse(out)["账本"], [["alice", "gold", 500, 10, 50000]])
        # quota_stats 按当前绑定取账，按限速补充演算不落账。
        stats = parse(s.quota_stats("alice", 10))
        self.assertEqual(stats["累计"], 500)
        self.assertEqual(stats["剩余"], 500)
        self.assertEqual(stats["令牌"], 50000)
        # meter 沿用三值：t=10，t=11 补 1000000 令牌，60 字节可过。
        res = parse(s.meter("m9", "s1", 60, 11))
        self.assertEqual(res["结果"], "通过")
        self.assertEqual(res["累计"], 560)

    def test_restore_is_full_atomic_replace_of_existing_template_ledgers(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        s.meter("m2", "s2", 1, 0)
        # 检查点只列 alice：bob/kill 账本（模板现存）应被清除。
        text = '{"版本":1,"账本":[["alice","gold",7,0,123]]}\n'
        s.quota_restore("r1", text)
        keys = [(r[0], r[1]) for r in parse(s.quota_checkpoint())["账本"]]
        self.assertEqual(keys, [("alice", "gold")])
        # 空账本列表同样合法：清空全部现存模板账本。
        s.quota_restore("r2", '{"版本":1,"账本":[]}')
        self.assertEqual(parse(s.quota_checkpoint())["账本"], [])

    def test_user_need_not_be_bound_to_template(self):
        s = make()
        # carol 已注册但未绑模板；可恢复其 gold 账本，不报错且可再导出。
        text = '{"版本":1,"账本":[["carol","gold",0,0,1000000000]]}\n'
        s.quota_restore("r1", text)
        self.assertEqual(
            parse(s.quota_checkpoint())["账本"],
            [["carol", "gold", 0, 0, 1000000000]],
        )
        with self.assertRaises(StateError):
            s.quota_stats("carol", 0)
        # 用户绑别的模板也允许并存。
        text2 = (
            '{"版本":1,"账本":[["alice","gold",0,0,1000000000],'
            '["alice","kill",0,0,1000000000],'
            '["carol","gold",0,0,1000000000]]}\n'
        )
        s.quota_restore("r2", text2)
        self.assertEqual(
            [(r[0], r[1]) for r in parse(s.quota_checkpoint())["账本"]],
            [("alice", "gold"), ("alice", "kill"), ("carol", "gold")],
        )

    def test_deleted_template_ledgers_untouched(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)  # alice/gold 累计 100
        # 删除 gold、alice 改绑 kill。
        config = json.loads(s.export_config())
        config["模板"] = [
            {"标识": "kill", "限速": 1000000, "突发": 0, "配额": 10, "超限": "下线"}
        ]
        config["用户模板"] = [["alice", "kill"], ["bob", "kill"]]
        s.load_config(json.dumps(config, ensure_ascii=False))
        # gold 已删：检查点不含其历史账本。
        self.assertEqual(parse(s.quota_checkpoint())["账本"], [])
        # 恢复现存模板账本（alice/kill）不得动 gold 历史账。
        s.quota_restore(
            "r1", '{"版本":1,"账本":[["alice","kill",3,0,999997000]]}\n'
        )
        # 引用已删模板即 ResourceError，且失败不改实例。
        with self.assertRaises(ResourceError):
            s.quota_restore(
                "r2", '{"版本":1,"账本":[["alice","gold",100,0,999900000]]}\n'
            )
        self.assertEqual(
            parse(s.quota_checkpoint())["账本"],
            [["alice", "kill", 3, 0, 999997000]],
        )
        # 回滚后 gold 复生：历史账本原样保留（桶容相同，截顶不影响）。
        s.rollback_config()
        rows = {
            (r[0], r[1]): r for r in parse(s.quota_checkpoint())["账本"]
        }
        self.assertEqual(rows[("alice", "gold")], ["alice", "gold", 100, 0, 999900000])

    def test_resource_errors(self):
        s = make()
        with self.assertRaises(ResourceError):
            s.quota_restore(
                "r1", '{"版本":1,"账本":[["nobody","gold",0,0,1]]}\n'
            )
        with self.assertRaises(ResourceError):
            s.quota_restore(
                "r2", '{"版本":1,"账本":[["alice","bronze",0,0,1]]}\n'
            )

    def test_token_capacity_violation_is_value_error(self):
        s = make()
        # gold 桶容 1,000,000,000。
        with self.assertRaises(ValueError):
            s.quota_restore(
                "r1", '{"版本":1,"账本":[["alice","gold",0,0,1000000001]]}\n'
            )
        # 临界值合法。
        s.quota_restore(
            "r2", '{"版本":1,"账本":[["alice","gold",0,0,1000000000]]}\n'
        )

    def test_value_errors(self):
        s = make()
        bad_texts = [
            "",
            "{",
            "[]",
            "1",
            '"x"',
            '{"版本":1}',
            '{"账本":[]}',
            '{"账本":[],"版本":1}',
            '{"版本":1,"账本":[],"x":1}',
            '{"版本":"1","账本":[]}',
            '{"版本":true,"账本":[]}',
            '{"版本":0,"账本":[]}',
            '{"版本":2,"账本":[]}',
            '{"版本":1,"账本":{}}',
            '{"版本":1,"账本":[{}]}',
            '{"版本":1,"账本":[["alice","gold",0,0]]}',
            '{"版本":1,"账本":[["alice","gold",0,0,0,0]]}',
            '{"版本":1,"账本":[["alice","gold",0,0,true]]}',
            '{"版本":1,"账本":[["alice","gold",0,-1,0]]}',
            '{"版本":1,"账本":[["alice","gold",0.5,0,0]]}',
            '{"版本":1,"账本":[[1,"gold",0,0,0]]}',
            '{"版本":1,"账本":[["alice",2,0,0,0]]}',
            '{"版本":1,"账本":[["","gold",0,0,0]]}',
            '{"版本":1,"账本":[["alice","gold\\u0000",0,0,0]]}',
            '{"版本":1,"账本":[["\\ud800","gold",0,0,0]]}',
            # 重复键。
            '{"版本":1,"版本":1,"账本":[]}',
            '{"版本":1,"账本":[],"账本":[]}',
            # 重复账本键 / 乱序。
            '{"版本":1,"账本":[["alice","gold",0,0,0],'
            '["alice","gold",1,1,1]]}',
            '{"版本":1,"账本":[["bob","kill",0,0,0],'
            '["alice","gold",0,0,0]]}',
            '{"版本":1,"账本":[["alice","kill",0,0,0],'
            '["alice","gold",0,0,0]]}',
        ]
        for text in bad_texts:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    s.quota_restore("k", text)

    def test_type_errors(self):
        s = make()
        for bad_key in (1, True, None, b"k"):
            with self.assertRaises(TypeError):
                s.quota_restore(bad_key, "x")
        for bad_text in (None, 1, True, b"x", [], {}):
            with self.assertRaises(TypeError):
                s.quota_restore("k", bad_text)

    def test_failure_does_not_change_instance(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("m1", "s1", 100, 0)
        before = s.quota_checkpoint()
        with self.assertRaises(ValueError):
            s.quota_restore("r1", "not json")
        with self.assertRaises(ResourceError):
            s.quota_restore("r2", '{"版本":1,"账本":[["x","gold",0,0,0]]}')
        with self.assertRaises(ValueError):
            s.quota_restore(
                "r3", '{"版本":1,"账本":[["alice","gold",0,0,99999999999999999999]]}'
            )
        self.assertEqual(s.quota_checkpoint(), before)

    def test_failure_does_not_occupy_key(self):
        s = make()
        good = '{"版本":1,"账本":[]}\n'
        with self.assertRaises(ValueError):
            s.quota_restore("r1", "bad")
        with self.assertRaises(TypeError):
            s.quota_restore("r1", None)
        # 同 key 此前失败不占位，合法文本首次成功。
        self.assertEqual(s.quota_restore("r1", good), s.quota_checkpoint())

    def test_replay_independent_domain_and_hetero_params(self):
        s = make()
        t1 = '{"版本":1,"账本":[]}\n'
        t2 = '{"版本":1,"账本":[["alice","gold",0,0,1000000000]]}\n'
        self.assertEqual(s.quota_restore("r1", t1), '{"版本":1,"账本":[]}\n')
        # 同型同 text 重放返回缓存首果。
        self.assertEqual(s.quota_restore("r1", t1), '{"版本":1,"账本":[]}\n')
        # 异参 ValueError。
        with self.assertRaises(ValueError):
            s.quota_restore("r1", t2)
        # 与 meter 域独立：meter 用过的 key 在此域可首次使用，反之亦然。
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.meter("shared", "s1", 1, 0)
        s.quota_restore("shared", t1)
        # 不同 key 同 text 各自独立成功。
        self.assertEqual(
            s.quota_restore("r2", t2),
            '{"版本":1,"账本":[["alice","gold",0,0,1000000000]]}\n',
        )

    def test_replay_returns_cached_result_without_revalidation(self):
        s = make()
        # gold 桶容 1,000,000,000；恢复一个合法但接近上限的账本。
        text = '{"版本":1,"账本":[["alice","gold",0,0,1000000000]]}\n'
        first = s.quota_restore("r1", text)
        # 缩小 gold 桶容后，同参重放不重新校验、直接返回缓存检查点。
        config = json.loads(s.export_config())
        config["模板"] = [
            {"标识": "gold", "限速": 1, "突发": 0, "配额": 1000, "超限": "拒绝"},
            {"标识": "kill", "限速": 1000000, "突发": 0, "配额": 10, "超限": "下线"},
        ]
        s.load_config(json.dumps(config, ensure_ascii=False))
        # 文本相对新桶容（1*1000）已非法，但同参重放不重新校验，
        # 直接返回缓存的首次检查点。
        self.assertEqual(s.quota_restore("r1", text), first)

    def test_restore_does_not_age(self):
        s = make()
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 越过空闲期限恢复：不老化，会话仍在线。
        s.quota_restore("r1", '{"版本":1,"账本":[]}\n')
        self.assertEqual(parse(s.qos("s1"))["会话"], "s1")

    def test_only_success_cached_and_no_audit(self):
        s = make()
        # 失败后同 key 换合法文本成功，再次同参返回首次成功结果。
        with self.assertRaises(ValueError):
            s.quota_restore("r1", "bad")
        good = '{"版本":1,"账本":[]}\n'
        self.assertEqual(s.quota_restore("r1", good), '{"版本":1,"账本":[]}\n')
        self.assertEqual(s.quota_restore("r1", good), '{"版本":1,"账本":[]}\n')
        # 不审计：防篡改链与接管审计均为空。
        self.assertEqual(parse(s.audit())["事件"], [])
        self.assertEqual(parse(s.takeover_audit())["事件"], [])


if __name__ == "__main__":
    unittest.main()
