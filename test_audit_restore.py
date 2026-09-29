import hashlib
import json
import unittest

from access import Authenticator, Sessions, StateError


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(compact(obj).encode("utf-8")).hexdigest()


def make(users=("alice", "bob", "carol")):
    auth = Authenticator(3, 1000)
    for user in users:
        auth.add(user, "pw")
    s = Sessions(
        auth, 10, 10, 100000,
        pool=("10.0.0.0/24", (), ()),
        lease_ms=100000,
    )
    return auth, s


def establish(s, key, sid, user="alice", now_ms=100):
    return s.do(key, "建立", sid, (user, "pw"), now_ms)


def empty_window(anchor_seq, anchor_hash, limit=100):
    """规范空窗快照（锚哈希由调用方按当前链给出）。"""
    head = {
        "版本": 1,
        "锚序号": anchor_seq,
        "锚哈希": anchor_hash,
        "上限": limit,
        "下个序号": anchor_seq,
        "事件": [],
    }
    head["摘要"] = digest(head)
    return compact(head) + "\n"


class AuditRestoreBasicTest(unittest.TestCase):
    def setUp(self):
        _auth, self.src = make()
        establish(self.src, "k1", "s1", now_ms=100)
        establish(self.src, "k2", "s2", user="bob", now_ms=200)
        establish(self.src, "k3", "会话丙", user="carol", now_ms=300)
        self.page = self.src.audit_snapshot(0, 100)

    def test_full_page_restores_identical_chain(self):
        _auth, dst = make()
        result = dst.audit_restore("rk", self.page)
        self.assertTrue(dst.verify_audit())
        self.assertEqual(dst._chain_events, self.src._chain_events)
        self.assertEqual(dst._chain_tail, self.src._chain_tail)

        doc = json.loads(result)
        self.assertEqual(doc["追加"], 3)
        self.assertEqual(doc["末序号"], 3)
        self.assertEqual(doc["末哈希"], self.src._chain_tail)
        self.assertEqual(
            doc["摘要"],
            digest({"追加": 3, "末序号": 3, "末哈希": self.src._chain_tail}),
        )
        # 键序与类型：追加:int/末序号:int/末哈希:str/摘要:str。
        self.assertEqual(
            list(doc), ["追加", "末序号", "末哈希", "摘要"]
        )
        self.assertTrue(result.endswith("\n"))
        self.assertNotIn("\\u", result)  # ensure_ascii=False：中文原样输出

    def test_result_bytes_canonical(self):
        _auth, dst = make()
        result = dst.audit_restore("rk", self.page)
        doc = json.loads(result)
        canonical = compact(doc) + "\n"
        self.assertEqual(result, canonical)

    def test_paged_restore_stitches_chain(self):
        _auth, dst = make()
        r1 = dst.audit_restore("p1", self.src.audit_snapshot(0, 1))
        r2 = dst.audit_restore("p2", self.src.audit_snapshot(1, 2))
        self.assertEqual(json.loads(r1)["追加"], 1)
        self.assertEqual(json.loads(r2)["追加"], 2)
        self.assertEqual(dst._chain_events, self.src._chain_events)
        self.assertTrue(dst.verify_audit())
        # 末页后可再以空窗落在链尾。
        r3 = dst.audit_restore(
            "p3", self.src.audit_snapshot(3, 100)
        )
        self.assertEqual(json.loads(r3)["追加"], 0)
        self.assertEqual(len(dst._chain_events), 3)

    def test_restore_into_matching_mid_chain_anchor(self):
        _auth, dst = make()
        establish(dst, "k1", "s1", now_ms=100)
        page = self.src.audit_snapshot(1, 100)
        result = dst.audit_restore("rk", page)
        self.assertEqual(json.loads(result)["追加"], 2)
        self.assertEqual(dst._chain_events, self.src._chain_events)
        self.assertTrue(dst.verify_audit())

    def test_empty_window_appends_zero(self):
        _auth, dst = make()
        tail = dst._chain_tail
        result = dst.audit_restore("e", empty_window(0, tail))
        doc = json.loads(result)
        self.assertEqual(
            (doc["追加"], doc["末序号"], doc["末哈希"]),
            (0, 0, "0" * 64),
        )
        self.assertEqual(
            doc["摘要"],
            digest({"追加": 0, "末序号": 0, "末哈希": "0" * 64}),
        )
        self.assertEqual(dst._chain_events, [])
        self.assertEqual(dst._chain_tail, "0" * 64)

    def test_empty_window_after_nonempty_chain(self):
        _auth, dst = make()
        establish(dst, "k1", "s1", now_ms=100)
        page = empty_window(1, dst._chain_tail)
        result = dst.audit_restore("e", page)
        self.assertEqual(
            (json.loads(result)["追加"], json.loads(result)["末序号"]),
            (0, 1),
        )
        self.assertEqual(len(dst._chain_events), 1)

    def test_origin_preserved_for_replay_events(self):
        _auth, chain = make()
        establish(chain, "k1", "s1", now_ms=100)
        # 同 key 同参重放：链上追加原序号指认首项的重放事件。
        chain.do("k1", "建立", "s1", ("alice", "pw"), 100)
        self.assertEqual(chain._chain_events[1][6], 1)

        page = chain.audit_snapshot(0, 100)
        _auth2, dst = make()
        result = dst.audit_restore("rk", page)
        self.assertEqual(json.loads(result)["追加"], 2)
        self.assertEqual(dst._chain_events, chain._chain_events)
        self.assertEqual(dst._chain_events[1][6], 1)
        self.assertTrue(dst.verify_audit())

    def test_many_events_over_pages(self):
        auth = Authenticator(3, 1000)
        for user in ("alice", "bob", "carol"):
            auth.add(user, "pw")
        big = Sessions(
            auth, 300, 100, 100000,
            pool=("10.0.0.0/24", (), ()),
            lease_ms=100000,
        )
        for i in range(1, 251):
            big.do(
                f"k{i}", "建立", f"s{i}",
                (("alice", "bob", "carol")[i % 3], "pw"), i,
            )
        _auth2, dst = make()
        for after in range(0, 250, 100):
            page = big.audit_snapshot(after, 100)
            dst.audit_restore(f"page-{after}", page)
        self.assertEqual(len(dst._chain_events), 250)
        self.assertEqual(dst._chain_events, big._chain_events)
        self.assertTrue(dst.verify_audit())


class AuditRestoreReplayTest(unittest.TestCase):
    def setUp(self):
        _auth, self.src = make()
        establish(self.src, "k1", "s1", now_ms=100)
        establish(self.src, "k2", "s2", user="bob", now_ms=200)

    def test_replay_returns_original_bytes_without_appending(self):
        _auth, dst = make()
        page = self.src.audit_snapshot(0, 100)
        first = dst.audit_restore("rk", page)
        second = dst.audit_restore("rk", page)
        self.assertIs(first, second)
        self.assertEqual(len(dst._chain_events), 2)
        # 重放不产生恢复事件本身：链内容恰为页内事件。
        self.assertEqual(dst._chain_events, self.src._chain_events)

    def test_replay_does_not_recheck_anchor(self):
        _auth, dst = make()
        page = self.src.audit_snapshot(0, 100)
        first = dst.audit_restore("rk", page)
        # 链继续增长后，缓存重放仍返回原字节且不追加、不校验锚点。
        establish(dst, "other", "so", now_ms=900)
        second = dst.audit_restore("rk", page)
        self.assertEqual(second, first)
        self.assertEqual(len(dst._chain_events), 3)

    def test_different_text_same_key_value_error(self):
        _auth, dst = make()
        dst.audit_restore("rk", self.src.audit_snapshot(0, 100))
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.src.audit_snapshot(0, 1))
        # 异参失败不追加。
        self.assertEqual(len(dst._chain_events), 2)

    def test_non_str_text_on_cached_key_value_error(self):
        _auth, dst = make()
        dst.audit_restore("rk", self.src.audit_snapshot(0, 100))
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", 123)

    def test_cache_is_per_instance_domain(self):
        _auth, a = make()
        _auth2, b = make()
        page = self.src.audit_snapshot(0, 100)
        a.audit_restore("rk", page)
        # 不同实例同 key 互不影响，b 仍为空链，锚点不符应 StateError。
        with self.assertRaises(StateError):
            b.audit_restore("rk", self.src.audit_snapshot(1, 100))


class AuditRestoreFailureTest(unittest.TestCase):
    def setUp(self):
        _auth, self.src = make()
        establish(self.src, "k1", "s1", now_ms=100)
        establish(self.src, "k2", "s2", user="bob", now_ms=200)
        self.page = self.src.audit_snapshot(0, 100)
        self.doc = json.loads(self.page)

    def rehash(self, doc, anchor_hash="0" * 64):
        """按当前 事件 重算页内哈希链与顶层摘要，返回规范 LF 尾文本。"""
        prev = anchor_hash
        events = doc["事件"]
        for ev in events:
            ev["前哈希"] = prev
            ev["哈希"] = self.src._chain_hash(
                ev["序号"], ev["时刻"], ev["键"], ev["操作"], ev["会话"],
                ev["结果"], ev["原序号"], prev,
            )
            prev = ev["哈希"]
        head = {
            "版本": doc["版本"],
            "锚序号": doc["锚序号"],
            "锚哈希": doc["锚哈希"],
            "上限": doc["上限"],
            "下个序号": doc["下个序号"],
            "事件": events,
        }
        doc["摘要"] = digest(head)
        return compact(doc) + "\n"

    def test_bad_json(self):
        _auth, dst = make()
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", "not json")

    def test_duplicate_key(self):
        _auth, dst = make()
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", '{"版本": 1, "版本": 1}')

    def test_top_level_keys(self):
        _auth, dst = make()
        d = dict(self.doc)
        del d["锚哈希"]
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")
        d = dict(self.doc)
        reordered = {
            "锚序号": d["锚序号"], "版本": d["版本"], "锚哈希": d["锚哈希"],
            "上限": d["上限"], "下个序号": d["下个序号"],
            "事件": d["事件"], "摘要": d["摘要"],
        }
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(reordered) + "\n")

    def test_version_must_be_one(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["版本"] = 2
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_range_errors(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["锚序号"] = -1
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))
        d = json.loads(self.page)
        d["上限"] = 0
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))
        d = json.loads(self.page)
        d["上限"] = 1001
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))
        d = json.loads(self.page)
        d["事件"][0]["时刻"] = -1
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))

    def test_wrong_types(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["事件"][0]["键"] = 7
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))
        d = json.loads(self.page)
        d["事件"][0]["序号"] = "1"
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))
        d = json.loads(self.page)
        d["事件"] = {"x": 1}
        d["摘要"] = "f" * 64
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_event_count_over_limit(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["上限"] = 1
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))

    def test_non_consecutive_sequence(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["事件"][1]["序号"] = 5
        d["下个序号"] = 5
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))

    def test_cursor_mismatch_nonempty_window(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["下个序号"] = 9
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))

    def test_cursor_mismatch_empty_window(self):
        _auth, dst = make()
        text = empty_window(0, "0" * 64)
        d = json.loads(text)
        d["下个序号"] = 1
        d["摘要"] = digest({
            "版本": 1, "锚序号": 0, "锚哈希": "0" * 64,
            "上限": 100, "下个序号": 1, "事件": [],
        })
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_origin_nonzero_not_less_than_seq(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["事件"][1]["原序号"] = 2
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", self.rehash(d))

    def test_prev_hash_error(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["事件"][1]["前哈希"] = "a" * 64
        # 顶层摘要重算后仍须因页内前哈希衔接失败而 ValueError。
        head = {
            "版本": 1, "锚序号": 0, "锚哈希": "0" * 64, "上限": 100,
            "下个序号": 2, "事件": d["事件"],
        }
        d["摘要"] = digest(head)
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_event_hash_error(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["事件"][0]["哈希"] = "0" * 64
        head = {
            "版本": 1, "锚序号": 0, "锚哈希": "0" * 64, "上限": 100,
            "下个序号": 2, "事件": d["事件"],
        }
        d["摘要"] = digest(head)
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_summary_error(self):
        _auth, dst = make()
        d = json.loads(self.page)
        d["摘要"] = "f" * 64
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_non_canonical_encoding(self):
        _auth, dst = make()
        d = json.loads(self.page)
        # 额外空白：摘要仍按紧凑值吻合，但字节非规范。
        with self.assertRaises(ValueError):
            dst.audit_restore(
                "rk",
                compact(d).replace('":', '": ', 1) + "\n",
            )
        # 缺尾 LF。
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d))
        # 缩进排版。
        with self.assertRaises(ValueError):
            dst.audit_restore(
                "rk", json.dumps(d, ensure_ascii=False, indent=2) + "\n"
            )
        # 多余尾空白。
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n\n")

    def test_anchor_seq_mismatch_state_error(self):
        _auth, dst = make()
        establish(dst, "k1", "s1", now_ms=100)
        establish(dst, "k2", "s2", user="bob", now_ms=200)
        # 快照锚在 0，目标链末为 2：StateError(锚序号, 当前末序号)。
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("rk", self.page)
        self.assertEqual(cm.exception.args, (0, 2))
        self.assertEqual(len(dst._chain_events), 2)

    def test_anchor_hash_mismatch_state_error(self):
        _auth, dst = make()
        establish(dst, "k1", "s1", now_ms=100)
        establish(dst, "k2", "s2", user="bob", now_ms=200)
        # 空窗锚序号等于当前末序号 2，但锚哈希不等于链尾：StateError(2, 2)。
        d = json.loads(empty_window(2, "1" * 64))
        with self.assertRaises(StateError) as cm:
            dst.audit_restore("rk", compact(d) + "\n")
        self.assertEqual(cm.exception.args, (2, 2))
        self.assertEqual(len(dst._chain_events), 2)

    def test_value_error_precedes_state_error(self):
        _auth, dst = make()
        # 目标为空链，锚序号 0 本可吻合；但坏 JSON 先抛 ValueError。
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", "{")
        d = json.loads(self.page)
        d["摘要"] = "0" * 64
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", compact(d) + "\n")

    def test_failures_do_not_occupy_key(self):
        _auth, dst = make()
        # ValueError 失败后同 key 可成功。
        with self.assertRaises(ValueError):
            dst.audit_restore("rk", "bad")
        good = dst.audit_restore("rk", empty_window(0, "0" * 64))
        self.assertEqual(json.loads(good)["追加"], 0)

        # StateError 失败后同 key 以合锚空窗成功。
        establish(dst, "k1", "s1", now_ms=100)
        establish(dst, "k2", "s2", user="bob", now_ms=200)
        with self.assertRaises(StateError):
            dst.audit_restore("rk2", self.page)
        ok = dst.audit_restore(
            "rk2", empty_window(2, dst._chain_tail)
        )
        self.assertEqual(json.loads(ok)["追加"], 0)

    def test_failure_appends_nothing(self):
        _auth, dst = make()
        snapshots_before = list(dst._chain_events)
        for bad in ("{", self.page.replace("\n", "", 1)):
            with self.assertRaises((ValueError, StateError)):
                dst.audit_restore("rk", bad)
        self.assertEqual(dst._chain_events, snapshots_before)
        self.assertEqual(dst._chain_tail, "0" * 64)


class AuditRestoreParamsTest(unittest.TestCase):
    def test_key_type_error(self):
        _auth, dst = make()
        with self.assertRaises(TypeError):
            dst.audit_restore(123, "x")

    def test_key_value_error(self):
        _auth, dst = make()
        with self.assertRaises(ValueError):
            dst.audit_restore("", "x")
        with self.assertRaises(ValueError):
            dst.audit_restore("a\0b", "x")

    def test_text_type_error(self):
        _auth, dst = make()
        for bad in (123, 5.0, b"x", None, ["x"]):
            with self.assertRaises(TypeError):
                dst.audit_restore("rk", bad)


class AuditRestoreIsolationTest(unittest.TestCase):
    def test_does_not_restore_business_state_or_indexes(self):
        _auth, src = make()
        establish(src, "k1", "s1", now_ms=100)
        page = src.audit_snapshot(0, 100)

        _auth2, dst = make()
        dst.audit_restore("rk", page)
        # 不恢复会话与业务缓存。
        self.assertEqual(dst._sessions, {})
        self.assertEqual(dst._cache, {})
        # 不恢复任何链 key 首次序号索引（接入事件原序号字段仍原样保留）。
        self.assertEqual(dst._chain_index, {})
        self.assertEqual(dst._audit_index, {})
        # 配置修订等不动。
        self.assertEqual(dst._revision, 0)

    def test_restore_operation_itself_not_audited(self):
        _auth, src = make()
        establish(src, "k1", "s1", now_ms=100)
        establish(src, "k2", "s2", user="bob", now_ms=200)
        page = src.audit_snapshot(0, 100)
        _auth2, dst = make()
        dst.audit_restore("rk", page)
        dst.audit_restore("rk", page)
        # 重放也不追加：链上恰为快照页两条事件，无额外恢复事件。
        self.assertEqual(len(dst._chain_events), 2)
        self.assertEqual(
            [ev[3] for ev in dst._chain_events], ["建立", "建立"]
        )

    def test_deterministic_bytes(self):
        _auth, a = make()
        _auth2, b = make()
        page = empty_window(0, "0" * 64)
        self.assertEqual(
            a.audit_restore("rk", page),
            b.audit_restore("rk", page),
        )


if __name__ == "__main__":
    unittest.main()
