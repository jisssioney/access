import json
import unittest

from access import (
    AuthError,
    Authenticator,
    ResourceError,
    Sessions,
    StateError,
)


def make():
    auth = Authenticator(3, 1000)
    for u in ("alice", "bob", "carol", "dave"):
        auth.add(u, "pw")
    return Sessions(auth, 10, 5, 5000, pool=("10.0.0.0/24", (), ()), lease_ms=1000)


V10 = {
    "版本": 10,
    "会话": {"总数": 10, "每用户": 5, "空闲毫秒": 5000, "租期毫秒": 1000},
    "地址池": [{"标识": "default", "CIDR": "10.0.0.0/24", "保留": [], "静态": []}],
    "模板": [
        {"标识": "t1", "限速": 100, "突发": 0, "配额": 1000, "周期毫秒": 0,
         "会话上限": 1, "排队优先级": 0, "超限": "拒绝"},
        {"标识": "t2", "限速": 100, "突发": 0, "配额": 1000, "周期毫秒": 0,
         "会话上限": 0, "排队优先级": 0, "超限": "拒绝"},
    ],
    "用户模板": [["alice", "t1"], ["bob", "t1"], ["carol", "t2"]],
    "容量": {"队列上限": 1024, "最大等待毫秒": 0, "队满策略": "拒绝"},
    "认证": {"最大失败": 3, "锁定毫秒": 1000,
            "重试基数毫秒": 0, "重试上限毫秒": 0},
}


def cfg_text():
    return json.dumps(V10, ensure_ascii=False, separators=(",", ":"))


class V10SmokeTest(unittest.TestCase):
    def test_export_v10(self):
        s = make()
        out = s.load_config(cfg_text())
        doc = json.loads(out)
        self.assertEqual(doc["版本"], 10)
        self.assertEqual(
            list(doc), ["版本", "会话", "地址池", "模板", "用户模板", "容量", "认证"]
        )
        self.assertEqual(
            list(doc["模板"][0]),
            ["标识", "限速", "突发", "配额", "周期毫秒", "会话上限",
             "排队优先级", "超限"],
        )
        self.assertEqual(doc["模板"][0]["会话上限"], 1)
        self.assertEqual(doc["模板"][1]["会话上限"], 0)
        self.assertEqual(out, s.export_config())
        self.assertTrue(out.endswith("\n"))

    def test_upgrade_v9_to_v10(self):
        s = make()
        v9 = json.loads(cfg_text())
        v9["版本"] = 9
        # v9 无重试两项。
        for key in ("重试基数毫秒", "重试上限毫秒"):
            del v9["认证"][key]
        raw = s.upgrade_config(json.dumps(v9, ensure_ascii=False, separators=(",", ":")))
        doc = json.loads(raw)
        self.assertEqual(list(doc), ["源版本", "目标版本", "改变", "摘要", "配置"])
        self.assertEqual(doc["源版本"], 9)
        self.assertEqual(doc["目标版本"], 10)
        self.assertIs(doc["改变"], True)
        self.assertEqual(doc["配置"]["版本"], 10)
        self.assertEqual(doc["配置"]["模板"][0]["会话上限"], 1)
        self.assertEqual(doc["配置"]["认证"]["重试基数毫秒"], 0)
        # 升级包可直接加载
        out = s.load_config(raw)
        self.assertEqual(json.loads(out)["版本"], 10)
        # v10 不再改变
        doc2 = json.loads(s.upgrade_config(cfg_text()))
        self.assertIs(doc2["改变"], False)
        self.assertEqual(doc2["源版本"], 10)
        # target 只许 10
        with self.assertRaises(ValueError):
            s.upgrade_config(cfg_text(), 9)
        with self.assertRaises(TypeError):
            s.upgrade_config(cfg_text(), "10")
        with self.assertRaises(TypeError):
            s.upgrade_config(123)

    def test_upgrade_bad_template_limit(self):
        s = make()
        for bad in (-1, 10001, True, "1", 1.5):
            doc = json.loads(cfg_text())
            doc["模板"][0]["会话上限"] = bad
            with self.assertRaises(ValueError, msg=repr(bad)):
                s.upgrade_config(json.dumps(doc, ensure_ascii=False))

    def test_do_establish_limit(self):
        s = make()
        s.load_config(cfg_text())
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # 同模板（t1 上限 1）另一用户建立超限
        with self.assertRaises(ResourceError):
            s.do("k2", "建立", "s2", ("bob", "pw"), 0)
        # t2 不限
        s.do("k3", "建立", "s3", ("carol", "pw"), 0)
        # 挂起仍占占用：挂起 s1 后 bob 仍超限
        s.do("k4", "挂起", "s1", None, 1)
        with self.assertRaises(ResourceError):
            s.do("k5", "建立", "s4", ("bob", "pw"), 1)
        # 下线释放占用后可建
        s.do("k6", "下线", "s1", None, 2)
        s.do("k7", "建立", "s4", ("bob", "pw"), 2)
        # 接管不净增占用：t1 已有 alice? 无——alice 已下线。bob 在线占 1。
        # carol 改绑 t1 验证接管豁免
        doc = json.loads(cfg_text())
        doc["用户模板"].append(["dave", "t1"])
        doc["用户模板"].sort()
        # 先让 dave 以 t2 上线（改绑前），再加载新绑定
        doc["用户模板"] = [p for p in doc["用户模板"] if p[0] != "dave"]
        s.do("k8", "建立", "s5", ("dave", "pw"), 3)

    def test_takeover_not_limited(self):
        s = make()
        s.load_config(cfg_text())
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        # t1 占用 1/1；接管 alice 的 s1 净增 0，不受限
        out = json.loads(s.do("k2", "接管", "s2", ("s1", "pw"), 1))
        self.assertEqual(out["状态"], "在线")

    def test_batch_online_limit(self):
        s = make()
        s.load_config(cfg_text())
        out = json.loads(
            s.batch_online(
                "kb",
                (("s1", "alice", "pw"), ("s2", "bob", "pw"), ("s3", "carol", "pw")),
                0,
            )
        )
        self.assertEqual(
            [i["结果"] for i in out["项目"]],
            ["上线", "ResourceError", "上线"],
        )
        self.assertEqual(out["结果"], "部分")

    def test_capacity_queue_and_advance_skip(self):
        s = make()
        s.load_config(cfg_text())
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)  # t1 占用 1/1
        # bob (t1) 超限 -> 排队
        out = json.loads(s.capacity("k2", "申请", "s2", ("bob", "pw", 100), 0))
        self.assertEqual(out["结果"], "排队")
        # carol (t2 不限) 立即可服务
        out = json.loads(s.capacity("k3", "申请", "s3", ("carol", "pw", 100), 0))
        self.assertEqual(out["结果"], "在线")
        # dave (未绑定) 排队在后
        out = json.loads(s.capacity("k4", "申请", "s4", ("dave", "pw", 100), 0))
        self.assertEqual(out["结果"], "在线")
        # 推进：bob 仍受限留队
        out = json.loads(s.capacity("k5", "推进", "", None, 1))
        self.assertEqual(out["排队"], 1)
        # alice 下线释放 t1 占用，推进晋升 bob
        s.do("k6", "下线", "s1", None, 2)
        out = json.loads(s.capacity("k7", "推进", "", None, 2))
        self.assertEqual(out["排队"], 0)
        self.assertEqual(out["变更"], [1])

    def test_load_limit_below_occupancy(self):
        s = make()
        doc = json.loads(cfg_text())
        doc["模板"][0]["会话上限"] = 0  # 先不限，建两个 t1 会话
        s.load_config(json.dumps(doc, ensure_ascii=False))
        s.do("k1", "建立", "s1", ("alice", "pw"), 0)
        s.do("k2", "建立", "s2", ("bob", "pw"), 0)  # t1 占用 2
        before = s.export_config()
        doc["模板"][0]["会话上限"] = 1  # 现占用 2 > 1
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc, ensure_ascii=False))
        # 失败不改配置
        self.assertEqual(s.export_config(), before)
        # 上限 2 可承载
        doc["模板"][0]["会话上限"] = 2
        s.load_config(json.dumps(doc, ensure_ascii=False))
        # 回滚点为上一份（上限 0）；占用 2 可承载 0（不限），回滚成功
        out = s.rollback_config()
        self.assertEqual(json.loads(out)["模板"][0]["会话上限"], 0)
        # 回滚点已清除
        with self.assertRaises(StateError):
            s.rollback_config()
        # 占用含挂起：挂起不计入？挂起计入占用
        doc["模板"][0]["会话上限"] = 1
        s.do("k3", "挂起", "s1", None, 1)
        with self.assertRaises(ResourceError):
            s.load_config(json.dumps(doc, ensure_ascii=False))

    def test_config_change_upgrade(self):
        s = make()
        v9 = json.loads(cfg_text())
        v9["版本"] = 9
        # v9 认证仅两键（无重试两项）。
        for key in ("重试基数毫秒", "重试上限毫秒"):
            del v9["认证"][key]
        text = json.dumps(v9, ensure_ascii=False, separators=(",", ":"))
        out = s.config_change("kc", "升级", text, 0)
        doc = json.loads(out)
        self.assertEqual(doc["目标版本"], 10)
        # 同参重放
        self.assertEqual(s.config_change("kc", "升级", text, 0), out)
        # 异参
        with self.assertRaises(ValueError):
            s.config_change("kc", "升级", cfg_text(), 0)


if __name__ == "__main__":
    unittest.main()
