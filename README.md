# access

从零实现的接入网后端服务框架，仅用 Python 标准库、不联网。

- 入口：`python access.py <子命令>`
- 所有超时、续租与老化必须由显式时钟驱动；相同请求序列必须产生逐字节相同的输出。
- 会话、地址池与统计结果统一写成 JSON，浮点数按固定小数位格式化。
- `Sessions.fault_plan(key, mode, steps, now_ms)` 批量演算后端/池/超时故障
  注入与恢复：mode 仅预检（只读）/执行（原子提交），steps 为 1..1000 项
  `(domain, target, op, value)`，成功返回演算态 `fault_checkpoint(now_ms)`
  JSON；执行按 key 重放缓存，首果与重放写防篡改审计链（操作“故障计划”）。

## 测试

    python -m unittest discover
