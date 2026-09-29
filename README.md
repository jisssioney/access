# access

从零实现的接入网后端服务框架，仅用 Python 标准库、不联网。

- 入口：`python access.py <子命令>`
- 所有超时、续租与老化必须由显式时钟驱动；相同请求序列必须产生逐字节相同的输出。
- 会话、地址池与统计结果统一写成 JSON，浮点数按固定小数位格式化。
- `Sessions.fault_plan(key, mode, steps, now_ms)` 批量演算后端/池/超时故障
  注入与恢复：mode 仅预检（只读）/执行（原子提交），steps 为 1..1000 项
  `(domain, target, op, value)`，成功返回演算态 `fault_checkpoint(now_ms)`
  JSON；执行按 key 重放缓存，首果与重放写防篡改审计链（操作“故障计划”）。
- CLI `python access.py stats-merge`：子命令不带额外参数，stdin 为 UTF-8
  JSON 对象（尾部仅许空白），键依次且仅为 `key,users,base,left,right`。
  key 沿凭据约束；users 为 1..10000 个按 Unicode 码点升序且互异的凭据串；
  base/left/right 为 str，遵循版本 1 统计检查点契约。临时实例注册 users 后
  调用 `Sessions.stats_merge(key, base, left, right)`。字段类型错抛
  TypeError；编码、JSON、键、长度、排序或重复错抛 ValueError；文档非法、
  用户未注册、分支回退分别为 ValueError、ResourceError、
  `StateError("left"/"right")`。成功仅向 stdout 写返回值、stderr 空、
  退出 0；失败 stdout 空，stderr 写 LF 尾紧凑 JSON
  `{"错误":"stats-merge","类型":"<异常类名>"}`；TypeError/ValueError
  退出 2，ResourceError 退出 3，StateError 退出 4。缺失或未知子命令（及
  额外参数）按 ValueError。同输入逐字节同结果；时空
  O(L+n log n)/O(L+n)，L/n 为输入字节长度/检查点总行数。

## 测试

    python -m unittest discover
