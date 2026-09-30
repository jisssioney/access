# access

从零实现的接入网后端服务框架，仅用 Python 标准库、不联网。

- 入口：`python access.py <子命令>`
- 所有超时、续租与老化必须由显式时钟驱动；相同请求序列必须产生逐字节相同的输出。
- 会话、地址池与统计结果统一写成 JSON，浮点数按固定小数位格式化。
- `Sessions.fault_plan(key, mode, steps, now_ms)` 批量演算后端/池/超时故障
  注入与恢复：mode 仅预检（只读）/执行（原子提交），steps 为 1..1000 项
  `(domain, target, op, value)`，成功返回演算态 `fault_checkpoint(now_ms)`
  JSON；执行按 key 重放缓存，首果与重放写防篡改审计链（操作“故障计划”）。
- `python access.py stats-merge`（不带额外参数）：stdin 读入
  UTF-8 JSON 对象，对象前不得有空白、尾部仅许空白，键依次且仅为
  `key,users,base,left,right`。`key` 沿凭据约束；`users` 为 1..10000 个
  按 Unicode 码点升序且互异的凭据串（临时实例注册这些用户后调用
  `stats_merge`）；`base/left/right` 为 str，遵循版本 1 统计检查点契约。
  成功仅向 stdout 写返回值（LF 尾基线 JSON）、stderr 空、退出 0；失败
  stdout 空，stderr 写 LF 尾紧凑 JSON，键序 `错误,类型`，值为
  `stats-merge` 与异常类名。字段类型错（TypeError）、编码/JSON/键/长度/
  排序/重复错（ValueError）退出 2；文档非法、用户未注册、分支回退分别为
  ValueError 退出 2、ResourceError 退出 3、StateError("left"/"right")
  退出 4。缺失或未知子命令按 ValueError 退出 2（信封错误值为
  `stats-merge`）。同输入逐字节同结果。
- `python access.py stats-delta`（不带额外参数）：stdin 读入 UTF-8 JSON
  对象，对象前不得有空白、尾部仅许 JSON 空白，顶层键依次且仅为
  `users,base,current`。`users` 约束同 stats-merge，临时实例仅注册这些
  用户（不加载地址池、模板或持久状态）后调用只读的
  `Sessions.stats_delta(base, current)`；`base/current` 为版本 1 统计
  检查点文本。成功仅向 stdout 写返回的 LF 尾紧凑 JSON、stderr 空、退出
  0；失败 stdout 空，stderr 写一行 LF 尾紧凑 JSON，键序 `错误,类型`，
  值为 `stats-delta` 与异常类名。TypeError/ValueError 退出 2，检查点
  用户失败或用户计量引用 users 之外用户为 ResourceError 退出 3，current
  相对 base 计数回退或成功增量大于总数增量为 StateError 退出 4。失败不
  产生部分输出、不改实例状态；同输入逐字节同结果，时间 O(L+n log n)、
  空间 O(L+n)。

## 测试

    python -m unittest discover
