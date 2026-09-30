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
  退出 4。缺失或未知子命令按 ValueError 退出 2。同输入逐字节同结果。
- `python access.py stats-delta`（不带额外参数）：stdin 读入 UTF-8 JSON
  对象，对象前不得有空白、尾部仅许空白，顶层键依次且仅为
  `users,base,current`。`users` 为 1..10000 个按 Unicode 码点升序且互异的
  凭据串（在不加载地址池、模板或持久状态的临时实例中注册后只读调用
  `Sessions.stats_delta`，不触发认证、老化、审计或计数变化）；
  `base/current` 为 str，遵循版本 1 统计检查点契约。成功仅向 stdout 写
  返回值（LF 尾紧凑 JSON，顶层依次基线摘要/当前摘要/建立/用户失败/
  用户计量/模板计量/摘要，成功率为整数万分比，三类明细按标识升序、
  四项全零行省略）、stderr 空、退出 0；失败 stdout 空，stderr 写 LF 尾
  紧凑 JSON，键序 `错误,类型`，值为 `stats-delta` 与异常类名。
  users/base/current 或用户元素类型错（TypeError）、编码/JSON/重键/键序/
  形态/长度/排序/重复或检查点结构、版本、摘要非法（ValueError）退出 2；
  检查点引用 users 之外用户 ResourceError 退出 3；current 相对 base 建立
  总数、建立成功或任一分类计数回退，或成功增量大于总数增量
  StateError("current") 退出 4。同输入逐字节同结果，单次处理 O(L+n log n)
  时间、O(L+n) 空间（L 为输入字节数，n 为 users 与两份检查点明细总数）。

## 测试

    python -m unittest discover
