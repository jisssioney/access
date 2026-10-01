"""access — 接入网后端服务框架（仅标准库）。

当前提供：
- Authenticator：带失败计数、锁定与按用户可配置指数退避的用户认证器。
- Sessions：基于 Authenticator 的会话管理（建立/续租/下线/接管/跨池迁移、空闲老化、
  零池起步可 add_pool 激活多地址池、租约、按 key 重放缓存、pool_stats、接管审计
  takeover_audit、防篡改审计链 audit/verify_audit、只读审计窗口快照
  audit_snapshot/verify_audit_snapshot（版本 1，锚哈希取锚项、摘要盖前六键，
  校验结构错抛 ValueError、与当前链不符返 False）、审计快照原子接尾恢复
  audit_restore（版本 1 规范快照严格全验，锚点不符 StateError(锚序号,末序号)，
  全验后一次追加且不恢复幂等索引、恢复不写审计，仅缓存成功、同参重放原字节，
  返回 追加/末序号/末哈希/摘要）、配置导出/升级/加载/回滚
  export_config/upgrade_config/load_config/rollback_config、修订查询/CAS 提交/
  历史回退 config_revision/config_cas/config_revert（构造态为修订 0，保留最近
  256 个配置修订供回退）、防篡改配置历史 config_history（构造即记录修订 0，
  四类提交首次成功依次追加“加载/回滚/CAS/回退”，失败与重放不追加，与修订
  快照同寿命 256 项、淘汰不缝合前哈希）、QoS 模板查询 qos、按
  (用户,模板) 共享账本计量的 meter、配额只读快照 quota_stats、共享账本检查点
  quota_checkpoint 与按 key 原子恢复 quota_restore、按用户/模板分组的
  计量统计 meter_stats、容量申请
  capacity：可配置队列上限与最大等待的申请/取消/推进，截止超时与按有效
  优先级（QoS 模板排队优先级随等待老化）确定性晋升、
  capacity_events 事件查询与 capacity_stats 容量统计）；clog/cverify/
  creplay 提供 capacity 状态检查点、事件哈希链校验与原子重放恢复。
  runtime_checkpoint/runtime_restore 提供覆盖会话/租约、容量队列/事件与
  共享 QoS 账本的运行态检查点（版本 1，摘要覆盖前四键）与按 key 原子
  恢复（仅缓存成功，同摘要空操作，异摘要覆盖状态 StateError），供续租、
  计量、推进一致恢复。
  service_checkpoint(now_ms)/service_restore(key,text) 提供跨域一致性
  检查点（版本 2，顶层依次版本/时刻/配置摘要/认证/运行态/故障/统计/计费/
  摘要，末摘要盖前八键 UTF-8 字节；“计费”域为版本 1，含计费哈希链、按会话
  升序的活动会话累计与最近计费时刻及链尾哈希）：生成先验显式毫秒时钟再只
  老化一次，随后从同一状态取当前 v11 配置规范摘要与认证（v2）、运行态
  （v1）、故障（v1）、统计（v1）、计费（v1）规范对象，除该次老化外只读、
  逐字节确定；恢复接受版本 1（无计费域，缺失计费态按空）与版本 2，在改任何
  状态前完成重键、键序、版本、类型、排序、各层摘要、计费链结构/顺序/哈希、
  统一时刻与跨域引用校验，参数型错 TypeError、新版本结构/顺序/哈希/生命周期
  或摘要非法 ValueError、引用未知用户或会话 ResourceError、配置摘要不符
  StateError("配置")、非空且异态计费 StateError("计费")、非空且异摘要运行态
  StateError("运行态")，各域为空或整体相同才整体替换并重建租约，失败不改任何
  域、不占 key，不导入/清空配置与配置历史、不恢复审计链与各域幂等缓存、不写
  审计与计费事件，成功返回版本 2 规范包，同键同文本重放原字节不产生修改；
  旧版本（v1）恢复的遗留在线会话无开始事件，后续 meter/interim 惰性建账；
  单次 O(N log N)/O(N)。
  accounting_interim(key,sid,now_ms)/accounting_events(after=0,limit=100)
  提供确定性会话计费：do 建立、capacity 立即建立/排队晋升、batch_online
  实际提交项产生“开始”事件；仅 meter 通过的字节按会话累计；中间计费产生
  “中间”累计事件；显式下线/批量下线/强制停用/QoS 超限下线/接管旧会话产生
  “停止”事件（原因依次下线/批量下线/停用/配额/接管，开始与中间原因为空串），
  接管新会话同刻产生开始；迁移、续租、挂起、恢复与超时老化（含演练）挂起不
  切分；原子批次回滚截断链不留事件，非原子只留实际提交项，失败与重放不重复
  记账。事件十一键（序号/类型/时刻/会话/用户/地址池/地址/累计字节/原因/
  前哈希/哈希），链首前哈希 64 个 0，哈希按前哈希与本条前九项紧凑 JSON
  UTF-8 字节算 SHA-256；accounting_interim 独立 key 重放原结果且不重复记账、
  异参复用抛 ValueError，未知 sid KeyError、非在线或时刻早于最近计费时刻
  StateError（旧检查点恢复的在线会话首次中间计费惰性开账）；accounting_events
  只读分页（after 非 bool 非负 int、limit 1..1000，型错 TypeError、界错
  ValueError，链尾后空页），顶层键序版本/起点/下页/事件/尾序号/尾哈希，LF
  尾紧凑 JSON，同状态逐字节一致，时空 O(limit)。
  fault 注入/恢复后端故障：do 建立/迁移/接管与 capacity 申请在验参后、
  老化前查后端，故障期按用户指数退避抛 BackendError；fault_stats 查询
  后端故障统计（含按类累计的失败次数），查询不老化、不改态。
  backend_checkpoint/backend_restore 提供后端故障态（故障截至、按用户
  退避、失败计数）检查点（版本 1，摘要覆盖前五键）与按 key 原子恢复：
  检查点只读、不清到期退避，恢复全验后原子替换，仅缓存首次成功、同参
  重放原字节，首次成功与重放写防篡改审计链（后端恢复，会话空串）。
  auth_checkpoint/auth_restore 提供认证器（全部用户的凭据摘要、失败计数、
  锁定至、下次可试时刻与停用态）检查点（版本 2，顶层版本/时刻/用户/摘要，
  摘要盖前三键；恢复亦接受版本 1 并把下次可试补 0）
  与按 key 原子恢复：检查点只读、不清到期锁与退避、不按当前策略折算，
  用户按码点升序，凭据为 64 位小写十六进制摘要，锁定至为 null 或非负 int，
  下次可试为非负 int（0 为无退避）；
  恢复严格全验（版本 1/2：JSON/重键/键序结构类型值/排序重复/版本摘要错
  ValueError，用户集与当前认证器不一致 ResourceError）后原子替换五项且不改
  认证策略，失败、锁定至与下次可试原样往返、后续认证沿既有规则；仅缓存首次
  成功、同型同 text 重放原字节（版本 1 输入返回版本 2 规范包）、异参
  ValueError，不老化、不审计。
  pool_fault 注入/恢复指定地址池的可恢复耗尽演练（不改真实租约及配置）：
  注入期该池视为无可分配地址，建立、迁入、无址接管在既有认证与老化后抛
  ResourceError，capacity 申请排队、推进跳过，到刻自动正常；首果独立域
  永久缓存，首次成功与重放写防篡改审计链（池注入/池恢复）。
  timeout_fault 注入/恢复全局超时演练待触发值（不改真实配置）：注入
  at_ms>=now_ms 设置或覆盖触发时刻，恢复取消；首果独立域永久缓存，首次
  成功与重放写防篡改审计链（超时注入/超时恢复，会话空串）。待触发时
  首次满足 now_ms>=触发值的 capacity 推进在普通老化与晋升前原子挂起全部
  在线会话、清期限释放租约，按入队序将全部队项记超时后删除，再清除触发，
  本批不晋升、不半释放；配置加载/回滚成功保留待触发值。
  user_stats 按用户只读快照：按 now_ms 取视图（在线期限到计挂起、租期或
  期限到不计占用、队项截止到不计排队、墓碑计下线），并给出该用户
  do/meter/capacity 新 key 首次且已定位用户的认证/资源/状态/后端失败
  累计；查询不认证、不老化、不改态。runtime_stats 全局只读快照：同口径
  会话视图、建立新 key 首次计数与万分比成功率、跨用户失败聚合与各池
  总量/占用/可用/保留；查询不认证、不老化、不改态。stats_checkpoint/
  stats_restore 提供建立计数、按用户失败计数与按用户/模板计量计数的
  统计快照检查点（版本 1，摘要覆盖前五键）与按 key 原子恢复：检查点
  只读、不老化，恢复严格全验（JSON/重键/键序结构类型值/排序重复/版本
  摘要错 ValueError，用户失败与用户计量引用未注册用户 ResourceError，
  模板计量不验引用）后原子替换五类统计，任何失败不改统计与缓存；仅缓存首次成功、
  同型同 text 重放原字节、异参 ValueError，不老化、不审计。stats_merge 提供
  base/left/right 三份版本 1 检查点的三方合并：缺标识计 0，先 left 后 right
  逐计数验分支不回退（低于 base）且成功增量不超总数增量（违者 StateError 标
  "left"/"right"），结果计数 left+right-base、列表取并集码点升序且全 0 项
  省略；用户失败或用户计量引用未注册用户 ResourceError、模板不验引用；全验后
  原子替换五类统计，返回 stats_checkpoint() 的 LF 尾 JSON，失败不改统计与缓存；
  独立 key 仅缓存成功，同型同四参重放原字节、异参 ValueError，不老化、不认证、
  不审计、不改其他状态。stats_delta(base,current) 只读算两份版本 1 检查点的
  逐计数增量 current-base：两参须 str（否则 TypeError），按版本 1 契约解析
  （违约 ValueError），用户失败或用户计量引用未注册用户 ResourceError、模板
  不验引用；按标识并集、缺标识计 0，任一增量为负或成功增量大于总数增量抛
  StateError("current")；返回 LF 尾紧凑 JSON，顶层依次基线摘要/当前摘要/建立/
  用户失败/用户计量/模板计量/摘要，前两值取输入摘要原文，建立为总数/成功/
  成功率万分比（总数增量 0 率为 0，否则 floor(成功*10000/总数)），三类列表
  码点升序、全 0 项省略，末摘要为前六键紧凑 JSON UTF-8 字节 sha256 小写值；
  不老化、不认证、不审计、不改状态，同参同字节，O(n log n)/O(n)。sessions(now_ms,
  after="", limit=100) 只读游标列出会话与未到期队项（不老化、不认证、
  不回收租约、不写审计/事件/缓存、不改计数）：按 now_ms 取视图，标识
  Unicode 码点升序、sid>after 的前 limit 项，顶层时刻/下个/剩余/项目，
  LF 尾紧凑 JSON，O((S+Q) log(S+Q))/O(S+Q)。
- Sessions.compliance_events/compliance_snapshot/compliance_restore 运行态
  合规全局链：把此后由 audit、batch_audit、capacity_events 可观察到的每条
  源事件，按真实追加先后（不按可回拨时刻重排）同步投影到同一条全局链，
  全局序号自 1 连续。事件六字段键序“全局序号/来源/来源序号/载荷/前哈希/
  哈希”，来源仅审计/批量/容量，载荷为对应公开源事件按既有键序（audit
  九键、batch_audit 十键、capacity_events 五键）生成的紧凑 JSON 串；哈希
  覆盖前五字段，首项前哈希为 64 个 0。源事件与其投影原子追加（源事件未
  产生不写全局链，批量项保持输入顺序，推进仍先超时后晋升）；audit_restore、
  batch_audit_restore 与 creplay 导入/替换源事件不回灌历史投影。
  compliance_events 沿 audit 的 after/limit（1..1000）只读查询，固定键序、
  LF 尾紧凑 JSON，空页游标保持 after；compliance_snapshot 返回版本 1、
  锚序号/锚哈希/上限/下个序号/事件/摘要（摘要盖前六键），供离线校验锚点、
  顺序、逐项哈希与摘要；compliance_restore 以独立幂等 key 将规范快照原子
  接到全局链尾，只恢复合规事件且不生成自身事件，同 key 同文本重放返回原
  字节不重复追加、异参 ValueError，结构/键序/类型/范围/摘要/链内衔接/来源
  载荷形态非法 ValueError、锚与链尾不符 StateError、text 非 str TypeError，
  失败不改链不占 key。三个入口不触发认证、老化或统计；查询与快照
  O(limit) 时空、恢复 O(事件数) 时空，同状态同参逐字节同结果。
- Sessions.batch_offline 批量下线：按 key 独立重放缓存，首果（含参数异常）
  永久缓存；首次合法先老化，非原子逐项下线/未知、原子全存在才提交否则整批
  回滚（保留老化），不写既有审计链或容量事件；合法首调与同参重放逐项写
  独立的批量防篡改审计链（batch_audit，操作“批量下线”）。
- Sessions.batch_online 批量建立：按 key 独立重放缓存，首果（含参数异常）
  永久缓存；首次合法先老化，逐项经后端、认证、容量、default 池与静态址
  规则建立，业务异常不抛而记项结果类名；非原子逐项提交，原子演算全部、
  任一失败整批回滚（保留老化、认证计数与退避），不写既有审计链或容量事件；
  合法首调与同参重放逐项写批量防篡改审计链（操作“批量上线”）。
- Sessions.batch_migrate 批量迁移：按 key 独立重放缓存，首果（含参数异常）
  永久缓存；首次合法先老化，逐项沿用 do 迁移规则，业务异常不抛而记项结果
  类名；非原子逐项提交，原子在同一老化后演算态预演全部、任一失败恢复至老化
  后快照（认证计数、锁定与退避保留），不写既有审计链或容量事件；合法首调与
  同参重放逐项写批量防篡改审计链（操作“批量迁移”）。
- Sessions.keepalive 批量保活：按 key 独立重放缓存，首果（含参数异常）
  永久缓存；首次合法先老化（期限到的在线项挂起退租，老化不回滚），非原子
  依序把在线项空闲期限改为 now_ms+idle_ms 记“保活”，未知记“未知”、挂起/
  下线墓碑记“状态”；原子先查快照，全在线才提交，否则失败项记未知/状态、
  在线项记“回滚”且不延长期限。保活只改期限，不续租、不分址、不记容量事件
  或统计、不写既有审计链；合法首调与同参重放逐项写批量防篡改审计链（操作
  “批量保活”）。
- Sessions.batch_audit(after=0,limit=100) 批量操作防篡改审计只读查询：返回
  上述五类批量合法首调与同参重放逐项追加的独立哈希链（与 audit 的接管/do
  链相互独立）。after/limit 为非 bool int，after<0 或 limit∉1..1000 分别抛
  TypeError/ValueError；只读返回序号>after 的前 limit 项，顶层键序
  “下个序号/事件”，空页游标为 after。事件键序“序号/时刻/键/操作/原子/会话/
  结果/原序号/前哈希/哈希”，首项前哈希 64 个 0、余项承前项，哈希为前九键
  紧凑 JSON（ensure_ascii=False、separators=(',',':')）UTF-8 字节 sha256
  小写值，输出加 LF。首调结果取项目结果、原序号 0；重放结果“重放”、原序号
  指认对应首次事件；参数错、异参 key 不记。查询 O(limit) 时空、不老化不改态。
- Sessions.batch_audit_restore(key,text) 将 batch_audit 分页结果原子接入批量
  防篡改审计链：key 沿凭据约束，text 非 str 抛 TypeError；JSON、重键、编码、
  结构、范围或事件超过 1000 项错均 ValueError；顶层“下个序号/事件”及事件
  十键“序号/时刻/键/操作/原子/会话/结果/原序号/前哈希/哈希”键序/类型沿
  batch_audit 基线；非空页序号连续、游标等于末序号，自第 2 项起前哈希衔接，
  每项哈希按前九键复算，原序号为 0 或指向同键/操作/原子/会话的更早首次项；
  空页游标即页锚。非空页锚为首序号减 1、首项前哈希，空页锚为游标；当前链尾
  不符（首序号≠当前末序号+1、首项前哈希≠当前末哈希，或空页游标≠当前末序号）
  抛 StateError(页锚,当前末序号)，余不符 ValueError。全验后原子追加十元组，
  失败不改链；不恢复业务态、缓存或幂等索引，接入不写链。独立缓存仅成功占位，
  同参重放原字节且不追加，异参 ValueError。返回 追加/末序号/末哈希/摘要，
  摘要为前三键紧凑 JSON UTF-8 字节 sha256 小写值，LF 尾；O(事件数) 时空。
- Sessions.credential_change 凭据轮换：按 key 独立重放缓存，首果（含参数
  异常）永久缓存；首次合法经 Authenticator 校验旧密码，非 ok（denied/
  locked/backoff）抛 AuthError 并保留失败计数、锁定与下次可试时刻，成功按
  摘要规则换密并清零此三类限制，会话与已入队队项保留；首果（成功/
  AuthError/KeyError）及同参重放写防篡改审计链（凭据轮换，会话=user），
  参数错不审计。
- Sessions.batch_credential_change 批量凭据轮换：items 为 1..1000 个
  (user,old_password,new_password) 三元组 tuple、三串沿凭据约束、旧新不同
  且 user 互异，now_ms 为非 bool 非负 int，atomic 为 bool；容器/元素/字段
  类型错 TypeError，数量/形态/重复用户/凭据取值/负时刻 ValueError，整批
  参数错不认证、不改态、不占 key、不审计。合法首果按 key 独立永久缓存，同
  参重放逐字节返回首果不再认证或轮换，异参 ValueError。逐项沿用
  credential_change 的停用检查与旧口令认证语义，未知用户记 KeyError，停用/
  口令错误/锁定/退避记 AuthError，业务失败入项结果而不抛；验证成功才换密
  并清零失败计数、锁定截止与下次可试时刻。非原子依次提交成功项；原子校验
  全部项、全成功才一次提交，任一失败则可成功项记“回滚”、全部凭据保持批次
  前值，而认证失败计数、锁定、退避及成功验证的限制清零均保留。两模式均不
  老化，不改变会话、租约、容量队列、QoS 账本或停用状态。合法首调与同参
  重放按输入序逐项写批量防篡改审计链（操作“批量凭据轮换”，会话字段=用户名）
  并沿既有规则投影到 compliance 链，不写单操作 audit 链。返回键序
  时刻/原子/结果/项目 的 LF 尾紧凑 JSON，结果仅成功/部分成功/失败/回滚，
  项键序 用户/结果，项结果仅轮换/回滚/实际异常类名；单批与重放均 O(B)
  时间、O(B) 空间（B≤1000）。
- Sessions.user_admin 用户停用/启用：key/user 沿用凭据，op 仅停用/启用，
  now_ms 为非 bool 非负 int、force 为 bool，启用限 force=False；型/值错
  TypeError/ValueError，未知用户 KeyError。停用遇非下线会话或队项且
  force=False 抛 StateError；force=True 原子下线其非下线会话、清期限退租
  并删队项，无容量事件；失败不变。停用后 do 建立/迁移/接管、capacity
  申请、batch_online 及 credential_change 先于后端和认证拒绝（单项
  AuthError、批量项 AuthError），锁定、退避、失败计数不变；启用恢复；
  同态成功且下线/取消二数为 0。独立域首果（含异常）永久缓存，同型同参
  重放、异参 ValueError；返回 LF 尾紧凑 JSON（用户/状态/时刻/下线/取消）；
  成功首果与成功同参重放写防篡改审计链（用户停用/用户启用，会话=user，
  成功/重放），参数错及业务异常不审计。
  停用态不随配置加载/回滚与检查点恢复改变。
- Sessions.fault_plan 批量故障演练计划：key 沿用凭据，mode 仅预检/执行，
  steps 为 1..1000 项 (domain,target,op,value) 四元组；域仅后端/池/超时、
  op 仅注入/恢复，后端/超时 target 为 "" 且各唯一，池 target 沿标识且互异，
  后端/池注入 value 为正 int（截至=now_ms+value），超时注入 value>=now_ms，
  恢复 value=None；型/结构值/未知池分别抛 TypeError/ValueError/KeyError。
  全验演算，预检只读、执行原子提交；后端变更清退避、留失败计数，未列域不变。
  执行以 key 缓存首个成功/KeyError，同参重放原果、异参 ValueError；首果与
  重放写防篡改审计链（故障计划，会话空串，结果/原序号沿 config_change），
  预检与参数错不缓存、不审计；成功返回演算态 fault_checkpoint(now_ms) 包。
- Sessions.fault_impact 只读评估计划：steps 沿用 fault_plan 的 1..1000 项
  tuple 契约（无 key/mode），now_ms 为非 bool 非负 int；型/结构值/重复/未知池
  分别抛 TypeError/ValueError/KeyError。不老化、不缓存、不审计、不改状态。
  按 now_ms 取视图（到期在线归挂起；租约须在线且期限、租期均 > now_ms；到期
  队项不计）：后端在 now_ms<演算截至时计全局四类，池同条件计本池在线/租约
  （default 另计全队、挂起 0），超时在等待且触发 <=now_ms 时计全局在线/排队/
  租约、挂起 0，否则行全 0；域行依次后端、升序注入池、超时，后端/超时目标
  空串。顶层时刻/域/合计/摘要，合计为各行和（可重复），摘要为前三键紧凑
  JSON UTF-8 字节的 sha256 小写值；LF 尾紧凑，同态同参同字节。
- Sessions.fault_diff 只读对比两份计划：left/right 沿用 fault_plan 的 steps
  契约，now_ms 为非 bool 非负 int；型/结构值/重复/未知池分别抛
  TypeError/ValueError/KeyError。不老化、不缓存、不审计、不改状态，两侧均
  从同一当前故障态演算，视图与计数沿用 fault_impact。域行按后端、两侧池
  标识并集 Unicode 升序、超时排列；缺侧池行按不生效、四项 0。行键序
  域/目标/左/右/增减，左/右均为 生效/在线/挂起/排队/租约，增减键序
  在线/挂起/排队/租约、值为右减左。顶层时刻/域/合计/摘要，合计为各行增减
  逐项和，摘要为前三键紧凑 JSON UTF-8 字节的 sha256 小写值；LF 尾紧凑。
- Sessions.fault_matrix 只读批量评估多份计划：scenarios 为 1..100 项
  (标识,steps) tuple，标识为互异凭据串，steps 沿用 fault_plan 的 steps
  契约，now_ms 为非 bool 非负 int；型/结构长度值/重复分别抛
  TypeError/ValueError，未知池抛 KeyError。不老化、不缓存、不审计、不改
  状态。基准（不施加步骤）与各场景均从实例当前同一故障态演算，视图与四类
  计数沿用 fault_impact。域取基准与各场景在册池标识并集，行按后端、池
  Unicode 升序、超时排列，缺侧行按不生效、四项 0，场景按输入序。基准行
  键序 域/目标/生效/在线/挂起/排队/租约；场景项键序 标识/域/合计，其域行
  在基准行后追加“增减”（键序 在线/挂起/排队/租约、值为场景-基准），合计
  键序同增减、为逐行增减之和。顶层时刻/基准/场景/摘要，摘要为前三键紧凑
  JSON UTF-8 字节的 sha256 小写值；LF 尾紧凑。时间
  O(S+Q+K+CP+P log P)、辅助空间 O(CP+K)，C/P/K 为场景数/池并集数/步骤
  总数。
所有时间均由调用方以显式时钟（毫秒整数）驱动。
"""

import hashlib
import heapq
import hmac
import ipaddress
import json
import sys

__all__ = [
    "Authenticator",
    "AuthError",
    "ResourceError",
    "StateError",
    "BackendError",
    "Sessions",
]

_MAX_USERS = 10000
_MIN_CRED_BYTES = 1
_MAX_CRED_BYTES = 256
_MIN_PREFIX = 16


class AuthError(Exception):
    """认证结果非 ok。"""


class ResourceError(Exception):
    """会话总数、单用户会话数或地址池资源已达上限。"""


class StateError(Exception):
    """会话状态不允许当前操作。"""


class BackendError(Exception):
    """后端故障未恢复或退避未到期；值为可重试时刻 retry_at。"""


def _check_int(name, value, minimum):
    """校验非 bool 的 int 且 >= minimum；类型不符 TypeError，越界 ValueError。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _effective_used(used, last, now_ms, period_ms):
    """按配额周期 P 折算当前有效累计：P>0 且 now_ms 与上次通过时刻 t 不在同一
    周期窗（now_ms//P != t//P）时累计已重置，有效累计为 0；否则为账本 u。
    P=0 表示不重置，恒取 u。调用方须已保证 now_ms >= t。"""
    if period_ms > 0 and now_ms // period_ms != last // period_ms:
        return 0
    return used


def _check_credential(name, value):
    """校验 str、UTF-8 编码后 1..256 字节、不含 U+0000。"""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    encoded = value.encode("utf-8")
    if not (_MIN_CRED_BYTES <= len(encoded) <= _MAX_CRED_BYTES):
        raise ValueError(
            f"{name} must be 1..256 bytes when UTF-8 encoded, got {len(encoded)}"
        )
    if "\0" in value:
        raise ValueError(f"{name} must not contain U+0000")
    return value


def _check_ip(name, value):
    """校验规范 IPv4 地址串，返回其 int；类型不符 TypeError，格式不符 ValueError。"""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a canonical IPv4 address: {value!r}") from exc
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical IPv4 address: {value!r}")
    return int(parsed)


def _check_pool(pool):
    """校验地址池三元组 (cidr, reserved, static)，返回解析后的池数据。

    cidr 为主机位零、前缀 16..32 的规范 IPv4 网串；reserved 为保留地址串元组，
    static 为 (user, IP) 对元组。地址须规范、属可用集且不重复，静态用户唯一，
    保留集与静态集不交。
    """
    if not isinstance(pool, tuple):
        raise TypeError(f"pool must be None or a tuple, got {type(pool).__name__}")
    if len(pool) != 3:
        raise ValueError(
            f"pool must be a 3-tuple (cidr, reserved, static), got {len(pool)} items"
        )
    cidr, reserved, static = pool

    if not isinstance(cidr, str):
        raise TypeError(f"cidr must be a str, got {type(cidr).__name__}")
    try:
        network = ipaddress.IPv4Network(cidr, strict=True)
    except ValueError as exc:
        raise ValueError(
            f"cidr must be a canonical IPv4 network with zero host bits: {cidr!r}"
        ) from exc
    # strict=True 已拒主机位非零；再限前缀范围并要求规范串（拒 /024 等写法）。
    if not (_MIN_PREFIX <= network.prefixlen <= 32) or str(network) != cidr:
        raise ValueError(
            f"cidr must be canonical with prefix length {_MIN_PREFIX}..32: {cidr!r}"
        )
    # hosts() 对 /16../30 去网络/广播地址，/31 给两址、/32 给独址。
    usable = {int(host) for host in network.hosts()}

    if not isinstance(reserved, tuple):
        raise TypeError(
            f"reserved must be a tuple, got {type(reserved).__name__}"
        )
    reserved_ips = set()
    for ip_str in reserved:
        ip_int = _check_ip("reserved IP", ip_str)
        if ip_int not in usable:
            raise ValueError(f"reserved IP {ip_str!r} is not in usable set of {cidr!r}")
        if ip_int in reserved_ips:
            raise ValueError(f"duplicate reserved IP: {ip_str!r}")
        reserved_ips.add(ip_int)

    if not isinstance(static, tuple):
        raise TypeError(f"static must be a tuple, got {type(static).__name__}")
    static_map = {}
    static_ips = set()
    for pair in static:
        if not isinstance(pair, tuple):
            raise TypeError(
                f"static entry must be a (user, IP) tuple, got {type(pair).__name__}"
            )
        if len(pair) != 2:
            raise ValueError(
                f"static entry must be a 2-tuple (user, IP), got {len(pair)} items"
            )
        user, ip_str = pair
        _check_credential("static user", user)
        ip_int = _check_ip("static IP", ip_str)
        if ip_int not in usable:
            raise ValueError(f"static IP {ip_str!r} is not in usable set of {cidr!r}")
        if user in static_map:
            raise ValueError(f"duplicate static user: {user!r}")
        if ip_int in static_ips:
            raise ValueError(f"duplicate static IP: {ip_str!r}")
        if ip_int in reserved_ips:
            raise ValueError(f"static IP {ip_str!r} must not be in reserved set")
        static_map[user] = ip_int
        static_ips.add(ip_int)

    return network, usable, reserved_ips, static_map, static_ips


def _unique_object(pairs):
    """json object_pairs_hook：重复键抛 ValueError。"""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key: {key!r}")
        obj[key] = value
    return obj


def _parse_config_pool(obj):
    """校验单个池对象（CIDR/保留/静态），返回规范化 (cidr, reserved, static)。

    reserved 为按 IPv4 整数升序的地址串元组，static 为按用户升序的
    (user, IP) 串对元组；结构、值或池规则错均抛 ValueError。
    """
    cidr = obj["CIDR"]
    reserved = obj["保留"]
    static = obj["静态"]
    if not isinstance(cidr, str):
        raise ValueError(f"CIDR must be a str, got {type(cidr).__name__}")
    if not isinstance(reserved, list) or not all(
        isinstance(item, str) for item in reserved
    ):
        raise ValueError("保留 must be a list of IPv4 address strings")
    if not isinstance(static, list):
        raise ValueError(f"静态 must be a list, got {type(static).__name__}")
    pairs = []
    for entry in static:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
        ):
            raise ValueError("静态 entries must be [user, IP] string pairs")
        pairs.append((entry[0], entry[1]))
    try:
        parsed = _check_pool((cidr, tuple(reserved), tuple(pairs)))
    except TypeError as exc:
        raise ValueError(str(exc)) from exc
    network, _usable, reserved_ips, static_map, _static_ips = parsed
    canonical_reserved = tuple(
        str(ipaddress.IPv4Address(ip_int)) for ip_int in sorted(reserved_ips)
    )
    canonical_static = tuple(
        (user, str(ipaddress.IPv4Address(static_map[user])))
        for user in sorted(static_map)
    )
    return (str(network), canonical_reserved, canonical_static)


def _parse_config_templates(doc, version):
    """校验 v3+ 的模板与用户模板，返回规范化 (templates, user_templates)。

    templates 为按标识升序的 (标识, 限速, 突发, 配额, 周期毫秒, 会话上限,
    排队优先级, 超限) 元组：标识沿用凭据约束，限速/配额为非 bool 正 int（限速为字节/秒、
    配额为字节），突发为非 bool 非负 int（字节），周期毫秒为非 bool 非负 int
    （0 表示不重置），会话上限为非 bool int 0..10000（0 表示不限并发占用），
    排队优先级为非 bool int 0..100，超限仅“拒绝”或“下线”。v8 模板项键序为
    标识/限速/突发/配额/周期毫秒/会话上限/排队优先级/超限；v7 模板项无排队
    优先级键，v6 模板项无周期毫秒与排队优先级键，v3-v5 模板项无周期毫秒、
    会话上限与排队优先级键，迁移均补 0。
    user_templates 为按用户升序的 (user, 标识) 元组：用户唯一，标识须已定义。
    结构、类型、值、重复项或标识引用错均抛 ValueError；用户是否在认证器中
    由调用方校验。
    """
    raw_templates = doc["模板"]
    if not isinstance(raw_templates, list):
        raise ValueError(f"模板 must be a list, got {type(raw_templates).__name__}")
    templates = []
    seen_ids = set()
    for item in raw_templates:
        # v8 模板项恰含八键（键序在规范重编码比对时约束）；v7 为七键；
        # v6 为六键；v3-v5 为五键。
        if version >= 8:
            keys_ok = isinstance(item, dict) and set(item) == {
                "标识", "限速", "突发", "配额", "周期毫秒", "会话上限",
                "排队优先级", "超限"
            }
            if not keys_ok:
                raise ValueError(
                    "template entry keys must be exactly "
                    "标识/限速/突发/配额/周期毫秒/会话上限/排队优先级/超限"
                )
        elif version >= 7:
            keys_ok = isinstance(item, dict) and set(item) == {
                "标识", "限速", "突发", "配额", "周期毫秒", "会话上限", "超限"
            }
            if not keys_ok:
                raise ValueError(
                    "template entry keys must be exactly "
                    "标识/限速/突发/配额/周期毫秒/会话上限/超限"
                )
        elif version >= 6:
            keys_ok = isinstance(item, dict) and set(item) == {
                "标识", "限速", "突发", "配额", "会话上限", "超限"
            }
            if not keys_ok:
                raise ValueError(
                    "template entry keys must be exactly "
                    "标识/限速/突发/配额/会话上限/超限"
                )
        elif not isinstance(item, dict) or set(item) != {
            "标识",
            "限速",
            "突发",
            "配额",
            "超限",
        }:
            raise ValueError(
                "template entry keys must be exactly 标识/限速/突发/配额/超限"
            )
        template_id = item["标识"]
        try:
            _check_credential("template id", template_id)
        except TypeError as exc:
            raise ValueError(str(exc)) from exc
        if template_id in seen_ids:
            raise ValueError(f"duplicate template id: {template_id!r}")
        seen_ids.add(template_id)
        numbers = {}
        for name, minimum in (("限速", 1), ("突发", 0), ("配额", 1)):
            value = item[name]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an int, got {type(value).__name__}")
            if value < minimum:
                raise ValueError(f"{name} must be >= {minimum}, got {value}")
            numbers[name] = value
        if version >= 7:
            period_ms = item["周期毫秒"]
            if isinstance(period_ms, bool) or not isinstance(period_ms, int):
                raise ValueError(
                    f"周期毫秒 must be an int, got {type(period_ms).__name__}"
                )
            if period_ms < 0:
                raise ValueError(f"周期毫秒 must be >= 0, got {period_ms}")
        else:
            # v3-v6 迁移：配额周期补 0（不重置）。
            period_ms = 0
        if version >= 6:
            session_limit = item["会话上限"]
            if isinstance(session_limit, bool) or not isinstance(session_limit, int):
                raise ValueError(
                    f"会话上限 must be an int, got {type(session_limit).__name__}"
                )
            if not (0 <= session_limit <= _MAX_TEMPLATE_SESSIONS):
                raise ValueError(
                    f"会话上限 must be 0..{_MAX_TEMPLATE_SESSIONS}, "
                    f"got {session_limit}"
                )
        else:
            # v3-v5 迁移：并发会话上限补 0（不限）。
            session_limit = 0
        if version >= 8:
            priority = item["排队优先级"]
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise ValueError(
                    f"排队优先级 must be an int, got {type(priority).__name__}"
                )
            if not (0 <= priority <= _MAX_QUEUE_PRIORITY):
                raise ValueError(
                    f"排队优先级 must be 0..{_MAX_QUEUE_PRIORITY}, got {priority}"
                )
        else:
            # v1-v7 迁移：排队基础优先级补 0。
            priority = 0
        exceed = item["超限"]
        if exceed not in ("拒绝", "下线"):
            raise ValueError(f"超限 must be 拒绝 or 下线, got {exceed!r}")
        templates.append(
            (
                template_id,
                numbers["限速"],
                numbers["突发"],
                numbers["配额"],
                period_ms,
                session_limit,
                priority,
                exceed,
            )
        )
    templates.sort(key=lambda item: item[0])

    raw_pairs = doc["用户模板"]
    if not isinstance(raw_pairs, list):
        raise ValueError(f"用户模板 must be a list, got {type(raw_pairs).__name__}")
    template_ids = {item[0] for item in templates}
    user_templates = []
    seen_users = set()
    for entry in raw_pairs:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
        ):
            raise ValueError("用户模板 entries must be [user, 标识] string pairs")
        user, template_id = entry
        try:
            _check_credential("user", user)
        except TypeError as exc:
            raise ValueError(str(exc)) from exc
        if user in seen_users:
            raise ValueError(f"duplicate user template user: {user!r}")
        seen_users.add(user)
        if template_id not in template_ids:
            raise ValueError(f"unknown template id: {template_id!r}")
        user_templates.append((user, template_id))
    user_templates.sort(key=lambda item: item[0])
    return tuple(templates), tuple(user_templates)


def _parse_config_capacity(doc, version):
    """校验容量节，返回 (队列上限, 最大等待毫秒, 队满策略)。

    v4..v8 容量须恰含“队列上限/最大等待毫秒”，迁移时队满策略补“拒绝”；
    v9 须恰含“队列上限/最大等待毫秒/队满策略”。队列上限与最大等待毫秒为
    非 bool int：队列上限 0..10000（0 表示不限），最大等待毫秒 >= 0（0
    表示不限）；队满策略为 str 且仅“拒绝/替换”。结构、类型或值错均抛
    ValueError。
    """
    raw = doc["容量"]
    if version >= 9:
        if not isinstance(raw, dict) or set(raw) != {
            "队列上限", "最大等待毫秒", "队满策略"
        }:
            raise ValueError(
                "容量 keys must be exactly 队列上限/最大等待毫秒/队满策略"
            )
        policy = raw["队满策略"]
        if not isinstance(policy, str) or policy not in _QUEUE_POLICIES:
            raise ValueError(
                "队满策略 must be one of 拒绝/替换, got "
                f"{policy!r}"
            )
    else:
        if not isinstance(raw, dict) or set(raw) != {"队列上限", "最大等待毫秒"}:
            raise ValueError("容量 keys must be exactly 队列上限/最大等待毫秒")
        # v1..v8 迁移：队满策略补“拒绝”。
        policy = _QUEUE_POLICY_REJECT
    queue_limit = raw["队列上限"]
    max_wait = raw["最大等待毫秒"]
    if isinstance(queue_limit, bool) or not isinstance(queue_limit, int):
        raise ValueError(
            f"队列上限 must be an int, got {type(queue_limit).__name__}"
        )
    if not (0 <= queue_limit <= _MAX_QUEUE_LIMIT):
        raise ValueError(
            f"队列上限 must be 0..{_MAX_QUEUE_LIMIT}, got {queue_limit}"
        )
    if isinstance(max_wait, bool) or not isinstance(max_wait, int):
        raise ValueError(f"最大等待毫秒 must be an int, got {type(max_wait).__name__}")
    if max_wait < 0:
        raise ValueError(f"最大等待毫秒 must be >= 0, got {max_wait}")
    return queue_limit, max_wait, policy


def _parse_config_auth(doc, version):
    """校验 v5+ 的认证节，返回 (最大失败, 锁定毫秒, 重试基数毫秒, 重试上限毫秒)。

    v5-v9 认证须恰含“最大失败/锁定毫秒”，迁移时两项重试补 0（无退避）；v10
    认证须恰含“最大失败/锁定毫秒/重试基数毫秒/重试上限毫秒”。四者为非 bool
    int：最大失败 >= 1，锁定毫秒 >= 0，两项重试 >= 0，且只许同时为 0 或同时
    为正，重试上限毫秒不得小于重试基数毫秒。结构、类型或值错均抛 ValueError。
    """
    raw = doc["认证"]
    if version >= 10:
        if not isinstance(raw, dict) or set(raw) != {
            "最大失败", "锁定毫秒", "重试基数毫秒", "重试上限毫秒"
        }:
            raise ValueError(
                "认证 keys must be exactly "
                "最大失败/锁定毫秒/重试基数毫秒/重试上限毫秒"
            )
    elif not isinstance(raw, dict) or set(raw) != {"最大失败", "锁定毫秒"}:
        raise ValueError("认证 keys must be exactly 最大失败/锁定毫秒")
    max_fail = raw["最大失败"]
    lock_ms = raw["锁定毫秒"]
    if isinstance(max_fail, bool) or not isinstance(max_fail, int):
        raise ValueError(f"最大失败 must be an int, got {type(max_fail).__name__}")
    if max_fail < 1:
        raise ValueError(f"最大失败 must be >= 1, got {max_fail}")
    if isinstance(lock_ms, bool) or not isinstance(lock_ms, int):
        raise ValueError(f"锁定毫秒 must be an int, got {type(lock_ms).__name__}")
    if lock_ms < 0:
        raise ValueError(f"锁定毫秒 must be >= 0, got {lock_ms}")
    if "重试基数毫秒" in raw:
        retry_base = raw["重试基数毫秒"]
        retry_cap = raw["重试上限毫秒"]
        if isinstance(retry_base, bool) or not isinstance(retry_base, int):
            raise ValueError(
                f"重试基数毫秒 must be an int, got {type(retry_base).__name__}"
            )
        if isinstance(retry_cap, bool) or not isinstance(retry_cap, int):
            raise ValueError(
                f"重试上限毫秒 must be an int, got {type(retry_cap).__name__}"
            )
        if retry_base < 0 or retry_cap < 0:
            raise ValueError("重试基数毫秒/重试上限毫秒 must be >= 0")
        if (retry_base == 0) != (retry_cap == 0):
            raise ValueError(
                "重试基数毫秒 and 重试上限毫秒 must be both 0 or both positive"
            )
        if retry_cap < retry_base:
            raise ValueError(
                "重试上限毫秒 must be >= 重试基数毫秒, got "
                f"{retry_cap} < {retry_base}"
            )
    else:
        # v5-v9 迁移：重试两项补 0，保持无退避行为。
        retry_base = 0
        retry_cap = 0
    return max_fail, lock_ms, retry_base, retry_cap


def _load_config_doc(text):
    """校验 text 为 str 并解析 JSON（拒重键），返回对象文档。

    text 非 str 抛 TypeError；JSON 解析错（JSONDecodeError 系 ValueError
    子类）或重复键抛 ValueError。是否为对象、键与结构由调用方校验。
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    return json.loads(text, object_pairs_hook=_unique_object)


def _parse_config_doc(doc, default_auth=None):
    """由已解析对象文档校验并迁移为规范化 spec；任何错均抛 ValueError。

    spec 为 (total, per, idle_ms, lease_ms, pools, templates, user_templates,
    capacity, auth, template_pool_order)，capacity 为 (队列上限, 最大等待毫秒,
    队满策略)，auth 为
    (最大失败, 锁定毫秒, 重试基数毫秒, 重试上限毫秒)，template_pool_order 为
    按模板标识升序的 (模板标识, (池标识...)) 元组（每项 1..32 个互异池标识）；
    pools 为按标识升序的 (标识, cidr, reserved,
    static) 元组，reserved/static 已规范化排序；templates 为按标识升序的
    (标识, 限速, 突发, 配额, 周期毫秒, 会话上限, 排队优先级, 超限) 元组，
    user_templates 为按用户升序的 (user, 标识) 元组。v1（版本=1）地址池为
    无标识单池对象，迁移为 default 池；v2（版本=2）地址池为池对象列表；
    v3（版本=3）增模板与用户模板；v4（版本=4）增容量背压（队列上限/最大
    等待毫秒）；v5（版本=5）增认证策略（最大失败/锁定毫秒）；v6（版本=6）
    模板项增会话上限（0..10000，0 不限）；v7（版本=7）模板项增周期毫秒
    （非负 int，0 表示不重置）；v8（版本=8）模板项增排队优先级（非 bool
    int 0..100）；v9（版本=9）容量节增队满策略（str，仅“拒绝/替换”，
    键序 队列上限/最大等待毫秒/队满策略）；v10（版本=10）认证节增重试基数
    毫秒/重试上限毫秒（非 bool 非负 int，同时为 0 或同时为正，上限不小于
    基数，键序 最大失败/锁定毫秒/重试基数毫秒/重试上限毫秒）；v11（版本=11）
    在认证节后新增“模板地址池”（顶层末位键，固定键序）：按模板标识升序的
    二元数组列表，每项 [模板标识, [池标识...]]，池序列为 1..32 个互异且已
    定义的池标识，同一模板至多出现一次，模板标识须已定义。v1/v2 迁移
    时模板、用户模板为空；v1-v3 迁移时容量补默认 (1024, 0, 拒绝)；v1-v8
    迁移时队满策略补“拒绝”；v1-v4 迁移时认证补 default_auth（认证器当前
    四值，缺省 None 时拒绝非 v5+ 文档）；v1-v5 迁移时模板会话上限补 0；
    v1-v6 迁移时模板周期毫秒补 0；v1-v7 迁移时模板排队优先级补 0；v8 只
    规范化容量旧两键；v1-v9 迁移时重试两项补 0（无退避）；v1-v10 升级时
    模板地址池列表补空。重复/未知/缺失
    键、结构、类型、数量、排序、值、引用或版本错均抛 ValueError。
    """
    if not isinstance(doc, dict):
        raise ValueError(f"config must be a JSON object, got {type(doc).__name__}")
    version = doc.get("版本")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"版本 must be an int, got {type(version).__name__}")
    if version not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        raise ValueError(f"版本 must be 1..11, got {version}")
    _config_keys_v5 = (
        "版本", "会话", "地址池", "模板", "用户模板", "容量", "认证"
    )
    if version == 11:
        if set(doc) != set(_config_keys_v5) | {_TEMPLATE_POOLS_KEY}:
            raise ValueError(
                "config keys must be exactly "
                "版本/会话/地址池/模板/用户模板/容量/认证/模板地址池"
            )
    elif version in (5, 6, 7, 8, 9, 10):
        if set(doc) != set(_config_keys_v5):
            raise ValueError(
                "config keys must be exactly 版本/会话/地址池/模板/用户模板/容量/认证"
            )
    elif version == 4:
        if set(doc) != {
            "版本", "会话", "地址池", "模板", "用户模板", "容量"
        }:
            raise ValueError(
                "config keys must be exactly 版本/会话/地址池/模板/用户模板/容量"
            )
    elif version == 3:
        if set(doc) != {"版本", "会话", "地址池", "模板", "用户模板"}:
            raise ValueError(
                "config keys must be exactly 版本/会话/地址池/模板/用户模板"
            )
    elif set(doc) != {"版本", "会话", "地址池"}:
        raise ValueError("config keys must be exactly 版本/会话/地址池")

    session = doc["会话"]
    if not isinstance(session, dict) or set(session) != {
        "总数",
        "每用户",
        "空闲毫秒",
        "租期毫秒",
    }:
        raise ValueError("会话 keys must be exactly 总数/每用户/空闲毫秒/租期毫秒")
    numbers = {}
    for name, minimum in (("总数", 1), ("每用户", 1), ("空闲毫秒", 0), ("租期毫秒", 1)):
        value = session[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an int, got {type(value).__name__}")
        if value < minimum:
            raise ValueError(f"{name} must be >= {minimum}, got {value}")
        numbers[name] = value

    raw_pools = doc["地址池"]
    if version == 1:
        if not isinstance(raw_pools, dict):
            raise ValueError("v1 地址池 must be a single pool object")
        if set(raw_pools) != {"CIDR", "保留", "静态"}:
            raise ValueError("v1 地址池 keys must be exactly CIDR/保留/静态")
        entries = [(_DEFAULT_POOL_ID, raw_pools)]
    else:
        if not isinstance(raw_pools, list):
            raise ValueError("v2 地址池 must be a list of pool objects")
        entries = []
        seen_ids = set()
        for item in raw_pools:
            if not isinstance(item, dict) or set(item) != {"标识", "CIDR", "保留", "静态"}:
                raise ValueError("pool entry keys must be exactly 标识/CIDR/保留/静态")
            pool_id = item["标识"]
            try:
                _check_credential("pool id", pool_id)
            except TypeError as exc:
                raise ValueError(str(exc)) from exc
            if pool_id in seen_ids:
                raise ValueError(f"duplicate pool id: {pool_id!r}")
            seen_ids.add(pool_id)
            entries.append((pool_id, item))

    pool_specs = []
    for pool_id, obj in entries:
        cidr, reserved, static = _parse_config_pool(obj)
        pool_specs.append((pool_id, cidr, reserved, static))
    pool_specs.sort(key=lambda item: item[0])
    if version >= 3:
        templates, user_templates = _parse_config_templates(doc, version)
    else:
        # v1/v2 迁移：模板与用户模板均为空。
        templates, user_templates = (), ()
    if version >= 4:
        capacity = _parse_config_capacity(doc, version)
    else:
        # v1-v3 迁移：容量补默认 1024 项队列、不限等待、队满拒绝。
        capacity = (_MAX_QUEUE, 0, _QUEUE_POLICY_REJECT)
    if version >= 5:
        auth = _parse_config_auth(doc, version)
    else:
        # v1-v4 迁移：认证补认证器当前两值；无默认（如升级包内嵌配置须为
        # v8 规范形态）时拒绝。
        if default_auth is None:
            raise ValueError(f"config version must be {_CONFIG_VERSION}")
        auth = default_auth
    if version >= 11:
        template_pool_order = _parse_template_pools(
            doc[_TEMPLATE_POOLS_KEY], pool_specs, templates
        )
    else:
        # v1-v10 迁移：模板地址池列表为空，全部自动取址沿用 default 池。
        template_pool_order = ()
    return (
        numbers["总数"],
        numbers["每用户"],
        numbers["空闲毫秒"],
        numbers["租期毫秒"],
        tuple(pool_specs),
        templates,
        user_templates,
        capacity,
        auth,
        template_pool_order,
    )


def _parse_template_pools(raw, pool_specs, templates):
    """校验 v11 “模板地址池”节，返回按模板标识升序的 (模板标识, 池序列)
    元组；池序列为 1..32 个互异池标识的 tuple，保持文档给出的优先次序。

    raw 须为二元数组列表：每项 [模板标识, [池标识...]]；模板标识须为凭据
    串、已在模板节定义且全表唯一；池标识须为凭据串、已在地址池节定义、项内
    互异且数量为 1..32；整表须按模板标识 Unicode 码点严格升序。结构、类型、
    数量、排序、重复或引用错均抛 ValueError。
    """
    if not isinstance(raw, list):
        raise ValueError(
            f"{_TEMPLATE_POOLS_KEY} must be a list, got {type(raw).__name__}"
        )
    pool_ids = {pool_id for pool_id, *_rest in pool_specs}
    template_ids = {template_id for template_id, *_rest in templates}
    entries = []
    previous_template = None
    seen_templates = set()
    for item in raw:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(
                f"{_TEMPLATE_POOLS_KEY} entries must be "
                "[模板标识, [池标识...]] pairs"
            )
        template_id, pool_sequence = item
        if not isinstance(template_id, str):
            raise ValueError(
                f"{_TEMPLATE_POOLS_KEY} template id must be a str, "
                f"got {type(template_id).__name__}"
            )
        try:
            _check_credential("template pool template id", template_id)
        except TypeError as exc:
            raise ValueError(str(exc)) from exc
        if template_id in seen_templates:
            raise ValueError(
                f"duplicate template in {_TEMPLATE_POOLS_KEY}: {template_id!r}"
            )
        if previous_template is not None and template_id <= previous_template:
            raise ValueError(
                f"{_TEMPLATE_POOLS_KEY} must be sorted by template id: "
                f"{template_id!r} after {previous_template!r}"
            )
        seen_templates.add(template_id)
        previous_template = template_id
        if template_id not in template_ids:
            raise ValueError(
                f"{_TEMPLATE_POOLS_KEY} references unknown template: "
                f"{template_id!r}"
            )
        if not isinstance(pool_sequence, list):
            raise ValueError(
                f"{_TEMPLATE_POOLS_KEY} pool sequence must be a list, "
                f"got {type(pool_sequence).__name__}"
            )
        if not (1 <= len(pool_sequence) <= _MAX_TEMPLATE_POOL_CHOICES):
            raise ValueError(
                f"{_TEMPLATE_POOLS_KEY} pool sequence for {template_id!r} "
                f"must contain 1..{_MAX_TEMPLATE_POOL_CHOICES} pool ids, "
                f"got {len(pool_sequence)}"
            )
        sequence = []
        seen_pools = set()
        for pool_id in pool_sequence:
            if not isinstance(pool_id, str):
                raise ValueError(
                    f"{_TEMPLATE_POOLS_KEY} pool id must be a str, "
                    f"got {type(pool_id).__name__}"
                )
            try:
                _check_credential("template pool id", pool_id)
            except TypeError as exc:
                raise ValueError(str(exc)) from exc
            if pool_id in seen_pools:
                raise ValueError(
                    f"duplicate pool {pool_id!r} in {_TEMPLATE_POOLS_KEY} "
                    f"sequence for {template_id!r}"
                )
            seen_pools.add(pool_id)
            if pool_id not in pool_ids:
                raise ValueError(
                    f"{_TEMPLATE_POOLS_KEY} references unknown pool: {pool_id!r}"
                )
            sequence.append(pool_id)
        entries.append((template_id, tuple(sequence)))
    return tuple(entries)


def _config_payload(spec):
    """由规范化 spec 构建 export/升级共用的 v11 配置 payload（固定键序与排序）。"""
    (
        total,
        per,
        idle_ms,
        lease_ms,
        pool_specs,
        templates,
        user_templates,
        (queue_limit, max_wait_ms, queue_policy),
        (max_fail, lock_ms, retry_base_ms, retry_cap_ms),
        template_pool_order,
    ) = spec
    pools = [
        {
            "标识": pool_id,
            "CIDR": cidr,
            "保留": list(reserved),
            "静态": [[user, ip] for user, ip in static],
        }
        for pool_id, cidr, reserved, static in pool_specs
    ]
    return {
        "版本": _CONFIG_VERSION,
        "会话": {
            "总数": total,
            "每用户": per,
            "空闲毫秒": idle_ms,
            "租期毫秒": lease_ms,
        },
        "地址池": pools,
        "模板": [
            {
                "标识": template_id,
                "限速": rate,
                "突发": burst,
                "配额": quota,
                "周期毫秒": period_ms,
                "会话上限": session_limit,
                "排队优先级": priority,
                "超限": exceed,
            }
            for template_id, rate, burst, quota, period_ms, session_limit,
            priority, exceed
            in templates
        ],
        "用户模板": [
            [user, template_id] for user, template_id in user_templates
        ],
        "容量": {
            "队列上限": queue_limit,
            "最大等待毫秒": max_wait_ms,
            "队满策略": queue_policy,
        },
        "认证": {
            "最大失败": max_fail,
            "锁定毫秒": lock_ms,
            "重试基数毫秒": retry_base_ms,
            "重试上限毫秒": retry_cap_ms,
        },
        _TEMPLATE_POOLS_KEY: [
            [template_id, list(pool_sequence)]
            for template_id, pool_sequence in template_pool_order
        ],
    }


def _compact_config(spec):
    """spec 的 v11 配置紧凑 JSON 串（无尾 LF），export_config 与升级包共用。"""
    return json.dumps(
        _config_payload(spec), ensure_ascii=False, separators=(",", ":")
    )


def _compact_envelope(source, target, changed, summary, config):
    """升级包五字段紧凑 JSON 串（无尾 LF），固定键序与字段类型。"""
    return json.dumps(
        {
            "源版本": source,
            "目标版本": target,
            "改变": changed,
            "摘要": summary,
            "配置": config,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _parse_upgrade_envelope(doc):
    """严格复核升级包对象，返回 (源版本, 目标版本, 改变, 摘要, spec)。

    文档须恰含“源版本/目标版本/改变/摘要/配置”五键（键序亦须如此），
    源版本为 1..11 的非 bool int、目标版本恒为 11、改变为 bool 且等于
    源版本 != 11、摘要为 str；配置须为能解析出 v11 spec 的对象，再将其
    规范化重编码与文档原编码逐字节比对（拒键序/形态/值偏差），摘要须为
    规范配置紧凑编码（无 LF）UTF-8 字节的 sha256 小写十六进制。任何不符
    均抛 ValueError。
    """
    if not isinstance(doc, dict) or set(doc) != {
        "源版本",
        "目标版本",
        "改变",
        "摘要",
        "配置",
    }:
        raise ValueError(
            "upgrade package keys must be exactly 源版本/目标版本/改变/摘要/配置"
        )
    if list(doc) != ["源版本", "目标版本", "改变", "摘要", "配置"]:
        raise ValueError(
            "upgrade package key order must be 源版本/目标版本/改变/摘要/配置"
        )
    source = doc["源版本"]
    target = doc["目标版本"]
    changed = doc["改变"]
    summary = doc["摘要"]
    if isinstance(source, bool) or not isinstance(source, int):
        raise ValueError(f"源版本 must be an int, got {type(source).__name__}")
    if source not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        raise ValueError(f"源版本 must be 1..11, got {source}")
    if isinstance(target, bool) or not isinstance(target, int):
        raise ValueError(f"目标版本 must be an int, got {type(target).__name__}")
    if target != _CONFIG_VERSION:
        raise ValueError(f"目标版本 must be {_CONFIG_VERSION}, got {target}")
    if not isinstance(changed, bool):
        raise ValueError(f"改变 must be a bool, got {type(changed).__name__}")
    if changed != (source != _CONFIG_VERSION):
        raise ValueError(
            f"改变 must be {source != _CONFIG_VERSION} for 源版本 {source}"
        )
    if not isinstance(summary, str):
        raise ValueError(f"摘要 must be a str, got {type(summary).__name__}")

    config = doc["配置"]
    if not isinstance(config, dict):
        raise ValueError(f"配置 must be a JSON object, got {type(config).__name__}")
    spec = _parse_config_doc(config)
    canonical = _compact_config(spec)
    # 配置自 JSON 解析而来，再编码必成功；键序/排序/值偏差令两串不一致。
    original = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    if original != canonical:
        raise ValueError("配置 must be a canonical v11 config object")
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if summary != digest:
        raise ValueError("摘要 does not match the canonical config digest")
    return source, target, changed, summary, spec


def _digest(user, password):
    return hashlib.sha256((user + "\0" + password).encode("utf-8")).digest()


class Authenticator:
    """基于 sha256 摘要的认证器，失败 max_fail 次后锁定 lock_ms 毫秒。

    retry_base_ms/retry_cap_ms 配置按用户指数退避：未达最大失败数的错口令把
    下次可试时刻设为 now_ms + min(retry_base_ms*2**(failed-1), retry_cap_ms)；
    二者同时为 0 表示关闭退避（仍返回 denied），同时为正才启用。
    """

    def __init__(self, max_fail, lock_ms, retry_base_ms=0, retry_cap_ms=0):
        self._max_fail = _check_int("max_fail", max_fail, 1)
        self._lock_ms = _check_int("lock_ms", lock_ms, 0)
        self._retry_base_ms = _check_int(
            "retry_base_ms", retry_base_ms, 0
        )
        self._retry_cap_ms = _check_int("retry_cap_ms", retry_cap_ms, 0)
        self._validate_retry_policy(
            self._retry_base_ms, self._retry_cap_ms
        )
        # user -> [digest, failed, until, retry_at]；until 为 None 表示未锁定，
        # 不能用 0 作哨兵，否则零时锁（lock_ms=0 于 now_ms=0）到期后
        # failed 永不清零。retry_at 为下次可试时刻，0 表示无退避：窗口判定
        # 为 now_ms < retry_at，now_ms >= 0，0 永不阻挡，同刻（now_ms==0）
        # 即可重试，故 0 可直接作哨兵。
        self._users = {}

    @staticmethod
    def _validate_retry_policy(retry_base_ms, retry_cap_ms):
        """两项重试须同时为 0 或同时为正，且上限不小于基数；违者 ValueError。"""
        if (retry_base_ms == 0) != (retry_cap_ms == 0):
            raise ValueError(
                "retry_base_ms and retry_cap_ms must be both 0 or both positive"
            )
        if retry_cap_ms < retry_base_ms:
            raise ValueError(
                "retry_cap_ms must be >= retry_base_ms, got "
                f"{retry_cap_ms} < {retry_base_ms}"
            )

    def __contains__(self, user):
        """用户是否已注册（供配置引用校验）。"""
        return user in self._users

    def policy(self):
        """当前认证策略 (max_fail, lock_ms, retry_base_ms, retry_cap_ms)，供
        配置导出/回滚点快照。"""
        return (
            self._max_fail,
            self._lock_ms,
            self._retry_base_ms,
            self._retry_cap_ms,
        )

    def set_policy(self, max_fail, lock_ms, retry_base_ms=0, retry_cap_ms=0):
        """原子替换认证策略；用户凭据、失败计数、锁定与下次可试时刻全保留。

        策略切换不重算已有失败数、锁定截止与下次可试时刻，新值仅作用于后续
        认证。
        """
        self._max_fail = max_fail
        self._lock_ms = lock_ms
        self._retry_base_ms = retry_base_ms
        self._retry_cap_ms = retry_cap_ms

    def add(self, user, password):
        """注册新用户，返回 (user, "created", 0)。"""
        _check_credential("user", user)
        _check_credential("password", password)
        if user in self._users:
            raise KeyError(f"duplicate user: {user!r}")
        if len(self._users) >= _MAX_USERS:
            raise OverflowError(f"user limit {_MAX_USERS} reached")
        self._users[user] = [_digest(user, password), 0, None, 0]
        return (user, "created", 0)

    def authenticate(self, user, password, now_ms):
        """验证凭据，返回 (user, status, until)，status ∈ ok/denied/locked/backoff。

        非 ok 的第三值：denied 为 0；locked 为锁定截止；backoff 为下次可试
        时刻。锁定中（now_ms < until）不验密、不改态，返回 locked 与锁定
        截止；锁到期（含同刻）先清零 failed/until/retry_at 再验证。退避窗口
        内（now_ms < retry_at）不验密、不增失败数，直接返回 backoff 与原
        时刻；等于该时刻可重试。允许时刻的正确口令清零 failed/until/retry_at
        返回 ok；错口令先增 failed，达 max_fail 即按现有规则锁定、清下次可试
        时刻并返回 locked 与锁定截止，未达 max_fail 且退避启用时把下次可试
        时刻设为 now_ms+min(base*2**(failed-1), cap) 并返回 backoff，退避
        关闭仍返回 denied 与 0。
        """
        _check_credential("user", user)
        _check_credential("password", password)
        _check_int("now_ms", now_ms, 0)
        record = self._users.get(user)
        if record is None:
            raise KeyError(f"unknown user: {user!r}")
        digest, failed, until, retry_at = record

        if until is not None:
            if now_ms < until:
                # 锁定中：不验密、不改状态。
                return (user, "locked", until)
            # 锁已到期（含同刻）：先清零 failed/until/retry_at 再验证。
            failed = 0
            until = None
            retry_at = 0
            record[1] = 0
            record[2] = None
            record[3] = 0

        if now_ms < retry_at:
            # 退避窗口内：不验密、不增失败数，回传原下次可试时刻。
            return (user, "backoff", retry_at)

        if hmac.compare_digest(digest, _digest(user, password)):
            record[1] = 0
            record[2] = None
            record[3] = 0
            return (user, "ok", 0)

        failed += 1
        record[1] = failed
        if failed >= self._max_fail:
            record[2] = now_ms + self._lock_ms
            # 锁定即清除下次可试时刻。
            record[3] = 0
            return (user, "locked", record[2])
        if self._retry_base_ms:
            # 指数退避：base*2**(failed-1)，以 cap 截顶；k 已达 cap 位数上界
            # 时直接取 cap，避免大整数运算（保持 O(1)）。
            exponent = failed - 1
            if exponent >= self._retry_cap_ms.bit_length():
                delay = self._retry_cap_ms
            else:
                delay = min(
                    self._retry_base_ms << exponent, self._retry_cap_ms
                )
            record[3] = now_ms + delay
            return (user, "backoff", record[3])
        return (user, "denied", 0)


def _strict_equal(left, right):
    """类型严格的递归相等比较（bool 不等于 int，tuple 不冒充 list）。"""
    if type(left) is not type(right):
        return False
    if isinstance(left, tuple):
        return len(left) == len(right) and all(
            _strict_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _replay_exception(exc_class, exc_args):
    """按缓存的类与 args 重建异常，不调用其构造器。

    配置非法可能抛 json.JSONDecodeError（ValueError 子类），其构造签名与
    args 不同，直接 cls(*args) 会再抛 TypeError；经 __new__ 建实例并回填
    args 可原样重放任意异常类型。
    """
    exc = exc_class.__new__(exc_class)
    exc.args = exc_args
    return exc


# 会话状态；初始/认证中仅为建立过程中的瞬态，落库状态为在线/挂起/下线。
_STATE_ONLINE = "在线"
_STATE_SUSPENDED = "挂起"
_STATE_OFFLINE = "下线"

_OP_ESTABLISH = "建立"
_OP_RENEW = "续租"
_OP_OFFLINE = "下线"
_OP_MIGRATE = "迁移"
_OP_TAKEOVER = "接管"
_OP_SUSPEND = "挂起"
_OP_RESUME = "恢复"

_DEFAULT_POOL_ID = "default"

# capacity 操作；申请/取消结果与推进产生的超时/晋升。
_OP_APPLY = "申请"
_OP_CANCEL = "取消"
_OP_ADVANCE = "推进"
_CAP_ONLINE = "在线"
_CAP_QUEUED = "排队"
_CAP_CANCELLED = "取消"
_CAP_TIMEOUT = "超时"
_CAP_PROMOTED = "晋升"
_CAP_QUEUE_FULL = "队满"
_CAP_EVICTED = "淘汰"
_CAP_AUTH_FAILED = "认证失败"
_CAP_STATE_FAILED = "状态失败"
_CAP_UNKNOWN = "未知"
# 检查点事件允许的全部结果。
_CAP_VERDICTS = (
    _CAP_ONLINE,
    _CAP_QUEUED,
    _CAP_CANCELLED,
    _CAP_TIMEOUT,
    _CAP_PROMOTED,
    _CAP_QUEUE_FULL,
    _CAP_EVICTED,
    _CAP_AUTH_FAILED,
    _CAP_STATE_FAILED,
    _CAP_UNKNOWN,
)
# 仅排队相关事件携带正入队序，其余事件入队序恒为 0。淘汰事件携带被删旧项
# 的原入队序（该序随即终结）。
_CAP_VERDICTS_WITH_ORDER = frozenset(
    (_CAP_QUEUED, _CAP_CANCELLED, _CAP_TIMEOUT, _CAP_PROMOTED, _CAP_EVICTED)
)
_MAX_QUEUE = 1024
_MAX_QUEUE_LIMIT = 10000
# v9 容量队满策略：拒绝沿用 ResourceError 与“队满”事件；替换按有效优先级
# 原子淘汰最低值旧项（并列取入队序最大）。
_QUEUE_POLICY_REJECT = "拒绝"
_QUEUE_POLICY_REPLACE = "替换"
_QUEUE_POLICIES = (_QUEUE_POLICY_REJECT, _QUEUE_POLICY_REPLACE)
# QoS 模板并发会话上限：0..10000，0 表示不限。
_MAX_TEMPLATE_SESSIONS = 10000
# QoS 模板排队优先级：非 bool int 0..100，作为推进老化提升的基础值。
_MAX_QUEUE_PRIORITY = 100
# 有效优先级上界：min(1000, 基础 + 等待秒数)。
_MAX_EFFECTIVE_PRIORITY = 1000
_CONFIG_VERSION = 11
# v11 新增顶层键“模板地址池”：按模板标识升序的二元数组列表
# [[模板标识, [池标识...]], ...]，每项池序列为 1..32 个互异且已定义的池标识，
# 同一模板至多出现一次；未列出的模板沿用 default 池自动取址。
_TEMPLATE_POOLS_KEY = "模板地址池"
_MAX_TEMPLATE_POOL_CHOICES = 32
# 每 Sessions 保留的最近配置修订条数（初始窗口含构造态修订 0）；超限淘汰
# 最旧项，当前修订永不淘汰。
_CONFIG_HISTORY_LIMIT = 256
# 防篡改配置历史的操作名：构造即记录修订 0；四类提交首次成功依次追加
# “加载/回滚/CAS/回退”，失败与同参重放不追加。记录随修订快照同寿命：
# 快照淘汰时同步淘汰记录，链上余记录的前哈希不改。
_CONFIG_HISTORY_OP_INIT = "构造"
_CONFIG_HISTORY_OP_LOAD = "加载"
_CONFIG_HISTORY_OP_ROLLBACK = "回滚"
_CONFIG_HISTORY_OP_CAS = "CAS"
_CONFIG_HISTORY_OP_REVERT = "回退"

# fault 操作与后端状态。
_OP_INJECT = "注入"
_OP_RECOVER = "恢复"
_BACKEND_FAULT = "故障"
_BACKEND_NORMAL = "正常"
# backend_restore 入防篡改审计链的操作名。
_BACKEND_RESTORE_OP = "后端恢复"
# fault_restore 入防篡改审计链的操作名。
_FAULT_RESTORE_OP = "故障恢复"

# fault_plan 批量故障演练计划：模式仅预检/执行，域仅后端/池/超时；
# 入防篡改审计链的操作名“故障计划”。
_FAULT_PLAN_MODE_PRECHECK = "预检"
_FAULT_PLAN_MODE_EXECUTE = "执行"
_FAULT_PLAN_DOMAIN_BACKEND = "后端"
_FAULT_PLAN_DOMAIN_POOL = "池"
_FAULT_PLAN_DOMAIN_TIMEOUT = "超时"
_FAULT_PLAN_OP = "故障计划"
_FAULT_PLAN_MAX_STEPS = 1000

# capacity_rebalance 容量热均衡：模式仅预检/执行；变更种类仅优先级/绑定/
# 容量，单次变更项 1..1000 个且 (种类, 目标) 两两互异。
_CAP_REBALANCE_MODE_PRECHECK = "预检"
_CAP_REBALANCE_MODE_EXECUTE = "执行"
_CAP_REBALANCE_KIND_PRIORITY = "优先级"
_CAP_REBALANCE_KIND_BINDING = "绑定"
_CAP_REBALANCE_KIND_CAPACITY = "容量"
_CAP_REBALANCE_MAX_CHANGES = 1000

# fault_matrix 多场景批量评估：scenarios 项数上界。
_FAULT_MATRIX_MAX_SCENARIOS = 100

# pool_fault 池演练状态：仅耗尽/正常。
_POOL_EXHAUSTED = "耗尽"
_POOL_NORMAL = "正常"
# pool_fault 入防篡改审计链的操作名。
_POOL_OP_INJECT = "池注入"
_POOL_OP_RECOVER = "池恢复"

# timeout_fault 全局超时演练状态：仅等待/正常。
_TIMEOUT_WAITING = "等待"
_TIMEOUT_NORMAL = "正常"
# timeout_fault 入防篡改审计链的操作名。
_TIMEOUT_OP_INJECT = "超时注入"
_TIMEOUT_OP_RECOVER = "超时恢复"

# timeout_storm 超时风暴多批清扫：每批固定取前 100 项，批数限 1..1000，
# 类别码会话 0、排队 1（"会话"码点本就小于"排队"）。
_STORM_BATCH_LIMIT = 100
_TIMEOUT_STORM_OP = "超时风暴"

# config_change 配置事务操作名与入防篡改审计链的操作名。
_CONFIG_OP_LOAD = "加载"
_CONFIG_OP_ROLLBACK = "回滚"
_CONFIG_OP_UPGRADE = "升级"
_CONFIG_CHAIN_LOAD = "配置加载"
_CONFIG_CHAIN_ROLLBACK = "配置回滚"
_CONFIG_CHAIN_UPGRADE = "配置升级"
# config_change 操作名 -> 审计链操作名（重放路径按缓存 op 查表）。
_CONFIG_CHAIN_OP = {
    _CONFIG_OP_LOAD: _CONFIG_CHAIN_LOAD,
    _CONFIG_OP_ROLLBACK: _CONFIG_CHAIN_ROLLBACK,
    _CONFIG_OP_UPGRADE: _CONFIG_CHAIN_UPGRADE,
}

# batch_offline 批量下线：单批 sid 数上界。
_BATCH_MAX_SIDS = 1000
# 顶层结果仅 提交/部分/回滚；项结果沿用 "下线"（_STATE_OFFLINE）、
# "未知"（_CAP_UNKNOWN），回滚为 "回滚"。
_BATCH_COMMIT = "提交"
_BATCH_PARTIAL = "部分"
_BATCH_ROLLBACK = "回滚"
# batch_online 批量建立：成功项结果“上线”，区别于会话状态“在线”。
_BATCH_ITEM_ONLINE = "上线"
# batch_migrate 批量迁移：成功项结果“迁移”（迁移后会话仍“在线”）。
_BATCH_ITEM_MIGRATE = "迁移"

# keepalive 批量保活：项结果“保活”（区别于会话状态“在线”）；非在线现存项
# （挂起/下线墓碑）记“状态”，沿用 _CAP_UNKNOWN 记未知 sid，回滚沿用
# _BATCH_ROLLBACK。
_KEEPALIVE_OK = "保活"
_KEEPALIVE_STATE = "状态"

# batch_credential_change 批量凭据轮换：顶层结果仅 成功/部分成功/失败/回滚；
# 成功项结果“轮换”，失败项取实际异常类名，原子回滚时可成功项记“回滚”。
_BATCH_CRED_COMMIT = "成功"
_BATCH_CRED_PARTIAL = "部分成功"
_BATCH_CRED_FAILED = "失败"
_BATCH_ITEM_ROTATE = "轮换"

# 五类批量操作（上线/下线/迁移/保活/凭据轮换）入独立防篡改审计链
# batch_audit 的操作名。
_BATCH_AUDIT_ONLINE = "批量上线"
_BATCH_AUDIT_OFFLINE = "批量下线"
_BATCH_AUDIT_MIGRATE = "批量迁移"
_BATCH_AUDIT_KEEPALIVE = "批量保活"
_BATCH_AUDIT_CREDENTIAL = "批量凭据轮换"
# 批量审计首次事件结果取项目结果（提交/部分/回滚），重放事件结果恒为“重放”。
_BATCH_AUDIT_REPLAY = "重放"

# 合规全局链：来源仅审计、批量、容量；事件六字段键序固定为
# 全局序号/来源/来源序号/载荷/前哈希/哈希，哈希覆盖前五字段，首项前哈希
# 为 64 个 0。载荷为对应公开源事件（audit 九键、batch_audit 十键、
# capacity_events 五键）按既有键序生成的紧凑 JSON 字符串。
_COMPLIANCE_SOURCE_AUDIT = "审计"
_COMPLIANCE_SOURCE_BATCH = "批量"
_COMPLIANCE_SOURCE_CAPACITY = "容量"
_COMPLIANCE_SOURCES = (
    _COMPLIANCE_SOURCE_AUDIT,
    _COMPLIANCE_SOURCE_BATCH,
    _COMPLIANCE_SOURCE_CAPACITY,
)
_COMPLIANCE_EVENT_KEYS = (
    "全局序号",
    "来源",
    "来源序号",
    "载荷",
    "前哈希",
    "哈希",
)
# 各来源公开源事件的既有键序。
_COMPLIANCE_AUDIT_KEYS = (
    "序号",
    "时刻",
    "键",
    "操作",
    "会话",
    "结果",
    "原序号",
    "前哈希",
    "哈希",
)
_COMPLIANCE_BATCH_KEYS = (
    "序号",
    "时刻",
    "键",
    "操作",
    "原子",
    "会话",
    "结果",
    "原序号",
    "前哈希",
    "哈希",
)
_COMPLIANCE_CAPACITY_KEYS = (
    "序号",
    "时刻",
    "会话",
    "结果",
    "入队序",
)

# credential_change 凭据轮换：入防篡改审计链的操作名与返回 JSON 的结果串。
_CREDENTIAL_OP = "凭据轮换"
_CREDENTIAL_ROTATED = "已轮换"

# user_admin 用户管理：op 仅停用/启用，返回状态仅停用/启用。
_ADMIN_OP_DISABLE = "停用"
_ADMIN_OP_ENABLE = "启用"
_ADMIN_DISABLED = "停用"
_ADMIN_ENABLED = "启用"
# user_admin 入防篡改审计链的操作名。
_ADMIN_CHAIN_DISABLE = "用户停用"
_ADMIN_CHAIN_ENABLE = "用户启用"

# 会话计费：事件类型仅开始/中间/停止；停止原因依次为下线/批量下线/停用/
# 配额/接管，开始与中间原因恒为空串。链首前哈希为 64 个 0，哈希按前哈希
# 与本条前九项（序号/类型/时刻/会话/用户/地址池/地址/累计字节/原因）的
# 紧凑 JSON（前哈希置末）UTF-8 字节计算 SHA-256。
_ACCOUNT_START = "开始"
_ACCOUNT_INTERIM = "中间"
_ACCOUNT_STOP = "停止"
_ACCOUNT_REASON_OFFLINE = "下线"
_ACCOUNT_REASON_BATCH = "批量下线"
_ACCOUNT_REASON_DISABLE = "停用"
_ACCOUNT_REASON_QUOTA = "配额"
_ACCOUNT_REASON_TAKEOVER = "接管"
_ACCOUNT_TYPES = (_ACCOUNT_START, _ACCOUNT_INTERIM, _ACCOUNT_STOP)
_ACCOUNT_STOP_REASONS = (
    _ACCOUNT_REASON_OFFLINE,
    _ACCOUNT_REASON_BATCH,
    _ACCOUNT_REASON_DISABLE,
    _ACCOUNT_REASON_QUOTA,
    _ACCOUNT_REASON_TAKEOVER,
)
# service 跨域检查点版本：1 无计费域，2 在统计后追加“计费”域。
_SERVICE_VERSION = 2


class _Pool:
    """单个地址池：保留/静态集、动态空闲最小堆与本池租用地址表。

    租用地址表按池隔离，故不同池的地址（int）允许重叠。
    """

    __slots__ = (
        "capacity",
        "cidr",
        "reserved",
        "static",
        "static_ips",
        "free",
        "leases",
    )

    def __init__(self, parsed):
        network, usable, reserved, static, static_ips = parsed
        self.capacity = len(usable)
        self.cidr = str(network)
        self.reserved = reserved
        self.static = static
        self.static_ips = static_ips
        # 动态地址最小堆：含全部未租用的非保留非静态地址（heapify 为 O(A)）。
        self.free = list(usable - reserved - static_ips)
        heapq.heapify(self.free)
        # 本池已租用地址 int -> sid（含静态与动态）。
        self.leases = {}


class Sessions:
    """会话管理：建立需先认证再查限额，续租限持址在线会话，下线按 sid。

    构造期传入地址池时建为 default 池；未传池则从零池起步，add_pool 可随时
    追加命名池（含 default），重名 ValueError。建立按模板地址池优先序列分配
    地址（未配置序列者仅 default 池），候选序列无现存池抛 StateError；无池时
    pool_stats 抛 StateError。各池地址空间
    相互独立、允许重叠，占用按池隔离。建立在每个候选池为静态用户取其专属地址、
    否则取最小未租用动态地址，候选池有效耗尽、无动态址或静态址被占用时切到
    下一后备池；租期到期、挂起或下线均释放地址，静态地址不回动态池。迁移
    在两池间原子换址。接管先老化：旧会话持址则新会话继承其池/地址/租约，
    无址则自 default 池新分配（不应用后备序列），租期 = now_ms+lease_ms；认证或资源失败仅保留
    老化结果。按 key 永久缓存重放。takeover_audit 记录首次成功/认证失败/资源
    失败及同参重放，查询不老化。do 验参后的首次结果（成功或
    AuthError/ResourceError/StateError/KeyError）及同参重放另记入防篡改
    审计链：逐事件 sha256 链接前项哈希，audit 查询、verify_audit 校验，
    参数错与异参 key 重放不入链。export_config 导出 v11 配置 JSON（顶层键序
    版本/会话/地址池/模板/用户模板/容量/认证/模板地址池；会话与地址池沿用 v2，模板按
    标识升序、项键序标识/限速/突发/配额/周期毫秒/会话上限/排队优先级/超限
    （周期毫秒为非 bool 非负 int、0 不重置，会话上限 0 不限并发占用，占用为
    绑定模板用户的在线加挂起会话数，排队优先级为非 bool int 0..100）、用户
    模板按用户升序、容量为队列上限/最大等待毫秒/队满策略（策略 str 仅
    “拒绝/替换”）、认证为最大失败/锁定毫秒/重试基数毫秒/重试上限毫秒，重试
    两项同时为 0 或同时为正、上限不小于基数；末位“模板地址池”为按模板标识
    升序的 [模板标识, [池标识...]] 二元数组列表，每项池序列为 1..32 个互异
    且已定义的池标识，同一模板至多一次，空列表表示所有自动取址沿用 default
    池）；
    upgrade_config(text,
    target=11) 只读地把 v1..v11 配置升级为 v11 升级包 JSON（LF 尾紧凑；顶层
    序/型源版本:int/目标版本:int/改变:bool/摘要:str/配置:object，改变=源版本
    !=11，配置同 export_config 的 v11，摘要为配置紧凑编码 UTF-8 字节的
    sha256 小写值），text 非 str 或 target 非非 bool int 抛 TypeError，
    target 只许 11，源版本限 1..11，解析、重键、键缺失/未知、结构/类型/数量/
    排序/值/引用/
    版本非法抛 ValueError，
    迁移沿 load_config 既有规则（v1 单池改 default、v1/v2 补空模板与用户模板、
    v1-v3 补容量 1024/0/拒绝、v1-v4 以认证器当前四值补认证、v1-v5 模板会话上限
    补 0、v1-v6 模板周期毫秒补 0、v1-v7 模板排队优先级补 0、v1-v8 容量队满
    策略补“拒绝”、v1-v9 重试两项补 0、v1-v10 模板地址池补空、v11 只规范化），
    升级不改任何实例状态；
    load_config
    直载 v1..v11 配置或经严格复核（键序、字段、配置规范形态、摘要）的升级包，
    全验后原子替换并保存旧配置为唯一回滚点，升级包复核不符抛 ValueError，
    引用错（用户模板引用未知用户或未知模板标识）抛 ValueError，上限、模板
    占用、租约或队长承载不满足抛 ResourceError，失败不改配置、回滚点、会话、
    租约与运行态，
    提交替换认证策略但保留认证记录（凭据、失败计数、锁定与下次可试时刻，策略
    切换不重算）；
    rollback_config 经同样校验恢复旧配置（含认证策略）并清除回滚点，无回滚点
    抛 StateError。
    配置修订历史保留最近 256 个修订：构造态为修订 0，load_config/
    rollback_config/config_cas 及历史回退首次成功后生成并保存提交态新修订，
    修订沿既有规则递增，失败、只读升级与同参重放不保存，超限淘汰最旧项且
    不淘汰当前项。config_revision() 只读返回“修订:int、摘要:str”。
    config_cas(key, text, expected, now_ms) 比较修订并原子加载，返回
    “修订/前摘要/后摘要”，同 key 同型同参重放原字节且不再比较修订，异参
    ValueError，仅缓存成功。config_revert(key, target, expected, now_ms)
    原子回退到历史保留修订：参数须为非 bool 非负 int，先比较 expected
    （不符 StateError(expected, current) 且不查目标），target>=expected
    抛 ValueError，目标未保留抛 KeyError(target)，目标快照按 load_config
    承载规则加载（冲突 ResourceError），成功覆盖回滚点、保存新修订并返回
    “修订:int、目标:int、前摘要:str、后摘要:str”；同 key 同型同参重放
    原字节且不再比较修订，异参 ValueError，仅缓存成功，不审计。
    config_history(after=-1, limit=100) 只读返回防篡改配置历史的 LF 尾紧凑
    JSON：构造即记录修订 0（父修订、目标 -1，前哈希 64 个 0），上述四类
    提交首次成功依次追加“加载/回滚/CAS/回退”（后项父修订取前一修订，回退
    目标取 target、余 -1，摘要同 config_revision，哈希为前六键修订/父修订/
    操作/目标/摘要/前哈希基线紧凑 JSON 的 UTF-8 字节 sha256 小写值），失败、
    只读升级与同参重放不追加；记录与修订快照同寿命，保留最近 256 项，快照
    淘汰时同步淘汰记录但留存项前哈希不缝合、不改写，当前项永不淘汰。两参须
    为非 bool int（型错 TypeError），after<-1 或 limit∉[1,1000] 抛 ValueError，
    after!=-1 且该修订未保留抛 KeyError(after)；返回修订 > after 的升序前
    limit 项，顶层为“下个修订:int、项目:list”，无项下个修订=after，查询
    O(limit) 时空。
    export/load/rollback 成功均返回 v11 配置 JSON，会话状态、期限、地址、租期与
    旧队项的等待/截止/入队序不受配置替换影响，新配置仅作用于后续操作与查询。
    自动选址（建立、批量上线、容量申请立即建立、队列推进、容量预测与热均衡
    预演共用同一规则）：绑定模板且该模板在“模板地址池”列有序列的用户按该
    1..32 个互异候选池的优先序取址，其余用户仅检查 default 池；候选池处于
    有效耗尽故障、没有动态地址，或该用户在该池的专属静态地址正被占用时，
    继续检查下一池；可取址时仍优先取该用户的静态地址，否则取数值最小的动态
    地址。配置热加载、回滚或历史回退只影响后续自动选池与尚未晋升的队项，
    现有在线或挂起会话保留原池、地址与租期；显式迁移与恢复只使用调用方指定
    的目标池，不应用后备序列。
    qos(sid) 以 O(1) 返回
    在线会话用户所绑 QoS 模板的生效值。meter(key, sid, size, now_ms) 按
    会话用户所绑模板做令牌桶加配额计量，计量态为 (用户, 模板) 共享账本
    （累计 u、上次通过时刻 t、千分字节令牌 c），同用户同模板的并发会话共享
    配额：模板周期毫秒 P>0 且 now_ms//P != t//P 时有效累计重置为 0，P=0
    不重置；令牌始终自 t 按原公式补充、跨周期不清零。通过则原子保存有效
    累计+size、now_ms 及扣后令牌，超限取模板动作（拒绝不改账，下线原子
    清场且不改账），异常与重放不改账；重放缓存与 do 分域；下线、新建、接管
    不清账，配置热加载或回滚后同标识原样保留 u/t/c 并以新 P 判窗，改绑用
    独立账本，加载或回滚失败不改账。quota_stats(user, now_ms) 以 O(1)
    只读返回用户所绑模板的配额快照（不老化、不建账；无账本按有效累计 0、
    满桶；累计为按新 P 折算的有效累计、剩余为 max(0, 配额-有效累计)、令牌
    为补充后只读值；now_ms<t 抛 StateError）。meter 新 key 首次
    结果为通过/拒绝/下线时按当时会话用户与当次模板标识各记一次统计
    （通过另计字节），配置热加载或回滚不迁移历史计数；meter_stats
    (now_ms, group) 老化后按用户或查询时生效绑定（未绑定归空串）汇总
    历史计数与当前在线数。capacity(key, op, sid, args, now_ms) 在既有
    认证、老化、上限与自动选池（模板地址池优先序列，未配置序列仅 default
    池）取址规则之上提供容量背压等待队列（队列
    上限与最大等待由配置给定，默认 1024 项、不限等待）：申请等待超过非零
    最大等待在认证/老化之前即抛 ValueError（不入队、不记事件），可立即
    服务则原子建立、否则入队（队长达上限 ResourceError），取消仅
    撤销排队项，推进先老化再清超时（截止=申请时刻+等待，含同刻），存活项
    有效优先级 = min(1000, 基础+max(0,now_ms-申请时刻)//1000)（基础取推进
    时刻用户绑定模板的排队优先级，未绑定为 0），按有效值降序、入队序升序
    晋升容量允许且可取址者；模板并发会话上限（占用为绑定
    模板用户的在线加挂起会话数）贯通建连背压：do 建立超限抛 ResourceError，
    batch_online 超限项记 ResourceError，capacity 申请超限排队、推进中受限
    项留队并继续后项（前项成功占用影响后项），接管/迁移/挂起/恢复不净增占用
    故不受限；
    老化挂起即释址，挂起会话不
    持址、不计在线但仍占全局与单用户上限；按 key 重放缓存与 do/meter
    分域；既有 do 建立仍立即拒绝、绝不入队。capacity_events(after,
    limit) 查询事件（游标与参数规则同 audit，查询不老化）：仅首个验参
    成功的新 key 记事件，结果限在线/排队/取消/超时/晋升/淘汰/队满/认证失败/
    状态失败/未知，推进先记超时（按入队序）后记晋升（按尝试序），替换成功先
    记旧项“淘汰”（原入队序）后记新项“排队”（新入队序），重放不记。capacity_stats
    (now_ms) 先验参再老化，输出全局在线/挂起/排队/可用/水位/最早截止
    与按标识升序的用户、池明细。clog(now_ms) 先验参再老化，输出检查点基线
    JSON：全量事件哈希链（事件键序序号/时刻/会话/结果/入队序/前哈希/
    哈希，取消保留原入队序、事件时刻可回拨）、按会话升序的在线/挂起/
    下线会话（下线墓碑清零）、按入队序的排队项与覆盖前四顶层键的状态
    哈希。cverify() 校验事件链
    连续序号与哈希衔接，空链为 True。creplay(text) 校验并恢复所列
    会话（含下线墓碑，墓碑不计容量、不建租约）、租约、队列与事件账本，
    验链、验状态哈希与承载力后原子提交，同状态哈希重放为空操作并保留
    墓碑，返回检查点时刻 capacity_stats。fault(key, op, ms, now_ms)
    注入（op=注入，ms 为非 bool 正 int）或恢复（op=恢复，ms=None）后端
    故障：注入置故障截至为 now_ms+ms，恢复清零，二者均清空全部用户退避；
    返回键序“状态/时刻/截至”的基线 LF 尾 JSON（注入为 故障/now_ms/
    now_ms+ms，恢复为 正常/now_ms/0），key 首果（含验参异常）永久缓存、
    同参重放、异参 ValueError，缓存与 do/meter/capacity 分域。do 建立/
    迁移/接管与 capacity 申请验参后、老化前查后端：建立/申请取 args
    用户，迁移/接管由 sid/old 只读定位（未知 KeyError 且不退避，仍缓存
    并入链），定位后 BackendError 先于状态、目标池与新 sid 错误，健康
    才老化并循旧序。故障中每用户 now_ms>=retry_at 则 n 加一并令
    retry_at=now_ms+min(100*2**(n-1), 1600)，抛 BackendError(retry_at)，
    否则 n 不变抛 BackendError(retry_at)；截至与 retry_at 均到才认证并
    清该用户退避。BackendError 按 key 入各自缓存；失败仅改退避与缓存，
    认证器、会话、租约与队列不变；BackendError 与 fault 均不审计。检查
    额外时空 O(1)。fault_stats(now_ms) 返回后端故障统计 JSON（时刻/
    故障/截至/退避用户/失败）：失败为故障、退避两项累计，仅新 key 首次
    后端检查抛 BackendError 时计数（now_ms<retry_at 归退避，否则归
    故障），注入/恢复/配置变更不清零；查询不认证、不老化、不改退避、
    不审计、不记事件、不动缓存，O(U) 时间、O(1) 辅助空间。
    backend_checkpoint(now_ms) 只读输出后端故障态检查点基线 JSON（LF 尾），
    不清到期退避：顶层依次版本:int/时刻:int/截至:int/退避:list/失败:object/
    摘要:str，版本 1；退避按用户 Unicode 升序，项键序用户:str/次数:int/
    下次:int，次数 >0、下次 >=0；失败键序故障:int/退避:int，值 >=0；摘要
    为前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写值；O(U log U) 时间、
    O(U) 空间。backend_restore(key, text) 校验并原子替换截至、退避与失败
    计数，返回规范包：key 沿凭据约束，text 非 str 抛 TypeError；解析、重键、
    键集/键序、结构、类型、范围、退避排序/重复、版本或摘要错抛 ValueError，
    退避引用未注册用户抛 ResourceError；全验后原子替换，失败不改实例、不
    老化、不审计。仅缓存首次成功，同 key 同型同 text 重放原字节且不重验，
    异参 ValueError，失败不占 key；首次成功与成功重放写现有防篡改审计链：
    操作“后端恢复”、会话空串、结果“成功/重放”、重放原序号指认首次，审计
    时刻取检查点时刻。
    pool_fault(key, op, pool, ms, now_ms) 对指定地址池做可恢复耗尽演练，
    不改真实租约及配置：key/pool 沿用凭据约束，op 仅注入/恢复，注入 ms
    为非 bool 正 int、置截至 now_ms+ms，恢复 ms 须为 None 并清零，
    now_ms 为非 bool 非负 int；类型、值、未知池错依次抛 TypeError、
    ValueError、KeyError，校验失败不改池状态。后续同池调用可覆盖。
    now_ms < 截至时该池无可分配地址、到刻（含同刻）自动正常：既有租约、
    续租、下线及从该池迁出不受影响，建立、迁入、无址接管在既有认证与
    老化后抛 ResourceError，capacity 申请排队、推进跳过，均不半分配，
    真实耗尽行为不变。成功 JSON 键序“池/状态/时刻/截至”，状态仅
    耗尽/正常，恢复截至 0，序列化沿基线。验 key 后以独立域永久缓存
    余参与首次成败（含验参异常与未知池），同参重放不改状态、异参
    ValueError；首次成功及成功重放写现有防篡改审计链，操作池注入/池
    恢复、会话记 pool，结果成功/重放、原序号沿用，异常不记。配置加载/
    回滚成功后保留同名池故障、清除已删池，失败不改故障。故障判定及
    变更 O(1) 时空。
    timeout_fault(key, op, at_ms, now_ms) 注入或恢复全局超时演练待触发
    值，不改真实配置：key 沿用凭据约束，op 仅注入/恢复，now_ms 为非 bool
    非负 int；注入 at_ms 为非 bool int 且 >= now_ms，设置或覆盖触发时刻，
    恢复 at_ms 须 None 并取消；类型/值错分别抛 TypeError/ValueError。
    成功 JSON 键序“状态/时刻/触发”，注入为 等待/now_ms/at_ms，恢复为
    正常/now_ms/0，序列化沿基线。验 key 后以独立域永久缓存余参与首次
    成败（含验参异常），严格同参重放不改态、异参 ValueError；首次成功
    及成功重放写现有防篡改审计链，操作超时注入/超时恢复、会话空串，
    结果成功/重放、原序号沿用，异常不记。待触发时首次
    capacity(key,"推进","",None,now_ms) 满足 now_ms>=触发值，须在普通
    老化和晋升前原子挂起全部在线会话、清期限并释放租约，按入队序将全部
    队项记超时后删除，再清除触发；本批不得晋升或半释放，推进输出在线 0、
    排队 0、变更为各超时项入队序。配置加载/回滚成功保留待触发值，失败
    不改。判定与变更 O(1) 时空，触发 O(S log A+Q) 时间、O(Q) 空间。
    user_stats(user, now_ms) 返回按用户只读快照 JSON：按 now_ms 取视图
    （不老化），在线期限 <= now_ms 计挂起，租期或期限 <= now_ms 不计
    占用，队项截止 <= now_ms 不计排队，墓碑计下线；失败为该用户
    do/meter/capacity 新 key 首次且已定位用户的认证/资源/状态/后端
    四类异常累计（参数错、KeyError、fault、重放与异参 key 不计），
    查询不认证、不老化、不改租约、退避、审计、事件、缓存与计数，
    O(S+Q) 时间、O(1) 辅助空间。
    runtime_stats(now_ms, pool=None) 返回全局只读快照 JSON：pool=None
    列全部池（无池列空），给定凭据约束的池标识仅列该池，未知池 KeyError；
    按 now_ms 取视图（不老化）：在线期限到计挂起，租期或期限到不计占用，
    截止到的队项不计排队。建立统计仅计已注册用户验参成功的新 key 首次
    do 建立：总数 +1，成功则成功 +1；参数错、未知用户与重放不计；成功率
    为万分比 floor(成功*10000/总数)（总数为 0 取 0），配置变更不清计数。
    失败为全部用户的 user_stats 口径聚合。顶层键序时刻/会话/建立/失败/池，
    会话键序在线/挂起/下线/排队，建立键序总数/成功/成功率万分比；失败恒按
    认证/资源/状态/后端；池按标识 Unicode 升序，项为标识/总量/占用/可用/
    保留，总量为可用地址数、占用为有效租约数、可用=总量-保留-占用。建立
    更新 O(1)，查询 O(S+Q+U+P log P)、无池时为 O(P) 的空列表。
    sessions(now_ms, after="", limit=100) 只读游标列出会话与未到期队项，
    查询不老化、不认证、不回收租约、不写审计/事件/缓存、不改计数：now_ms
    为非 bool 非负 int；after 为 str，空串从头、非空沿用凭据约束；limit 为
    非 bool int 且 1..1000，型/值错分别 TypeError/ValueError。按 now_ms 取
    视图：在线期限 <= now_ms 视为挂起；期限或租期 <= now_ms 则池址空、租期
    0；截止 <= now_ms 的队项不列。会话与队项按标识 Unicode 码点升序，取
    标识 > after 的前 limit 项；队项状态“排队”、期限取截止、入队序取原值、
    池址空、租期 0；普通会话入队序 0，挂起/下线池址空、期限租期 0。LF 尾
    紧凑 JSON 顶层时刻:int/下个:str/剩余:int/项目:list，有项下个取末项会话、
    否则为 after，剩余为游标后未返回数；项键序会话/用户/状态/期限/池/地址/
    租期/入队序；同态同参同字节，O((S+Q) log(S+Q))/O(S+Q)。
    batch_offline(key, sids, now_ms, atomic=False) 批量下线：key/sid 沿用
    凭据约束，sids 为 1..1000 个互异 sid 的 tuple，now_ms 为非 bool 非负
    int，atomic 为 bool；类型错 TypeError，取值/长度/重复错 ValueError。
    验 key 后以独立域永久缓存首果（含参数异常），同型同参重放不老化、不改态，
    异参 ValueError。首次合法先老化；非原子逐项处理，现存项（在线/挂起/
    下线墓碑）置下线、期限 0、释放地址租约并记“下线”，未知记“未知”不影响
    后项；原子先查老化后快照，有未知则未知记“未知”、其余记“回滚”且不执行
    （保留老化），全存在才提交。未知不抛异常；不写既有 audit 链或容量事件，
    合法首调与同参重放逐项写独立的批量防篡改审计链 batch_audit（操作
    “批量下线”），参数错与异参 key 不记。返回键序
    时刻/原子/结果/项目的 LF 尾紧凑 JSON，结果仅提交/部分/回滚，项为
    会话/结果（下线/未知/回滚）。首次 O(S+B log A) 时间、O(B) 辅助空间，
    S/B/A 为会话/批项/池地址数。
    batch_online(key, items, now_ms, atomic=False) 批量建立：key 及三项
    串沿用凭据约束，items 为 1..1000 个 (sid, user, password) 三元组的
    tuple，sid 互异；now_ms 为非 bool 非负 int，atomic 为 bool；类型错
    TypeError，取值/长度/重复错 ValueError。验 key 后以独立域（与
    do/meter/capacity/fault/pool_fault/timeout_fault/batch_offline 分域）
    永久缓存首果（含参数异常），同型同参重放不老化、不改态，异参
    ValueError。首次合法先老化；逐项依次经后端（故障期按用户指数退避
    抛 BackendError，只改退避）、认证、全局与单用户容量、sid 唯一、
    default 池与静态址规则建立，业务异常（AuthError/ResourceError/
    StateError/BackendError/KeyError）不抛，项结果记其类名。非原子
    逐项提交，失败不影响后项；原子演算全部项，任一失败则批内不建
    会话/租约（已建者回滚释址），失败项记异常类名、余项记回滚；
    老化、认证计数与退避保留。不写既有 audit 链或容量事件，不计建立/失败/
    后端故障统计；合法首调与同参重放逐项写独立的批量防篡改审计链
    batch_audit（操作“批量上线”），参数错与异参 key 不记。返回键序时刻/原子/结果/项目的 LF 尾紧凑 JSON，
    结果仅提交（全上线）/部分（非原子有失败）/回滚（原子有失败），
    项目依输入顺序，项键序“会话/结果”，项结果仅上线/业务异常类名/
    回滚。首次 O(S+B log A) 时间、O(B) 辅助空间，重放 O(B)。
    keepalive(key, sids, now_ms, atomic=False) 批量保活：key/sid 沿用
    凭据约束，sids 为 1..1000 个互异 sid 的 tuple，now_ms 为非 bool 非负
    int，atomic 为 bool；类型错 TypeError，取值/长度/重复错 ValueError。
    验 key 后以独立域（与 do/meter/capacity/fault/pool_fault/timeout_fault/
    batch_offline/batch_online 分域）永久缓存首果（含参数异常），同型同参
    重放不老化、不改态，异参 ValueError。首次合法先老化：期限 <= now_ms
    的在线项挂起、清期限退租且不回滚。非原子依序将在线项空闲期限改为
    now_ms+idle_ms 并记“保活”，未知记“未知”，其余现存项（挂起/下线墓碑）
    记“状态”；原子先查老化后快照，全在线才提交，否则失败项记未知/状态、
    在线项记“回滚”且不延长期限。保活只改空闲期限，不续租、不分址、不写
    既有 audit 链、不记容量事件或统计；合法首调与同参重放逐项写独立的批量
    防篡改审计链 batch_audit（操作“批量保活”），参数错与异参 key 不记。
    返回键序时刻/原子/结果/项目的 LF 尾紧凑 JSON，
    结果仅提交（全保活）/部分（非原子有失败）/回滚（原子有失败），项目依
    输入顺序，项键序“会话/结果/期限”，项结果仅保活/未知/状态/回滚，保活项
    期限取改后新值、余项期限为 0。首次 O(S+B log A) 时间、O(B) 辅助空间，
    重放 O(B)。
    batch_migrate(key, items, now_ms, atomic=False) 批量迁移：key 及三项串
    沿用凭据约束，items 为 1..1000 个 (sid, target, password) 三元组的 tuple，
    sid 互异；now_ms 为非 bool 非负 int，atomic 为 bool；类型错 TypeError，
    取值/长度/重复错 ValueError。验 key 后以独立域永久缓存首果（含参数异常），
    同型同参重放不老化、不改态，异参 ValueError。首次合法先老化，逐项沿用 do
    迁移规则，业务异常不抛而记项结果类名；非原子逐项提交，原子在同一老化后
    演算态预演全部、任一失败恢复至老化后快照（认证计数、锁定与退避保留），不
    写既有 audit 链或容量事件；合法首调与同参重放逐项写独立的批量防篡改审计
    链 batch_audit（操作“批量迁移”），参数错与异参 key 不记。返回键序时刻/
    原子/结果/项目的 LF 尾紧凑 JSON，结果仅提交/部分/回滚，项为会话/结果
    （迁移/业务异常类名/回滚）。首次 O(S+B log A) 时间、O(B) 辅助空间，重放 O(B)。
    batch_audit(after=0, limit=100) 只读返回五类批量操作的独立防篡改审计链：
    after/limit 为非 bool int，after<0 或 limit∉1..1000 分别抛
    TypeError/ValueError；取序号>after 的前 limit 项，查询不老化不改态、
    O(limit) 时空。顶层键序下个序号/事件（空页游标为 after），事件键序序号/
    时刻/键/操作/原子/会话/结果/原序号/前哈希/哈希，原子为 bool、序号/时刻/
    原序号为 int、余为 str；首项前哈希 64 个 0、余项承前项，哈希为前九键紧凑
    JSON（ensure_ascii=False、separators=(',',':')）UTF-8 字节 sha256 小写值，
    输出加 LF。合法首调逐项结果取项目结果、原序号 0；同参重放逐项结果“重放”、
    原序号指认对应首次事件；参数错与异参 key 不记。与 audit 的 do/接管链及
    verify_audit 互不影响。
    batch_audit_restore(key, text) 将 batch_audit 分页结果原子接入批量链尾：
    key 沿用凭据约束，text 非 str 抛 TypeError；JSON、重键、编码、结构、范围
    或事件超过 1000 项错均 ValueError。非空页序号须连续、游标等于末序号，
    自第 2 项起前哈希衔接，每项哈希按前九键复算，原序号为 0 或指向同
    （键,操作,原子,会话）的更早首次项；空页游标即页锚。非空页锚为首序号减 1、
    首项前哈希，空页锚为游标；当前链尾不符（首序号≠末序号+1、首项前哈希≠
    当前末哈希，或空页游标≠末序号）抛 StateError(页锚, 当前末序号)。全验后
    原子追加十元组，失败不改链；不恢复业务态、缓存或幂等索引，接入不写链、
    不老化。独立缓存仅成功占位，同型同 text 重放原字节且不追加，异参
    ValueError。返回 LF 尾紧凑 JSON：追加:int/末序号:int/末哈希:str/摘要:str，
    摘要为前三键同法编码 UTF-8 字节的 sha256 小写值，空页追加 0。O(事件数)
    时空。
    runtime_checkpoint(now_ms) 先验参再老化一次，输出运行态检查点基线
    JSON（LF 尾）：顶层键序版本/时刻/容量/配额/摘要，版本 1，容量沿用
    同刻 clog 对象契约（时刻等于顶层）、配额沿用同刻 quota_checkpoint
    对象契约，摘要为前四键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写
    值；覆盖会话/租约、容量队列/事件与共享 QoS 账本。
    runtime_restore(key, text) 校验并原子恢复上述运行态：key 沿用凭据、
    text 须 str（类型错 TypeError）；JSON/重键/键序/结构/类型/值/排序、
    版本/摘要/时刻错均 ValueError，用户/模板/池址/令牌/容量或引用不承载
    ResourceError，目标有不同摘要的覆盖状态 StateError；全验后原子替换
    并返回规范包，同摘要空操作，失败不改运行态、配置、缓存、审计；仅
    缓存成功，同 key 同型同 text 重放无副作用，异参 ValueError；不审计。
    credential_change(key, user, old_password, new_password, now_ms) 轮换
    用户密码：四串沿用凭据约束，now_ms 为非 bool 非负 int；型/值错分别抛
    TypeError/ValueError，旧新相同抛 ValueError，未知用户抛 KeyError。首次
    合法先经 Authenticator 校验旧密码，非 ok（denied/locked/backoff）抛
    AuthError 并保留失败计数、锁定与下次可试时刻；成功按摘要规则换密并清零
    失败计数、锁定与下次可试时刻。除缓存、审计与认证副作用外失败不改其他
    状态；成功保留会话与已入队队项，此后仅新密码可认证。返回键序“用户/时刻/结果”、结果恒为“已轮换”的 LF 尾紧凑 JSON。
    验 key 后以独立域永久缓存余参与首果（含参数异常），同型同参重放不认证、
    不换密，原样返回或重抛同类同 args，异参抛 ValueError 且不审计。参数错不
    审计；首果（成功/AuthError/KeyError）及同参重放写现有防篡改审计链：操作
    “凭据轮换”、会话记 user，首次原序号 0、重放原序号指认首次且结果加“重放”
    前缀。O(1) 时空（凭据长度有界）。
    batch_credential_change(key, items, now_ms, atomic=False) 一次轮换多个
    用户的凭据：key 与三元组三串沿用凭据约束，items 为 1..1000 个
    (user, old_password, new_password) 三元组的 tuple，旧新口令须不同且
    user 互异；now_ms 为非 bool 非负 int，atomic 为 bool；容器/元素/字段
    类型不符 TypeError，数量/形态/重复用户/凭据取值/负时刻 ValueError。
    整批参数错误不认证、不改状态、不占幂等键、不写审计。验 key 后以独立
    域永久缓存合法首果：同型同参重放逐字节返回首果、不再认证或轮换，异参
    ValueError。合法批次逐项沿用 credential_change 的停用检查与旧口令认证
    语义：未知用户项记 KeyError，停用/口令错误/锁定/退避项记 AuthError，
    业务失败记入项目结果而不抛出；验证成功才切换新凭据并清零该用户失败
    次数、锁定截止与下次可试时刻。非原子依次提交成功项，失败项不影响后
    项；原子校验全部项，全成功才一次提交，任一失败则可成功项记“回滚”且
    全部凭据保持批次前值，而认证产生的失败计数、锁定、退避及成功验证的
    限制清零均保留。两种模式都不老化，且不改变会话、租约、容量队列、
    QoS 账本或停用状态。合法首调与同参重放均按输入序逐项写独立批量防
    篡改审计链 batch_audit（操作“批量凭据轮换”，会话字段取用户名），首调
    记录项目结果、原序号 0，重放记“重放”、原序号指认对应首项，并沿既有
    规则投影到 compliance 链，不写单操作 audit 链；参数错与异参 key 不记。
    返回键序“时刻/原子/结果/项目”的 LF 尾紧凑 JSON，结果仅成功（全部
    轮换）/部分成功（非原子有成功有失败）/失败（非原子全失败）/回滚
    （原子有失败），项目依输入顺序、项键序“用户/结果”，项结果仅轮换/
    回滚/实际异常类名。单批 O(B) 时间与 O(B) 辅助空间，重放 O(B)。
    user_admin(key, op, user, now_ms, force=False) 停用或启用用户：key/user
    沿用凭据约束，op 仅停用/启用，now_ms 为非 bool 非负 int，force 为 bool，
    启用限 force=False；型/值错分别抛 TypeError/ValueError，未知用户
    KeyError。停用遇该用户非下线（在线/挂起）会话或排队队项且 force=False
    抛 StateError、状态不变；force=True 原子下线其全部非下线会话（清期限、
    释址退租）并删除其全部排队队项，不记 capacity 事件；失败不改态。启用无
    副作用；同态成功且下线/取消恒 0。停用后该用户 do 建立/迁移/接管、
    capacity 申请、batch_online、credential_change 先于后端检查与认证拒绝：
    单项抛 AuthError、批量项结果记 AuthError，不老化、不退避、不认证，锁定、
    退避与失败计数不变；启用恢复。返回键序“用户/状态/时刻/下线/取消”的
    LF 尾紧凑 JSON（ensure_ascii=False、separators=(',',':')），状态仅
    停用/启用，下线/取消为 int。验 key 后以独立域永久缓存余参与首果（含参数
    异常），同型同参重放不改态、异参 ValueError；参数错与 StateError/KeyError
    等业务异常不审计，成功首果及成功的同参重放写现有防篡改审计链：操作
    “用户停用/用户启用”、会话记 user，首次原序号 0、结果“成功”，重放
    原序号指认首次、结果“重放”。停用态不随配置加载/回滚或
    creplay/runtime_restore 改变。首次
    O(S+Q) 时间、O(1) 辅助空间，重放 O(1)。
    do 另受理挂起/恢复：挂起 args 须为 None 否则 ValueError，先老化，
    未知 sid 抛 KeyError、非在线抛 StateError，置挂起、期限 0 并释址
    退租；恢复 args 为 (pool, password) 二元 tuple（非 tuple 抛
    TypeError、长度错抛 ValueError、两字段沿用凭据约束），先由 sid
    只读定位（未知 KeyError），再查停用（AuthError）与后端
    （BackendError），老化后查池（未知 KeyError）与状态（非挂起
    StateError）、认证（非 ok AuthError）、取址（池故障演练、静态址
    占用或动态址耗尽均 ResourceError）：取用户静态址，否则取池内最小
    动态址，置在线，期限 = now_ms+idle_ms、租期 = now_ms+lease_ms；
    失败仅保留老化、认证计数与退避，不半分配。二者返回键序
    会话/状态/时刻/期限/池/地址/租期的 LF 尾 JSON（会话/状态/池/地址
    为 str，余为 int；挂起时池/地址空串、租期 0），缓存与审计沿用 do。
    fault_plan(key, mode, steps, now_ms) 批量演算后端/池/超时三域故障注入
    或恢复：key 沿用凭据约束，mode 仅预检/执行；steps 为 1..1000 项 tuple，
    每项 (domain, target, op, value)，domain 限后端/池/超时、op 限注入/恢复；
    后端与超时项 target 须为 "" 且在各自域唯一（至多一项），池项 target 沿用
    池标识凭据且互异；后端/池注入 value 为非 bool 正 int（截至=now_ms+value），
    超时注入 value 为非 bool int 且 >= now_ms，恢复 value 须 None；now_ms 为
    非 bool 非负 int。类型错 TypeError、结构/值错 ValueError、未知池
    KeyError。全验后整体演算：后端注入/恢复均清全部用户退避、失败计数保留，
    池注入置截至/恢复移除，超时注入覆盖待触发/恢复取消，未列域不变。预检只读
    演算、不落实例；执行在副本上演算（异常实例不变）后原子提交三域。成功返回
    演算态 fault_checkpoint(now_ms) 契约的 LF 尾基线 JSON。执行以 key 缓存首个
    成功或 KeyError（预检不缓存）：严格同参重放原字节或重抛同类同 args，异参
    ValueError，参数错不占 key；首果（成功/KeyError）及同参重放写现有防篡改
    审计链：操作“故障计划”、会话空串，首次结果“成功/KeyError”、原序号 0，
    重放结果“重放成功/重放KeyError”、原序号指认首次，审计时刻取 now_ms；预检、
    参数错不审计。首次 O(U log U+P log P+K) 时间、O(U+P+K) 空间，重放 O(1)。
    fault_impact(steps, now_ms) 只读评估计划在 now_ms 视图下的影响：steps 沿用
    fault_plan 的 1..1000 项 tuple 契约（无 key/mode），now_ms 为非 bool 非负
    int；型/结构值/重复/未知池分别抛 TypeError/ValueError/KeyError。不老化、
    不缓存、不审计、不改状态，演算仅在副本上推演三域生效态。按 now_ms 取视图：
    到期在线归挂起；租约须在线且期限、租期均 > now_ms；到期队项不计。域行依次
    为后端、按标识升序的注入池、超时，后端/超时目标为空串，行键序
    域/目标/生效/在线/挂起/排队/租约；后端在 now_ms<演算截至时计全局四类，
    池同条件计本池在线/租约（default 另计全队、挂起 0），超时在等待且触发
    <=now_ms 时计全局在线/排队/租约、挂起 0，否则行全 0。顶层键序
    时刻/域/合计/摘要，合计键序在线/挂起/排队/租约（各行和，域间可重复），
    摘要为前三键紧凑 JSON UTF-8 字节的 sha256 小写值；ensure_ascii=False、
    separators=(',',':')、LF 结尾，同态同参同字节。O(S+Q+P log P+K) 时间、
    O(P+K) 辅助空间。
    fault_diff(left, right, now_ms) 只读对比两份计划在同一 now_ms 视图下的
    影响：left/right 沿用 fault_plan 的 1..1000 项 tuple 契约，now_ms 为非
    bool 非负 int；型/结构值/重复/未知池分别抛 TypeError/ValueError/
    KeyError（先校验/演算 left 再 right）。不老化、不缓存、不审计、不改状态，
    两侧均从实例当前同一故障态演算，视图与四类计数沿用 fault_impact。域行按
    后端、两侧池标识并集 Unicode 升序、超时排列，后端/超时目标为空串；某侧
    演算后不在册的池对应侧按不生效、四项 0 计（后端/超时两侧恒在册）。行键序
    域/目标/左/右/增减，左/右均为键序 生效/在线/挂起/排队/租约 的对象，
    增减键序 在线/挂起/排队/租约、值逐项为右减左。顶层键序
    时刻/域/合计/摘要，合计键序同增减、为各行增减逐项求和，摘要为前三键紧凑
    JSON UTF-8 字节的 sha256 小写值；ensure_ascii=False、separators=(',',':')、
    LF 结尾，同态同参同字节。O(S+Q+(P+K) log(P+K)) 时间、O(P+K) 辅助空间。
    fault_matrix(scenarios, now_ms) 只读批量评估多份计划：scenarios 为
    1..100 项 (label, steps) tuple，label 为互异凭据 str（1..256 UTF-8 字节、
    不含 U+0000），steps 沿用 fault_plan 的 1..1000 项 tuple 契约，now_ms
    为非 bool 非负 int。类型错 TypeError、结构/长度/取值/重复错 ValueError、
    未知池 KeyError（先校验全部场景，再依序演算）。不老化、不缓存、不审计、
    不改状态。基准（不施加步骤）与各场景均从实例当前同一故障态演算，视图与
    四类计数沿用 fault_impact。域键取基准与各场景在册池标识并集，行按后端、
    池 Unicode 升序、超时排列，缺侧行按不生效、四项 0，场景按输入序。基准行
    键序 域/目标/生效/在线/挂起/排队/租约；场景项键序 标识/域/合计，其域行
    在基准行后追加“增减”（键序 在线/挂起/排队/租约、值为场景-基准），合计
    键序同增减、为逐行增减之和。顶层键序 时刻/基准/场景/摘要，摘要为前三键
    紧凑 JSON UTF-8 字节的 sha256 小写值；ensure_ascii=False、
    separators=(',',':')、LF 结尾，同态同参同字节。O(S+Q+K+CP+P log P)
    时间、O(CP+K) 辅助空间，C/P/K 为场景数/池并集数/步骤总数。
    audit_restore(key, text) 将 audit_snapshot 分页结果原子接入防篡改审计链：
    key 沿用凭据约束，text 非 str 抛 TypeError；text 须为版本 1 规范快照
    （逐层键集/键序与类型、事件九键序、LF 尾紧凑 JSON 沿用现有契约），解析或
    重键、非规范编码、范围、事件数超过上限、序号不连续、游标不等于空窗锚或
    末项、原序号非 0 且不小于本项序号、前哈希/哈希/摘要错误均抛 ValueError。
    结构全验后当前链末尾须恰等于快照锚序号/锚哈希，否则抛
    StateError(锚序号, 当前末序号)。全验后一次追加窗口事件；不恢复会话、配置、
    业务缓存或操作幂等（原序号）索引，恢复不写审计，失败不追加。不老化。
    验 key 后以独立缓存且仅缓存成功：同型同 text 重放原字节且不追加，异参
    ValueError，失败不占 key。成功返回 LF 尾紧凑 JSON（ensure_ascii=False、
    separators=(',',':')），键序/型 追加:int/末序号:int/末哈希:str/摘要:str，
    摘要为前三键同法编码 UTF-8 字节的 sha256 小写值；空页追加 0。
    O(limit) 时间、O(limit) 空间。
    """

    def __init__(self, auth, total, per, idle_ms, pool=None, lease_ms=1):
        if not isinstance(auth, Authenticator):
            raise TypeError(f"auth must be an Authenticator, got {type(auth).__name__}")
        self._auth = auth
        self._total = _check_int("total", total, 1)
        self._per = _check_int("per", per, 1)
        self._idle_ms = _check_int("idle_ms", idle_ms, 0)

        # 池 id -> _Pool，插入顺序即 add_pool 顺序；统计另按 id 升序输出。
        self._pools = {}
        if pool is not None:
            self._pools[_DEFAULT_POOL_ID] = _Pool(_check_pool(pool))
        self._lease_ms = _check_int("lease_ms", lease_ms, 1)

        # QoS 模板：标识 -> (限速, 突发, 配额, 周期毫秒, 会话上限, 排队优先级,
        # 超限)，周期毫秒 0 表示不重置、会话上限 0 表示不限并发占用、排队
        # 优先级为推进老化提升的基础值 0..100；用户模板：user -> 标识。
        self._templates = {}
        self._user_templates = {}
        # v11 模板地址池优先序列：模板标识 -> (池标识, ...)（1..32 项互异、
        # 按文档优先序）；未列入的模板自动取址沿用 default 池。
        self._template_pool_order = {}
        # 容量背压：队列上限（0 表示不限）、最大等待毫秒（0 表示不限）、
        # 队满策略（拒绝/替换）。
        self._queue_limit = _MAX_QUEUE
        self._max_wait_ms = 0
        self._queue_policy = _QUEUE_POLICY_REJECT

        # sid -> {"user": str, "state": str, "deadline": int, "ip": int|None,
        #         "lease": int, "pool": str|None}
        self._sessions = {}
        # key -> (op, sid, args, now_ms, outcome)
        # outcome 为 ("ok", json_str) 或 ("err", (exc_class, exc_args))
        self._cache = {}
        # meter 的重放缓存，与 do 分域：key -> (sid, size, now_ms, outcome)
        self._meter_cache = {}
        # QoS 计量账本：(用户, 模板标识) -> [累计 u, 上次通过时刻 t, 千分字节
        # 令牌 c]；同用户同模板的并发会话共享一本账，仅“通过”原子更新，拒绝、
        # 下线、异常与重放不改账，会话下线/新建/接管不清账；配置提交后同标识
        # 保留 u/t 并按新模板桶容截顶 c，改绑按新 (用户, 模板) 独立建账。
        self._meter_ledgers = {}
        # 计量统计：标识 -> [通过, 拒绝, 下线, 通过字节]，用户组按当时会话
        # 用户、模板组按当次模板标识归集；历史计数不随配置热加载或回滚迁移。
        self._meter_stats_user = {}
        self._meter_stats_template = {}
        # 接管审计事件追加序列（序号自 1）；key -> 首次事件序号，供重放指认。
        self._audit_events = []
        self._audit_index = {}
        # 防篡改审计链：事件九元组序列（序号自 1）、key -> 首次事件序号、
        # 末项哈希（空链为 64 个 0，即首项前哈希）。
        self._chain_events = []
        self._chain_index = {}
        self._chain_tail = "0" * 64
        # 配置回滚点：最近一次成功 load_config 前的规范化 spec，无则 None。
        self._rollback = None
        # 配置修订号：初值 0，load_config/rollback_config/config_revert
        # 成功（含经 config_change/config_cas 提交）加 1；失败、导出与升级
        # 不变。
        self._revision = 0
        # 配置修订历史：修订号 -> 该修订提交后的规范化 spec，构造态修订 0
        # 初始在册；仅 load_config/rollback_config/config_revert 首次成功后
        # 追加当前修订，失败、只读升级与同参重放不写入。保留最近
        # _CONFIG_HISTORY_LIMIT 项：超限时淘汰最小修订号，当前修订不淘汰
        # （故修订 0 亦可在窗口满后被淘汰）。
        self._config_history = {0: self._current_spec()}
        # 防篡改配置历史：与修订快照同寿命的七元组记录序列，键序为
        # 修订/父修订/操作/目标/摘要/前哈希/哈希。构造即记录修订 0：
        # 父修订、目标为 -1，前哈希为 64 个 0，摘要同 config_revision。
        # 仅 load_config/rollback_config/config_cas/config_revert 首次成功
        # 追加“加载/回滚/CAS/回退”，失败与同参重放不追加；后项父修订取
        # 前一记录的修订（恒为前一修订号），回退目标为 target，余目标 -1。
        # 快照淘汰时同步淘汰对应记录，但不改动留存记录的前哈希（链不缝合），
        # 永不淘汰当前项。记录按修订升序，下标恒为“该提交时刻的序号”，与
        # 快照窗口内最小修订对齐。
        self._config_history_log = [
            self._config_history_record(
                0,
                -1,
                _CONFIG_HISTORY_OP_INIT,
                -1,
                self._config_summary(),
                "0" * 64,
            )
        ]

        # capacity 等待队列：sid -> [user, 申请时刻, 等待, 截止, 入队序]，
        # _queue_order 为按入队序的 sid 列表，_queue_seq 为下一入队序。
        self._capacity_queue = {}
        self._queue_order = []
        self._queue_seq = 0
        # capacity 的重放缓存，与 do/meter 分域：
        # key -> (op, sid, args, now_ms, outcome)。
        self._capacity_cache = {}
        # capacity 事件哈希链：七元组序列 (序号, 时刻, 会话, 结果, 入队序,
        # 前哈希, 哈希)，序号自 1；末项哈希（空链为 64 个 0，即首项前哈希）。
        # 取消保留原入队序；事件时刻可早于前事件（显式时钟允许回拨）。
        self._capacity_events = []
        self._capacity_tail = "0" * 64

        # 后端故障：截至时刻（0 表示无故障）与按用户退避 (n, retry_at)；
        # fault 的重放缓存与 do/meter/capacity 分域：
        # key -> (op, ms, now_ms, outcome)。
        self._fault_until = 0
        self._backoff = {}
        self._fault_cache = {}
        # 后端失败累计 [故障, 退避]：仅新 key 首次后端检查抛 BackendError
        # 时按类归计；注入/恢复/配置变更不清零。
        self._fault_fail = [0, 0]
        # 地址池可恢复耗尽演练：pool_id -> 截至时刻（不存即无演练）；
        # now_ms < 截至时该池视为无可分配地址，既有租约、续租、下线与从该池
        # 迁出不受影响，到刻自动正常。pool_fault 的重放缓存与 do/meter/
        # capacity/fault 分域：key -> (pool, op, ms, now_ms, outcome)。
        self._pool_fault = {}
        self._pool_fault_cache = {}
        # pool_fault 写现有防篡改链，但原序号索引与 do 分域，避免同名字符串
        # key 跨域互相指认首次事件。
        self._pool_fault_chain_index = {}
        # 全局超时演练：待触发时刻（None 表示无待触发）。首次
        # capacity 推进满足 now_ms >= 触发值时，于普通老化与晋升前原子挂起
        # 全部在线会话、清期限并释放租约，按入队序将全部队项记超时后删除，
        # 再清除触发；该批不晋升、不半释放。timeout_fault 的重放缓存与
        # do/meter/capacity/fault/pool_fault 分域：
        # key -> (op, at_ms, now_ms, outcome)；原序号索引亦独立分域。
        self._timeout_at = None
        self._timeout_fault_cache = {}
        self._timeout_fault_chain_index = {}
        # batch_offline 批量下线的重放缓存，与 do/meter/capacity/fault/
        # pool_fault/timeout_fault 分域：key -> (sids, now_ms, atomic, outcome)。
        self._batch_offline_cache = {}
        # batch_online 批量建立的重放缓存，与 do/meter/capacity/fault/
        # pool_fault/timeout_fault/batch_offline 分域：
        # key -> (items, now_ms, atomic, outcome)。
        self._batch_online_cache = {}
        # keepalive 批量保活的重放缓存，与 do/meter/capacity/fault/
        # pool_fault/timeout_fault/batch_offline/batch_online 分域：
        # key -> (sids, now_ms, atomic, outcome)。
        self._keepalive_cache = {}
        # batch_migrate 批量迁移的重放缓存，与 do/meter/capacity/fault/
        # pool_fault/timeout_fault/batch_offline/batch_online/keepalive
        # 分域：key -> (items, now_ms, atomic, outcome)。
        self._batch_migrate_cache = {}
        # 五类批量操作（batch_online/batch_offline/batch_migrate/keepalive/
        # batch_credential_change）的独立防篡改审计链：事件十元组序列（序号自
        # 1）与末项哈希（空链为 64 个 0，即首项前哈希）。与 do 等所用的
        # _chain_events（audit）相互独立，批量操作不写既有审计链。五类各持
        # key -> 该 key 合法首调首批事件的首序号索引（各缓存已按 key 分域，
        # 同名 key 跨操作不互相指认），供逐项重放指认对应首次事件；事件始终
        # 追加到同一条批量链。
        self._batch_chain_events = []
        self._batch_online_chain_index = {}
        self._batch_offline_chain_index = {}
        self._batch_migrate_chain_index = {}
        self._batch_keepalive_chain_index = {}
        self._batch_credential_chain_index = {}
        self._batch_chain_tail = "0" * 64
        # 链内各（键,操作,原子,会话）签名的全局首次序号，供 batch_audit_restore
        # O(1) 指认原序号；随 _batch_chain_record 与接入追加按序 setdefault。
        self._batch_chain_sig_first = {}
        # config_change 配置加载/回滚/升级事务的重放缓存，与 do/meter/
        # capacity/fault/pool_fault/timeout_fault/batch_offline 分域：
        # key -> (op, text, now_ms, outcome)；原序号索引亦独立分域。
        self._config_change_cache = {}
        self._config_change_chain_index = {}
        # config_cas 配置比较并提交的重放缓存，与其余各域独立：
        # key -> (text, expected, now_ms, 结果)；仅首次成功缓存，失败
        # （含参数错与修订不符）不占 key。本接口不审计，无原序号索引。
        self._config_cas_cache = {}
        # config_revert 历史回退的重放缓存，与其余各域独立：
        # key -> (target, expected, now_ms, 结果)；仅首次成功缓存，失败
        # （含参数错、修订不符与目标未保留）不占 key。本接口不审计。
        self._config_revert_cache = {}
        # credential_change 凭据轮换的重放缓存，与其余各域独立：
        # key -> (user, old_password, new_password, now_ms, outcome)；原序号
        # 索引亦独立分域。
        self._credential_change_cache = {}
        self._credential_change_chain_index = {}
        # batch_credential_change 批量凭据轮换的重放缓存，与其余各域独立：
        # key -> (items, now_ms, atomic, 结果 JSON)；仅合法首果占位，参数错
        # （TypeError/ValueError）不占 key；原序号索引亦独立分域。
        self._batch_credential_change_cache = {}
        # user_admin 用户停用/启用管理：停用态用户集合（停用即先于后端与认证
        # 拒绝建立/迁移/接管、capacity 申请、batch_online 与 credential_change）。
        # 重放缓存与各域独立：key -> (op, user, now_ms, force, outcome)；
        # 原序号索引亦独立分域。
        self._disabled_users = set()
        self._user_admin_cache = {}
        self._user_admin_chain_index = {}
        # quota_restore 共享 QoS 账本恢复的重放缓存，与其余各域独立：
        # key -> (text, outcome)；仅首次成功缓存，失败（含参数错）不占 key。
        self._quota_restore_cache = {}
        # auth_restore 认证器检查点恢复的重放缓存，与其余各域独立：
        # key -> (text, 规范包)；仅首次成功缓存，失败（含参数错与
        # ResourceError）不占 key。恢复不写审计链，故无原序号索引。
        self._auth_restore_cache = {}
        # runtime_restore 运行态检查点恢复的重放缓存，与其余各域独立：
        # key -> (text, 规范包)；仅首次成功缓存，失败（含参数错）不占 key。
        self._runtime_restore_cache = {}
        # backend_restore 后端故障态检查点恢复的重放缓存与原序号索引，与其余
        # 各域独立：key -> (text, 规范包)；仅首次成功缓存，失败（含参数错）
        # 不占 key。
        self._backend_restore_cache = {}
        self._backend_restore_chain_index = {}
        # fault_restore 故障演练总检查点恢复的重放缓存与原序号索引，与其余
        # 各域独立：key -> (text, 规范包, 时刻)；仅首次成功缓存，失败
        # （含参数错）不占 key。
        self._fault_restore_cache = {}
        self._fault_restore_chain_index = {}
        # timeout_sweep 超时清扫的重放缓存，与其余各域独立：
        # key -> (now_ms, limit, 结果 JSON)；仅首次成功缓存，失败不占 key。
        self._timeout_sweep_cache = {}
        # timeout_storm 超时风暴多批清扫的重放缓存与原序号索引，与其余各域
        # 独立：key -> (now_ms, batches, 结果 JSON)；仅首次成功缓存，失败
        # （含参数错）不占 key。
        self._timeout_storm_cache = {}
        self._timeout_storm_chain_index = {}
        # fault_plan 批量故障演练计划的重放缓存与原序号索引，与其余各域独立：
        # key -> (mode, steps, now_ms, outcome)；仅首次成功与 KeyError 占位，
        # 参数错不占 key。预检永不缓存。
        self._fault_plan_cache = {}
        self._fault_plan_chain_index = {}
        # capacity_rebalance 容量热均衡的重放缓存，与其余各域独立：
        # key -> (mode, changes, now_ms, 结果 JSON)；仅执行模式首次成功缓存，
        # 预检永不缓存，失败（含参数错、StateError、ResourceError）不占 key。
        # 不写审计链，故无原序号索引。
        self._capacity_rebalance_cache = {}
        # audit_restore 审计窗口快照恢复的重放缓存，与其余各域独立：
        # key -> (text, 结果 JSON)；仅首次成功缓存，失败（含参数错与
        # StateError）不占 key。恢复不写审计链，故无原序号索引。
        self._audit_restore_cache = {}
        # batch_audit_restore 批量审计页接入的重放缓存，与其余各域独立：
        # key -> (text, 结果 JSON)；仅首次成功缓存，失败（含参数错与
        # StateError）不占 key。接入不写批量链幂等（原序号）索引。
        self._batch_audit_restore_cache = {}
        # 合规全局链：把此后由 audit（_chain_events）、batch_audit
        # （_batch_chain_events）、capacity_events（_capacity_events）可观察
        # 到的每条源事件，按真实追加先后投影到同一条六元组全局链
        # （全局序号, 来源, 来源序号, 载荷, 前哈希, 哈希），序号自 1；末项
        # 哈希空链为 64 个 0。源事件与其投影原子追加；audit_restore、
        # batch_audit_restore、creplay 导入/替换源事件不回灌历史投影，
        # compliance_restore 只恢复本链且不生成自身事件。
        self._compliance_events = []
        self._compliance_tail = "0" * 64
        # compliance_restore 规范快照接尾的独立幂等缓存，与其余各域独立：
        # key -> (text, 结果 JSON)；仅首次成功占位，失败（含参数错与
        # StateError）不占 key。
        self._compliance_restore_cache = {}
        # stats_restore 统计快照恢复的重放缓存，与其余各域独立：
        # key -> (text, 规范包)；仅首次成功缓存，失败（含参数错与
        # ResourceError）不占 key。恢复不写审计链，故无原序号索引。
        self._stats_restore_cache = {}
        # stats_merge 统计快照三方合并的重放缓存，与其余各域独立：
        # key -> ((base, left, right), 结果 JSON)；仅首次成功缓存，失败
        # （含参数错、ResourceError、StateError）不占 key。合并不写审计链，
        # 故无原序号索引。
        self._stats_merge_cache = {}
        # service_restore 跨域一致性检查点恢复的重放缓存，与其余各域独立：
        # key -> (text, 规范包)；仅首次成功缓存，失败（含参数错、
        # ResourceError 与 StateError）不占 key。恢复不写任何审计链，故无
        # 原序号索引。
        self._service_restore_cache = {}
        # 按用户失败累计 user -> [认证, 资源, 状态, 后端]：仅 do/meter/
        # capacity 新 key 首次且已定位用户的四类异常各计一次；参数错、
        # KeyError、fault、重放与异参 key 不计，配置变更与重放恢复不清零。
        self._user_fail = {}
        # 建立统计 [总数, 成功]：仅已注册用户验参成功的新 key 首次 do 建立
        # 计总数，成功再计成功；参数错、未知用户（认证失败的已注册用户照计）
        # 与重放不计；配置变更不清零。
        self._establish_total = 0
        self._establish_success = 0

        # 会话计费：十一元组哈希链事件序列（序号, 类型, 时刻, 会话, 用户,
        # 地址池, 地址, 累计字节, 原因, 前哈希, 哈希），序号自 1；末项哈希
        # （空链为 64 个 0，即首项前哈希）。开始/中间原因恒为空串；停止原因
        # 为下线/批量下线/停用/配额/接管。仅会话建立、容量申请立即建立、
        # 容量晋升与批量上线成功追加开始；显式下线、批量下线、强制停用、
        # QoS 超限下线与接管追加停止；接管的新会话同刻追加开始。迁移、续租、
        # 挂起、恢复、超时老化挂起与超时演练挂起均不切分计费。
        self._account_events = []
        self._account_tail = "0" * 64
        # 活动（在线或挂起、未停止）会话的计费账：sid -> [累计字节, 用户,
        # 最近计费时刻]；池/地址不缓存，始终取会话当前持址（迁移改址不切分
        # 计费，故中间/停止事件须反映迁移后池址；挂起为 ""）。仅 meter 通过
        # 的字节计入累计；最近计费时刻取开始、历次中间与 meter 通过时刻的
        # 最大值。停止后删账；同 sid 再建立即新账。
        self._account_active = {}
        # accounting_interim 的重放缓存，与其余各域独立：
        # key -> (sid, now_ms, 结果 JSON)；仅首次成功缓存，失败不占 key。
        self._account_interim_cache = {}

    def add_pool(self, pool_id, pool):
        """追加命名池；零池起步时借此激活地址池（含 default），返回 None。

        重名抛 ValueError，pool_id/pool 类型或取值不合法抛 TypeError/ValueError。
        新池地址空间独立，可与既有池重叠。
        """
        _check_credential("pool id", pool_id)
        # 先完成全部入参校验（与 do() 一致：参数类异常先于状态类异常），再查重名。
        parsed = _check_pool(pool)
        if pool_id in self._pools:
            raise ValueError(f"duplicate pool id: {pool_id!r}")
        self._pools[pool_id] = _Pool(parsed)

    def do(self, key, op, sid, args, now_ms):
        """执行一次建立/续租/下线/迁移/接管/挂起/恢复操作，返回 LF 结尾的 JSON 字符串。

        建立/迁移/接管/恢复在验参后、老化前查后端：故障期按用户指数退避抛
        BackendError（只入缓存，不老化、不认证、不审计），健康才老化。
        """
        _check_credential("key", key)

        cached = self._cache.get(key)
        if cached is not None:
            # 重放：不老化、不认证、不改租约，仅按缓存返回或重抛。
            c_op, c_sid, c_args, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, sid, args, now_ms), (c_op, c_sid, c_args, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 接管缓存命中（成功/认证失败/资源失败）记重放，指认首次事件序号。
            if c_op == _OP_TAKEOVER and key in self._audit_index:
                self._audit_append(
                    key, c_args[0], c_sid, "重放", now_ms, self._audit_index[key]
                )
            # 防篡改链：可记结果（成功/四类异常）的同参重放沿用首次结果入链，
            # 原序号指认首次事件；参数错重放不在链索引中，自然跳过。
            chain_origin = self._chain_index.get(key)
            if chain_origin is not None:
                if outcome[0] == "ok":
                    chain_result = "成功"
                else:
                    chain_result = outcome[1][0].__name__
                self._chain_append(
                    key, c_op, c_sid, chain_result, now_ms, chain_origin
                )
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存。
        try:
            self._validate_params(op, sid, args, now_ms)
        except (TypeError, ValueError) as exc:
            self._cache[key] = (
                op,
                sid,
                args,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 建立统计：已注册用户验参成功的新 key 首次 do 建立即计总数（参数错、
        # 未知用户与重放均不到此）；成功路径再计成功，故后端故障等各类失败
        # 计总数但不计成功。
        count_establish = op == _OP_ESTABLISH and args[0] in self._auth
        if count_establish:
            self._establish_total += 1

        # 建立/迁移/接管/恢复：验参后、老化前查后端。迁移/接管/恢复由
        # sid/old 只读定位，未知 KeyError（不退避，仍缓存并入链）；定位后
        # BackendError 先于状态、目标池与新 sid 错误；健康才老化并循旧序。
        if op == _OP_ESTABLISH:
            backend_user = args[0]
        elif op == _OP_MIGRATE:
            session = self._sessions.get(sid)
            if session is None:
                exc = KeyError(f"unknown sid: {sid!r}")
                self._cache[key] = (
                    op,
                    sid,
                    args,
                    now_ms,
                    ("err", (type(exc), exc.args)),
                )
                self._chain_append(key, op, sid, type(exc).__name__, now_ms)
                raise exc
            backend_user = session["user"]
        elif op == _OP_TAKEOVER:
            old_session = self._sessions.get(args[0])
            if old_session is None:
                exc = KeyError(f"unknown old sid: {args[0]!r}")
                self._cache[key] = (
                    op,
                    sid,
                    args,
                    now_ms,
                    ("err", (type(exc), exc.args)),
                )
                self._chain_append(key, op, sid, type(exc).__name__, now_ms)
                raise exc
            backend_user = old_session["user"]
        elif op == _OP_RESUME:
            session = self._sessions.get(sid)
            if session is None:
                exc = KeyError(f"unknown sid: {sid!r}")
                self._cache[key] = (
                    op,
                    sid,
                    args,
                    now_ms,
                    ("err", (type(exc), exc.args)),
                )
                self._chain_append(key, op, sid, type(exc).__name__, now_ms)
                raise exc
            backend_user = session["user"]
        else:
            backend_user = None
        # 停用态用户：建立/迁移/接管/恢复先于后端检查与认证拒绝，只入缓存；
        # 不老化、不退避、不认证、不计失败、不入审计链（重放自然不重记入链）。
        if backend_user is not None and backend_user in self._disabled_users:
            exc = AuthError(f"user {backend_user!r} is disabled")
            self._cache[key] = (
                op,
                sid,
                args,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise exc
        if backend_user is not None:
            try:
                self._backend_check(backend_user, now_ms)
            except BackendError as exc:
                # 失败只改退避、计数与缓存：不老化、不认证、不审计。
                self._record_user_failure(backend_user, exc)
                self._cache[key] = (
                    op,
                    sid,
                    args,
                    now_ms,
                    ("err", (type(exc), exc.args)),
                )
                raise

        # 非重放：先将到期在线会话挂起、到期租约释放。
        self._age(now_ms)
        is_takeover = op == _OP_TAKEOVER
        try:
            if op == _OP_ESTABLISH:
                result = self._establish(sid, args[0], args[1], now_ms)
                if count_establish:
                    self._establish_success += 1
            elif op == _OP_RENEW:
                result = self._renew(sid, now_ms)
            elif op == _OP_MIGRATE:
                result = self._migrate(sid, args[0], args[1], now_ms)
            elif is_takeover:
                result = self._takeover(sid, args[0], args[1], now_ms)
            elif op == _OP_SUSPEND:
                result = self._suspend(sid, now_ms)
            elif op == _OP_RESUME:
                result = self._resume(sid, args[0], args[1], now_ms)
            else:
                result = self._offline(sid, now_ms)
        except (AuthError, ResourceError, StateError, KeyError) as exc:
            self._cache[key] = (
                op,
                sid,
                args,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            # 按用户失败计数：KeyError 不计；余三类须已定位用户（建立取
            # args 用户，迁移/接管取老化前定位用户，续租/下线由 sid 定位）。
            if not isinstance(exc, KeyError):
                if op == _OP_ESTABLISH:
                    fail_user = args[0]
                elif backend_user is not None:
                    fail_user = backend_user
                else:
                    fail_session = self._sessions.get(sid)
                    fail_user = (
                        fail_session["user"] if fail_session is not None else None
                    )
                if fail_user is not None:
                    self._record_user_failure(fail_user, exc)
            # 仅接管的认证/资源失败入账（老化结果已保留）；
            # StateError、KeyError 不记。
            if is_takeover and isinstance(exc, (AuthError, ResourceError)):
                verdict = "认证失败" if isinstance(exc, AuthError) else "资源失败"
                self._audit_append(key, args[0], sid, verdict, now_ms)
            # 防篡改链：验参后的四类异常结果均入链（参数错已在上方提前返回）。
            self._chain_append(key, op, sid, type(exc).__name__, now_ms)
            raise
        self._cache[key] = (op, sid, args, now_ms, ("ok", result))
        if is_takeover:
            self._audit_append(key, args[0], sid, "成功", now_ms)
        self._chain_append(key, op, sid, "成功", now_ms)
        return result

    def _validate_params(self, op, sid, args, now_ms):
        """校验 key 之外的四个参数；迁移、接管、挂起与恢复始终受理（无池于
        老化后抛 StateError 或 KeyError），续租仅在已有地址池时受理。"""
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        # 迁移、接管、挂起与恢复在零池模式下亦通过验参，状态类异常延后到
        # 老化之后。
        valid_ops = (
            _OP_ESTABLISH,
            _OP_OFFLINE,
            _OP_MIGRATE,
            _OP_TAKEOVER,
            _OP_SUSPEND,
            _OP_RESUME,
        )
        if self._pools:
            valid_ops = (
                _OP_ESTABLISH,
                _OP_RENEW,
                _OP_OFFLINE,
                _OP_MIGRATE,
                _OP_TAKEOVER,
                _OP_SUSPEND,
                _OP_RESUME,
            )
        if op not in valid_ops:
            raise ValueError(f"op must be one of {valid_ops}, got {op!r}")
        _check_credential("sid", sid)
        if op == _OP_ESTABLISH:
            if not isinstance(args, tuple):
                raise TypeError(f"args must be a tuple, got {type(args).__name__}")
            if len(args) != 2:
                raise ValueError(
                    f"args must be a 2-tuple (user, password), got {len(args)} items"
                )
            _check_credential("user", args[0])
            _check_credential("password", args[1])
        elif op == _OP_MIGRATE:
            if not isinstance(args, tuple):
                raise TypeError(f"args must be a tuple, got {type(args).__name__}")
            if len(args) != 2:
                raise ValueError(
                    "args must be a 2-tuple (target, password), "
                    f"got {len(args)} items"
                )
            _check_credential("target", args[0])
            _check_credential("password", args[1])
        elif op == _OP_TAKEOVER:
            if not isinstance(args, tuple):
                raise TypeError(f"args must be a tuple, got {type(args).__name__}")
            if len(args) != 2:
                raise ValueError(
                    "args must be a 2-tuple (old, password), "
                    f"got {len(args)} items"
                )
            _check_credential("old", args[0])
            _check_credential("password", args[1])
        elif op == _OP_RESUME:
            if not isinstance(args, tuple):
                raise TypeError(f"args must be a tuple, got {type(args).__name__}")
            if len(args) != 2:
                raise ValueError(
                    "args must be a 2-tuple (pool, password), "
                    f"got {len(args)} items"
                )
            _check_credential("pool", args[0])
            _check_credential("password", args[1])
        elif args is not None:
            raise ValueError(f"args must be None for {op}, got {args!r}")
        _check_int("now_ms", now_ms, 0)

    def _age(self, now_ms):
        """到期（含同刻）处理：租约到期或空闲到期均释址，空闲到期再挂起。

        挂起即无址：空闲到期先释址再挂起、期限清零，挂起会话仍占全局与
        单用户上限但不计在线。
        """
        for session in self._sessions.values():
            if session["state"] != _STATE_ONLINE:
                continue
            expired = session["deadline"] <= now_ms
            if session["ip"] is not None and (expired or session["lease"] <= now_ms):
                self._release(session)
            if expired:
                session["state"] = _STATE_SUSPENDED
                session["deadline"] = 0

    def _release(self, session):
        """释放会话持址：动态地址回本池堆，静态地址仅退租，仍专属其用户。"""
        ip_int = session["ip"]
        if ip_int is None:
            return
        pool = self._pools[session["pool"]]
        del pool.leases[ip_int]
        # 租用地址非动态即静态（保留地址从不租用），静态地址不入动态堆。
        if ip_int not in pool.static_ips:
            heapq.heappush(pool.free, ip_int)
        session["ip"] = None
        session["lease"] = 0
        session["pool"] = None

    def _backend_check(self, user, now_ms, count_fault=True):
        """老化前的后端健康检查，O(1) 时空。

        截至与 retry_at 均到（含无故障）则清该用户退避并返回；故障中且
        retry_at 已到则 n 加一、retry_at = now_ms+min(100*2**(n-1), 1600)
        并抛 BackendError(retry_at)，计一次“故障”失败；retry_at 未到则
        n 不变，抛 BackendError(retry_at)，计一次“退避”失败。本方法仅由
        新 key 首次路径调用，重放不到达，故每次抛错恰计一次。count_fault
        为 False 时（batch_online 批内检查）只维护退避，不计 fault_stats
        失败（其口径仅含 do 与 capacity）。
        """
        n, retry_at = self._backoff.get(user, (0, 0))
        if now_ms >= self._fault_until and now_ms >= retry_at:
            # 健康：清该用户退避（无则空操作）。
            self._backoff.pop(user, None)
            return
        if now_ms >= retry_at:
            # 故障中且退避到期：n 加一，指数退避重算 retry_at（封顶 1600）。
            n += 1
            retry_at = now_ms + min(100 * 2 ** (n - 1), 1600)
            self._backoff[user] = (n, retry_at)
            if count_fault:
                self._fault_fail[0] += 1
        else:
            # 退避未到期：n 不变。
            if count_fault:
                self._fault_fail[1] += 1
        raise BackendError(retry_at)

    def _capacity_counts(self, user=None):
        """非下线会话计数（排队项不计数）：返回 (总数, 该用户数)。"""
        total_count = 0
        user_count = 0
        for session in self._sessions.values():
            if session["state"] != _STATE_OFFLINE:
                total_count += 1
                if user is not None and session["user"] == user:
                    user_count += 1
        return total_count, user_count

    def _template_occupancy(self, template_id):
        """模板当前占用：绑定该模板用户的在线加挂起会话数，O(S)/O(1)。"""
        occupancy = 0
        for session in self._sessions.values():
            if (
                session["state"] != _STATE_OFFLINE
                and self._user_templates.get(session["user"]) == template_id
            ):
                occupancy += 1
        return occupancy

    def _queue_effective(self, user, applied, now_ms):
        """队项在 now_ms 的有效优先级（与推进同口径）：
        min(1000, 基础+max(0,now_ms-申请时刻)//1000)，基础取此刻用户绑定
        模板的排队优先级、未绑定为 0。O(1) 时空。"""
        template_id = self._user_templates.get(user)
        base = (
            self._templates[template_id][5]
            if template_id is not None
            else 0
        )
        return min(
            _MAX_EFFECTIVE_PRIORITY,
            base + max(0, now_ms - applied) // 1000,
        )

    def _template_limit_of(self, user):
        """用户所绑模板的并发会话上限；未绑定或模板无上限（0）返回 0。"""
        template_id = self._user_templates.get(user)
        if template_id is None:
            return 0
        return self._templates[template_id][4]

    def _pool_is_exhausted(self, pool_id, now_ms):
        """池耗尽演练判定，O(1) 时空：注入后 now_ms < 截至即视为无可分配
        地址，到刻（含同刻）自动正常；不演练或已恢复无记录。只读不改态。"""
        until = self._pool_fault.get(pool_id)
        return until is not None and now_ms < until

    def _candidate_pools(self, user):
        """user 自动取址的候选池序列（按优先序），O(1) 时空。

        绑定模板且该模板配置了“模板地址池”序列时返回配置序列
        （1..32 个互异池标识）；未绑定模板或模板未列序列时仅 default 池，
        以保持旧配置与未绑定用户的行为。
        """
        return self._candidate_pools_for(
            user, self._user_templates, self._template_pool_order
        )

    @staticmethod
    def _candidate_pools_for(user, user_templates, template_pool_order):
        """同 _candidate_pools，但绑定与模板池序列由调用方给出（供容量热
        均衡在候选配置视图上演算）。"""
        template_id = user_templates.get(user)
        if template_id is not None:
            sequence = template_pool_order.get(template_id)
            if sequence is not None:
                return sequence
        return (_DEFAULT_POOL_ID,)

    @staticmethod
    def _pool_candidate_address(pool, user):
        """单池对 user 的可取址窥视，O(1) 时空，不弹堆、不改态。

        该用户在本池有专属静态地址时：未租用即返回该静态址，已被任一会话
        租用（含其自身另一会话）返回 None 且不回落动态址；否则返回动态空闲
        堆顶（不弹出），无动态空闲址返回 None。
        """
        static_ip = pool.static.get(user)
        if static_ip is None:
            return pool.free[0] if pool.free else None
        if static_ip in pool.leases:
            return None
        return static_ip

    def _select_address(self, user, now_ms):
        """按候选池优先序确定性选池取址，只读窥视不改态，O(P) 时间 O(1) 空间。

        候选池序见 _candidate_pools（至多 32 个）。依次跳过：处于有效耗尽
        故障（now_ms < 注入截至）的池、没有可取动态地址且该用户在本池无可用
        专属静态址的池（无动态址，或专属静态址正被占用）。首个可取址池返回
        (pool_id, ip)（动态仅窥堆顶、不弹出，落库由 _commit_session 完成）。
        全部不可用时返回 (pool_id, None)，pool_id 为序列中最后一个现存池；
        候选序列无任何现存池（零池模式且序列仅 default）时返回 (None, None)。
        """
        last_pool_id = None
        for pool_id in self._candidate_pools(user):
            pool = self._pools.get(pool_id)
            if pool is None:
                continue
            last_pool_id = pool_id
            if self._pool_is_exhausted(pool_id, now_ms):
                continue
            ip_int = self._pool_candidate_address(pool, user)
            if ip_int is not None:
                return pool_id, ip_int
        return last_pool_id, None

    def _sim_pool_state(self, now_ms, relevant_pools, do_age):
        """构建只读预测/热均衡演算用的多池地址态，不触碰实例。

        返回 (dyn_free, static_held, owners)：dyn_free 为每池老化后动态空闲
        槽计数（do_age=False 即当前空闲堆计数），static_held 为未老化持租的
        (池标识, 专属用户) 集合，owners 为每池静态址 -> 专属用户的反查表。
        仅为现存相关池建态（地址空间跨池独立，其余池的释放不影响候选判定）。
        地址表与租约表均不复制。时间 O(S)、辅助 O(P+U_st)。
        """
        relevant = set(relevant_pools)
        dyn_free = {}
        owners = {}
        for pool_id in relevant:
            pool = self._pools.get(pool_id)
            if pool is None:
                continue
            dyn_free[pool_id] = len(pool.free)
            owners[pool_id] = {
                ip_int: held_user for held_user, ip_int in pool.static.items()
            }
        static_held = set()
        for session in self._sessions.values():
            if session["state"] == _STATE_OFFLINE:
                continue
            if session["state"] != _STATE_ONLINE or session["ip"] is None:
                continue
            pool_id = session["pool"]
            if pool_id not in relevant:
                continue
            aging = do_age and (
                session["deadline"] <= now_ms or session["lease"] <= now_ms
            )
            pool = self._pools[pool_id]
            if aging:
                # 老化释放：动态址回空闲槽；静态址仅退租（不计动态槽）。
                if session["ip"] not in pool.static_ips:
                    dyn_free[pool_id] += 1
            else:
                held_user = owners[pool_id].get(session["ip"])
                if held_user is not None:
                    static_held.add((pool_id, held_user))
        return dyn_free, static_held, owners

    def _sim_try_address(
        self, user, now_ms, candidates, dyn_free, static_held
    ):
        """模拟态下按候选池序尝试取址，成功即扣模拟占用并返回 ("ok", 池标识)。

        全部失败返回 ("wait", 原因)：候选无现存池为“无池”，现存候选全部处于
        有效耗尽故障为“池故障”，否则（非故障池中动态址均耗尽或该用户专属
        静态址均被占用）为“地址”。与 _select_address 同一跳过次序。
        """
        present = False
        non_exhausted = False
        for pool_id in candidates:
            pool = self._pools.get(pool_id)
            if pool is None:
                continue
            present = True
            if self._pool_is_exhausted(pool_id, now_ms):
                continue
            non_exhausted = True
            static_ip = pool.static.get(user)
            if static_ip is None:
                if dyn_free.get(pool_id, 0) > 0:
                    dyn_free[pool_id] -= 1
                    return "ok", pool_id
            elif (pool_id, user) not in static_held:
                static_held.add((pool_id, user))
                return "ok", pool_id
        if not present:
            return "wait", "无池"
        if not non_exhausted:
            return "wait", "池故障"
        return "wait", "地址"

    def _commit_session(self, sid, user, pool_id, ip_int, now_ms):
        """全部校验通过后原子落库：登记租约（动态弹出堆顶）并建在线会话。

        返回 (期限, 租期)；失败路径不到达此方法，故无半分配残留。
        """
        pool = self._pools[pool_id]
        if pool.static.get(user) != ip_int:
            heapq.heappop(pool.free)
        pool.leases[ip_int] = sid
        deadline = now_ms + self._idle_ms
        lease = now_ms + self._lease_ms
        self._sessions[sid] = {
            "user": user,
            "state": _STATE_ONLINE,
            "deadline": deadline,
            "ip": ip_int,
            "lease": lease,
            "pool": pool_id,
        }
        return deadline, lease

    def _establish(self, sid, user, password, now_ms):
        """初始→认证中→在线；任一失败不留会话与租约残留。"""
        # 先认证。
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")
        # 后查 total 及用户 per，均计非下线会话。
        total_count, user_count = self._capacity_counts(user)
        if total_count >= self._total:
            raise ResourceError(f"total session limit {self._total} reached")
        if user_count >= self._per:
            raise ResourceError(f"per-user session limit {self._per} reached for {user!r}")
        # 模板并发会话上限：占用为绑定该模板用户的在线加挂起会话数。
        template_id = self._user_templates.get(user)
        if template_id is not None:
            session_limit = self._templates[template_id][4]
            if session_limit and self._template_occupancy(template_id) >= session_limit:
                raise ResourceError(
                    f"template session limit {session_limit} reached "
                    f"for template {template_id!r}"
                )
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")

        # 自动取址：绑定模板按其模板地址池优先序列、其余仅 default 池依次
        # 检查；序列无现存池为 StateError（零池模式）。
        pool_id, ip_int = self._select_address(user, now_ms)
        if pool_id is None:
            raise StateError("no address pool available: cannot establish session")
        if ip_int is None:
            raise ResourceError(
                f"no address available in candidate pools for {user!r}"
            )

        # 全部校验通过后再落库，杜绝失败残留。
        deadline, lease = self._commit_session(sid, user, pool_id, ip_int, now_ms)
        # 计费开始：仅建立成功产生开始事件（累计 0）。
        self._account_start(sid, now_ms)
        address = str(ipaddress.IPv4Address(ip_int))
        return self._render(sid, _STATE_ONLINE, now_ms, deadline, address, lease)

    def _renew(self, sid, now_ms):
        """仅持址在线会话可续租；未知 sid 为 KeyError，其余状态为 StateError。"""
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] != _STATE_ONLINE or session["ip"] is None:
            raise StateError(
                f"cannot renew sid {sid!r} in state {session['state']!r} without address"
            )
        # 续租只顺延租期，空闲期限（期限）不因续租改变。
        session["lease"] = now_ms + self._lease_ms
        address = str(ipaddress.IPv4Address(session["ip"]))
        return self._render(
            sid,
            _STATE_ONLINE,
            now_ms,
            session["deadline"],
            address,
            session["lease"],
        )

    def _migrate(self, sid, target, password, now_ms):
        """持址在线会话从原池原子迁至目标池；失败不换址，老化不回滚。

        依次：零池 StateError、未知 sid/target KeyError、非持址在线或同池
        StateError、认证非 ok AuthError、目标池耗尽或静态占用 ResourceError。
        """
        if not self._pools:
            raise StateError("no pool: no address pool configured")
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        target_pool = self._pools.get(target)
        if target_pool is None:
            raise KeyError(f"unknown target pool: {target!r}")
        if session["state"] != _STATE_ONLINE or session["ip"] is None:
            raise StateError(
                f"cannot migrate sid {sid!r} in state {session['state']!r} "
                "without address"
            )
        source_id = session["pool"]
        if source_id == target:
            raise StateError(f"sid {sid!r} already in target pool {target!r}")

        user = session["user"]
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")

        # 耗尽演练：目标池在注入期视为无址可分配，先于任何池变更，无半换址。
        # 从故障池迁出不受影响（仅查目标池）。
        if self._pool_is_exhausted(target, now_ms):
            raise ResourceError(f"target pool {target!r} exhausted")

        source_pool = self._pools[source_id]
        old_ip = session["ip"]
        new_ip = target_pool.static.get(user)
        if new_ip is None:
            # 非静态用户：取目标池最小动态空闲址。
            if not target_pool.free:
                raise ResourceError(f"target pool {target!r} exhausted")
            new_ip = heapq.heappop(target_pool.free)
        elif new_ip in target_pool.leases:
            # 目标静态址已被同用户的另一会话占用。
            raise ResourceError(
                f"static address {ipaddress.IPv4Address(new_ip)} for {user!r} "
                "already in use"
            )

        # 全部校验通过：原子释旧址、换池址。动态旧址回本池堆。
        del source_pool.leases[old_ip]
        if old_ip not in source_pool.static_ips:
            heapq.heappush(source_pool.free, old_ip)
        target_pool.leases[new_ip] = sid

        old_address = str(ipaddress.IPv4Address(old_ip))
        new_address = str(ipaddress.IPv4Address(new_ip))
        session["ip"] = new_ip
        session["pool"] = target
        # 迁移重置租期，空闲期限（期限）保持不变。
        session["lease"] = now_ms + self._lease_ms
        return self._render_migration(
            sid,
            _STATE_ONLINE,
            now_ms,
            session["deadline"],
            source_id,
            old_address,
            target,
            new_address,
            session["lease"],
        )

    def _takeover(self, sid, old, password, now_ms):
        """同用户接管：旧会话原子下线，新会话接管其地址或自 default 池分配。

        依次：未知 old KeyError、sid 已存在或旧会话已下线 StateError、认证非 ok
        AuthError；旧会话持址则转移池/地址并继承其租期，否则自 default 池取静态
        址或最小动态址（租期 = now_ms+lease_ms），缺 default StateError、无可分配
        址 ResourceError。失败不建 sid，保持老化后状态与池水位。时/空
        O(S+logA)/O(1)。
        """
        old_session = self._sessions.get(old)
        if old_session is None:
            raise KeyError(f"unknown old sid: {old!r}")
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")
        if old_session["state"] == _STATE_OFFLINE:
            raise StateError(f"cannot take over offline sid {old!r}")

        user = old_session["user"]
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")

        # 旧值取接管前，供输出且不受后续清场影响。
        old_ip = old_session["ip"]
        old_deadline = old_session["deadline"]
        old_lease = old_session["lease"]

        if old_ip is not None:
            # 转移：池、地址与租约记录由旧会话让渡给新会话，池水位不变；
            # 新会话继承旧租期而非重置。
            pool_id = old_session["pool"]
            ip_int = old_ip
            lease = old_lease
        else:
            # 分配：default 池静态址或最小动态址，新租期自此刻起算。
            pool = self._pools.get(_DEFAULT_POOL_ID)
            if pool is None:
                raise StateError("no default pool: cannot assign address")
            if self._pool_is_exhausted(_DEFAULT_POOL_ID, now_ms):
                raise ResourceError("address pool exhausted")
            ip_int = pool.static.get(user)
            if ip_int is None:
                if not pool.free:
                    raise ResourceError("address pool exhausted")
                ip_int = heapq.heappop(pool.free)
            elif ip_int in pool.leases:
                # 静态地址专属该用户，但同一时刻只能租给一个会话。
                raise ResourceError(
                    f"static address {ipaddress.IPv4Address(ip_int)} for {user!r} "
                    "already in use"
                )
            pool_id = _DEFAULT_POOL_ID
            lease = now_ms + self._lease_ms

        # 全部校验通过：原子下线旧会话（清期限/地址/租期），新会话在线接管。
        # 计费：旧会话先以“接管”结账停止（须在清场前，取其当前持址），
        # 新会话同刻开账产生开始事件。
        self._account_stop(old, now_ms, _ACCOUNT_REASON_TAKEOVER)
        pool = self._pools[pool_id]
        pool.leases[ip_int] = sid
        old_session["state"] = _STATE_OFFLINE
        old_session["deadline"] = 0
        old_session["ip"] = None
        old_session["lease"] = 0
        old_session["pool"] = None
        deadline = now_ms + self._idle_ms
        self._sessions[sid] = {
            "user": user,
            "state": _STATE_ONLINE,
            "deadline": deadline,
            "ip": ip_int,
            "lease": lease,
            "pool": pool_id,
        }
        self._account_start(sid, now_ms)
        old_address = (
            str(ipaddress.IPv4Address(old_ip)) if old_ip is not None else ""
        )
        return self._render_takeover(
            old,
            old_address,
            old_deadline,
            old_lease,
            sid,
            now_ms,
            deadline,
            pool_id,
            str(ipaddress.IPv4Address(ip_int)),
            lease,
        )

    def _offline(self, sid, now_ms):
        """在线/挂起/下线→下线、期限与租约清零、释址。"""
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] not in (_STATE_ONLINE, _STATE_SUSPENDED, _STATE_OFFLINE):
            raise StateError(f"cannot offline sid {sid!r} in state {session['state']!r}")
        # 计费停止：须在清场前结账（取当前持址）；下线墓碑无活动账为空操作。
        self._account_stop(sid, now_ms, _ACCOUNT_REASON_OFFLINE)
        session["state"] = _STATE_OFFLINE
        session["deadline"] = 0
        self._release(session)
        address = "" if self._pools else None
        return self._render(sid, _STATE_OFFLINE, now_ms, 0, address, 0)

    def _suspend(self, sid, now_ms):
        """在线→挂起：期限清零、释址退租；未知 sid KeyError，非在线 StateError。"""
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] != _STATE_ONLINE:
            raise StateError(
                f"cannot suspend sid {sid!r} in state {session['state']!r}"
            )
        session["state"] = _STATE_SUSPENDED
        session["deadline"] = 0
        self._release(session)
        return self._render_suspend_resume(sid, _STATE_SUSPENDED, now_ms, 0, "", "", 0)

    def _resume(self, sid, pool_id, password, now_ms):
        """挂起→在线：自指定池取用户静态址或最小动态址，失败不留半分配。

        依次：未知 sid/池 KeyError、非挂起 StateError、认证非 ok AuthError、
        池故障演练/静态址占用/动态址耗尽 ResourceError；全部通过才落库，
        期限 = now_ms+idle_ms、租期 = now_ms+lease_ms。定位、停用与后端
        检查已在老化前由 do 完成。
        """
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        pool = self._pools.get(pool_id)
        if pool is None:
            raise KeyError(f"unknown pool: {pool_id!r}")
        if session["state"] != _STATE_SUSPENDED:
            raise StateError(
                f"cannot resume sid {sid!r} in state {session['state']!r}"
            )

        user = session["user"]
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")

        # 取址：耗尽演练期该池视为无址；静态址专属该用户但同时只能租给
        # 一个会话；非静态用户取池内最小动态空闲址。
        if self._pool_is_exhausted(pool_id, now_ms):
            raise ResourceError("address pool exhausted")
        ip_int = pool.static.get(user)
        if ip_int is None:
            if not pool.free:
                raise ResourceError("address pool exhausted")
            ip_int = heapq.heappop(pool.free)
        elif ip_int in pool.leases:
            raise ResourceError(
                f"static address {ipaddress.IPv4Address(ip_int)} for {user!r} "
                "already in use"
            )

        # 全部校验通过：原子落库，置在线。
        pool.leases[ip_int] = sid
        deadline = now_ms + self._idle_ms
        lease = now_ms + self._lease_ms
        session["state"] = _STATE_ONLINE
        session["deadline"] = deadline
        session["ip"] = ip_int
        session["lease"] = lease
        session["pool"] = pool_id
        address = str(ipaddress.IPv4Address(ip_int))
        return self._render_suspend_resume(
            sid, _STATE_ONLINE, now_ms, deadline, pool_id, address, lease
        )

    def pool_stats(self, now_ms):
        """返回各池占用统计 JSON；无池抛 StateError，否则先老化再统计。"""
        _check_int("now_ms", now_ms, 0)
        if not self._pools:
            raise StateError("no pool: no address pool configured")
        self._age(now_ms)
        pools = []
        for pool_id in sorted(self._pools):
            pool = self._pools[pool_id]
            # 项序：标识、容量（可用数）、保留、静态、租用、动态空闲。
            pools.append(
                [
                    pool_id,
                    pool.capacity,
                    len(pool.reserved),
                    len(pool.static_ips),
                    len(pool.leases),
                    len(pool.free),
                ]
            )
        payload = {"时刻": now_ms, "池": pools}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def qos(self, sid):
        """返回会话用户所绑 QoS 模板的生效值 JSON，O(1) 时空；查询不老化。

        sid 类型/取值错抛 TypeError/ValueError，未知 sid 抛 KeyError，会话非
        在线或其用户未绑定模板抛 StateError。键序为
        “会话/用户/模板/限速/突发/配额/超限”，文本为 str、数值为 int。
        """
        _check_credential("sid", sid)
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] != _STATE_ONLINE:
            raise StateError(
                f"cannot query qos for sid {sid!r} in state {session['state']!r}"
            )
        user = session["user"]
        template_id = self._user_templates.get(user)
        if template_id is None:
            raise StateError(f"no qos template bound for user {user!r}")
        rate, burst, quota, _period_ms, _session_limit, _priority, exceed = (
            self._templates[template_id]
        )
        payload = {
            "会话": sid,
            "用户": user,
            "模板": template_id,
            "限速": rate,
            "突发": burst,
            "配额": quota,
            "超限": exceed,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def meter(self, key, sid, size, now_ms):
        """按会话用户所绑 QoS 模板计量一次流量，返回 LF 结尾的 JSON 字符串。

        计量态为 (用户, 模板) 共享账本，并发会话共享配额。key/sid 沿用凭据
        约束；size/now_ms 为非 bool 的正/非负 int，类型错
        TypeError、范围错 ValueError。重放缓存与 do 分域：首个结果（成功或
        异常）永久缓存，同型同参重放不老化、直接返回或重抛，异参抛
        ValueError。首次调用先老化；未知 sid 抛 KeyError，会话非在线、用户
        未绑模板或 now_ms 早于上次通过时刻抛 StateError；异常仅保留老化
        结果。单次 O(S) 时间、O(1) 辅助空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._meter_cache.get(key)
        if cached is not None:
            # 重放：不老化、不计量，仅按缓存返回或重抛。
            c_sid, c_size, c_now_ms, outcome = cached
            if not _strict_equal((sid, size, now_ms), (c_sid, c_size, c_now_ms)):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存。
        try:
            _check_credential("sid", sid)
            _check_int("size", size, 1)
            _check_int("now_ms", now_ms, 0)
        except (TypeError, ValueError) as exc:
            self._meter_cache[key] = (
                sid,
                size,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 非重放：先将到期在线会话挂起、到期租约释放。
        self._age(now_ms)
        try:
            result = self._meter(sid, size, now_ms)
        except (StateError, KeyError) as exc:
            self._meter_cache[key] = (
                sid,
                size,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            # 按用户失败计数：KeyError 不计；StateError 时会话必在，由 sid 定位。
            if isinstance(exc, StateError):
                self._record_user_failure(self._sessions[sid]["user"], exc)
            raise
        self._meter_cache[key] = (sid, size, now_ms, ("ok", result))
        return result

    def _meter(self, sid, size, now_ms):
        """令牌桶加配额计量：通过则提交账本，拒绝不提交，下线原子清场。

        计量账本按 (用户, 模板标识) 共享：(u, t, c) 为累计字节、上次通过
        时刻、千分字节令牌，首笔本地态 (0, now_ms, C)，C=(限速+突发)*1000；
        之后 c 按限速自 t 补足并以当前桶容 C 截顶（读取即截顶；配置热加载或
        回滚后同标识原样保留 u/t/c，不主动改 c，新桶容在补充时自然截顶，
        周期窗自新 P 判定）。P=模板周期毫秒：P>0 且 now_ms//P != t//P 时累计
        已跨周期重置，有效累计按 0 计，否则按 u 计（P=0 不重置）；令牌始终
        自 t 按原公式补充，不因跨周期清零。size*1000 <= c 且有效累计+size
        <= 配额则通过并原子提交 (有效累计+size, now_ms, c-size*1000)；否则
        取超限动作：拒绝不改账，下线不累计并原子下线、清期限、释址退租，账本
        不变。
        """
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] != _STATE_ONLINE:
            raise StateError(
                f"cannot meter sid {sid!r} in state {session['state']!r}"
            )
        user = session["user"]
        template_id = self._user_templates.get(user)
        if template_id is None:
            raise StateError(f"no qos template bound for user {user!r}")
        rate, burst, quota, period_ms, _session_limit, _priority, exceed = (
            self._templates[template_id]
        )
        capacity = (rate + burst) * 1000

        ledger_key = (user, template_id)
        ledger = self._meter_ledgers.get(ledger_key)
        if ledger is None:
            # 首笔：满桶起步，时刻即此刻；未通过不落账。
            stored_used, last, stored_tokens = 0, now_ms, capacity
        else:
            stored_used, last, stored_tokens = ledger
        if now_ms < last:
            raise StateError(
                f"now_ms {now_ms} before last meter time {last} for sid {sid!r}"
            )
        # 令牌自上次通过时刻按原公式补充并截顶；跨周期不清零。
        tokens = min(capacity, stored_tokens + rate * (now_ms - last))
        # 有效累计：跨周期窗则视为 0，否则取账本累计 u。
        used = _effective_used(stored_used, last, now_ms, period_ms)

        if size * 1000 <= tokens and used + size <= quota:
            # 通过：原子提交有效累计+size、本次时刻与扣减后的令牌。
            used += size
            tokens -= size * 1000
            self._meter_ledgers[ledger_key] = [used, now_ms, tokens]
            result = "通过"
            # 计费：仅 meter 通过的字节计入该会话活动账。
            self._account_add_bytes(sid, size, now_ms)
        else:
            result = exceed
            if exceed == "下线":
                # 不累计：原子下线、清期限、释址退租，账本不提交。
                # 计费停止（配额）须在清场前结账；本次拒绝字节不计入。
                self._account_stop(sid, now_ms, _ACCOUNT_REASON_QUOTA)
                session["state"] = _STATE_OFFLINE
                session["deadline"] = 0
                self._release(session)
            # 拒绝：不改账。
        # 账本/清场与统计同事务提交；本方法仅由新 key 路径调用，
        # 异常、同参重放与异参复用均不到达此处，故每 key 恰记一次。
        self._record_meter_stat(user, template_id, result, size)
        return self._render_meter(sid, now_ms, size, result, used)

    def _record_meter_stat(self, user, template_id, result, size):
        """按用户与模板标识各记一次计量事件，O(1) 时空。

        通过累加次数与 size 字节，拒绝/下线仅累加各自次数。
        """
        for stats, ident in (
            (self._meter_stats_user, user),
            (self._meter_stats_template, template_id),
        ):
            entry = stats.get(ident)
            if entry is None:
                entry = stats[ident] = [0, 0, 0, 0]
            if result == "通过":
                entry[0] += 1
                entry[3] += size
            elif result == "拒绝":
                entry[1] += 1
            else:
                entry[2] += 1

    def meter_stats(self, now_ms, group="用户"):
        """返回计量统计 JSON；先验参再按既有规则老化。

        now_ms 为非 bool 非负 int，group 须为 str 且仅“用户”或“模板”，
        类型错 TypeError、取值错 ValueError。用户组按会话用户归集，模板组
        按查询时生效绑定归集、未绑定归入空串标识；输出有历史计数或当前
        在线（老化后恰为在线）会话的组，按标识 Unicode 码点升序。顶层键序
        为“时刻/分组/汇总”，项键序为“标识/在线/通过/拒绝/下线/通过字节”，
        LF 结尾紧凑 JSON。查询 O(S+GlogG) 时间、O(G) 空间。
        """
        _check_int("now_ms", now_ms, 0)
        if not isinstance(group, str):
            raise TypeError(f"group must be a str, got {type(group).__name__}")
        if group not in ("用户", "模板"):
            raise ValueError(f"group must be 用户 or 模板, got {group!r}")
        self._age(now_ms)

        # 当前在线会话按组归集计数。
        online = {}
        for session in self._sessions.values():
            if session["state"] != _STATE_ONLINE:
                continue
            if group == "用户":
                ident = session["user"]
            else:
                ident = self._user_templates.get(session["user"], "")
            online[ident] = online.get(ident, 0) + 1

        stats = self._meter_stats_user if group == "用户" else (
            self._meter_stats_template
        )
        summary = []
        for ident in sorted(set(online) | set(stats)):
            passed, denied, offlined, passed_bytes = stats.get(ident, (0, 0, 0, 0))
            summary.append(
                {
                    "标识": ident,
                    "在线": online.get(ident, 0),
                    "通过": passed,
                    "拒绝": denied,
                    "下线": offlined,
                    "通过字节": passed_bytes,
                }
            )
        payload = {"时刻": now_ms, "分组": group, "汇总": summary}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def quota_stats(self, user, now_ms):
        """返回用户所绑模板的配额只读快照 JSON，O(1) 时空。

        user 沿用凭据约束，now_ms 为非 bool 非负 int；类型错 TypeError、
        取值错 ValueError，未知用户抛 KeyError，未绑模板或 now_ms 早于账本
        上次通过时刻抛 StateError。查询不老化、不建账、不改账；无账本按
        累计 0、满桶返回。键序为“时刻/用户/模板/累计/剩余/令牌”：累计为
        当前周期窗内有效累计（模板周期毫秒 P>0 且 now_ms//P != t//P 时为
        0，否则为账本 u；P=0 恒为 u），剩余为 max(0, 配额-有效累计)，令牌
        为自 t 按限速补充并以桶容截顶后的千分字节数（只读演算，不落账，跨
        周期不清零）。
        """
        _check_credential("user", user)
        _check_int("now_ms", now_ms, 0)
        if user not in self._auth:
            raise KeyError(f"unknown user: {user!r}")
        template_id = self._user_templates.get(user)
        if template_id is None:
            raise StateError(f"no qos template bound for user {user!r}")
        rate, burst, quota, period_ms, _session_limit, _priority, _exceed = (
            self._templates[template_id]
        )
        capacity = (rate + burst) * 1000
        ledger = self._meter_ledgers.get((user, template_id))
        if ledger is None:
            # 无账本：有效累计 0、满桶，时刻即此刻（不可能触发时刻回拨）。
            used, last, tokens = 0, now_ms, capacity
        else:
            used, last, tokens = ledger
        if now_ms < last:
            raise StateError(
                f"now_ms {now_ms} before last meter time {last} for user {user!r}"
            )
        tokens = min(capacity, tokens + rate * (now_ms - last))
        used = _effective_used(used, last, now_ms, period_ms)
        payload = {
            "时刻": now_ms,
            "用户": user,
            "模板": template_id,
            "累计": used,
            "剩余": max(0, quota - used),
            "令牌": tokens,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _account_location(self, session):
        """会话当前持址快照 (地址池, 地址)：无址（挂起或在线租期到期）为
        ("", "")，持址为 (池标识, 规范 IPv4 串)。"""
        if session["ip"] is None:
            return "", ""
        return session["pool"], str(ipaddress.IPv4Address(session["ip"]))

    @staticmethod
    def _account_hash(
        seq, kind, now_ms, sid, user, pool_id, address, total, reason, prev_hash
    ):
        """计费哈希：前哈希与本条前九项（序号/类型/时刻/会话/用户/地址池/
        地址/累计字节/原因/前哈希）的紧凑 JSON（无 LF）之 UTF-8 字节
        sha256 小写十六进制串。"""
        head = {
            "序号": seq,
            "类型": kind,
            "时刻": now_ms,
            "会话": sid,
            "用户": user,
            "地址池": pool_id,
            "地址": address,
            "累计字节": total,
            "原因": reason,
            "前哈希": prev_hash,
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _account_append(self, kind, sid, user, pool_id, address, total,
                        reason, now_ms):
        """追加一条计费事件（序号自 1），O(1) 时空，返回十一元组。

        前哈希首项为 64 个 0，余取前项哈希；事件时刻允许回拨，链接只认追加
        序。仅由各业务提交点与 accounting_interim 调用。
        """
        seq = len(self._account_events) + 1
        prev_hash = self._account_tail
        digest = self._account_hash(
            seq, kind, now_ms, sid, user, pool_id, address, total, reason,
            prev_hash,
        )
        event = (
            seq, kind, now_ms, sid, user, pool_id, address, total, reason,
            prev_hash, digest,
        )
        self._account_events.append(event)
        self._account_tail = digest
        return event

    def _account_start(self, sid, now_ms):
        """会话建立成功（do 建立/capacity 立即建立与晋升/批量上线提交项）后
        原子开账：按当前持址追加累计 0、原因空串的开始事件并建活动账。"""
        session = self._sessions[sid]
        pool_id, address = self._account_location(session)
        user = session["user"]
        self._account_append(
            _ACCOUNT_START, sid, user, pool_id, address, 0, "", now_ms
        )
        # 活动账三元组：累计字节、用户、最近计费时刻（开始/中间事件时刻）。
        self._account_active[sid] = [0, user, now_ms]

    def _account_stop(self, sid, now_ms, reason):
        """会话停止（显式下线/批量下线/强制停用/QoS 超限/接管旧会话）前
        原子结账：按当前持址与累计追加停止事件并销活动账。

        须在清场（置下线、释址）之前调用；挂起会话无址，池址记 ""。下线
        墓碑无活动账（停止事件已在首次清场时追加），为空操作。
        """
        account = self._account_active.get(sid)
        if account is None:
            return
        pool_id, address = self._account_location(self._sessions[sid])
        self._account_append(
            _ACCOUNT_STOP, sid, account[1], pool_id, address, account[0],
            reason, now_ms,
        )
        del self._account_active[sid]

    def _account_add_bytes(self, sid, size, now_ms):
        """meter 通过后把 size 字节计入该会话活动账；不产生事件、不改最近
        计费时刻。仅由 _meter 通过分支调用，会话必在线。旧检查点（v1 service/
        runtime/creplay）恢复的遗留会话无开始事件：首次计费时惰性建账（累计
        从本次起、不补开始事件）。"""
        account = self._account_active.get(sid)
        if account is None:
            self._account_active[sid] = [size, self._sessions[sid]["user"], now_ms]
        else:
            account[0] += size

    def accounting_interim(self, key, sid, now_ms):
        """对活动会话生成一条累计（中间）计费事件，返回该事件的 LF 结尾
        紧凑 JSON（十一键，键序同 accounting_events 事件项）。

        key/sid 沿用凭据约束，now_ms 为非 bool 非负 int：类型错 TypeError、
        取值错 ValueError。首果（成功或异常）以独立域永久缓存：同型同参
        重放不老化、不重复记账、原样返回或重抛，异参复用抛 ValueError。
        首次合法调用先老化（与 meter 同序）；未知 sid 抛 KeyError，非在线
        会话（挂起/下线墓碑）抛 StateError，now_ms 早于该会话最近计费时刻
        （开始或上一中间时刻）抛 StateError；中间事件原因恒为空串，累计为
        该会话仅由 meter 通过累计的字节数，池址取当前持址（无址为 ""）。
        """
        _check_credential("key", key)

        cached = self._account_interim_cache.get(key)
        if cached is not None:
            # 重放：不老化、不记账、不追加事件，仅按缓存返回或重抛。
            c_sid, c_now_ms, outcome = cached
            if not _strict_equal((sid, now_ms), (c_sid, c_now_ms)):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise _replay_exception(exc_class, exc_args)

        # 新 key：余参校验本身的异常同样入缓存。
        try:
            _check_credential("sid", sid)
            _check_int("now_ms", now_ms, 0)
        except (TypeError, ValueError) as exc:
            self._account_interim_cache[key] = (
                sid, now_ms, ("err", (type(exc), exc.args))
            )
            raise

        # 首次合法调用：先老化（与 meter 同序）；到期在线会话挂起释址后
        # 按非在线会话抛 StateError。
        self._age(now_ms)
        session = self._sessions.get(sid)
        if session is None:
            exc = KeyError(f"unknown sid: {sid!r}")
            self._account_interim_cache[key] = (
                sid, now_ms, ("err", (type(exc), exc.args))
            )
            raise exc
        account = self._account_active.get(sid)
        if session["state"] != _STATE_ONLINE:
            exc = StateError(
                f"cannot account sid {sid!r} in state {session['state']!r}"
            )
            self._account_interim_cache[key] = (
                sid, now_ms, ("err", (type(exc), exc.args))
            )
            raise exc
        if account is None:
            # 旧检查点（v1 service/runtime/creplay）恢复的遗留在线会话无开始
            # 事件：首次中间计费惰性建账，不补开始事件。
            account = self._account_active[sid] = [
                0, session["user"], now_ms
            ]
        if now_ms < account[2]:
            exc = StateError(
                f"now_ms {now_ms} before last accounting time {account[2]} "
                f"for sid {sid!r}"
            )
            self._account_interim_cache[key] = (
                sid, now_ms, ("err", (type(exc), exc.args))
            )
            raise exc

        pool_id, address = self._account_location(session)
        account[2] = now_ms
        event = self._account_append(
            _ACCOUNT_INTERIM, sid, account[1], pool_id, address, account[0],
            "", now_ms,
        )
        result = self._render_account_event(event)
        self._account_interim_cache[key] = (sid, now_ms, ("ok", result))
        return result

    @staticmethod
    def _account_event_dict(event):
        """计费事件十一元组 → 十一键 dict（固定键序）。"""
        seq, kind, now_ms, sid, user, pool_id, address, total, reason, \
            prev_hash, digest = event
        return {
            "序号": seq,
            "类型": kind,
            "时刻": now_ms,
            "会话": sid,
            "用户": user,
            "地址池": pool_id,
            "地址": address,
            "累计字节": total,
            "原因": reason,
            "前哈希": prev_hash,
            "哈希": digest,
        }

    @classmethod
    def _render_account_event(cls, event):
        """计费事件十一元组 → 十一键 LF 尾紧凑 JSON（固定键序）。"""
        return (
            json.dumps(
                cls._account_event_dict(event),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )

    def accounting_events(self, after=0, limit=100):
        """只读分页返回计费哈希链事件的 LF 结尾紧凑 JSON，不老化、不改态。

        after 为非 bool 非负 int，limit 为非 bool int 且 1..1000：类型错抛
        TypeError，范围错抛 ValueError。取序号 > after 的前 limit 项，序号
        即位置，切片 O(limit)。顶层键序固定为
        “版本/起点/下页/事件/尾序号/尾哈希”：版本恒为 1，起点为 after，
        下页为末项序号、空页为 after（链尾后返回空页），尾序号为链长、
        尾哈希为链末哈希（空链为 64 个 0）。事件项十一键，顺序为
        序号/类型/时刻/会话/用户/地址池/地址/累计字节/原因/前哈希/哈希；
        开始与中间原因为空串，停止原因为下线/批量下线/停用/配额/接管。
        同状态逐字节一致，时空均为 O(limit)。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        window = self._account_events[after : after + limit]
        events = [self._account_event_dict(event) for event in window]
        next_cursor = window[-1][0] if window else after
        payload = {
            "版本": 1,
            "起点": after,
            "下页": next_cursor,
            "事件": events,
            "尾序号": len(self._account_events),
            "尾哈希": self._account_tail,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _auth_payload(self, now_ms):
        """组装认证器检查点文档 dict（顶层键序：版本/时刻/用户/摘要）。

        版本恒为 2；用户按用户名 Unicode 码点升序，项键序
        “用户/凭据/失败/锁定至/下次可试/停用”；凭据为
        sha256(user+"\\0"+password) 摘要字节的 64 位小写十六进制串；失败、
        锁定至与下次可试原样取自认证记录（不清到期锁/退避、不按当前 max_fail
        折算），停用取自停用态集合；摘要为前三键紧凑 JSON（无 LF）UTF-8 字节
        的 sha256 小写十六进制串。纯渲染：不老化、不清到期锁与退避、不改态。
        """
        users = [
            {
                "用户": user,
                "凭据": digest.hex(),
                "失败": failed,
                "锁定至": until,
                "下次可试": retry_at,
                "停用": user in self._disabled_users,
            }
            for user, (digest, failed, until, retry_at)
            in sorted(self._auth._users.items())
        ]
        doc = {"版本": 2, "时刻": now_ms, "用户": users}
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return doc

    def _auth_checkpoint_text(self, now_ms):
        """认证器检查点的 LF 结尾紧凑 JSON（基线序列化，不老化、不改态）。"""
        return json.dumps(
            self._auth_payload(now_ms), ensure_ascii=False, separators=(",", ":")
        ) + "\n"

    def auth_checkpoint(self, now_ms):
        """只读输出认证器检查点的 LF 结尾基线 JSON，O(U log U) 时间、O(U)
        空间；不认证、不老化、不清到期锁与退避、不审计、不动各域缓存。

        now_ms 限非 bool 非负 int：类型错 TypeError、取值错 ValueError。
        顶层依次为“版本/时刻/用户/摘要”：版本恒为 2，时刻为 now_ms；用户
        为按用户名 Unicode 码点升序的列表，项键序
        “用户/凭据/失败/锁定至/下次可试/停用”——用户为凭据约束串，凭据为
        64 位小写十六进制摘要，失败为非 bool 非负 int，锁定至为 null 或非
        bool 非负 int，下次可试为非 bool 非负 int（0 表示无退避；锁定已到期、
        失败为 0 或退避已过亦原样导出，不按当前 max_fail 或退避策略校验、清零
        或折算），停用为 bool；摘要为前三键紧凑 JSON（无 LF）UTF-8 字节的
        sha256 小写值。同态同时刻查询逐字节相同。
        """
        _check_int("now_ms", now_ms, 0)
        return self._auth_checkpoint_text(now_ms)

    def auth_restore(self, key, text):
        """按认证器检查点原子替换全部用户的凭据、失败计数、锁定至、下次可试
        时刻与停用态，返回替换后检查点（版本 2 规范包）的 LF 结尾基线 JSON。

        key 沿凭据约束，text 须为 str：key 型/值错抛 TypeError/ValueError，
        text 非 str 抛 TypeError。接受版本 1 与版本 2 文档：版本 1 用户项无
        “下次可试”，恢复时补 0（无退避）；版本 2 须含该键并纳入摘要。JSON
        解析、重键、键集/键序、结构、类型、取值范围、用户排序或重复、版本或
        摘要错均抛 ValueError；检查点用户集与当前认证器不完全一致（多、少或
        不同）抛 ResourceError。全部校验通过后原子替换认证器的用户记录（凭据
        摘要、失败、锁定至、下次可试）与停用态集合；认证策略 max_fail/
        lock_ms/重试两项不变，失败、锁定至与下次可试不依当前策略折算、原样
        往返，后续认证沿既有规则（锁定未到即 locked、退避未到即 backoff、到
        刻先清零再验密）。会话、租约、队列、统计、配置及其余各域缓存均不变；
        任何失败不改实例、不老化、不审计。版本 1 输入的返回值为版本 2 规范
        包，与原文字节不同；版本 2 输入逐字节往返。

        重放缓存与各域独立：仅缓存首次成功，同 key 同型同 text 重放不解析、
        不重验、不替换，直接返回首次规范包原字节，异参（含异型）抛
        ValueError；失败（含参数错与 ResourceError）不占 key。首次
        O(U log U) 时间、O(U) 空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._auth_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text 后返回缓存原字节。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        # 全部校验在新数据上进行，通过后一次性替换；任何失败实例不变。
        now_ms, rows = self._parse_auth_checkpoint(text)
        current_users = set(self._auth._users)
        checkpoint_users = {
            user
            for user, _digest, _failed, _until, _retry_at, _disabled in rows
        }
        if checkpoint_users != current_users:
            raise ResourceError(
                "auth checkpoint user set does not match the current authenticator"
            )

        # 全验后原子替换认证器用户记录与停用态；认证策略四项不变。
        new_users = {
            user: [digest, failed, until, retry_at]
            for user, digest, failed, until, retry_at, _disabled in rows
        }
        self._auth._users = new_users
        self._disabled_users = {
            user
            for user, _digest, _failed, _until, _retry_at, disabled in rows
            if disabled
        }

        result = self._auth_checkpoint_text(now_ms)
        self._auth_restore_cache[key] = (text, result)
        return result

    def _parse_auth_checkpoint(self, text):
        """解析并全量校验认证器检查点文本，返回
        (时刻, [(用户, 凭据bytes, 失败, 锁定至, 下次可试, 停用), ...])；任何
        文本非法均抛 ValueError。

        顶层须恰含“版本/时刻/用户/摘要”且键序如此；版本为非 bool int 且仅
        接受 1 或 2，时刻为非 bool 非负 int。版本 2 用户项键序为
        “用户/凭据/失败/锁定至/下次可试/停用”，版本 1 为
        “用户/凭据/失败/锁定至/停用”（恢复时下次可试补 0）。用户为凭据约束
        串，凭据为 64 位小写十六进制串，失败为非 bool 非负 int，锁定至为
        null 或非 bool 非负 int，下次可试为非 bool 非负 int，停用为 bool，
        行按用户 Unicode 码点严格升序、无重复；失败、锁定至与下次可试仅做非
        bool 非负校验，不依当前策略折算。摘要须为同版本规范化前三键紧凑 JSON
        （无 LF）UTF-8 字节的 sha256 小写值（与原文排版无关）：版本 1 文档
        按版本 1 用户项五键验摘，版本 2 按六键验摘。仅做结构自洽校验；用户
        集与当前认证器一致由调用方判定（ResourceError）。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"auth checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("auth checkpoint top level must be an object")
        if list(doc) != ["版本", "时刻", "用户", "摘要"]:
            raise ValueError(
                "auth checkpoint top-level keys must be 版本/时刻/用户/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version not in (1, 2):
            raise ValueError(f"版本 must be 1 or 2, got {version}")
        now_ms = self._cp_int(doc["时刻"], "时刻", 0)

        users_raw = doc["用户"]
        if not isinstance(users_raw, list):
            raise ValueError("用户 must be a list")
        rows = []
        last_user = None
        expected_keys = (
            ["用户", "凭据", "失败", "锁定至", "下次可试", "停用"]
            if version == 2
            else ["用户", "凭据", "失败", "锁定至", "停用"]
        )
        for index, item in enumerate(users_raw, start=1):
            if not isinstance(item, dict) or list(item) != expected_keys:
                if version == 2:
                    raise ValueError(
                        f"user {index} keys must be "
                        "用户/凭据/失败/锁定至/下次可试/停用 in order"
                    )
                raise ValueError(
                    f"user {index} keys must be 用户/凭据/失败/锁定至/停用 in order"
                )
            user = self._cp_str(item["用户"], "用户.用户")
            credential_hex = self._cp_hex64(item["凭据"], "用户.凭据")
            failed = item["失败"]
            if isinstance(failed, bool) or not isinstance(failed, int):
                raise ValueError(
                    f"用户.失败 must be an int, got {type(failed).__name__}"
                )
            if failed < 0:
                raise ValueError(f"用户.失败 must be >= 0, got {failed}")
            until = item["锁定至"]
            if until is not None:
                until = self._cp_int(until, "用户.锁定至", 0)
            if version == 2:
                retry_at = self._cp_int(item["下次可试"], "用户.下次可试", 0)
            else:
                # 版本 1 恢复：下次可试补 0（无退避）。
                retry_at = 0
            disabled = item["停用"]
            if not isinstance(disabled, bool):
                raise ValueError(
                    f"用户.停用 must be a bool, got {type(disabled).__name__}"
                )
            if last_user is not None and user <= last_user:
                raise ValueError(
                    "user rows must be strictly sorted by 用户 ascending "
                    "with no duplicates"
                )
            last_user = user
            rows.append(
                (
                    user,
                    bytes.fromhex(credential_hex),
                    failed,
                    until,
                    retry_at,
                    disabled,
                )
            )

        summary = self._cp_hex64(doc["摘要"], "摘要")
        # 摘要：按文档版本重建同形态前三键（版本 1 五项、版本 2 六项），数值
        # 相等即与生成方基线逐字节一致。
        if version == 2:
            canonical_users = [
                {
                    "用户": user,
                    "凭据": digest.hex(),
                    "失败": failed,
                    "锁定至": until,
                    "下次可试": retry_at,
                    "停用": disabled,
                }
                for user, digest, failed, until, retry_at, disabled in rows
            ]
        else:
            canonical_users = [
                {
                    "用户": user,
                    "凭据": digest.hex(),
                    "失败": failed,
                    "锁定至": until,
                    "停用": disabled,
                }
                for user, digest, failed, until, _retry_at, disabled in rows
            ]
        canonical_head = {
            "版本": version,
            "时刻": now_ms,
            "用户": canonical_users,
        }
        blob = json.dumps(canonical_head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical auth checkpoint")
        return now_ms, rows

    def _quota_checkpoint_text(self):
        """导出模板仍存在的全部现存账本的检查点文本（不老化、不建账、不改账）。

        顶层依次为“版本/账本”，版本 1；项依次为
        [用户, 模板, 累计, 上次, 令牌]，整数非 bool 且 >= 0，按用户、模板
        Unicode 码点升序。已删模板的历史账本不在导出范围。
        """
        rows = [
            [user, template_id, used, last, tokens]
            for (user, template_id), (used, last, tokens)
            in sorted(self._meter_ledgers.items())
            if template_id in self._templates
        ]
        payload = {"版本": 1, "账本": rows}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def quota_checkpoint(self):
        """返回共享 QoS 账本检查点的 LF 结尾紧凑 JSON，O(L log L) 时间、
        O(L) 空间；查询不老化、不建账、不改账、不审计。

        顶层键序为“版本/账本”，版本为 1；账本项为五元列表
        [用户, 模板, 累计, 上次, 令牌]，按用户、模板 Unicode 码点升序，
        整数为非 bool 非负 int。仅导出模板仍存在的全部账本（用户可已改绑
        该模板）；已删模板的历史账本不导出，恢复时亦不变。
        """
        return self._quota_checkpoint_text()

    def quota_restore(self, key, text):
        """按检查点原子替换模板仍存在的共享 QoS 账本，返回替换后的检查点。

        key 沿用凭据约束，text 须为 str；类型错抛 TypeError、取值错抛
        ValueError。重放缓存与各域独立：仅缓存首次成功结果，同型同 text
        重放不验参、不替换，直接返回缓存检查点，异参抛 ValueError；任何
        失败（含参数错）不占 key。

        解析失败、重键、键序/键集/结构/类型/数值、版本、排序或重复非法
        均抛 ValueError；引用未注册用户或当前不存在的模板标识抛
        ResourceError（用户可未绑定该模板）；现存模板的令牌不得超过其
        (限速+突发)*1000，超出为数值非法 ValueError。全部校验通过后原子
        替换模板仍存在的账本；已删模板的历史账本原样保留；任何失败不改
        实例（不老化、不建账、不审计、不改统计与配置）。恢复后 meter
        沿用账本三值，quota_stats 按当前绑定取账。首次 O(L log L) 时间、
        O(L) 空间，重放 O(1)（直接返回缓存检查点）。
        """
        _check_credential("key", key)

        cached = self._quota_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text 后返回缓存结果。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        # 全部校验在新字典上进行，通过后一次性替换；任何失败实例不变。
        rows = self._parse_quota_checkpoint(text)
        for user, template_id, _used, _last, tokens in rows:
            if user not in self._auth:
                raise ResourceError(
                    f"quota checkpoint references unregistered user: {user!r}"
                )
            template = self._templates.get(template_id)
            if template is None:
                raise ResourceError(
                    f"quota checkpoint references unknown template: {template_id!r}"
                )
            if tokens > (template[0] + template[1]) * 1000:
                raise ValueError(
                    f"令牌 for {(user, template_id)!r} exceeds template bucket "
                    f"capacity {(template[0] + template[1]) * 1000}"
                )

        # 原子替换：检查点仅覆盖模板仍存在的账本，已删模板的历史账本原样保留。
        new_ledgers = {
            ledger_key: ledger
            for ledger_key, ledger in self._meter_ledgers.items()
            if ledger_key[1] not in self._templates
        }
        for user, template_id, used, last, tokens in rows:
            new_ledgers[(user, template_id)] = [used, last, tokens]
        self._meter_ledgers = new_ledgers

        result = self._quota_checkpoint_text()
        self._quota_restore_cache[key] = (text, result)
        return result

    def _parse_quota_checkpoint(self, text):
        """解析并全量校验共享账本检查点文本，返回规范化五行元组列表
        (用户, 模板, 累计, 上次, 令牌)；任何文本非法均抛 ValueError。

        仅做结构自洽与数值校验；用户注册、模板存在与令牌上限由调用方按
        实例现状判定（ResourceError/ValueError）。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"quota checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("quota checkpoint top level must be an object")
        # 键集与键序：恰为“版本/账本”且版本先于账本（dict 保序）。
        if list(doc) != ["版本", "账本"]:
            raise ValueError("quota checkpoint top-level keys must be 版本 then 账本")
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        rows_raw = doc["账本"]
        if not isinstance(rows_raw, list):
            raise ValueError("账本 must be a list")

        rows = []
        last_key = None
        for index, item in enumerate(rows_raw, start=1):
            if not isinstance(item, list) or len(item) != 5:
                raise ValueError(
                    f"ledger {index} must be a list of 5 elements "
                    "[用户, 模板, 累计, 上次, 令牌]"
                )
            user, template_id, used, last, tokens = item
            try:
                _check_credential("用户", user)
                _check_credential("模板", template_id)
            except (TypeError, ValueError) as exc:
                # 含孤代理等引发的 UnicodeEncodeError（ValueError 子类），
                # 统一归为文本 ValueError。
                raise ValueError(str(exc)) from exc
            for label, value in (
                ("累计", used),
                ("上次", last),
                ("令牌", tokens),
            ):
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(
                        f"{label} must be an int, got {type(value).__name__}"
                    )
                if value < 0:
                    raise ValueError(f"{label} must be >= 0, got {value}")
            ledger_key = (user, template_id)
            if last_key is not None and ledger_key <= last_key:
                raise ValueError(
                    "ledger rows must be strictly sorted by 用户 then 模板 "
                    "ascending with no duplicates"
                )
            last_key = ledger_key
            rows.append((user, template_id, used, last, tokens))
        return rows

    def fault(self, key, op, ms, now_ms):
        """注入或恢复后端故障，返回 LF 结尾的 JSON 字符串。

        key 沿用凭据约束；op 仅“注入/恢复”：注入 ms 为非 bool 正 int，
        恢复 ms 须为 None；now_ms 为非 bool 非负 int，类型错 TypeError、
        取值错 ValueError。注入置故障截至为 now_ms+ms，恢复清零；二者
        均清空全部用户退避。返回基线 LF 尾 JSON，键序“状态/时刻/截至”，
        注入为 故障/now_ms/now_ms+ms，恢复为 正常/now_ms/0。key 首果
        （含验参异常）永久缓存，同参重放直接返回或重抛，异参抛
        ValueError；缓存与 do/meter/capacity 分域。fault 不审计。
        """
        _check_credential("key", key)

        cached = self._fault_cache.get(key)
        if cached is not None:
            # 重放：不改故障态与退避，仅按缓存返回或重抛。
            c_op, c_ms, c_now_ms, outcome = cached
            if not _strict_equal((op, ms, now_ms), (c_op, c_ms, c_now_ms)):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存。
        try:
            self._validate_fault_params(op, ms, now_ms)
        except (TypeError, ValueError) as exc:
            self._fault_cache[key] = (
                op,
                ms,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 注入与恢复均清空全部用户退避。
        self._backoff.clear()
        if op == _OP_INJECT:
            self._fault_until = now_ms + ms
            result = self._render_fault(_BACKEND_FAULT, now_ms, self._fault_until)
        else:
            self._fault_until = 0
            result = self._render_fault(_BACKEND_NORMAL, now_ms, 0)
        self._fault_cache[key] = (op, ms, now_ms, ("ok", result))
        return result

    @staticmethod
    def _validate_fault_params(op, ms, now_ms):
        """校验 fault 三参数：op 限注入/恢复，注入 ms 为正 int、恢复 ms=None。"""
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op not in (_OP_INJECT, _OP_RECOVER):
            raise ValueError(f"op must be one of 注入/恢复, got {op!r}")
        if op == _OP_INJECT:
            _check_int("ms", ms, 1)
        elif ms is not None:
            raise ValueError(f"ms must be None for 恢复, got {ms!r}")
        _check_int("now_ms", now_ms, 0)

    @staticmethod
    def _render_fault(state, now_ms, until):
        # 键序：状态、时刻、截至；状态为 str，余为 int。
        payload = {"状态": state, "时刻": now_ms, "截至": until}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _backend_payload(self, now_ms):
        """组装后端故障态检查点文档 dict（顶层键序：
        版本/时刻/截至/退避/失败/摘要）。

        退避按用户 Unicode 码点升序，项键序“用户/次数/下次”；失败键序
        “故障/退避”；摘要为前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256
        小写十六进制串。纯渲染：不老化、不清到期退避、不改态。
        """
        backoff = [
            {"用户": user, "次数": n, "下次": retry_at}
            for user, (n, retry_at) in sorted(self._backoff.items())
        ]
        doc = {
            "版本": 1,
            "时刻": now_ms,
            "截至": self._fault_until,
            "退避": backoff,
            "失败": {"故障": self._fault_fail[0], "退避": self._fault_fail[1]},
        }
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return doc

    def _backend_checkpoint_text(self, now_ms):
        """后端故障态检查点的 LF 结尾紧凑 JSON（基线序列化，不老化、不改态）。"""
        return json.dumps(
            self._backend_payload(now_ms), ensure_ascii=False, separators=(",", ":")
        ) + "\n"

    def backend_checkpoint(self, now_ms):
        """只读输出后端故障态检查点的 LF 结尾基线 JSON，O(U log U) 时间、
        O(U) 空间；不认证、不老化、不清到期退避、不审计、不动各域缓存。

        now_ms 限非 bool 非负 int：类型错 TypeError、取值错 ValueError。
        顶层依次为“版本/时刻/截至/退避/失败/摘要”：版本恒为 1，时刻为
        now_ms，截至为当前故障截至（0 为无故障）；退避为按用户 Unicode
        码点升序的列表，项键序“用户/次数/下次”，次数为 >0 的非 bool int、
        下次为 >=0 的非 bool int；失败为对象，键序“故障/退避”，值均为
        >=0 的非 bool int；摘要为前五键紧凑 JSON（无 LF）UTF-8 字节的
        sha256 小写值。同态同时刻查询逐字节相同。
        """
        _check_int("now_ms", now_ms, 0)
        return self._backend_checkpoint_text(now_ms)

    def backend_restore(self, key, text):
        """按后端故障态检查点原子替换故障截至、按用户退避与失败计数，返回
        替换后检查点（规范包）的 LF 结尾基线 JSON。

        key 沿用凭据约束，text 须为 str：key 型/值错抛 TypeError/ValueError，
        text 非 str 抛 TypeError。JSON 解析、重键、键集/键序、结构、类型、
        取值范围、退避排序或重复用户、版本或摘要错均抛 ValueError；退避项
        引用未注册用户抛 ResourceError。全部校验通过后原子替换截至、退避与
        失败计数（二者之外的认证器、会话、租约、队列及各域缓存均不变）；
        任何失败不改实例、不审计。不老化。

        重放缓存与各域独立：仅缓存首次成功，同 key 同型同 text 重放不解析、
        不重验、不替换，直接返回首次规范包原字节，异参抛 ValueError；失败
        （含参数错）不占 key。首次成功及成功的同参重放写现有防篡改审计链：
        操作“后端恢复”、会话记空串，首次结果“成功”、原序号 0，重放结果
        “重放”、原序号指认首次；事件时刻取检查点“时刻”（接口无时钟参数）；
        参数与文本异常不记。首次 O(U log U) 时间、O(U) 空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._backend_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text，追加重放审计后
            # 返回缓存规范包原字节；时刻随缓存保存，重放 O(1)。
            c_text, result, c_now_ms = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            self._chain_append(
                key,
                _BACKEND_RESTORE_OP,
                "",
                "重放",
                c_now_ms,
                self._backend_restore_chain_index[key],
                self._backend_restore_chain_index,
            )
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        # 全部校验在新数据上进行，通过后一次性替换；任何失败实例不变。
        now_ms, until, backoff_rows, fail = self._parse_backend_checkpoint(text)
        for user, _n, _retry_at in backoff_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"backend checkpoint references unregistered user: {user!r}"
                )

        # 全验后原子替换截至、退避与失败计数；退避存活储为 (n, retry_at) 元组。
        self._fault_until = until
        self._backoff = {
            user: (n, retry_at) for user, n, retry_at in backoff_rows
        }
        self._fault_fail = [fail[0], fail[1]]

        result = self._backend_checkpoint_text(now_ms)
        self._backend_restore_cache[key] = (text, result, now_ms)
        self._chain_append(
            key,
            _BACKEND_RESTORE_OP,
            "",
            "成功",
            now_ms,
            index=self._backend_restore_chain_index,
        )
        return result

    def _parse_backend_checkpoint(self, text):
        """解析并全量校验后端故障态检查点文本，返回
        (时刻, 截至, 退避行三元组列表 (用户,次数,下次), (失败故障,失败退避))；
        任何文本非法均抛 ValueError。

        顶层须恰含“版本/时刻/截至/退避/失败/摘要”且键序如此；版本为 1，
        时刻/截至为非 bool 非负 int；退避项键序“用户/次数/下次”，用户为
        凭据约束串，次数为非 bool 正 int、下次为非 bool 非负 int，行按用户
        Unicode 码点严格升序、无重复；失败键序“故障/退避”，均为非 bool
        非负 int；摘要须为规范化前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256
        小写值（与原文排版无关）。仅做结构自洽校验；用户注册由调用方判定。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"backend checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("backend checkpoint top level must be an object")
        if list(doc) != ["版本", "时刻", "截至", "退避", "失败", "摘要"]:
            raise ValueError(
                "backend checkpoint top-level keys must be "
                "版本/时刻/截至/退避/失败/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        now_ms = self._cp_int(doc["时刻"], "时刻", 0)
        until = self._cp_int(doc["截至"], "截至", 0)

        backoff_raw = doc["退避"]
        if not isinstance(backoff_raw, list):
            raise ValueError("退避 must be a list")
        backoff_rows = []
        last_user = None
        for index, item in enumerate(backoff_raw, start=1):
            if not isinstance(item, dict) or list(item) != ["用户", "次数", "下次"]:
                raise ValueError(
                    f"backoff {index} keys must be 用户/次数/下次 in order"
                )
            user = self._cp_str(item["用户"], "退避.用户")
            n = item["次数"]
            if isinstance(n, bool) or not isinstance(n, int):
                raise ValueError(
                    f"退避.次数 must be an int, got {type(n).__name__}"
                )
            if n <= 0:
                raise ValueError(f"退避.次数 must be > 0, got {n}")
            retry_at = self._cp_int(item["下次"], "退避.下次", 0)
            if last_user is not None and user <= last_user:
                raise ValueError(
                    "backoff rows must be strictly sorted by 用户 ascending "
                    "with no duplicates"
                )
            last_user = user
            backoff_rows.append((user, n, retry_at))

        fail_raw = doc["失败"]
        if not isinstance(fail_raw, dict) or list(fail_raw) != ["故障", "退避"]:
            raise ValueError("失败 keys must be 故障/退避 in order")
        fault_fail = self._cp_int(fail_raw["故障"], "失败.故障", 0)
        backoff_fail = self._cp_int(fail_raw["退避"], "失败.退避", 0)
        summary = self._cp_hex64(doc["摘要"], "摘要")

        # 摘要：用规范化值重建前五键（数值相等即与生成方基线逐字节一致）。
        canonical_head = {
            "版本": 1,
            "时刻": now_ms,
            "截至": until,
            "退避": [
                {"用户": user, "次数": n, "下次": retry_at}
                for user, n, retry_at in backoff_rows
            ],
            "失败": {"故障": fault_fail, "退避": backoff_fail},
        }
        blob = json.dumps(canonical_head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical backend checkpoint")
        return now_ms, until, backoff_rows, (fault_fail, backoff_fail)

    def pool_fault(self, key, op, pool, ms, now_ms):
        """对指定地址池注入可恢复耗尽演练或恢复，返回 LF 结尾 JSON。

        不改真实租约与配置，仅令该池在注入期被视为无可分配地址。key/pool
        沿用凭据约束；op 仅“注入/恢复”：注入 ms 为非 bool 正 int，置截至
        = now_ms+ms，恢复 ms 须为 None 并清零（移除演练）；now_ms 为非 bool
        非负 int。类型、值、未知池错依次抛 TypeError、ValueError、KeyError，
        校验失败不改池状态。后续同池调用可覆盖。now_ms < 截至时该池无可
        分配地址、到刻（含同刻）自动正常；既有租约、续租、下线及从该池迁出
        不受影响，建立、迁入、无址接管在既有认证与老化后抛 ResourceError，
        capacity 申请排队、推进跳过，均不半分配。

        成功 JSON 键序“池/状态/时刻/截至”，状态仅“耗尽/正常”，恢复截至为 0。
        验 key 后以独立域（与 do/meter/capacity/fault 分域）永久缓存余参与
        首次成败（含验参异常与未知池）：同参重放不改状态、直接返回或重抛，
        异参抛 ValueError。首次成功及成功的同参重放写现有防篡改审计链：
        操作“池注入/池恢复”、会话记 pool，结果“成功/重放”，重放原序号沿用
        首次；异常不记。配置加载/回滚成功后保留同名池故障、清除已删池。
        故障判定与变更均 O(1) 时空。
        """
        _check_credential("key", key)

        cached = self._pool_fault_cache.get(key)
        if cached is not None:
            # 重放：不改池故障态，仅按缓存返回或重抛。
            c_op, c_pool, c_ms, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, pool, ms, now_ms), (c_op, c_pool, c_ms, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 仅首次成功的同参重放入链记“重放”，原序号沿用首次；
            # 首次异常不在本域链索引中，自然跳过。
            origin = self._pool_fault_chain_index.get(key)
            if origin is not None:
                chain_op = (
                    _POOL_OP_INJECT if c_op == _OP_INJECT else _POOL_OP_RECOVER
                )
                self._chain_append(
                    key,
                    chain_op,
                    c_pool,
                    "重放",
                    now_ms,
                    origin,
                    self._pool_fault_chain_index,
                )
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存；校验失败不改池故障态。
        try:
            self._validate_pool_fault_params(op, pool, ms, now_ms)
        except (TypeError, ValueError) as exc:
            self._pool_fault_cache[key] = (
                op,
                pool,
                ms,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 类型、值校验全过后方查池存在：未知池 KeyError（业务失败，缓存、不审计）。
        if pool not in self._pools:
            exc = KeyError(f"unknown pool: {pool!r}")
            self._pool_fault_cache[key] = (
                op,
                pool,
                ms,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise exc

        if op == _OP_INJECT:
            until = now_ms + ms
            self._pool_fault[pool] = until
            state = _POOL_EXHAUSTED
            chain_op = _POOL_OP_INJECT
        else:
            self._pool_fault.pop(pool, None)
            until = 0
            state = _POOL_NORMAL
            chain_op = _POOL_OP_RECOVER
        result = self._render_pool_fault(pool, state, now_ms, until)
        self._pool_fault_cache[key] = (
            op,
            pool,
            ms,
            now_ms,
            ("ok", result),
        )
        self._chain_append(
            key,
            chain_op,
            pool,
            "成功",
            now_ms,
            index=self._pool_fault_chain_index,
        )
        return result

    @staticmethod
    def _validate_pool_fault_params(op, pool, ms, now_ms):
        """校验 pool_fault 四参数：类型错先于值错，未知池由调用方查。

        op 限注入/恢复，pool 为凭据约束的池标识，注入 ms 为非 bool 正 int、
        恢复 ms 须为 None（任何非 None 皆值错），now_ms 为非 bool 非负 int。
        """
        # 类型阶段：任一类型错先于任何值错抛出。
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if not isinstance(pool, str):
            raise TypeError(f"pool must be a str, got {type(pool).__name__}")
        if op == _OP_INJECT and (isinstance(ms, bool) or not isinstance(ms, int)):
            raise TypeError(f"ms must be an int, got {type(ms).__name__}")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值阶段。
        if op not in (_OP_INJECT, _OP_RECOVER):
            raise ValueError(f"op must be one of 注入/恢复, got {op!r}")
        # pool 已确认为 str，此处仅做凭据取值（字节长度、U+0000）校验。
        _check_credential("pool", pool)
        if op == _OP_INJECT:
            if ms < 1:
                raise ValueError(f"ms must be >= 1, got {ms}")
        elif ms is not None:
            raise ValueError(f"ms must be None for 恢复, got {ms!r}")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")

    @staticmethod
    def _render_pool_fault(pool, state, now_ms, until):
        # 键序：池、状态、时刻、截至；池/状态为 str，余为 int。
        payload = {"池": pool, "状态": state, "时刻": now_ms, "截至": until}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def timeout_fault(self, key, op, at_ms, now_ms):
        """注入或恢复全局超时演练（待触发值），返回 LF 结尾 JSON。

        key 沿用凭据约束；op 仅“注入/恢复”：注入 at_ms 为非 bool int 且
        >= now_ms，设置或覆盖待触发时刻；恢复 at_ms 须为 None，取消待触发。
        now_ms 为非 bool 非负 int。类型错抛 TypeError、取值错抛 ValueError。
        返回键序“状态/时刻/触发”的基线 LF 尾 JSON：注入为 等待/now_ms/
        at_ms，恢复为 正常/now_ms/0。验 key 后以独立域（与 do/meter/
        capacity/fault/pool_fault 分域）永久缓存余参与首次成败（含验参
        异常）：严格同参重放不改态、直接返回或重抛，异参抛 ValueError。
        首次成功及成功的同参重放写现有防篡改审计链：操作“超时注入/超时
        恢复”、会话记空串，结果“成功/重放”，重放原序号沿用首次；异常
        不记。配置加载/回滚成功保留待触发值，失败不改。判定与变更均
        O(1) 时空。
        """
        _check_credential("key", key)

        cached = self._timeout_fault_cache.get(key)
        if cached is not None:
            # 重放：不改待触发值，仅按缓存返回或重抛。
            c_op, c_at_ms, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, at_ms, now_ms), (c_op, c_at_ms, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 仅首次成功的同参重放入链记“重放”，原序号沿用首次；
            # 首次异常不在本域链索引中，自然跳过。
            origin = self._timeout_fault_chain_index.get(key)
            if origin is not None:
                chain_op = (
                    _TIMEOUT_OP_INJECT if c_op == _OP_INJECT
                    else _TIMEOUT_OP_RECOVER
                )
                self._chain_append(
                    key,
                    chain_op,
                    "",
                    "重放",
                    now_ms,
                    origin,
                    self._timeout_fault_chain_index,
                )
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存；校验失败不改待触发值。
        try:
            self._validate_timeout_fault_params(op, at_ms, now_ms)
        except (TypeError, ValueError) as exc:
            self._timeout_fault_cache[key] = (
                op,
                at_ms,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        if op == _OP_INJECT:
            # 注入设置或覆盖触发时刻。
            self._timeout_at = at_ms
            state = _TIMEOUT_WAITING
            trigger = at_ms
            chain_op = _TIMEOUT_OP_INJECT
        else:
            # 恢复取消待触发。
            self._timeout_at = None
            state = _TIMEOUT_NORMAL
            trigger = 0
            chain_op = _TIMEOUT_OP_RECOVER
        result = self._render_timeout_fault(state, now_ms, trigger)
        self._timeout_fault_cache[key] = (
            op,
            at_ms,
            now_ms,
            ("ok", result),
        )
        self._chain_append(
            key,
            chain_op,
            "",
            "成功",
            now_ms,
            index=self._timeout_fault_chain_index,
        )
        return result

    @staticmethod
    def _validate_timeout_fault_params(op, at_ms, now_ms):
        """校验 timeout_fault 三参数：类型错先于值错。

        op 限注入/恢复；注入 at_ms 为非 bool int 且 >= now_ms，恢复 at_ms
        须为 None（任何非 None 皆值错）；now_ms 为非 bool 非负 int。
        """
        # 类型阶段：任一类型错先于任何值错抛出。
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op == _OP_INJECT and (isinstance(at_ms, bool) or not isinstance(at_ms, int)):
            raise TypeError(f"at_ms must be an int, got {type(at_ms).__name__}")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值阶段。
        if op not in (_OP_INJECT, _OP_RECOVER):
            raise ValueError(f"op must be one of 注入/恢复, got {op!r}")
        if op == _OP_INJECT:
            if at_ms < now_ms:
                raise ValueError(f"at_ms must be >= now_ms, got {at_ms} < {now_ms}")
        elif at_ms is not None:
            raise ValueError(f"at_ms must be None for 恢复, got {at_ms!r}")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")

    @staticmethod
    def _render_timeout_fault(state, now_ms, trigger):
        # 键序：状态、时刻、触发；状态为 str，余为 int。
        payload = {"状态": state, "时刻": now_ms, "触发": trigger}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _timeout_armed(self, now_ms):
        """待触发且 now_ms 已到触发值（含同刻），O(1) 时空。"""
        return self._timeout_at is not None and now_ms >= self._timeout_at

    def _timeout_fire(self, now_ms):
        """超时演练触发：在普通老化与晋升前原子清场，O(S log A + Q)。

        挂起全部在线会话、期限清零并释放租约（静态址仅退租）；按入队序将
        全部队项记超时（capacity 事件沿用既有规则记其 sid 与入队序）后删除；
        最后清除待触发。本批不晋升、不半释放。返回按入队序的超时入队序列表
        （供推进输出“变更”）。
        """
        for session in self._sessions.values():
            if session["state"] == _STATE_ONLINE:
                self._release(session)
                session["state"] = _STATE_SUSPENDED
                session["deadline"] = 0
        timed_out = [
            (queued_sid, self._capacity_queue[queued_sid][4])
            for queued_sid in self._queue_order
        ]
        self._capacity_queue.clear()
        self._queue_order.clear()
        for queued_sid, order in timed_out:
            self._cap_event(now_ms, queued_sid, _CAP_TIMEOUT, order)
        # 触发后清除待触发值。
        self._timeout_at = None
        return [order for _sid, order in timed_out]

    def _fault_payload(
        self,
        now_ms,
        until=None,
        backoff=None,
        fail=None,
        pool_fault=None,
        timeout_waiting=None,
        timeout_at=0,
    ):
        """组装故障演练总检查点文档 dict（顶层键序：
        版本/时刻/后端/池/超时/摘要）。

        缺省渲染当前实例状态；fault_plan 传入演算态（until/backoff/fail/
        pool_fault/timeout_waiting/timeout_at）渲染同契约包，渲染后状态不变。

        后端对象键序“截至/退避/失败”，契约同 backend_checkpoint 同名字段
        （退避按用户 Unicode 码点升序，项键序“用户/次数/下次”；失败键序
        “故障/退避”）；池为全部池演练记录、按标识 Unicode 码点升序，项键序
        “标识/截至”；超时键序“等待/触发”，未等待时触发为 0；摘要为前五键
        紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写十六进制串。纯渲染：
        不老化、不清到期项、不改态。
        """
        if until is None:
            until = self._fault_until
        if backoff is None:
            backoff = self._backoff
        if fail is None:
            fail = self._fault_fail
        if pool_fault is None:
            pool_fault = self._pool_fault
        if timeout_waiting is None:
            timeout_waiting = self._timeout_at is not None
            timeout_at = self._timeout_at if timeout_waiting else 0
        backend = {
            "截至": until,
            "退避": [
                {"用户": user, "次数": n, "下次": retry_at}
                for user, (n, retry_at) in sorted(backoff.items())
            ],
            "失败": {"故障": fail[0], "退避": fail[1]},
        }
        pools = [
            {"标识": pool_id, "截至": pool_until}
            for pool_id, pool_until in sorted(pool_fault.items())
        ]
        doc = {
            "版本": 1,
            "时刻": now_ms,
            "后端": backend,
            "池": pools,
            "超时": {"等待": timeout_waiting, "触发": timeout_at},
        }
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return doc

    @staticmethod
    def _fault_doc_text(doc):
        """给定故障演练总检查点文档 dict 渲染 LF 结尾紧凑 JSON（基线序列化）。"""
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _fault_checkpoint_text(self, now_ms):
        """故障演练总检查点的 LF 结尾紧凑 JSON（基线序列化，不老化、不改态）。"""
        return self._fault_doc_text(self._fault_payload(now_ms))

    def fault_checkpoint(self, now_ms):
        """只读输出故障演练总检查点的 LF 结尾基线 JSON，覆盖后端故障、池演练
        与超时演练三域；O((U+P) log(U+P)) 时间、O(U+P) 空间；不认证、不老化、
        不清到期项、不审计、不动各域缓存。

        now_ms 限非 bool 非负 int：类型错 TypeError、取值错 ValueError。
        顶层依次为“版本/时刻/后端/池/超时/摘要”：版本恒为 1，时刻为
        now_ms；后端为对象，键序“截至/退避/失败”，截至、退避与失败的
        契约同 backend_checkpoint 同名字段；池为全部池演练记录的列表，
        按标识 Unicode 码点升序，项键序“标识/截至”，标识为 str、截至为
        >=0 的非 bool int；超时为对象，键序“等待/触发”，等待为 bool，
        触发为 >=0 的非 bool int、未等待时恒为 0；摘要为前五键紧凑 JSON
        （无 LF）UTF-8 字节的 sha256 小写值。同态同时刻查询逐字节相同。
        """
        _check_int("now_ms", now_ms, 0)
        return self._fault_checkpoint_text(now_ms)

    def fault_restore(self, key, text):
        """按故障演练总检查点原子替换后端故障态、池演练与超时演练三域，
        返回替换后检查点（规范包）的 LF 结尾基线 JSON。

        key 沿用凭据约束，text 须为 str：key 型/值错抛 TypeError/ValueError，
        text 非 str 抛 TypeError。JSON 解析、重键、键集/键序、结构、类型、
        取值范围、排序或重复、版本或摘要错均抛 ValueError；退避项引用未
        注册用户、池项引用未知池抛 ResourceError。全部校验通过后原子替换
        故障截至、按用户退避、失败计数、池演练记录与待触发时刻（三者之外
        的认证器、会话、租约、队列及各域缓存均不变）；任何失败不改实例、
        不审计。不老化。

        重放缓存与各域独立：仅缓存首次成功，同 key 同型同 text 重放不解析、
        不重验、不替换，直接返回首次规范包原字节，异参抛 ValueError；失败
        （含参数错）不占 key。首次成功及成功的同参重放写现有防篡改审计链：
        操作“故障恢复”、会话记空串，首次结果“成功”、原序号 0，重放结果
        “重放”、原序号指认首次；事件时刻取检查点“时刻”（接口无时钟参数）；
        参数与文本异常不记。首次 O((U+P) log(U+P)) 时间、O(U+P) 空间，
        重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._fault_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text，追加重放审计后
            # 返回缓存规范包原字节；时刻随缓存保存，重放 O(1)。
            c_text, result, c_now_ms = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            self._chain_append(
                key,
                _FAULT_RESTORE_OP,
                "",
                "重放",
                c_now_ms,
                self._fault_restore_chain_index[key],
                self._fault_restore_chain_index,
            )
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        # 全部校验在新数据上进行，通过后一次性替换；任何失败实例不变。
        now_ms, until, backoff_rows, fail, pool_rows, waiting, trigger = (
            self._parse_fault_checkpoint(text)
        )
        for user, _n, _retry_at in backoff_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"fault checkpoint references unregistered user: {user!r}"
                )
        for pool_id, _pool_until in pool_rows:
            if pool_id not in self._pools:
                raise ResourceError(
                    f"fault checkpoint references unknown pool: {pool_id!r}"
                )

        # 全验后原子替换三域：故障截至、退避（存活储为 (n, retry_at) 元组）、
        # 失败计数、池演练记录与待触发时刻（未等待为 None）。
        self._fault_until = until
        self._backoff = {
            user: (n, retry_at) for user, n, retry_at in backoff_rows
        }
        self._fault_fail = [fail[0], fail[1]]
        self._pool_fault = {
            pool_id: pool_until for pool_id, pool_until in pool_rows
        }
        self._timeout_at = trigger if waiting else None

        result = self._fault_checkpoint_text(now_ms)
        self._fault_restore_cache[key] = (text, result, now_ms)
        self._chain_append(
            key,
            _FAULT_RESTORE_OP,
            "",
            "成功",
            now_ms,
            index=self._fault_restore_chain_index,
        )
        return result

    def _parse_fault_checkpoint(self, text):
        """解析并全量校验故障演练总检查点文本，返回
        (时刻, 截至, 退避行三元组列表 (用户,次数,下次), (失败故障,失败退避),
        池行二元组列表 (标识,截至), 等待, 触发)；任何文本非法均抛 ValueError。

        顶层须恰含“版本/时刻/后端/池/超时/摘要”且键序如此；版本为 1，
        时刻为非 bool 非负 int；后端键序“截至/退避/失败”，字段契约同
        backend_checkpoint 同名字段（退避行按用户 Unicode 码点严格升序、
        无重复）；池项键序“标识/截至”，标识为凭据约束串、截至为非 bool
        非负 int，行按标识 Unicode 码点严格升序、无重复；超时键序
        “等待/触发”，等待为 bool、触发为非 bool 非负 int 且未等待时须为
        0；摘要须为规范化前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写
        值（与原文排版无关）。仅做结构自洽校验；用户注册与池存在由调用方
        判定。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"fault checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("fault checkpoint top level must be an object")
        if list(doc) != ["版本", "时刻", "后端", "池", "超时", "摘要"]:
            raise ValueError(
                "fault checkpoint top-level keys must be "
                "版本/时刻/后端/池/超时/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        now_ms = self._cp_int(doc["时刻"], "时刻", 0)

        backend_raw = doc["后端"]
        if not isinstance(backend_raw, dict) or list(backend_raw) != [
            "截至",
            "退避",
            "失败",
        ]:
            raise ValueError("后端 keys must be 截至/退避/失败 in order")
        until = self._cp_int(backend_raw["截至"], "后端.截至", 0)

        backoff_raw = backend_raw["退避"]
        if not isinstance(backoff_raw, list):
            raise ValueError("后端.退避 must be a list")
        backoff_rows = []
        last_user = None
        for index, item in enumerate(backoff_raw, start=1):
            if not isinstance(item, dict) or list(item) != ["用户", "次数", "下次"]:
                raise ValueError(
                    f"backoff {index} keys must be 用户/次数/下次 in order"
                )
            user = self._cp_str(item["用户"], "后端.退避.用户")
            n = item["次数"]
            if isinstance(n, bool) or not isinstance(n, int):
                raise ValueError(
                    f"后端.退避.次数 must be an int, got {type(n).__name__}"
                )
            if n <= 0:
                raise ValueError(f"后端.退避.次数 must be > 0, got {n}")
            retry_at = self._cp_int(item["下次"], "后端.退避.下次", 0)
            if last_user is not None and user <= last_user:
                raise ValueError(
                    "backoff rows must be strictly sorted by 用户 ascending "
                    "with no duplicates"
                )
            last_user = user
            backoff_rows.append((user, n, retry_at))

        fail_raw = backend_raw["失败"]
        if not isinstance(fail_raw, dict) or list(fail_raw) != ["故障", "退避"]:
            raise ValueError("失败 keys must be 故障/退避 in order")
        fault_fail = self._cp_int(fail_raw["故障"], "失败.故障", 0)
        backoff_fail = self._cp_int(fail_raw["退避"], "失败.退避", 0)

        pools_raw = doc["池"]
        if not isinstance(pools_raw, list):
            raise ValueError("池 must be a list")
        pool_rows = []
        last_pool = None
        for index, item in enumerate(pools_raw, start=1):
            if not isinstance(item, dict) or list(item) != ["标识", "截至"]:
                raise ValueError(f"pool {index} keys must be 标识/截至 in order")
            pool_id = self._cp_str(item["标识"], "池.标识")
            pool_until = self._cp_int(item["截至"], "池.截至", 0)
            if last_pool is not None and pool_id <= last_pool:
                raise ValueError(
                    "pool rows must be strictly sorted by 标识 ascending "
                    "with no duplicates"
                )
            last_pool = pool_id
            pool_rows.append((pool_id, pool_until))

        timeout_raw = doc["超时"]
        if not isinstance(timeout_raw, dict) or list(timeout_raw) != ["等待", "触发"]:
            raise ValueError("超时 keys must be 等待/触发 in order")
        waiting = timeout_raw["等待"]
        if not isinstance(waiting, bool):
            raise ValueError(
                f"超时.等待 must be a bool, got {type(waiting).__name__}"
            )
        trigger = self._cp_int(timeout_raw["触发"], "超时.触发", 0)
        if not waiting and trigger != 0:
            raise ValueError(f"超时.触发 must be 0 when 等待 is false, got {trigger}")
        summary = self._cp_hex64(doc["摘要"], "摘要")

        # 摘要：用规范化值重建前五键（数值相等即与生成方基线逐字节一致）。
        canonical_head = {
            "版本": 1,
            "时刻": now_ms,
            "后端": {
                "截至": until,
                "退避": [
                    {"用户": user, "次数": n, "下次": retry_at}
                    for user, n, retry_at in backoff_rows
                ],
                "失败": {"故障": fault_fail, "退避": backoff_fail},
            },
            "池": [
                {"标识": pool_id, "截至": pool_until}
                for pool_id, pool_until in pool_rows
            ],
            "超时": {"等待": waiting, "触发": trigger},
        }
        blob = json.dumps(canonical_head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical fault checkpoint")
        return (
            now_ms,
            until,
            backoff_rows,
            (fault_fail, backoff_fail),
            pool_rows,
            waiting,
            trigger,
        )

    def fault_plan(self, key, mode, steps, now_ms):
        """按步骤列表批量演算后端/池/超时三域故障注入或恢复，返回演算态
        fault_checkpoint(now_ms) 契约的 LF 尾基线 JSON。

        key 沿用凭据约束；mode 仅“预检/执行”；steps 为 1..1000 项 tuple，
        每项 (domain, target, op, value) 四元组：domain/op 为非 bool str，
        domain 仅后端/池/超时，op 仅注入/恢复。后端与超时项 target 须为 ""
        且在各自域内唯一（至多一项）；池项 target 沿用池标识凭据约束、各项
        互异。后端/池注入 value 为非 bool 正 int，截至 = now_ms+value；超时
        注入 value 为非 bool int 且 >= now_ms（触发时刻）；恢复 value 须为
        None。now_ms 为非 bool 非负 int。类型错 TypeError，结构/取值错
        ValueError，池项引用未知池 KeyError。

        全量校验后整体演算：后端注入置故障截至、恢复清零，二者均清全部用户
        退避（失败计数保留）；池注入置该池截至、恢复移除；超时注入覆盖待触发
        时刻、恢复取消。未列域与字段不变。预检只读：演算不落实例；执行原子
        提交：先在副本上演算（任何异常实例不变），再一次性替换三域。

        执行以 key 缓存首个成功或 KeyError：同 (mode, steps, now_ms) 严格
        同参重放原果（KeyError 重抛同类同 args），异参 ValueError；预检、
        参数错不缓存、不审计。首个成功/KeyError 及其同参重放写现有防篡改
        审计链：操作“故障计划”、会话记空串，结果与原序号沿用 config_change
        口径（首次“成功”/“KeyError”、原序号 0，重放“重放成功”/“重放
        KeyError”、原序号指认首次），审计时刻取 now_ms。

        首次 O(U log U + P log P + K) 时间、O(U+P+K) 辅助空间，U/P/K 为
        退避用户数、池演练记录数、步骤数；重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._fault_plan_cache.get(key)
        if cached is not None:
            # 仅执行模式缓存首果；重放不演算、不老化、不改态，直接返回或重抛。
            c_mode, c_steps, c_now_ms, outcome = cached
            if not _strict_equal(
                (mode, steps, now_ms), (c_mode, c_steps, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            origin = self._fault_plan_chain_index[key]
            if outcome[0] == "ok":
                chain_result = "重放成功"
            else:
                chain_result = "重放" + outcome[1][0].__name__
            self._chain_append(
                key,
                _FAULT_PLAN_OP,
                "",
                chain_result,
                now_ms,
                origin,
                self._fault_plan_chain_index,
            )
            if outcome[0] == "ok":
                return outcome[1]
            raise _replay_exception(outcome[1][0], outcome[1][1])

        # 预检与执行共用同一全量校验；参数错不缓存、不审计，实例不变。
        self._validate_fault_plan_params(mode, steps, now_ms)

        # 在副本上演算全部步骤：未知池在演算阶段抛 KeyError，实例不变。
        # 后端退避为仅在本计划内清空的副本；失败计数沿用且不改。
        new_until = self._fault_until
        new_backoff = dict(self._backoff)
        new_pool_fault = dict(self._pool_fault)
        new_timeout_waiting = self._timeout_at is not None
        new_timeout_at = self._timeout_at if new_timeout_waiting else 0
        try:
            for domain, target, op, value in steps:
                if domain == _FAULT_PLAN_DOMAIN_BACKEND:
                    # 后端变更（注入与恢复）均清退避、保留失败计数。
                    new_backoff.clear()
                    if op == _OP_INJECT:
                        new_until = now_ms + value
                    else:
                        new_until = 0
                elif domain == _FAULT_PLAN_DOMAIN_POOL:
                    if target not in self._pools:
                        raise KeyError(f"unknown pool: {target!r}")
                    if op == _OP_INJECT:
                        new_pool_fault[target] = now_ms + value
                    else:
                        new_pool_fault.pop(target, None)
                else:  # _FAULT_PLAN_DOMAIN_TIMEOUT
                    if op == _OP_INJECT:
                        new_timeout_waiting = True
                        new_timeout_at = value
                    else:
                        new_timeout_waiting = False
                        new_timeout_at = 0
        except KeyError as exc:
            # 执行模式缓存首个 KeyError（业务首果）并写审计；预检不缓存、不审计。
            if mode == _FAULT_PLAN_MODE_EXECUTE:
                self._fault_plan_cache[key] = (
                    mode,
                    steps,
                    now_ms,
                    ("err", (KeyError, exc.args)),
                )
                self._chain_append(
                    key,
                    _FAULT_PLAN_OP,
                    "",
                    "KeyError",
                    now_ms,
                    index=self._fault_plan_chain_index,
                )
            raise

        doc = self._fault_payload(
            now_ms,
            until=new_until,
            backoff=new_backoff,
            fail=self._fault_fail,
            pool_fault=new_pool_fault,
            timeout_waiting=new_timeout_waiting,
            timeout_at=new_timeout_at,
        )
        result = self._fault_doc_text(doc)

        if mode == _FAULT_PLAN_MODE_EXECUTE:
            # 演算全过：原子提交三域（失败计数本就未改）。
            self._fault_until = new_until
            self._backoff = new_backoff
            self._pool_fault = new_pool_fault
            self._timeout_at = new_timeout_at if new_timeout_waiting else None
            self._fault_plan_cache[key] = (
                mode,
                steps,
                now_ms,
                ("ok", result),
            )
            self._chain_append(
                key,
                _FAULT_PLAN_OP,
                "",
                "成功",
                now_ms,
                index=self._fault_plan_chain_index,
            )
        return result

    @staticmethod
    def _fault_plan_check_types(mode, steps, now_ms, check_mode=True):
        """fault_plan 校验的类型阶段：容器/模式/各步前三字段/注入 value/
        now_ms 的任一类型错均在此阶段抛出，先于任何长度、取值、重复等结构/
        值错（沿 batch/pool_fault 约定）。check_mode=False 跳过 mode 校验。
        """
        if check_mode and (isinstance(mode, bool) or not isinstance(mode, str)):
            raise TypeError(f"mode must be a str, got {type(mode).__name__}")
        if not isinstance(steps, tuple):
            raise TypeError(f"steps must be a tuple, got {type(steps).__name__}")
        for step in steps:
            if not isinstance(step, tuple):
                raise TypeError(
                    f"step must be a tuple, got {type(step).__name__}"
                )
            # 长度未定前仅查存在的前三字段：domain/target/op 均须为 str
            # （bool 非 str）；长度属结构错，留待取值阶段。
            for field in step[:3]:
                if not isinstance(field, str):
                    raise TypeError(
                        "domain/target/op must be str, got "
                        f"{type(field).__name__}"
                    )
            # 注入 value 的 int 类型仅在恰为四项且 op 恰为“注入”时可判定，
            # 沿 pool_fault：恢复 value 非 None 归取值错（含 bool）。
            if len(step) == 4 and step[2] == _OP_INJECT:
                value = step[3]
                if isinstance(value, bool) or not isinstance(value, int):
                    raise TypeError(
                        f"value must be an int, got {type(value).__name__}"
                    )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

    @staticmethod
    def _fault_plan_check_values(mode, steps, now_ms, check_mode=True):
        """fault_plan 校验的取值/结构阶段：模式、时钟下界、步数、逐项长度/
        域/操作/target/唯一性/value 取值。须在 _fault_plan_check_types 之后
        调用；check_mode=False 跳过 mode 校验。池存在与否不在本结构校验内
        （演算阶段查，未知池抛 KeyError）。
        """
        if check_mode and mode not in (
            _FAULT_PLAN_MODE_PRECHECK,
            _FAULT_PLAN_MODE_EXECUTE,
        ):
            raise ValueError(
                f"mode must be one of 预检/执行, got {mode!r}"
            )
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(steps) <= _FAULT_PLAN_MAX_STEPS):
            raise ValueError(
                f"steps must contain 1..{_FAULT_PLAN_MAX_STEPS} items, "
                f"got {len(steps)}"
            )

        backend_seen = False
        timeout_seen = False
        pool_targets = set()
        for step in steps:
            if len(step) != 4:
                raise ValueError(
                    "step must be a 4-tuple (domain, target, op, value), "
                    f"got {len(step)} items"
                )
            domain, target, op, value = step
            if domain not in (
                _FAULT_PLAN_DOMAIN_BACKEND,
                _FAULT_PLAN_DOMAIN_POOL,
                _FAULT_PLAN_DOMAIN_TIMEOUT,
            ):
                raise ValueError(
                    "domain must be one of 后端/池/超时, got "
                    f"{domain!r}"
                )
            if op not in (_OP_INJECT, _OP_RECOVER):
                raise ValueError(
                    f"op must be one of 注入/恢复, got {op!r}"
                )
            if domain == _FAULT_PLAN_DOMAIN_BACKEND:
                if target != "":
                    raise ValueError(
                        f"backend target must be \"\", got {target!r}"
                    )
                if backend_seen:
                    raise ValueError("backend step must be unique")
                backend_seen = True
            elif domain == _FAULT_PLAN_DOMAIN_TIMEOUT:
                if target != "":
                    raise ValueError(
                        f"timeout target must be \"\", got {target!r}"
                    )
                if timeout_seen:
                    raise ValueError("timeout step must be unique")
                timeout_seen = True
            else:  # 池
                _check_credential("pool target", target)
                if target in pool_targets:
                    raise ValueError(
                        f"pool target must be unique, got duplicate {target!r}"
                    )
                pool_targets.add(target)

            if op == _OP_INJECT:
                # 类型已在类型阶段确认；此处仅查取值范围。
                if domain == _FAULT_PLAN_DOMAIN_TIMEOUT:
                    if value < now_ms:
                        raise ValueError(
                            "timeout value must be >= now_ms, got "
                            f"{value} < {now_ms}"
                        )
                elif value < 1:
                    raise ValueError(f"value must be >= 1, got {value}")
            elif value is not None:
                raise ValueError(f"value must be None for 恢复, got {value!r}")

    @classmethod
    def _validate_fault_plan_params(cls, mode, steps, now_ms, check_mode=True):
        """校验 fault_plan 三参数：类型阶段先于结构/取值阶段。

        mode 限预检/执行；steps 须为 tuple，含 1..1000 项 4 元组
        (domain, target, op, value)：domain/op 为非 bool str，域限后端/池/
        超时，op 限注入/恢复；后端/超时项 target 为 ""、各域至多一项，池项
        target 满足凭据约束且各项互异；后端/池注入 value 为非 bool 正 int，
        超时注入 value 为非 bool int 且 >= now_ms，恢复 value 须 None；
        now_ms 为非 bool 非负 int。池存在与否不在本结构校验内（演算阶段查，
        未知池抛 KeyError）。fault_impact/fault_diff 无 mode 参数，
        check_mode=False 时跳过 mode 的类型与取值校验。
        """
        cls._fault_plan_check_types(mode, steps, now_ms, check_mode)
        cls._fault_plan_check_values(mode, steps, now_ms, check_mode)

    def _fault_plan_simulate(self, steps, now_ms):
        """从实例当前三域在副本上演算 steps（fault_plan 同口径），返回
        (until, pool_fault, timeout_waiting, timeout_at)：仅决定三域生效态，
        后端退避与失败计数不参与；未知池抛 KeyError。不改任何实例状态。
        """
        new_until = self._fault_until
        new_pool_fault = dict(self._pool_fault)
        new_timeout_waiting = self._timeout_at is not None
        new_timeout_at = self._timeout_at if new_timeout_waiting else 0
        for domain, target, op, value in steps:
            if domain == _FAULT_PLAN_DOMAIN_BACKEND:
                if op == _OP_INJECT:
                    new_until = now_ms + value
                else:
                    new_until = 0
            elif domain == _FAULT_PLAN_DOMAIN_POOL:
                if target not in self._pools:
                    raise KeyError(f"unknown pool: {target!r}")
                if op == _OP_INJECT:
                    new_pool_fault[target] = now_ms + value
                else:
                    new_pool_fault.pop(target, None)
            else:  # _FAULT_PLAN_DOMAIN_TIMEOUT
                if op == _OP_INJECT:
                    new_timeout_waiting = True
                    new_timeout_at = value
                else:
                    new_timeout_waiting = False
                    new_timeout_at = 0
        return new_until, new_pool_fault, new_timeout_waiting, new_timeout_at

    def _fault_view_counts(self, now_ms):
        """单扫会话表与队列表，取 now_ms 视图计数（口径同 runtime_stats），
        返回 (global_online, global_suspended, global_queued, global_leased,
        pool_online, pool_leased)：在线会话期限 <= now_ms 归挂起；租约须在线
        且期限、租期均 > now_ms；截止 <= now_ms 的到期队项不计排队。不老化、
        不改态。
        """
        global_online = 0
        global_suspended = 0
        global_leased = 0
        pool_online = {}
        pool_leased = {}
        for session in self._sessions.values():
            state = session["state"]
            view_online = state == _STATE_ONLINE and session["deadline"] > now_ms
            if view_online:
                global_online += 1
                pool_id = session["pool"]
                if pool_id is not None:
                    pool_online[pool_id] = pool_online.get(pool_id, 0) + 1
            elif state == _STATE_OFFLINE:
                # 下线墓碑不计任何影响行。
                continue
            else:
                # 挂起，或在线但期限已到（视图归挂起）。
                global_suspended += 1
            if (
                view_online
                and session["ip"] is not None
                and session["lease"] > now_ms
            ):
                global_leased += 1
                pool_leased[session["pool"]] = (
                    pool_leased.get(session["pool"], 0) + 1
                )

        global_queued = 0
        for entry in self._capacity_queue.values():
            if entry[3] > now_ms:
                global_queued += 1
        return (
            global_online,
            global_suspended,
            global_queued,
            global_leased,
            pool_online,
            pool_leased,
        )

    def fault_impact(self, steps, now_ms):
        """只读评估故障计划在 now_ms 视图下的影响，返回 LF 结尾紧凑 JSON。

        steps 沿用 fault_plan 的 1..1000 项 (domain, target, op, value) tuple
        契约（无 mode/key）；now_ms 为非 bool 非负 int。类型错 TypeError，
        结构/取值/重复错 ValueError，池项引用未知池 KeyError。不老化、不缓存、
        不审计、不改任何实例状态（演算仅在副本上进行）。

        按 now_ms 取视图（口径同 runtime_stats）：在线会话期限 <= now_ms
        归挂起；租约须在线且期限、租期均 > now_ms；截止 <= now_ms 的到期队项
        不计排队。域行依次为后端、按标识 Unicode 升序的各注入池、超时；后端与
        超时行目标恒为空串。行键序“域/目标/生效/在线/挂起/排队/租约”。
        后端注入在 now_ms < 演算截至时生效，计全局四类计数，否则全 0；各池
        注入在同条件下生效，仅计本池在线会话与本池有效租约，default 池另计
        全队排队、挂起恒 0，未生效全 0；超时注入在仍等待（演算不触发）且
        触发时刻 <= now_ms 时生效，计全局在线/排队/租约、挂起恒 0，否则全 0。
        顶层键序“时刻/域/合计/摘要”：合计键序“在线/挂起/排队/租约”，为各
        行对应值之和（域间可重复计数）；摘要为前三键紧凑 JSON（无 LF）UTF-8
        字节的 sha256 小写值。同态同参逐字节相同。时间 O(S+Q+P log P+K)、
        辅助空间 O(P+K)，S/Q/P/K 为会话数、队项数、注入池数、步骤数。
        """
        # steps/now_ms 沿用 fault_plan 契约（mode 位传预检但跳过其校验）。
        self._validate_fault_plan_params(
            _FAULT_PLAN_MODE_PRECHECK, steps, now_ms, check_mode=False
        )

        # 在副本上推演（与 fault_plan 同口径）：仅决定三域生效态；后端退避与
        # 失败计数不影响影响评估，无需复制。未知池在演算阶段抛 KeyError。
        (
            new_until,
            new_pool_fault,
            new_timeout_waiting,
            new_timeout_at,
        ) = self._fault_plan_simulate(steps, now_ms)

        # 会话表/队列表单扫取 now_ms 视图计数（在线、挂起、有效租约、按池
        # 归集与排队）；池与址同置同清，pool 非 None 即持址，在线、租约两列
        # 分计（视图在线但租期到者归本池在线而非本池租约）。
        (
            global_online,
            global_suspended,
            global_queued,
            global_leased,
            pool_online,
            pool_leased,
        ) = self._fault_view_counts(now_ms)

        rows = [
            {
                "域": domain,
                "目标": target,
                "生效": active,
                "在线": online if active else 0,
                "挂起": suspended if active else 0,
                "排队": queued if active else 0,
                "租约": leased if active else 0,
            }
            for domain, target, active, online, suspended, queued, leased
            in self._fault_domain_rows(
                now_ms,
                (new_until, new_pool_fault,
                 new_timeout_waiting, new_timeout_at),
                (global_online, global_suspended, global_queued,
                 global_leased, pool_online, pool_leased),
            )
        ]

        totals = {"在线": 0, "挂起": 0, "排队": 0, "租约": 0}
        for row in rows:
            totals["在线"] += row["在线"]
            totals["挂起"] += row["挂起"]
            totals["排队"] += row["排队"]
            totals["租约"] += row["租约"]

        doc = {"时刻": now_ms, "域": rows, "合计": totals}
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _fault_side_entries(self, now_ms, sim, counts):
        """按 fault_impact 口径演算单侧，返回
        (backend_entry, pool_entries, timeout_entry)：各 entry 为
        (domain, target, active, online, suspended, queued, leased)，后四列为
        该域生效时的原始计数（调用方据 active 自行归零）。pool_entries 不保证
        序（调用方按需排序或取并集），后端/超时目标恒空串。sim 为
        _fault_plan_simulate 的四元组，counts 为 _fault_view_counts 的六元组。
        """
        new_until, new_pool_fault, new_timeout_waiting, new_timeout_at = sim
        (global_online, global_suspended, global_queued, global_leased,
         pool_online, pool_leased) = counts

        # 后端行：now_ms < 演算截至时计全局四类。
        backend = (
            _FAULT_PLAN_DOMAIN_BACKEND,
            "",
            now_ms < new_until,
            global_online,
            global_suspended,
            global_queued,
            global_leased,
        )

        # 池行：仅列演算后仍在册的注入池（注入新增/覆盖、恢复移除）；在册池
        # 均为现存池（注入验未知、配置提交裁剪已删池）。此处不排序，交由
        # 需要全序的调用方统一排序（fault_matrix 取多侧并集只排一次）。
        pools = [
            (
                _FAULT_PLAN_DOMAIN_POOL,
                pool_id,
                now_ms < new_pool_fault[pool_id],
                pool_online.get(pool_id, 0),
                0,
                global_queued if pool_id == _DEFAULT_POOL_ID else 0,
                pool_leased.get(pool_id, 0),
            )
            for pool_id in new_pool_fault
        ]

        # 超时行：演算仅覆盖待触发态、从不触发清场，故仍等待且触发时刻已到
        # （含同刻）时生效，计全局在线/排队/租约、挂起 0。
        timeout = (
            _FAULT_PLAN_DOMAIN_TIMEOUT,
            "",
            new_timeout_waiting and new_timeout_at <= now_ms,
            global_online,
            0,
            global_queued,
            global_leased,
        )
        return backend, pools, timeout

    def _fault_domain_rows(self, now_ms, sim, counts):
        """按 fault_impact 口径演算单侧的域行，返回依序的
        (domain, target, active, online, suspended, queued, leased) 列表：
        后端、按标识 Unicode 升序的在册注入池、超时；后端/超时目标恒空串。
        后四列为该域生效时的原始计数（调用方据 active 自行归零）。
        sim 为 _fault_plan_simulate 的四元组，counts 为 _fault_view_counts
        的六元组。
        """
        backend, pools, timeout = self._fault_side_entries(now_ms, sim, counts)
        return [backend] + sorted(pools, key=lambda entry: entry[1]) + [timeout]

    def _fault_side_map(self, now_ms, sim, counts):
        """按 fault_impact 口径演算单侧，返回
        {(domain, target): (active, online, suspended, queued, leased)}：四列
        已按 active 应用（未生效归 0）。fault_matrix 对基准与各场景各建一表，
        缺侧键由调用方以不生效全 0 补。池行不排序，故多侧只在并集上排一次。
        """
        backend, pools, timeout = self._fault_side_entries(now_ms, sim, counts)
        result = {}
        for domain, target, active, online, suspended, queued, leased in (
            backend, *pools, timeout
        ):
            result[(domain, target)] = (
                active,
                online if active else 0,
                suspended if active else 0,
                queued if active else 0,
                leased if active else 0,
            )
        return result

    def fault_diff(self, left, right, now_ms):
        """只读对比两份故障计划在同一 now_ms 视图下的影响，返回 LF 结尾紧凑
        JSON。

        left/right 沿用 fault_plan 的 1..1000 项 (domain, target, op, value)
        tuple 契约；now_ms 为非 bool 非负 int。类型错 TypeError，结构/取值/
        重复错 ValueError，池项引用未知池 KeyError（先校验演算 left，再
        right）。不老化、不缓存、不审计、不改任何实例状态（演算仅在副本上
        进行，两侧均从实例当前同一故障态出发）。

        视图与四类计数口径沿用 fault_impact。域行按后端、两侧池标识并集的
        Unicode 升序各池、超时排列；后端/超时目标恒空串。某侧演算后不在册
        的池或缺侧后端/超时（恒在册）对应侧按不生效、四项 0 计。行键序
        “域/目标/左/右/增减”：左、右均为
        “生效/在线/挂起/排队/租约”对象；增减键序“在线/挂起/排队/租约”，
        值逐项为右减左（按两侧生效后计入值）。
        顶层键序“时刻/域/合计/摘要”：合计键序同增减，为各行增减逐项求和；
        摘要为前三键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写值。
        时间 O(S+Q+(P+K) log(P+K))、辅助空间 O(P+K)，S/Q/P/K 为会话数、
        队项数、两侧注入池并集数、两侧步骤数之和。
        """
        # left/right/now_ms 沿用 fault_plan 契约。两侧类型阶段先全部通过，
        # 再进入任一取值/结构阶段（沿“类型错先于结构/取值错”约定）；全量
        # 校验后再演算，未知池在演算阶段抛 KeyError（先演算 left 再 right）。
        self._fault_plan_check_types(
            _FAULT_PLAN_MODE_PRECHECK, left, now_ms, check_mode=False
        )
        self._fault_plan_check_types(
            _FAULT_PLAN_MODE_PRECHECK, right, now_ms, check_mode=False
        )
        self._fault_plan_check_values(
            _FAULT_PLAN_MODE_PRECHECK, left, now_ms, check_mode=False
        )
        self._fault_plan_check_values(
            _FAULT_PLAN_MODE_PRECHECK, right, now_ms, check_mode=False
        )
        left_sim = self._fault_plan_simulate(left, now_ms)
        right_sim = self._fault_plan_simulate(right, now_ms)

        # 两侧共享同一 now_ms 视图，会话/队列表只扫一遍。
        view = self._fault_view_counts(now_ms)
        left_rows = {
            (domain, target): (active, online, suspended, queued, leased)
            for domain, target, active, online, suspended, queued, leased
            in self._fault_domain_rows(now_ms, left_sim, view)
        }
        right_rows = {
            (domain, target): (active, online, suspended, queued, leased)
            for domain, target, active, online, suspended, queued, leased
            in self._fault_domain_rows(now_ms, right_sim, view)
        }

        # 域键并集按（域固定序后端/池/超时，池内标识 Unicode 升序）排列：
        # 后端与超时两侧恒在册，池行取两侧在册标识并集升序。
        keys = [(_FAULT_PLAN_DOMAIN_BACKEND, "")]
        pool_ids = sorted(set(left_sim[1]) | set(right_sim[1]))
        keys.extend((_FAULT_PLAN_DOMAIN_POOL, pid) for pid in pool_ids)
        keys.append((_FAULT_PLAN_DOMAIN_TIMEOUT, ""))

        zero = (False, 0, 0, 0, 0)

        def side_obj(entry):
            active, online, suspended, queued, leased = entry
            return {
                "生效": active,
                "在线": online if active else 0,
                "挂起": suspended if active else 0,
                "排队": queued if active else 0,
                "租约": leased if active else 0,
            }

        rows = []
        totals = {"在线": 0, "挂起": 0, "排队": 0, "租约": 0}
        for domain, target in keys:
            lobj = side_obj(left_rows.get((domain, target), zero))
            robj = side_obj(right_rows.get((domain, target), zero))
            delta = {
                name: robj[name] - lobj[name]
                for name in ("在线", "挂起", "排队", "租约")
            }
            for name in totals:
                totals[name] += delta[name]
            rows.append(
                {"域": domain, "目标": target, "左": lobj, "右": robj,
                 "增减": delta}
            )

        doc = {"时刻": now_ms, "域": rows, "合计": totals}
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _fault_matrix_check_types(scenarios, now_ms):
        """fault_matrix 校验的类型阶段：now_ms/容器/各项二元/标识 str/各项
        steps 内字段的任一类型错均在此阶段抛出，先于长度、取值、重复等结构/
        值错。steps 复用 fault_plan 的类型阶段（mode 位传预检但跳过其校验）。
        """
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if not isinstance(scenarios, tuple):
            raise TypeError(
                f"scenarios must be a tuple, got {type(scenarios).__name__}"
            )
        for item in scenarios:
            if not isinstance(item, tuple):
                raise TypeError(
                    f"scenario must be a tuple, got {type(item).__name__}"
                )
            # 长度未定前仅查存在的字段：标识须为 str（bool 非 str）；长度属
            # 结构错，留待取值阶段。steps 的类型交由 fault_plan 类型阶段。
            if len(item) >= 1 and not isinstance(item[0], str):
                raise TypeError(
                    f"scenario label must be a str, got {type(item[0]).__name__}"
                )
            if len(item) >= 2:
                Sessions._fault_plan_check_types(
                    _FAULT_PLAN_MODE_PRECHECK, item[1], now_ms, check_mode=False
                )

    @staticmethod
    def _fault_matrix_check_values(scenarios, now_ms):
        """fault_matrix 校验的取值/结构阶段：时钟下界、项数 1..100、逐项
        长度/标识凭据/标识互异，steps 复用 fault_plan 的取值阶段。须在
        _fault_matrix_check_types 之后调用；池存在与否不在本结构校验内
        （演算阶段查，未知池抛 KeyError）。
        """
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(scenarios) <= _FAULT_MATRIX_MAX_SCENARIOS):
            raise ValueError(
                f"scenarios must contain 1..{_FAULT_MATRIX_MAX_SCENARIOS} "
                f"items, got {len(scenarios)}"
            )
        labels = set()
        for item in scenarios:
            if len(item) != 2:
                raise ValueError(
                    "scenario must be a 2-tuple (label, steps), got "
                    f"{len(item)} items"
                )
            label, steps = item
            _check_credential("scenario label", label)
            if label in labels:
                raise ValueError(
                    f"scenario label must be unique, got duplicate {label!r}"
                )
            labels.add(label)
            Sessions._fault_plan_check_values(
                _FAULT_PLAN_MODE_PRECHECK, steps, now_ms, check_mode=False
            )

    def fault_matrix(self, scenarios, now_ms):
        """只读批量评估多份故障计划在同一 now_ms 视图下相对基准的影响，返回
        LF 结尾紧凑 JSON。

        scenarios 为 1..100 项 (label, steps) tuple：label 为互异凭据 str
        （1..256 UTF-8 字节、不含 U+0000），steps 沿用 fault_plan 的
        1..1000 项 (domain, target, op, value) tuple 契约；now_ms 为非 bool
        非负 int。类型错 TypeError，结构/长度/取值/重复错 ValueError，池项
        引用未知池 KeyError（全部场景先全量校验，再按基准、场景输入序演算）。
        不老化、不缓存、不审计、不改任何实例状态（演算仅在副本上进行，基准与
        各场景均从实例当前同一故障态出发；基准不施加任何步骤）。

        视图与四类计数口径沿用 fault_impact。域键取基准与各场景在册池标识
        并集，行按后端、池标识 Unicode 升序、超时排列，后端/超时目标恒空串；
        基准或某场景演算后不在册的池对应行按不生效、四项 0 计，场景按输入序。
        基准行键序“域/目标/生效/在线/挂起/排队/租约”；场景项键序
        “标识/域/合计”，其域行在基准行口径后追加“增减”，增减键序
        “在线/挂起/排队/租约”、值逐项为场景减基准（按两侧生效后计入值），
        合计键序同增减、为逐行增减之和。
        顶层键序“时刻/基准/场景/摘要”：摘要为前三键紧凑 JSON（无 LF）
        UTF-8 字节的 sha256 小写值。时间 O(S+Q+K+CP+P log P)、辅助空间
        O(CP+K)，S/Q/C/P/K 为会话数、队项数、场景数、池并集数、全部步骤数。
        """
        # 类型阶段先全部通过，再进入结构/取值阶段；全量校验后再演算，未知池
        # 在演算阶段抛 KeyError（基准为空步骤、不会有未知池，随后按输入序演算
        # 各场景）。
        self._fault_matrix_check_types(scenarios, now_ms)
        self._fault_matrix_check_values(scenarios, now_ms)

        # 基准与各场景共享同一 now_ms 视图，会话/队列表只扫一遍。
        view = self._fault_view_counts(now_ms)
        base_sim = self._fault_plan_simulate((), now_ms)
        sims = [
            (label, self._fault_plan_simulate(steps, now_ms))
            for label, steps in scenarios
        ]

        # 域键并集：后端、基准与各场景在册池标识并集的 Unicode 升序各池、超时；
        # 多侧池行不在各自排序，并集只排一次。
        pool_ids = set(base_sim[1])
        for _label, sim in sims:
            pool_ids.update(sim[1])
        keys = [(_FAULT_PLAN_DOMAIN_BACKEND, "")]
        keys.extend((_FAULT_PLAN_DOMAIN_POOL, pid) for pid in sorted(pool_ids))
        keys.append((_FAULT_PLAN_DOMAIN_TIMEOUT, ""))

        zero = (False, 0, 0, 0, 0)
        count_names = ("在线", "挂起", "排队", "租约")

        def applied_obj(key, entry):
            domain, target = key
            active, online, suspended, queued, leased = entry
            return {
                "域": domain,
                "目标": target,
                "生效": active,
                "在线": online,
                "挂起": suspended,
                "排队": queued,
                "租约": leased,
            }

        base_map = self._fault_side_map(now_ms, base_sim, view)
        baseline = [
            applied_obj(key, base_map.get(key, zero)) for key in keys
        ]

        scenario_objs = []
        for label, sim in sims:
            sc_map = self._fault_side_map(now_ms, sim, view)
            rows = []
            totals = {name: 0 for name in count_names}
            for key in keys:
                b_entry = base_map.get(key, zero)
                s_entry = sc_map.get(key, zero)
                delta = {
                    name: s_entry[i] - b_entry[i]
                    for i, name in enumerate(count_names, start=1)
                }
                for name in count_names:
                    totals[name] += delta[name]
                row = applied_obj(key, s_entry)
                row["增减"] = delta
                rows.append(row)
            scenario_objs.append(
                {"标识": label, "域": rows, "合计": totals}
            )

        doc = {"时刻": now_ms, "基准": baseline, "场景": scenario_objs}
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"

    def timeout_sweep(self, key, now_ms, limit=100):
        """清扫到期的在线会话与排队项，返回 LF 结尾的基线 JSON。

        key 沿用凭据约束；now_ms 为非 bool 非负 int，limit 为非 bool int
        且 1..1000：类型错 TypeError、取值错 ValueError。重放缓存与各域
        独立：仅缓存首次成功，同 key 同型同参重放不清扫、不改态，直接
        返回缓存结果，异参抛 ValueError；任何失败（含参数错）不占 key。

        不做普通老化。候选为期限非 0 且 <= now_ms 的在线会话与截止
        <= now_ms 的排队项，按（截止, 类别, 次序）升序取前 limit 项：
        类别会话先于排队，会话按 sid 升序、排队按入队序。会话挂起、
        期限清零并释放租约（静态址仅退租）；排队项删除并按处理序追加
        既有超时容量事件（沿用其 sid 与入队序）。整批原子：先全部选定
        再一次性提交，不晋升、不半释放。

        顶层键序为“时刻/处理/会话超时/排队超时/剩余/完成/项目”：处理
        为本次处理项数，剩余为处理后仍候选的项数，完成当且仅当剩余为
        0。项目按处理序，项键序为“类型/标识/结果/截止/入队序”：类型
        仅会话/排队，标识为 sid，会话入队序恒 0，结果仅挂起/超时。
        时间 O(S+Q+limit log limit)、空间 O(limit)。
        """
        _check_credential("key", key)

        cached = self._timeout_sweep_cache.get(key)
        if cached is not None:
            # 重放：不清扫、不改态，仅核对同型同参后返回缓存结果。
            c_now_ms, c_limit, result = cached
            if not _strict_equal((now_ms, limit), (c_now_ms, c_limit)):
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        _check_int("now_ms", now_ms, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        # 候选扫描（不老化）：在线且期限非 0 到期者、截止到期队项。类别键
        # “会话”码点小于“排队”，会话次序取 sid、排队取入队序；同类内次序
        # 互异，异类先比类别，故混合长度元组不会跨类比较次序。
        candidate_count = 0

        def candidates():
            nonlocal candidate_count
            for sid, session in self._sessions.items():
                if (
                    session["state"] == _STATE_ONLINE
                    and session["deadline"] != 0
                    and session["deadline"] <= now_ms
                ):
                    candidate_count += 1
                    yield (session["deadline"], "会话", sid)
            for queued_sid in self._queue_order:
                entry = self._capacity_queue[queued_sid]
                if entry[3] <= now_ms:
                    candidate_count += 1
                    yield (entry[3], "排队", entry[4], queued_sid)

        # nsmallest 惰性消费生成器：仅留前 limit 项（升序），空间 O(limit)。
        selected = heapq.nsmallest(limit, candidates())
        remaining = candidate_count - len(selected)

        # 整批原子：选定不改态，提交步骤不可失败，一次性落库。
        items = []
        session_timeouts = 0
        queued_timeouts = 0
        removed = set()
        for entry in selected:
            deadline = entry[0]
            if entry[1] == "会话":
                sid = entry[2]
                session = self._sessions[sid]
                self._release(session)
                session["state"] = _STATE_SUSPENDED
                session["deadline"] = 0
                session_timeouts += 1
                items.append(
                    {
                        "类型": "会话",
                        "标识": sid,
                        "结果": "挂起",
                        "截止": deadline,
                        "入队序": 0,
                    }
                )
            else:
                order = entry[2]
                sid = entry[3]
                del self._capacity_queue[sid]
                removed.add(sid)
                self._cap_event(now_ms, sid, _CAP_TIMEOUT, order)
                queued_timeouts += 1
                items.append(
                    {
                        "类型": "排队",
                        "标识": sid,
                        "结果": "超时",
                        "截止": deadline,
                        "入队序": order,
                    }
                )
        if removed:
            self._queue_order = [
                sid for sid in self._queue_order if sid not in removed
            ]

        payload = {
            "时刻": now_ms,
            "处理": len(selected),
            "会话超时": session_timeouts,
            "排队超时": queued_timeouts,
            "剩余": remaining,
            "完成": remaining == 0,
            "项目": items,
        }
        output = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        self._timeout_sweep_cache[key] = (now_ms, limit, output)
        return output

    def timeout_storm(self, key, now_ms, batches=10):
        """超时风暴多批清扫，返回 LF 结尾的基线 JSON。

        key 沿用凭据约束；now_ms 为非 bool 非负 int，batches 为 1..1000 的
        非 bool int：类型错 TypeError、取值错 ValueError。重放缓存与各域
        独立：仅缓存首次成功，同 key 同型同参重放不清扫、不改态，直接返回
        首次缓存原字节，异参抛 ValueError；任何失败（含参数错）不占 key。

        不做普通老化。每批沿用 timeout_sweep 的候选与提交规则取前 100 项：
        候选为期限非 0 且 <= now_ms 的在线会话（类别 0）与截止 <= now_ms
        的排队项（类别 1），按（截止, 类别, 次序）升序取前 100，会话按
        sid 升序、排队按入队序；会话挂起、期限清零并释放租约，排队项删除
        并按处理序追加既有超时容量事件。无候选或已运行满 batches 批即停止，
        故初始无候选时批次列表为空（允许 0 批），批次序号自 1 连续。各批
        选定后即按上述规则提交；提交步骤皆不可失败且验参已毕，故逐批落库
        对调用方仍为整次原子（无中途失败的部分提交），不晋升、不半释放。

        顶层键序为“时刻/处理/剩余/完成/批次”：处理为各批处理项之和，剩余
        取末批运行后仍候选的项数（无批为 0），完成当且仅当剩余为 0。批次
        项键序为“序号/会话/排队/剩余/池”：会话/排队为本批两类项数，剩余为
        该批后仍候选的项数；池按标识 Unicode 升序，项键序为“标识/占用/可用”，
        占用取该批提交后租约数，可用取动态空闲加未租静态地址数。

        首次成功写现有防篡改审计链：操作“超时风暴”、会话空串、结果
        “完成/未完成”、原序号 0；同参重放写“重放”并指认首次序号，异常不记。
        时间 O(B(S+Q+P))、空间 O(S+Q+BP)，B=batches。
        """
        _check_credential("key", key)

        cached = self._timeout_storm_cache.get(key)
        if cached is not None:
            # 重放：不清扫、不改态，仅核对同型同参后返回首次缓存原字节。
            c_now_ms, c_batches, result = cached
            if not _strict_equal((now_ms, batches), (c_now_ms, c_batches)):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 首次成功的同参重放入链记“重放”，原序号指认首次。
            origin = self._timeout_storm_chain_index.get(key)
            if origin is not None:
                self._chain_append(
                    key,
                    _TIMEOUT_STORM_OP,
                    "",
                    "重放",
                    now_ms,
                    origin,
                    self._timeout_storm_chain_index,
                )
            return result

        _check_int("now_ms", now_ms, 0)
        _check_int("batches", batches, 1)
        if batches > 1000:
            raise ValueError(f"batches must be <= 1000, got {batches}")

        # 各池已租静态地址数，批后水位按 O(1)/池快照（未租静态数 = 静态
        # 总数 - 已租静态数）；初始统计遍历静态址 O(S)，批内释址时维护。
        rented_static = {}
        for pool_id, pool in self._pools.items():
            rented_static[pool_id] = sum(
                1 for ip_int in pool.static_ips if ip_int in pool.leases
            )
        pool_ids = sorted(self._pools)

        # 逐批：扫描当下候选（不老化）取前 100，随即按 timeout_sweep 规则
        # 提交。提交步骤皆不可失败，且验参已全部完成，故逐批落库对调用方
        # 仍为整次原子（无中途失败的部分提交）；不晋升、不半释放。
        batch_rows = []
        processed_total = 0
        final_remaining = 0
        for index in range(1, batches + 1):
            # 键序沿用 timeout_sweep，类别码会话 0、排队 1（"会话"码点小于
            # "排队"）：同类内次序互异，异类先比截止再比类别。
            found = []
            for sid, session in self._sessions.items():
                if (
                    session["state"] == _STATE_ONLINE
                    and session["deadline"] != 0
                    and session["deadline"] <= now_ms
                ):
                    found.append((session["deadline"], 0, sid))
            for queued_sid in self._queue_order:
                entry = self._capacity_queue[queued_sid]
                if entry[3] <= now_ms:
                    found.append((entry[3], 1, entry[4], queued_sid))
            # 无候选即停，故初始无候选时批次列表为空；已运行批次必非空。
            if not found:
                break
            # nsmallest 惰性取前 100（升序），空间 O(100)。
            selected = heapq.nsmallest(_STORM_BATCH_LIMIT, found)
            remaining = len(found) - len(selected)

            session_hits = 0
            queued_hits = 0
            removed = set()
            for entry in selected:
                if entry[1] == 0:
                    sid = entry[2]
                    session = self._sessions[sid]
                    is_static = (
                        session["ip"] is not None
                        and session["ip"]
                        in self._pools[session["pool"]].static_ips
                    )
                    pool_id = session["pool"]
                    self._release(session)
                    session["state"] = _STATE_SUSPENDED
                    session["deadline"] = 0
                    if is_static:
                        rented_static[pool_id] -= 1
                    session_hits += 1
                else:
                    order = entry[2]
                    sid = entry[3]
                    del self._capacity_queue[sid]
                    removed.add(sid)
                    self._cap_event(now_ms, sid, _CAP_TIMEOUT, order)
                    queued_hits += 1
            if removed:
                self._queue_order = [
                    sid for sid in self._queue_order if sid not in removed
                ]
            processed_total += len(selected)
            final_remaining = remaining

            # 批后池水位：占用为现存租约数，可用为动态空闲加未租静态地址数。
            pool_rows = []
            for pool_id in pool_ids:
                pool = self._pools[pool_id]
                pool_rows.append(
                    {
                        "标识": pool_id,
                        "占用": len(pool.leases),
                        "可用": len(pool.free)
                        + len(pool.static_ips)
                        - rented_static[pool_id],
                    }
                )
            batch_rows.append(
                {
                    "序号": index,
                    "会话": session_hits,
                    "排队": queued_hits,
                    "剩余": remaining,
                    "池": pool_rows,
                }
            )

        completed = final_remaining == 0
        payload = {
            "时刻": now_ms,
            "处理": processed_total,
            "剩余": final_remaining,
            "完成": completed,
            "批次": batch_rows,
        }
        output = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        self._timeout_storm_cache[key] = (now_ms, batches, output)
        self._chain_append(
            key,
            _TIMEOUT_STORM_OP,
            "",
            "完成" if completed else "未完成",
            now_ms,
            index=self._timeout_storm_chain_index,
        )
        return output

    def batch_offline(self, key, sids, now_ms, atomic=False):
        """批量下线一批会话，返回 LF 结尾的 JSON 字符串。

        key 沿用凭据约束；sids 为含 1..1000 个互异 sid 的 tuple（sid 沿用
        凭据约束）；now_ms 为非 bool 非负 int，atomic 为 bool。依序校验：
        类型错 TypeError，取值、长度、重复 sid 错 ValueError。key 有效后以
        独立域（与 do/meter/capacity/fault/pool_fault/timeout_fault 分域）
        永久缓存首果（含参数异常）：同型同参重放不老化、不改态，直接返回或
        重抛；异参抛 ValueError。

        首次合法调用先老化（在线期限到先挂起释址、租期到释址）。非原子时依
        输入顺序逐项处理：现存项（在线/挂起/下线墓碑）置下线、期限 0 并释放
        地址租约，记“下线”；未知 sid 记“未知”，不影响后项。原子时基于老化
        后快照先查全部项：有未知项则未知项记“未知”、其余现存项记“回滚”，
        不执行任何下线（但保留老化结果）；全部存在才逐项提交下线。未知不抛
        异常。不写既有审计（audit）或容量事件。合法首调按输入序逐项写独立的
        批量防篡改审计链 batch_audit（操作“批量下线”）：逐项结果取项目结果
        （下线/未知/回滚）、原序号 0；同参重放不老化、不改态，逐项记结果
        “重放”、原序号指认对应首次事件；参数错首果与异参 key 不记。返回
        顶层键序“时刻/原子/结果/项目”：结果
        仅提交（全部项处理成功）、部分（非原子含未知）、回滚（原子含未知）；
        项目依输入顺序，项键序“会话/结果”，项结果仅下线/未知/回滚。首次
        调用 O(S+B log A) 时间、O(B) 辅助空间，重放 O(B)。
        """
        _check_credential("key", key)

        cached = self._batch_offline_cache.get(key)
        if cached is not None:
            # 重放：不老化、不下线、不改态；合法首果的同参重放按输入序逐项
            # 记“重放”，原序号指认对应首次事件。参数错首果不记。
            c_sids, c_now_ms, c_atomic, outcome = cached
            if not _strict_equal(
                (sids, now_ms, atomic), (c_sids, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                origin = self._batch_offline_chain_index.get(key)
                if origin is not None:
                    self._batch_chain_record(
                        key, _BATCH_AUDIT_OFFLINE, c_sids, c_atomic, now_ms, origin,
                        self._batch_offline_chain_index,
                    )
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存；校验失败不老化、不改态。
        try:
            self._validate_batch_offline_params(sids, now_ms, atomic)
        except (TypeError, ValueError) as exc:
            self._batch_offline_cache[key] = (
                sids,
                now_ms,
                atomic,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 首次合法调用：先老化（与其他写接口一致，老化先于业务处理）。
        self._age(now_ms)

        if atomic:
            items, commit = self._batch_offline_atomic(sids, now_ms)
        else:
            items, commit = self._batch_offline_sequential(sids, now_ms)
        if commit:
            result = _BATCH_COMMIT
        else:
            result = _BATCH_PARTIAL if not atomic else _BATCH_ROLLBACK
        output = self._render_batch_offline(now_ms, atomic, result, items)
        self._batch_offline_cache[key] = (
            sids,
            now_ms,
            atomic,
            ("ok", output),
        )
        # 合法首调：按输入序逐项追加首次事件，结果取各项目结果、原序号 0。
        self._batch_chain_record(
            key,
            _BATCH_AUDIT_OFFLINE,
            sids,
            atomic,
            now_ms,
            0,
            self._batch_offline_chain_index,
            [item["结果"] for item in items],
        )
        return output

    @staticmethod
    def _validate_batch_offline_params(sids, now_ms, atomic):
        """校验 batch_offline 三参数：类型错先于取值/长度/重复错。

        sids 须为 tuple，含 1..1000 个满足凭据约束且互异的 sid；now_ms 为
        非 bool 非负 int；atomic 为 bool。类型阶段先查容器/各 sid/now_ms/
        atomic 的类型；取值阶段依序查 sid 取值与 now_ms 下界、长度上下界、
        sid 重复。
        """
        # 类型阶段：任一类型错先于任何取值错抛出。
        if not isinstance(sids, tuple):
            raise TypeError(f"sids must be a tuple, got {type(sids).__name__}")
        for sid in sids:
            if not isinstance(sid, str):
                raise TypeError(
                    f"sid must be a str, got {type(sid).__name__}"
                )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if not isinstance(atomic, bool):
            raise TypeError(f"atomic must be a bool, got {type(atomic).__name__}")

        # 取值阶段：值、长度、重复。
        for sid in sids:
            _check_credential("sid", sid)
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(sids) <= _BATCH_MAX_SIDS):
            raise ValueError(
                f"sids must contain 1..{_BATCH_MAX_SIDS} items, got {len(sids)}"
            )
        if len(set(sids)) != len(sids):
            raise ValueError("sids must not contain duplicate sid")

    def _batch_offline_sequential(self, sids, now_ms):
        """非原子逐项处理：现存项下线释址记“下线”，未知记“未知”，不影响后项。

        返回 (items, commit)：commit 恒为是否无未知项。
        """
        items = []
        commit = True
        for sid in sids:
            session = self._sessions.get(sid)
            if session is None:
                items.append({"会话": sid, "结果": _CAP_UNKNOWN})
                commit = False
                continue
            # 现存项（在线/挂起/下线墓碑）：置下线、期限 0 并释放地址租约。
            # 计费停止（批量下线）在清场前结账；墓碑无活动账为空操作。
            self._account_stop(sid, now_ms, _ACCOUNT_REASON_BATCH)
            session["state"] = _STATE_OFFLINE
            session["deadline"] = 0
            self._release(session)
            items.append({"会话": sid, "结果": _STATE_OFFLINE})
        return items, commit

    def _batch_offline_atomic(self, sids, now_ms):
        """原子批量：基于老化后快照先查全部项。

        有未知项则不执行任何下线（保留老化结果），未知记“未知”、现存记
        “回滚”，commit=False；全部存在才逐项提交下线，commit=True。
        返回 (items, commit)。
        """
        unknown = [sid for sid in sids if sid not in self._sessions]
        if unknown:
            unknown_set = set(unknown)
            items = [
                {"会话": sid, "结果": _CAP_UNKNOWN if sid in unknown_set else _BATCH_ROLLBACK}
                for sid in sids
            ]
            return items, False
        # 全部存在：逐项提交下线（置下线、期限 0、释放地址租约）；计费停止
        # （批量下线）在清场前按输入序结账。
        items = []
        for sid in sids:
            session = self._sessions[sid]
            self._account_stop(sid, now_ms, _ACCOUNT_REASON_BATCH)
            session["state"] = _STATE_OFFLINE
            session["deadline"] = 0
            self._release(session)
            items.append({"会话": sid, "结果": _STATE_OFFLINE})
        return items, True

    @staticmethod
    def _render_batch_offline(now_ms, atomic, result, items):
        # 顶层键序：时刻、原子、结果、项目；时刻为 int，原子为 bool，
        # 结果为 str，项目为项（会话/结果）列表，依输入顺序。
        payload = {
            "时刻": now_ms,
            "原子": atomic,
            "结果": result,
            "项目": items,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def batch_online(self, key, items, now_ms, atomic=False):
        """批量建立一批会话，返回 LF 结尾的 JSON 字符串。

        key 沿用凭据约束；items 为含 1..1000 个 (sid, user, password)
        三元组 tuple 的 tuple，三个串均沿用凭据约束且 sid 互异；now_ms
        为非 bool 非负 int，atomic 为 bool。依序校验：类型错 TypeError，
        取值、长度、重复 sid 错 ValueError。key 有效后以独立域（与
        do/meter/capacity/fault/pool_fault/timeout_fault/batch_offline
        分域）永久缓存首果（含参数异常）：同型同参重放不老化、不改态，
        直接返回或重抛；异参抛 ValueError。

        首次合法调用先老化（在线期限到先挂起释址、租期到释址），随后依
        输入顺序逐项处理：先查后端（故障期按用户指数退避抛 BackendError，
        只改退避、不计故障统计），再沿用建立的认证、全局与单用户容量、
        sid 唯一、自动选池（模板地址池序列，未配置序列仅 default）与静态址规则。业务异常（AuthError/
        ResourceError/StateError/BackendError/KeyError）不抛，项结果记
        其类名。非原子逐项提交，失败项不影响后项；原子演算全部项，任一
        失败则批内不建会话/租约（已建者回滚、释放地址租约），失败项记
        异常类名、余项记“回滚”；老化、认证计数与退避保留。不写既有审计
        （audit）或容量事件，不计建立/失败统计。合法首调按输入序逐项写独立
        的批量防篡改审计链 batch_audit（操作“批量上线”）：逐项结果取项目结果
        （上线/业务异常类名/回滚）、原序号 0；同参重放不老化、不改态，逐项
        记结果“重放”、原序号指认对应首次事件；参数错首果与异参 key 不记。
        返回顶层键序“时刻/原子/结果/项目”：
        结果仅提交（全部上线）、部分（非原子有失败）、回滚（原子有
        失败）；项目依输入顺序，项键序“会话/结果”，项结果仅上线/业务
        异常类名/回滚。首次调用 O(S+B log A) 时间、O(B) 辅助空间，
        重放 O(B)。
        """
        _check_credential("key", key)

        cached = self._batch_online_cache.get(key)
        if cached is not None:
            # 重放：不老化、不建立、不改态；合法首果的同参重放按输入序逐项
            # 记“重放”，原序号指认对应首次事件。参数错首果不记。
            c_items, c_now_ms, c_atomic, outcome = cached
            if not _strict_equal(
                (items, now_ms, atomic), (c_items, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                origin = self._batch_online_chain_index.get(key)
                if origin is not None:
                    self._batch_chain_record(
                        key,
                        _BATCH_AUDIT_ONLINE,
                        [entry[0] for entry in c_items],
                        c_atomic,
                        now_ms,
                        origin,
                        self._batch_online_chain_index,
                    )
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存；校验失败不老化、不改态。
        try:
            self._validate_batch_online_params(items, now_ms, atomic)
        except (TypeError, ValueError) as exc:
            self._batch_online_cache[key] = (
                items,
                now_ms,
                atomic,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 首次合法调用：先老化（与其他写接口一致，老化先于业务处理）。
        self._age(now_ms)

        # 容量计数只扫一次会话表，随批内建立增量维护（同 _cap_advance）。
        total_count, per_user, per_template = self._active_counts()
        results = []
        created = []
        # 计费：批内每成功一项即在其提交点开账（开始事件按输入序追加）；
        # 原子批回滚时整批撤账（链截断至批前、删活动账），非原子只留实际
        # 提交项。失败项与重放不产生事件或累计。
        account_seq = len(self._account_events)
        all_ok = True
        for sid, user, password in items:
            try:
                # 停用态用户先于后端检查与认证拒绝：项结果记 AuthError，
                # 不认证、不退避、不计失败计数。
                if user in self._disabled_users:
                    raise AuthError(f"user {user!r} is disabled")
                self._backend_check(user, now_ms, count_fault=False)
                self._batch_establish(
                    sid, user, password, now_ms, total_count, per_user, per_template
                )
            except (AuthError, ResourceError, StateError, BackendError, KeyError) as exc:
                # 业务异常不抛：项结果记异常类名，不影响后项。
                results.append({"会话": sid, "结果": type(exc).__name__})
                all_ok = False
            else:
                created.append(sid)
                self._account_start(sid, now_ms)
                total_count += 1
                per_user[user] = per_user.get(user, 0) + 1
                template_id = self._user_templates.get(user)
                if template_id is not None:
                    per_template[template_id] = per_template.get(template_id, 0) + 1
                results.append({"会话": sid, "结果": _BATCH_ITEM_ONLINE})

        if atomic and not all_ok:
            # 整批回滚：摘除批内所建会话并释放其地址租约（静态址仅退租）；
            # 老化、认证计数与退避保留。计费整批撤账：链截断至批前长度，
            # 末哈希与活动账同步回退，不留开始事件或累计。
            for sid in created:
                self._release(self._sessions.pop(sid))
                self._account_active.pop(sid, None)
            del self._account_events[account_seq:]
            self._account_tail = (
                self._account_events[-1][10] if self._account_events else "0" * 64
            )
            for entry in results:
                if entry["结果"] == _BATCH_ITEM_ONLINE:
                    entry["结果"] = _BATCH_ROLLBACK

        if all_ok:
            result = _BATCH_COMMIT
        else:
            result = _BATCH_ROLLBACK if atomic else _BATCH_PARTIAL
        output = self._render_batch_online(now_ms, atomic, result, results)
        self._batch_online_cache[key] = (items, now_ms, atomic, ("ok", output))
        # 合法首调：按输入序逐项追加首次事件，结果取各项目结果（原子回滚后
        # 已为“回滚”）、原序号 0。
        self._batch_chain_record(
            key,
            _BATCH_AUDIT_ONLINE,
            [entry[0] for entry in items],
            atomic,
            now_ms,
            0,
            self._batch_online_chain_index,
            [entry["结果"] for entry in results],
        )
        return output

    @staticmethod
    def _validate_batch_online_params(items, now_ms, atomic):
        """校验 batch_online 三参数：类型错先于取值/长度/重复错。

        items 须为 tuple，含 1..1000 个 (sid, user, password) 三元组
        tuple，三个串均满足凭据约束且 sid 互异；now_ms 为非 bool 非负
        int；atomic 为 bool。类型阶段先查容器/各项/各串/now_ms/atomic
        的类型；取值阶段依序查各项长度与三串取值、now_ms 下界、项数
        上下界、sid 重复。
        """
        # 类型阶段：任一类型错先于任何取值错抛出。
        if not isinstance(items, tuple):
            raise TypeError(f"items must be a tuple, got {type(items).__name__}")
        for item in items:
            if not isinstance(item, tuple):
                raise TypeError(
                    f"item must be a tuple, got {type(item).__name__}"
                )
            for field in item:
                if not isinstance(field, str):
                    raise TypeError(
                        f"item field must be a str, got {type(field).__name__}"
                    )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if not isinstance(atomic, bool):
            raise TypeError(f"atomic must be a bool, got {type(atomic).__name__}")

        # 取值阶段：项长度、凭据值、下界、项数、重复。
        for item in items:
            if len(item) != 3:
                raise ValueError(
                    "item must be a 3-tuple (sid, user, password), "
                    f"got {len(item)} items"
                )
            _check_credential("sid", item[0])
            _check_credential("user", item[1])
            _check_credential("password", item[2])
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(items) <= _BATCH_MAX_SIDS):
            raise ValueError(
                f"items must contain 1..{_BATCH_MAX_SIDS} items, got {len(items)}"
            )
        sids = [item[0] for item in items]
        if len(set(sids)) != len(sids):
            raise ValueError("items must not contain duplicate sid")

    def _batch_establish(
        self, sid, user, password, now_ms, total_count, per_user, per_template
    ):
        """批内单项建立：规则与 _establish 相同（认证→容量→模板占用→sid
        唯一→自动选池序列→各池静态址），但容量与模板占用计数由调用方按批增量
        维护，故批处理整体为 O(S+B log A) 而非 O(B*S)。

        成功原子落库在线会话；失败抛既有业务异常，不留会话与租约残留。
        """
        # 先认证。
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")
        # 后查 total 及用户 per，均计非下线会话（计数由调用方增量维护）。
        if total_count >= self._total:
            raise ResourceError(f"total session limit {self._total} reached")
        if per_user.get(user, 0) >= self._per:
            raise ResourceError(
                f"per-user session limit {self._per} reached for {user!r}"
            )
        # 模板并发会话上限：占用为绑定该模板用户的在线加挂起会话数。
        template_id = self._user_templates.get(user)
        if template_id is not None:
            session_limit = self._templates[template_id][4]
            if session_limit and per_template.get(template_id, 0) >= session_limit:
                raise ResourceError(
                    f"template session limit {session_limit} reached "
                    f"for template {template_id!r}"
                )
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")

        # 自动取址：绑定模板按其模板地址池优先序列、其余仅 default 池依次
        # 检查；序列无现存池为 StateError（零池模式）。
        pool_id, ip_int = self._select_address(user, now_ms)
        if pool_id is None:
            raise StateError("no address pool available: cannot establish session")
        if ip_int is None:
            raise ResourceError(
                f"no address available in candidate pools for {user!r}"
            )

        # 全部校验通过后再落库，杜绝失败残留。
        self._commit_session(sid, user, pool_id, ip_int, now_ms)

    @staticmethod
    def _render_batch_online(now_ms, atomic, result, items):
        # 顶层键序：时刻、原子、结果、项目；时刻为 int，原子为 bool，
        # 结果为 str，项目为项（会话/结果）列表，依输入顺序。
        payload = {
            "时刻": now_ms,
            "原子": atomic,
            "结果": result,
            "项目": items,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def batch_migrate(self, key, items, now_ms, atomic=False):
        """批量迁移一批会话，返回 LF 结尾的 JSON 字符串。

        key 沿用凭据约束；items 为含 1..1000 个 (sid, target, password)
        三元组 tuple 的 tuple，三个串均沿用凭据约束且 sid 互异；now_ms
        为非 bool 非负 int，atomic 为 bool。依序校验：类型错 TypeError，
        取值、长度、重复 sid 错 ValueError。key 有效后以独立域（与
        do/meter/capacity/fault/pool_fault/timeout_fault/batch_offline/
        batch_online/keepalive 分域）永久缓存首果（含参数异常）：同型同参
        重放不老化、不改态，直接返回或重抛；异参抛 ValueError。

        首次合法调用先老化（在线期限到先挂起释址、租期到释址），随后逐项
        沿用 do 迁移规则（零池 StateError、未知 sid/target KeyError、非持址
        在线或同池 StateError、认证非 ok AuthError、目标池耗尽或静态占用
        ResourceError；后端故障期按会话用户指数退避抛 BackendError，只改
        退避）。业务异常不抛，项结果记其类名。非原子逐项提交：释出地址即
        回本池堆，影响后项取址，失败项不影响后项。原子时在同一老化后演算态
        上按输入顺序预演全部项：前项失败不阻止后项判定，成功项的临时地址
        变化影响后项取址；每个失败项保留自身异常类名，仅预演成功项记“回滚”，
        任一失败即把会话、池空闲地址与租约恢复至老化后快照（认证失败计数、
        锁定与退避保留），全成功才提交并记“迁移”。失败不计 user_stats/
        runtime_stats/fault_stats；不写既有审计（audit）或容量事件。合法首调
        按输入序逐项写独立的批量防篡改审计链 batch_audit（操作“批量迁移”）：
        逐项结果取项目结果（迁移/业务异常类名/回滚）、原序号 0；同参重放不
        老化、不改态，逐项记结果“重放”、原序号指认对应首次事件；参数错首果
        与异参 key 不记。返回顶层键序
        “时刻/原子/结果/项目”：结果仅提交（全部迁移）、部分（非原子有
        失败）、回滚（原子有失败）；项目依输入顺序，项键序“会话/结果”，
        项结果仅迁移/业务异常类名/回滚。首次调用 O(S+B log A) 时间、O(B)
        辅助空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._batch_migrate_cache.get(key)
        if cached is not None:
            # 重放：不老化、不迁移、不改态；合法首果的同参重放按输入序逐项
            # 记“重放”，原序号指认对应首次事件。参数错首果不记。
            c_items, c_now_ms, c_atomic, outcome = cached
            if not _strict_equal(
                (items, now_ms, atomic), (c_items, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                origin = self._batch_migrate_chain_index.get(key)
                if origin is not None:
                    self._batch_chain_record(
                        key,
                        _BATCH_AUDIT_MIGRATE,
                        [entry[0] for entry in c_items],
                        c_atomic,
                        now_ms,
                        origin,
                        self._batch_migrate_chain_index,
                    )
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise _replay_exception(exc_class, exc_args)

        # 新 key：余参校验本身的异常同样入缓存；校验失败不老化、不改态。
        try:
            self._validate_batch_migrate_params(items, now_ms, atomic)
        except (TypeError, ValueError) as exc:
            self._batch_migrate_cache[key] = (
                items,
                now_ms,
                atomic,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 首次合法调用：先老化（与其他写接口一致，老化先于业务处理）。
        self._age(now_ms)

        if atomic:
            results, all_ok = self._batch_migrate_atomic(items, now_ms)
        else:
            results, all_ok = self._batch_migrate_sequential(items, now_ms)

        if all_ok:
            result = _BATCH_COMMIT
        else:
            result = _BATCH_ROLLBACK if atomic else _BATCH_PARTIAL
        output = self._render_batch_migrate(now_ms, atomic, result, results)
        self._batch_migrate_cache[key] = (items, now_ms, atomic, ("ok", output))
        # 合法首调：按输入序逐项追加首次事件，结果取各项目结果（原子回滚后
        # 成功预演项已为“回滚”）、原序号 0。
        self._batch_chain_record(
            key,
            _BATCH_AUDIT_MIGRATE,
            [entry[0] for entry in items],
            atomic,
            now_ms,
            0,
            self._batch_migrate_chain_index,
            [entry["结果"] for entry in results],
        )
        return output

    @staticmethod
    def _validate_batch_migrate_params(items, now_ms, atomic):
        """校验 batch_migrate 三参数：类型错先于取值/长度/重复错。

        items 须为 tuple，含 1..1000 个 (sid, target, password) 三元组
        tuple，三个串均满足凭据约束且 sid 互异；now_ms 为非 bool 非负
        int；atomic 为 bool。类型阶段先查容器/各项/各串/now_ms/atomic
        的类型；取值阶段依序查各项长度与三串取值、now_ms 下界、项数
        上下界、sid 重复。
        """
        # 类型阶段：任一类型错先于任何取值错抛出。
        if not isinstance(items, tuple):
            raise TypeError(f"items must be a tuple, got {type(items).__name__}")
        for item in items:
            if not isinstance(item, tuple):
                raise TypeError(
                    f"item must be a tuple, got {type(item).__name__}"
                )
            for field in item:
                if not isinstance(field, str):
                    raise TypeError(
                        f"item field must be a str, got {type(field).__name__}"
                    )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if not isinstance(atomic, bool):
            raise TypeError(f"atomic must be a bool, got {type(atomic).__name__}")

        # 取值阶段：项长度、凭据值、下界、项数、重复。
        for item in items:
            if len(item) != 3:
                raise ValueError(
                    "item must be a 3-tuple (sid, target, password), "
                    f"got {len(item)} items"
                )
            _check_credential("sid", item[0])
            _check_credential("target", item[1])
            _check_credential("password", item[2])
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(items) <= _BATCH_MAX_SIDS):
            raise ValueError(
                f"items must contain 1..{_BATCH_MAX_SIDS} items, got {len(items)}"
            )
        sids = [item[0] for item in items]
        if len(set(sids)) != len(sids):
            raise ValueError("items must not contain duplicate sid")

    def _batch_migrate_sequential(self, items, now_ms):
        """非原子逐项迁移，逐项提交：释出地址即回本池堆，影响后项取址。

        业务异常不抛：项结果记异常类名，失败项不影响后项。后端故障只改
        退避；认证失败计数与锁定由认证器自然保留。返回 (results, all_ok)。
        """
        results = []
        all_ok = True
        for sid, target, password in items:
            try:
                self._batch_migrate_one(sid, target, password, now_ms)
            except (
                AuthError,
                ResourceError,
                StateError,
                BackendError,
                KeyError,
            ) as exc:
                results.append({"会话": sid, "结果": type(exc).__name__})
                all_ok = False
            else:
                results.append({"会话": sid, "结果": _BATCH_ITEM_MIGRATE})
        return results, all_ok

    def _batch_migrate_atomic(self, items, now_ms):
        """原子批量迁移：对老化后快照预演全部项，全部成功才提交。

        预演即在真实状态上按输入顺序逐项迁移，但动态址的取/释用两套 O(B)
        结构与原池堆协同：迁出释出的动态址入按池的 reclaimed 侧堆（仍可见，
        供后项取址），自原池堆弹出的址记入 borrowed 供回滚推回。取址取
        “原池堆顶”与“reclaimed 堆顶”的较小者，故与逐项提交的取址完全一致，
        且不会把尚未提交的释址误计为空闲而虚假耗尽。前项失败不阻止后项判定：
        失败项不改会话/池/租约（失败路径先于任何池变更），故后项在其之前
        全部成功项临时改址后的演算态上继续判定，成功项的临时址变化可见。
        任一失败即回滚：各失败项保留自身异常类名，仅预演成功项改记“回滚”，
        逆序撤销成功项（恢复旧址/源池/旧租期与原池堆）；认证失败计数、锁定
        与后端退避不回滚（老化结果亦保留）。全部成功则把剩余 reclaimed 址
        并入各源池堆提交。整体 O(B log A) 时间、O(B) 辅助空间。返回
        (results, all_ok)。
        """
        # pool_id -> 预演中释出且尚未被后项再取走的动态址最小堆。
        reclaimed = {}
        # pool_id -> 预演中自原池堆弹出的动态址（回滚时推回）。
        borrowed = {}
        # 每条成功迁移的反向信息：
        # (sid, 源池, 旧址, 旧租期, 目标池, 新址)。
        undo = []
        results = []
        all_ok = True
        for sid, target, password in items:
            # 前项失败不阻止后项：每项都在老化后且含此前成功项临时改址的
            # 演算态上判定。失败项在任何池/会话变更前抛出，仅留下须保留的
            # 认证计数/退避，故不留地址残留，后项可继续。
            session = self._sessions.get(sid)
            # 先记录迁移前旧值（session 即 self._sessions[sid]，会被就地改写）。
            old_pool = session["pool"] if session is not None else None
            old_ip = session["ip"] if session is not None else None
            old_lease = session["lease"] if session is not None else None
            try:
                self._batch_migrate_one(
                    sid, target, password, now_ms, reclaimed, borrowed
                )
            except (
                AuthError,
                ResourceError,
                StateError,
                BackendError,
                KeyError,
            ) as exc:
                # 各失败项保留自身异常类名；预演继续判定后项。
                results.append({"会话": sid, "结果": type(exc).__name__})
                all_ok = False
            else:
                undo.append(
                    (
                        sid,
                        old_pool,
                        old_ip,
                        old_lease,
                        target,
                        self._sessions[sid]["ip"],
                    )
                )
                results.append({"会话": sid, "结果": _BATCH_ITEM_MIGRATE})
        if not all_ok:
            # 各失败项保留异常类名，仅预演成功项改记“回滚”，并把会话、池
            # 空闲地址与租约恢复至老化后快照。
            for entry in results:
                if entry["结果"] == _BATCH_ITEM_MIGRATE:
                    entry["结果"] = _BATCH_ROLLBACK
            self._batch_migrate_undo(undo, reclaimed, borrowed)
        else:
            # 全部成功才提交：把未被再取走的 reclaimed 动态址并入各源池堆。
            for pool_id, heap in reclaimed.items():
                target_free = self._pools[pool_id].free
                for addr in heap:
                    heapq.heappush(target_free, addr)
        return results, all_ok

    def _batch_migrate_undo(self, undo, reclaimed, borrowed):
        """按反向日志逆序撤销预演中已成功的迁移，恢复至老化后快照。

        逆序删各项目标池新租约、恢复其源池旧租约与会话址/池/旧租期。动态
        新址分两类恢复：自原池堆弹出者（在 borrowed 中）最后统一推回原池
        堆；取自 reclaimed 者必为本批更早某项的旧址，随该项逆序恢复自然
        重新入源池租约（消费恒晚于释出，故逆序恢复恒先于释出项）。reclaimed
        弃置。
        """
        for sid, source_id, old_ip, old_lease, target_id, new_ip in reversed(undo):
            del self._pools[target_id].leases[new_ip]
            self._pools[source_id].leases[old_ip] = sid
            session = self._sessions[sid]
            session["ip"] = old_ip
            session["pool"] = source_id
            session["lease"] = old_lease
        # 自原池堆弹出的动态址未被迁移最终持有，推回各原池堆。
        for pool_id, addrs in borrowed.items():
            target_free = self._pools[pool_id].free
            for addr in addrs:
                heapq.heappush(target_free, addr)

    def _batch_migrate_one(
        self, sid, target, password, now_ms, reclaimed=None, borrowed=None
    ):
        """批内单项迁移：规则同 do 迁移，后端检查沿用 do 首次路径（按会话
        用户退避，不计 fault_stats）；失败抛既有业务异常，不换址。

        序同 do 迁移：未知 sid KeyError、停用 AuthError、后端 BackendError
        均先于老化后的零池 StateError、未知 target KeyError、状态/同池
        StateError、认证 AuthError、目标池耗尽或静态占用 ResourceError。

        reclaimed/borrowed 均为 None（非原子）时动态旧址即回源池堆、逐项
        提交；否则（原子预演）动态址经两结构与原池堆协同取释，见
        _batch_migrate_atomic。成功即就地换址，无返回值。
        """
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        user = session["user"]
        # 停用态用户先于后端检查与认证拒绝（同 do 迁移）：不认证、不退避。
        if user in self._disabled_users:
            raise AuthError(f"user {user!r} is disabled")
        # 后端检查在状态与目标池校验之前（同 do 迁移）；只改退避，不计
        # fault_stats（其口径仅 do 与 capacity）。
        self._backend_check(user, now_ms, count_fault=False)

        if not self._pools:
            raise StateError("no pool: no address pool configured")
        target_pool = self._pools.get(target)
        if target_pool is None:
            raise KeyError(f"unknown target pool: {target!r}")
        if session["state"] != _STATE_ONLINE or session["ip"] is None:
            raise StateError(
                f"cannot migrate sid {sid!r} in state {session['state']!r} "
                "without address"
            )
        source_id = session["pool"]
        if source_id == target:
            raise StateError(f"sid {sid!r} already in target pool {target!r}")

        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")

        # 耗尽演练：目标池在注入期视为无址可分配，先于任何池变更，无半换址。
        if self._pool_is_exhausted(target, now_ms):
            raise ResourceError(f"target pool {target!r} exhausted")

        source_pool = self._pools[source_id]
        old_ip = session["ip"]
        new_ip = target_pool.static.get(user)
        if new_ip is None:
            # 非静态用户取最小动态空闲址。非原子直接取原池堆顶；原子预演时
            # 可取址为“原池堆”并“本批释出的 reclaimed 堆”，取两者堆顶较小者，
            # 与逐项提交的单一空闲堆取址完全一致。
            reclaim_heap = None if reclaimed is None else reclaimed.get(target)
            free_top = target_pool.free[0] if target_pool.free else None
            rec_top = reclaim_heap[0] if reclaim_heap else None
            if free_top is None and rec_top is None:
                raise ResourceError(f"target pool {target!r} exhausted")
            if rec_top is None or (
                free_top is not None and free_top <= rec_top
            ):
                new_ip = heapq.heappop(target_pool.free)
                if borrowed is not None:
                    borrowed.setdefault(target, []).append(new_ip)
            else:
                new_ip = heapq.heappop(reclaim_heap)
        elif new_ip in target_pool.leases:
            # 目标静态址已被同用户的另一会话占用。
            raise ResourceError(
                f"static address {ipaddress.IPv4Address(new_ip)} for {user!r} "
                "already in use"
            )

        # 全部校验通过：原子释旧址、换池址。非原子时动态旧址即回源池堆
        # （逐项提交，影响后项）；原子预演时旧址入源池 reclaimed 堆，仍对
        # 后项可见，提交时未被再取走者才并入源池堆。
        del source_pool.leases[old_ip]
        if old_ip not in source_pool.static_ips:
            if reclaimed is None:
                heapq.heappush(source_pool.free, old_ip)
            else:
                heapq.heappush(reclaimed.setdefault(source_id, []), old_ip)
        target_pool.leases[new_ip] = sid
        session["ip"] = new_ip
        session["pool"] = target
        # 迁移重置租期，空闲期限（期限）保持不变。
        session["lease"] = now_ms + self._lease_ms

    @staticmethod
    def _render_batch_migrate(now_ms, atomic, result, items):
        # 顶层键序：时刻、原子、结果、项目；时刻为 int，原子为 bool，
        # 结果为 str，项目为项（会话/结果）列表，依输入顺序。
        payload = {
            "时刻": now_ms,
            "原子": atomic,
            "结果": result,
            "项目": items,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def keepalive(self, key, sids, now_ms, atomic=False):
        """批量保活一批会话，返回 LF 结尾的 JSON 字符串。

        key 沿用凭据约束；sids 为含 1..1000 个互异 sid 的 tuple（sid 沿用
        凭据约束）；now_ms 为非 bool 非负 int，atomic 为 bool。依序校验：
        类型错 TypeError，取值、长度、重复 sid 错 ValueError。key 有效后以
        独立域（与 do/meter/capacity/fault/pool_fault/timeout_fault/
        batch_offline/batch_online 分域）永久缓存首果（含参数异常）：同型
        同参重放不老化、不改态，直接返回或重抛；异参抛 ValueError。

        首次合法调用先老化（期限 <= now_ms 的在线项挂起、清期限并释放地址
        租约，老化不回滚）。非原子时依输入顺序逐项处理：在线项（老化后仍
        在线）把空闲期限改为 now_ms+idle_ms 并记“保活”（只改期限，不续租、
        不分址、不写既有审计链、不记容量事件、不计统计）；未知 sid 记“未知”，
        其余现存项（挂起/下线墓碑）记“状态”，失败项不影响后项。原子时基于
        老化后快照先查全部项：全部在线才逐项提交保活；否则失败项记“未知”/
        “状态”、在线项记“回滚”，不延长任何期限（老化保留）。合法首调按输入
        序逐项写独立的批量防篡改审计链 batch_audit（操作“批量保活”）：逐项
        结果取项目结果（保活/未知/状态/回滚）、原序号 0；同参重放不老化、不
        改态，逐项记结果“重放”、原序号指认对应首次事件；参数错首果与异参
        key 不记。返回顶层键序
        “时刻/原子/结果/项目”：结果仅提交（全部保活）、部分（非原子有失败
        项）、回滚（原子有失败项）；项目依输入顺序，项键序“会话/结果/期限”，
        项结果仅保活/未知/状态/回滚，保活项期限取改后的新值，余项期限恒为 0。
        首次调用 O(S+B log A) 时间、O(B) 辅助空间，重放 O(B)。
        """
        _check_credential("key", key)

        cached = self._keepalive_cache.get(key)
        if cached is not None:
            # 重放：不老化、不保活、不改态；合法首果的同参重放按输入序逐项
            # 记“重放”，原序号指认对应首次事件。参数错首果不记。
            c_sids, c_now_ms, c_atomic, outcome = cached
            if not _strict_equal(
                (sids, now_ms, atomic), (c_sids, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                origin = self._batch_keepalive_chain_index.get(key)
                if origin is not None:
                    self._batch_chain_record(
                        key, _BATCH_AUDIT_KEEPALIVE, c_sids, c_atomic, now_ms, origin,
                        self._batch_keepalive_chain_index,
                    )
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存；校验失败不老化、不改态。
        # 参数契约与 batch_offline 完全一致（tuple、1..1000、sid 凭据、互异）。
        try:
            self._validate_batch_offline_params(sids, now_ms, atomic)
        except (TypeError, ValueError) as exc:
            self._keepalive_cache[key] = (
                sids,
                now_ms,
                atomic,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 首次合法调用：先老化（期限到先挂起释址，老化不回滚）。
        self._age(now_ms)

        if atomic:
            items, commit = self._keepalive_atomic(sids, now_ms)
        else:
            items, commit = self._keepalive_sequential(sids, now_ms)
        if commit:
            result = _BATCH_COMMIT
        else:
            result = _BATCH_PARTIAL if not atomic else _BATCH_ROLLBACK
        output = self._render_keepalive(now_ms, atomic, result, items)
        self._keepalive_cache[key] = (sids, now_ms, atomic, ("ok", output))
        # 合法首调：按输入序逐项追加首次事件，结果取各项目结果、原序号 0。
        self._batch_chain_record(
            key,
            _BATCH_AUDIT_KEEPALIVE,
            sids,
            atomic,
            now_ms,
            0,
            self._batch_keepalive_chain_index,
            [item["结果"] for item in items],
        )
        return output

    def _keepalive_sequential(self, sids, now_ms):
        """非原子逐项保活：在线项改期限为 now_ms+idle_ms 记“保活”，未知记
        “未知”，挂起/下线墓碑记“状态”，失败项不影响后项。

        只改空闲期限，不续租、不分址。返回 (items, commit)：commit 恒为
        是否无失败项。
        """
        items = []
        commit = True
        new_deadline = now_ms + self._idle_ms
        for sid in sids:
            session = self._sessions.get(sid)
            if session is None:
                items.append({"会话": sid, "结果": _CAP_UNKNOWN, "期限": 0})
                commit = False
                continue
            if session["state"] != _STATE_ONLINE:
                items.append({"会话": sid, "结果": _KEEPALIVE_STATE, "期限": 0})
                commit = False
                continue
            session["deadline"] = new_deadline
            items.append(
                {"会话": sid, "结果": _KEEPALIVE_OK, "期限": new_deadline}
            )
        return items, commit

    def _keepalive_atomic(self, sids, now_ms):
        """原子批量：基于老化后快照先查全部项。

        全部在线才逐项提交保活（改期限）；否则失败项记“未知”（不存在）/
        “状态”（挂起/下线墓碑），在线项记“回滚”，不延长任何期限（老化保留），
        commit=False。返回 (items, commit)。
        """
        failed = {}
        all_online = True
        for sid in sids:
            session = self._sessions.get(sid)
            if session is None:
                failed[sid] = _CAP_UNKNOWN
                all_online = False
            elif session["state"] != _STATE_ONLINE:
                failed[sid] = _KEEPALIVE_STATE
                all_online = False
        if not all_online:
            items = [
                {"会话": sid, "结果": failed[sid], "期限": 0}
                if sid in failed
                else {"会话": sid, "结果": _BATCH_ROLLBACK, "期限": 0}
                for sid in sids
            ]
            return items, False
        # 全部在线：逐项保活，仅把空闲期限改为 now_ms+idle_ms。
        new_deadline = now_ms + self._idle_ms
        items = []
        for sid in sids:
            session = self._sessions[sid]
            session["deadline"] = new_deadline
            items.append(
                {"会话": sid, "结果": _KEEPALIVE_OK, "期限": new_deadline}
            )
        return items, True

    @staticmethod
    def _render_keepalive(now_ms, atomic, result, items):
        # 顶层键序：时刻、原子、结果、项目；时刻为 int，原子为 bool，
        # 结果为 str，项目为项（会话/结果/期限）列表，依输入顺序，期限为 int。
        payload = {
            "时刻": now_ms,
            "原子": atomic,
            "结果": result,
            "项目": items,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _batch_chain_hash(
        seq, now_ms, key, op, atomic, sid, result, origin, prev_hash
    ):
        """由前九键（键序固定）的紧凑 JSON 之 UTF-8 字节算 sha256 十六进制串。"""
        head = {
            "序号": seq,
            "时刻": now_ms,
            "键": key,
            "操作": op,
            "原子": atomic,
            "会话": sid,
            "结果": result,
            "原序号": origin,
            "前哈希": prev_hash,
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _batch_chain_record(self, key, op, sids, atomic, now_ms, origin, index, results=None):
        """按输入序逐项向批量防篡改审计链追加 B 个事件，O(B) 时空。

        origin=0 为合法首调：逐项结果取 results[i]（返回 JSON 的项目结果）、
        原序号 0，首项序号登记到该操作域的 index；origin>0 为同参重放：逐项
        结果恒“重放”、原序号指认对应首次事件 origin+i（results 不用）。四类
        操作各持 index（同名 key 跨操作不互相指认），事件始终追加到同一条链。
        首项前哈希为 64 个 0，余项承前项。仅追加链事件，不改其余任何状态。
        """
        first_seq = len(self._batch_chain_events) + 1
        for i, sid in enumerate(sids):
            seq = first_seq + i
            prev_hash = self._batch_chain_tail
            if origin:
                result = _BATCH_AUDIT_REPLAY
                item_origin = origin + i
            else:
                result = results[i]
                item_origin = 0
            digest = self._batch_chain_hash(
                seq, now_ms, key, op, atomic, sid, result, item_origin, prev_hash
            )
            event = (seq, now_ms, key, op, atomic, sid, result, item_origin,
                     prev_hash, digest)
            self._batch_chain_events.append(event)
            self._batch_chain_sig_first.setdefault(
                (key, op, atomic, sid), seq
            )
            self._batch_chain_tail = digest
            # 批量项保持输入顺序逐项与其合规投影原子追加。
            self._compliance_append_batch(event)
        if origin == 0:
            index[key] = first_seq

    def batch_audit(self, after=0, limit=100):
        """返回批量操作（上线/下线/迁移/保活/凭据轮换）防篡改审计事件 JSON。

        只读、查询不老化、不改状态，O(limit) 时空。取序号 > after 的前 limit
        项。after/limit 须为非 bool 的 int：类型不符抛 TypeError，after<0 或
        limit ∉ [1,1000] 抛 ValueError。顶层键序为“下个序号/事件”，游标为
        末项序号、空页取 after；事件键序为
        “序号/时刻/键/操作/原子/会话/结果/原序号/前哈希/哈希”，原子为 bool，
        序号/时刻/原序号为 int，余为 str。首项前哈希为 64 个 0，余项承前项
        哈希；哈希为前九键紧凑 JSON（ensure_ascii=False、无空白）UTF-8 字节
        的 sha256 小写值，输出末尾加 LF。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        # 序号即位置+1，序号 > after 的事件自下标 after 起，直接切片。
        window = self._batch_chain_events[after : after + limit]
        events = [
            {
                "序号": seq,
                "时刻": now_ms,
                "键": key,
                "操作": op,
                "原子": atomic,
                "会话": sid,
                "结果": result,
                "原序号": origin,
                "前哈希": prev_hash,
                "哈希": digest,
            }
            for seq, now_ms, key, op, atomic, sid, result, origin, prev_hash, digest in window
        ]
        # 有项取下一序号为末项序号，无项取 after。
        next_seq = window[-1][0] if window else after
        payload = {"下个序号": next_seq, "事件": events}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def batch_audit_restore(self, key, text):
        """将 batch_audit 分页结果原子接入批量防篡改审计链尾，返回 LF 结尾紧凑 JSON。

        key 沿用凭据约束（型/值错 TypeError/ValueError），text 须为 str
        （非 str 抛 TypeError）。text 须为 batch_audit 同法的规范页：JSON、
        重键、编码、结构、范围或事件超过 1000 项错均抛 ValueError；顶层恰为
        “下个序号/事件”且键序如此，事件项恰为十键
        “序号/时刻/键/操作/原子/会话/结果/原序号/前哈希/哈希”且键序如此，
        键序/类型沿 batch_audit 基线（原子为 bool，序号/时刻/原序号为非 bool
        int，余为 str，前哈希/哈希为 64 位小写十六进制）。非空页序号须逐项
        连续、游标（下个序号）等于末项序号，自第 2 项起前哈希须等于上项哈希，
        每项哈希按前九键规则复算相符，原序号为 0 或指向同（键,操作,原子,
        会话）的更早首次项；空页游标须为页锚。整体须为与 batch_audit 同法
        （ensure_ascii=False、separators=(',',':')、单个 LF 结尾）的规范编码。

        页锚：非空页锚序号为首序号减 1、锚哈希为首项前哈希；空页锚序号为
        游标（无锚哈希）。接入前当前批量链末尾须恰为页锚：非空页要求首序号
        等于当前末序号 +1 且首项前哈希等于当前末哈希，空页要求游标等于当前
        末序号；任一不符抛 StateError(页锚序号, 当前末序号)，发生在任何追加
        之前。结构与锚点全验后一次性把事件按原十元组接到批量链尾，失败不改
        链；不恢复业务态、缓存或任何操作幂等（原序号）索引，接入本身不写链。
        不老化。

        验 key 后以独立缓存域且仅缓存成功：同型同 text 重放不解析、不重验、
        不追加，直接返回首次结果原字节，异参抛 ValueError；失败（含参数错与
        StateError）不占 key。返回键序“追加/末序号/末哈希/摘要”：追加:int、
        末序号:int、末哈希:str，摘要为前三键同法紧凑编码 UTF-8 字节的
        sha256 小写值；空页追加 0。O(事件数) 时间、O(事件数) 空间。
        """
        _check_credential("key", key)

        cached = self._batch_audit_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不重验、不追加，仅核对同型同 text 后返回原字节。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        anchor_seq, anchor_hash, events = self._parse_batch_audit_restore_page(text)

        # 锚点：当前批量链末尾（空链为序号 0、64 个 0）须恰为页锚；不符即
        # StateError(页锚序号, 当前末序号)，发生在任何追加之前。空页不携带
        # 锚哈希，仅核对游标序号。
        tail_seq = len(self._batch_chain_events)
        tail_hash = self._batch_chain_tail if tail_seq else "0" * 64
        if events:
            if anchor_seq != tail_seq or anchor_hash != tail_hash:
                raise StateError(anchor_seq, tail_seq)
        elif anchor_seq != tail_seq:
            raise StateError(anchor_seq, tail_seq)

        # 全验后一次追加：事件十元组原样接尾，仅推进批量链序列与末哈希及链
        # 内（键,操作,原子,会话）首次序号校验视图；不动业务态、各缓存与四类
        # 操作幂等（原序号）索引，接入不入链。
        self._batch_chain_events.extend(events)
        if events:
            self._batch_chain_tail = events[-1][9]
            for seq, _now, bkey, op, atomic, sid, _r, _o, _p, _h in events:
                self._batch_chain_sig_first.setdefault(
                    (bkey, op, atomic, sid), seq
                )

        appended = len(events)
        result = self._render_audit_restore(
            appended, tail_seq + appended, self._batch_chain_tail
        )
        self._batch_audit_restore_cache[key] = (text, result)
        return result

    def _parse_batch_audit_restore_page(self, text):
        """解析并严格全量校验 batch_audit 分页文本，返回
        (锚序号, 锚哈希, 事件十元组列表)；空页锚哈希为 None。任何不符契约
        （含非规范编码）处均抛 ValueError，且不读不改当前批量链。

        JSON 解析或重键失败；顶层非恰为“下个序号/事件”且键序如此；
        下个序号非非 bool 非负 int；事件非列表或项数超过 1000；事件项非恰
        为十键序，原子非 bool，序号/时刻/原序号非非 bool int 或越界
        （序号>=1、时刻>=0、原序号>=0），四个负载字段非 str，前哈希/哈希
        非 64 位小写十六进制；非空页序号不逐项连续、游标不等于末项序号，
        自第 2 项起前哈希不衔接、哈希复算不符，原序号非 0 且不小于本项序号
        或未指向同（键,操作,原子,会话）的更早首次项，皆 ValueError。最后以
        解析值按 batch_audit 基线重建完整页（单个 LF 结尾），与原文逐字节
        不一致即非规范编码 ValueError。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"batch audit page is not valid JSON: {exc}") from exc
        top_keys = ["下个序号", "事件"]
        if not isinstance(doc, dict) or list(doc) != top_keys:
            raise ValueError(
                "batch audit page top-level keys must be 下个序号/事件 in order"
            )
        next_seq = self._cp_int(doc["下个序号"], "下个序号", 0)
        raw_events = doc["事件"]
        if not isinstance(raw_events, list):
            raise ValueError("事件 must be a list")
        if len(raw_events) > 1000:
            raise ValueError(f"事件 count {len(raw_events)} exceeds 1000")

        event_keys = [
            "序号",
            "时刻",
            "键",
            "操作",
            "原子",
            "会话",
            "结果",
            "原序号",
            "前哈希",
            "哈希",
        ]
        events = []
        # 本页内各（键,操作,原子,会话）的首次序号；更早历史的首次序号查实例
        # 链签名视图 _batch_chain_sig_first（O(1)），整页校验 O(事件数)。
        page_first = {}
        prev_hash = None
        first_seq = None
        for index, item in enumerate(raw_events, start=1):
            if not isinstance(item, dict) or list(item) != event_keys:
                raise ValueError(
                    f"batch audit event {index} keys must be "
                    "序号/时刻/键/操作/原子/会话/结果/原序号/前哈希/哈希 in order"
                )
            seq = self._cp_int(item["序号"], "事件.序号", 1)
            now_ms = self._cp_int(item["时刻"], "事件.时刻", 0)
            bkey = item["键"]
            op = item["操作"]
            atomic = item["原子"]
            sid = item["会话"]
            result = item["结果"]
            if not isinstance(atomic, bool):
                raise ValueError(
                    f"事件.原子 must be a bool, got {type(atomic).__name__}"
                )
            for label, value in (
                ("事件.键", bkey),
                ("事件.操作", op),
                ("事件.会话", sid),
                ("事件.结果", result),
            ):
                if not isinstance(value, str):
                    raise ValueError(
                        f"{label} must be a str, got {type(value).__name__}"
                    )
            origin = self._cp_int(item["原序号"], "事件.原序号", 0)
            given_prev = self._cp_hex64(item["前哈希"], "事件.前哈希")
            digest = self._cp_hex64(item["哈希"], "事件.哈希")

            if first_seq is None:
                first_seq = seq
            elif seq != first_seq + index - 1:
                raise ValueError(
                    "batch audit event seq must be contiguous: "
                    f"want {first_seq + index - 1}, got {seq}"
                )
            if index > 1 and given_prev != prev_hash:
                raise ValueError(
                    f"batch audit event {seq} 前哈希 does not link to the prior hash"
                )
            sig = (bkey, op, atomic, sid)
            if origin:
                if origin >= seq:
                    raise ValueError(
                        f"batch audit event {seq} 原序号 must be 0 or < {seq}, "
                        f"got {origin}"
                    )
                # 原序号须指向同签名的更早首次项：序号在已入链历史则取链上
                # 十元组，否则取本页已解析前缀（连续序号直接定位）。锚点核对
                # 在解析之后，此处历史可能尚短，越界一律 ValueError。
                if origin < first_seq:
                    chain_events = self._batch_chain_events
                    if origin > len(chain_events):
                        raise ValueError(
                            f"batch audit event {seq} 原序号 {origin} is beyond "
                            "the events currently on the chain"
                        )
                    target = chain_events[origin - 1]
                else:
                    target = events[origin - first_seq]
                target_sig = (target[2], target[3], target[4], target[5])
                if target_sig != sig:
                    raise ValueError(
                        f"batch audit event {seq} 原序号 must point to an earlier "
                        "first event with the same 键/操作/原子/会话"
                    )
                # 全局首次：历史在册取历史首序号，否则取本页已见首序号。
                hist_first = self._batch_chain_sig_first.get(sig)
                want_first = (
                    hist_first if hist_first is not None else page_first.get(sig)
                )
                if want_first != origin:
                    raise ValueError(
                        f"batch audit event {seq} 原序号 must point to the first "
                        f"occurrence seq {want_first}, got {origin}"
                    )
            if (
                self._batch_chain_hash(
                    seq, now_ms, bkey, op, atomic, sid, result, origin, given_prev
                )
                != digest
            ):
                raise ValueError(f"batch audit event {seq} 哈希 does not match")

            events.append(
                (seq, now_ms, bkey, op, atomic, sid, result, origin,
                 given_prev, digest)
            )
            page_first.setdefault(sig, seq)
            prev_hash = digest

        if events:
            anchor_seq = first_seq - 1
            anchor_hash = events[0][8]
            if next_seq != events[-1][0]:
                raise ValueError(
                    "下个序号 must equal the last event seq: "
                    f"want {events[-1][0]}, got {next_seq}"
                )
        else:
            # 空页锚即游标；无事件可校，锚哈希缺省。
            anchor_seq = next_seq
            anchor_hash = None

        # 非规范编码：完整二键页（单个 LF 结尾）须与原文逐字节一致；任何排版
        # 差异（空白、Unicode 转义、键序、多余/缺失 LF）皆拒绝。
        canonical = json.dumps(
            {
                "下个序号": next_seq,
                "事件": [
                    {
                        "序号": seq,
                        "时刻": now_ms,
                        "键": bkey,
                        "操作": op,
                        "原子": atomic,
                        "会话": sid,
                        "结果": result,
                        "原序号": origin,
                        "前哈希": given_prev,
                        "哈希": digest,
                    }
                    for seq, now_ms, bkey, op, atomic, sid, result, origin,
                    given_prev, digest in events
                ],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"
        if canonical != text:
            raise ValueError("batch audit page is not canonical compact JSON")
        return anchor_seq, anchor_hash, events

    # -- 合规全局链 ------------------------------------------------------

    def compliance_events(self, after=0, limit=100):
        """返回合规全局链事件 JSON；只读、不认证、不老化、不统计，O(limit)
        时空。

        after/limit 语义沿 audit：均须为非 bool int，类型不符抛 TypeError，
        after<0 或 limit ∉ [1,1000] 抛 ValueError。取全局序号 > after 的前
        limit 项，空页游标保持 after。顶层键序“下个序号/事件”；事件六字段
        键序“全局序号/来源/来源序号/载荷/前哈希/哈希”，全局序号/来源序号
        为 int，余为 str，载荷为来源公开事件按既有键序生成的紧凑 JSON 串，
        首项前哈希为 64 个 0。输出为固定键序的 LF 结尾紧凑 JSON。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        # 全局序号即位置+1，序号 > after 自下标 after 起，直接切片。
        window = self._compliance_events[after : after + limit]
        events = [
            {
                "全局序号": global_seq,
                "来源": source,
                "来源序号": source_seq,
                "载荷": payload,
                "前哈希": prev_hash,
                "哈希": digest_hash,
            }
            for global_seq, source, source_seq, payload, prev_hash, digest_hash
            in window
        ]
        # 有项取下一序号为末项全局序号，无项取 after。
        next_seq = window[-1][0] if window else after
        payload_doc = {"下个序号": next_seq, "事件": events}
        return (
            json.dumps(payload_doc, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        )

    def compliance_snapshot(self, after=0, limit=100):
        """返回合规全局链窗口快照 JSON；只读、不认证、不老化、不统计，
        O(limit) 时空。

        参数规则同 compliance_events；after 大于末全局序号（空链为 0）抛
        KeyError(after)。顶层键序“版本/锚序号/锚哈希/上限/下个序号/事件/
        摘要”：版本恒 1，锚序号=after，after=0 锚哈希为 64 个 0、否则取第
        after 项哈希，上限=limit，下个序号取末项全局序号、空窗取 after；
        事件复用 compliance_events 六键序及类型。摘要为前六键紧凑 JSON
        （ensure_ascii=False、无空白）UTF-8 字节的 sha256 小写值。页面可
        离线校验锚点、顺序、逐项哈希与摘要；输出末尾加 LF。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")
        total = len(self._compliance_events)
        if after > total:
            raise KeyError(after)

        # 锚哈希取第 after 项（下标 after-1），窗口自下标 after 起。
        anchor_hash = (
            "0" * 64 if after == 0 else self._compliance_events[after - 1][5]
        )
        window = self._compliance_events[after : after + limit]
        events = [
            {
                "全局序号": global_seq,
                "来源": source,
                "来源序号": source_seq,
                "载荷": payload,
                "前哈希": prev_hash,
                "哈希": digest_hash,
            }
            for global_seq, source, source_seq, payload, prev_hash, digest_hash
            in window
        ]
        # 有项取下一序号为末项全局序号，无项取 after。
        next_seq = window[-1][0] if window else after
        head = {
            "版本": 1,
            "锚序号": after,
            "锚哈希": anchor_hash,
            "上限": limit,
            "下个序号": next_seq,
            "事件": events,
        }
        # 摘要只盖前六键：先对无摘要的头算 sha256，再补末键输出。
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        head["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(head, ensure_ascii=False, separators=(",", ":")) + "\n"

    def compliance_restore(self, key, text):
        """将版本 1 合规快照分页结果原子接到全局合规链尾，只恢复合规事件，
        返回 LF 结尾紧凑 JSON。

        key 沿用凭据约束（型/值错 TypeError/ValueError），text 须为 str
        （非 str 抛 TypeError）。text 须为版本 1 规范快照：JSON/重键、逐层
        键集/键序与类型、范围、事件数不超过上限、全局序号自锚序号起逐项
        连续、前哈希衔接且逐项哈希与顶层摘要正确、来源仅审计/批量/容量、
        载荷为对应公开源事件按既有键序（审计九键、批量十键、容量五键）
        生成的规范紧凑 JSON（键序、类型、范围自洽，审计/批量载荷哈希可
        复算，来源序号须等于载荷内序号），且整体须为与 compliance_snapshot
        同法（ensure_ascii=False、separators=(',',':')、单个 LF 结尾）的
        规范编码；以上任一不符抛 ValueError。

        结构全验后核对锚点：当前全局链末尾（空链为序号 0、64 个 0）须恰
        等于快照锚序号/锚哈希，否则抛 StateError(锚序号, 当前末序号) 且不
        追加。通过后一次性把六元组事件接到全局链尾；只恢复合规事件，不
        恢复任何源链、会话、配置、缓存或幂等索引，恢复动作本身不生成
        合规事件。任何失败均不改变链或占用 key。不认证、不老化、不统计。

        以独立缓存域且仅缓存成功：同 key 同型同 text 重放不解析、不重验、
        不追加，直接返回首次结果原字节；异参抛 ValueError。返回键序
        “追加/末序号/末哈希/摘要”：追加:int、末序号:int、末哈希:str，
        摘要为前三键同法紧凑编码 UTF-8 字节的 sha256 小写值；空页追加 0。
        O(事件数) 时间、O(事件数) 空间。
        """
        _check_credential("key", key)

        cached = self._compliance_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不重验、不追加，仅核对同型同 text 后返回原字节。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        anchor_seq, anchor_hash, events = self._parse_compliance_snapshot(text)

        # 锚点：当前全局链末尾（空链为序号 0、64 个 0）须恰为快照锚；不符
        # 即 StateError(锚序号, 当前末序号)，发生在任何追加之前。
        tail_seq = len(self._compliance_events)
        tail_hash = self._compliance_tail if tail_seq else "0" * 64
        if anchor_seq != tail_seq or anchor_hash != tail_hash:
            raise StateError(anchor_seq, tail_seq)

        # 全验后一次追加：六元组原样接尾，仅推进全局链序列与末哈希；不动
        # 任何源链、业务态、缓存与幂等索引，恢复不生成自身事件。
        self._compliance_events.extend(events)
        if events:
            self._compliance_tail = events[-1][5]

        appended = len(events)
        result = self._render_audit_restore(
            appended, tail_seq + appended, self._compliance_tail
        )
        self._compliance_restore_cache[key] = (text, result)
        return result

    def _parse_compliance_snapshot(self, text):
        """解析并严格全量校验版本 1 合规窗口快照文本，返回
        (锚序号, 锚哈希, 事件六元组列表)；任何不符规范契约处均抛 ValueError。

        仅做快照自洽校验，不读当前链。除顶层七键契约（沿 audit_snapshot）
        外，逐项核对：全局序号自锚序号+1 连续；来源仅审计/批量/容量；
        来源序号为正 int 且等于载荷内序号；载荷为对应来源公开事件既有
        键序的规范紧凑 JSON 串（无 LF、无重键、键集键序与类型范围自洽，
        审计/批量载荷的源哈希可复算）；合规层前哈希逐项衔接、哈希按前五
        字段复算相符；游标等于末项全局序号、空窗等于锚序号；摘要等于前
        六键规范化紧凑 JSON 的 UTF-8 sha256；整体文档（单个 LF 结尾）与
        原文逐字节一致。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(
                f"compliance snapshot is not valid JSON: {exc}"
            ) from exc
        top_keys = ["版本", "锚序号", "锚哈希", "上限", "下个序号", "事件", "摘要"]
        if not isinstance(doc, dict) or list(doc) != top_keys:
            raise ValueError(
                "compliance snapshot top-level keys must be "
                "版本/锚序号/锚哈希/上限/下个序号/事件/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        anchor_seq = self._cp_int(doc["锚序号"], "锚序号", 0)
        anchor_hash = self._cp_hex64(doc["锚哈希"], "锚哈希")
        limit = self._cp_int(doc["上限"], "上限", 1)
        if limit > 1000:
            raise ValueError(f"上限 must be <= 1000, got {limit}")
        next_seq = self._cp_int(doc["下个序号"], "下个序号", 0)
        summary = self._cp_hex64(doc["摘要"], "摘要")

        event_keys = list(_COMPLIANCE_EVENT_KEYS)
        raw_events = doc["事件"]
        if not isinstance(raw_events, list):
            raise ValueError("事件 must be a list")
        if len(raw_events) > limit:
            raise ValueError(
                f"事件 count {len(raw_events)} exceeds 上限 {limit}"
            )

        events = []
        prev_hash = anchor_hash
        expect_global = anchor_seq + 1
        for index, item in enumerate(raw_events, start=1):
            if not isinstance(item, dict) or list(item) != event_keys:
                raise ValueError(
                    f"compliance event {index} keys must be "
                    "全局序号/来源/来源序号/载荷/前哈希/哈希 in order"
                )
            global_seq = self._cp_int(item["全局序号"], "事件.全局序号", 1)
            source = item["来源"]
            source_seq = self._cp_int(item["来源序号"], "事件.来源序号", 1)
            payload = item["载荷"]
            given_prev = self._cp_hex64(item["前哈希"], "事件.前哈希")
            digest_hash = self._cp_hex64(item["哈希"], "事件.哈希")
            if not isinstance(source, str):
                raise ValueError(
                    f"事件.来源 must be a str, got {type(source).__name__}"
                )
            if source not in _COMPLIANCE_SOURCES:
                raise ValueError(f"事件.来源 is not a valid source: {source!r}")
            if not isinstance(payload, str):
                raise ValueError(
                    f"事件.载荷 must be a str, got {type(payload).__name__}"
                )

            if global_seq != expect_global:
                raise ValueError(
                    "compliance event 全局序号 must be contiguous from the "
                    f"anchor: want {expect_global}, got {global_seq}"
                )
            if given_prev != prev_hash:
                raise ValueError(
                    f"compliance event {global_seq} 前哈希 does not link to "
                    "the prior hash"
                )
            # 来源载荷形态：解析载荷串并按来源公开事件契约全量自洽校验。
            self._check_compliance_payload(source, source_seq, payload)

            head = {
                "全局序号": global_seq,
                "来源": source,
                "来源序号": source_seq,
                "载荷": payload,
                "前哈希": given_prev,
            }
            blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
            if (
                hashlib.sha256(blob.encode("utf-8")).hexdigest()
                != digest_hash
            ):
                raise ValueError(
                    f"compliance event {global_seq} 哈希 does not match"
                )
            events.append(
                (global_seq, source, source_seq, payload, given_prev, digest_hash)
            )
            prev_hash = digest_hash
            expect_global += 1

        expected_next = events[-1][0] if events else anchor_seq
        if next_seq != expected_next:
            raise ValueError(
                f"下个序号 must equal the last event seq (or 锚序号 for an "
                f"empty window): want {expected_next}, got {next_seq}"
            )

        # 摘要：以解析值规范化重建前六键，重算 sha256（载荷串作为字符串值
        # 原样嵌入，不二次序列化）。
        head = {
            "版本": 1,
            "锚序号": anchor_seq,
            "锚哈希": anchor_hash,
            "上限": limit,
            "下个序号": next_seq,
            "事件": [
                {
                    "全局序号": global_seq,
                    "来源": source,
                    "来源序号": source_seq,
                    "载荷": payload,
                    "前哈希": given_prev,
                    "哈希": digest_hash,
                }
                for global_seq, source, source_seq, payload, given_prev,
                digest_hash in events
            ],
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical compliance snapshot")

        # 非规范编码：完整七键文档（单个 LF 结尾）须与原文逐字节一致。
        canonical = json.dumps(
            {**head, "摘要": summary},
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"
        if canonical != text:
            raise ValueError("compliance snapshot is not canonical compact JSON")
        return anchor_seq, anchor_hash, events

    def _check_compliance_payload(self, source, source_seq, payload):
        """校验单条合规事件的来源载荷形态；任何不符抛 ValueError。

        载荷须为对象的规范紧凑 JSON（无重键、无多余空白/LF、重排与原文
        逐字节一致）；键集/键序、类型、范围沿来源公开事件：审计九键、
        批量十键、容量五键。载荷内序号须等于来源序号；审计/批量载荷的源
        前哈希/哈希为 64 位小写十六进制且哈希可按来源规则复算。
        """
        try:
            row = json.loads(payload, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"事件.载荷 is not valid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError("事件.载荷 must be a JSON object")

        if source == _COMPLIANCE_SOURCE_AUDIT:
            keys = list(_COMPLIANCE_AUDIT_KEYS)
            if list(row) != keys:
                raise ValueError(
                    "审计 载荷 keys must be "
                    "序号/时刻/键/操作/会话/结果/原序号/前哈希/哈希 in order"
                )
            seq = self._cp_int(row["序号"], "载荷.序号", 1)
            now_ms = self._cp_int(row["时刻"], "载荷.时刻", 0)
            chain_key = row["键"]
            op = row["操作"]
            sid = row["会话"]
            result = row["结果"]
            for label, value in (
                ("载荷.键", chain_key),
                ("载荷.操作", op),
                ("载荷.会话", sid),
                ("载荷.结果", result),
            ):
                if not isinstance(value, str):
                    raise ValueError(
                        f"{label} must be a str, got {type(value).__name__}"
                    )
            origin = self._cp_int(row["原序号"], "载荷.原序号", 0)
            if origin != 0 and origin >= seq:
                raise ValueError(
                    f"审计 载荷 原序号 must be 0 or < 序号 {seq}, got {origin}"
                )
            payload_prev = self._cp_hex64(row["前哈希"], "载荷.前哈希")
            payload_hash = self._cp_hex64(row["哈希"], "载荷.哈希")
            if (
                self._chain_hash(
                    seq, now_ms, chain_key, op, sid, result, origin, payload_prev
                )
                != payload_hash
            ):
                raise ValueError("审计 载荷 哈希 does not match")
        elif source == _COMPLIANCE_SOURCE_BATCH:
            keys = list(_COMPLIANCE_BATCH_KEYS)
            if list(row) != keys:
                raise ValueError(
                    "批量 载荷 keys must be "
                    "序号/时刻/键/操作/原子/会话/结果/原序号/前哈希/哈希 in order"
                )
            seq = self._cp_int(row["序号"], "载荷.序号", 1)
            now_ms = self._cp_int(row["时刻"], "载荷.时刻", 0)
            chain_key = row["键"]
            op = row["操作"]
            atomic = row["原子"]
            sid = row["会话"]
            result = row["结果"]
            if not isinstance(atomic, bool):
                raise ValueError(
                    f"载荷.原子 must be a bool, got {type(atomic).__name__}"
                )
            for label, value in (
                ("载荷.键", chain_key),
                ("载荷.操作", op),
                ("载荷.会话", sid),
                ("载荷.结果", result),
            ):
                if not isinstance(value, str):
                    raise ValueError(
                        f"{label} must be a str, got {type(value).__name__}"
                    )
            origin = self._cp_int(row["原序号"], "载荷.原序号", 0)
            if origin != 0 and origin >= seq:
                raise ValueError(
                    f"批量 载荷 原序号 must be 0 or < 序号 {seq}, got {origin}"
                )
            payload_prev = self._cp_hex64(row["前哈希"], "载荷.前哈希")
            payload_hash = self._cp_hex64(row["哈希"], "载荷.哈希")
            if (
                self._batch_chain_hash(
                    seq, now_ms, chain_key, op, atomic, sid, result, origin,
                    payload_prev,
                )
                != payload_hash
            ):
                raise ValueError("批量 载荷 哈希 does not match")
        else:
            keys = list(_COMPLIANCE_CAPACITY_KEYS)
            if list(row) != keys:
                raise ValueError(
                    "容量 载荷 keys must be 序号/时刻/会话/结果/入队序 in order"
                )
            seq = self._cp_int(row["序号"], "载荷.序号", 1)
            now_ms = self._cp_int(row["时刻"], "载荷.时刻", 0)
            sid = row["会话"]
            verdict = row["结果"]
            order = self._cp_int(row["入队序"], "载荷.入队序", 0)
            if not isinstance(sid, str):
                raise ValueError(
                    f"载荷.会话 must be a str, got {type(sid).__name__}"
                )
            if not isinstance(verdict, str) or verdict not in _CAP_VERDICTS:
                raise ValueError(
                    f"载荷.结果 is not a valid capacity verdict: {verdict!r}"
                )
            # 公开事件的结果/入队序耦合：排队相关结果携带正入队序，余恒为 0。
            if verdict in _CAP_VERDICTS_WITH_ORDER:
                if order < 1:
                    raise ValueError(
                        f"容量 载荷 verdict {verdict!r} needs 入队序 >= 1"
                    )
            elif order != 0:
                raise ValueError(
                    f"容量 载荷 verdict {verdict!r} needs 入队序 0"
                )

        if seq != source_seq:
            raise ValueError(
                f"事件.来源序号 {source_seq} must equal 载荷.序号 {seq}"
            )

        # 载荷本身须为规范紧凑 JSON（无 LF、无转义差异、无多余键序/空白）；
        # 以解析值按其键序重排须与原文逐字节一致。
        canonical = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        if canonical != payload:
            raise ValueError("事件.载荷 is not canonical compact JSON")

    def fault_stats(self, now_ms):
        """返回后端故障统计 JSON；查询不认证、不老化、不改退避、不审计、
        不记事件、不动各域缓存。

        now_ms 为非 bool 非负 int：类型错 TypeError、取值错 ValueError。
        顶层键序为“时刻/故障/截至/退避用户/失败”：故障当且仅当
        now_ms < 故障截至，截至为当前存值；退避用户为 retry_at > now_ms
        的不同用户数；失败恒为故障、退避两项，项键序为“类型/次数”，
        次数为 do 建立/迁移/接管与 capacity 申请在新 key 首次后端检查
        抛 BackendError 的累计（now_ms<retry_at 归退避，否则归故障），
        注入/恢复/配置变更不清零。LF 结尾紧凑 JSON；同状态同时刻查询
        逐字节相同。查询 O(U) 时间、O(1) 辅助空间，U 为退避记录数。
        """
        _check_int("now_ms", now_ms, 0)
        backoff_users = 0
        for _n, retry_at in self._backoff.values():
            if retry_at > now_ms:
                backoff_users += 1
        payload = {
            "时刻": now_ms,
            "故障": now_ms < self._fault_until,
            "截至": self._fault_until,
            "退避用户": backoff_users,
            "失败": [
                {"类型": "故障", "次数": self._fault_fail[0]},
                {"类型": "退避", "次数": self._fault_fail[1]},
            ],
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _record_user_failure(self, user, exc):
        """为已定位用户按异常类记一次失败（认证/资源/状态/后端），O(1) 时空。

        仅由 do/meter/capacity 的新 key 首次异常路径调用，重放、异参 key、
        参数错与 KeyError 均不到达，故每次抛错恰计一次。
        """
        if isinstance(exc, AuthError):
            index = 0
        elif isinstance(exc, ResourceError):
            index = 1
        elif isinstance(exc, StateError):
            index = 2
        else:  # BackendError
            index = 3
        entry = self._user_fail.get(user)
        if entry is None:
            entry = self._user_fail[user] = [0, 0, 0, 0]
        entry[index] += 1

    def user_stats(self, user, now_ms):
        """返回指定用户的只读快照 JSON；查询不认证、不老化、不改租约、
        退避、审计、事件、各域缓存与失败计数。

        user 沿用凭据约束、now_ms 为非 bool 非负 int：类型错 TypeError、
        取值错 ValueError；未注册用户抛 KeyError。按 now_ms 取视图（不
        老化）：在线期限 <= now_ms 计挂起；租期或期限 <= now_ms 不计占用；
        队项截止 <= now_ms 不计排队；墓碑计下线。顶层键序为
        “时刻/用户/会话/租约/失败”：会话键序“在线/挂起/下线/排队”，租约
        键序“占用/最早到期”（无占用时最早到期为 0），失败恒按认证/资源/
        状态/后端排列，项键序“类型/次数”，次数为 do/meter/capacity 新 key
        首次且已定位用户的四类异常累计（参数错、KeyError、fault、重放与
        异参 key 不计）。LF 结尾紧凑 JSON；同状态同时刻查询逐字节相同。
        查询 O(S+Q) 时间、O(1) 辅助空间。
        """
        _check_credential("user", user)
        _check_int("now_ms", now_ms, 0)
        if user not in self._auth:
            raise KeyError(f"unknown user: {user!r}")

        online = 0
        suspended = 0
        offline = 0
        leased = 0
        earliest = 0
        for session in self._sessions.values():
            if session["user"] != user:
                continue
            state = session["state"]
            if state == _STATE_ONLINE and session["deadline"] > now_ms:
                online += 1
            elif state == _STATE_OFFLINE:
                offline += 1
            else:
                # 挂起，或在线但期限已到（视图为挂起）。
                suspended += 1
            if (
                session["ip"] is not None
                and session["lease"] > now_ms
                and session["deadline"] > now_ms
            ):
                leased += 1
                if earliest == 0 or session["lease"] < earliest:
                    earliest = session["lease"]

        queued = 0
        for entry in self._capacity_queue.values():
            if entry[0] == user and entry[3] > now_ms:
                queued += 1

        auth_fail, resource_fail, state_fail, backend_fail = self._user_fail.get(
            user, (0, 0, 0, 0)
        )
        payload = {
            "时刻": now_ms,
            "用户": user,
            "会话": {
                "在线": online,
                "挂起": suspended,
                "下线": offline,
                "排队": queued,
            },
            "租约": {"占用": leased, "最早到期": earliest},
            "失败": [
                {"类型": "认证", "次数": auth_fail},
                {"类型": "资源", "次数": resource_fail},
                {"类型": "状态", "次数": state_fail},
                {"类型": "后端", "次数": backend_fail},
            ],
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def runtime_stats(self, now_ms, pool=None):
        """返回运行期只读全局快照 JSON；查询不认证、不老化、不改任何状态。

        now_ms 为非 bool 非负 int：类型错 TypeError、取值错 ValueError；pool
        限 None 或凭据约束的池标识：类型错 TypeError、取值错 ValueError，未知
        池抛 KeyError。pool=None 列全部池，未配置任何池时池列表为空；给定池
        标识则仅列该池。按 now_ms 取视图（不老化）：在线期限 <= now_ms 计
        挂起；租期或期限 <= now_ms 不计占用；队项截止 <= now_ms 不计排队。
        顶层键序为“时刻/会话/建立/失败/池”：会话键序“在线/挂起/下线/排队”，
        建立键序“总数/成功/成功率万分比”，均 int；失败恒按认证/资源/状态/
        后端排列，项键序“类型/次数”，次数为全部用户的 user_stats 口径累计；
        池按标识 Unicode 升序，项键序“标识/总量/占用/可用/保留”，总量为
        可用地址数，占用为视图内有效租约数，可用 = 总量-保留-占用。
        LF 结尾紧凑 JSON；同状态同时刻查询逐字节相同。更新（建立）O(1)，
        查询 O(S+Q+U+P log P) 时间、O(P) 辅助空间，无池时 O(P)=O(0)。
        """
        _check_int("now_ms", now_ms, 0)
        if pool is not None:
            _check_credential("pool", pool)
            if pool not in self._pools:
                raise KeyError(f"unknown pool: {pool!r}")

        # 会话表单扫：全局在线/挂起/下线视图计数与各池有效租约数。有效租约
        # 须持址、在线且未挂起、期限与租期均未到（含同刻不计）。
        online = 0
        suspended = 0
        offline = 0
        pool_leased = {}
        for session in self._sessions.values():
            state = session["state"]
            if state == _STATE_ONLINE and session["deadline"] > now_ms:
                online += 1
            elif state == _STATE_OFFLINE:
                offline += 1
            else:
                # 挂起，或在线但期限已到（视图为挂起）。
                suspended += 1
            if (
                state == _STATE_ONLINE
                and session["ip"] is not None
                and session["deadline"] > now_ms
                and session["lease"] > now_ms
            ):
                pool_id = session["pool"]
                pool_leased[pool_id] = pool_leased.get(pool_id, 0) + 1

        # 队列表单扫：截止 > now_ms 的队项计排队（截止到的不摘队、仅不计）。
        queued = 0
        for entry in self._capacity_queue.values():
            if entry[3] > now_ms:
                queued += 1

        # 建立成功率万分比：无尝试为 0，否则 floor(成功*10000/总数)。
        if self._establish_total == 0:
            rate = 0
        else:
            rate = self._establish_success * 10000 // self._establish_total

        # 失败按 user_stats 口径跨全部用户聚合，恒按认证/资源/状态/后端。
        fail_totals = [0, 0, 0, 0]
        for counts in self._user_fail.values():
            for i in range(4):
                fail_totals[i] += counts[i]

        pool_ids = sorted(self._pools) if pool is None else [pool]
        pool_rows = []
        for pool_id in pool_ids:
            target = self._pools[pool_id]
            occupied = pool_leased.get(pool_id, 0)
            reserved = len(target.reserved)
            pool_rows.append(
                {
                    "标识": pool_id,
                    "总量": target.capacity,
                    "占用": occupied,
                    "可用": target.capacity - reserved - occupied,
                    "保留": reserved,
                }
            )

        payload = {
            "时刻": now_ms,
            "会话": {
                "在线": online,
                "挂起": suspended,
                "下线": offline,
                "排队": queued,
            },
            "建立": {
                "总数": self._establish_total,
                "成功": self._establish_success,
                "成功率万分比": rate,
            },
            "失败": [
                {"类型": "认证", "次数": fail_totals[0]},
                {"类型": "资源", "次数": fail_totals[1]},
                {"类型": "状态", "次数": fail_totals[2]},
                {"类型": "后端", "次数": fail_totals[3]},
            ],
            "池": pool_rows,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _stats_payload(self):
        """组装统计快照文档 dict（顶层键序：
        版本/建立/用户失败/用户计量/模板计量/摘要）。

        三类列表均按首字段（用户/标识）Unicode 码点升序；失败项键序
        “用户/认证/资源/状态/后端”，计量项键序“标识/通过/拒绝/下线/
        通过字节”；摘要为前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256
        小写十六进制串。纯渲染：不老化、不改态。
        """
        user_fail = [
            {
                "用户": user,
                "认证": counts[0],
                "资源": counts[1],
                "状态": counts[2],
                "后端": counts[3],
            }
            for user, counts in sorted(self._user_fail.items())
        ]
        user_meter = [
            {
                "标识": ident,
                "通过": counts[0],
                "拒绝": counts[1],
                "下线": counts[2],
                "通过字节": counts[3],
            }
            for ident, counts in sorted(self._meter_stats_user.items())
        ]
        template_meter = [
            {
                "标识": ident,
                "通过": counts[0],
                "拒绝": counts[1],
                "下线": counts[2],
                "通过字节": counts[3],
            }
            for ident, counts in sorted(self._meter_stats_template.items())
        ]
        doc = {
            "版本": 1,
            "建立": {"总数": self._establish_total, "成功": self._establish_success},
            "用户失败": user_fail,
            "用户计量": user_meter,
            "模板计量": template_meter,
        }
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return doc

    def _stats_checkpoint_text(self):
        """统计快照检查点的 LF 结尾紧凑 JSON（基线序列化，不老化、不改态）。"""
        return json.dumps(
            self._stats_payload(), ensure_ascii=False, separators=(",", ":")
        ) + "\n"

    def stats_checkpoint(self):
        """只读输出建立/失败/计量统计快照检查点的 LF 结尾基线 JSON，
        O((U+M) log(U+M)) 时间、O(U+M) 空间；不认证、不老化、不审计、
        不动各域缓存与任何计数。

        顶层依次为“版本/建立/用户失败/用户计量/模板计量/摘要”：版本恒为
        1；建立键序“总数/成功”，均为非 bool 非负 int 且成功 <= 总数；
        用户失败项键序“用户/认证/资源/状态/后端”，四项均为非 bool 非负
        int，按用户 Unicode 码点升序、无重复；用户计量与模板计量项键序
        “标识/通过/拒绝/下线/通过字节”，五项均为非 bool 非负 int（标识
        沿凭据约束，模板标识可为已删模板），按标识 Unicode 码点升序、无
        重复；摘要为前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写值。
        同态查询逐字节相同。
        """
        return self._stats_checkpoint_text()

    def stats_restore(self, key, text):
        """按统计快照检查点原子替换建立计数、按用户失败计数与按用户/模板
        计量计数，返回替换后检查点（规范包）的 LF 结尾基线 JSON。

        key 沿凭据约束，text 须为 str：key 型/值错抛 TypeError/ValueError，
        text 非 str 抛 TypeError。JSON 解析、重键、键集/键序、结构、类型、
        取值范围（含成功 > 总数）、排序或重复、版本或摘要错均抛 ValueError；
        用户失败行与用户计量行引用未注册用户抛 ResourceError，模板计量行不验
        模板引用（允许历史/已删标识）。全部校验通过后原子替换五类统计
        （认证器、会话、租约、队列、配置及各域缓存均不变）；任何失败不改
        实例统计与缓存，不老化、不审计。

        重放缓存与各域独立：仅缓存首次成功，同 key 同型同 text 重放不解析、
        不重验、不替换，直接返回首次规范包原字节；异参（含异型）抛
        ValueError；失败（含参数错与 ResourceError）不占 key。首次
        O((U+M) log(U+M)) 时间、O(U+M) 空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._stats_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text 后返回缓存原字节。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        # 全部校验在新数据上进行，通过后一次性替换；任何失败实例不变。
        total, success, fail_rows, user_rows, template_rows, _digest = (
            self._parse_stats_checkpoint(text)
        )
        for user, _a, _r, _st, _b in fail_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"stats checkpoint references unregistered user: {user!r}"
                )
        for ident, _p, _d, _o, _by in user_rows:
            if ident not in self._auth:
                raise ResourceError(
                    f"stats checkpoint references unregistered user: {ident!r}"
                )

        # 全验后原子替换五类统计；计数值存活储为 list，沿用既有 += 更新路径。
        self._establish_total = total
        self._establish_success = success
        self._user_fail = {user: [a, r, st, b] for user, a, r, st, b in fail_rows}
        self._meter_stats_user = {
            ident: [p, d, o, b] for ident, p, d, o, b in user_rows
        }
        self._meter_stats_template = {
            ident: [p, d, o, b] for ident, p, d, o, b in template_rows
        }

        result = self._stats_checkpoint_text()
        self._stats_restore_cache[key] = (text, result)
        return result

    def stats_merge(self, key, base, left, right):
        """按 base/left/right 三份版本 1 统计快照检查点做同源分支三方合并，
        原子替换五类统计后返回 stats_checkpoint() 的 LF 尾基线 JSON。

        key 沿凭据约束，base/left/right 须为 str：key 型/值错抛
        TypeError/ValueError，三文本型错抛 TypeError。三文本按
        stats_checkpoint 版本 1 契约解析（JSON/重键/键序结构类型值/排序
        重复/版本/摘要），任一非法抛 ValueError；任一文本的用户失败行或
        用户计量行引用未注册用户抛 ResourceError，模板计量不验模板引用。
        全部解析与引用校验先于合并语义校验，任何失败不改实例统计与缓存。

        合并逐计数进行，标识缺失按计数 0 计：先验 left 再验 right，分支
        任一计数低于 base（含建立总数/成功）抛 StateError("left")/
        StateError("right")；建立成功增量大于建立总数增量同样抛对应侧
        StateError。结果建立计数为 left+right-base；用户失败、用户计量、
        模板计量各取三文本标识并集、按 Unicode 码点升序，结果计数同为
        left+right-base，四项全 0 的行省略。全验后原子替换五类统计
        （认证器、会话、租约、队列、配置及各域缓存均不变），不老化、
        不认证、不审计、不改其他状态。

        重放缓存与各域独立：仅缓存首次成功，同 key 同型同四参重放不解析、
        不重验、不替换，直接返回首次结果原字节；异参（含异型）抛
        ValueError；失败（含参数错、ResourceError 与 StateError）不占
        key。首次 O(n log n) 时间、O(n) 空间（n 为三文本行数之和），
        重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._stats_merge_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同四参后返回缓存原字节。
            c_params, result = cached
            params = (base, left, right)
            if any(
                type(value) is not type(c_value) or value != c_value
                for value, c_value in zip(params, c_params)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        for name, value in (
            ("base", base), ("left", left), ("right", right),
        ):
            if not isinstance(value, str):
                raise TypeError(
                    f"{name} must be a str, got {type(value).__name__}"
                )

        # 三份文本全部解析（ValueError 先于引用与合并语义校验）。
        parsed = {}
        for label, text in (("base", base), ("left", left), ("right", right)):
            total, success, fail_rows, user_rows, template_rows, _digest = (
                self._parse_stats_checkpoint(text)
            )
            parsed[label] = (
                total,
                success,
                {user: (a, r, st, b) for user, a, r, st, b in fail_rows},
                {ident: (p, d, o, by) for ident, p, d, o, by in user_rows},
                {ident: (p, d, o, by) for ident, p, d, o, by in template_rows},
            )

        # 引用校验：三份文本的用户失败与用户计量标识均须已注册；模板不验。
        for label in ("base", "left", "right"):
            _t, _s, fail_map, user_map, _tm = parsed[label]
            for ident in fail_map:
                if ident not in self._auth:
                    raise ResourceError(
                        f"stats checkpoint references unregistered user: {ident!r}"
                    )
            for ident in user_map:
                if ident not in self._auth:
                    raise ResourceError(
                        f"stats checkpoint references unregistered user: {ident!r}"
                    )

        # 逐计数分支校验，先 left 后 right；缺失标识计 0。
        def check_side(label):
            b_total, b_success, b_fail, b_user, b_template = parsed["base"]
            s_total, s_success, s_fail, s_user, s_template = parsed[label]
            if s_total < b_total or s_success < b_success:
                raise StateError(label)
            if s_success - b_success > s_total - b_total:
                raise StateError(label)
            for b_map, s_map in (
                (b_fail, s_fail), (b_user, s_user), (b_template, s_template),
            ):
                for ident in sorted(set(b_map) | set(s_map)):
                    b_values = b_map.get(ident, (0, 0, 0, 0))
                    s_values = s_map.get(ident, (0, 0, 0, 0))
                    if any(
                        s_values[i] < b_values[i] for i in range(4)
                    ):
                        raise StateError(label)

        check_side("left")
        check_side("right")

        b_total, b_success, b_fail, b_user, b_template = parsed["base"]
        l_total, l_success, l_fail, l_user, l_template = parsed["left"]
        r_total, r_success, r_fail, r_user, r_template = parsed["right"]

        def merge_map(b_map, l_map, r_map):
            merged = {}
            for ident in sorted(set(b_map) | set(l_map) | set(r_map)):
                b_values = b_map.get(ident, (0, 0, 0, 0))
                l_values = l_map.get(ident, (0, 0, 0, 0))
                r_values = r_map.get(ident, (0, 0, 0, 0))
                values = [
                    l_values[i] + r_values[i] - b_values[i] for i in range(4)
                ]
                if any(values):
                    merged[ident] = values
            return merged

        total = l_total + r_total - b_total
        success = l_success + r_success - b_success
        fail_merged = merge_map(b_fail, l_fail, r_fail)
        user_merged = merge_map(b_user, l_user, r_user)
        template_merged = merge_map(b_template, l_template, r_template)

        # 全验后原子替换五类统计；计数值存活储为 list，沿用既有 += 更新路径。
        self._establish_total = total
        self._establish_success = success
        self._user_fail = {
            ident: list(values) for ident, values in fail_merged.items()
        }
        self._meter_stats_user = {
            ident: list(values) for ident, values in user_merged.items()
        }
        self._meter_stats_template = {
            ident: list(values) for ident, values in template_merged.items()
        }

        result = self._stats_checkpoint_text()
        self._stats_merge_cache[key] = ((base, left, right), result)
        return result

    def stats_delta(self, base, current):
        """只读计算 current 相对 base 的逐计数增量（current-base），返回 LF 结尾
        紧凑 JSON；纯函数：不老化、不认证、不审计、不动缓存与任何计数，同参
        同字节。

        base/current 须为 str，否则抛 TypeError；两文本按 stats_checkpoint
        版本 1 契约解析（JSON/重键/键序结构类型值/排序重复/版本/摘要），任一
        非法抛 ValueError；任一文本的用户失败行或用户计量行引用未注册用户抛
        ResourceError，模板计量不验模板引用。全部解析与引用校验先于增量语义
        校验。

        按标识并集逐计数相减，标识缺失按计数 0 计：建立总数/成功任一增量为负、
        建立成功增量大于建立总数增量，或任一失败/计量计数增量为负，均抛
        StateError("current")。输出顶层依次为“基线摘要/当前摘要/建立/用户失败/
        用户计量/模板计量/摘要”：前两值取两输入的“摘要”原文；建立键序
        “总数/成功/成功率万分比”，均为 int，总数增量为 0 时率为 0，否则
        floor(成功增量*10000/总数增量)；失败项键序“用户/认证/资源/状态/后端”，
        计量项键序“标识/通过/拒绝/下线/通过字节”，三项之差均为非负 int；三类
        列表按标识 Unicode 码点升序，四项全 0 的行省略；末摘要为前六键紧凑
        JSON（无 LF）UTF-8 字节的 sha256 小写值。
        O(n log n) 时间、O(n) 空间（n 为两文本行数之和）。
        """
        for name, value in (("base", base), ("current", current)):
            if not isinstance(value, str):
                raise TypeError(
                    f"{name} must be a str, got {type(value).__name__}"
                )

        # 两份文本全部解析（ValueError 先于引用与增量语义校验）。
        parsed = {}
        for label, text in (("base", base), ("current", current)):
            total, success, fail_rows, user_rows, template_rows, digest = (
                self._parse_stats_checkpoint(text)
            )
            parsed[label] = (
                total,
                success,
                digest,
                {user: (a, r, st, b) for user, a, r, st, b in fail_rows},
                {ident: (p, d, o, byt) for ident, p, d, o, byt in user_rows},
                {ident: (p, d, o, byt) for ident, p, d, o, byt in template_rows},
            )

        # 引用校验：两份文本的用户失败与用户计量标识均须已注册；模板不验。
        for label in ("base", "current"):
            _t, _s, _dg, fail_map, user_map, _tm = parsed[label]
            for ident in fail_map:
                if ident not in self._auth:
                    raise ResourceError(
                        f"stats checkpoint references unregistered user: {ident!r}"
                    )
            for ident in user_map:
                if ident not in self._auth:
                    raise ResourceError(
                        f"stats checkpoint references unregistered user: {ident!r}"
                    )

        b_total, b_success, b_digest, b_fail, b_user, b_template = parsed["base"]
        c_total, c_success, c_digest, c_fail, c_user, c_template = parsed["current"]

        d_total = c_total - b_total
        d_success = c_success - b_success
        if d_total < 0 or d_success < 0 or d_success > d_total:
            raise StateError("current")
        rate = 0 if d_total == 0 else d_success * 10000 // d_total

        def diff_map(b_map, c_map):
            """标识并集逐计数 current-base；缺失计 0，负增量 StateError，
            全 0 行省略；按标识 Unicode 码点升序。"""
            diff = {}
            for ident in sorted(set(b_map) | set(c_map)):
                b_values = b_map.get(ident, (0, 0, 0, 0))
                c_values = c_map.get(ident, (0, 0, 0, 0))
                values = [c_values[i] - b_values[i] for i in range(4)]
                if any(value < 0 for value in values):
                    raise StateError("current")
                if any(values):
                    diff[ident] = values
            return diff

        fail_diff = diff_map(b_fail, c_fail)
        user_diff = diff_map(b_user, c_user)
        template_diff = diff_map(b_template, c_template)

        doc = {
            "基线摘要": b_digest,
            "当前摘要": c_digest,
            "建立": {"总数": d_total, "成功": d_success, "成功率万分比": rate},
            "用户失败": [
                {
                    "用户": ident,
                    "认证": values[0],
                    "资源": values[1],
                    "状态": values[2],
                    "后端": values[3],
                }
                for ident, values in sorted(fail_diff.items())
            ],
            "用户计量": [
                {
                    "标识": ident,
                    "通过": values[0],
                    "拒绝": values[1],
                    "下线": values[2],
                    "通过字节": values[3],
                }
                for ident, values in sorted(user_diff.items())
            ],
            "模板计量": [
                {
                    "标识": ident,
                    "通过": values[0],
                    "拒绝": values[1],
                    "下线": values[2],
                    "通过字节": values[3],
                }
                for ident, values in sorted(template_diff.items())
            ],
        }
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _parse_stats_checkpoint(self, text):
        """解析并全量校验统计快照检查点文本，返回
        (建立总数, 建立成功, 用户失败行五元组列表 (用户,认证,资源,状态,后端),
        用户计量行五元组列表 (标识,通过,拒绝,下线,通过字节), 模板计量行五元组
        列表, 摘要)；任何文本非法均抛 ValueError。

        顶层须恰含“版本/建立/用户失败/用户计量/模板计量/摘要”且键序如此；
        版本为 1；建立键序“总数/成功”，均为非 bool 非负 int 且成功 <= 总数；
        失败行键序“用户/认证/资源/状态/后端”，用户为凭据约束串，四项为
        非 bool 非负 int，行按用户 Unicode 码点严格升序、无重复；计量行
        键序“标识/通过/拒绝/下线/通过字节”，标识为凭据约束串，四项为
        非 bool 非负 int，行按标识 Unicode 码点严格升序、无重复；摘要须为
        规范化前五键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写值（与原文
        排版无关）。仅做结构自洽校验；用户失败的用户与用户计量标识的注册由
        调用方判定，模板计量不验引用。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"stats checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("stats checkpoint top level must be an object")
        if list(doc) != [
            "版本", "建立", "用户失败", "用户计量", "模板计量", "摘要"
        ]:
            raise ValueError(
                "stats checkpoint top-level keys must be "
                "版本/建立/用户失败/用户计量/模板计量/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")

        establish_raw = doc["建立"]
        if not isinstance(establish_raw, dict) or list(establish_raw) != ["总数", "成功"]:
            raise ValueError("建立 keys must be 总数/成功 in order")
        total = self._cp_int(establish_raw["总数"], "建立.总数", 0)
        success = self._cp_int(establish_raw["成功"], "建立.成功", 0)
        if success > total:
            raise ValueError(
                f"建立.成功 must be <= 建立.总数, got {success} > {total}"
            )

        def parse_fail_rows(raw, label):
            if not isinstance(raw, list):
                raise ValueError(f"{label} must be a list")
            rows = []
            last_ident = None
            for index, item in enumerate(raw, start=1):
                if not isinstance(item, dict) or list(item) != [
                    "用户", "认证", "资源", "状态", "后端"
                ]:
                    raise ValueError(
                        f"{label} {index} keys must be "
                        "用户/认证/资源/状态/后端 in order"
                    )
                ident = self._cp_str(item["用户"], f"{label}.用户")
                values = tuple(
                    self._cp_int(item[name], f"{label}.{name}", 0)
                    for name in ("认证", "资源", "状态", "后端")
                )
                if last_ident is not None and ident <= last_ident:
                    raise ValueError(
                        f"{label} rows must be strictly sorted by 用户 ascending "
                        "with no duplicates"
                    )
                last_ident = ident
                rows.append((ident, *values))
            return rows

        def parse_meter_rows(raw, label):
            if not isinstance(raw, list):
                raise ValueError(f"{label} must be a list")
            rows = []
            last_ident = None
            for index, item in enumerate(raw, start=1):
                if not isinstance(item, dict) or list(item) != [
                    "标识", "通过", "拒绝", "下线", "通过字节"
                ]:
                    raise ValueError(
                        f"{label} {index} keys must be "
                        "标识/通过/拒绝/下线/通过字节 in order"
                    )
                ident = self._cp_str(item["标识"], f"{label}.标识")
                values = tuple(
                    self._cp_int(item[name], f"{label}.{name}", 0)
                    for name in ("通过", "拒绝", "下线", "通过字节")
                )
                if last_ident is not None and ident <= last_ident:
                    raise ValueError(
                        f"{label} rows must be strictly sorted by 标识 ascending "
                        "with no duplicates"
                    )
                last_ident = ident
                rows.append((ident, *values))
            return rows

        fail_rows = parse_fail_rows(doc["用户失败"], "用户失败")
        user_rows = parse_meter_rows(doc["用户计量"], "用户计量")
        template_rows = parse_meter_rows(doc["模板计量"], "模板计量")
        summary = self._cp_hex64(doc["摘要"], "摘要")

        # 摘要：用规范化值重建前五键（数值相等即与生成方基线逐字节一致）。
        canonical_head = {
            "版本": 1,
            "建立": {"总数": total, "成功": success},
            "用户失败": [
                {"用户": user, "认证": a, "资源": r, "状态": st, "后端": b}
                for user, a, r, st, b in fail_rows
            ],
            "用户计量": [
                {"标识": ident, "通过": p, "拒绝": d, "下线": o, "通过字节": byt}
                for ident, p, d, o, byt in user_rows
            ],
            "模板计量": [
                {"标识": ident, "通过": p, "拒绝": d, "下线": o, "通过字节": byt}
                for ident, p, d, o, byt in template_rows
            ],
        }
        blob = json.dumps(canonical_head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical stats checkpoint")
        return total, success, fail_rows, user_rows, template_rows, summary

    def sessions(self, now_ms, after="", limit=100):
        """返回会话与排队项的只读游标列表 JSON；查询不老化、不认证、不回收
        租约、不写审计/事件/缓存、不改任何计数。

        now_ms 为非 bool 非负 int；after 须为 str，空串从头、非空沿用凭据
        约束；limit 为非 bool int 且 1..1000。类型错 TypeError、取值错
        ValueError。按 now_ms 取视图（不落实例）：在线期限 <= now_ms 视为
        挂起（期限清零）；期限或租期 <= now_ms 则池/地址为空串、租期 0；
        截止 <= now_ms 的队项不列出。会话与队项按标识 Unicode 码点升序，
        取标识 > after 的前 limit 项。队项状态恒为“排队”、期限取其截止、
        入队序取原值、池/地址空串、租期 0；普通会话入队序恒 0，挂起/下线
        的池/地址空串、期限与租期 0。顶层键序“时刻/下个/剩余/项目”：有项
        时“下个”取末项会话标识，无项为 after；“剩余”为游标之后未返回项数。
        项键序“会话/用户/状态/期限/池/地址/租期/入队序”。LF 结尾紧凑 JSON
        （ensure_ascii=False、separators=(',',':')）；同态同参同字节。
        查询 O((S+Q) log(S+Q)) 时间、O(S+Q) 辅助空间。
        """
        _check_int("now_ms", now_ms, 0)
        if not isinstance(after, str):
            raise TypeError(f"after must be a str, got {type(after).__name__}")
        if after:
            _check_credential("after", after)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        rows = []
        for sid, session in self._sessions.items():
            state = session["state"]
            deadline = session["deadline"]
            pool_id = ""
            address = ""
            lease = 0
            if state == _STATE_ONLINE and deadline > now_ms:
                # 在线且期限未到：租期亦未到才保留池/地址/租期视图。
                status = _STATE_ONLINE
                view_deadline = deadline
                if session["ip"] is not None and session["lease"] > now_ms:
                    pool_id = session["pool"]
                    address = str(ipaddress.IPv4Address(session["ip"]))
                    lease = session["lease"]
            elif state == _STATE_ONLINE:
                # 在线但期限已到（含同刻）：视图为挂起，期限/池址/租期清零。
                status = _STATE_SUSPENDED
                view_deadline = 0
            elif state == _STATE_SUSPENDED:
                status = _STATE_SUSPENDED
                view_deadline = 0
            else:
                # 下线墓碑：全部清零。
                status = _STATE_OFFLINE
                view_deadline = 0
            rows.append(
                (
                    sid,
                    {
                        "会话": sid,
                        "用户": session["user"],
                        "状态": status,
                        "期限": view_deadline,
                        "池": pool_id,
                        "地址": address,
                        "租期": lease,
                        "入队序": 0,
                    },
                )
            )

        # 队项：截止 > now_ms 者列出（截止到的不摘队、仅不列），入队序取原值。
        for queued_sid, entry in self._capacity_queue.items():
            cutoff = entry[3]
            if cutoff <= now_ms:
                continue
            rows.append(
                (
                    queued_sid,
                    {
                        "会话": queued_sid,
                        "用户": entry[0],
                        "状态": _CAP_QUEUED,
                        "期限": cutoff,
                        "池": "",
                        "地址": "",
                        "租期": 0,
                        "入队序": entry[4],
                    },
                )
            )

        # 标识与队项 sid 互不重叠（同一 sid 不会既会话又排队），按码点升序。
        rows.sort(key=lambda row: row[0])
        page = [item for sid, item in rows if sid > after]
        total_after = len(page)
        page = page[:limit]
        next_sid = page[-1]["会话"] if page else after
        payload = {
            "时刻": now_ms,
            "下个": next_sid,
            "剩余": total_after - len(page),
            "项目": page,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def capacity(self, key, op, sid, args, now_ms):
        """容量申请：可配置背压等待队列的申请/取消/推进，返回 LF 结尾 JSON。

        key/sid 沿用凭据约束（推进 sid 恒为空串）；now_ms 为非 bool 非负 int，
        类型错 TypeError、取值错 ValueError。op 仅“申请/取消/推进”：申请 args 为
        (user, password, 等待)，等待为非 bool 正 int；取消 args 须为 None；
        推进 sid 须为 ""、args 须为 None。

        申请等待超过配置的非零最大等待毫秒（0 表示不限）时在老化、认证之前
        即抛 ValueError：不老化、不认证、不入队、不记事件，随验参异常入
        重放缓存。验参通过后申请在老化前查后端：故障期按用户指数退避抛
        BackendError（只入缓存，不老化、不认证、不入队、不记事件），健康
        才老化。通过该上界后申请先老化再认证：认证非 ok 抛 AuthError，
        sid 已存在（在线/挂起/下线会话或排队项）抛 StateError。非下线会话数
        达全局/单用户上限或候选序列无现存池、全部候选池无可取址则入队等待，需排队且非零
        队限已满时按队满策略处理：“拒绝”沿用 ResourceError 与既有“队满”
        事件；“替换”在 now_ms 按推进同口径公式算有效优先级（新项申请时刻
        取 now_ms），旧项选有效值最低、并列取入队序最大者，新值严格更高才
        原子删旧入新——先追加旧项“淘汰”（原入队序）再追加新项“排队”
        （新入队序），返回“排队”，否则按“拒绝”处理。失败除既有老化、认证
        副作用和“队满”事件外不改队列、入队序号或其他事件。否则原子建立在线
        会话，失败不留半分配。老化挂起即释址，
        挂起会话不持址、不计在线，但仍占全局与单用户上限。
        取消未知 sid 抛 KeyError，sid 为非排队项抛 StateError。推进遇待触发
        且 now_ms>=触发值的全局超时演练（timeout_fault 注入）时，不老化、不
        走普通超时与晋升，直接原子挂起全部在线会话、清期限释放租约，按入队序
        将全部队项记超时后删除并清除触发，输出在线 0、排队 0、变更为各超时项
        入队序；无待触发或未到刻时推进先老化，再清除截止（=申请时刻+等待）
        ≤ now_ms 的排队项；存活项有效优先级
        =min(1000, 基础+max(0,now_ms-申请时刻)//1000)，基础取推进时刻用户
        绑定模板的排队优先级（未绑定为 0，热加载/回滚即时影响本值），随后按
        有效值降序、入队序升序依次尝试晋升容量允许且可取址者：受限项留队并
        继续后项，前项成功占用影响后项，仅成功项原子建立会话与租约；变更仅
        含本次推进超时与晋升项的入队序，超时按入队序、晋升按尝试序；输出
        “在线”仅计在线会话。新 key 首次结果（成功或
        AuthError/ResourceError/StateError/KeyError，含验参异常）永久缓存，
        同参重放无副作用、直接返回或重抛，异参抛 ValueError；缓存与
        do/meter 分域。仅首个验参成功的新 key 记 capacity 事件，重放不记。
        时间复杂度：申请 O(S+Q+log A)（替换策略满队时须扫全队选旧项，余为
        O(S+log A)）、取消 O(Q)、推进
        O(Q log Q+S+Q log A)（超时演练触发批为 O(S log A+Q)），申请辅助
        空间 O(1)。
        """
        _check_credential("key", key)

        cached = self._capacity_cache.get(key)
        if cached is not None:
            # 重放：不老化、不申请、不推进、不记事件，仅按缓存返回或重抛。
            c_op, c_sid, c_args, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, sid, args, now_ms), (c_op, c_sid, c_args, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 新 key：余参校验本身的异常同样入缓存；验参失败不记事件。
        try:
            self._validate_capacity_params(op, sid, args, now_ms)
        except (TypeError, ValueError) as exc:
            self._capacity_cache[key] = (
                op,
                sid,
                args,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 申请：停用态用户先于后端检查与认证拒绝，只入缓存；不老化、不退避、
        # 不认证、不计失败、不记 capacity 事件。
        if op == _OP_APPLY and args[0] in self._disabled_users:
            exc = AuthError(f"user {args[0]!r} is disabled")
            self._capacity_cache[key] = (
                op,
                sid,
                args,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise exc

        # 申请：验参后、老化前查后端（用户取自 args）；BackendError 只入
        # 计数与缓存，不老化、不认证、不入队、不记事件。
        if op == _OP_APPLY:
            try:
                self._backend_check(args[0], now_ms)
            except BackendError as exc:
                self._record_user_failure(args[0], exc)
                self._capacity_cache[key] = (
                    op,
                    sid,
                    args,
                    now_ms,
                    ("err", (type(exc), exc.args)),
                )
                raise

        # 待触发的超时演练仅由首次满足 now_ms>=触发值的推进引爆：先于普通
        # 老化与晋升原子清场（挂起全部在线会话、清期限释放租约，全部队项按
        # 入队序记超时后删除，清除触发），本批不晋升、不半释放。
        if op == _OP_ADVANCE and self._timeout_armed(now_ms):
            changed = self._timeout_fire(now_ms)
            # 清场后在线会话全部转挂起，在线为 0、队列为空。
            result = self._render_capacity_advance(now_ms, 0, 0, changed)
        else:
            # 申请与推进先老化（取消不老化）；取消结果不受老化影响。
            if op != _OP_CANCEL:
                self._age(now_ms)
            try:
                if op == _OP_APPLY:
                    result = self._cap_apply(sid, args[0], args[1], args[2], now_ms)
                elif op == _OP_CANCEL:
                    result = self._cap_cancel(sid, now_ms)
                else:
                    result = self._cap_advance(now_ms)
            except (AuthError, ResourceError, StateError, KeyError) as exc:
                if isinstance(exc, AuthError):
                    verdict = _CAP_AUTH_FAILED
                elif isinstance(exc, ResourceError):
                    # 申请路径唯一 ResourceError 即队满。
                    verdict = _CAP_QUEUE_FULL
                elif isinstance(exc, StateError):
                    verdict = _CAP_STATE_FAILED
                else:
                    verdict = _CAP_UNKNOWN
                self._cap_event(now_ms, sid, verdict, 0)
                # 按用户失败计数：KeyError 不计；申请取 args 用户，取消由 sid
                # 定位（StateError 时 sid 必为既有会话），推进无用户且不抛。
                if not isinstance(exc, KeyError):
                    if op == _OP_APPLY:
                        fail_user = args[0]
                    elif op == _OP_CANCEL:
                        fail_user = self._sessions[sid]["user"]
                    else:
                        fail_user = None
                    if fail_user is not None:
                        self._record_user_failure(fail_user, exc)
                self._capacity_cache[key] = (
                    op,
                    sid,
                    args,
                    now_ms,
                    ("err", (type(exc), exc.args)),
                )
                raise
        self._capacity_cache[key] = (op, sid, args, now_ms, ("ok", result))
        return result

    def _validate_capacity_params(self, op, sid, args, now_ms):
        """校验 capacity 四参数：op 限三项，申请三参、取消/推进 args=None。"""
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op not in (_OP_APPLY, _OP_CANCEL, _OP_ADVANCE):
            raise ValueError(
                f"op must be one of 申请/取消/推进, got {op!r}"
            )
        if op == _OP_ADVANCE:
            if not isinstance(sid, str):
                raise TypeError(f"sid must be a str, got {type(sid).__name__}")
            if sid != "":
                raise ValueError(f'sid must be "" for 推进, got {sid!r}')
        else:
            _check_credential("sid", sid)
        if op == _OP_APPLY:
            if not isinstance(args, tuple):
                raise TypeError(f"args must be a tuple, got {type(args).__name__}")
            if len(args) != 3:
                raise ValueError(
                    "args must be a 3-tuple (user, password, 等待), "
                    f"got {len(args)} items"
                )
            _check_credential("user", args[0])
            _check_credential("password", args[1])
            _check_int("等待", args[2], 1)
            # 容量背压：非零最大等待为硬上界，超限在老化/认证之前即拒（不老化、
            # 不认证、不入队、不记事件），随验参异常入重放缓存；0 表示不限。
            if self._max_wait_ms != 0 and args[2] > self._max_wait_ms:
                raise ValueError(
                    f"等待 must be <= {self._max_wait_ms}, got {args[2]}"
                )
        elif args is not None:
            raise ValueError(f"args must be None for {op}, got {args!r}")
        _check_int("now_ms", now_ms, 0)

    def _cap_apply(self, sid, user, password, wait, now_ms):
        """认证后能立即服务则原子建立，否则入队；失败不留半分配。

        全局与单用户闸计非下线会话（挂起不持址但仍占上限）；地址须可取。
        """
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")
        if sid in self._sessions or sid in self._capacity_queue:
            raise StateError(f"sid already exists: {sid!r}")

        # 截止对在线与排队一致：申请时刻 + 等待。
        deadline = now_ms + wait
        total_count, user_count = self._capacity_counts(user)
        pool_id, ip_int = self._select_address(user, now_ms)
        # 模板并发会话上限：占用为绑定该模板用户的在线加挂起会话数；超限
        # 不拒绝而排队（背压），由推进在占用回落后晋升。
        template_id = self._user_templates.get(user)
        template_open = True
        if template_id is not None:
            session_limit = self._templates[template_id][4]
            template_open = (
                not session_limit
                or self._template_occupancy(template_id) < session_limit
            )
        servable = (
            total_count < self._total
            and user_count < self._per
            and template_open
            and pool_id is not None
            and ip_int is not None
        )
        if servable:
            self._commit_session(sid, user, pool_id, ip_int, now_ms)
            self._cap_event(now_ms, sid, _CAP_ONLINE, 0)
            # 计费开始：申请立即服务成功即开账。
            self._account_start(sid, now_ms)
            return self._render_capacity(sid, _CAP_ONLINE, now_ms, deadline)

        # 在线满（含挂起占位）或缺址：入队等待，队列本身达上限则按队满策略
        # 处理；队列上限为 0 表示不限。
        if self._queue_limit != 0 and len(self._capacity_queue) >= self._queue_limit:
            if self._queue_policy != _QUEUE_POLICY_REPLACE:
                raise ResourceError(
                    f"capacity queue limit {self._queue_limit} reached"
                )
            # 替换：在 now_ms 按推进同口径算各队项与新项的有效优先级（新项
            # 申请时刻取 now_ms），选有效值最低、并列取入队序最大的旧项。
            new_effective = self._queue_effective(user, now_ms, now_ms)
            victim_sid = None
            victim_effective = None
            victim_order = None
            for queued_sid in self._queue_order:
                entry = self._capacity_queue[queued_sid]
                effective = self._queue_effective(entry[0], entry[1], now_ms)
                order = entry[4]
                if (
                    victim_sid is None
                    or effective < victim_effective
                    or (effective == victim_effective and order > victim_order)
                ):
                    victim_sid = queued_sid
                    victim_effective = effective
                    victim_order = order
            # 新值严格更高才原子删旧入新；否则按“拒绝”处理（ResourceError
            # 由调用方记“队满”事件，队列、入队序号与其他事件均不变）。
            if new_effective <= victim_effective:
                raise ResourceError(
                    f"capacity queue limit {self._queue_limit} reached"
                )
            victim_entry = self._capacity_queue.pop(victim_sid)
            self._queue_order.remove(victim_sid)
            # 先追加旧项“淘汰”（原入队序），再追加新项“排队”（新入队序）。
            self._cap_event(now_ms, victim_sid, _CAP_EVICTED, victim_entry[4])
            self._queue_seq += 1
            order = self._queue_seq
            self._capacity_queue[sid] = [user, now_ms, wait, deadline, order]
            self._queue_order.append(sid)
            self._cap_event(now_ms, sid, _CAP_QUEUED, order)
            return self._render_capacity(sid, _CAP_QUEUED, now_ms, deadline)

        self._queue_seq += 1
        order = self._queue_seq
        self._capacity_queue[sid] = [user, now_ms, wait, deadline, order]
        self._queue_order.append(sid)
        self._cap_event(now_ms, sid, _CAP_QUEUED, order)
        return self._render_capacity(sid, _CAP_QUEUED, now_ms, deadline)

    def _cap_cancel(self, sid, now_ms):
        """撤销排队项：未知 sid KeyError，非排队项（在线/挂起/下线）StateError。"""
        entry = self._capacity_queue.pop(sid, None)
        if entry is None:
            if sid in self._sessions:
                raise StateError(f"sid {sid!r} is not a queued item")
            raise KeyError(f"unknown sid: {sid!r}")
        self._queue_order.remove(sid)
        self._cap_event(now_ms, sid, _CAP_CANCELLED, entry[4])
        return self._render_capacity(sid, _CAP_CANCELLED, now_ms, entry[3])

    def _cap_advance(self, now_ms):
        """先清超时项，再按有效优先级确定性晋升，返回时刻/在线/排队/变更 JSON。

        先摘除截止 <= now_ms 的到期队项（按入队序记超时事件）；存活项的有效
        优先级 = min(1000, 基础 + max(0, now_ms-申请时刻)//1000)，基础取推进
        时刻该用户绑定模板的排队优先级、未绑定为 0。存活项按有效优先级降序、
        入队序升序依次尝试：受全局、单用户、模板上限或全部候选池故障、地址
        限制者留队并继续尝试后项，前项成功占用即时影响后项，仅成功项原子建立
        会话与租约。输出“在线”仅计在线会话；挂起会话不持址、不计在线，但仍
        占全局与单用户上限，晋升闸以非下线计数为准。余留队项保持原入队序；
        晋升事件按尝试序（同有效优先级即入队序）追加。
        时间 O(Q log Q + S + Q log A)、辅助 O(Q)。
        """
        # 超时（含同刻）：按入队序摘除截止 <= now_ms 者，记录入队序。
        timed_out = []
        survivors = []
        for queued_sid in self._queue_order:
            entry = self._capacity_queue[queued_sid]
            if entry[3] <= now_ms:
                timed_out.append((queued_sid, entry[4]))
                del self._capacity_queue[queued_sid]
            else:
                survivors.append(queued_sid)
        for queued_sid, order in timed_out:
            self._cap_event(now_ms, queued_sid, _CAP_TIMEOUT, order)

        # 存活项按 (有效优先级降序, 入队序升序) 排序；基础优先级取推进时刻
        # 用户绑定模板的“排队优先级”，未绑定为 0，老化按等待整秒提升、封顶
        # 1000。热加载/回滚只在此刻经绑定与模板值生效，不改入队序、截止与事件。
        candidates = []
        for queued_sid in survivors:
            user, applied, _wait, _deadline, order = self._capacity_queue[queued_sid]
            template_id = self._user_templates.get(user)
            base = (
                self._templates[template_id][5]
                if template_id is not None
                else 0
            )
            effective = min(
                _MAX_EFFECTIVE_PRIORITY,
                base + max(0, now_ms - applied) // 1000,
            )
            candidates.append((-effective, order, queued_sid))
        candidates.sort()

        # 晋升：计数只扫一次会话表，晋升时增量维护；取址落库每弹一堆 O(log A)。
        # 受限项（全局/用户/模板/池故障/地址）按优先级序跳过、继续后项，受限
        # 项留队不晋升；前项成功占用即时影响后项。
        total_count, per_user, per_template = self._active_counts()
        promoted = []
        promoted_sids = set()
        for _neg_effective, order, queued_sid in candidates:
            entry = self._capacity_queue[queued_sid]
            user = entry[0]
            template_id = self._user_templates.get(user)
            template_open = True
            if template_id is not None:
                session_limit = self._templates[template_id][4]
                template_open = (
                    not session_limit
                    or per_template.get(template_id, 0) < session_limit
                )
            pool_id, ip_int = self._select_address(user, now_ms)
            if (
                total_count < self._total
                and per_user.get(user, 0) < self._per
                and template_open
                and pool_id is not None
                and ip_int is not None
            ):
                self._commit_session(queued_sid, user, pool_id, ip_int, now_ms)
                promoted.append((queued_sid, order))
                promoted_sids.add(queued_sid)
                # 计费开始：晋升提交即开账，按尝试序追加，与后附的晋升
                # capacity 事件同序。
                self._account_start(queued_sid, now_ms)
                del self._capacity_queue[queued_sid]
                total_count += 1
                per_user[user] = per_user.get(user, 0) + 1
                if template_id is not None:
                    per_template[template_id] = per_template.get(template_id, 0) + 1
        # 余留项保持原入队序（入队序不随调度改写）。
        remaining = [sid for sid in survivors if sid not in promoted_sids]
        self._queue_order = remaining
        for queued_sid, order in promoted:
            self._cap_event(now_ms, queued_sid, _CAP_PROMOTED, order)

        # 在线仅计老化后在线会话数（挂起不计）；排队为余留项。
        online = sum(
            1
            for session in self._sessions.values()
            if session["state"] == _STATE_ONLINE
        )
        changed = [order for _sid, order in timed_out]
        changed += [order for _sid, order in promoted]
        return self._render_capacity_advance(now_ms, online, len(remaining), changed)

    def _active_counts(self):
        """非下线会话计数（排队项不计）：返回 (总数, 按用户, 按模板)，单次 O(S)。

        按模板计数即模板占用：绑定该模板用户的在线加挂起会话数（未绑定模板
        的用户不计入任何模板）。
        """
        total_count = 0
        per_user = {}
        per_template = {}
        for session in self._sessions.values():
            if session["state"] != _STATE_OFFLINE:
                total_count += 1
                user = session["user"]
                per_user[user] = per_user.get(user, 0) + 1
                template_id = self._user_templates.get(user)
                if template_id is not None:
                    per_template[template_id] = per_template.get(template_id, 0) + 1
        return total_count, per_user, per_template

    @staticmethod
    def _cap_hash(seq, now_ms, sid, verdict, order, prev_hash):
        """由前六字段（键序固定）的基线 JSON（无 LF）之 UTF-8 字节算
        sha256 十六进制小写串。"""
        head = {
            "序号": seq,
            "时刻": now_ms,
            "会话": sid,
            "结果": verdict,
            "入队序": order,
            "前哈希": prev_hash,
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _cap_event(self, now_ms, sid, verdict, order):
        """追加一条带哈希链接的 capacity 事件（序号自 1），O(1) 时空。

        同一推进产生的超时/晋升按入队序追加（先超时后晋升）；取消沿用原入队
        序；无入队序者（申请立即结果与各类失败）入队序为 0。前哈希首项为
        64 个 0，余取前项哈希；事件时刻可回拨，链接只认追加序。
        """
        seq = len(self._capacity_events) + 1
        prev_hash = self._capacity_tail
        digest = self._cap_hash(seq, now_ms, sid, verdict, order, prev_hash)
        event = (seq, now_ms, sid, verdict, order, prev_hash, digest)
        self._capacity_events.append(event)
        self._capacity_tail = digest
        # 源事件与其合规投影原子追加；推进内先超时后晋升的调用序即投影序。
        # creplay/runtime_restore 直接替换 _capacity_events，不经过本入口，
        # 故导入账本不回灌全局链。
        self._compliance_append_capacity(event)

    def capacity_events(self, after=0, limit=100):
        """返回 capacity 事件 JSON；查询不老化，O(limit) 时空。

        取序号 > after 的前 limit 项。after/limit 须为非 bool 的 int：类型不符
        TypeError，after<0 或 limit ∉ [1,1000] 抛 ValueError。顶层键序为
        “下个序号/事件”，游标为末项序号、无项为 after；事件键序为
        “序号/时刻/会话/结果/入队序”，序号/时刻/入队序为 int，会话/结果为
        str，无入队序为 0。仅首个验参成功的新 key 产生事件，重放不记。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        # 序号即位置+1，序号 > after 的事件自下标 after 起，直接切片。
        window = self._capacity_events[after : after + limit]
        events = [
            {
                "序号": seq,
                "时刻": now_ms,
                "会话": sid,
                "结果": verdict,
                "入队序": order,
            }
            for seq, now_ms, sid, verdict, order, _prev_hash, _digest in window
        ]
        # 有项取下一序号为末项序号，无项取 after。
        next_seq = window[-1][0] if window else after
        payload = {"下个序号": next_seq, "事件": events}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def capacity_stats(self, now_ms):
        """返回容量统计 JSON；先验参再按既有规则老化。

        now_ms 为非 bool 非负 int：类型错 TypeError、取值错 ValueError。
        时间 O(S+Q+P log P+U log U)、辅助空间 O(P+U)。顶层键序为
        “时刻/在线/挂起/排队/可用/水位/最早截止/用户/池”，前七项为 int：
        在线/挂起为老化后对应状态会话数，排队为等待项数，全局可用
        = max(0, 总数-在线-挂起)，水位=排队，最早截止为最早队项截止、空队
        为 0。用户列含非下线会话所属或排队涉及的用户，按标识升序；项键序为
        “标识/在线/挂起/排队/可用/最早截止”，可用按每用户上限计算，最早
        截止取该用户最早队项、无队项为 0。池按标识升序；项键序为
        “标识/在线/排队/可用”，在线为持租在线会话数，仅 default 池计排队
        项，可用为动态空闲数加未租静态地址数。LF 结尾紧凑 JSON。
        """
        _check_int("now_ms", now_ms, 0)
        self._age(now_ms)

        # 会话表单扫：全局/用户的在线、挂起计数，与各池持租在线数、
        # 持租静态地址数（未租静态数 = 静态总数 - 持租静态数）。
        online_total = 0
        suspended_total = 0
        # user -> [在线, 挂起, 排队]；排队随后并入。
        users = {}
        pool_online = {}
        pool_rented_static = {}
        for session in self._sessions.values():
            state = session["state"]
            if state == _STATE_ONLINE:
                online_total += 1
            elif state == _STATE_SUSPENDED:
                suspended_total += 1
            if state != _STATE_OFFLINE:
                record = users.get(session["user"])
                if record is None:
                    record = users[session["user"]] = [0, 0, 0]
                if state == _STATE_ONLINE:
                    record[0] += 1
                else:
                    record[1] += 1
            if state == _STATE_ONLINE and session["ip"] is not None:
                pool_id = session["pool"]
                pool_online[pool_id] = pool_online.get(pool_id, 0) + 1
                ip_int = session["ip"]
                if ip_int in self._pools[pool_id].static_ips:
                    pool_rented_static[pool_id] = (
                        pool_rented_static.get(pool_id, 0) + 1
                    )

        # 队列表单扫：排队计数并入用户，求全局最早截止。
        queued_total = len(self._capacity_queue)
        earliest = 0
        # user -> 该用户最早截止；另以一次有序扫描求各用户最早截止。
        user_deadlines = {}
        for queued_sid in self._queue_order:
            entry = self._capacity_queue[queued_sid]
            user = entry[0]
            record = users.get(user)
            if record is None:
                record = users[user] = [0, 0, 0]
            record[2] += 1
            deadline = entry[3]
            if earliest == 0 or deadline < earliest:
                earliest = deadline
            prev = user_deadlines.get(user)
            if prev is None or deadline < prev:
                user_deadlines[user] = deadline

        user_rows = []
        for user in sorted(users):
            user_online, user_suspended, user_queued = users[user]
            user_rows.append(
                {
                    "标识": user,
                    "在线": user_online,
                    "挂起": user_suspended,
                    "排队": user_queued,
                    "可用": max(0, self._per - user_online - user_suspended),
                    "最早截止": user_deadlines.get(user, 0),
                }
            )

        pool_rows = []
        for pool_id in sorted(self._pools):
            pool = self._pools[pool_id]
            unrented_static = len(pool.static_ips) - pool_rented_static.get(pool_id, 0)
            pool_rows.append(
                {
                    "标识": pool_id,
                    "在线": pool_online.get(pool_id, 0),
                    "排队": queued_total if pool_id == _DEFAULT_POOL_ID else 0,
                    "可用": len(pool.free) + unrented_static,
                }
            )

        payload = {
            "时刻": now_ms,
            "在线": online_total,
            "挂起": suspended_total,
            "排队": queued_total,
            "可用": max(0, self._total - online_total - suspended_total),
            "水位": queued_total,
            "最早截止": earliest,
            "用户": user_rows,
            "池": pool_rows,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def capacity_forecast(self, now_ms, limit=100):
        """只读预测一次推进的结果，返回 LF 结尾紧凑 JSON；不老化、不缓存、
        不审计、不写事件、不改任何状态（模拟态全部为局部副本）。

        now_ms/limit 须为非 bool int：类型错 TypeError；now_ms<0 或
        limit ∉ [1,1000] 抛 ValueError。预测语义与 capacity 推进同构：
        待触发且 now_ms 已到触发值（含同刻）的超时演练令全队超时，不老化、
        不晋升；否则先模拟老化——在线会话期限或租期 <= now_ms 即释址
        （动态址回模拟空闲堆、静态址仅退租），期限到期另转挂起，挂起仍占
        全局/用户/模板上限但不持址；窗口项截止 <= now_ms 者记为超时（不占
        任何资源）；存活项（含窗口外）按推进同口径的有效优先级
        （min(1000, 基础+max(0,now_ms-申请时刻)//1000)，基础取此刻用户绑定
        模板的排队优先级、未绑定为 0）降序、入队序升序依次模拟晋升，按全局
        上限、单用户上限、模板并发上限及自动选池取址规则判定，前项晋升
        对计数与地址的占用影响后项；窗口外存活项同样参与模拟，其占用可决定
        窗口项的判定结果，但不输出。自动取址与推进同规则：绑定模板且配置了
        模板地址池序列的用户按其候选池优先序（至多 32 个）检查，其余仅
        default 池；候选池处于有效耗尽故障、无动态地址或该用户专属静态址被
        占用时检查下一池。未晋升项
        的等待原因按固定次序取首个受阻项：全局（非下线会话数达全局上限）/
        用户（达每用户上限）/模板（达模板会话上限）/无池（候选序列无现存
        池）/池故障（现存候选池均处于耗尽演练，now_ms < 注入截至）/地址
        （非故障候选池均动态耗尽或该用户专属静态址已租用）；静态址已占用时
        不回落同池动态址，与 _select_address 一致。

        顶层键序/型为“时刻:int、剩余:int、项目:list”：项目按入队序取前
        limit 项（判定结果可由窗口外更高优先级项的模拟占用决定），剩余为未
        列队项数（O(1) 取队长）。项键序/型为“会话:str、用户:
        str、入队序:int、结果:str、原因:str”：结果仅“晋升/超时/等待”，
        原因依次为空串、“截止”、上述六个等待原因之一。时间
        O(S+Q log Q)、辅助空间 O(U+T+Q)（S 为会话数、Q 为队项数、U/T 为
        涉及用户/模板数；动态址全池可互换，仅记老化后空闲槽计数，静态址按
        用户记持租，均不复制地址表或租约表）。
        """
        _check_int("now_ms", now_ms, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        queue_order = self._queue_order
        capacity_queue = self._capacity_queue
        total_queue = len(queue_order)
        window = queue_order[:limit]

        # 到点的超时演练：全队超时，不老化、不晋升；窗口外队项无需处理。
        if self._timeout_at is not None and now_ms >= self._timeout_at:
            items = [
                {
                    "会话": queued_sid,
                    "用户": capacity_queue[queued_sid][0],
                    "入队序": capacity_queue[queued_sid][4],
                    "结果": _CAP_TIMEOUT,
                    "原因": "截止",
                }
                for queued_sid in window
            ]
            payload = {
                "时刻": now_ms,
                "剩余": total_queue - len(items),
                "项目": items,
            }
            return (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )

        # 模拟老化 + 非下线计数单扫 O(S)：不触碰实例会话。在线→挂起仍是非
        # 下线，全局/用户/模板三类计数与老化前一致（挂起不持址但仍占上限）。
        total_count = 0
        per_user = {}
        per_template = {}
        for session in self._sessions.values():
            if session["state"] == _STATE_OFFLINE:
                continue
            total_count += 1
            user = session["user"]
            per_user[user] = per_user.get(user, 0) + 1
            template_id = self._user_templates.get(user)
            if template_id is not None:
                per_template[template_id] = (
                    per_template.get(template_id, 0) + 1
                )

        # 存活项先确定候选池序列（绑定模板的模板地址池序列，其余仅 default），
        # 以候选并集构造模拟多池地址态（含老化释址）；每项至多 32 个候选池。
        queued_users = {
            queued_sid: capacity_queue[queued_sid][0]
            for queued_sid in queue_order
        }
        candidate_of = {
            queued_sid: self._candidate_pools(user)
            for queued_sid, user in queued_users.items()
        }
        relevant_pools = set()
        for sequence in candidate_of.values():
            relevant_pools.update(sequence)
        dyn_free, static_held, _owners = self._sim_pool_state(
            now_ms, relevant_pools, True
        )

        # 全部队项先判超时（不占资源），存活项（含窗口外）按推进同口径有效
        # 优先级排序后依次模拟，结果按 sid 暂存；输出仅渲染窗口，仍按入队序。
        verdicts = {}
        survivors = []
        for queued_sid in queue_order:
            entry = capacity_queue[queued_sid]
            if entry[3] <= now_ms:
                verdicts[queued_sid] = (_CAP_TIMEOUT, "截止")
            else:
                survivors.append(queued_sid)

        def effective_of(queued_sid):
            user, applied, _wait, _deadline, order = capacity_queue[queued_sid]
            template_id = self._user_templates.get(user)
            base = (
                self._templates[template_id][5]
                if template_id is not None
                else 0
            )
            effective = min(
                _MAX_EFFECTIVE_PRIORITY,
                base + max(0, now_ms - applied) // 1000,
            )
            return (-effective, order, queued_sid)

        for _neg_effective, _order, queued_sid in sorted(
            effective_of(sid) for sid in survivors
        ):
            entry = capacity_queue[queued_sid]
            user = entry[0]
            template_id = self._user_templates.get(user)
            session_limit = (
                self._templates[template_id][4]
                if template_id is not None
                else 0
            )
            if total_count >= self._total:
                result, reason = "等待", "全局"
            elif per_user.get(user, 0) >= self._per:
                result, reason = "等待", "用户"
            elif (
                session_limit
                and per_template.get(template_id, 0) >= session_limit
            ):
                result, reason = "等待", "模板"
            else:
                # 容量闸通过后按候选池优先序模拟取址（多池后备切换）。
                outcome, detail = self._sim_try_address(
                    user,
                    now_ms,
                    candidate_of[queued_sid],
                    dyn_free,
                    static_held,
                )
                if outcome == "ok":
                    total_count += 1
                    per_user[user] = per_user.get(user, 0) + 1
                    if template_id is not None:
                        per_template[template_id] = (
                            per_template.get(template_id, 0) + 1
                        )
                    result, reason = _CAP_PROMOTED, ""
                else:
                    result, reason = "等待", detail
            verdicts[queued_sid] = (result, reason)

        items = []
        for queued_sid in window:
            entry = capacity_queue[queued_sid]
            result, reason = verdicts[queued_sid]
            items.append(
                {
                    "会话": queued_sid,
                    "用户": entry[0],
                    "入队序": entry[4],
                    "结果": result,
                    "原因": reason,
                }
            )

        payload = {
            "时刻": now_ms,
            "剩余": total_queue - len(items),
            "项目": items,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def capacity_rebalance(self, key, mode, changes, now_ms):
        """容量热均衡：按批直接改优先级/绑定/容量三元组后，一次性收敛等待队列，
        返回基线 LF 尾 JSON。

        key、now_ms 沿用 capacity 凭据/时钟约束；mode 仅“预检/执行”；changes
        为 1..1000 项 tuple，每项为 (种类, 目标, 值) 三元组，且 (种类, 目标)
        两两互异。种类仅三种：
          - (“优先级”, 模板标识, 当前配置优先级)：值为非 bool int 0..100；
          - (“绑定”, 用户, 模板标识或空串)：值为 str，空串表示解绑；
          - (“容量”, 空串, 当前配置容量三元组)：目标须为 ""，值为
            (队列上限, 最大等待毫秒, 队满策略)，队列上限为非 bool int
            0..10000（0 不限）、最大等待毫秒为非 bool int >=0（0 不限）、
            队满策略仅“拒绝/替换”。
        类型错抛 TypeError，结构/取值/互异错抛 ValueError；优先级目标为未知
        模板、绑定目标为未知用户或值引用未知模板、或新绑定承载失败（模板并发
        上限低于其当前占用）抛 ResourceError；now_ms 小于调用前任一排队项的
        申请时刻抛 StateError（空队列不触发）。

        全量校验与承载通过后，在候选配置下统一收敛队列：新最大等待毫秒非 0
        时令每个现存队项截止 = min(旧截止, 申请时刻+新值)（0 不限不改）；随后
        截止 <= now_ms 者按入队序记为超时并摘除；存活项按候选绑定模板的排队
        优先级算此刻有效值（与推进同口径
        min(1000, 基础+max(0,now_ms-申请时刻)//1000)），按 (有效值升序、
        入队序降序) 淘汰至候选队列上限（0 不限，不淘汰）；再按其反序
        （有效值降序、入队序升序）把受全局/单用户/模板上限或候选序列取址
        约束者留队、依次晋升可承载项（候选池序由候选绑定与模板地址池决定），受限项留队并继续后项。不老化既有会话、
        不记 capacity 事件、不动入队序号、不写审计。

        预检只读：全部演算仅在局部副本上进行，不改配置、修订、历史、回滚点、
        会话与队列；执行原子提交：旧配置作回滚点，修订号加 1 并存 v11 快照，
        config_history 追加“加载”记录（目标 -1），不关联 audit；随后原子改
        队列、原子建立晋升会话与租约；任何承载前失败均不改实例。执行仅缓存
        首次成功：同 (mode, changes, now_ms) 同型同参重放原字节，异参抛
        ValueError；预检与任何失败不缓存。

        返回键序/型为“时刻:int、模式:str、修订:int、超时:list、淘汰:list、
        晋升:list、剩余:int”：修订为提交后的新值（预检为当前修订加 1），三个
        列表按各自事件序装 sid 串（超时按入队序、淘汰按有效值升序入队序降序、
        晋升按尝试序），剩余为收敛后余留队项数。时间
        O((S+Q) log Q+Q log A+K)、辅助空间 O(S+Q+K)，S/Q/A/K 为会话数、
        队项数、default 池地址数与变更项数。
        """
        _check_credential("key", key)

        cached = self._capacity_rebalance_cache.get(key)
        if cached is not None:
            # 仅执行成功占 key；重放不演算、不老化、不改态，核对同型同参后
            # 原样返回首次字节。
            c_mode, c_changes, c_now_ms, result = cached
            if not _strict_equal(
                (mode, changes, now_ms), (c_mode, c_changes, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        # 类型阶段先于结构/取值阶段（沿 fault_plan 两阶段约定）。
        self._rebalance_check_types(mode, changes, now_ms)
        self._rebalance_check_values(mode, changes, now_ms)

        # 未知引用：优先级改的模板、绑定的用户与模板均须现存（空串解绑除外）。
        for kind, target, value in changes:
            if kind == _CAP_REBALANCE_KIND_PRIORITY:
                if target not in self._templates:
                    raise ResourceError(f"unknown template: {target!r}")
            elif kind == _CAP_REBALANCE_KIND_BINDING:
                if target not in self._auth:
                    raise ResourceError(f"unknown user: {target!r}")
                if value != "" and value not in self._templates:
                    raise ResourceError(f"unknown template: {value!r}")

        # 组候选 v11 spec；_build_pools 以候选绑定做模板占用承载（更小的目标
        # 队限由本接口自身超时/淘汰收敛，故跳过队长承载判定）。模板地址池序列
        # 本接口不可修改，候选与当前一致。
        spec, bindings, tmpl_priority, tmpl_limit, queue_limit, max_wait_ms = (
            self._rebalance_candidate(changes)
        )
        new_pools = self._build_pools(spec, check_queue=False)

        # 时钟回拨门（未知引用与承载失败之后）：now_ms 不得早于调用前任一排
        # 队项的申请时刻；空队不触发。
        for entry in self._capacity_queue.values():
            if now_ms < entry[1]:
                raise StateError(
                    f"now_ms {now_ms} before queued apply time {entry[1]}"
                )

        # 在局部副本上统一演算超时/淘汰/晋升（不老化既有会话）。
        plan = self._rebalance_plan(
            now_ms, queue_limit, max_wait_ms, bindings, tmpl_priority,
            tmpl_limit, dict(spec[9])
        )

        result = self._render_rebalance(
            mode, now_ms, self._revision + 1, plan
        )

        if mode == _CAP_REBALANCE_MODE_EXECUTE:
            # 原子提交：先装候选配置（旧配置作回滚点、修订加 1、存 v11 快照、
            # config_history 追加“加载”、目标 -1），再落实队列收敛与晋升；
            # 所有可能失败的承载校验均已在提交前通过，提交后不留失败路径。
            self._commit_config(
                spec, new_pools, self._current_spec(), _CONFIG_HISTORY_OP_LOAD
            )
            self._rebalance_apply(now_ms, max_wait_ms, plan)
            self._capacity_rebalance_cache[key] = (mode, changes, now_ms, result)
        return result

    @staticmethod
    def _rebalance_check_types(mode, changes, now_ms):
        """capacity_rebalance 类型阶段：mode/changes/各前二字段/可判定值类型/
        now_ms 的任一类型错在此先于长度、取值与互异等结构错抛出。"""
        if isinstance(mode, bool) or not isinstance(mode, str):
            raise TypeError(f"mode must be a str, got {type(mode).__name__}")
        if not isinstance(changes, tuple):
            raise TypeError(
                f"changes must be a tuple, got {type(changes).__name__}"
            )
        for change in changes:
            if not isinstance(change, tuple):
                raise TypeError(
                    f"change must be a tuple, got {type(change).__name__}"
                )
            # 长度未定前仅查存在的前二字段：种类/目标均须为 str。
            for field in change[:2]:
                if not isinstance(field, str):
                    raise TypeError(
                        "kind/target must be str, got "
                        f"{type(field).__name__}"
                    )
            # 值类型按种类可判定时即查（未知种类留待取值阶段）；容量值须为
            # tuple，恰三项时其内两个 int 与策略 str 的类型错亦在本阶段抛
            # （长度属结构错，留待取值阶段）。
            if len(change) == 3 and change[0] in (
                _CAP_REBALANCE_KIND_PRIORITY,
                _CAP_REBALANCE_KIND_BINDING,
                _CAP_REBALANCE_KIND_CAPACITY,
            ):
                kind, _target, value = change
                if kind == _CAP_REBALANCE_KIND_PRIORITY:
                    if isinstance(value, bool) or not isinstance(value, int):
                        raise TypeError(
                            f"priority value must be an int, got {type(value).__name__}"
                        )
                elif kind == _CAP_REBALANCE_KIND_BINDING:
                    if not isinstance(value, str):
                        raise TypeError(
                            f"binding value must be a str, got {type(value).__name__}"
                        )
                else:  # 容量
                    if not isinstance(value, tuple):
                        raise TypeError(
                            f"capacity value must be a tuple, got {type(value).__name__}"
                        )
                    if len(value) == 3:
                        queue_limit, max_wait_ms, policy = value
                        if isinstance(queue_limit, bool) or not isinstance(
                            queue_limit, int
                        ):
                            raise TypeError(
                                "队列上限 must be an int, got "
                                f"{type(queue_limit).__name__}"
                            )
                        if isinstance(max_wait_ms, bool) or not isinstance(
                            max_wait_ms, int
                        ):
                            raise TypeError(
                                "最大等待毫秒 must be an int, got "
                                f"{type(max_wait_ms).__name__}"
                            )
                        if isinstance(policy, bool) or not isinstance(policy, str):
                            raise TypeError(
                                f"队满策略 must be a str, got {type(policy).__name__}"
                            )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

    @staticmethod
    def _rebalance_check_values(mode, changes, now_ms):
        """capacity_rebalance 取值/结构阶段：模式、时钟下界、变更数、逐项长度/
        种类/目标/取值范围/容量三元组，及 (种类,目标) 互异。须在类型阶段后
        调用；未知模板/用户引用不在此查（演算前按现存配置查，抛 ResourceError）。"""
        if mode not in (
            _CAP_REBALANCE_MODE_PRECHECK,
            _CAP_REBALANCE_MODE_EXECUTE,
        ):
            raise ValueError(
                f"mode must be one of 预检/执行, got {mode!r}"
            )
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(changes) <= _CAP_REBALANCE_MAX_CHANGES):
            raise ValueError(
                f"changes must contain 1..{_CAP_REBALANCE_MAX_CHANGES} items, "
                f"got {len(changes)}"
            )
        seen = set()
        for change in changes:
            if len(change) != 3:
                raise ValueError(
                    "change must be a 3-tuple (kind, target, value), "
                    f"got {len(change)} items"
                )
            kind, target, value = change
            if kind not in (
                _CAP_REBALANCE_KIND_PRIORITY,
                _CAP_REBALANCE_KIND_BINDING,
                _CAP_REBALANCE_KIND_CAPACITY,
            ):
                raise ValueError(
                    "kind must be one of 优先级/绑定/容量, got "
                    f"{kind!r}"
                )
            pair = (kind, target)
            if pair in seen:
                raise ValueError(
                    f"(kind, target) must be unique, got duplicate {pair!r}"
                )
            seen.add(pair)
            if kind == _CAP_REBALANCE_KIND_PRIORITY:
                _check_credential("template target", target)
                if not (0 <= value <= _MAX_QUEUE_PRIORITY):
                    raise ValueError(
                        f"priority value must be 0..{_MAX_QUEUE_PRIORITY}, "
                        f"got {value}"
                    )
            elif kind == _CAP_REBALANCE_KIND_BINDING:
                _check_credential("user target", target)
                if value != "":
                    _check_credential("template value", value)
            else:  # 容量
                if target != "":
                    raise ValueError(
                        f'capacity target must be "", got {target!r}'
                    )
                if len(value) != 3:
                    raise ValueError(
                        "capacity value must be a 3-tuple "
                        f"(队列上限, 最大等待毫秒, 队满策略), got {len(value)} items"
                    )
                # 三项类型已在类型阶段确认；此处仅查取值范围与策略枚举。
                queue_limit, max_wait_ms, policy = value
                if not (0 <= queue_limit <= _MAX_QUEUE_LIMIT):
                    raise ValueError(
                        f"队列上限 must be 0..{_MAX_QUEUE_LIMIT}, got {queue_limit}"
                    )
                if max_wait_ms < 0:
                    raise ValueError(
                        f"最大等待毫秒 must be >= 0, got {max_wait_ms}"
                    )
                if policy not in _QUEUE_POLICIES:
                    raise ValueError(
                        "队满策略 must be one of 拒绝/替换, got "
                        f"{policy!r}"
                    )

    def _rebalance_candidate(self, changes):
        """由当前 v11 spec 与变更组候选 spec 及演算视图，不改实例。

        返回 (候选 spec, 候选绑定 dict, 候选模板优先级 dict, 候选队列上限,
        候选最大等待毫秒)。优先级仅改命中模板的排队优先级；绑定按用户覆盖或
        解绑后重排；容量三元组至多一项，缺省沿用现值。
        """
        spec = self._current_spec()
        # spec 模板项：(标识,限速,突发,配额,周期毫秒,会话上限,排队优先级,超限)。
        templates = list(spec[5])
        priority_value = {
            target: value
            for kind, target, value in changes
            if kind == _CAP_REBALANCE_KIND_PRIORITY
        }
        new_templates = []
        tmpl_priority = {}
        tmpl_limit = {}
        for item in templates:
            item = list(item)
            if item[0] in priority_value:
                item[6] = priority_value[item[0]]
            new_templates.append(tuple(item))
            tmpl_priority[item[0]] = item[6]
            tmpl_limit[item[0]] = item[5]
        # 绑定：用户 -> 模板标识；空串解绑。
        bindings = dict(self._user_templates)
        for kind, target, value in changes:
            if kind == _CAP_REBALANCE_KIND_BINDING:
                if value == "":
                    bindings.pop(target, None)
                else:
                    bindings[target] = value
        user_templates = tuple(sorted(bindings.items(), key=lambda pair: pair[0]))
        # 容量三元组缺省沿用现值。
        queue_limit, max_wait_ms, policy = spec[7]
        for kind, _target, value in changes:
            if kind == _CAP_REBALANCE_KIND_CAPACITY:
                queue_limit, max_wait_ms, policy = value
        candidate = (
            spec[0],
            spec[1],
            spec[2],
            spec[3],
            spec[4],
            tuple(new_templates),
            user_templates,
            (queue_limit, max_wait_ms, policy),
            spec[8],
            spec[9],
        )
        return (candidate, bindings, tmpl_priority, tmpl_limit, queue_limit,
                max_wait_ms)

    def _rebalance_plan(self, now_ms, queue_limit, max_wait_ms, bindings,
                        tmpl_priority, tmpl_limit, template_pool_order):
        """在局部副本上演算队列收敛（不老化、不改实例），返回决策 dict。

        队列条目复制为 [用户,申请时刻,等待,截止,入队序]；先按新最大等待缩短
        截止，再按入队序摘超时，再按 (有效值升序,入队序降序) 淘汰至队限，最后
        按反序（有效值降序、入队序升序）以计数/取址副本模拟晋升。晋升承载口径
        同 capacity_forecast 但不老化：动态址以各池空闲槽计数、专属静态址按
        (池, 用户) 记持租；候选绑定与模板地址池序列决定每个存活项的候选池序
        （未绑定或未列序列的用户仅 default 池）。
        """
        queue = {
            sid: list(entry)
            for sid, entry in self._capacity_queue.items()
        }
        order = list(self._queue_order)

        # 新最大等待非 0：截止 = min(旧截止, 申请时刻+新值)；0 不限不改。
        if max_wait_ms != 0:
            for sid in order:
                entry = queue[sid]
                entry[3] = min(entry[3], entry[1] + max_wait_ms)

        # 超时（含同刻）：按入队序摘除截止 <= now_ms 者。
        timed_out = []
        survivors = []
        for sid in order:
            if queue[sid][3] <= now_ms:
                timed_out.append(sid)
            else:
                survivors.append(sid)

        # 存活项有效值（候选绑定/优先级），键 (-有效值, 入队序) 供晋升排序，
        # (有效值, -入队序) 供淘汰排序。
        def effective(sid):
            user, applied = queue[sid][0], queue[sid][1]
            template_id = bindings.get(user)
            base = tmpl_priority.get(template_id, 0) if template_id else 0
            return min(
                _MAX_EFFECTIVE_PRIORITY,
                base + max(0, now_ms - applied) // 1000,
            )

        eff = {sid: effective(sid) for sid in survivors}

        # 淘汰至队限（0 不限）：有效值升序、并列入队序降序，自最低者先淘汰。
        evicted = []
        if queue_limit != 0 and len(survivors) > queue_limit:
            ranked = sorted(survivors, key=lambda sid: (eff[sid], -queue[sid][4]))
            evicted = ranked[: len(survivors) - queue_limit]
        evicted_set = set(evicted)
        survivors = [sid for sid in survivors if sid not in evicted_set]

        # 晋升：候选绑定下的非下线计数（不老化，在线/挂起均占全局、单用户与
        # 模板上限）；地址按候选绑定的模板地址池序列模拟各候选池当前空闲，
        # 不释放任何在租址。
        total_count = 0
        per_user = {}
        per_template = {}
        for session in self._sessions.values():
            if session["state"] == _STATE_OFFLINE:
                continue
            total_count += 1
            user = session["user"]
            per_user[user] = per_user.get(user, 0) + 1
            template_id = bindings.get(user)
            if template_id is not None:
                per_template[template_id] = per_template.get(template_id, 0) + 1

        # 地址态（不老化）：候选绑定与候选模板地址池序列决定存活项的候选池
        # 序，候选并集内的池按当前空闲槽与持租静态址建模拟态；热均衡不改变
        # 模板地址池序列，沿用当前配置 spec 的第 10 项。
        candidate_of = {
            sid: self._candidate_pools_for(
                queue[sid][0], bindings, template_pool_order
            )
            for sid in survivors
        }
        relevant_pools = set()
        for sequence in candidate_of.values():
            relevant_pools.update(sequence)
        dyn_free, static_held, _owners = self._sim_pool_state(
            now_ms, relevant_pools, False
        )

        promoted = []
        promoted_set = set()
        for sid in sorted(survivors, key=lambda q: (-eff[q], queue[q][4])):
            user = queue[sid][0]
            template_id = bindings.get(user)
            # 会话上限取候选模板（本接口不改模板上限，与现存一致；优先级改不动
            # 此项，但统一经候选视图取值）。
            session_limit = (
                tmpl_limit.get(template_id, 0) if template_id is not None else 0
            )
            servable = False
            if (
                total_count < self._total
                and per_user.get(user, 0) < self._per
                and (not session_limit or per_template.get(template_id, 0)
                     < session_limit)
            ):
                outcome, _pool_id = self._sim_try_address(
                    user,
                    now_ms,
                    candidate_of[sid],
                    dyn_free,
                    static_held,
                )
                servable = outcome == "ok"
            if servable:
                promoted.append(sid)
                promoted_set.add(sid)
                total_count += 1
                per_user[user] = per_user.get(user, 0) + 1
                if template_id is not None:
                    per_template[template_id] = per_template.get(template_id, 0) + 1

        remaining = [sid for sid in survivors if sid not in promoted_set]
        return {
            "超时": timed_out,
            "淘汰": evicted,
            "晋升": promoted,
            "剩余": remaining,
        }

    def _rebalance_apply(self, now_ms, max_wait_ms, plan):
        """候选配置已安装后把演算决策落实到实例队列并原子建立晋升会话。

        截止缩短、摘除超时与淘汰项、余留项保持原入队序；晋升按决策序经真实
        default 池取址落库（_commit_session），不记 capacity 事件、不动入队序。
        """
        # 截止缩短（与演算同式）。
        if max_wait_ms != 0:
            for sid in self._queue_order:
                entry = self._capacity_queue[sid]
                entry[3] = min(entry[3], entry[1] + max_wait_ms)

        removed = set(plan["超时"]) | set(plan["淘汰"])
        for sid in plan["超时"]:
            del self._capacity_queue[sid]
        for sid in plan["淘汰"]:
            del self._capacity_queue[sid]
        self._queue_order = [
            sid for sid in self._queue_order if sid not in removed
        ]

        # 晋升：演算已确保按序承载，落库取址与计数口径与之一致（候选配置已
        # 安装，_select_address 按此刻绑定与模板地址池序列取址）。
        for sid in plan["晋升"]:
            entry = self._capacity_queue[sid]
            user = entry[0]
            pool_id, ip_int = self._select_address(user, now_ms)
            self._commit_session(sid, user, pool_id, ip_int, now_ms)
            del self._capacity_queue[sid]
        promoted_set = set(plan["晋升"])
        self._queue_order = [
            sid for sid in self._queue_order if sid not in promoted_set
        ]

    @staticmethod
    def _render_rebalance(mode, now_ms, revision, plan):
        """键序/型：时刻:int、模式:str、修订:int、超时/淘汰/晋升:list（sid 串
        按各事件序）、剩余:int；基线紧凑 JSON，LF 结尾。"""
        payload = {
            "时刻": now_ms,
            "模式": mode,
            "修订": revision,
            "超时": list(plan["超时"]),
            "淘汰": list(plan["淘汰"]),
            "晋升": list(plan["晋升"]),
            "剩余": len(plan["剩余"]),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _checkpoint_sessions(self):
        """检查点会话快照：在线、挂起与下线墓碑全列，按会话升序。

        项键序为“会话/用户/状态/期限/池/地址/租期”；期限/租期为 int，
        余为 str。无址（挂起及租约到期未挂起）项池址为 ""、租期为 0。
        下线墓碑固定状态“下线”、期限 0、池 ""、地址 ""、租期 0，不计
        容量、不持址，仅随检查点往返保留用户归属与 sid。
        """
        rows = []
        for sid in sorted(self._sessions):
            session = self._sessions[sid]
            if session["state"] == _STATE_OFFLINE:
                rows.append(
                    {
                        "会话": sid,
                        "用户": session["user"],
                        "状态": _STATE_OFFLINE,
                        "期限": 0,
                        "池": "",
                        "地址": "",
                        "租期": 0,
                    }
                )
                continue
            if session["ip"] is None:
                pool_id = ""
                address = ""
                lease = 0
            else:
                pool_id = session["pool"]
                address = str(ipaddress.IPv4Address(session["ip"]))
                lease = session["lease"]
            rows.append(
                {
                    "会话": sid,
                    "用户": session["user"],
                    "状态": session["state"],
                    "期限": session["deadline"],
                    "池": pool_id,
                    "地址": address,
                    "租期": lease,
                }
            )
        return rows

    def _checkpoint_queued(self):
        """检查点排队快照：按入队序（即 _queue_order）。

        项键序为“会话/用户/申请时刻/等待/截止/入队序”；会话/用户为 str，
        余为 int。
        """
        rows = []
        for queued_sid in self._queue_order:
            user, applied, wait, deadline, order = self._capacity_queue[queued_sid]
            rows.append(
                {
                    "会话": queued_sid,
                    "用户": user,
                    "申请时刻": applied,
                    "等待": wait,
                    "截止": deadline,
                    "入队序": order,
                }
            )
        return rows

    @staticmethod
    def _checkpoint_state_hash(now_ms, event_rows, session_rows, queued_rows):
        """状态哈希：前四顶层键（时刻/事件/会话/排队）基线 JSON（无 LF）
        的 UTF-8 字节 sha256 小写十六进制串。"""
        state = {
            "时刻": now_ms,
            "事件": event_rows,
            "会话": session_rows,
            "排队": queued_rows,
        }
        blob = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _checkpoint_payload(self, now_ms):
        """组装检查点文档 dict（顶层键序：时刻/事件/会话/排队/状态哈希）。"""
        event_rows = [
            {
                "序号": seq,
                "时刻": ev_now,
                "会话": sid,
                "结果": verdict,
                "入队序": order,
                "前哈希": prev_hash,
                "哈希": digest,
            }
            for seq, ev_now, sid, verdict, order, prev_hash, digest
            in self._capacity_events
        ]
        session_rows = self._checkpoint_sessions()
        queued_rows = self._checkpoint_queued()
        state_hash = self._checkpoint_state_hash(
            now_ms, event_rows, session_rows, queued_rows
        )
        return {
            "时刻": now_ms,
            "事件": event_rows,
            "会话": session_rows,
            "排队": queued_rows,
            "状态哈希": state_hash,
        }

    def clog(self, now_ms):
        """输出 capacity 检查点：先验参再老化，返回 LF 结尾的基线 JSON。

        now_ms 为非 bool 非负 int，类型错 TypeError、取值错 ValueError。
        顶层键序为“时刻/事件/会话/排队/状态哈希”。事件为全量哈希链账本，
        项键序为“序号/时刻/会话/结果/入队序/前哈希/哈希”，首项前哈希为
        64 个 0、余承前项，哈希为前六键基线 JSON（无 LF）的 UTF-8 字节
        sha256 小写值；取消事件保留原入队序，事件时刻允许回拨。会话含
        在线、挂起与下线墓碑、按会话升序，下线项固定期限 0、池/地址为
        ""、租期 0；排队按入队序；状态哈希同法覆盖前四顶层键。
        """
        _check_int("now_ms", now_ms, 0)
        self._age(now_ms)
        payload = self._checkpoint_payload(now_ms)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def cverify(self):
        """校验 capacity 事件哈希链：序号连续、前哈希衔接、哈希重算一致。

        空链为 True；O(N) 时间、O(1) 空间，逐项重算不另建序列。
        """
        prev_hash = "0" * 64
        for expect, event in enumerate(self._capacity_events, start=1):
            seq, now_ms, sid, verdict, order, stored_prev, digest = event
            if seq != expect or stored_prev != prev_hash:
                return False
            if (
                self._cap_hash(seq, now_ms, sid, verdict, order, stored_prev)
                != digest
            ):
                return False
            prev_hash = digest
        return True

    @staticmethod
    def _cp_int(value, label, minimum):
        """检查点字段：非 bool 的 int 且 >= minimum，否则 ValueError。"""
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{label} must be an int, got {type(value).__name__}")
        if value < minimum:
            raise ValueError(f"{label} must be >= {minimum}, got {value}")
        return value


    @staticmethod
    def _cp_str(value, label):
        """检查点字段：str 且满足凭据约束（1..256 UTF-8 字节、无 U+0000）。"""
        if not isinstance(value, str):
            raise ValueError(f"{label} must be a str, got {type(value).__name__}")
        try:
            _check_credential(label, value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @staticmethod
    def _cp_hex64(value, label):
        """检查点字段：64 位小写十六进制 str。"""
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)
        ):
            raise ValueError(f"{label} must be a 64-char lowercase hex string")
        return value

    @staticmethod
    def _cp_plain_str(value, label):
        """检查点字段：普通 str（允许空串，用于推进失败事件的空会话）；
        非空时仍须满足凭据约束（1..256 UTF-8 字节、无 U+0000）。"""
        if not isinstance(value, str):
            raise ValueError(f"{label} must be a str, got {type(value).__name__}")
        if value != "":
            try:
                _check_credential(label, value)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        return value

    def _parse_checkpoint(self, text):
        """解析并全量校验检查点文本，返回 (时刻, 事件七元组, 会话行, 排队行,
        状态哈希)；结构、类型、取值、重复项、排序、链或状态哈希错均抛 ValueError。

        会话/排队行为规范化 dict（键序与输出一致）；会话行含在线、挂起与
        下线墓碑，墓碑固定期限 0、池/地址为 ""、租期 0。仅做结构自洽校验，
        用户注册、上限与池址承载力由 creplay 判定。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("checkpoint top level must be an object")
        if set(doc) != {"时刻", "事件", "会话", "排队", "状态哈希"}:
            raise ValueError(
                "checkpoint top-level keys must be 时刻/事件/会话/排队/状态哈希"
            )
        now_ms = self._cp_int(doc["时刻"], "时刻", 0)
        state_hash = self._cp_hex64(doc["状态哈希"], "状态哈希")

        events_raw = doc["事件"]
        sessions_raw = doc["会话"]
        queued_raw = doc["排队"]
        if not isinstance(events_raw, list):
            raise ValueError("事件 must be a list")
        if not isinstance(sessions_raw, list):
            raise ValueError("会话 must be a list")
        if not isinstance(queued_raw, list):
            raise ValueError("排队 must be a list")

        event_keys = {"序号", "时刻", "会话", "结果", "入队序", "前哈希", "哈希"}
        events = []
        event_rows = []
        prev_hash = "0" * 64
        # 入队序交叉校验：排队事件的序自 1 连续、不重复；取消/超时/晋升必引
        # 用一条此前未终结的排队序，终结后不可再用（真实账本恒如此）。
        enqueued = {}
        consumed = set()
        next_order = 1
        for expect, item in enumerate(events_raw, start=1):
            if not isinstance(item, dict) or set(item) != event_keys:
                raise ValueError(
                    f"event {expect} keys must be 序号/时刻/会话/结果/入队序/"
                    "前哈希/哈希"
                )
            seq = self._cp_int(item["序号"], "事件.序号", 1)
            ev_now = self._cp_int(item["时刻"], "事件.时刻", 0)
            sid = self._cp_plain_str(item["会话"], "事件.会话")
            verdict = item["结果"]
            if not isinstance(verdict, str) or verdict not in _CAP_VERDICTS:
                raise ValueError(f"事件.结果 is not a valid verdict: {verdict!r}")
            order = self._cp_int(item["入队序"], "事件.入队序", 0)
            if verdict in _CAP_VERDICTS_WITH_ORDER:
                if order < 1:
                    raise ValueError(f"event {seq} verdict {verdict!r} needs 入队序 >= 1")
                if verdict == _CAP_QUEUED:
                    if order != next_order:
                        raise ValueError(
                            f"event {seq} 排队 入队序 must be contiguous from 1"
                        )
                    next_order += 1
                    enqueued[order] = sid
                elif order in consumed or order not in enqueued:
                    raise ValueError(
                        f"event {seq} verdict {verdict!r} references no live 排队 order"
                    )
                else:
                    consumed.add(order)
            elif order != 0:
                raise ValueError(f"event {seq} verdict {verdict!r} needs 入队序 0")
            stored_prev = self._cp_hex64(item["前哈希"], "事件.前哈希")
            digest = self._cp_hex64(item["哈希"], "事件.哈希")
            if seq != expect:
                raise ValueError(f"event seq must be contiguous: want {expect}, got {seq}")
            if stored_prev != prev_hash:
                raise ValueError(f"event {seq} 前哈希 does not link to previous event")
            if self._cap_hash(seq, ev_now, sid, verdict, order, stored_prev) != digest:
                raise ValueError(f"event {seq} hash mismatch")
            events.append((seq, ev_now, sid, verdict, order, stored_prev, digest))
            event_rows.append(
                {
                    "序号": seq,
                    "时刻": ev_now,
                    "会话": sid,
                    "结果": verdict,
                    "入队序": order,
                    "前哈希": stored_prev,
                    "哈希": digest,
                }
            )
            prev_hash = digest

        session_keys = {"会话", "用户", "状态", "期限", "池", "地址", "租期"}
        sessions = []
        session_sids = set()
        last_sid = None
        for item in sessions_raw:
            if not isinstance(item, dict) or set(item) != session_keys:
                raise ValueError(
                    "session keys must be 会话/用户/状态/期限/池/地址/租期"
                )
            sid = self._cp_str(item["会话"], "会话.会话")
            user = self._cp_str(item["用户"], "会话.用户")
            state = item["状态"]
            if state not in (_STATE_ONLINE, _STATE_SUSPENDED, _STATE_OFFLINE):
                raise ValueError(
                    f"会话.状态 must be 在线, 挂起 or 下线: {state!r}"
                )
            deadline = self._cp_int(item["期限"], "会话.期限", 0)
            pool_id = item["池"]
            address = item["地址"]
            lease = self._cp_int(item["租期"], "会话.租期", 0)
            if not isinstance(pool_id, str) or not isinstance(address, str):
                raise ValueError("会话.池 and 会话.地址 must be str")
            if state == _STATE_OFFLINE:
                # 下线墓碑：期限 0、池 ""、地址 ""、租期 0，固定清零。
                if (
                    deadline != 0
                    or pool_id != ""
                    or address != ""
                    or lease != 0
                ):
                    raise ValueError(
                        "offline tombstone must have 期限/池/地址/租期 zeroed"
                    )
            else:
                if (pool_id == "") != (address == ""):
                    raise ValueError(
                        "会话.池 and 会话.地址 must be both empty or both set"
                    )
                if pool_id == "":
                    if lease != 0:
                        raise ValueError("会话.租期 must be 0 when 会话.池 is empty")
                else:
                    self._cp_str(pool_id, "会话.池")
                    try:
                        _check_ip("会话.地址", address)
                    except ValueError as exc:
                        raise ValueError(str(exc)) from exc
                if state == _STATE_SUSPENDED and (
                    deadline != 0 or pool_id != "" or address != "" or lease != 0
                ):
                    raise ValueError(
                        "suspended session must have 期限/池/地址/租期 zeroed"
                    )
                if state == _STATE_ONLINE:
                    if deadline < 1:
                        raise ValueError("online session must have 期限 >= 1")
                    if pool_id != "" and lease < 1:
                        raise ValueError(
                            "online session with address must have 租期 >= 1"
                        )
            if sid in session_sids:
                raise ValueError(f"duplicate session in checkpoint: {sid!r}")
            if last_sid is not None and sid <= last_sid:
                raise ValueError("会话 rows must be sorted by 会话 ascending")
            last_sid = sid
            session_sids.add(sid)
            sessions.append(
                {
                    "会话": sid,
                    "用户": user,
                    "状态": state,
                    "期限": deadline,
                    "池": pool_id,
                    "地址": address,
                    "租期": lease,
                }
            )

        queued_keys = {"会话", "用户", "申请时刻", "等待", "截止", "入队序"}
        queued = []
        prev_order = 0
        queued_sids = set()
        for item in queued_raw:
            if not isinstance(item, dict) or set(item) != queued_keys:
                raise ValueError(
                    "queued keys must be 会话/用户/申请时刻/等待/截止/入队序"
                )
            sid = self._cp_str(item["会话"], "排队.会话")
            user = self._cp_str(item["用户"], "排队.用户")
            applied = self._cp_int(item["申请时刻"], "排队.申请时刻", 0)
            wait = self._cp_int(item["等待"], "排队.等待", 1)
            deadline = self._cp_int(item["截止"], "排队.截止", 0)
            order = self._cp_int(item["入队序"], "排队.入队序", 1)
            if deadline != applied + wait:
                raise ValueError(
                    f"排队.截止 must equal 申请时刻+等待 for {sid!r}"
                )
            if order <= prev_order:
                raise ValueError("排队 rows must be strictly ordered by 入队序")
            prev_order = order
            if sid in queued_sids:
                raise ValueError(f"duplicate queued sid in checkpoint: {sid!r}")
            if sid in session_sids:
                raise ValueError(f"sid both session and queued: {sid!r}")
            queued_sids.add(sid)
            queued.append(
                {
                    "会话": sid,
                    "用户": user,
                    "申请时刻": applied,
                    "等待": wait,
                    "截止": deadline,
                    "入队序": order,
                }
            )

        # 事件与排队行交叉校验：每行入队序须有未终结排队事件且会话一致，
        # 反之亦然（真实账本中在队项恰为入队未取消/超时/晋升者）。
        live_orders = {order for order in enqueued if order not in consumed}
        queued_orders = {row["入队序"] for row in queued}
        if queued_orders != live_orders:
            raise ValueError("排队 rows do not match live 排队 events")
        for row in queued:
            if enqueued[row["入队序"]] != row["会话"]:
                raise ValueError(
                    f"排队 row {row['会话']!r} sid does not match its 排队 event"
                )

        # 状态哈希：用规范化行重算（数值相等即与生成方基线逐字节一致，与原文排版无关）。
        if self._checkpoint_state_hash(
            now_ms, event_rows, sessions, queued
        ) != state_hash:
            raise ValueError("状态哈希 mismatch: checkpoint is not canonical")
        return now_ms, events, sessions, queued, state_hash

    def _rebuild_pool_leases(self, required_leases):
        """按承载租约重建全部池的租约表与动态空闲堆（租约表完全由在租会话
        决定，属可由检查点派生的状态）：租约表只保留所列在租址，空闲堆为
        可用集扣除保留、静态与在租动态址。静态址未租时不回堆，语义同 _Pool。
        """
        for pool_id, pool in self._pools.items():
            pool_leases = required_leases.get(pool_id, {})
            pool.leases.clear()
            pool.leases.update(pool_leases)
            usable = {
                int(host) for host in ipaddress.IPv4Network(pool.cidr).hosts()
            }
            pool.free = [
                ip_int
                for ip_int in usable
                if ip_int not in pool.reserved
                and ip_int not in pool.static_ips
                and ip_int not in pool_leases
            ]
            heapq.heapify(pool.free)

    def _checkpoint_carry_leases(self, sessions, queued):
        """检查点承载力校验（ResourceError）：用户注册（墓碑仍归属已注册
        用户）、全局/单用户上限（仅计在线/挂起，墓碑不计容量）、池与地址
        （墓碑不建租约）。sessions/queued 为 _parse_checkpoint 的规范化行；
        通过则返回 pool -> {ip_int: sid} 的承载租约表，供重建全部池租约。
        """
        for row in sessions:
            if row["用户"] not in self._auth:
                raise ResourceError(
                    f"checkpoint references unregistered user: {row['用户']!r}"
                )
        for row in queued:
            if row["用户"] not in self._auth:
                raise ResourceError(
                    f"checkpoint references unregistered user: {row['用户']!r}"
                )
        live_sessions = [
            row for row in sessions if row["状态"] != _STATE_OFFLINE
        ]
        if len(live_sessions) > self._total:
            raise ResourceError(
                f"total session limit {self._total} below "
                f"{len(live_sessions)} sessions"
            )
        per_user = {}
        for row in live_sessions:
            user = row["用户"]
            per_user[user] = per_user.get(user, 0) + 1
        for user, count in per_user.items():
            if count > self._per:
                raise ResourceError(
                    f"per-user session limit {self._per} below {count} sessions "
                    f"for {user!r}"
                )
        # pool -> ip_int -> sid：同址重复占用即不可承载。
        pool_usable = {}

        def usable_of(pool_id):
            usable = pool_usable.get(pool_id)
            if usable is None:
                usable = {
                    int(host)
                    for host in ipaddress.IPv4Network(self._pools[pool_id].cidr).hosts()
                }
                pool_usable[pool_id] = usable
            return usable

        required_leases = {}
        for row in sessions:
            if row["池"] == "":
                continue
            pool = self._pools.get(row["池"])
            if pool is None:
                raise ResourceError(
                    f"checkpoint cannot carry lease of sid {row['会话']!r}: "
                    f"no pool {row['池']!r}"
                )
            ip_int = _check_ip("会话.地址", row["地址"])
            if ip_int not in usable_of(row["池"]) or ip_int in pool.reserved:
                raise ResourceError(
                    f"checkpoint cannot carry lease of sid {row['会话']!r}: "
                    f"address {row['地址']} not usable in pool {row['池']!r}"
                )
            if ip_int in pool.static_ips and pool.static.get(row["用户"]) != ip_int:
                raise ResourceError(
                    f"checkpoint cannot carry lease of sid {row['会话']!r}: "
                    f"address {row['地址']} is static for another user"
                )
            pool_leases = required_leases.setdefault(row["池"], {})
            if ip_int in pool_leases:
                raise ResourceError(
                    f"address {row['地址']} in pool {row['池']!r} rented by "
                    f"{pool_leases[ip_int]!r} and {row['会话']!r}"
                )
            pool_leases[ip_int] = row["会话"]
        return required_leases

    def creplay(self, text):
        """按检查点恢复所列会话（含下线墓碑）、租约、队列与 capacity 事件
        账本，返回检查点时刻 capacity_stats 的 LF 结尾 JSON。

        text 非 str 抛 TypeError；非规范包（JSON/结构/类型/取值/清零字段不符/
        非法状态/重复项/乱序）、链断或状态哈希不符抛 ValueError。目标当前持有
        检查点之外的会话（在线/挂起/下线墓碑）、排队项或事件，或同标识会话
        状态或字段不一致，抛 StateError。检查点引用未注册用户、非下线会话数超
        全局/单用户上限、池缺失或地址不可用/被保留/静态易主/重复占用，抛
        ResourceError；下线墓碑不计容量、不建租约，仅保留 sid 与用户归属。
        全部校验通过后原子替换会话、租约、队列、账本与入队序游标，失败全不变；
        配置、认证器、QoS、计量账本与统计、各域重放缓存、接管与 do 审计链均
        不受影响。当前状态与检查点同状态哈希时重放为空操作（不替换、不追加事件），
        现状墓碑原样保留。
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        now_ms, events, sessions, queued, state_hash = self._parse_checkpoint(text)

        # 同状态哈希（以当前实况、不老化重算规范化前四键）：会话（含墓碑）、
        # 队列与账本已与检查点逐字段一致，空操作不替换、不追加事件，现状墓碑
        # 原样保留；租约表为在租会话的派生态（墓碑无址不入表），顺带对齐。
        current = self._checkpoint_payload(now_ms)
        current_hash = self._checkpoint_state_hash(
            now_ms, current["事件"], current["会话"], current["排队"]
        )
        if current_hash == state_hash:
            live_leases = {}
            for sid, session in self._sessions.items():
                if session["ip"] is not None:
                    live_leases.setdefault(session["pool"], {})[session["ip"]] = sid
            self._rebuild_pool_leases(live_leases)
            return self.capacity_stats(now_ms)

        target_sessions = {row["会话"]: row for row in sessions}
        target_queued = {row["会话"]: row for row in queued}

        # 非同批状态（StateError 先于承载力判定）：账本只能在同链上延展，
        # 目标现存会话（在线/挂起/下线墓碑）与排队项必须与检查点同批行
        # 逐字段一致；包外任一项（含包外墓碑）即非同批轨迹。
        if len(self._capacity_events) > len(events):
            raise StateError("current ledger has events beyond checkpoint")
        for current, wanted in zip(self._capacity_events, events):
            if current != wanted:
                raise StateError(
                    f"event {wanted[0]} diverges from current ledger"
                )
        for sid, session in self._sessions.items():
            row = target_sessions.get(sid)
            if row is None:
                # 目标存在而检查点未列：在线/挂起为包外会话，下线为包外墓碑。
                raise StateError(f"current session {sid!r} is not in checkpoint")
            current_ip = (
                "" if session["ip"] is None
                else str(ipaddress.IPv4Address(session["ip"]))
            )
            current_pool = "" if session["pool"] is None else session["pool"]
            if (
                session["user"] != row["用户"]
                or session["state"] != row["状态"]
                or session["deadline"] != row["期限"]
                or current_pool != row["池"]
                or current_ip != row["地址"]
                or session["lease"] != row["租期"]
            ):
                # 同标识但状态或字段不同（在线/挂起/下线三态互异）。
                raise StateError(f"current session {sid!r} diverges from checkpoint")
        for queued_sid in self._queue_order:
            entry = self._capacity_queue[queued_sid]
            row = target_queued.get(queued_sid)
            if row is None:
                raise StateError(f"current queued sid {queued_sid!r} not in checkpoint")
            user, applied, wait, deadline, order = entry
            if (
                user != row["用户"]
                or applied != row["申请时刻"]
                or wait != row["等待"]
                or deadline != row["截止"]
                or order != row["入队序"]
            ):
                raise StateError(f"current queued sid {queued_sid!r} diverges")

        # 承载力（ResourceError）：用户注册（墓碑仍归属已注册用户）、全局/单用户
        # 上限（仅计在线/挂起，墓碑不计容量）、池与地址（墓碑不建租约）。
        required_leases = self._checkpoint_carry_leases(sessions, queued)

        # 全部校验通过：原子替换会话（含墓碑）、租约、队列、入队序游标与账本。
        new_sessions = {}
        for row in sessions:
            if row["池"] == "":
                pool_id = None
                ip_int = None
            else:
                pool_id = row["池"]
                ip_int = _check_ip("会话.地址", row["地址"])
            new_sessions[row["会话"]] = {
                "user": row["用户"],
                "state": row["状态"],
                "deadline": row["期限"],
                "ip": ip_int,
                "lease": row["租期"],
                "pool": pool_id,
            }
        self._sessions = new_sessions
        # 以承载租约重建全部池（租约表与空闲堆为在租会话的派生态）。
        self._rebuild_pool_leases(required_leases)
        self._capacity_queue = {
            row["会话"]: [
                row["用户"],
                row["申请时刻"],
                row["等待"],
                row["截止"],
                row["入队序"],
            ]
            for row in queued
        }
        self._queue_order = [row["会话"] for row in queued]
        # 入队序计数取账本中历次排队事件的最大序（消费不回收序号），解析已
        # 保证排队序自 1 连续，故即排队行空（全部超时/晋升/取消后）也不重用。
        self._queue_seq = max(
            (order for _s, _t, _sid, verdict, order, _p, _h in events
             if verdict == _CAP_QUEUED),
            default=0,
        )
        self._capacity_events = list(events)
        self._capacity_tail = events[-1][6] if events else "0" * 64
        return self.capacity_stats(now_ms)

    def _runtime_payload(self, now_ms):
        """组装运行态检查点文档 dict（顶层键序：版本/时刻/容量/配额/摘要）。

        容量为同刻 clog 对象（其时刻等于顶层时刻），配额为同刻
        quota_checkpoint 对象；摘要为前四键紧凑 JSON（无 LF）UTF-8 字节的
        sha256 小写十六进制串。纯渲染，不老化、不改态。
        """
        doc = {
            "版本": 1,
            "时刻": now_ms,
            "容量": self._checkpoint_payload(now_ms),
            "配额": json.loads(self._quota_checkpoint_text()),
        }
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return doc

    def _runtime_checkpoint_text(self, now_ms):
        """运行态检查点的 LF 结尾紧凑 JSON（基线序列化，不老化、不改态）。"""
        return json.dumps(
            self._runtime_payload(now_ms), ensure_ascii=False, separators=(",", ":")
        ) + "\n"

    def runtime_checkpoint(self, now_ms):
        """输出运行态检查点：先验参再老化一次，返回 LF 结尾的基线 JSON。

        now_ms 为非 bool 非负 int，类型错 TypeError、取值错 ValueError。
        顶层键序为“版本/时刻/容量/配额/摘要”，版本为 1；容量沿用同刻
        clog 对象契约（时刻等于顶层时刻），配额沿用同刻 quota_checkpoint
        对象契约；摘要为前四键紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写
        值。检查点覆盖会话/租约、容量队列/事件与共享 QoS 账本，供续租、
        计量、推进一致恢复。时间 O(N log N)、空间 O(N)。
        """
        _check_int("now_ms", now_ms, 0)
        self._age(now_ms)
        return self._runtime_checkpoint_text(now_ms)

    def runtime_restore(self, key, text):
        """按运行态检查点原子替换会话/租约、容量队列/事件与共享 QoS 账本，
        返回规范包的 LF 结尾基线 JSON。

        key 沿用凭据约束，text 须为 str；类型错抛 TypeError。JSON 解析、
        重键、键序/结构/类型/取值/排序、版本、摘要或时刻（容量时刻不等于
        顶层时刻）非法均抛 ValueError；检查点引用未注册用户、未知模板、
        池址不承载、令牌超桶容、全局/单用户上限或引用不承载抛
        ResourceError；目标持有与包摘要不同的覆盖状态（待替换的会话、
        队列、事件或现存模板账本）抛 StateError。全部校验通过后原子替换；
        目标现状与包同摘要时为空操作（顺带对齐派生租约）。任何失败不改
        运行态、配置、缓存与审计；不审计。重放缓存与各域独立：仅缓存首次
        成功，同 key 同型同 text 重放无副作用，异参抛 ValueError。
        时间 O(N log N)、空间 O(N)。
        """
        _check_credential("key", key)

        cached = self._runtime_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text 后返回缓存规范包。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        # 全部校验在新数据上进行，通过后一次性替换；任何失败实例不变。
        now_ms, events, sessions, queued, quota_rows, summary = (
            self._parse_runtime_checkpoint(text)
        )

        # 同摘要（以当前实况、不老化重算规范化前四键）：会话（含墓碑）、队列、
        # 账本与现存模板账本已与检查点逐字段一致，空操作不替换；租约表为在租
        # 会话的派生态，顺带对齐。
        if self._runtime_payload(now_ms)["摘要"] == summary:
            live_leases = {}
            for sid, session in self._sessions.items():
                if session["ip"] is not None:
                    live_leases.setdefault(session["pool"], {})[session["ip"]] = sid
            self._rebuild_pool_leases(live_leases)
            result = self._runtime_checkpoint_text(now_ms)
            self._runtime_restore_cache[key] = (text, result)
            return result

        # 承载力（ResourceError）：容量部分沿 creplay 口径（用户、全局/单用户
        # 上限、池址）；配额部分沿 quota_restore 口径（用户、模板、令牌桶容，
        # 本题归为不承载 ResourceError）。
        required_leases = self._checkpoint_carry_leases(sessions, queued)
        for user, template_id, _used, _last, tokens in quota_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"runtime checkpoint references unregistered user: {user!r}"
                )
            template = self._templates.get(template_id)
            if template is None:
                raise ResourceError(
                    f"runtime checkpoint references unknown template: "
                    f"{template_id!r}"
                )
            if tokens > (template[0] + template[1]) * 1000:
                raise ResourceError(
                    f"令牌 for {(user, template_id)!r} exceeds template bucket "
                    f"capacity {(template[0] + template[1]) * 1000}"
                )

        # 覆盖状态（StateError）：目标持有待替换的会话（含墓碑）、排队项、
        # 事件或现存模板账本，且摘要与包不同（同摘要已在上方空操作返回）。
        if (
            self._sessions
            or self._capacity_queue
            or self._capacity_events
            or any(
                template_id in self._templates
                for _user, template_id in self._meter_ledgers
            )
        ):
            raise StateError(
                "current runtime state diverges from checkpoint 摘要"
            )

        # 全部校验通过：原子替换会话（含墓碑）、租约、队列、入队序游标、
        # 事件账本与现存模板账本；已删模板的历史账本原样保留。
        new_sessions = {}
        for row in sessions:
            if row["池"] == "":
                pool_id = None
                ip_int = None
            else:
                pool_id = row["池"]
                ip_int = _check_ip("会话.地址", row["地址"])
            new_sessions[row["会话"]] = {
                "user": row["用户"],
                "state": row["状态"],
                "deadline": row["期限"],
                "ip": ip_int,
                "lease": row["租期"],
                "pool": pool_id,
            }
        self._sessions = new_sessions
        # 以承载租约重建全部池（租约表与空闲堆为在租会话的派生态）。
        self._rebuild_pool_leases(required_leases)
        self._capacity_queue = {
            row["会话"]: [
                row["用户"],
                row["申请时刻"],
                row["等待"],
                row["截止"],
                row["入队序"],
            ]
            for row in queued
        }
        self._queue_order = [row["会话"] for row in queued]
        # 入队序计数取账本中历次排队事件的最大序（消费不回收序号）。
        self._queue_seq = max(
            (order for _s, _t, _sid, verdict, order, _p, _h in events
             if verdict == _CAP_QUEUED),
            default=0,
        )
        self._capacity_events = list(events)
        self._capacity_tail = events[-1][6] if events else "0" * 64
        new_ledgers = {
            ledger_key: ledger
            for ledger_key, ledger in self._meter_ledgers.items()
            if ledger_key[1] not in self._templates
        }
        for user, template_id, used, last, tokens in quota_rows:
            new_ledgers[(user, template_id)] = [used, last, tokens]
        self._meter_ledgers = new_ledgers

        result = self._runtime_checkpoint_text(now_ms)
        self._runtime_restore_cache[key] = (text, result)
        return result

    def _parse_runtime_checkpoint(self, text):
        """解析并全量校验运行态检查点文本，返回 (时刻, 事件七元组, 会话行,
        排队行, 配额行, 摘要)；任何文本非法均抛 ValueError。

        顶层须恰含“版本/时刻/容量/配额/摘要”且键序如此；版本为 1，时刻为
        非 bool 非负 int，容量/配额分别沿用 clog/quota_checkpoint 对象契约
        （嵌套键序按原文校验后，经 _parse_checkpoint/_parse_quota_checkpoint
        全量校验），容量时刻
        须等于顶层时刻，摘要须为规范化前四键紧凑 JSON（无 LF）UTF-8 字节的
        sha256 小写值（与原文排版无关）。仅做结构自洽校验；用户注册、模板
        存在、令牌桶容、上限与池址承载力由 runtime_restore 判定。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"runtime checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("runtime checkpoint top level must be an object")
        # 键集与键序：恰为“版本/时刻/容量/配额/摘要”且依此序（dict 保序）。
        if list(doc) != ["版本", "时刻", "容量", "配额", "摘要"]:
            raise ValueError(
                "runtime checkpoint top-level keys must be "
                "版本/时刻/容量/配额/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        now_ms = self._cp_int(doc["时刻"], "时刻", 0)
        summary = self._cp_hex64(doc["摘要"], "摘要")
        if not isinstance(doc["容量"], dict):
            raise ValueError("容量 must be an object")
        if not isinstance(doc["配额"], dict):
            raise ValueError("配额 must be an object")

        # 嵌套键序按原文校验（dict 保序），先于规范化与摘要重算：容量顶层
        # 及事件/会话/排队各项沿用 clog 键序，配额沿用 quota_checkpoint
        # 键序；错序即 ValueError。非 list 列与非 dict 项交由下游解析器
        # 按其键集/类型规则报 ValueError。
        capacity = doc["容量"]
        if list(capacity) != ["时刻", "事件", "会话", "排队", "状态哈希"]:
            raise ValueError(
                "容量 keys must be 时刻/事件/会话/排队/状态哈希 in order"
            )
        if list(doc["配额"]) != ["版本", "账本"]:
            raise ValueError("配额 keys must be 版本/账本 in order")
        for label, key_order in (
            ("事件", ["序号", "时刻", "会话", "结果", "入队序", "前哈希", "哈希"]),
            ("会话", ["会话", "用户", "状态", "期限", "池", "地址", "租期"]),
            ("排队", ["会话", "用户", "申请时刻", "等待", "截止", "入队序"]),
        ):
            rows = capacity[label]
            if not isinstance(rows, list):
                continue
            for item in rows:
                if isinstance(item, dict) and list(item) != key_order:
                    raise ValueError(
                        f"容量.{label} item keys must be "
                        f"{'/'.join(key_order)} in order"
                    )

        # 子文档重编码为紧凑 JSON 后沿用既有解析器全量校验（重键已在顶层
        # 解析时拒绝；规范化行由解析器返回，与原文排版无关）。
        cap_now, events, sessions, queued, state_hash = self._parse_checkpoint(
            json.dumps(doc["容量"], ensure_ascii=False, separators=(",", ":"))
        )
        if cap_now != now_ms:
            raise ValueError(
                f"容量.时刻 must equal top-level 时刻 {now_ms}, got {cap_now}"
            )
        quota_rows = self._parse_quota_checkpoint(
            json.dumps(doc["配额"], ensure_ascii=False, separators=(",", ":"))
        )

        # 摘要：用规范化行重建前四键（数值相等即与生成方基线逐字节一致）。
        canonical_capacity = {
            "时刻": cap_now,
            "事件": [
                {
                    "序号": seq,
                    "时刻": ev_now,
                    "会话": sid,
                    "结果": verdict,
                    "入队序": order,
                    "前哈希": prev_hash,
                    "哈希": digest,
                }
                for seq, ev_now, sid, verdict, order, prev_hash, digest in events
            ],
            "会话": sessions,
            "排队": queued,
            "状态哈希": state_hash,
        }
        canonical_head = {
            "版本": 1,
            "时刻": now_ms,
            "容量": canonical_capacity,
            "配额": {"版本": 1, "账本": [list(row) for row in quota_rows]},
        }
        blob = json.dumps(canonical_head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical runtime checkpoint")
        return now_ms, events, sessions, queued, quota_rows, summary

    def _accounting_payload(self):
        """组装计费检查点文档 dict（顶层键序：版本/事件/活动/尾哈希）。

        事件为计费哈希链全量十一键行（序号升序）；活动按会话 Unicode 码点
        升序，项键序“会话/累计字节/最近计费时刻”；尾哈希为链末哈希（空链
        64 个 0）。纯渲染：不老化、不改态。
        """
        active_rows = [
            {
                "会话": sid,
                "累计字节": self._account_active[sid][0],
                "最近计费时刻": self._account_active[sid][2],
            }
            for sid in sorted(self._account_active)
        ]
        return {
            "版本": 1,
            "事件": [
                self._account_event_dict(event) for event in self._account_events
            ],
            "活动": active_rows,
            "尾哈希": self._account_tail,
        }

    def _service_payload(self, now_ms, config_summary):
        """组装跨域一致性检查点文档 dict（v2 顶层键序：
        版本/时刻/配置摘要/认证/运行态/故障/统计/计费/摘要）。

        各子对象直接取同一状态、同一时刻的规范域文档（认证 v2、运行态 v1、
        故障 v1、统计 v1、计费 v1，均含各自摘要）；摘要为前八键紧凑 JSON
        （无 LF）UTF-8 字节的 sha256 小写十六进制串。纯渲染：不老化、不改态。
        """
        doc = {
            "版本": _SERVICE_VERSION,
            "时刻": now_ms,
            "配置摘要": config_summary,
            "认证": self._auth_payload(now_ms),
            "运行态": self._runtime_payload(now_ms),
            "故障": self._fault_payload(now_ms),
            "统计": self._stats_payload(),
            "计费": self._accounting_payload(),
        }
        blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        doc["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return doc

    def _service_checkpoint_text(self, now_ms, config_summary):
        """跨域一致性检查点的 LF 尾紧凑 JSON（基线序列化，不老化、不改态）。"""
        return json.dumps(
            self._service_payload(now_ms, config_summary),
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"

    def service_checkpoint(self, now_ms):
        """只读输出跨域一致性检查点的 LF 结尾基线 JSON，把认证（凭据限制
        摘要）、会话与租约、容量队列及事件、QoS 账本、故障演练态、统计与
        会话计费链收进同一份包；单次 O(N log N) 时间、O(N) 辅助空间（N 为
        用户、会话、排队项、容量/计费事件、账本、故障项、统计明细与配置项
        总数）。

        先校验显式毫秒时钟（非 bool 非负 int：类型错 TypeError、取值错
        ValueError），且只执行一次既有老化（_age），随后从同一状态取得当前
        v11 配置的规范摘要与各域对象；除本次老化外只读：不认证、不计量、不
        推进容量、不新增统计、不写任何审计/计费事件、不动各域幂等缓存，也不
        导出或清空配置与配置历史。顶层键固定依次为
        “版本/时刻/配置摘要/认证/运行态/故障/统计/计费/摘要”，版本恒为 2；
        配置摘要为当前 v11 配置紧凑编码（无 LF）UTF-8 字节的 sha256 小写值；
        认证沿用同刻 auth_checkpoint 的版本 2 规范对象，运行态沿用同刻
        runtime_checkpoint 对象（容量时刻等于顶层时刻），故障沿用同刻
        fault_checkpoint 对象，统计沿用 stats_checkpoint 对象，计费为版本 1
        对象（键序版本/事件/活动/尾哈希：事件为计费哈希链全量十一键行，活动
        按会话升序列“会话/累计字节/最近计费时刻”，尾哈希为链末哈希，空链
        64 个 0）；末摘要覆盖前八键紧凑编码（无 LF）的 UTF-8 字节。同一状态
        与同一时刻逐字节相同。
        """
        _check_int("now_ms", now_ms, 0)
        # 唯一副作用：先老化一次；之后全部从同一老化后状态取快照。
        self._age(now_ms)
        config_summary = self._config_summary()
        return self._service_checkpoint_text(now_ms, config_summary)

    def service_restore(self, key, text):
        """按跨域一致性检查点原子恢复认证、会话与租约、容量队列及事件、QoS
        账本、故障演练态、统计与会话计费态，返回恢复后同格式规范检查点（版本
        恒为 2）的 LF 结尾基线 JSON。

        key 沿凭据约束，text 须为 str：key 型/值错抛 TypeError/ValueError，
        text 非 str 抛 TypeError。在改变任何状态前完成全部校验：JSON、重键、
        顶层键集/键序、版本（接受 1 与 2：版本 1 无“计费”域，缺失计费态按空
        处理；版本与键序形态不符即 ValueError）、字段类型、排序、各层
        （认证/运行态/故障/统计及容量事件链与状态哈希）摘要、计费链结构与
        哈希、统一时刻（认证、容量、故障时刻均须等于顶层时刻）与跨域引用。
        非法 JSON、结构、版本、顺序、值、排序、计费链哈希/生命周期或摘要，或
        同 key 异参抛 ValueError；目标当前配置摘要与包“配置摘要”不一致抛
        StateError("配置")；认证用户集合与当前认证器不同，或内容引用未注册
        用户、未知模板、未知地址池（含池址不承载、全局/单用户上限不足、令牌
        超桶容、计费事件引用未知地址池或未知会话）抛 ResourceError。若目标
        已有与包计费态不同的非空计费链或活动账，抛 StateError("计费")；若目标
        已有与包运行态摘要不同的会话、排队项、容量事件或现存模板账本，抛
        StateError("运行态")；目标各域为空或整体相同（全部五域摘要均相同）时，
        认证限制与凭据摘要、运行态、故障态、统计与计费态整体替换；恢复后地址
        池租约由在租会话重建，必与会话一致。版本 1 包恢复后，其遗留在线会话
        无开始事件：后续 meter/accounting_interim 惰性建账，不补开始事件。

        不导入或清空配置与配置历史，不恢复主审计链、批量审计链、合规链及既有
        各域幂等缓存，也不为生成、恢复或重放追加任何审计/计费事件；不触发认证、
        计量、容量推进或新的统计。任何失败都不改变任何域、不占用幂等 key；成功
        缓存首次规范包，同 key 同型同 text 重放不解析、不重验、不替换、原样
        返回缓存字节且不产生修改，异参（含异型）抛 ValueError。单次
        O(N log N) 时间、O(N) 辅助空间。
        """
        _check_credential("key", key)

        cached = self._service_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不替换、不老化，仅核对同型同 text 后返回缓存规范包。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        parsed = self._parse_service_checkpoint(text)
        now_ms = parsed["now"]
        config_summary = parsed["config_summary"]
        auth_summary, auth_rows = parsed["auth"]
        (
            rt_summary, events, sessions, queued, quota_rows
        ) = parsed["runtime"]
        (
            until, backoff_rows, fail_pair, pool_rows, waiting, trigger
        ) = parsed["fault"][1:]
        fault_summary = parsed["fault"][0]
        (
            stats_summary, total, success, fail_rows, user_rows, template_rows
        ) = parsed["stats"]
        account_events, active_rows, account_refs = parsed["accounting"]
        account_unknown_sids, _account_pool_refs = account_refs

        # 配置先于一切：目标当前 v11 配置摘要须与包一致，否则 StateError。
        if self._config_summary() != config_summary:
            raise StateError("配置")

        # 认证用户集合须与当前认证器完全一致。
        if {user for user, *_ in auth_rows} != set(self._auth._users):
            raise ResourceError(
                "service checkpoint auth user set does not match the current "
                "authenticator"
            )

        # 承载力/引用（ResourceError），沿 runtime_restore/creplay 口径：
        # 会话与队项用户注册、全局/单用户上限、池址承载；账本用户注册、模板
        # 存在、令牌桶容。
        required_leases = self._checkpoint_carry_leases(sessions, queued)
        for user, template_id, _used, _last, tokens in quota_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"service checkpoint references unregistered user: {user!r}"
                )
            template = self._templates.get(template_id)
            if template is None:
                raise ResourceError(
                    f"service checkpoint references unknown template: "
                    f"{template_id!r}"
                )
            if tokens > (template[0] + template[1]) * 1000:
                raise ResourceError(
                    f"令牌 for {(user, template_id)!r} exceeds template bucket "
                    f"capacity {(template[0] + template[1]) * 1000}"
                )
        # 故障演练引用：退避用户注册、池标识存在。
        for user, _n, _retry_at in backoff_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"service checkpoint references unregistered user: {user!r}"
                )
        for pool_id, _pool_until in pool_rows:
            if pool_id not in self._pools:
                raise ResourceError(
                    f"service checkpoint references unknown pool: {pool_id!r}"
                )
        # 统计引用：用户失败行与用户计量行的标识须注册；模板计量不验引用。
        for user, _a, _r, _st, _b in fail_rows:
            if user not in self._auth:
                raise ResourceError(
                    f"service checkpoint references unregistered user: {user!r}"
                )
        for ident, _p, _d, _o, _by in user_rows:
            if ident not in self._auth:
                raise ResourceError(
                    f"service checkpoint references unregistered user: {ident!r}"
                )
        # 计费引用（仅 v2）：事件或活动行引用未知会话，或事件引用未知地址池。
        for sid in account_unknown_sids:
            raise ResourceError(
                f"service checkpoint accounting references unknown session: {sid!r}"
            )
        for pool_id in _account_pool_refs:
            if pool_id not in self._pools:
                raise ResourceError(
                    f"service checkpoint accounting references unknown pool: "
                    f"{pool_id!r}"
                )

        # 计费覆盖判定：包计费态（v1 缺失按空）与目标当前计费态不同，且目标
        # 已有非空计费链或活动账时，拒绝整体替换。
        package_accounting = {
            "版本": 1,
            "事件": [
                self._account_event_dict(event) for event in account_events
            ],
            "活动": [
                {"会话": sid, "累计字节": total, "最近计费时刻": last_account}
                for sid, total, last_account in active_rows
            ],
            "尾哈希": account_events[-1][10] if account_events else "0" * 64,
        }
        if self._accounting_payload() != package_accounting and (
            self._account_events or self._account_active
        ):
            raise StateError("计费")

        # 运行态覆盖判定：同摘要为空操作轨迹；否则目标运行态（会话、队项、事件
        # 或现存模板账本）必须为空，才允许整体替换。
        runtime_same = self._runtime_payload(now_ms)["摘要"] == rt_summary
        if not runtime_same and (
            self._sessions
            or self._capacity_queue
            or self._capacity_events
            or any(
                template_id in self._templates
                for _user, template_id in self._meter_ledgers
            )
        ):
            raise StateError("运行态")

        # 全部校验通过：从老化后同一目标状态原子替换四域。认证策略四项不变；
        # 配置、配置历史、三类审计链与全部既有幂等缓存均不触碰；已删模板的
        # 历史账本原样保留。
        new_users = {
            user: [digest, failed, until_v, retry_at]
            for user, digest, failed, until_v, retry_at, _disabled in auth_rows
        }
        self._auth._users = new_users
        self._disabled_users = {
            user
            for user, _digest, _failed, _until, _retry, disabled in auth_rows
            if disabled
        }

        new_sessions = {}
        for row in sessions:
            if row["池"] == "":
                pool_id = None
                ip_int = None
            else:
                pool_id = row["池"]
                ip_int = _check_ip("会话.地址", row["地址"])
            new_sessions[row["会话"]] = {
                "user": row["用户"],
                "state": row["状态"],
                "deadline": row["期限"],
                "ip": ip_int,
                "lease": row["租期"],
                "pool": pool_id,
            }
        self._sessions = new_sessions
        # 以承载租约重建全部池（租约表与空闲堆为在租会话的派生态），保证恢复
        # 后租约必与会话一致。
        self._rebuild_pool_leases(required_leases)
        self._capacity_queue = {
            row["会话"]: [
                row["用户"],
                row["申请时刻"],
                row["等待"],
                row["截止"],
                row["入队序"],
            ]
            for row in queued
        }
        self._queue_order = [row["会话"] for row in queued]
        # 入队序计数取账本中历次排队事件的最大序（消费不回收序号）。
        self._queue_seq = max(
            (order for _s, _t, _sid, verdict, order, _p, _h in events
             if verdict == _CAP_QUEUED),
            default=0,
        )
        self._capacity_events = list(events)
        self._capacity_tail = events[-1][6] if events else "0" * 64
        new_ledgers = {
            ledger_key: ledger
            for ledger_key, ledger in self._meter_ledgers.items()
            if ledger_key[1] not in self._templates
        }
        for user, template_id, used, last, tokens in quota_rows:
            new_ledgers[(user, template_id)] = [used, last, tokens]
        self._meter_ledgers = new_ledgers

        self._fault_until = until
        self._backoff = {
            user: (n, retry_at) for user, n, retry_at in backoff_rows
        }
        self._fault_fail = [fail_pair[0], fail_pair[1]]
        self._pool_fault = {
            pool_id: pool_until for pool_id, pool_until in pool_rows
        }
        self._timeout_at = trigger if waiting else None

        self._establish_total = total
        self._establish_success = success
        self._user_fail = {
            user: [a, r, st, b] for user, a, r, st, b in fail_rows
        }
        self._meter_stats_user = {
            ident: [p, d, o, byt] for ident, p, d, o, byt in user_rows
        }
        self._meter_stats_template = {
            ident: [p, d, o, byt] for ident, p, d, o, byt in template_rows
        }

        # 计费（v1 包按空计费态；v2 包取链与活动行）：链整体替换，活动账用户
        # 以恢复后的会话归属为准（结构校验已保证与事件用户一致）。
        self._account_events = list(account_events)
        self._account_tail = (
            account_events[-1][10] if account_events else "0" * 64
        )
        self._account_active = {
            sid: [total, self._sessions[sid]["user"], last_account]
            for sid, total, last_account in active_rows
        }

        result = self._service_checkpoint_text(now_ms, config_summary)
        self._service_restore_cache[key] = (text, result)
        return result

    def _parse_accounting_section(self, raw, sessions, non_offline_sids):
        """解析并全量校验 service v2 的“计费”子对象，返回
        (事件十一元组列表, 活动行 (sid, 累计, 最近时刻) 列表, 引用集合,
        规范计费 dict)；引用集合为 (未知会话 sid 集合, 引用地址池集合)。

        结构、键序、类型、取值、排序、重复、链序号衔接、逐项哈希或 sid 生命
        周期非法均抛 ValueError；事件或活动行引用运行态会话行之外的 sid 由
        调用方按实例现状判 ResourceError。旧版本恢复后无开始事件的遗留在线
        会话可仅有中间事件（甚至无事件、只在活动行携累计），故中间允许为某
        sid 首条事件，活动行允许是运行态非下线会话集的子集；在链 sid 的活动
        行须与链重放值逐字段一致。
        """
        if not isinstance(raw, dict):
            raise ValueError("计费 must be an object")
        if list(raw) != ["版本", "事件", "活动", "尾哈希"]:
            raise ValueError(
                "计费 keys must be 版本/事件/活动/尾哈希 in order"
            )
        version = raw["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"计费.版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"计费.版本 must be 1, got {version}")
        tail_hash = self._cp_hex64(raw["尾哈希"], "计费.尾哈希")
        events_raw = raw["事件"]
        active_raw = raw["活动"]
        if not isinstance(events_raw, list):
            raise ValueError("计费.事件 must be a list")
        if not isinstance(active_raw, list):
            raise ValueError("计费.活动 must be a list")

        event_keys = [
            "序号", "类型", "时刻", "会话", "用户", "地址池", "地址",
            "累计字节", "原因", "前哈希", "哈希",
        ]
        # 沿链重放每 sid 生命周期：None=链中未见（遗留账），
        # [累计, 最近时刻]=在账，False=已停止。
        lifecycle = {}
        events = []
        referenced_pools = set()
        unknown_sids = set()
        prev_hash = "0" * 64
        for expect, item in enumerate(events_raw, start=1):
            if not isinstance(item, dict) or list(item) != event_keys:
                raise ValueError(
                    "计费.事件 item keys must be "
                    "序号/类型/时刻/会话/用户/地址池/地址/累计字节/原因/"
                    "前哈希/哈希 in order"
                )
            seq = self._cp_int(item["序号"], "计费.事件.序号", 1)
            kind = item["类型"]
            if not isinstance(kind, str) or kind not in _ACCOUNT_TYPES:
                raise ValueError(
                    f"计费.事件.类型 must be one of {_ACCOUNT_TYPES}, "
                    f"got {kind!r}"
                )
            ev_now = self._cp_int(item["时刻"], "计费.事件.时刻", 0)
            sid = self._cp_str(item["会话"], "计费.事件.会话")
            user = self._cp_str(item["用户"], "计费.事件.用户")
            pool_id = self._cp_plain_str(item["地址池"], "计费.事件.地址池")
            address = self._cp_plain_str(item["地址"], "计费.事件.地址")
            total = self._cp_int(item["累计字节"], "计费.事件.累计字节", 0)
            reason = item["原因"]
            if not isinstance(reason, str):
                raise ValueError("计费.事件.原因 must be a str")
            stored_prev = self._cp_hex64(item["前哈希"], "计费.事件.前哈希")
            digest = self._cp_hex64(item["哈希"], "计费.事件.哈希")

            if seq != expect:
                raise ValueError(
                    f"计费 event seq must be contiguous: want {expect}, got {seq}"
                )
            if stored_prev != prev_hash:
                raise ValueError("计费 event 前哈希 does not link to previous event")
            recomputed = self._account_hash(
                seq, kind, ev_now, sid, user, pool_id, address, total, reason,
                stored_prev,
            )
            if recomputed != digest:
                raise ValueError(f"计费 event {seq} hash mismatch")

            # 池址成对；非空池登记引用（存在性由调用方判），地址须规范 IPv4。
            if (pool_id == "") != (address == ""):
                raise ValueError(
                    "计费.事件 地址池 and 地址 must be both empty or both set"
                )
            if pool_id != "":
                _check_ip("计费.事件.地址", address)
                referenced_pools.add(pool_id)

            # 引用会话：sid 不在运行态会话行内记未知（调用方判 ResourceError）；
            # 在册则用户须与其会话归属一致。
            session_row = sessions.get(sid)
            if session_row is None:
                unknown_sids.add(sid)
            elif user != session_row["用户"]:
                raise ValueError(
                    f"计费 event user {user!r} does not match session owner "
                    f"{session_row['用户']!r} for {sid!r}"
                )

            state = lifecycle.get(sid)
            if kind == _ACCOUNT_START:
                if reason != "":
                    raise ValueError("开始 event 原因 must be empty")
                if total != 0:
                    raise ValueError("开始 event 累计字节 must be 0")
                if state is not None:
                    raise ValueError(
                        f"计费 开始 for {sid!r} must be its first event"
                    )
                lifecycle[sid] = [0, ev_now]
            elif kind == _ACCOUNT_INTERIM:
                if reason != "":
                    raise ValueError("中间 event 原因 must be empty")
                if state is False:
                    raise ValueError(f"计费 中间 for {sid!r} after 停止")
                if isinstance(state, list):
                    if total < state[0]:
                        raise ValueError(
                            f"计费 中间 累计字节 for {sid!r} decreased"
                        )
                    if ev_now < state[1]:
                        raise ValueError(
                            f"计费 中间 时刻 for {sid!r} before its last "
                            "accounting time"
                        )
                    state[0] = total
                    state[1] = ev_now
                else:
                    # 遗留账（旧版本恢复的会话无开始事件）：中间可为首条。
                    lifecycle[sid] = [total, ev_now]
            else:
                if reason not in _ACCOUNT_STOP_REASONS:
                    raise ValueError(
                        f"停止 event 原因 must be one of {_ACCOUNT_STOP_REASONS}, "
                        f"got {reason!r}"
                    )
                if state is False:
                    raise ValueError(f"重复停止 event for {sid!r}")
                if isinstance(state, list):
                    if total < state[0]:
                        raise ValueError(
                            f"计费 停止 累计字节 for {sid!r} below last interim total"
                        )
                # 链中未见（遗留账，旧版本恢复的会话无开始/中间事件）：停止
                # 可为首条事件，累计仅须非负。
                lifecycle[sid] = False
            events.append(
                (seq, kind, ev_now, sid, user, pool_id, address, total, reason,
                 stored_prev, digest)
            )
            prev_hash = digest

        if (events[-1][10] if events else "0" * 64) != tail_hash:
            raise ValueError("计费.尾哈希 does not match the last event hash")

        # 活动行：键序、类型、取值、按会话升序互异；在链 sid 与链重放态核对，
        # 不在运行态非下线会话集的 sid 记未知（调用方判 ResourceError）。
        active_rows = []
        active_sids = set()
        last_sid = None
        active_keys = ["会话", "累计字节", "最近计费时刻"]
        for item in active_raw:
            if not isinstance(item, dict) or list(item) != active_keys:
                raise ValueError(
                    "计费.活动 item keys must be 会话/累计字节/最近计费时刻 in order"
                )
            sid = self._cp_str(item["会话"], "计费.活动.会话")
            total = self._cp_int(item["累计字节"], "计费.活动.累计字节", 0)
            last_account = self._cp_int(
                item["最近计费时刻"], "计费.活动.最近计费时刻", 0
            )
            if sid in active_sids:
                raise ValueError(f"duplicate active account: {sid!r}")
            if last_sid is not None and sid <= last_sid:
                raise ValueError("计费.活动 rows must be sorted by 会话 ascending")
            last_sid = sid
            active_sids.add(sid)
            active_rows.append((sid, total, last_account))

        for sid, total, last_account in active_rows:
            if sid in non_offline_sids:
                state = lifecycle.get(sid)
                if state is False:
                    raise ValueError(f"计费.活动 lists stopped session: {sid!r}")
                if isinstance(state, list):
                    # 链仅在开始/中间/停止处留痕，meter 通过字节不产生事件，
                    # 故活动账允许较链末值增长（累计）或推进（最近时刻），但
                    # 不得回退。
                    if total < state[0] or last_account < state[1]:
                        raise ValueError(
                            f"计费.活动 totals for {sid!r} regress from the chain"
                        )
                # 链中未见的遗留账：累计/时刻仅须非负（cp_int 已保证）。
            elif sid in sessions:
                # 运行态中为下线墓碑却在活动账：结构矛盾。
                raise ValueError(
                    f"计费.活动 lists offline session: {sid!r}"
                )
            else:
                # 完全未知会话引用，交由调用方判 ResourceError。
                unknown_sids.add(sid)

        # 链生命周期与运行态会话状态须一致：在账（开始/中间后无停止）会话在
        # 运行态中必为非下线；已停止会话在运行态中必为下线墓碑。
        for sid, state in lifecycle.items():
            if sid in unknown_sids:
                continue
            if isinstance(state, list) and sid not in non_offline_sids:
                raise ValueError(
                    f"计费 chain leaves {sid!r} active but runtime session is "
                    "offline"
                )
            if state is False and sid in non_offline_sids:
                raise ValueError(
                    f"计费 chain stops {sid!r} but runtime session is not offline"
                )

        canon_accounting = {
            "版本": 1,
            "事件": [self._account_event_dict(event) for event in events],
            "活动": [
                {"会话": sid, "累计字节": total, "最近计费时刻": last_account}
                for sid, total, last_account in active_rows
            ],
            "尾哈希": events[-1][10] if events else "0" * 64,
        }
        return events, active_rows, (unknown_sids, referenced_pools), canon_accounting

    def _parse_service_checkpoint(self, text):
        """解析并全量校验跨域一致性检查点文本，返回含各域规范化行的 dict；
        任何文本非法均抛 ValueError。

        接受版本 1（无“计费”域，计费态按空处理）与版本 2（统计后、摘要前
        含“计费”域）。顶层键序分别为
        “版本/时刻/配置摘要/认证/运行态/故障/统计/摘要”与
        “版本/时刻/配置摘要/认证/运行态/故障/统计/计费/摘要”；版本为 1/2，
        时刻为非 bool 非负 int，配置摘要与末摘要为 64 位小写十六进制串。
        四个子对象分别重编码后沿用
        _parse_auth_checkpoint/_parse_runtime_checkpoint/
        _parse_fault_checkpoint/_parse_stats_checkpoint 全量校验（嵌套重键、
        键序、结构、类型、取值、排序、链、状态哈希与各层摘要），且认证、容量
        （运行态）与故障的时刻须统一等于顶层时刻；嵌入认证对象须为版本 2 规范
        形态（版本 1 不予接受）。各子对象原文重编码须与其规范形态逐字节一致，
        末摘要须为用同版本规范子对象重建的紧凑 JSON（无 LF）UTF-8 字节的
        sha256 小写值（与原文排版无关）。仅做结构自洽与同刻校验；配置摘要、
        用户集合与各域引用由调用方按实例现状判定（StateError/ResourceError）。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"service checkpoint is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("service checkpoint top level must be an object")
        v1_keys = [
            "版本", "时刻", "配置摘要", "认证", "运行态", "故障", "统计", "摘要"
        ]
        v2_keys = [
            "版本", "时刻", "配置摘要", "认证", "运行态", "故障", "统计",
            "计费", "摘要",
        ]
        top_keys = list(doc)
        if top_keys == v1_keys:
            version = 1
        elif top_keys == v2_keys:
            version = 2
        else:
            raise ValueError(
                "service checkpoint top-level keys must be "
                "版本/时刻/配置摘要/认证/运行态/故障/统计/[计费/]摘要 in order"
            )
        version_value = doc["版本"]
        if isinstance(version_value, bool) or not isinstance(version_value, int):
            raise ValueError(
                f"版本 must be an int, got {type(version_value).__name__}"
            )
        if version_value != version:
            raise ValueError(
                f"版本 {version_value} does not match its top-level shape"
            )
        now_ms = self._cp_int(doc["时刻"], "时刻", 0)
        config_summary = self._cp_hex64(doc["配置摘要"], "配置摘要")
        top_summary = self._cp_hex64(doc["摘要"], "摘要")
        for name in ("认证", "运行态", "故障", "统计"):
            if not isinstance(doc[name], dict):
                raise ValueError(f"{name} must be an object")
        if version == 2 and not isinstance(doc["计费"], dict):
            raise ValueError("计费 must be an object")

        def recode(sub):
            return json.dumps(sub, ensure_ascii=False, separators=(",", ":"))

        raw_auth, raw_runtime, raw_fault, raw_stats = (
            doc["认证"], doc["运行态"], doc["故障"], doc["统计"]
        )

        # 认证：解析返回 (时刻, 六字段行)；嵌入对象须为版本 2 规范形态。
        auth_now, auth_rows = self._parse_auth_checkpoint(recode(raw_auth))
        if auth_now != now_ms:
            raise ValueError(
                f"认证.时刻 must equal top-level 时刻 {now_ms}, got {auth_now}"
            )
        canon_auth_users = [
            {
                "用户": user,
                "凭据": digest.hex(),
                "失败": failed,
                "锁定至": until,
                "下次可试": retry_at,
                "停用": disabled,
            }
            for user, digest, failed, until, retry_at, disabled in auth_rows
        ]
        canon_auth_head = {
            "版本": 2, "时刻": now_ms, "用户": canon_auth_users
        }
        auth_blob = json.dumps(
            canon_auth_head, ensure_ascii=False, separators=(",", ":")
        )
        auth_summary = hashlib.sha256(auth_blob.encode("utf-8")).hexdigest()
        canon_auth = dict(canon_auth_head)
        canon_auth["摘要"] = auth_summary
        if recode(raw_auth) != recode(canon_auth):
            raise ValueError(
                "认证 must be a canonical version 2 auth checkpoint object"
            )

        # 运行态：解析返回 (时刻, 事件七元组, 会话行, 排队行, 配额行, 摘要)。
        (
            runtime_now, events, sessions, queued, quota_rows, rt_summary
        ) = self._parse_runtime_checkpoint(recode(raw_runtime))
        if runtime_now != now_ms:
            raise ValueError(
                f"运行态.时刻 must equal top-level 时刻 {now_ms}, got {runtime_now}"
            )
        event_rows = [
            {
                "序号": seq,
                "时刻": ev_now,
                "会话": sid,
                "结果": verdict,
                "入队序": order,
                "前哈希": prev_hash,
                "哈希": ev_hash,
            }
            for seq, ev_now, sid, verdict, order, prev_hash, ev_hash in events
        ]
        state_hash = self._checkpoint_state_hash(
            now_ms, event_rows, sessions, queued
        )
        canon_runtime = {
            "版本": 1,
            "时刻": now_ms,
            "容量": {
                "时刻": now_ms,
                "事件": event_rows,
                "会话": sessions,
                "排队": queued,
                "状态哈希": state_hash,
            },
            "配额": {"版本": 1, "账本": [list(row) for row in quota_rows]},
        }
        canon_runtime["摘要"] = hashlib.sha256(
            recode(canon_runtime).encode("utf-8")
        ).hexdigest()
        if canon_runtime["摘要"] != rt_summary:
            # 解析器已校验，不可达；保守防御。
            raise ValueError("运行态 摘要 does not match canonical object")
        if recode(raw_runtime) != recode(canon_runtime):
            raise ValueError("运行态 must be a canonical runtime checkpoint object")

        # 故障：解析返回 (时刻, 截至, 退避行, (故障,退避), 池行, 等待, 触发)。
        (
            fault_now, until, backoff_rows, fail_pair, pool_rows,
            waiting, trigger,
        ) = self._parse_fault_checkpoint(recode(raw_fault))
        if fault_now != now_ms:
            raise ValueError(
                f"故障.时刻 must equal top-level 时刻 {now_ms}, got {fault_now}"
            )
        canon_fault_head = {
            "版本": 1,
            "时刻": now_ms,
            "后端": {
                "截至": until,
                "退避": [
                    {"用户": user, "次数": n, "下次": retry_at}
                    for user, n, retry_at in backoff_rows
                ],
                "失败": {"故障": fail_pair[0], "退避": fail_pair[1]},
            },
            "池": [
                {"标识": pool_id, "截至": pool_until}
                for pool_id, pool_until in pool_rows
            ],
            "超时": {"等待": waiting, "触发": trigger},
        }
        fault_summary = hashlib.sha256(
            recode(canon_fault_head).encode("utf-8")
        ).hexdigest()
        canon_fault = dict(canon_fault_head)
        canon_fault["摘要"] = fault_summary
        if recode(raw_fault) != recode(canon_fault):
            raise ValueError("故障 must be a canonical fault checkpoint object")

        # 统计：解析返回 (总数, 成功, 用户失败行, 用户计量行, 模板计量行, 摘要)。
        (
            total, success, fail_rows, user_rows, template_rows, stats_summary
        ) = self._parse_stats_checkpoint(recode(raw_stats))
        canon_stats_head = {
            "版本": 1,
            "建立": {"总数": total, "成功": success},
            "用户失败": [
                {"用户": user, "认证": a, "资源": r, "状态": st, "后端": b}
                for user, a, r, st, b in fail_rows
            ],
            "用户计量": [
                {"标识": ident, "通过": p, "拒绝": d, "下线": o, "通过字节": byt}
                for ident, p, d, o, byt in user_rows
            ],
            "模板计量": [
                {"标识": ident, "通过": p, "拒绝": d, "下线": o, "通过字节": byt}
                for ident, p, d, o, byt in template_rows
            ],
        }
        recomputed_stats_summary = hashlib.sha256(
            recode(canon_stats_head).encode("utf-8")
        ).hexdigest()
        if recomputed_stats_summary != stats_summary:
            raise ValueError("统计 摘要 does not match canonical object")
        canon_stats = dict(canon_stats_head)
        canon_stats["摘要"] = stats_summary
        if recode(raw_stats) != recode(canon_stats):
            raise ValueError("统计 must be a canonical stats checkpoint object")

        # 计费：版本 2 必有“计费”域，版本 1 缺失按空计费态处理。
        sessions_by_sid = {row["会话"]: row for row in sessions}
        non_offline_sids = {
            row["会话"]
            for row in sessions
            if row["状态"] != _STATE_OFFLINE
        }
        if version == 2:
            (
                account_events,
                active_rows,
                account_refs,
                canon_accounting,
            ) = self._parse_accounting_section(
                doc["计费"], sessions_by_sid, non_offline_sids
            )
            if recode(doc["计费"]) != recode(canon_accounting):
                raise ValueError(
                    "计费 must be a canonical accounting checkpoint object"
                )
        else:
            account_events = []
            active_rows = []
            account_refs = (set(), set())

        # 末摘要：用同版本规范子对象重建顶层。
        canonical_top = {
            "版本": version,
            "时刻": now_ms,
            "配置摘要": config_summary,
            "认证": canon_auth,
            "运行态": canon_runtime,
            "故障": canon_fault,
            "统计": canon_stats,
        }
        if version == 2:
            canonical_top["计费"] = canon_accounting
        if hashlib.sha256(
            recode(canonical_top).encode("utf-8")
        ).hexdigest() != top_summary:
            raise ValueError("摘要 does not match the canonical service checkpoint")

        return {
            "version": version,
            "now": now_ms,
            "config_summary": config_summary,
            "auth": (auth_summary, auth_rows),
            "runtime": (rt_summary, events, sessions, queued, quota_rows),
            "fault": (
                fault_summary, until, backoff_rows, fail_pair, pool_rows,
                waiting, trigger,
            ),
            "stats": (
                stats_summary, total, success, fail_rows, user_rows,
                template_rows,
            ),
            "accounting": (account_events, active_rows, account_refs),
        }

    @staticmethod
    def _render_capacity(sid, result, now_ms, deadline):
        # 键序：会话、结果、时刻、截止；会话/结果为 str，时刻/截止为 int。
        payload = {
            "会话": sid,
            "结果": result,
            "时刻": now_ms,
            "截止": deadline,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _render_capacity_advance(now_ms, online, queued, changed):
        # 键序：时刻、在线、排队、变更；变更为入队序（int）列表。
        payload = {
            "时刻": now_ms,
            "在线": online,
            "排队": queued,
            "变更": changed,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _current_spec(self):
        """当前配置的规范化 spec：池按标识、保留按 IPv4 整数、静态按用户升序，
        模板按标识、用户模板按用户升序，容量为 (队列上限, 最大等待毫秒,
        队满策略)，认证为认证器当前 (最大失败, 锁定毫秒)，末项为模板地址池
        （按模板标识升序的 (模板标识, (池标识...)) 元组）。"""
        pool_specs = []
        for pool_id in sorted(self._pools):
            pool = self._pools[pool_id]
            reserved = tuple(
                str(ipaddress.IPv4Address(ip_int)) for ip_int in sorted(pool.reserved)
            )
            static = tuple(
                (user, str(ipaddress.IPv4Address(pool.static[user])))
                for user in sorted(pool.static)
            )
            pool_specs.append((pool_id, pool.cidr, reserved, static))
        templates = tuple(
            (template_id,) + self._templates[template_id]
            for template_id in sorted(self._templates)
        )
        user_templates = tuple(
            (user, self._user_templates[user])
            for user in sorted(self._user_templates)
        )
        template_pool_order = tuple(
            (template_id, self._template_pool_order[template_id])
            for template_id in sorted(self._template_pool_order)
        )
        return (
            self._total,
            self._per,
            self._idle_ms,
            self._lease_ms,
            tuple(pool_specs),
            templates,
            user_templates,
            (self._queue_limit, self._max_wait_ms, self._queue_policy),
            self._auth.policy(),
            template_pool_order,
        )

    def export_config(self):
        """导出当前配置为 v11 JSON（LF 结尾），O(n log n + S + Q)/O(n)。

        顶层键序为“版本/会话/地址池/模板/用户模板/容量/认证/模板地址池”；
        会话键序为
        “总数/每用户/空闲毫秒/租期毫秒”；地址池为按标识升序的列表，项键序为
        “标识/CIDR/保留/静态”，保留为按 IPv4 整数升序的串列表，静态为按用户
        再 IP 升序的二元串列表；模板为按标识升序的列表，项键序为“标识/限速/
        突发/配额/周期毫秒/会话上限/排队优先级/超限”，周期毫秒 0 表示不重置，
        会话上限 0 表示不限并发占用，排队优先级 0..100 为推进老化提升的基础
        值；用户模板为按用户升序的 [user, 标识] 二元串列表；容量键序为
        “队列上限/最大等待毫秒/队满策略”，队列上限 0 表示不限队长、最大
        等待毫秒 0 表示不限等待，队满策略为“拒绝/替换”；认证键序为
        “最大失败/锁定毫秒/重试基数毫秒/重试上限毫秒”，取认证器当前四值；
        末位“模板地址池”为按模板标识升序的 [模板标识, [池标识...]] 二元数组
        列表，每项池序列为 1..32 个互异且已定义的池标识。
        """
        return _compact_config(self._current_spec()) + "\n"

    def upgrade_config(self, text, target=11):
        """只读地将 v1..v11 配置文本升级到 target（仅支持 11），返回升级包 JSON。

        text 须为 str、target 须为非 bool int，否则抛 TypeError；源版本限
        1..11 且 target 只许 11；JSON 解析、重复键、键缺失或未知、结构、类型、
        数量、排序、值、引用或版本非法均抛 ValueError。迁移沿既有规则：v1 单池
        改 default，v1/v2 补空模板与用户模板，v1-v3 补容量 (1024, 0, 拒绝)，
        v1-v4 以认证器当前四值补认证，v1-v5 模板会话上限补 0，v1-v6 模板周期
        毫秒补 0，v1-v7 模板排队优先级补 0，v1-v8 容量队满策略补“拒绝”，
        v1-v9 重试两项补 0，v1-v10 模板地址池补空，v11 只规范化。返回基线
        格式的 LF 尾紧凑 JSON：
        顶层序/型为“源版本:int、目标版本:int、改变:bool、摘要:str、配置:
        object”，改变 = 源版本 != 11；配置逐层键序、类型与排序同
        export_config() 的 v11；摘要为配置对象同法编码、去 LF 后的 UTF-8 字节
        sha256 小写值。升级只读，不触碰任何实例状态；时/空上界 O(n log n)/
        O(n)。
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        if isinstance(target, bool) or not isinstance(target, int):
            raise TypeError(
                f"target must be an int, got {type(target).__name__}"
            )
        if target != _CONFIG_VERSION:
            raise ValueError(f"target must be {_CONFIG_VERSION}, got {target}")
        doc = _load_config_doc(text)
        spec = _parse_config_doc(doc, self._auth.policy())
        source = doc["版本"]
        config_text = _compact_config(spec)
        summary = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
        changed = source != _CONFIG_VERSION
        return (
            _compact_envelope(
                source, target, changed, summary, _config_payload(spec)
            )
            + "\n"
        )

    def _build_pools(self, spec, check_queue=True):
        """校验 spec 对现有会话与等待队列的承载力并构建新池表；失败抛 ResourceError。

        任一上限低于对应非下线会话数，模板并发会话上限（0 表示不限）低于其
        当前占用（新绑定下该模板用户的在线加挂起会话数），或新池无法按原池、
        地址、用户承载在租租约（池缺失、地址不可用/被保留、静态址易主），或
        当前队长大于目标队列上限（0 表示不限），均抛 ResourceError；本方法
        不改任何状态，旧队项的等待、截止与入队序均不触碰。

        check_queue=False 时跳过队长承载判定：供 capacity_rebalance——其超时
        与淘汰本就把队列收敛到目标队限，更小的目标队限不构成承载失败。
        """
        (
            total,
            per,
            _idle_ms,
            _lease_ms,
            pool_specs,
            templates,
            user_templates,
            (queue_limit, _max_wait_ms, _queue_policy),
            _auth_policy,
            _template_pool_order,
        ) = spec
        total_count = 0
        per_user = {}
        for session in self._sessions.values():
            if session["state"] != _STATE_OFFLINE:
                total_count += 1
                user = session["user"]
                per_user[user] = per_user.get(user, 0) + 1
        if total_count > total:
            raise ResourceError(
                f"total session limit {total} below {total_count} active sessions"
            )
        for user, count in per_user.items():
            if count > per:
                raise ResourceError(
                    f"per-user session limit {per} below {count} active "
                    f"sessions for {user!r}"
                )
        # 模板占用承载：新绑定下任一模板占用 > 目标会话上限（0 表示不限）即
        # 不可承载。
        new_bindings = dict(user_templates)
        template_limits = {
            template_id: session_limit
            for template_id, _rate, _burst, _quota, _period_ms, session_limit,
            _priority, _exceed in templates
            if session_limit
        }
        if template_limits:
            per_template = {}
            for session in self._sessions.values():
                if session["state"] == _STATE_OFFLINE:
                    continue
                template_id = new_bindings.get(session["user"])
                if template_id is not None:
                    per_template[template_id] = per_template.get(template_id, 0) + 1
            for template_id, session_limit in template_limits.items():
                occupancy = per_template.get(template_id, 0)
                if occupancy > session_limit:
                    raise ResourceError(
                        f"template session limit {session_limit} below "
                        f"{occupancy} active sessions for template {template_id!r}"
                    )
        # 队长承载：当前队长 > 目标上限即不可承载（上限 0 表示不限）。
        # capacity_rebalance 经自身超时与淘汰收敛队长，跳过本判定。
        if (
            check_queue
            and queue_limit != 0
            and len(self._capacity_queue) > queue_limit
        ):
            raise ResourceError(
                f"capacity queue limit {queue_limit} below current queue length "
                f"{len(self._capacity_queue)}"
            )

        parsed = {}
        for pool_id, cidr, reserved, static in pool_specs:
            parsed[pool_id] = _check_pool((cidr, reserved, static))
        static_owners = {
            pool_id: {ip_int: user for user, ip_int in data[3].items()}
            for pool_id, data in parsed.items()
        }
        for sid, session in self._sessions.items():
            ip_int = session["ip"]
            if ip_int is None:
                continue
            pool_id = session["pool"]
            data = parsed.get(pool_id)
            address = str(ipaddress.IPv4Address(ip_int))
            if data is None:
                raise ResourceError(
                    f"new config cannot carry lease of sid {sid!r}: "
                    f"no pool {pool_id!r}"
                )
            _network, usable, reserved_ips, _static_map, static_ips = data
            if ip_int not in usable or ip_int in reserved_ips:
                raise ResourceError(
                    f"new config cannot carry lease of sid {sid!r}: "
                    f"address {address} not usable in pool {pool_id!r}"
                )
            if (
                ip_int in static_ips
                and static_owners[pool_id][ip_int] != session["user"]
            ):
                raise ResourceError(
                    f"new config cannot carry lease of sid {sid!r}: "
                    f"address {address} is static for another user "
                    f"in pool {pool_id!r}"
                )

        # 全部校验通过：构建新池表并回挂在租租约，空闲堆剔除租用动态址。
        leased = {}
        for sid, session in self._sessions.items():
            if session["ip"] is not None:
                leased.setdefault(session["pool"], {})[session["ip"]] = sid
        new_pools = {}
        for pool_id, data in parsed.items():
            pool = _Pool(data)
            pool_leases = leased.get(pool_id)
            if pool_leases:
                pool.leases.update(pool_leases)
                pool.free = [x for x in pool.free if x not in pool_leases]
                heapq.heapify(pool.free)
            new_pools[pool_id] = pool
        return new_pools

    def _install_spec(self, spec, new_pools):
        """原子替换配置数值、池表、QoS 模板、容量背压与认证策略；会话状态、
        期限、地址、租期及旧队项的等待、截止、入队序均不变，认证器的用户
        凭据、失败计数与锁定记录全部保留。计量账本同标识原样保留 u/t/c，
        周期重置自新模板的周期毫秒 P 即时按窗判定（不截顶 c、不重算累计）。"""
        (
            total,
            per,
            idle_ms,
            lease_ms,
            _pool_specs,
            templates,
            user_templates,
            (queue_limit, max_wait_ms, queue_policy),
            (max_fail, lock_ms, retry_base_ms, retry_cap_ms),
            template_pool_order,
        ) = spec
        self._total = total
        self._per = per
        self._idle_ms = idle_ms
        self._lease_ms = lease_ms
        self._pools = new_pools
        self._templates = {
            template_id: (
                rate, burst, quota, period_ms, session_limit, priority, exceed
            )
            for template_id, rate, burst, quota, period_ms, session_limit,
            priority, exceed
            in templates
        }
        self._user_templates = dict(user_templates)
        # 模板地址池序列仅作用于后续自动选池与尚未晋升的队项；既有在线或
        # 挂起会话保留原池、地址与租期，不随配置重绑或迁移。
        self._template_pool_order = dict(template_pool_order)
        self._queue_limit = queue_limit
        self._max_wait_ms = max_wait_ms
        self._queue_policy = queue_policy
        # 认证策略随配置提交；认证记录（凭据、失败计数、锁定、下次可试时刻）
        # 保留，策略切换不重算这三类限制。
        self._auth.set_policy(max_fail, lock_ms, retry_base_ms, retry_cap_ms)
        # 计量账本：同标识原样保留 u/t/c；周期窗由 _meter/quota_stats 按新
        # 模板周期毫秒 P 即时判定（P>0 且 now_ms//P != t//P 即视为新窗）。
        # 已删模板的历史账本原样保留（改绑后按新 (用户, 模板) 独立建账），
        # 加载/回滚失败不经过本方法。
        # 配置加载/回滚成功后保留同名池的耗尽演练、清除已删池（截至不改）；
        # 加载失败不经过本方法，故障态不变。
        self._pool_fault = {
            pool_id: until
            for pool_id, until in self._pool_fault.items()
            if pool_id in new_pools
        }

    def _commit_config(self, spec, new_pools, rollback_spec, op, target=-1):
        """校验通过后原子提交配置：覆盖回滚点、安装 spec、修订号加 1，并把
        新修订的 spec 写入历史后按 _CONFIG_HISTORY_LIMIT 淘汰最旧项。

        仅在 _build_pools 成功后调用；调用方负责先解析/承载校验，任何失败
        都不进入本方法，故本方法不改变“失败不改状态”的既有语义。修订号
        单调递增，新写入项恒为最大键、永不被淘汰；窗口溢出时仅淘汰最小
        修订号（构造态修订 0 亦可在窗口满后被淘汰）。

        同步追加一条防篡改配置历史记录（操作 op 为“加载/回滚/CAS/回退”，
        回退提交携带 target、余为 -1），追加与淘汰均与修订快照同步：快照
        淘汰最旧项时同步删除链首记录，但不缝合链——留存记录的前哈希一律
        不改；当前项随快照永不淘汰。
        """
        self._rollback = rollback_spec
        self._install_spec(spec, new_pools)
        self._revision += 1
        revision = self._revision
        history = self._config_history
        history[revision] = self._current_spec()
        # 记录追加在淘汰之前：父修订取前一修订（revision-1），前哈希取链尾
        # 记录的哈希；摘要取提交后当前配置，同 config_revision 口径。
        log = self._config_history_log
        prev_hash = log[-1][6]
        log.append(
            self._config_history_record(
                revision,
                revision - 1,
                op,
                target,
                self._config_summary(),
                prev_hash,
            )
        )
        if len(history) > _CONFIG_HISTORY_LIMIT:
            oldest = min(history)
            del history[oldest]
            # 快照与记录一一对应且同序追加，最旧快照即链首记录；仅同步删除，
            # 不重写后续记录的前哈希（链不缝合），链尾（当前项）不受影响。
            del log[0]

    @staticmethod
    def _config_history_hash(revision, parent, op, target, summary, prev_hash):
        """由前六键（修订/父修订/操作/目标/摘要/前哈希，键序固定）的基线
        紧凑 JSON（无 LF）之 UTF-8 字节算 sha256 小写十六进制串。"""
        head = {
            "修订": revision,
            "父修订": parent,
            "操作": op,
            "目标": target,
            "摘要": summary,
            "前哈希": prev_hash,
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _config_history_record(
        self, revision, parent, op, target, summary, prev_hash
    ):
        """组装一条防篡改配置历史七元组
        （修订, 父修订, 操作, 目标, 摘要, 前哈希, 哈希）。"""
        digest = self._config_history_hash(
            revision, parent, op, target, summary, prev_hash
        )
        return (revision, parent, op, target, summary, prev_hash, digest)

    def _parse_config_text(self, text):
        """按 load_config 规则解析配置文本或升级包并完成承载校验，返回
        (规范化 spec, 新池表)；任一错误抛出且不改状态，不提交。

        供 load_config 与 config_cas 共用：两者解析/承载规则一致，仅提交
        时追加的防篡改配置历史操作不同（“加载”与“CAS”）。
        """
        doc = _load_config_doc(text)
        if isinstance(doc, dict) and "源版本" in doc:
            _source, _target, _changed, _summary, spec = (
                _parse_upgrade_envelope(doc)
            )
        else:
            spec = _parse_config_doc(doc, self._auth.policy())
        for user, _template_id in spec[6]:
            if user not in self._auth:
                raise ValueError(
                    f"user template user not in authenticator: {user!r}"
                )
        return spec, self._build_pools(spec)

    def load_config(self, text):
        """校验并原子加载配置文本，保存旧配置为唯一回滚点，返回新配置 v11 JSON。

        直载 v1..v11 配置，或加载 upgrade_config 产出的升级包；升级包须复核
        键序、字段、配置规范形态与摘要，任一不符抛 ValueError。text 非 str
        抛 TypeError；JSON 解析、重复/未知/缺失键、结构、类型、值、重复项或
        引用（用户模板引用未注册用户或未知模板标识）错抛 ValueError；上限、
        模板占用、租约或队长承载不满足抛 ResourceError。v1-v4 迁移时认证节
        补认证器当前两值，v1-v5 迁移时模板会话上限补 0，v1-v6 迁移时模板
        周期毫秒补 0，v1-v8 迁移时容量队满策略补“拒绝”。全部校验通过后原子提交：失败不改配置、历史、回滚点、
        会话、租约与运行态；成功不老化，会话与租约不变，计量账本同标识原样
        保留 u/t/c 并自新模板周期毫秒 P 即时判窗，认证策略随配置替换但认证
        记录（凭据、失败计数、锁定）保留，新值仅作用于后续操作与查询。成功
        加载覆盖唯一回滚点并将配置修订号加 1，新修订（连同构造态修订 0）
        保留在最近 256 项修订历史中，超限淘汰最旧项且不淘汰当前项；失败修订
        号与历史不变。

        首次成功另向防篡改配置历史追加“加载”记录（父修订取前一修订、
        目标 -1、摘要同 config_revision、哈希为前六键基线紧凑 JSON 的
        UTF-8 字节 sha256 小写值）；失败与同参重放（经 config_change/
        config_cas 缓存）不追加。
        """
        spec, new_pools = self._parse_config_text(text)
        self._commit_config(
            spec, new_pools, self._current_spec(), _CONFIG_HISTORY_OP_LOAD
        )
        return self.export_config()

    def rollback_config(self):
        """经同样校验恢复唯一回滚点配置并清除回滚点，返回恢复后的 v11 JSON。

        无回滚点抛 StateError；校验失败（ResourceError）不改配置、回滚点、
        历史或运行态，回滚点保留；成功清除回滚点并将配置修订号加 1，生成
        并保留新修订历史项（最近 256 项，超限淘汰最旧项且不淘汰当前项），
        认证策略一并恢复（认证记录保留），不老化。

        首次成功另向防篡改配置历史追加“回滚”记录（父修订取前一修订、
        目标 -1）；失败与同参重放（经 config_change 缓存）不追加。
        """
        spec = self._rollback
        if spec is None:
            raise StateError("no config rollback point")
        new_pools = self._build_pools(spec)
        self._commit_config(
            spec, new_pools, None, _CONFIG_HISTORY_OP_ROLLBACK
        )
        return self.export_config()

    def _config_summary(self):
        """当前配置摘要：export_config 去尾 LF 的 UTF-8 字节 sha256 小写值。"""
        return hashlib.sha256(
            self.export_config()[:-1].encode("utf-8")
        ).hexdigest()

    def config_revision(self):
        """只读返回当前配置修订号与摘要的 LF 尾紧凑 JSON。

        键序/型为“修订:int、摘要:str”；修订号初值 0，load_config/
        rollback_config/config_cas/config_revert 首次成功加 1，失败、导出、
        升级与同参重放不变；每次成功提交的配置按修订号保留在最近 256 项
        历史中（构造态为修订 0），供 config_revert 回退，超限淘汰最旧项且
        不淘汰当前项；摘要为
        export_config 去尾 LF 的 UTF-8 字节 sha256 小写值。不审计、不改
        任何状态；O(n log n) 时间、O(n) 空间（导出需排序）。
        """
        payload = {"修订": self._revision, "摘要": self._config_summary()}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def config_history_diff(self, left, right):
        """只读比较两个仍保留的配置快照，返回 LF 尾紧凑 JSON；不老化、不缓存、
        不审计、不改任何状态，同态同参逐字节相同。

        left/right 须为非 bool 非负 int：类型错抛 TypeError，负值抛
        ValueError；校验后依 left、right 次序在保留窗口（最近 256 项）查找，
        未保留（已淘汰或超过当前修订）抛 KeyError(修订)。比较两份规范 v11
        配置：对象取键并集逐键递归，数组按索引逐项递归；一侧缺失或两侧节点
        JSON 类型不同（bool 与数值不同型）即在当前路径记一项且不再下探，
        同型容器继续递归，同型叶值仅在不同时记一项。路径为 JSON Pointer：
        “~”转“~0”、“/”转“~1”（先转 ~），根为空串，数组索引为十进制串；
        项目按路径 Unicode 码点升序。每项键序/型为“路径:str、左值:str、
        右值:str”：存在值用基线紧凑 JSON 编码（ensure_ascii=False、
        无空白），缺失为空串。

        顶层键序/型为“左修订:int、右修订:int、改变:bool、变更:list、
        摘要:str”；改变等于变更列表非空；摘要为前四键同法编码之 UTF-8 字节
        的 sha256 小写值。时间 O(C+D log D)、辅助空间 O(D)（外加两份规范
        配置 O(C)），C 为单份配置规模、D 为变更项数；各项取值子树互不相
        交，取值编码总成本 O(C)。
        """
        if isinstance(left, bool) or not isinstance(left, int):
            raise TypeError(f"left must be an int, got {type(left).__name__}")
        if isinstance(right, bool) or not isinstance(right, int):
            raise TypeError(f"right must be an int, got {type(right).__name__}")
        if left < 0:
            raise ValueError(f"left must be >= 0, got {left}")
        if right < 0:
            raise ValueError(f"right must be >= 0, got {right}")

        history = self._config_history
        if left not in history:
            raise KeyError(left)
        if right not in history:
            raise KeyError(right)

        left_doc = _config_payload(history[left])
        right_doc = _config_payload(history[right])
        missing = object()
        entries = []

        def encode(value):
            return json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            )

        def json_type(value):
            # 规范 v9 仅含 JSON 类型；bool 须与数值区分（True 亦是 int）。
            if value is None:
                return "null"
            if isinstance(value, bool):
                return "bool"
            if isinstance(value, (int, float)):
                return "number"
            if isinstance(value, str):
                return "string"
            if isinstance(value, list):
                return "array"
            return "object"

        def emit(path, lvalue, rvalue):
            entries.append(
                (
                    path,
                    "" if lvalue is missing else encode(lvalue),
                    "" if rvalue is missing else encode(rvalue),
                )
            )

        def pointer_token(token):
            return str(token).replace("~", "~0").replace("/", "~1")

        def walk(path, lvalue, rvalue):
            if lvalue is missing or rvalue is missing:
                emit(path, lvalue, rvalue)
                return
            ltype = json_type(lvalue)
            rtype = json_type(rvalue)
            if ltype != rtype:
                # 节点类型不同：当前路径记一项，不再下探。
                emit(path, lvalue, rvalue)
                return
            if ltype == "object":
                # 对象取键并集（键序无关，最终按路径排序）。
                for key in set(lvalue) | set(rvalue):
                    child = path + "/" + pointer_token(key)
                    walk(
                        child,
                        lvalue.get(key, missing),
                        rvalue.get(key, missing),
                    )
            elif ltype == "array":
                # 数组按索引递归，越界侧为缺失。
                for index in range(max(len(lvalue), len(rvalue))):
                    child = path + "/" + str(index)
                    walk(
                        child,
                        lvalue[index] if index < len(lvalue) else missing,
                        rvalue[index] if index < len(rvalue) else missing,
                    )
            else:
                # 同型叶值：以基线紧凑编码逐字节判异（数值 1 与 1.0 亦异）。
                if encode(lvalue) != encode(rvalue):
                    emit(path, lvalue, rvalue)

        walk("", left_doc, right_doc)
        entries.sort(key=lambda item: item[0])
        changes = [
            {"路径": path, "左值": ltext, "右值": rtext}
            for path, ltext, rtext in entries
        ]
        head = {
            "左修订": left,
            "右修订": right,
            "改变": bool(changes),
            "变更": changes,
        }
        summary = hashlib.sha256(
            encode(head).encode("utf-8")
        ).hexdigest()
        payload = dict(head)
        payload["摘要"] = summary
        return encode(payload) + "\n"

    def config_preflight(self, text):
        """只读预检配置文本若按 load_config 加载将产生的差异，返回 LF 尾紧凑
        JSON；不老化、不缓存、不审计，不改配置、修订、历史、回滚点及任何运行
        态，同态同参逐字节相同。

        text 非 str 抛 TypeError；接受与 load_config 相同的 v1..v11 配置或经
        严格复核的升级包，解析、重键、键集/键序、结构、类型、值、排序或引用
        错抛 ValueError，当前会话上限、模板占用、队长或在租租约不能承载抛
        ResourceError；校验次序与 load_config 完全一致（共用 _parse_config_text：
        先解析/迁移并复核升级包，再校验用户模板引用，最后做承载校验），承载
        校验只构造临时池表、不触碰实例状态。

        预检文本先规范化为 v11 spec，再与当前配置（_current_spec() 的规范 v11
        形态）递归比较：对象取键并集逐键递归，数组按索引逐项递归；一侧缺失或
        两侧节点 JSON 类型不同（bool 与数值不同型）即在当前路径记一项且不再
        下探，同型容器继续递归，同型叶值仅在不同时记一项。路径为 JSON Pointer
        （“~”转“~0”、“/”转“~1”，先转 ~，根为空串，数组索引为十进制串），
        项目按路径 Unicode 码点升序；两侧值编码同 config_history_diff：存在值
        用基线紧凑 JSON 编码（ensure_ascii=False、separators=(',',':')），缺失
        为空串；变更项键序/型为“路径:str、当前:str、目标:str”。

        顶层键序/型为“修订:int、当前摘要:str、目标摘要:str、改变:bool、
        变更:list、摘要:str”；修订与当前摘要沿 config_revision（修订号、当前
        export 去 LF 的 sha256），目标摘要为规范 v11 对象紧凑编码 UTF-8 字节的
        sha256 小写值，摘要覆盖前五键（前五键同法编码之 UTF-8 字节 sha256），
        改变恰为变更列表非空。时间 O(n log n + S + Q + D log D)、辅助空间
        O(n + D)（外加两份规范配置），n 为配置规模、S/Q 为会话与等待队列规模、
        D 为变更项数。
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        # 与 load_config 同一解析/引用/承载校验链；该方法只读，返回的池表为
        # 临时对象，预检结束即弃，不安装、不提交。
        spec, _new_pools = self._parse_config_text(text)

        current_doc = _config_payload(self._current_spec())
        target_doc = _config_payload(spec)
        missing = object()
        entries = []

        def encode(value):
            return json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            )

        def json_type(value):
            # 规范 v9 仅含 JSON 类型；bool 须与数值区分（True 亦是 int）。
            if value is None:
                return "null"
            if isinstance(value, bool):
                return "bool"
            if isinstance(value, (int, float)):
                return "number"
            if isinstance(value, str):
                return "string"
            if isinstance(value, list):
                return "array"
            return "object"

        def emit(path, current, target):
            entries.append(
                (
                    path,
                    "" if current is missing else encode(current),
                    "" if target is missing else encode(target),
                )
            )

        def pointer_token(token):
            return str(token).replace("~", "~0").replace("/", "~1")

        def walk(path, current, target):
            if current is missing or target is missing:
                emit(path, current, target)
                return
            cur_type = json_type(current)
            tgt_type = json_type(target)
            if cur_type != tgt_type:
                # 节点类型不同：当前路径记一项，不再下探。
                emit(path, current, target)
                return
            if cur_type == "object":
                # 对象取键并集（键序无关，最终按路径排序）。
                for key in set(current) | set(target):
                    child = path + "/" + pointer_token(key)
                    walk(
                        child,
                        current.get(key, missing),
                        target.get(key, missing),
                    )
            elif cur_type == "array":
                # 数组按索引递归，越界侧为缺失。
                for index in range(max(len(current), len(target))):
                    child = path + "/" + str(index)
                    walk(
                        child,
                        current[index] if index < len(current) else missing,
                        target[index] if index < len(target) else missing,
                    )
            else:
                # 同型叶值：以基线紧凑编码逐字节判异（数值 1 与 1.0 亦异）。
                if encode(current) != encode(target):
                    emit(path, current, target)

        walk("", current_doc, target_doc)
        entries.sort(key=lambda item: item[0])
        changes = [
            {"路径": path, "当前": cur_text, "目标": tgt_text}
            for path, cur_text, tgt_text in entries
        ]
        head = {
            "修订": self._revision,
            "当前摘要": self._config_summary(),
            "目标摘要": hashlib.sha256(
                _compact_config(spec).encode("utf-8")
            ).hexdigest(),
            "改变": bool(changes),
            "变更": changes,
        }
        summary = hashlib.sha256(encode(head).encode("utf-8")).hexdigest()
        payload = dict(head)
        payload["摘要"] = summary
        return encode(payload) + "\n"

    def config_history(self, after=-1, limit=100):
        """只读返回防篡改配置历史的 LF 尾紧凑 JSON，查询不老化、不改任何状态。

        取修订 > after 的升序前 limit 项。after/limit 须为非 bool 的 int：
        类型不符抛 TypeError；after < -1 或 limit ∉ [1,1000] 抛 ValueError；
        after != -1 且该修订未保留（窗口满后被淘汰，或超过当前修订）抛
        KeyError(after)。after=-1 自首项（构造态修订 0）起取。顶层键序为
        “下个修订/项目”，游标为末项修订、无项为 after；项目键序为
        “修订/父修订/操作/目标/摘要/前哈希/哈希”，修订/父修订/目标为 int，
        余为 str；首项父修订、目标为 -1、前哈希为 64 个 0，后项父修订取
        前一修订，回退项目标取 target、余为 -1，哈希为前六键基线紧凑 JSON
        的 UTF-8 字节 sha256 小写值。历史与修订快照同寿命（最近 256 项），
        快照淘汰时记录同步淘汰但留存记录的前哈希不改，当前项永不淘汰。
        O(limit) 时间、O(limit) 空间（仅输出窗口；修订连续，定位为 O(1)
        下标计算）。
        """
        if isinstance(after, bool) or not isinstance(after, int):
            raise TypeError(f"after must be an int, got {type(after).__name__}")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(f"limit must be an int, got {type(limit).__name__}")
        if after < -1:
            raise ValueError(f"after must be >= -1, got {after}")
        if limit < 1 or limit > 1000:
            raise ValueError(f"limit must be in 1..1000, got {limit}")

        log = self._config_history_log
        # 记录按提交序连续编号且仅从链首整项淘汰，故 log[i] 的修订恒为
        # oldest + i，定位首个修订 > after 的记录为 O(1) 下标计算。
        oldest = log[0][0]
        current = log[-1][0]
        if after == -1:
            start = 0
        else:
            if after < oldest or after > current:
                raise KeyError(after)
            start = after - oldest + 1

        window = log[start : start + limit]
        items = [
            {
                "修订": revision,
                "父修订": parent,
                "操作": op,
                "目标": target,
                "摘要": summary,
                "前哈希": prev_hash,
                "哈希": digest,
            }
            for revision, parent, op, target, summary, prev_hash, digest in window
        ]
        # 有项取下个修订为末项修订，无项取 after。
        next_revision = window[-1][0] if window else after
        payload = {"下个修订": next_revision, "项目": items}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def config_history_verify(self, after=-1, limit=100):
        """只读验证防篡改配置历史窗口，返回 LF 尾紧凑 JSON；首错即停且不抛
        业务异常（参数/取窗异常同 config_history 照常抛出）。

        参数、取值与取窗规则同 config_history：after/limit 须为非 bool 的
        int，after < -1 或 limit ∉ [1,1000] 抛 ValueError，after != -1 且
        该修订未保留抛 KeyError(after)。验证不老化、不改任何状态。

        可信锚：after != -1 时取该在册项的修订与哈希；after == -1 且修订 0
        在册时取 (-1, 64 个 0)，否则取（最老在册修订 - 1，最老在册项的前哈希）。
        空窗口仅报告锚，检查为 0 且视为完整。

        自锚之后逐项检查：修订连续（恰为锚修订 + 已通过数 + 1）；父修订等于
        前项修订（首项即锚修订）；操作限构造/加载/回滚/CAS/回退，构造仅允许
        修订 0 且目标 -1，回退目标须非负且小于父修订，其余操作目标须为 -1；
        摘要等于对应保留快照按 config_revision 口径（_compact_config(spec)
        的 UTF-8 字节 sha256 小写值）重算的值；前哈希衔接前项哈希（首项衔接
        锚哈希）；哈希可由前六键重算。任一项首次出错即停：完整为 false，断点
        取首错项修订、无可读修订取 -1，原因仅取
        “修订/父修订/操作/目标/快照/摘要/前哈希/哈希”；检查只计通过项，末哈希
        取末个通过项的哈希、无通过项取锚哈希。顶层键序/型为
        “锚修订:int、锚哈希:str、检查:int、完整:bool、断点:int、原因:str、
        末哈希:str”，成功时断点 -1、原因为空串。时间 O(limit·C)、辅助空间
        O(C)，C 为单份配置编码成本。
        """
        if isinstance(after, bool) or not isinstance(after, int):
            raise TypeError(f"after must be an int, got {type(after).__name__}")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(f"limit must be an int, got {type(limit).__name__}")
        if after < -1:
            raise ValueError(f"after must be >= -1, got {after}")
        if limit < 1 or limit > 1000:
            raise ValueError(f"limit must be in 1..1000, got {limit}")

        log = self._config_history_log
        history = self._config_history
        oldest = log[0][0]
        current = log[-1][0]
        zero_hash = "0" * 64
        if after == -1:
            start = 0
            if 0 in history:
                anchor_revision = -1
                anchor_hash = zero_hash
            else:
                # 修订 0 已随窗口淘汰：锚退到最老在册项之前，其哈希即最老项
                # 未被缝合的前哈希。
                anchor_revision = oldest - 1
                anchor_hash = log[0][5]
        else:
            if after < oldest or after > current:
                raise KeyError(after)
            start = after - oldest + 1
            anchor_revision = after
            anchor_hash = log[start - 1][6]

        # 按索引窗口逐项读取，不复制记录，辅助空间仅 O(C)（单份配置编码）。
        end = min(len(log), start + limit)

        allowed_ops = (
            _CONFIG_HISTORY_OP_INIT,
            _CONFIG_HISTORY_OP_LOAD,
            _CONFIG_HISTORY_OP_ROLLBACK,
            _CONFIG_HISTORY_OP_CAS,
            _CONFIG_HISTORY_OP_REVERT,
        )
        expected_revision = anchor_revision
        prev_revision = anchor_revision
        prev_hash = anchor_hash
        checked = 0
        complete = True
        breakpoint_revision = -1
        reason = ""
        for index in range(start, end):
            revision, parent, op, target, summary, rec_prev_hash, digest = log[index]
            expected_revision += 1
            # 修订须可读（非 bool 的 int）且连续；不可读时断点取 -1。
            revision_ok = (
                isinstance(revision, int)
                and not isinstance(revision, bool)
                and revision == expected_revision
            )
            broken = None
            if not revision_ok:
                broken = (revision if isinstance(revision, int)
                          and not isinstance(revision, bool) else -1, "修订")
            if broken is None and parent != prev_revision:
                broken = (revision, "父修订")
            if broken is None:
                if op not in allowed_ops:
                    broken = (revision, "操作")
                elif op == _CONFIG_HISTORY_OP_INIT:
                    if revision != 0 or target != -1:
                        broken = (revision, "目标")
                elif op == _CONFIG_HISTORY_OP_REVERT:
                    # 回退目标须为非 bool 非负 int 且小于父修订。
                    if (
                        not isinstance(target, int)
                        or isinstance(target, bool)
                        or target < 0
                        or target >= parent
                    ):
                        broken = (revision, "目标")
                elif target != -1:
                    broken = (revision, "目标")
            if broken is None:
                # 记录在册而对应快照缺失或已损坏（二者应同寿命、同形态）：
                # 无法按 config_revision 口径重算摘要，记“快照”。
                spec = history.get(revision)
                recomputed_summary = None
                if spec is not None:
                    try:
                        recomputed_summary = hashlib.sha256(
                            _compact_config(spec).encode("utf-8")
                        ).hexdigest()
                    except Exception:
                        recomputed_summary = None
                if spec is None:
                    broken = (revision, "快照")
                elif recomputed_summary is None:
                    broken = (revision, "快照")
                elif summary != recomputed_summary:
                    broken = (revision, "摘要")
            if broken is None and rec_prev_hash != prev_hash:
                broken = (revision, "前哈希")
            if broken is None:
                try:
                    recomputed_hash = self._config_history_hash(
                        revision, parent, op, target, summary, rec_prev_hash
                    )
                except Exception:
                    recomputed_hash = None
                if recomputed_hash is None or digest != recomputed_hash:
                    broken = (revision, "哈希")

            if broken is not None:
                breakpoint_revision, reason = broken
                complete = False
                break

            checked += 1
            prev_revision = revision
            prev_hash = digest

        tail_hash = prev_hash
        payload = {
            "锚修订": anchor_revision,
            "锚哈希": anchor_hash,
            "检查": checked,
            "完整": complete,
            "断点": breakpoint_revision,
            "原因": reason,
            "末哈希": tail_hash,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _config_history_scan(self, trust_boundary=False):
        """按 config_history_replay 契约全量校验并演算在册配置历史（只读），
        不老化、不改任何状态，首错即停，供 config_history_replay 与
        config_audit_reconcile 共用同一扫描。

        trust_boundary=False（config_history_replay）时，演算依赖（回退目标
        快照、回滚点）随窗口淘汰而不可知即归“边界”失败；trust_boundary=True
        （config_audit_reconcile，淘汰修订为可信边界）时不失败：回退目标已
        淘汰则信任本项快照并保存前态，回滚点未知则信任本项快照并清除回滚点，
        余契约校验不变。

        可信锚：修订 0 在册时锚为 (-1, 64 个 0)、当前态为空、回滚点已知为空；
        否则信任最老在册快照与最老在册记录的哈希为锚（锚修订取最老在册修订），
        回滚点未知。锚后逐项先按 config_history_verify 契约校验字段、修订链、
        操作/目标、快照摘要与哈希链（快照/哈希编码失败各归同名原因），再按提交
        语义演算：构造仅生成修订 0；加载/CAS 取本项快照为新当前态；回退须目标
        快照在册且本项快照与其规范 v9 JSON 逐字节相同；加载/CAS/回退均保存前态
        为回滚点；回滚须回滚点已知且本项快照与其逐字节相同，随后清除回滚点。
        演算依赖（回退目标快照、回滚点）随窗口淘汰而不可知时归“边界”。

        返回 dict：anchor_revision/anchor_hash 为锚；start 为首项被扫描的
        log 下标（修订 0 在册为 0，否则最老在册项作为锚不扫描、取 1）；
        checked 为通过项数；complete 为是否全量通过；broken 为 None 或
        (断点修订, 原因)（修订号不可读时取 -1）；last_revision/last_summary
        取末个通过态（无通过项取锚）。原因限“修订/父修订/操作/目标/快照/
        摘要/前哈希/哈希/回退/回滚/边界”；检查只计通过项。时间 O(H·C)、
        辅助空间 O(C)。
        """
        log = self._config_history_log
        history = self._config_history
        zero_hash = "0" * 64
        # 回滚点未知哨兵：仅用于修订 0 已淘汰的锚态，区别于已知为空（None）。
        unknown = object()
        if 0 in history:
            anchor_revision = -1
            anchor_hash = zero_hash
            start = 0
            current = None
            rollback = None
            last_revision = -1
            last_summary = zero_hash
        else:
            # 修订 0 已随窗口淘汰：信任最老在册快照与记录哈希为锚，自次项起
            # 校验；回滚点未知。锚快照若缺失（内部状态被破坏），锚不可信，
            # 立即以最老在册记录的修订与“快照”失败返回，不抛异常。
            anchor_revision = log[0][0]
            anchor_hash = log[0][6]
            anchor_spec = history.get(anchor_revision) if (
                isinstance(anchor_revision, int)
                and not isinstance(anchor_revision, bool)
            ) else None
            if anchor_spec is None:
                return {
                    "anchor_revision": anchor_revision,
                    "anchor_hash": anchor_hash,
                    "start": len(log),
                    "checked": 0,
                    "complete": False,
                    "broken": (
                        anchor_revision
                        if isinstance(anchor_revision, int)
                        and not isinstance(anchor_revision, bool)
                        else -1,
                        "快照",
                    ),
                    "last_revision": anchor_revision
                    if isinstance(anchor_revision, int)
                    and not isinstance(anchor_revision, bool)
                    else -1,
                    "last_summary": log[0][4],
                }
            start = 1
            current = anchor_spec
            rollback = unknown
            last_revision = anchor_revision
            last_summary = log[0][4]

        allowed_ops = (
            _CONFIG_HISTORY_OP_INIT,
            _CONFIG_HISTORY_OP_LOAD,
            _CONFIG_HISTORY_OP_ROLLBACK,
            _CONFIG_HISTORY_OP_CAS,
            _CONFIG_HISTORY_OP_REVERT,
        )
        expected_revision = anchor_revision
        prev_revision = anchor_revision
        prev_hash = anchor_hash
        checked = 0
        complete = True
        broken = None
        for index in range(start, len(log)):
            revision, parent, op, target, summary, rec_prev_hash, digest = log[
                index
            ]
            expected_revision += 1
            # 契约校验同 config_history_verify：修订须可读（非 bool 的 int）
            # 且连续；不可读时断点取 -1。
            revision_ok = (
                isinstance(revision, int)
                and not isinstance(revision, bool)
                and revision == expected_revision
            )
            broken = None
            if not revision_ok:
                broken = (revision if isinstance(revision, int)
                          and not isinstance(revision, bool) else -1, "修订")
            if broken is None and parent != prev_revision:
                broken = (revision, "父修订")
            if broken is None:
                if op not in allowed_ops:
                    broken = (revision, "操作")
                elif op == _CONFIG_HISTORY_OP_INIT:
                    if revision != 0 or target != -1:
                        broken = (revision, "目标")
                elif op == _CONFIG_HISTORY_OP_REVERT:
                    # 回退目标须为非 bool 非负 int 且小于父修订。
                    if (
                        not isinstance(target, int)
                        or isinstance(target, bool)
                        or target < 0
                        or target >= parent
                    ):
                        broken = (revision, "目标")
                elif target != -1:
                    broken = (revision, "目标")
            spec = None
            if broken is None:
                # 记录在册而对应快照缺失或编码失败：无法按 config_revision
                # 口径重算摘要，记“快照”。
                spec = history.get(revision)
                recomputed_summary = None
                if spec is not None:
                    try:
                        recomputed_summary = hashlib.sha256(
                            _compact_config(spec).encode("utf-8")
                        ).hexdigest()
                    except Exception:
                        recomputed_summary = None
                if spec is None or recomputed_summary is None:
                    broken = (revision, "快照")
                elif summary != recomputed_summary:
                    broken = (revision, "摘要")
            if broken is None and rec_prev_hash != prev_hash:
                broken = (revision, "前哈希")
            if broken is None:
                try:
                    recomputed_hash = self._config_history_hash(
                        revision, parent, op, target, summary, rec_prev_hash
                    )
                except Exception:
                    recomputed_hash = None
                if recomputed_hash is None or digest != recomputed_hash:
                    broken = (revision, "哈希")

            # 演算：契约通过后按提交语义推进当前态与回滚点；spec 已经快照
            # 校验，必在册且可编码。
            new_current = current
            new_rollback = rollback
            if broken is None:
                if op == _CONFIG_HISTORY_OP_INIT:
                    # 构造仅生成修订 0（契约已限）：当前态置本项快照，回滚点空。
                    new_current, new_rollback = spec, None
                elif op in (_CONFIG_HISTORY_OP_LOAD, _CONFIG_HISTORY_OP_CAS):
                    # 加载/CAS 取本项快照，保存前态为回滚点。
                    new_current, new_rollback = spec, current
                elif op == _CONFIG_HISTORY_OP_REVERT:
                    target_spec = history.get(target)
                    if target_spec is None:
                        if trust_boundary:
                            # 目标快照已随窗口淘汰：对账视淘汰为可信边界，
                            # 信任本项快照并保存前态，继续演算。
                            new_current, new_rollback = spec, current
                        else:
                            # 目标快照已随窗口淘汰：依赖不可知，归“边界”。
                            broken = (revision, "边界")
                    else:
                        try:
                            same = _compact_config(spec) == _compact_config(
                                target_spec
                            )
                        except Exception:
                            same = None
                        if same is None:
                            broken = (revision, "快照")
                        elif not same:
                            # 本项快照与目标快照规范 v9 JSON 不逐字节相同。
                            broken = (revision, "回退")
                        else:
                            new_current, new_rollback = spec, current
                else:
                    # 回滚须回滚点已知且本项快照与其逐字节相同，随后清除。
                    if rollback is unknown:
                        if trust_boundary:
                            # 回滚点随窗口淘汰而不可知：对账视淘汰为可信
                            # 边界，信任本项快照并清除回滚点，继续演算。
                            new_current, new_rollback = spec, None
                        else:
                            broken = (revision, "边界")
                    elif rollback is None:
                        broken = (revision, "回滚")
                    else:
                        try:
                            same = _compact_config(spec) == _compact_config(
                                rollback
                            )
                        except Exception:
                            same = None
                        if same is None:
                            broken = (revision, "快照")
                        elif not same:
                            broken = (revision, "回滚")
                        else:
                            new_current, new_rollback = spec, None

            if broken is not None:
                complete = False
                break

            checked += 1
            current, rollback = new_current, new_rollback
            prev_revision = revision
            prev_hash = digest
            last_revision = revision
            last_summary = summary

        return {
            "anchor_revision": anchor_revision,
            "anchor_hash": anchor_hash,
            "start": start,
            "checked": checked,
            "complete": complete,
            "broken": broken,
            "last_revision": last_revision,
            "last_summary": last_summary,
        }

    def config_history_replay(self):
        """只读重放保留的配置历史，返回 LF 尾紧凑 JSON；不老化、不改任何状态，
        首错即停且不抛业务异常。

        校验与演算规则见 _config_history_scan（与 config_audit_reconcile
        共用同一扫描）：可信锚、逐项契约校验与提交语义演算不变，原因限
        “修订/父修订/操作/目标/快照/摘要/前哈希/哈希/回退/回滚/边界”。
        顶层键序/型为“锚修订:int、锚哈希:str、检查:int、完整:bool、
        断点:int、原因:str、末修订:int、末摘要:str”，成功时断点 -1、原因
        空串；末修订/末摘要取最后通过态（无通过项取锚），完整时恒等于
        config_revision 的修订与摘要。时间 O(H·C)、辅助空间 O(C)，H 为
        在册记录数（≤256），C 为单份配置编码成本。
        """
        scan = self._config_history_scan()
        breakpoint_revision = -1
        reason = ""
        if scan["broken"] is not None:
            breakpoint_revision, reason = scan["broken"]
        payload = {
            "锚修订": scan["anchor_revision"],
            "锚哈希": scan["anchor_hash"],
            "检查": scan["checked"],
            "完整": scan["complete"],
            "断点": breakpoint_revision,
            "原因": reason,
            "末修订": scan["last_revision"],
            "末摘要": scan["last_summary"],
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def config_audit_reconcile(self):
        """
        只读对账……规则与输出契约见下；本公开方法为不抛异常的总入口：
        正常对账与可预期的链/历史损坏均返回结构化失败 JSON，任何未预期的
        内部损坏（如被直接破坏的在册数据结构）也统一兜底为“历史”失败、
        断点均 -1，而不抛出异常。

        修订来源仅“构造/直接/事务”：修订 0 为构造；非经 config_change 的
        提交（直载/直滚/CAS/回退）为直接；config_change 首次加载/回滚成功
        为事务，并在 audit 链记原序号 0 的首次事件；失败、升级、重放不产生
        修订。

        校验次序固定：
        一、先按 config_history_replay 规则（见 _config_history_scan）全量
        校验并演算在册配置历史，但淘汰导致的演算依赖不可知（回退目标快照、
        回滚点）视为可信边界而不断裂（信任本项快照继续演算）；其余首次出错
        即归“历史”，断点修订取该修订（修订号不可读取 -1）、断点审计 -1
        （audit 尚未校验）。
        二、再自空哈希（64 个 0）起校验全量 audit 链：序号自 1 连续、前哈希
        衔接前项（首项衔接 64 个 0）、哈希可由前八字段重算；任一首次出错即
        归“审计”，断点修订 -1、断点审计取该事件序号（不可读取 -1）。
        三、最后按修订升序验来源（覆盖历史扫描范围内的全部在册记录，修订 0
        已淘汰时最老在册项作为可信锚不重验、不计），再做索引与链级复核。
        config_change 域的“键 → 首次事件序号”索引为权威指认：构造与直接项
        无关联；事务项（加载/回滚）由其键缓存原调操作与首果配置摘要
        (操作, 摘要) 定位唯一在册修订（加载与回滚同摘要不互配）。候选按审计
        序号升序收集：仅取由同键索引指认的原序号 0 首次事件，且缓存原调为
        成功的加载/回滚（失败、升级、重放与未指认事件不入候选）；其首果配置
        为缓存返回的 v9 JSON，摘要按 config_revision 既有口径（去尾 LF 的
        UTF-8 字节 sha256）求。再按修订升序扫描在册“加载/回滚”记录做配对：
        候选仅允许丢弃一段连续前缀作为已淘汰边界（其数量不得超过已淘汰修订
        数，且由反向就近同 (操作, 摘要) 对齐定切点）；其余候选必须与记录形成
        保序一一映射——候选按序各取其后首个 (操作, 摘要) 相同且未消费的记录，
        配出事件序号随修订严格升序，两候选间被越过的异组记录判为直接来源。
        禁止分组贪心换配、禁止跳过候选或逆序；候选缺失、多余或失序即在首个
        分歧归“来源”（断点修订取冲突记录修订、断点审计取冲突事件序号，无
        对应项取 -1，检查只计此前通过修订）；加载/回滚记录无候选配对即为直接
        来源，合法。配对项的指认事件须为同键、原序号 0
        的首事件，操作须为“配置加载/配置回滚”且与缓存原调及历史操作一致
        （违例归“操作”），缓存首果与事件结果须同为“成功”（违例归“结果”），
        键、时刻取原调用且会话为空串（时刻须等于缓存首调时刻，违例归“关联”）。
        索引复核（断点修订 -1、断点审计取首次事件序号；
        已与在册修订配对的首事件不重验）：每个键指认的首事件须存在、原序号
        0、同键、同操作、同时刻、结果名与缓存首果相符（成功或业务异常类名）、
        会话为空串，缓存缺失或指认失效归“关联”。链级复核（按事件序号升序，
        不关联修订）：config_change 三操作的原序号 0 事件须恰为其键索引指认
        事件（重复或未指认归“关联”，自报重放归“重放”）；原序号非 0 的
        重放事件须指向其前同键同操作、原序号 0 的首次事件，结果须为
        “重放成功”或“重放”加首果名（违例归“重放”）。配置升级及其余域
        事件不关联修订。

        淘汰修订（配置历史仅留最近 256 项，audit 链全量不淘汰）为可信
        边界：仅对账在册修订，对应已淘汰修订的首次事件不要求关联。检查仅
        计通过修订（来源阶段逐项计）；成功时两断点均 -1、原因为空串，末
        修订取当前修订、末审计取末事件序号（空链为 0）；失败时末修订/末
        审计取已验通过位置（历史阶段失败取历史扫描末态与 0，审计阶段失败
        取当前修订与末个通过链序号，来源逐项失败取前一在册修订与全链序号，
        索引/链级失败取当前修订与全链序号）。顶层键序/型为
        “锚修订:int、检查:int、完整:bool、断点修订:int、断点审计:int、
        原因:str、末修订:int、末审计:int”，原因仅取
        “历史/审计/来源/关联/操作/结果/重放”，不可读断点为 -1。时间
        O(A+H·C)、辅助空间 O(H)，A 为审计事件数、H 为在册修订数、C 为
        单份配置编码成本。
        """
        try:
            return self._config_audit_reconcile_check()
        except Exception:
            payload = {
                "锚修订": -1,
                "检查": 0,
                "完整": False,
                "断点修订": -1,
                "断点审计": -1,
                "原因": "历史",
                "末修订": -1,
                "末审计": 0,
            }
            return (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )

    def _config_audit_reconcile_check(self):
        """config_audit_reconcile 的对账实现；完整契约见公开方法文档。
        """
        scan = self._config_history_scan(trust_boundary=True)
        anchor_revision = scan["anchor_revision"]

        def render(checked, complete, bp_revision, bp_audit, reason,
                   last_revision, last_audit):
            payload = {
                "锚修订": anchor_revision,
                "检查": checked,
                "完整": complete,
                "断点修订": bp_revision,
                "断点审计": bp_audit,
                "原因": reason,
                "末修订": last_revision,
                "末审计": last_audit,
            }
            return (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )

        # 一、配置历史（含提交语义演算）；audit 链尚未校验，末审计取 0，
        # 检查仅计历史扫描中已通过的修订数。
        if not scan["complete"]:
            bp_revision, _hist_reason = scan["broken"]
            return render(
                scan["checked"], False, bp_revision, -1, "历史",
                scan["last_revision"], 0,
            )

        log = self._config_history_log
        current_revision = log[-1][0]
        chain = self._chain_events
        config_ops = (
            _CONFIG_CHAIN_LOAD,
            _CONFIG_CHAIN_ROLLBACK,
            _CONFIG_CHAIN_UPGRADE,
        )

        # 二、全量 audit 链：连续序号、前哈希衔接、哈希重算。此阶段历史已
        # 全量通过，检查取历史扫描通过修订数，末修订取当前修订。
        history_checked = scan["checked"]
        prev_hash = "0" * 64
        last_audit = 0
        for expect, event in enumerate(chain, start=1):
            (seq, ev_now, key, op, sid, result, origin,
             stored_prev, digest) = event
            seq_ok = (
                isinstance(seq, int)
                and not isinstance(seq, bool)
                and seq == expect
            )
            bp_audit = seq if seq_ok else -1
            if not seq_ok or stored_prev != prev_hash:
                return render(
                    history_checked, False, -1, bp_audit, "审计",
                    current_revision, last_audit,
                )
            recomputed = None
            try:
                recomputed = self._chain_hash(
                    seq, ev_now, key, op, sid, result, origin, stored_prev
                )
            except Exception:
                recomputed = None
            if recomputed is None or digest != recomputed:
                return render(
                    history_checked, False, -1, bp_audit, "审计",
                    current_revision, last_audit,
                )
            prev_hash = digest
            last_audit = seq
        total_audit = len(chain)

        # 三、来源对账。config_change 域的“键 → 首次事件序号”索引
        # （_config_change_chain_index）为权威指认：每次合法首调（成功或
        # 业务异常）均在链上留一个原序号 0 首次事件并把其序号记入索引。
        # 事务修订由“索引指认事件 + 缓存原调操作/首果摘要”保序配对（见下）；
        # 事件的键/操作/时刻/结果/会话字段一律作为被验对象而非配对依据，故
        # 篡改任一字段都会在本阶段暴露而不会令事务修订伪装成直接来源。重放
        # 缓存不老化、audit 链全量不淘汰，索引、缓存与事件同寿。
        cindex = self._config_change_chain_index
        ccache = self._config_change_cache

        # 候选选取（审计序号升序；时间 O(A)、不在此步算配置摘要）：事务候选
        # 仅取 config_change 域“键 → 首次事件序号”索引指认
        # （cindex[事件键] == 序号）的原序号 0 事件，且该键缓存原调为成功的
        # 加载/回滚（首果 ("ok", v9 JSON 文本)）；失败、升级、重放与未被同键
        # 索引指认的事件一律不是候选。每个在册修订至多消费一个候选，故事务候
        # 选与在册 load/rollback 记录的保序配对所用候选必为候选序列的一个后缀
        # （更早的成功首调皆对应已淘汰修订，为可信边界前缀）：自链尾反向仅收
        # 集至多 R 个（R 为在册“加载/回滚”记录数），再翻回升序，识别只用
        # O(1) 字段与缓存判定；配置摘要只对这至多 R 个候选计算（O(H·C)），
        # 不哈希全链，辅助空间 O(H)。事件字段本身仍是被验对象，篡改致错配时
        # 由下述配对及 3.1/3.2/3.3 捕获。
        start = scan["start"]
        load_rollback_records = [
            (li, record)
            for li, record in enumerate(log)
            if li >= start
            and record[2] in (
                _CONFIG_HISTORY_OP_LOAD,
                _CONFIG_HISTORY_OP_ROLLBACK,
            )
        ]
        pair_cap = len(load_rollback_records)
        # 已淘汰的事务修订数上界：修订 0 在册（start=0）时无淘汰；否则淘汰
        # 修订为 0..锚修订，其中修订 0 为构造（永非事务候选），故事务候选可
        # 占的已淘汰修订至多为锚修订号个（1..锚修订）。
        eliminated_cap = anchor_revision if start == 1 else 0
        total_candidates = 0
        window_rev = []
        for index in range(total_audit - 1, -1, -1):
            event = chain[index]
            seq, _ev_now, ev_key, _ev_op, _sid, _result, origin = event[:7]
            # 键须为 str 才能查域索引；非 str 键的链项不入候选（由 3.3 归
            # “关联”），亦保证不抛异常。
            if (
                not isinstance(ev_key, str)
                or origin != 0
                or cindex.get(ev_key) != seq
            ):
                continue
            cache = ccache.get(ev_key)
            if not isinstance(cache, tuple) or len(cache) != 4:
                continue
            c_op, _c_text, _c_now_ms, outcome = cache
            if (
                not isinstance(outcome, tuple)
                or len(outcome) != 2
                or c_op not in (_CONFIG_OP_LOAD, _CONFIG_OP_ROLLBACK)
                or outcome[0] != "ok"
                or not isinstance(outcome[1], str)
            ):
                continue
            total_candidates += 1
            if len(window_rev) < pair_cap:
                window_rev.append((seq, ev_key, cache))
            # 已收满配对窗口后仍计数（供淘汰前缀上界校验），但不再保留。
        window_rev.reverse()  # 回到审计序号升序。
        # 早于末 R 个候选的事务首调必对应已淘汰修订（在册记录至多消费 R 个，
        # 且配对候选为候选序列后缀）：其数量即不经哈希即采信的淘汰前缀。
        pre_eliminated = max(0, total_candidates - pair_cap)
        # 仅对窗口内候选按既有口径求摘要：缓存返回的 v9 配置 JSON 去尾 LF 后
        # 的 UTF-8 字节 sha256 小写值（同 config_revision/历史摘要）。
        candidates = []
        for fseq, ckey, cache in window_rev:
            try:
                config_digest = hashlib.sha256(
                    cache[3][1][:-1].encode("utf-8")
                ).hexdigest()
            except Exception:
                config_digest = None
            candidates.append((fseq, ckey, cache, config_digest))

        def source_conflict(conflict_record_index, cand):
            """首个来源分歧 → 原因“来源”。conflict_record_index 为 R 下标
            （越界表示无对应记录，断点修订取 -1）；检查只计此前通过修订。"""
            cfseq = cand[0]
            audit_bp = (
                cfseq
                if isinstance(cfseq, int) and not isinstance(cfseq, bool)
                else -1
            )
            if 0 <= conflict_record_index < len(load_rollback_records):
                log_index, conflict_record = load_rollback_records[
                    conflict_record_index
                ]
                revision_bp = conflict_record[0]
                if not (
                    isinstance(revision_bp, int)
                    and not isinstance(revision_bp, bool)
                ):
                    revision_bp = -1
                passed = log_index - start
                last_rev = (
                    log[log_index - 1][0] if log_index > start
                    else anchor_revision
                )
            else:
                # 候选无对应在册记录（缺失/多余）：断点修订 -1，此前在册记录
                # 均已通过，检查计全部在册扫描项。
                revision_bp = -1
                passed = len(log) - start
                last_rev = log[-1][0] if len(log) > start else anchor_revision
            return render(
                passed, False, revision_bp, audit_bp, "来源",
                last_rev, total_audit,
            )

        # 淘汰边界反向定位（仅用于切出连续前缀）：自末个候选与末个在册
        # load/rollback 记录起，反向就近找同 (操作, 摘要) 记录；找不到的候选
        # 及其前全部候选为已淘汰连续前缀。此趟只确定切点，不做最终配对。
        ci = len(candidates) - 1
        ri = len(load_rollback_records) - 1
        while ci >= 0:
            _fseq, _ckey, cache, config_digest = candidates[ci]
            j = ri
            while j >= 0 and not (
                load_rollback_records[j][1][2] == cache[0]
                and load_rollback_records[j][1][4] == config_digest
            ):
                j -= 1
            if j < 0:
                break
            ri = j - 1
            ci -= 1
        boundary_in_window = ci + 1
        # 淘汰候选总数不得超过已淘汰修订数上界；超过则属来源断裂（正常历史
        # 下不可能：链与历史均已全量校验通过），在窗口首个分歧判“来源”。
        if pre_eliminated + boundary_in_window > eliminated_cap:
            # 首个分歧候选取反向就近对齐首次失配的候选：窗口内有失配项时为
            # window[b-1]（其后候选均已反向配平，唯它无记录可配）；窗口全部
            # 配平而溢出全落在被丢弃前缀时，前 eliminated_cap 个候选可作淘汰
            # 边界、其后首个候选即首个分歧——窗口只保留末 R 个候选，故按同一
            # 候选判定口径正向重扫链定位该候选（仅算这一份摘要，O(C)）。
            if boundary_in_window > 0:
                first_cand = candidates[boundary_in_window - 1]
            else:
                first_cand = None
                seen = 0
                for fc_event in chain:
                    (fseq, _f_now, fkey, _f_op, _f_sid,
                     _f_result, forigin) = fc_event[:7]
                    if (
                        not isinstance(fkey, str)
                        or forigin != 0
                        or cindex.get(fkey) != fseq
                    ):
                        continue
                    fcache = ccache.get(fkey)
                    if not isinstance(fcache, tuple) or len(fcache) != 4:
                        continue
                    fc_op, _fc_text, _fc_now, foutcome = fcache
                    if (
                        not isinstance(foutcome, tuple)
                        or len(foutcome) != 2
                        or fc_op not in (_CONFIG_OP_LOAD, _CONFIG_OP_ROLLBACK)
                        or foutcome[0] != "ok"
                        or not isinstance(foutcome[1], str)
                    ):
                        continue
                    if seen == eliminated_cap:
                        try:
                            fc_digest0 = hashlib.sha256(
                                fcache[3][1][:-1].encode("utf-8")
                            ).hexdigest()
                        except Exception:
                            fc_digest0 = None
                        first_cand = (fseq, fkey, fcache, fc_digest0)
                        break
                    seen += 1
                if first_cand is None:
                    first_cand = (-1, None, None, None)
            fc_cache = first_cand[2]
            fc_digest = first_cand[3]
            # 该失配候选在全册（锚后）找不到任何同 (操作, 摘要) 记录时，即
            # “多余事务候选无在册记录”：它不可能属于已淘汰前缀（前缀已超淘汰
            # 上界），断点修订取 -1、断点审计取候选序号，检查计全部在册扫描
            # 项、末修订取当前修订（此前在册记录均保持已通过，仅候选为外来
            # 分歧，不抛异常）；否则按既有口径在首个冲突记录处记“来源”
            # （如互换首事件的失序/换配）。
            if fc_cache is not None and not any(
                record[2] == fc_cache[0] and record[4] == fc_digest
                for _li, record in load_rollback_records
            ):
                return source_conflict(len(load_rollback_records), first_cand)
            return source_conflict(0, first_cand)
        survivors = candidates[boundary_in_window:]

        # 正向保序一一映射：候选按审计序号升序，各取其后首个 (操作, 摘要)
        # 相同且尚未消费的在册“加载/回滚”记录（记录按修订升序）。映射严格
        # 保序——配出的事件序号随修订升序单调；两候选间被越过的异组记录判
        # 直接来源（直接提交合法交错）。禁止分组贪心换配、禁止跳过候选或逆
        # 序：某候选在其后找不到同 (操作, 摘要) 记录即首个来源分歧（缺失/
        # 多余/失序），断点修订取分歧记录修订（记录已尽取 -1）、断点审计取
        # 该候选事件序号。时间 O(H)、辅助空间 O(H)。
        paired = {}
        record_cursor = 0
        for cand in survivors:
            _fseq, _ckey, cache, config_digest = cand
            j = record_cursor
            while j < len(load_rollback_records) and not (
                load_rollback_records[j][1][2] == cache[0]
                and load_rollback_records[j][1][4] == config_digest
            ):
                j += 1
            if j >= len(load_rollback_records):
                # 该候选与其后在册记录无同 (操作, 摘要) 项：若全册（锚后）
                # 亦无同组记录，则属“多余候选找不到任何在册记录”，断点修订
                # 取 -1、检查计全部在册扫描项、末修订取当前修订（此前在册
                # 记录均保持已通过，仅候选为外来分歧）；否则为失序/换配分歧，
                # 断点取游标处冲突记录修订。
                if not any(
                    record[2] == cache[0] and record[4] == config_digest
                    for _li, record in load_rollback_records
                ):
                    return source_conflict(len(load_rollback_records), cand)
                return source_conflict(record_cursor, cand)
            pair_record = load_rollback_records[j][1]
            paired[pair_record[0]] = cand
            record_cursor = j + 1

        # 3.1 按修订升序验在册项（可信锚记录不重验、不计；构造/CAS/回退恒
        # 为无关联来源；加载/回滚无配对候选即为直接来源）。检查逐项计，
        # 末修订取前一通过项（无通过项取锚修订）。
        checked = 0
        last_good_revision = anchor_revision
        last_paired_seq = 0
        for record in log[scan["start"]:]:
            revision, _parent, hist_op, _target, _summary, _ph, _h = record
            candidate = paired.get(revision)
            if candidate is not None:
                fseq, ckey, cache, config_digest = candidate
                # 索引指认须可读且落在链内；事件须为同键的原序号 0 首事件。
                fseq_ok = (
                    isinstance(fseq, int)
                    and not isinstance(fseq, bool)
                    and 1 <= fseq <= total_audit
                )
                first_event = chain[fseq - 1] if fseq_ok else None
                if (
                    not fseq_ok
                    or first_event is None
                    or first_event[6] != 0
                    or first_event[2] != ckey
                ):
                    return render(
                        checked, False, revision,
                        fseq if fseq_ok else -1, "关联",
                        last_good_revision, total_audit,
                    )
                (_ev_seq, ev_now, _ev_key, ev_op, ev_sid,
                 ev_result, ev_origin) = first_event[:7]
                # 配对事件序号须随修订升序单调（记录先提交、事件后入链）。
                if fseq <= last_paired_seq:
                    return render(
                        checked, False, revision, fseq, "来源",
                        last_good_revision, total_audit,
                    )
                c_op, _c_text, c_now_ms, outcome = cache
                # 操作匹配历史：缓存原调操作映射的链操作须等于事件操作，且
                # 原调操作须等于历史记录操作（加载↔配置加载、回滚↔配置回滚）。
                if _CONFIG_CHAIN_OP.get(c_op) != ev_op or c_op != hist_op:
                    return render(
                        checked, False, revision, fseq, "操作",
                        last_good_revision, total_audit,
                    )
                # 事务首事件结果须为“成功”，缓存首果须同为成功。
                if outcome[0] != "ok" or ev_result != "成功":
                    return render(
                        checked, False, revision, fseq, "结果",
                        last_good_revision, total_audit,
                    )
                # 键、时刻取原调用：事件键须为缓存键（上方已验同源），时刻
                # 须等于首调时刻；config_change 事件会话恒为空串。
                if ev_now != c_now_ms or ev_sid != "":
                    return render(
                        checked, False, revision, fseq, "关联",
                        last_good_revision, total_audit,
                    )
                last_paired_seq = fseq
            checked += 1
            last_good_revision = revision

        # 3.2 索引全量复核（不关联修订，断点修订取 -1）：已与在册修订配对
        # 的首事件在 3.1 验过，此处跳过；其余键指认的首次事件（成功加载/
        # 回滚对应已淘汰修订——可信边界但缓存与事件仍须自洽；失败与升级不
        # 产生修订）须存在、原序号 0、同键，且与缓存原调同操作、同时刻、
        # 结果名相符（成功或业务异常类名）、会话为空串；缓存缺失归“关联”。
        paired_pairs = {
            (candidate[1], candidate[0])
            for candidate in paired.values()
        }
        for ckey, fseq in cindex.items():
            if (ckey, fseq) in paired_pairs:
                continue
            fseq_ok = (
                isinstance(fseq, int)
                and not isinstance(fseq, bool)
                and 1 <= fseq <= total_audit
            )
            if not fseq_ok:
                return render(
                    checked, False, -1, -1, "关联",
                    current_revision, total_audit,
                )
            event = chain[fseq - 1]
            (_ev_seq, ev_now, ev_key, ev_op, ev_sid,
             ev_result, ev_origin) = event[:7]
            if ev_origin != 0 or ev_key != ckey:
                return render(
                    checked, False, -1, fseq, "关联",
                    current_revision, total_audit,
                )
            cache = ccache.get(ckey)
            if (
                not isinstance(cache, tuple)
                or len(cache) != 4
                or not isinstance(cache[3], tuple)
                or len(cache[3]) != 2
            ):
                return render(
                    checked, False, -1, fseq, "关联",
                    current_revision, total_audit,
                )
            c_op, _c_text, c_now_ms, outcome = cache
            if _CONFIG_CHAIN_OP.get(c_op) != ev_op:
                return render(
                    checked, False, -1, fseq, "操作",
                    current_revision, total_audit,
                )
            if outcome[0] == "ok":
                if ev_result != "成功":
                    return render(
                        checked, False, -1, fseq, "结果",
                        current_revision, total_audit,
                    )
            else:
                exc_class = outcome[1][0]
                exc_name = getattr(exc_class, "__name__", None)
                if exc_name is None or ev_result != exc_name:
                    return render(
                        checked, False, -1, fseq, "结果",
                        current_revision, total_audit,
                    )
            if ev_now != c_now_ms or ev_sid != "":
                return render(
                    checked, False, -1, fseq, "关联",
                    current_revision, total_audit,
                )

        # 3.3 链级复核（按事件序号升序，不关联修订）：config_change 三操作
        # 的原序号 0 事件须恰为其键索引指认的首次事件（唯一关联；未被指认
        # 或自报重放均违例）；原序号非 0 的重放事件须指向其前同键同操作的
        # 原序号 0 首次事件，结果为“重放成功”或“重放”加首果名。
        for event in chain:
            seq, ev_now, key, op, sid, result, origin = event[:7]
            if op not in config_ops:
                continue
            # 字段型态由入链约束保证；此处对被篡改的内部状态做形状兜底，
            # 保证不抛异常（原序号/结果非预期归“重放”，键不可读归“关联”）。
            if not isinstance(origin, int) or isinstance(origin, bool):
                return render(
                    checked, False, -1,
                    seq if isinstance(seq, int)
                    and not isinstance(seq, bool) else -1,
                    "重放", current_revision, total_audit,
                )
            if not isinstance(result, str):
                return render(
                    checked, False, -1,
                    seq if isinstance(seq, int)
                    and not isinstance(seq, bool) else -1,
                    "重放", current_revision, total_audit,
                )
            if origin == 0:
                if not isinstance(key, str) or cindex.get(key) != seq:
                    # 未被其键索引指认：首次事件不唯一或来源不可证。
                    return render(
                        checked, False, -1, seq, "关联",
                        current_revision, total_audit,
                    )
                if result.startswith("重放"):
                    # 原序号 0 的事件不得自报重放结果。
                    return render(
                        checked, False, -1, seq, "重放",
                        current_revision, total_audit,
                    )
            else:
                if not (1 <= origin < seq):
                    return render(
                        checked, False, -1, seq, "重放",
                        current_revision, total_audit,
                    )
                target = chain[origin - 1]
                if target[6] != 0 or target[2] != key or target[3] != op:
                    return render(
                        checked, False, -1, seq, "重放",
                        current_revision, total_audit,
                    )
                if not isinstance(target[5], str):
                    return render(
                        checked, False, -1, seq, "重放",
                        current_revision, total_audit,
                    )
                expected_result = (
                    "重放成功"
                    if target[5] == "成功"
                    else "重放" + target[5]
                )
                if result != expected_result:
                    return render(
                        checked, False, -1, seq, "重放",
                        current_revision, total_audit,
                    )

        return render(
            checked, True, -1, -1, "", current_revision, total_audit
        )

    def config_cas(self, key, text, expected, now_ms):
        """比较修订号并原子加载配置，返回 LF 尾紧凑 JSON。

        key 沿用凭据约束；text 须为 str，expected/now_ms 须为非 bool 非负
        int；类型错抛 TypeError，取值错抛 ValueError。验参后先比较
        expected 与当前修订号：不等抛 StateError(expected, current)，不解析
        text；相等时按 load_config 规则加载，文档非法抛 ValueError、承载
        冲突抛 ResourceError。成功原子提交、覆盖回滚点、修订号加 1 并保存
        新修订历史项（最近 256 项，超限淘汰最旧项且不淘汰当前项），返回
        键序/型“修订:int、前摘要:str、后摘要:str”的 JSON，两摘要同
        config_revision 定义（分别为提交前、后的配置摘要）。

        重放缓存与各域独立且仅缓存首次成功：同型同参重放不再比较修订号、
        不加载，原样返回首次字节；异参抛 ValueError；任何失败（含参数错与
        修订不符）不占 key 且不改实例。本接口不审计。首次成功另向防篡改
        配置历史追加“CAS”记录，失败与同参重放不追加。首次 O(n log n + S + Q)
        时间、O(n) 空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._config_cas_cache.get(key)
        if cached is not None:
            # 重放：不比较修订号、不解析、不加载，仅核对同型同参后返回原字节。
            c_text, c_expected, c_now_ms, result = cached
            if not _strict_equal(
                (text, expected, now_ms), (c_text, c_expected, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        # 类型阶段：任一类型错先于任何值错抛出。
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise TypeError(
                f"expected must be an int, got {type(expected).__name__}"
            )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值阶段。
        if expected < 0:
            raise ValueError(f"expected must be >= 0, got {expected}")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")

        # 先比修订号，不符不得解析 text；失败不占 key、不改实例。
        if expected != self._revision:
            raise StateError(expected, self._revision)

        before = self._config_summary()
        # 按 load_config 规则解析并承载校验，成功后以“CAS”操作原子提交、
        # 覆盖回滚点并将修订号加 1（不经 load_config，以免配置历史误记
        # “加载”）；文档错 ValueError、承载冲突 ResourceError，失败实例不变。
        spec, new_pools = self._parse_config_text(text)
        self._commit_config(
            spec, new_pools, self._current_spec(), _CONFIG_HISTORY_OP_CAS
        )
        after = self._config_summary()
        payload = {"修订": self._revision, "前摘要": before, "后摘要": after}
        result = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self._config_cas_cache[key] = (text, expected, now_ms, result)
        return result

    def config_revert(self, key, target, expected, now_ms):
        """原子回退到历史保留的配置修订，返回 LF 尾紧凑 JSON。

        key 沿用凭据约束；target/expected/now_ms 须为非 bool 非负 int，类型
        错抛 TypeError，负值抛 ValueError。验参后先比较 expected 与当前修订
        号：不等抛 StateError(expected, current)，不查目标；target >= expected
        抛 ValueError；目标修订未保留（构造态修订 0 初始在册，窗口满后亦可
        被淘汰；在册的为最近 256 项）抛 KeyError(target)。目标快照按 load_config 的承载规则原子
        加载：承载冲突抛 ResourceError。成功后覆盖唯一回滚点（记回退前配置）、
        生成并保存新修订（修订号在当前值上加 1，沿用既有递增规则；历史保留
        最近 256 项，超限淘汰最旧项且不淘汰当前项），返回键序/型
        “修订:int、目标:int、前摘要:str、后摘要:str”的 JSON，两摘要同
        config_revision 定义（分别为提交前、后的配置摘要）。失败不改配置、
        历史、回滚点与运行态。

        重放缓存与各域独立且仅缓存首次成功：同型同参重放不再比较修订号、
        不查目标、不加载，原样返回首次字节；异参抛 ValueError；任何失败
        （含参数错、修订不符、目标未保留与承载冲突）不占 key 且不改实例。
        本接口不审计。首次成功另向防篡改配置历史追加“回退”记录（目标取
        target、父修订取前一修订），失败与同参重放不追加。首次
        O(n log n + S + Q) 时间、O(n) 空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._config_revert_cache.get(key)
        if cached is not None:
            # 重放：不比较修订号、不查目标、不加载，仅核对同型同参后返回
            # 原字节。
            c_target, c_expected, c_now_ms, result = cached
            if not _strict_equal(
                (target, expected, now_ms),
                (c_target, c_expected, c_now_ms),
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        # 类型阶段：按 target、expected、now_ms 声明顺序，任一类型错先于
        # 任何值错抛出。
        if isinstance(target, bool) or not isinstance(target, int):
            raise TypeError(
                f"target must be an int, got {type(target).__name__}"
            )
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise TypeError(
                f"expected must be an int, got {type(expected).__name__}"
            )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值阶段：三个参数均非负，按同一声明顺序。
        if target < 0:
            raise ValueError(f"target must be >= 0, got {target}")
        if expected < 0:
            raise ValueError(f"expected must be >= 0, got {expected}")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")

        # 先比修订号，不符不得查目标；失败不占 key、不改实例。
        if expected != self._revision:
            raise StateError(expected, self._revision)
        if target >= expected:
            raise ValueError(
                f"target must be < expected {expected}, got {target}"
            )
        spec = self._config_history.get(target)
        if spec is None:
            raise KeyError(target)

        # 按 load_config 承载规则原子加载目标快照：承载冲突 ResourceError，
        # _build_pools 不改状态，故失败配置、历史、回滚点与运行态均不变。
        # 成功以“回退”操作提交并携带 target（记录目标取 target）。
        before = self._config_summary()
        new_pools = self._build_pools(spec)
        self._commit_config(
            spec, new_pools, self._current_spec(),
            _CONFIG_HISTORY_OP_REVERT, target,
        )
        after = self._config_summary()
        payload = {
            "修订": self._revision,
            "目标": target,
            "前摘要": before,
            "后摘要": after,
        }
        result = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self._config_revert_cache[key] = (target, expected, now_ms, result)
        return result

    def config_change(self, key, op, text, now_ms):
        """配置加载/回滚/升级的幂等事务入口，原样返回各业务接口的 LF 尾 JSON。

        依次校验：key 沿用凭据约束；op 须为非 bool str 且仅“加载/回滚/升级”；
        加载与升级时 text 须为 str，回滚时 text 须为 None；now_ms 须为非 bool
        非负 int。类型错抛 TypeError，op 非三值、now_ms 为负或升级文本的
        JSON/重键/键集/结构/值/引用/版本非法均抛 ValueError，校验顺序沿基线。
        key 有效后以独立域永久缓存余参与首果（含参数异常）：严格同型同参重放
        不预检，直接返回原字节或重抛同类同 args；异参抛 ValueError；参数错也
        缓存但不审计。

        首次合法调用分别执行既有 load_config(text)/rollback_config()/
        upgrade_config(text, 10)：成功原样返回其 JSON；加载时配置非法抛
        ValueError、承载冲突抛 ResourceError、无回滚点抛 StateError，升级只读
        （不触碰配置、运行态与回滚点），异常类型与 args 一并缓存。除缓存、
        审计外，失败不得改变配置、回滚点、用户、会话、租约、队列、统计或故障态。

        首次业务结果（成功或异常）与同参重放均向既有防篡改审计哈希链追加
        一项：操作为“配置加载/配置回滚/配置升级”，会话记空串；首次原序号 0，
        结果为“成功”或异常实际类名；重放原序号指认首次事件，结果为“重放成功”
        或“重放”加异常类名，并返回或重抛首果。异参不审计。首次升级沿
        upgrade_config 的 O(n log n) 时/O(n) 空，重放 O(1) 时空。
        """
        _check_credential("key", key)

        cached = self._config_change_cache.get(key)
        if cached is not None:
            # 重放：不加载、不回滚、不升级、不老化、不改任何状态，仅按缓存
            # 返回或重抛。
            c_op, c_text, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, text, now_ms), (c_op, c_text, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 首次业务结果（成功/异常）的同参重放入链记“重放成功”或“重放”
            # 加异常类名，原序号指认首次事件；参数错不在本域链索引中，自然跳过。
            origin = self._config_change_chain_index.get(key)
            if origin is not None:
                if outcome[0] == "ok":
                    chain_result = "重放成功"
                else:
                    chain_result = "重放" + outcome[1][0].__name__
                self._chain_append(
                    key,
                    _CONFIG_CHAIN_OP[c_op],
                    "",
                    chain_result,
                    now_ms,
                    origin,
                    self._config_change_chain_index,
                )
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise _replay_exception(exc_class, exc_args)

        # 新 key：余参校验本身的异常同样入缓存但不审计；校验失败不改任何状态。
        try:
            self._validate_config_change_params(op, text, now_ms)
        except (TypeError, ValueError) as exc:
            self._config_change_cache[key] = (
                op,
                text,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 首次合法调用：执行加载/回滚/升级；业务异常（ValueError/
        # ResourceError/StateError，升级仅 ValueError）缓存类型与 args 并入链，
        # 不改配置与运行态（升级本就只读）。
        chain_op = _CONFIG_CHAIN_OP[op]
        try:
            if op == _CONFIG_OP_LOAD:
                result = self.load_config(text)
            elif op == _CONFIG_OP_UPGRADE:
                result = self.upgrade_config(text, _CONFIG_VERSION)
            else:
                result = self.rollback_config()
        except (ValueError, ResourceError, StateError) as exc:
            self._config_change_cache[key] = (
                op,
                text,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            self._chain_append(
                key,
                chain_op,
                "",
                type(exc).__name__,
                now_ms,
                index=self._config_change_chain_index,
            )
            raise
        self._config_change_cache[key] = (
            op,
            text,
            now_ms,
            ("ok", result),
        )
        self._chain_append(
            key,
            chain_op,
            "",
            "成功",
            now_ms,
            index=self._config_change_chain_index,
        )
        return result

    @staticmethod
    def _validate_config_change_params(op, text, now_ms):
        """校验 config_change 三参数（key 已由调用方校验）：类型错先于值错。

        op 限加载/回滚/升级；加载与升级 text 须为 str，回滚 text 须为 None
        （任何非 None 皆值错）；now_ms 为非 bool 非负 int。加载文本的内容
        合法性由 load_config 复核、升级文本由 upgrade_config 复核（空串等在此
        仅视为 str，业务失败归 ValueError）。
        """
        # 类型阶段：任一类型错先于任何值/模式错抛出。
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op in (_CONFIG_OP_LOAD, _CONFIG_OP_UPGRADE) and not isinstance(
            text, str
        ):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值/模式阶段。
        if op not in (_CONFIG_OP_LOAD, _CONFIG_OP_ROLLBACK, _CONFIG_OP_UPGRADE):
            raise ValueError(
                f"op must be one of 加载/回滚/升级, got {op!r}"
            )
        if op == _CONFIG_OP_ROLLBACK and text is not None:
            raise ValueError(f"text must be None for 回滚, got {text!r}")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")

    def credential_change(self, key, user, old_password, new_password, now_ms):
        """轮换用户密码，返回 LF 结尾的紧凑 JSON（键序 用户/时刻/结果，
        结果恒为“已轮换”）。

        key/user/old_password/new_password 均沿用凭据约束（str、UTF-8 编码
        1..256 字节、无 U+0000），now_ms 为非 bool 非负 int；类型错抛
        TypeError，取值错抛 ValueError，旧新密码相同抛 ValueError，未知用户
        抛 KeyError。首次合法调用先经 Authenticator 校验旧密码：denied/
        locked 抛 AuthError，失败计数与锁定由 Authenticator 保留；成功按
        sha256(user+"\\0"+password) 摘要规则换密并清零失败计数与锁定。除缓存、
        审计与认证副作用外，失败不改其他状态；成功保留会话与已入队队项，此后
        仅新密码可认证。

        验 key 后以独立域永久缓存余参与首果（含参数异常）：同型同参重放不
        认证、不换密，原样返回或重抛同类同 args 的异常；异参抛 ValueError 且
        不审计。参数错不审计；首果（成功/AuthError/KeyError）及同参重放写
        现有防篡改审计链：操作“凭据轮换”、会话记 user，首次结果为“成功”/
        异常类名、原序号 0，重放结果加“重放”前缀且原序号指认首次事件。
        O(1) 时空（凭据长度有界）。
        """
        _check_credential("key", key)

        cached = self._credential_change_cache.get(key)
        if cached is not None:
            # 重放：不认证、不换密、不改其他状态，仅按缓存返回或重抛。
            c_user, c_old, c_new, c_now_ms, outcome = cached
            if not _strict_equal(
                (user, old_password, new_password, now_ms),
                (c_user, c_old, c_new, c_now_ms),
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 首次业务结果（成功/AuthError/KeyError）的同参重放入链，结果加
            # “重放”前缀，原序号指认首次事件；参数错不在本域链索引中，自然跳过。
            origin = self._credential_change_chain_index.get(key)
            if origin is not None:
                if outcome[0] == "ok":
                    chain_result = "重放成功"
                else:
                    chain_result = "重放" + outcome[1][0].__name__
                self._chain_append(
                    key,
                    _CREDENTIAL_OP,
                    c_user,
                    chain_result,
                    now_ms,
                    origin,
                    self._credential_change_chain_index,
                )
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise _replay_exception(exc_class, exc_args)

        # 新 key：余参校验本身的异常同样入缓存但不审计；校验失败不改任何状态。
        try:
            self._validate_credential_change_params(
                user, old_password, new_password, now_ms
            )
        except (TypeError, ValueError) as exc:
            self._credential_change_cache[key] = (
                user,
                old_password,
                new_password,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 首次合法：停用态用户先于认证拒绝（保留失败计数与锁定，不换密）。
        if user in self._disabled_users:
            exc = AuthError(f"user {user!r} is disabled")
            self._credential_change_cache[key] = (
                user,
                old_password,
                new_password,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            self._chain_append(
                key,
                _CREDENTIAL_OP,
                user,
                type(exc).__name__,
                now_ms,
                index=self._credential_change_chain_index,
            )
            raise exc

        # 首次合法：先用 Authenticator 校验旧密码；未知用户由其抛 KeyError。
        try:
            _, status, _ = self._auth.authenticate(user, old_password, now_ms)
        except KeyError as exc:
            self._credential_change_cache[key] = (
                user,
                old_password,
                new_password,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            self._chain_append(
                key,
                _CREDENTIAL_OP,
                user,
                type(exc).__name__,
                now_ms,
                index=self._credential_change_chain_index,
            )
            raise
        if status != "ok":
            # denied/locked/backoff：失败计数、锁定与下次可试时刻已由
            # Authenticator 保留，此处不改。
            exc = AuthError(
                f"authentication not ok for user {user!r}: {status}"
            )
            self._credential_change_cache[key] = (
                user,
                old_password,
                new_password,
                now_ms,
                ("err", (type(exc), exc.args)),
            )
            self._chain_append(
                key,
                _CREDENTIAL_OP,
                user,
                type(exc).__name__,
                now_ms,
                index=self._credential_change_chain_index,
            )
            raise exc

        # 成功：按摘要规则换密并清零失败计数、锁定与下次可试时刻；会话与已
        # 入队队项保持不变。
        record = self._auth._users[user]
        record[0] = _digest(user, new_password)
        record[1] = 0
        record[2] = None
        record[3] = 0
        result = self._render_credential_change(user, now_ms)
        self._credential_change_cache[key] = (
            user,
            old_password,
            new_password,
            now_ms,
            ("ok", result),
        )
        self._chain_append(
            key,
            _CREDENTIAL_OP,
            user,
            "成功",
            now_ms,
            index=self._credential_change_chain_index,
        )
        return result

    @staticmethod
    def _validate_credential_change_params(user, old_password, new_password, now_ms):
        """校验 credential_change 的余参（key 已由调用方校验）：类型错先于值错。

        三个串均沿用凭据约束，旧新相同为值错；now_ms 为非 bool 非负 int。
        """
        # 类型阶段：任一类型错先于任何取值错抛出。
        if not isinstance(user, str):
            raise TypeError(f"user must be a str, got {type(user).__name__}")
        if not isinstance(old_password, str):
            raise TypeError(
                f"old_password must be a str, got {type(old_password).__name__}"
            )
        if not isinstance(new_password, str):
            raise TypeError(
                f"new_password must be a str, got {type(new_password).__name__}"
            )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值阶段。
        _check_credential("user", user)
        _check_credential("old_password", old_password)
        _check_credential("new_password", new_password)
        if old_password == new_password:
            raise ValueError("old_password and new_password must be different")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")

    @staticmethod
    def _render_credential_change(user, now_ms):
        # 键序：用户、时刻、结果；用户/结果为 str，时刻为 int。
        payload = {"用户": user, "时刻": now_ms, "结果": _CREDENTIAL_ROTATED}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def batch_credential_change(self, key, items, now_ms, atomic=False):
        """一次轮换多个用户的凭据，返回 LF 结尾的紧凑 JSON 字符串。

        key 沿用凭据约束；items 为含 1..1000 个
        (user, old_password, new_password) 三元组 tuple 的 tuple，三个串均
        沿用凭据约束、旧新口令不同，且同一用户不得重复；now_ms 为非 bool
        非负 int，atomic 为 bool。容器、元素或字段类型不符抛 TypeError；
        数量、形态、重复用户、凭据取值（含旧新相同）或负时刻抛 ValueError。
        整批参数错误不认证、不改状态、不占用幂等键、不写审计；同 key 此后以
        合法参数首调仍按首次处理。key 有效后以独立域永久缓存合法首果：同型
        同参重放逐字节返回首果、不再认证或轮换，异参复用抛 ValueError。

        合法批次逐项沿用 credential_change 的停用检查与旧口令认证语义：
        停用先于认证拒（AuthError，不认证）；未知用户记 KeyError；停用、
        口令错误、锁定或退避记 AuthError；业务失败写入项目结果而不从批量
        入口抛出。仅验证成功才切换新凭据并清零该用户的失败次数、锁定截止
        与下次可试时刻。非原子模式逐项依序提交成功项，失败项不影响后项；
        原子模式按输入顺序校验全部项目（前项失败不阻止后项判定），全部成功
        才一次提交切换，任一失败则所有可成功项标为“回滚”且全部凭据保持
        批次前值，但认证产生的失败计数、锁定、退避及成功验证造成的限制清零
        均保留。两种模式都不老化，且不改变会话、租约、容量队列、QoS 账本
        或停用状态。合法首调与同参重放均按输入序逐项写独立的批量防篡改
        审计链 batch_audit（操作“批量凭据轮换”，会话字段取用户名）：首调
        逐项结果取项目结果（轮换/回滚/异常类名）、原序号 0；重放逐项记
        “重放”、原序号指认对应首次事件；不写单操作 audit 链。返回顶层
        键序“时刻/原子/结果/项目”：结果仅成功（全部轮换）、部分成功
        （非原子有成功有失败）、失败（非原子全失败）、回滚（原子有失败）；
        项目保持输入顺序，项键序“用户/结果”，项结果仅轮换/回滚/实际
        异常类名。单批 O(B) 时间与 O(B) 辅助空间（B ≤ 1000），重放 O(B)。
        """
        _check_credential("key", key)

        cached = self._batch_credential_change_cache.get(key)
        if cached is not None:
            # 重放：不认证、不轮换、不改态；合法首果的同参重放按输入序逐项
            # 记“重放”，原序号指认对应首次事件。
            c_items, c_now_ms, c_atomic, c_output = cached
            if not _strict_equal(
                (items, now_ms, atomic), (c_items, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            origin = self._batch_credential_chain_index.get(key)
            if origin is not None:
                self._batch_chain_record(
                    key,
                    _BATCH_AUDIT_CREDENTIAL,
                    [entry[0] for entry in c_items],
                    c_atomic,
                    now_ms,
                    origin,
                    self._batch_credential_chain_index,
                )
            return c_output

        # 新 key：余参校验失败不占幂等键、不认证、不改态、不审计。
        self._validate_batch_credential_change_params(items, now_ms, atomic)

        if atomic:
            results, all_ok = self._batch_credential_atomic(items, now_ms)
        else:
            results, all_ok = self._batch_credential_sequential(items, now_ms)

        if all_ok:
            result = _BATCH_CRED_COMMIT
        elif atomic:
            result = _BATCH_ROLLBACK
        else:
            # 非原子：有成功项为部分成功，全失败为失败。
            any_ok = any(entry["结果"] == _BATCH_ITEM_ROTATE for entry in results)
            result = _BATCH_CRED_PARTIAL if any_ok else _BATCH_CRED_FAILED
        output = self._render_batch_credential(now_ms, atomic, result, results)
        self._batch_credential_change_cache[key] = (items, now_ms, atomic, output)
        # 合法首调：按输入序逐项追加首次事件，会话字段取用户名，结果取各
        # 项目结果（原子回滚后可成功项已为“回滚”）、原序号 0。
        self._batch_chain_record(
            key,
            _BATCH_AUDIT_CREDENTIAL,
            [entry[0] for entry in items],
            atomic,
            now_ms,
            0,
            self._batch_credential_chain_index,
            [entry["结果"] for entry in results],
        )
        return output

    @staticmethod
    def _validate_batch_credential_change_params(items, now_ms, atomic):
        """校验 batch_credential_change 三参数：类型错先于取值/长度/重复错。

        items 须为 tuple，含 1..1000 个 (user, old_password, new_password)
        三元组 tuple，三个串均满足凭据约束且旧新口令不同、user 互异；
        now_ms 为非 bool 非负 int；atomic 为 bool。类型阶段先查容器/各项/
        各字段/now_ms/atomic 的类型；取值阶段依序查各项长度与三串取值
        （含旧新不同）、now_ms 下界、项数上下界、user 重复。
        """
        # 类型阶段：任一类型错先于任何取值错抛出。
        if not isinstance(items, tuple):
            raise TypeError(f"items must be a tuple, got {type(items).__name__}")
        for item in items:
            if not isinstance(item, tuple):
                raise TypeError(
                    f"item must be a tuple, got {type(item).__name__}"
                )
            for field in item:
                if not isinstance(field, str):
                    raise TypeError(
                        f"item field must be a str, got {type(field).__name__}"
                    )
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if not isinstance(atomic, bool):
            raise TypeError(f"atomic must be a bool, got {type(atomic).__name__}")

        # 取值阶段：项长度、凭据值（含旧新不同）、下界、项数、重复用户。
        for item in items:
            if len(item) != 3:
                raise ValueError(
                    "item must be a 3-tuple (user, old_password, new_password), "
                    f"got {len(item)} items"
                )
            _check_credential("user", item[0])
            _check_credential("old_password", item[1])
            _check_credential("new_password", item[2])
            if item[1] == item[2]:
                raise ValueError("old_password and new_password must be different")
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if not (1 <= len(items) <= _BATCH_MAX_SIDS):
            raise ValueError(
                f"items must contain 1..{_BATCH_MAX_SIDS} items, got {len(items)}"
            )
        users = [item[0] for item in items]
        if len(set(users)) != len(users):
            raise ValueError("items must not contain duplicate user")

    def _batch_credential_rotate(self, user, old_password, new_password, now_ms):
        """批内单项轮换：规则同 credential_change 核心路径。

        停用态先于认证拒绝（AuthError，不认证、不增失败计数）；随后由
        Authenticator 校验旧口令，未知用户抛 KeyError，denied/locked/
        backoff 抛 AuthError（失败计数、锁定与退避由认证器保留）。仅验证
        成功才按摘要规则换密并清零失败计数、锁定截止与下次可试时刻。无
        返回值；失败不改凭据。
        """
        if user in self._disabled_users:
            raise AuthError(f"user {user!r} is disabled")
        _, status, _ = self._auth.authenticate(user, old_password, now_ms)
        if status != "ok":
            # denied/locked/backoff：失败计数、锁定与下次可试时刻已由
            # Authenticator 保留，此处不改。
            raise AuthError(
                f"authentication not ok for user {user!r}: {status}"
            )
        record = self._auth._users[user]
        record[0] = _digest(user, new_password)
        record[1] = 0
        record[2] = None
        record[3] = 0

    def _batch_credential_sequential(self, items, now_ms):
        """非原子逐项轮换，逐项依序提交：失败项不影响后项。

        业务异常（AuthError/KeyError）不抛：项结果记异常类名。返回
        (results, all_ok)。
        """
        results = []
        for user, old_password, new_password in items:
            try:
                self._batch_credential_rotate(
                    user, old_password, new_password, now_ms
                )
            except (AuthError, KeyError) as exc:
                results.append({"用户": user, "结果": type(exc).__name__})
            else:
                results.append({"用户": user, "结果": _BATCH_ITEM_ROTATE})
        all_ok = all(entry["结果"] == _BATCH_ITEM_ROTATE for entry in results)
        return results, all_ok

    def _batch_credential_atomic(self, items, now_ms):
        """原子批量凭据轮换：先校验全部项，全部成功才一次提交。

        按输入顺序对每项做停用检查与旧口令认证但不即刻换密：前项失败不
        阻止后项判定，失败项记自身异常类名；成功验证的清零（失败次数、
        锁定截止、下次可试时刻）即刻生效并保留。每个验证成功项记下
        (user, 批次前摘要)。全部成功才统一切换为新摘要（唯一提交点）；
        任一失败则全部凭据恢复批次前摘要，可成功项改记“回滚”，而认证
        产生的失败计数、锁定、退避与成功验证造成的清零均保留。返回
        (results, all_ok)。
        """
        results = []
        # 验证成功项的反向信息：(user, 批次前摘要)；用户在批内互异。
        undo = []
        all_ok = True
        for user, old_password, new_password in items:
            if user in self._disabled_users:
                results.append({"用户": user, "结果": AuthError.__name__})
                all_ok = False
                continue
            try:
                _, status, _ = self._auth.authenticate(user, old_password, now_ms)
            except KeyError:
                results.append({"用户": user, "结果": KeyError.__name__})
                all_ok = False
                continue
            if status != "ok":
                # 认证副作用（失败计数、锁定、退避）保留，不换密。
                results.append({"用户": user, "结果": AuthError.__name__})
                all_ok = False
                continue
            record = self._auth._users[user]
            undo.append((user, record[0], new_password))
            results.append({"用户": user, "结果": _BATCH_ITEM_ROTATE})

        if all_ok:
            # 全部成功才一次提交：认证器已清零各成功用户的限制，此处仅切换
            # 摘要。
            for user, _old_digest, new_password in undo:
                self._auth._users[user][0] = _digest(user, new_password)
        else:
            # 任一失败：全部凭据保持批次前值，可成功项改记“回滚”；限制
            # 清零与认证失败副作用均保留，不回滚。
            for user, old_digest, _new_password in undo:
                self._auth._users[user][0] = old_digest
            for entry in results:
                if entry["结果"] == _BATCH_ITEM_ROTATE:
                    entry["结果"] = _BATCH_ROLLBACK
        return results, all_ok

    @staticmethod
    def _render_batch_credential(now_ms, atomic, result, items):
        # 顶层键序：时刻、原子、结果、项目；时刻为 int，原子为 bool，
        # 结果为 str，项目为项（用户/结果）列表，依输入顺序。
        payload = {
            "时刻": now_ms,
            "原子": atomic,
            "结果": result,
            "项目": items,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def user_admin(self, key, op, user, now_ms, force=False):
        """停用或启用用户，返回 LF 结尾的紧凑 JSON。

        key/user 沿用凭据约束；op 仅“停用/启用”；now_ms 为非 bool 非负
        int；force 为 bool。类型错抛 TypeError、取值错抛 ValueError，未知
        用户抛 KeyError；启用限 force=False（force=True 为值错）。

        停用：该用户存在非下线（在线/挂起）会话或排队队项且 force=False
        时抛 StateError，状态不变；force=True 原子下线其全部非下线会话
        （期限清零、释放地址租约）并删除其全部排队队项（不记 capacity
        事件），无容量事件。失败不改任何状态。启用无副作用，恢复其正常
        认证与操作。停用后 do 建立/迁移/接管、capacity 申请、batch_online
        及 credential_change 均先于后端检查与认证拒绝：单项抛 AuthError，
        批量项结果记 AuthError，锁定、退避与失败计数不变；启用后恢复。

        返回键序“用户/状态/时刻/下线/取消”：状态仅停用/启用，下线为本次
        停用强制下线的非下线会话数，取消为删除的排队队项数（启用二者恒 0，
        同态成功亦为 0）。验 key 后以独立域永久缓存余参与首果（含参数
        异常）：同型同参重放不改态、直接返回或重抛，异参抛 ValueError。
        首果（成功）及成功的同参重放写现有防篡改审计链：操作“用户停用/用户
        启用”、会话记 user，首次原序号 0、结果“成功”，重放原序号指认首次、
        结果“重放”；参数错与 StateError/KeyError 等业务异常不审计。
        首次 O(S+Q) 时间、O(1) 辅助空间，重放 O(1)。
        """
        _check_credential("key", key)

        cached = self._user_admin_cache.get(key)
        if cached is not None:
            # 重放：不改停用态，仅按缓存返回或重抛。
            c_op, c_user, c_now_ms, c_force, outcome = cached
            if not _strict_equal(
                (op, user, now_ms, force), (c_op, c_user, c_now_ms, c_force)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 仅首次成功的同参重放入链记“重放”，原序号沿用首次；
            # 首次异常不在本域链索引中，自然跳过。
            origin = self._user_admin_chain_index.get(key)
            if origin is not None:
                chain_op = (
                    _ADMIN_CHAIN_DISABLE if c_op == _ADMIN_OP_DISABLE
                    else _ADMIN_CHAIN_ENABLE
                )
                self._chain_append(
                    key,
                    chain_op,
                    c_user,
                    "重放",
                    now_ms,
                    origin,
                    self._user_admin_chain_index,
                )
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise _replay_exception(exc_class, exc_args)

        # 新 key：余参校验本身的异常同样入缓存但不审计；校验失败不改任何状态。
        try:
            self._validate_user_admin_params(op, user, now_ms, force)
        except (TypeError, ValueError) as exc:
            self._user_admin_cache[key] = (
                op,
                user,
                now_ms,
                force,
                ("err", (type(exc), exc.args)),
            )
            raise

        # 类型、值校验全过后方查用户存在：未知用户 KeyError（业务失败，缓存、
        # 不审计、不改态）。
        if user not in self._auth:
            exc = KeyError(f"unknown user: {user!r}")
            self._user_admin_cache[key] = (
                op,
                user,
                now_ms,
                force,
                ("err", (type(exc), exc.args)),
            )
            raise exc

        if op == _ADMIN_OP_ENABLE:
            # 启用无副作用；同态（本就启用）成功，下线/取消恒 0。
            self._disabled_users.discard(user)
            offline = 0
            cancelled = 0
            status = _ADMIN_ENABLED
            chain_op = _ADMIN_CHAIN_ENABLE
        else:
            if not force:
                # 先探测在途项（不随扫描改态）：存在任一非下线会话或排队队项
                # 即拒，O(S+Q) 时间、O(1) 辅助空间。
                blocked = False
                for session in self._sessions.values():
                    if (
                        session["user"] == user
                        and session["state"] != _STATE_OFFLINE
                    ):
                        blocked = True
                        break
                if not blocked:
                    for queued_sid in self._queue_order:
                        if self._capacity_queue[queued_sid][0] == user:
                            blocked = True
                            break
                if blocked:
                    exc = StateError(
                        "cannot disable user "
                        f"{user!r} with active sessions or queued items"
                    )
                    self._user_admin_cache[key] = (
                        op,
                        user,
                        now_ms,
                        force,
                        ("err", (type(exc), exc.args)),
                    )
                    raise exc
                offline = 0
                cancelled = 0
            else:
                # force=True：原子下线该用户全部非下线会话（清期限、释址退租），
                # 再原地压缩队列、删除其全部排队队项；不记 capacity 事件、不老化。
                # 仅改会话项与池租约值、不动会话表键，遍历中修改安全；O(S+Q)
                # 时间、O(1) 辅助空间。下线墓碑不重复下线。
                offline = 0
                for force_sid, session in self._sessions.items():
                    if (
                        session["user"] == user
                        and session["state"] != _STATE_OFFLINE
                    ):
                        # 计费停止（停用）须在清场前结账，按会话表迭代序。
                        self._account_stop(
                            force_sid, now_ms, _ACCOUNT_REASON_DISABLE
                        )
                        session["state"] = _STATE_OFFLINE
                        session["deadline"] = 0
                        self._release(session)
                        offline += 1
                cancelled = 0
                write = 0
                for queued_sid in self._queue_order:
                    if self._capacity_queue[queued_sid][0] == user:
                        del self._capacity_queue[queued_sid]
                        cancelled += 1
                    else:
                        self._queue_order[write] = queued_sid
                        write += 1
                del self._queue_order[write:]
            self._disabled_users.add(user)
            status = _ADMIN_DISABLED
            chain_op = _ADMIN_CHAIN_DISABLE

        result = self._render_user_admin(user, status, now_ms, offline, cancelled)
        self._user_admin_cache[key] = (
            op,
            user,
            now_ms,
            force,
            ("ok", result),
        )
        self._chain_append(
            key,
            chain_op,
            user,
            "成功",
            now_ms,
            index=self._user_admin_chain_index,
        )
        return result

    @staticmethod
    def _validate_user_admin_params(op, user, now_ms, force):
        """校验 user_admin 的余参（key 已由调用方校验）：类型错先于值错。

        op 限停用/启用；user 为凭据约束串；now_ms 为非 bool 非负 int；
        force 为 bool，且启用仅允许 force=False。
        """
        # 类型阶段：任一类型错先于任何取值错抛出。
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if not isinstance(user, str):
            raise TypeError(f"user must be a str, got {type(user).__name__}")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if not isinstance(force, bool):
            raise TypeError(f"force must be a bool, got {type(force).__name__}")

        # 取值阶段。
        if op not in (_ADMIN_OP_DISABLE, _ADMIN_OP_ENABLE):
            raise ValueError(f"op must be one of 停用/启用, got {op!r}")
        _check_credential("user", user)
        if now_ms < 0:
            raise ValueError(f"now_ms must be >= 0, got {now_ms}")
        if op == _ADMIN_OP_ENABLE and force:
            raise ValueError("force must be False for 启用")

    @staticmethod
    def _render_user_admin(user, status, now_ms, offline, cancelled):
        # 键序：用户、状态、时刻、下线、取消；用户/状态为 str，余为 int。
        payload = {
            "用户": user,
            "状态": status,
            "时刻": now_ms,
            "下线": offline,
            "取消": cancelled,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _audit_append(self, key, old, sid, result, now_ms, origin=0):
        """追加一条接管审计事件，O(1) 时空。

        序号自 1 递增（即事件在序列中的位置）；首次事件登记 key -> 序号且
        原序号为 0，重放事件原序号指认首次事件序号。
        """
        seq = len(self._audit_events) + 1
        if origin == 0:
            self._audit_index[key] = seq
        self._audit_events.append((seq, now_ms, key, old, sid, result, origin))

    def takeover_audit(self, after=0, limit=100):
        """返回接管审计事件 JSON；查询不老化，O(limit) 时空。

        取序号 > after 的前 limit 项。after/limit 须为非 bool 的 int：类型不符
        TypeError，after<0 或 limit ∉ [1,1000] 抛 ValueError。顶层键序为
        “下个序号/事件”；事件键序为“序号/时刻/键/旧会话/新会话/结果/原序号”。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        # 序号即位置+1，序号 > after 的事件自下标 after 起，直接切片。
        window = self._audit_events[after : after + limit]
        events = [
            {
                "序号": seq,
                "时刻": now_ms,
                "键": key,
                "旧会话": old,
                "新会话": sid,
                "结果": result,
                "原序号": origin,
            }
            for seq, now_ms, key, old, sid, result, origin in window
        ]
        # 有项取下一序号为末项序号，无项取 after。
        next_seq = window[-1][0] if window else after
        payload = {"下个序号": next_seq, "事件": events}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _chain_hash(seq, now_ms, key, op, sid, result, origin, prev_hash):
        """由前八字段（键序固定）的紧凑 JSON 之 UTF-8 字节算 sha256 十六进制串。"""
        head = {
            "序号": seq,
            "时刻": now_ms,
            "键": key,
            "操作": op,
            "会话": sid,
            "结果": result,
            "原序号": origin,
            "前哈希": prev_hash,
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _chain_append(self, key, op, sid, result, now_ms, origin=0, index=None):
        """追加一条防篡改审计事件，O(1) 时空。

        序号自 1 递增；首次事件登记 key -> 序号且原序号为 0，重放事件沿用
        首次结果、原序号指认首次事件序号。前哈希首项为 64 个 0，余取前项哈希。
        index 给定时写入该域的 key -> 首次序号索引（供 pool_fault 与 do 分域
        指认），缺省用 do 的 _chain_index；事件始终追加到同一条链。
        """
        if index is None:
            index = self._chain_index
        seq = len(self._chain_events) + 1
        prev_hash = self._chain_tail
        digest = self._chain_hash(
            seq, now_ms, key, op, sid, result, origin, prev_hash
        )
        if origin == 0:
            index[key] = seq
        event = (seq, now_ms, key, op, sid, result, origin, prev_hash, digest)
        self._chain_events.append(event)
        self._chain_tail = digest
        # 源事件与其合规投影原子追加（同序）：audit_restore 的 extend 不经过
        # 本入口，故导入历史不会回灌全局链。
        self._compliance_append_audit(event)

    # -- 合规全局链 ------------------------------------------------------

    def _compliance_append(self, source, source_seq, payload):
        """按追加先后向合规全局链投影一条源事件，O(1) 时空。

        全局序号自 1 连续，不按可能回拨的时刻重排；前哈希首项为 64 个 0，
        余取前项哈希；哈希覆盖前五字段（全局序号/来源/来源序号/载荷/
        前哈希）以既有键序生成的紧凑 JSON 之 UTF-8 字节 sha256 小写值。
        """
        global_seq = len(self._compliance_events) + 1
        prev_hash = self._compliance_tail
        head = {
            "全局序号": global_seq,
            "来源": source,
            "来源序号": source_seq,
            "载荷": payload,
            "前哈希": prev_hash,
        }
        digest_hash = hashlib.sha256(
            json.dumps(head, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self._compliance_events.append(
            (global_seq, source, source_seq, payload, prev_hash, digest_hash)
        )
        self._compliance_tail = digest_hash

    def _compliance_audit_payload(self, event):
        """审计九元组 -> audit 公开事件九键紧凑 JSON 字符串（无 LF）。"""
        seq, now_ms, key, op, sid, result, origin, prev_hash, digest = event
        row = {
            "序号": seq,
            "时刻": now_ms,
            "键": key,
            "操作": op,
            "会话": sid,
            "结果": result,
            "原序号": origin,
            "前哈希": prev_hash,
            "哈希": digest,
        }
        return json.dumps(row, ensure_ascii=False, separators=(",", ":"))

    def _compliance_batch_payload(self, event):
        """批量十元组 -> batch_audit 公开事件十键紧凑 JSON 字符串（无 LF）。"""
        (seq, now_ms, key, op, atomic, sid, result, origin,
         prev_hash, digest) = event
        row = {
            "序号": seq,
            "时刻": now_ms,
            "键": key,
            "操作": op,
            "原子": atomic,
            "会话": sid,
            "结果": result,
            "原序号": origin,
            "前哈希": prev_hash,
            "哈希": digest,
        }
        return json.dumps(row, ensure_ascii=False, separators=(",", ":"))

    def _compliance_capacity_payload(self, event):
        """容量七元组 -> capacity_events 公开事件五键紧凑 JSON 字符串。"""
        seq, now_ms, sid, verdict, order, _prev_hash, _digest = event
        row = {
            "序号": seq,
            "时刻": now_ms,
            "会话": sid,
            "结果": verdict,
            "入队序": order,
        }
        return json.dumps(row, ensure_ascii=False, separators=(",", ":"))

    def _compliance_append_audit(self, event):
        self._compliance_append(
            _COMPLIANCE_SOURCE_AUDIT, event[0], self._compliance_audit_payload(event)
        )

    def _compliance_append_batch(self, event):
        self._compliance_append(
            _COMPLIANCE_SOURCE_BATCH, event[0], self._compliance_batch_payload(event)
        )

    def _compliance_append_capacity(self, event):
        self._compliance_append(
            _COMPLIANCE_SOURCE_CAPACITY,
            event[0],
            self._compliance_capacity_payload(event),
        )

    def audit(self, after=0, limit=100):
        """返回防篡改审计事件 JSON；查询不老化，O(limit) 时空。

        取序号 > after 的前 limit 项。after/limit 须为非 bool 的 int：类型不符
        TypeError，after<0 或 limit ∉ [1,1000] 抛 ValueError。顶层键序为
        “下个序号/事件”，游标为末项序号、无项为 after；事件键序为
        “序号/时刻/键/操作/会话/结果/原序号/前哈希/哈希”，序号/时刻/原序号
        为 int，余为 str。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")

        # 序号即位置+1，序号 > after 的事件自下标 after 起，直接切片。
        window = self._chain_events[after : after + limit]
        events = [
            {
                "序号": seq,
                "时刻": now_ms,
                "键": key,
                "操作": op,
                "会话": sid,
                "结果": result,
                "原序号": origin,
                "前哈希": prev_hash,
                "哈希": digest,
            }
            for seq, now_ms, key, op, sid, result, origin, prev_hash, digest in window
        ]
        # 有项取下一序号为末项序号，无项取 after。
        next_seq = window[-1][0] if window else after
        payload = {"下个序号": next_seq, "事件": events}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def verify_audit(self):
        """校验审计链序号连续、前哈希衔接、哈希无误；空链为 True。

        O(N) 时间、O(1) 空间：逐项重算，不另建序列。
        """
        prev_hash = "0" * 64
        for expect, event in enumerate(self._chain_events, start=1):
            seq, now_ms, key, op, sid, result, origin, stored_prev, digest = event
            if seq != expect or stored_prev != prev_hash:
                return False
            if (
                self._chain_hash(
                    seq, now_ms, key, op, sid, result, origin, stored_prev
                )
                != digest
            ):
                return False
            prev_hash = digest
        return True

    def audit_snapshot(self, after=0, limit=100):
        """返回审计窗口快照 JSON；只读、查询不老化，O(limit) 时空。

        取序号 > after 的前 limit 项。after/limit 须为非 bool 的 int：类型不符
        抛 TypeError，after<0 或 limit ∉ [1,1000] 抛 ValueError；after 大于末
        序号（空链为 0）抛 KeyError(after)。顶层键序为
        “版本/锚序号/锚哈希/上限/下个序号/事件/摘要”：版本恒 1，锚序号=after，
        after=0 时锚哈希为 64 个 0、否则取第 after 项哈希，上限=limit，下个序号
        取末项序号、空窗取 after；事件复用 audit 九键序及类型。摘要为前六键
        紧凑 JSON（ensure_ascii=False、无空白）UTF-8 字节的 sha256 小写值，
        输出末尾加 LF。
        """
        _check_int("after", after, 0)
        _check_int("limit", limit, 1)
        if limit > 1000:
            raise ValueError(f"limit must be <= 1000, got {limit}")
        total = len(self._chain_events)
        if after > total:
            raise KeyError(after)

        # 序号即位置+1：锚哈希取第 after 项（下标 after-1），窗口自下标 after 起。
        anchor_hash = "0" * 64 if after == 0 else self._chain_events[after - 1][8]
        window = self._chain_events[after : after + limit]
        events = [
            {
                "序号": seq,
                "时刻": now_ms,
                "键": key,
                "操作": op,
                "会话": sid,
                "结果": result,
                "原序号": origin,
                "前哈希": prev_hash,
                "哈希": digest,
            }
            for seq, now_ms, key, op, sid, result, origin, prev_hash, digest in window
        ]
        # 有项取下一序号为末项序号，无项取 after。
        next_seq = window[-1][0] if window else after
        head = {
            "版本": 1,
            "锚序号": after,
            "锚哈希": anchor_hash,
            "上限": limit,
            "下个序号": next_seq,
            "事件": events,
        }
        # 摘要只盖前六键：重排前先对无摘要的头算 sha256，再补末键输出。
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        head["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(head, ensure_ascii=False, separators=(",", ":")) + "\n"

    def verify_audit_snapshot(self, text):
        """校验审计快照文本：结构问题抛 ValueError，与当前 audit 链不符返 False。

        text 非 str 抛 TypeError；JSON 解析、重键、键集/键序、结构、类型、范围
        或版本非法抛 ValueError。结构通过后核对摘要、锚哈希、窗口事件（逐条
        重算哈希链并与当前链比对）与游标：任一与当前 audit 链不符返回 False，
        全部相符（含空窗）返回 True。只读，O(limit) 时空。
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"audit snapshot is not valid JSON: {exc}") from exc
        top_keys = ["版本", "锚序号", "锚哈希", "上限", "下个序号", "事件", "摘要"]
        if not isinstance(doc, dict) or list(doc) != top_keys:
            raise ValueError(
                "audit snapshot top-level keys must be "
                "版本/锚序号/锚哈希/上限/下个序号/事件/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        anchor_seq = self._cp_int(doc["锚序号"], "锚序号", 0)
        anchor_hash = self._cp_hex64(doc["锚哈希"], "锚哈希")
        limit = self._cp_int(doc["上限"], "上限", 1)
        if limit > 1000:
            raise ValueError(f"上限 must be <= 1000, got {limit}")
        next_seq = self._cp_int(doc["下个序号"], "下个序号", 0)
        summary = self._cp_hex64(doc["摘要"], "摘要")

        event_keys = [
            "序号",
            "时刻",
            "键",
            "操作",
            "会话",
            "结果",
            "原序号",
            "前哈希",
            "哈希",
        ]
        raw_events = doc["事件"]
        if not isinstance(raw_events, list):
            raise ValueError("事件 must be a list")
        events = []
        for index, item in enumerate(raw_events, start=1):
            if not isinstance(item, dict) or list(item) != event_keys:
                raise ValueError(
                    f"snapshot event {index} keys must be "
                    "序号/时刻/键/操作/会话/结果/原序号/前哈希/哈希 in order"
                )
            seq = self._cp_int(item["序号"], "事件.序号", 1)
            now_ms = self._cp_int(item["时刻"], "事件.时刻", 0)
            key = item["键"]
            op = item["操作"]
            sid = item["会话"]
            result = item["结果"]
            for label, value in (
                ("事件.键", key),
                ("事件.操作", op),
                ("事件.会话", sid),
                ("事件.结果", result),
            ):
                if not isinstance(value, str):
                    raise ValueError(
                        f"{label} must be a str, got {type(value).__name__}"
                    )
            origin = self._cp_int(item["原序号"], "事件.原序号", 0)
            prev_hash = self._cp_hex64(item["前哈希"], "事件.前哈希")
            digest = self._cp_hex64(item["哈希"], "事件.哈希")
            events.append(
                (seq, now_ms, key, op, sid, result, origin, prev_hash, digest)
            )

        # 摘要：前六键紧凑 JSON 的 UTF-8 sha256；事件子文档沿用解析键序，
        # 紧凑重排与生成端逐字节一致。
        head = {
            "版本": version,
            "锚序号": anchor_seq,
            "锚哈希": anchor_hash,
            "上限": limit,
            "下个序号": next_seq,
            "事件": raw_events,
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            return False

        # 与当前 audit 链核对：锚序号越界、锚哈希、游标、窗口逐项（含哈希链
        # 重算与前哈希衔接）任一不符即 False。
        total = len(self._chain_events)
        if anchor_seq > total:
            return False
        expected_anchor = (
            "0" * 64 if anchor_seq == 0 else self._chain_events[anchor_seq - 1][8]
        )
        if anchor_hash != expected_anchor:
            return False
        window = self._chain_events[anchor_seq : anchor_seq + limit]
        if next_seq != (window[-1][0] if window else anchor_seq):
            return False
        if len(events) != len(window):
            return False
        prev_hash = anchor_hash
        for presented, stored in zip(events, window):
            seq, now_ms, key, op, sid, result, origin, given_prev, given_digest = (
                presented
            )
            if given_prev != prev_hash:
                return False
            if (
                self._chain_hash(
                    seq, now_ms, key, op, sid, result, origin, given_prev
                )
                != given_digest
            ):
                return False
            if presented != stored:
                return False
            prev_hash = given_digest
        return True

    def audit_restore(self, key, text):
        """将版本 1 审计窗口快照分页结果原子接入当前防篡改审计链尾，返回
        LF 结尾紧凑 JSON。

        key 沿用凭据约束（型/值错 TypeError/ValueError），text 须为 str
        （非 str 抛 TypeError）。text 须为版本 1 规范快照：逐层键集/键序与
        类型、事件九键序、范围、事件数不超过上限、序号自锚序号起逐项连续、
        游标等于末项序号（空窗等于锚序号）、原序号非 0 时须小于本项序号、
        事件前哈希衔接且哈希、顶层摘要均须正确，且整体须为与 audit_snapshot
        同法（ensure_ascii=False、separators=(',',':')、单个 LF 结尾）的
        规范编码；解析或重键及以上任一不符抛 ValueError。

        结构全验后核对锚点：当前链末尾须恰等于快照锚序号/锚哈希，否则抛
        StateError(锚序号, 当前末序号) 且不追加。通过后一次性把窗口事件按
        原九元组（含原序号、键、时刻、前哈希/哈希）接到链尾；不恢复会话、
        配置、业务缓存或任何操作幂等（原序号）索引，恢复动作本身不写审计，
        任何失败均不追加。不老化。

        验 key 后以独立缓存域且仅缓存成功：同型同 text 重放不解析、不重验、
        不追加，直接返回首次结果原字节，异参抛 ValueError；失败（含参数错与
        StateError）不占 key。返回键序“追加/末序号/末哈希/摘要”：追加:int、
        末序号:int、末哈希:str，摘要为前三键同法紧凑编码 UTF-8 字节的
        sha256 小写值；空页追加 0。O(limit) 时间、O(limit) 空间。
        """
        _check_credential("key", key)

        cached = self._audit_restore_cache.get(key)
        if cached is not None:
            # 重放：不解析、不重验、不追加，仅核对同型同 text 后返回原字节。
            c_text, result = cached
            if type(text) is not type(c_text) or text != c_text:
                raise ValueError(f"key {key!r} reused with different parameters")
            return result

        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        anchor_seq, anchor_hash, events = self._parse_audit_restore_snapshot(text)

        # 锚点：当前链末尾（空链为序号 0、64 个 0）须恰为快照锚；不符即
        # StateError(锚序号, 当前末序号)，发生在任何追加之前。
        tail_seq = len(self._chain_events)
        tail_hash = self._chain_tail if tail_seq else "0" * 64
        if anchor_seq != tail_seq or anchor_hash != tail_hash:
            raise StateError(anchor_seq, tail_seq)

        # 全验后一次追加：事件九元组原样接尾（序号即锚后连续位置），仅推进
        # 链序列与末哈希；不动任何原序号索引（操作幂等不恢复），恢复不入审计。
        self._chain_events.extend(events)
        if events:
            self._chain_tail = events[-1][8]

        appended = len(events)
        result = self._render_audit_restore(
            appended, tail_seq + appended, self._chain_tail
        )
        self._audit_restore_cache[key] = (text, result)
        return result

    def _parse_audit_restore_snapshot(self, text):
        """解析并严格全量校验版本 1 审计窗口快照文本，返回
        (锚序号, 锚哈希, 事件九元组列表)；任何不符规范契约处均抛 ValueError。

        与 verify_audit_snapshot 的“与当前链不符返 False”不同，本校验供
        audit_restore 使用，一切不符（含非规范编码）皆为 ValueError：
        JSON 解析或重键失败；顶层非恰为
        版本/锚序号/锚哈希/上限/下个序号/事件/摘要且键序如此；版本非 1；
        锚序号/上限/下个序号非非 bool int 或越界（锚序号>=0、上限 1..1000、
        下个序号>=0），锚哈希/摘要非 64 位小写十六进制；事件非列表或项数超过
        上限；事件项非恰为九键序，序号/时刻/原序号非非 bool int 或越界
        （序号>=1、时刻>=0、原序号>=0），四个负载字段非 str；序号须自锚序号
        +1 起逐项连续；原序号非 0 时须小于本项序号；前哈希须逐项衔接锚哈希、
        哈希须重算相符；下个序号须等于末项序号、空窗等于锚序号；摘要须等于
        前六键规范化紧凑 JSON（无 LF）UTF-8 字节的 sha256 小写值。最后以解析
        值按 audit_snapshot 基线重建完整文档（单个 LF 结尾），与原文逐字节
        不一致即非规范编码 ValueError。仅做快照自洽校验，不读当前链。
        """
        try:
            doc = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError as exc:
            raise ValueError(f"audit snapshot is not valid JSON: {exc}") from exc
        top_keys = ["版本", "锚序号", "锚哈希", "上限", "下个序号", "事件", "摘要"]
        if not isinstance(doc, dict) or list(doc) != top_keys:
            raise ValueError(
                "audit snapshot top-level keys must be "
                "版本/锚序号/锚哈希/上限/下个序号/事件/摘要 in order"
            )
        version = doc["版本"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError(f"版本 must be an int, got {type(version).__name__}")
        if version != 1:
            raise ValueError(f"版本 must be 1, got {version}")
        anchor_seq = self._cp_int(doc["锚序号"], "锚序号", 0)
        anchor_hash = self._cp_hex64(doc["锚哈希"], "锚哈希")
        limit = self._cp_int(doc["上限"], "上限", 1)
        if limit > 1000:
            raise ValueError(f"上限 must be <= 1000, got {limit}")
        next_seq = self._cp_int(doc["下个序号"], "下个序号", 0)
        summary = self._cp_hex64(doc["摘要"], "摘要")

        event_keys = [
            "序号",
            "时刻",
            "键",
            "操作",
            "会话",
            "结果",
            "原序号",
            "前哈希",
            "哈希",
        ]
        raw_events = doc["事件"]
        if not isinstance(raw_events, list):
            raise ValueError("事件 must be a list")
        if len(raw_events) > limit:
            raise ValueError(
                f"事件 count {len(raw_events)} exceeds 上限 {limit}"
            )

        events = []
        prev_hash = anchor_hash
        expect_seq = anchor_seq + 1
        for index, item in enumerate(raw_events, start=1):
            if not isinstance(item, dict) or list(item) != event_keys:
                raise ValueError(
                    f"snapshot event {index} keys must be "
                    "序号/时刻/键/操作/会话/结果/原序号/前哈希/哈希 in order"
                )
            seq = self._cp_int(item["序号"], "事件.序号", 1)
            now_ms = self._cp_int(item["时刻"], "事件.时刻", 0)
            key = item["键"]
            op = item["操作"]
            sid = item["会话"]
            result = item["结果"]
            for label, value in (
                ("事件.键", key),
                ("事件.操作", op),
                ("事件.会话", sid),
                ("事件.结果", result),
            ):
                if not isinstance(value, str):
                    raise ValueError(
                        f"{label} must be a str, got {type(value).__name__}"
                    )
            origin = self._cp_int(item["原序号"], "事件.原序号", 0)
            given_prev = self._cp_hex64(item["前哈希"], "事件.前哈希")
            digest = self._cp_hex64(item["哈希"], "事件.哈希")

            if seq != expect_seq:
                raise ValueError(
                    f"snapshot event seq must be contiguous from the anchor: "
                    f"want {expect_seq}, got {seq}"
                )
            if origin != 0 and origin >= seq:
                raise ValueError(
                    f"snapshot event {seq} 原序号 must be 0 or < {seq}, got {origin}"
                )
            if given_prev != prev_hash:
                raise ValueError(
                    f"snapshot event {seq} 前哈希 does not link to the prior hash"
                )
            if (
                self._chain_hash(
                    seq, now_ms, key, op, sid, result, origin, given_prev
                )
                != digest
            ):
                raise ValueError(f"snapshot event {seq} 哈希 does not match")
            events.append(
                (seq, now_ms, key, op, sid, result, origin, given_prev, digest)
            )
            prev_hash = digest
            expect_seq += 1

        expected_next = events[-1][0] if events else anchor_seq
        if next_seq != expected_next:
            raise ValueError(
                f"下个序号 must equal the last event seq (or 锚序号 for an empty "
                f"window): want {expected_next}, got {next_seq}"
            )

        # 摘要：以解析值规范化重建前六键（数值/结构相等即与生成端基线逐字节
        # 一致），重算 sha256。
        head = {
            "版本": 1,
            "锚序号": anchor_seq,
            "锚哈希": anchor_hash,
            "上限": limit,
            "下个序号": next_seq,
            "事件": [
                {
                    "序号": seq,
                    "时刻": now_ms,
                    "键": key,
                    "操作": op,
                    "会话": sid,
                    "结果": result,
                    "原序号": origin,
                    "前哈希": given_prev,
                    "哈希": digest,
                }
                for seq, now_ms, key, op, sid, result, origin, given_prev, digest in (
                    events
                )
            ],
        }
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(blob.encode("utf-8")).hexdigest() != summary:
            raise ValueError("摘要 does not match the canonical audit snapshot")

        # 非规范编码：完整七键文档（单个 LF 结尾）须与原文逐字节一致；
        # 任何排版差异（空白、Unicode 转义、键序、数值写法、多余/缺失 LF）
        # 皆拒绝。
        canonical = json.dumps(
            {**head, "摘要": summary},
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"
        if canonical != text:
            raise ValueError("audit snapshot is not canonical compact JSON")
        return anchor_seq, anchor_hash, events

    @staticmethod
    def _render_audit_restore(appended, tail_seq, tail_hash):
        # 键序：追加、末序号、末哈希（int/int/str），摘要盖前三键同法编码的
        # UTF-8 字节 sha256 小写值；LF 尾紧凑 JSON。
        head = {"追加": appended, "末序号": tail_seq, "末哈希": tail_hash}
        blob = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        head["摘要"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return json.dumps(head, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _render_meter(sid, now_ms, size, result, used):
        # 键序：会话、时刻、字节、结果、累计；会话/结果为 str，余为 int。
        payload = {
            "会话": sid,
            "时刻": now_ms,
            "字节": size,
            "结果": result,
            "累计": used,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _render(sid, state, now_ms, deadline, address=None, lease=0):
        # address=None 表示未启用地址池，JSON 与基线逐字节一致；
        # 启用时在线给地址串与租期，下线给 "" 与 0。
        payload = {"会话": sid, "状态": state, "时刻": now_ms, "期限": deadline}
        if address is not None:
            payload["地址"] = address
            payload["租期"] = lease
        return (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        )

    @staticmethod
    def _render_suspend_resume(sid, state, now_ms, deadline, pool_id, address, lease):
        # 键序：会话、状态、时刻、期限、池、地址、租期；会话/状态/池/地址为
        # str，余为 int；挂起时池/地址为 ""、期限与租期为 0。
        payload = {
            "会话": sid,
            "状态": state,
            "时刻": now_ms,
            "期限": deadline,
            "池": pool_id,
            "地址": address,
            "租期": lease,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _render_migration(
        sid, state, now_ms, deadline, source, old_address, target, new_address, lease
    ):
        payload = {
            "会话": sid,
            "状态": state,
            "时刻": now_ms,
            "期限": deadline,
            "原池": source,
            "原地址": old_address,
            "目标池": target,
            "目标地址": new_address,
            "租期": lease,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    @staticmethod
    def _render_takeover(
        old,
        old_address,
        old_deadline,
        old_lease,
        sid,
        now_ms,
        deadline,
        pool_id,
        address,
        lease,
    ):
        # 旧值取接管前，旧会话无地址时旧地址为 ""；新会话状态恒为在线。
        payload = {
            "旧会话": old,
            "旧地址": old_address,
            "旧期限": old_deadline,
            "旧租期": old_lease,
            "新会话": sid,
            "状态": _STATE_ONLINE,
            "时刻": now_ms,
            "期限": deadline,
            "池": pool_id,
            "地址": address,
            "租期": lease,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

# ---------------------------------------------------------------------------
# 命令行入口：python access.py <子命令>
#
# 三个无额外参数的子命令，均从 stdin 读入 UTF-8 JSON 请求对象（对象前不得
# 有空白、尾部仅许 JSON 空白）：
# - stats-merge：顶层键依次 key/users/base/left/right，在不加载地址池/模板/
#   持久状态的临时实例中注册 users 后调用 Sessions.stats_merge；
# - stats-delta：顶层键依次 users/base/current，同样注册 users 后只读调用
#   Sessions.stats_delta；
# - session-run：顶层键依次 users/config/requests/query_ms，在全新实例中
#   注册 users、加载版本 11 配置（须含 default 池），依序调用 Sessions.do，
#   时间只取请求自带 now_ms；业务失败记录后继续，最后按 query_ms 取会话
#   全量查询与地址池统计，输出版本/项目/会话/地址池/摘要。
# 成功把返回值原字节写 stdout（退出 0、stderr 空），失败 stdout 空、
# stderr 写 LF 尾紧凑 JSON {"错误":<子命令名>,"类型":<异常类名>}，
# TypeError/ValueError 退出 2、ResourceError 退出 3、StateError 退出 4；
# 缺失或未知子命令按 stats-merge 名写 ValueError 信封（退出 2）。同输入
# 逐字节同结果。stats-merge/stats-delta 时间 O(L+n log n)、空间 O(L+n)，
# L 为输入字节长度、n 为 users 与检查点明细总数；session-run 时间
# O(L+A+R(S+log A)+S log S)、空间 O(L+U+R+S+A)。
# ---------------------------------------------------------------------------

_CLI_MERGE_COMMAND = "stats-merge"
_CLI_DELTA_COMMAND = "stats-delta"
_CLI_RUN_COMMAND = "session-run"
_CLI_MERGE_REQUEST_KEYS = ("key", "users", "base", "left", "right")
_CLI_DELTA_REQUEST_KEYS = ("users", "base", "current")
_CLI_RUN_REQUEST_KEYS = ("users", "config", "requests", "query_ms")
_CLI_USERS_MIN = 1
_CLI_USERS_MAX = 10000
_CLI_RUN_REQUESTS_MIN = 1
_CLI_RUN_REQUESTS_MAX = 1000
# session-run 每个会话必由 requests 建立，故会话数不超过请求数；全量查询
# 一页（limit 上限 1000）即可取全。
_CLI_RUN_QUERY_LIMIT = _CLI_RUN_REQUESTS_MAX
_CLI_RUN_OPS = (
    _OP_ESTABLISH,
    _OP_RENEW,
    _OP_MIGRATE,
    _OP_TAKEOVER,
    _OP_SUSPEND,
    _OP_RESUME,
    _OP_OFFLINE,
)
_CLI_RUN_ITEM_KEYS = ("key", "op", "sid", "args", "now_ms")
# 失败信封的退出码：参数类错误 2、资源错误 3、状态错误 4。
_CLI_EXIT_CODES = {
    TypeError: 2,
    ValueError: 2,
    ResourceError: 3,
    StateError: 4,
}


def _decode_cli_request(raw):
    """stdin 原始字节按 UTF-8 解码；编码错抛 ValueError。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"stdin must be valid UTF-8: {exc}") from exc


def _decode_cli_object(text):
    """把请求文本解析为单个 JSON 对象：对象前不得有空白（连合法空白也不
    允许）、对象后仅许 JSON 定义的空白（空格/制表/换行/回车）；JSON 语法、
    重键、顶层非对象或前后杂字符错抛 ValueError。"""
    if text[:1] in " \t\r\n":
        raise ValueError("request must start directly with the JSON object")
    try:
        doc, end = json.JSONDecoder(
            object_pairs_hook=_unique_object
        ).raw_decode(text)
    except ValueError as exc:
        raise ValueError(f"request is not valid JSON: {exc}") from exc
    tail = text[end:]
    if any(char not in " \t\r\n" for char in tail):
        raise ValueError("request may only have whitespace after the JSON object")
    if not isinstance(doc, dict):
        raise ValueError("request top level must be a JSON object")
    return doc


def _check_cli_users(users):
    """校验 users 数组：须 1..10000 个 str，元素沿凭据约束（1..256 UTF-8
    字节、不含 U+0000），按 Unicode 码点严格升序且互异。users 非 list 或
    元素非 str 抛 TypeError，长度、取值、排序或重复错抛 ValueError。
    """
    if not isinstance(users, list):
        raise TypeError(
            f"users must be an array, got {type(users).__name__}"
        )
    if not (_CLI_USERS_MIN <= len(users) <= _CLI_USERS_MAX):
        raise ValueError(
            f"users must contain {_CLI_USERS_MIN}..{_CLI_USERS_MAX} items, "
            f"got {len(users)}"
        )
    previous = None
    for index, user in enumerate(users):
        if not isinstance(user, str):
            raise TypeError(
                f"users[{index}] must be a string, got {type(user).__name__}"
            )
        _check_credential(f"users[{index}]", user)
        if previous is not None:
            if user == previous:
                raise ValueError(f"users[{index}] duplicates {user!r}")
            if user < previous:
                raise ValueError(
                    "users must be sorted by Unicode codepoint"
                )
        previous = user


def _parse_cli_request(raw):
    """解析 stats-merge 请求字节，返回 (key, users, base, left, right)。

    raw 须为 UTF-8 编码的单个 JSON 对象，对象前不得有空白、对象后仅许
    空白；编码、JSON、重键、顶层形态、键集或键序错抛 ValueError。
    key/base/left/right 字段类型错抛 TypeError，users 字段非 list 抛
    TypeError；users 须 1..10000 个 str，元素沿凭据约束（1..256 UTF-8
    字节、不含 U+0000），按 Unicode 码点严格升序且互异，长度、取值、
    排序或重复错抛 ValueError，元素型错抛 TypeError。
    """
    text = _decode_cli_request(raw)
    doc = _decode_cli_object(text)
    if list(doc) != list(_CLI_MERGE_REQUEST_KEYS):
        raise ValueError(
            "request keys must be exactly and in order: "
            "key, users, base, left, right"
        )
    key = doc["key"]
    users = doc["users"]
    base = doc["base"]
    left = doc["left"]
    right = doc["right"]
    for name, value in (
        ("key", key), ("base", base), ("left", left), ("right", right),
    ):
        if not isinstance(value, str):
            raise TypeError(
                f"{name} must be a string, got {type(value).__name__}"
            )
    _check_cli_users(users)
    return key, users, base, left, right


def _parse_cli_delta_request(raw):
    """解析 stats-delta 请求字节，返回 (users, base, current)。

    形态约束与 stats-merge 相同，唯顶层键依次且仅为 users/base/current；
    base/current 字段类型错抛 TypeError，users 字段非 list 抛 TypeError；
    users 长度、取值、排序或重复错抛 ValueError，元素型错抛 TypeError。
    """
    text = _decode_cli_request(raw)
    doc = _decode_cli_object(text)
    if list(doc) != list(_CLI_DELTA_REQUEST_KEYS):
        raise ValueError(
            "request keys must be exactly and in order: "
            "users, base, current"
        )
    users = doc["users"]
    base = doc["base"]
    current = doc["current"]
    for name, value in (("base", base), ("current", current)):
        if not isinstance(value, str):
            raise TypeError(
                f"{name} must be a string, got {type(value).__name__}"
            )
    _check_cli_users(users)
    return users, base, current


def _temporary_sessions(users):
    """建临时实例：注册全部 users 为已认证用户，不加载地址池、模板或任何
    持久状态（容量取默认值）；实例仅存活于本次子命令调用。"""
    auth = Authenticator(1, 0)
    for user in users:
        # 固定占位密码：仅完成注册，两个统计接口都不认证，逐次结果不受影响。
        auth.add(user, "x")
    return Sessions(auth, 1, 1, 0, lease_ms=1)


def _run_stats_merge(key, users, base, left, right):
    """临时实例注册 users 后直接执行一次 stats_merge。

    不加载任何配置（无地址池、无模板、容量取默认值），stats_merge
    不老化、不认证、不审计、不碰其他状态，实例仅存活于本次调用。
    """
    sessions = _temporary_sessions(users)
    return sessions.stats_merge(key, base, left, right)


def _run_stats_delta(users, base, current):
    """临时实例注册 users 后只读执行一次 stats_delta。

    不加载任何配置（无地址池、无模板、容量取默认值），stats_delta
    不老化、不认证、不审计、不计数、不改任何状态，实例仅存活于本次调用。
    """
    sessions = _temporary_sessions(users)
    return sessions.stats_delta(base, current)


def _check_run_users(users):
    """校验 session-run 的 users：1..10000 个按用户名 Unicode 码点升序且
    互异的凭据二元数组 [user, password]。users 非 list 抛 TypeError；元素
    非 list 抛 TypeError（元组非法形态为 ValueError，仅 list 为数组）；
    长度、字段类型、取值、排序或重复错抛 ValueError。
    """
    if not isinstance(users, list):
        raise TypeError(
            f"users must be an array, got {type(users).__name__}"
        )
    if not (_CLI_USERS_MIN <= len(users) <= _CLI_USERS_MAX):
        raise ValueError(
            f"users must contain {_CLI_USERS_MIN}..{_CLI_USERS_MAX} items, "
            f"got {len(users)}"
        )
    previous = None
    for index, entry in enumerate(users):
        if not isinstance(entry, list):
            if isinstance(entry, tuple):
                raise ValueError(
                    f"users[{index}] must be an array pair, not a tuple"
                )
            raise TypeError(
                f"users[{index}] must be an array, got {type(entry).__name__}"
            )
        if len(entry) != 2:
            raise ValueError(
                f"users[{index}] must be a [user, password] pair, "
                f"got {len(entry)} items"
            )
        user, password = entry
        if not isinstance(user, str):
            raise TypeError(
                f"users[{index}][0] must be a string, got "
                f"{type(user).__name__}"
            )
        if not isinstance(password, str):
            raise TypeError(
                f"users[{index}][1] must be a string, got "
                f"{type(password).__name__}"
            )
        _check_credential(f"users[{index}][0]", user)
        _check_credential(f"users[{index}][1]", password)
        if previous is not None:
            if user == previous:
                raise ValueError(f"users[{index}] duplicates {user!r}")
            if user < previous:
                raise ValueError(
                    "users must be sorted by Unicode codepoint"
                )
        previous = user


def _check_run_config(config, registered_users=None):
    """校验 session-run 的 config：须为版本 11 配置对象（load_config 的键、
    结构与取值规则）且含 default 地址池。config 非 object 抛 TypeError；
    版本、键集/键序、结构、类型、值、引用、排序/重复或缺 default 池抛
    ValueError。registered_users 给定时，用户模板引用的用户须在其中，
    否则按引用非法抛 ValueError。仅做静态形态校验，不触碰任何实例。返回
    规范化 spec（仅供调用方做进一步引用校验）。
    """
    if not isinstance(config, dict):
        raise TypeError(
            f"config must be an object, got {type(config).__name__}"
        )
    spec = _parse_config_doc(config, None)
    pool_ids = {pool_id for pool_id, *_rest in spec[4]}
    if _DEFAULT_POOL_ID not in pool_ids:
        raise ValueError("config must contain a default address pool")
    if registered_users is not None:
        for user, _template_id in spec[6]:
            if user not in registered_users:
                raise ValueError(
                    f"user template references unregistered user: {user!r}"
                )
    return spec


def _run_args_to_tuple(index, op, args):
    """把会话请求的 args 数组转成 Sessions.do 原接口元组。

    建立/迁移/接管/恢复须为恰含两个凭据字符串的数组（转为二元 tuple）；
    续租/挂起/下线须为 null；其余形态按非法处理：非数组容器（tuple 等）
    为 ValueError，非数组标量为 TypeError，长度/字段类型/取值错分别为
    ValueError/TypeError/ValueError。
    """
    if op in (
        _OP_ESTABLISH,
        _OP_MIGRATE,
        _OP_TAKEOVER,
        _OP_RESUME,
    ):
        if isinstance(args, tuple):
            raise ValueError(
                f"requests[{index}].args must be an array, not a tuple"
            )
        if not isinstance(args, list):
            raise TypeError(
                f"requests[{index}].args must be an array, "
                f"got {type(args).__name__}"
            )
        if len(args) != 2:
            raise ValueError(
                f"requests[{index}].args must have exactly 2 items, "
                f"got {len(args)}"
            )
        field_names = {
            _OP_ESTABLISH: ("user", "password"),
            _OP_MIGRATE: ("target", "password"),
            _OP_TAKEOVER: ("old", "password"),
            _OP_RESUME: ("pool", "password"),
        }[op]
        first = _run_args_to_tuple_cred(index, 0, field_names[0], args[0])
        second = _run_args_to_tuple_cred(index, 1, field_names[1], args[1])
        return first, second
    if args is not None:
        if isinstance(args, (list, tuple)):
            raise ValueError(
                f"requests[{index}].args must be null for {op!r}"
            )
        raise TypeError(
            f"requests[{index}].args must be null for {op!r}, "
            f"got {type(args).__name__}"
        )
    return None


def _run_args_to_tuple_cred(index, field_index, field_name, value):
    """args 单个凭据字段的类型/取值校验（带请求下标定位）。"""
    if not isinstance(value, str):
        raise TypeError(
            f"requests[{index}].args[{field_index}] ({field_name}) must be a "
            f"string, got {type(value).__name__}"
        )
    _check_credential(
        f"requests[{index}].args[{field_index}] ({field_name})", value
    )
    return value


def _check_run_requests(requests):
    """校验 session-run 的 requests：1..1000 个对象，键依次且仅为
    key/op/sid/args/now_ms；key/sid 沿凭据约束，op 仅七个会话操作，
    args 形态随 op（见 _run_args_to_tuple），now_ms 为非 bool 非负 int。
    返回 [(key, op, sid, args_tuple, now_ms), ...]，保持请求顺序。
    requests 非 list 抛 TypeError；长度、键集/键序、op、args 形态或取值
    错抛 ValueError，字段类型错抛 TypeError。
    """
    if not isinstance(requests, list):
        raise TypeError(
            f"requests must be an array, got {type(requests).__name__}"
        )
    if not (
        _CLI_RUN_REQUESTS_MIN
        <= len(requests)
        <= _CLI_RUN_REQUESTS_MAX
    ):
        raise ValueError(
            f"requests must contain {_CLI_RUN_REQUESTS_MIN}.."
            f"{_CLI_RUN_REQUESTS_MAX} items, got {len(requests)}"
        )
    parsed = []
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            raise TypeError(
                f"requests[{index}] must be an object, "
                f"got {type(request).__name__}"
            )
        if list(request) != list(_CLI_RUN_ITEM_KEYS):
            raise ValueError(
                "requests[%d] keys must be exactly and in order: "
                "key, op, sid, args, now_ms" % index
            )
        key = request["key"]
        op = request["op"]
        sid = request["sid"]
        args = request["args"]
        now_ms = request["now_ms"]
        _check_credential(f"requests[{index}].key", key)
        if not isinstance(op, str):
            raise TypeError(
                f"requests[{index}].op must be a string, "
                f"got {type(op).__name__}"
            )
        if op not in _CLI_RUN_OPS:
            raise ValueError(
                f"requests[{index}].op must be one of {_CLI_RUN_OPS}, "
                f"got {op!r}"
            )
        _check_credential(f"requests[{index}].sid", sid)
        args_tuple = _run_args_to_tuple(index, op, args)
        # 非 bool 非负 int：bool 归 TypeError，非 int 归 TypeError，负数归
        # ValueError，与 _check_int 一致。
        _check_int(f"requests[{index}].now_ms", now_ms, 0)
        parsed.append((key, op, sid, args_tuple, now_ms))
    return parsed


def _parse_cli_run_request(raw):
    """解析 session-run 请求字节，返回 (users, config, requests, query_ms)。

    raw 须为 UTF-8 编码的单个 JSON 对象，对象前不得有空白、对象后仅许
    空白；编码、JSON、重键、顶层形态、键集或键序错抛 ValueError。users
    为按用户名 Unicode 码点升序且互异的 [user, password] 二元数组；
    config 为版本 11 配置对象且含 default 池；requests 为 1..1000 个会话
    请求对象；query_ms 为非 bool 非负 int。类型错抛 TypeError，其余形态/
    取值/排序/重复/配置非法抛 ValueError。
    """
    text = _decode_cli_request(raw)
    doc = _decode_cli_object(text)
    if list(doc) != list(_CLI_RUN_REQUEST_KEYS):
        raise ValueError(
            "request keys must be exactly and in order: "
            "users, config, requests, query_ms"
        )
    users = doc["users"]
    config = doc["config"]
    requests = doc["requests"]
    query_ms = doc["query_ms"]
    _check_run_users(users)
    registered_users = {user for user, _password in users}
    _check_run_config(config, registered_users)
    parsed_requests = _check_run_requests(requests)
    _check_int("query_ms", query_ms, 0)
    return users, config, parsed_requests, query_ms


def _run_session_run(users, config, requests, query_ms):
    """在全新实例中注册 users、加载 v11 配置并依序执行 Sessions.do。

    注册与配置加载均已在输入校验阶段静态通过，此处不会失败。时间只取
    各请求自带 now_ms：业务失败（AuthError/ResourceError/StateError/
    KeyError/BackendError）记录异常类名后继续，老化、租约、认证、审计与
    幂等副作用沿用 Sessions.do 既有语义（同一 key 同参重放原结果、异参
    复用抛 ValueError 亦记为业务失败），失败不留半分配状态。全部结束后
    按 query_ms 取会话全量查询（只读视图，不老化）与地址池统计
    （pool_stats 先老化），组装 LF 尾紧凑 JSON：顶层键序版本/项目/会话/
    地址池/摘要，版本 1；项目保持请求顺序，项键序序号/结果/输出/类型；
    摘要为前四顶层字段紧凑编码 UTF-8 字节的 SHA-256 小写值。
    """
    auth = Authenticator(1, 0)
    for user, password in users:
        auth.add(user, password)
    sessions = Sessions(auth, 1, 1, 0, lease_ms=1)
    # v11 直载：键、结构、引用、承载力与 default 池均已静态校验，必成功。
    config_text = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    sessions.load_config(config_text)

    items = []
    for index, (key, op, sid, args, now_ms) in enumerate(requests):
        try:
            output_text = sessions.do(key, op, sid, args, now_ms)
        except (
            AuthError,
            ResourceError,
            StateError,
            KeyError,
            BackendError,
            ValueError,
            TypeError,
        ) as exc:
            # 业务失败统一记异常类名后继续。请求形态已在执行前静态校验，
            # 故执行期出现的 ValueError/TypeError 只可能是幂等域冲突
            # （同一 key 异参复用按 do 既有语义抛 ValueError），属业务
            # 结果而非输入非法；老化、租约、认证、审计与幂等副作用沿用
            # do 既有语义，失败不留半分配。
            items.append(
                {
                    "序号": index,
                    "结果": False,
                    "输出": None,
                    "类型": type(exc).__name__,
                }
            )
        else:
            items.append(
                {
                    "序号": index,
                    "结果": True,
                    "输出": json.loads(output_text),
                    "类型": "",
                }
            )

    # 会话全量查询：会话数不超过请求数（<=1000），单页取全；只读视图，
    # 不老化、不认证、不写审计/缓存/计数。
    sessions_view = json.loads(
        sessions.sessions(query_ms, "", _CLI_RUN_QUERY_LIMIT)
    )
    # 地址池统计：pool_stats 先按 query_ms 老化一次再统计。
    pool_view = json.loads(sessions.pool_stats(query_ms))

    document = {
        "版本": 1,
        "项目": items,
        "会话": sessions_view,
        "地址池": pool_view,
    }
    head = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    document["摘要"] = hashlib.sha256(head.encode("utf-8")).hexdigest()
    return (
        json.dumps(document, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    )


def _write_cli_error(command, exc):
    """向 stderr 写 LF 尾紧凑 JSON 信封，键序“错误/类型”，UTF-8 字节。"""
    envelope = json.dumps(
        {"错误": command, "类型": type(exc).__name__},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    sys.stderr.buffer.write(envelope.encode("utf-8") + b"\n")
    sys.stderr.buffer.flush()


def main(argv):
    """命令行分派：受理无额外参数的 stats-merge、stats-delta 与 session-run。

    缺失或未知子命令（含多余参数）沿用 stats-merge 名写 ValueError
    信封，退出 2；其余失败信封的“错误”取实际子命令名。
    """
    if (
        len(argv) != 2
        or argv[1]
        not in (
            _CLI_MERGE_COMMAND,
            _CLI_DELTA_COMMAND,
            _CLI_RUN_COMMAND,
        )
    ):
        _write_cli_error(_CLI_MERGE_COMMAND, ValueError("missing or unknown subcommand"))
        return 2
    command = argv[1]
    raw = sys.stdin.buffer.read()
    try:
        if command == _CLI_MERGE_COMMAND:
            key, users, base, left, right = _parse_cli_request(raw)
            result = _run_stats_merge(key, users, base, left, right)
        elif command == _CLI_DELTA_COMMAND:
            users, base, current = _parse_cli_delta_request(raw)
            result = _run_stats_delta(users, base, current)
        else:
            users, config, requests, query_ms = _parse_cli_run_request(raw)
            result = _run_session_run(users, config, requests, query_ms)
    except (TypeError, ValueError, ResourceError, StateError) as exc:
        # 失败：stdout 保持空，信封仅含命令名与异常类名。
        _write_cli_error(command, exc)
        return _CLI_EXIT_CODES[type(exc)]
    sys.stdout.buffer.write(result.encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
