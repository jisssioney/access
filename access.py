"""access — 接入网后端服务框架（仅标准库）。

当前提供：
- Authenticator：带失败计数与锁定的用户认证器。
- Sessions：基于 Authenticator 的会话管理（建立/续租/下线/接管/跨池迁移、空闲老化、
  零池起步可 add_pool 激活多地址池、租约、按 key 重放缓存、pool_stats、接管审计
  takeover_audit、防篡改审计链 audit/verify_audit、配置导出/升级/加载/回滚
  export_config/upgrade_config/load_config/rollback_config、QoS 模板查询 qos、按
  (用户,模板) 共享账本计量的 meter、配额只读快照 quota_stats、共享账本检查点
  quota_checkpoint 与按 key 原子恢复 quota_restore、按用户/模板分组的
  计量统计 meter_stats、容量申请
  capacity：可配置队列上限与最大等待的申请/取消/推进，截止超时与按入队序晋升、
  capacity_events 事件查询与 capacity_stats 容量统计）；clog/cverify/
  creplay 提供 capacity 状态检查点、事件哈希链校验与原子重放恢复。
  runtime_checkpoint/runtime_restore 提供覆盖会话/租约、容量队列/事件与
  共享 QoS 账本的运行态检查点（版本 1，摘要覆盖前四键）与按 key 原子
  恢复（仅缓存成功，同摘要空操作，异摘要覆盖状态 StateError），供续租、
  计量、推进一致恢复。
  fault 注入/恢复后端故障：do 建立/迁移/接管与 capacity 申请在验参后、
  老化前查后端，故障期按用户指数退避抛 BackendError；fault_stats 查询
  后端故障统计（含按类累计的失败次数），查询不老化、不改态。
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
  总量/占用/可用/保留；查询不认证、不老化、不改态。
- Sessions.batch_offline 批量下线：按 key 独立重放缓存，首果（含参数异常）
  永久缓存；首次合法先老化，非原子逐项下线/未知、原子全存在才提交否则整批
  回滚（保留老化），不记审计或容量事件。
- Sessions.batch_online 批量建立：按 key 独立重放缓存，首果（含参数异常）
  永久缓存；首次合法先老化，逐项经后端、认证、容量、default 池与静态址
  规则建立，业务异常不抛而记项结果类名；非原子逐项提交，原子演算全部、
  任一失败整批回滚（保留老化、认证计数与退避），不记审计或容量事件。
- Sessions.credential_change 凭据轮换：按 key 独立重放缓存，首果（含参数
  异常）永久缓存；首次合法经 Authenticator 校验旧密码，denied/locked 抛
  AuthError 并保留失败计数与锁定，成功按摘要规则换密并清零二者，会话与
  已入队队项保留；首果（成功/AuthError/KeyError）及同参重放写防篡改审计链
  （凭据轮换，会话=user），参数错不审计。
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
所有时间均由调用方以显式时钟（毫秒整数）驱动。
"""

import hashlib
import heapq
import hmac
import ipaddress
import json

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


def _parse_config_templates(doc):
    """校验 v3 的模板与用户模板，返回规范化 (templates, user_templates)。

    templates 为按标识升序的 (标识, 限速, 突发, 配额, 超限) 元组：标识沿用
    凭据约束，限速/配额为非 bool 正 int（限速为字节/秒、配额为字节），突发为
    非 bool 非负 int（字节），超限仅“拒绝”或“下线”。user_templates 为按用户
    升序的 (user, 标识) 元组：用户唯一，标识须已定义。结构、类型、值、重复项
    或标识引用错均抛 ValueError；用户是否在认证器中由调用方校验。
    """
    raw_templates = doc["模板"]
    if not isinstance(raw_templates, list):
        raise ValueError(f"模板 must be a list, got {type(raw_templates).__name__}")
    templates = []
    seen_ids = set()
    for item in raw_templates:
        if not isinstance(item, dict) or set(item) != {
            "标识",
            "限速",
            "突发",
            "配额",
            "超限",
        }:
            raise ValueError("template entry keys must be exactly 标识/限速/突发/配额/超限")
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
        exceed = item["超限"]
        if exceed not in ("拒绝", "下线"):
            raise ValueError(f"超限 must be 拒绝 or 下线, got {exceed!r}")
        templates.append(
            (template_id, numbers["限速"], numbers["突发"], numbers["配额"], exceed)
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


def _parse_config_capacity(doc):
    """校验 v4 的容量节，返回 (队列上限, 最大等待毫秒)。

    容量须恰含“队列上限/最大等待毫秒”，二者为非 bool int：队列上限
    0..10000（0 表示不限），最大等待毫秒 >= 0（0 表示不限）。结构、类型或
    值错均抛 ValueError。
    """
    raw = doc["容量"]
    if not isinstance(raw, dict) or set(raw) != {"队列上限", "最大等待毫秒"}:
        raise ValueError("容量 keys must be exactly 队列上限/最大等待毫秒")
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
    return queue_limit, max_wait


def _load_config_doc(text):
    """校验 text 为 str 并解析 JSON（拒重键），返回对象文档。

    text 非 str 抛 TypeError；JSON 解析错（JSONDecodeError 系 ValueError
    子类）或重复键抛 ValueError。是否为对象、键与结构由调用方校验。
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    return json.loads(text, object_pairs_hook=_unique_object)


def _parse_config_doc(doc):
    """由已解析对象文档校验并迁移为规范化 spec；任何错均抛 ValueError。

    spec 为 (total, per, idle_ms, lease_ms, pools, templates, user_templates,
    capacity)，capacity 为 (队列上限, 最大等待毫秒)；pools 为按标识升序的
    (标识, cidr, reserved, static) 元组，reserved/static 已规范化排序；
    templates 为按标识升序的 (标识, 限速, 突发, 配额, 超限) 元组，
    user_templates 为按用户升序的 (user, 标识) 元组。v1（版本=1）地址池为无
    标识单池对象，迁移为 default 池；v2（版本=2）地址池为池对象列表；v3
    （版本=3）增模板与用户模板；v4（版本=4）增容量背压（队列上限/最大等待
    毫秒）。v1/v2 迁移时模板、用户模板为空；v1-v3 迁移时容量补默认
    (1024, 0)。重复/未知/缺失键、结构、值、引用或版本错均抛 ValueError。
    """
    if not isinstance(doc, dict):
        raise ValueError(f"config must be a JSON object, got {type(doc).__name__}")
    version = doc.get("版本")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"版本 must be an int, got {type(version).__name__}")
    if version not in (1, 2, 3, 4):
        raise ValueError(f"版本 must be 1, 2, 3 or 4, got {version}")
    if version == 4:
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
        templates, user_templates = _parse_config_templates(doc)
    else:
        # v1/v2 迁移：模板与用户模板均为空。
        templates, user_templates = (), ()
    if version == 4:
        capacity = _parse_config_capacity(doc)
    else:
        # v1-v3 迁移：容量补默认 1024 项队列、不限等待。
        capacity = (_MAX_QUEUE, 0)
    return (
        numbers["总数"],
        numbers["每用户"],
        numbers["空闲毫秒"],
        numbers["租期毫秒"],
        tuple(pool_specs),
        templates,
        user_templates,
        capacity,
    )


def _config_payload(spec):
    """由规范化 spec 构建 export/升级共用的 v4 配置 payload（固定键序与排序）。"""
    (
        total,
        per,
        idle_ms,
        lease_ms,
        pool_specs,
        templates,
        user_templates,
        (queue_limit, max_wait_ms),
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
                "超限": exceed,
            }
            for template_id, rate, burst, quota, exceed in templates
        ],
        "用户模板": [
            [user, template_id] for user, template_id in user_templates
        ],
        "容量": {
            "队列上限": queue_limit,
            "最大等待毫秒": max_wait_ms,
        },
    }


def _compact_config(spec):
    """spec 的 v4 配置紧凑 JSON 串（无尾 LF），export_config 与升级包共用。"""
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
    源版本为 1..4 的非 bool int、目标版本恒为 4、改变为 bool 且等于
    源版本 != 4、摘要为 str；配置须为能解析出 v4 spec 的对象，再将其
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
    if source not in (1, 2, 3, 4):
        raise ValueError(f"源版本 must be 1, 2, 3 or 4, got {source}")
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
        raise ValueError("配置 must be a canonical v4 config object")
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if summary != digest:
        raise ValueError("摘要 does not match the canonical config digest")
    return source, target, changed, summary, spec


def _digest(user, password):
    return hashlib.sha256((user + "\0" + password).encode("utf-8")).digest()


class Authenticator:
    """基于 sha256 摘要的认证器，失败 max_fail 次后锁定 lock_ms 毫秒。"""

    def __init__(self, max_fail, lock_ms):
        self._max_fail = _check_int("max_fail", max_fail, 1)
        self._lock_ms = _check_int("lock_ms", lock_ms, 0)
        # user -> [digest, failed, until]；until 为 None 表示未锁定，
        # 不能用 0 作哨兵，否则零时锁（lock_ms=0 于 now_ms=0）到期后
        # failed 永不清零。
        self._users = {}

    def __contains__(self, user):
        """用户是否已注册（供配置引用校验）。"""
        return user in self._users

    def add(self, user, password):
        """注册新用户，返回 (user, "created", 0)。"""
        _check_credential("user", user)
        _check_credential("password", password)
        if user in self._users:
            raise KeyError(f"duplicate user: {user!r}")
        if len(self._users) >= _MAX_USERS:
            raise OverflowError(f"user limit {_MAX_USERS} reached")
        self._users[user] = [_digest(user, password), 0, None]
        return (user, "created", 0)

    def authenticate(self, user, password, now_ms):
        """验证凭据，返回 (user, status, until)，status ∈ ok/denied/locked。"""
        _check_credential("user", user)
        _check_credential("password", password)
        _check_int("now_ms", now_ms, 0)
        record = self._users.get(user)
        if record is None:
            raise KeyError(f"unknown user: {user!r}")
        digest, failed, until = record

        if until is not None:
            if now_ms < until:
                # 锁定中：不验密、不改状态。
                return (user, "locked", until)
            # 锁已到期（含同刻）：先清零 failed 与 until 再验证。
            failed = 0
            until = None
            record[1] = 0
            record[2] = None

        if hmac.compare_digest(digest, _digest(user, password)):
            record[1] = 0
            return (user, "ok", 0)

        failed += 1
        record[1] = failed
        if failed >= self._max_fail:
            record[2] = now_ms + self._lock_ms
            return (user, "locked", record[2])
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
    _CAP_AUTH_FAILED,
    _CAP_STATE_FAILED,
    _CAP_UNKNOWN,
)
# 仅排队相关事件携带正入队序，其余事件入队序恒为 0。
_CAP_VERDICTS_WITH_ORDER = frozenset(
    (_CAP_QUEUED, _CAP_CANCELLED, _CAP_TIMEOUT, _CAP_PROMOTED)
)
_MAX_QUEUE = 1024
_MAX_QUEUE_LIMIT = 10000
_CONFIG_VERSION = 4

# fault 操作与后端状态。
_OP_INJECT = "注入"
_OP_RECOVER = "恢复"
_BACKEND_FAULT = "故障"
_BACKEND_NORMAL = "正常"

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
_CONFIG_CHAIN_LOAD = "配置加载"
_CONFIG_CHAIN_ROLLBACK = "配置回滚"

# batch_offline 批量下线：单批 sid 数上界。
_BATCH_MAX_SIDS = 1000
# 顶层结果仅 提交/部分/回滚；项结果沿用 "下线"（_STATE_OFFLINE）、
# "未知"（_CAP_UNKNOWN），回滚为 "回滚"。
_BATCH_COMMIT = "提交"
_BATCH_PARTIAL = "部分"
_BATCH_ROLLBACK = "回滚"
# batch_online 批量建立：成功项结果“上线”，区别于会话状态“在线”。
_BATCH_ITEM_ONLINE = "上线"

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
    追加命名池（含 default），重名 ValueError。建立须经 default 池分配地址，
    缺 default 抛 StateError；无池时 pool_stats 抛 StateError。各池地址空间
    相互独立、允许重叠，占用按池隔离。建立为静态用户取其专属地址，否则取最小
    未租用动态地址；租期到期、挂起或下线均释放地址，静态地址不回动态池。迁移
    在两池间原子换址。接管先老化：旧会话持址则新会话继承其池/地址/租约，
    无址则自 default 池新分配，租期 = now_ms+lease_ms；认证或资源失败仅保留
    老化结果。按 key 永久缓存重放。takeover_audit 记录首次成功/认证失败/资源
    失败及同参重放，查询不老化。do 验参后的首次结果（成功或
    AuthError/ResourceError/StateError/KeyError）及同参重放另记入防篡改
    审计链：逐事件 sha256 链接前项哈希，audit 查询、verify_audit 校验，
    参数错与异参 key 重放不入链。export_config 导出 v4 配置 JSON（顶层键序
    版本/会话/地址池/模板/用户模板/容量；会话与地址池沿用 v2，模板按标识升序、
    用户模板按用户升序、容量为队列上限/最大等待毫秒）；upgrade_config(text,
    target=4) 只读地把 v1..v4 配置升级为 v4 升级包 JSON（LF 尾紧凑；顶层序/型
    源版本:int/目标版本:int/改变:bool/摘要:str/配置:object，改变=源版本!=4，
    配置同 export_config 的 v4，摘要为配置紧凑编码 UTF-8 字节的 sha256
    小写值），text 非 str 或 target 非非 bool int 抛 TypeError，target 只许 4，
    源版本限 1..4，解析、重键、键缺失/未知、结构/值/引用/版本非法抛 ValueError，
    迁移沿 load_config 既有规则（v1 单池改 default、v1/v2 补空模板与用户模板、
    v1-v3 补容量 1024/0、v4 只规范化），升级不改任何实例状态；load_config
    直载 v1..v4 配置或经严格复核（键序、字段、配置规范形态、摘要）的升级包，
    全验后原子替换并保存旧配置为唯一回滚点，升级包复核不符抛 ValueError，
    引用错（用户模板引用未知用户或未知模板标识）抛 ValueError，上限、租约或
    队长承载不满足抛 ResourceError，失败不改配置、回滚点、会话、租约与运行态；
    rollback_config 经同样校验恢复旧配置并清除回滚点，无回滚点抛 StateError。
    export/load/rollback 成功均返回 v4 配置 JSON，会话状态、期限、地址、租期与
    旧队项的等待/截止/入队序不受配置替换影响，新配置仅作用于后续操作与查询。
    qos(sid) 以 O(1) 返回
    在线会话用户所绑 QoS 模板的生效值。meter(key, sid, size, now_ms) 按
    会话用户所绑模板做令牌桶加配额计量，计量态为 (用户, 模板) 共享账本
    （累计 u、上次通过时刻 t、千分字节令牌 c），同用户同模板的并发会话
    共享配额、互不重置：通过则原子提交账本，超限取模板动作（拒绝不改账，
    下线原子清场且不改账），重放缓存与 do 分域；下线、新建、接管不清账，
    配置提交后同标识保留 u/t 并截顶 c，改绑用独立账本，加载或回滚失败
    不改账。quota_stats(user, now_ms) 以 O(1) 只读返回用户所绑模板的
    配额快照（不老化、不建账；无账本按累计 0、满桶）。meter 新 key 首次
    结果为通过/拒绝/下线时按当时会话用户与当次模板标识各记一次统计
    （通过另计字节），配置热加载或回滚不迁移历史计数；meter_stats
    (now_ms, group) 老化后按用户或查询时生效绑定（未绑定归空串）汇总
    历史计数与当前在线数。capacity(key, op, sid, args, now_ms) 在既有
    认证、老化、上限与 default 池取址规则之上提供容量背压等待队列（队列
    上限与最大等待由配置给定，默认 1024 项、不限等待）：申请等待超过非零
    最大等待在认证/老化之前即抛 ValueError（不入队、不记事件），可立即
    服务则原子建立、否则入队（队长达上限 ResourceError），取消仅
    撤销排队项，推进先老化再清超时（截止=申请时刻+等待，含同刻）并依
    入队序晋升容量允许且可取址者至全局满；老化挂起即释址，挂起会话不
    持址、不计在线但仍占全局与单用户上限；按 key 重放缓存与 do/meter
    分域；既有 do 建立仍立即拒绝、绝不入队。capacity_events(after,
    limit) 查询事件（游标与参数规则同 audit，查询不老化）：仅首个验参
    成功的新 key 记事件，结果限在线/排队/取消/超时/晋升/队满/认证失败/
    状态失败/未知，推进按入队序先超时后晋升，重放不记。capacity_stats
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
    batch_offline(key, sids, now_ms, atomic=False) 批量下线：key/sid 沿用
    凭据约束，sids 为 1..1000 个互异 sid 的 tuple，now_ms 为非 bool 非负
    int，atomic 为 bool；类型错 TypeError，取值/长度/重复错 ValueError。
    验 key 后以独立域永久缓存首果（含参数异常），同型同参重放不老化、不改态，
    异参 ValueError。首次合法先老化；非原子逐项处理，现存项（在线/挂起/
    下线墓碑）置下线、期限 0、释放地址租约并记“下线”，未知记“未知”不影响
    后项；原子先查老化后快照，有未知则未知记“未知”、其余记“回滚”且不执行
    （保留老化），全存在才提交。未知不抛异常；不记审计或容量事件。返回键序
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
    老化、认证计数与退避保留。不记审计或容量事件，不计建立/失败/
    后端故障统计。返回键序时刻/原子/结果/项目的 LF 尾紧凑 JSON，
    结果仅提交（全上线）/部分（非原子有失败）/回滚（原子有失败），
    项目依输入顺序，项键序“会话/结果”，项结果仅上线/业务异常类名/
    回滚。首次 O(S+B log A) 时间、O(B) 辅助空间，重放 O(B)。
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
    合法先经 Authenticator 校验旧密码，denied/locked 抛 AuthError 并保留
    失败计数与锁定；成功按摘要规则换密并清零失败计数与锁定。除缓存、审计与
    认证副作用外失败不改其他状态；成功保留会话与已入队队项，此后仅新密码可
    认证。返回键序“用户/时刻/结果”、结果恒为“已轮换”的 LF 尾紧凑 JSON。
    验 key 后以独立域永久缓存余参与首果（含参数异常），同型同参重放不认证、
    不换密，原样返回或重抛同类同 args，异参抛 ValueError 且不审计。参数错不
    审计；首果（成功/AuthError/KeyError）及同参重放写现有防篡改审计链：操作
    “凭据轮换”、会话记 user，首次原序号 0、重放原序号指认首次且结果加“重放”
    前缀。O(1) 时空（凭据长度有界）。
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

        # QoS 模板：标识 -> (限速, 突发, 配额, 超限)；用户模板：user -> 标识。
        self._templates = {}
        self._user_templates = {}
        # 容量背压：队列上限（0 表示不限）、最大等待毫秒（0 表示不限）。
        self._queue_limit = _MAX_QUEUE
        self._max_wait_ms = 0

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
        # config_change 配置加载/回滚事务的重放缓存，与 do/meter/capacity/
        # fault/pool_fault/timeout_fault/batch_offline 分域：
        # key -> (op, text, now_ms, outcome)；原序号索引亦独立分域。
        self._config_change_cache = {}
        self._config_change_chain_index = {}
        # credential_change 凭据轮换的重放缓存，与其余各域独立：
        # key -> (user, old_password, new_password, now_ms, outcome)；原序号
        # 索引亦独立分域。
        self._credential_change_cache = {}
        self._credential_change_chain_index = {}
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
        # runtime_restore 运行态检查点恢复的重放缓存，与其余各域独立：
        # key -> (text, 规范包)；仅首次成功缓存，失败（含参数错）不占 key。
        self._runtime_restore_cache = {}
        # timeout_sweep 超时清扫的重放缓存，与其余各域独立：
        # key -> (now_ms, limit, 结果 JSON)；仅首次成功缓存，失败不占 key。
        self._timeout_sweep_cache = {}
        # timeout_storm 超时风暴多批清扫的重放缓存与原序号索引，与其余各域
        # 独立：key -> (now_ms, batches, 结果 JSON)；仅首次成功缓存，失败
        # （含参数错）不占 key。
        self._timeout_storm_cache = {}
        self._timeout_storm_chain_index = {}
        # 按用户失败累计 user -> [认证, 资源, 状态, 后端]：仅 do/meter/
        # capacity 新 key 首次且已定位用户的四类异常各计一次；参数错、
        # KeyError、fault、重放与异参 key 不计，配置变更与重放恢复不清零。
        self._user_fail = {}
        # 建立统计 [总数, 成功]：仅已注册用户验参成功的新 key 首次 do 建立
        # 计总数，成功再计成功；参数错、未知用户（认证失败的已注册用户照计）
        # 与重放不计；配置变更不清零。
        self._establish_total = 0
        self._establish_success = 0

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
        """执行一次建立/续租/下线/迁移/接管操作，返回 LF 结尾的 JSON 字符串。

        建立/迁移/接管在验参后、老化前查后端：故障期按用户指数退避抛
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

        # 建立/迁移/接管：验参后、老化前查后端。迁移/接管由 sid/old 只读
        # 定位，未知 KeyError（不退避，仍缓存并入链）；定位后 BackendError
        # 先于状态、目标池与新 sid 错误；健康才老化并循旧序。
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
        else:
            backend_user = None
        # 停用态用户：建立/迁移/接管先于后端检查与认证拒绝，只入缓存；
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
        """校验 key 之外的四个参数；迁移与接管始终受理（无池于老化后抛
        StateError 或 KeyError），续租仅在已有地址池时受理。"""
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        # 迁移与接管在零池模式下亦通过验参，状态类异常延后到老化之后。
        valid_ops = (_OP_ESTABLISH, _OP_OFFLINE, _OP_MIGRATE, _OP_TAKEOVER)
        if self._pools:
            valid_ops = (
                _OP_ESTABLISH,
                _OP_RENEW,
                _OP_OFFLINE,
                _OP_MIGRATE,
                _OP_TAKEOVER,
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

    def _pool_is_exhausted(self, pool_id, now_ms):
        """池耗尽演练判定，O(1) 时空：注入后 now_ms < 截至即视为无可分配
        地址，到刻（含同刻）自动正常；不演练或已恢复无记录。只读不改态。"""
        until = self._pool_fault.get(pool_id)
        return until is not None and now_ms < until

    def _default_candidate(self, user, now_ms):
        """判定 default 池此刻能否为 user 取址，不改动任何状态。

        返回 (pool_id, ip)：(None, None) 表示缺 default 池；
        ("default", None) 表示有池但动态耗尽、静态址已占用或池处于耗尽
        演练（now_ms < 注入截至）；ip 非 None 为可取址（动态仅窥堆顶、
        不弹出），落库由 _commit_session 完成。
        """
        pool = self._pools.get(_DEFAULT_POOL_ID)
        if pool is None:
            return None, None
        if self._pool_is_exhausted(_DEFAULT_POOL_ID, now_ms):
            return _DEFAULT_POOL_ID, None
        ip_int = pool.static.get(user)
        if ip_int is None:
            ip_int = pool.free[0] if pool.free else None
        elif ip_int in pool.leases:
            # 静态地址专属该用户，但同一时刻只能租给一个会话。
            ip_int = None
        return _DEFAULT_POOL_ID, ip_int

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
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")

        # 建立须经 default 池分配地址；缺 default 池为 StateError。
        pool_id, ip_int = self._default_candidate(user, now_ms)
        if pool_id is None:
            raise StateError("no default pool: cannot establish session")
        if ip_int is None:
            pool = self._pools[pool_id]
            if self._pool_is_exhausted(pool_id, now_ms):
                raise ResourceError("address pool exhausted")
            static_ip = pool.static.get(user)
            if static_ip is not None:
                raise ResourceError(
                    f"static address {ipaddress.IPv4Address(static_ip)} for {user!r} "
                    "already in use"
                )
            raise ResourceError("address pool exhausted")

        # 全部校验通过后再落库，杜绝失败残留。
        deadline, lease = self._commit_session(sid, user, pool_id, ip_int, now_ms)
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
        session["state"] = _STATE_OFFLINE
        session["deadline"] = 0
        self._release(session)
        address = "" if self._pools else None
        return self._render(sid, _STATE_OFFLINE, now_ms, 0, address, 0)

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
        rate, burst, quota, exceed = self._templates[template_id]
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
        时刻、千分字节令牌，首笔 (0, now_ms, C)，C=(限速+突发)*1000；之后
        c 按限速补足并以 C 截顶（配置提交后同标识保留 u/t 并按新模板桶容
        截顶 c）。size*1000 <= c 且 u+size <= 配额则通过并原子提交
        (u+size, now_ms, c-size*1000)；否则取超限动作：拒绝不改账，下线
        不累计并原子下线、清期限、释址退租，账本不变。
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
        rate, burst, quota, exceed = self._templates[template_id]
        capacity = (rate + burst) * 1000

        ledger_key = (user, template_id)
        ledger = self._meter_ledgers.get(ledger_key)
        if ledger is None:
            # 首笔：满桶起步，时刻即此刻；未通过不落账。
            ledger = [0, now_ms, capacity]
        used, last, tokens = ledger
        if now_ms < last:
            raise StateError(
                f"now_ms {now_ms} before last meter time {last} for sid {sid!r}"
            )
        tokens = min(capacity, tokens + rate * (now_ms - last))

        if size * 1000 <= tokens and used + size <= quota:
            # 通过：原子提交累计、时刻与扣减后的令牌。
            used += size
            tokens -= size * 1000
            self._meter_ledgers[ledger_key] = [used, now_ms, tokens]
            result = "通过"
        else:
            result = exceed
            if exceed == "下线":
                # 不累计：原子下线、清期限、释址退租，账本不提交。
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
        账本 u，剩余为 max(0, 配额-u)，令牌为按限速补充并以桶容截顶后的
        千分字节数（只读演算，不落账）。
        """
        _check_credential("user", user)
        _check_int("now_ms", now_ms, 0)
        if user not in self._auth:
            raise KeyError(f"unknown user: {user!r}")
        template_id = self._user_templates.get(user)
        if template_id is None:
            raise StateError(f"no qos template bound for user {user!r}")
        rate, burst, quota, _exceed = self._templates[template_id]
        capacity = (rate + burst) * 1000
        ledger = self._meter_ledgers.get((user, template_id))
        if ledger is None:
            # 无账本：累计 0、满桶，时刻即此刻（不可能触发时刻回拨）。
            used, last, tokens = 0, now_ms, capacity
        else:
            used, last, tokens = ledger
        if now_ms < last:
            raise StateError(
                f"now_ms {now_ms} before last meter time {last} for user {user!r}"
            )
        tokens = min(capacity, tokens + rate * (now_ms - last))
        payload = {
            "时刻": now_ms,
            "用户": user,
            "模板": template_id,
            "累计": used,
            "剩余": max(0, quota - used),
            "令牌": tokens,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

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
        异常。不记审计或容量事件。返回顶层键序“时刻/原子/结果/项目”：结果
        仅提交（全部项处理成功）、部分（非原子含未知）、回滚（原子含未知）；
        项目依输入顺序，项键序“会话/结果”，项结果仅下线/未知/回滚。首次
        调用 O(S+B log A) 时间、O(B) 辅助空间，重放 O(B)。
        """
        _check_credential("key", key)

        cached = self._batch_offline_cache.get(key)
        if cached is not None:
            # 重放：不老化、不下线、不记审计/事件，仅按缓存返回或重抛。
            c_sids, c_now_ms, c_atomic, outcome = cached
            if not _strict_equal(
                (sids, now_ms, atomic), (c_sids, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
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
            items, commit = self._batch_offline_atomic(sids)
        else:
            items, commit = self._batch_offline_sequential(sids)
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

    def _batch_offline_sequential(self, sids):
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
            session["state"] = _STATE_OFFLINE
            session["deadline"] = 0
            self._release(session)
            items.append({"会话": sid, "结果": _STATE_OFFLINE})
        return items, commit

    def _batch_offline_atomic(self, sids):
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
        # 全部存在：逐项提交下线（置下线、期限 0、释放地址租约）。
        items = []
        for sid in sids:
            session = self._sessions[sid]
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
        sid 唯一、default 池与静态址规则。业务异常（AuthError/
        ResourceError/StateError/BackendError/KeyError）不抛，项结果记
        其类名。非原子逐项提交，失败项不影响后项；原子演算全部项，任一
        失败则批内不建会话/租约（已建者回滚、释放地址租约），失败项记
        异常类名、余项记“回滚”；老化、认证计数与退避保留。不记审计或
        容量事件，不计建立/失败统计。返回顶层键序“时刻/原子/结果/项目”：
        结果仅提交（全部上线）、部分（非原子有失败）、回滚（原子有
        失败）；项目依输入顺序，项键序“会话/结果”，项结果仅上线/业务
        异常类名/回滚。首次调用 O(S+B log A) 时间、O(B) 辅助空间，
        重放 O(B)。
        """
        _check_credential("key", key)

        cached = self._batch_online_cache.get(key)
        if cached is not None:
            # 重放：不老化、不建立、不记审计/事件，仅按缓存返回或重抛。
            c_items, c_now_ms, c_atomic, outcome = cached
            if not _strict_equal(
                (items, now_ms, atomic), (c_items, c_now_ms, c_atomic)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
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
        total_count, per_user = self._active_counts()
        results = []
        created = []
        all_ok = True
        for sid, user, password in items:
            try:
                # 停用态用户先于后端检查与认证拒绝：项结果记 AuthError，
                # 不认证、不退避、不计失败计数。
                if user in self._disabled_users:
                    raise AuthError(f"user {user!r} is disabled")
                self._backend_check(user, now_ms, count_fault=False)
                self._batch_establish(
                    sid, user, password, now_ms, total_count, per_user
                )
            except (AuthError, ResourceError, StateError, BackendError, KeyError) as exc:
                # 业务异常不抛：项结果记异常类名，不影响后项。
                results.append({"会话": sid, "结果": type(exc).__name__})
                all_ok = False
            else:
                created.append(sid)
                total_count += 1
                per_user[user] = per_user.get(user, 0) + 1
                results.append({"会话": sid, "结果": _BATCH_ITEM_ONLINE})

        if atomic and not all_ok:
            # 整批回滚：摘除批内所建会话并释放其地址租约（静态址仅退租）；
            # 老化、认证计数与退避保留。
            for sid in created:
                self._release(self._sessions.pop(sid))
            for entry in results:
                if entry["结果"] == _BATCH_ITEM_ONLINE:
                    entry["结果"] = _BATCH_ROLLBACK

        if all_ok:
            result = _BATCH_COMMIT
        else:
            result = _BATCH_ROLLBACK if atomic else _BATCH_PARTIAL
        output = self._render_batch_online(now_ms, atomic, result, results)
        self._batch_online_cache[key] = (items, now_ms, atomic, ("ok", output))
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

    def _batch_establish(self, sid, user, password, now_ms, total_count, per_user):
        """批内单项建立：规则与 _establish 相同（认证→容量→sid 唯一→
        default 池→静态址），但容量计数由调用方按批增量维护，故批处理
        整体为 O(S+B log A) 而非 O(B*S)。

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
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")

        # 建立须经 default 池分配地址；缺 default 池为 StateError。
        pool_id, ip_int = self._default_candidate(user, now_ms)
        if pool_id is None:
            raise StateError("no default pool: cannot establish session")
        if ip_int is None:
            pool = self._pools[pool_id]
            if self._pool_is_exhausted(pool_id, now_ms):
                raise ResourceError("address pool exhausted")
            static_ip = pool.static.get(user)
            if static_ip is not None:
                raise ResourceError(
                    f"static address {ipaddress.IPv4Address(static_ip)} for {user!r} "
                    "already in use"
                )
            raise ResourceError("address pool exhausted")

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
        达全局/单用户上限或缺 default 池、无可取址则入队等待，需排队且队长
        已达配置队列上限（0 表示不限，默认 1024）抛 ResourceError 并记既有
        “队满”事件；否则原子建立在线会话，失败不留半分配。老化挂起即释址，
        挂起会话不持址、不计在线，但仍占全局与单用户上限。
        取消未知 sid 抛 KeyError，sid 为非排队项抛 StateError。推进遇待触发
        且 now_ms>=触发值的全局超时演练（timeout_fault 注入）时，不老化、不
        走普通超时与晋升，直接原子挂起全部在线会话、清期限释放租约，按入队序
        将全部队项记超时后删除并清除触发，输出在线 0、排队 0、变更为各超时项
        入队序；无待触发或未到刻时推进先老化，再清除截止（=申请时刻+等待）
        ≤ now_ms 的排队项，随后依入队序晋升上限
        允许且可取址者，直至全局上限满；变更仅含本次推进超时与晋升项的入队序，
        先超时后晋升；输出“在线”仅计在线会话。新 key 首次结果（成功或
        AuthError/ResourceError/StateError/KeyError，含验参异常）永久缓存，
        同参重放无副作用、直接返回或重抛，异参抛 ValueError；缓存与
        do/meter 分域。仅首个验参成功的新 key 记 capacity 事件，重放不记。
        时间复杂度：申请 O(S+log A)、取消 O(Q)、推进 O(S+Q log A)
        （超时演练触发批为 O(S log A+Q)），辅助空间 O(Q)。
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
        pool_id, ip_int = self._default_candidate(user, now_ms)
        servable = (
            total_count < self._total
            and user_count < self._per
            and pool_id is not None
            and ip_int is not None
        )
        if servable:
            self._commit_session(sid, user, pool_id, ip_int, now_ms)
            self._cap_event(now_ms, sid, _CAP_ONLINE, 0)
            return self._render_capacity(sid, _CAP_ONLINE, now_ms, deadline)

        # 在线满（含挂起占位）或缺址：入队等待，队列本身达上限则 ResourceError；
        # 队列上限为 0 表示不限。
        if self._queue_limit != 0 and len(self._capacity_queue) >= self._queue_limit:
            raise ResourceError(
                f"capacity queue limit {self._queue_limit} reached"
            )
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
        """先清超时项再依入队序晋升，返回时刻/在线/排队/变更 JSON。

        输出“在线”仅计在线会话；挂起会话不持址、不计在线，但仍占全局与
        单用户上限，晋升闸以非下线计数为准。事件按入队序先记超时、后记晋升。
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

        # 晋升：计数只扫一次会话表，晋升时增量维护；取址落库每弹一堆 O(log A)。
        total_count, per_user = self._active_counts()
        promoted = []
        remaining = []
        for queued_sid in survivors:
            entry = self._capacity_queue[queued_sid]
            user = entry[0]
            pool_id, ip_int = self._default_candidate(user, now_ms)
            if (
                total_count < self._total
                and per_user.get(user, 0) < self._per
                and pool_id is not None
                and ip_int is not None
            ):
                self._commit_session(queued_sid, user, pool_id, ip_int, now_ms)
                promoted.append((queued_sid, entry[4]))
                del self._capacity_queue[queued_sid]
                total_count += 1
                per_user[user] = per_user.get(user, 0) + 1
            else:
                remaining.append(queued_sid)
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
        """非下线会话总数与按用户计数（含在线与挂起，排队项不计），单次 O(S)。"""
        total_count = 0
        per_user = {}
        for session in self._sessions.values():
            if session["state"] != _STATE_OFFLINE:
                total_count += 1
                user = session["user"]
                per_user[user] = per_user.get(user, 0) + 1
        return total_count, per_user

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
        self._capacity_events.append(
            (seq, now_ms, sid, verdict, order, prev_hash, digest)
        )
        self._capacity_tail = digest

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
        模板按标识、用户模板按用户升序，容量为 (队列上限, 最大等待毫秒)。"""
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
        return (
            self._total,
            self._per,
            self._idle_ms,
            self._lease_ms,
            tuple(pool_specs),
            templates,
            user_templates,
            (self._queue_limit, self._max_wait_ms),
        )

    def export_config(self):
        """导出当前配置为 v4 JSON（LF 结尾），O(n log n + S + Q)/O(n)。

        顶层键序为“版本/会话/地址池/模板/用户模板/容量”；会话键序为“总数/
        每用户/空闲毫秒/租期毫秒”；地址池为按标识升序的列表，项键序为“标识/
        CIDR/保留/静态”，保留为按 IPv4 整数升序的串列表，静态为按用户再 IP
        升序的二元串列表；模板为按标识升序的列表，项键序为“标识/限速/突发/
        配额/超限”；用户模板为按用户升序的 [user, 标识] 二元串列表；容量键序
        为“队列上限/最大等待毫秒”，0 分别表示不限队长与不限等待。
        """
        return _compact_config(self._current_spec()) + "\n"

    def upgrade_config(self, text, target=4):
        """只读地将 v1..v4 配置文本升级到 target（仅支持 4），返回升级包 JSON。

        text 须为 str、target 须为非 bool int，否则抛 TypeError；源版本限
        1..4 且 target 只许 4；JSON 解析、重复键、键缺失或未知、结构、值、
        引用或版本非法均抛 ValueError。迁移沿既有规则：v1 单池改 default，
        v1/v2 补空模板与用户模板，v1-v3 补容量 (1024, 0)，v4 只规范化。
        返回基线格式的 LF 尾紧凑 JSON：顶层序/型为“源版本:int、目标版本:int、
        改变:bool、摘要:str、配置:object”，改变 = 源版本 != 4；配置逐层键序、
        类型与排序同 export_config() 的 v4；摘要为配置对象同法编码、去 LF 后
        的 UTF-8 字节 sha256 小写值。升级只读，不触碰任何实例状态；时/空上界
        O(n log n)/O(n)。
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
        spec = _parse_config_doc(doc)
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

    def _build_pools(self, spec):
        """校验 spec 对现有会话与等待队列的承载力并构建新池表；失败抛 ResourceError。

        任一上限低于对应非下线会话数，或新池无法按原池、地址、用户承载
        在租租约（池缺失、地址不可用/被保留、静态址易主），或当前队长大于
        目标队列上限（0 表示不限），均抛 ResourceError；本方法不改任何状态，
        旧队项的等待、截止与入队序均不触碰。
        """
        (
            total,
            per,
            _idle_ms,
            _lease_ms,
            pool_specs,
            _templates,
            _user_templates,
            (queue_limit, _max_wait_ms),
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
        # 队长承载：当前队长 > 目标上限即不可承载（上限 0 表示不限）。
        if queue_limit != 0 and len(self._capacity_queue) > queue_limit:
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
        """原子替换配置数值、池表、QoS 模板与容量背压；会话状态、期限、地址、
        租期及旧队项的等待、截止、入队序均不变。计量账本同标识保留 u/t 并
        按新模板桶容截顶 c。"""
        (
            total,
            per,
            idle_ms,
            lease_ms,
            _pool_specs,
            templates,
            user_templates,
            (queue_limit, max_wait_ms),
        ) = spec
        self._total = total
        self._per = per
        self._idle_ms = idle_ms
        self._lease_ms = lease_ms
        self._pools = new_pools
        self._templates = {
            template_id: (rate, burst, quota, exceed)
            for template_id, rate, burst, quota, exceed in templates
        }
        self._user_templates = dict(user_templates)
        self._queue_limit = queue_limit
        self._max_wait_ms = max_wait_ms
        # 计量账本：同标识保留 u/t 并按新模板桶容截顶 c；已删模板的账本原样
        # 保留（改绑后按新 (用户, 模板) 独立建账），加载/回滚失败不经过本方法。
        for (_ledger_user, ledger_template), ledger in self._meter_ledgers.items():
            template = self._templates.get(ledger_template)
            if template is not None:
                ledger[2] = min(ledger[2], (template[0] + template[1]) * 1000)
        # 配置加载/回滚成功后保留同名池的耗尽演练、清除已删池（截至不改）；
        # 加载失败不经过本方法，故障态不变。
        self._pool_fault = {
            pool_id: until
            for pool_id, until in self._pool_fault.items()
            if pool_id in new_pools
        }

    def load_config(self, text):
        """校验并原子加载配置文本，保存旧配置为唯一回滚点，返回新配置 v4 JSON。

        直载 v1..v4 配置，或加载 upgrade_config 产出的升级包；升级包须复核
        键序、字段、配置规范形态与摘要，任一不符抛 ValueError。text 非 str
        抛 TypeError；JSON 解析、重复/未知/缺失键、结构、类型、值、重复项或
        引用（用户模板引用未注册用户或未知模板标识）错抛 ValueError；上限、
        租约或队长承载不满足抛 ResourceError。全部校验通过后原子提交：失败
        不改配置、回滚点、会话、租约与运行态；成功不老化，会话与租约不变，
        新值仅作用于后续操作与查询。成功加载覆盖唯一回滚点。
        """
        doc = _load_config_doc(text)
        if isinstance(doc, dict) and "源版本" in doc:
            _source, _target, _changed, _summary, spec = (
                _parse_upgrade_envelope(doc)
            )
        else:
            spec = _parse_config_doc(doc)
        for user, _template_id in spec[6]:
            if user not in self._auth:
                raise ValueError(
                    f"user template user not in authenticator: {user!r}"
                )
        new_pools = self._build_pools(spec)
        self._rollback = self._current_spec()
        self._install_spec(spec, new_pools)
        return self.export_config()

    def rollback_config(self):
        """经同样校验恢复唯一回滚点配置并清除回滚点，返回恢复后的 v4 JSON。

        无回滚点抛 StateError；校验失败（ResourceError）不改配置、回滚点或
        运行态，回滚点保留；成功清除回滚点，不老化。
        """
        spec = self._rollback
        if spec is None:
            raise StateError("no config rollback point")
        new_pools = self._build_pools(spec)
        self._rollback = None
        self._install_spec(spec, new_pools)
        return self.export_config()

    def config_change(self, key, op, text, now_ms):
        """配置加载/回滚的幂等事务入口，原样返回 load_config/rollback_config
        的 v4、LF 尾紧凑 JSON。

        依次校验：key 沿用凭据约束；op 须为非 bool str 且仅“加载/回滚”；
        加载时 text 须为 str，回滚时 text 须为 None；now_ms 须为非 bool
        非负 int。类型错抛 TypeError，值或模式错抛 ValueError。key 有效后以
        独立域永久缓存余参与首果（含参数异常）：严格同型同参重放不改配置，
        直接返回或重抛首果；异参抛 ValueError；参数错也缓存但不审计。

        首次合法调用分别执行既有 load_config(text)/rollback_config()：成功
        原样返回其 JSON；配置非法抛 ValueError、承载冲突抛 ResourceError、
        无回滚点抛 StateError，异常类型与 args 一并缓存。除缓存、审计外，
        失败不得改变配置、回滚点、用户、会话、租约、队列、统计或故障态。

        首次业务结果（成功或异常）与同参重放均向既有防篡改审计哈希链追加
        一项：操作为“配置加载/配置回滚”，会话记空串；首次原序号 0，结果为
        “成功”或异常类名；重放原序号指认首次事件，结果为“重放成功”或
        “重放”加异常类名，并返回或重抛首果。异参不审计。首次复杂度沿既有
        接口，重放 O(1) 时空。
        """
        _check_credential("key", key)

        cached = self._config_change_cache.get(key)
        if cached is not None:
            # 重放：不加载、不回滚、不老化、不改任何状态，仅按缓存返回或重抛。
            c_op, c_text, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, text, now_ms), (c_op, c_text, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
            # 首次业务结果（成功/异常）的同参重放入链记“重放成功”或“重放”
            # 加异常类名，原序号指认首次事件；参数错不在本域链索引中，自然跳过。
            origin = self._config_change_chain_index.get(key)
            if origin is not None:
                chain_op = (
                    _CONFIG_CHAIN_LOAD if c_op == _CONFIG_OP_LOAD
                    else _CONFIG_CHAIN_ROLLBACK
                )
                if outcome[0] == "ok":
                    chain_result = "重放成功"
                else:
                    chain_result = "重放" + outcome[1][0].__name__
                self._chain_append(
                    key,
                    chain_op,
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

        # 首次合法调用：执行既有加载/回滚；业务异常（ValueError/
        # ResourceError/StateError）缓存类型与 args 并入链，不改配置与运行态。
        if op == _CONFIG_OP_LOAD:
            chain_op = _CONFIG_CHAIN_LOAD
            try:
                result = self.load_config(text)
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
        else:
            chain_op = _CONFIG_CHAIN_ROLLBACK
            try:
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

        op 限加载/回滚；加载 text 须为 str，回滚 text 须为 None（任何非 None
        皆值错）；now_ms 为非 bool 非负 int。加载文本的内容合法性由
        load_config 复核（空串等在此仅视为 str，业务失败归 ValueError）。
        """
        # 类型阶段：任一类型错先于任何值/模式错抛出。
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op == _CONFIG_OP_LOAD and not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")

        # 取值/模式阶段。
        if op not in (_CONFIG_OP_LOAD, _CONFIG_OP_ROLLBACK):
            raise ValueError(f"op must be one of 加载/回滚, got {op!r}")
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
            # denied/locked：失败计数与锁定已由 Authenticator 保留，此处不改。
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

        # 成功：按摘要规则换密并清零失败计数与锁定；会话与已入队队项保持不变。
        record = self._auth._users[user]
        record[0] = _digest(user, new_password)
        record[1] = 0
        record[2] = None
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
                for session in self._sessions.values():
                    if (
                        session["user"] == user
                        and session["state"] != _STATE_OFFLINE
                    ):
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
        self._chain_events.append(
            (seq, now_ms, key, op, sid, result, origin, prev_hash, digest)
        )
        self._chain_tail = digest

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
