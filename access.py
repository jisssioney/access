"""access — 接入网后端服务框架（仅标准库）。

当前提供：
- Authenticator：带失败计数与锁定的用户认证器。
- Sessions：基于 Authenticator 的会话管理（建立/续租/下线/接管/跨池迁移、空闲老化、
  零池起步可 add_pool 激活多地址池、租约、按 key 重放缓存、pool_stats、接管审计
  takeover_audit、防篡改审计链 audit/verify_audit、配置导出/加载/回滚
  export_config/load_config/rollback_config）。
所有时间均由调用方以显式时钟（毫秒整数）驱动。
"""

import hashlib
import heapq
import hmac
import ipaddress
import json

__all__ = ["Authenticator", "AuthError", "ResourceError", "StateError", "Sessions"]

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


def _config_object(pairs):
    """json object_pairs_hook：重复键抛 ValueError。"""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key: {key!r}")
        obj[key] = value
    return obj


def _require_keys(obj, expected, name):
    """要求 dict 键集恰好为 expected；缺失/未知键均抛 ValueError。"""
    keys = set(obj)
    missing = expected - keys
    if missing:
        raise ValueError(f"{name} missing keys: {sorted(missing)}")
    unknown = keys - expected
    if unknown:
        raise ValueError(f"{name} unknown keys: {sorted(unknown)}")


def _config_int(name, value, minimum):
    """配置数校验：非 bool 的 int 且 >= minimum，否则 ValueError。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int, got {type(value).__name__}")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _config_pool_id(value):
    """配置中的池标识校验：规则同 add_pool 的 pool id，但一律 ValueError。"""
    if not isinstance(value, str):
        raise ValueError(f"pool id must be a str, got {type(value).__name__}")
    encoded = value.encode("utf-8")
    if not (_MIN_CRED_BYTES <= len(encoded) <= _MAX_CRED_BYTES):
        raise ValueError(
            f"pool id must be 1..256 bytes when UTF-8 encoded, got {len(encoded)}"
        )
    if "\0" in value:
        raise ValueError("pool id must not contain U+0000")
    return value


def _parse_config_pool(entry):
    """由配置池对象的 CIDR/保留/静态构造 _check_pool 入参并解析。

    保留为字符串列表、静态为二元字符串列表；池规则与 add_pool 一致，
    类型类错误在此一律转为 ValueError。
    """
    cidr = entry["CIDR"]
    reserved = entry["保留"]
    static = entry["静态"]
    if not isinstance(cidr, str):
        raise ValueError(f"CIDR must be a str, got {type(cidr).__name__}")
    if not isinstance(reserved, list):
        raise ValueError(f"保留 must be a list, got {type(reserved).__name__}")
    if not isinstance(static, list):
        raise ValueError(f"静态 must be a list, got {type(static).__name__}")
    static_pairs = []
    for pair in static:
        if not isinstance(pair, list):
            raise ValueError(
                f"static entry must be a 2-list [user, IP], got {type(pair).__name__}"
            )
        if len(pair) != 2:
            raise ValueError(
                f"static entry must be a 2-list [user, IP], got {len(pair)} items"
            )
        static_pairs.append((pair[0], pair[1]))
    try:
        return _check_pool((cidr, tuple(reserved), tuple(static_pairs)))
    except TypeError as exc:
        raise ValueError(str(exc)) from exc


def _parse_config(text):
    """解析并校验配置文本，返回 (total, per, idle_ms, lease_ms, pool_items)。

    pool_items 为 [(标识, _check_pool 返回值)]，v1 的无标识单池迁移为 default。
    JSON 解析、重复/未知/缺失键、结构、值或池规则错误均抛 ValueError。
    """
    data = json.loads(text, object_pairs_hook=_config_object)
    if not isinstance(data, dict):
        raise ValueError(f"config must be a JSON object, got {type(data).__name__}")
    _require_keys(data, {"版本", "会话", "地址池"}, "config")

    version = data["版本"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"版本 must be an int, got {type(version).__name__}")
    if version not in (1, 2):
        raise ValueError(f"版本 must be 1 or 2, got {version}")

    session = data["会话"]
    if not isinstance(session, dict):
        raise ValueError(f"会话 must be an object, got {type(session).__name__}")
    _require_keys(session, {"总数", "每用户", "空闲毫秒", "租期毫秒"}, "会话")
    total = _config_int("总数", session["总数"], 1)
    per = _config_int("每用户", session["每用户"], 1)
    idle_ms = _config_int("空闲毫秒", session["空闲毫秒"], 0)
    lease_ms = _config_int("租期毫秒", session["租期毫秒"], 1)

    pools_raw = data["地址池"]
    pool_items = []
    if version == 2:
        if not isinstance(pools_raw, list):
            raise ValueError(
                f"地址池 must be a list for 版本 2, got {type(pools_raw).__name__}"
            )
        seen = set()
        for entry in pools_raw:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"地址池 entry must be an object, got {type(entry).__name__}"
                )
            _require_keys(entry, {"标识", "CIDR", "保留", "静态"}, "地址池 entry")
            pool_id = _config_pool_id(entry["标识"])
            if pool_id in seen:
                raise ValueError(f"duplicate pool id: {pool_id!r}")
            seen.add(pool_id)
            pool_items.append((pool_id, _parse_config_pool(entry)))
    else:
        # v1：无标识单池对象，迁移为 default 池。
        if not isinstance(pools_raw, dict):
            raise ValueError(
                f"地址池 must be an object for 版本 1, got {type(pools_raw).__name__}"
            )
        _require_keys(pools_raw, {"CIDR", "保留", "静态"}, "地址池")
        pool_items.append((_DEFAULT_POOL_ID, _parse_config_pool(pools_raw)))
    return total, per, idle_ms, lease_ms, pool_items


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


class _Pool:
    """单个地址池：保留/静态集、动态空闲最小堆与本池租用地址表。

    租用地址表按池隔离，故不同池的地址（int）允许重叠。
    """

    __slots__ = ("network", "capacity", "reserved", "static", "static_ips", "free",
                 "leases")

    def __init__(self, parsed):
        network, usable, reserved, static, static_ips = parsed
        self.network = network
        self.capacity = len(usable)
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
    参数错与异参 key 重放不入链。export_config 导出 v2 配置 JSON（键序固定、
    池按标识、保留按 IPv4 整数、静态按用户再 IP 升序，LF 结尾）；load_config
    校验后原子替换配置（v1 无标识单池迁移为 default）并保存旧配置为回滚点，
    上限低于对应非下线会话数或新池无法按原池、地址、用户承载既有租约时抛
    ResourceError；rollback_config 经同样校验恢复回滚点并清除之，无回滚点
    抛 StateError。配置替换不影响会话状态、期限、地址与租期，新值仅作用于
    后续操作；失败不改状态。
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

        # sid -> {"user": str, "state": str, "deadline": int, "ip": int|None,
        #         "lease": int, "pool": str|None}
        self._sessions = {}
        # key -> (op, sid, args, now_ms, outcome)
        # outcome 为 ("ok", json_str) 或 ("err", (exc_class, exc_args))
        self._cache = {}
        # 接管审计事件追加序列（序号自 1）；key -> 首次事件序号，供重放指认。
        self._audit_events = []
        self._audit_index = {}
        # 防篡改审计链：事件九元组序列（序号自 1）、key -> 首次事件序号、
        # 末项哈希（空链为 64 个 0，即首项前哈希）。
        self._chain_events = []
        self._chain_index = {}
        self._chain_tail = "0" * 64
        # 配置回滚点：最近一次 load_config 成功前的配置（v2 JSON 文本），无则 None。
        self._rollback = None

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
        """执行一次建立/续租/下线/迁移/接管操作，返回 LF 结尾的 JSON 字符串。"""
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

        # 非重放：先将到期在线会话挂起、到期租约释放。
        self._age(now_ms)
        is_takeover = op == _OP_TAKEOVER
        try:
            if op == _OP_ESTABLISH:
                result = self._establish(sid, args[0], args[1], now_ms)
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
        """到期（含同刻）处理：租约到期先释址，空闲到期再挂起、期限清零。"""
        for session in self._sessions.values():
            if session["state"] != _STATE_ONLINE:
                continue
            if session["ip"] is not None and session["lease"] <= now_ms:
                self._release(session)
            if session["deadline"] <= now_ms:
                self._release(session)
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

    def _establish(self, sid, user, password, now_ms):
        """初始→认证中→在线；任一失败不留会话与租约残留。"""
        # 先认证。
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")
        # 后查 total 及用户 per，均计非下线会话。
        total_count = 0
        user_count = 0
        for session in self._sessions.values():
            if session["state"] != _STATE_OFFLINE:
                total_count += 1
                if session["user"] == user:
                    user_count += 1
        if total_count >= self._total:
            raise ResourceError(f"total session limit {self._total} reached")
        if user_count >= self._per:
            raise ResourceError(f"per-user session limit {self._per} reached for {user!r}")
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")

        # 建立须经 default 池分配地址；缺 default 池为 StateError。
        pool = self._pools.get(_DEFAULT_POOL_ID)
        if pool is None:
            raise StateError("no default pool: cannot establish session")
        pool_id = _DEFAULT_POOL_ID
        ip_int = pool.static.get(user)
        if ip_int is None:
            # 非静态用户：取最小未租用的非保留非静态地址。
            if not pool.free:
                raise ResourceError("address pool exhausted")
            ip_int = heapq.heappop(pool.free)
        elif ip_int in pool.leases:
            # 静态地址专属该用户，但同一时刻只能租给一个会话。
            raise ResourceError(
                f"static address {ipaddress.IPv4Address(ip_int)} for {user!r} "
                "already in use"
            )
        lease = now_ms + self._lease_ms

        # 全部校验通过后再落库，杜绝失败残留。
        pool.leases[ip_int] = sid
        deadline = now_ms + self._idle_ms
        self._sessions[sid] = {
            "user": user,
            "state": _STATE_ONLINE,
            "deadline": deadline,
            "ip": ip_int,
            "lease": lease,
            "pool": pool_id,
        }
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

    def export_config(self):
        """导出当前配置为 v2 JSON 字符串（LF 结尾），O((P+A)log(P+A)) 时间。

        顶层键序为“版本/会话/地址池”；会话键序为“总数/每用户/空闲毫秒/
        租期毫秒”；地址池按标识升序，项键序为“标识/CIDR/保留/静态”，保留按
        IPv4 整数升序、静态按用户再 IP 升序，均为字符串列表/二元字符串列表。
        """
        pools = []
        for pool_id in sorted(self._pools):
            pool = self._pools[pool_id]
            reserved = [
                str(ipaddress.IPv4Address(ip_int))
                for ip_int in sorted(pool.reserved)
            ]
            static = [
                [user, str(ipaddress.IPv4Address(ip_int))]
                for user, ip_int in sorted(pool.static.items())
            ]
            pools.append(
                {
                    "标识": pool_id,
                    "CIDR": str(pool.network),
                    "保留": reserved,
                    "静态": static,
                }
            )
        payload = {
            "版本": 2,
            "会话": {
                "总数": self._total,
                "每用户": self._per,
                "空闲毫秒": self._idle_ms,
                "租期毫秒": self._lease_ms,
            },
            "地址池": pools,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def load_config(self, text):
        """校验并原子替换配置，保存旧配置为回滚点，返回新配置 v2 JSON。

        text 非 str 抛 TypeError；JSON 解析、重复/未知/缺失键、结构、值或
        池规则错误抛 ValueError；v1 单池迁移为 default 池，输出恒为 v2。
        任一上限低于对应非下线会话数，或新池无法按原池、地址、用户承载
        既有租约，抛 ResourceError。会话状态、期限、地址、租期不变，新值
        仅作用于后续操作；失败不改状态（含回滚点）。
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")
        config = _parse_config(text)
        # 先导出旧配置作回滚点，再校验资源约束，全部通过才落库。
        old_config = self.export_config()
        self._apply_config(config)
        self._rollback = old_config
        return self.export_config()

    def rollback_config(self):
        """经与 load_config 相同的校验恢复回滚点配置并清除回滚点。

        无回滚点抛 StateError；恢复时上限/租约承载校验失败抛 ResourceError，
        此时状态与回滚点均不变。成功返回恢复后的配置 v2 JSON。
        """
        if self._rollback is None:
            raise StateError("no rollback point: nothing to roll back to")
        config = _parse_config(self._rollback)
        self._apply_config(config)
        self._rollback = None
        return self.export_config()

    def _apply_config(self, config):
        """校验资源约束并原子替换配置；ResourceError 时不改任何状态。

        时/空 O(P+A+S)/O(P+A)：先计数非下线会话、按池归集既有租约并校验
        新池可按原池、地址、用户承载，再建新池（含既有租约）整体替换。
        """
        total, per, idle_ms, lease_ms, pool_items = config

        total_count = 0
        user_counts = {}
        # 池 id -> {地址 int: (sid, user)}，仅含持址会话。
        leases_by_pool = {}
        for sid, session in self._sessions.items():
            if session["state"] != _STATE_OFFLINE:
                total_count += 1
                user = session["user"]
                user_counts[user] = user_counts.get(user, 0) + 1
            ip_int = session["ip"]
            if ip_int is not None:
                leases_by_pool.setdefault(session["pool"], {})[ip_int] = (
                    sid,
                    session["user"],
                )
        if total < total_count:
            raise ResourceError(
                f"total session limit {total} below active count {total_count}"
            )
        for user, count in user_counts.items():
            if per < count:
                raise ResourceError(
                    f"per-user session limit {per} below active count {count} "
                    f"for {user!r}"
                )

        pool_map = dict(pool_items)
        for pool_id, leases in leases_by_pool.items():
            parsed = pool_map.get(pool_id)
            if parsed is None:
                raise ResourceError(
                    f"new config lacks pool {pool_id!r} holding active leases"
                )
            _network, usable, reserved, static_map, static_ips = parsed
            for ip_int, (sid, user) in leases.items():
                address = ipaddress.IPv4Address(ip_int)
                if ip_int not in usable:
                    raise ResourceError(
                        f"address {address} of sid {sid!r} not usable in new "
                        f"pool {pool_id!r}"
                    )
                if ip_int in reserved:
                    raise ResourceError(
                        f"address {address} of sid {sid!r} is reserved in new "
                        f"pool {pool_id!r}"
                    )
                if ip_int in static_ips and static_map.get(user) != ip_int:
                    raise ResourceError(
                        f"address {address} of sid {sid!r} is static for another "
                        f"user in new pool {pool_id!r}"
                    )

        # 全部校验通过：建新池并迁入既有租约，再一次赋值完成原子替换。
        pools = {}
        for pool_id, parsed in pool_items:
            pool = _Pool(parsed)
            held = leases_by_pool.get(pool_id)
            if held:
                pool.leases = {ip_int: sid for ip_int, (sid, _u) in held.items()}
                dynamic = set(pool.leases) - pool.static_ips
                if dynamic:
                    pool.free = [x for x in pool.free if x not in dynamic]
                    heapq.heapify(pool.free)
            pools[pool_id] = pool
        self._total = total
        self._per = per
        self._idle_ms = idle_ms
        self._lease_ms = lease_ms
        self._pools = pools

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

    def _chain_append(self, key, op, sid, result, now_ms, origin=0):
        """追加一条防篡改审计事件，O(1) 时空。

        序号自 1 递增；首次事件登记 key -> 序号且原序号为 0，重放事件沿用
        首次结果、原序号指认首次事件序号。前哈希首项为 64 个 0，余取前项哈希。
        """
        seq = len(self._chain_events) + 1
        prev_hash = self._chain_tail
        digest = self._chain_hash(
            seq, now_ms, key, op, sid, result, origin, prev_hash
        )
        if origin == 0:
            self._chain_index[key] = seq
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
