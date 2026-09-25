"""access — 接入网后端服务框架（仅标准库）。

当前提供：
- Authenticator：带失败计数与锁定的用户认证器。
- Sessions：基于 Authenticator 的会话管理（建立/续租/下线、空闲老化、
  可选 IPv4 地址租约、按 key 重放缓存）。
所有时间均由调用方以显式时钟（毫秒整数）驱动。
"""

import hashlib
import hmac
import json

__all__ = ["Authenticator", "AuthError", "ResourceError", "StateError", "Sessions"]

_MAX_USERS = 10000
_MIN_CRED_BYTES = 1
_MAX_CRED_BYTES = 256


class AuthError(Exception):
    """认证结果非 ok。"""


class ResourceError(Exception):
    """会话总数、单用户会话数或地址池可用地址已达上限。"""


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


def _check_ipv4(name, value):
    """校验规范点分十进制 IPv4 串（无前导零），返回 32 位整数。"""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    parts = value.split(".")
    if len(parts) != 4:
        raise ValueError(f"{name} must be a dotted quad, got {value!r}")
    result = 0
    for part in parts:
        if not part or any(ch < "0" or ch > "9" for ch in part):
            raise ValueError(f"{name} must be a canonical IPv4 address, got {value!r}")
        if len(part) > 1 and part[0] == "0":
            raise ValueError(f"{name} must not have leading zero octets, got {value!r}")
        octet = int(part)
        if octet > 255:
            raise ValueError(f"{name} octet out of range 0..255, got {value!r}")
        result = (result << 8) | octet
    return result


def _format_ipv4(value):
    """把 32 位整数格式化为规范点分十进制串。"""
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _check_cidr(name, value):
    """校验主机位零、前缀 16..32 的规范 IPv4 网串，返回 (网络地址, 前缀)。"""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if value.count("/") != 1:
        raise ValueError(f"{name} must look like 'a.b.c.d/prefix', got {value!r}")
    ip_text, prefix_text = value.split("/")
    network = _check_ipv4(name, ip_text)
    if (
        not prefix_text
        or any(ch < "0" or ch > "9" for ch in prefix_text)
        or (len(prefix_text) > 1 and prefix_text[0] == "0")
    ):
        raise ValueError(f"{name} has a non-canonical prefix, got {value!r}")
    prefix = int(prefix_text)
    if not 16 <= prefix <= 32:
        raise ValueError(f"{name} prefix must be 16..32, got {prefix}")
    if network & ((1 << (32 - prefix)) - 1):
        raise ValueError(f"{name} must have zero host bits, got {value!r}")
    return network, prefix


def _check_pool(pool):
    """校验地址池；返回 None 或 (升序动态地址列表, {user: 静态地址})。

    可用集：/16../30 去网络/广播地址，/31 两址、/32 独址全可用。
    保留与静态地址均须规范、属可用集且唯一，静态用户唯一，两集不交。
    """
    if pool is None:
        return None
    if not isinstance(pool, tuple):
        raise TypeError(
            f"pool must be None or a 3-tuple (cidr, reserved, static), "
            f"got {type(pool).__name__}"
        )
    if len(pool) != 3:
        raise ValueError(
            f"pool must be a 3-tuple (cidr, reserved, static), got {len(pool)} items"
        )
    cidr, reserved, static = pool
    network, prefix = _check_cidr("cidr", cidr)
    size = 1 << (32 - prefix)
    if prefix >= 31:
        available = set(range(network, network + size))
    else:
        available = set(range(network + 1, network + size - 1))

    if not isinstance(reserved, tuple):
        raise TypeError(
            f"reserved must be a tuple of IP strings, got {type(reserved).__name__}"
        )
    reserved_ips = set()
    for ip in reserved:
        ipn = _check_ipv4("reserved ip", ip)
        if ipn not in available:
            raise ValueError(f"reserved ip {ip!r} is not in the available set")
        if ipn in reserved_ips:
            raise ValueError(f"duplicate reserved ip: {ip!r}")
        reserved_ips.add(ipn)

    if not isinstance(static, tuple):
        raise TypeError(
            f"static must be a tuple of (user, IP) pairs, got {type(static).__name__}"
        )
    static_by_user = {}
    static_ips = set()
    for item in static:
        if not isinstance(item, tuple):
            raise TypeError(
                f"static entry must be a (user, IP) tuple, got {type(item).__name__}"
            )
        if len(item) != 2:
            raise ValueError(
                f"static entry must be a (user, IP) pair, got {len(item)} items"
            )
        user, ip = item
        _check_credential("user", user)
        ipn = _check_ipv4("static ip", ip)
        if user in static_by_user:
            raise ValueError(f"duplicate static user: {user!r}")
        if ipn not in available:
            raise ValueError(f"static ip {ip!r} is not in the available set")
        if ipn in reserved_ips or ipn in static_ips:
            raise ValueError(f"duplicate ip across reserved/static: {ip!r}")
        static_by_user[user] = ipn
        static_ips.add(ipn)

    dynamic = sorted(available - reserved_ips - static_ips)
    return (dynamic, static_by_user)


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


# 会话状态；初始/认证中仅为建立过程中的瞬态，落库状态为在线/挂起/下线。
_STATE_ONLINE = "在线"
_STATE_SUSPENDED = "挂起"
_STATE_OFFLINE = "下线"

_OP_ESTABLISH = "建立"
_OP_OFFLINE = "下线"
_OP_RENEW = "续租"


class Sessions:
    """会话管理：建立需先认证再查限额，下线按 sid；按 key 永久缓存重放。

    pool 非 None 时启用 IPv4 地址租约：建立分配地址（静态用户取其专属
    地址，否则取最小未租动态地址，耗尽 ResourceError），续租延长租期，
    租期到期、挂起或下线即释放地址；静态地址释放后仍专属原用户。
    """

    def __init__(self, auth, total, per, idle_ms, pool=None, lease_ms=1):
        if not isinstance(auth, Authenticator):
            raise TypeError(f"auth must be an Authenticator, got {type(auth).__name__}")
        self._auth = auth
        self._total = _check_int("total", total, 1)
        self._per = _check_int("per", per, 1)
        self._idle_ms = _check_int("idle_ms", idle_ms, 0)
        parsed_pool = _check_pool(pool)
        self._lease_ms = _check_int("lease_ms", lease_ms, 1)
        self._pool_enabled = parsed_pool is not None
        if parsed_pool is None:
            self._dynamic = ()
            self._static = {}
        else:
            self._dynamic, self._static = parsed_pool
        # sid -> {"user": str, "state": str, "deadline": int,
        #         "ip": str, "ipn": int|None, "lease": int}
        self._sessions = {}
        # 当前已租出的地址（int 集合）。
        self._leased = set()
        # key -> (op, sid, args, now_ms, outcome)
        # outcome 为 ("ok", json_str) 或 ("err", (exc_class, exc_args))，
        # 参数校验异常与四种业务异常均按 ("err", ...) 缓存。
        self._cache = {}

    def do(self, key, op, sid, args, now_ms):
        """执行一次建立/续租/下线操作，返回 LF 结尾的 JSON 字符串。"""
        _check_credential("key", key)
        cached = self._cache.get(key)
        if cached is not None:
            # 重放：不老化、不认证、不改租约，仅按缓存返回或重抛。
            c_op, c_sid, c_args, c_now_ms, outcome = cached
            if (op, sid, args, now_ms) != (c_op, c_sid, c_args, c_now_ms):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        try:
            self._check_params(op, sid, args, now_ms)
        except (TypeError, ValueError) as exc:
            self._cache[key] = (op, sid, args, now_ms, ("err", (type(exc), exc.args)))
            raise

        # 非重放：先将到期在线会话挂起、到期租约释放。
        self._age(now_ms)
        try:
            if op == _OP_ESTABLISH:
                result = self._establish(sid, args[0], args[1], now_ms)
            elif op == _OP_RENEW:
                result = self._renew(sid, now_ms)
            else:
                result = self._offline(sid, now_ms)
        except (AuthError, ResourceError, StateError, KeyError) as exc:
            self._cache[key] = (op, sid, args, now_ms, ("err", (type(exc), exc.args)))
            raise
        self._cache[key] = (op, sid, args, now_ms, ("ok", result))
        return result

    def _check_params(self, op, sid, args, now_ms):
        """校验 key 以外的四个参数；续租仅在启用地址池时可用。"""
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        ops = (_OP_ESTABLISH, _OP_OFFLINE)
        if self._pool_enabled:
            ops = ops + (_OP_RENEW,)
        if op not in ops:
            raise ValueError(f"op must be one of {ops}, got {op!r}")
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
        elif args is not None:
            raise ValueError(f"args must be None for {op}, got {args!r}")
        _check_int("now_ms", now_ms, 0)

    def _age(self, now_ms):
        """到期（含同刻）在线会话转为挂起并释放地址；租期到期（含同刻）释放地址。"""
        for session in self._sessions.values():
            if session["state"] == _STATE_ONLINE and session["deadline"] <= now_ms:
                session["state"] = _STATE_SUSPENDED
                session["deadline"] = 0
                self._release(session)
            elif session["ipn"] is not None and session["lease"] <= now_ms:
                self._release(session)

    def _allocate(self, user):
        """静态用户取其专属地址，否则取最小未租动态地址；耗尽 ResourceError。"""
        ipn = self._static.get(user)
        if ipn is not None:
            if ipn in self._leased:
                raise ResourceError(
                    f"static address for user {user!r} is already leased"
                )
            self._leased.add(ipn)
            return ipn
        for candidate in self._dynamic:
            if candidate not in self._leased:
                self._leased.add(candidate)
                return candidate
        raise ResourceError("address pool exhausted")

    def _release(self, session):
        """释放会话所持地址；静态地址不回流动态集，仍专属原用户。"""
        ipn = session["ipn"]
        if ipn is not None:
            self._leased.discard(ipn)
            session["ipn"] = None
            session["ip"] = ""
            session["lease"] = 0

    def _establish(self, sid, user, password, now_ms):
        """初始→认证中→在线；任一失败不留残留。"""
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
        # 最后分配地址：之前无任何副作用，分配失败即天然回滚。
        ipn = None
        ip = ""
        lease = 0
        if self._pool_enabled:
            ipn = self._allocate(user)
            ip = _format_ipv4(ipn)
            lease = now_ms + self._lease_ms
        deadline = now_ms + self._idle_ms
        self._sessions[sid] = {
            "user": user,
            "state": _STATE_ONLINE,
            "deadline": deadline,
            "ip": ip,
            "ipn": ipn,
            "lease": lease,
        }
        return self._render(sid, _STATE_ONLINE, now_ms, deadline, ip, lease)

    def _renew(self, sid, now_ms):
        """持址在线会话续租：租期 = now_ms + lease_ms。"""
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] != _STATE_ONLINE or session["ipn"] is None:
            raise StateError(f"cannot renew sid {sid!r} in state {session['state']!r}")
        session["lease"] = now_ms + self._lease_ms
        return self._render(
            sid, _STATE_ONLINE, now_ms, session["deadline"], session["ip"], session["lease"]
        )

    def _offline(self, sid, now_ms):
        """在线/挂起/下线→下线、期限清零、释放地址。"""
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] not in (_STATE_ONLINE, _STATE_SUSPENDED, _STATE_OFFLINE):
            raise StateError(f"cannot offline sid {sid!r} in state {session['state']!r}")
        session["state"] = _STATE_OFFLINE
        session["deadline"] = 0
        self._release(session)
        return self._render(sid, _STATE_OFFLINE, now_ms, 0, "", 0)

    def _render(self, sid, state, now_ms, deadline, ip="", lease=0):
        record = {"会话": sid, "状态": state, "时刻": now_ms, "期限": deadline}
        if self._pool_enabled:
            record["地址"] = ip
            record["租期"] = lease
        return json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
