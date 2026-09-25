"""access — 接入网后端服务框架（仅标准库）。

当前提供：
- Authenticator：带失败计数与锁定的用户认证器。
- Sessions：基于 Authenticator 的会话管理（建立/续租/迁移/下线、空闲老化、
  可经 add_pool 注册的多个 IPv4 地址池与租约、按 key 重放缓存）。
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
        raise TypeError(f"pool must be a tuple, got {type(pool).__name__}")
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

    return usable, reserved_ips, static_map, static_ips


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
_OP_MIGRATE = "迁移"
_OP_OFFLINE = "下线"
_VALID_OPS = (_OP_ESTABLISH, _OP_RENEW, _OP_MIGRATE, _OP_OFFLINE)


class Sessions:
    """会话管理：建立需先认证再查限额，续租限持址在线会话，下线按 sid。

    地址池经 add_pool 动态注册，首个注册池为缺省池（建立的目标池）；未注册
    任何池时建立/迁移抛 StateError。各池独立计费占用，地址空间允许重叠。
    会话引用其当前所在池条目，迁移只改引用、不动池定义；后续 add_pool 只
    追加，不影响既有池条目。启用地址池时，建立为静态用户取其专属地址，
    否则取最小未租用动态地址；租期到期、挂起或下线均释放地址，静态地址不
    回动态池。按 key 永久缓存重放。
    """

    def __init__(self, auth, total, per, idle_ms, lease_ms=1):
        if not isinstance(auth, Authenticator):
            raise TypeError(f"auth must be an Authenticator, got {type(auth).__name__}")
        self._auth = auth
        self._total = _check_int("total", total, 1)
        self._per = _check_int("per", per, 1)
        self._idle_ms = _check_int("idle_ms", idle_ms, 0)
        self._lease_ms = _check_int("lease_ms", lease_ms, 1)

        # 缺省池条目：首个 add_pool 注册的池；无池时为 None。
        self._default_pool = None
        # id 升序的池列表（pool_stats 直接顺序输出），每项字段：
        # {"id", "capacity", "reserved", "static", "static_ips", "free",
        #  "leases"}；free 为动态空闲最小堆，leases 为租用地址 int -> sid，
        # 池间互不影响、地址可重叠。另以 id -> 条目 的字典保 O(1) 查目标池。
        self._pools = []
        self._pool_by_id = {}

        # sid -> {"user": str, "state": str, "deadline": int, "ip": int|None,
        #         "lease": int, "pool": dict|None}
        self._sessions = {}
        # key -> (op, sid, args, now_ms, outcome)
        # outcome 为 ("ok", json_str) 或 ("err", (exc_class, exc_args))
        self._cache = {}

    def add_pool(self, id, pool):
        """注册地址池；首个注册的池成为缺省池。返回 None。"""
        _check_credential("id", id)
        if id in self._pool_by_id:
            raise ValueError(f"duplicate pool id: {id!r}")
        usable, reserved, static, static_ips = _check_pool(pool)
        # 动态地址最小堆：含全部未租用的非保留非静态地址（heapify 为 O(A)）。
        free = list(usable - reserved - static_ips)
        heapq.heapify(free)
        entry = {
            "id": id,
            "capacity": len(usable),
            "reserved": reserved,
            "static": static,
            "static_ips": static_ips,
            "free": free,
            "leases": {},
        }
        self._pool_by_id[id] = entry
        # 维持 id 升序（线性插排），统计即可 O(P) 顺序遍历。
        position = 0
        while position < len(self._pools) and self._pools[position]["id"] < id:
            position += 1
        self._pools.insert(position, entry)
        if self._default_pool is None:
            self._default_pool = entry
        return None

    def do(self, key, op, sid, args, now_ms):
        """执行一次建立/续租/迁移/下线操作，返回 LF 结尾的 JSON 字符串。"""
        _check_credential("key", key)

        cached = self._cache.get(key)
        if cached is not None:
            # 重放：不老化、不认证、不改租约，仅按缓存返回或重抛。
            c_op, c_sid, c_args, c_now_ms, outcome = cached
            if not _strict_equal(
                (op, sid, args, now_ms), (c_op, c_sid, c_args, c_now_ms)
            ):
                raise ValueError(f"key {key!r} reused with different parameters")
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
        try:
            if op == _OP_ESTABLISH:
                result = self._establish(sid, args[0], args[1], now_ms)
            elif op == _OP_RENEW:
                result = self._renew(sid, now_ms)
            elif op == _OP_MIGRATE:
                result = self._migrate(sid, args[0], args[1], now_ms)
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
            raise
        self._cache[key] = (op, sid, args, now_ms, ("ok", result))
        return result

    def _validate_params(self, op, sid, args, now_ms):
        """校验 key 之外的四个参数；池相关状态在执行阶段判定。"""
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op not in _VALID_OPS:
            raise ValueError(f"op must be one of {_VALID_OPS}, got {op!r}")
        _check_credential("sid", sid)
        if op in (_OP_ESTABLISH, _OP_MIGRATE):
            if not isinstance(args, tuple):
                raise TypeError(f"args must be a tuple, got {type(args).__name__}")
            if len(args) != 2:
                label = "(user, password)" if op == _OP_ESTABLISH else "(target, password)"
                raise ValueError(
                    f"args must be a 2-tuple {label}, got {len(args)} items"
                )
            first_name = "user" if op == _OP_ESTABLISH else "target"
            _check_credential(first_name, args[0])
            _check_credential("password", args[1])
        elif args is not None:
            raise ValueError(f"args must be None for {op}, got {args!r}")
        _check_int("now_ms", now_ms, 0)

    def pool_stats(self, now_ms):
        """老化后返回各池统计的 JSON 串；零池抛 StateError。"""
        _check_int("now_ms", now_ms, 0)
        if self._default_pool is None:
            raise StateError("no pool registered")
        # pool_stats 为查询操作：同样驱动一次老化，统计反映时刻 now_ms 的现状。
        self._age(now_ms)
        pools = []
        for entry in self._pools:
            # 项序：标识、容量（可用址数）、保留、静态、租用、动态空闲。
            item = [
                entry["id"],
                entry["capacity"],
                len(entry["reserved"]),
                len(entry["static_ips"]),
                len(entry["leases"]),
                len(entry["free"]),
            ]
            pools.append(item)
        payload = {"时刻": now_ms, "池": pools}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

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
        """释放会话持址：动态地址回所属池堆，静态地址仅退租，仍专属其用户。"""
        ip_int = session["ip"]
        if ip_int is None:
            return
        pool = session["pool"]
        del pool["leases"][ip_int]
        # 租用地址非动态即静态（保留地址从不租用），静态地址不入动态堆。
        if ip_int not in pool["static_ips"]:
            heapq.heappush(pool["free"], ip_int)
        session["ip"] = None
        session["lease"] = 0
        session["pool"] = None

    def _establish(self, sid, user, password, now_ms):
        """初始→认证中→在线；任一失败不留会话与租约残留。"""
        # 建立须有缺省池；零池在认证之前即拒绝。
        if self._default_pool is None:
            raise StateError("no default pool: no pool has been registered")
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

        pool = self._default_pool
        ip_int = self._allocate(pool, user)
        lease = now_ms + self._lease_ms

        # 全部校验通过后再落库，杜绝失败残留。
        pool["leases"][ip_int] = sid
        deadline = now_ms + self._idle_ms
        self._sessions[sid] = {
            "user": user,
            "state": _STATE_ONLINE,
            "deadline": deadline,
            "ip": ip_int,
            "lease": lease,
            "pool": pool,
        }
        address = str(ipaddress.IPv4Address(ip_int))
        return self._render(sid, _STATE_ONLINE, now_ms, deadline, address, lease)

    def _allocate(self, pool, user):
        """在指定池中取址：静态用户取其专属址，否则取最小空闲动态址。

        静态址已被任一会话租用（ResourceError 子类语义的占用冲突）由调用方
        在迁移/建立的既定异常次序下处理；本方法仅负责“静态占用/目标耗尽”。
        """
        ip_int = pool["static"].get(user)
        if ip_int is not None:
            if ip_int in pool["leases"]:
                # 静态地址专属该用户，但同一时刻只能租给一个会话。
                raise ResourceError(
                    f"static address {ipaddress.IPv4Address(ip_int)} for {user!r} "
                    "already in use"
                )
            return ip_int
        # 非静态用户：取最小未租用的非保留非静态地址。
        if not pool["free"]:
            raise ResourceError(f"address pool {pool['id']!r} exhausted")
        return heapq.heappop(pool["free"])

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
        """持址在线会话跨池迁移：释旧址、换池址，期限不变。

        异常次序（老化之后）：零池 StateError、未知 sid KeyError、未知 target
        KeyError、非持址在线或同池 StateError、认证非 ok AuthError、
        目标耗尽或静态占用 ResourceError。
        """
        if self._default_pool is None:
            raise StateError("no pool registered")
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        target_pool = self._pool_by_id.get(target)
        if target_pool is None:
            raise KeyError(f"unknown target pool: {target!r}")
        if session["state"] != _STATE_ONLINE or session["ip"] is None:
            raise StateError(
                f"cannot migrate sid {sid!r} in state {session['state']!r} without address"
            )
        if session["pool"] is target_pool:
            raise StateError(f"sid {sid!r} is already in target pool {target!r}")

        # 认证在状态检查之后、资源分配之前。
        user = session["user"]
        _, status, _ = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication not ok for user {user!r}: {status}")

        old_pool = session["pool"]
        old_ip = session["ip"]
        old_address = str(ipaddress.IPv4Address(old_ip))
        new_ip = self._allocate(target_pool, user)
        new_address = str(ipaddress.IPv4Address(new_ip))
        lease = now_ms + self._lease_ms

        # 全部校验通过后原子切换：先释旧址（动态回源池堆），再占用新址。
        del old_pool["leases"][old_ip]
        if old_ip not in old_pool["static_ips"]:
            heapq.heappush(old_pool["free"], old_ip)
        target_pool["leases"][new_ip] = sid

        session["ip"] = new_ip
        session["lease"] = lease
        session["pool"] = target_pool
        # 迁移不顺延空闲期限（期限不变）。
        payload = {
            "会话": sid,
            "状态": _STATE_ONLINE,
            "时刻": now_ms,
            "期限": session["deadline"],
            "原池": old_pool["id"],
            "原地址": old_address,
            "目标池": target,
            "目标地址": new_address,
            "租期": lease,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

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
        return self._render(sid, _STATE_OFFLINE, now_ms, 0, "", 0)

    @staticmethod
    def _render(sid, state, now_ms, deadline, address="", lease=0):
        # 会话必定隶属于某个池：在线给地址串与租期，下线给 "" 与 0。
        payload = {
            "会话": sid,
            "状态": state,
            "时刻": now_ms,
            "期限": deadline,
            "地址": address,
            "租期": lease,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
