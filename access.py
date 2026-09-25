"""access — 接入网后端服务框架（仅标准库）。

提供 Authenticator（带失败计数与锁定的用户认证器）与
Sessions（基于认证器的会话建立/下线管理，幂等键永久缓存）。
所有时间均由调用方以显式时钟（毫秒整数）驱动。
"""

import hashlib
import hmac
import json

__all__ = [
    "Authenticator",
    "Sessions",
    "AuthError",
    "ResourceError",
    "StateError",
]

_MAX_USERS = 10000
_MIN_CRED_BYTES = 1
_MAX_CRED_BYTES = 256


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


def _digest(user, password):
    return hashlib.sha256((user + "\0" + password).encode("utf-8")).digest()


class AuthError(Exception):
    """认证未通过（含锁定）时抛出。"""


class ResourceError(Exception):
    """会话总数或单用户会话数达到上限时抛出。"""


class StateError(Exception):
    """会话状态不允许当前操作时抛出。"""


class Authenticator:
    """基于 sha256 摘要的认证器，失败 max_fail 次后锁定 lock_ms 毫秒。"""

    def __init__(self, max_fail, lock_ms):
        self._max_fail = _check_int("max_fail", max_fail, 1)
        self._lock_ms = _check_int("lock_ms", lock_ms, 0)
        # user -> [digest, failed, until]
        self._users = {}

    def add(self, user, password):
        """注册新用户，返回 (user, "created", 0)。"""
        _check_credential("user", user)
        _check_credential("password", password)
        if user in self._users:
            raise KeyError(f"duplicate user: {user!r}")
        if len(self._users) >= _MAX_USERS:
            raise OverflowError(f"user limit {_MAX_USERS} reached")
        self._users[user] = [_digest(user, password), 0, 0]
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

        if now_ms < until:
            # 锁定中：不验密、不改状态。
            return (user, "locked", until)
        if until:
            # 锁已到期：先清零 failed 与 until 再验证。
            failed = 0
            until = 0
            record[1] = 0
            record[2] = 0

        if hmac.compare_digest(digest, _digest(user, password)):
            record[1] = 0
            return (user, "ok", record[2])

        failed += 1
        record[1] = failed
        if failed >= self._max_fail:
            record[2] = now_ms + self._lock_ms
            return (user, "locked", record[2])
        return (user, "denied", record[2])


def _emit(sid, state, now_ms, deadline):
    """按固定键序与格式输出会话 JSON，LF 结尾。"""
    return json.dumps(
        {"会话": sid, "状态": state, "时刻": now_ms, "期限": deadline},
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"


class Sessions:
    """会话管理：op 仅 建立/下线；有效 key 首次成败均永久缓存。

    状态机：初始 → 认证中 → 在线；到期在线 → 挂起；在线/挂起/下线 → 下线。
    """

    _OP_ESTABLISH = "建立"
    _OP_OFFLINE = "下线"

    _ST_ONLINE = "在线"
    _ST_SUSPENDED = "挂起"
    _ST_OFFLINE = "下线"

    def __init__(self, auth, total, per, idle_ms):
        self._auth = auth
        self._total = _check_int("total", total, 1)
        self._per = _check_int("per", per, 1)
        self._idle_ms = _check_int("idle_ms", idle_ms, 0)
        # sid -> [user, state, deadline]
        self._sessions = {}
        # key -> (op, sid, args, now_ms, ok, payload)
        self._cache = {}

    def do(self, key, op, sid, args, now_ms):
        """执行一次会话操作，返回 LF 结尾的 JSON 字符串。"""
        _check_credential("key", key)
        if not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op not in (self._OP_ESTABLISH, self._OP_OFFLINE):
            raise ValueError(f"op must be 建立 or 下线, got {op!r}")
        _check_credential("sid", sid)
        if op == self._OP_ESTABLISH:
            if not isinstance(args, tuple):
                raise TypeError(
                    f"args must be a tuple, got {type(args).__name__}"
                )
            if len(args) != 2:
                raise ValueError(f"args must be a 2-tuple, got {len(args)}")
            _check_credential("user", args[0])
            _check_credential("password", args[1])
        elif args is not None:
            raise ValueError(f"args must be None for {op}, got {args!r}")
        _check_int("now_ms", now_ms, 0)

        cached = self._cache.get(key)
        if cached is not None:
            # 复用：不老化、不认证；余四参同则返 str/重抛同类同 args 异常。
            c_op, c_sid, c_args, c_now, ok, payload = cached
            if (op, sid, args, now_ms) != (c_op, c_sid, c_args, c_now):
                raise ValueError(f"key {key!r} reused with different parameters")
            if ok:
                return payload
            exc_class, exc_args = payload
            raise exc_class(*exc_args)

        try:
            result = self._execute(op, sid, args, now_ms)
        except Exception as exc:
            self._cache[key] = (op, sid, args, now_ms, False,
                                (type(exc), exc.args))
            raise
        self._cache[key] = (op, sid, args, now_ms, True, result)
        return result

    def _execute(self, op, sid, args, now_ms):
        # 老化：到期在线 → 挂起、期限 0（到期含同刻）。
        for record in self._sessions.values():
            if record[1] == self._ST_ONLINE and record[2] <= now_ms:
                record[1] = self._ST_SUSPENDED
                record[2] = 0
        if op == self._OP_ESTABLISH:
            return self._establish(sid, args, now_ms)
        return self._offline(sid, now_ms)

    def _establish(self, sid, args, now_ms):
        user, password = args
        # 先认证，后查 total 及用户 per（计非下线），失败无残留。
        _user, status, _until = self._auth.authenticate(user, password, now_ms)
        if status != "ok":
            raise AuthError(f"authentication failed for {user!r}: {status}")
        active = 0
        mine = 0
        for record in self._sessions.values():
            if record[1] != self._ST_OFFLINE:
                active += 1
                if record[0] == user:
                    mine += 1
        if active >= self._total:
            raise ResourceError(f"total session limit {self._total} reached")
        if mine >= self._per:
            raise ResourceError(
                f"per-user session limit {self._per} reached for {user!r}"
            )
        if sid in self._sessions:
            raise StateError(f"duplicate sid: {sid!r}")
        deadline = now_ms + self._idle_ms
        self._sessions[sid] = [user, self._ST_ONLINE, deadline]
        return _emit(sid, self._ST_ONLINE, now_ms, deadline)

    def _offline(self, sid, now_ms):
        record = self._sessions.get(sid)
        if record is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if record[1] not in (
            self._ST_ONLINE,
            self._ST_SUSPENDED,
            self._ST_OFFLINE,
        ):
            raise StateError(
                f"cannot offline sid {sid!r} in state {record[1]!r}"
            )
        record[1] = self._ST_OFFLINE
        record[2] = 0
        return _emit(sid, self._ST_OFFLINE, now_ms, 0)
