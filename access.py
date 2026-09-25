"""access — 接入网后端服务框架（仅标准库）。

当前提供：
- Authenticator：带失败计数与锁定的用户认证器。
- Sessions：基于 Authenticator 的会话管理（建立/下线、空闲老化、按 key 重放缓存）。
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
    """会话总数或单用户会话数已达上限。"""


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


class Sessions:
    """会话管理：建立需先认证再查限额，下线按 sid；按 key 永久缓存重放。"""

    def __init__(self, auth, total, per, idle_ms):
        if not isinstance(auth, Authenticator):
            raise TypeError(f"auth must be an Authenticator, got {type(auth).__name__}")
        self._auth = auth
        self._total = _check_int("total", total, 1)
        self._per = _check_int("per", per, 1)
        self._idle_ms = _check_int("idle_ms", idle_ms, 0)
        # sid -> {"user": str, "state": str, "deadline": int}
        self._sessions = {}
        # key -> (op, sid, args, now_ms, outcome)
        # outcome 为 ("ok", json_str) 或 ("err", (exc_class, exc_args))
        self._cache = {}

    def do(self, key, op, sid, args, now_ms):
        """执行一次建立/下线操作，返回 LF 结尾的 JSON 字符串。"""
        _check_credential("key", key)
        if isinstance(op, bool) or not isinstance(op, str):
            raise TypeError(f"op must be a str, got {type(op).__name__}")
        if op not in (_OP_ESTABLISH, _OP_OFFLINE):
            raise ValueError(f"op must be {_OP_ESTABLISH} or {_OP_OFFLINE}, got {op!r}")
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

        cached = self._cache.get(key)
        if cached is not None:
            # 重放：不老化、不认证，仅按缓存返回或重抛。
            c_op, c_sid, c_args, c_now_ms, outcome = cached
            if (op, sid, args, now_ms) != (c_op, c_sid, c_args, c_now_ms):
                raise ValueError(f"key {key!r} reused with different parameters")
            if outcome[0] == "ok":
                return outcome[1]
            exc_class, exc_args = outcome[1]
            raise exc_class(*exc_args)

        # 非重放：先将到期在线会话挂起。
        self._age(now_ms)
        try:
            if op == _OP_ESTABLISH:
                result = self._establish(sid, args[0], args[1], now_ms)
            else:
                result = self._offline(sid, now_ms)
        except (AuthError, ResourceError, StateError, KeyError) as exc:
            self._cache[key] = (op, sid, args, now_ms, ("err", (type(exc), exc.args)))
            raise
        self._cache[key] = (op, sid, args, now_ms, ("ok", result))
        return result

    def _age(self, now_ms):
        """到期（含同刻）在线会话转为挂起、期限清零。"""
        for session in self._sessions.values():
            if session["state"] == _STATE_ONLINE and session["deadline"] <= now_ms:
                session["state"] = _STATE_SUSPENDED
                session["deadline"] = 0

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
        deadline = now_ms + self._idle_ms
        self._sessions[sid] = {"user": user, "state": _STATE_ONLINE, "deadline": deadline}
        return self._render(sid, _STATE_ONLINE, now_ms, deadline)

    def _offline(self, sid, now_ms):
        """在线/挂起/下线→下线、期限清零。"""
        session = self._sessions.get(sid)
        if session is None:
            raise KeyError(f"unknown sid: {sid!r}")
        if session["state"] not in (_STATE_ONLINE, _STATE_SUSPENDED, _STATE_OFFLINE):
            raise StateError(f"cannot offline sid {sid!r} in state {session['state']!r}")
        session["state"] = _STATE_OFFLINE
        session["deadline"] = 0
        return self._render(sid, _STATE_OFFLINE, now_ms, 0)

    @staticmethod
    def _render(sid, state, now_ms, deadline):
        return json.dumps(
            {"会话": sid, "状态": state, "时刻": now_ms, "期限": deadline},
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"
