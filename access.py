"""接入网后端服务框架：认证模块。

仅使用 Python 标准库。所有时间均由调用方以显式时钟（毫秒整数）驱动，
相同请求序列产生逐字节相同的结果。
"""

import hashlib
import hmac

_MAX_USERS = 10000
_MAX_CRED_BYTES = 256


def _check_int(name, value, minimum):
    """校验非 bool 的 int 且不小于 minimum；类型不符 TypeError，越界 ValueError。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an int, got %s" % (name, type(value).__name__))
    if value < minimum:
        raise ValueError("%s must be >= %d, got %d" % (name, minimum, value))
    return value


def _check_credential(name, value):
    """校验 str、UTF-8 编码后 1..256 字节、不含 U+0000。"""
    if not isinstance(value, str):
        raise TypeError("%s must be a str, got %s" % (name, type(value).__name__))
    size = len(value.encode("utf-8"))
    if not 1 <= size <= _MAX_CRED_BYTES:
        raise ValueError("%s must be 1..%d bytes in UTF-8, got %d"
                         % (name, _MAX_CRED_BYTES, size))
    if "\0" in value:
        raise ValueError("%s must not contain U+0000" % name)
    return value


def _digest(user, password):
    return hashlib.sha256((user + "\0" + password).encode("utf-8")).digest()


class Authenticator:
    """基于显式时钟的失败计数锁定认证器。

    每个用户记录 [凭据摘要, 连续失败次数, 锁定截止毫秒]，
    单条操作为 O(1) 均摊时间、O(1) 额外空间。
    """

    def __init__(self, max_fail, lock_ms):
        self._max_fail = _check_int("max_fail", max_fail, 1)
        self._lock_ms = _check_int("lock_ms", lock_ms, 0)
        self._users = {}

    def add(self, user, password):
        """注册用户，返回 (user, "created", 0)。"""
        _check_credential("user", user)
        _check_credential("password", password)
        if user in self._users:
            raise KeyError(user)
        if len(self._users) >= _MAX_USERS:
            raise OverflowError("user limit %d reached" % _MAX_USERS)
        self._users[user] = [_digest(user, password), 0, 0]
        return (user, "created", 0)

    def authenticate(self, user, password, now_ms):
        """验证凭据，返回 (user, status, until)，status ∈ ok/denied/locked。"""
        _check_credential("user", user)
        _check_credential("password", password)
        _check_int("now_ms", now_ms, 0)
        entry = self._users.get(user)
        if entry is None:
            raise KeyError(user)
        digest, failed, until = entry
        if now_ms < until:
            # 锁定中：不验密、不改状态。
            return (user, "locked", until)
        if until:
            # 锁已到期：先清零 failed 与 until 再验证。
            failed = 0
            until = 0
        if hmac.compare_digest(digest, _digest(user, password)):
            entry[1] = 0
            entry[2] = 0
            return (user, "ok", 0)
        failed += 1
        if failed >= self._max_fail:
            until = now_ms + self._lock_ms
            entry[1] = failed
            entry[2] = until
            return (user, "locked", until)
        entry[1] = failed
        entry[2] = 0
        return (user, "denied", 0)
