"""登录失败计数与锁定：并发安全，失败计数与锁定判定在同一把锁内完成。"""
from __future__ import annotations

import threading
import time


class LoginGuard:
    """线程安全的登录失败计数器。

    连续失败达到 max_failures 后账号锁定 lockout_seconds 秒；
    锁定期间不计数，解锁后计数清零重新开始。
    """

    def __init__(self, max_failures: int, lockout_seconds: float) -> None:
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        # username -> (连续失败次数, 锁定截止时刻；0 表示未锁定)
        self._state: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def is_locked(self, username: str) -> bool:
        """账号当前是否处于锁定状态。"""
        with self._lock:
            return self._locked_locked(username)

    def record_failure(self, username: str) -> None:
        """记录一次失败，达到阈值即进入锁定。"""
        with self._lock:
            if self._locked_locked(username):
                return
            count, _ = self._state.get(username, (0, 0.0))
            count += 1
            locked_until = (
                time.monotonic() + self._lockout_seconds
                if count >= self._max_failures
                else 0.0
            )
            self._state[username] = (count, locked_until)

    def record_success(self, username: str) -> None:
        """登录成功，清零失败计数与锁定。"""
        with self._lock:
            self._state.pop(username, None)

    def _locked_locked(self, username: str) -> bool:
        """锁内判定：锁定到期则自动清零并视为未锁定。"""
        count, locked_until = self._state.get(username, (0, 0.0))
        if locked_until == 0.0:
            return False
        if time.monotonic() < locked_until:
            return True
        self._state.pop(username, None)
        return False
