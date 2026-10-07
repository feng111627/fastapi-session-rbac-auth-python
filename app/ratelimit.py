"""登录失败计数与锁定。

- record_failure / is_locked 的全部状态变更都在同一把锁内完成，
  并发失败请求不会丢失计数，也不会绕过锁定。
- 连续失败达到上限即锁定 login_lockout_seconds；锁定期间 is_locked 为真。
- 登录成功清零计数并解除锁定。
"""
from __future__ import annotations

import threading
import time

from .config import Settings


class LoginGuard:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, username: str) -> bool:
        now = time.time()
        with self._lock:
            until = self._locked_until.get(username)
            if until is None:
                return False
            if now >= until:  # 锁定期满，自动解除
                del self._locked_until[username]
                self._failures.pop(username, None)
                return False
            return True

    def record_failure(self, username: str) -> None:
        now = time.time()
        with self._lock:
            count = self._failures.get(username, 0) + 1
            self._failures[username] = count
            if count >= self._settings.login_max_failures:
                self._locked_until[username] = now + self._settings.login_lockout_seconds

    def record_success(self, username: str) -> None:
        with self._lock:
            self._failures.pop(username, None)
            self._locked_until.pop(username, None)
