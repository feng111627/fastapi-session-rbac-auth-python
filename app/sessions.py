"""服务端会话管理。

- create: 建立会话；同一账号会话数达到上限时淘汰最旧会话（FIFO 驱逐），
  保证并发创建下数量上限不被突破（整段临界区持锁）。
- validate: 校验令牌有效性并滑动续期（重置过期时间）。
- revoke: 主动注销；被注销/被淘汰的令牌再校验一律返回 None。
"""
from __future__ import annotations

import threading
import time

from .config import Settings
from .models import Session
from .security import generate_token


class SessionManager:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}

    def _purge_expired(self, now: float) -> None:
        expired = [t for t, s in self._sessions.items() if s.is_expired(now)]
        for t in expired:
            del self._sessions[t]

    def create(self, username: str) -> Session:
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            # 并发上限：淘汰该账号最旧的会话
            mine = sorted(
                (s for s in self._sessions.values() if s.username == username),
                key=lambda s: s.created_at,
            )
            while len(mine) >= self._settings.max_sessions_per_user:
                oldest = mine.pop(0)
                self._sessions.pop(oldest.token, None)
            session = Session(
                token=generate_token(),
                username=username,
                created_at=now,
                expires_at=now + self._settings.session_ttl_seconds,
                csrf_token=generate_token(),
            )
            self._sessions[session.token] = session
            return session

    def validate(self, token: str) -> Session | None:
        """校验并滑动续期；无效/过期返回 None。"""
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None or session.is_expired(now):
                return None
            session.expires_at = now + self._settings.session_ttl_seconds
            return session

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def active_count(self, username: str) -> int:
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            return sum(1 for s in self._sessions.values() if s.username == username)
