"""服务端会话存储：滑动过期、单账号并发上限、主动注销。"""
from __future__ import annotations

import threading
import time

from .models import Session
from .security import new_token


class SessionStore:
    """线程安全的内存会话存储。

    - 滑动过期：每次成功取用都会刷新 last_seen。
    - 并发上限：同一账号会话数超过上限时淘汰最旧（last_seen 最小）的会话。
    - 注销/淘汰后的会话再访问一律判为失效。
    """

    def __init__(self, idle_timeout: float, max_per_user: int) -> None:
        self._idle_timeout = idle_timeout
        self._max_per_user = max_per_user
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, username: str, csrf_token: str) -> Session:
        """创建会话；超过单账号并发上限时淘汰最旧会话。"""
        with self._lock:
            now = time.time()
            self._evict_expired(now)
            mine = [s for s in self._sessions.values() if s.username == username]
            while len(mine) >= self._max_per_user:
                oldest = min(mine, key=lambda s: s.last_seen)
                oldest.revoked = True
                del self._sessions[oldest.session_id]
                mine.remove(oldest)
            session = Session(
                session_id=new_token(),
                username=username,
                csrf_token=csrf_token,
            )
            self._sessions[session.session_id] = session
            return session

    def get_valid(self, session_id: str) -> Session | None:
        """取出有效会话并滑动续期；无效/过期/已注销返回 None。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked:
                return None
            now = time.time()
            if now - session.last_seen > self._idle_timeout:
                del self._sessions[session_id]
                return None
            session.last_seen = now
            return session

    def revoke(self, session_id: str) -> bool:
        """主动注销会话；返回是否注销了存在的会话。"""
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return False
            session.revoked = True
            return True

    def _evict_expired(self, now: float) -> None:
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s.last_seen > self._idle_timeout
        ]
        for sid in expired:
            del self._sessions[sid]
