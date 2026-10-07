"""全局配置（骨架）。"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    session_ttl_seconds: float = 1800.0          # 滑动过期窗口
    max_sessions_per_user: int = 3               # 超过则淘汰最旧会话
    login_max_failures: int = 5                  # 连续失败上限
    login_lockout_seconds: float = 300.0         # 锁定时长
    cookie_name: str = "sid"
    cookie_secure: bool = False                  # 本地 http 测试置 False
    csrf_header: str = "x-csrf-token"


DEFAULT_SETTINGS = Settings()
