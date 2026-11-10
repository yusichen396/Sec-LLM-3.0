"""Scan scope: what this session is authorised to touch.

An allowlist checked only in the API handler is not enough — the planner can hand a
tool a URL that was never submitted as the target. The scope object is therefore
built once per session and enforced again at the tool layer (``tools.browser``).

Production additionally requires an authorization reference (change ticket / pentest
engagement id) so every scan can be tied back to an approval.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

PRODUCTION_MODES = {"prod", "production"}


class ScopeError(ValueError):
    """Raised when a target or configuration violates the scan scope."""


@dataclass(frozen=True)
class ScanScope:
    target: str
    host: str
    allowed_hosts: List[str] = field(default_factory=list)
    authorization_ref: str = ""
    window_minutes: int = 0
    expires_at: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def host_allowed(self, hostname: str) -> bool:
        if not self.allowed_hosts:
            return True
        return (hostname or "").lower().rstrip(".") in self.allowed_hosts

    def expired(self, now: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return False
        now = now or datetime.now(timezone.utc)
        try:
            return now > datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False


def _host_of(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"//{target}")
    return (parsed.hostname or "").lower().rstrip(".")


def build_scope(
    target: str,
    *,
    env_mode: str = "dev",
    allowed_targets: str = "",
    authorization_ref: str = "",
    window_minutes: int = 0,
) -> ScanScope:
    """Validate configuration and return the immutable scope for one session."""
    host = _host_of(target)
    if not host:
        raise ScopeError("扫描目标必须包含主机名")

    allowed = [item.strip().lower().rstrip(".") for item in (allowed_targets or "").split(",") if item.strip()]
    mode = (env_mode or "dev").strip().lower()

    if mode in PRODUCTION_MODES:
        if not allowed:
            raise ScopeError("生产环境必须配置 AGENT_ALLOWED_TARGETS")
        if not (authorization_ref or "").strip():
            raise ScopeError("生产环境必须提供授权凭据（authorization_ref / 工单号）")

    if allowed and host not in allowed:
        raise ScopeError("扫描目标不在 AGENT_ALLOWED_TARGETS 内")

    expires_at = None
    window = int(window_minutes or 0)
    if window > 0:
        if window > 24 * 60:
            raise ScopeError("扫描时间窗不能超过 24 小时")
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=window)).isoformat()

    return ScanScope(
        target=target,
        host=host,
        allowed_hosts=allowed,
        authorization_ref=(authorization_ref or "").strip(),
        window_minutes=window,
        expires_at=expires_at,
    )


def assert_in_scope(scope: Optional[ScanScope], url: str) -> None:
    """Enforce the scope for a tool-level URL (defence in depth)."""
    if scope is None:
        return
    if scope.expired():
        raise ScopeError("扫描时间窗已过期")
    host = _host_of(url)
    if not host:
        raise ScopeError("目标缺少主机名")
    if host != scope.host and not scope.host_allowed(host):
        raise ScopeError(f"主机 {host} 不在本次扫描授权范围内")
