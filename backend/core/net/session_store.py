"""Per-origin browser session state (cookies + localStorage).

Authenticated scanning needs a way to carry a logged-in context across tool calls.
Playwright's ``storage_state`` is exactly that blob; this store keeps one per origin
with a TTL and never exposes it through the API.

The stored blob **is** a credential (session cookies). It lives under
``backend/data/sessions`` which is gitignored, is written with restrictive
permissions where the platform supports it, and is deleted on TTL expiry.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TTL_SECONDS = 1800
_MAX_STATE_BYTES = 512 * 1024


def _origin_key(origin: str) -> str:
    return hashlib.sha256((origin or "").strip().lower().encode("utf-8")).hexdigest()[:16]


class SessionStore:
    def __init__(self, root: Optional[str] = None, ttl: int = DEFAULT_TTL_SECONDS):
        if root is None:
            from config import settings

            root = getattr(settings, "AGENT_SESSION_DIR", "data/sessions")
            ttl = int(getattr(settings, "AGENT_SESSION_TTL_SECONDS", DEFAULT_TTL_SECONDS))
        self.root = Path(root)
        self.ttl = int(ttl)

    # ---- internals -----------------------------------------------------
    def _path(self, origin: str) -> Path:
        return self.root / f"{_origin_key(origin)}.json"

    def _read(self, origin: str) -> Optional[Dict[str, Any]]:
        path = self._path(origin)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(record, dict):
            return None
        if time.time() - float(record.get("saved_at", 0)) > self.ttl:
            self.delete(origin)
            return None
        return record

    # ---- public API ----------------------------------------------------
    def save(self, origin: str, storage_state: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Persist a Playwright storage_state for one origin. Returns a safe summary."""
        if not isinstance(storage_state, dict):
            raise ValueError("storage_state must be a dict")
        encoded = json.dumps(storage_state, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > _MAX_STATE_BYTES:
            raise ValueError("session state too large")
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(origin)
        record = {
            "origin": origin,
            "saved_at": time.time(),
            "meta": {k: v for k, v in (meta or {}).items() if k in {"username_hint", "login_url", "method"}},
            "storage_state": storage_state,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        try:  # best effort on POSIX; Windows ACLs are managed by the OS
            os.chmod(path, 0o600)
        except OSError:
            pass
        return self.describe(origin)

    def load(self, origin: str) -> Optional[Dict[str, Any]]:
        record = self._read(origin)
        state = (record or {}).get("storage_state")
        return state if isinstance(state, dict) else None

    def describe(self, origin: str) -> Dict[str, Any]:
        """Non-secret view of a session, safe to return from a tool."""
        record = self._read(origin)
        if record is None:
            return {"origin": origin, "exists": False, "expired": True}
        age = max(0, int(time.time() - float(record.get("saved_at", 0))))
        cookies = (record.get("storage_state") or {}).get("cookies") or []
        return {
            "origin": origin,
            "exists": True,
            "expired": False,
            "age_seconds": age,
            "expires_in_seconds": max(0, self.ttl - age),
            "cookie_count": len(cookies) if isinstance(cookies, list) else 0,
            "reusable": bool(cookies),
        }

    def delete(self, origin: str) -> bool:
        path = self._path(origin)
        try:
            path.unlink()
            return True
        except OSError:
            return False
