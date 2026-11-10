"""Reproducible evidence artifacts for findings.

A finding may only be reported as *verified* when this module holds an artifact for
it: the exact request, the observed response, the payload, a content hash and a
replayable PoC. That makes "verified" a checkable property instead of a model's
self-assessment.

Artifacts land in ``AGENT_EVIDENCE_DIR/<session_id>/`` as JSON (plus ``poc.sh`` when
a replay command can be derived) and are referenced from the session's findings by
``evidence_id`` + ``evidence_path`` + ``evidence_sha256``.
"""
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-skill-api-key", "key"}
_MAX_BODY_CHARS = 4000


def _redact(headers: Any) -> Any:
    if not isinstance(headers, dict):
        return headers
    return {
        key: ("<redacted>" if key.lower() in _SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }


def _clip(value: Any, limit: int = _MAX_BODY_CHARS) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…[truncated]"
    return value


class EvidenceRecorder:
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            from config import settings

            base_dir = getattr(settings, "AGENT_EVIDENCE_DIR", "artifacts/evidence")
        self.base = Path(base_dir)

    def _session_dir(self, session_id: str) -> Path:
        safe = "".join(ch for ch in (session_id or "unknown") if ch.isalnum() or ch in "-_")[:64] or "unknown"
        return self.base / safe

    def record(
        self,
        *,
        session_id: str,
        tool: str,
        kind: str,
        payload: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        extra: Optional[Dict[str, Any]] = None,
        poc: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist one artifact and return the reference to embed in the finding."""
        evidence_id = f"EV-{uuid.uuid4().hex[:12]}"
        directory = self._session_dir(session_id)
        directory.mkdir(parents=True, exist_ok=True)

        record = {
            "evidence_id": evidence_id,
            "session_id": session_id,
            "tool": tool,
            "kind": kind,
            "payload": payload,
            "request": {
                "method": request.get("method", "GET"),
                "url": request.get("url"),
                "headers": _redact(request.get("headers") or {}),
                "body": _clip(request.get("body")),
            },
            "response": {
                "status": response.get("status"),
                "url": response.get("url"),
                "headers": _redact(response.get("headers") or {}),
                "body_excerpt": _clip(response.get("body") or response.get("body_excerpt") or ""),
            },
            "observed": _clip(json.dumps(extra or {}, ensure_ascii=False), 2000),
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        canonical = json.dumps(
            {
                "tool": record["tool"],
                "kind": record["kind"],
                "payload": record["payload"],
                "request": record["request"],
                "response": record["response"],
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        record["sha256"] = digest

        path = directory / f"{evidence_id}.json"
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        if poc:
            poc_path = directory / f"{evidence_id}.repro.sh"
            poc_path.write_text(poc if poc.endswith("\n") else poc + "\n", encoding="utf-8")
            try:
                os.chmod(poc_path, 0o700)
            except OSError:
                pass
            record["poc_path"] = str(poc_path)

        return {
            "evidence_id": evidence_id,
            "evidence_path": str(path),
            "evidence_sha256": digest,
            "kind": kind,
            "tool": tool,
            "payload": payload,
            "poc_path": record.get("poc_path"),
        }

    def verify(self, reference: Dict[str, Any]) -> bool:
        """Re-read the artifact and confirm it still matches its recorded hash."""
        path = reference.get("evidence_path")
        expected = reference.get("evidence_sha256")
        if not path or not expected:
            return False
        try:
            record = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        canonical = json.dumps(
            {
                "tool": record.get("tool"),
                "kind": record.get("kind"),
                "payload": record.get("payload"),
                "request": record.get("request"),
                "response": record.get("response"),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return actual == expected == record.get("sha256")
