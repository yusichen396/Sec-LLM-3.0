"""Bridge between tool results and the evidence store.

Every finding passes through here before it reaches the report: the tool result is
inspected for an observed demonstration, an artifact is written when one exists, and
the finding is annotated with the resulting reference. No artifact ⇒ no "verified".
"""
import shlex
from typing import Any, Dict, List, Optional

from agents.reporting import annotate_finding, observed_result
from core.evidence import EvidenceRecorder

_CURL_POC = """#!/usr/bin/env bash
# Replay the {kind} probe captured by Sec-LLM.
set -euo pipefail
curl -sS -i {url}
"""


def _curl_poc(kind: str, url: str) -> str:
    return _CURL_POC.format(kind=kind, url=shlex.quote(url or ""))


def attach_evidence(
    findings: List[Dict[str, Any]],
    tool: str,
    result: Any,
    session_id: str,
    *,
    recorder: Optional[EvidenceRecorder] = None,
) -> List[Dict[str, Any]]:
    """Annotate findings, recording an artifact for each observed demonstration."""
    recorder = recorder or EvidenceRecorder()
    annotated: List[Dict[str, Any]] = []

    for finding in findings:
        reference = None
        payload = finding.get("evidence")
        match = observed_result(result, payload) if payload else None
        if match:
            url = match.get("url") or (result.get("url") if isinstance(result, dict) else "") or ""
            parameter = match.get("parameter") or (result.get("parameter") if isinstance(result, dict) else "") or ""
            request = match.get("request") or {"method": "GET", "url": url, "headers": {}}
            response = match.get("response") or {
                "status": match.get("status"),
                "url": match.get("final_url") or url,
                "body_excerpt": match.get("response_excerpt") or "",
            }
            signal = match.get("signal") or ("reflected_xss" if tool == "browser_check_xss" else tool)
            try:
                reference = recorder.record(
                    session_id=session_id,
                    tool=tool,
                    kind=str(signal),
                    payload=str(payload),
                    request=request,
                    response=response,
                    extra={
                        "executed": bool(match.get("executed")),
                        "dialog_triggered": bool(match.get("dialog_triggered")),
                        "conclusive": bool(match.get("conclusive")),
                        "parameter": parameter,
                        "detail": match.get("detail"),
                    },
                    poc=_curl_poc(str(signal), url) if url else None,
                )
            except OSError as error:
                print(f"[EVIDENCE] failed to record artifact: {error}")
                reference = None
        annotated.append(annotate_finding(finding, tool, result, evidence=reference))
    return annotated
