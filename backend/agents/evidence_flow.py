"""Bridge between tool results and the evidence store.

Every finding passes through here before it reaches the report: the tool result is
inspected for an observed execution, an artifact is written when one exists, and the
finding is annotated with the resulting reference. No artifact ⇒ no "verified".
"""
import shlex
from typing import Any, Dict, List, Optional

from agents.reporting import annotate_finding
from core.evidence import EvidenceRecorder


def _xss_poc(url: str, payload: str, parameter: str) -> str:
    quoted = shlex.quote(url)
    return (
        "#!/usr/bin/env bash\n"
        "# Replay the reflected-XSS payload captured by Sec-LLM.\n"
        "# 1) The curl below shows the payload is delivered unchanged by the server.\n"
        "# 2) Open the same URL in a browser: the dialog proves execution.\n"
        f"set -euo pipefail\n"
        f"URL={quoted}\n"
        f"echo \"payload: {payload.replace(chr(39), chr(39) + chr(34) + chr(39) + chr(34) + chr(39))}\"\n"
        f"echo \"parameter: {parameter}\"\n"
        f"curl -sS -i \"$URL\" | head -n 40\n"
        f"echo\n"
        f"echo \"Now open: $URL\"\n"
    )


def _matching_result(findings: List[Dict[str, Any]], tool: str, result: Any) -> Dict[str, Dict[str, Any]]:
    """Map each finding's payload to the tool result entry that observed it."""
    if tool != "browser_check_xss" or not isinstance(result, dict):
        return {}
    observed = {}
    for item in result.get("results") or []:
        if not isinstance(item, dict):
            continue
        payload = item.get("payload")
        if payload and (item.get("executed") or item.get("dialog_triggered")):
            observed[payload] = item
    return observed


def attach_evidence(
    findings: List[Dict[str, Any]],
    tool: str,
    result: Any,
    session_id: str,
    *,
    recorder: Optional[EvidenceRecorder] = None,
) -> List[Dict[str, Any]]:
    """Annotate findings, recording an artifact for each observed execution."""
    recorder = recorder or EvidenceRecorder()
    observed = _matching_result(findings, tool, result)
    annotated: List[Dict[str, Any]] = []

    for finding in findings:
        reference = None
        payload = finding.get("evidence")
        match = observed.get(payload) if payload else None
        if match:
            url = match.get("url") or (result.get("url") if isinstance(result, dict) else None) or ""
            parameter = (result.get("parameter") if isinstance(result, dict) else None) or ""
            try:
                reference = recorder.record(
                    session_id=session_id,
                    tool=tool,
                    kind="reflected_xss",
                    payload=str(payload),
                    request={"method": "GET", "url": url, "headers": {}},
                    response={
                        "status": match.get("status"),
                        "url": match.get("final_url") or url,
                        "body_excerpt": match.get("response_excerpt") or "",
                    },
                    extra={
                        "executed": bool(match.get("executed")),
                        "dialog_triggered": bool(match.get("dialog_triggered")),
                        "reflected": bool(match.get("reflected")),
                        "parameter": parameter,
                    },
                    poc=_xss_poc(url, str(payload), parameter) if url else None,
                )
            except OSError as error:
                print(f"[EVIDENCE] failed to record artifact: {error}")
                reference = None
        annotated.append(annotate_finding(finding, tool, result, evidence=reference))
    return annotated
