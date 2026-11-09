"""Error-based SSRF probing.

A full SSRF test needs an out-of-band receiver, which this environment does not have.
What *is* verifiable offline is the error-based signal: if a parameter that is supposed
to hold a URL starts producing upstream connection errors for internal destinations
(closed port, cloud metadata IP) that the baseline response does not contain, the
server tried to fetch it.

Two distinct internal targets must both produce the marker before it is reported, and
the finding stays a *lead* unless the artifact is stored — same rule as every other check.
"""
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from tools.http_probe import fetch
from tools.registry import register_tool

INTERNAL_TARGETS = (
    "http://127.0.0.1:1/",
    "http://169.254.169.254/latest/meta-data/",
)

ERROR_MARKERS = (
    "connection refused",
    "could not connect",
    "failed to connect",
    "connection timed out",
    "no route to host",
    "name or service not known",
    "getaddrinfo failed",
    "econnrefused",
    "unreachable",
)

METADATA_MARKERS = ("ami-id", "instance-id", "iam/security-credentials", "meta-data")


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query.append((param, value))
    return urlunsplit(parts._replace(query=urlencode(query), fragment=""))


def _markers(body: str) -> tuple[list[str], list[str]]:
    lowered = (body or "").lower()
    return (
        [marker for marker in ERROR_MARKERS if marker in lowered],
        [marker for marker in METADATA_MARKERS if marker in lowered],
    )


@register_tool(
    name="ssrf_probe",
    description="Probe a URL-valued parameter for server-side request forgery using "
    "error-based signals: internal destinations must produce upstream connection errors "
    "or metadata content that the baseline lacks.",
    category="exploit",
        accepts="url",
        expects="findings_list",
    requires_provider=False,
)
async def ssrf_probe(url: str, param: str) -> dict:
    try:
        baseline = await fetch(url)
    except ValueError as error:
        return {"url": url, "status": "error", "error": str(error)[:300]}
    except Exception as error:
        return {"url": url, "status": "error", "error": f"baseline request failed: {error}"[:300]}

    baseline_errors, baseline_meta = _markers(baseline["body"])
    results: List[Dict[str, Any]] = []
    hits: List[Dict[str, Any]] = []

    for target in INTERNAL_TARGETS:
        try:
            probe = await fetch(_with_param(url, param, target))
        except Exception as error:
            results.append({"payload": target, "conclusive": False,
                            "signal": "request_failed", "detail": str(error)[:200]})
            continue
        errors, metadata = _markers(probe["body"])
        new_errors = [m for m in errors if m not in baseline_errors]
        new_metadata = [m for m in metadata if m not in baseline_meta]
        conclusive = bool(new_errors or new_metadata)
        detail = (
            f"内部目标触发上游错误: {new_errors[:2]}" if new_errors
            else f"响应包含云元数据标记: {new_metadata[:2]}" if new_metadata
            else "无内网访问迹象"
        )
        results.append({
            "payload": target,
            "conclusive": conclusive,
            "signal": "metadata_content" if new_metadata else "upstream_error",
            "detail": detail,
            "parameter": param,
            "url": probe["request"]["url"],
            "status": probe["status"],
            "response_excerpt": probe["response_meta"]["body_excerpt"],
            "request": probe["request"],
            "response": probe["response_meta"],
        })
        if conclusive:
            hits.append(results[-1])

    # 两个不同的内网目标都命中才判定，避免单次巧合
    vulnerable = len(hits) >= 2
    if vulnerable:
        findings = [{
            "title": f"Server-side request forgery via {param}",
            "severity": "High",
            "evidence": hits[0]["payload"],
            "parameter": param,
            "description": "两个不同的内部目标均触发了可观测的访问迹象",
            "evidence_kind": "http_response",
        }]
    else:
        findings = []

    return {
        "url": url,
        "status": "success",
        "parameter": param,
        "payloads_tested": len(results),
        "vulnerable": vulnerable,
        "findings": findings,
        "leads": [
            {"title": f"Possible SSRF in {param}", "severity": "Info",
             "evidence": item["payload"], "reason": item["detail"]}
            for item in hits if not vulnerable
        ],
        "results": results,
        "conclusion": "confirmed" if vulnerable else "no_signal",
        "limitation": "错误回显型检测；带外（DNS/HTTP 回连）未覆盖",
    }
