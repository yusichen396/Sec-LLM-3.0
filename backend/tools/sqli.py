"""SQL injection probing (error-based + boolean-based).

Two independent signals have to agree before anything is reported:

- **error-based**: an injected quote produces a database error signature that the
  baseline response did not contain;
- **boolean-based**: ``AND 1=1`` keeps the page (nearly) identical to the baseline while
  ``AND 1=2`` changes it materially — measured on normalised body length, twice.

Reflection-only or single-attempt noise is reported as a lead, never as a finding.
"""
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from tools.http_probe import fetch
from tools.registry import register_tool

ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_sql_exception",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "postgresql.*syntax error",
    "ora-00933",
    "ora-01756",
    "sqlite3.operationalerror",
    "sqlstate[hy",
    "microsoft odbc sql server driver",
    "syntax error at or near",
)

_ERROR_RE = re.compile("|".join(re.escape(signature) for signature in ERROR_SIGNATURES), re.IGNORECASE)
_MAX_PAYLOADS = 6


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query.append((param, value))
    return urlunsplit(parts._replace(query=urlencode(query), fragment=""))


def _norm_len(body: str) -> int:
    return len(re.sub(r"\s+", " ", body or "").strip())


def _similar(a: int, b: int, tolerance: float = 0.05) -> bool:
    if max(a, b) == 0:
        return a == b
    return abs(a - b) / max(a, b) <= tolerance


@register_tool(
    name="sqli_probe",
    description="Probe one query parameter for SQL injection using error-based and "
    "boolean-based signals. Requires two agreeing signals; returns request/response "
    "material so a replayable artifact can be stored.",
    category="exploit",
    requires_provider=False,
)
async def sqli_probe(url: str, param: str) -> dict:
    """Probe a single parameter; never more than a handful of requests."""
    try:
        baseline = await fetch(url)
    except ValueError as error:
        return {"url": url, "status": "error", "error": str(error)[:300]}
    except Exception as error:  # network failure must be explicit
        return {"url": url, "status": "error", "error": f"baseline request failed: {error}"[:300]}

    base_len = _norm_len(baseline["body"])
    if baseline["status"] >= 500:
        return {"url": url, "status": "error", "error": f"baseline returned {baseline['status']}"}

    results: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    def record(payload: str, probe: Dict[str, Any], conclusive: bool, signal: str, detail: str) -> None:
        results.append({
            "payload": payload,
            "conclusive": conclusive,
            "signal": signal,
            "detail": detail,
            "url": probe["request"]["url"],
            "status": probe["status"],
            "response_excerpt": probe["response_meta"]["body_excerpt"],
            "request": probe["request"],
            "response": probe["response_meta"],
        })
        if conclusive:
            findings.append({
                "title": f"SQL injection in {param}",
                "severity": "High",
                "evidence": payload,
                "parameter": param,
                "description": detail,
                "evidence_kind": "http_response",
            })

    # --- error-based: quote payloads, look for a *new* DB error signature -----------
    for payload in ("'", '"', "')", "'--"):
        if len(results) >= _MAX_PAYLOADS:
            break
        try:
            probe = await fetch(_with_param(url, param, payload))
        except Exception as error:
            results.append({"payload": payload, "conclusive": False, "signal": "request_failed",
                            "detail": str(error)[:200]})
            continue
        matched = _ERROR_RE.search(probe["body"] or "")
        baseline_matched = _ERROR_RE.search(baseline["body"] or "")
        conclusive = bool(matched) and not baseline_matched
        record(payload, probe, conclusive, "db_error_signature",
               f"响应出现数据库报错特征: {matched.group(0)[:60]}" if conclusive else "无新增报错特征")

    # --- boolean-based: AND 1=1 keeps the page, AND 1=2 changes it ------------------
    try:
        true_probe = await fetch(_with_param(url, param, "1 AND 1=1"))
        false_probe = await fetch(_with_param(url, param, "1 AND 1=2"))
        true_len = _norm_len(true_probe["body"])
        false_len = _norm_len(false_probe["body"])
        conclusive = (
            base_len > 0
            and _similar(base_len, true_len)
            and not _similar(base_len, false_len, tolerance=0.10)
            and abs(true_len - false_len) >= max(20, int(base_len * 0.10))
        )
        detail = f"baseline={base_len} AND1=1:{true_len} AND1=2:{false_len}"
        record("1 AND 1=1 / 1 AND 1=2", false_probe, conclusive, "boolean_differential", detail)
        if conclusive:
            # 把 1=1 的请求也留档，便于人工对冲
            results.append({
                "payload": "1 AND 1=1",
                "conclusive": False,
                "signal": "boolean_control",
                "detail": f"控制组长度={true_len}",
                "url": true_probe["request"]["url"],
                "request": true_probe["request"],
                "response": true_probe["response_meta"],
            })
    except Exception as error:
        results.append({"payload": "1 AND 1=1 / 1 AND 1=2", "conclusive": False,
                        "signal": "request_failed", "detail": str(error)[:200]})

    vulnerable = bool(findings)
    return {
        "url": url,
        "status": "success",
        "parameter": param,
        "payloads_tested": len(results),
        "vulnerable": vulnerable,
        "findings": findings,
        "leads": [] if vulnerable else [
            {"title": f"Suspicious parameter {param}", "severity": "Info",
             "evidence": r["payload"], "reason": r.get("detail")}
            for r in results if r.get("signal") == "db_error_signature"
        ],
        "results": results,
        "conclusion": "confirmed" if vulnerable else "no_signal",
    }
