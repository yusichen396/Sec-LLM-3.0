"""Asset typing and per-type check selection.

The old web_scan path was four hardcoded steps regardless of what the target turned
out to be. This module turns recon output into explicit assets, then picks the checks
that make sense for each type — and records what it deliberately did *not* check, so
the report can be honest about coverage.
"""
from typing import Any, Dict, List

WEB_APP = "web_app"
API = "api"
HOST = "host"


def classify(discoveries: Dict[str, Any]) -> Dict[str, Any]:
    """Derive asset types and testable parameters from recon output."""
    pages = [p for p in (discoveries.get("pages") or []) if isinstance(p, dict)]
    forms = [f for f in (discoveries.get("forms") or []) if isinstance(f, dict)]

    parameters: List[str] = []
    for page in pages:
        for name in page.get("query_parameters") or []:
            if isinstance(name, str) and name and name not in parameters:
                parameters.append(name)

    api_hints = [
        page.get("url") for page in pages
        if isinstance(page.get("url"), str)
        and ("/api/" in page["url"].lower() or page["url"].lower().endswith(".json"))
    ]
    hosts = bool((discoveries.get("nmap_output") or "").strip())

    assets: Dict[str, Any] = {
        "types": [t for t, present in ((WEB_APP, bool(pages or forms)), (API, bool(api_hints)), (HOST, hosts)) if present],
        "pages": len(pages),
        "forms": len(forms),
        "parameters": parameters[:50],
        "api_endpoints": api_hints[:20],
    }
    return assets


def checks_for(assets: Dict[str, Any], discoveries: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Ordered checks for the discovered asset types.

    Each entry says what to run and why; unknown types are reported as skipped instead
    of silently producing an empty result.
    """
    checks: List[Dict[str, Any]] = []
    types = set(assets.get("types") or [])

    if WEB_APP in types:
        for form in (discoveries.get("forms") or [])[:5]:
            for field in (form.get("inputs") or [])[:3]:
                if field.get("type") in ("text", "search", "url", ""):
                    checks.append({
                        "check": "reflected_xss",
                        "via": "form",
                        "url": form.get("action"),
                        "parameter": field.get("name") or "q",
                    })
        for parameter in assets.get("parameters") or []:
            checks.append({"check": "reflected_xss", "via": "query", "url": None, "parameter": parameter})

    skipped: List[str] = []
    if API in types:
        skipped.append("api：当前没有 schema 发现与越权( IDOR )检测器，仅记录端点")
    if HOST in types:
        skipped.append("host：只做了 nmap 服务识别，未做 CVE 匹配")
    skipped.append("sql_injection / ssrf / xxe / idor：暂无专用检测器（需人工复核或外部工具）")

    # 去重（同 url+参数 只跑一次），并限制总量
    unique: List[Dict[str, Any]] = []
    seen = set()
    for check in checks:
        key = (check.get("url"), check.get("parameter"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(check)
    return unique[:12] + [{"check": "skipped", "reasons": skipped}]


def summarize_plan(checks: List[Dict[str, Any]]) -> str:
    active = [c for c in checks if c.get("check") != "skipped"]
    skipped = [c for c in checks if c.get("check") == "skipped"]
    parts = [f"[STRATEGY] {len(active)} 项检查"]
    if active:
        parts.append(": " + ", ".join(sorted({c["check"] for c in active})))
    if skipped:
        parts.append("；未覆盖：" + "；".join(skipped[0].get("reasons") or []))
    return "".join(parts)
