"""Asset typing and per-type check selection.

Recon output is turned into explicit assets; the checks that make sense for those
assets are then selected, and everything the project *cannot* test is reported as a
coverage gap instead of silently producing an empty result.
"""
import re
from typing import Any, Dict, List

WEB_APP = "web_app"
API = "api"
HOST = "host"

MAX_CHECKS = 18
MAX_PARAMETERS = 3
_URL_LIKE = re.compile(r"url|uri|link|next|redirect|callback|fetch|src|dest|target", re.IGNORECASE)


def classify(discoveries: Dict[str, Any]) -> Dict[str, Any]:
    """Derive asset types and testable parameters from recon output."""
    pages = [p for p in (discoveries.get("pages") or []) if isinstance(p, dict)]
    forms = [f for f in (discoveries.get("forms") or []) if isinstance(f, dict)]

    parameters: List[str] = []
    page_for: Dict[str, str] = {}
    for page in pages:
        for name in page.get("query_parameters") or []:
            if isinstance(name, str) and name and name not in parameters:
                parameters.append(name)
            if isinstance(name, str) and page.get("url"):
                page_for.setdefault(name, page["url"])

    spec_endpoints = [e for e in (discoveries.get("api_endpoints") or []) if isinstance(e, dict)]
    api_hints = [e.get("path") for e in spec_endpoints if e.get("path")]
    if not api_hints:
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
        "parameter_pages": page_for,
        "api_endpoints": api_hints[:20],
        "api_spec_endpoints": spec_endpoints[:50],
    }
    return assets


def checks_for(assets: Dict[str, Any], discoveries: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Ordered checks for the discovered asset types."""
    checks: List[Dict[str, Any]] = []
    types = set(assets.get("types") or [])
    parameters = list(assets.get("parameters") or [])
    forms = [f for f in (discoveries.get("forms") or []) if isinstance(f, dict)]

    if WEB_APP in types:
        for form in forms[:5]:
            for field in (form.get("inputs") or [])[:3]:
                if field.get("type") in ("text", "search", "url", ""):
                    checks.append({
                        "check": "reflected_xss",
                        "via": "form",
                        "url": form.get("action"),
                        "parameter": field.get("name") or "q",
                    })
        for parameter in parameters:
            checks.append({"check": "reflected_xss", "via": "query",
                           "url": assets.get("parameter_pages", {}).get(parameter),
                           "parameter": parameter})
        # 注入类检查只测前几个参数，避免请求爆炸
        for parameter in parameters[:MAX_PARAMETERS]:
            page_url = assets.get("parameter_pages", {}).get(parameter)
            checks.append({"check": "sqli_probe", "via": "query", "url": page_url, "parameter": parameter})
            checks.append({"check": "lfi_probe", "via": "query", "url": page_url, "parameter": parameter})

        # URL 形态的参数做 SSRF（错误回显型）
        for parameter in [p for p in parameters if _URL_LIKE.search(p)][:2]:
            checks.append({"check": "ssrf_probe", "via": "query",
                           "url": assets.get("parameter_pages", {}).get(parameter),
                           "parameter": parameter})

        # POST 表单做一次 SQLi（urlencoded body）
        for form in forms[:3]:
            if (form.get("method") or "get").lower() != "post":
                continue
            fields = {
                str(field.get("name")): ""
                for field in (form.get("inputs") or [])
                if field.get("name") and field.get("type") not in ("submit", "button", "checkbox", "radio", "file")
            }
            for name in list(fields)[:2]:
                checks.append({
                    "check": "sqli_probe", "via": "form_post",
                    "url": form.get("action"), "parameter": name,
                    "method": "POST", "form_fields": fields,
                })

    skipped: List[str] = []
    if API in types:
        skipped.append(
            f"api：已从规范发现 {len(assets.get('api_spec_endpoints') or [])} 个端点，"
            "但越权(IDOR)测试尚未实现"
        )
    if HOST in types:
        skipped.append("host：只做了 nmap 服务识别，未做 CVE 匹配")
    skipped.append("SSRF 仅覆盖错误回显型；带外（DNS/HTTP 回连）未覆盖")
    skipped.append("xxe / 反序列化：缺少专用检测器")
    skipped.append("POST 仅测试 urlencoded 表单；JSON body 与 multipart 未纳入")

    unique: List[Dict[str, Any]] = []
    seen = set()
    for check in checks:
        key = (check.get("check"), check.get("url"), check.get("parameter"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(check)
    return unique[:MAX_CHECKS] + [{"check": "skipped", "reasons": skipped}]


def summarize_plan(checks: List[Dict[str, Any]]) -> str:
    active = [c for c in checks if c.get("check") != "skipped"]
    skipped = [c for c in checks if c.get("check") == "skipped"]
    kinds = sorted({c["check"] for c in active})
    parts = [f"[STRATEGY] {len(active)} 项检查"]
    if kinds:
        parts.append(": " + ", ".join(kinds))
    if skipped:
        parts.append("；未覆盖：" + "；".join(skipped[0].get("reasons") or []))
    return "".join(parts)
