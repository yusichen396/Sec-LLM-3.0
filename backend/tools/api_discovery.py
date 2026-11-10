"""API surface discovery from published specs.

Turns an unknown API into a testable list of endpoints: try the well-known spec paths,
parse OpenAPI/Swagger JSON, and return paths, methods and parameter names. No guessing
of hidden endpoints and no brute force — only specs the service publishes itself.
"""
from typing import Any, Dict, List
from urllib.parse import urljoin, urlsplit, urlunsplit

from tools.http_probe import fetch
from tools.registry import register_tool

SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
    "/api-docs",
)
_MAX_ENDPOINTS = 100


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _extract(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    endpoints: List[Dict[str, Any]] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return endpoints
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            params: List[str] = []
            if isinstance(operation, dict):
                for parameter in operation.get("parameters") or []:
                    if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
                        params.append(parameter["name"])
                body = (operation.get("requestBody") or {}).get("content") or {}
                if isinstance(body, dict) and body:
                    params.append("<requestBody>")
            endpoints.append({"path": path, "method": method.upper(), "parameters": params})
            if len(endpoints) >= _MAX_ENDPOINTS:
                return endpoints
    return endpoints


@register_tool(
    name="api_discovery",
    description="Discover an API surface by reading its published OpenAPI/Swagger spec, "
    "returning endpoints, methods and parameter names for later authorization testing.",
    category="recon",
        accepts="url",
    requires_provider=False,
)
async def api_discovery(url: str) -> dict:
    origin = _origin(url)
    attempts: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []

    for path in SPEC_PATHS:
        candidate = urljoin(origin + "/", path.lstrip("/"))
        try:
            response = await fetch(candidate)
        except Exception as error:
            attempts.append({"url": candidate, "error": str(error)[:160]})
            continue
        attempts.append({"url": candidate, "status": response["status"]})
        if response["status"] != 200:
            continue
        try:
            import json

            spec = json.loads(response["body"])
        except (ValueError, TypeError):
            continue
        endpoints = _extract(spec if isinstance(spec, dict) else {})
        if endpoints:
            return {
                "url": url,
                "status": "success",
                "spec_url": candidate,
                "endpoint_count": len(endpoints),
                "endpoints": endpoints,
                "attempts": attempts,
            }

    return {
        "url": url,
        "status": "success",
        "spec_url": None,
        "endpoint_count": 0,
        "endpoints": [],
        "attempts": attempts,
        "note": "未发现公开的 OpenAPI/Swagger 规范；API 资产无法自动枚举",
    }
