"""Shared HTTP probing for content-based checks (SQLi, LFI, SSRF, API discovery).

Uses httpx (no browser) so request/response material is exact and cheap to capture.
Every request still goes through the SSRF guard, the tool-layer allowlist and the
per-origin rate limiter — probing must obey the same rules as browsing.
"""
import time
from typing import Any, Dict, Optional

import httpx

from core.net.politeness import get_limiter

_USER_AGENT = "Sec-LLM-Agent/4.0 (authorized-assessment)"
_MAX_BODY = 200_000


async def fetch(
    url: str,
    *,
    params: Optional[dict] = None,
    method: str = "GET",
    data: Optional[dict] = None,
    json_body: Optional[dict] = None,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """Send one request and return status/headers/body plus timing.

    Redirects are not followed: the caller decides what a 3xx means, and following
    them blindly would defeat the post-redirect SSRF check.
    """
    from tools.browser import validate_target_url

    validate_target_url(url)  # raises ValueError for out-of-scope / internal targets
    await get_limiter().wait(url)

    request_url = str(httpx.URL(url, params=params))
    request_meta = {
        "method": method.upper(),
        "url": request_url,
        "headers": {"content-type": "application/x-www-form-urlencoded"} if data else (
            {"content-type": "application/json"} if json_body else {}
        ),
        "body": (data if data else json_body) or None,
    }

    started = time.monotonic()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=5.0),
        follow_redirects=False,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        if method.upper() == "POST":
            response = await client.post(url, params=params, data=data, json=json_body)
        else:
            response = await client.get(url, params=params)
        body = response.text[:_MAX_BODY]
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "request": request_meta,
            "response_meta": {
                "status": response.status_code,
                "url": request_url,
                "headers": dict(response.headers),
                "body_excerpt": body[:800],
            },
        }
