"""Playwright browser automation tools for web security testing."""
import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from tools.registry import register_tool

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")
_MAX_PAGE_TEXT = 10_000


def _blocked_addresses(hostname: str) -> list[str]:
    """Resolve a hostname and return every address we refuse to reach."""
    blocked: list[str] = []
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as error:
        raise ValueError(f"目标无法解析: {hostname}") from error
    for info in infos:
        raw = info[4][0].split("%")[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            blocked.append(raw)
            continue
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            blocked.append(raw)
    return blocked


def validate_target_url(url: str) -> str:
    """Reject non-HTTP schemes, credentials, and internal/loopback destinations.

    This is the tool-level SSRF guard: the agent planner supplies these URLs, so an
    allowed scan target must not be able to redirect the sandbox into the internal
    network or the cloud metadata endpoint.
    """
    from config import settings

    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("URL 不能为空")
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(f"只允许 http/https，收到: {parts.scheme or '空'}")
    if parts.username or parts.password:
        raise ValueError("URL 不能携带凭据")
    hostname = (parts.hostname or "").rstrip(".").lower()
    if not hostname:
        raise ValueError("URL 缺少主机名")
    if getattr(settings, "AGENT_ALLOW_PRIVATE_TARGETS", False):
        return candidate
    if hostname == "localhost" or hostname.endswith(_BLOCKED_HOST_SUFFIXES):
        raise ValueError("拒绝访问本机/内网主机名")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        blocked = _blocked_addresses(hostname)
        if blocked:
            raise ValueError(f"目标解析到内网/保留地址: {', '.join(sorted(set(blocked))[:3])}")
        return candidate
    if (
        literal.is_private
        or literal.is_loopback
        or literal.is_link_local
        or literal.is_multicast
        or literal.is_reserved
        or literal.is_unspecified
    ):
        raise ValueError("拒绝访问内网/保留地址")
    return candidate


def _same_origin(a: str, b: str) -> bool:
    left, right = urlsplit(a), urlsplit(b)
    def origin(parts):
        return (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port)
    return origin(left) == origin(right)


async def _launch(playwright):
    from config import settings

    headless = bool(getattr(settings, "AGENT_BROWSER_HEADLESS", True))
    return await playwright.chromium.launch(headless=headless)


@register_tool(
    name="browser_navigate",
    description="Navigate to a URL using a headless browser and capture the page "
    "title, text content, and all links/forms found. Use for reconnaissance of web targets. "
    "Only public http/https targets are accepted.",
    category="recon",
    requires_provider=False,
)
async def browser_navigate(url: str) -> dict:
    """Navigate to URL and extract page content."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return {"url": url, "status": "error", "error": str(error)[:300]}

    async with async_playwright() as p:
        browser = await _launch(p)
        try:
            page = await browser.new_page()
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
            # 重定向可能把浏览器带到内网地址，落地后再校验一次
            final_url = page.url
            try:
                validate_target_url(final_url)
            except ValueError as error:
                return {"url": url, "final_url": final_url, "status": "error",
                        "error": f"重定向被拒绝: {error}"[:300]}
            title = await page.title()
            text = await page.inner_text("body")
            links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(el => ({href: el.href, text: el.textContent.trim()}))"
            )
            forms = await page.eval_on_selector_all(
                "form",
                "els => els.map(el => ({action: el.action, method: el.method, inputs: [...el.querySelectorAll('input,textarea,select')].map(i => ({name: i.name, type: i.type}))}))"
            )
            return {
                "url": url,
                "title": title,
                "text": text[:_MAX_PAGE_TEXT],
                "links": links[:200],
                "forms": forms[:50],
                "status": "success",
            }
        except Exception as e:
            return {"url": url, "error": str(e)[:500], "status": "error"}
        finally:
            await browser.close()


@register_tool(
    name="browser_check_xss",
    description="Test a URL for reflected XSS by injecting payloads into query parameters "
    "and observing whether the browser actually executes them. Reflection alone is "
    "reported as a lead, not as a confirmed vulnerability.",
    category="exploit",
    requires_provider=False,
)
async def browser_check_xss(url: str, param: str) -> dict:
    """Test for reflected XSS on a URL parameter."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return {"url": url, "status": "error", "error": str(error)[:300]}

    # 用带回调的载荷判定"是否真的执行"，而不是"是否出现在 HTML 里"
    token = "sec_llm_probe"
    payloads = [
        f"<script>window.{token}=1;alert(1)</script>",
        f"\"><script>window.{token}=1;alert(1)</script>",
        f"<img src=x onerror=\"window.{token}=1;alert(1)\">",
        f"';window.{token}=1;alert(1);//",
    ]
    results = []

    async with async_playwright() as p:
        browser = await _launch(p)
        try:
            page = await browser.new_page()
            dialog_triggered = False

            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)
            for payload in payloads:
                dialog_triggered = False
                try:
                    parts = urlsplit(url)
                    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != param]
                    test_url = urlunsplit(parts._replace(query=urlencode([*query, (param, payload)]), fragment=""))
                    await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_timeout(150)
                        executed = await page.evaluate(f"() => window.{token} === 1")
                    except Exception:
                        executed = False
                    content = await page.content()
                    results.append({
                        "payload": payload,
                        "executed": bool(executed) or dialog_triggered,
                        "dialog_triggered": dialog_triggered,
                        "reflected": payload in content,
                        "url": test_url,
                    })
                except Exception as error:
                    results.append({"payload": payload, "executed": False,
                                    "dialog_triggered": False, "reflected": False,
                                    "error": str(error)[:200], "url": url})
            if hasattr(page, "remove_listener"):
                page.remove_listener("dialog", handle_dialog)
        finally:
            await browser.close()

    executed_results = [item for item in results if item.get("executed")]
    reflected_only = [item for item in results if item.get("reflected") and not item.get("executed")]
    attempted = len(results)
    failed = [item for item in results if item.get("error")]
    response = {
        "url": url,
        "parameter": param,
        "payloads_tested": len(payloads),
        "vulnerable_count": len(executed_results),
        "reflected_count": len(reflected_only),
        # 只有执行证据才算发现；仅回显作为线索单独返回
        "findings": [
            {"title": f"Reflected XSS in {param}", "severity": "High",
             "evidence": item["payload"], "execution": "dialog_or_window_flag"}
            for item in executed_results
        ],
        "leads": [
            {"title": f"Reflected input in {param} (not executed)",
             "severity": "Info", "evidence": item["payload"]}
            for item in reflected_only
        ],
        "results": results,
    }
    if attempted and len(failed) == attempted:
        # 全部因网络/超时失败时不能返回"无漏洞"，否则会造成静默假阴性
        response["status"] = "error"
        response["error"] = "所有载荷都未完成加载，无法判定"
        response["findings"] = []
        response["leads"] = []
    return response


@register_tool(
    name="browser_screenshot",
    description="Take a screenshot of a web page at the given URL.",
    category="recon",
    requires_provider=False,
)
async def browser_screenshot(url: str) -> dict:
    """Take a screenshot of a URL (bounded in size)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return {"url": url, "status": "error", "error": str(error)[:300]}

    import base64

    async with async_playwright() as p:
        browser = await _launch(p)
        try:
            page = await browser.new_page()
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
            screenshot = await page.screenshot(full_page=False, type="png")
            if len(screenshot) > 4_000_000:
                return {"url": url, "status": "error", "error": "截图超过 4MB 上限"}
            return {
                "url": url,
                "screenshot_base64": base64.b64encode(screenshot).decode(),
                "status": "success",
            }
        except Exception as e:
            return {"url": url, "error": str(e)[:500], "status": "error"}
        finally:
            await browser.close()
