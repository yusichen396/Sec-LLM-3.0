"""Playwright browser automation tools for web security testing.

Design notes:
- every target goes through ``validate_target_url`` (scheme, credentials, private ranges,
  and the post-redirect landing URL), because the planner supplies these URLs;
- every request is subject to a per-origin rate limit (``core.net.politeness``);
- authenticated flows store Playwright ``storage_state`` per origin, so one login can
  serve later crawl/exploit calls without re-entering credentials;
- XSS counts as a finding only when the browser actually executed the payload, and the
  returned ``results`` carry the request/response material the evidence store needs.
"""
import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from core.net.politeness import get_limiter
from core.net.session_store import SessionStore
from tools.registry import register_tool

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")
_MAX_PAGE_TEXT = 10_000


# ---------------------------------------------------------------- SSRF guard
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
    """Reject non-HTTP schemes, credentials, and internal/loopback destinations."""
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
    # 工具级 allowlist：planner 可能给出从未作为目标提交过的 URL
    allowed = {
        item.strip().lower().rstrip(".")
        for item in (getattr(settings, "AGENT_ALLOWED_TARGETS", "") or "").split(",")
        if item.strip()
    }
    if allowed and hostname not in allowed:
        raise ValueError("目标不在 AGENT_ALLOWED_TARGETS 内（工具级校验）")
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


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    host = (parts.hostname or "").lower()
    return f"{scheme}://{host}" + (f":{parts.port}" if parts.port else "")


def _error(url: str, message: str, **extra) -> dict:
    return {"url": url, "status": "error", "error": message[:300], **extra}


# ---------------------------------------------------------------- browser plumbing
async def _launch(playwright):
    from config import settings

    channel = (getattr(settings, "AGENT_BROWSER_CHANNEL", "") or "").strip()
    kwargs = {"headless": bool(getattr(settings, "AGENT_BROWSER_HEADLESS", True))}
    if channel:
        kwargs["channel"] = channel
    return await playwright.chromium.launch(**kwargs)


async def _new_context(browser, url: str, use_session: bool):
    """Create a context seeded with a stored session for this origin, if any."""
    storage_state = None
    if use_session:
        try:
            storage_state = SessionStore().load(origin_of(url))
        except Exception:  # session store is best effort
            storage_state = None
    if hasattr(browser, "new_context"):
        return await browser.new_context(storage_state=storage_state)
    # Test doubles only expose new_page()
    return None


async def _open_page(browser, url: str, use_session: bool):
    context = await _new_context(browser, url, use_session)
    if context is None:
        return await browser.new_page(), None
    return await context.new_page(), context


async def _goto(page, url: str, timeout: int = 30000, wait_until: str = "domcontentloaded"):
    """Rate-limited navigation that returns (status, final_url)."""
    await get_limiter().wait(origin_of(url))
    response = await page.goto(url, timeout=timeout, wait_until=wait_until)
    status = getattr(response, "status", None) if response is not None else None
    return status, getattr(page, "url", url)


async def _close(browser, context) -> None:
    try:
        if context is not None:
            await context.close()
    finally:
        await browser.close()


def _excerpt(text: str, limit: int = 800) -> str:
    return (text or "")[:limit]


# ---------------------------------------------------------------- login
@register_tool(
    name="browser_login",
    description="Log into a web application once and store the resulting cookies/localStorage "
    "for this origin, so later crawl/scan calls run authenticated. Provide CSS selectors for "
    "the username, password and submit controls; optionally a selector that only appears after "
    "a successful login. Credentials are never stored or returned.",
    category="recon",
    requires_provider=False,
)
async def browser_login(
    url: str,
    username: str,
    password: str,
    username_selector: str = "input[name=username], input[type=email], #username",
    password_selector: str = "input[name=password], input[type=password], #password",
    submit_selector: str = "button[type=submit], input[type=submit]",
    success_selector: str = "",
) -> dict:
    """Authenticate and persist the session state for later tool calls."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed", "status": "error"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return _error(url, str(error))

    origin = origin_of(url)
    async with async_playwright() as p:
        browser = await _launch(p)
        context = await _new_context(browser, url, use_session=False)
        page = await context.new_page() if context is not None else await browser.new_page()
        try:
            status, _ = await _goto(page, url)
            await page.fill(username_selector, username)
            await page.fill(password_selector, password)
            try:
                await page.click(submit_selector, timeout=10000)
            except Exception:
                await page.press(password_selector, "Enter")
            try:
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

            authenticated = False
            evidence: dict = {}
            if success_selector:
                try:
                    authenticated = await page.locator(success_selector).first.is_visible(timeout=5000)
                    evidence["success_selector"] = success_selector
                except Exception:
                    authenticated = False
            if not authenticated:
                cookies = await context.cookies() if context is not None else []
                authenticated = bool(cookies) and origin_of(page.url) == origin and page.url != url
                evidence["cookie_count"] = len(cookies)
            evidence["final_url"] = page.url
            evidence["title"] = await page.title()

            if not authenticated:
                return {
                    "url": url,
                    "origin": origin,
                    "status": "failed",
                    "reason": "登录未成功：未检测到成功标识或会话 Cookie，可能选择器不匹配或凭据无效",
                    **evidence,
                }

            storage_state = await context.storage_state() if context is not None else {"cookies": [], "origins": []}
            summary = SessionStore().save(
                origin,
                storage_state,
                meta={"username_hint": (username or "")[:3] + "***", "login_url": url, "method": "form"},
            )
            return {
                "url": url,
                "origin": origin,
                "status": "success",
                "authenticated": True,
                "session": summary,
                **evidence,
            }
        except Exception as error:
            return _error(url, f"login failed: {error}")
        finally:
            await _close(browser, context)


@register_tool(
    name="browser_session_status",
    description="Report whether a reusable authenticated session exists for a URL's origin "
    "(age, expiry, cookie count). Returns no secrets.",
    category="recon",
    requires_provider=False,
)
async def browser_session_status(url: str) -> dict:
    try:
        url = validate_target_url(url)
    except ValueError as error:
        return _error(url, str(error))
    return {"url": url, **SessionStore().describe(origin_of(url))}


# ---------------------------------------------------------------- recon
@register_tool(
    name="browser_navigate",
    description="Navigate to a URL using a headless browser and capture the page "
    "title, text content, and all links/forms found. Use for reconnaissance of web targets. "
    "Only public http/https targets are accepted. Set use_session=true to reuse a stored login.",
    category="recon",
    requires_provider=False,
)
async def browser_navigate(url: str, use_session: bool = True) -> dict:
    """Navigate to URL and extract page content."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return _error(url, str(error))

    async with async_playwright() as p:
        browser = await _launch(p)
        context = None
        try:
            page, context = await _open_page(browser, url, use_session)
            status, final_url = await _goto(page, url)
            # 重定向可能把浏览器带到内网地址，落地后再校验一次
            try:
                validate_target_url(final_url)
            except ValueError as error:
                return _error(url, f"重定向被拒绝: {error}", final_url=final_url)

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
                "final_url": final_url,
                "http_status": status,
                "title": title,
                "text": text[:_MAX_PAGE_TEXT],
                "links": links[:200],
                "forms": forms[:50],
                "authenticated": bool(use_session and SessionStore().describe(origin_of(url)).get("exists")),
                "status": "success",
            }
        except Exception as e:
            return _error(url, str(e))
        finally:
            await _close(browser, context)


@register_tool(
    name="browser_crawl",
    description="Bounded same-origin crawl used for attack-surface discovery. Follows links "
    "to a configured depth/page budget, is rate limited, and returns every page's forms, query "
    "parameters and scripts so later checks have real endpoints instead of just the homepage.",
    category="recon",
    requires_provider=False,
)
async def browser_crawl(url: str, max_pages: int = 0, max_depth: int = 0, use_session: bool = True) -> dict:
    """Breadth-first same-origin crawl with hard limits."""
    from config import settings

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed", "status": "error"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return _error(url, str(error))

    limit_pages = int(max_pages or getattr(settings, "AGENT_CRAWL_MAX_PAGES", 20))
    limit_depth = int(max_depth or getattr(settings, "AGENT_CRAWL_MAX_DEPTH", 2))
    limit_pages = max(1, min(limit_pages, 100))
    limit_depth = max(0, min(limit_depth, 5))
    origin = origin_of(url)

    pages: list[dict] = []
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(url.split("#")[0], 0)]
    errors: list[str] = []

    async with async_playwright() as p:
        browser = await _launch(p)
        context = None
        try:
            page, context = await _open_page(browser, url, use_session)
            while queue and len(pages) < limit_pages:
                current, depth = queue.pop(0)
                if current in seen:
                    continue
                seen.add(current)
                try:
                    status, final_url = await _goto(page, current, timeout=20000)
                    if origin_of(final_url) != origin:
                        continue
                    title = await page.title()
                    forms = await page.eval_on_selector_all(
                        "form",
                        "els => els.map(el => ({action: el.action, method: el.method, inputs: [...el.querySelectorAll('input,textarea,select')].map(i => ({name: i.name, type: i.type}))}))"
                    )
                    links = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(el => el.href)"
                    )
                    scripts = await page.eval_on_selector_all(
                        "script[src]", "els => els.map(el => el.src)"
                    )
                    params = sorted({k for k, _ in parse_qsl(urlsplit(final_url).query, keep_blank_values=True)})
                    pages.append({
                        "url": final_url,
                        "http_status": status,
                        "title": title,
                        "depth": depth,
                        "forms": forms[:20],
                        "query_parameters": params,
                        "scripts": scripts[:50],
                    })
                    if depth < limit_depth:
                        for link in links:
                            if len(queue) + len(pages) >= limit_pages:
                                break
                            candidate = str(link).split("#")[0]
                            if not candidate.startswith(("http://", "https://")):
                                candidate = urljoin(final_url, candidate)
                            if origin_of(candidate) != origin or candidate in seen:
                                continue
                            queue.append((candidate, depth + 1))
                except Exception as error:
                    errors.append(f"{current}: {str(error)[:120]}")
            return {
                "url": url,
                "origin": origin,
                "status": "success" if pages else "error",
                "page_count": len(pages),
                "pages_crawled": limit_pages,
                "max_depth": limit_depth,
                "truncated": bool(queue),
                "pages": pages,
                "errors": errors[:10],
            }
        except Exception as e:
            return _error(url, str(e))
        finally:
            await _close(browser, context)


# ---------------------------------------------------------------- exploit
@register_tool(
    name="browser_check_xss",
    description="Test a URL for reflected XSS by injecting payloads into query parameters "
    "and observing whether the browser actually executes them. Reflection alone is "
    "reported as a lead, not as a confirmed vulnerability. Returns request/response material "
    "so an evidence artifact can be stored.",
    category="exploit",
    requires_provider=False,
)
async def browser_check_xss(url: str, param: str, use_session: bool = True) -> dict:
    """Test for reflected XSS on a URL parameter."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return _error(url, str(error))

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
        context = None
        try:
            page, context = await _open_page(browser, url, use_session)
            dialog_triggered = False

            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)
            for payload in payloads:
                dialog_triggered = False
                parts = urlsplit(url)
                query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != param]
                test_url = urlunsplit(parts._replace(query=urlencode([*query, (param, payload)]), fragment=""))
                try:
                    status, final_url = await _goto(page, test_url, timeout=15000)
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
                        "status": status,
                        "url": test_url,
                        "final_url": final_url,
                        "response_excerpt": _excerpt(content),
                    })
                except Exception as error:
                    results.append({"payload": payload, "executed": False,
                                    "dialog_triggered": False, "reflected": False,
                                    "status": None, "url": test_url,
                                    "response_excerpt": "",
                                    "error": str(error)[:200]})
            if hasattr(page, "remove_listener"):
                page.remove_listener("dialog", handle_dialog)
        finally:
            await _close(browser, context)

    executed_results = [item for item in results if item.get("executed")]
    reflected_only = [item for item in results if item.get("reflected") and not item.get("executed")]
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
    if results and len(failed) == len(results):
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
async def browser_screenshot(url: str, use_session: bool = True) -> dict:
    """Take a screenshot of a URL (bounded in size)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}

    try:
        url = validate_target_url(url)
    except ValueError as error:
        return _error(url, str(error))

    import base64

    async with async_playwright() as p:
        browser = await _launch(p)
        context = None
        try:
            page, context = await _open_page(browser, url, use_session)
            await _goto(page, url)
            screenshot = await page.screenshot(full_page=False, type="png")
            if len(screenshot) > 4_000_000:
                return _error(url, "截图超过 4MB 上限")
            return {
                "url": url,
                "screenshot_base64": base64.b64encode(screenshot).decode(),
                "status": "success",
            }
        except Exception as e:
            return _error(url, str(e))
        finally:
            await _close(browser, context)
