"""Playwright browser automation tools for web security testing."""
from tools.registry import register_tool
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@register_tool(
    name="browser_navigate",
    description="Navigate to a URL using a headless browser and capture the page "
    "title, text content, and all links/forms found. Use for reconnaissance of web targets.",
    category="recon",
    requires_provider=False,
)
async def browser_navigate(url: str) -> dict:
    """Navigate to URL and extract page content."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
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
                "text": text[:10000],
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
    "and checking if they appear unescaped in the response.",
    category="exploit",
    requires_provider=False,
)
async def browser_check_xss(url: str, param: str) -> dict:
    """Test for reflected XSS on a URL parameter."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}

    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "';alert(1);//",
    ]
    results = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        for payload in payloads:
            try:
                parts = urlsplit(url)
                query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != param]
                test_url = urlunsplit(parts._replace(query=urlencode([*query, (param, payload)]), fragment=""))
                # Register dialog handler BEFORE goto so it catches alert() from XSS
                dialog_triggered = False
                async def handle_dialog(dialog):
                    nonlocal dialog_triggered
                    dialog_triggered = True
                    await dialog.dismiss()
                page.on("dialog", handle_dialog)

                await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                content = await page.content()

                # Check if payload appears unescaped OR dialog was triggered
                is_vulnerable = payload in content or dialog_triggered

                results.append({
                    "payload": payload,
                    "vulnerable": is_vulnerable,
                    "dialog_triggered": dialog_triggered,
                    "url": test_url,
                })
            except Exception:
                results.append({"payload": payload, "vulnerable": False, "error": "timeout"})

        await browser.close()

    found = [r for r in results if r["vulnerable"]]
    return {
        "url": url,
        "parameter": param,
        "payloads_tested": len(payloads),
        "vulnerable_count": len(found),
        "findings": [
            {"title": f"Reflected XSS in {param}", "severity": "High", "evidence": r["payload"]}
            for r in found
        ] if found else [],
        "results": results,
    }


@register_tool(
    name="browser_screenshot",
    description="Take a screenshot of a web page at the given URL.",
    category="recon",
    requires_provider=False,
)
async def browser_screenshot(url: str) -> dict:
    """Take a screenshot of a URL."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}

    import base64

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
            screenshot = await page.screenshot(full_page=False, type="png")
            return {
                "url": url,
                "screenshot_base64": base64.b64encode(screenshot).decode(),
                "status": "success",
            }
        except Exception as e:
            return {"url": url, "error": str(e)[:500], "status": "error"}
        finally:
            await browser.close()
