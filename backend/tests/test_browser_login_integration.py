"""Real-browser test for authenticated scanning.

Uses an installed system browser (msedge/chrome) because the bundled Chromium download
is not available in every environment; skips cleanly when no browser can be launched.
The point of the test is the part mocks cannot prove: a login form is submitted, the
session (cookies) is persisted, and a later tool call reaches a protected page.
"""
import asyncio
import shutil
import uuid
from pathlib import Path

import pytest

from tests.fixtures import vuln_target


def _pick_channel():
    """Return a browser channel that actually launches in this environment."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:  # pragma: no cover - optional dependency
        return None

    async def probe():
        async with async_playwright() as p:
            for channel in ("msedge", "chrome", None):
                kwargs = {"headless": True}
                if channel:
                    kwargs["channel"] = channel
                try:
                    browser = await p.chromium.launch(**kwargs)
                except Exception:
                    continue
                await browser.close()
                return channel or ""
        return None

    try:
        return asyncio.run(probe())
    except Exception:
        return None


CHANNEL = _pick_channel()


@pytest.fixture(scope="module")
def target():
    server, base, thread = vuln_target.start()
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def lab(monkeypatch):
    from config import settings
    import core.net.politeness as politeness

    session_dir = Path(__file__).resolve().parents[2] / (".tmp_sessions_" + uuid.uuid4().hex[:8])
    session_dir.mkdir(mode=0o777, exist_ok=True)
    monkeypatch.setattr(settings, "AGENT_ALLOW_PRIVATE_TARGETS", True)
    monkeypatch.setattr(settings, "AGENT_ALLOWED_TARGETS", "")
    monkeypatch.setattr(settings, "AGENT_MIN_REQUEST_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(settings, "AGENT_SESSION_DIR", str(session_dir))
    monkeypatch.setattr(settings, "AGENT_SESSION_TTL_SECONDS", 300)
    monkeypatch.setattr(settings, "AGENT_BROWSER_CHANNEL", CHANNEL or "")
    monkeypatch.setattr(politeness, "_limiter", None)
    try:
        yield session_dir
    finally:
        politeness._limiter = None
        shutil.rmtree(session_dir, ignore_errors=True)


@pytest.mark.skipif(not CHANNEL and CHANNEL != "", reason="没有可用的浏览器（Chromium 未下载且无系统浏览器）")
def test_login_then_reach_protected_page(target, lab):
    from tools import browser

    if CHANNEL is None:
        pytest.skip("Playwright 不可用")

    login = asyncio.run(browser.browser_login(
        url=f"{target}/login",
        username="admin",
        password="s3cret",
        username_selector="input[name=username]",
        password_selector="input[name=password]",
        submit_selector="button[type=submit]",
        success_selector="#welcome",
    ))
    assert login["status"] == "success", login
    assert login["authenticated"] is True
    assert login["session"]["reusable"] is True
    # 凭据绝不出现在返回里
    assert "s3cret" not in str(login)

    status = asyncio.run(browser.browser_session_status(url=f"{target}/home"))
    assert status["exists"] is True and status["cookie_count"] >= 1

    authed = asyncio.run(browser.browser_navigate(url=f"{target}/home", use_session=True))
    assert authed["status"] == "success", authed
    assert "protected area" in authed["text"]

    anonymous = asyncio.run(browser.browser_navigate(url=f"{target}/home", use_session=False))
    assert anonymous["status"] == "success"
    assert "protected area" not in anonymous["text"]


@pytest.mark.skipif(not CHANNEL and CHANNEL != "", reason="没有可用的浏览器")
def test_failed_login_is_reported_not_swallowed(target, lab):
    from tools import browser

    if CHANNEL is None:
        pytest.skip("Playwright 不可用")

    result = asyncio.run(browser.browser_login(
        url=f"{target}/login",
        username="admin",
        password="wrong-password",
        username_selector="input[name=username]",
        password_selector="input[name=password]",
        submit_selector="button[type=submit]",
        success_selector="#welcome",
    ))
    assert result["status"] == "failed", result
    assert "登录未成功" in result["reason"]
