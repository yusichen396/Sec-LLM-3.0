"""Against a running Next.js dev server: RUN_AGENT_UI=1 AGENT_UI_URL=http://localhost:3002."""
import json
import os

import pytest


@pytest.mark.skipif(os.environ.get("RUN_AGENT_UI") != "1", reason="requires local Next.js dev server and Playwright Chromium")
def test_strict_mode_submission_recovers_premature_stream_eof():
    from playwright.sync_api import sync_playwright

    calls = {"run": 0, "status": 0}
    def api(route):
        url = route.request.url.split("?")[0]
        body = {}
        headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*",
                   "Access-Control-Allow-Methods": "GET,POST,OPTIONS"}
        if route.request.method == "OPTIONS":
            route.fulfill(status=204, headers=headers)
            return
        if url.endswith("/sessions"):
            body = {"sessions": []}
        elif url.endswith("/run"):
            calls["run"] += 1
            body = {"session_id": "ui-fixture", "status": "running", "message": "started"}
        elif url.endswith("/status"):
            calls["status"] += 1
            body = {"session_id": "ui-fixture", "status": "running" if calls["status"] == 1 else "completed",
                    "phase": "report", "findings_count": 0, "logs": ["fixture progress"], "report": None}
        elif url.endswith("/stream"):
            route.fulfill(content_type="text/event-stream", headers=headers,
                          body='data: {"type":"log","message":"fixture progress"}\n\n')
            return  # EOF without a done event must trigger status recovery.
        elif url.endswith("/report"):
            body = {"status": "completed", "findings": [], "report": "UI fixture report completed"}
        else:
            pytest.fail("Unexpected API call: " + url)
        route.fulfill(content_type="application/json", headers=headers, body=json.dumps(body))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            page.add_init_script("localStorage.setItem('token','ui-fixture-token')")
            page.route("**/api/agent/**", api)
            page.goto(os.environ.get("AGENT_UI_URL", "http://localhost:3002") + "/agent")
            page.get_by_placeholder("https://example.com or 192.168.1.1 or path/to/code").fill("https://example.com")
            page.get_by_role("button", name="Start Agent Task").click()
            page.get_by_text("UI fixture report completed", exact=True).wait_for(timeout=20000)
            assert page.get_by_role("button", name="Start Agent Task").is_enabled()
            assert calls["run"] == 1 and calls["status"] >= 2
        finally:
            browser.close()
