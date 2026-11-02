"""Tests for the authenticated-scanning, evidence and strategy capabilities."""
import asyncio
import json
import shutil
import uuid
from pathlib import Path

import pytest

from agents.strategy import API, HOST, WEB_APP, checks_for, classify, summarize_plan
from core.evidence import EvidenceRecorder
from core.net.politeness import OriginRateLimiter
from core.net.session_store import SessionStore


@pytest.fixture()
def workdir():
    """Scratch dir under the repo root.

    ``tmp_path`` is unusable in this sandbox: pytest creates its base dir with mode
    0700, which the restricted token cannot traverse. An explicit 0777 directory is
    writable, so the capability tests keep a real (removed afterwards) scratch dir.
    """
    base = Path(__file__).resolve().parents[2]
    directory = base / (".tmp_caps_" + uuid.uuid4().hex[:8])
    directory.mkdir(mode=0o777, exist_ok=False)
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# --------------------------------------------------------------- session store
def test_session_store_roundtrip_and_summary(workdir):
    store = SessionStore(root=str(workdir), ttl=60)
    state = {"cookies": [{"name": "sid", "value": "secret", "domain": "example.com"}], "origins": []}
    summary = store.save("https://example.com", state, meta={"username_hint": "adm***"})

    assert summary["exists"] is True and summary["reusable"] is True
    assert summary["cookie_count"] == 1
    assert "storage_state" not in summary  # never leak secrets through the tool surface
    assert store.load("https://example.com") == state


def test_session_store_expires_and_deletes(workdir):
    store = SessionStore(root=str(workdir), ttl=0)
    store.save("https://example.com", {"cookies": [{"name": "sid", "value": "x"}]})
    assert store.load("https://example.com") is None
    assert store.describe("https://example.com")["exists"] is False


def test_session_store_rejects_oversized_state(workdir):
    store = SessionStore(root=str(workdir), ttl=60)
    with pytest.raises(ValueError):
        store.save("https://example.com", {"cookies": [], "origins": ["x" * 600_000]})


# --------------------------------------------------------------- politeness
def test_rate_limiter_serialises_same_origin_only():
    limiter = OriginRateLimiter(min_interval=0.05)

    async def run():
        waited_first = await limiter.wait("https://a.example")
        waited_second = await limiter.wait("https://a.example")
        waited_other = await limiter.wait("https://b.example")
        return waited_first, waited_second, waited_other

    first, second, other = asyncio.run(run())
    assert first == 0
    assert second >= 0.03  # 同源必须等待
    assert other == 0  # 不同源互不影响


# --------------------------------------------------------------- evidence
def test_evidence_record_hashes_redacts_and_verifies(workdir):
    recorder = EvidenceRecorder(base_dir=str(workdir))
    ref = recorder.record(
        session_id="sess-1",
        tool="browser_check_xss",
        kind="reflected_xss",
        payload="<script>alert(1)</script>",
        request={"method": "GET", "url": "https://example.com/?q=payload",
                 "headers": {"Authorization": "Bearer secret", "Cookie": "sid=1"}},
        response={"status": 200, "url": "https://example.com/?q=payload",
                  "body_excerpt": "<script>alert(1)</script>"},
        extra={"executed": True},
        poc="#!/usr/bin/env bash\ncurl -sS -i 'https://example.com/?q=payload'\n",
    )

    record = json.loads(Path(ref["evidence_path"]).read_text(encoding="utf-8"))
    assert record["request"]["headers"]["Authorization"] == "<redacted>"
    assert record["request"]["headers"]["Cookie"] == "<redacted>"
    assert record["sha256"] == ref["evidence_sha256"]
    assert ref["poc_path"] and ref["poc_path"].endswith(".repro.sh")
    assert recorder.verify(ref) is True

    # 篡改后必须校验失败
    record["payload"] = "tampered"
    Path(ref["evidence_path"]).write_text(json.dumps(record), encoding="utf-8")
    assert recorder.verify(ref) is False


def test_evidence_verify_rejects_missing_reference(workdir):
    recorder = EvidenceRecorder(base_dir=str(workdir))
    assert recorder.verify({}) is False
    assert recorder.verify({"evidence_path": str(workdir / "nope.json"),
                            "evidence_sha256": "0" * 64}) is False


# --------------------------------------------------------------- strategy
def test_classify_detects_assets_and_parameters():
    discoveries = {
        "pages": [
            {"url": "https://example.com/search?q=a&page=2",
             "query_parameters": ["q", "page"], "forms": []},
            {"url": "https://example.com/api/users",
             "query_parameters": [], "forms": []},
        ],
        "forms": [{"action": "/search", "inputs": [{"name": "q", "type": "text"}]}],
        "nmap_output": "80/tcp open http",
    }
    assets = classify(discoveries)
    assert WEB_APP in assets["types"]
    assert API in assets["types"]
    assert HOST in assets["types"]
    assert assets["parameters"] == ["q", "page"]
    assert assets["api_endpoints"] == ["https://example.com/api/users"]


def test_checks_are_bounded_deduplicated_and_declare_gaps():
    discoveries = {
        "pages": [
            {"url": "https://example.com/?q=1", "query_parameters": ["q"], "forms": []},
            {"url": "https://example.com/api/users", "query_parameters": [], "forms": []},
        ],
        "forms": [{"action": "https://example.com/s", "inputs": [{"name": "q", "type": "text"}]}],
        "nmap_output": "22/tcp open ssh",
    }
    assets = classify(discoveries)
    plan = checks_for(assets, discoveries)

    active = [c for c in plan if c["check"] == "reflected_xss"]
    assert 1 <= len(active) <= 12
    assert any(c["check"] == "sqli_probe" for c in plan)
    assert any(c["check"] == "lfi_probe" for c in plan)
    keys = [(c.get("check"), c.get("url"), c.get("parameter")) for c in plan if c["check"] != "skipped"]
    assert len(keys) == len(set(keys))

    gaps = next(c for c in plan if c["check"] == "skipped")["reasons"]
    assert any("ssrf" in reason for reason in gaps)
    assert any("api" in reason for reason in gaps)
    assert any("POST" in reason for reason in gaps)
    assert "未覆盖" in summarize_plan(plan)


def test_empty_discoveries_produce_no_active_checks():
    plan = checks_for(classify({}), {})
    assert [c for c in plan if c["check"] == "reflected_xss"] == []
    assert plan[-1]["check"] == "skipped"


# --------------------------------------------------------------- scope
def test_scope_requires_allowlist_and_authorisation_in_production():
    from core.safety.scope import ScopeError, build_scope

    with pytest.raises(ScopeError):  # 生产没配 allowlist
        build_scope("https://example.com", env_mode="prod", allowed_targets="", authorization_ref="T-1")
    with pytest.raises(ScopeError):  # 生产没给授权凭据
        build_scope("https://example.com", env_mode="prod", allowed_targets="example.com", authorization_ref="")
    scope = build_scope("https://example.com/path", env_mode="prod",
                        allowed_targets="example.com,api.example.com", authorization_ref="T-1")
    assert scope.authorization_ref == "T-1" and scope.host == "example.com"
    assert scope.as_dict()["allowed_hosts"] == ["example.com", "api.example.com"]


def test_scope_rejects_out_of_allowlist_and_oversized_window():
    from core.safety.scope import ScopeError, build_scope

    with pytest.raises(ScopeError):
        build_scope("https://other.example", env_mode="dev", allowed_targets="example.com")
    with pytest.raises(ScopeError):
        build_scope("https://example.com", env_mode="dev", window_minutes=24 * 60 + 1)


def test_scope_window_expiry_blocks_further_tool_calls():
    from core.safety.scope import ScanScope, ScopeError, assert_in_scope

    scope = ScanScope(target="https://example.com", host="example.com",
                      expires_at="2000-01-01T00:00:00+00:00")
    with pytest.raises(ScopeError):
        assert_in_scope(scope, "https://example.com/x")


def test_tool_layer_enforces_allowlist(monkeypatch):
    from config import settings
    from tools import browser as browser_tools

    monkeypatch.setattr(settings, "AGENT_ALLOWED_TARGETS", "example.com")
    monkeypatch.setattr(settings, "AGENT_ALLOW_PRIVATE_TARGETS", False)
    assert browser_tools.validate_target_url("https://example.com/x") == "https://example.com/x"
    with pytest.raises(ValueError):
        browser_tools.validate_target_url("https://not-allowed.example/x")


# --------------------------------------------------------------- SQLi / LFI probes
def _fake_response(body: str, status: int = 200, url: str = "https://example.com/?q=x"):
    return {
        "status": status,
        "headers": {},
        "body": body,
        "elapsed_ms": 5,
        "request": {"method": "GET", "url": url, "headers": {}},
        "response_meta": {"status": status, "url": url, "headers": {}, "body_excerpt": body[:800]},
    }


def test_sqli_requires_two_agreeing_signals(monkeypatch):
    from tools import sqli

    calls = []

    async def fake_fetch(url, params=None, timeout=15.0):
        calls.append(url)
        if "AND 1=1" in url:
            return _fake_response("hello " * 100)
        if "AND 1=2" in url:
            return _fake_response("empty")
        if url.endswith("q=%27"):
            return _fake_response("You have an error in your SQL syntax near ''")
        return _fake_response("hello " * 100)

    monkeypatch.setattr(sqli, "fetch", fake_fetch)
    result = asyncio.run(sqli.sqli_probe("https://example.com/?q=x", "q"))

    assert result["vulnerable"] is True
    assert result["conclusion"] == "confirmed"
    assert result["findings"][0]["parameter"] == "q"
    conclusive = [r for r in result["results"] if r.get("conclusive")]
    assert conclusive and conclusive[0]["signal"] in {"db_error_signature", "boolean_differential"}
    assert conclusive[0]["request"]["url"].startswith("https://example.com/")
    assert len(calls) <= 12  # 有请求上限


def test_sqli_stays_quiet_without_signals(monkeypatch):
    from tools import sqli

    async def fake_fetch(url, params=None, timeout=15.0):
        return _fake_response("stable page body " * 50)

    monkeypatch.setattr(sqli, "fetch", fake_fetch)
    result = asyncio.run(sqli.sqli_probe("https://example.com/?q=x", "q"))
    assert result["vulnerable"] is False
    assert result["findings"] == []
    assert result["conclusion"] == "no_signal"


def test_lfi_only_reports_when_a_file_marker_appears(monkeypatch):
    from tools import lfi

    async def hit(url, params=None, timeout=15.0):
        lowered = url.lower()
        if "etc/passwd" in lowered or "etc%2fpasswd" in lowered:
            return _fake_response("root:x:0:0:root:/root:/bin/bash")
        return _fake_response("nice page")

    monkeypatch.setattr(lfi, "fetch", hit)
    result = asyncio.run(lfi.lfi_probe("https://example.com/?file=x", "file"))
    assert result["vulnerable"] is True
    assert result["findings"][0]["title"].startswith("Path traversal")
    assert any(r["signal"] == "file_marker" for r in result["results"])

    async def miss(url, params=None, timeout=15.0):
        return _fake_response("nice page")

    monkeypatch.setattr(lfi, "fetch", miss)
    quiet = asyncio.run(lfi.lfi_probe("https://example.com/?file=x", "file"))
    assert quiet["vulnerable"] is False


# --------------------------------------------------------------- API discovery / rule lint
def test_api_discovery_parses_published_spec(monkeypatch):
    from tools import api_discovery

    spec = '{"paths": {"/users": {"get": {"parameters": [{"name": "id"}]}}, "/login": {"post": {}}}}'

    async def fake_fetch(url, params=None, timeout=15.0):
        if url.endswith("/openapi.json"):
            return _fake_response(spec, url=url)
        return _fake_response("not found", status=404, url=url)

    monkeypatch.setattr(api_discovery, "fetch", fake_fetch)
    result = asyncio.run(api_discovery.api_discovery("https://example.com/app"))
    assert result["status"] == "success"
    assert result["endpoint_count"] == 2
    assert {e["method"] for e in result["endpoints"]} == {"GET", "POST"}
    assert result["endpoints"][0]["parameters"] == ["id"]


def test_api_discovery_reports_absence_without_guessing(monkeypatch):
    from tools import api_discovery

    async def fake_fetch(url, params=None, timeout=15.0):
        return _fake_response("nothing", status=404, url=url)

    monkeypatch.setattr(api_discovery, "fetch", fake_fetch)
    result = asyncio.run(api_discovery.api_discovery("https://example.com/app"))
    assert result["endpoint_count"] == 0
    assert "未发现" in result["note"]


def test_rule_lint_flags_missing_structure():
    from tools.rule_gen import lint_rule

    good_yara = 'rule demo { strings: $a = "x" condition: $a }'
    assert lint_rule(good_yara, "yara")["ok"] is True
    bad_yara = 'rule demo { strings: $a = "x" }'
    assert lint_rule(bad_yara, "yara")["ok"] is False

    good_suricata = 'alert http any any -> any any (msg:"t"; sid:1000001; classtype:trojan-activity;)'
    assert lint_rule(good_suricata, "suricata")["ok"] is True
    assert lint_rule('alert http any any -> any any (msg:"t";)', "suricata")["ok"] is False
    assert lint_rule("", "yara")["ok"] is False


# --------------------------------------------------------------- scan diff
def test_scan_diff_classifies_new_resolved_and_persistent():
    from core.scan_diff import diff_findings

    previous = [
        {"title": "XSS", "severity": "High", "source_tool": "browser_check_xss",
         "parameter": "q", "verification_status": "verified"},
        {"title": "Old issue", "severity": "Low", "source_tool": "code_auditor", "parameter": ""},
    ]
    current = [
        {"title": "XSS", "severity": "High", "source_tool": "browser_check_xss",
         "parameter": "q", "verification_status": "unverified"},
        {"title": "New SQLi", "severity": "High", "source_tool": "sqli_probe", "parameter": "id"},
    ]
    result = diff_findings(previous, current)
    assert result["counts"]["new"] == 1 and result["counts"]["resolved"] == 1
    assert result["counts"]["persistent"] == 1
    assert result["counts"]["verified_previous"] == 1
    assert result["counts"]["verified_current"] == 0
    assert result["new"][0]["title"] == "New SQLi"
    assert result["verdict"] == "unchanged"


def test_scan_diff_reports_improvement_and_empty_baseline():
    from core.scan_diff import diff_findings

    improved = diff_findings(
        [{"title": "A", "severity": "High"}, {"title": "B", "severity": "Medium"}],
        [{"title": "A", "severity": "High"}],
    )
    assert improved["verdict"] == "improved"
    assert improved["counts"]["resolved"] == 1

    empty = diff_findings([], [{"title": "A", "severity": "High"}])
    assert empty["counts"]["previous"] == 0 and empty["counts"]["new"] == 1
