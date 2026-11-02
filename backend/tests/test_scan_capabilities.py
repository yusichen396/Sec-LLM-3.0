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
    keys = [(c.get("url"), c.get("parameter")) for c in active]
    assert len(keys) == len(set(keys))

    gaps = next(c for c in plan if c["check"] == "skipped")["reasons"]
    assert any("sql_injection" in reason for reason in gaps)
    assert any("api" in reason for reason in gaps)
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
