"""End-to-end detector tests against a real local HTTP target.

These are the tests that would have caught "the detector only works in a mock": a real
socket, real responses, real rate limiting, and the evidence artifact written to disk.
"""
import asyncio

import pytest

from tests.fixtures import vuln_target


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
def private_lab(monkeypatch):
    """Allow loopback targets and disable waiting so the suite stays fast."""
    from config import settings
    import core.net.politeness as politeness

    monkeypatch.setattr(settings, "AGENT_ALLOW_PRIVATE_TARGETS", True)
    monkeypatch.setattr(settings, "AGENT_ALLOWED_TARGETS", "")
    monkeypatch.setattr(settings, "AGENT_MIN_REQUEST_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(politeness, "_limiter", None)
    yield
    politeness._limiter = None


def test_sqli_detected_against_real_target(target, private_lab):
    from tools import sqli

    result = asyncio.run(sqli.sqli_probe(f"{target}/search?q=hello", "q"))
    assert result["status"] == "success"
    assert result["vulnerable"] is True, result
    conclusive = [r for r in result["results"] if r.get("conclusive")]
    assert conclusive, result["results"]
    signals = {r["signal"] for r in conclusive}
    assert signals & {"db_error_signature", "boolean_differential"}
    # 结论必须带可复现素材
    assert conclusive[0]["request"]["url"].startswith(target)
    assert conclusive[0]["response"]["status"] in (200, 500)


def test_lfi_detected_against_real_target(target, private_lab):
    from tools import lfi

    result = asyncio.run(lfi.lfi_probe(f"{target}/download?file=readme", "file"))
    assert result["vulnerable"] is True, result
    assert any(r["signal"] == "file_marker" for r in result["results"])


def test_api_discovery_reads_real_spec(target, private_lab):
    from tools import api_discovery

    result = asyncio.run(api_discovery.api_discovery(f"{target}/"))
    assert result["endpoint_count"] == 2
    assert result["spec_url"].endswith("/openapi.json")
    assert {e["method"] for e in result["endpoints"]} == {"GET", "POST"}


def test_evidence_artifact_is_written_for_a_real_detection(target, private_lab):
    from agents.evidence_flow import attach_evidence
    from core.evidence import EvidenceRecorder
    from tools import lfi

    result = asyncio.run(lfi.lfi_probe(f"{target}/download?file=readme", "file"))

    # 用一个显式的可写目录做证据根，避免依赖 pytest 的临时目录权限
    import uuid
    from pathlib import Path
    base = Path(__file__).resolve().parents[2] / (".tmp_evidence_" + uuid.uuid4().hex[:8])
    base.mkdir(mode=0o777, exist_ok=True)
    try:
        annotated = attach_evidence(result["findings"], "lfi_probe", result, "itest",
                                    recorder=EvidenceRecorder(base_dir=str(base)))
        assert annotated and annotated[0]["verification_status"] == "verified"
        artifact = Path(annotated[0]["evidence_path"])
        assert artifact.is_file()
        assert annotated[0]["reproduction"]["poc_path"].endswith(".repro.sh")
        assert EvidenceRecorder(base_dir=str(base)).verify({
            "evidence_path": str(artifact),
            "evidence_sha256": annotated[0]["evidence_sha256"],
        }) is True
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)
