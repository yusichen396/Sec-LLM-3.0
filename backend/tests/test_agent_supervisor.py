"""Tests for the multi-agent supervisor and specialists."""
import pytest
from agents.collaboration import Blackboard
from agents.supervisor import run_multi_agent
from agents.specialists.recon import run_recon
from agents.specialists.exploit import run_exploit


class TestBlackboard:
    def test_publish_and_get(self):
        bb = Blackboard()
        bb.publish("key1", "value1", "test")
        assert bb.get("key1") == "value1"

    def test_get_all(self):
        bb = Blackboard()
        bb.publish("a", 1)
        bb.publish("b", 2)
        all_data = bb.get_all()
        assert all_data == {"a": 1, "b": 2}

    def test_get_by_source(self):
        bb = Blackboard()
        bb.publish("x", 10, "recon")
        bb.publish("y", 20, "exploit")
        assert bb.get_by_source("recon") == {"x": 10}
        assert bb.get_by_source("exploit") == {"y": 20}

    def test_shared_keys_keep_owner_and_snapshot(self):
        bb = Blackboard()
        value = ["first"]
        bb.publish("endpoints", value, "recon")
        value.append("later")
        bb.get("endpoints").append("outside")
        assert bb.get("endpoints") == ["first"]
        with pytest.raises(ValueError):
            bb.publish("endpoints", ["overwritten"], "exploit")
        bb.publish("endpoints", ["updated"], "recon")
        assert bb.get_by_source("recon") == {"endpoints": ["updated"]}
        assert bb.get_history()[0]["value"] == ["first"]

    def test_history(self):
        bb = Blackboard()
        bb.publish("k", "v", "src")
        assert len(bb.get_history()) == 1
        assert bb.get_history()[0]["source"] == "src"

    def test_list_keys(self):
        bb = Blackboard()
        bb.publish("z", 1)
        bb.publish("a", 2)
        assert bb.list_keys() == ["a", "z"]

    def test_clear(self):
        bb = Blackboard()
        bb.publish("k", "v")
        bb.clear()
        assert bb.get_all() == {}
        assert bb.get_history() == []


class TestReconSpecialist:
    def test_run_recon_no_tools(self):
        """Recon should return gracefully when tools are unavailable."""
        import asyncio
        bb = Blackboard()
        result = asyncio.run(run_recon("http://example.com", "local", bb))
        assert result["phase"] == "recon_complete"
        assert isinstance(result["findings"], list)


class TestExploitSpecialist:
    def test_tool_failures_are_reported(self, monkeypatch):
        import asyncio
        import agents.specialists.exploit as specialist

        async def fail(*args, **kwargs):
            raise RuntimeError("tool unavailable")

        monkeypatch.setattr(specialist, "invoke_tool", fail)
        result = asyncio.run(run_exploit(
            "http://example.com", "local", Blackboard(),
            {"forms": [{"action": "/", "inputs": [{"name": "q", "type": "text"}]}]},
        ))
        assert {item["tool"] for item in result["errors"]} == {"browser_check_xss", "code_auditor"}

    def test_missing_payload_cannot_be_verified(self):
        from agents.reporting import annotate_finding
        result = {"results": [{"dialog_triggered": True}]}
        assert annotate_finding({"title": "XSS"}, "browser_check_xss", result)["verification_status"] == "unverified"

    def test_only_observed_execution_is_verified(self, monkeypatch):
        import asyncio
        import agents.specialists.exploit as specialist
        import agents.evidence_flow as evidence_flow

        class Recorder:
            """Stand-in for the artifact store: verification must depend on a reference."""
            def __init__(self, *args, **kwargs):
                pass

            def record(self, **kwargs):
                if kwargs.get("payload") != "executed":
                    raise AssertionError("only executed payloads may be recorded")
                return {"evidence_id": "EV-test", "evidence_path": "mem://EV-test",
                        "evidence_sha256": "0" * 64, "poc_path": "mem://EV-test.repro.sh",
                        "kind": "reflected_xss", "tool": kwargs.get("tool"), "payload": "executed"}

        monkeypatch.setattr(evidence_flow, "EvidenceRecorder", Recorder)

        async def tool(name, **kwargs):
            if name == "browser_check_xss":
                return {
                    "url": kwargs["url"], "parameter": kwargs["param"],
                    "findings": [
                        {"title": "XSS", "evidence": "executed"},
                        {"title": "XSS", "evidence": "reflected"},
                    ],
                    "results": [
                        {"payload": "executed", "executed": True, "dialog_triggered": True,
                         "url": "http://example.com/?q=executed", "status": 200,
                         "response_excerpt": "<script>alert(1)</script>"},
                        {"payload": "reflected", "executed": False, "dialog_triggered": False},
                    ],
                }
            return {"findings": [{"title": "SQL injection hypothesis"}]}

        monkeypatch.setattr(specialist, "invoke_tool", tool)
        bb = Blackboard()
        discoveries = {"forms": [{"action": "/", "inputs": [{"name": "q", "type": "text"}]}]}
        asyncio.run(run_exploit("http://example.com", "local", bb, discoveries, session_id="s1"))
        findings = bb.get("all_findings")
        assert [f["verification_status"] for f in findings] == ["verified", "unverified", "unverified"]
        assert findings[0]["evidence_id"] == "EV-test"
        assert findings[0]["reproduction"]["observed"] == "browser_dialog_triggered"
        assert "reproduction" not in findings[1]

    def test_run_exploit_empty_blackboard(self):
        """Exploit should handle empty blackboard gracefully."""
        import asyncio
        bb = Blackboard()
        result = asyncio.run(run_exploit("http://example.com", "local", bb))
        assert result["phase"] == "exploit_complete"
        assert result["findings_count"] == 0


class TestSupervisor:
    @pytest.mark.parametrize("source", ["recon", "exploit"])
    def test_partial_report_does_not_hide_tool_errors(self, monkeypatch, source):
        import asyncio
        import agents.supervisor as supervisor

        async def recon(*args, **kwargs):
            return {"findings": [{"type": "error", "tool": "fixture", "error": "offline"}] if source == "recon" else []}

        async def exploit(*args, **kwargs):
            return {"errors": [{"tool": "fixture", "error": "offline"}] if source == "exploit" else []}

        async def complete(*args, **kwargs):
            return "partial report"

        monkeypatch.setattr(supervisor, "run_recon", recon)
        monkeypatch.setattr(supervisor, "run_exploit", exploit)
        monkeypatch.setattr(supervisor, "single_shot_completion", complete)
        result = asyncio.run(supervisor.run_multi_agent("fixture"))
        assert result["status"] == "failed"
        assert result["report"] == "partial report"

    @pytest.mark.parametrize("response", [RuntimeError("model offline"), "   "])
    def test_report_failure_is_published_to_session_progress(self, monkeypatch, response):
        import asyncio
        import agents.supervisor as supervisor

        async def recon(*args, **kwargs):
            return {"findings": []}

        async def exploit(*args, **kwargs):
            return {"errors": []}

        async def fail(*args, **kwargs):
            if isinstance(response, Exception):
                raise response
            return response

        async def collect(state):
            progress.append(state)

        monkeypatch.setattr(supervisor, "run_recon", recon)
        monkeypatch.setattr(supervisor, "run_exploit", exploit)
        monkeypatch.setattr(supervisor, "single_shot_completion", fail)
        progress = []
        result = asyncio.run(supervisor.run_multi_agent("fixture", on_progress=collect))
        assert result["status"] == "failed"
        assert result["report"] is None
        assert progress[-1]["status"] == "failed"

    def test_graph_hands_recon_output_to_exploit(self, monkeypatch):
        import asyncio
        import agents.supervisor as supervisor

        async def recon(target, provider, blackboard):
            blackboard.publish("forms", [{"action": "/search", "inputs": []}], "recon")
            return {"phase": "recon_complete"}

        async def exploit(target, provider, blackboard, discoveries, **kwargs):
            assert discoveries["forms"][0]["action"] == "/search"
            blackboard.publish("all_findings", [{"title": "sample"}], "exploit")
            return {"phase": "exploit_complete", "findings_count": 1}

        async def report(*args, **kwargs):
            return "sample report"

        monkeypatch.setattr(supervisor, "run_recon", recon)
        monkeypatch.setattr(supervisor, "run_exploit", exploit)
        monkeypatch.setattr(supervisor, "single_shot_completion", report)
        result = asyncio.run(supervisor._graph.ainvoke({
            "target": "example.com", "task_type": "web_scan", "provider": "local",
            "blackboard": Blackboard(), "recon_state": {}, "exploit_state": {},
            "report_state": {}, "logs": [],
        }))
        assert result["exploit_state"]["findings_count"] == 1
        assert result["report_state"]["report"] == "sample report"

        progress = []

        async def collect(snapshot):
            progress.append(snapshot)

        output = asyncio.run(supervisor.run_multi_agent("example.com", "web_scan", "local", collect))
        assert output["report"] == "sample report"
        assert [item["steps_completed"] for item in progress] == [0, 1, 2, 3]
        assert progress[-1]["status"] == "completed"

    def test_run_supervisor_basic(self):
        """Supervisor should complete multi-agent run without crashing."""
        import asyncio
        result = asyncio.run(run_multi_agent(
            target="http://example.com",
            task_type="comprehensive",
            provider="local",
        ))
        assert result["status"] == "completed"
        assert "target" in result
        assert "logs" in result
        assert "blackboard_keys" in result
