"""Tests for the agent orchestrator and session management."""
import asyncio
import pytest
from agents.state import AgentState
from agents.orchestrator import (
    create_session,
    get_session,
    list_sessions,
    get_agent_graph,
)


class TestAgentGraph:
    @pytest.mark.parametrize("response,step_status,existing_error", [
        (RuntimeError("model offline"), "done", None),
        ("  ", "done", None),
        ("report", "timeout", None),
        ("report", "skipped", None),
        ("report", "error", None),
        ("report", "done", "Planning failed"),
    ])
    def test_reporting_cannot_turn_failures_into_success(self, monkeypatch, response, step_status, existing_error):
        import agents.orchestrator as orch

        async def complete(*args, **kwargs):
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(orch, "single_shot_completion", complete)
        state = {"target": "fixture", "task_type": "code_audit", "provider": "local",
                 "findings": [], "plan": [{"status": step_status}], "logs": [], "error": existing_error}
        result = asyncio.run(orch.report_node(state))
        assert result["status"] == "failed"
        if isinstance(response, Exception) or not response.strip():
            assert result["report"] is None
            assert result["error"]

    def test_graph_nodes(self):
        graph = get_agent_graph()
        nodes = list(graph.nodes.keys())
        assert "__start__" in nodes
        assert "plan" in nodes
        assert "execute" in nodes
        assert "reflect" in nodes
        assert "report" in nodes

    def test_graph_is_singleton(self):
        g1 = get_agent_graph()
        g2 = get_agent_graph()
        assert g1 is g2

    def test_node_states_exchange_outputs(self, monkeypatch):
        import agents.orchestrator as orch
        prompts = []

        async def completion(*args, **kwargs):
            prompts.append(args[0][-1]["content"])
            return '[{"tool":"fake_tool","args":{},"reason":"test"}]' if kwargs.get("temperature") == 0.1 else "report"

        async def tool(*args, **kwargs):
            return {"findings": [{"title": "test", "severity": "low"}]}

        monkeypatch.setattr(orch, "single_shot_completion", completion)
        monkeypatch.setattr(orch, "get_all_tools", lambda: {
            "fake_tool": {"func": lambda: None, "description": "fixture tool"},
        })
        monkeypatch.setattr(orch, "get_tool", lambda name: {"requires_provider": False})
        monkeypatch.setattr(orch, "invoke_tool", tool)
        state = {
            "task": "test", "target": "example.com", "task_type": "web_scan", "provider": "local",
            "messages": [], "plan": [], "current_step": 0, "observations": [], "findings": [],
            "phase": "planning", "status": "running", "error": None, "report": None, "logs": [],
            "planner_state": {}, "executor_state": {}, "reflector_state": {}, "reporter_state": {},
        }
        result = asyncio.run(get_agent_graph().ainvoke(state, {"configurable": {"thread_id": "private-state-test"}}))
        assert result["planner_state"]["plan"][0]["status"] == "pending"
        assert result["executor_state"]["plan"][0]["status"] == "done"
        assert result["executor_state"]["findings"][0]["title"] == "test"
        assert result["executor_state"]["findings"][0]["verification_status"] == "unverified"
        assert result["reporter_state"]["report"] == "report"
        assert "Verified vulnerabilities (0)" in prompts[-1]
        assert "Unverified leads (1)" in prompts[-1]
        assert result["plan"] == result["executor_state"]["plan"]


class TestSessionManagement:
    @pytest.fixture(autouse=True)
    def isolate_session_storage(self, monkeypatch):
        import agents.orchestrator as orch
        monkeypatch.setattr(orch, "_load_session", lambda session_id: None)
        monkeypatch.setattr(orch, "_claim_session", lambda session_id, recovered=False: True)

    def setup_method(self):
        import agents.orchestrator as orch
        orch._sessions.clear()

    def teardown_method(self):
        import agents.orchestrator as orch
        orch._sessions.clear()

    def test_production_scan_scope_is_explicit(self, monkeypatch):
        import agents.orchestrator as orch
        monkeypatch.setattr(orch.settings, "ENV_MODE", "prod")
        monkeypatch.setattr(orch.settings, "AGENT_ALLOWED_TARGETS", "")
        with pytest.raises(ValueError, match="AGENT_ALLOWED_TARGETS"):
            orch._validate_task({"target": "https://example.com", "task_type": "web_scan"})
        monkeypatch.setattr(orch.settings, "AGENT_ALLOWED_TARGETS", "example.com")
        assert orch._validate_task({"target": "https://EXAMPLE.com/path", "task_type": "web_scan"})
        with pytest.raises(ValueError, match="outside"):
            orch._validate_task({"target": "https://other.example/path", "task_type": "web_scan"})
        with pytest.raises(ValueError, match="credentials"):
            orch._validate_task({"target": "https://user:pass@example.com", "task_type": "web_scan"})

    def test_heartbeat_stops_worker_after_remote_cancel(self, monkeypatch):
        import agents.orchestrator as orch
        queries = []

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def execute(self, sql, params):
                queries.append((sql, params))
                return 0

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def cursor(self):
                return Cursor()

        class Owner:
            cancelled = False

            def cancel(self):
                self.cancelled = True

        async def no_wait(seconds):
            assert seconds == 30

        monkeypatch.setattr(orch, "_db_connection", Connection)
        monkeypatch.setattr(orch.asyncio, "sleep", no_wait)
        owner = Owner()
        asyncio.run(orch._heartbeat_session("test1234", owner))
        assert owner.cancelled
        assert queries[0][1] == ("test1234",)

    def test_create_and_get(self, monkeypatch):
        import agents.orchestrator as orch
        monkeypatch.setattr(orch, "_persist_session", lambda session_id: None)
        async def run():
            sid = await create_session({"target": "test.com", "task_type": "web_scan"})
            s = get_session(sid)
            assert s is not None
            assert s["status"] == "running"
            assert s["task"]["target"] == "test.com"
        asyncio.run(run())

    def test_get_nonexistent(self, monkeypatch):
        import agents.orchestrator as orch
        monkeypatch.setattr(orch, "_load_session", lambda session_id: None)
        assert get_session("nonexistent") is None

    def test_list_sessions(self, monkeypatch):
        import agents.orchestrator as orch
        monkeypatch.setattr(orch, "_persist_session", lambda session_id: None)
        monkeypatch.setattr(orch, "_list_session_rows", lambda limit, user_id=None: [])
        async def run():
            await create_session({"target": "a.com"}, user_id=1)
            await create_session({"target": "b.com"}, user_id=2)
            sessions = list_sessions()
            assert len(sessions) >= 2
            from api.agent import list_sessions as list_sessions_endpoint
            response = await list_sessions_endpoint(None, {"id": 1}, None)
            assert len(response["sessions"]) == 1
            assert response["sessions"][0]["target"] == "a.com"
        asyncio.run(run())

    def test_task_type_routes_with_one_session_shape(self, monkeypatch):
        import agents.orchestrator as orch
        from api.agent import get_agent_status

        calls = []
        persisted = []

        async def specialists(target, task_type, provider, on_progress=None):
            calls.append("specialists")
            if on_progress:
                await on_progress({"phase": "recon", "status": "running", "steps_completed": 1,
                                   "steps_total": 3, "findings": [], "report": None, "logs": ["recon done"]})
            return {"phase": "complete", "status": "completed", "findings": [],
                    "report": "specialist report", "logs": ["specialists done"]}

        class GeneralGraph:
            async def astream(self, state, config, stream_mode):
                calls.append("general")
                yield {**state, "phase": "report", "status": "completed",
                       "report": "general report"}

        monkeypatch.setattr(orch, "run_multi_agent", specialists)
        monkeypatch.setattr(orch, "get_agent_graph", lambda: GeneralGraph())
        monkeypatch.setattr(orch, "_persist_session", lambda session_id: persisted.append(orch._sessions[session_id]["status"]))
        monkeypatch.setattr(orch, "_claim_session", lambda session_id, recovered=False: True)

        async def run():
            web_id = await orch.run_agent({"target": "http://example.com", "task_type": "web_scan"}, user_id=1)
            web = await get_agent_status(web_id, None, {"id": 1}, None)
            assert (web.status, web.steps_completed, web.steps_total) == ("completed", 3, 3)
            assert orch.get_session(web_id)["report"] == "specialist report"

            audit_id = await orch.run_agent({"target": "sample.py", "task_type": "code_audit"}, user_id=2)
            audit = await get_agent_status(audit_id, None, {"id": 2}, None)
            assert (audit.status, audit.steps_completed, audit.steps_total) == ("completed", 0, 0)
            assert orch.get_session(audit_id)["report"] == "general report"

        asyncio.run(run())
        assert calls == ["specialists", "general"]
        assert persisted.count("running") >= 2
        assert persisted.count("completed") >= 2

    def test_other_user_cannot_read_session(self, monkeypatch):
        from fastapi import HTTPException
        from api.agent import get_agent_status, get_agent_report
        import agents.orchestrator as orch

        monkeypatch.setattr(orch, "_persist_session", lambda session_id: None)

        async def run():
            session_id = await create_session({"target": "private.example"}, user_id=1)
            for endpoint in (get_agent_status, get_agent_report):
                with pytest.raises(HTTPException) as error:
                    await endpoint(session_id, None, {"id": 2}, None)
                assert error.value.status_code == 404

        asyncio.run(run())

    def test_start_agent_returns_before_execution_finishes(self, monkeypatch):
        import agents.orchestrator as orch

        release = asyncio.Event()

        async def execute(session_id, task):
            await release.wait()

        monkeypatch.setattr(orch, "_persist_session", lambda session_id: None)
        monkeypatch.setattr(orch, "_execute_agent", execute)

        async def run():
            session_id = await orch.start_agent({"target": "example.com"}, user_id=1)
            assert orch.get_session(session_id)["status"] == "running"
            assert orch._running_tasks
            release.set()
            await asyncio.gather(*orch._running_tasks.values())

        asyncio.run(run())

    def test_cancel_agent_updates_session(self, monkeypatch):
        import agents.orchestrator as orch

        monkeypatch.setattr(orch, "_persist_session", lambda session_id: None)

        async def execute(session_id, task):
            await asyncio.Event().wait()

        monkeypatch.setattr(orch, "_execute_agent", execute)

        async def run():
            session_id = await orch.start_agent({"target": "example.com"}, user_id=1)
            assert await orch.cancel_agent(session_id)
            assert orch.get_session(session_id)["status"] == "cancelled"

        asyncio.run(run())

    def test_mysql_snapshot_and_live_session_loading(self, monkeypatch):
        import json
        import agents.orchestrator as orch

        writes = []

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def execute(self, sql, params):
                writes.append((sql, params))
                return 1

            def fetchone(self):
                return None

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def cursor(self):
                return Cursor()

        monkeypatch.setattr(orch, "_db_connection", Connection)
        orch._sessions["test1234"] = {
            "id": "test1234", "user_id": 1,
            "task": {"target": "example.com", "task_type": "web_scan", "provider": "local"},
            "state": {"phase": "exploit", "steps_completed": 2, "steps_total": 3},
            "created_at": "2026-01-01T00:00:00+00:00", "status": "running",
            "logs": ["step complete"], "findings": [{"title": "lead"}], "report": None,
        }
        orch._persist_session("test1234")
        update = next(item for item in writes if "UPDATE agent_sessions" in item[0])
        assert "findings" in update[0]
        assert json.loads(update[1][7]) == [{"title": "lead"}]

        recovered = orch._session_from_row({
            "id": "test1234", "target": "example.com", "task_type": "web_scan", "provider": "local",
            "status": "running", "phase": "exploit", "steps_completed": 2, "steps_total": 3,
            "logs": '["step complete"]', "findings": '[{"title":"lead"}]',
            "report": None, "created_at": "2026-01-01 00:00:00",
        })
        assert recovered["status"] == "running"
        assert recovered["state"]["phase"] == "exploit"
        assert recovered["findings"] == [{"title": "lead"}]

    def test_session_creation_requires_mysql(self, monkeypatch):
        import agents.orchestrator as orch

        def fail(session_id):
            raise ConnectionError("db unavailable")

        monkeypatch.setattr(orch, "_persist_session", fail)
        with pytest.raises(ConnectionError):
            asyncio.run(create_session({"target": "example.com"}))
        assert orch._sessions == {}

    def test_active_session_is_not_evicted(self):
        import agents.orchestrator as orch
        orch._sessions["running1"] = {
            "status": "running", "created_at": "2000-01-01T00:00:00+00:00",
        }
        orch._cleanup_expired_sessions()
        assert "running1" in orch._sessions
