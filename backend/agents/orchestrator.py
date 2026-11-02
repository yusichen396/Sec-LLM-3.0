"""Agent orchestrator — LangGraph StateGraph for autonomous security testing."""
import asyncio
import json
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from langgraph.graph import END, StateGraph

from agents.state import AgentState, AgentTask
from agents.evidence_flow import attach_evidence
from agents.reporting import annotate_finding
from agents.policy import parse_plan, planning_messages, policy_for, report_messages
from core.safety.scope import ScopeError, build_scope
from dataclasses import asdict
from agents.supervisor import run_multi_agent
from config import settings
from core.llm.router import single_shot_completion
from tools.registry import get_all_tools, get_tool, invoke_tool

# Auto-import tool modules so TOOL_REGISTRY is always populated
import tools.phishing      # noqa: E402
import tools.code_audit    # noqa: E402
import tools.rule_gen      # noqa: E402
import tools.report        # noqa: E402
import tools.threat_intel  # noqa: E402
import tools.browser       # noqa: E402
import tools.shell         # noqa: E402
import tools.source_reader  # noqa: E402

# Live cache; MySQL keeps the recoverable session record.
_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = asyncio.Lock()
_running_tasks: Dict[str, asyncio.Task] = {}
_session_events: Dict[str, asyncio.Event] = {}
_agent_slots = asyncio.Semaphore(settings.AGENT_MAX_CONCURRENT)
_SESSION_TTL_SECONDS = 3600  # 1 hour auto-eviction


def _finish_background_task(session_id: str, task: asyncio.Task) -> None:
    _running_tasks.pop(session_id, None)
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception as error:
        print(f"[Agent] Background task failed: {error}")


def _cleanup_expired_sessions():
    """Remove sessions older than TTL."""
    cutoff = time.time() - _SESSION_TTL_SECONDS
    expired = []
    for sid, s in list(_sessions.items()):
        if s.get("status") == "running":
            continue
        try:
            created = datetime.fromisoformat(s["created_at"]).timestamp()
            if created < cutoff:
                expired.append(sid)
        except (ValueError, KeyError):
            expired.append(sid)
    for sid in expired:
        del _sessions[sid]
        _session_events.pop(sid, None)
    if expired:
        print(f"[Sessions] Cleaned up {len(expired)} expired sessions")


def _db_connection():
    import pymysql
    from pymysql.constants import CLIENT
    return pymysql.connect(
        host=settings.MYSQL_HOST, user=settings.MYSQL_USER, password=settings.MYSQL_PASSWORD,
        database=settings.MYSQL_DB, port=settings.MYSQL_PORT, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor, autocommit=True, client_flag=CLIENT.FOUND_ROWS,
    )


def _persist_session(session_id: str) -> None:
    """Durably upsert a live session; callers must handle DB failure."""
    s = _sessions[session_id]
    state = s.get("state") or {}
    progress = state.get("steps_completed", state.get("current_step", 0))
    total = state.get("steps_total", len(state.get("plan", [])))
    logs = json.dumps(s.get("logs", []), ensure_ascii=False)
    findings = json.dumps(s.get("findings", []), ensure_ascii=False)
    created = datetime.fromisoformat(s["created_at"]).replace(tzinfo=None)
    with _db_connection() as conn:
        with conn.cursor() as cursor:
            if s["state"] is None:
                cursor.execute(
                    """INSERT INTO agent_sessions (id, user_id, target, task_type, provider, status, phase,
                   findings_count, steps_completed, steps_total, report, logs, findings, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (session_id, s.get("user_id"), s["task"].get("target", ""), s["task"].get("task_type", "web_scan"),
                     s["task"].get("provider", "local"), s["status"], state.get("phase", ""),
                     len(s.get("findings", [])), progress, total, s.get("report"), logs, findings, created),
                )
            else:
                updated = cursor.execute(
                    """UPDATE agent_sessions SET status=%s, phase=%s, findings_count=%s,
                       steps_completed=%s, steps_total=%s, report=%s, logs=%s, findings=%s
                       WHERE id=%s AND status='running'""",
                    (s["status"], state.get("phase", ""), len(s.get("findings", [])), progress,
                     total, s.get("report"), logs, findings, session_id),
                )
                if not updated and s["status"] == "running":
                    raise asyncio.CancelledError


def _audit_scan(session_id: str, final: bool = False) -> None:
    """Record who scanned what, under which authorisation. Never breaks the task."""
    session = _sessions.get(session_id)
    if not session:
        return
    task = session.get("task") or {}
    scope = task.get("scope") or {}
    try:
        with _db_connection() as conn:
            with conn.cursor() as cursor:
                if not final:
                    cursor.execute(
                        """INSERT INTO scan_audit
                           (session_id, user_id, target, task_type, authorization_ref, scope_json, status)
                           VALUES (%s,%s,%s,%s,%s,%s,%s)
                           ON DUPLICATE KEY UPDATE status=VALUES(status)""",
                        (session_id, session.get("user_id"), task.get("target", ""),
                         task.get("task_type", "web_scan"), scope.get("authorization_ref") or None,
                         json.dumps(scope, ensure_ascii=False), session.get("status", "running")),
                    )
                else:
                    cursor.execute(
                        """UPDATE scan_audit
                           SET status=%s, findings_count=%s, finished_at=NOW()
                           WHERE session_id=%s""",
                        (session.get("status", "unknown"), len(session.get("findings") or []), session_id),
                    )
    except Exception as error:  # 审计失败不影响扫描本身，但必须留痕
        print(f"[AUDIT] failed for {session_id}: {error}")


def _session_from_row(row: dict) -> Dict[str, Any]:
    """Reconstruct API-facing state without replaying any tool call."""
    logs = row.get("logs") or []
    findings = row.get("findings") or []
    if isinstance(logs, str):
        logs = json.loads(logs)
    if isinstance(findings, str):
        findings = json.loads(findings)
    status = row["status"]
    phase = row.get("phase") or "unknown"
    created = row["created_at"]
    return {
        "id": row["id"], "user_id": row.get("user_id"),
        "task": {"target": row["target"], "task_type": row["task_type"], "provider": row["provider"]},
        "state": {"phase": phase, "steps_completed": row.get("steps_completed") or 0,
                  "steps_total": row.get("steps_total") or 0},
        "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
        "status": status, "logs": logs, "findings": findings, "report": row.get("report"),
    }


def _load_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM agent_sessions WHERE id=%s", (session_id,))
            row = cursor.fetchone()
    return _session_from_row(row) if row else None


def _list_session_rows(limit: int, user_id: int | None = None) -> List[Dict[str, Any]]:
    with _db_connection() as conn:
        with conn.cursor() as cursor:
            if user_id is None:
                cursor.execute("SELECT * FROM agent_sessions ORDER BY created_at DESC LIMIT %s", (limit,))
            else:
                cursor.execute("SELECT * FROM agent_sessions WHERE user_id=%s ORDER BY created_at DESC LIMIT %s",
                               (user_id, limit))
            rows = cursor.fetchall()
    return [_session_from_row(row) for row in rows]


async def create_session(task: AgentTask, user_id: int | None = None) -> str:
    session_id = str(uuid.uuid4())[:8]
    async with _sessions_lock:
        _cleanup_expired_sessions()
        _sessions[session_id] = {
            "id": session_id,
            "user_id": user_id,
            "task": task,
            "state": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "logs": [],
            "findings": [],
            "_synced_at": time.monotonic(),
        }
        _session_events[session_id] = asyncio.Event()
    try:
        await asyncio.to_thread(_persist_session, session_id)
    except Exception:
        async with _sessions_lock:
            _sessions.pop(session_id, None)
        raise
    await asyncio.to_thread(_audit_scan, session_id, False)
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Serve the live in-memory snapshot when it is fresh, else fall back to MySQL.

    The previous order (DB first) opened a new MySQL connection on every SSE tick,
    which was one connect+auth per second per watcher.
    """
    live = _sessions.get(session_id)
    if live is not None and time.monotonic() - live.get("_synced_at", 0.0) < 5.0:
        return live
    return _load_session(session_id) or live


def list_sessions(limit: int = 20, user_id: int | None = None) -> List[Dict[str, Any]]:
    """Public API for listing recent sessions."""
    items = {session["id"]: session for session in _list_session_rows(limit, user_id)}
    for sid, s in _sessions.items():
        if user_id is None or s.get("user_id") == user_id:
            items.setdefault(sid, s)
    items = list(items.values())
    items.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return items[:limit]


async def _store_progress(session_id: str, state: Dict[str, Any]) -> None:
    async with _sessions_lock:
        session = _sessions[session_id]
        session["state"] = state
        session["status"] = state.get("status", "running")
        session["findings"] = state.get("findings", [])
        session["logs"] = state.get("logs", [])
        session["report"] = state.get("report")
        session["_synced_at"] = time.monotonic()
    await asyncio.to_thread(_persist_session, session_id)
    _session_events.setdefault(session_id, asyncio.Event()).set()


def get_session_event(session_id: str) -> asyncio.Event | None:
    return _session_events.get(session_id)


# ---- Graph Nodes ----

async def planner_node(state: AgentState) -> AgentState:
    """Analyze task and target, generate ordered tool execution plan."""
    state["phase"] = "planning"
    policy = policy_for(state)
    state["policy"] = asdict(policy)
    tools = get_all_tools()
    messages = planning_messages(state, tools, policy, settings.AGENT_MAX_STEPS)

    try:
        raw = await single_shot_completion(
            messages, provider=state.get("provider", "local"), temperature=0.1, json_mode=False
        )
        state["plan"] = parse_plan(raw, tools, settings.AGENT_MAX_STEPS)
        state["current_step"] = 0
        state["logs"].append(f"[POLICY] {policy.version}")
        state["logs"].append(f"[PLAN] Generated {len(state['plan'])}-step plan")
    except Exception as e:
        state["error"] = f"Planning failed: {e}"
        state["status"] = "failed"

    return state


async def execute_node(state: AgentState) -> AgentState:
    """Execute the current plan step's tool."""
    if state["current_step"] >= len(state["plan"]):
        state["phase"] = "done"
        return state

    step = state["plan"][state["current_step"]]
    tool_name = step["tool"]
    tool_args = dict(step.get("args", {}))

    tool_info = get_tool(tool_name)
    if tool_info is None:
        state["logs"].append(f"[ERROR] Unknown tool: {tool_name}")
        step["status"] = "skipped"
        state["current_step"] += 1
        return state

    state["logs"].append(f"[EXEC] {tool_name}({json.dumps(tool_args, ensure_ascii=False)})")
    step["status"] = "running"

    try:
        if tool_info.get("requires_provider"):
            tool_args["provider"] = state.get("provider", "local")

        loop = asyncio.get_event_loop()
        start = loop.time()
        result = await asyncio.wait_for(
            invoke_tool(tool_name, **tool_args),
            timeout=settings.AGENT_STEP_TIMEOUT_SECONDS,
        )
        elapsed = int((loop.time() - start) * 1000)

        state["observations"].append({
            "tool": tool_name, "args": tool_args,
            "result": result, "duration_ms": elapsed,
        })
        if isinstance(result, dict) and (
            result.get("status") in ("error", "failed") or result.get("error")
            or ("exit_code" in result and result["exit_code"] != 0)
        ):
            raise RuntimeError(f"Tool returned failure: {str(result)[:1000]}")
        step["status"] = "done"
        state["logs"].append(f"[DONE] {tool_name} completed in {elapsed}ms")

        if isinstance(result, dict):
            if "findings" in result and isinstance(result["findings"], list):
                for annotated in attach_evidence(
                    result["findings"], tool_name, result, state.get("session_id", "")
                ):
                    state["findings"].append(annotated)
                    state["logs"].append(
                        f"[FINDING] {annotated.get('severity', '?')}: {annotated.get('title', 'Untitled')}"
                        f" ({annotated.get('verification_status')})"
                    )

    except asyncio.TimeoutError:
        step["status"] = "timeout"
        state["logs"].append(f"[TIMEOUT] {tool_name} exceeded {settings.AGENT_STEP_TIMEOUT_SECONDS}s")
    except Exception as e:
        step["status"] = "error"
        state["logs"].append(f"[ERROR] {tool_name} failed: {e}")

    state["current_step"] += 1
    return state


async def reflect_node(state: AgentState) -> AgentState:
    """Evaluate progress and decide next action."""
    state["phase"] = "reflect"
    if state.get("error"):
        state["status"] = "failed"
        return state
    if state["current_step"] >= len(state["plan"]):
        state["logs"].append("[REFLECT] All planned steps executed")
    return state


async def report_node(state: AgentState) -> AgentState:
    """Generate final security assessment report."""
    state["phase"] = "report"

    findings = state.get("findings", [])
    policy = policy_for(state)
    limitations = {"error": state.get("error"), "steps": state["plan"],
                   "tool_errors": [line for line in state["logs"] if "[ERROR]" in line or "[TIMEOUT]" in line]}

    try:
        from core.safety.prompt_injection import validate_model_output, wrap_untrusted_data
        _, evidence_scan = wrap_untrusted_data(
            "agent_report_input",
            {"target": state["target"], "task_type": state["task_type"],
             "findings": findings, "limitations": limitations},
        )
        report = await single_shot_completion(
            report_messages(state["target"], state["task_type"], findings, limitations, policy),
            provider=state.get("provider", "local"), temperature=0.3
        )
        verdict = validate_model_output(report, evidence_scan.requested_outputs)
        if not verdict.allowed:
            raise ValueError(f"Report output guard rejected response: {', '.join(verdict.reasons)}")
        if policy.reporting != "baseline":
            from agents.evaluation import score_report
            if not score_report(report, findings)["success"]:
                raise ValueError("Report failed the evidence citation contract")
        state["report"] = report
        failed_steps = any(step.get("status") != "done" for step in state["plan"])
        state["status"] = "failed" if state.get("error") or failed_steps else "completed"
        state["logs"].append(f"[REPORT] Generated report ({len(report)} chars)")
    except Exception as e:
        state["report"] = None
        state["error"] = f"Report generation failed: {e}"
        state["status"] = "failed"
        state["logs"].append(f"[ERROR] Report generation: {e}")

    return state


# ---- Routing ----

def route_after_plan(state: AgentState) -> str:
    return "report" if state["planner_state"]["error"] else "execute"


def route_after_execute(state: AgentState) -> str:
    if state.get("error"):
        return "report"
    execution = state["executor_state"]
    if execution["current_step"] < len(execution["plan"]):
        return "execute"
    return "reflect"


def route_after_reflect(state: AgentState) -> str:
    execution = state["executor_state"]
    return "execute" if execution["current_step"] < len(execution["plan"]) else "report"


async def planner_agent(state: AgentState) -> dict:
    """Run the planner on a private copy and publish its output to the graph."""
    result = await planner_node(deepcopy(state))
    own = {key: deepcopy(result[key]) for key in ("plan", "error", "status")}
    return {
        "planner_state": own,
        "policy": result["policy"],
        "plan": result["plan"], "error": result["error"],
        "status": result["status"], "phase": result["phase"], "logs": result["logs"],
    }


async def executor_agent(state: AgentState) -> dict:
    """Own execution state; consume the planner's published plan."""
    local = deepcopy(state)
    own = state["executor_state"]
    local["plan"] = deepcopy(own.get("plan", state["planner_state"]["plan"]))
    for key in ("current_step", "observations", "findings"):
        if key in own:
            local[key] = deepcopy(own[key])
    result = await execute_node(local)
    own = {key: deepcopy(result[key]) for key in ("plan", "current_step", "observations", "findings")}
    return {
        "executor_state": own,
        "plan": result["plan"], "current_step": result["current_step"],
        "observations": result["observations"], "findings": result["findings"],
        "phase": result["phase"], "logs": result["logs"],
    }


async def reflector_agent(state: AgentState) -> dict:
    local = deepcopy(state)
    local.update({key: deepcopy(state["executor_state"][key]) for key in ("plan", "current_step")})
    result = await reflect_node(local)
    own = {key: deepcopy(result[key]) for key in ("phase", "status", "error")}
    return {
        "reflector_state": own, "phase": result["phase"], "status": result["status"],
        "logs": result["logs"],
    }


async def reporter_agent(state: AgentState) -> dict:
    local = deepcopy(state)
    local["plan"] = deepcopy(state["executor_state"].get("plan", state["planner_state"].get("plan", [])))
    local["findings"] = deepcopy(state["executor_state"].get("findings", []))
    result = await report_node(local)
    own = {key: deepcopy(result[key]) for key in ("report", "status", "phase", "error")}
    return {
        "reporter_state": own, "report": result["report"], "status": result["status"],
        "phase": result["phase"], "logs": result["logs"], "error": result["error"],
    }


# ---- Build Graph (module-level singleton) ----

_agent_graph = None

def get_agent_graph():
    global _agent_graph
    if _agent_graph is None:
        workflow = StateGraph(AgentState)
        workflow.add_node("plan", planner_agent)
        workflow.add_node("execute", executor_agent)
        workflow.add_node("reflect", reflector_agent)
        workflow.add_node("report", reporter_agent)
        workflow.set_entry_point("plan")
        workflow.add_conditional_edges("plan", route_after_plan, {"execute": "execute", "report": "report"})
        workflow.add_conditional_edges("execute", route_after_execute, {"execute": "execute", "reflect": "reflect", "report": "report"})
        workflow.add_conditional_edges("reflect", route_after_reflect, {"execute": "execute", "report": "report"})
        workflow.add_edge("report", END)
        _agent_graph = workflow.compile()
    return _agent_graph


# ---- Run Agent ----

def _validate_task(task: AgentTask) -> str:
    target = task.get("target", "")
    if not target:
        raise ValueError("Task must include a 'target' field")
    task_type = task.get("task_type", "web_scan")
    if task_type in {"web_scan", "comprehensive"}:
        try:
            parsed = urlsplit(target if "://" in target else f"//{target}")
            hostname = (parsed.hostname or "").lower().rstrip(".")
        except ValueError as error:
            raise ValueError("Invalid scan target") from error
        if not hostname or parsed.username or parsed.password:
            raise ValueError("Scan target must be a hostname, IP, or URL without credentials")
        try:
            scope = build_scope(
                target,
                env_mode=settings.ENV_MODE,
                allowed_targets=settings.AGENT_ALLOWED_TARGETS,
                authorization_ref=task.get("authorization_ref", ""),
                window_minutes=task.get("window_minutes", 0),
            )
        except ScopeError as error:
            raise ValueError(str(error)) from error
        task["scope"] = scope.as_dict()
    elif task_type == "code_audit" and (settings.AGENT_CODE_AUDIT_ROOT or "").strip():
        # 配置了审计根目录时，先在这里把越界路径挡掉
        from pathlib import Path

        root = Path(settings.AGENT_CODE_AUDIT_ROOT).expanduser().resolve()
        candidate = Path(target).expanduser()
        resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError("code_audit target is outside AGENT_CODE_AUDIT_ROOT") from error
    return target


async def _execute_agent(session_id: str, task: AgentTask) -> None:
    target = task["target"]
    task_type = task.get("task_type", "web_scan")
    if task_type == "code_audit":
        # 明确要求先读源码再审计；read_source 只在 AGENT_CODE_AUDIT_ROOT 内可用
        task_text = (
            f"Audit the source code under '{target}'. "
            "Step 1: call read_source(path=...). "
            "Step 2: pass the returned code to code_auditor. "
            "Never invent code that read_source did not return."
        )
    else:
        task_text = task.get("task", f"Security assessment of {target}")
    initial_state: AgentState = {
        "task": task_text,
        "target": target,
        "task_type": task_type,
        "provider": task.get("provider", settings.LLM_PROVIDER),
        "session_id": session_id,
        "messages": [],
        "plan": [],
        "current_step": 0,
        "observations": [],
        "findings": [],
        "phase": "planning",
        "status": "running",
        "error": None,
        "report": None,
        "logs": [f"[START] Agent task: {target} (type={task.get('task_type', 'web_scan')})"],
        "planner_state": {},
        "executor_state": {},
        "reflector_state": {},
        "reporter_state": {},
    }

    try:
        if task.get("task_type", "web_scan") == "web_scan":
            result = await run_multi_agent(
                target, "web_scan", initial_state["provider"],
                on_progress=lambda state: _store_progress(session_id, {
                    **state, "logs": initial_state["logs"] + state["logs"],
                }),
                session_id=session_id,
            )
            final_state = {
                "phase": result["phase"], "status": result["status"],
                "steps_completed": 3, "steps_total": 3,
                "findings": result["findings"], "report": result["report"],
                "logs": initial_state["logs"] + result["logs"],
            }
        else:
            final_state = None
            async for snapshot in get_agent_graph().astream(
                initial_state,
                {"configurable": {"thread_id": session_id}},
                stream_mode="values",
            ):
                final_state = snapshot
                await _store_progress(session_id, snapshot)
        await _store_progress(session_id, final_state)
    except Exception as e:
        previous = _sessions[session_id].get("state") or {}
        await _store_progress(session_id, {
            **previous, "phase": "error", "status": "failed",
            "logs": _sessions[session_id]["logs"] + [f"[FATAL] {e}"],
        })



def _claim_session(session_id: str, recovered: bool = False) -> bool:
    """Atomically claim a queued session before invoking any tool."""
    with _db_connection() as conn:
        with conn.cursor() as cursor:
            return bool(cursor.execute(
                """UPDATE agent_sessions SET phase='claimed'
                   WHERE id=%s AND status='running' AND (phase IS NULL OR phase='')
                   AND (%s=0 OR TIMESTAMPDIFF(SECOND, updated_at, NOW()) > %s)""",
                (session_id, int(bool(recovered)), settings.AGENT_TASK_TIMEOUT_SECONDS + 30),
            ))


async def _heartbeat_session(session_id: str, owner: asyncio.Task) -> None:
    """Keep the database lease fresh even while a tool or LLM call is running."""
    while True:
        await asyncio.sleep(30)
        def touch() -> bool:
            with _db_connection() as conn:
                with conn.cursor() as cursor:
                    return bool(cursor.execute(
                        "UPDATE agent_sessions SET updated_at=NOW() WHERE id=%s AND status='running'",
                        (session_id,),
                    ))
        try:
            active = await asyncio.to_thread(touch)
        except Exception as error:
            print(f"[Agent] Heartbeat failed for {session_id}: {error}")
            owner.cancel()
            return
        if not active:
            owner.cancel()
            return


async def _run_limited(session_id: str, task: AgentTask, recovered: bool = False) -> None:
    heartbeat = None
    try:
        async with _agent_slots:
            if not await asyncio.to_thread(_claim_session, session_id, recovered):
                _sessions.pop(session_id, None)
                _session_events.pop(session_id, None)
                return
            heartbeat = asyncio.create_task(_heartbeat_session(session_id, asyncio.current_task()))
            current = _sessions[session_id]
            await _store_progress(session_id, {
                **(current.get("state") or {}), "phase": "starting", "status": "running",
                "logs": current["logs"], "findings": current["findings"],
                "report": current.get("report"),
            })
            await asyncio.wait_for(_execute_agent(session_id, task), settings.AGENT_TASK_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        previous = _sessions[session_id].get("state") or {}
        await _store_progress(session_id, {
            **previous, "phase": "timeout", "status": "failed",
            "logs": _sessions[session_id]["logs"] +
                    [f"[TIMEOUT] Task exceeded {settings.AGENT_TASK_TIMEOUT_SECONDS}s"],
        })
    except asyncio.CancelledError:
        previous = _sessions[session_id].get("state") or {}
        await _store_progress(session_id, {
            **previous, "phase": "cancelled", "status": "cancelled",
            "logs": _sessions[session_id]["logs"] + ["[CANCELLED] Task cancelled by user"],
        })
        raise
    finally:
        if heartbeat is not None:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
        await asyncio.to_thread(_audit_scan, session_id, True)


async def run_agent(task: AgentTask, user_id: int | None = None) -> str:
    """Run an agent to completion and return its session id."""
    _validate_task(task)
    session_id = await create_session(task, user_id)
    await _run_limited(session_id, task)
    return session_id


async def start_agent(task: AgentTask, user_id: int | None = None) -> str:
    """Persist and start an agent without blocking the request."""
    _validate_task(task)
    session_id = await create_session(task, user_id)
    background = asyncio.create_task(_run_limited(session_id, task))
    _running_tasks[session_id] = background
    background.add_done_callback(lambda completed: _finish_background_task(session_id, completed))
    return session_id


async def cancel_agent(session_id: str) -> bool:
    """Cancel locally, or leave a cooperative cancellation marker for its worker."""
    task = _running_tasks.get(session_id)
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        if _sessions[session_id]["status"] == "running":
            await _store_progress(session_id, {
                **(_sessions[session_id].get("state") or {}),
                "phase": "cancelled", "status": "cancelled",
                "logs": _sessions[session_id]["logs"] + ["[CANCELLED] Task cancelled by user"],
            })
        return True

    def mark_cancelled() -> bool:
        with _db_connection() as conn:
            with conn.cursor() as cursor:
                return bool(cursor.execute(
                    "UPDATE agent_sessions SET status='cancelled', phase='cancelled' "
                    "WHERE id=%s AND status='running'", (session_id,),
                ))

    return await asyncio.to_thread(mark_cancelled)


async def recover_agent_sessions() -> int:
    """Resume never-started sessions and fail interrupted executions without replaying tools."""
    def reconcile() -> tuple[list[dict], int]:
        with _db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM agent_sessions WHERE status='running' "
                    "AND TIMESTAMPDIFF(SECOND, updated_at, NOW()) > %s",
                    (settings.AGENT_TASK_TIMEOUT_SECONDS + 30,),
                )
                rows = cursor.fetchall()
                pending = [row for row in rows if not row.get("phase")]
                interrupted = [row["id"] for row in rows if row.get("phase")]
                failed_count = 0
                if interrupted:
                    failed_count = cursor.execute(
                        "UPDATE agent_sessions SET status='failed', phase='interrupted' "
                        "WHERE id IN %s AND status='running' "
                        "AND phase IS NOT NULL AND phase<>'' "
                        "AND TIMESTAMPDIFF(SECOND, updated_at, NOW()) > %s",
                        (tuple(interrupted), settings.AGENT_TASK_TIMEOUT_SECONDS + 30),
                    )
                return pending, failed_count

    pending, interrupted_count = await asyncio.to_thread(reconcile)
    for row in pending:
        if row["id"] in _running_tasks:
            continue
        session = _session_from_row(row)
        async with _sessions_lock:
            _sessions[session["id"]] = session
            _session_events[session["id"]] = asyncio.Event()
        task = asyncio.create_task(_run_limited(session["id"], session["task"], recovered=True))
        _running_tasks[session["id"]] = task
        task.add_done_callback(lambda completed, sid=session["id"]: _finish_background_task(sid, completed))
    if interrupted_count:
        print(f"[Agent] Marked {interrupted_count} interrupted sessions as failed")
    return len(pending)
