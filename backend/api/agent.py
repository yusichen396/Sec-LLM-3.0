"""Agent task API endpoints."""
import asyncio
import json
import time
from typing import Any, Dict, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agents.orchestrator import cancel_agent, get_session, get_session_event, list_sessions as list_agent_sessions, start_agent
from core.auth.dependencies import get_current_user_or_skill, get_db

router = APIRouter(prefix="/api/agent", tags=["agent"])


async def _owned_session(session_id: str, user_id: int) -> Dict[str, Any]:
    session = await asyncio.to_thread(get_session, session_id)
    if session is None or session.get("user_id") != user_id:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


# ---- Request/Response Models ----

class AgentTaskRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, file path, or repository")
    task_type: Literal["web_scan", "code_audit", "threat_intel", "comprehensive"] = Field(
        default="web_scan",
        description="web_scan | code_audit | threat_intel | comprehensive",
    )
    provider: Literal["local", "cloud"] = Field(default="local", description="LLM provider: local or cloud")
    authorization_ref: str = Field(
        default="",
        max_length=200,
        description="工单号 / 授权凭据；生产环境的 web_scan 必填，会记入扫描审计",
    )
    window_minutes: int = Field(
        default=0,
        ge=0,
        le=1440,
        description="本次扫描的时间窗（分钟），0 表示不限",
    )


class AgentTaskResponse(BaseModel):
    session_id: str
    status: str
    message: str


class AgentStatusResponse(BaseModel):
    session_id: str
    status: str
    phase: str
    findings_count: int
    steps_completed: int
    steps_total: int
    logs: list
    report: str | None = None


# ---- Routes ----

@router.post("/run", response_model=AgentTaskResponse)
async def run_agent_task(
    req: AgentTaskRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Submit a new agent task for execution."""
    task_dict: Dict[str, Any] = {
        "target": req.target,
        "task_type": req.task_type,
        "provider": req.provider,
        "authorization_ref": req.authorization_ref,
        "window_minutes": req.window_minutes,
    }
    try:
        session_id = await start_agent(task_dict, user_id=current_user["id"])
        return AgentTaskResponse(
            session_id=session_id,
            status="running",
            message=f"Agent task started. Track with /api/agent/{session_id}/status",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """List recent agent sessions."""
    sessions = await asyncio.to_thread(list_agent_sessions, limit=20, user_id=current_user["id"])
    return {
        "sessions": [
            {
                "id": s["id"],
                "status": s["status"],
                "task_type": s["task"].get("task_type", "?"),
                "target": s["task"].get("target", "?")[:80],
                "created_at": s["created_at"],
                "findings_count": len(s.get("findings", [])),
            }
            for s in sessions
        ]
    }


# Logs grow for the whole task; returning all of them on every poll is O(n^2) traffic.
_MAX_STATUS_LOGS = 500


@router.get("/{session_id}/status")
async def get_agent_status(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Get current agent session status."""
    session = await _owned_session(session_id, current_user["id"])

    state = session.get("state") or {}
    logs = session.get("logs", [])
    return AgentStatusResponse(
        session_id=session_id,
        status=session["status"],
        phase=state.get("phase", "unknown"),
        findings_count=len(session.get("findings", [])),
        steps_completed=state.get("steps_completed", state.get("current_step", 0)),
        steps_total=state.get("steps_total", len(state.get("plan", []))),
        logs=logs[-_MAX_STATUS_LOGS:],
        report=session.get("report"),
    )


@router.get("/{session_id}/stream")
async def stream_agent_logs(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """SSE stream of agent execution progress."""
    session = await _owned_session(session_id, current_user["id"])

    async def generate():
        sent_count = 0
        changed = get_session_event(session_id)
        last_keepalive = time.monotonic()
        while True:
            if await request.is_disconnected():
                break
            s = await _owned_session(session_id, current_user["id"])
            logs = s.get("logs", [])
            while sent_count < len(logs):
                yield f"data: {json.dumps({'type': 'log', 'message': logs[sent_count]}, ensure_ascii=False)}\n\n"
                sent_count += 1
                await asyncio.sleep(0.05)

            if s["status"] in ("completed", "failed", "cancelled"):
                yield f"data: {json.dumps({'type': 'done', 'status': s['status'], 'findings_count': len(s.get('findings', []))}, ensure_ascii=False)}\n\n"
                break

            if changed:
                changed.clear()
                try:
                    await asyncio.wait_for(changed.wait(), timeout=1)
                except asyncio.TimeoutError:
                    pass
            else:
                await asyncio.sleep(1)
            if time.monotonic() - last_keepalive >= 15:
                yield ": keepalive\n\n"
                last_keepalive = time.monotonic()

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.get("/{session_id}/report")
async def get_agent_report(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Get the final report for a completed agent session."""
    session = await _owned_session(session_id, current_user["id"])
    if session["status"] not in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail="Task still running")

    return {
        "session_id": session_id,
        "status": session["status"],
        "findings": session.get("findings", []),
        "report": session.get("report"),
    }


@router.get("/{session_id}/diff")
async def get_agent_diff(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Compare the findings of this scan with the previous scan of the same target."""
    from core.scan_diff import diff_findings

    session = await _owned_session(session_id, current_user["id"])
    if session["status"] == "running":
        raise HTTPException(status_code=400, detail="Task still running")

    def previous_for(target: str):
        with db.cursor() as cursor:
            cursor.execute(
                """SELECT id, findings, status FROM agent_sessions
                   WHERE user_id=%s AND target=%s AND id<>%s
                     AND status IN ('completed','failed','cancelled')
                   ORDER BY created_at DESC LIMIT 1""",
                (current_user["id"], target, session_id),
            )
            return cursor.fetchone()

    previous_row = await asyncio.to_thread(previous_for, session.get("task", {}).get("target", ""))
    if not previous_row:
        return {
            "session_id": session_id,
            "baseline_session_id": None,
            "counts": {"previous": 0, "current": len(session.get("findings", [])),
                       "new": len(session.get("findings", [])), "resolved": 0,
                       "persistent": 0, "verified_previous": 0,
                       "verified_current": sum(1 for f in session.get("findings", [])
                                               if f.get("verification_status") == "verified")},
            "new": session.get("findings", []),
            "resolved": [],
            "persistent": [],
            "verdict": "baseline",
            "note": "该目标没有可比较的历史扫描",
        }

    previous_findings = previous_row.get("findings") or []
    if isinstance(previous_findings, str):
        try:
            previous_findings = json.loads(previous_findings)
        except ValueError:
            previous_findings = []

    result = diff_findings(previous_findings, session.get("findings", []))
    return {"session_id": session_id, "baseline_session_id": previous_row["id"], **result}


@router.delete("/{session_id}")
async def cancel_agent_task(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Cancel an Agent task running in this worker."""
    session = await _owned_session(session_id, current_user["id"])
    if session["status"] != "running":
        raise HTTPException(status_code=409, detail="Task is not running")
    if not await cancel_agent(session_id):
        raise HTTPException(status_code=409, detail="Task is no longer running")
    return {"session_id": session_id, "status": "cancelled"}
