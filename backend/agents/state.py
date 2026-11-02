"""Agent state schema for LangGraph StateGraph."""
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph.message import add_messages


class AgentTask(TypedDict, total=False):
    """Input task specification."""
    target: str
    task_type: str  # "web_scan" | "code_audit" | "threat_intel" | "comprehensive"
    provider: str   # "local" | "cloud"
    authorization_ref: str   # 工单号/授权凭据；生产环境必填
    window_minutes: int      # 扫描时间窗（分钟），0 表示不限
    scope: Dict[str, Any]    # 由 _validate_task 构建并冻结


class AgentState(TypedDict):
    """State carried through the agent execution graph."""
    # Input
    task: str                          # Original task description
    target: str                        # Target URL, IP, file path, or repo
    task_type: str                     # web_scan / code_audit / threat_intel / comprehensive
    provider: str                      # local or cloud
    session_id: str                    # Session id, used to key evidence artifacts
    policy: Dict[str, Any]              # Snapshot pinned for this execution

    # Conversation
    messages: Annotated[List[Dict[str, str]], add_messages]

    # Planning
    plan: List[Dict[str, Any]]         # [{tool, args, reason, status}]
    current_step: int                  # Index into plan

    # Execution results
    observations: List[Dict[str, Any]] # [{tool, args, result, duration_ms}]
    findings: List[Dict[str, Any]]     # [{title, severity, description, evidence, file, line}]

    # Control flow
    phase: str                         # planning | recon | exploit | verify | report | done | error
    status: str                        # running | completed | failed
    error: Optional[str]

    # Output
    report: Optional[str]              # Final report markdown
    logs: List[str]                    # Execution log stream for SSE

    # Node-owned state; flat fields above remain as API/session compatibility projections.
    planner_state: Dict[str, Any]
    executor_state: Dict[str, Any]
    reflector_state: Dict[str, Any]
    reporter_state: Dict[str, Any]
