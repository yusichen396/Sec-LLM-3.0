"""Multi-Agent Supervisor — orchestrates ReconAgent + ExploitAgent + ReportAgent."""
from typing import Any, Awaitable, Callable, Dict, TypedDict

from langgraph.graph import END, StateGraph

from agents.collaboration import Blackboard
from agents.specialists.recon import run_recon
from agents.specialists.exploit import run_exploit
from core.llm.router import single_shot_completion
from dataclasses import asdict
from agents.policy import load_policy, policy_for, report_messages
from core.safety.prompt_injection import validate_model_output, wrap_untrusted_data


class SupervisorState(TypedDict):
    target: str
    task_type: str
    provider: str
    policy: Dict[str, Any]
    blackboard: Blackboard
    recon_state: Dict[str, Any]
    exploit_state: Dict[str, Any]
    report_state: Dict[str, Any]
    logs: list[str]


async def _recon_node(state: SupervisorState) -> dict:
    result = await run_recon(state["target"], state["provider"], state["blackboard"])
    result = {**result, "discoveries": state["blackboard"].get_by_source("recon")}
    errors = [f"[RECON] {item['tool']} failed: {item['error']}" for item in result.get("findings", []) if item.get("type") == "error"]
    return {
        "recon_state": result,
        "logs": state["logs"] + ["[SUPERVISOR] Starting Reconnaissance phase...",
                                 f"[SUPERVISOR] Recon complete — {len(state['blackboard'].list_keys())} discoveries on blackboard"] + errors,
    }


async def _exploit_node(state: SupervisorState) -> dict:
    result = await run_exploit(state["target"], state["provider"], state["blackboard"],
                               discoveries=state["recon_state"]["discoveries"])
    count = len(state["blackboard"].get("all_findings", []))
    errors = [f"[EXPLOIT] {item['tool']} failed: {item['error']}" for item in result.get("errors", [])]
    return {
        "exploit_state": result,
        "logs": state["logs"] + ["[SUPERVISOR] Starting Exploitation phase...",
                                 f"[SUPERVISOR] Detection complete — {count} findings awaiting classification"] + errors,
    }


async def _report_node(state: SupervisorState) -> dict:
    blackboard = state["blackboard"]
    all_findings = blackboard.get("all_findings", [])
    verified = [f for f in all_findings if f.get("verification_status") == "verified"]
    unverified = [f for f in all_findings if f.get("verification_status") != "verified"]
    logs = state["logs"] + ["[SUPERVISOR] Generating final report..."]
    report = None
    try:
        report_input = {
            "target": state["target"],
            "task_type": state["task_type"],
            "findings": all_findings,
            "limitations": {
                "recon": state["recon_state"].get("findings", []),
                "tool_errors": state["exploit_state"].get("errors", []),
            },
        }
        _, evidence_scan = wrap_untrusted_data("agent_report_input", report_input)
        messages = report_messages(state["target"], state["task_type"], all_findings,
                                   report_input["limitations"], policy_for(state))
        report = await single_shot_completion(messages, provider=state["provider"], temperature=0.3)
        verdict = validate_model_output(report, evidence_scan.requested_outputs)
        if not verdict.allowed:
            raise ValueError(f"Report output guard rejected response: {', '.join(verdict.reasons)}")
        if policy_for(state).reporting != "baseline":
            from agents.evaluation import score_report
            if not score_report(report, all_findings)["success"]:
                raise ValueError("Report failed the evidence citation contract")
    except Exception as e:
        report = None
        logs.append(f"[SUPERVISOR] Report generation failed: {e}")

    logs.append(f"[SUPERVISOR] Assessment complete. {len(verified)} verified, {len(unverified)} unverified.")
    tool_errors = any(item.get("type") == "error" for item in state["recon_state"].get("findings", [])) or bool(state["exploit_state"].get("errors"))
    status = "completed" if report and not tool_errors else "failed"
    return {"report_state": {"report": report, "findings": all_findings, "status": status}, "logs": logs}


def _build_graph():
    workflow = StateGraph(SupervisorState)
    workflow.add_node("recon", _recon_node)
    workflow.add_node("exploit", _exploit_node)
    workflow.add_node("report", _report_node)
    workflow.set_entry_point("recon")
    workflow.add_conditional_edges("recon", lambda state: "exploit" if state["task_type"] in ("comprehensive", "web_scan") else "report")
    workflow.add_edge("exploit", "report")
    workflow.add_edge("report", END)
    return workflow.compile()


_graph = _build_graph()


async def run_multi_agent(
    target: str,
    task_type: str = "comprehensive",
    provider: str = "local",
    on_progress: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
) -> Dict[str, Any]:
    """Run independent specialist nodes through LangGraph; keep the public result shape."""
    policy = load_policy()
    initial = {
        "target": target, "task_type": task_type, "provider": provider,
        "policy": asdict(policy),
        "blackboard": Blackboard(), "recon_state": {}, "exploit_state": {},
        "report_state": {}, "logs": [f"[POLICY] {policy.version}"],
    }
    if on_progress:
        async for state in _graph.astream(initial, stream_mode="values"):
            completed = sum(bool(state[key]) for key in ("recon_state", "exploit_state", "report_state"))
            await on_progress({
                "phase": ("complete" if state["report_state"] else
                          "exploit" if state["exploit_state"] else
                          "recon" if state["recon_state"] else "pending"),
                "status": state["report_state"].get("status", "running"),
                "steps_completed": completed, "steps_total": 3 if task_type in ("web_scan", "comprehensive") else 2,
                "findings": state["blackboard"].get("all_findings", []),
                "report": state["report_state"].get("report"), "logs": state["logs"],
            })
    else:
        state = await _graph.ainvoke(initial)
    return {
        "status": state["report_state"]["status"],
        "target": target,
        "phase": "complete",
        "findings": state["report_state"]["findings"],
        "report": state["report_state"]["report"],
        "blackboard_keys": state["blackboard"].list_keys(),
        "logs": state["logs"],
    }
