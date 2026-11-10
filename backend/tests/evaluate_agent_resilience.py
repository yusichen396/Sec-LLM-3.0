"""容错效果评测：故障注入，测修复成功率、尝试次数、虚假成功。

不依赖网络、不依赖真实 LLM：重规划用脚本化的完成函数代替。

运行：
    python -m tests.evaluate_agent_resilience
    python -m tests.evaluate_agent_resilience --json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents import orchestrator as orch  # noqa: E402
from agents.state import AgentState  # noqa: E402
from tools.registry import register_tool  # noqa: E402

MAX_STEPS = 5


def _state(plan: list[dict], target: str = "https://example.com") -> AgentState:
    return {
        "task": {"task": "fault injection", "target": target, "task_type": "recon"},
        "target": target,
        "plan": plan,
        "current_step": 0,
        "observations": [],
        "findings": [],
        "logs": [],
        "status": "running",
        "error": "",
        "answer": "",
        "report": "",
        "provider": "local",
        "policy": {},
        "safety": {},
        "skills": [],
        "blackboard": {},
        "replans": 0,
        "consecutive_failures": 0,
        "planner_state": {},
        "executor_state": {},
        "reflector_state": {},
        "reporter_state": {},
    }


# ---------- 故障工具 ----------
@register_tool(name="fj_flaky", description="times out once then succeeds", category="recon",
               requires_provider=False)
async def _flaky(url: str = "") -> dict:
    if not _flaky.__dict__.get("calls"):
        _flaky.__dict__["calls"] = 0
    _flaky.__dict__["calls"] += 1
    if _flaky.__dict__["calls"] == 1:
        raise asyncio.TimeoutError("simulated timeout")
    return {"status": "success", "exit_code": 0}


@register_tool(name="fj_dead", description="always times out", category="recon",
               requires_provider=False)
async def _dead(url: str = "") -> dict:
    raise asyncio.TimeoutError("always down")


@register_tool(name="fj_empty", description="returns no findings", category="exploit",
               requires_provider=False, expects="findings_list")
async def _empty(url: str = "") -> dict:
    return {"status": "success", "pages": ["x"]}


@register_tool(name="fj_good", description="produces findings", category="exploit",
               requires_provider=False, expects="findings_list")
async def _good(url: str = "") -> dict:
    return {"status": "success", "findings": [{"title": "found", "severity": "High"}]}


@register_tool(name="fj_code", description="audits source", category="exploit",
               requires_provider=False, accepts="code", expects="findings_list")
async def _code(code: str = "") -> dict:
    return {"status": "success", "findings": [{"title": "sqli", "severity": "High"}]}


@register_tool(name="fj_fatal", description="always raises", category="recon",
               requires_provider=False)
async def _fatal(url: str = "") -> dict:
    raise ValueError("permanently broken")


@dataclass
class Case:
    id: str
    description: str
    plan: list[dict]
    target: str
    replan_with: dict | None = None   # 脚本化重规划返回
    expect_success: bool = True
    max_exec: int = 6


CASES = [
    Case("timeout_once", "首次超时、重试成功",
         [{"tool": "fj_flaky", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com", None, True),
    Case("transient_dead", "工具持续超时，应熔断且不虚假成功",
         [{"tool": "fj_dead", "args": {"url": "http://x"}, "status": "pending"},
          {"tool": "fj_dead", "args": {"url": "http://y"}, "status": "pending"},
          {"tool": "fj_dead", "args": {"url": "http://z"}, "status": "pending"}],
         "https://example.com", None, False),
    Case("weak_result_replan", "结果不含 findings，应重规划换工具",
         [{"tool": "fj_empty", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com",
         {"tool": "fj_good", "args": {"url": "http://x"}, "reason": "alternative"}, True),
    Case("target_mismatch_replan", "代码工具拿到 URL，应拦截并重规划",
         [{"tool": "fj_code", "args": {"code": "x"}, "status": "pending"}],
         "https://example.com",
         {"tool": "fj_good", "args": {"url": "https://example.com"}, "reason": "url tool"}, True),
    Case("fatal_no_retry", "致命错误不重试，直接重规划",
         [{"tool": "fj_fatal", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com",
         {"tool": "fj_good", "args": {"url": "http://x"}, "reason": "alternative"}, True),
    Case("replan_abort", "重规划返回 abort，应保持失败",
         [{"tool": "fj_fatal", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com", {"abort": True}, False),
    Case("baseline_ok", "无故障，应一次成功",
         [{"tool": "fj_good", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com", None, True),
    Case("good_then_timeout", "成功步骤后超时，不应误熔断",
         [{"tool": "fj_good", "args": {"url": "http://x"}, "status": "pending"},
          {"tool": "fj_flaky", "args": {"url": "http://y"}, "status": "pending"}],
         "https://example.com", None, True),
    Case("weak_twice", "重规划后仍然无产出，应最终失败而不是假装成功",
         [{"tool": "fj_empty", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com",
         {"tool": "fj_empty", "args": {"url": "http://x"}, "reason": "same"}, False),
    Case("invalid_replan", "重规划给出不存在的工具，应拒绝并保持失败",
         [{"tool": "fj_fatal", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com",
         {"tool": "not_a_real_tool", "args": {}, "reason": "hallucinated"}, False),
    Case("mismatch_no_valid_alt", "目标不匹配且无可用替代，应保持失败",
         [{"tool": "fj_code", "args": {"code": "x"}, "status": "pending"}],
         "https://example.com", {"abort": True}, False),
    Case("two_step_first_fails", "两步计划首步失败，重规划后应完成全部",
         [{"tool": "fj_fatal", "args": {"url": "http://x"}, "status": "pending"},
          {"tool": "fj_good", "args": {"url": "http://x"}, "status": "pending"}],
         "https://example.com",
         {"tool": "fj_good", "args": {"url": "http://x"}, "reason": "alt"}, True),
]


async def run_case(case: Case) -> dict:
    """执行一个故障场景，返回结果指标。"""
    calls = {"exec": 0, "replans": 0}

    async def scripted_completion(messages, **kwargs):
        calls["replans"] += 1
        return json.dumps(case.replan_with or {"abort": True}, ensure_ascii=False)

    original = orch.single_shot_completion
    orch.single_shot_completion = scripted_completion
    try:
        state = _state([dict(step) for step in case.plan], case.target)
        for _ in range(case.max_exec):
            state = await orch.execute_node(state)
            calls["exec"] += 1
            if state.get("error"):
                break

            has_failure = any(s.get("status") in ("error", "timeout") for s in state["plan"])
            if has_failure:
                state = await orch.reflect_node(state)
                if state.get("error"):
                    break

            if not any(s.get("status") == "pending" for s in state["plan"]):
                break
        final = state
    finally:
        orch.single_shot_completion = original

    statuses = [s.get("status") for s in final["plan"]]
    succeeded = all(status == "done" for status in statuses) and not final.get("error")
    return {
        "id": case.id,
        "description": case.description,
        "expect_success": case.expect_success,
        "succeeded": succeeded,
        "statuses": statuses,
        "exec_calls": calls["exec"],
        "replans": calls["replans"],
        "error": (final.get("error") or "")[:80],
        "falsely_successful": succeeded and not case.expect_success,
        "recovered": succeeded and case.expect_success,
    }


async def main_async(as_json: bool) -> int:
    rows = [await run_case(case) for case in CASES]

    total = len(rows)
    recoverable = [r for r in rows if r["expect_success"]]
    failing = [r for r in rows if not r["expect_success"]]
    recovered = sum(1 for r in recoverable if r["recovered"])
    falsely = sum(1 for r in rows if r["falsely_successful"])
    correctly_failed = sum(1 for r in failing if not r["succeeded"])

    summary = {
        "cases": total,
        "recoverable": len(recoverable),
        "recovered": recovered,
        "recovery_rate": round(recovered / max(len(recoverable), 1), 4),
        "expected_failures": len(failing),
        "correctly_failed": correctly_failed,
        "falsely_successful": falsely,
        "avg_exec_calls": round(sum(r["exec_calls"] for r in rows) / max(total, 1), 2),
        "replans_used": sum(r["replans"] for r in rows),
    }

    if as_json:
        print(json.dumps({"summary": summary, "cases": rows}, ensure_ascii=False, indent=2))
    else:
        print("=== 故障注入用例 ===")
        for row in rows:
            mark = "✔" if (row["recovered"] or (not row["expect_success"] and not row["succeeded"])) else "✘"
            print(f"{mark} {row['id']:<24} exec={row['exec_calls']} replans={row['replans']} "
                  f"statuses={row['statuses']} err={row['error'][:40]}")
        print("\n=== 汇总 ===")
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    return 0 if falsely == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    return asyncio.run(main_async(args.json))


if __name__ == "__main__":
    raise SystemExit(main())
