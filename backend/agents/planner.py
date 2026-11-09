"""规划器：带校验反馈的重试。

生产与评测共用这一条路径：
    planning_messages -> single_shot_completion -> parse_plan
校验失败时把错误回灌给模型重试，避免"参数名写错就整单失败"。
"""
from __future__ import annotations

import inspect
import json
from typing import Any, Callable, Dict, List, Tuple

from agents.policy import parse_plan, planning_messages
from core.llm.router import single_shot_completion

RETRY_HINT = (
    "Your previous plan was rejected by the validator: {error}\n"
    "Fix the problem and output ONLY the JSON array.\n"
    "Rules: use only tool names that appear in the catalog, and use the exact argument "
    "names shown in each tool signature. Do not invent parameters."
)


async def plan_with_retry(
    *,
    task: Dict[str, Any],
    tools: Dict[str, Dict[str, Any]],
    policy: Any,
    max_steps: int,
    provider: str = "local",
    retries: int = 1,
    temperature: float = 0.1,
    log: Callable[[str], None] | None = None,
    raise_on_fail: bool = True,
    complete: Callable[..., Any] | None = None,
) -> Tuple[List[Dict[str, Any]] | None, Dict[str, Any]]:
    """生成并校验计划；校验失败时带错误信息重试。

    返回 (plan, meta)。meta 记录尝试次数与每次的错误，便于评估重试收益。
    """
    messages: List[Dict[str, str]] = planning_messages(task, tools, policy, max_steps)
    completion = complete or single_shot_completion
    errors: List[str] = []
    last_raw = ""

    for attempt in range(retries + 1):
        raw = await completion(
            messages, provider=provider, temperature=temperature, json_mode=False
        )
        last_raw = raw
        try:
            plan = parse_plan(raw, tools, max_steps)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
            if log:
                log(f"[PLAN-RETRY] attempt {attempt + 1} rejected: {exc}")
            if attempt >= retries:
                break
            messages = messages + [
                {"role": "assistant", "content": raw},
                {"role": "user", "content": RETRY_HINT.format(error=exc)},
            ]
            continue

        meta = {"attempts": attempt + 1, "errors": errors, "recovered": attempt > 0, "last_raw": last_raw}
        if log and attempt > 0:
            log(f"[PLAN] recovered after {attempt + 1} attempts")
        return plan, meta

    meta = {"attempts": retries + 1, "errors": errors, "recovered": False, "last_raw": last_raw if errors else ""}
    if not raise_on_fail:
        return None, meta
    raise ValueError(f"planning failed after {retries + 1} attempt(s): {errors[-1] if errors else 'unknown'}")


REVISE_PROMPT = """A step of the plan failed. Propose a replacement step, or abort.

Task: {task}
Target: {target}
Failed step: {failed}
Error: {error}
Already collected results: {context}

Available tools:
{catalog}

Choose a DIFFERENT tool or corrected arguments that can still make progress on the task.
Output ONLY one JSON object: {{"tool": "name", "args": {{}}, "reason": "why"}}
If no alternative can help, output {{"abort": true}}.
"""


async def revise_failed_step(
    *,
    task: Dict[str, Any],
    tools: Dict[str, Dict[str, Any]],
    failed_step: Dict[str, Any],
    error: str,
    context: str,
    provider: str = "local",
    temperature: float = 0.0,
    complete: Callable[..., Any] | None = None,
) -> Dict[str, Any] | None:
    """让模型为失败的步骤给出替代方案；返回新的 step 或 None。"""
    completion = complete or single_shot_completion
    catalog = "\n".join(
        f"- {name}{inspect.signature(info['func'])}: {info['description']}"
        for name, info in sorted(tools.items())
    )
    prompt = REVISE_PROMPT.format(
        task=task.get("task", ""),
        target=task.get("target", ""),
        failed=json.dumps({"tool": failed_step.get("tool"), "args": failed_step.get("args", {})}, ensure_ascii=False),
        error=error,
        context=context or "(none)",
        catalog=catalog,
    )
    messages = [
        {"role": "system", "content": "You are a security testing planner repairing a failed step. Output ONLY JSON."},
        {"role": "user", "content": prompt},
    ]
    raw = await completion(messages, provider=provider, temperature=temperature, json_mode=False)

    start, end = raw.find("{"), raw.rfind("}") + 1
    if start < 0 or end <= start:
        return None
    try:
        proposal = json.loads(raw[start:end])
    except json.JSONDecodeError:
        return None
    if not isinstance(proposal, dict) or proposal.get("abort"):
        return None
    if not isinstance(proposal.get("tool"), str):
        return None
    proposal.setdefault("args", {})
    proposal["status"] = "pending"
    proposal["revised"] = True

    # 用生产校验器验证替代方案
    try:
        parse_plan(json.dumps([proposal]), tools, 1)
    except Exception:  # noqa: BLE001
        return None
    return proposal
