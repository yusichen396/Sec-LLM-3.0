"""工具选择评测：给自然语言任务，看规划器是否选对工具。

与生产同一条路径：
    agents.planner.plan_with_retry
        -> agents.policy.planning_messages
        -> core.llm.router.single_shot_completion
        -> agents.policy.parse_plan（含校验重试）

用法（在 backend 目录下）：
    python tests/evaluate_tool_selection.py --provider cloud --repeats 3

指标：
    covered    期望工具出现在计划里（覆盖命中）
    top1       计划第一个工具就是期望工具
    args_valid 计划通过生产校验（工具名与参数名都对）
    attempts   平均调用模型的次数（>1 说明发生过重试）
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# 导入即注册工具（与 main.py 一致）
import tools.api_discovery  # noqa: F401,E402
import tools.browser  # noqa: F401,E402
import tools.code_audit  # noqa: F401,E402
import tools.lfi  # noqa: F401,E402
import tools.phishing  # noqa: F401,E402
import tools.report  # noqa: F401,E402
import tools.rule_gen  # noqa: F401,E402
import tools.shell  # noqa: F401,E402
import tools.source_reader  # noqa: F401,E402
import tools.sqli  # noqa: F401,E402
import tools.ssrf  # noqa: F401,E402
import tools.threat_intel  # noqa: F401,E402

from agents.planner import plan_with_retry  # noqa: E402
from agents.policy import load_policy  # noqa: E402
from config import settings  # noqa: E402
from tools import get_all_tools  # noqa: E402

CASES_PATH = Path(__file__).parent / "data" / "tool_selection_cases_v3.json"


def load_cases() -> list[dict]:
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases = data["cases"]
    assert cases, "用例为空"
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "用例 id 重复"
    for c in cases:
        assert c.get("expected_tools"), f"{c['id']} 缺少期望工具"
        assert c.get("split") in ("dev", "validation", "test"), f"{c['id']} split 非法"
    groups = {}
    for c in cases:
        if groups.setdefault(c["group"], c["split"]) != c["split"]:
            raise AssertionError(f"group {c['group']} 跨 split 泄漏")
    return cases


def _loose_tools(raw: str) -> list[str]:
    """只取工具名，不校验参数。"""
    start, end = raw.find("["), raw.rfind("]") + 1
    if start < 0 or end <= start:
        return []
    try:
        loose = json.loads(raw[start:end])
    except json.JSONDecodeError:
        return []
    if not isinstance(loose, list):
        return []
    return [s["tool"] for s in loose if isinstance(s, dict) and isinstance(s.get("tool"), str)]


async def run_case(case: dict, tools: dict, policy, max_steps: int, provider: str) -> dict:
    task = {
        "task": case["task"],
        "target": case["target"],
        "task_type": case.get("task_type", "recon"),
    }

    started = time.perf_counter()
    plan, meta = await plan_with_retry(
        task=task,
        tools=tools,
        policy=policy,
        max_steps=max_steps,
        provider=provider,
        retries=settings.AGENT_PLAN_RETRIES,
        temperature=0.0,
        raise_on_fail=False,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000

    raw = meta.get("last_raw", "")
    if plan is not None:
        picked = [step["tool"] for step in plan]
        args_valid = True
    else:
        picked = _loose_tools(raw)
        args_valid = False

    expected = case["expected_tools"]
    return {
        "id": case["id"],
        "split": case.get("split", "dev"),
        "group": case.get("group", "unknown"),
        "expected": expected,
        "picked": picked,
        "top1_hit": bool(picked) and picked[0] in expected,
        "covered": (
            all(tool in picked for tool in expected)
            if case.get("require_all")
            else bool(set(expected) & set(picked))
        ),
        "exact_plan": picked == expected,
        "args_valid": args_valid,
        "attempts": meta.get("attempts", 1),
        "recovered": bool(meta.get("recovered")),
        "errors": meta.get("errors", []),
        "extra_steps": len([t for t in picked if t not in expected]),
        "elapsed_ms": round(elapsed_ms, 1),
        "raw": raw[:600],
    }


async def main_async(args) -> int:
    cases = load_cases()
    tools = get_all_tools()
    policy = load_policy()

    missing = sorted({t for c in cases for t in c["expected_tools"]} - set(tools))
    if missing:
        print(f"[warn] 期望工具未注册: {missing}")

    runs = []
    for run_idx in range(args.repeats):
        rows = []
        for case in cases:
            row = await run_case(case, tools, policy, args.max_steps, args.provider)
            rows.append(row)
            flag = "OK  " if row["covered"] else "MISS"
            retry = f" (retry×{row['attempts']})" if row["attempts"] > 1 else ""
            print(f"[run{run_idx + 1}][{flag}] {case['id']:<14} 期望 {row['expected']} 实选 {row['picked']}{retry}")
        runs.append(rows)

    flat = [r for rows in runs for r in rows]

    def rate(key: str) -> list[float]:
        return [round(sum(1 for r in rows if r[key]) / len(rows), 4) for rows in runs]

    covered = rate("covered")
    top1 = rate("top1_hit")
    exact = rate("exact_plan")
    args_ok = rate("args_valid")

    summary = {
        "cases": len(cases),
        "repeats": args.repeats,
        "retries_configured": settings.AGENT_PLAN_RETRIES,
        "covered_accuracy": covered,
        "covered_mean": round(statistics.mean(covered), 4),
        "top1_accuracy": top1,
        "top1_mean": round(statistics.mean(top1), 4),
        "args_valid_rate": args_ok,
        "args_valid_mean": round(statistics.mean(args_ok), 4),
        "exact_plan_mean": round(statistics.mean(exact), 4),
        "avg_extra_steps": round(statistics.mean([r["extra_steps"] for r in flat]), 2),
        "retry_attempts_mean": round(statistics.mean([r["attempts"] for r in flat]), 2),
        "retry_recovered": sum(1 for r in flat if r["recovered"]),
        "unstable_cases": sorted({
            r["id"]
            for r in flat
            if any(x["covered"] != r["covered"] for rows in runs for x in rows if x["id"] == r["id"])
        }),
    }

    def breakdown(key: str) -> dict:
        buckets: dict[str, list[bool]] = {}
        for row in flat:
            buckets.setdefault(row[key], []).append(row["covered"])
        return {
            name: {"n": len(values), "covered": round(sum(values) / len(values), 4)}
            for name, values in sorted(buckets.items())
        }

    summary["by_split"] = breakdown("split")
    summary["by_group"] = breakdown("group")

    print("\n=== 汇总 ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": CASES_PATH.name,
        "provider": args.provider,
        "summary": summary,
        "runs": runs,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[saved] {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="工具选择评测")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=3)
    parser.add_argument("--provider", default="local", choices=["local", "cloud"])
    parser.add_argument("--out", default=str(Path(__file__).parent / "data" / "tool_selection_result.json"))
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
