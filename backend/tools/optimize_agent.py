"""Offline search of finite Agent planning/reporting prompts, using tool-result replay."""
import argparse
import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
import uuid

from agents.evaluation import EvaluationBudgetExceeded, evaluate, load_dataset
from agents.policy import ACTIVE_POLICY, AgentPolicy, load_policy
from tools.optimize_rag import atomic_json, environment, safety_regression

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "tests" / "data" / "agent_optimization_v1.json"


def propose(baseline, metrics):
    changes = []
    if metrics["plan_score"] < 1:
        changes += [{"planning": "schema_first"}, {"planning": "minimal"}]
    if metrics["report_score"] < 1:
        changes += [{"reporting": "evidence_table"}, {"reporting": "concise"}]
    if metrics["plan_score"] < 1 and metrics["report_score"] < 1:
        changes.append({"planning": "schema_first", "reporting": "evidence_table"})
    policies = {p.version: p for p in (replace(baseline, **change) for change in changes)}
    policies.pop(baseline.version, None)
    return list(policies.values())


def qualifies(baseline, candidate, *, gain=0.02, latency=True):
    return (
        not baseline["errors"] and not candidate["errors"] and not candidate["violations"]
        and candidate["metrics"]["score"] >= baseline["metrics"]["score"] + gain
        and all(candidate["metrics"][key] >= baseline["metrics"][key]
                for key in ("plan_score", "report_score", "success_rate"))
        and all(c >= b for b, c in zip(baseline["per_repeat"], candidate["per_repeat"]))
        and (not latency or candidate["median_latency_ms"] <= baseline["median_latency_ms"] * 1.5)
    )


async def run_search(dataset, tools, complete, baseline, repeats):
    splits = {split: [case for case in dataset["cases"] if case["split"] == split]
              for split in ("dev", "validation", "test")}
    from config import settings
    async def measure(policies, split):
        print(f"[Agent eval] {split}: {len(policies)} policies, {len(splits[split])} cases x {repeats}", flush=True)
        return await evaluate(policies, splits[split], tools, complete, repeats=repeats, max_steps=settings.AGENT_MAX_STEPS)

    initial = await measure([baseline], "dev")
    candidates = propose(baseline, initial[baseline.version]["metrics"])
    dev = await measure([baseline] + candidates, "dev") if candidates else initial
    selected = max(candidates, key=lambda p: dev[p.version]["metrics"]["score"], default=baseline)
    if not qualifies(dev[baseline.version], dev[selected.version], latency=False):
        selected = baseline
    policies = [baseline] if selected == baseline else [baseline, selected]
    validation = await measure(policies, "validation")
    validated = selected != baseline and qualifies(validation[baseline.version], validation[selected.version])
    test = await measure(policies, "test")
    # A final regression veto, never a chance to choose another development candidate.
    test_ok = (not test[selected.version]["violations"] and not test[selected.version]["errors"]
               and all(test[selected.version]["metrics"][key] >= test[baseline.version]["metrics"][key]
                       for key in ("score", "success_rate", "plan_score", "report_score")))
    safety = safety_regression()
    infrastructure_ok = all(not result["errors"] for split in (dev, validation, test) for result in split.values())
    accepted = validated and test_ok and safety["passed"] and infrastructure_ok
    return {
        "baseline": asdict(baseline), "baseline_version": baseline.version,
        "candidate": asdict(selected), "candidate_version": selected.version,
        "candidates": [asdict(p) for p in candidates], "dev": dev, "validation": validation, "test_audit": test,
        "split_sizes": {key: len(value) for key, value in splits.items()}, "safety": safety,
        "accepted": bool(accepted), "test_regression_passed": bool(test_ok),
        "decision": "validation_gain" if accepted else "execution_errors" if not infrastructure_ok else "keep_baseline",
        "test_used_for_selection": False, "test_used_as_release_gate": True,
        "development_failures": sorted({row["case_id"] for row in dev[baseline.version]["rows"] if not row["success"]}),
    }


class LiveCompletion:
    def __init__(self):
        self.calls = self.input_chars = self.output_chars = 0
        self.started = time.monotonic()

    async def __call__(self, messages, *, temperature):
        from core.llm.router import single_shot_completion
        remaining = 900 - (time.monotonic() - self.started)
        if self.calls >= 200 or remaining <= 0:
            raise EvaluationBudgetExceeded("Agent evaluation exceeded 200 calls or 900 seconds")
        self.calls += 1
        self.input_chars += sum(len(message["content"]) for message in messages)
        text = await asyncio.wait_for(single_shot_completion(messages, provider="local", temperature=temperature),
                                      timeout=min(45, remaining))
        self.output_chars += len(text)
        return text


def activate(report, path, baseline):
    if report["mode"] != "live" or not report["accepted"] or not report.get("task_audit_approved"):
        raise ValueError("Only accepted live-model evaluations with an approved task audit can activate an Agent policy")
    if load_policy(path) != baseline:
        raise ValueError("Active Agent policy changed during evaluation")
    atomic_json(path.with_suffix(".previous.json"), asdict(baseline))
    atomic_json(path, report["candidate"])


def write_summary(run_dir, report):
    b, c = report["baseline_version"], report["candidate_version"]
    lines = ["# Agent 规划与报告策略评测", "", f"模式：{report['mode']}；决策：{report['decision']}；已启用：{report['activated']}。",
             "", "评测不执行安全工具。fixture 模式使用标准答案回放，仅检查闭环，所有分数均非真实模型能力证据。",
             "", "| 集合 | 任务数 | 基线合同得分 | 候选合同得分 | 基线/候选中位延迟(ms) |",
             "|---|---:|---:|---:|---:|"]
    for split, key in (("dev", "dev"), ("validation", "validation"), ("test", "test_audit")):
        before, after = report[key][b], report[key][c]
        lines.append(f"| {split} | {report['split_sizes'][split]} | {before['metrics']['score']:.3f} | "
                     f"{after['metrics']['score']:.3f} | {before['median_latency_ms']:.2f} / {after['median_latency_ms']:.2f} |")
    lines += ["", "得分衡量工具/参数选择、报告章节和证据引用位置，不等同于漏洞检测准确率、真实任务成功率或全文事实正确率。",
              f"安全护栏回归：{report['safety']['total']} 条，通过：{report['safety']['passed']}。",
              "候选只由开发集选择，验证集用于晋级，测试集只否决回归；工具权限、证据验证和评分器不参与搜索。",
              "完整配置、逐项输出、失败案例、调用预算和版本指纹见 result.json。"]
    (run_dir / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


async def run(args):
    from config import settings
    path = Path(settings.AGENT_POLICY_PATH) if settings.AGENT_POLICY_PATH else ACTIVE_POLICY
    if args.rollback:
        previous = AgentPolicy(**json.loads(path.with_suffix(".previous.json").read_text(encoding="utf-8")))
        atomic_json(path, asdict(previous))
        print(f"Restored Agent policy {previous.version}")
        return 0
    dataset, digest = load_dataset(args.dataset)
    baseline = load_policy(path)
    run_dir = args.output_dir / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8])
    sources = [ROOT / "agents" / name for name in ("policy.py", "evaluation.py", "orchestrator.py", "supervisor.py", "reporting.py")]
    sources += [Path(__file__), args.dataset.resolve()]
    metadata = {"created_at": datetime.now(timezone.utc).isoformat(), "mode": "live" if args.live else "fixture",
                "dataset": dataset["name"], "dataset_sha256": digest, "environment": environment(),
                "source_sha256": {str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p):
                                  hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                "budget": {"repeats": args.repeats, "max_candidates": 5, "max_llm_calls": 200, "max_seconds": 900,
                           "max_steps": settings.AGENT_MAX_STEPS, "min_gain": 0.02, "max_latency_ratio": 1.5},
                "model": settings.OLLAMA_MODEL_NAME if args.live else "oracle_fixture_replay"}
    try:
        if args.live:
            import httpx
            async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                response = await client.get(settings.OLLAMA_BASE_URL.rstrip("/") + "/api/tags")
                response.raise_for_status()
                name = settings.OLLAMA_MODEL_NAME
                match = next((m for m in response.json()["models"] if m["name"] == name or m["name"] == name + ":latest"), None)
                if not match:
                    raise ValueError(f"Configured Ollama model {name} is not installed")
                metadata["model_digest"] = match["digest"]
        # Import registers tool signatures only; no invoke_tool call is made by this evaluator.
        from agents.orchestrator import get_all_tools
        complete = LiveCompletion() if args.live else None
        report = {**metadata, **await run_search(dataset, get_all_tools(), complete, baseline, args.repeats)}
        if not args.live:
            report["accepted"] = False
            report["decision"] = "fixture_only_keep_baseline"
        report["usage"] = {"llm_calls": complete.calls if complete else 0,
                           "input_chars": complete.input_chars if complete else 0,
                           "output_chars": complete.output_chars if complete else 0,
                           "tokens": None, "monetary_compute_cost": None,
                           "note": "Token usage/cost unavailable from the existing text-only provider interface; characters are not tokens."}
        report["activated"] = False
        report["task_audit_approved"] = False
        audit_path = getattr(args, "task_audit", None)
        if audit_path:
            from tools.evaluate_agent_tasks import source_fingerprints
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            report["task_audit_approved"] = bool(
                audit.get("mode") == "live" and audit.get("approved") is True
                and audit.get("policy_version") == report["candidate_version"]
                and audit.get("source_sha256") == source_fingerprints()
                and audit.get("model", {}).get("digest") == metadata.get("model_digest")
                and metadata.get("model_digest"))
            report["task_audit_sha256"] = hashlib.sha256(audit_path.read_bytes()).hexdigest()
        atomic_json(run_dir / "result.json", report)
        atomic_json(run_dir / "candidate.json", report["candidate"])
        if args.activate and report["accepted"] and not report["task_audit_approved"]:
            report["decision"] = "task_audit_required"
            atomic_json(run_dir / "result.json", report)
        if args.activate and report["accepted"] and report["task_audit_approved"]:
            activate(report, path, baseline)
            report["activated"] = True
            atomic_json(run_dir / "result.json", report)
        write_summary(run_dir, report)
        print(json.dumps({key: report[key] for key in ("mode", "decision", "accepted", "activated", "split_sizes")}, indent=2))
        print(f"Report: {run_dir / 'SUMMARY.md'}")
        return 0
    except Exception as exc:
        atomic_json(run_dir / "error.json", {**metadata, "accepted": False, "error": str(exc) or type(exc).__name__})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data" / "agent_optimization" / "runs")
    parser.add_argument("--live", action="store_true", help="use the configured local Ollama model")
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--repeats", type=int, choices=(2, 3), default=2)
    parser.add_argument("--task-audit", type=Path, help="approved live task benchmark for the same candidate policy and model digest")
    args = parser.parse_args()
    if args.activate and (not args.live or args.rollback):
        parser.error("--activate requires --live and cannot be combined with --rollback")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
