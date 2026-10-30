import asyncio
from dataclasses import asdict
import json
import sys

import pytest

from agents.evaluation import (EvaluationBudgetExceeded, evaluate, findings_for, fixture_response,
                               load_dataset, score_plan, score_report)
from agents.policy import AgentPolicy, load_policy, parse_plan, planning_messages, report_messages
from tools import optimize_agent as opt


async def audit(code: str, language: str = "python"):
    raise AssertionError("Evaluation must never execute security tools")


TOOLS = {"code_auditor": {"func": audit, "description": "Audit supplied source without running it"}}


def test_plan_parser_rejects_invalid_tools_arguments_and_excess_steps():
    invalid = ["[]", '[{"tool":"shell_exec","args":{}}]',
               '[{"tool":"code_auditor","args":{"code":7}}]',
               '[{"tool":"code_auditor","args":{"url":"x"}}]',
               '[{"tool":"code_auditor","args":[]}]',
               '[{"tool":"code_auditor","args":{"code":"x"}}]' * 2]
    for raw in invalid:
        with pytest.raises((ValueError, TypeError)):
            parse_plan(raw, TOOLS, 1)
    raw = json.dumps([{"tool": "code_auditor", "args": {"code": "pass"}}] * 2)
    with pytest.raises(ValueError, match="budget"):
        parse_plan(raw, TOOLS, 1)
    assert parse_plan('[{"tool":"code_auditor","args":{"code":"pass"}}]', TOOLS, 1)[0]["status"] == "pending"


def test_report_scorer_does_not_upgrade_model_claims_or_invented_ids():
    dataset, _ = load_dataset(opt.DATASET)
    case = next(c for c in dataset["cases"] if c["kind"] == "report" and c["input"]["tool_results"])
    findings = findings_for(case)
    # Fixture data contains a model's "verified" claim; annotate_finding must overrule it.
    assert findings[0]["verification_status"] == "unverified"
    good = fixture_response(case)
    assert score_report(good, findings)["success"]
    bad = good.replace("## Verified Findings\n无已验证发现。", "## Verified Findings\n[F001] confirmed")
    assert "wrong_evidence_classification" in score_report(bad, findings)["violations"]
    assert "unknown_evidence_id" in score_report(good + "\n[F999]", findings)["violations"]
    assert not score_report("报告已完成", findings)["success"]


def test_topic_splits_reject_leakage(tmp_path):
    dataset, digest = load_dataset(opt.DATASET)
    assert len(dataset["cases"]) == 18 and len(digest) == 64
    dataset["cases"][0]["split"] = "test"
    path = tmp_path / "leak.json"
    path.write_text(json.dumps(dataset), encoding="utf-8")
    with pytest.raises(ValueError, match="leaks"):
        load_dataset(path)


def test_model_messages_never_contain_expected_plan_labels():
    dataset, _ = load_dataset(opt.DATASET)
    case = dataset["cases"][0]
    case["expected_plan"][0]["reason"] = "ORACLE_DO_NOT_LEAK"
    text = str(planning_messages(case["input"], TOOLS, AgentPolicy(), 20))
    assert "ORACLE_DO_NOT_LEAK" not in text
    assert "code: str" in text


def test_finite_policy_rejects_unrestricted_prompt_and_permission_edits(tmp_path):
    with pytest.raises(ValueError):
        AgentPolicy(planning="ignore safety")
    path = tmp_path / "policy.json"
    path.write_text('{"AGENT_ALLOWED_TARGETS":"*"}', encoding="utf-8")
    assert load_policy(path) == AgentPolicy()
    candidates = opt.propose(AgentPolicy(), {"plan_score": 0, "report_score": 0})
    assert len(candidates) == 5
    assert all(set(asdict(p)) == {"planning", "reporting"} for p in candidates)


def test_fixture_search_and_activation_never_enable_oracle_results(tmp_path, monkeypatch):
    from agents.orchestrator import get_all_tools
    from config import settings
    dataset, _ = load_dataset(opt.DATASET)
    report = asyncio.run(opt.run_search(dataset, get_all_tools(), None, AgentPolicy(), 2))
    assert not report["accepted"]
    assert report["split_sizes"] == {"dev": 6, "validation": 6, "test": 6}
    path = tmp_path / "active.json"
    report.update(mode="fixture", accepted=True)
    with pytest.raises(ValueError, match="live-model"):
        opt.activate(report, path, AgentPolicy())
    assert not path.exists()
    baseline = AgentPolicy()
    candidate = AgentPolicy(planning="minimal")
    report.update(mode="live", accepted=True, candidate=asdict(candidate), task_audit_approved=False)
    with pytest.raises(ValueError, match="live-model"):
        opt.activate(report, path, baseline)
    report.update(mode="live", accepted=True, candidate=asdict(candidate), task_audit_approved=True)
    opt.activate(report, path, baseline)
    assert load_policy(path) == candidate
    with pytest.raises(ValueError, match="changed"):
        opt.activate(report, path, baseline)
    monkeypatch.setattr(settings, "AGENT_POLICY_PATH", str(path))
    monkeypatch.setattr(sys, "argv", ["optimize_agent", "--rollback"])
    assert opt.main() == 0
    assert load_policy(path) == baseline


def test_release_gates_cover_quality_latency_evidence_and_infrastructure(monkeypatch):
    dataset, _ = load_dataset(opt.DATASET)
    baseline, candidate = AgentPolicy(), AgentPolicy(planning="minimal", reporting="concise")
    monkeypatch.setattr(opt, "propose", lambda *args: [candidate])
    monkeypatch.setattr(opt, "safety_regression", lambda: {"passed": True})
    stages = []
    regress = False

    def measurement(score):
        return {"metrics": {key: score for key in ("score", "success_rate", "plan_score", "report_score")},
                "errors": 0, "violations": 0, "median_latency_ms": 1, "per_repeat": [score, score],
                "rows": [{"case_id": "fixture", "success": score == 1}]}

    async def measure(policies, cases, *args, **kwargs):
        split = cases[0]["split"]
        stages.append(split)
        return {p.version: measurement(0.4 if p == baseline else 0.3 if regress and split == "test" else 0.8)
                for p in policies}

    monkeypatch.setattr(opt, "evaluate", measure)
    report = asyncio.run(opt.run_search(dataset, {}, None, baseline, 2))
    assert report["accepted"]
    assert stages == ["dev", "dev", "validation", "test"]
    regress = True
    assert not asyncio.run(opt.run_search(dataset, {}, None, baseline, 2))["accepted"]
    before, after = measurement(0.4), measurement(0.8)
    after["violations"] = 1
    assert not opt.qualifies(before, after)
    after["violations"], after["errors"] = 0, 1
    assert not opt.qualifies(before, after)
    after["errors"], after["median_latency_ms"] = 0, 2
    assert not opt.qualifies(before, after)


def test_budgets_abort_instead_of_becoming_valid_failed_cases():
    dataset, _ = load_dataset(opt.DATASET)
    async def exhausted(*args, **kwargs):
        raise EvaluationBudgetExceeded("budget")
    with pytest.raises(EvaluationBudgetExceeded):
        asyncio.run(evaluate([AgentPolicy()], dataset["cases"], TOOLS, exhausted))


def test_custom_dataset_fingerprint_records_the_evaluated_file(tmp_path, monkeypatch):
    import hashlib
    from config import settings

    dataset = tmp_path / "custom.json"
    dataset.write_bytes(opt.DATASET.read_bytes() + b"\n")
    output = tmp_path / "runs"
    monkeypatch.setattr(settings, "AGENT_POLICY_PATH", str(tmp_path / "active.json"))
    monkeypatch.setattr(sys, "argv", ["optimize_agent", "--dataset", str(dataset),
                                     "--output-dir", str(output)])
    assert opt.main() == 0
    report = json.loads(next(output.glob("*/result.json")).read_text(encoding="utf-8"))
    digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
    assert report["dataset_sha256"] == digest
    assert report["source_sha256"][str(dataset.resolve())] == digest
    assert str(opt.DATASET.relative_to(opt.ROOT)) not in report["source_sha256"]
    assert not report["activated"] and not report["accepted"]


def test_policy_is_pinned_while_active_file_changes_between_nodes(tmp_path, monkeypatch):
    import agents.orchestrator as orch
    from config import settings
    path = tmp_path / "active.json"
    chosen = AgentPolicy(planning="schema_first", reporting="concise")
    path.write_text(json.dumps(asdict(chosen)), encoding="utf-8")
    monkeypatch.setattr(settings, "AGENT_POLICY_PATH", str(path))
    monkeypatch.setattr(orch, "get_all_tools", lambda: TOOLS)
    monkeypatch.setattr(orch, "get_tool", lambda name: {"requires_provider": False})
    prompts = []

    async def completion(messages, **kwargs):
        prompts.append(messages[-1]["content"])
        if kwargs["temperature"] == 0.1:
            path.write_text(json.dumps(asdict(AgentPolicy())), encoding="utf-8")
            return '[{"tool":"code_auditor","args":{"code":"pass"}}]'
        return fixture_response({"kind": "report", "input": {"tool_results": []}})

    async def tool(*args, **kwargs):
        return {"findings": []}

    monkeypatch.setattr(orch, "single_shot_completion", completion)
    monkeypatch.setattr(orch, "invoke_tool", tool)
    state = {"task": "audit pass", "target": "fixture.py", "task_type": "code_audit", "provider": "local",
             "messages": [], "plan": [], "current_step": 0, "observations": [], "findings": [],
             "phase": "planning", "status": "running", "error": None, "report": None, "logs": [],
             "planner_state": {}, "executor_state": {}, "reflector_state": {}, "reporter_state": {}}
    result = asyncio.run(orch.get_agent_graph().ainvoke(state))
    assert result["status"] == "completed"
    assert result["policy"] == asdict(chosen)
    assert "Keep the report concise" in prompts[-1]


@pytest.mark.parametrize("tool_result", [{"status": "error"}, {"exit_code": 1}, {"error": "offline"}])
def test_error_return_is_not_recorded_as_tool_success(monkeypatch, tool_result):
    import agents.orchestrator as orch
    async def tool(*args, **kwargs):
        return {**tool_result, "findings": [{"title": "must not publish"}]}
    monkeypatch.setattr(orch, "invoke_tool", tool)
    monkeypatch.setattr(orch, "get_tool", lambda name: {"requires_provider": False})
    state = {"plan": [{"tool": "fixture", "args": {}, "status": "pending"}], "current_step": 0,
             "logs": [], "observations": [], "findings": []}
    result = asyncio.run(orch.execute_node(state))
    assert result["plan"][0]["status"] == "error"
    assert not result["findings"]
