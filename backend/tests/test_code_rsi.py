from argparse import Namespace
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

from tools import code_rsi as rsi
from tools.optimize_rag import atomic_json


def source_tree(root):
    for path in sorted(rsi.ALLOWED):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("def example():\n    return 1\n", encoding="utf-8")
    target = root / "tests" / "data" / "frozen.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"fixed":true}', encoding="utf-8")
    return root


def proposal(root):
    path = sorted(rsi.ALLOWED)[0]
    return {"hypothesis": "Exercise source change lifecycle", "changes": [
        {"path": path, "before_sha256": rsi.digest((root / path).read_bytes()),
         "content": "def example():\n    return 2\n"}]}


def accepted_run(tmp_path, *, mode="full"):
    root = source_tree(tmp_path / "source")
    run = tmp_path / "run"
    rsi.snapshot(root, run / "baseline")
    value = proposal(root)
    rsi.snapshot(root, run / "candidate")
    for change in value["changes"]:
        (run / "candidate" / change["path"]).write_text(change["content"], encoding="utf-8")
    atomic_json(run / "proposal.json", value)
    atomic_json(run / "result.json", {"accepted": True, "release_eligible": True,
                "mode": mode, "state": "evaluated", "decision": "quality_gain",
                "baseline_manifest": rsi.manifest(run / "baseline"),
                "candidate_manifest": rsi.manifest(run / "candidate")})
    return root, run, value


def test_snapshot_preserves_frozen_inputs_and_excludes_runtime_and_secrets(tmp_path):
    assert rsi.private_file(".ENV.production") and rsi.private_file("SECRETS.JSON")
    root = source_tree(tmp_path / "source")
    (root / ".env").write_text("secret", encoding="utf-8")
    (root / "secrets.json").write_text('{"private":"secret"}', encoding="utf-8")
    (root / ".aws").mkdir()
    (root / ".aws/credentials").write_text("private", encoding="utf-8")
    (root / "data").mkdir()
    (root / "data" / "runtime.json").write_text("{}", encoding="utf-8")
    target = tmp_path / "copy"
    rsi.snapshot(root, target)
    assert (target / "tests/data/frozen.json").is_file()
    assert not (target / "data").exists() and not (target / ".env").exists()
    assert not (target / "secrets.json").exists() and not (target / ".aws").exists()
    assert rsi.manifest(root) == rsi.manifest(target)
    (target / "tests/data/frozen.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        rsi.check_snapshot(target, rsi.manifest(root))


@pytest.mark.parametrize("path", ["../config.py", "core/safety/guard.py", "core/rag/evaluation.py",
                                  "tests/test_rag_optimization.py", "tools/code_rsi.py", "C:/escape.py"])
def test_candidate_cannot_edit_grader_tests_permissions_or_escape(tmp_path, path):
    root = source_tree(tmp_path)
    value = proposal(root)
    value["changes"][0]["path"] = path
    with pytest.raises(ValueError, match="allowlist"):
        rsi.validate_candidate(value, root)


def test_candidate_rejects_stale_duplicate_invalid_and_unchanged_source(tmp_path):
    root = source_tree(tmp_path)
    valid = proposal(root)
    assert rsi.validate_candidate(valid, root)
    for changes in ([{**valid["changes"][0], "before_sha256": "stale"}], valid["changes"] * 2):
        with pytest.raises(ValueError):
            rsi.validate_candidate({**valid, "changes": changes}, root)
    for content in ("def invalid(:", (root / valid["changes"][0]["path"]).read_text(encoding="utf-8")):
        with pytest.raises((ValueError, SyntaxError)):
            rsi.validate_candidate({**valid, "changes": [{**valid["changes"][0], "content": content}]}, root)


def test_quality_requires_gain_safety_latency_policy_and_no_regression():
    before = {"dataset_sha256": "frozen", "policy": {"fixed": True}, "safety": {"passed": True},
              "metrics": {"mrr_at_3": 0.5, "hit_at_1": 0.5, "hit_at_3": 0.5},
              "per_repeat": [{"mrr_at_3": 0.5}] * 2, "median_latency_ms": 10}
    after = deepcopy(before)
    after["metrics"] = {k: 0.6 for k in before["metrics"]}
    after["per_repeat"] = [{"mrr_at_3": 0.6}] * 2
    assert rsi.quality_gate(before, after, gain=0.01)
    assert not rsi.quality_gate(before, before, gain=0.01)
    for key, value in (("dataset_sha256", "other"), ("policy", {}),
                       ("safety", {"passed": False}), ("median_latency_ms", 16)):
        assert not rsi.quality_gate(before, {**after, key: value}, gain=0.01)
    after["metrics"]["hit_at_1"] = 0.4
    assert not rsi.test_gate(before, after)


def test_apply_then_rollback_preserves_unrelated_edits_and_original_bytes(tmp_path):
    root, run, value = accepted_run(tmp_path)
    rsi.promote(run, root)
    changed = root / value["changes"][0]["path"]
    assert changed.read_text(encoding="utf-8") == value["changes"][0]["content"]
    # Rollback only touches promoted files, so subsequent unrelated work survives.
    (root / "unrelated.py").write_text("keep = True", encoding="utf-8")
    rsi.rollback(run, root)
    assert changed.read_bytes() == (run / "baseline" / value["changes"][0]["path"]).read_bytes()
    assert (root / "unrelated.py").read_text(encoding="utf-8") == "keep = True"
    assert json.loads((run / "result.json").read_text())["state"] == "rolled_back"


def test_apply_rejects_smoke_and_changed_baseline(tmp_path):
    root, run, _ = accepted_run(tmp_path, mode="smoke")
    with pytest.raises(ValueError, match="full evaluation"):
        rsi.promote(run, root)
    report = json.loads((run / "result.json").read_text())
    report["mode"] = "full"
    atomic_json(run / "result.json", report)
    (root / "tests/data/frozen.json").write_text("edited", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        rsi.promote(run, root)


def test_rollback_refuses_to_overwrite_subsequent_source_edits(tmp_path):
    root, run, value = accepted_run(tmp_path)
    rsi.promote(run, root)
    changed = root / value["changes"][0]["path"]
    changed.write_text("user_work = True", encoding="utf-8")
    with pytest.raises(ValueError, match="user edits"):
        rsi.rollback(run, root)
    assert changed.read_text(encoding="utf-8") == "user_work = True"


def test_partial_apply_failure_restores_already_written_sources(tmp_path, monkeypatch):
    root, run, value = accepted_run(tmp_path)
    second = sorted(rsi.ALLOWED)[1]
    original = (root / second).read_bytes()
    value["changes"].append({"path": second, "before_sha256": rsi.digest(original),
                             "content": "value = 3\n"})
    (run / "candidate" / second).write_bytes(b"value = 3\n")
    atomic_json(run / "proposal.json", value)
    report = json.loads((run / "result.json").read_text())
    report["candidate_manifest"] = rsi.manifest(run / "candidate")
    atomic_json(run / "result.json", report)
    replace = rsi.replace_bytes
    calls = 0

    def fail_once(path, content):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated write failure")
        replace(path, content)

    monkeypatch.setattr(rsi, "replace_bytes", fail_once)
    with pytest.raises(OSError):
        rsi.promote(run, root)
    assert rsi.manifest(root) == report["baseline_manifest"]
    assert json.loads((run / "result.json").read_text())["state"] == "rolled_back"


def test_source_lock_excludes_concurrent_mutation_and_can_be_reused(tmp_path):
    with rsi.mutation_lock(tmp_path):
        with pytest.raises(RuntimeError, match="in progress"):
            with rsi.mutation_lock(tmp_path):
                pytest.fail("Concurrent writer acquired the same lock")
    with rsi.mutation_lock(tmp_path):
        assert (tmp_path / "temp/code_rsi.lock").is_file()


def test_crashed_process_does_not_leave_a_stale_source_lock(tmp_path):
    import subprocess
    script = (f"import os,sys; sys.path.insert(0, {str(rsi.ROOT)!r}); "
              "from pathlib import Path; from tools.code_rsi import mutation_lock; "
              f"lock = mutation_lock(Path({str(tmp_path)!r})); lock.__enter__(); os._exit(0)")
    subprocess.run([sys.executable, "-c", script], check=True, timeout=15)
    with rsi.mutation_lock(tmp_path):
        assert (tmp_path / "temp/code_rsi.lock").is_file()


def test_acceptance_failure_leaves_log_and_timeout_does_not_become_success(tmp_path):
    import os
    import time
    log = tmp_path / "failure.log"
    with pytest.raises(RuntimeError, match="Acceptance command failed"):
        rsi.execute([sys.executable, "-c", "raise SystemExit(2)"], tmp_path, log,
                    time.monotonic() + 10, os.environ.copy())
    assert log.exists()
    with pytest.raises(TimeoutError):
        rsi.execute([], tmp_path, log, time.monotonic() - 1, {})


def test_model_proposer_only_receives_failed_development_cases(tmp_path, monkeypatch):
    import asyncio
    import core.llm.router as router

    root = source_tree(tmp_path)
    dataset = json.loads((rsi.ROOT / "tests/data/rag_optimization_v1.json").read_text(encoding="utf-8"))
    (root / "tests/data/rag_optimization_v1.json").write_text(json.dumps(dataset), encoding="utf-8")
    query = next(q for q in dataset["queries"] if q["split"] == "dev")
    prompts = []
    value = proposal(root)

    async def complete(messages, **kwargs):
        assert kwargs["provider"] == "local"
        prompts.append(json.loads(messages[-1]["content"]))
        return json.dumps(value)

    monkeypatch.setattr(router, "single_shot_completion", complete)
    result = asyncio.run(rsi.generate(root, {"rows": [
        {"id": query["id"], "ranked_ids": [], "relevant_ids": query["relevant_ids"]}]}, 10))
    assert result == value
    assert prompts[0]["development_queries"] == [query]
    assert {d["id"] for d in prompts[0]["development_documents"]} == set(query["relevant_ids"])
    assert set(prompts[0]["sources"]) == rsi.ALLOWED


@pytest.mark.parametrize("failure,expected_splits", [
    ("dev", ["dev", "dev"]),
    ("validation", ["dev", "dev", "validation", "validation"]),
    ("test", ["dev", "dev", "validation", "validation", "test", "test"]),
    (None, ["dev", "dev", "validation", "validation", "test", "test"]),
])
def test_search_stages_freeze_policy_and_never_consult_later_splits_after_failure(
        tmp_path, monkeypatch, failure, expected_splits):
    root = source_tree(tmp_path / "backend")
    dataset = Path(rsi.ROOT / "tests/data/rag_optimization_v1.json").read_bytes()
    (root / "tests/data/rag_optimization_v1.json").write_bytes(dataset)
    candidate_path = tmp_path / "proposal.json"
    atomic_json(candidate_path, proposal(root))
    initial = rsi.manifest(root)
    monkeypatch.setattr(rsi, "ROOT", root)
    from tools.rsi_host import perform
    monkeypatch.setattr(rsi, "host_step", lambda action, request, *args: perform(action, request))
    monkeypatch.setattr("tools.rsi_preflight.check", lambda **kwargs:
                        {"executor": "local", "reranker_path": str(root / "models/bge-reranker-base")})
    monkeypatch.setattr("tools.rsi_vectors.prepare", lambda projection, *args, **kwargs: projection)
    calls, policies = [], []

    def fake_execute(command, cwd, log, deadline, env):
        log.write_text("fixed tests passed", encoding="utf-8")
        if "tools.code_rsi_grade" not in command:
            return
        request = json.loads(Path(command[-4]).read_text(encoding="utf-8"))
        split = next(s for s in ("dev", "validation", "test") if "_" + s in Path(command[-4]).name)
        calls.append(split)
        policies.append(request["policy"])
        is_baseline = Path(command[-1]).name == "baseline"
        score = 0.5 if is_baseline else 0.4 if split == failure else 0.6
        atomic_json(Path(command[-3]), {"rows": [], "test_score": score})

    def fake_score(raw, data, split, **kwargs):
        score = raw["test_score"]
        return {"dataset_sha256": kwargs["dataset_sha256"], "policy": kwargs["policy"],
                "safety": {"passed": True}, "metrics": {k: score for k in ("hit_at_1", "hit_at_3", "mrr_at_3")},
                "per_repeat": [{"mrr_at_3": score}] * 2, "median_latency_ms": 1, "rows": [{}] * 10}

    monkeypatch.setattr(rsi, "execute", fake_execute)
    monkeypatch.setattr("tools.code_rsi_grade.score_rankings", fake_score)
    original_gate = rsi.quality_gate
    monkeypatch.setattr(rsi, "quality_gate", lambda before, after, **kwargs:
                        original_gate({**before, "host_ms_per_query": 1}, {**after, "host_ms_per_query": 1}, **kwargs))
    run_dir = rsi.run(Namespace(output_dir=tmp_path / "runs", max_seconds=30, smoke=False,
                                generate=False, candidate=candidate_path, apply=False, trusted_candidate=True))
    report = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert not report["accepted"]  # Local and authored runs never have release eligibility.
    assert (report["decision"] == "quality_gain_but_ineligible") == (failure is None)
    assert calls == expected_splits
    assert all(policy == policies[0] for policy in policies)
    assert rsi.manifest(root) == initial
