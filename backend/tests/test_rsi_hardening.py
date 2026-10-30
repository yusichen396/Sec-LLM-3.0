import asyncio
from argparse import Namespace
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from unittest.mock import MagicMock

from tools import code_rsi, rsi_dataset, rsi_sandbox, rsi_campaign
from tools.code_rsi_grade import score_rankings, ReplayStore
from tools.evaluate_agent_tasks import static_audit, score_claims, audit_review, approve_existing, output_fingerprint
from tools.optimize_rag import atomic_json


def dataset(prefix="a"):
    return {"name": "independent_fixture_" + prefix,
            "documents": [{"id": prefix + str(i), "text": prefix + " unique topic " + str(i)} for i in range(3)],
            "queries": [{"id": prefix + "q" + str(i), "text": prefix + " question " + str(i),
                         "relevant_ids": [prefix + str(i)], "group": prefix + "group" + str(i), "split": split}
                        for i, split in enumerate(("dev", "validation", "test"))]}


def bundle(tmp_path, prefix="a", origin="authored"):
    source, destination = tmp_path / (prefix + ".json"), tmp_path / (prefix + "_sealed.json")
    atomic_json(source, dataset(prefix))
    rsi_dataset.seal(source, destination, origin=origin, annotator="annotator", reviewer="reviewer")
    return destination


def test_sealing_checks_provenance_fingerprints_and_immutability(tmp_path):
    path = bundle(tmp_path)
    value = rsi_dataset.read_bundle(path)
    assert value["provenance"]["origin"] == "authored"
    with pytest.raises(ValueError, match="overwritten"):
        rsi_dataset.seal(tmp_path / "a.json", path, origin="business", annotator="a", reviewer="b")
    with pytest.raises(ValueError, match="distinct"):
        rsi_dataset.seal(tmp_path / "a.json", tmp_path / "bad.json", origin="business", annotator="a", reviewer="a")
    value["dataset"]["queries"][0]["text"] = "tampered"
    atomic_json(path, value)
    with pytest.raises(ValueError, match="fingerprint"):
        rsi_dataset.read_bundle(path)


def test_holdouts_are_consumed_before_execution_and_reject_rewritten_bundle(tmp_path):
    path = bundle(tmp_path)
    value = rsi_dataset.read_bundle(path)
    ledger = tmp_path / "ledger.json"
    rsi_dataset.reserve_holdout(value, ledger, "failed_round")
    # Even failed rounds consume the answers; changing dataset names cannot bypass topic/query checks.
    value["dataset"]["name"] = "another_version"
    value["dataset_sha256"] = rsi_dataset.fingerprint(value["dataset"])
    with pytest.raises(ValueError, match="consumed"):
        rsi_dataset.reserve_holdout(value, ledger, "retry")
    rsi_dataset.reserve_holdout(rsi_dataset.read_bundle(bundle(tmp_path, "b")), ledger, "fresh")
    assert len(json.loads(ledger.read_text(encoding="utf-8"))["uses"]) == 2


def test_worker_projection_does_not_expose_labels_topics_or_other_split_queries():
    value = dataset()
    projection = rsi_dataset.public_projection(value, "dev")
    assert projection["queries"] == [{"id": "aq0", "text": "a question 0"}]
    assert "relevant_ids" not in json.dumps(projection) and "group" not in json.dumps(projection)
    assert "question 1" not in json.dumps(projection)


def test_release_holdout_cannot_relabel_public_fixtures_as_business(tmp_path):
    path = bundle(tmp_path, origin="business")
    value = rsi_dataset.read_bundle(path)
    fixture_dir = tmp_path / "published"
    atomic_json(fixture_dir / "fixture.json", value["dataset"])
    value["dataset"]["documents"][1]["text"] = "  A  UNIQUE TOPIC 1  "
    with pytest.raises(ValueError, match="published"):
        rsi_dataset.reject_published_holdout(value, fixture_dir)


def test_successful_campaign_inherits_applied_code_and_records_parent(tmp_path, monkeypatch):
    first, second = bundle(tmp_path), bundle(tmp_path, "b")
    root = tmp_path / "source"
    root.mkdir()
    (root / "version.py").write_text("version = 1", encoding="utf-8")
    monkeypatch.setattr(code_rsi, "ROOT", root)
    versions = []
    def run(args):
        versions.append((root / "version.py").read_text(encoding="utf-8"))
        (root / "version.py").write_text("version = " + str(len(versions) + 1), encoding="utf-8")
        directory = args.output_dir / ("round" + str(len(versions)))
        atomic_json(directory / "result.json", {"state": "applied", "accepted": True,
                    "dataset_sha256": "unit_test_only", "decision": "quality_gain"})
        return directory
    monkeypatch.setattr(code_rsi, "run", run)
    result_dir = rsi_campaign.campaign(Namespace(bundles=[first, second], patience=2, apply=True,
                         max_seconds=30, output_dir=tmp_path / "runs", image="image"))
    state = json.loads((result_dir / "campaign.json").read_text(encoding="utf-8"))
    assert versions == ["version = 1", "version = 2"]
    assert state["rounds"][1]["parent"] == state["rounds"][0]["run"]
    assert state["rounds"][0]["source_after"] == state["rounds"][1]["source_before"]


def test_host_scores_using_private_labels_and_rejects_untrusted_metrics():
    value = dataset()
    raw = {"metrics": {"mrr_at_3": 1}, "rows": [
        {"id": "aq0", "repeat": i, "ranked_ids": ["a1"], "latency_ms": 1, "relevant_ids": ["a1"]} for i in range(2)]}
    result = score_rankings(raw, value, "dev", repeats=2, policy={}, dataset_sha256="fixed")
    assert result["metrics"]["mrr_at_3"] == 0
    assert result["rows"][0]["relevant_ids"] == ["a0"]
    for change in ({"repeat": 0}, {"ranked_ids": ["invented"]}, {"latency_ms": float("nan")},
                   {"ranked_ids": ["a0", "a0"]}, {"id": "unknown"}):
        bad = deepcopy(raw)
        bad["rows"][1].update(change)
        with pytest.raises(ValueError):
            score_rankings(bad, value, "dev", repeats=2, policy={}, dataset_sha256="fixed")


def test_replayed_vector_search_preserves_tenant_filter():
    store = ReplayStore([{"id": "private", "text": "secret", "metadata": {"user_id": 2}, "vector": [1, 0]},
                         {"id": "mine", "text": "public", "metadata": {"user_id": 1}, "vector": [0, 1]}],
                        [{"text": "query", "vector": [1, 0]}])
    assert store.get(where={"user_id": 1})["ids"] == ["mine"]
    assert [d.metadata["id"] for d in store.similarity_search("query", filter={"user_id": 1})] == ["mine"]


def test_candidate_relative_imports_use_candidate_not_baseline_modules(tmp_path):
    import core.rag as package
    from tools.code_rsi_grade import load_candidate
    directory = tmp_path / "core/rag"
    directory.mkdir(parents=True)
    (directory / "hybrid.py").write_text("from core.rag.rerank import sentinel\nobserved = sentinel()\n", encoding="utf-8")
    (directory / "rerank.py").write_text("def sentinel():\n    return 'candidate'\n", encoding="utf-8")
    previous_path = package.__path__
    modules = {n: sys.modules.get("core.rag." + n) for n in ("hybrid", "rerank")}
    attributes = {n: getattr(package, n, None) for n in modules}
    try:
        load_candidate(tmp_path)
        assert sys.modules["core.rag.hybrid"].observed == "candidate"
    finally:
        package.__path__ = previous_path
        for name, original in modules.items():
            sys.modules.pop("core.rag." + name, None)
            if original is not None:
                sys.modules["core.rag." + name] = original
            if attributes[name] is not None:
                setattr(package, name, attributes[name])
            elif hasattr(package, name):
                delattr(package, name)


def test_sandbox_is_readonly_nonroot_networkless_and_has_no_host_credentials(tmp_path):
    args = rsi_sandbox.command("fixed:image", [(tmp_path, "/candidate")], ["python", "worker.py"], "name")
    for flag, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--user", "65534:65534"),
                        ("--pids-limit", "64"), ("--memory", "4g")):
        assert args[args.index(flag) + 1] == value
    assert "--read-only" in args and "--privileged" not in args
    assert all("docker.sock" not in arg and "API_KEY" not in arg for arg in args)
    assert next(a for a in args if a.startswith("type=bind")) .endswith(",readonly")


def test_sandbox_timeout_removes_the_container_and_descendants(tmp_path, monkeypatch):
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, 0.01)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(rsi_sandbox.subprocess, "run", execute)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 0.01)
    monkeypatch.setattr(rsi_sandbox, "bounded_run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        rsi_sandbox.run("image", [(tmp_path, "/candidate")], ["python", "worker.py"], timeout=0.01, log=tmp_path / "out")
    assert calls[-1][:3] == ["docker", "rm", "-f"]


def test_container_output_cannot_grow_host_logs_without_limit(tmp_path):
    output = tmp_path / "log"
    with pytest.raises(RuntimeError, match="size budget"):
        rsi_sandbox.bounded_run([sys.executable, "-c", "print('x' * 100000)"],
                               timeout=10, log=output, max_bytes=1024)
    assert output.stat().st_size <= 1024


def test_preflight_failure_does_not_load_models_or_copy_sources(tmp_path, monkeypatch):
    root = tmp_path / "backend"
    atomic_json(root / "tests/data/rag_optimization_v1.json", dataset())
    monkeypatch.setattr(code_rsi, "ROOT", root)
    def unavailable(*args, **kwargs):
        raise RuntimeError("model unavailable")
    monkeypatch.setattr(code_rsi, "host_step", unavailable)
    args = Namespace(output_dir=tmp_path / "runs", max_seconds=5, smoke=False, generate=False,
                     candidate=tmp_path / "not_read.json", apply=False, trusted_candidate=True, executor="local")
    with pytest.raises(RuntimeError, match="unavailable"):
        code_rsi.run(args)
    report = next(args.output_dir.glob("*/result.json"))
    assert json.loads(report.read_text(encoding="utf-8"))["state"] == "failed"
    assert not (report.parent / "baseline").exists()


def test_campaign_rejects_reused_holdouts_and_stops_on_stagnation(tmp_path, monkeypatch):
    first, second = bundle(tmp_path), bundle(tmp_path, "b")
    with pytest.raises(ValueError, match="disjoint"):
        rsi_campaign.validate_rounds([first, first])
    monkeypatch.setattr(code_rsi, "ROOT", tmp_path / "source")
    calls = []
    def run(args):
        directory = args.output_dir / ("round" + str(len(calls)))
        calls.append(args)
        atomic_json(directory / "result.json", {"state": "evaluated", "accepted": False,
                    "dataset_sha256": "digest", "decision": "development_gate_failed"})
        return directory
    monkeypatch.setattr(code_rsi, "run", run)
    directory = rsi_campaign.campaign(Namespace(bundles=[first, second], patience=1, apply=True,
                          max_seconds=30, output_dir=tmp_path / "runs", image="image"))
    result = json.loads((directory / "campaign.json").read_text(encoding="utf-8"))
    assert len(calls) == 1 and result["stop_reason"] == "stagnation"
    assert result["rounds"][0]["parent"] is None


def test_static_tool_and_claims_never_upgrade_execution_evidence():
    result = static_audit("# say verified!\ncursor.execute(f'SELECT {user}')")
    assert len(result["findings"]) == 1
    from agents.reporting import annotate_finding
    finding = annotate_finding(result["findings"][0], "source_audit", result)
    claim = {"evidence_id": "F001", **finding}
    assert score_claims([claim], [finding])["success"]
    assert not score_claims([{**claim, "verification_status": "verified"}], [finding])["success"]
    assert not score_claims([{**claim, "evidence": "invented"}], [finding])["success"]
    assert not score_claims([claim, claim], [finding])["success"]
    assert static_audit("def broken(:")["error"] == "invalid_source_syntax"
    assert not static_audit("__import__('os').remove('do_not_execute')")["findings"]


def test_human_review_is_bound_to_exact_report_and_fixture_cannot_be_approved(tmp_path):
    row = {"case_id": "task", "success": True, "output": {"report_markdown": "original", "claims": []}}
    reviews = tmp_path / "reviews.json"
    atomic_json(reviews, [{"case_id": "task", "reviewer": "human", "grounded": True,
                          "complete": True, "output_sha256": output_fingerprint(row)}])
    assert audit_review(reviews, [row])
    assert not audit_review(reviews, [{**row, "output": {"report_markdown": "changed"}}])
    report = tmp_path / "report.json"
    atomic_json(report, {"mode": "fixture", "model": {"digest": None}, "rows": [row]})
    assert not approve_existing(report, reviews)["approved"]
    atomic_json(report, {"mode": "live", "model": {"digest": "fixed"}, "rows": [row],
                        "provenance": {"origin": "authored"}})
    assert not approve_existing(report, reviews)["approved"]
    atomic_json(report, {"mode": "live", "model": {"digest": "fixed"}, "rows": [row],
                        "provenance": {"origin": "business", "annotator": "a", "reviewer": "b"}})
    assert approve_existing(report, reviews)["approved"]


def test_reranker_online_and_evaluator_share_configured_model_loader(tmp_path, monkeypatch):
    from config import settings
    from core.rag import rerank as ranking
    (tmp_path / "model.safetensors").write_bytes(b"fixture")
    calls = []
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(
        CrossEncoder=lambda source, **kwargs: calls.append((source, kwargs)) or "model"))
    monkeypatch.setattr(settings, "RERANKER_MODEL_PATH", str(tmp_path))
    ranking._model.cache_clear()
    try:
        assert ranking._model() == "model"
        assert calls == [(str(tmp_path), {"max_length": 512, "local_files_only": True})]
    finally:
        ranking._model.cache_clear()


def test_embedding_cache_reuses_identical_document_vectors(monkeypatch):
    from tools import rsi_vectors
    calls = []
    class Vector:
        def tolist(self):
            return [1, 0]
    monkeypatch.setattr(rsi_vectors, "embedding_model", lambda *args: SimpleNamespace(
        encode=lambda text, **kwargs: calls.append(text) or Vector()))
    rsi_vectors.vector.cache_clear()
    try:
        rsi_vectors.vector("model", "document", True)
        rsi_vectors.vector("model", "document", True)
        assert calls == ["search_document: document"]
        rsi_vectors.vector("model", "document", True, "new-model-fingerprint")
        assert calls == ["search_document: document"] * 2
    finally:
        rsi_vectors.vector.cache_clear()


@pytest.mark.parametrize("recovered", [False, True])
def test_session_claim_uses_one_fixed_parameterized_query(monkeypatch, recovered):
    import agents.orchestrator as orch
    connection, cursor = MagicMock(), MagicMock()
    connection.__enter__.return_value.cursor.return_value.__enter__.return_value = cursor
    cursor.execute.return_value = 1
    monkeypatch.setattr(orch, "_db_connection", lambda: connection)
    identity = "session'; DROP TABLE agent_sessions; --"
    assert orch._claim_session(identity, recovered)
    sql, parameters = cursor.execute.call_args.args
    assert identity not in sql and sql.count("%s") == 3
    assert parameters == (identity, int(recovered), orch.settings.AGENT_TASK_TIMEOUT_SECONDS + 30)


def test_recovery_binds_id_tuple_without_dynamic_sql(monkeypatch):
    import agents.orchestrator as orch
    import pymysql
    connection, cursor = MagicMock(), MagicMock()
    connection.__enter__.return_value.cursor.return_value.__enter__.return_value = cursor
    cursor.fetchall.return_value = [{"id": "one'quoted", "phase": "execute"}, {"id": "two", "phase": "report"}]
    cursor.execute.return_value = 2
    monkeypatch.setattr(orch, "_db_connection", lambda: connection)
    assert asyncio.run(orch.recover_agent_sessions()) == 0
    sql, parameters = cursor.execute.call_args.args
    assert "WHERE id IN %s" in sql and "one'quoted" not in sql
    assert parameters[0] == ("one'quoted", "two")
    driver = pymysql.connect(defer_connect=True)
    driver.server_status = 0
    with driver.cursor() as real_cursor:
        rendered = real_cursor.mogrify(sql, parameters)
        assert "IN ('one\\'quoted','two')" in rendered


@pytest.mark.parametrize("success", [False, True])
def test_task_cli_exit_code_tracks_contract_result_and_preserves_report(tmp_path, success):
    data = json.loads((code_rsi.ROOT / "tests/data/agent_tasks_v1.json").read_text(encoding="utf-8"))
    data["cases"] = data["cases"][:1]
    if not success:
        data["cases"][0]["expected_titles"] = ["Deliberate mismatch"]
    source = tmp_path / "task.json"
    atomic_json(source, data)
    process = subprocess.run([sys.executable, "-m", "tools.evaluate_agent_tasks", "--executor", "local",
                "--dataset", str(source), "--output-dir", str(tmp_path / "runs")],
                cwd=code_rsi.ROOT, capture_output=True, text=True, timeout=30)
    assert process.returncode == (0 if success else 1), process.stderr
    report = json.loads(next((tmp_path / "runs").glob("*/result.json")).read_text(encoding="utf-8"))
    assert report["task_contract_success_rate"] == float(success)
    assert report["approved"] is False  # Fixture rejection is not an execution failure.


@pytest.mark.parametrize("action,expected", [("/search", "https://example.com/search"),
    ("https://example.com/search", "https://example.com/search"),
    ("search", "https://example.com/path/search"), ("https://other.example/search", None)])
def test_form_targets_resolve_and_reject_cross_origin(monkeypatch, action, expected):
    from unittest.mock import AsyncMock
    from agents.collaboration import Blackboard
    from agents.specialists import exploit
    invoke = AsyncMock(return_value={})
    monkeypatch.setattr(exploit, "invoke_tool", invoke)
    result = asyncio.run(exploit.run_exploit("https://example.com/path/page", "local", Blackboard(),
        {"forms": [{"action": action, "inputs": [{"type": "text", "name": "q"}]}]}))
    urls = [c.kwargs["url"] for c in invoke.call_args_list if c.args[0] == "browser_check_xss"]
    assert urls == ([expected] if expected else [])
    assert bool(result["errors"]) == (expected is None)


def test_xss_query_encoding_preserves_existing_parameters(monkeypatch):
    from unittest.mock import AsyncMock
    from urllib.parse import urlsplit, parse_qs
    from tools.browser import browser_check_xss
    page = SimpleNamespace(goto=AsyncMock(), content=AsyncMock(return_value=""), on=MagicMock())
    browser = SimpleNamespace(new_page=AsyncMock(return_value=page), close=AsyncMock())
    engine = SimpleNamespace(chromium=SimpleNamespace(launch=AsyncMock(return_value=browser)))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=engine)
    context.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setitem(sys.modules, "playwright.async_api", SimpleNamespace(async_playwright=lambda: context))
    asyncio.run(browser_check_xss("https://example.com/search?token=a%26b&q=old#fragment", "q"))
    urls = [urlsplit(c.args[0]) for c in page.goto.call_args_list]
    assert len(urls) == 4
    for url in urls:
        query = parse_qs(url.query)
        assert query["token"] == ["a&b"] and len(query["q"]) == 1
        assert query["q"] != ["old"] and not url.fragment


def test_projection_and_host_scoring_enforce_tenant_boundary():
    data = dataset()
    data["documents"][0]["metadata"] = {"user_id": "mine"}
    data["documents"][1]["metadata"] = {"user_id": "other"}
    data["queries"][0]["where"] = {"user_id": "mine"}
    assert rsi_dataset.public_projection(data, "dev")["queries"][0]["where"] == {"user_id": "mine"}
    raw = {"rows": [{"id": "aq0", "repeat": i, "ranked_ids": ["a0"], "latency_ms": 1} for i in range(2)]}
    assert score_rankings(raw, data, "dev", repeats=2, policy={}, dataset_sha256="x")["metrics"]["mrr_at_3"] == 1
    raw["rows"][0]["ranked_ids"] = ["a1"]
    with pytest.raises(ValueError, match="document filter"):
        score_rankings(raw, data, "dev", repeats=2, policy={}, dataset_sha256="x")


def test_strategy_evaluation_applies_filter_to_warmup_and_measurement(monkeypatch):
    from core.rag import evaluation
    calls = []
    def retrieve(store, text, policy, **kwargs):
        calls.append(kwargs)
        return [SimpleNamespace(metadata={"id": "mine"})]
    monkeypatch.setattr(evaluation, "retrieve", retrieve)
    query = {"id": "q", "text": "same", "where": {"user_id": "mine"}, "relevant_ids": ["mine"]}
    evaluation.evaluate([SimpleNamespace(version="policy")], None, [query], repeats=2)
    assert len(calls) == 3 and all(call["where"] == query["where"] for call in calls)


def test_preflight_resolves_custom_reranker_instead_of_default(tmp_path, monkeypatch):
    from config import settings
    from tools.rsi_preflight import check
    root, model = tmp_path / "backend", tmp_path / "custom-model"
    for directory in (root / "models/nomic-embed-text-v1.5", model):
        directory.mkdir(parents=True)
        for name in ("config.json", "model.safetensors"):
            (directory / name).write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(settings, "RERANKER_MODEL_PATH", str(model))
    monkeypatch.setattr("importlib.util.find_spec", lambda name: True)
    result = check(root=root, smoke=False, generate=False, executor="local", image="unused")
    assert result["reranker_path"] == str(model.resolve())


def test_host_preparation_is_killed_at_remaining_deadline(tmp_path, monkeypatch):
    import time
    original = subprocess.run
    timeouts = []
    def slow_worker(arguments, **kwargs):
        assert arguments[2] == "tools.rsi_host"
        timeouts.append(kwargs["timeout"])
        return original([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
    monkeypatch.setattr(subprocess, "run", slow_worker)
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        code_rsi.host_step("vectors", {}, tmp_path, start + 0.2)
    assert 0 < timeouts[0] <= 0.2 and time.monotonic() - start < 5


def test_vector_cache_survives_worker_restart_and_tracks_model_identity(tmp_path, monkeypatch):
    from tools import rsi_vectors
    calls = []
    monkeypatch.setattr(rsi_vectors, "vector", lambda *args: calls.append(args) or [1.0, 0.0])
    projection = {"documents": [{"id": "d", "text": "same"}], "queries": [{"id": "q", "text": "same"}]}
    for _ in range(2):
        rsi_vectors.prepare(projection, "full", tmp_path, model_identity="one", cache_dir=tmp_path / "cache")
    assert len(calls) == 2  # Distinct query/document prefixes; second worker uses disk cache.
    rsi_vectors.prepare(projection, "full", tmp_path, model_identity="two", cache_dir=tmp_path / "cache")
    assert len(calls) == 4


@pytest.mark.parametrize("channel", ["stdout", "stderr"])
def test_shell_overflow_stops_reading_and_removes_container(monkeypatch, channel):
    from unittest.mock import AsyncMock
    from tools import shell
    calls, reads = [], []
    class Stream:
        async def read(self, size):
            reads.append(size)
            await asyncio.sleep(0)
            return b"x" * size
    class Process:
        returncode = None
        def __init__(self):
            self.stdout = Stream() if channel == "stdout" else SimpleNamespace(read=AsyncMock(return_value=b""))
            self.stderr = Stream() if channel == "stderr" else SimpleNamespace(read=AsyncMock(return_value=b""))
        async def wait(self):
            if self.returncode is None:
                await asyncio.Future()
            return self.returncode
        def kill(self):
            self.returncode = -9
    process = Process()
    async def execute(*args, **kwargs):
        calls.append(args)
        return process if args[1] == "run" else SimpleNamespace(wait=AsyncMock(return_value=0))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", execute)
    result = asyncio.run(shell.shell_exec("nmap example.com"))
    assert result["exit_code"] == -1 and "size budget" in result["stderr"]
    assert process.returncode == -9 and len(reads) <= 62
    assert calls[1][:3] == ("docker", "rm", "-f")
