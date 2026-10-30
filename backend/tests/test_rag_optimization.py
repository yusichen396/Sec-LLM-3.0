from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from core.rag.evaluation import evaluate, load_dataset, summarize
from core.rag.policy import RetrievalPolicy, load_policy, retrieve
from tools import optimize_rag as opt


def test_top_three_metrics_ignore_a_correct_fourth_result():
    row = {"ranked_ids": ["a", "b", "c", "answer"], "relevant_ids": ["answer"]}
    assert summarize([row]) == {"hit_at_1": 0, "hit_at_3": 0, "mrr_at_3": 0}
    row["ranked_ids"] = ["a", "b", "answer"]
    assert summarize([row])["mrr_at_3"] == 1 / 3


def test_frozen_dataset_rejects_cross_split_topic_leakage(tmp_path):
    data, digest = load_dataset(opt.DATASET)
    assert len(digest) == 64
    moved = next(q for q in data["queries"] if q["split"] == "dev")
    moved["split"] = "test"
    path = tmp_path / "leaked.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="multiple splits"):
        load_dataset(path)


def test_serving_policy_preserves_user_filter_and_top_three(monkeypatch):
    documents = [{"id": str(i), "text": "SQL query " + str(i)} for i in range(8)]
    store = opt.LexicalStore(documents)
    original = store.get
    filters = []

    def get(*, where=None, include=None):
        filters.append(where)
        got = original(include=include)
        selected = slice(0, 4) if where == {"user_id": "7"} else slice(4, 8)
        return {key: value[selected] for key, value in got.items()}

    monkeypatch.setattr(store, "get", get)
    docs = retrieve(store, "SQL query", RetrievalPolicy(strategy="bm25", rerank=False),
                    where={"user_id": "7"}, strict=True)
    assert len(docs) == 3
    assert all(int(doc.metadata["id"]) < 4 for doc in docs)
    assert filters and all(f == {"user_id": "7"} for f in filters)
    # Same collection, another user: the cached sparse index must not be shared.
    other_docs = retrieve(store, "SQL query", RetrievalPolicy(strategy="bm25", rerank=False), where={"user_id": "8"})
    assert all(int(doc.metadata["id"]) >= 4 for doc in other_docs)


def test_evaluation_fails_instead_of_scoring_vector_fallback(monkeypatch):
    class BrokenStore(opt.LexicalStore):
        def similarity_search_with_score(self, *args, **kwargs):
            raise RuntimeError("embedding offline")

    with pytest.raises(RuntimeError, match="embedding offline"):
        retrieve(BrokenStore([{"id": "a", "text": "SQL"}]), "SQL", RetrievalPolicy(rerank=False), strict=True)


def test_uploaded_documents_without_metadata_id_still_use_vector_recall():
    from langchain_core.documents import Document

    class UploadedStore(opt.LexicalStore):
        def get(self, *, where=None, include=None):
            got = super().get(include=include)
            got["metadatas"] = [{}, {}]
            return got

        def similarity_search_with_score(self, query, *, k, filter):
            assert filter == {"user_id": "7"}
            return [(Document(id="semantic", page_content="semantic result"), 0.1)]

    store = UploadedStore([{"id": "semantic", "text": "semantic result"}, {"id": "keyword", "text": "SQL query"}])
    docs = retrieve(store, "SQL", RetrievalPolicy(rerank=False, vector_weight=4), where={"user_id": "7"}, strict=True)
    assert docs[0].metadata["id"] == "semantic"


def test_reranker_strict_mode_propagates_failure(monkeypatch):
    import core.rag.rerank as reranking

    def fail():
        raise RuntimeError("reranker offline")

    monkeypatch.setattr(reranking, "_model", fail)
    with pytest.raises(RuntimeError, match="reranker offline"):
        reranking.rerank("query", [SimpleNamespace(page_content="doc")], strict=True)


def test_activation_rejects_smoke_runs_and_stale_baseline(tmp_path, monkeypatch):
    baseline = RetrievalPolicy()
    candidate = replace(baseline, candidate_k=12)
    path = tmp_path / "active.json"
    report = {"mode": "lexical", "accepted": True, "candidate": asdict(candidate)}
    with pytest.raises(ValueError, match="full-model"):
        opt.activate(report, path, baseline)
    assert not path.exists()
    report["mode"] = "full"
    opt.activate(report, path, baseline)
    assert load_policy(path, baseline) == candidate
    assert json.loads(path.with_suffix(".previous.json").read_text())["candidate_k"] == 8
    with pytest.raises(ValueError, match="baseline changed"):
        opt.activate(report, path, baseline)
    import sys
    from config import settings
    monkeypatch.setattr(settings, "RAG_POLICY_PATH", str(path))
    monkeypatch.setattr(sys, "argv", ["optimize_rag", "--rollback"])
    assert opt.main() == 0
    assert load_policy(path, candidate) == baseline


def test_bad_policy_keeps_baseline(tmp_path):
    path = tmp_path / "active.json"
    path.write_text('{"candidate_k": 1000}', encoding="utf-8")
    assert load_policy(path, RetrievalPolicy()) == RetrievalPolicy()
    with pytest.raises(ValueError):
        RetrievalPolicy(bm25_b=float("nan"))


def test_candidate_rejected_on_quality_latency_or_safety_regression(monkeypatch):
    baseline = RetrievalPolicy(strategy="bm25", rerank=False)
    candidate = replace(baseline, bm25_b=0.0)
    data = {"queries": [{"id": split, "text": split, "relevant_ids": [split], "split": split}
                        for split in ("dev", "validation", "test")]}
    monkeypatch.setattr(opt, "propose", lambda *args: [candidate])
    monkeypatch.setattr(opt, "safety_regression", lambda: {"passed": True})
    stages = []
    test_score = 0.4

    def result(score, latency=1):
        return {"metrics": {key: score for key in ("hit_at_1", "hit_at_3", "mrr_at_3")},
                "per_repeat": [{"mrr_at_3": score}] * 2, "median_latency_ms": latency,
                "rows": [{"id": "dev", "ranked_ids": ["wrong"], "relevant_ids": ["dev"]}]}

    def fake_evaluate(policies, store, queries, repeats):
        stage = queries[0]["split"]
        stages.append((stage, [p.version for p in policies]))
        return {p.version: result(0.5 if p == baseline else (test_score if stage == "test" else 0.8)) for p in policies}

    monkeypatch.setattr(opt, "evaluate", fake_evaluate)
    report = opt.run_search(None, data, baseline, repeats=2, min_gain=0.01, max_latency_ratio=1.5)
    assert report["decision"] == "test_regression"
    assert not report["accepted"]
    assert [stage for stage, _ in stages] == ["dev", "dev", "validation", "test"]
    assert not opt.qualifies(result(0.5), result(0.8, latency=2), min_gain=0.01, max_latency_ratio=1.5)
    test_score = 0.8
    report = opt.run_search(None, data, baseline, repeats=2, min_gain=0.01, max_latency_ratio=1.5)
    assert report["accepted"]
    assert report["decision"] == "validation_gain"
    monkeypatch.setattr(opt, "safety_regression", lambda: {"passed": False})
    report = opt.run_search(None, data, baseline, repeats=2, min_gain=0.01, max_latency_ratio=1.5)
    assert not report["accepted"]


def test_cpu_evaluation_repeats_and_records_all_queries():
    docs = [{"id": "sql", "text": "SQL parameter query"}, {"id": "cookie", "text": "Cookie session"}]
    policy = RetrievalPolicy(strategy="bm25", rerank=False)
    queries = [{"id": "q1", "text": "SQL", "relevant_ids": ["sql"]}]
    result = evaluate([policy], opt.LexicalStore(docs), queries, repeats=2)[policy.version]
    assert result["metrics"]["hit_at_1"] == 1
    assert len(result["rows"]) == 2
    assert len(result["per_repeat"]) == 2
