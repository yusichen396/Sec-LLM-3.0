"""Candidate worker: return rankings only. Ground-truth labels stay on the host."""
import argparse
import importlib
import json
import math
from pathlib import Path
import statistics
import sys
import time

from langchain_core.documents import Document


class ReplayStore:
    def __init__(self, documents, queries):
        self.documents = documents
        self.queries = {q["text"]: q.get("vector") for q in queries}
        self._collection_name = "rsi_replay"

    def _documents(self, where):
        return [d for d in self.documents if all(d.get("metadata", {}).get(k) == v for k, v in (where or {}).items())]

    def get(self, *, where=None, include=None):
        docs = self._documents(where)
        return {"ids": [d["id"] for d in docs], "documents": [d["text"] for d in docs],
                "metadatas": [{**d.get("metadata", {}), "id": d["id"]} for d in docs]}

    def similarity_search_with_score(self, query, k=8, filter=None):
        vector = self.queries[query]
        if vector is None:
            raise ValueError("Vector retrieval is unavailable in smoke mode")
        pairs = [(Document(page_content=d["text"], metadata={**d.get("metadata", {}), "id": d["id"]}),
                  1 - sum(a * b for a, b in zip(vector, d["vector"]))) for d in self._documents(filter)]
        return sorted(pairs, key=lambda item: item[1])[:k]

    def similarity_search(self, query, k=8, filter=None):
        return [doc for doc, _ in self.similarity_search_with_score(query, k, filter)]


def load_candidate(root):
    # Relative imports between the changed modules must resolve like the installed candidate.
    import core.rag
    core.rag.__path__ = [str(root / "core/rag"), *core.rag.__path__]
    for name in ("hybrid", "rerank"):
        sys.modules.pop("core.rag." + name, None)
        if hasattr(core.rag, name):
            delattr(core.rag, name)
    for name in ("hybrid", "rerank"):
        importlib.import_module("core.rag." + name)


def grade(request, candidate_root):
    load_candidate(candidate_root)
    from core.rag.policy import RetrievalPolicy, retrieve

    policy = RetrievalPolicy(**request["policy"])
    store = ReplayStore(request["documents"], request["queries"])
    queries = request["queries"]
    retrieve(store, queries[0]["text"], policy, strict=True)
    rows = []
    for repeat in range(request["repeats"]):
        for query in queries:
            started = time.perf_counter()
            docs = retrieve(store, query["text"], policy, where=query.get("where"), strict=True)
            rows.append({"id": query["id"], "repeat": repeat,
                         "ranked_ids": [d.metadata["id"] for d in docs],
                         "latency_ms": (time.perf_counter() - started) * 1000})
    return {"rows": rows}


def score_rankings(raw, data, split, *, repeats, policy, dataset_sha256):
    """Trusted host scoring, including strict validation of untrusted worker output."""
    from core.rag.evaluation import summarize
    from tools.optimize_rag import safety_regression

    gold = {q["id"]: q for q in data["queries"] if q["split"] == split}
    documents = {d["id"] for d in data["documents"]}
    rows = raw.get("rows")
    if not isinstance(rows, list) or len(rows) != len(gold) * repeats:
        raise ValueError("Worker omitted or added evaluation cases")
    seen, scored = set(), []
    for row in rows:
        identity = (row.get("id"), row.get("repeat"))
        ids, latency = row.get("ranked_ids"), row.get("latency_ms")
        if (identity in seen or identity[0] not in gold or type(identity[1]) is not int
                or not 0 <= identity[1] < repeats or not isinstance(ids, list) or len(ids) > 3
                or not all(isinstance(i, str) and i in documents for i in ids) or len(set(ids)) != len(ids)
                or type(latency) not in (float, int) or not math.isfinite(latency) or latency < 0):
            raise ValueError("Invalid worker ranking, identity or latency")
        seen.add(identity)
        scored.append({**row, "relevant_ids": gold[row["id"]]["relevant_ids"]})
    return {"metrics": summarize(scored), "rows": scored, "policy": policy, "dataset_sha256": dataset_sha256,
            "per_repeat": [summarize([r for r in scored if r["repeat"] == n]) for n in range(repeats)],
            "median_latency_ms": statistics.median(r["latency_ms"] for r in scored),
            "safety": safety_regression(), "latency_scope": "retrieval_and_rerank_over_precomputed_vectors"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--candidate-root", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_text(encoding="utf-8"))
    result = grade(request, args.candidate_root)
    if args.output:
        from tools.optimize_rag import atomic_json
        atomic_json(args.output, result)
    else:
        print("RSI_RESULT=" + json.dumps(result, ensure_ascii=False), flush=True)
