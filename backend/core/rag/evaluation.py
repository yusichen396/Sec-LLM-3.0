"""Frozen split validation and top-three retrieval measurements."""
import hashlib
import json
import statistics
import time
from pathlib import Path

from core.rag.policy import retrieve


def summarize(rows, key="ranked_ids"):
    if not rows:
        raise ValueError("Cannot score an empty evaluation set")
    ranks = [next((i + 1 for i, doc_id in enumerate(row[key][:3])
                   if doc_id in row["relevant_ids"]), None) for row in rows]
    return {
        "hit_at_1": sum(rank == 1 for rank in ranks) / len(ranks),
        "hit_at_3": sum(rank is not None for rank in ranks) / len(ranks),
        "mrr_at_3": sum(1 / rank for rank in ranks if rank is not None) / len(ranks),
    }


def load_dataset(path: Path):
    raw = path.read_bytes()
    data = json.loads(raw)
    docs, queries = data["documents"], data["queries"]
    doc_ids = {doc["id"] for doc in docs}
    if not docs or len(doc_ids) != len(docs) or not all(doc["text"].strip() for doc in docs):
        raise ValueError("Documents must have unique IDs and nonempty text")
    ids, texts, groups, labels = set(), set(), {}, {}
    for q in queries:
        text = " ".join(q["text"].lower().split())
        if not text or q["id"] in ids or text in texts:
            raise ValueError("Queries must have unique IDs and normalized text")
        ids.add(q["id"])
        texts.add(text)
        split = q["split"]
        if split not in ("dev", "validation", "test") or not q["relevant_ids"] or not set(q["relevant_ids"]) <= doc_ids:
            raise ValueError("Invalid split or relevance labels")
        group = q["group"]
        if groups.setdefault(group, split) != split:
            raise ValueError("A topic group occurs in multiple splits")
        for doc_id in q["relevant_ids"]:
            if labels.setdefault(doc_id, split) != split:
                raise ValueError("A relevance topic occurs in multiple splits")
    if set(groups.values()) != {"dev", "validation", "test"}:
        raise ValueError("All three nonempty splits are required")
    return data, hashlib.sha256(raw).hexdigest()


def evaluate(policies, store, queries, repeats=3):
    """Warm every policy, rotate execution order, and time the entire retrieval path."""
    if not queries or repeats < 2:
        raise ValueError("Evaluation requires queries and at least two repeats")
    for policy in policies:
        retrieve(store, queries[0]["text"], policy, strict=True)
    rows = {policy.version: [] for policy in policies}
    for repeat in range(repeats):
        for index, q in enumerate(queries):
            offset = (repeat + index) % len(policies)
            for policy in policies[offset:] + policies[:offset]:
                start = time.perf_counter()
                docs = retrieve(store, q["text"], policy, strict=True)
                elapsed = (time.perf_counter() - start) * 1000
                rows[policy.version].append({
                    "id": q["id"], "repeat": repeat,
                    "relevant_ids": q["relevant_ids"],
                    "ranked_ids": [doc.metadata["id"] for doc in docs],
                    "latency_ms": elapsed,
                })
    return {version: {
        "metrics": summarize(items),
        "per_repeat": [summarize([row for row in items if row["repeat"] == r]) for r in range(repeats)],
        "median_latency_ms": statistics.median(row["latency_ms"] for row in items),
        "rows": items,
        "retrieval_requests": len(items) + 1,
    } for version, items in rows.items()}
