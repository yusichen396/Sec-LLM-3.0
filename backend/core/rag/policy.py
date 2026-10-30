"""Bounded retrieval settings shared by serving and offline optimization."""
from dataclasses import asdict, dataclass
import hashlib
import json
import logging
from pathlib import Path

ACTIVE_POLICY = Path(__file__).resolve().parents[2] / "data" / "rag_optimization" / "active.json"

@dataclass(frozen=True)
class RetrievalPolicy:
    strategy: str = "hybrid"
    candidate_k: int = 8
    rerank: bool = True
    rrf_k: int = 60
    vector_weight: float = 1.0
    bm25_k1: float = 1.5
    bm25_b: float = 0.75

    def __post_init__(self):
        if self.strategy not in ("vector", "hybrid", "bm25"):
            raise ValueError("Unknown retrieval strategy")
        if type(self.candidate_k) is not int or not 3 <= self.candidate_k <= 32:
            raise ValueError("candidate_k must be an integer in [3, 32]")
        if type(self.rerank) is not bool or type(self.rrf_k) is not int or not 1 <= self.rrf_k <= 100:
            raise ValueError("Invalid rerank or rrf_k")
        if not 0.1 <= self.vector_weight <= 4 or not 0.1 <= self.bm25_k1 <= 3 or not 0 <= self.bm25_b <= 1:
            raise ValueError("Retrieval weights outside allowed bounds")

    @property
    def version(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()[:12]


def load_policy(path: Path | None, default: RetrievalPolicy) -> RetrievalPolicy:
    path = path if path is not None else ACTIVE_POLICY
    if not path.exists():
        return default
    try:
        return RetrievalPolicy(**json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        logging.exception("Invalid RAG policy %s; using configured baseline", path)
        return default


def retrieve(store, query: str, policy: RetrievalPolicy, *, where=None, strict=False):
    from core.rag.hybrid import hybrid_search
    from core.rag.rerank import rerank

    if policy.strategy == "vector":
        docs = store.similarity_search(query, k=policy.candidate_k, filter=where)
    else:
        docs = [doc for doc, _ in hybrid_search(
            store, query, k=policy.candidate_k, where=where,
            rrf_k=policy.rrf_k,
            vector_weight=policy.vector_weight if policy.strategy == "hybrid" else 0,
            bm25_k1=policy.bm25_k1, bm25_b=policy.bm25_b,
            strict=strict,
        )]
    return rerank(query, docs, limit=3, strict=strict) if policy.rerank else docs[:3]
