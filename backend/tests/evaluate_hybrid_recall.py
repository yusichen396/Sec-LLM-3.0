"""四路召回对比：向量 / BM25 / 混合(RRF) / 混合+重排。

在 backend/ 下运行：
    python -m tests.evaluate_hybrid_recall --local-embedding-model models/nomic-embed-text-v1.5
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

from core.rag.evaluation import summarize

DATASET = Path(__file__).parent / "data" / "rag_retrieval_eval.json"


def load(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    docs, queries = data["documents"], data["queries"]
    assert len(docs) >= 20 and len(queries) >= 20
    return docs, queries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", type=Path, default=DATASET)
    ap.add_argument("--local-embedding-model", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--query-prefix", default="", help="查询侧指令前缀（BGE 中文模型需要）")
    ap.add_argument("--doc-prefix", default="", help="文档侧前缀（nomic 需要 search_document: ）")
    ap.add_argument("--chunk-size", type=int, default=0, help="按字符切分文档，0 表示不切分")
    ap.add_argument("--chunk-overlap", type=int, default=0)
    args = ap.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from langchain_chroma import Chroma

    from config import settings
    from core.rag.hybrid import BM25Index, hybrid_search
    from core.rag.rerank import _model, rerank

    documents, queries = load(args.dataset)

    if args.local_embedding_model:
        from langchain_core.embeddings import Embeddings
        from sentence_transformers import SentenceTransformer

        class LocalNomic(Embeddings):
            def __init__(self):
                self.m = SentenceTransformer(str(args.local_embedding_model), trust_remote_code=True)

            def embed_documents(self, texts):
                return self.m.encode([args.doc_prefix + t for t in texts],
                                     normalize_embeddings=True).tolist()

            def embed_query(self, text):
                return self.m.encode(args.query_prefix + text,
                                     normalize_embeddings=True).tolist()

        embeddings = LocalNomic()
        emb_src = str(args.local_embedding_model)
    else:
        from langchain_ollama import OllamaEmbeddings
        embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=settings.OLLAMA_BASE_URL)
        emb_src = "ollama:nomic-embed-text"

    _model()  # 提前加载重排模型，避免把加载时间算进延迟

    def split_chunks(text: str) -> list[str]:
        size = args.chunk_size
        if size <= 0 or len(text) <= size:
            return [text]
        step = max(1, size - args.chunk_overlap)
        return [text[i:i + size] for i in range(0, len(text), step)]

    chunk_texts: list[str] = []
    chunk_meta: list[dict] = []
    chunk_ids: list[str] = []
    chunk_to_doc: dict[str, str] = {}
    for doc in documents:
        for index, piece in enumerate(split_chunks(doc["text"])):
            cid = f"{doc['id']}#{index}"
            chunk_ids.append(cid)
            chunk_texts.append(piece)
            chunk_meta.append({"id": doc["id"], "chunk": index})
            chunk_to_doc[cid] = doc["id"]

    store = Chroma.from_texts(
        chunk_texts,
        embedding=embeddings,
        metadatas=chunk_meta,
        collection_name=f"hybrid_eval_{uuid.uuid4().hex}",
    )

    sparse = BM25Index(chunk_ids, chunk_texts)

    def unique_docs(hit_chunk_ids: list[str], limit: int = 8) -> list[str]:
        seen: list[str] = []
        for cid in hit_chunk_ids:
            doc_id = chunk_to_doc.get(cid, cid)
            if doc_id not in seen:
                seen.append(doc_id)
            if len(seen) >= limit:
                break
        return seen

    rows, lat = [], {"vector": [], "bm25": [], "hybrid": [], "hybrid_rerank": []}
    try:
        for q in queries:
            t0 = time.perf_counter()
            vec = store.similarity_search(q["text"], k=8)
            lat["vector"].append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            bm = sparse.search(q["text"], 8)
            lat["bm25"].append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            hy = hybrid_search(store, q["text"], k=8)
            lat["hybrid"].append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            rer = rerank(q["text"], [d for d, _ in hy], strict=True)
            lat["hybrid_rerank"].append(lat["hybrid"][-1] + (time.perf_counter() - t0) * 1000)

            rows.append({
                "id": q["id"],
                "relevant_ids": q["relevant_ids"],
                "vector": unique_docs([(d.metadata or {}).get("id", "") for d in vec]),
                "bm25": unique_docs(bm),
                "hybrid": unique_docs([(d.metadata or {}).get("id", "") for d, _ in hy]),
                "hybrid_rerank": unique_docs([(d.metadata or {}).get("id", "") for d in rer]),
            })
    finally:
        store.delete_collection()

    result = {
        "dataset": args.dataset.name,
        "document_count": len(documents),
        "query_count": len(queries),
        "embedding_source": emb_src,
        "query_prefix": args.query_prefix,
        "doc_prefix": args.doc_prefix,
        "chunk_size": args.chunk_size,
        "chunk_overlap": args.chunk_overlap,
        "hit_rate": {k: summarize(rows, k) for k in ("vector", "bm25", "hybrid", "hybrid_rerank")},
        "median_latency_ms": {k: round(statistics.median(v), 1) for k, v in lat.items()},
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.output:
        args.output.write_text(json.dumps({**result, "rows": rows}, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
