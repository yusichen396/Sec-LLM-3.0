"""Compare the app's vector retrieval with and without BGE reranking.

Run from backend/: python -m tests.evaluate_rag_rerank
Check labels only: python -m tests.evaluate_rag_rerank --check
"""
import argparse
import json
import statistics
import time
import uuid
from pathlib import Path

from core.rag.evaluation import summarize


DATASET = Path(__file__).parent / "data" / "rag_retrieval_eval.json"


def load_dataset():
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    documents = data["documents"]
    queries = data["queries"]
    document_ids = [item["id"] for item in documents]
    query_ids = [item["id"] for item in queries]
    assert len(document_ids) == len(set(document_ids)) and len(documents) >= 20
    assert len(query_ids) == len(set(query_ids)) and len(queries) >= 20
    assert all(item["text"].strip() for item in documents + queries)
    assert all(set(item["relevant_ids"]) <= set(document_ids) and item["relevant_ids"]
               for item in queries)
    return documents, queries


def evaluate(documents, queries, local_embedding_model=None):
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaEmbeddings

    from config import settings
    from core.rag.rerank import _model, rerank

    # Fail before measuring if the reranker is unavailable; do not count fallback as model output.
    _model()
    if local_embedding_model:
        from langchain_core.embeddings import Embeddings
        from sentence_transformers import SentenceTransformer

        class LocalNomicEmbeddings(Embeddings):
            def __init__(self):
                self.model = SentenceTransformer(str(local_embedding_model), trust_remote_code=True)

            def embed_documents(self, texts):
                return self.model.encode(["search_document: " + text for text in texts], normalize_embeddings=True).tolist()

            def embed_query(self, text):
                return self.model.encode("search_query: " + text, normalize_embeddings=True).tolist()

        embeddings = LocalNomicEmbeddings()
    else:
        embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=settings.OLLAMA_BASE_URL)
    store = Chroma.from_texts(
        [item["text"] for item in documents],
        embedding=embeddings,
        metadatas=[{"id": item["id"]} for item in documents],
        collection_name=f"rag_eval_{uuid.uuid4().hex}",
    )
    rows = []
    try:
        for item in queries:
            candidates = store.similarity_search(item["text"], k=8)
            start = time.perf_counter()
            ranked = rerank(item["text"], candidates, strict=True)
            rerank_ms = (time.perf_counter() - start) * 1000
            rows.append({
                "id": item["id"],
                "relevant_ids": item["relevant_ids"],
                "candidate_ids": [doc.metadata["id"] for doc in candidates],
                "vector_top3": [doc.metadata["id"] for doc in candidates[:3]],
                "rerank_top3": [doc.metadata["id"] for doc in ranked],
                "rerank_ms": round(rerank_ms, 2),
            })
    finally:
        store.delete_collection()

    before = summarize(rows, "vector_top3")
    after = summarize(rows, "rerank_top3")
    return {
        "dataset": "handwritten_security_smoke_test",
        "embedding_source": str(local_embedding_model) if local_embedding_model else "ollama:nomic-embed-text",
        "query_count": len(queries),
        "document_count": len(documents),
        "candidate_k": 8,
        "output_k": 3,
        "vector": before,
        "rerank": after,
        "delta": {key: round(after[key] - before[key], 4) for key in before},
        "median_rerank_ms": round(statistics.median(row["rerank_ms"] for row in rows), 2),
        "rows": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="validate labels without loading models")
    parser.add_argument("--local-embedding-model", type=Path, help="offline nomic model directory")
    parser.add_argument("--output", type=Path, help="save the complete JSON result")
    args = parser.parse_args()
    documents, queries = load_dataset()
    result = {"document_count": len(documents), "query_count": len(queries)} if args.check else evaluate(documents, queries, args.local_embedding_model)
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output if args.check else json.dumps({key: value for key, value in result.items() if key != "rows"}, ensure_ascii=False, indent=2))
