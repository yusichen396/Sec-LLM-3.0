"""覆盖评测：文档去重后，答案所在小节是否还在上下文里。

对比 expand_chunks=1（只回一块）与 expand_chunks=2/3（回多块）。
"""
from __future__ import annotations

import json
import sys
import uuid
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langchain_chroma import Chroma  # noqa: E402
from langchain_core.embeddings import Embeddings  # noqa: E402
from sentence_transformers import SentenceTransformer  # noqa: E402

from core.rag.chunking import split_text  # noqa: E402
from core.rag.embeddings import BGE_ZH_QUERY_PREFIX  # noqa: E402
from core.rag.hybrid import hybrid_search  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data" / "rag_retrieval_large_v2.json"
MODEL = ROOT / "models" / "bge-large-zh-v1.5"


class Emb(Embeddings):
    def __init__(self):
        self.m = SentenceTransformer(str(MODEL), trust_remote_code=True)

    def embed_documents(self, texts):
        return self.m.encode(list(texts), normalize_embeddings=True).tolist()

    def embed_query(self, text):
        return self.m.encode(BGE_ZH_QUERY_PREFIX + text, normalize_embeddings=True).tolist()


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    documents, queries = data["documents"], data["queries"]

    texts, metas = [], []
    for doc in documents:
        for index, piece in enumerate(split_text(doc["text"], size=400, overlap=80)):
            texts.append(piece["text"])
            metas.append({"id": doc["id"], "chunk": index, "section": piece["section"]})

    store = Chroma.from_texts(texts, embedding=Emb(), metadatas=metas,
                              collection_name=f"cov_{uuid.uuid4().hex}")

    long_queries = [q for q in queries if q.get("relevant_section")]
    print(f"带小节标注的问题: {len(long_queries)}")

    results: dict[int, Counter] = {1: Counter(), 2: Counter(), 3: Counter()}

    for query in long_queries:
        ranked = [doc for doc, _ in hybrid_search(store, query["text"], k=8)]
        doc_ids = []
        for doc in ranked:
            did = (doc.metadata or {}).get("id")
            if did and did not in doc_ids:
                doc_ids.append(did)
        top_docs = doc_ids[:3]

        for per_doc in (1, 2, 3):
            if per_doc == 1:
                picked = [p for p in ranked if (p.metadata or {}).get("id") in top_docs][:3]
            else:
                from core.rag.hybrid import expand_documents

                picked = expand_documents(store, query["text"],
                                          [p for p in ranked if (p.metadata or {}).get("id") in top_docs],
                                          per_doc=per_doc)

            sections = [str((p.metadata or {}).get("section", "")) for p in picked]
            doc_ok = any((p.metadata or {}).get("id") in query["relevant_ids"] for p in picked)
            section_ok = any(query["relevant_section"] in section and
                             (p.metadata or {}).get("id") in query["relevant_ids"]
                             for section, p in zip(sections, picked))
            results[per_doc]["doc_hit"] += int(doc_ok)
            results[per_doc]["section_hit"] += int(section_ok)
            results[per_doc]["chunks"] += len(picked)

    store.delete_collection()

    total = len(long_queries)
    print(f"{'每文档块数':<12}{'文档命中':<12}{'小节命中':<12}{'平均块数':<10}")
    for per_doc in (1, 2, 3):
        row = results[per_doc]
        print(f"{per_doc:<12}{row['doc_hit'] / total:<12.3f}{row['section_hit'] / total:<12.3f}{row['chunks'] / total:<10.2f}")


if __name__ == "__main__":
    main()
