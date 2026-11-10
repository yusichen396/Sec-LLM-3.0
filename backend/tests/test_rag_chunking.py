"""分块文档的检索聚合：同一文档的多个片段应折叠成一个候选。"""
from core.rag.hybrid import _corpus, _dedupe, hybrid_search


class FakeStore:
    """最小可用假库：分块存储，metadata 带 doc_id。"""

    def __init__(self, rows):
        # rows: [(chunk_id, text, metadata)]
        self.rows = rows
        self._collection_name = "fake"

    def get(self, where=None, include=None):
        rows = [r for r in self.rows if self._match(r[2], where)]
        return {
            "ids": [r[0] for r in rows],
            "documents": [r[1] for r in rows],
            "metadatas": [r[2] for r in rows],
        }

    @staticmethod
    def _match(meta, where):
        if not where:
            return True
        return all(meta.get(k) == v for k, v in where.items())

    def similarity_search_with_score(self, query, k=8, filter=None):
        from langchain_core.documents import Document

        rows = [r for r in self.rows if self._match(r[2], filter)]
        # 简单按查询词出现次数排序，够用
        scored = sorted(rows, key=lambda r: -r[1].count(query[:2]))[:k]
        return [(Document(page_content=r[1], metadata=r[2]), 1.0) for r in scored]

    def similarity_search(self, query, k=8, filter=None):
        return [d for d, _ in self.similarity_search_with_score(query, k, filter)]


def test_corpus_folds_chunks_to_one_document():
    rows = [
        ("c1", "第一阶段 需求", {"id": "docA", "chunk": 0}),
        ("c2", "第二阶段 设计", {"id": "docA", "chunk": 1}),
        ("c3", "第三阶段 测试", {"id": "docA", "chunk": 2}),
        ("c4", "另一篇文档", {"id": "docB", "chunk": 0}),
    ]
    ids, texts, docs = _corpus(FakeStore(rows), None)

    assert sorted(docs) == ["docA", "docB"], "两个文档应各折叠成一个候选"
    assert ids.count("docA") == 3, "检索仍按片段计数"
    assert docs["docA"].page_content == "第一阶段 需求", "保留首个片段，结果可复现"


def test_dedupe_keeps_best_rank():
    assert _dedupe(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_hybrid_search_returns_distinct_documents():
    rows = [(f"c{i}", f"注入相关的第{i}段内容", {"id": "docA", "chunk": i}) for i in range(5)]
    rows.append(("c9", "钓鱼邮件识别", {"id": "docB", "chunk": 0}))

    results = hybrid_search(FakeStore(rows), "注入", k=3)

    ids = [d.metadata["id"] for d, _ in results]
    assert len(ids) == len(set(ids)), "同文档的多个片段不应重复出现在结果里"
    assert "docA" in ids
