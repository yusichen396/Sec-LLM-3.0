"""混合召回：BM25 稀疏检索 + 向量召回，用 RRF 融合。

动机：向量召回擅长语义相近，但在"术语精确命中"（CVE 编号、工具名、
命令、报错原文）上明显弱于关键词检索；两者互补。

对外只暴露 hybrid_search()，内部维护一个按 (集合, 过滤条件) 缓存的 BM25 索引。
"""
from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter
from typing import Any

from langchain_core.documents import Document

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_LATIN_RE = re.compile(r"[a-zA-Z0-9_\-\.]{2,}")

RRF_K = 60          # RRF 平滑常数，业界常用 60
INDEX_TTL = 60.0    # BM25 索引缓存秒数
MAX_CORPUS = 5000   # 超过这个规模就不建全量 BM25，避免拖慢请求


def tokenize(text: str) -> list[str]:
    """中文按字符二元组切，英文/数字按词切。"""
    low = text.lower()
    cjk = "".join(_CJK_RE.findall(low))
    grams = [cjk[i:i + 2] for i in range(len(cjk) - 1)]
    if len(cjk) == 1:
        grams = [cjk]
    return grams + _LATIN_RE.findall(low)


class BM25Index:
    """极简 BM25（k1=1.5, b=0.75），只依赖标准库。"""

    def __init__(self, ids: list[str], texts: list[str]):
        self.ids = ids
        self.tokens = [Counter(tokenize(t)) for t in texts]
        n = len(texts)
        df: Counter = Counter()
        for toks in self.tokens:
            df.update(toks.keys())
        self.n = n
        self.avgdl = (sum(sum(t.values()) for t in self.tokens) / n) if n else 0.0
        self.idf = {g: math.log(1 + (n - c + 0.5) / (c + 0.5)) for g, c in df.items()}

    def search(self, query: str, k: int = 10, *, k1: float = 1.5, b: float = 0.75) -> list[str]:
        q = set(tokenize(query))
        if not q or not self.n:
            return []
        scored: list[tuple[float, str]] = []
        for idx, toks in enumerate(self.tokens):
            dl = sum(toks.values())
            s = 0.0
            for g in q:
                tf = toks.get(g)
                if not tf:
                    continue
                s += self.idf.get(g, 0.0) * tf * (k1 + 1) / (
                    tf + k1 * (1 - b + b * dl / self.avgdl)
                )
            if s > 0:
                scored.append((s, self.ids[idx]))
        scored.sort(reverse=True)
        return [i for _, i in scored[:k]]


_cache: dict[str, tuple[float, BM25Index]] = {}
_lock = threading.Lock()


def _dedupe(ids: list[str]) -> list[str]:
    """保留首次出现的顺序去重。"""
    seen: set[str] = set()
    out: list[str] = []
    for item in ids:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _corpus(store: Any, where: dict | None) -> tuple[list[str], list[str], dict[str, Document]]:
    """取集合内文档。统一用 metadata['id'] 作为身份，缺失时回退到 Chroma 内部 id。"""
    got = store.get(where=where, include=["documents", "metadatas"])
    raw_ids = list(got.get("ids") or [])
    texts = list(got.get("documents") or [])
    metas = list(got.get("metadatas") or [])
    ids, docs = [], {}
    for i, raw in enumerate(raw_ids):
        meta = metas[i] or {}
        doc_id = str(meta.get("id") or raw)
        meta = dict(meta) | {"id": doc_id}
        ids.append(doc_id)
        docs[doc_id] = Document(page_content=texts[i], metadata=meta)
    return ids, texts, docs


def _index(store: Any, where: dict | None, key: str) -> BM25Index | None:
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < INDEX_TTL:
            return hit[1]
    ids, texts, _ = _corpus(store, where)
    if not ids or len(ids) > MAX_CORPUS:
        return None
    idx = BM25Index(ids, texts)
    with _lock:
        _cache[key] = (time.time(), idx)
        if len(_cache) > 32:
            oldest = min(_cache.items(), key=lambda kv: kv[1][0])[0]
            _cache.pop(oldest, None)
    return idx


def hybrid_search(
    store: Any,
    query: str,
    k: int = 8,
    where: dict | None = None,
    pool: int | None = None,
    rrf_k: int = RRF_K,
    vector_weight: float = 1.0,
    bm25_k1: float = 1.5,
    bm25_b: float = 0.75,
    strict: bool = False,
) -> list[tuple[Document, float]]:
    """向量 + BM25 双路召回，RRF 融合。返回 [(doc, rrf_score)]，按分数降序。"""
    pool = pool or max(k * 3, 12)
    key = f"{getattr(store, '_collection_name', 'c')}|{sorted((where or {}).items())}"

    # 1) 向量路
    vec_ids: list[str] = []
    try:
        for doc, _score in (store.similarity_search_with_score(query, k=pool, filter=where) if vector_weight else []):
            doc_id = (doc.metadata or {}).get("id") or getattr(doc, "id", None)
            if not doc_id and strict:
                raise ValueError("Vector result has no stable document ID")
            if doc_id:
                vec_ids.append(str(doc_id))
    except Exception as error:  # 向量路失败不应拖垮整条链路
        if strict:
            raise
        print(f"[HYBRID] vector branch failed: {error}")

    # 2) 稀疏路
    idx = _index(store, where, key)
    bm25_ids = idx.search(query, pool, k1=bm25_k1, b=bm25_b) if idx else []

    if not vec_ids and not bm25_ids:
        return []

    # 3) 按文档去重：切分后同一文档会有多个 chunk，若逐个累加 RRF 分数，
    #    块多的长文档会被系统性抬高（长度偏置），短文档的正确结果被挤出。
    #    每个分支只保留该文档的最好名次。
    vec_ids = _dedupe(vec_ids)
    bm25_ids = _dedupe(bm25_ids)

    # 4) RRF 融合
    fused: dict[str, float] = {}
    for rank, doc_id in enumerate(vec_ids):
        fused[doc_id] = fused.get(doc_id, 0.0) + vector_weight / (rrf_k + rank + 1)
    for rank, doc_id in enumerate(bm25_ids):
        fused[doc_id] = fused.get(doc_id, 0.0) + 1.0 / (rrf_k + rank + 1)

    _, _, docs = _corpus(store, where)
    ranked = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[:k]
    return [(docs[i], s) for i, s in ranked if i in docs]
