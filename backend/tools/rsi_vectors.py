"""Trusted embedding preparation, cached across baseline/candidate and campaign rounds."""
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def embedding_model(path, identity=""):
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(path, trust_remote_code=True, local_files_only=True)


@lru_cache(maxsize=8192)
def vector(path, text, document, identity=""):
    prefix = "search_document: " if document else "search_query: "
    return embedding_model(path, identity).encode(prefix + text, normalize_embeddings=True).tolist()


def prepare(projection, mode, root, *, model_identity="", cache_dir=None):
    if mode == "smoke":
        return projection
    path = str((Path(root) / "models/nomic-embed-text-v1.5").resolve())
    def cached(text, document):
        import hashlib
        import json
        from tools.optimize_rag import atomic_json
        key = hashlib.sha256(json.dumps([path, model_identity, text, document]).encode()).hexdigest()
        cache = Path(cache_dir) / (key + ".json") if cache_dir else None
        if cache and cache.is_file():
            return json.loads(cache.read_text(encoding="utf-8"))
        value = vector(path, text, document, model_identity)
        if cache:
            atomic_json(cache, value)
        return value
    return {"documents": [{**d, "vector": cached(d["text"], True)} for d in projection["documents"]],
            "queries": [{**q, "vector": cached(q["text"], False)} for q in projection["queries"]]}
