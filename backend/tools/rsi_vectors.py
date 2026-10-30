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


def prepare(projection, mode, root, *, model_identity=""):
    if mode == "smoke":
        return projection
    path = str((Path(root) / "models/nomic-embed-text-v1.5").resolve())
    return {"documents": [{**d, "vector": vector(path, d["text"], True, model_identity)} for d in projection["documents"]],
            "queries": [{**q, "vector": vector(path, q["text"], False, model_identity)} for q in projection["queries"]]}
