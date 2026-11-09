"""Cross-encoder reranking for RAG candidates."""
from functools import lru_cache


MODEL_NAME = "BAAI/bge-reranker-large"


@lru_cache(maxsize=1)
def _model():
    from sentence_transformers import CrossEncoder
    from config import settings

    from core.rag.model_paths import reranker_path
    local_model = reranker_path()
    source = str(local_model) if (local_model / "model.safetensors").is_file() else MODEL_NAME
    if settings.RERANKER_MODEL_PATH and source == MODEL_NAME:
        raise FileNotFoundError(f"Configured reranker model is incomplete: {local_model}")
    return CrossEncoder(source, max_length=512, local_files_only=bool(settings.RERANKER_MODEL_PATH))


def rerank(query: str, documents: list, limit: int = 3, *, strict: bool = False) -> list:
    """Score query-document pairs; retain vector order when scores tie."""
    if not documents:
        return []
    try:
        scores = _model().predict([(query, doc.page_content) for doc in documents])
        return [doc for _, doc in sorted(
            enumerate(documents), key=lambda item: float(scores[item[0]]), reverse=True
        )[:limit]]
    except Exception as error:
        if strict:
            raise
        print(f"[RAG] Reranker unavailable ({error}); using vector order")
        return documents[:limit]
