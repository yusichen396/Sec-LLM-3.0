"""Resolve the serving reranker path identically for runtime and acceptance."""
from pathlib import Path


def reranker_path(root=None):
    from config import settings
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    path = Path(settings.RERANKER_MODEL_PATH) if settings.RERANKER_MODEL_PATH else Path("models/bge-reranker-base")
    return (path if path.is_absolute() else root / path).resolve()
