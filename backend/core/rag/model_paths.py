"""Resolve the serving reranker path identically for runtime and acceptance."""
from pathlib import Path


def reranker_path(root=None):
    from config import settings
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    if settings.RERANKER_MODEL_PATH:
        path = Path(settings.RERANKER_MODEL_PATH)
        return (path if path.is_absolute() else root / path).resolve()

    # 优先同量级 large 版（base 版比嵌入模型弱，重排反而降分），缺失时回退 base
    for name in ("models/bge-reranker-large", "models/bge-reranker-base"):
        candidate = (root / name).resolve()
        if (candidate / "model.safetensors").is_file():
            return candidate
    return (root / "models/bge-reranker-base").resolve()
