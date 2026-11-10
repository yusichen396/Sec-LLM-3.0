"""生产环境的嵌入模型：优先用本地中文 bge，其次回退 Ollama。

中文 bge 系列必须在查询侧加指令前缀，否则检索质量明显下降（实测 Hit@3 −10 点）。
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from langchain_core.embeddings import Embeddings

# BGE 官方建议的查询指令（中文）
BGE_ZH_QUERY_PREFIX = "为这个句子生成表示以用于检索相关文章："
# nomic 系列的查询指令
NOMIC_QUERY_PREFIX = "search_query: "
NOMIC_DOC_PREFIX = "search_document: "

DEFAULT_ZH_MODEL = Path("models/bge-large-zh-v1.5")


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def zh_model_path() -> Path | None:
    """返回可用的本地中文嵌入模型目录，没有则 None。"""
    from config import settings

    configured = getattr(settings, "EMBEDDING_MODEL_PATH", None)
    candidate = Path(configured) if configured else DEFAULT_ZH_MODEL
    candidate = candidate if candidate.is_absolute() else _root() / candidate
    if (candidate / "config.json").is_file() and (
        (candidate / "model.safetensors").is_file() or (candidate / "pytorch_model.bin").is_file()
    ):
        return candidate
    return None


class LocalBGEEmbeddings(Embeddings):
    """本地 sentence-transformers 模型，查询侧自动加 BGE 指令前缀。"""

    def __init__(self, path: Path, query_prefix: str = BGE_ZH_QUERY_PREFIX) -> None:
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(str(path), trust_remote_code=True)
        self.query_prefix = query_prefix

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(list(texts), normalize_embeddings=True).tolist()

    def embed_query(self, text: str) -> list[float]:
        return self.model.encode(self.query_prefix + text, normalize_embeddings=True).tolist()


class PrefixedOllamaEmbeddings(Embeddings):
    """Ollama 的 nomic 模型，补上它要求的查询/文档前缀。"""

    def __init__(self) -> None:
        from langchain_ollama import OllamaEmbeddings

        from config import settings

        self.inner = OllamaEmbeddings(model="nomic-embed-text", base_url=settings.OLLAMA_BASE_URL)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self.inner.embed_documents([NOMIC_DOC_PREFIX + t for t in texts])

    def embed_query(self, text: str) -> list[float]:
        return self.inner.embed_query(NOMIC_QUERY_PREFIX + text)


@lru_cache(maxsize=1)
def get_embeddings() -> Embeddings:
    """生产入口：优先中文 bge，缺失时回退 Ollama（带前缀）。"""
    path = zh_model_path()
    if path is not None:
        return LocalBGEEmbeddings(path)
    return PrefixedOllamaEmbeddings()


def embedding_source() -> str:
    path = zh_model_path()
    return str(path) if path is not None else "ollama:nomic-embed-text"
