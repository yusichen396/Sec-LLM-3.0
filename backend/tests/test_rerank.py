from types import SimpleNamespace
from unittest.mock import patch

from core.rag.rerank import rerank


def test_rerank_uses_cross_encoder_scores_and_falls_back_on_failure():
    docs = [SimpleNamespace(page_content=text) for text in ("first", "second", "third")]
    model = SimpleNamespace(predict=lambda pairs: [0.1, 0.9, 0.2])
    with patch("core.rag.rerank._model", return_value=model):
        assert rerank("query", docs) == [docs[1], docs[2], docs[0]]
    with patch("core.rag.rerank._model", side_effect=RuntimeError("offline")):
        assert rerank("query", docs, limit=2) == docs[:2]
