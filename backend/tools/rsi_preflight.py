"""Cheap preflight before snapshots, hashing, model loading or model calls."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


async def model_check():
    import httpx
    from config import settings
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        try:
            response = await client.get(settings.OLLAMA_BASE_URL.rstrip("/") + "/api/tags")
            response.raise_for_status()
            configured = settings.OLLAMA_MODEL_NAME
            model = next((m for m in response.json()["models"] if m["name"] in
                          (configured, configured + ":latest")), None)
            if not model:
                raise ValueError(f"Configured model {configured} is not installed")
            return {"provider": "local", "model": configured, "digest": model["digest"]}
        except (httpx.HTTPError, KeyError, ValueError) as error:
            raise RuntimeError(f"Local generation model unavailable: {error}") from error


def check(*, root, smoke, generate, executor, image):
    missing = [name for name in ("pytest", "langgraph", "httpx", "fastapi", "pymysql", "jose", "passlib")
               if importlib.util.find_spec(name) is None]
    if missing:
        raise RuntimeError("Missing RSI test dependencies: " + ", ".join(missing))
    result = {"python": sys.version, "executor": executor}
    if not smoke:
        from core.rag.model_paths import reranker_path
        reranker = reranker_path(root)
        result["reranker_path"] = str(reranker)
        for model in (root / "models/nomic-embed-text-v1.5", reranker):
            for filename in ("config.json", "model.safetensors"):
                if not (model / filename).is_file():
                    raise RuntimeError(f"Missing local model file: {model}/{filename}")
        if importlib.util.find_spec("sentence_transformers") is None:
            raise RuntimeError("Full RSI evaluation needs sentence-transformers")
    if generate:
        import asyncio
        result["generation"] = asyncio.run(model_check())
    if executor == "docker":
        from tools.rsi_sandbox import preflight
        result.update(preflight(image))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--executor", choices=("docker", "local"), default="docker")
    parser.add_argument("--image", default="sec-llm-rsi:latest")
    args = parser.parse_args()
    try:
        result = check(root=Path(__file__).resolve().parents[1], **vars(args))
        print(json.dumps({"passed": True, **result}, ensure_ascii=False, indent=2))
    except Exception as error:
        print(json.dumps({"passed": False, "error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
