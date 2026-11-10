"""Trusted, disposable host preparation worker; parent enforces its remaining budget."""
import json
from pathlib import Path
import sys

from tools.optimize_rag import atomic_json


def perform(action, request):
    if action == "preflight":
        from tools.rsi_preflight import check
        return check(**{**request, "root": Path(request["root"])})
    if action == "models":
        from tools.optimize_rag import model_manifest
        return {"embedding_manifest": model_manifest(Path(request["embedding"])),
                "reranker_manifest": model_manifest(Path(request["reranker"]))}
    if action == "snapshot":
        from tools.code_rsi import snapshot, manifest
        source, target = Path(request["source"]), Path(request["target"])
        snapshot(source, target)
        expected = manifest(target)
        if manifest(source) != expected:
            raise ValueError("Working source changed during snapshot")
        return expected
    if action == "vectors":
        from tools.rsi_vectors import prepare
        return prepare(request["projection"], request["mode"], Path(request["root"]),
                       model_identity=request["model_identity"], cache_dir=Path(request["cache_dir"]))
    raise ValueError("Unknown host preparation action")


if __name__ == "__main__":
    action, request, output = sys.argv[1:]
    atomic_json(Path(output), perform(action, json.loads(Path(request).read_text(encoding="utf-8"))))
