"""Offline RAG configuration search. Run `python -m tools.optimize_rag --help`."""
import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import platform
import subprocess
import uuid

from core.rag.evaluation import evaluate, load_dataset
from core.rag.policy import ACTIVE_POLICY, RetrievalPolicy, load_policy

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "tests" / "data" / "rag_optimization_v1.json"


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def propose(baseline, failures):
    """Only bounded retrieval mutations; no prompts, labels, code, or guards are edited."""
    if not failures:
        return []
    changes = [{"bm25_k1": 0.5, "bm25_b": 0.0}, {"bm25_k1": 2.5, "bm25_b": 1.0}]
    if baseline.strategy != "bm25":
        changes += [{"candidate_k": 12}, {"candidate_k": 16}]
    if baseline.strategy == "hybrid":
        changes += [{"vector_weight": 0.5}, {"vector_weight": 2.0}, {"rrf_k": 20}]
    candidates = {p.version: p for p in (replace(baseline, **change) for change in changes)}
    candidates.pop(baseline.version, None)
    return list(candidates.values())


def qualifies(baseline, candidate, *, min_gain, max_latency_ratio):
    """A strict gain in MRR with no hit-rate regression, within the same time budget."""
    return (
        candidate["metrics"]["mrr_at_3"] >= baseline["metrics"]["mrr_at_3"] + min_gain
        and all(candidate["metrics"][key] >= baseline["metrics"][key] for key in ("hit_at_1", "hit_at_3"))
        and candidate["median_latency_ms"] <= baseline["median_latency_ms"] * max_latency_ratio
        and all(c["mrr_at_3"] >= b["mrr_at_3"] for b, c in zip(baseline["per_repeat"], candidate["per_repeat"]))
    )


def safety_regression():
    from core.safety.guard import check

    path = ROOT / "tests" / "data" / "safety_guard_eval.json"
    items = json.loads(path.read_text(encoding="utf-8"))["items"]
    errors = [item["id"] for item in items
              if (check(item["text"]).decision != "allow") != (item["label"] == "block")]
    return {"total": len(items), "errors": errors, "passed": bool(items) and not errors,
            "dataset_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


class LexicalStore:
    """Fixture corpus only; vector methods deliberately fail if called."""
    def __init__(self, documents):
        self._collection_name = "lexical_" + uuid.uuid4().hex
        self.documents = documents

    def get(self, *, where=None, include=None):
        if where:
            raise ValueError("Lexical smoke corpus does not contain user metadata")
        return {"ids": [doc["id"] for doc in self.documents],
                "documents": [doc["text"] for doc in self.documents],
                "metadatas": [{"id": doc["id"]} for doc in self.documents]}


def create_store(documents, local_model):
    from langchain_chroma import Chroma
    from config import settings

    if local_model:
        from langchain_core.embeddings import Embeddings
        from sentence_transformers import SentenceTransformer

        class LocalNomic(Embeddings):
            def __init__(self):
                self.model = SentenceTransformer(str(local_model), trust_remote_code=True, local_files_only=True)

            def embed_documents(self, texts):
                return self.model.encode(["search_document: " + t for t in texts], normalize_embeddings=True).tolist()

            def embed_query(self, text):
                return self.model.encode("search_query: " + text, normalize_embeddings=True).tolist()

        embeddings = LocalNomic()
    else:
        from langchain_ollama import OllamaEmbeddings
        embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=settings.OLLAMA_BASE_URL)
    return Chroma.from_texts(
        [doc["text"] for doc in documents], embedding=embeddings,
        metadatas=[{"id": doc["id"]} for doc in documents],
        collection_name="rag_opt_" + uuid.uuid4().hex,
    )


def environment():
    packages = {}
    for name in ("langchain-chroma", "langchain-ollama", "sentence-transformers", "torch"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = None
    revision_text, diff_digest = None, None
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
        diff = subprocess.run(["git", "diff", "HEAD", "--", "backend"], cwd=ROOT.parent, capture_output=True, check=False)
        revision_text = revision.stdout.strip() if revision.returncode == 0 else None
        diff_digest = hashlib.sha256(diff.stdout).hexdigest() if diff.returncode == 0 else None
    except OSError:
        pass  # Source fingerprints remain available in minimal read-only containers without Git.
    sources = list((ROOT / "core" / "rag").glob("*.py")) + [Path(__file__), ROOT / "core" / "safety" / "guard.py"]
    return {"python": platform.python_version(), "platform": platform.platform(), "packages": packages,
            "thread_environment": {name: os.environ.get(name) for name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS")},
            "git_commit": revision_text, "tracked_diff_sha256": diff_digest,
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}


def model_manifest(directory):
    if directory is None:
        return None
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix in (".json", ".py", ".safetensors", ".model", ".txt"):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            files[path.relative_to(directory).as_posix()] = digest.hexdigest()
    return {"path": str(directory.resolve()), "files_sha256": files}


def write_summary(run_dir, report):
    baseline, candidate = report["baseline_version"], report["candidate_version"]
    lines = ["# RAG 离线优化评测", "", f"模式：{report['mode']}；决策：{report['decision']}；已启用：{report['activated']}。",
             "", "数据为已有人工样本组成的小型冒烟集，不代表真实业务泛化效果。", "",
             "| 集合 | 样本数 | 基线 Hit@1 | 候选 Hit@1 | 基线 MRR@3 | 候选 MRR@3 | 基线/候选中位延迟(ms) |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for split, key in (("dev", "dev"), ("validation", "validation"), ("test", "test_audit")):
        b, c = report[key][baseline], report[key][candidate]
        lines.append(f"| {split} | {report['split_sizes'][split]} | {b['metrics']['hit_at_1']:.3f} | {c['metrics']['hit_at_1']:.3f} | "
                     f"{b['metrics']['mrr_at_3']:.3f} | {c['metrics']['mrr_at_3']:.3f} | {b['median_latency_ms']:.2f} / {c['median_latency_ms']:.2f} |")
    lines += ["", f"安全回归：{report['safety']['total']} 条，通过：{report['safety']['passed']}。",
              f"数据 SHA256：`{report['dataset_sha256']}`。",
              "", "候选只由开发集选择；验证集用于晋级，测试集只作最终回归否决，不尝试测试集上的第二名。",
              "每条查询重复运行，轮换策略执行顺序；延迟覆盖完整检索和重排，不包含模型冷加载。",
              "lexical 模式只验证 BM25 和闭环，不具备启用资格；未达标时保留基线。",
              "", "完整配置、逐条结果、失败问题 ID、环境、源码与模型指纹见 result.json。"]
    (run_dir / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_search(store, dataset, baseline, *, repeats, min_gain, max_latency_ratio):
    splits = {split: [q for q in dataset["queries"] if q["split"] == split]
              for split in ("dev", "validation", "test")}
    print("[RAG eval] Measuring baseline on development split...", flush=True)
    initial = evaluate([baseline], store, splits["dev"], repeats)[baseline.version]
    failures = sorted({row["id"] for row in initial["rows"] if not row["ranked_ids"]
                       or row["ranked_ids"][0] not in row["relevant_ids"]})
    candidates = propose(baseline, failures)
    print(f"[RAG eval] Comparing baseline and {len(candidates)} candidates on development split...", flush=True)
    dev = evaluate([baseline] + candidates, store, splits["dev"], repeats)
    # Only the best development candidate reaches validation. The test set is never ranked on.
    selected = max(candidates, key=lambda p: (dev[p.version]["metrics"]["mrr_at_3"],
                                              dev[p.version]["metrics"]["hit_at_1"]), default=baseline)
    gain = dev[selected.version]["metrics"]["mrr_at_3"] - dev[baseline.version]["metrics"]["mrr_at_3"]
    if gain < min_gain:
        selected = baseline
    policies = [baseline] if selected == baseline else [baseline, selected]
    print("[RAG eval] Checking one selected candidate on validation split...", flush=True)
    validation = evaluate(policies, store, splits["validation"], repeats)
    accepted = selected != baseline and qualifies(
        validation[baseline.version], validation[selected.version],
        min_gain=min_gain, max_latency_ratio=max_latency_ratio,
    )
    # One final regression veto; never try a runner-up based on the test results.
    print("[RAG eval] Running final held-out regression audit...", flush=True)
    test = evaluate(policies, store, splits["test"], repeats)
    test_passed = all(test[selected.version]["metrics"][key] >= test[baseline.version]["metrics"][key]
                      for key in ("hit_at_1", "hit_at_3", "mrr_at_3"))
    safety = safety_regression()
    return {
        "baseline": asdict(baseline), "baseline_version": baseline.version,
        "candidate": asdict(selected), "candidate_version": selected.version,
        "split_sizes": {key: len(value) for key, value in splits.items()},
        "development_failures": failures, "candidates": [asdict(p) for p in candidates],
        "dev": dev, "validation": validation, "test_audit": test,
        "safety": safety, "test_regression_passed": test_passed,
        "accepted": bool(accepted and test_passed and safety["passed"]),
        "decision": ("validation_gain" if accepted and test_passed and safety["passed"] else
                     "test_regression" if accepted and not test_passed else
                     "safety_failed" if not safety["passed"] else "keep_baseline"),
        "test_used_for_selection": False,
        "test_used_as_release_gate": True,
        "budget": {"repeats": repeats, "candidate_limit": 7, "min_mrr_gain": min_gain,
                   "max_validation_latency_ratio": max_latency_ratio,
                   "llm_calls": 0, "cloud_llm_cost": 0,
                   "cost_note": "Local embedding/reranking compute is reflected in latency, not monetary cost."},
    }


def activate(report, path, expected_baseline):
    if report["mode"] != "full" or not report["accepted"]:
        raise ValueError("Only accepted full-model runs can be activated; lexical runs are smoke tests")
    if load_policy(path, expected_baseline) != expected_baseline:
        raise ValueError("Active baseline changed during evaluation; rerun before activation")
    # Save a rollback point before atomically replacing the live policy.
    atomic_json(path.with_suffix(".previous.json"), asdict(expected_baseline))
    atomic_json(path, report["candidate"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data" / "rag_optimization" / "runs")
    parser.add_argument("--lexical-only", action="store_true", help="CPU smoke search; cannot activate")
    parser.add_argument("--local-embedding-model", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--activate", action="store_true", help="activate only if the full run passes gates")
    parser.add_argument("--rollback", action="store_true", help="restore the previous active policy and exit")
    args = parser.parse_args()
    from config import settings
    path = Path(settings.RAG_POLICY_PATH) if settings.RAG_POLICY_PATH else ACTIVE_POLICY
    if args.rollback:
        if args.activate:
            parser.error("--rollback cannot be combined with --activate")
        previous = RetrievalPolicy(**json.loads(path.with_suffix(".previous.json").read_text(encoding="utf-8")))
        atomic_json(path, asdict(previous))
        print(f"Restored {previous.version}: {path}")
        return 0
    if not 2 <= args.repeats <= 10:
        parser.error("--repeats must be between 2 and 10")
    if args.lexical_only and args.activate:
        parser.error("--lexical-only cannot activate a serving policy")
    data, digest = load_dataset(args.dataset)
    default = RetrievalPolicy(strategy="hybrid" if settings.HYBRID_RECALL_ENABLED else "vector")
    baseline = RetrievalPolicy(strategy="bm25", rerank=False) if args.lexical_only else load_policy(path, default)
    run_dir = args.output_dir / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8])
    metadata = {"created_at": datetime.now(timezone.utc).isoformat(), "mode": "lexical" if args.lexical_only else "full",
                "dataset": data["name"], "dataset_sha256": digest, "environment": environment(),
                "embedding_source": ("none" if args.lexical_only else str(args.local_embedding_model or "ollama:nomic-embed-text")),
                "reranker": "none" if args.lexical_only else "BAAI/bge-reranker-base",
                "embedding_manifest": None if args.lexical_only else model_manifest(args.local_embedding_model),
                "reranker_manifest": None if args.lexical_only else model_manifest(ROOT / "models" / "bge-reranker-base"),
                "serving_policy_path": str(path)}
    store = None
    try:
        store = LexicalStore(data["documents"]) if args.lexical_only else create_store(data["documents"], args.local_embedding_model)
        report = {**metadata, **run_search(store, data, baseline, repeats=args.repeats,
                                         min_gain=0.01, max_latency_ratio=1.5)}
        report["activated"] = False
        atomic_json(run_dir / "result.json", report)
        atomic_json(run_dir / "candidate.json", report["candidate"])
        if args.activate and report["accepted"]:
            activate(report, path, baseline)
            report["activated"] = True
            atomic_json(run_dir / "result.json", report)
        write_summary(run_dir, report)
        print(json.dumps({key: report[key] for key in ("mode", "decision", "accepted", "activated", "split_sizes",
                                                       "baseline_version", "candidate_version")}, indent=2))
        print(f"Report: {run_dir / 'result.json'}")
        return 0
    except Exception as error:
        atomic_json(run_dir / "error.json", {**metadata, "accepted": False, "error": str(error)})
        raise
    finally:
        if store is not None and not args.lexical_only:
            store.delete_collection()


if __name__ == "__main__":
    raise SystemExit(main())
