"""Bounded multi-round code RSI with fresh holdouts, lineage and stagnation stops."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import uuid

from tools import code_rsi
from tools.optimize_rag import atomic_json
from tools.rsi_dataset import read_bundle, holdout_keys


def validate_rounds(paths):
    seen = {"queries": set(), "topics": set(), "documents": set()}
    for path in paths:
        keys = holdout_keys(read_bundle(path)["dataset"])
        for key, values in keys.items():
            if seen[key] & set(values):
                raise ValueError("Every campaign round requires disjoint holdout queries, topics and documents")
            seen[key].update(values)


def campaign(args):
    if not 1 <= args.patience <= 5 or not 1 <= len(args.bundles) <= 5 or not 1 <= args.max_seconds <= 3600:
        raise ValueError("Use 1-5 bundles, patience 1-5 and a total budget of 1-3600 seconds")
    validate_rounds(args.bundles)
    if len(args.bundles) > 1 and not args.apply:
        raise ValueError("Multi-round improvement requires --apply so the next round inherits the accepted code")
    directory = args.output_dir.resolve() / ("campaign_" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True)
    state = {"created_at": datetime.now(timezone.utc).isoformat(), "state": "running", "rounds": [],
             "budget_seconds": args.max_seconds, "stop_reason": None}
    deadline, stagnant = time.monotonic() + args.max_seconds, 0
    ledger = directory / "campaign.json"
    atomic_json(ledger, state)
    try:
        for number, bundle in enumerate(args.bundles, 1):
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                state["stop_reason"] = "budget_exhausted"
                break
            before = code_rsi.manifest(code_rsi.ROOT)
            run_args = argparse.Namespace(output_dir=directory, max_seconds=remaining, smoke=False,
                        generate=True, candidate=None, apply=args.apply, trusted_candidate=False,
                        executor="docker", image=args.image, dataset_bundle=bundle)
            run_dir = code_rsi.run(run_args)
            report = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            applied = report["state"] == "applied"
            parent = state["rounds"][-1]["run"] if state["rounds"] else None
            state["rounds"].append({"number": number, "run": str(run_dir), "parent": parent,
                       "dataset_sha256": report["dataset_sha256"], "decision": report["decision"],
                       "accepted": report["accepted"], "applied": applied,
                       "source_before": code_rsi.digest(json.dumps(before, sort_keys=True).encode()),
                       "source_after": code_rsi.digest(json.dumps(code_rsi.manifest(code_rsi.ROOT), sort_keys=True).encode())})
            stagnant = 0 if applied else stagnant + 1
            atomic_json(ledger, state)
            if stagnant >= args.patience:
                state["stop_reason"] = "stagnation"
                break
        state["state"] = "finished"
        state["stop_reason"] = state["stop_reason"] or "round_limit"
    except Exception as error:
        state.update(state="failed", stop_reason="execution_error", error=str(error))
        atomic_json(ledger, state)
        raise
    atomic_json(ledger, state)
    return directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundles", type=Path, nargs="+")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--max-seconds", type=int, default=3600)
    parser.add_argument("--image", default="sec-llm-rsi:latest")
    parser.add_argument("--output-dir", type=Path, default=code_rsi.ROOT.parent / "artifacts/code_rsi")
    print(campaign(parser.parse_args()))
