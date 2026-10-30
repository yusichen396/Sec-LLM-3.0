"""Trusted dataset sealing and one-use holdout ledger. No labels go to candidates."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import unicodedata
from pathlib import Path

from core.rag.evaluation import load_dataset
from tools.optimize_rag import atomic_json


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def normalized_text(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def seal(source, destination, *, origin, annotator, reviewer):
    if origin not in ("authored", "business") or not annotator.strip() or not reviewer.strip() or annotator == reviewer:
        raise ValueError("Declare provenance and two distinct annotation/review identities")
    data, _ = load_dataset(source)
    if destination.exists():
        raise ValueError("A sealed bundle cannot be overwritten")
    bundle = {"schema": 1, "provenance": {"origin": origin, "annotator": annotator, "reviewer": reviewer,
               "source": source.name, "sealed_at": datetime.now(timezone.utc).isoformat(),
               "independence": "declared_by_dataset_owner_not_verified_by_software"},
              "dataset": data, "dataset_sha256": fingerprint(data)}
    atomic_json(destination, bundle)
    return bundle


def read_bundle(path):
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("schema") != 1 or fingerprint(bundle["dataset"]) != bundle.get("dataset_sha256"):
        raise ValueError("Sealed dataset fingerprint mismatch")
    provenance = bundle.get("provenance", {})
    if (provenance.get("origin") not in ("business", "authored") or not provenance.get("annotator")
            or not provenance.get("reviewer") or provenance["annotator"] == provenance["reviewer"]):
        raise ValueError("Invalid dataset provenance")
    validate_data(bundle["dataset"])
    return bundle


def validate_data(data):
    # Reuse the canonical validation without writing labels into a source snapshot.
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "dataset.json"
        atomic_json(path, data)
        load_dataset(path)


def holdout_keys(data):
    queries = [q for q in data["queries"] if q["split"] != "dev"]
    return {"queries": sorted({fingerprint(normalized_text(q["text"])) for q in queries}),
            "topics": sorted({normalized_text(q["group"]) for q in queries}),
            "documents": sorted({fingerprint(normalized_text(d["text"])) for d in data["documents"]
                                  if any(d["id"] in q["relevant_ids"] for q in queries)})}


def reserve_holdout(bundle, ledger_path, run_id):
    """Reserve before execution; interrupted/rejected rounds also consume the holdout."""
    from tools.code_rsi import mutation_lock
    with mutation_lock(ledger_path.parent):
        ledger = json.loads(ledger_path.read_text(encoding="utf-8")) if ledger_path.exists() else {"uses": []}
        keys = holdout_keys(bundle["dataset"])
        for previous in ledger["uses"]:
            if previous["dataset_sha256"] == bundle["dataset_sha256"] or any(
                    set(keys[key]) & set(previous["keys"][key]) for key in keys):
                raise ValueError("Holdout dataset, topic, document or normalized query has already been consumed")
        ledger["uses"].append({"run_id": run_id, "dataset_sha256": bundle["dataset_sha256"], "keys": keys,
                               "reserved_at": datetime.now(timezone.utc).isoformat()})
        atomic_json(ledger_path, ledger)


def public_projection(data, split):
    return {"documents": [{"id": d["id"], "text": d["text"], "metadata": d.get("metadata", {})}
                          for d in data["documents"]],
            "queries": [{"id": q["id"], "text": q["text"]} for q in data["queries"] if q["split"] == split]}


def reject_published_holdout(bundle, fixture_dir):
    keys = holdout_keys(bundle["dataset"])
    for path in fixture_dir.glob("*.json"):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        if "queries" not in fixture or "documents" not in fixture:
            continue
        public_queries = {fingerprint(normalized_text(q["text"])) for q in fixture["queries"]}
        public_documents = {fingerprint(normalized_text(d["text"])) for d in fixture["documents"]}
        if set(keys["queries"]) & public_queries or set(keys["documents"]) & public_documents:
            raise ValueError("Release holdout overlaps a published fixture visible to candidates")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--origin", choices=("authored", "business"), required=True)
    parser.add_argument("--annotator", required=True)
    parser.add_argument("--reviewer", required=True)
    args = parser.parse_args()
    seal(args.source, args.destination, origin=args.origin, annotator=args.annotator, reviewer=args.reviewer)
    print(f"Sealed dataset: {args.destination}")
