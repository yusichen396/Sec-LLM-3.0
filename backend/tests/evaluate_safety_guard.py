"""安全护栏对抗集评测。

用法（在 backend/ 下）：
    python -m tests.evaluate_safety_guard
    python -m tests.evaluate_safety_guard --verbose
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

DATASET = Path(__file__).parent / "data" / "safety_guard_eval.json"


def load(path: Path | None = None):
    data = json.loads((path or DATASET).read_text(encoding="utf-8"))
    items = data["items"]
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids)), "重复 id"
    assert all(i["label"] in ("block", "allow") for i in items)
    assert all(i["text"].strip() for i in items)
    return data["name"], items


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--dataset", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from core.safety.guard import check

    name, items = load(args.dataset)
    rows = []
    for item in items:
        res = check(item["text"])
        blocked = res.decision != "allow"
        rows.append({
            "id": item["id"],
            "type": item["type"],
            "label": item["label"],
            "decision": res.decision,
            "category": res.category,
            "blocked": blocked,
            "correct": blocked == (item["label"] == "block"),
            "text": item["text"],
            "reasons": res.reasons,
        })

    tp = sum(r["blocked"] and r["label"] == "block" for r in rows)
    fn = sum((not r["blocked"]) and r["label"] == "block" for r in rows)
    fp = sum(r["blocked"] and r["label"] == "allow" for r in rows)
    tn = sum((not r["blocked"]) and r["label"] == "allow" for r in rows)

    recall = tp / (tp + fn) if tp + fn else 0.0        # 越权/越界拦截率
    fpr = fp / (fp + tn) if fp + tn else 0.0           # 误拦率
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    acc = (tp + tn) / len(rows)

    by_type = defaultdict(lambda: {"n": 0, "ok": 0})
    for r in rows:
        by_type[r["type"]]["n"] += 1
        by_type[r["type"]]["ok"] += r["correct"]

    summary = {
        "dataset": name,
        "total": len(rows),
        "block_count": tp + fn,
        "allow_count": fp + tn,
        "intercept_rate": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "accuracy": round(acc, 4),
        "by_type": {k: {"n": v["n"], "correct": v["ok"],
                        "acc": round(v["ok"] / v["n"], 4)}
                    for k, v in sorted(by_type.items())},
        "errors": [{"id": r["id"], "type": r["type"], "label": r["label"],
                    "decision": r["decision"], "text": r["text"]}
                   for r in rows if not r["correct"]],
        "decision_distribution": dict(Counter(r["decision"] for r in rows)),
    }

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.verbose:
        print("\n--- 错判明细 ---")
        for r in rows:
            if not r["correct"]:
                print(f'[{r["id"]}] 期望={r["label"]} 实际={r["decision"]}/{r["category"]} | {r["text"]}')
    if args.output:
        args.output.write_text(
            json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
