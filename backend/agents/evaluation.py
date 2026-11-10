"""Agent planning/reporting contract evaluation; never executes security tools."""
import hashlib
import json
import re
import statistics
import time

from agents.policy import parse_plan, planning_messages, report_messages
from agents.reporting import annotate_finding

HEADINGS = ("Executive Summary", "Verified Findings", "Unverified Leads",
            "Remediation Recommendations", "Testing Limitations")


class EvaluationBudgetExceeded(RuntimeError):
    pass


def load_dataset(path):
    raw = path.read_bytes()
    data = json.loads(raw)
    ids, inputs, groups = set(), set(), {}
    for case in data["cases"]:
        fingerprint = json.dumps(case["input"], sort_keys=True, ensure_ascii=False)
        if case["id"] in ids or fingerprint in inputs:
            raise ValueError("Duplicate case ID or input")
        ids.add(case["id"])
        inputs.add(fingerprint)
        split = case["split"]
        if split not in ("dev", "validation", "test") or case["kind"] not in ("plan", "report"):
            raise ValueError("Invalid evaluation split or case kind")
        if groups.setdefault(case["group"], split) != split:
            raise ValueError("Topic group leaks across evaluation splits")
        if case["kind"] == "plan" and not case.get("expected_plan"):
            raise ValueError("Planning cases need fixed expectations")
    if set(groups.values()) != {"dev", "validation", "test"}:
        raise ValueError("Three nonempty topic-disjoint splits are required")
    for split in ("dev", "validation", "test"):
        if {c["kind"] for c in data["cases"] if c["split"] == split} != {"plan", "report"}:
            raise ValueError("Each split must cover both planning and reporting")
    return data, hashlib.sha256(raw).hexdigest()


def findings_for(case):
    findings = []
    for item in case["input"].get("tool_results", []):
        for finding in item["result"].get("findings", []):
            findings.append(annotate_finding(finding, item["tool"], item["result"]))
    return findings


def score_plan(raw, case, tools, max_steps):
    try:
        plan = parse_plan(raw, tools, max_steps)
    except (ValueError, TypeError, KeyError):
        return {"score": 0.0, "success": False, "schema_valid": False, "correct_tools": False, "violations": []}
    expected = case["expected_plan"]
    names_match = [p["tool"] for p in plan] == [p["tool"] for p in expected]
    args_match = names_match and all(
        all(actual.get("args", {}).get(key) == value for key, value in gold["args"].items())
        and all(key in gold["args"] or key == "provider" for key in actual.get("args", {}))
        for actual, gold in zip(plan, expected)
    )
    return {"score": 0.5 + 0.5 * args_match, "success": bool(args_match), "schema_valid": True,
            "correct_tools": names_match, "violations": []}


def score_report(text, findings):
    """Measures citation placement/format, not free-text factual truth or exploit success."""
    sections = {}
    matches = list(re.finditer(r"^#{1,6}\s+(.+?)\s*$", text, re.MULTILINE))
    for index, match in enumerate(matches):
        title = match.group(1).strip()
        if title in sections:
            return {"score": 0.0, "success": False, "violations": ["duplicate_heading"]}
        sections[title] = text[match.end():matches[index + 1].start() if index + 1 < len(matches) else len(text)]
    known = {f"F{index:03}": f.get("verification_status") == "verified" for index, f in enumerate(findings, 1)}
    cited = set(re.findall(r"\[(F\d{3,})\]", text))
    verified = set(re.findall(r"\[(F\d{3,})\]", sections.get("Verified Findings", "")))
    leads = set(re.findall(r"\[(F\d{3,})\]", sections.get("Unverified Leads", "")))
    violations = ["unknown_evidence_id"] if cited - known.keys() else []
    if any(not known.get(ref, False) for ref in verified) or any(known.get(ref, False) for ref in leads):
        violations.append("wrong_evidence_classification")
    correct = sum(ref in (verified if is_verified else leads) for ref, is_verified in known.items())
    coverage = correct / len(known) if known else 1.0
    format_ok = all(sections.get(title, "").strip() for title in HEADINGS)
    score = 0.5 * format_ok + 0.5 * coverage if not violations else 0.0
    return {"score": score, "success": score == 1.0, "violations": violations}


def fixture_response(case):
    # An explicit oracle replay for harness smoke checks; never eligible for activation.
    if case["kind"] == "plan":
        return json.dumps(case["expected_plan"], ensure_ascii=False)
    findings = findings_for(case)
    verified, leads = [], []
    for index, finding in enumerate(findings, 1):
        (verified if finding["verification_status"] == "verified" else leads).append(f"- [F{index:03}] {finding['title']}")
    return "\n\n".join(f"## {title}\n{body}" for title, body in zip(HEADINGS, [
        "固定工具结果回放。", "\n".join(verified) or "无已验证发现。", "\n".join(leads) or "无待验证线索。",
        "复核并修复风险。", "这是固定工具结果，不代表真实扫描。",
    ]))


async def evaluate(policies, cases, tools, complete, *, repeats=2, max_steps=20):
    rows = {policy.version: [] for policy in policies}
    for repeat in range(repeats):
        for index, case in enumerate(cases):
            offset = (index + repeat) % len(policies)
            for policy in policies[offset:] + policies[:offset]:
                source = case["input"]
                if case["kind"] == "plan":
                    messages = planning_messages(source, tools, policy, max_steps)
                else:
                    messages = report_messages(source["target"], source["task_type"], findings_for(case),
                                               source.get("limitations", []), policy)
                start = time.perf_counter()
                error, raw = None, ""
                try:
                    raw = await complete(messages, temperature=0.1 if case["kind"] == "plan" else 0.3) if complete else fixture_response(case)
                    result = score_plan(raw, case, tools, max_steps) if case["kind"] == "plan" else score_report(raw, findings_for(case))
                except EvaluationBudgetExceeded:
                    raise
                except Exception as exc:
                    error = str(exc)
                    result = {"score": 0.0, "success": False, "violations": []}
                rows[policy.version].append({"case_id": case["id"], "kind": case["kind"], "repeat": repeat,
                                             **result, "error": error, "output": raw,
                                             "latency_ms": (time.perf_counter() - start) * 1000})
    results = {}
    for key, items in rows.items():
        metrics = {"score": statistics.mean(row["score"] for row in items),
                   "success_rate": statistics.mean(row["success"] for row in items)}
        for kind in ("plan", "report"):
            subset = [row for row in items if row["kind"] == kind]
            metrics[kind + "_score"] = statistics.mean(row["score"] for row in subset)
        results[key] = {"metrics": metrics, "violations": sum(bool(row["violations"]) for row in items),
                        "errors": sum(row["error"] is not None for row in items),
                        "per_repeat": [statistics.mean(row["score"] for row in items if row["repeat"] == r) for r in range(repeats)],
                        "median_latency_ms": statistics.median(row["latency_ms"] for row in items), "rows": items}
    return results
