"""Planning -> isolated static audit -> report/claims benchmark. Never scans network targets."""
import argparse
import ast
import asyncio
from dataclasses import asdict
import hashlib
import json
import re
from pathlib import Path
import statistics
import time
import uuid

from agents.evaluation import score_plan, score_report
from agents.policy import AgentPolicy, load_policy, parse_plan, planning_messages, report_messages
from agents.reporting import annotate_finding
from tools.optimize_rag import atomic_json

ROOT = Path(__file__).resolve().parents[1]
AUDIT_SOURCES = ("agents/policy.py", "agents/reporting.py", "agents/orchestrator.py", "agents/supervisor.py",
                 "tools/evaluate_agent_tasks.py")


def source_fingerprints(root=ROOT):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in AUDIT_SOURCES}


def static_audit(code):
    """Parse supplied text only; no eval, exec, subprocess or imports from the submitted code."""
    if not isinstance(code, str) or len(code.encode("utf-8")) > 100_000:
        return {"error": "source_size_exceeded", "findings": []}
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"error": "invalid_source_syntax", "findings": []}
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        title = None
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            title = "Dynamic code execution lead"
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr == "execute" and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                title = "SQL string interpolation lead"
            elif node.func.attr == "run" and any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                                                and k.value.value is True for k in node.keywords):
                title = "Shell command execution lead"
        if title:
            findings.append({"title": title, "severity": "High", "evidence": ast.get_source_segment(code, node)})
    return {"findings": findings}


async def source_audit(code: str):
    return static_audit(code)


TOOLS = {"source_audit": {"func": source_audit, "description": "Statically audit exactly the supplied Python source; never execute it"}}


def score_claims(claims, findings):
    gold = {f"F{i:03}": f for i, f in enumerate(findings, 1)}
    if not isinstance(claims, list):
        return {"precision": 0.0, "recall": 0.0, "success": False}
    seen, correct = set(), 0
    for claim in claims:
        if not isinstance(claim, dict) or not isinstance(claim.get("evidence_id"), str):
            continue
        identity = claim["evidence_id"]
        expected = gold.get(identity)
        if identity not in seen and expected and all(claim.get(k) == expected.get(k)
                for k in ("title", "severity", "evidence", "verification_status")):
            correct += 1
        seen.add(identity)
    precision = correct / len(claims) if claims else float(not gold)
    recall = correct / len(gold) if gold else 1.0
    return {"precision": precision, "recall": recall, "success": precision == recall == 1.0}


def output_fingerprint(row):
    trace = {key: row.get(key) for key in ("plan", "tool_result", "output")}
    return hashlib.sha256(json.dumps(trace, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def business_provenance(provenance):
    return bool(isinstance(provenance, dict) and provenance.get("origin") == "business"
                and provenance.get("annotator") and provenance.get("reviewer")
                and provenance["annotator"] != provenance["reviewer"])


def audit_review(path, rows):
    if path is None:
        return False
    reviews = json.loads(path.read_text(encoding="utf-8"))
    ids = {r["case_id"]: output_fingerprint(r) for r in rows}
    if not isinstance(reviews, list) or len(reviews) != len(ids):
        raise ValueError("Every task needs exactly one independent human review")
    if {r.get("case_id") for r in reviews} != set(ids):
        raise ValueError("Human review task IDs do not match")
    return all(r.get("grounded") is True and r.get("complete") is True and r.get("output_sha256") == ids[r["case_id"]]
               and isinstance(r.get("reviewer"), str) and r["reviewer"].strip() for r in reviews)


async def evaluate(args):
    from tools.rsi_preflight import model_check
    from tools.rsi_sandbox import preflight, run as sandbox_run, read_result
    from core.llm.router import single_shot_completion

    raw_dataset = args.dataset.read_bytes()
    dataset = json.loads(raw_dataset)
    ids = [c["id"] for c in dataset["cases"]]
    if (not ids or len(ids) > 50 or len(set(ids)) != len(ids)
            or not all(isinstance(i, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", i) for i in ids)):
        raise ValueError("Task IDs must be nonempty and unique")
    if args.live and args.executor != "docker":
        raise ValueError("Live end-to-end task audits require isolated Docker tool execution")
    model = await model_check() if args.live else {"model": "oracle_fixture", "digest": None}
    if args.executor == "docker":
        image = preflight(args.image)["image_id"]
    policy = AgentPolicy(**json.loads(args.policy.read_text(encoding="utf-8"))) if args.policy else load_policy()
    directory = args.output_dir.resolve() / ("tasks_" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True)
    deadline = time.monotonic() + args.max_seconds
    rows = []
    for case in dataset["cases"]:
        started = time.perf_counter()
        source = {"target": case["id"] + ".py", "task_type": "code_audit",
                  "task": "Audit exactly this Python source without executing it:\n" + case["code"]}
        gold = {"expected_plan": [{"tool": "source_audit", "args": {"code": case["code"]}}]}
        row = {"case_id": case["id"], "success": False}
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError("Agent task evaluation budget exhausted")
            async def complete(messages, temperature):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Agent task evaluation budget exhausted")
                return await asyncio.wait_for(single_shot_completion(messages, provider="local", temperature=temperature),
                                              timeout=min(45, remaining))

            raw_plan = (await complete(planning_messages(source, TOOLS, policy, 1), 0.1) if args.live else
                        json.dumps(gold["expected_plan"]))
            row["plan"] = raw_plan
            if not score_plan(raw_plan, gold, TOOLS, 1)["success"]:
                raise ValueError("Planner changed source, tool or arguments")
            plan = parse_plan(raw_plan, TOOLS, 1)
            if args.executor == "docker":
                request = directory / (case["id"] + "_tool.json")
                atomic_json(request, plan[0]["args"])
                log = directory / (case["id"] + "_tool.log")
                sandbox_run(image, [(ROOT, "/workspace"), (request, "/inputs/task.json")],
                            ["python", "-m", "tools.evaluate_agent_tasks", "--tool-input", "/inputs/task.json"],
                            timeout=max(0.01, deadline - time.monotonic()), log=log)
                tool_result = read_result(log)
            else:
                tool_result = static_audit(plan[0]["args"]["code"])
            findings = [annotate_finding(f, "source_audit", tool_result) for f in tool_result["findings"]]
            if sorted(f["title"] for f in findings) != sorted(case["expected_titles"]):
                raise ValueError("Tool output differs from independently fixed fixture expectations")
            if bool(tool_result.get("error")) != bool(case.get("expected_error")):
                raise ValueError("Tool failure status mismatch")
            if args.live:
                messages = report_messages(source["target"], source["task_type"], findings, [tool_result.get("error")], policy)
                messages[-1]["content"] += ('\nReturn ONLY JSON with report_markdown and claims. Each claim has evidence_id '
                                            '(F001 etc.), title, severity, evidence and verification_status. '
                                            'Also include execution_status (failed if the tool returned an error, otherwise completed). '
                                            'Copy claim facts exactly from supplied evidence. Use [] when there are no findings.')
                payload = json.loads(await complete(messages, 0.1))
            else:
                sections = ["Executive Summary", "Verified Findings", "Unverified Leads", "Remediation Recommendations", "Testing Limitations"]
                bodies = ["Static audit fixture.", "No verified vulnerabilities.",
                          "\n".join(f"- [F{i:03}] {f['title']}" for i, f in enumerate(findings, 1)) or "No leads.",
                          "Review leads before remediation.", "Static analysis only; no exploitation. " + str(tool_result.get("error") or "")]
                payload = {"report_markdown": "\n\n".join(f"## {h}\n{b}" for h, b in zip(sections, bodies)),
                           "execution_status": "failed" if tool_result.get("error") else "completed",
                           "claims": [{"evidence_id": f"F{i:03}", **{k: f[k] for k in
                                       ("title", "severity", "evidence", "verification_status")}} for i, f in enumerate(findings, 1)]}
            row["tool_result"], row["output"] = tool_result, payload
            row["structured_claims"] = score_claims(payload.get("claims"), findings)
            row["report_contract"] = score_report(payload.get("report_markdown", ""), findings)
            row["execution_status_correct"] = payload.get("execution_status") == ("failed" if tool_result.get("error") else "completed")
            row["success"] = (row["structured_claims"]["success"] and row["report_contract"]["success"]
                              and row["execution_status_correct"])
        except Exception as error:
            row["error"] = str(error)
        row["latency_ms"] = (time.perf_counter() - started) * 1000
        rows.append(row)
    reviewed = audit_review(args.reviews, rows)
    report = {"schema": 1, "mode": "live" if args.live else "fixture", "policy_version": policy.version,
              "source_sha256": source_fingerprints(),
              "provenance": dataset.get("provenance", {"origin": "authored"}),
              "model": model, "dataset_sha256": hashlib.sha256(raw_dataset).hexdigest(), "rows": rows,
              "task_contract_success_rate": statistics.mean(r["success"] for r in rows),
              "human_review_passed": reviewed, "free_text_truth_automatically_verified": False,
              "approved": bool(args.live and reviewed and business_provenance(dataset.get("provenance"))
                               and all(r["success"] for r in rows))}
    atomic_json(directory / "result.json", report)
    atomic_json(directory / "review_template.json", [{"case_id": r["case_id"], "grounded": None, "complete": None,
                              "output_sha256": output_fingerprint(r), "reviewer": ""} for r in rows])
    print(json.dumps({"mode": report["mode"], "success_rate": report["task_contract_success_rate"],
                      "approved": report["approved"], "report": str(directory / "result.json")}, ensure_ascii=False))
    return report


def approve_existing(path, reviews):
    report = json.loads(path.read_text(encoding="utf-8"))
    report["human_review_passed"] = audit_review(reviews, report["rows"])
    report["approved"] = bool(report["mode"] == "live" and report["model"].get("digest")
                              and business_provenance(report.get("provenance"))
                              and report["human_review_passed"] and all(r["success"] for r in report["rows"]))
    report["human_review_sha256"] = hashlib.sha256(reviews.read_bytes()).hexdigest()
    atomic_json(path, report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "tests/data/agent_tasks_v1.json")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--executor", choices=("docker", "local"), default="docker")
    parser.add_argument("--image", default="sec-llm-rsi:tests")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--reviews", type=Path)
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument("--output-dir", type=Path, default=ROOT.parent / "artifacts/agent_tasks")
    parser.add_argument("--tool-input", type=Path)
    parser.add_argument("--approve-existing", type=Path, help="attach human reviews to the exact saved outputs without rerunning the model")
    args = parser.parse_args()
    if args.approve_existing:
        if not args.reviews:
            parser.error("--approve-existing requires --reviews")
        print(json.dumps({"approved": approve_existing(args.approve_existing, args.reviews)["approved"]}))
    elif args.tool_input:
        print("RSI_RESULT=" + json.dumps(static_audit(json.loads(args.tool_input.read_text(encoding="utf-8"))["code"])), flush=True)
    else:
        asyncio.run(evaluate(args))
