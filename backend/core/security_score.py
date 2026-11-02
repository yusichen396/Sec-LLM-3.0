"""Explainable security posture score.

The score is deliberately boring: 100 points minus a fixed penalty per open item.
Every point is traceable to a number the system actually observed, and the same
inputs always produce the same score. No decay, no magic weighting, no "risk
model" that cannot be explained on a slide.

Weights are a product decision and live here so the policy is changed in one place.
"""
from typing import Any, Dict

WEIGHTS = {
    "critical_unresolved": 12,
    "high_unresolved": 8,
    "medium_unresolved": 3,
    "verified_finding": 10,
}

GRADES = (
    (90, "优秀"),
    (75, "良好"),
    (60, "一般"),
    (40, "较差"),
    (0, "危险"),
)

FORMULA = (
    "100 - (12×Critical未处置 + 8×High未处置 + 3×Medium未处置 + 10×已验证发现)，下限 0"
)
WINDOW = "全部日志分析记录 + 最近 50 个 Agent 会话"

_LABELS = (
    ("critical_unresolved", "Critical 未处置"),
    ("high_unresolved", "High 未处置"),
    ("medium_unresolved", "Medium 未处置"),
    ("verified_finding", "已验证的 Agent 发现"),
)


def compute_security_score(
    *,
    total_events: int = 0,
    critical_unresolved: int = 0,
    high_unresolved: int = 0,
    medium_unresolved: int = 0,
    verified_findings: int = 0,
) -> Dict[str, Any]:
    """Return the score plus everything needed to explain it.

    ``score`` is ``None`` when nothing has been observed yet: an empty install must
    not look like a perfect 100 just because no telemetry exists.
    """
    inputs = {
        "total_events": int(total_events or 0),
        "critical_unresolved": int(critical_unresolved or 0),
        "high_unresolved": int(high_unresolved or 0),
        "medium_unresolved": int(medium_unresolved or 0),
        "verified_findings": int(verified_findings or 0),
    }
    base = {
        "inputs": inputs,
        "formula": FORMULA,
        "window": WINDOW,
    }
    if inputs["total_events"] == 0 and inputs["verified_findings"] == 0:
        return {
            "score": None,
            "grade": "暂无数据",
            "computed": False,
            "penalties": [],
            "reason": "还没有日志分析与 Agent 扫描数据，不给出分数",
            **base,
        }

    penalties = []
    total_penalty = 0
    for key, label in _LABELS:
        count = inputs["verified_findings"] if key == "verified_finding" else inputs[key]
        if count <= 0:
            continue
        points = count * WEIGHTS[key]
        total_penalty += points
        penalties.append({"reason": label, "count": count, "points": points})

    score = max(0, min(100, 100 - total_penalty))
    grade = next(name for threshold, name in GRADES if score >= threshold)
    return {
        "score": score,
        "grade": grade,
        "computed": True,
        "penalties": penalties,
        "reason": None,
        **base,
    }
