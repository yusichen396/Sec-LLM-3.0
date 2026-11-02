"""Tests for the explainable security posture score."""
from core.security_score import compute_security_score


def test_no_telemetry_yields_no_score_instead_of_perfect_100():
    result = compute_security_score()
    assert result["score"] is None
    assert result["computed"] is False
    assert result["grade"] == "暂无数据"
    assert "数据" in result["reason"]


def test_clean_state_is_100_and_has_no_penalties():
    result = compute_security_score(total_events=5)
    assert result["score"] == 100
    assert result["penalties"] == []
    assert result["grade"] == "优秀"


def test_each_penalty_is_itemised_and_sums_exactly():
    result = compute_security_score(
        total_events=10,
        critical_unresolved=1,
        high_unresolved=2,
        medium_unresolved=3,
        verified_findings=1,
    )
    # 100 - (12 + 16 + 9 + 10)
    assert result["score"] == 53
    assert result["grade"] == "较差"
    assert sum(item["points"] for item in result["penalties"]) == 47
    reasons = {item["reason"]: (item["count"], item["points"]) for item in result["penalties"]}
    assert reasons["Critical 未处置"] == (1, 12)
    assert reasons["已验证的 Agent 发现"] == (1, 10)


def test_score_is_deterministic_and_never_negative():
    args = dict(total_events=3, critical_unresolved=9, high_unresolved=9, medium_unresolved=9)
    first = compute_security_score(**args)
    second = compute_security_score(**args)
    assert first["score"] == second["score"] == 0
    assert first["grade"] == "危险"


def test_verified_findings_alone_trigger_a_score():
    """没有日志但有扫描发现时也必须给分，否则会看起来'满 100 分'。"""
    result = compute_security_score(verified_findings=3)
    assert result["computed"] is True
    assert result["score"] == 70
    assert result["grade"] == "一般"
