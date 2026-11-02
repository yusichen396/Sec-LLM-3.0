"""Compare two scans of the same target.

Answers the question a report cannot answer on its own: *is this better than last
time?* Findings are matched on a stable key (tool + title + parameter + severity) so
re-ordering or timestamp changes do not look like new vulnerabilities.
"""
from typing import Any, Dict, Iterable, List

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}


def finding_key(finding: Dict[str, Any]) -> str:
    parameter = (
        finding.get("parameter")
        or (finding.get("reproduction") or {}).get("parameter")
        or ""
    )
    return "|".join(
        str(part or "")
        for part in (
            finding.get("source_tool"),
            finding.get("title"),
            parameter,
            finding.get("severity"),
        )
    )


def _sorted(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.get("severity", "Unknown"), 9), finding_key(f)))


def diff_findings(previous: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return new / resolved / persistent findings plus summary counts."""
    previous_map = {finding_key(f): f for f in previous or [] if isinstance(f, dict)}
    current_map = {finding_key(f): f for f in current or [] if isinstance(f, dict)}

    new = [current_map[key] for key in current_map.keys() - previous_map.keys()]
    resolved = [previous_map[key] for key in previous_map.keys() - current_map.keys()]
    persistent = [current_map[key] for key in current_map.keys() & previous_map.keys()]

    verified_now = sum(1 for f in current_map.values() if f.get("verification_status") == "verified")
    verified_before = sum(1 for f in previous_map.values() if f.get("verification_status") == "verified")
    return {
        "counts": {
            "previous": len(previous_map),
            "current": len(current_map),
            "new": len(new),
            "resolved": len(resolved),
            "persistent": len(persistent),
            "verified_previous": verified_before,
            "verified_current": verified_now,
        },
        "new": _sorted(new),
        "resolved": _sorted(resolved),
        "persistent": _sorted(persistent),
        "verdict": (
            "regressed" if len(new) > len(resolved)
            else "improved" if len(resolved) > len(new)
            else "unchanged"
        ),
    }
