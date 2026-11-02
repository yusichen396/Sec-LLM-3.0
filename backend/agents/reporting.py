"""CVSS 3.1 calculator and OWASP classifier for agent findings."""
import math


def annotate_finding(finding: dict, tool: str, result: dict, evidence: dict | None = None) -> dict:
    """Only observed execution *with a stored artifact* counts as verified.

    ``evidence`` is the reference returned by ``core.evidence.EvidenceRecorder``.
    Without it a finding stays a lead, even when the browser observed a dialog —
    a claim the customer cannot replay is not a verified vulnerability.
    """
    annotated = {
        **finding,
        "source_tool": tool,
        "verification_status": "unverified",
        "verification_reason": "No independently replayable artifact",
    }
    if tool == "browser_check_xss":
        observed = finding.get("evidence")
        match = next((item for item in result.get("results", [])
                      if observed and item.get("payload") == observed
                      and (item.get("executed") or item.get("dialog_triggered"))), None)
        if match and evidence:
            annotated["verification_status"] = "verified"
            annotated["verification_reason"] = "Browser execution observed and artifact stored"
            annotated["evidence_id"] = evidence.get("evidence_id")
            annotated["evidence_path"] = evidence.get("evidence_path")
            annotated["evidence_sha256"] = evidence.get("evidence_sha256")
            annotated["reproduction"] = {
                "url": match.get("url", result.get("url")),
                "parameter": result.get("parameter"),
                "payload": observed,
                "observed": "browser_dialog_triggered",
                "poc_path": evidence.get("poc_path"),
            }
        elif match:
            annotated["verification_reason"] = "Execution observed but no evidence artifact was stored"
    # CVSS/OWASP 之前只定义未接线，导致报告里没有评分与分类
    return enhance_finding(annotated)

# OWASP Top 10 (2021) mapping by keyword
OWASP_CATEGORIES = {
    "sql injection": ("A03:2021 - Injection", "CWE-89"),
    "xss": ("A03:2021 - Injection", "CWE-79"),
    "cross-site scripting": ("A03:2021 - Injection", "CWE-79"),
    "command injection": ("A03:2021 - Injection", "CWE-77"),
    "ssti": ("A03:2021 - Injection", "CWE-94"),
    "broken access control": ("A01:2021 - Broken Access Control", "CWE-284"),
    "auth bypass": ("A01:2021 - Broken Access Control", "CWE-287"),
    "sensitive data": ("A02:2021 - Cryptographic Failures", "CWE-311"),
    "encryption": ("A02:2021 - Cryptographic Failures", "CWE-327"),
    "xxe": ("A05:2021 - Security Misconfiguration", "CWE-611"),
    "misconfiguration": ("A05:2021 - Security Misconfiguration", "CWE-16"),
    "deserialization": ("A08:2021 - Software and Data Integrity Failures", "CWE-502"),
    "ssrf": ("A10:2021 - Server-Side Request Forgery", "CWE-918"),
    "logging": ("A09:2021 - Security Logging and Monitoring Failures", "CWE-778"),
    "cve": ("Vulnerable Component", "CVE"),
}


def classify_owasp(title: str, description: str = "") -> tuple:
    """Map a finding to OWASP Top 10 category and CWE ID."""
    combined = (title + " " + description).lower()
    for keyword, (owasp, cwe) in OWASP_CATEGORIES.items():
        if keyword in combined:
            return owasp, cwe
    return ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104")


def calculate_cvss(
    attack_vector: str = "N",   # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L",  # L=Low, H=High
    privileges_required: str = "N",  # N=None, L=Low, H=High
    user_interaction: str = "N",  # N=None, R=Required
    scope: str = "U",  # U=Unchanged, C=Changed
    confidentiality: str = "H",  # N=None, L=Low, H=High
    integrity: str = "H",
    availability: str = "N",
) -> dict:
    """Calculate CVSS 3.1 base score (simplified).
    Full spec: https://www.first.org/cvss/v3.1/specification-document
    """
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac = {"L": 0.77, "H": 0.44}
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui = {"N": 0.85, "R": 0.62}
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}

    # Impact sub-score
    c = cia.get(confidentiality, 0)
    i = cia.get(integrity, 0)
    a = cia.get(availability, 0)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        # CVSS v3.1 formula
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02) ** 13

    # Exploitability sub-score
    e = 8.22 * av.get(attack_vector, 0.85) * ac.get(attack_complexity, 0.77)
    if scope == "U":
        e *= pr_u.get(privileges_required, 0.85)
    else:
        e *= pr_c.get(privileges_required, 0.85)
    e *= ui.get(user_interaction, 0.85)

    # Base score with RoundUp per CVSS 3.1 spec (ceiling to 1 decimal)
    if impact < 1e-9:
        score = 0.0
    elif scope == "U":
        score = math.ceil((impact + e) * 10) / 10
    else:
        score = math.ceil((impact + e) * 1.08 * 10) / 10
    score = max(0.0, min(10.0, score))

    if score >= 9.0: severity = "Critical"
    elif score >= 7.0: severity = "High"
    elif score >= 4.0: severity = "Medium"
    else: severity = "Low"

    return {
        "score": score,
        "severity": severity,
        "vector": f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}",
    }


def enhance_finding(finding: dict) -> dict:
    """Add CVSS + OWASP classification to a finding."""
    severity_map = {"Critical": ("N", "L", "N", "H", "H", "H"),
                    "High": ("N", "L", "N", "H", "H", "N"),
                    "Medium": ("N", "L", "L", "H", "L", "N"),
                    "Low": ("L", "H", "H", "L", "L", "N")}
    defaults = severity_map.get(finding.get("severity", "Medium"), ("N", "L", "N", "H", "L", "N"))
    av, ac, pr, c, i, a = defaults
    cvss = calculate_cvss(av, ac, pr, "N", "U", c, i, a)
    owasp, cwe = classify_owasp(finding.get("title", ""), finding.get("description", ""))
    finding["cvss_score"] = cvss["score"]
    finding["cvss_vector"] = cvss["vector"]
    finding["owasp_category"] = owasp
    finding["cwe_id"] = cwe
    return finding
