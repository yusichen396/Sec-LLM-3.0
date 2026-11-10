"""Blue-team detection rule generator tool (with offline syntax lint)."""
import re
from typing import Any, Dict, List

from core.llm.router import stream_completion
from tools.registry import register_tool

_YARA_RULE = re.compile(r"^\s*(?:private\s+|global\s+)?rule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", re.MULTILINE)
_SURICATA_RULE = re.compile(r"^\s*(?:alert|drop|pass|reject)\s+\w+\s+.*\(.*\)\s*$", re.MULTILINE)
_SID = re.compile(r"\bsid\s*:\s*\d+")


def lint_rule(text: str, rule_type: str) -> Dict[str, Any]:
    """Cheap structural lint — not a substitute for compiling with the real engine."""
    issues: List[str] = []
    body = text or ""
    if not body.strip():
        return {"ok": False, "issues": ["规则内容为空"], "engine": "lint-only"}

    if rule_type == "yara":
        if not _YARA_RULE.search(body):
            issues.append("缺少 YARA rule 头（rule <name> {）")
        if "condition:" not in body:
            issues.append("缺少 condition: 段")
        if body.count("{") != body.count("}"):
            issues.append("花括号不配对")
    elif rule_type in {"suricata", "snort"}:
        if not _SURICATA_RULE.search(body):
            issues.append("缺少 action ... ( ... ) 形式的规则体")
        if not _SID.search(body):
            issues.append("缺少 sid 字段")
        for field in ("msg:", "classtype:"):
            if field not in body:
                issues.append(f"缺少 {field} 字段")
    else:
        issues.append(f"未知规则类型: {rule_type}")

    return {
        "ok": not issues,
        "issues": issues,
        "engine": "lint-only",
        "note": "仅做结构检查；请用 yara/suricata 实际加载验证",
    }


@register_tool(
    name="rule_generator",
    description="Generate YARA/Suricata/Snort detection rules from a natural language "
    "description of the threat or detection requirement. The result is structurally "
    "linted and returned with the lint report.",
    category="report",
        expects="content",
)
async def generate_rule(
    requirement: str,
    rule_type: str = "yara",
    provider: str = "local",
) -> dict:
    """Generate a defensive detection rule, lint it, and return both."""
    rule_type = (rule_type or "yara").strip().lower()
    if rule_type not in {"yara", "suricata", "snort"}:
        return {"status": "error", "error": "rule_type 仅支持 yara/suricata/snort"}

    system_prompt = (
        "You are a senior blue-team detection engineer. "
        "Generate practical defensive rules based on user requirement.\n\n"
        "Rules:\n"
        "1) Output in Simplified Chinese summary first.\n"
        f"2) Then provide the final {rule_type} rule in a fenced code block.\n"
        "3) Add a short validation checklist.\n"
        "4) Never answer non-security content."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"需求：{requirement}"},
    ]
    chunks: List[str] = []
    async for chunk in stream_completion(messages, provider=provider, temperature=0.2):
        chunks.append(chunk)
    text = "".join(chunks)
    if not text.strip():
        return {"status": "error", "error": "模型未返回内容"}

    code_blocks = re.findall(r"```[a-zA-Z]*\s*\n(.*?)```", text, re.DOTALL)
    rule_text = code_blocks[0] if code_blocks else text
    return {
        "status": "success",
        "rule_type": rule_type,
        "rule": rule_text.strip(),
        "explanation": text,
        "validation": lint_rule(rule_text, rule_type),
    }
