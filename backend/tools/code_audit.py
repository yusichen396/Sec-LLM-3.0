"""Code vulnerability auditor tool (SAST)."""
from core.llm.router import single_shot_completion
from tools.registry import register_tool

CODE_AUDIT_SYSTEM_PROMPT = """
你是高级应用安全代码审计专家。请审计用户提供的 {language} 代码，并且只返回 JSON。
输出结构：
{{
  "risk_level": "Low|Medium|High|Critical",
  "findings": [
    {{
      "title": "漏洞标题",
      "severity": "Low|Medium|High|Critical",
      "line_hint": "行号或位置描述",
      "description": "漏洞说明",
      "fix": "修复建议"
    }}
  ],
  "fixed_code": "修复后的完整代码（保留换行）",
  "summary": "中文总结"
}}
不要输出 markdown 或解释文本。
"""

_PARSE_ERROR = {
    "status": "error",
    "error": "模型输出无法解析为预期 JSON，本次审计结论不可用",
    "risk_level": "Unknown",
    "findings": [],
    "fixed_code": "",
    "summary": "",
}


@register_tool(
    name="code_auditor",
    description="Perform LLM-assisted source review. Returns vulnerability findings "
    "with severity ratings, descriptions, and fix suggestions. Supports Python, "
    "JavaScript, Go, Java, and more. This is model judgement, not a static analyser: "
    "every finding is a lead until independently verified.",
    category="exploit",
)
async def audit_code(code: str, language: str = "python", provider: str = "local") -> dict:
    """Audit source code for security vulnerabilities."""
    from tools.registry import _extract_json

    if not code.strip():
        return {**_PARSE_ERROR, "error": "代码内容为空"}

    # language 进入 system prompt，做白名单避免注入提示词
    language = language if language in {
        "python", "javascript", "typescript", "go", "java", "php", "ruby", "c", "cpp", "csharp", "html", "other"
    } else "other"
    system_prompt = CODE_AUDIT_SYSTEM_PROMPT.format(language=language)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"请审计并修复以下代码：\n\n{code[:30000]}"},
    ]
    raw = await single_shot_completion(messages, provider=provider, temperature=0.2, json_mode=True)
    parsed = _extract_json(raw)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("findings"), list):
        return _PARSE_ERROR
    return {
        "status": "success",
        "risk_level": parsed.get("risk_level", "Unknown"),
        "findings": parsed.get("findings", []),
        "fixed_code": parsed.get("fixed_code", ""),
        "summary": parsed.get("summary", ""),
        # 明确标注结论来源，避免被当成可验证证据
        "evidence_kind": "model_judgement",
    }
