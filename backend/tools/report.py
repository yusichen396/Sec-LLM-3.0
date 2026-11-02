"""Scan report explainer tool."""
from core.llm.router import single_shot_completion
from tools.registry import register_tool

REPORT_SYSTEM_PROMPT = """
你是资深蓝队分析师。请把扫描报告（例如 Nmap/Nessus）转换为管理层可读的执行摘要，并只返回 JSON。
输出结构：
{
  "executive_summary": "1-2段中文总结",
  "critical_findings": [
    {"item":"问题点","risk":"High|Critical|Medium|Low","impact":"影响","action":"建议"}
  ],
  "exposed_ports": ["端口/服务列表"],
  "priority_actions": ["优先行动1","优先行动2","优先行动3"],
  "plain_language_brief": "给非技术人员的解释"
}
不要输出 markdown 或额外说明。
"""

_EMPTY = {
    "executive_summary": "",
    "critical_findings": [],
    "exposed_ports": [],
    "priority_actions": [],
    "plain_language_brief": "",
}


@register_tool(
    name="report_explainer",
    description="Convert Nmap/Nessus scan reports into executive summaries "
    "suitable for management. Extracts critical findings, exposed ports, "
    "and prioritized action items.",
    category="report",
)
async def explain_report(content: str, provider: str = "local") -> dict:
    """Parse a scan report into a structured executive summary."""
    from tools.registry import _extract_json

    if not content.strip():
        return {"status": "error", "error": "报告内容为空", **_EMPTY}

    messages = [
        {"role": "system", "content": REPORT_SYSTEM_PROMPT},
        {"role": "user", "content": f"请解析这份扫描报告：\n\n{content[:40000]}"},
    ]
    raw = await single_shot_completion(messages, provider=provider, temperature=0.2, json_mode=True)
    parsed = _extract_json(raw)
    if not isinstance(parsed, dict) or "executive_summary" not in parsed:
        return {"status": "error", "error": "模型输出无法解析为预期 JSON，本次解析结果不可用", **_EMPTY}
    return {
        "status": "success",
        "executive_summary": parsed.get("executive_summary", ""),
        "critical_findings": parsed.get("critical_findings", []),
        "exposed_ports": parsed.get("exposed_ports", []),
        "priority_actions": parsed.get("priority_actions", []),
        "plain_language_brief": parsed.get("plain_language_brief", ""),
    }
