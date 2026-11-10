"""Threat intelligence IOC enrichment + AI report tool."""
import ipaddress
import re
from typing import Any, Dict, List

import httpx

from config import settings
from core.llm.router import single_shot_completion, stream_completion
from tools.registry import register_tool

IOC_IPV4_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
IOC_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
IOC_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
IOC_DOMAIN_RE = re.compile(
    r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"
)


def _detect_ioc_type(ioc: str) -> str:
    candidate = (ioc or "").strip()
    if not candidate:
        return "unknown"
    if IOC_IPV4_RE.match(candidate):
        try:
            ipaddress.ip_address(candidate)
            return "ip"
        except ValueError:
            pass
    if IOC_MD5_RE.match(candidate):
        return "md5"
    if IOC_SHA256_RE.match(candidate):
        return "sha256"
    if IOC_DOMAIN_RE.match(candidate):
        return "domain"
    return "unknown"


def _normalize_ioc(ioc: str, ioc_type: str) -> str:
    value = (ioc or "").strip()
    if ioc_type in {"domain", "md5", "sha256"}:
        return value.lower()
    return value


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _threat_verdict(score: int) -> str:
    if score >= 80:
        return "高危"
    if score >= 50:
        return "中危"
    if score > 0:
        return "低危"
    return "未见明显恶意"


async def _fetch_abuseipdb(ioc: str) -> Dict[str, Any]:
    if not settings.ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "status": "skipped", "reason": "missing_api_key"}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.THREAT_INTEL_TIMEOUT_SECONDS)
        ) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ioc, "maxAgeInDays": "90"},
                headers={"Accept": "application/json", "Key": settings.ABUSEIPDB_API_KEY},
            )
            resp.raise_for_status()
            data = resp.json().get("data") or {}
            score = max(0, min(100, _safe_int(data.get("abuseConfidenceScore"), 0)))
            return {
                "source": "abuseipdb",
                "status": "success",
                "score": score,
                "tags": [],
                "summary": f"近90天上报次数: {_safe_int(data.get('totalReports'), 0)}",
                "evidence": {
                    "total_reports": _safe_int(data.get("totalReports"), 0),
                    "last_reported_at": data.get("lastReportedAt"),
                },
            }
    except Exception as e:
        return {"source": "abuseipdb", "status": "error", "reason": str(e)[:180]}


async def _fetch_otx(ioc: str, ioc_type: str) -> Dict[str, Any]:
    route_type = {"ip": "IPv4", "domain": "domain", "md5": "file", "sha256": "file"}.get(
        ioc_type
    )
    if not route_type:
        return {"source": "alienvault_otx", "status": "skipped", "reason": "unsupported_ioc_type"}
    try:
        headers: Dict[str, str] = {}
        if settings.OTX_API_KEY:
            headers["X-OTX-API-KEY"] = settings.OTX_API_KEY
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.THREAT_INTEL_TIMEOUT_SECONDS)
        ) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{route_type}/{ioc}/general",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json() or {}
            pulses = (data.get("pulse_info") or {}).get("pulses") or []
            pulse_count = len(pulses)
            score = min(100, pulse_count * 15)
            tags = sorted({tag for pulse in pulses for tag in (pulse.get("tags") or []) if tag})[:20]
            return {
                "source": "alienvault_otx",
                "status": "success",
                "score": score,
                "tags": tags,
                "summary": f"关联情报脉冲数: {pulse_count}",
                "evidence": {"pulse_count": pulse_count},
            }
    except Exception as e:
        return {"source": "alienvault_otx", "status": "error", "reason": str(e)[:180]}


@register_tool(
    name="threat_intel_enrich",
    description="Enrich an IOC (IP, domain, MD5, SHA256) with threat intelligence "
    "from AbuseIPDB and AlienVault OTX. Returns scores, confidence, tags, and verdict.",
    category="recon",
        accepts="ioc",
)
async def enrich_ioc(ioc: str, ioc_type: str = "auto") -> dict:
    """Multi-source threat intelligence enrichment for an IOC."""
    import asyncio

    ioc_raw = ioc.strip()
    if not ioc_raw:
        raise ValueError("IOC cannot be empty")

    detected_type = _detect_ioc_type(ioc_raw)
    if ioc_type != "auto":
        if ioc_type not in {"ip", "domain", "md5", "sha256"}:
            raise ValueError("ioc_type must be auto/ip/domain/md5/sha256")
        # 声明类型与检测结果冲突时拒绝，避免把任意字符串塞进第三方 API 路径
        if detected_type != "unknown" and ioc_type != detected_type:
            raise ValueError(f"ioc_type 不匹配：检测为 {detected_type}")
        detected_type = ioc_type

    if detected_type == "unknown":
        raise ValueError(f"Cannot detect IOC type for: {ioc_raw}")

    normalized = _normalize_ioc(ioc_raw, detected_type)
    tasks = [asyncio.wait_for(_fetch_otx(normalized, detected_type), timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS)]
    if detected_type == "ip":
        tasks.insert(0, asyncio.wait_for(_fetch_abuseipdb(normalized), timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    successful = [r for r in results if isinstance(r, dict) and r.get("status") == "success"]
    source_status = {}
    for item in results:
        if isinstance(item, Exception):
            source_status[type(item).__name__] = "error"
        elif isinstance(item, dict):
            source_status[item.get("source", "unknown")] = item.get("status", "unknown")

    if not successful:
        # 全部情报源不可用时必须明确标为 error，否则调用方会把"没查到"当成"无害"
        return {
            "status": "error",
            "error": "所有情报源均不可用（缺 Key / 超时 / 配额）",
            "ioc": ioc_raw,
            "detected_type": detected_type,
            "total_score": 0,
            "verdict": "未知（情报不可用，不代表无害）",
            "source_hits": 0,
            "source_status": source_status,
            "enrichment": {"signals": [], "tags": [], "confidence": 0, "summary": ""},
        }

    total_score = min(100, max(_safe_int(x.get("score"), 0) for x in successful))
    return {
        "status": "success",
        "source_status": source_status,
        "ioc": ioc_raw,
        "detected_type": detected_type,
        "total_score": total_score,
        "verdict": _threat_verdict(total_score),
        "source_hits": len(successful),
        "enrichment": {
            "signals": successful,
            "tags": sorted({tag for item in successful for tag in (item.get("tags") or [])})[:20],
            # 这是"情报源覆盖率"，不是对恶意程度的置信度
            "source_coverage": int(100 * len(successful) / max(1, len(tasks))),
            "summary": " | ".join(x.get("summary", "") for x in successful)[:600],
        },
    }


@register_tool(
    name="threat_intel_report",
    description="Generate a Chinese-language threat intelligence assessment report "
    "from enrichment data. Call enrich_ioc first, then pass its output here.",
    category="report",
        expects="content",
)
async def report_ioc(ioc: str, detected_type: str, enrichment: dict, provider: str = "local") -> str:
    """Generate an AI threat intelligence assessment report."""
    system_prompt = (
        "你是资深威胁情报分析师。请基于给定情报证据撰写中文研判报告。\n"
        "要求：\n"
        "1) 输出为 Markdown，包含：执行摘要、威胁归因猜测、主要攻击手法、处置建议、误报风险提示。\n"
        "2) 结论要标注'依据来源'（例如 AbuseIPDB/OTX）。\n"
        "3) 禁止编造不存在的数据；不确定时明确写'暂无充分证据'。\n"
        "4) 不输出 JSON。"
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"IOC: {ioc}\n类型: {detected_type}\n"
                f"标准化情报数据(JSON):\n{json.dumps(enrichment, ensure_ascii=False)[:24000]}"
            ),
        },
    ]
    chunks: list[str] = []
    async for chunk in stream_completion(messages, provider=provider, temperature=0.2):
        chunks.append(chunk)
    return "".join(chunks)


# Import json at module level for report_ioc
import json  # noqa: E402
