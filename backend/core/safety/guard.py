"""话题域识别与越权请求拦截（规则层）。

设计目标：
1. 把请求分成「安全域内」与「非安全域」，非安全域拒答；
2. 识别「越权」——对真实目标发起攻击且没有授权声明；
3. 区分「已授权渗透」与「未授权攻击」，并把"口头声称已授权但打外网"降级为澄清。

纯规则实现，无外部依赖，可离线评测。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Decision = Literal["allow", "clarify", "refuse"]

OFFENSIVE = [
    "入侵", "打点", "拿shell", "getshell", "提权", "拖库", "撞库", "盗号",
    "免杀", "木马", "后门", "社工", "钓鱼邮件", "钓鱼链接", "ddos",
    "拒绝服务", "绕过登录", "爆破", "扫号", "刷单", "薅羊毛", "破解",
    "爬取个人信息", "查开房", "查住址", "人肉", "勒索", "打穿", "打掉",
    "搞掉", "黑掉", "窃取", "偷取", "盗取", "入侵检测",  # 最后一项由上下文规则排除
]

DEFENSIVE = [
    "防御", "加固", "检测", "检测规则", "应急", "响应", "溯源", "修复方案",
    "审计", "合规", "等保", "基线", "告警", "排查", "防范", "防护", "防止",
    "安全设计", "安全评估", "安全意识", "培训", "风险", "治理", "零信任",
    "日志分析", "异常请求", "漏洞修复", "补丁", "策略", "被入侵", "失陷",
    "被攻击", "泄露", "中招", "处置", "避免", "整改",
    "判断", "识别", "辨别", "区分", "甄别", "研判",
]

AUTHORIZATION = [
    "已授权", "授权", "书面授权", "获得许可", "已获许可", "我方", "我们公司",
    "自有", "自己的", "内部", "靶场", "测试环境", "实验环境", "ctf",
    "渗透测试", "红队", "众测", "甲方", "工单",
]

OFF_TOPIC = [
    "天气", "作文", "失恋", "电影", "翻译", "减肥", "股票", "红烧肉", "菜谱",
    "起名", "辞职信", "手机推荐", "英语口语", "健身", "旅游", "星座",
    "写诗", "情书", "简历", "高考", "考研", "房价", "基金", "表白", "星座",
]

SECURITY_DOMAIN = [
    "漏洞", "攻击", "渗透", "安全", "加密", "证书", "防火墙", "waf", "ids",
    "ips", "杀毒", "病毒", "恶意", "样本", "情报", "ioc", "cve", "注入",
    "xss", "csrf", "ssrf", "rce", "0day", "apt", "蜜罐", "溯源", "靶场",
    "ctf", "逆向", "二进制", "端口扫描", "子域名", "横向", "内网", "webshell",
    "木马", "钓鱼", "等保", "合规", "日志", "权限", "提权", "加固",
    "入侵", "应急", "响应", "失陷", "owasp", "零信任", "红队", "攻防",
]

# "打瘫 / 拖库 / 拿权限" 这类动宾被拆开的说法，用正则补
SPLIT_OFFENSIVE = [
    re.compile(r"拖.{0,30}库"),
    re.compile(r"打.{0,2}瘫"),
    re.compile(r"搞.{0,2}掉"),
    re.compile(r"拿.{0,4}权限"),
    re.compile(r"提.{0,2}权"),
    re.compile(r"绕.{0,4}登录"),
    re.compile(r"盗.{0,2}号"),
    re.compile(r"进.{0,6}(?:内网|后台|系统)"),
    re.compile(r"(?:黑|搞|弄).{0,3}(?:进去|进来)"),
]

TARGET_RE = re.compile(
    r"(https?://[^\s，。；、）)]+"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|\b[a-z0-9][a-z0-9-]*\.(?:com|cn|net|org|io|top|xyz|test|local|dev|lab|internal)\b)",
    re.IGNORECASE,
)

PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)
LAB_TLD_RE = re.compile(r"\.(?:test|local|lab|internal)$", re.IGNORECASE)


def _norm(text: str) -> str:
    """去掉空白，避免 'SQL 注入' 匹配不到 'sql注入'。"""
    return re.sub(r"\s+", "", text.lower())


def _hits(text: str, words: list[str]) -> list[str]:
    low = _norm(text)
    return [w for w in words if _norm(w) in low]


def _is_public_target(target: str) -> bool:
    host = re.sub(r"^https?://", "", target, flags=re.IGNORECASE).split("/")[0]
    host = host.split(":")[0]
    if PRIVATE_IP_RE.match(host) or LAB_TLD_RE.search(host):
        return False
    return True


@dataclass
class GuardResult:
    decision: Decision
    category: str
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"decision": self.decision, "category": self.category, "reasons": self.reasons}


def check(text: str) -> GuardResult:
    if not text or not text.strip():
        return GuardResult("refuse", "empty", ["请求为空"])

    query = text.strip()
    off = _hits(query, OFFENSIVE)
    dfn = _hits(query, DEFENSIVE)
    auth = _hits(query, AUTHORIZATION)
    topic = _hits(query, OFF_TOPIC)
    domain = _hits(query, SECURITY_DOMAIN)
    m = TARGET_RE.search(query)
    target = m.group(0) if m else None

    # "入侵检测" 是防御术语，不该被当成攻击意图
    if "入侵检测" in off and ("检测" in dfn or "检测" in query):
        off = [w for w in off if w != "入侵检测"]

    # 动宾被拆开的说法（"拖 xx 的库"）
    off = off + [p.pattern for p in SPLIT_OFFENSIVE if p.search(query)]

    reasons: list[str] = []

    # 1) 攻击意图 + 真实外网目标 + 无授权 -> 拒答
    if off and target and not auth:
        return GuardResult("refuse", "unauthorized_attack",
                           [f"攻击意图={off[:2]} 目标={target} 无授权声明"])

    # 2) 自称授权，但目标是外网资产（或压根没说目标）-> 降级为澄清
    if off and auth and (target is None or _is_public_target(target)):
        return GuardResult("clarify", "require_authorization_scope",
                           [f"攻击意图={off[:2]}，需补充授权范围/工单号"])

    # 3) 有攻击意图、无授权、且不是防御语境 -> 拒答
    if off and not auth and not dfn:
        return GuardResult("refuse", "offensive_without_authorization",
                           [f"攻击意图={off[:2]} 无授权 非防御语境"])

    # 4) 提到目标但没授权、也不是防御咨询 -> 先澄清
    if target and _is_public_target(target) and not auth and not dfn:
        return GuardResult("clarify", "missing_authorization",
                           [f"目标={target} 未声明授权范围"])

    # 5) 非安全话题，且没有任何安全域词汇 -> 拒答
    if topic and not domain:
        return GuardResult("refuse", "off_topic", [f"非安全话题={topic[:2]}"])

    # 6) 完全没有安全域特征（也没有防御意图）-> 拒答
    if not domain and not auth and not dfn:
        return GuardResult("refuse", "off_topic", ["未命中安全域词汇"])

    if dfn:
        return GuardResult("allow", "defensive", [f"防御意图={dfn[:2]}"])
    if auth:
        return GuardResult("allow", "authorized_assessment", [f"授权声明={auth[:2]}"])
    return GuardResult("allow", "security_domain", ["命中安全域词汇"])
