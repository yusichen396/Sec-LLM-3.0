"""Prompt-injection controls for untrusted RAG and tool data.

The filter removes only instruction-like spans. It deliberately keeps the rest
of a document intact so quoted examples and security discussions remain useful.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re


NEUTRALIZED = "[已中和不可信指令]"
SAFE_OUTPUT = "检测到模型输出可能受不可信内容影响，本次响应已拦截，请移除相关指令后重试。"
MAX_MODEL_OUTPUT_CHARS = 100_000

_CONTROL_PATTERNS = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+"
            r"(?:(?:all|any|the|your)\s+)?(?:previous|prior|above|system|developer)\s+"
            r"(?:instructions?|prompts?|rules?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override_zh",
        re.compile(
            r"(?:忽略|无视|绕过|覆盖|忘掉)(?:以上|之前|先前|系统|开发者|所有)(?:的)?"
            r"(?:所有(?:的)?)?(?:指令|提示词|规则|要求)"
        ),
    ),
    (
        "prompt_exfiltration",
        re.compile(
            r"\b(?:reveal|print|show|leak|repeat)\s+(?:the\s+)?"
            r"(?:system|developer)\s+(?:prompt|message|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_exfiltration_zh",
        re.compile(r"(?:输出|泄露|打印|显示|复述)(?:系统|开发者)(?:提示词|指令|消息)"),
    ),
    (
        "role_override",
        re.compile(r"\b(?:you are now|act as|pretend to be)\s+[^\r\n,.;，。；]{1,80}", re.IGNORECASE),
    ),
    (
        "role_override_zh",
        re.compile(r"(?:你现在是|扮演|假装你是)[^\r\n，。；]{1,40}"),
    ),
)

_OUTPUT_COMMAND = re.compile(
    r"(?:\b(?:and\s+)?(?:output|print|say|reply\s+with|return)\b|(?:然后|并且)?(?:输出|打印|回复))"
    r"\s*(?:exactly\s+|仅|只)?\s*"
    r"(?P<payload>\"[^\"\r\n]{1,80}\"|'[^'\r\n]{1,80}'|`[^`\r\n]{1,80}`|[A-Za-z0-9_:-]{3,64})",
    re.IGNORECASE,
)

_QUOTED = re.compile(r"`[^`\r\n]*`|\"[^\"\r\n]*\"|'[^'\r\n]*'|“[^”\r\n]*”|‘[^’\r\n]*’")
_DISCUSSION_CUES = (
    "讨论", "解释", "检测", "识别", "防御", "示例", "短语", "字符串", "提示注入", "引用",
    "discuss", "explain", "detect", "identify", "defend", "example", "phrase", "string",
    "prompt injection", "quoted",
)
_PROMPT_LEAK = re.compile(
    r"(?:\[ROLE\]|\[RULES\]|ANTI-JAILBREAK\s*\(CRITICAL\)|"
    r"You are \*\*Sec-LLM \(灵犀网卫\)\*\*)",
    re.IGNORECASE | re.DOTALL,
)
_INJECTION_COMPLIANCE = re.compile(
    r"(?:I (?:have )?(?:ignored|overridden) (?:the )?(?:previous|system) instructions|"
    r"previous instructions (?:have been|were) ignored|"
    r"我(?:已经|已)?(?:忽略|覆盖)了?(?:之前|系统)(?:的)?(?:指令|提示词))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SanitizedText:
    text: str
    detected: bool
    matches: tuple[str, ...] = ()
    requested_outputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class OutputValidation:
    allowed: bool
    reasons: tuple[str, ...] = ()


_DIRECT_BLOCK_MATCHES = {
    "instruction_override",
    "instruction_override_zh",
    "prompt_exfiltration",
    "prompt_exfiltration_zh",
}
_DIRECT_OVERRIDE_DISCUSSION = re.compile(
    r"(?:"
    r"(?:如何|怎么|请)?(?:讨论|解释|检测|识别|防御|分析).{0,80}(?:ignore|disregard|忽略|无视|覆盖)"
    r"|(?:discuss|explain|detect|identify|defend|analy[sz]e).{0,80}(?:ignore|disregard)"
    r"|(?:ignore previous instructions|忽略之前(?:所有)?指令).{0,40}(?:是什么意思|是什么|风险|攻击|防御|mean)"
    r")",
    re.IGNORECASE,
)


def _quoted_ranges(text: str) -> list[tuple[int, int]]:
    return [match.span() for match in _QUOTED.finditer(text)]


def _starts_in_range(start: int, ranges: list[tuple[int, int]]) -> bool:
    return any(left <= start < right for left, right in ranges)


def _is_quoted_discussion(text: str, start: int, ranges: list[tuple[int, int]]) -> bool:
    if not _starts_in_range(start, ranges):
        return False
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    line = text[line_start:None if line_end < 0 else line_end].casefold()
    return any(cue in line for cue in _DISCUSSION_CUES)


def _payload_value(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'`":
        return raw[1:-1].strip()
    return raw.strip()


def sanitize_untrusted_text(value: object) -> SanitizedText:
    """Neutralize high-confidence control spans in untrusted text.

    Quoted mentions are preserved only when their line has discussion context.
    Output commands are neutralized only when the same input contains another
    high-confidence injection primitive.
    """
    text = "" if value is None else str(value)
    quoted = _quoted_ranges(text)
    spans: list[tuple[int, int, str]] = []

    for name, pattern in _CONTROL_PATTERNS:
        for match in pattern.finditer(text):
            if not _is_quoted_discussion(text, match.start(), quoted):
                spans.append((*match.span(), name))

    requested_outputs: list[str] = []
    if spans:
        for match in _OUTPUT_COMMAND.finditer(text):
            if _is_quoted_discussion(text, match.start(), quoted):
                continue
            spans.append((*match.span(), "requested_output"))
            payload = _payload_value(match.group("payload"))
            if payload:
                requested_outputs.append(payload)

    if not spans:
        return SanitizedText(text=text, detected=False)

    # Prefer the earliest, widest non-overlapping match and leave all other
    # prose untouched.
    selected: list[tuple[int, int, str]] = []
    for span in sorted(spans, key=lambda item: (item[0], -(item[1] - item[0]))):
        if selected and span[0] < selected[-1][1]:
            continue
        selected.append(span)

    parts: list[str] = []
    cursor = 0
    for start, end, _ in selected:
        parts.extend((text[cursor:start], NEUTRALIZED))
        cursor = end
    parts.append(text[cursor:])
    names = tuple(dict.fromkeys(name for _, _, name in selected))
    payloads = tuple(dict.fromkeys(requested_outputs))
    return SanitizedText(text="".join(parts), detected=True, matches=names, requested_outputs=payloads)


def detect_direct_prompt_injection(value: object) -> SanitizedText:
    """Detect high-confidence direct attempts without blocking benign role play."""
    original = "" if value is None else str(value)
    scan = sanitize_untrusted_text(original)
    blocked = tuple(name for name in scan.matches if name in _DIRECT_BLOCK_MATCHES)
    if not scan.requested_outputs and _DIRECT_OVERRIDE_DISCUSSION.search(original):
        blocked = tuple(name for name in blocked if not name.startswith("instruction_override"))
    return SanitizedText(
        text=scan.text,
        detected=bool(blocked),
        matches=blocked,
        requested_outputs=scan.requested_outputs,
    )


def wrap_untrusted_text(label: str, value: object) -> tuple[str, SanitizedText]:
    """Return a clearly delimited, JSON-escaped data block and its scan result."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", label):
        raise ValueError("Invalid untrusted-data label")
    scan = sanitize_untrusted_text(value)
    encoded = json.dumps(scan.text, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")
    block = f"<{label}_data>\n{encoded}\n</{label}_data>"
    return block, scan


def wrap_untrusted_data(
    label: str, value: object, max_chars: int | None = None
) -> tuple[str, SanitizedText]:
    """Recursively sanitize structured data before JSON serialization."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", label):
        raise ValueError("Invalid untrusted-data label")

    scans: list[SanitizedText] = []

    def clean(item: object) -> object:
        if isinstance(item, str):
            scan = sanitize_untrusted_text(item)
            scans.append(scan)
            return scan.text
        if isinstance(item, dict):
            return {str(clean(key)): clean(inner) for key, inner in item.items()}
        if isinstance(item, (list, tuple)):
            return [clean(inner) for inner in item]
        return item

    cleaned = clean(value)
    encoded = json.dumps(cleaned, ensure_ascii=False, default=str)
    if max_chars is not None:
        encoded = encoded[:max_chars]
    encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e")
    matches = tuple(dict.fromkeys(name for scan in scans for name in scan.matches))
    payloads = tuple(dict.fromkeys(payload for scan in scans for payload in scan.requested_outputs))
    combined = SanitizedText(
        text=encoded,
        detected=any(scan.detected for scan in scans),
        matches=matches,
        requested_outputs=payloads,
    )
    return f"<{label}_data>\n{encoded}\n</{label}_data>", combined


def validate_model_output(text: object, requested_outputs: tuple[str, ...] = ()) -> OutputValidation:
    """Reject observable injection compliance before model output reaches a user."""
    output = "" if text is None else str(text)
    reasons: list[str] = []
    if not output.strip():
        reasons.append("empty_output")
    if len(output) > MAX_MODEL_OUTPUT_CHARS:
        reasons.append("output_too_large")
    if _PROMPT_LEAK.search(output):
        reasons.append("system_prompt_disclosure")
    if _INJECTION_COMPLIANCE.search(output):
        reasons.append("instruction_override_acknowledged")

    normalized = re.sub(r"[^\w\u4e00-\u9fff:-]+", "", output.casefold())
    for requested in requested_outputs:
        payload = re.sub(r"[^\w\u4e00-\u9fff:-]+", "", requested.casefold())
        if payload and normalized == payload:
            reasons.append("requested_payload_emitted")
            break

    return OutputValidation(allowed=not reasons, reasons=tuple(reasons))


def split_complete_sentences(text: str) -> tuple[list[str], str]:
    """Split complete response sentences while retaining an unfinished tail."""
    sentences: list[str] = []
    start = 0
    for index, char in enumerate(text):
        boundary = char in "。！？!?；;\n"
        if char == ".":
            previous = text[index - 1] if index else ""
            following = text[index + 1] if index + 1 < len(text) else ""
            boundary = not (previous.isdigit() and following.isdigit()) and (
                not following or following.isspace()
            )
        if boundary:
            sentences.append(text[start:index + 1])
            start = index + 1
    return sentences, text[start:]
