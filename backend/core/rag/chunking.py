"""结构感知切分：先按标题/段落分节，超长再按句子聚合，表格整块保留。

相比纯字符递归切分：
- 不跨章节切（标题是天然语义边界）
- 表格整块保留，表头和数据不分离
- 段落过长时才退化为按句子切
"""
from __future__ import annotations

import re

# 中文与 Markdown 标题
HEADING_RE = re.compile(
    r"^\s*(?:"
    r"#{1,6}\s+\S"                     # Markdown 标题
    r"|第[一二三四五六七八九十百]+[章节条]"   # 第X章 / 第X节
    r"|[一二三四五六七八九十]+[、.．]"        # 一、
    r"|[（(][一二三四五六七八九十]+[）)]"      # （一）
    r"|\d+(?:\.\d+)+\s+\S"              # 1.2 标题
    r")"
)
TABLE_RE = re.compile(r"^\s*\|.*\|\s*$")
SENTENCE_END = "。！？；!?;\n"


def _is_heading(line: str) -> bool:
    return bool(HEADING_RE.match(line))


def _split_sentences(paragraph: str) -> list[str]:
    """按句末标点切句，保留标点。"""
    out, buf = [], ""
    for char in paragraph:
        buf += char
        if char in SENTENCE_END:
            out.append(buf)
            buf = ""
    if buf.strip():
        out.append(buf)
    return [s for s in out if s.strip()]


def _pack(sentences: list[str], size: int, overlap: int) -> list[str]:
    """把句子打包成不超过 size 的块，块间按字符数重叠若干句。"""
    if not sentences:
        return []
    chunks: list[str] = []
    current: list[str] = []
    length = 0

    for sentence in sentences:
        if length + len(sentence) > size and current:
            chunks.append("".join(current).strip())
            # 尾部重叠：保留末尾若干句
            tail, tail_len = [], 0
            for item in reversed(current):
                if tail_len + len(item) > overlap:
                    break
                tail.insert(0, item)
                tail_len += len(item)
            current, length = tail, tail_len
        current.append(sentence)
        length += len(sentence)

    if current:
        chunks.append("".join(current).strip())
    return [c for c in chunks if c]


def split_text(text: str, size: int = 500, overlap: int = 50) -> list[dict]:
    """返回 [{'text': 块内容, 'section': 所属标题}]。"""
    lines = text.splitlines()
    sections: list[tuple[str, list[str]]] = [("", [])]
    table_buffer: list[str] = []

    def flush_table() -> None:
        if table_buffer:
            sections[-1][1].extend(table_buffer)
            table_buffer.clear()

    for line in lines:
        if TABLE_RE.match(line):
            table_buffer.append(line)
            continue
        flush_table()
        if _is_heading(line):
            sections.append((line.strip(), []))
        else:
            sections[-1][1].append(line)
    flush_table()

    chunks: list[dict] = []
    for title, body_lines in sections:
        body = "\n".join(body_lines).strip()
        if not body:
            if title:
                chunks.append({"text": title, "section": title})
            continue
        prefix = f"{title}\n" if title else ""
        budget = max(size - len(prefix), 80)

        paragraph = []
        for block in re.split(r"\n\s*\n", body):
            block = block.strip()
            if not block:
                continue
            if TABLE_RE.match(block.splitlines()[0]):
                # 表格整块，不拆
                if paragraph:
                    for piece in _pack(_split_sentences("\n".join(paragraph)), budget, overlap):
                        chunks.append({"text": prefix + piece, "section": title})
                    paragraph = []
                chunks.append({"text": prefix + block, "section": title})
                continue
            paragraph.append(block)

        if paragraph:
            for piece in _pack(_split_sentences("\n".join(paragraph)), budget, overlap):
                chunks.append({"text": prefix + piece, "section": title})

    return chunks or [{"text": text.strip(), "section": ""}]


def split_text_semantic(
    text: str,
    embed_fn,
    size: int = 500,
    overlap: int = 50,
    threshold: float = 0.55,
) -> list[dict]:
    """语义切分：相邻句子余弦相似度低于阈值处断开，再按 size 合并。

    embed_fn: 把一批句子转成向量列表的函数（复用入库时的嵌入模型）。
    """
    sections = split_text(text, size=size, overlap=0)
    chunks: list[dict] = []
    for section in sections:
        body = section["text"]
        sentences = _split_sentences(body)
        if len(sentences) <= 1:
            chunks.append(section)
            continue

        vectors = embed_fn(sentences)
        group: list[str] = [sentences[0]]
        for i in range(1, len(sentences)):
            prev, cur = vectors[i - 1], vectors[i]
            dot = sum(a * b for a, b in zip(prev, cur))
            norm = (sum(a * a for a in prev) ** 0.5) * (sum(b * b for b in cur) ** 0.5) or 1.0
            similarity = dot / norm
            long_enough = sum(len(s) for s in group) >= size // 2
            if similarity < threshold or sum(len(s) for s in group) >= size:
                if long_enough:
                    chunks.append({"text": "".join(group).strip(), "section": section["section"]})
                    group = []
            group.append(sentences[i])
        if group:
            chunks.append({"text": "".join(group).strip(), "section": section["section"]})
    return [c for c in chunks if c["text"]] or [{"text": text.strip(), "section": ""}]
