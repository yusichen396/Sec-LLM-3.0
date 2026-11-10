"""结构切分测试。"""
from core.rag.chunking import split_text

DOC = """# 安全开发规范

## 一、适用范围

本规范适用于公司所有对外提供服务的系统，包括 Web 应用、开放平台 API 与小程序。
内部工具只要处理个人信息，同样适用。

## 二、开发要求

所有 SQL 必须使用参数化查询，禁止把用户输入拼接进语句。
输出到页面的用户数据必须按上下文编码，HTML、属性、JavaScript 与 URL 分别处理。
口令存储统一使用 bcrypt，cost 不低于 12。

## 三、数据分级

| 级别 | 说明 | 访问控制 |
|---|---|---|
| 公开 | 可对外发布 | 无限制 |
| 内部 | 限员工 | 登录即可 |
| 敏感 | 个人信息 | 需审批 |
| 核心 | 重大影响 | 双人复核 |
"""


def test_headings_become_section_boundaries():
    chunks = split_text(DOC, size=200, overlap=20)
    sections = {c["section"] for c in chunks}
    assert "## 一、适用范围" in sections
    assert "## 二、开发要求" in sections
    assert "## 三、数据分级" in sections


def test_table_is_not_split():
    chunks = split_text(DOC, size=120, overlap=20)
    table_chunks = [c for c in chunks if "| 级别 |" in c["text"]]
    assert table_chunks, "表格应保留在某个块中"
    joined = "".join(c["text"] for c in table_chunks)
    for row in ("| 公开 |", "| 内部 |", "| 敏感 |", "| 核心 |"):
        assert row in joined, f"表格行 {row} 不应被切散"


def test_chunk_text_carries_its_section_title():
    chunks = split_text(DOC, size=200, overlap=20)
    body_chunks = [c for c in chunks if "参数化查询" in c["text"]]
    assert body_chunks
    assert body_chunks[0]["text"].startswith("## 二、开发要求"), "块应带章节标题作为上下文"


def test_long_paragraph_falls_back_to_sentences():
    long_text = "## 长段落\n\n" + "这是一句用来测试切分的说明。" * 40
    chunks = split_text(long_text, size=150, overlap=0)
    assert len(chunks) > 1
    for chunk in chunks:
        assert chunk["text"].endswith("。"), "按句子切时不应把句子截断"


def test_empty_input_returns_single_chunk():
    chunks = split_text("   ", size=100, overlap=10)
    assert len(chunks) == 1
