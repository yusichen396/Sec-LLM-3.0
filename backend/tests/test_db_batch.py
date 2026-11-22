"""批量写入事务测试：整批成功、坏行整批回滚、分批提交。

用 sqlite 跑（DB-API 同构），把占位符换成 ?，验证的是事务语义本身。
"""

import sqlite3

import pytest

from agents.findings_store import persist_findings, persist_findings_safe
from db.batch import BulkWriteError, bulk_insert

DDL = """
CREATE TABLE scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    evidence_id TEXT,
    title TEXT,
    severity TEXT,
    target TEXT,
    detail TEXT
)
"""


@pytest.fixture()
def connect(tmp_path):
    db = tmp_path / "findings.db"

    def _connect():
        conn = sqlite3.connect(db)
        return conn

    conn = _connect()
    conn.execute(DDL)
    conn.commit()
    conn.close()
    return _connect


def _count(connect) -> int:
    conn = connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0]
    finally:
        conn.close()


def _findings(n: int) -> list[dict]:
    return [
        {
            "evidence_id": f"F{i:03d}",
            "title": f"发现 {i}",
            "severity": "high" if i % 2 else "low",
        }
        for i in range(n)
    ]


def test_bulk_insert_writes_all_rows(connect):
    rows = [("s1", f"F{i}", f"发现 {i}", "high", "https://a.test", "{}") for i in range(5)]
    written = bulk_insert(
        connect,
        "INSERT INTO scan_findings (session_id, evidence_id, title, severity, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
        rows,
        placeholder="?",
    )
    assert written == 5
    assert _count(connect) == 5


def test_bulk_insert_rolls_back_whole_batch(connect):
    """第二条整行缺列 -> executemany 失败 -> 第一条也不能留下。"""
    rows = [
        ("s1", "F1", "正常", "low", "https://a.test", "{}"),
        ("s1",),
    ]
    with pytest.raises(BulkWriteError):
        bulk_insert(
            connect,
            "INSERT INTO scan_findings (session_id, evidence_id, title, severity, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
            placeholder="?",
        )
    assert _count(connect) == 0


def test_bulk_insert_chunks_but_commits_once(connect):
    rows = [("s2", f"F{i}", f"发现 {i}", "low", "https://b.test", "{}") for i in range(7)]
    written = bulk_insert(
        connect,
        "INSERT INTO scan_findings (session_id, evidence_id, title, severity, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
        rows,
        chunk_size=3,
        placeholder="?",
    )
    assert written == 7
    assert _count(connect) == 7


def test_persist_findings_maps_fields(connect):
    written = persist_findings(connect, "s3", "https://c.test", _findings(3), placeholder="?")
    assert written == 3
    conn = connect()
    try:
        row = conn.execute(
            "SELECT evidence_id, severity, target FROM scan_findings ORDER BY id LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "F000"
    assert row[1] == "low"
    assert row[2] == "https://c.test"


def test_persist_findings_safe_swallows_error(connect):
    """扫描主流程用 safe 版：写失败只打日志，返回 0，不抛。"""
    bad_rows = [{"evidence_id": "F1", "title": "x"}]
    original = connect

    def broken_connect():
        conn = original()
        conn.execute("DROP TABLE scan_findings")
        conn.commit()
        return conn

    assert persist_findings_safe(broken_connect, "s4", "https://d.test", bad_rows, placeholder="?") == 0


def test_connect_failure_is_wrapped_and_safe():
    """连接本身失败也要包装成 BulkWriteError，safe 版更不能把异常抛给扫描主流程。"""

    def dead_connect():
        raise ConnectionError("MySQL 不可用")

    with pytest.raises(BulkWriteError):
        bulk_insert(
            dead_connect,
            "INSERT INTO scan_findings (session_id) VALUES (?)",
            [("s5",)],
            placeholder="?",
        )

    assert persist_findings_safe(
        dead_connect, "s5", "https://e.test", [{"evidence_id": "F9"}], placeholder="?"
    ) == 0

