"""扫描发现的落库：把 findings 从 JSON blob 拆成可查询的行。

agent_sessions.findings 里存的是 JSON，能看不能查（按严重级别统计、按目标检索都要全表扫）。
这里在报告完成时把发现的摘要批量写进 scan_findings，一条事务写完，
失败只记日志不打断扫描本身——审计和展示都不该因为这一张表挂了而停摆。
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable

from db.batch import bulk_insert

INSERT_SQL = (
    "INSERT INTO scan_findings (session_id, evidence_id, title, severity, target, detail) "
    "VALUES (%s, %s, %s, %s, %s, %s)"
)


def _row(session_id: str, target: str, finding: dict) -> tuple:
    return (
        session_id,
        str(finding.get("evidence_id") or "")[:64],
        str(finding.get("title") or finding.get("name") or "")[:255],
        str(finding.get("severity") or "")[:20],
        target[:500],
        json.dumps(finding, ensure_ascii=False)[:4000],
    )


def persist_findings(
    connect: Callable[[], Any],
    session_id: str,
    target: str,
    findings: Iterable[dict],
    *,
    placeholder: str = "%s",
) -> int:
    """批量写入发现，返回写入行数；整批失败会抛 BulkWriteError，由调用方兜住。"""
    rows = [_row(session_id, target, f) for f in findings if isinstance(f, dict)]
    if not rows:
        return 0
    return bulk_insert(connect, INSERT_SQL, rows, placeholder=placeholder)


def persist_findings_safe(
    connect: Callable[[], Any],
    session_id: str,
    target: str,
    findings: Iterable[dict],
    *,
    placeholder: str = "%s",
) -> int:
    """同 persist_findings，但把异常吞掉只打日志（给扫描主流程用）。

    这里故意捕获所有异常：落库只是附带产物，数据库连不上也不该让扫描结果丢失。
    """
    try:
        return persist_findings(connect, session_id, target, findings, placeholder=placeholder)
    except Exception as error:  # noqa: BLE001
        print(f"[FINDINGS] batch write failed for {session_id}: {error}")
        return 0
