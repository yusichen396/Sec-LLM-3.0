"""事务化的批量写入。

单条循环 INSERT 的问题：一是慢（每行一次往返），二是中途失败会留下半批数据。
这里攒成一批 executemany，全部成功才 commit；任何一批失败就 rollback 整批，
调用方拿到 BulkWriteError 时库里不会多出半截数据。

MySQL 用 %s 占位符；测试里换 sqlite 时可以传 placeholder="?"。
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Sequence


class BulkWriteError(RuntimeError):
    """整批写入失败，已回滚。"""


def bulk_insert(
    connect: Callable[[], Any],
    sql: str,
    rows: Iterable[Sequence[Any]],
    *,
    chunk_size: int = 200,
    placeholder: str = "%s",
) -> int:
    """分批 executemany，一次事务提交；任一批失败整批回滚。

    connect: 返回 DB-API 连接的工厂（如 _db_connection）。
    返回实际写入的行数。
    """
    data = [tuple(row) for row in rows]
    if not data:
        return 0

    if placeholder != "%s":
        sql = sql.replace("%s", placeholder)

    written = 0
    conn = None
    try:
        conn = connect()
        by_chunk = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
        cursor = conn.cursor()
        try:
            for chunk in by_chunk:
                cursor.executemany(sql, chunk)
                written += len(chunk)
            conn.commit()
        finally:
            cursor.close()
    except Exception as exc:  # noqa: BLE001  连接失败也算整批失败
        if conn is not None:
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001  连接已断时 rollback 也会失败，忽略
                pass
        raise BulkWriteError(f"批量写入失败，已回滚 {written} 行：{exc}") from exc
    finally:
        if conn is not None:
            conn.close()

    return written
