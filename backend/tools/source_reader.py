"""Bounded, root-confined source reader for the code_audit task type.

The agent planner may only read files below ``AGENT_CODE_AUDIT_ROOT``; when that
setting is empty the tool refuses, because an LLM-driven path reader without a
root is an arbitrary file read.
"""
from pathlib import Path

from config import settings
from tools.registry import register_tool

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next", ".mypy_cache"}
_SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".whl",
    ".so", ".dll", ".exe", ".pyc", ".class", ".jar", ".bin", ".safetensors", ".onnx", ".sqlite3",
}
_MAX_FILES = 40
_MAX_FILE_BYTES = 200_000


def _resolve_under_root(raw: str) -> Path:
    root_value = (getattr(settings, "AGENT_CODE_AUDIT_ROOT", "") or "").strip()
    if not root_value:
        raise ValueError("AGENT_CODE_AUDIT_ROOT 未配置：代码审计需要显式允许的服务端根目录")
    root = Path(root_value).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"AGENT_CODE_AUDIT_ROOT 不是目录: {root}")
    candidate = Path(raw).expanduser()
    target = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("目标路径超出允许的审计根目录") from error
    return target


def _collect(path: Path, budget: int) -> tuple[list[dict], bool]:
    root = Path(getattr(settings, "AGENT_CODE_AUDIT_ROOT")).expanduser().resolve()
    files: list[dict] = []
    truncated = False

    def add(file_path: Path) -> None:
        nonlocal budget, truncated
        if len(files) >= _MAX_FILES or budget <= 0:
            truncated = True
            return
        if file_path.suffix.lower() in _SKIP_SUFFIXES:
            return
        limit = min(_MAX_FILE_BYTES, budget)
        try:
            with file_path.open("rb") as handle:
                blob = handle.read(limit + 1)
        except OSError:
            return
        if b"\x00" in blob[:2048]:
            return
        if len(blob) > limit:
            blob = blob[:limit]
            truncated = True
        budget -= len(blob)
        files.append({
            "path": file_path.relative_to(root).as_posix(),
            "content": blob.decode("utf-8", errors="replace"),
        })

    if path.is_file():
        add(path)
    else:
        for child in sorted(path.rglob("*")):
            if child.is_dir() or any(part in _SKIP_DIRS for part in child.parts):
                continue
            if child.is_symlink():
                continue
            add(child)
            if len(files) >= _MAX_FILES or budget <= 0:
                truncated = True
                break
    return files, truncated


@register_tool(
    name="read_source",
    description="Read source files for a code audit. Path must be inside the server-side "
    "AGENT_CODE_AUDIT_ROOT. Returns file contents (bounded) for the code_auditor tool. "
    "Call this first for task_type=code_audit, then pass the returned code to code_auditor.",
    category="recon",
        accepts="code",
        expects="content",
    requires_provider=False,
)
async def read_source(path: str = ".") -> dict:
    """Read a file or directory tree below the configured audit root."""
    try:
        target = _resolve_under_root(path or ".")
    except ValueError as error:
        return {"status": "error", "error": str(error)}
    if not target.exists():
        return {"status": "error", "error": f"路径不存在: {path}"}
    budget = int(getattr(settings, "AGENT_CODE_AUDIT_MAX_BYTES", 2 * 1024 * 1024))
    files, truncated = _collect(target, budget)
    if not files:
        return {"status": "error", "error": "没有可审计的文本文件", "path": str(target)}
    return {
        "status": "success",
        "root": str(Path(getattr(settings, "AGENT_CODE_AUDIT_ROOT")).expanduser().resolve()),
        "path": str(target),
        "file_count": len(files),
        "truncated": truncated,
        "files": files,
    }
