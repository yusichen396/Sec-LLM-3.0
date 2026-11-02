"""Docker sandbox security-tool execution."""
import shlex
import uuid

from config import settings
from tools.registry import register_tool

_ALLOWED_TOOLS = {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb", "semgrep", "bandit"}
_STDOUT_LIMIT = 1_000_000
_STDERR_LIMIT = 256_000


async def _capture(proc):
    import asyncio

    async def read(stream, limit):
        content = bytearray()
        while chunk := await stream.read(16384):
            if len(content) + len(chunk) > limit:
                raise ValueError("Tool output exceeded its size budget")
            content.extend(chunk)
        return bytes(content)

    tasks = [asyncio.create_task(read(proc.stdout, _STDOUT_LIMIT)),
             asyncio.create_task(read(proc.stderr, _STDERR_LIMIT)), asyncio.create_task(proc.wait())]
    try:
        stdout, stderr, _ = await asyncio.gather(*tasks)
        return stdout, stderr
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@register_tool(
    name="shell_exec",
    description="Execute an approved security tool in an isolated Docker sandbox. "
    "Use for running security tools like nmap, sqlmap, nuclei, ffuf, etc. "
    "Returns stdout, stderr, and exit code. Max 300s timeout.",
    category="recon",
    requires_provider=False,
)
async def shell_exec(command: str, timeout: int = 300) -> dict:
    """Execute an approved tool without invoking a shell."""
    import asyncio

    if any(char in command for char in ";&|><`$\n\r"):
        return {"stdout": "", "stderr": "Command rejected: shell syntax is not allowed", "exit_code": -1}
    try:
        args = shlex.split(command)
    except ValueError:
        args = []
    if not args or args[0] not in _ALLOWED_TOOLS:
        return {"stdout": "", "stderr": "Command rejected: unsupported tool", "exit_code": -1}

    sandbox_image = settings.AGENT_SANDBOX_IMAGE
    container_name = f"sec-llm-{uuid.uuid4().hex}"
    effective_timeout = min(max(timeout, 1), 300)

    tool_name = args[0]
    needs_network = tool_name in {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb"}

    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--network", "bridge" if needs_network else "none",
        "--memory", "512m",
        "--cpus", "1",
        "--pids-limit", "64",
        # 与 RSI 沙箱对齐：去掉所有 capability、禁止提权、不作 root 运行
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev",  # nosec B108: private per-container tmpfs, not a host temporary file
        "--log-driver", "none",
        "--env", "HOME=/tmp",
        sandbox_image,
        *args,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            _capture(proc), timeout=effective_timeout
        )
        return {
            "stdout": stdout.decode("utf-8", errors="replace")[:50000],
            "stderr": stderr.decode("utf-8", errors="replace")[:10000],
            "exit_code": proc.returncode or 0,
        }
    except (asyncio.TimeoutError, asyncio.CancelledError, ValueError) as error:
        cleanup_error = ""
        try:
            cleanup = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if await asyncio.wait_for(cleanup.wait(), 10):
                cleanup_error = "; container removal could not be confirmed"
        except (OSError, asyncio.TimeoutError):
            cleanup_error = "; container removal could not be confirmed"
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
        if isinstance(error, asyncio.CancelledError):
            raise
        reason = str(error) if isinstance(error, ValueError) else f"Command timed out after {effective_timeout}s"
        return {"stdout": "", "stderr": reason + cleanup_error, "exit_code": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "Docker is not available on this system", "exit_code": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e)[:1000], "exit_code": -1}
