"""Docker sandbox security-tool execution."""
import shlex
import uuid

from tools.registry import register_tool

_ALLOWED_TOOLS = {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb", "semgrep", "bandit"}


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

    sandbox_image = "sec-llm-sandbox:latest"
    container_name = f"sec-llm-{uuid.uuid4().hex}"
    effective_timeout = min(max(timeout, 1), 300)

    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--network", "bridge" if args[0] in {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb"} else "none",
        "--memory", "512m",
        "--cpus", "1",
        "--pids-limit", "64",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec",  # nosec B108: private per-container tmpfs, not a host temporary file
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
            proc.communicate(), timeout=effective_timeout
        )
        return {
            "stdout": stdout.decode("utf-8", errors="replace")[:50000],
            "stderr": stderr.decode("utf-8", errors="replace")[:10000],
            "exit_code": proc.returncode or 0,
        }
    except (asyncio.TimeoutError, asyncio.CancelledError) as error:
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
        return {"stdout": "", "stderr": f"Command timed out after {effective_timeout}s{cleanup_error}", "exit_code": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "Docker is not available on this system", "exit_code": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e)[:1000], "exit_code": -1}
