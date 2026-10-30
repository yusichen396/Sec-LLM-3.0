"""Fail-closed Docker execution. No daemon socket, credentials or labels are mounted."""
import json
from pathlib import Path
import subprocess
import threading
import time
import uuid

DEFAULT_IMAGE = "sec-llm-rsi:latest"


def bounded_run(arguments, *, timeout, log, max_bytes=8_000_000):
    """Bound both execution time and host log growth for untrusted container output."""
    if timeout <= 0:
        raise TimeoutError("Sandbox time budget exhausted")
    stopped = threading.Event()
    errors = []
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + timeout
    with log.open("wb") as stream:
        def drain():
            total = 0
            try:
                while chunk := process.stdout.read(65536):
                    stream.write(chunk[:max(0, max_bytes - total)])
                    total += len(chunk)
                    if total > max_bytes:
                        errors.append("Sandbox output exceeded its size budget")
                        stopped.set()
                        return
            except (OSError, ValueError) as error:
                errors.append(str(error))
                stopped.set()
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            while process.poll() is None:
                if stopped.wait(0.05):
                    raise RuntimeError(errors[0])
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(arguments, timeout)
            reader.join(timeout=max(0.01, deadline - time.monotonic()))
            if reader.is_alive():
                raise subprocess.TimeoutExpired(arguments, timeout)
            if errors:
                raise RuntimeError(errors[0])
            if process.returncode:
                raise RuntimeError(f"Sandbox acceptance failed ({process.returncode}); see {log}")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            reader.join(timeout=1)


def preflight(image=DEFAULT_IMAGE):
    for command in (["docker", "info", "--format", "{{.OSType}}"],
                    ["docker", "image", "inspect", image, "--format", "{{.Id}}"]):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=True)
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("RSI Docker engine/image unavailable; build sandbox/rsi/Dockerfile first") from error
        if command[1] == "info" and result.stdout.strip() != "linux":
            raise RuntimeError("RSI requires Linux containers")
    return {"executor": "docker", "image": image, "image_id": result.stdout.strip()}


def command(image, mounts, arguments, name):
    result = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "64",
              "--memory", "4g", "--cpus", "2", "--user", "65534:65534", "--log-driver", "none",
              "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g", "--workdir", "/workspace",  # nosec B108: private per-container tmpfs, not host /tmp
              "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONPATH=/workspace",
              "--env", "HF_HUB_OFFLINE=1", "--env", "TRANSFORMERS_OFFLINE=1",
              "--env", "HF_HOME=/tmp/huggingface", "--env", "HOME=/tmp",
              "--env", "OMP_NUM_THREADS=2", "--env", "MKL_NUM_THREADS=2",
              "--env", "OPENBLAS_NUM_THREADS=2", "--env", "RERANKER_MODEL_PATH=/models/bge-reranker-base"]
    for source, target in mounts:
        source = Path(source).resolve()
        if "," in str(source) or not source.exists():
            raise ValueError("Invalid read-only sandbox mount")
        result += ["--mount", f"type=bind,source={source},target={target},readonly"]
    return result + [image, *arguments]


def run(image, mounts, arguments, *, timeout, log):
    name = "sec-rsi-" + uuid.uuid4().hex
    try:
        bounded_run(command(image, mounts, arguments, name), timeout=timeout, log=log)
    finally:
        # Also kills descendants when the client times out; --rm alone is insufficient.
        try:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            pass


def read_result(log):
    if log.stat().st_size > 8_000_000:
        raise ValueError("Sandbox output exceeded its size budget")
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    matches = [line[len("RSI_RESULT="):] for line in lines if line.startswith("RSI_RESULT=")]
    if len(matches) != 1 or len(matches[0]) > 5_000_000:
        raise ValueError("Sandbox must return exactly one bounded result")
    return json.loads(matches[0])
