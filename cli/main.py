"""Sec-LLM Agent CLI — command-line interface for the AI agent platform.

Every command talks to the authenticated API: provide a JWT with --token /
SEC_LLM_TOKEN, or the OpenClaw skill key with --skill-key /
SEC_LLM_SKILL_API_KEY.
"""
import json
import os
import sys

import typer

DEFAULT_BASE_URL = os.environ.get("SEC_LLM_BASE_URL", "http://localhost:8000")

app = typer.Typer(
    name="sec-llm",
    help="Sec-LLM AI Agent — autonomous cybersecurity testing platform",
)

_base_url_option = typer.Option(
    DEFAULT_BASE_URL, "--base-url", "-u", help="Sec-LLM API base URL", envvar="SEC_LLM_BASE_URL"
)
_token_option = typer.Option(
    None, "--token", "-t", help="JWT access token", envvar="SEC_LLM_TOKEN"
)
_skill_key_option = typer.Option(
    None, "--skill-key", help="OpenClaw skill API key", envvar="SEC_LLM_SKILL_API_KEY"
)


def _headers(token: str | None, skill_key: str | None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif skill_key:
        headers["X-Skill-Api-Key"] = skill_key
    return headers


def _require_auth(token: str | None, skill_key: str | None) -> dict:
    if not token and not skill_key:
        typer.echo(
            "未提供凭据：请传 --token / SEC_LLM_TOKEN，或 --skill-key / SEC_LLM_SKILL_API_KEY",
            err=True,
        )
        raise typer.Exit(code=2)
    return _headers(token, skill_key)


def _url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or IP to scan"),
    provider: str = typer.Option("local", help="LLM provider: local or cloud"),
    base_url: str = _base_url_option,
    token: str = _token_option,
    skill_key: str = _skill_key_option,
):
    """Run an automated web scan against a target."""
    import httpx

    headers = _require_auth(token, skill_key)
    typer.echo(f"Starting web_scan against {target} (provider={provider})...")
    try:
        resp = httpx.post(
            _url(base_url, "/api/agent/run"),
            headers=headers,
            json={"target": target, "task_type": "web_scan", "provider": provider},
            timeout=15,
        )
        resp.raise_for_status()
        session_id = resp.json()["session_id"]
        typer.echo(f"Task started. Session ID: {session_id}")
        typer.echo(f"Monitor: sec-llm stream {session_id}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def audit(
    path: str = typer.Argument(..., help="Server-side path under AGENT_CODE_AUDIT_ROOT"),
    provider: str = typer.Option("local", help="LLM provider"),
    base_url: str = _base_url_option,
    token: str = _token_option,
    skill_key: str = _skill_key_option,
):
    """Audit server-side source code (the path is read on the server, not locally)."""
    import httpx

    headers = _require_auth(token, skill_key)
    typer.echo(f"Auditing {path} (server side)...")
    try:
        resp = httpx.post(
            _url(base_url, "/api/agent/run"),
            headers=headers,
            json={"target": path, "task_type": "code_audit", "provider": provider},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        typer.echo(f"Task started. Session ID: {data['session_id']}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def stream(
    session_id: str = typer.Argument(..., help="Agent session ID to monitor"),
    base_url: str = _base_url_option,
    token: str = _token_option,
    skill_key: str = _skill_key_option,
):
    """Stream agent execution logs in real-time."""
    import httpx

    headers = _require_auth(token, skill_key)
    typer.echo(f"Streaming agent session {session_id}...\n")
    try:
        with httpx.stream(
            "GET", _url(base_url, f"/api/agent/{session_id}/stream"),
            headers=headers, timeout=None,
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                try:
                    event = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "log":
                    typer.echo(event.get("message", ""))
                elif event.get("type") == "done":
                    typer.echo(f"\n{'=' * 60}")
                    typer.echo(f"Task {event.get('status')}. Findings: {event.get('findings_count', 0)}")
                    break
    except KeyboardInterrupt:
        typer.echo("\nStream interrupted.")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def status(
    session_id: str = typer.Argument(..., help="Agent session ID"),
    base_url: str = _base_url_option,
    token: str = _token_option,
    skill_key: str = _skill_key_option,
):
    """Check agent task status."""
    import httpx

    headers = _require_auth(token, skill_key)
    try:
        resp = httpx.get(_url(base_url, f"/api/agent/{session_id}/status"), headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        typer.echo(f"Session: {data['session_id']}")
        typer.echo(f"Status: {data['status']}")
        typer.echo(f"Phase: {data['phase']}")
        typer.echo(f"Progress: {data['steps_completed']}/{data['steps_total']} steps")
        typer.echo(f"Findings: {data['findings_count']}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def report(
    session_id: str = typer.Argument(..., help="Agent session ID"),
    base_url: str = _base_url_option,
    token: str = _token_option,
    skill_key: str = _skill_key_option,
):
    """Print the final agent report."""
    import httpx

    headers = _require_auth(token, skill_key)
    try:
        resp = httpx.get(_url(base_url, f"/api/agent/{session_id}/report"), headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if data.get("report"):
            typer.echo(data["report"])
        else:
            typer.echo(f"No report available (status={data.get('status')}).")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def intel(
    ioc: str = typer.Argument(..., help="IOC to lookup: IP, domain, MD5, or SHA256"),
    base_url: str = _base_url_option,
    token: str = _token_option,
    skill_key: str = _skill_key_option,
):
    """Lookup threat intelligence for an IOC."""
    import httpx

    headers = _require_auth(token, skill_key)
    typer.echo(f"Looking up threat intelligence for: {ioc}")
    try:
        resp = httpx.post(
            _url(base_url, "/api/security-tools/threat-intel/enrich"),
            headers=headers,
            json={"ioc": ioc, "ioc_type": "auto"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        typer.echo(f"Type: {data.get('detected_type', '?')}")
        typer.echo(f"Verdict: {data.get('verdict', '?')}")
        typer.echo(f"Score: {data.get('total_score', 0)}/100")
        typer.echo(f"Sources: {data.get('source_hits', 0)}")
        if data.get("source_status"):
            typer.echo(f"Source status: {data['source_status']}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
