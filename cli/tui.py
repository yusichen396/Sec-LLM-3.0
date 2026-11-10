"""Textual TUI for Sec-LLM Agent — real-time agent monitoring terminal interface."""
import asyncio
import os
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, Button, ListView, ListItem, RichLog
from textual.screen import Screen
from textual.binding import Binding

API_BASE = os.environ.get("SEC_LLM_BASE_URL", "http://localhost:8000").rstrip("/")
_TOKEN = os.environ.get("SEC_LLM_TOKEN")
_SKILL_KEY = os.environ.get("SEC_LLM_SKILL_API_KEY")


def _auth_headers() -> dict:
    """TUI 与 CLI 使用同一套凭据；没有凭据时后端会返回 401。"""
    if _TOKEN:
        return {"Authorization": f"Bearer {_TOKEN}"}
    if _SKILL_KEY:
        return {"X-Skill-Api-Key": _SKILL_KEY}
    return {}


class AgentMonitorScreen(Screen):
    """Main agent monitoring screen with live log stream and status panel."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("c", "clear_log", "Clear Log"),
        Binding("r", "refresh", "Refresh Status"),
    ]

    def __init__(self, session_id: str = ""):
        super().__init__()
        self.session_id = session_id
        self._stream_task = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="left-panel"):
                yield Static("Agent Status", id="status-title")
                yield Static("Session: --", id="session-id")
                yield Static("Status: --", id="status-text")
                yield Static("Phase: --", id="phase-text")
                yield Static("Findings: 0", id="findings-count")
                yield Static("Progress: 0/0 steps", id="progress-text")
            with Vertical(id="right-panel"):
                yield RichLog(id="log-view", highlight=True, markup=True, wrap=True)
        with Horizontal(id="input-bar"):
            yield Input(placeholder="Enter target URL or session ID...", id="target-input")
            yield Button("Start Scan", id="start-btn", variant="primary")
            yield Button("Check Status", id="status-btn")
            yield Button("Stream", id="stream-btn")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#log-view", RichLog).write("[bold cyan]Sec-LLM Agent TUI Ready[/bold cyan]")
        self.query_one("#log-view", RichLog).write("Enter a target URL and click 'Start Scan' or enter a session ID and click 'Stream'.")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        target = self.query_one("#target-input", Input).value.strip()

        if event.button.id == "start-btn":
            if not target:
                self._log("[red]Please enter a target URL[/red]")
                return
            await self._start_scan(target)

        elif event.button.id == "status-btn":
            sid = target or self.session_id
            if not sid:
                self._log("[red]Enter a session ID or start a scan first[/red]")
                return
            await self._check_status(sid)

        elif event.button.id == "stream-btn":
            sid = target or self.session_id
            if not sid:
                self._log("[red]Enter a session ID or start a scan first[/red]")
                return
            self._start_stream(sid)

    async def _start_scan(self, target: str) -> None:
        import httpx
        self._log(f"[yellow]Starting scan: {target}[/yellow]")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{API_BASE}/api/agent/run",
                    headers=_auth_headers(),
                    json={"target": target, "task_type": "web_scan", "provider": "local"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self.session_id = data["session_id"]
                    self.query_one("#session-id", Static).update(f"Session: {self.session_id}")
                    self._log(f"[green]Task started: {self.session_id}[/green]")
                    self._start_stream(self.session_id)
                else:
                    self._log(f"[red]API Error: {resp.status_code}[/red]")
        except Exception as e:
            self._log(f"[red]Connection error: {e}[/red]")

    async def _check_status(self, session_id: str) -> None:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{API_BASE}/api/agent/{session_id}/status", headers=_auth_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    self.query_one("#status-text", Static).update(f"Status: {data['status']}")
                    self.query_one("#phase-text", Static).update(f"Phase: {data['phase']}")
                    self.query_one("#findings-count", Static).update(f"Findings: {data['findings_count']}")
                    self.query_one("#progress-text", Static).update(
                        f"Progress: {data['steps_completed']}/{data['steps_total']} steps"
                    )
                    self._log(f"[green]Status: {data['status']} | Phase: {data['phase']}[/green]")
        except Exception as e:
            self._log(f"[red]Status check failed: {e}[/red]")

    def _start_stream(self, session_id: str) -> None:
        self.session_id = session_id
        self.query_one("#session-id", Static).update(f"Session: {session_id}")
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
        self._stream_task = asyncio.create_task(self._stream_logs(session_id))

    async def _stream_logs(self, session_id: str) -> None:
        import httpx
        import json
        self._log(f"[cyan]Streaming logs for {session_id}...[/cyan]")
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{API_BASE}/api/agent/{session_id}/stream", headers=_auth_headers()) as resp:
                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            try:
                                event = json.loads(line[6:])
                                if event["type"] == "log":
                                    self._log(event["message"])
                                elif event["type"] == "done":
                                    self._log(f"[bold green]Task {event['status']}. Findings: {event['findings_count']}[/bold green]")
                                    await self._check_status(session_id)
                                    return
                            except json.JSONDecodeError:
                                pass
        except asyncio.CancelledError:
            self._log("[yellow]Stream cancelled[/yellow]")
        except Exception as e:
            self._log(f"[red]Stream error: {e}[/red]")

    def _log(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.query_one("#log-view", RichLog).write(f"[dim]{ts}[/dim] {message}")

    def action_clear_log(self) -> None:
        self.query_one("#log-view", RichLog).clear()

    def action_refresh(self) -> None:
        if self.session_id:
            asyncio.create_task(self._check_status(self.session_id))


class SecLLMTui(App):
    """Sec-LLM Agent Terminal UI."""

    CSS = """
    #left-panel { width: 30%; border-right: solid $primary; padding: 1; }
    #right-panel { width: 70%; }
    #status-title { text-style: bold; color: $primary; height: 1; }
    #input-bar { height: 3; dock: bottom; padding: 1; }
    #log-view { height: 1fr; }
    Static { height: 1; }
    """

    def on_mount(self) -> None:
        self.push_screen(AgentMonitorScreen())


def main():
    """Entry point for the TUI."""
    app = SecLLMTui()
    app.run()


if __name__ == "__main__":
    main()
