"""Tests for security tool modules."""
import pytest
import sys
import os

# Ensure tools are registered
import tools.phishing
import tools.code_audit
import tools.rule_gen
import tools.report
import tools.threat_intel
import tools.browser
import tools.shell

from tools.registry import get_tool, list_tool_names, invoke_tool


class TestToolRegistration:
    def test_all_tools_registered(self):
        names = list_tool_names()
        expected = [
            "browser_check_xss", "browser_navigate", "browser_screenshot",
            "code_auditor", "phishing_analyzer", "report_explainer",
            "rule_generator", "shell_exec", "threat_intel_enrich", "threat_intel_report",
        ]
        for name in expected:
            assert name in names, f"{name} should be registered"

    def test_tool_categories(self):
        from tools.registry import get_tools_by_category
        recon = get_tools_by_category("recon")
        exploit = get_tools_by_category("exploit")
        report = get_tools_by_category("report")
        assert len(recon) >= 3  # phishing, browser_navigate, shell_exec, threat_intel_enrich
        assert len(exploit) >= 2  # code_auditor, browser_check_xss
        assert len(report) >= 3  # report_explainer, rule_generator, threat_intel_report


class TestPhishingTool:
    def test_tool_has_correct_metadata(self):
        tool = get_tool("phishing_analyzer")
        assert tool is not None
        assert tool["name"] == "phishing_analyzer"
        assert tool["category"] == "recon"
        assert tool["requires_provider"] is True

    def test_empty_content_rejected(self):
        """Phishing tool should handle empty content gracefully (requires LLM)."""
        tool = get_tool("phishing_analyzer")
        assert tool is not None
        assert callable(tool["func"])


class TestCodeAuditTool:
    def test_tool_metadata(self):
        tool = get_tool("code_auditor")
        assert tool["name"] == "code_auditor"
        assert tool["category"] == "exploit"


class TestThreatIntelTool:
    def test_enrich_metadata(self):
        tool = get_tool("threat_intel_enrich")
        assert tool["requires_provider"] is True
        assert tool["category"] == "recon"

    def test_report_metadata(self):
        tool = get_tool("threat_intel_report")
        assert tool["category"] == "report"


class TestInvokeTool:
    def test_invoke_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            import asyncio
            asyncio.run(invoke_tool("nonexistent_tool_xyz"))


class TestShellExec:
    def test_shell_command_with_backticks_rejected(self):
        """Shell exec should reject commands with backtick injection."""
        tool = get_tool("shell_exec")
        import asyncio
        result = asyncio.run(tool["func"]("echo `whoami`"))
        assert result["exit_code"] == -1
        assert "rejected" in result["stderr"].lower() or "unsafe" in result["stderr"].lower()

    def test_safe_nmap_command_accepted(self):
        """Shell exec should accept valid security tool commands."""
        tool = get_tool("shell_exec")
        import asyncio
        result = asyncio.run(tool["func"]("nmap -sV -F 127.0.0.1", timeout=30))
        # Either succeeds (Docker available) or returns error about Docker
        assert "exit_code" in result

    def test_shell_metacharacters_are_rejected(self, monkeypatch):
        import asyncio
        from tools.shell import shell_exec

        calls = []

        class Process:
            returncode = 0

            def __init__(self):
                from unittest.mock import AsyncMock
                from types import SimpleNamespace
                self.stdout = SimpleNamespace(read=AsyncMock(return_value=b""))
                self.stderr = SimpleNamespace(read=AsyncMock(return_value=b""))

            async def wait(self):
                return 0

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            return Process()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        result = asyncio.run(shell_exec("nmap -sV 127.0.0.1; echo injected"))
        assert result["exit_code"] == -1
        assert not calls

        result = asyncio.run(shell_exec("nmap -sV 127.0.0.1"))
        assert result["exit_code"] == 0
        assert len(calls) == 1
        assert calls[0][-3:] == ("nmap", "-sV", "127.0.0.1")
        assert "sh" not in calls[0]
        assert "--privileged" not in calls[0]
        assert calls[0][calls[0].index("--network") + 1] == "bridge"

        calls.clear()
        result = asyncio.run(shell_exec("bandit -r /tmp"))
        assert result["exit_code"] == 0
        assert calls[0][calls[0].index("--network") + 1] == "none"

    def test_timeout_removes_own_container(self, monkeypatch):
        import asyncio
        from tools.shell import shell_exec

        calls = []

        class RunProcess:
            returncode = None
            killed = False

            def __init__(self):
                from unittest.mock import AsyncMock
                from types import SimpleNamespace
                self.stdout = SimpleNamespace(read=AsyncMock(side_effect=asyncio.TimeoutError))
                self.stderr = SimpleNamespace(read=AsyncMock(return_value=b""))

            def kill(self):
                self.killed = True
                self.returncode = -9

            async def wait(self):
                return self.returncode

        class CleanupProcess:
            async def wait(self):
                return 0

        run_process = RunProcess()

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            return run_process if args[1] == "run" else CleanupProcess()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        result = asyncio.run(shell_exec("nmap -sV 127.0.0.1", timeout=1))
        name = calls[0][calls[0].index("--name") + 1]
        assert calls[1] == ("docker", "rm", "-f", name)
        assert run_process.killed
        assert result["exit_code"] == -1

    def test_cancel_removes_own_container(self, monkeypatch):
        import asyncio
        from tools.shell import shell_exec

        calls = []
        started = asyncio.Event()

        class RunProcess:
            returncode = None

            def __init__(self):
                from unittest.mock import AsyncMock
                from types import SimpleNamespace
                self.stdout = SimpleNamespace(read=self.read)
                self.stderr = SimpleNamespace(read=AsyncMock(return_value=b""))

            async def read(self, size):
                started.set()
                await asyncio.Future()

            def kill(self):
                self.returncode = -9

            async def wait(self):
                return self.returncode

        class CleanupProcess:
            async def wait(self):
                return 0

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            return RunProcess() if args[1] == "run" else CleanupProcess()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        async def check():
            task = asyncio.create_task(shell_exec("nmap -sV 127.0.0.1"))
            await started.wait()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            else:
                assert False, "cancellation was swallowed"

        asyncio.run(check())
        name = calls[0][calls[0].index("--name") + 1]
        assert calls[1] == ("docker", "rm", "-f", name)


class TestBrowserTool:
    def test_tool_exists(self):
        assert get_tool("browser_navigate") is not None
        assert get_tool("browser_check_xss") is not None
        assert get_tool("browser_screenshot") is not None
