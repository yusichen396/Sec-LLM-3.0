"""Opt-in infrastructure checks: RUN_AGENT_INTEGRATION=1 pytest tests/test_agent_integration.py."""
import os
import subprocess
import sys
import time
import asyncio

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_AGENT_INTEGRATION") != "1",
    reason="set RUN_AGENT_INTEGRATION=1 to test local infrastructure",
)


def test_mysql_connection():
    from agents.orchestrator import _db_connection

    with _db_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 AS ok")
            assert cursor.fetchone()["ok"] == 1


def test_docker_connection():
    result = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.asyncio
async def test_playwright_browser():
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.set_content("<title>agent-integration</title>")
        assert await page.title() == "agent-integration"
        await browser.close()


@pytest.mark.asyncio
async def test_two_workers_stream_and_cancel():
    """A separate Python process executes; this process observes and cancels it."""
    from agents.orchestrator import _db_connection, cancel_agent, create_session, get_session
    from api.agent import stream_agent_logs

    session_id = await create_session({"target": "integration.invalid", "task_type": "web_scan"})
    worker_code = """
import asyncio, sys
import agents.orchestrator as agent

sid = sys.argv[1]
agent._sessions[sid] = agent._load_session(sid)

async def fake_execution(session_id, task):
    for logs in (["worker-a started"], ["worker-a started", "worker-a progressed"]):
        await agent._store_progress(session_id, {
            "phase": "work", "status": "running", "logs": logs,
            "findings": [], "report": None,
        })
        await asyncio.sleep(1)
    while True:
        await agent._store_progress(session_id, {
            "phase": "work", "status": "running", "logs": ["worker-a started", "worker-a progressed"],
            "findings": [], "report": None,
        })
        await asyncio.sleep(0.2)

agent._execute_agent = fake_execution
try:
    asyncio.run(agent._run_limited(sid, agent._sessions[sid]["task"]))
except asyncio.CancelledError:
    pass
"""
    worker = subprocess.Popen([sys.executable, "-c", worker_code, session_id], cwd=os.getcwd())
    try:
        deadline = time.monotonic() + 10
        while "worker-a started" not in get_session(session_id)["logs"]:
            assert worker.poll() is None, "worker exited before starting"
            assert time.monotonic() < deadline, "worker did not publish progress"
            await asyncio.sleep(0.1)

        class Request:
            async def is_disconnected(self):
                return False

        response = await stream_agent_logs(session_id, Request(), {"id": None}, None)
        stream = response.body_iterator
        seen = []
        while not any("worker-a progressed" in event for event in seen):
            seen.append(await asyncio.wait_for(stream.__anext__(), 4))
            assert len(seen) < 8, "other-worker SSE progress was not observed"

        assert await cancel_agent(session_id)
        await asyncio.to_thread(worker.wait, 10)
        assert worker.returncode == 0
        assert get_session(session_id)["status"] == "cancelled"
    finally:
        if worker.poll() is None:
            worker.terminate()
            await asyncio.to_thread(worker.wait, 10)
        with _db_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM agent_sessions WHERE id=%s", (session_id,))


@pytest.mark.asyncio
async def test_two_workers_claim_queued_session_once():
    from agents.orchestrator import _db_connection, create_session, get_session
    from config import settings

    session_id = await create_session({"target": "integration.invalid", "task_type": "web_scan"})
    with _db_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE agent_sessions SET updated_at=DATE_SUB(NOW(), INTERVAL %s SECOND) WHERE id=%s",
                (settings.AGENT_TASK_TIMEOUT_SECONDS + 40, session_id),
            )

    worker_code = """
import asyncio, sys
import agents.orchestrator as agent

sid = sys.argv[1]
agent._sessions[sid] = agent._load_session(sid)

async def fake_execution(session_id, task):
    print("EXECUTED", flush=True)
    await agent._store_progress(session_id, {
        "phase": "complete", "status": "completed", "logs": ["claimed"],
        "findings": [], "report": None,
    })

agent._execute_agent = fake_execution
sys.stdin.readline()
asyncio.run(agent._run_limited(sid, agent._sessions[sid]["task"], recovered=True))
"""
    workers = [subprocess.Popen(
        [sys.executable, "-c", worker_code, session_id], cwd=os.getcwd(),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for _ in range(2)]
    try:
        for worker in workers:
            worker.stdin.write("\n")
            worker.stdin.flush()
        results = [await asyncio.to_thread(worker.communicate, timeout=15) for worker in workers]
        assert all(worker.returncode == 0 for worker in workers), results
        assert sum(stdout.count("EXECUTED") for stdout, _ in results) == 1
        assert get_session(session_id)["status"] == "completed"
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.terminate()
                await asyncio.to_thread(worker.wait, 10)
        with _db_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM agent_sessions WHERE id=%s", (session_id,))
