"""Real containment checks, run by the Linux Docker CI job (never mocked)."""
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from tools import rsi_sandbox

pytestmark = pytest.mark.skipif(os.environ.get("RSI_DOCKER_TESTS") != "1", reason="requires the built RSI Docker test image")


def test_real_container_denies_network_writes_secrets_and_host_files(tmp_path, monkeypatch):
    tmp_path.chmod(0o755)
    (tmp_path / "frozen.txt").write_text("frozen", encoding="utf-8")
    monkeypatch.setenv("HOST_SECRET", "must_not_reach_candidate")
    script = """
import json, os, socket
from pathlib import Path
assert os.getuid() == 65534
assert 'HOST_SECRET' not in os.environ
assert not Path('/var/run/docker.sock').exists()
assert not Path('/host/private_answers.json').exists()
assert Path('/workspace/frozen.txt').read_text() == 'frozen'
try:
    Path('/workspace/frozen.txt').write_text('tampered')
except OSError:
    pass
else:
    raise AssertionError('read-only source was writable')
try:
    socket.create_connection(('1.1.1.1', 53), timeout=1)
except OSError:
    pass
else:
    raise AssertionError('network was reachable')
Path('/tmp/allowed').write_text('temporary only')
print('RSI_RESULT=' + json.dumps({'passed': True}))
"""
    log = tmp_path / "isolation.log"
    rsi_sandbox.run("sec-llm-rsi:tests", [(tmp_path, "/workspace")], ["python", "-c", script], timeout=30, log=log)
    assert rsi_sandbox.read_result(log) == {"passed": True}
    assert (tmp_path / "frozen.txt").read_text(encoding="utf-8") == "frozen"


def test_real_timeout_kills_container_process_tree(tmp_path, monkeypatch):
    tmp_path.chmod(0o755)
    monkeypatch.setattr(rsi_sandbox.uuid, "uuid4", lambda: SimpleNamespace(hex="timeoutcheck"))
    script = "import subprocess,time; subprocess.Popen(['python','-c','import time; time.sleep(120)']); time.sleep(120)"
    with pytest.raises(subprocess.TimeoutExpired):
        rsi_sandbox.run("sec-llm-rsi:tests", [(tmp_path, "/workspace")], ["python", "-c", script],
                        timeout=5, log=tmp_path / "timeout.log")
    output = subprocess.run(["docker", "ps", "-a", "--filter", "name=sec-rsi-timeoutcheck", "--format", "{{.Names}}"],
                            capture_output=True, text=True, check=True, timeout=10)
    assert not output.stdout.strip()
