"""步骤级错误处理测试：可重试分类、重试、熔断。

用假工具模拟三类失败，不依赖 Docker 沙箱与真实目标。
"""
import asyncio

import pytest

import agents.orchestrator as orch
from tools.registry import register_tool


def _state(plan):
    return {
        "target": "fixture",
        "task_type": "code_audit",
        "provider": "local",
        "session_id": "test",
        "plan": plan,
        "current_step": 0,
        "observations": [],
        "findings": [],
        "logs": [],
        "error": "",
        "status": "running",
    }


def _register_flaky(name, failures, error):
    """注册一个前 failures 次必失败、之后成功的工具。"""
    calls = {"n": 0}

    @register_tool(name=name, description=f"flaky tool {name}", category="recon", requires_provider=False)
    async def _tool(url: str = "") -> dict:
        calls["n"] += 1
        if calls["n"] <= failures:
            raise error
        return {"status": "ok", "stdout": "ok", "exit_code": 0}

    return calls


class TestStepRetry:
    def test_transient_error_is_retried(self):
        calls = _register_flaky("flaky_transient", 1, ConnectionResetError("connection reset by peer"))
        state = _state([{"tool": "flaky_transient", "args": {"url": "http://x"}, "status": "pending"}])

        result = asyncio.run(orch.execute_node(state))

        step = result["plan"][0]
        assert calls["n"] == 2, "应重试一次"
        assert step["status"] == "done"
        assert any("[RETRY]" in line for line in result["logs"])

    def test_timeout_is_retried(self):
        calls = _register_flaky("flaky_timeout", 1, asyncio.TimeoutError())
        state = _state([{"tool": "flaky_timeout", "args": {"url": "http://x"}, "status": "pending"}])

        result = asyncio.run(orch.execute_node(state))

        assert calls["n"] == 2
        assert result["plan"][0]["status"] == "done"

    def test_fatal_error_is_not_retried(self):
        calls = _register_flaky("flaky_fatal", 1, ValueError("invalid argument payload"))
        state = _state([{"tool": "flaky_fatal", "args": {"url": "http://x"}, "status": "pending"}])

        result = asyncio.run(orch.execute_node(state))

        step = result["plan"][0]
        assert calls["n"] == 1, "不可重试错误不应重试"
        assert step["status"] == "error"
        assert step["error_class"] == "fatal"

    def test_rejected_error_is_not_retried(self):
        calls = _register_flaky("flaky_rejected", 1, RuntimeError("Command rejected: unsupported tool"))
        state = _state([{"tool": "flaky_rejected", "args": {"url": "http://x"}, "status": "pending"}])

        result = asyncio.run(orch.execute_node(state))

        assert calls["n"] == 1
        assert result["plan"][0]["error_class"] == "rejected"

    def test_unknown_tool_is_skipped(self):
        state = _state([{"tool": "no_such_tool", "args": {}, "status": "pending"}])

        result = asyncio.run(orch.execute_node(state))

        assert result["plan"][0]["status"] == "skipped"
        assert result["plan"][0]["error_class"] == "unknown_tool"


class TestCircuitBreaker:
    def test_aborts_after_consecutive_failures(self):
        _register_flaky("always_fatal_a", 99, ValueError("bad"))
        _register_flaky("always_fatal_b", 99, ValueError("bad"))
        state = _state([
            {"tool": "always_fatal_a", "args": {"url": "http://x"}, "status": "pending"},
            {"tool": "always_fatal_b", "args": {"url": "http://x"}, "status": "pending"},
            {"tool": "always_fatal_a", "args": {"url": "http://x"}, "status": "pending"},
        ])

        result = asyncio.run(orch.execute_node(state))
        assert result["consecutive_failures"] == 1
        assert not result["error"], "一步失败不该触发熔断"

        result = asyncio.run(orch.execute_node(result))
        assert result["consecutive_failures"] == 2
        assert "consecutive step failures" in result["error"]
        assert result["current_step"] == len(result["plan"]), "熔断后应跳过剩余步骤"
        assert any("[CIRCUIT]" in line for line in result["logs"])

    def test_success_resets_counter(self):
        calls = _register_flaky("recover_ok", 0, ValueError("never"))
        _register_flaky("recover_bad", 99, ValueError("bad"))
        state = _state([
            {"tool": "recover_bad", "args": {"url": "http://x"}, "status": "pending"},
            {"tool": "recover_ok", "args": {"url": "http://x"}, "status": "pending"},
        ])

        result = asyncio.run(orch.execute_node(state))
        assert result["consecutive_failures"] == 1

        result = asyncio.run(orch.execute_node(result))
        assert result["consecutive_failures"] == 0, "成功一步应清零"
        assert result["plan"][1]["status"] == "done"


class TestStepReferences:
    def test_prev_reference_receives_previous_result(self):
        seen = {}

        @register_tool(name="ref_sink", description="capture args", category="recon", requires_provider=False)
        async def _sink(payload: dict) -> dict:
            seen["payload"] = payload
            return {"status": "ok", "exit_code": 0}

        @register_tool(name="ref_source", description="produce result", category="recon", requires_provider=False)
        async def _source() -> dict:
            return {"status": "ok", "value": 42}

        state = _state([
            {"tool": "ref_source", "args": {}, "status": "pending"},
            {"tool": "ref_sink", "args": {"payload": "$prev"}, "status": "pending"},
        ])
        result = asyncio.run(orch.execute_node(state))
        result = asyncio.run(orch.execute_node(result))

        assert seen["payload"] == {"status": "ok", "value": 42}, "引用应替换为真实结果"
        assert result["plan"][1]["status"] == "done"

    def test_unresolvable_reference_is_left_untouched(self):
        resolved = orch.resolve_step_refs({"payload": "$prev", "other": "x"}, [])
        assert resolved["payload"] == "$prev", "没有前序结果时应原样保留"
        assert resolved["other"] == "x"

    def test_step_index_reference(self):
        observations = [{"result": {"n": 1}}, {"result": {"n": 2}}]
        resolved = orch.resolve_step_refs({"a": "$step:0", "b": "$step:1"}, observations)
        assert resolved["a"] == {"n": 1}
        assert resolved["b"] == {"n": 2}


class TestSelfCorrection:
    def _patch_revision(self, monkeypatch, payload):
        captured = {}

        async def fake_completion(messages, **kwargs):
            captured["prompt"] = messages[-1]["content"]
            return payload

        monkeypatch.setattr(orch, "single_shot_completion", fake_completion)
        return captured

    def test_failed_step_is_replaced_and_reexecuted(self, monkeypatch):
        @register_tool(name="sc_bad", description="always fails", category="recon", requires_provider=False)
        async def _bad(url: str = "") -> dict:
            raise ValueError("tool exploded")

        executed = {"n": 0}

        @register_tool(name="sc_good", description="works", category="recon", requires_provider=False)
        async def _good(url: str = "") -> dict:
            executed["n"] += 1
            return {"status": "ok", "exit_code": 0}

        captured = self._patch_revision(
            monkeypatch, '{"tool": "sc_good", "args": {"url": "http://x"}, "reason": "alternative"}'
        )

        state = _state([{"tool": "sc_bad", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))
        assert state["plan"][0]["status"] == "error"

        state = asyncio.run(orch.reflect_node(state))
        assert state["plan"][0]["tool"] == "sc_good"
        assert state["plan"][0]["status"] == "pending"
        assert state["current_step"] == 0, "应回到失败那一步重跑"
        assert state["replans"] == 1
        assert any("[REPLAN]" in line for line in state["logs"])
        assert "tool exploded" in captured["prompt"], "错误信息应回灌给模型"

        state = asyncio.run(orch.execute_node(state))
        assert state["plan"][0]["status"] == "done"
        assert executed["n"] == 1

    def test_abort_proposal_keeps_failure(self, monkeypatch):
        @register_tool(name="sc_bad2", description="always fails", category="recon", requires_provider=False)
        async def _bad2(url: str = "") -> dict:
            raise ValueError("nope")

        self._patch_revision(monkeypatch, '{"abort": true}')

        state = _state([{"tool": "sc_bad2", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))
        state = asyncio.run(orch.reflect_node(state))

        assert state["plan"][0]["status"] == "error"
        assert state["replans"] == 0
        assert any("no viable alternative" in line for line in state["logs"])

    def test_replan_budget_is_enforced(self, monkeypatch):
        @register_tool(name="sc_bad3", description="always fails", category="recon", requires_provider=False)
        async def _bad3(url: str = "") -> dict:
            raise ValueError("nope")

        self._patch_revision(monkeypatch, '{"tool": "sc_bad3", "args": {"url": "http://x"}}')

        state = _state([{"tool": "sc_bad3", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))
        state = asyncio.run(orch.reflect_node(state))
        assert state["replans"] == 1

        state = asyncio.run(orch.execute_node(state))
        state = asyncio.run(orch.reflect_node(state))
        assert state["replans"] == 1, "超出预算后不再重规划"
        assert any("budget exhausted" in line for line in state["logs"])

    def test_invalid_proposal_is_rejected(self, monkeypatch):
        @register_tool(name="sc_bad4", description="always fails", category="recon", requires_provider=False)
        async def _bad4(url: str = "") -> dict:
            raise ValueError("nope")

        self._patch_revision(monkeypatch, '{"tool": "not_a_real_tool", "args": {}}')

        state = _state([{"tool": "sc_bad4", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))
        state = asyncio.run(orch.reflect_node(state))

        assert state["plan"][0]["tool"] == "sc_bad4", "非法替代方案不应被采纳"
        assert state["replans"] == 0


class TestResultContract:
    def test_missing_findings_is_weak_result(self):
        @register_tool(name="rc_no_findings", description="wrong tool", category="recon",
                       requires_provider=False, expects="findings_list")
        async def _no_findings(url: str = "") -> dict:
            return {"status": "success", "pages": ["a", "b"]}

        state = _state([{"tool": "rc_no_findings", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))

        step = state["plan"][0]
        assert step["status"] == "error"
        assert step["error_class"] == "weak_result"
        assert any("no findings list" in line for line in state["logs"])

    def test_empty_findings_list_is_acceptable(self):
        @register_tool(name="rc_clean_scan", description="clean scan", category="recon",
                       requires_provider=False, expects="findings_list")
        async def _clean(url: str = "") -> dict:
            return {"status": "success", "findings": [], "conclusion": "no_signal"}

        state = _state([{"tool": "rc_clean_scan", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))

        assert state["plan"][0]["status"] == "done", "扫干净是合法结果，不该判错"

    def test_empty_content_is_weak_result(self):
        @register_tool(name="rc_empty_content", description="empty output", category="report",
                       requires_provider=False, expects="content")
        async def _empty(url: str = "") -> dict:
            return {"status": "success", "rule": "   "}

        state = _state([{"tool": "rc_empty_content", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))

        assert state["plan"][0]["error_class"] == "weak_result"

    def test_contract_any_is_not_checked(self):
        @register_tool(name="rc_lenient", description="no contract", category="recon",
                       requires_provider=False)
        async def _lenient(url: str = "") -> dict:
            return {"status": "success", "pages": []}

        state = _state([{"tool": "rc_lenient", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))

        assert state["plan"][0]["status"] == "done"

    def test_weak_result_triggers_replan(self, monkeypatch):
        @register_tool(name="rc_wrong", description="wrong tool", category="recon",
                       requires_provider=False, expects="findings_list")
        async def _wrong(url: str = "") -> dict:
            return {"status": "success", "pages": ["a"]}

        @register_tool(name="rc_right", description="right tool", category="exploit",
                       requires_provider=False, expects="findings_list")
        async def _right(url: str = "") -> dict:
            return {"status": "success", "findings": [{"title": "x", "severity": "High"}]}

        async def fake_completion(messages, **kwargs):
            return '{"tool": "rc_right", "args": {"url": "http://x"}, "reason": "alt"}'

        monkeypatch.setattr(orch, "single_shot_completion", fake_completion)

        state = _state([{"tool": "rc_wrong", "args": {"url": "http://x"}, "status": "pending"}])
        state = asyncio.run(orch.execute_node(state))
        assert state["plan"][0]["error_class"] == "weak_result"

        state = asyncio.run(orch.reflect_node(state))
        assert state["plan"][0]["tool"] == "rc_right"

        state = asyncio.run(orch.execute_node(state))
        assert state["plan"][0]["status"] == "done"
        assert state["findings"], "替代工具产出的发现应被收集"


class TestTargetToolMatch:
    def test_url_target_with_code_tool_is_blocked(self):
        called = {"n": 0}

        @register_tool(name="tm_audit", description="audit code", category="exploit",
                       requires_provider=False, accepts="code")
        async def _audit(code: str = "") -> dict:
            called["n"] += 1
            return {"status": "success", "findings": []}

        state = _state([{"tool": "tm_audit", "args": {"code": "x"}, "status": "pending"}])
        state["target"] = "https://example.com/login"
        state = asyncio.run(orch.execute_node(state))

        step = state["plan"][0]
        assert step["status"] == "error"
        assert step["error_class"] == "target_mismatch"
        assert called["n"] == 0, "不匹配时不应真正执行工具"

    def test_code_target_with_url_tool_is_blocked(self):
        called = {"n": 0}

        @register_tool(name="tm_sqli", description="probe url", category="exploit",
                       requires_provider=False, accepts="url")
        async def _sqli(url: str = "") -> dict:
            called["n"] += 1
            return {"status": "success", "findings": []}

        state = _state([{"tool": "tm_sqli", "args": {"url": "http://x"}, "status": "pending"}])
        state["target"] = "def handler(request):\n    pass"
        state = asyncio.run(orch.execute_node(state))

        assert state["plan"][0]["error_class"] == "target_mismatch"
        assert called["n"] == 0

    def test_matching_target_runs(self):
        called = {"n": 0}

        @register_tool(name="tm_sqli_ok", description="probe url", category="exploit",
                       requires_provider=False, accepts="url")
        async def _sqli_ok(url: str = "") -> dict:
            called["n"] += 1
            return {"status": "success", "findings": []}

        state = _state([{"tool": "tm_sqli_ok", "args": {"url": "http://x"}, "status": "pending"}])
        state["target"] = "https://example.com/item?id=1"
        state = asyncio.run(orch.execute_node(state))

        assert state["plan"][0]["status"] == "done"
        assert called["n"] == 1

    def test_unknown_target_kind_is_allowed(self):
        called = {"n": 0}

        @register_tool(name="tm_sqli_unknown", description="probe url", category="exploit",
                       requires_provider=False, accepts="url")
        async def _sqli_unknown(url: str = "") -> dict:
            called["n"] += 1
            return {"status": "success", "findings": []}

        state = _state([{"tool": "tm_sqli_unknown", "args": {"url": "http://x"}, "status": "pending"}])
        state["target"] = "some free-form description"
        state = asyncio.run(orch.execute_node(state))

        assert state["plan"][0]["status"] == "done", "类型不明时不应拦截"
        assert called["n"] == 1

    def test_mismatch_triggers_replan(self, monkeypatch):
        @register_tool(name="tm_code_tool", description="audit code", category="exploit",
                       requires_provider=False, accepts="code")
        async def _code(code: str = "") -> dict:
            return {"status": "success", "findings": []}

        @register_tool(name="tm_url_tool", description="probe url", category="exploit",
                       requires_provider=False, expects="findings_list", accepts="url")
        async def _url(url: str = "") -> dict:
            return {"status": "success", "findings": [{"title": "x", "severity": "High"}]}

        async def fake_completion(messages, **kwargs):
            return '{"tool": "tm_url_tool", "args": {"url": "https://example.com/x"}, "reason": "alt"}'

        monkeypatch.setattr(orch, "single_shot_completion", fake_completion)

        state = _state([{"tool": "tm_code_tool", "args": {"code": "x"}, "status": "pending"}])
        state["target"] = "https://example.com/x"
        state = asyncio.run(orch.execute_node(state))
        assert state["plan"][0]["error_class"] == "target_mismatch"

        state = asyncio.run(orch.reflect_node(state))
        assert state["plan"][0]["tool"] == "tm_url_tool"

        state = asyncio.run(orch.execute_node(state))
        assert state["plan"][0]["status"] == "done"


class TestAdaptiveCircuit:
    def test_limit_scales_with_plan_length(self):
        assert orch._circuit_limit(1) == 2, "短计划用固定下限"
        assert orch._circuit_limit(3) == 2
        assert orch._circuit_limit(6) == 2
        assert orch._circuit_limit(9) == 3, "9 步 -> 3"
        assert orch._circuit_limit(12) == 4, "12 步 -> 4"

    def test_nine_step_plan_tolerates_two_failures(self):
        @register_tool(name="ac_fail", description="always fails", category="recon", requires_provider=False)
        async def _fail(url: str = "") -> dict:
            raise ValueError("boom")

        plan = [{"tool": "ac_fail", "args": {"url": "http://x"}, "status": "pending"} for _ in range(9)]
        state = _state(plan)

        state = asyncio.run(orch.execute_node(state))
        assert state["consecutive_failures"] == 1
        assert not state["error"], "第 1 次失败不该熔断"

        state = asyncio.run(orch.execute_node(state))
        assert state["consecutive_failures"] == 2
        assert not state["error"], "9 步计划容忍 2 次，第 2 次仍不熔断"

        state = asyncio.run(orch.execute_node(state))
        assert state["consecutive_failures"] == 3
        assert "consecutive step failures" in state["error"], "第 3 次才熔断"
        assert any("[CIRCUIT] 3/3" in line for line in state["logs"])

    def test_three_step_plan_still_breaks_at_two(self):
        @register_tool(name="ac_fail_short", description="always fails", category="recon",
                       requires_provider=False)
        async def _fail_short(url: str = "") -> dict:
            raise ValueError("boom")

        plan = [{"tool": "ac_fail_short", "args": {"url": "http://x"}, "status": "pending"} for _ in range(3)]
        state = _state(plan)

        state = asyncio.run(orch.execute_node(state))
        state = asyncio.run(orch.execute_node(state))

        assert "consecutive step failures" in state["error"]
