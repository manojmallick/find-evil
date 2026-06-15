# Find Evil! — Autonomous reasoning-agent tests.
#
# Drives the LLM agent loop with a *scripted* fake Anthropic client (no API key,
# no network), proving: the agent dispatches forensic tools, records findings,
# flags discrepancies, and that the architectural integrity guarantee still
# holds — an LLM-invented CONFIRMED call_id is rejected by the report generator.
#
# License: Apache 2.0

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent.reasoning import ReasoningAgent
from reports import Tier, generate_report
from reports.generator import IntegrityError


def _text(t):
    return SimpleNamespace(type="text", text=t)


def _tool_use(name, inp, id="tu_1"):
    return SimpleNamespace(type="tool_use", name=name, input=inp, id=id)


class FakeMessages:
    """Replays a scripted list of assistant responses, one per create() call."""

    def __init__(self, script):
        self._script = list(script)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        content = self._script.pop(0)
        stop = "end_turn" if not any(getattr(b, "type", None) == "tool_use" for b in content) else "tool_use"
        return SimpleNamespace(content=content, stop_reason=stop)


class FakeClient:
    def __init__(self, script):
        self.messages = FakeMessages(script)


def _stub_forensic_tools(monkeypatch, log_dir):
    """Make the forensic tools return a FIXED, real logged call_id (no SIFT)."""
    from mcp_server import logger, tools

    def make(tool):
        def _impl(*a, **k):
            cid = logger.log_tool_call(tool=tool, call_id=f"{tool}_fixed",
                                       args={"image_path": "/mnt/case_disk"}, output="match")
            return {"call_id": cid, "ok": True, "output_sha256": "h", "stdout": "C2_Beacon /mnt/x"}
        return _impl

    for name in ("get_disk_hash", "scan_yara", "get_mft_timeline", "extract_prefetch",
                 "detect_timestomping", "get_registry_key", "get_event_logs",
                 "run_volatility_pslist", "run_volatility_malfind", "run_volatility_netscan"):
        monkeypatch.setattr(tools, name, make(name))


def test_reasoning_agent_runs_tool_then_records_finding(monkeypatch, log_dir, tmp_path):
    _stub_forensic_tools(monkeypatch, log_dir)
    script = [
        [_text("I'll establish chain of custody and sweep for IOCs first."),
         _tool_use("scan_yara", {"image_path": "/mnt/case_disk"}, "tu_scan")],
        # The tool returned call_id "scan_yara_fixed"; the model cites it.
        [_text("Found a C2 beacon."),
         _tool_use("record_finding", {
             "tier": "CONFIRMED", "category": "command_and_control",
             "title": "YARA: C2_Beacon", "call_id": "scan_yara_fixed"}, "tu_rec")],
        [_tool_use("finish_analysis", {"summary": "done"}, "tu_fin")],
    ]
    agent = ReasoningAgent("/x/CASE1", "/mnt/case_disk", client=FakeClient(script), verbose=False)
    result = agent.run()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.tier is Tier.CONFIRMED and f.category == "command_and_control"
    assert f.call_id == "scan_yara_fixed"
    # The cited call_id is real → report generates cleanly (integrity holds).
    out = generate_report(result, tmp_path, log_dir / "tool_calls.jsonl", strict=True)
    assert out["summary"]["confirmed"] == 1
    # And the model actually drove tool selection (sent tools to the API).
    assert any("tools" in c for c in agent._client.messages.calls)


def test_llm_invented_call_id_is_rejected(monkeypatch, log_dir, tmp_path):
    """The integrity guarantee holds even when the LLM drives — a fabricated
    CONFIRMED call_id cannot pass the report generator."""
    _stub_forensic_tools(monkeypatch, log_dir)
    script = [
        [_tool_use("record_finding", {
            "tier": "CONFIRMED", "category": "persistence",
            "title": "fabricated", "call_id": "scan_yara_DOESNOTEXIST"}, "tu_1")],
        [_tool_use("finish_analysis", {"summary": "done"}, "tu_2")],
    ]
    agent = ReasoningAgent("/x/CASE1", "/mnt/case_disk", client=FakeClient(script), verbose=False)
    result = agent.run()
    assert len(result.findings) == 1
    with pytest.raises(IntegrityError):
        generate_report(result, tmp_path, log_dir / "tool_calls.jsonl", strict=True)


def test_reasoning_agent_flags_discrepancy(monkeypatch, log_dir, tmp_path):
    _stub_forensic_tools(monkeypatch, log_dir)
    script = [
        [_tool_use("flag_discrepancy", {
            "summary": "cmd.exe in prefetch but not memory",
            "hypotheses": ["terminated", "rootkit", "timestomp"],
            "resolved": True}, "tu_1")],
        [_tool_use("finish_analysis", {"summary": "done"}, "tu_2")],
    ]
    agent = ReasoningAgent("/x/CASE1", "/mnt/case_disk", memory_path="/cases/m.raw",
                           client=FakeClient(script), verbose=False)
    result = agent.run()
    assert len(result.discrepancies) == 1
    assert result.discrepancies[0].resolved is True
    assert result.iterations == 1


def test_blocked_tool_surfaces_to_model(monkeypatch, log_dir):
    """A guardrail block returns a structured error to the model, not a crash."""
    from mcp_server import tools
    monkeypatch.setattr(tools, "get_disk_hash",
                        lambda **k: {"ok": False, "blocked": True, "error": "BLOCKED: bad path"})
    script = [
        [_tool_use("get_disk_hash", {"image_path": "/etc/passwd"}, "tu_1")],
        [_tool_use("finish_analysis", {"summary": "done"}, "tu_2")],
    ]
    agent = ReasoningAgent("/x/CASE1", "/etc/passwd", client=FakeClient(script), verbose=False)
    result = agent.run()
    # The agent handled the block without raising; no findings fabricated.
    assert result.findings == []
