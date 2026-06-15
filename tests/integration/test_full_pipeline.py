# Find Evil! — Full-pipeline integration test (no SIFT required).
#
# Simulates real forensic-tool output by stubbing the typed tools, then drives
# the full six-phase agent and asserts the end-to-end contract:
#   - CONFIRMED findings carry real, audit-logged call_ids
#   - the disk/memory discrepancy (the demo's tiebreaker) is detected + resolved
#   - generate_report passes the integrity check and writes a populated report
#
# This is what the DEMO_VIDEO_SCRIPT.md "tiebreaker moment" looks like in code.
#
# License: Apache 2.0

from __future__ import annotations

import json

import pytest

from agent import loop


@pytest.fixture()
def stub_tools(monkeypatch, log_dir):
    """Stub the typed tools to return synthetic output + a real logged call_id."""
    from mcp_server import logger

    def _logged(tool, stdout, **summary):
        cid = logger.log_tool_call(tool=tool, args={"image_path": "/mnt/case_disk"},
                                   output=stdout, result_summary=summary)
        return {"call_id": cid, "ok": True, "returncode": 0,
                "output_sha256": logger.compute_hash(stdout), "stdout": stdout, "stderr": ""}

    monkeypatch.setattr(loop.tools, "get_disk_hash",
                        lambda p: {"call_id": "x", "ok": True, "sha256": "a" * 64})
    monkeypatch.setattr(loop.tools, "scan_yara",
                        lambda p, r="/x": _logged("scan_yara",
                            "C2_Cobalt_Strike_Beacon /mnt/case_disk/Windows/Temp/evil.exe\n"
                            "Persistence_Registry_Run_Keys_Suspicious /mnt/case_disk/sw.hiv\n"))
    monkeypatch.setattr(loop.tools, "get_mft_timeline",
                        lambda p, parsers="x": _logged("get_mft_timeline", ""))
    # cmd.exe ran on disk (prefetch)...
    monkeypatch.setattr(loop.tools, "extract_prefetch",
                        lambda p, output_format="json": _logged("extract_prefetch",
                            "CMD.EXE-12345.pf executed 14:22:03\nEXPLORER.EXE-AAA.pf"))
    # ...but is absent from memory (only explorer present).
    monkeypatch.setattr(loop.tools, "run_volatility_pslist",
                        lambda p, output_format="json": _logged("run_volatility_pslist",
                            '[{"ImageFileName": "explorer.exe"}, {"ImageFileName": "lsass.exe"}]'))
    monkeypatch.setattr(loop.tools, "get_registry_key",
                        lambda p, hive: _logged("get_registry_key",
                            "Microsoft\\Windows\\CurrentVersion\\Run -> C:\\Temp\\evil.exe"))
    monkeypatch.setattr(loop.tools, "get_event_logs",
                        lambda p, event_ids="x": _logged("get_event_logs",
                            '{"event_identifier": "4648"}\n{"event_identifier":"4648"}'))
    return log_dir


def test_full_pipeline_produces_verifiable_report(tmp_path, stub_tools):
    case_dir = tmp_path / "CASE001"
    case_dir.mkdir()
    agent = loop.FindEvilAgent(
        case_dir=str(case_dir),
        disk_path="/mnt/case_disk",
        memory_path="/cases/CASE001/memory.raw",
        max_iterations=3,
        verbose=False,
    )
    out = agent.run(strict=True)  # strict: every CONFIRMED must verify

    summary = out["summary"]
    # YARA C2 + persistence Run key + registry persistence + event 4648 = confirmed.
    assert summary["confirmed"] >= 3
    # The cmd.exe disk/memory discrepancy was caught.
    assert summary["discrepancies"] >= 1
    disc = agent.result.discrepancies[0]
    assert "cmd.exe" in disc.summary
    assert disc.resolved is True

    # Report files exist and the integrity block is clean.
    data = json.loads((case_dir / "findings" / "findings.json").read_text())
    assert data["integrity"]["confirmed_findings_verified"] is True
    assert (case_dir / "findings" / "report.html").exists()

    # Every CONFIRMED finding's call_id is greppable in the audit log.
    log_lines = (stub_tools / "tool_calls.jsonl").read_text()
    for f in agent.result.confirmed():
        assert f.call_id in log_lines, f"{f.id} call_id not in audit log"
