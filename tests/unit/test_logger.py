# Find Evil! — Audit logger tests.
# License: Apache 2.0

from __future__ import annotations

import json


def test_compute_hash_is_sha256(log_dir):
    import hashlib

    from mcp_server import logger

    digest = logger.compute_hash("findings")
    assert len(digest) == 64
    assert digest == hashlib.sha256(b"findings").hexdigest()
    # bytes and str inputs hash identically
    assert logger.compute_hash(b"findings") == digest


def test_executed_call_is_logged_with_call_id(log_dir):
    from mcp_server import logger

    cid = logger.log_tool_call(
        tool="get_mft_timeline",
        args={"image_path": "/mnt/case_disk", "parsers": "mft"},
        output="14729 events",
        result_summary={"total_events": 14729},
    )
    entries = [json.loads(l) for l in (log_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert len(entries) == 1
    e = entries[0]
    assert e["call_id"] == cid
    assert e["tool"] == "get_mft_timeline"
    assert e["status"] == "executed"
    assert len(e["output_sha256"]) == 64
    # Audit log must never contain raw evidence content — only metadata.
    assert "14729 events" not in json.dumps(e)


def test_blocked_attempt_is_logged(log_dir):
    from mcp_server import logger

    bid = logger.log_blocked_attempt(
        tool="get_mft_timeline",
        args={"parsers": "mft; rm /cases/x"},
        reason="BLOCKED: Command 'rm' is not permitted.",
    )
    entries = [json.loads(l) for l in (log_dir / "tool_calls.jsonl").read_text().splitlines()]
    e = entries[0]
    assert e["call_id"] == bid
    assert e["tool"] == "BLOCKED_ATTEMPT"
    assert e["status"] == "blocked"
    assert e["output_sha256"] is None


def test_evidence_hash_integrity_violation_recorded(log_dir):
    from mcp_server import logger

    logger.record_evidence_hash("/cases/x.E01", "a" * 64)
    logger.record_evidence_hash("/cases/x.E01", "a" * 64)  # same — fine
    logger.record_evidence_hash("/cases/x.E01", "b" * 64)  # changed — spoliation
    data = json.loads((log_dir / "evidence_hashes.json").read_text())
    assert data["/cases/x.E01"]["INTEGRITY_VIOLATION"] is True
    assert data["/cases/x.E01"]["prior_sha256"] == "a" * 64
