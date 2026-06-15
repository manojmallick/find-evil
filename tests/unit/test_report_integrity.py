# Find Evil! — Report integrity tests.
#
# Locks in the 0%-hallucination architectural guarantee: a CONFIRMED finding
# whose call_id is not present in the audit log is rejected (strict) or demoted
# to INFERRED (non-strict) at report-generation time.
#
# License: Apache 2.0

from __future__ import annotations

import json

import pytest

from reports import AnalysisResult, Finding, Tier, generate_report
from reports.generator import IntegrityError, verify_findings


def _write_log(path, call_ids):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for cid in call_ids:
            f.write(json.dumps({"call_id": cid, "tool": "get_mft_timeline"}) + "\n")


def test_confirmed_without_call_id_is_rejected(tmp_path):
    log = tmp_path / "tool_calls.jsonl"
    _write_log(log, ["get_mft_timeline_aaa"])
    result = AnalysisResult(case_id="C1")
    result.findings.append(
        Finding(id="F-001", tier=Tier.CONFIRMED, category="persistence", title="bad", call_id=None)
    )
    with pytest.raises(IntegrityError):
        generate_report(result, tmp_path, log, strict=True)


def test_confirmed_with_untraceable_call_id_is_rejected(tmp_path):
    log = tmp_path / "tool_calls.jsonl"
    _write_log(log, ["get_mft_timeline_aaa"])
    result = AnalysisResult(case_id="C1")
    result.findings.append(
        Finding(
            id="F-001",
            tier=Tier.CONFIRMED,
            category="persistence",
            title="fabricated",
            call_id="get_mft_timeline_DOES_NOT_EXIST",
        )
    )
    with pytest.raises(IntegrityError):
        generate_report(result, tmp_path, log, strict=True)


def test_confirmed_with_valid_call_id_passes(tmp_path):
    log = tmp_path / "tool_calls.jsonl"
    _write_log(log, ["scan_yara_7f2a1b3c"])
    result = AnalysisResult(case_id="C1", disk_path="/mnt/case_disk")
    result.findings.append(
        Finding(
            id="F-001",
            tier=Tier.CONFIRMED,
            category="command_and_control",
            title="YARA match: C2_Cobalt_Strike_Beacon",
            call_id="scan_yara_7f2a1b3c",
            artifact_path="/mnt/case_disk/evil.exe",
        )
    )
    out = generate_report(result, tmp_path, log, strict=True)
    assert out["summary"]["confirmed"] == 1
    data = json.loads((tmp_path / "findings" / "findings.json").read_text())
    assert data["integrity"]["confirmed_findings_verified"] is True
    assert (tmp_path / "findings" / "report.html").exists()


def test_non_strict_demotes_untraceable_to_inferred(tmp_path):
    log = tmp_path / "tool_calls.jsonl"
    _write_log(log, [])
    result = AnalysisResult(case_id="C1")
    result.findings.append(
        Finding(id="F-001", tier=Tier.CONFIRMED, category="x", title="t", call_id="nope")
    )
    out = generate_report(result, tmp_path, log, strict=False)
    assert out["summary"]["confirmed"] == 0
    assert out["summary"]["inferred"] == 1


def test_inferred_findings_never_require_call_id(tmp_path):
    log = tmp_path / "tool_calls.jsonl"
    _write_log(log, [])
    result = AnalysisResult(case_id="C1")
    result.findings.append(
        Finding(
            id="F-001",
            tier=Tier.INFERRED,
            category="suspicious_execution",
            title="LOLBIN executed: powershell.exe",
            confidence=0.55,
        )
    )
    # No exception even with an empty audit log.
    assert verify_findings(result.findings, set()) == []
    out = generate_report(result, tmp_path, log, strict=True)
    assert out["summary"]["inferred"] == 1
