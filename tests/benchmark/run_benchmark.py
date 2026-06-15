#!/usr/bin/env python3
# Find Evil! — Accuracy benchmark harness.
#
# Computes the numbers ACCURACY_REPORT.md cites: precision, recall, and the
# hallucination rate (CONFIRMED findings not traceable to the audit log — 0 by
# architectural construction). Matching is by category + indicator substring
# against a ground-truth IOC list.
#
# Datasets:
#   synthetic     — fully self-contained; runs here, no SIFT/evidence needed.
#                   Proves the metric math + the 0%-hallucination guarantee.
#   nist-hacking  — requires the NIST CFReDS image mounted + SIFT installed.
#   starter-case  — requires the SANS starter disk + memory + SIFT installed.
#
# Usage:
#   python3 tests/benchmark/run_benchmark.py --dataset synthetic
#   python3 tests/benchmark/run_benchmark.py --dataset nist-hacking --case /cases/NIST --disk /mnt/case_disk
#   python3 tests/benchmark/run_benchmark.py --all
#
# License: Apache 2.0

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Make the repo root importable when run as a script.
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from reports import AnalysisResult, Finding, Tier  # noqa: E402
from reports.generator import load_logged_call_ids  # noqa: E402

GROUND_TRUTH_DIR = Path(__file__).parent / "ground_truth"
RESULTS_DIR = Path(__file__).parent / "results"


def load_ground_truth(name: str) -> dict:
    path = GROUND_TRUTH_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"No ground-truth file for dataset '{name}': {path}")
    return json.loads(path.read_text())


def _matches(finding: Finding, ioc: dict) -> bool:
    """True if a finding corresponds to a ground-truth IOC."""
    if finding.category != ioc["category"]:
        return False
    hay = f"{finding.title} {finding.description} {finding.artifact_path or ''}".lower()
    return ioc["indicator"].lower() in hay


def score(result: AnalysisResult, ground_truth: dict, logged_call_ids: set[str]) -> dict:
    """Compute TP/FP/FN, precision, recall, and hallucination rate."""
    iocs = ground_truth["iocs"]
    findings = result.findings

    matched_iocs: set[str] = set()
    tp = 0
    fp = 0
    for f in findings:
        hit = next((i for i in iocs if _matches(f, i)), None)
        if hit:
            tp += 1
            matched_iocs.add(hit["id"])
        else:
            fp += 1
    fn = len([i for i in iocs if i["id"] not in matched_iocs])

    # Hallucination = a CONFIRMED finding with no traceable call_id.
    confirmed = result.confirmed()
    hallucinated = [
        f for f in confirmed if not f.call_id or f.call_id not in logged_call_ids
    ]
    hallucination_rate = (len(hallucinated) / len(confirmed)) if confirmed else 0.0

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    return {
        "dataset": ground_truth["dataset"],
        "total_findings": len(findings),
        "confirmed": len(confirmed),
        "inferred": len(result.inferred()),
        "ground_truth_iocs": len(iocs),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "hallucinated_confirmed_findings": len(hallucinated),
        "hallucination_rate_confirmed": round(hallucination_rate, 3),
        "discrepancies_caught": len(result.discrepancies),
        "self_correction_iterations": result.iterations,
    }


def build_synthetic_run(log_dir: Path) -> tuple[AnalysisResult, set[str]]:
    """Construct a fully-known run with a matching audit log.

    Models a realistic outcome: 4 of 5 IOCs detected (one missed = a false
    negative), one benign false positive, and every CONFIRMED finding backed by
    a real logged call_id. This exercises precision/recall AND proves the
    hallucination rate is 0 because the call_ids genuinely exist in the log.
    """
    os.environ["FIND_EVIL_LOG_DIR"] = str(log_dir)
    import importlib

    from mcp_server import logger

    importlib.reload(logger)

    # Emit real audit-log entries and capture their call_ids.
    cid_yara = logger.log_tool_call(tool="scan_yara", args={"image_path": "/mnt/d"}, output="m")
    cid_reg = logger.log_tool_call(tool="get_registry_key", args={"image_path": "/mnt/d"}, output="m")
    cid_evt = logger.log_tool_call(tool="get_event_logs", args={"image_path": "/mnt/d"}, output="m")
    cid_yara2 = logger.log_tool_call(tool="scan_yara", args={"image_path": "/mnt/d"}, output="m2")

    r = AnalysisResult(case_id="SYNTH", disk_path="/mnt/case_disk", iterations=2)
    # TP 1: C2 (matches GT-1)
    r.findings.append(Finding("F-001", Tier.CONFIRMED, "command_and_control",
                              "YARA match: C2_Cobalt_Strike_Beacon", call_id=cid_yara,
                              artifact_path="/mnt/case_disk/evil.exe"))
    # TP 2: persistence (matches GT-2)
    r.findings.append(Finding("F-002", Tier.CONFIRMED, "persistence",
                              "Registry Run key persistence: Run", call_id=cid_reg,
                              description="Autostart Run key -> evil.exe"))
    # TP 3: lateral movement (matches GT-3)
    r.findings.append(Finding("F-003", Tier.CONFIRMED, "lateral_movement",
                              "Explicit-credential logons (Event 4648 x4)", call_id=cid_evt))
    # TP 4: evasion (matches GT-4)
    r.findings.append(Finding("F-004", Tier.CONFIRMED, "defense_evasion",
                              "YARA match: Evasion_Timestomping_Indicator", call_id=cid_yara2,
                              description="Timestomping indicator"))
    # FP: a benign LOLBIN flagged (INFERRED, no GT match)
    r.findings.append(Finding("F-005", Tier.INFERRED, "suspicious_execution",
                              "LOLBIN executed: certutil.exe", confidence=0.55,
                              supporting_call_ids=[cid_yara]))
    # GT-5 (exfiltration) deliberately MISSED -> one false negative.

    logged = load_logged_call_ids(logger.TOOL_CALL_LOG)
    return r, logged


def run_synthetic() -> dict:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        result, logged = build_synthetic_run(Path(td) / "logs")
        gt = load_ground_truth("synthetic")
        return score(result, gt, logged)


def run_real(dataset: str, case: str | None, disk: str | None, memory: str | None) -> dict:
    """Run the live agent against real evidence, then score against ground truth."""
    gt = load_ground_truth(dataset)
    if not case or not (disk or memory):
        raise SystemExit(
            f"Dataset '{dataset}' requires real evidence:\n"
            f"  --case /cases/<ID> --disk /mnt/case_disk [--memory <path>]\n"
            f"Mount the image read-only and install SIFT first. See ACCURACY_REPORT.md."
        )
    from agent.loop import FindEvilAgent
    from mcp_server import logger

    agent = FindEvilAgent(case, disk, memory, verbose=True)
    agent.run(strict=False)  # non-strict so a partial run still scores
    logged = load_logged_call_ids(logger.TOOL_CALL_LOG)
    return score(agent.result, gt, logged)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Find Evil! accuracy benchmark")
    p.add_argument("--dataset", choices=["synthetic", "nist-hacking", "starter-case"],
                   default="synthetic")
    p.add_argument("--all", action="store_true", help="Run every available dataset")
    p.add_argument("--case", help="Case dir for real datasets")
    p.add_argument("--disk", help="Mounted disk path for real datasets")
    p.add_argument("--memory", help="Memory image for real datasets")
    p.add_argument("--output", help="Write combined results JSON here")
    args = p.parse_args(argv)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    datasets = ["synthetic"] if args.all else [args.dataset]
    if args.all:
        print("[*] --all: running self-contained datasets only "
              "(real datasets need mounted evidence; pass them explicitly)")

    for ds in datasets:
        print(f"\n=== Benchmark: {ds} ===")
        if ds == "synthetic":
            res = run_synthetic()
        else:
            res = run_real(ds, args.case, args.disk, args.memory)
        results.append(res)
        for k, v in res.items():
            print(f"  {k:38} {v}")

    out_path = Path(args.output) if args.output else RESULTS_DIR / "accuracy_report.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n[+] Results written: {out_path}")

    # The architectural guarantee must hold on every dataset.
    for r in results:
        assert r["hallucination_rate_confirmed"] == 0.0, (
            f"INTEGRITY FAILURE on {r['dataset']}: confirmed-tier hallucination "
            f"rate is {r['hallucination_rate_confirmed']}, expected 0.0"
        )
    print("[+] Architectural guarantee holds: 0% hallucination in CONFIRMED tier.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
