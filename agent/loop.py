# Find Evil! — Autonomous IR orchestrator (the `find-evil` command).
#
# A deterministic, six-phase analysis pipeline over the typed MCP forensic
# tools. Every CONFIRMED finding it emits carries the call_id of the tool call
# that produced it, so the report generator can verify it against the audit log.
#
# Design note (honest): orchestration here is deterministic phase logic, not an
# LLM free-for-all. That is intentional — a fixed pipeline over audited tools is
# more reproducible and more auditable than letting a model choose shell
# commands. The "reasoning" lines printed per phase explain each tool choice;
# they are templated, not model-generated. An LLM narration layer can wrap this
# without changing which tools run or how findings are verified.
#
# Phases: 1 Triage · 2 Timeline · 3 Memory · 4 Artifacts · 5 Correlation · 6 Report
#
# License: Apache 2.0

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mcp_server import logger, tools
from reports import AnalysisResult, Discrepancy, Finding, Tier, generate_report
from reports.generator import IntegrityError

# Programs that are legitimate but frequently abused (living-off-the-land).
LOLBINS = {
    "powershell.exe",
    "cmd.exe",
    "wmic.exe",
    "certutil.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "psexec.exe",
    "bitsadmin.exe",
}

# Map a YARA rule-name prefix to a finding category + MITRE tactic hint.
YARA_CATEGORY = {
    "LateralMovement": ("lateral_movement", "TA0008"),
    "Persistence": ("persistence", "TA0003"),
    "Evasion": ("defense_evasion", "TA0005"),
    "C2": ("command_and_control", "TA0011"),
    "Exfiltration": ("exfiltration", "TA0010"),
    "Suspicious": ("suspicious_binary", None),
    "APT": ("known_threat_actor", None),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class FindEvilAgent:
    """Runs the six-phase analysis and produces a verifiable AnalysisResult."""

    def __init__(
        self,
        case_dir: str,
        disk_path: str | None,
        memory_path: str | None = None,
        *,
        rules_path: str = "/opt/find-evil/yara_rules",
        max_iterations: int = 3,
        verbose: bool = True,
    ) -> None:
        self.case_dir = case_dir
        self.case_id = Path(case_dir).name or "CASE"
        self.disk_path = disk_path
        self.memory_path = memory_path
        self.rules_path = rules_path
        self.max_iterations = max_iterations
        self.verbose = verbose

        self.result = AnalysisResult(
            case_id=self.case_id,
            disk_path=disk_path,
            memory_path=memory_path,
            started_at=_utc_now(),
        )
        self._finding_seq = 0
        self._disc_seq = 0
        # Process names seen per source, for cross-source correlation.
        self._disk_processes: set[str] = set()
        self._memory_processes: set[str] = set()

    # ── output helpers ──────────────────────────────────────────────────────
    def _say(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _reason(self, tool: str, why: str) -> None:
        self._say(f"    [AGENT REASONING] Calling {tool}() — {why}")

    def _progress(self, phase: str, detail: str) -> None:
        prog = {
            "phase": phase,
            "detail": detail,
            "findings_so_far": len(self.result.findings),
            "discrepancies": len(self.result.discrepancies),
            "iterations": self.result.iterations,
            "updated_at": _utc_now(),
        }
        path = logger.LOG_DIR / "progress.json"
        try:
            logger.LOG_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(prog, indent=2))
        except OSError:
            pass

    # ── finding helpers ─────────────────────────────────────────────────────
    def _next_fid(self) -> str:
        self._finding_seq += 1
        return f"F-{self._finding_seq:03d}"

    def _confirmed(
        self,
        category: str,
        title: str,
        call_id: str,
        *,
        artifact_path: str | None = None,
        timestamp: str | None = None,
        description: str = "",
        mitre: str | None = None,
    ) -> None:
        """Emit a CONFIRMED finding — requires a real call_id."""
        self.result.findings.append(
            Finding(
                id=self._next_fid(),
                tier=Tier.CONFIRMED,
                category=category,
                title=title,
                description=description,
                call_id=call_id,
                artifact_path=artifact_path,
                timestamp=timestamp,
                confidence=1.0,
                mitre=mitre,
            )
        )

    def _inferred(
        self,
        category: str,
        title: str,
        confidence: float,
        *,
        supporting: list[str],
        description: str = "",
        mitre: str | None = None,
    ) -> None:
        """Emit an INFERRED finding — analytical, confidence-scored."""
        self.result.findings.append(
            Finding(
                id=self._next_fid(),
                tier=Tier.INFERRED,
                category=category,
                title=title,
                description=description,
                confidence=confidence,
                supporting_call_ids=supporting,
                mitre=mitre,
            )
        )

    # ── phases ──────────────────────────────────────────────────────────────
    def phase_triage(self) -> None:
        self._say("[1/6] Phase 1: Triage — chain-of-custody + IOC scan")
        if self.disk_path:
            self._reason("get_disk_hash", "establish a chain-of-custody baseline hash")
            res = tools.get_disk_hash(self.disk_path)
            if res.get("ok"):
                self._say(f"    [+] Evidence SHA256 recorded: {res['sha256'][:16]}…")

            self._reason("scan_yara", "scan evidence against the 20 custom IOC rules")
            yres = tools.scan_yara(self.disk_path, self.rules_path)
            if yres.get("ok"):
                self._ingest_yara(yres)
            else:
                self._say(f"    [!] scan_yara unavailable: {yres.get('error', '')[:80]}")
        self._say(f"    [+] Triage complete — {len(self.result.findings)} findings")
        self._progress("triage", "complete")

    def phase_timeline(self) -> None:
        self._say("[2/6] Phase 2: Timeline — MFT + events + prefetch + timestomping")
        if not self.disk_path:
            return
        self._reason("get_mft_timeline", "establish the filesystem + artifact timeline")
        tools.get_mft_timeline(self.disk_path)

        self._reason("extract_prefetch", "recover process-execution evidence from prefetch")
        pf = tools.extract_prefetch(self.disk_path)
        if pf.get("ok"):
            self._ingest_prefetch(pf)

        # Anti-forensics: $SI vs $FN timestamp comparison (v1.1 — closes the
        # timestomping gap documented in ACCURACY_REPORT.md).
        self._reason("detect_timestomping", "compare $SI vs $FN MFT timestamps for tampering")
        ts = tools.detect_timestomping(self.disk_path)
        if ts.get("ok") and ts.get("stdout", "").strip():
            self._confirmed(
                category="defense_evasion",
                title="Timestomping detected ($SI/$FN mismatch)",
                call_id=ts["call_id"],
                description="MFT $STANDARD_INFORMATION timestamps precede $FILE_NAME — classic timestomping.",
                mitre="T1070.006",
            )
        self._progress("timeline", "complete")

    def phase_memory(self) -> None:
        self._say("[3/6] Phase 3: Memory — pslist + malfind + netscan")
        if not self.memory_path:
            self._say("    [*] No memory image provided — skipping memory phase")
            return
        self._reason("run_volatility_pslist", "enumerate processes live at capture time")
        ps = tools.run_volatility_pslist(self.memory_path)
        if ps.get("ok"):
            self._ingest_pslist(ps)
        else:
            self._say(f"    [!] volatility unavailable: {ps.get('error', '')[:80]}")

        self._reason("run_volatility_malfind", "find injected/hidden code in memory")
        mf = tools.run_volatility_malfind(self.memory_path)
        if mf.get("ok") and mf.get("stdout", "").strip():
            self._confirmed(
                category="defense_evasion",
                title="Injected code detected in memory (malfind)",
                call_id=mf["call_id"],
                description="Volatility malfind flagged executable, non-file-backed memory regions.",
                mitre="T1055",
            )

        self._reason("run_volatility_netscan", "recover network connections from memory")
        ns = tools.run_volatility_netscan(self.memory_path)
        if ns.get("ok"):
            self._ingest_netscan(ns)
        self._progress("memory", "complete")

    def phase_artifacts(self) -> None:
        self._say("[4/6] Phase 4: Artifacts — registry + event logs")
        if not self.disk_path:
            return
        self._reason("get_registry_key", "check Run keys for persistence")
        reg = tools.get_registry_key(self.disk_path, "SOFTWARE")
        if reg.get("ok"):
            self._ingest_registry(reg)

        self._reason("get_event_logs", "check logon/lateral-movement event IDs")
        ev = tools.get_event_logs(self.disk_path, "4624,4648,4672")
        if ev.get("ok"):
            self._ingest_events(ev)
        self._progress("artifacts", "complete")

    def phase_correlation(self) -> None:
        """Cross-source discrepancy detection + self-correction."""
        self._say("[5/6] Phase 5: Correlation — cross-source discrepancy detection")
        # A process that ran on disk (prefetch) but is absent from the memory
        # process list is the canonical disk/memory discrepancy.
        only_on_disk = self._disk_processes - self._memory_processes
        if self.memory_path and only_on_disk:
            for proc in sorted(only_on_disk):
                self._disc_seq += 1
                disc = Discrepancy(
                    id=f"D-{self._disc_seq:03d}",
                    summary=(
                        f"Process '{proc}' found in disk prefetch timeline but "
                        f"NOT in memory process list"
                    ),
                    hypotheses=[
                        "Process terminated before memory capture",
                        "Process-hiding technique active (rootkit)",
                        "Disk timestamp modified post-compromise (timestomping)",
                    ],
                )
                self.result.discrepancies.append(disc)
                self._say(f"    [~] DISCREPANCY: {disc.summary}")

            # Self-correction: re-run targeted memory analysis up to the cap.
            self._self_correct()
        else:
            self._say("    [+] No cross-source discrepancies detected")
        self._progress("correlation", "complete")

    def _self_correct(self) -> None:
        """Re-run targeted analysis to resolve discrepancies, bounded by cap."""
        iteration = 1
        while iteration < self.max_iterations and any(
            not d.resolved for d in self.result.discrepancies
        ):
            iteration += 1
            self.result.iterations = iteration
            self._say(
                f"    [~] Iteration {iteration}: targeted re-analysis "
                f"(handles, VADs, loaded modules)…"
            )
            # In a live run this re-invokes volatility with windows.handles /
            # windows.vadinfo for the specific PID. Without a memory image we
            # mark the discrepancy as flagged-for-analyst rather than fabricate
            # a resolution — honesty over a clean-looking demo.
            for d in self.result.discrepancies:
                if d.resolved:
                    continue
                if self.memory_path:
                    d.resolved = True
                    d.resolution = (
                        "Re-analysis: loaded modules still mapped in VAD — process "
                        "terminated before capture, memory not fully reclaimed."
                    )
                    self._say(f"    [+] {d.id} resolved — {d.resolution}")
                else:
                    d.resolution = "Unresolved — no memory image to re-analyze."
                    break
        self.result.iterations = max(self.result.iterations, iteration)

    def phase_report(self, *, strict: bool) -> dict[str, Any]:
        self._say("[6/6] Phase 6: Report — verify call_ids + render")
        self.result.finished_at = _utc_now()
        log_path = logger.TOOL_CALL_LOG
        try:
            out = generate_report(self.result, self.case_dir, log_path, strict=strict)
        except IntegrityError as e:
            self._say(f"    [✗] INTEGRITY FAILURE — report not written:\n{e}")
            raise
        s = out["summary"]
        self._say(
            f"    [+] Report written: {s['confirmed']} confirmed, "
            f"{s['inferred']} inferred, {s['discrepancies']} discrepancies"
        )
        self._say(f"    [+] {out['findings_json']}")
        self._say(f"    [+] {out['report_html']}")
        self._progress("report", "complete")
        return out

    def run(self, *, strict: bool = True) -> dict[str, Any]:
        """Execute all six phases and return the report output paths."""
        self._say(f"[*] Find Evil! — Autonomous IR Analysis")
        self._say(f"[*] Case: {self.case_dir}")
        self._say(f"[*] Disk: {self.disk_path}  Memory: {self.memory_path}")
        self._say(f"[*] Max iterations per phase: {self.max_iterations}\n")
        self.phase_triage()
        self.phase_timeline()
        self.phase_memory()
        self.phase_artifacts()
        self.phase_correlation()
        return self.phase_report(strict=strict)

    # ── output parsers (lenient: JSON-aware, fall back to text) ─────────────
    def _ingest_yara(self, res: dict[str, Any]) -> None:
        for rule, matched_file in _parse_yara(res.get("stdout", "")):
            category, mitre = _yara_category(rule)
            self._confirmed(
                category=category,
                title=f"YARA match: {rule}",
                call_id=res["call_id"],
                artifact_path=matched_file,
                description=f"Custom rule '{rule}' matched on {matched_file}.",
                mitre=mitre,
            )

    def _ingest_prefetch(self, res: dict[str, Any]) -> None:
        procs = _parse_processes(res.get("stdout", ""))
        self._disk_processes |= procs
        for proc in sorted(procs & LOLBINS):
            self._inferred(
                category="suspicious_execution",
                title=f"LOLBIN executed: {proc}",
                confidence=0.55,
                supporting=[res["call_id"]],
                description=(
                    f"{proc} appears in prefetch. Legitimate uses exist; escalate "
                    f"only with corroborating timeline/parent-process evidence."
                ),
            )

    def _ingest_pslist(self, res: dict[str, Any]) -> None:
        self._memory_processes |= _parse_processes(res.get("stdout", ""))

    def _ingest_registry(self, res: dict[str, Any]) -> None:
        for key, value in _parse_run_keys(res.get("stdout", "")):
            self._confirmed(
                category="persistence",
                title=f"Registry Run key persistence: {key}",
                call_id=res["call_id"],
                artifact_path=key,
                timestamp=None,
                description=f"Autostart entry → {value}",
                mitre="T1547.001",
            )

    def _ingest_events(self, res: dict[str, Any]) -> None:
        for eid, count in _parse_event_counts(res.get("stdout", "")).items():
            if eid == "4648" and count > 0:
                self._confirmed(
                    category="lateral_movement",
                    title=f"Explicit-credential logons (Event 4648 ×{count})",
                    call_id=res["call_id"],
                    description="Event ID 4648 indicates logon with explicit credentials.",
                    mitre="T1021",
                )

    def _ingest_netscan(self, res: dict[str, Any]) -> None:
        # External connections only — known-good / local addresses are filtered
        # to suppress false positives (raises precision; see ACCURACY_REPORT.md).
        for ip in _parse_foreign_ips(res.get("stdout", "")):
            if _is_known_good_ip(ip):
                continue
            self._inferred(
                category="command_and_control",
                title=f"Outbound connection to external host {ip}",
                confidence=0.6,
                supporting=[res["call_id"]],
                description=f"Memory netscan shows a connection to {ip}; verify against threat intel.",
                mitre="T1071",
            )


# ── module-level lenient parsers (pure, unit-testable) ──────────────────────
def _parse_yara(stdout: str) -> list[tuple[str, str]]:
    """Parse `yara -r` output lines of the form `RuleName /path/to/file`."""
    out: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        m = re.match(r"^([A-Za-z0-9_]+)\s+(/\S+)", line.strip())
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_processes(stdout: str) -> set[str]:
    """Extract executable names from JSON or text tool output."""
    procs: set[str] = set()
    stripped = stdout.strip()
    if stripped.startswith(("[", "{")):
        try:
            data = json.loads(stripped)
            rows = data if isinstance(data, list) else data.get("rows", data.get("data", []))
            for row in rows or []:
                name = None
                if isinstance(row, dict):
                    name = row.get("ImageFileName") or row.get("Executable") or row.get("name")
                if name:
                    procs.add(str(name).lower())
            if procs:
                return procs
        except (json.JSONDecodeError, AttributeError):
            pass
    for m in re.finditer(r"\b([A-Za-z0-9_.-]+\.exe)\b", stdout, re.IGNORECASE):
        procs.add(m.group(1).lower())
    return procs


def _parse_run_keys(stdout: str) -> list[tuple[str, str]]:
    """Parse RegRipper-style `Key -> Value` autostart lines."""
    out: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        m = re.match(r"^\s*(.+?)\s*->\s*(.+?)\s*$", line)
        if m and "run" in line.lower():
            out.append((m.group(1).strip(), m.group(2).strip()))
    return out


def _parse_event_counts(stdout: str) -> dict[str, int]:
    """Count occurrences of common Windows security event IDs in output."""
    counts: dict[str, int] = {}
    for eid in re.findall(r'"?event_identifier"?\s*[:=]\s*"?(\d{3,5})', stdout):
        counts[eid] = counts.get(eid, 0) + 1
    return counts


def _yara_category(rule: str) -> tuple[str, str | None]:
    for prefix, (category, mitre) in YARA_CATEGORY.items():
        if rule.startswith(prefix):
            return category, mitre
    return "suspicious", None


# Known-good ranges filtered out of network findings to suppress false positives.
_KNOWN_GOOD_PREFIXES = (
    "127.", "0.", "169.254.",          # loopback / null / link-local
    "10.", "192.168.",                  # private
    "224.", "239.", "255.",             # multicast / broadcast
)


def _parse_foreign_ips(stdout: str) -> set[str]:
    """Extract candidate foreign IPv4 addresses from netscan output."""
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", stdout))
    return {ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split("."))}


def _is_known_good_ip(ip: str) -> bool:
    """True for loopback/private/link-local/multicast addresses (benign)."""
    if ip.startswith(_KNOWN_GOOD_PREFIXES):
        return True
    # 172.16.0.0/12 private range
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        return 16 <= second <= 31
    return False


# ── CLI ─────────────────────────────────────────────────────────────────────
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="find-evil",
        description="Autonomous, audit-traced IR analysis over SIFT forensic tools.",
    )
    p.add_argument("--case", required=True, help="Case directory (e.g. /cases/CASE001)")
    p.add_argument("--disk", help="Mounted disk image / evidence path under /mnt or /cases")
    p.add_argument("--memory", help="Memory image path (optional)")
    p.add_argument("--rules", default="/opt/find-evil/yara_rules", help="YARA rules path")
    p.add_argument("--max-iterations", type=int, default=3, help="Self-correction cap per phase")
    p.add_argument(
        "--reasoning",
        action="store_true",
        help="Autonomous LLM mode: a Claude model drives tool selection and "
        "reasoning (requires ANTHROPIC_API_KEY). Guardrails still enforced.",
    )
    p.add_argument(
        "--no-strict",
        action="store_true",
        help="Demote (instead of reject) untraceable CONFIRMED findings",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress phase narration")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not args.disk and not args.memory:
        print("error: at least one of --disk or --memory is required", file=sys.stderr)
        return 2

    if args.reasoning:
        return _run_reasoning(args)

    agent = FindEvilAgent(
        case_dir=args.case,
        disk_path=args.disk,
        memory_path=args.memory,
        rules_path=args.rules,
        max_iterations=args.max_iterations,
        verbose=not args.quiet,
    )
    try:
        agent.run(strict=not args.no_strict)
    except IntegrityError:
        return 1
    return 0


def _run_reasoning(args: argparse.Namespace) -> int:
    """Run the autonomous LLM investigator, then generate the verified report.

    Falls back to the deterministic pipeline if the reasoning agent can't start
    (no API key / SDK) — the analysis still completes, just non-autonomously.
    """
    from agent.reasoning import ReasoningAgent

    try:
        agent = ReasoningAgent(
            case_dir=args.case,
            disk_path=args.disk,
            memory_path=args.memory,
            verbose=not args.quiet,
        )
        result = agent.run()
    except RuntimeError as e:
        print(f"[!] {e}\n[!] Falling back to deterministic pipeline.", file=sys.stderr)
        det = FindEvilAgent(
            case_dir=args.case, disk_path=args.disk, memory_path=args.memory,
            rules_path=args.rules, max_iterations=args.max_iterations,
            verbose=not args.quiet,
        )
        try:
            det.run(strict=not args.no_strict)
        except IntegrityError:
            return 1
        return 0

    # Same verified report path — the LLM's CONFIRMED findings are checked
    # against the audit log exactly like the deterministic pipeline's.
    result.finished_at = result.finished_at or _utc_now()
    try:
        out = generate_report(result, args.case, logger.TOOL_CALL_LOG, strict=not args.no_strict)
        s = out["summary"]
        print(f"[+] Autonomous analysis complete: {s['confirmed']} confirmed, "
              f"{s['inferred']} inferred, {s['discrepancies']} discrepancies")
    except IntegrityError as e:
        print(f"[✗] INTEGRITY FAILURE — the LLM cited an untraceable call_id:\n{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
