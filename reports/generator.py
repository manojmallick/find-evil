# Find Evil! — Report generator.
#
# This module is where the 0%-hallucination guarantee is mechanically enforced:
# every CONFIRMED finding MUST carry a call_id that is present in the audit log
# (tool_calls.jsonl). Any CONFIRMED finding without a traceable call_id is
# rejected at report-generation time — not asked-about in a prompt. A finding
# that cannot be traced to a real tool call cannot appear in the CONFIRMED tier.
#
# License: Apache 2.0

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .models import AnalysisResult, Finding, Tier


class IntegrityError(ValueError):
    """Raised when a CONFIRMED finding cannot be traced to the audit log."""


def load_logged_call_ids(log_path: str | Path) -> set[str]:
    """Return the set of every call_id recorded in the audit log.

    Args:
        log_path: Path to tool_calls.jsonl.

    Returns:
        Set of call_id strings. Empty set if the log does not exist.
    """
    path = Path(log_path)
    if not path.exists():
        return set()
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = entry.get("call_id")
        if cid:
            ids.add(cid)
    return ids


def verify_findings(
    findings: list[Finding],
    logged_call_ids: set[str],
) -> list[str]:
    """Check that every CONFIRMED finding traces to a logged call_id.

    Args:
        findings: All findings produced by the analysis.
        logged_call_ids: call_ids known to exist in the audit log.

    Returns:
        A list of human-readable integrity errors (empty if all valid).
    """
    errors: list[str] = []
    for f in findings:
        if f.tier is not Tier.CONFIRMED:
            continue
        if not f.call_id:
            errors.append(
                f"{f.id}: CONFIRMED finding has no call_id "
                f"('{f.title}'). CONFIRMED requires a traceable artifact."
            )
        elif f.call_id not in logged_call_ids:
            errors.append(
                f"{f.id}: call_id '{f.call_id}' not found in audit log "
                f"('{f.title}'). Cannot confirm without a real tool call."
            )
    return errors


def generate_report(
    result: AnalysisResult,
    case_dir: str | Path,
    log_path: str | Path = "/opt/find-evil/logs/tool_calls.jsonl",
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Write findings.json and report.html for an analysis run.

    Enforces the CONFIRMED-tier integrity guarantee before writing anything.

    Args:
        result: The completed AnalysisResult.
        case_dir: Case directory; output goes to ``<case_dir>/findings/``.
        log_path: Path to the audit log used to verify call_ids.
        strict: If True (default), a CONFIRMED finding with an unverifiable
            call_id raises IntegrityError. If False, such findings are demoted
            to INFERRED with a note (useful for partial/dev runs).

    Returns:
        A dict with output paths and the summary counts.

    Raises:
        IntegrityError: In strict mode, if any CONFIRMED finding is untraceable.
    """
    logged = load_logged_call_ids(log_path)
    errors = verify_findings(result.findings, logged)

    if errors:
        if strict:
            raise IntegrityError(
                "Report generation aborted — untraceable CONFIRMED findings:\n  "
                + "\n  ".join(errors)
            )
        # Non-strict: demote offenders to INFERRED so they cannot masquerade as
        # confirmed evidence, and annotate why.
        bad_ids = {e.split(":", 1)[0] for e in errors}
        for f in result.findings:
            if f.id in bad_ids and f.tier is Tier.CONFIRMED:
                f.tier = Tier.INFERRED
                f.confidence = min(f.confidence, 0.5)
                f.description += " [DEMOTED: call_id not traceable in audit log]"

    out_dir = Path(case_dir) / "findings"
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "findings.json"
    html_path = out_dir / "report.html"

    payload = result.to_dict()
    payload["integrity"] = {
        "confirmed_findings_verified": True,
        "untraceable_confirmed_findings": 0 if strict else len(errors),
        "audit_log": str(log_path),
        "logged_call_ids": len(logged),
    }

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    html_path.write_text(_render_html(result, payload), encoding="utf-8")

    return {
        "findings_json": str(json_path),
        "report_html": str(html_path),
        "summary": payload["summary"],
        "integrity_errors": [] if strict else errors,
    }


def _render_html(result: AnalysisResult, payload: dict[str, Any]) -> str:
    """Render a self-contained, dependency-free HTML report."""
    s = payload["summary"]
    rows_confirmed = "\n".join(_finding_row(f) for f in result.confirmed())
    rows_inferred = "\n".join(_finding_row(f) for f in result.inferred())
    rows_disc = "\n".join(_discrepancy_row(d) for d in result.discrepancies)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Find Evil! Report — {html.escape(result.case_id)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#0d1117; color:#e6edf3; }}
  header {{ background:#161b22; padding:24px 32px; border-bottom:1px solid #30363d; }}
  h1 {{ margin:0; font-size:22px; }}
  .sub {{ color:#8b949e; font-size:13px; margin-top:4px; }}
  .bar {{ display:flex; gap:16px; padding:20px 32px; }}
  .stat {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px 20px; min-width:120px; }}
  .stat .n {{ font-size:28px; font-weight:700; }}
  .stat .l {{ color:#8b949e; font-size:12px; text-transform:uppercase; }}
  section {{ padding:8px 32px 24px; }}
  h2 {{ border-bottom:1px solid #30363d; padding-bottom:6px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #21262d; vertical-align:top; }}
  th {{ color:#8b949e; font-weight:600; }}
  .pill {{ padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }}
  .confirmed {{ background:#1f6f3f; color:#d5ffe0; }}
  .inferred {{ background:#7a5c12; color:#fff6d5; }}
  code {{ background:#21262d; padding:1px 5px; border-radius:4px; font-size:12px; }}
  .verify {{ color:#58a6ff; font-size:11px; }}
</style></head><body>
<header>
  <h1>Find Evil! — Incident Report</h1>
  <div class="sub">Case <code>{html.escape(result.case_id)}</code> ·
    disk <code>{html.escape(result.disk_path or "—")}</code> ·
    memory <code>{html.escape(result.memory_path or "—")}</code> ·
    {s['iterations']} self-correction iteration(s)</div>
</header>
<div class="bar">
  <div class="stat"><div class="n">{s['total_findings']}</div><div class="l">Total</div></div>
  <div class="stat"><div class="n">{s['confirmed']}</div><div class="l">Confirmed</div></div>
  <div class="stat"><div class="n">{s['inferred']}</div><div class="l">Inferred</div></div>
  <div class="stat"><div class="n">{s['discrepancies']}</div><div class="l">Discrepancies</div></div>
</div>
<section>
  <h2>CONFIRMED findings <span class="verify">— every row traceable to the audit log</span></h2>
  <table><tr><th>ID</th><th>Category</th><th>Finding</th><th>Artifact</th><th>When</th><th>Verify (call_id)</th></tr>
  {rows_confirmed or '<tr><td colspan="6">None.</td></tr>'}
  </table>
</section>
<section>
  <h2>INFERRED findings <span class="verify">— analytical, confidence-scored</span></h2>
  <table><tr><th>ID</th><th>Category</th><th>Finding</th><th>Confidence</th><th>Support</th></tr>
  {rows_inferred or '<tr><td colspan="5">None.</td></tr>'}
  </table>
</section>
<section>
  <h2>Cross-source discrepancies</h2>
  <table><tr><th>ID</th><th>Summary</th><th>Resolution</th></tr>
  {rows_disc or '<tr><td colspan="3">None.</td></tr>'}
  </table>
</section>
</body></html>"""


def _finding_row(f: Finding) -> str:
    if f.tier is Tier.CONFIRMED:
        verify = (
            f'<code>{html.escape(f.call_id or "")}</code>'
            f'<br><span class="verify">grep {html.escape(f.call_id or "")} '
            f"/opt/find-evil/logs/tool_calls.jsonl</span>"
        )
        return (
            f"<tr><td>{html.escape(f.id)}</td>"
            f'<td><span class="pill confirmed">{html.escape(f.category)}</span></td>'
            f"<td>{html.escape(f.title)}</td>"
            f"<td><code>{html.escape(f.artifact_path or '—')}</code></td>"
            f"<td>{html.escape(f.timestamp or '—')}</td>"
            f"<td>{verify}</td></tr>"
        )
    support = ", ".join(html.escape(c) for c in (f.supporting_call_ids or [])) or "—"
    return (
        f"<tr><td>{html.escape(f.id)}</td>"
        f'<td><span class="pill inferred">{html.escape(f.category)}</span></td>'
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{f.confidence:.0%}</td>"
        f"<td><code>{support}</code></td></tr>"
    )


def _discrepancy_row(d: Any) -> str:
    res = d.resolution if d.resolved else "UNRESOLVED — flagged for analyst"
    return (
        f"<tr><td>{html.escape(d.id)}</td>"
        f"<td>{html.escape(d.summary)}</td>"
        f"<td>{html.escape(res or '—')}</td></tr>"
    )
