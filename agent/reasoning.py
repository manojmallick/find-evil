# Find Evil! — Autonomous LLM reasoning agent.
#
# This is the "thinks like a senior analyst" mode the hackathon's tiebreaker
# criterion (Autonomous Execution Quality) rewards. A Claude model drives the
# investigation: it chooses which forensic tool to run next based on what it has
# found, narrates its reasoning, forms and tests hypotheses, and self-corrects.
#
# Crucially, the architectural guarantees still hold while the LLM is in control:
#   - The model can ONLY call the typed forensic tools (rm/dd/curl are not in its
#     tool surface). Every call still passes through tools.py → _safe_run.
#   - A CONFIRMED finding the model records must cite a call_id that the report
#     generator can verify against the audit log; an LLM-invented call_id is
#     rejected. The model cannot hallucinate a confirmed finding into existence.
#
# This is the key story: full autonomous reasoning, zero loss of evidence
# integrity, because the constraints are architectural — not prompt-based.
#
# Runs live with ANTHROPIC_API_KEY set. Falls back to the deterministic
# FindEvilAgent when no key/SDK is available (agent/loop.py).
#
# License: Apache 2.0

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mcp_server import logger, tools
from reports import AnalysisResult, Discrepancy, Finding, Tier

# Default to the most capable model; override with FIND_EVIL_MODEL.
DEFAULT_MODEL = os.environ.get("FIND_EVIL_MODEL", "claude-opus-4-8")
MAX_STEPS = int(os.environ.get("FIND_EVIL_MAX_STEPS", "40"))
# Cap tool stdout fed back to the model so a huge timeline doesn't blow context.
MAX_TOOL_OUTPUT_CHARS = 6000


SYSTEM_PROMPT = """\
You are a senior DFIR (digital forensics & incident response) analyst running an \
autonomous investigation on a SANS SIFT Workstation. You think and work the way \
an experienced analyst does: you form hypotheses, choose the next tool based on \
what you've found, recognize anomalies, and cross-check sources against each \
other.

## Your tools
You have a fixed set of typed forensic tools (timeline, prefetch, memory, \
registry, event logs, YARA, timestomping). You do NOT have a shell. Destructive \
or network commands (rm, dd, curl, ssh) do not exist for you — by design. Work \
only through the tools provided.

## How to investigate
1. Start by establishing chain of custody (hash the evidence) and a quick IOC \
sweep, then follow the evidence. Explain your reasoning in one or two sentences \
BEFORE each tool call: what you expect to find and why this tool.
2. Build a timeline, enumerate execution evidence, check memory, then registry \
and event logs. Adapt the order to what you discover.
3. Actively look for cross-source discrepancies — e.g. a process in the disk \
prefetch timeline that is absent from the memory process list. When you find \
one, flag it with flag_discrepancy, state 2-3 hypotheses, and run targeted \
follow-up analysis to resolve it. This self-correction is the most important \
thing you do.

## Recording findings — STRICT rules
- Use record_finding for every conclusion.
- tier="CONFIRMED" requires the `call_id` of the tool result that proves it. \
The report is rejected if a CONFIRMED finding's call_id is not in the audit log, \
so never invent one — cite the exact call_id returned by the tool.
- tier="INFERRED" is for analytical conclusions; give a confidence 0.0-1.0 and \
the supporting call_ids. Benign-but-suspicious tools (certutil, psexec) are \
INFERRED, not CONFIRMED, unless corroborated.
- Be honest. If you cannot prove something, say so and use INFERRED. A missed \
artifact is better than a fabricated one.

When the investigation is complete, call finish_analysis with a short summary."""


# ── Tool schemas exposed to the model ───────────────────────────────────────
# Each forensic tool maps 1:1 to a function in mcp_server.tools. The control
# tools (record_finding, flag_discrepancy, finish_analysis) are handled here.
def _forensic_tool_schemas() -> list[dict[str, Any]]:
    disk = {
        "image_path": {
            "type": "string",
            "description": "Absolute evidence path under /cases or /mnt",
        }
    }
    return [
        {
            "name": "get_disk_hash",
            "description": "Compute SHA256 of the disk image for chain of custody.",
            "input_schema": {"type": "object", "properties": disk, "required": ["image_path"]},
        },
        {
            "name": "scan_yara",
            "description": "Scan evidence against the 20 custom IOC rules (lateral movement, persistence, C2, evasion, exfil).",
            "input_schema": {
                "type": "object",
                "properties": {**disk, "rules_path": {"type": "string"}},
                "required": ["image_path"],
            },
        },
        {
            "name": "get_mft_timeline",
            "description": "Build the filesystem + artifact timeline (MFT, events, prefetch, registry) with log2timeline.",
            "input_schema": {
                "type": "object",
                "properties": {**disk, "parsers": {"type": "string"}},
                "required": ["image_path"],
            },
        },
        {
            "name": "extract_prefetch",
            "description": "Parse Windows Prefetch to recover process-execution evidence (what ran, when).",
            "input_schema": {"type": "object", "properties": disk, "required": ["image_path"]},
        },
        {
            "name": "detect_timestomping",
            "description": "Detect anti-forensic timestamp manipulation by comparing $STANDARD_INFORMATION vs $FILE_NAME MFT timestamps.",
            "input_schema": {"type": "object", "properties": disk, "required": ["image_path"]},
        },
        {
            "name": "get_registry_key",
            "description": "Read registry persistence/config keys with RegRipper. hive e.g. SOFTWARE, SYSTEM, NTUSER.",
            "input_schema": {
                "type": "object",
                "properties": {**disk, "hive": {"type": "string"}},
                "required": ["image_path", "hive"],
            },
        },
        {
            "name": "get_event_logs",
            "description": "Extract Windows event-log records for logon/lateral-movement IDs (e.g. 4624,4648,4672).",
            "input_schema": {
                "type": "object",
                "properties": {**disk, "event_ids": {"type": "string"}},
                "required": ["image_path"],
            },
        },
        {
            "name": "run_volatility_pslist",
            "description": "List processes from a memory image (Volatility windows.pslist).",
            "input_schema": {
                "type": "object",
                "properties": {"memory_path": {"type": "string"}},
                "required": ["memory_path"],
            },
        },
        {
            "name": "run_volatility_malfind",
            "description": "Find injected/hidden code in a memory image (Volatility windows.malfind).",
            "input_schema": {
                "type": "object",
                "properties": {"memory_path": {"type": "string"}},
                "required": ["memory_path"],
            },
        },
        {
            "name": "run_volatility_netscan",
            "description": "Recover network connections from a memory image (Volatility windows.netscan).",
            "input_schema": {
                "type": "object",
                "properties": {"memory_path": {"type": "string"}},
                "required": ["memory_path"],
            },
        },
    ]


def _control_tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "name": "record_finding",
            "description": "Record a forensic finding. CONFIRMED requires a real call_id from a prior tool result.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "tier": {"type": "string", "enum": ["CONFIRMED", "INFERRED"]},
                    "category": {"type": "string", "description": "e.g. persistence, lateral_movement, command_and_control"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "call_id": {"type": "string", "description": "Required for CONFIRMED. The proving tool's call_id."},
                    "artifact_path": {"type": "string"},
                    "timestamp": {"type": "string", "description": "Event time in the evidence (not now)."},
                    "confidence": {"type": "number", "description": "0.0-1.0, for INFERRED."},
                    "supporting_call_ids": {"type": "array", "items": {"type": "string"}},
                    "mitre": {"type": "string", "description": "MITRE ATT&CK id, e.g. T1021.002"},
                },
                "required": ["tier", "category", "title"],
            },
        },
        {
            "name": "flag_discrepancy",
            "description": "Flag a cross-source contradiction (e.g. process on disk but not in memory) with hypotheses.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "hypotheses": {"type": "array", "items": {"type": "string"}},
                    "resolution": {"type": "string", "description": "Fill in once resolved by follow-up analysis."},
                    "resolved": {"type": "boolean"},
                    "supporting_call_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["summary"],
            },
        },
        {
            "name": "finish_analysis",
            "description": "End the investigation. Call when all phases are done and findings recorded.",
            "input_schema": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    ]


class ReasoningAgent:
    """Claude-driven autonomous DFIR investigator over the typed forensic tools."""

    def __init__(
        self,
        case_dir: str,
        disk_path: str | None,
        memory_path: str | None = None,
        *,
        model: str = DEFAULT_MODEL,
        max_steps: int = MAX_STEPS,
        client: Any | None = None,
        verbose: bool = True,
    ) -> None:
        self.case_dir = case_dir
        self.case_id = Path(case_dir).name or "CASE"
        self.disk_path = disk_path
        self.memory_path = memory_path
        self.model = model
        self.max_steps = max_steps
        self.verbose = verbose
        self._client = client  # injectable for tests

        self.result = AnalysisResult(
            case_id=self.case_id,
            disk_path=disk_path,
            memory_path=memory_path,
            started_at=_utc_now(),
        )
        self._fid = 0
        self._did = 0
        # Map of tool name -> implementation in mcp_server.tools.
        self._dispatch: dict[str, Callable[..., dict[str, Any]]] = {
            name: getattr(tools, name)
            for name in (
                "get_disk_hash", "scan_yara", "get_mft_timeline", "extract_prefetch",
                "detect_timestomping", "get_registry_key", "get_event_logs",
                "run_volatility_pslist", "run_volatility_malfind", "run_volatility_netscan",
            )
            if hasattr(tools, name)
        }

    # ── public API ──────────────────────────────────────────────────────────
    def run(self) -> AnalysisResult:
        """Drive the autonomous investigation to completion."""
        client = self._client or _make_client()
        tool_schemas = _forensic_tool_schemas() + _control_tool_schemas()
        # Only advertise tools whose implementation exists.
        tool_schemas = [
            t for t in tool_schemas
            if t["name"] in self._dispatch or t["name"] in {"record_finding", "flag_discrepancy", "finish_analysis"}
        ]

        messages: list[dict[str, Any]] = [{"role": "user", "content": self._kickoff()}]
        for step in range(self.max_steps):
            response = client.messages.create(
                model=self.model,
                max_tokens=8000,
                system=SYSTEM_PROMPT,
                tools=tool_schemas,
                messages=messages,
            )
            self._echo_text(response)
            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
            if not tool_uses or getattr(response, "stop_reason", None) == "end_turn":
                if not tool_uses:
                    break

            tool_results = []
            finished = False
            for block in tool_uses:
                if block.name == "finish_analysis":
                    self._say(f"[AGENT] Analysis complete: {block.input.get('summary', '')}")
                    finished = True
                    tool_results.append(self._ok_result(block.id, "acknowledged"))
                    continue
                result_text = self._handle_tool(block.name, dict(block.input))
                tool_results.append(self._ok_result(block.id, result_text))

            if finished:
                break
            messages.append({"role": "user", "content": tool_results})

        self.result.finished_at = _utc_now()
        return self.result

    # ── tool handling ───────────────────────────────────────────────────────
    def _handle_tool(self, name: str, args: dict[str, Any]) -> str:
        if name == "record_finding":
            return self._record_finding(args)
        if name == "flag_discrepancy":
            return self._flag_discrepancy(args)
        if name in self._dispatch:
            self._say(f"[AGENT REASONING] -> {name}({_short_args(args)})")
            res = self._dispatch[name](**args)
            if res.get("ok"):
                out = (res.get("stdout") or "")[:MAX_TOOL_OUTPUT_CHARS]
                return json.dumps({
                    "call_id": res.get("call_id"),
                    "ok": True,
                    "output_sha256": res.get("output_sha256"),
                    "output": out or "(no stdout)",
                    "note": "Cite this call_id when recording a CONFIRMED finding from this output.",
                })
            return json.dumps({
                "ok": False,
                "blocked": res.get("blocked", False),
                "error": res.get("error", "tool unavailable"),
            })
        return json.dumps({"ok": False, "error": f"unknown tool {name}"})

    def _record_finding(self, args: dict[str, Any]) -> str:
        self._fid += 1
        tier = Tier.CONFIRMED if args.get("tier") == "CONFIRMED" else Tier.INFERRED
        f = Finding(
            id=f"F-{self._fid:03d}",
            tier=tier,
            category=args.get("category", "unknown"),
            title=args.get("title", ""),
            description=args.get("description", ""),
            call_id=args.get("call_id"),
            artifact_path=args.get("artifact_path"),
            timestamp=args.get("timestamp"),
            confidence=float(args.get("confidence", 1.0 if tier is Tier.CONFIRMED else 0.5)),
            supporting_call_ids=list(args.get("supporting_call_ids", [])),
            mitre=args.get("mitre"),
        )
        self.result.findings.append(f)
        self._say(f"    [+] {f.tier.value} finding {f.id}: {f.title}")
        return f"recorded {f.id}"

    def _flag_discrepancy(self, args: dict[str, Any]) -> str:
        self._did += 1
        d = Discrepancy(
            id=f"D-{self._did:03d}",
            summary=args.get("summary", ""),
            hypotheses=list(args.get("hypotheses", [])),
            resolution=args.get("resolution"),
            resolved=bool(args.get("resolved", False)),
            supporting_call_ids=list(args.get("supporting_call_ids", [])),
        )
        self.result.discrepancies.append(d)
        if d.resolved:
            self.result.iterations += 1
        self._say(f"    [~] DISCREPANCY {d.id}: {d.summary}")
        return f"flagged {d.id}"

    # ── helpers ─────────────────────────────────────────────────────────────
    def _kickoff(self) -> str:
        return (
            f"Investigate case {self.case_id}. "
            f"Disk evidence: {self.disk_path or '(none)'}. "
            f"Memory image: {self.memory_path or '(none)'}. "
            "Find all indicators of compromise. Establish chain of custody first, "
            "build a timeline, check memory, look for cross-source discrepancies, "
            "and record every finding with its proving call_id."
        )

    @staticmethod
    def _ok_result(tool_use_id: str, content: str) -> dict[str, Any]:
        return {"type": "tool_result", "tool_use_id": tool_use_id, "content": content}

    def _echo_text(self, response: Any) -> None:
        for b in response.content:
            if getattr(b, "type", None) == "text" and b.text.strip():
                self._say(f"[AGENT] {b.text.strip()}")

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)


def _short_args(args: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in args.items())[:80]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _make_client() -> Any:
    """Construct an Anthropic client, with a clear error if unavailable."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set — autonomous reasoning mode requires it. "
            "Run without --reasoning to use the deterministic pipeline."
        )
    try:
        import anthropic
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "The 'anthropic' package is required for --reasoning mode "
            "(pip install -r requirements.txt)."
        ) from e
    return anthropic.Anthropic()
