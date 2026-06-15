# Find Evil! — Audit logging and evidence integrity.
#
# Every tool call (executed OR blocked) is written to an append-only JSONL
# audit log. Each entry carries a UUID `call_id` that appears in the final
# report, so any finding can be grepped back to the exact tool, arguments, and
# SHA256 of the output that produced it. This is the chain-of-custody backbone.
#
# License: Apache 2.0

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default log locations mirror install.sh (/opt/find-evil/logs). Overridable
# via env var so unit tests and non-root dev machines can redirect them.
LOG_DIR = Path(os.environ.get("FIND_EVIL_LOG_DIR", "/opt/find-evil/logs"))
TOOL_CALL_LOG = LOG_DIR / "tool_calls.jsonl"
EVIDENCE_HASH_LOG = LOG_DIR / "evidence_hashes.json"

_write_lock = threading.Lock()

# Read chunk size for hashing large evidence/output files without loading them
# fully into memory.
_HASH_CHUNK = 1024 * 1024


def _utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def new_call_id(tool: str) -> str:
    """Generate a unique, greppable call id for a tool invocation.

    Format: ``<tool>_<8 hex chars>`` — e.g. ``get_mft_timeline_7f2a1b3c``.
    The tool prefix makes audit logs scannable by eye.

    Args:
        tool: The tool name this call belongs to.

    Returns:
        A unique call id string.
    """
    return f"{tool}_{uuid.uuid4().hex[:8]}"


def compute_hash(data: str | bytes) -> str:
    """Compute the SHA256 hex digest of in-memory data.

    Args:
        data: Bytes or text to hash. Text is encoded as UTF-8.

    Returns:
        Lowercase hex SHA256 digest.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_file_hash(path: str | Path) -> str:
    """Compute the SHA256 of a file by streaming it in chunks.

    Args:
        path: Path to the file to hash.

    Returns:
        Lowercase hex SHA256 digest.

    Raises:
        FileNotFoundError: If the path does not exist.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def log_tool_call(
    *,
    tool: str,
    args: dict[str, Any],
    call_id: str | None = None,
    output: str | bytes | None = None,
    result_summary: dict[str, Any] | None = None,
    status: str = "executed",
) -> str:
    """Append an audit record for an executed tool call.

    Args:
        tool: Tool name.
        args: Arguments the tool was called with. Paths only — never raw
            evidence content (see Privacy rules).
        call_id: Pre-allocated call id; one is generated if omitted.
        output: Raw tool output, hashed (not stored) for integrity.
        result_summary: Small machine-readable summary of the result.
        status: "executed" by default.

    Returns:
        The call_id written to the log.
    """
    call_id = call_id or new_call_id(tool)
    entry = {
        "call_id": call_id,
        "timestamp": _utc_now(),
        "tool": tool,
        "args": args,
        "status": status,
        "output_sha256": compute_hash(output) if output is not None else None,
        "result_summary": result_summary or {},
    }
    _append(entry)
    return call_id


def log_blocked_attempt(
    *,
    tool: str,
    args: dict[str, Any],
    reason: str,
) -> str:
    """Append an audit record for a blocked tool call.

    Blocked attempts are logged but never executed — this is the evidence trail
    that the bypass tests in BYPASS_TESTING.md rely on.

    Args:
        tool: The tool the agent tried to use (or "BLOCKED_ATTEMPT").
        args: The arguments that were rejected.
        reason: Human-readable reason the call was blocked.

    Returns:
        The generated call_id.
    """
    call_id = f"blocked_{uuid.uuid4().hex[:8]}"
    entry = {
        "call_id": call_id,
        "timestamp": _utc_now(),
        "tool": "BLOCKED_ATTEMPT",
        "attempted_tool": tool,
        "args": args,
        "status": "blocked",
        "result": reason,
        "output_sha256": None,
    }
    _append(entry)
    return call_id


def record_evidence_hash(path: str, sha256: str) -> None:
    """Record (or verify) the SHA256 of an evidence file at mount/analysis time.

    Maintains a JSON map of evidence path -> first-seen hash. If a path is seen
    again with a different hash, that is spoliation and we record it loudly.

    Args:
        path: Evidence file path.
        sha256: The computed SHA256 of the file.
    """
    _ensure_log_dir()
    with _write_lock:
        existing: dict[str, Any] = {}
        if EVIDENCE_HASH_LOG.exists():
            try:
                existing = json.loads(EVIDENCE_HASH_LOG.read_text())
            except json.JSONDecodeError:
                existing = {}

        prior = existing.get(path)
        if prior and prior.get("sha256") and prior["sha256"] != sha256:
            existing[path] = {
                "sha256": sha256,
                "first_seen": prior.get("first_seen"),
                "INTEGRITY_VIOLATION": True,
                "prior_sha256": prior["sha256"],
                "changed_at": _utc_now(),
            }
        elif not prior:
            existing[path] = {"sha256": sha256, "first_seen": _utc_now()}

        EVIDENCE_HASH_LOG.write_text(json.dumps(existing, indent=2))


def _append(entry: dict[str, Any]) -> None:
    """Atomically append one JSON object as a line to the audit log."""
    _ensure_log_dir()
    line = json.dumps(entry, separators=(",", ":"), sort_keys=False)
    with _write_lock:
        with open(TOOL_CALL_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
