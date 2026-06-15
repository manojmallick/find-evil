# Find Evil! — Guarded subprocess execution.
#
# `_safe_run()` is the single chokepoint through which every forensic tool
# reaches the OS. It enforces the architectural guardrails (blocked commands,
# protected write paths), executes WITHOUT a shell so chained/injected commands
# cannot run, and writes an audit record for both successes and blocks.
#
# License: Apache 2.0

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Any, Sequence

from . import config
from . import logger

# Hard wall-clock ceiling for any single tool. Forensic parsers on large images
# are slow; this prevents a hung subprocess from stalling the whole analysis.
DEFAULT_TIMEOUT_SECONDS = 1800


@dataclass
class ExecResult:
    """Result of a guarded subprocess execution."""

    call_id: str
    returncode: int
    stdout: str
    stderr: str
    output_sha256: str
    command: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _as_argv(command: str | Sequence[str]) -> list[str]:
    """Normalize a command into an argv list without invoking a shell.

    Accepts either a pre-split argv (preferred) or a string, which is split
    with shlex. We never pass the string to a shell — splitting here is only so
    the guardrail checks see the same tokens the OS would.
    """
    if isinstance(command, str):
        return shlex.split(command)
    return list(command)


def _flatten(command: str | Sequence[str]) -> str:
    """Render a command back to a string for guardrail screening + logging."""
    if isinstance(command, str):
        return command
    return " ".join(command)


def _safe_run(
    command: str | Sequence[str],
    *,
    tool: str,
    args: dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> ExecResult:
    """Execute a forensic command behind the architectural guardrails.

    Enforcement order (each step can reject before the next runs):
      1. Screen the command string for blocked commands / injection patterns.
      2. Screen for writes into protected evidence paths.
      3. Execute with ``shell=False`` so no shell metacharacters are honored.
      4. Hash and audit-log the output; return a structured result.

    Args:
        command: The command to run, as an argv list (preferred) or string.
        tool: The typed-tool name this execution belongs to (for the audit log).
        args: The tool's original arguments, recorded in the audit log.
        timeout: Wall-clock timeout in seconds.

    Returns:
        An ExecResult with the captured output and its call_id.

    Raises:
        config.GuardrailError: If the command violates an architectural
            constraint. The attempt is logged as a blocked attempt first.
        subprocess.TimeoutExpired: If the command exceeds ``timeout``.
    """
    flat = _flatten(command)

    # ── Guardrails — these run BEFORE any process is spawned ────────────────
    try:
        config.assert_command_allowed(flat)
        config.assert_no_protected_write(flat)
    except config.GuardrailError as e:
        logger.log_blocked_attempt(tool=tool, args=args, reason=str(e))
        raise

    argv = _as_argv(command)
    if not argv:
        raise config.GuardrailError("BLOCKED: empty command.")

    # Re-screen the *program* token explicitly. _as_argv may strip a path
    # prefix that the string-level check tokenized differently.
    program = argv[0].rsplit("/", 1)[-1]
    if program.lower() in config.BLOCKED_COMMANDS:
        reason = f"BLOCKED: Command '{program}' is not permitted.\nFull command: {flat}"
        logger.log_blocked_attempt(tool=tool, args=args, reason=reason)
        raise config.GuardrailError(reason)

    # ── Execute — shell=False is what makes injection inert ─────────────────
    completed = subprocess.run(  # noqa: S603 - argv is screened, shell disabled
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        check=False,
    )

    output_hash = logger.compute_hash(completed.stdout)
    call_id = logger.log_tool_call(
        tool=tool,
        args=args,
        output=completed.stdout,
        result_summary={
            "returncode": completed.returncode,
            "stdout_bytes": len(completed.stdout),
            "stderr_bytes": len(completed.stderr),
        },
    )

    return ExecResult(
        call_id=call_id,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        output_sha256=output_hash,
        command=argv,
    )
