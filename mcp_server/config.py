# Find Evil! — MCP server configuration and architectural guardrails.
#
# This module is the single source of truth for what the agent physically
# cannot do. The checks here run BEFORE any subprocess is spawned and BEFORE
# any tool output reaches the LLM. They are not prompt instructions — they are
# enforced in code. See BYPASS_TESTING.md for the documented threat model.
#
# License: Apache 2.0

from __future__ import annotations

import re
from pathlib import PurePosixPath

# ── Destructive / exfiltration commands the agent may never invoke ──────────
# Matched as whole tokens against every command string before execution.
# Membership here is what makes "rm doesn't exist" architectural rather than a
# polite request in a prompt.
BLOCKED_COMMANDS: frozenset[str] = frozenset(
    {
        # Destruction / mutation of evidence
        "rm",
        "rmdir",
        "dd",
        "shred",
        "mkfs",
        "wipe",
        "truncate",
        "fallocate",
        "mv",
        "cp",  # copying evidence off-box is staging; reads go through typed tools
        "ln",
        "chmod",
        "chown",
        "chattr",
        # Exfiltration / outbound network
        "curl",
        "wget",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "nc",
        "ncat",
        "netcat",
        "telnet",
        "ftp",
        "tftp",
        # Arbitrary code execution vectors
        "bash",
        "sh",
        "zsh",
        "eval",
        "exec",
        "source",
        "perl",
        "ruby",
        "php",
        "node",
        # Python one-liners are a common injection vector. We block the *flag
        # form* ("python3 -c") via the substring check below; the bare token is
        # also listed so a standalone `python` invocation is rejected.
        "python",
        "python3",
    }
)

# Substring patterns (not whole tokens) that indicate code injection or
# redirection regardless of tokenization. Checked case-insensitively.
BLOCKED_PATTERNS: tuple[str, ...] = (
    "python -c",
    "python3 -c",
    "-c ",  # generic "-c <code>" inline-execution flag
    "<(",  # process substitution
    ">(",
    "$(",  # command substitution
    "`",  # backtick command substitution
)

# ── Paths the agent may never write to ──────────────────────────────────────
# Evidence lives here. The server refuses any command whose effect is a write
# (redirect, tee, or a tool's output path) into these trees.
PROTECTED_WRITE_PATHS: tuple[str, ...] = (
    "/cases",
    "/mnt",
    "/media",
    "/evidence",
)

# ── Paths the agent is allowed to READ evidence from ────────────────────────
# Typed tools validate that any evidence path resolves under one of these.
ALLOWED_EVIDENCE_PATHS: tuple[str, ...] = (
    "/cases",
    "/mnt",
    "/media",
    "/evidence",
)

# ── Scratch space ───────────────────────────────────────────────────────────
# The ONLY place tool output may be written. Never holds evidence copies, only
# parsed tool artifacts. See Known Limitations in BYPASS_TESTING.md.
OUTPUT_DIR = "/tmp/find-evil-output"

# Characters that must never appear in a path argument. Their presence means
# someone is trying to chain a second command onto a typed tool call.
ILLEGAL_PATH_CHARS: tuple[str, ...] = (
    ";",
    "&",
    "|",
    "`",
    "$",
    ">",
    "<",
    "\n",
    "\r",
    "(",
    ")",
    "*",
    "?",
    "\\",
)

# Commands whose effect is to create or modify a file. If any of these targets
# a protected (evidence) path, that is a write attempt and is rejected — even
# though it is not a shell redirect. Destructive ones (rm, dd, cp, mv, shred)
# are already in BLOCKED_COMMANDS and rejected outright; these are the
# write-but-not-in-BLOCKED_COMMANDS gap-fillers.
WRITE_COMMANDS: frozenset[str] = frozenset(
    {"touch", "mkdir", "tee", "install", "cat", "echo", "printf", "sed"}
)

# Word-boundary token splitter — splits a command string into the tokens we
# screen against BLOCKED_COMMANDS. Mirrors how a shell would word-split, but we
# never actually hand the string to a shell.
_TOKEN_RE = re.compile(r"[^\s;&|>()<`'\"]+")


class GuardrailError(ValueError):
    """Raised when a command or path violates an architectural constraint.

    Subclasses ValueError so existing `except ValueError` handlers in tool code
    continue to work, while callers that care can catch this specifically.
    """


def assert_command_allowed(cmd: str) -> None:
    """Reject a command string that invokes a blocked command or pattern.

    Args:
        cmd: The full command string about to be executed.

    Raises:
        GuardrailError: If any token is in BLOCKED_COMMANDS or any blocked
            pattern is present. The message names the offending command so the
            audit log and demo show exactly what was stopped.
    """
    lowered = cmd.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern in lowered:
            raise GuardrailError(
                f"BLOCKED: injection pattern '{pattern.strip()}' detected.\n"
                f"Full command: {cmd}"
            )

    for token in _TOKEN_RE.findall(cmd):
        base = token.lower()
        # Compare against the bare program name (strip any path prefix the
        # tokenizer left, and a trailing arg-glued form).
        program = PurePosixPath(base).name
        if program in BLOCKED_COMMANDS:
            raise GuardrailError(
                f"BLOCKED: Command '{program}' is not permitted.\n"
                f"Full command: {cmd}"
            )


def assert_no_protected_write(cmd: str) -> None:
    """Reject a command that would write into a protected (evidence) path.

    Catches shell redirection (`>`, `>>`), `tee`, and any bare occurrence of a
    protected path on the *write* side of a redirect.

    Args:
        cmd: The full command string about to be executed.

    Raises:
        GuardrailError: If a write into a protected path is detected.
    """
    # Any redirection target landing in a protected tree.
    for protected in PROTECTED_WRITE_PATHS:
        # `> /cases`, `>> /cases`, `tee /cases`, `tee -a /cases`
        redirect_re = re.compile(
            r"(?:>>?|\btee\b(?:\s+-a)?)\s*" + re.escape(protected),
        )
        if redirect_re.search(cmd):
            raise GuardrailError(
                f"BLOCKED: Write to protected path '{protected}' not permitted.\n"
                f"Pattern '> {protected}' detected in command string.\n"
                f"Full command: {cmd}"
            )

    # A file-creating command (touch/mkdir/tee/...) targeting a protected path.
    tokens = _TOKEN_RE.findall(cmd)
    saw_write_cmd = False
    for token in tokens:
        program = PurePosixPath(token.lower()).name
        if program in WRITE_COMMANDS:
            saw_write_cmd = True
            continue
        if saw_write_cmd and is_protected_write_path(token):
            raise GuardrailError(
                f"BLOCKED: Write to protected path '{token}' not permitted.\n"
                f"Full command: {cmd}"
            )


def validate_evidence_path(path: str) -> str:
    """Validate and normalize an evidence path argument for a typed tool.

    This is the Pydantic-layer check referenced throughout BYPASS_TESTING.md:
    it runs before the path ever reaches a subprocess, and rejects injection
    attempts (extra commands chained onto a path) as well as paths outside the
    permitted evidence trees.

    Args:
        path: The user/agent supplied evidence path.

    Returns:
        The normalized absolute path.

    Raises:
        GuardrailError: If the path contains illegal characters or does not
            resolve under an allowed evidence root.
    """
    if not path or not path.strip():
        raise GuardrailError("BLOCKED: empty evidence path.")

    for ch in ILLEGAL_PATH_CHARS:
        if ch in path:
            raise GuardrailError(
                f"BLOCKED: image_path contains invalid character "
                f"({ch!r} detected). Path injection rejected.\n"
                f"Value: {path}"
            )

    normalized = PurePosixPath(path)
    if not normalized.is_absolute():
        raise GuardrailError(
            f"BLOCKED: evidence path must be absolute. Value: {path}"
        )

    # Block traversal that could escape the evidence root after normalization.
    if ".." in normalized.parts:
        raise GuardrailError(
            f"BLOCKED: path traversal ('..') not permitted. Value: {path}"
        )

    resolved = str(normalized)
    for root in ALLOWED_EVIDENCE_PATHS:
        if resolved == root or resolved.startswith(root.rstrip("/") + "/"):
            return resolved

    raise GuardrailError(
        f"BLOCKED: image_path must be under one of "
        f"{', '.join(ALLOWED_EVIDENCE_PATHS)}. Value: {path}"
    )


def is_protected_write_path(path: str) -> bool:
    """Return True if writing to `path` would touch a protected evidence tree."""
    resolved = str(PurePosixPath(path))
    for root in PROTECTED_WRITE_PATHS:
        if resolved == root or resolved.startswith(root.rstrip("/") + "/"):
            return True
    return False
