# Find Evil! — Custom MCP server for autonomous, audit-traced DFIR.
#
# Public surface kept small and import-light so config/logger can be imported
# (e.g. by install.sh smoke tests and unit tests) without pulling in the heavy
# `mcp` dependency that server.py needs.
#
# License: Apache 2.0

from __future__ import annotations

from .config import (
    BLOCKED_COMMANDS,
    PROTECTED_WRITE_PATHS,
    GuardrailError,
    assert_command_allowed,
    assert_no_protected_write,
    validate_evidence_path,
)
from .logger import compute_hash, compute_file_hash, log_blocked_attempt, log_tool_call

__version__ = "1.0.0"

__all__ = [
    "BLOCKED_COMMANDS",
    "PROTECTED_WRITE_PATHS",
    "GuardrailError",
    "assert_command_allowed",
    "assert_no_protected_write",
    "validate_evidence_path",
    "compute_hash",
    "compute_file_hash",
    "log_blocked_attempt",
    "log_tool_call",
    "__version__",
]
