# Find Evil! — Typed forensic tool implementations.
#
# Plain functions, no MCP dependency. server.py registers thin MCP wrappers
# around these; agent/loop.py calls them directly in-process. Keeping the logic
# here (not in server.py) means the orchestrator and the unit tests do not need
# the `mcp` package installed to exercise the forensic pipeline.
#
# Every function:
#   - validates its evidence path via Pydantic (config.validate_evidence_path)
#   - screens auxiliary string args for injection
#   - runs the underlying SIFT binary through _safe_run (guardrails + audit log)
#   - returns a uniform envelope carrying the traceable call_id
#
# Guardrail rejections are logged as blocked attempts AT THE POINT OF DETECTION
# (path validation, aux-field screen, or _safe_run) — exactly once — and then
# surfaced to the caller as a structured {"blocked": true} envelope rather than
# raised. This keeps the audit trail complete and the tool interface total.
#
# License: Apache 2.0

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

from . import config
from . import logger
from .safe_exec import ExecResult, _safe_run

_INJECTION_CHARS = (";", "&", "|", "`", "$", ">", "<", "(", ")", "\n", "\r")


class DiskToolInput(BaseModel):
    """Validated input for disk-image tools."""

    image_path: str = Field(..., description="Absolute path under /cases or /mnt")

    @field_validator("image_path")
    @classmethod
    def _validate_image_path(cls, v: str) -> str:
        return config.validate_evidence_path(v)


class MemoryToolInput(BaseModel):
    """Validated input for memory-image tools."""

    memory_path: str = Field(..., description="Absolute path under /cases or /mnt")

    @field_validator("memory_path")
    @classmethod
    def _validate_memory_path(cls, v: str) -> str:
        return config.validate_evidence_path(v)


def _pydantic_reason(err: ValidationError) -> str:
    """Pull our GuardrailError message back out of a wrapped Pydantic error."""
    try:
        msg = err.errors()[0]["msg"]
        # Pydantic prefixes "Value error, " — strip it for a clean message.
        return msg.split("Value error, ", 1)[-1]
    except (IndexError, KeyError):
        return "BLOCKED: invalid evidence path."


def _validate_disk_path(image_path: str, *, tool: str, args: dict[str, Any]) -> str:
    """Validate a disk path, logging + converting any rejection to GuardrailError."""
    try:
        return DiskToolInput(image_path=image_path).image_path
    except ValidationError as e:
        reason = _pydantic_reason(e)
        logger.log_blocked_attempt(tool=tool, args=args, reason=reason)
        raise config.GuardrailError(reason) from None


def _validate_memory_path(memory_path: str, *, tool: str, args: dict[str, Any]) -> str:
    """Validate a memory path, logging + converting any rejection to GuardrailError."""
    try:
        return MemoryToolInput(memory_path=memory_path).memory_path
    except ValidationError as e:
        reason = _pydantic_reason(e)
        logger.log_blocked_attempt(tool=tool, args=args, reason=reason)
        raise config.GuardrailError(reason) from None


def _screen_aux_field(
    value: str, *, field_name: str, tool: str, args: dict[str, Any]
) -> str:
    """Reject injection characters / blocked commands in a non-path argument.

    Logs the blocked attempt at the point of detection so the audit trail is
    complete even for rejections that never reach `_safe_run`.

    Raises:
        config.GuardrailError: On any injection character or blocked token.
    """
    for ch in _INJECTION_CHARS:
        if ch in value:
            reason = (
                f"BLOCKED: {field_name} contains invalid character ({ch!r}). "
                f"Injection rejected. Value: {value}"
            )
            logger.log_blocked_attempt(tool=tool, args=args, reason=reason)
            raise config.GuardrailError(reason)
    try:
        config.assert_command_allowed(value)
    except config.GuardrailError as e:
        logger.log_blocked_attempt(tool=tool, args=args, reason=str(e))
        raise
    return value


def _result(exec_result: ExecResult, **extra: Any) -> dict[str, Any]:
    """Standard success envelope carrying the traceable call_id."""
    return {
        "call_id": exec_result.call_id,
        "ok": exec_result.ok,
        "returncode": exec_result.returncode,
        "output_sha256": exec_result.output_sha256,
        "stdout": exec_result.stdout,
        "stderr": exec_result.stderr,
        **extra,
    }


def _blocked(tool: str, args: dict[str, Any], err: Exception) -> dict[str, Any]:
    """Standard failure/blocked envelope. The block is already audit-logged."""
    return {
        "call_id": None,
        "ok": False,
        "blocked": isinstance(err, config.GuardrailError),
        "error": str(err),
        "tool": tool,
        "args": args,
    }


def get_disk_hash(image_path: str) -> dict[str, Any]:
    """Compute the SHA256 of a disk image for chain-of-custody verification."""
    args = {"image_path": image_path}
    try:
        validated = _validate_disk_path(image_path, tool="get_disk_hash", args=args)
        sha = logger.compute_file_hash(validated)
        logger.record_evidence_hash(validated, sha)
        call_id = logger.log_tool_call(
            tool="get_disk_hash", args=args, output=sha, result_summary={"sha256": sha}
        )
        return {"call_id": call_id, "ok": True, "image_path": validated, "sha256": sha}
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("get_disk_hash", args, e)


def get_mft_timeline(
    image_path: str, parsers: str = "mft,ntfs,winevt,prefetch,winreg"
) -> dict[str, Any]:
    """Build a filesystem + artifact timeline with log2timeline/plaso."""
    args = {"image_path": image_path, "parsers": parsers}
    try:
        validated = _validate_disk_path(image_path, tool="get_mft_timeline", args=args)
        parsers = _screen_aux_field(parsers, field_name="parsers", tool="get_mft_timeline", args=args)
        storage = f"{config.OUTPUT_DIR}/{validated.strip('/').replace('/', '_')}.plaso"
        result = _safe_run(
            ["log2timeline.py", "--storage-file", storage, "--parsers", parsers, validated],
            tool="get_mft_timeline",
            args=args,
        )
        return _result(result, storage_file=storage)
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("get_mft_timeline", args, e)


def get_event_logs(image_path: str, event_ids: str = "4624,4648,4672,4688") -> dict[str, Any]:
    """Extract Windows event log records for the given event IDs."""
    args = {"image_path": image_path, "event_ids": event_ids}
    try:
        validated = _validate_disk_path(image_path, tool="get_event_logs", args=args)
        event_ids = _screen_aux_field(event_ids, field_name="event_ids", tool="get_event_logs", args=args)
        result = _safe_run(
            ["psort.py", "-q", "-o", "json", validated, f"event_identifier in ({event_ids})"],
            tool="get_event_logs",
            args=args,
        )
        return _result(result)
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("get_event_logs", args, e)


def extract_prefetch(image_path: str, output_format: str = "json") -> dict[str, Any]:
    """Parse Windows Prefetch files to recover process-execution evidence."""
    args = {"image_path": image_path, "output_format": output_format}
    try:
        validated = _validate_disk_path(image_path, tool="extract_prefetch", args=args)
        output_format = _screen_aux_field(output_format, field_name="output_format", tool="extract_prefetch", args=args)
        result = _safe_run(
            ["prefetch.py", "--format", output_format, validated],
            tool="extract_prefetch",
            args=args,
        )
        return _result(result)
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("extract_prefetch", args, e)


def get_registry_key(image_path: str, hive: str) -> dict[str, Any]:
    """Read registry persistence / configuration keys with RegRipper."""
    args = {"image_path": image_path, "hive": hive}
    try:
        validated = _validate_disk_path(image_path, tool="get_registry_key", args=args)
        hive = _screen_aux_field(hive, field_name="hive", tool="get_registry_key", args=args)
        result = _safe_run(
            ["rip.pl", "-r", validated, "-f", hive], tool="get_registry_key", args=args
        )
        return _result(result)
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("get_registry_key", args, e)


def scan_yara(image_path: str, rules_path: str = "/opt/find-evil/yara_rules") -> dict[str, Any]:
    """Scan an evidence file/tree against a YARA ruleset (read-only)."""
    args = {"image_path": image_path, "rules_path": rules_path}
    try:
        validated = _validate_disk_path(image_path, tool="scan_yara", args=args)
        rules_path = _screen_aux_field(rules_path, field_name="rules_path", tool="scan_yara", args=args)
        result = _safe_run(
            ["yara", "-r", rules_path, validated], tool="scan_yara", args=args
        )
        return _result(result)
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("scan_yara", args, e)


def run_volatility_pslist(memory_path: str, output_format: str = "json") -> dict[str, Any]:
    """List processes from a memory image with Volatility 3 (windows.pslist)."""
    args = {"memory_path": memory_path, "output_format": output_format}
    try:
        validated = _validate_memory_path(memory_path, tool="run_volatility_pslist", args=args)
        output_format = _screen_aux_field(output_format, field_name="output_format", tool="run_volatility_pslist", args=args)
        result = _safe_run(
            ["vol.py", "-r", output_format, "-f", validated, "windows.pslist"],
            tool="run_volatility_pslist",
            args=args,
        )
        return _result(result)
    except (config.GuardrailError, FileNotFoundError) as e:
        return _blocked("run_volatility_pslist", args, e)


# The complete typed tool surface. rm/dd/curl/ssh are deliberately absent.
ALL_TOOLS = (
    get_disk_hash,
    get_mft_timeline,
    get_event_logs,
    extract_prefetch,
    get_registry_key,
    scan_yara,
    run_volatility_pslist,
)
