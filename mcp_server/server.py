# Find Evil! — MCP server: typed forensic tool surface.
#
# This is the thin registration layer. The agent reaches the OS ONLY through
# the functions registered here (implemented in tools.py). rm/dd/curl/ssh are
# not registered — they do not exist in the agent's tool surface. That absence,
# plus the guardrails in config.py/safe_exec.py, is the architectural guarantee.
#
# Run:  python3 -m mcp_server.server
#
# License: Apache 2.0

from __future__ import annotations

from . import tools

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:  # pragma: no cover - import guard for dev machines
    raise SystemExit(
        "The 'mcp' package is required to run the server. "
        "Install dependencies with: pip install -r requirements.txt"
    ) from e


mcp = FastMCP("find-evil")

# Register each typed forensic tool. The implementations live in tools.py so
# they can be unit-tested and called by the orchestrator without importing MCP.
for _tool in tools.ALL_TOOLS:
    mcp.tool()(_tool)


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
