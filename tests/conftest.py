# Find Evil! — pytest fixtures.
#
# Redirects the audit log to a per-test temp directory so unit tests never
# touch /opt/find-evil/logs and never need root. Tests reload the logger so it
# picks up the redirected FIND_EVIL_LOG_DIR.
#
# License: Apache 2.0

from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def log_dir(tmp_path, monkeypatch):
    """Point the logger at a temp dir and return its path."""
    d = tmp_path / "logs"
    monkeypatch.setenv("FIND_EVIL_LOG_DIR", str(d))
    from mcp_server import logger

    importlib.reload(logger)
    assert logger.LOG_DIR == d
    yield d
