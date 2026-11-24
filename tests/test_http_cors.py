"""Tests for CORS policy application in ida_mcp/http.py (IDA layer stubbed).

http.py applies the CORS policy once at import and on /config change, rather
than via an @idasync netnode read on every HTTP request. These tests pin the
policy-to-origins mapping.
"""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _localhost_marker(origin):
    return True


@pytest.fixture
def http_module(monkeypatch):
    """Import ida_mcp.http with the IDA-dependent layer stubbed out."""
    # Stub the ida_mcp package so its IDA-heavy __init__ does not run.
    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(SRC_ROOT / "ida_multi_mcp" / "ida_mcp")]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    monkeypatch.setitem(sys.modules, "ida_netnode", MagicMock())

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.idasync = lambda f: f  # no-op decorator
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    # Fake MCP_SERVER with the attributes http.py touches at import time.
    fake_server = types.SimpleNamespace()
    fake_server.tools = types.SimpleNamespace(methods={})
    fake_server.cors_localhost = _localhost_marker
    fake_server.cors_allowed_origins = None

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.McpRpcRegistry = object
    rpc.McpHttpRequestHandler = type("McpHttpRequestHandler", (), {})
    rpc.MCP_SERVER = fake_server
    rpc.MCP_UNSAFE = set()
    rpc.get_cached_output = lambda *_a, **_k: None
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    import importlib
    sys.modules.pop("ida_multi_mcp.ida_mcp.http", None)
    http = importlib.import_module("ida_multi_mcp.ida_mcp.http")
    return http, fake_server


class TestApplyCorsPolicy:
    def test_unrestricted(self, http_module):
        http, server = http_module
        http.apply_cors_policy(server, "unrestricted")
        assert server.cors_allowed_origins == "*"

    def test_local_uses_localhost_checker(self, http_module):
        http, server = http_module
        http.apply_cors_policy(server, "local")
        assert server.cors_allowed_origins is server.cors_localhost

    def test_direct_sets_none(self, http_module):
        http, server = http_module
        http.apply_cors_policy(server, "direct")
        assert server.cors_allowed_origins is None

    def test_unknown_policy_falls_back_to_default(self, http_module):
        http, server = http_module
        server.cors_allowed_origins = "sentinel"
        http.apply_cors_policy(server, "bogus")
        # DEFAULT_CORS_POLICY is "local" → localhost checker.
        assert server.cors_allowed_origins is server.cors_localhost

    def test_handler_has_no_per_request_cors_override(self, http_module):
        http, _ = http_module
        # The old per-request update_cors_policy method must be gone.
        assert not hasattr(http.IdaMcpHttpRequestHandler, "update_cors_policy")
        assert "__init__" not in http.IdaMcpHttpRequestHandler.__dict__
