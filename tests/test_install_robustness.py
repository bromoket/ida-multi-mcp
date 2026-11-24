"""Tests for install_mcp_servers resilience to malformed / unusable configs.

A single broken client config must never crash the installer or corrupt the
file; the client is skipped and the run continues.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class _FactoryEnv:
    """Context manager: isolated HOME with a Factory Droid config at *content*."""

    def __init__(self, content, as_dir=False):
        self.content = content
        self.as_dir = as_dir

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        home = Path(self._td.name)
        factory = home / ".factory"
        factory.mkdir(parents=True, exist_ok=True)
        self.config_path = factory / "mcp.json"
        if self.as_dir:
            self.config_path.mkdir()
        elif self.content is not None:
            self.config_path.write_text(self.content, encoding="utf-8")
        self._old_env = dict(os.environ)
        os.environ["HOME"] = str(home)
        os.environ["USERPROFILE"] = str(home)
        self._patcher = mock.patch(
            "ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)
        )
        self._patcher.start()
        return self

    def __exit__(self, *exc):
        self._patcher.stop()
        os.environ.clear()
        os.environ.update(self._old_env)
        self._td.cleanup()


class TestInstallRobustness(unittest.TestCase):
    def _install(self):
        from ida_multi_mcp.__main__ import install_mcp_servers
        # Must not raise regardless of the config contents.
        install_mcp_servers(quiet=True)

    def test_non_dict_root_is_skipped_and_preserved(self):
        with _FactoryEnv("[1, 2, 3]") as env:
            self._install()
            # File left untouched (not clobbered).
            self.assertEqual(json.loads(env.config_path.read_text()), [1, 2, 3])

    def test_non_dict_server_map_is_skipped_and_preserved(self):
        original = json.dumps({"mcpServers": "not-a-dict"})
        with _FactoryEnv(original) as env:
            self._install()
            self.assertEqual(env.config_path.read_text(), original)

    def test_list_server_map_is_skipped(self):
        original = json.dumps({"mcpServers": ["a", "b"]})
        with _FactoryEnv(original) as env:
            self._install()
            self.assertEqual(env.config_path.read_text(), original)

    def test_unreadable_config_is_skipped(self):
        # A directory where a file is expected → open() raises OSError.
        with _FactoryEnv(None, as_dir=True) as env:
            self._install()  # must not raise
            self.assertTrue(env.config_path.is_dir())

    def test_invalid_json_is_skipped_and_preserved(self):
        original = "{ this is not json "
        with _FactoryEnv(original) as env:
            self._install()
            self.assertEqual(env.config_path.read_text(), original)

    def test_valid_config_still_installs(self):
        # Sanity: a normal config is installed (guards don't block the happy path).
        from ida_multi_mcp.__main__ import SERVER_NAME
        with _FactoryEnv(json.dumps({"mcpServers": {}})) as env:
            self._install()
            config = json.loads(env.config_path.read_text())
            self.assertIn(SERVER_NAME, config["mcpServers"])


if __name__ == "__main__":
    unittest.main()
