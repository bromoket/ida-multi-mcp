"""Tests for install_mcp_servers idempotency and replace notification."""

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


class TestInstallIdempotent(unittest.TestCase):
    def _run_install(self, home):
        from ida_multi_mcp.__main__ import install_mcp_servers
        with mock.patch("ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)):
            install_mcp_servers(quiet=True)

    def test_reinstall_is_idempotent(self):
        from ida_multi_mcp.__main__ import SERVER_NAME

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / ".factory").mkdir(parents=True, exist_ok=True)
            factory_path = home / ".factory" / "mcp.json"

            old_env = dict(os.environ)
            try:
                os.environ["HOME"] = str(home)
                os.environ["USERPROFILE"] = str(home)

                self._run_install(home)
                first = factory_path.read_text(encoding="utf-8")
                config = json.loads(first)
                assert SERVER_NAME in config["mcpServers"]

                # Second install must produce byte-identical output.
                self._run_install(home)
                second = factory_path.read_text(encoding="utf-8")
                self.assertEqual(first, second)
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    def test_replace_notifies_when_entry_differs(self):
        from ida_multi_mcp.__main__ import SERVER_NAME

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            factory_dir = home / ".factory"
            factory_dir.mkdir(parents=True, exist_ok=True)
            factory_path = factory_dir / "mcp.json"
            # Pre-seed a customized (stale) entry.
            factory_path.write_text(
                json.dumps({"mcpServers": {SERVER_NAME: {"command": "old-custom"}}}),
                encoding="utf-8",
            )

            from ida_multi_mcp.__main__ import install_mcp_servers
            old_env = dict(os.environ)
            try:
                os.environ["HOME"] = str(home)
                os.environ["USERPROFILE"] = str(home)
                printed = []
                with (
                    mock.patch("ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)),
                    mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(map(str, a)))),
                ):
                    install_mcp_servers(quiet=False)

                # The customized entry was replaced, and the user was told.
                config = json.loads(factory_path.read_text(encoding="utf-8"))
                self.assertNotEqual(config["mcpServers"][SERVER_NAME].get("command"), "old-custom")
                self.assertTrue(any("Replacing existing" in line for line in printed))
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
