"""Tests for tools/index_store.py — persistent similarity-index storage."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ida_multi_mcp.tools import index_store


def _shard_files(index_dir: str, sha: str) -> list[str]:
    """Basenames of any function-shard files for *sha* (name is unique per write)."""
    prefix = f"{sha}.functions."
    return [n for n in os.listdir(index_dir)
            if n.startswith(prefix) and n.endswith(".jsonl")]


@pytest.fixture
def registry_path():
    """Fresh temp dir per test; index files land in ``<td>/index`` (never ~/.ida-mcp)."""
    with tempfile.TemporaryDirectory() as td:
        yield os.path.join(td, "instances.json")


def _make_index(sha: str = "a" * 64, n_functions: int = 3) -> dict:
    """Build a synthetic index dict matching design §4.2 (JSON-native values)."""
    functions = {
        f"0x40{i:04x}": {
            "addr": f"0x40{i:04x}",
            "name": f"sub_40{i:04x}",
            "is_named": False,
            "size": 100 + i,
            "cfg": {"bb_count": 3 + i, "edge_count": 4 + i, "complexity": i},
            "minhash": [i, i + 1, i + 2],
            "apis": ["CreateFileW", "WriteFile"],
            "strings": ["%s.enc", "Locked"],
            "consts": ["0xedb88320", "0x1000"],
        }
        for i in range(n_functions)
    }
    return {
        "schema_version": 1,
        "binary_sha256": sha,
        "binary_name": "malware.exe",
        "arch": "x86_64",
        "built_at": "2026-07-07T00:00:00Z",
        "function_count": n_functions,
        "params": {"M": 64, "k": 4, "bands": 16, "rows": 4},
        "df": {"apis": {"CreateFileW": 812}, "strings": {}, "consts": {}},
        "zstats": {"bb_count": {"mean": 3.0, "std": 1.0}},
        "functions": functions,
        "lsh": {"0": {"a1b2c3d4": ["0x400000", "0x400001"]}},
    }


# ---------------------------------------------------------------------------
# resolve_index_dir / index_path
# ---------------------------------------------------------------------------

class TestResolveIndexDir:
    def test_creates_dir_with_explicit_registry_path(self, registry_path):
        index_dir = index_store.resolve_index_dir(registry_path)
        assert os.path.isdir(index_dir)
        assert Path(index_dir) == Path(os.path.dirname(registry_path)) / "index"

    def test_default_honors_env(self, monkeypatch, tmp_path):
        reg = tmp_path / "custom" / "instances.json"
        monkeypatch.setenv("IDA_MULTI_MCP_REGISTRY_PATH", str(reg))
        index_dir = index_store.resolve_index_dir()
        assert os.path.isdir(index_dir)
        assert Path(index_dir) == tmp_path / "custom" / "index"

    def test_index_path_matches_dir(self, registry_path):
        p = index_store.index_path("a" * 64, registry_path)
        expected = Path(os.path.dirname(registry_path)) / "index" / (("a" * 64) + ".json")
        assert Path(p) == expected


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_write_read_inline(self, registry_path):
        index = _make_index()
        path = index_store.write_index(index, registry_path)
        assert path.endswith(".json")
        assert os.path.isfile(path)
        loaded = index_store.read_index(index["binary_sha256"], registry_path)
        assert loaded == index

    def test_read_absent_returns_none(self, registry_path):
        assert index_store.read_index("f" * 64, registry_path) is None


# ---------------------------------------------------------------------------
# has_index / delete_index
# ---------------------------------------------------------------------------

class TestHasDelete:
    def test_has_index_lifecycle(self, registry_path):
        index = _make_index()
        sha = index["binary_sha256"]
        assert index_store.has_index(sha, registry_path) is False
        index_store.write_index(index, registry_path)
        assert index_store.has_index(sha, registry_path) is True
        assert index_store.delete_index(sha, registry_path) is True
        assert index_store.has_index(sha, registry_path) is False

    def test_delete_absent_returns_false(self, registry_path):
        assert index_store.delete_index("b" * 64, registry_path) is False

    def test_delete_removes_shard(self, registry_path, monkeypatch):
        monkeypatch.setattr(index_store, "SHARD_THRESHOLD", 2)
        index = _make_index(n_functions=5)
        sha = index["binary_sha256"]
        index_store.write_index(index, registry_path)
        index_dir = index_store.resolve_index_dir(registry_path)
        assert _shard_files(index_dir, sha), "expected a shard to be written"
        assert index_store.delete_index(sha, registry_path) is True
        assert not _shard_files(index_dir, sha)


# ---------------------------------------------------------------------------
# Corruption handling
# ---------------------------------------------------------------------------

class TestCorruption:
    def test_corrupt_meta_quarantined(self, registry_path):
        index = _make_index()
        sha = index["binary_sha256"]
        path = index_store.write_index(index, registry_path)

        with open(path, "w", encoding="utf-8") as f:
            f.write("{ this is not valid json ]]]")

        assert index_store.read_index(sha, registry_path) is None

        index_dir = os.path.dirname(path)
        corrupt = [n for n in os.listdir(index_dir) if ".corrupt-" in n]
        assert corrupt, "expected a quarantined *.corrupt-* file"
        assert not os.path.exists(path), "corrupt meta should have been moved aside"


# ---------------------------------------------------------------------------
# Sharding (large indexes)
# ---------------------------------------------------------------------------

class TestSharding:
    def test_large_index_sharded_and_reassembled(self, registry_path, monkeypatch):
        monkeypatch.setattr(index_store, "SHARD_THRESHOLD", 2)
        index = _make_index(n_functions=5)
        sha = index["binary_sha256"]
        path = index_store.write_index(index, registry_path)

        index_dir = os.path.dirname(path)
        assert _shard_files(index_dir, sha), "expected a .functions.jsonl shard"

        # Meta on disk must not inline the functions map.
        with open(path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        assert meta.get("functions_sharded") is True
        assert "functions" not in meta

        loaded = index_store.read_index(sha, registry_path)
        assert loaded is not None
        assert "functions_sharded" not in loaded
        assert loaded["functions"] == index["functions"]
        assert loaded == index

    def test_inline_write_clears_previous_shard(self, registry_path, monkeypatch):
        sha = "d" * 64
        # First write is sharded.
        monkeypatch.setattr(index_store, "SHARD_THRESHOLD", 2)
        index_store.write_index(_make_index(sha=sha, n_functions=5), registry_path)
        index_dir = index_store.resolve_index_dir(registry_path)
        assert _shard_files(index_dir, sha)

        # Second write (default threshold) is inline; stale shard must be dropped.
        monkeypatch.setattr(index_store, "SHARD_THRESHOLD", 20000)
        small = _make_index(sha=sha, n_functions=2)
        index_store.write_index(small, registry_path)
        assert not _shard_files(index_dir, sha)
        assert index_store.read_index(sha, registry_path) == small

    def test_corrupt_shard_with_valid_meta_quarantined(self, registry_path, monkeypatch):
        monkeypatch.setattr(index_store, "SHARD_THRESHOLD", 2)
        sha = "1" * 64
        path = index_store.write_index(_make_index(sha=sha, n_functions=5), registry_path)
        index_dir = os.path.dirname(path)
        shard = os.path.join(index_dir, _shard_files(index_dir, sha)[0])
        with open(shard, "w", encoding="utf-8") as f:
            f.write("{ not valid jsonl ]]]")
        assert index_store.read_index(sha, registry_path) is None
        corrupt = [n for n in os.listdir(index_dir) if ".corrupt-" in n]
        assert corrupt, "a corrupt shard (with valid meta) should be quarantined"

    def test_sharded_rebuild_interruption_is_consistent(self, registry_path, monkeypatch):
        # Regression: an interrupted rebuild (new shard on disk, meta not yet
        # updated to reference it) must NOT merge old meta with the new shard.
        monkeypatch.setattr(index_store, "SHARD_THRESHOLD", 2)
        sha = "e" * 64
        v1 = _make_index(sha=sha, n_functions=3)
        index_store.write_index(v1, registry_path)
        index_dir = index_store.resolve_index_dir(registry_path)
        # A stray new-generation shard lands on disk (as a killed rebuild would
        # leave), but the committed meta still references the original shard.
        stray = os.path.join(index_dir, f"{sha}.functions.{'f' * 32}.jsonl")
        with open(stray, "w", encoding="utf-8") as f:
            for i in range(7):
                f.write(json.dumps({"addr": f"0x{i}", "feat": {"x": i}}) + "\n")
        loaded = index_store.read_index(sha, registry_path)
        assert loaded is not None
        assert loaded["function_count"] == 3            # old meta, not the stray shard
        assert loaded["functions"] == v1["functions"]   # old shard, fully consistent


# ---------------------------------------------------------------------------
# Listing / repeated writes
# ---------------------------------------------------------------------------

class TestListing:
    def test_list_indexes_reports_entry(self, registry_path):
        index = _make_index(n_functions=4)
        index_store.write_index(index, registry_path)
        entries = index_store.list_indexes(registry_path)
        assert len(entries) == 1
        e = entries[0]
        assert e["sha256"] == index["binary_sha256"]
        assert e["binary_name"] == "malware.exe"
        assert e["function_count"] == 4
        assert e["built_at"] == "2026-07-07T00:00:00Z"
        assert os.path.isfile(e["path"])

    def test_list_skips_corrupt(self, registry_path):
        index = _make_index()
        path = index_store.write_index(index, registry_path)
        index_dir = os.path.dirname(path)
        with open(os.path.join(index_dir, ("c" * 64) + ".json"), "w", encoding="utf-8") as f:
            f.write("not json at all")
        entries = index_store.list_indexes(registry_path)
        assert len(entries) == 1
        assert entries[0]["sha256"] == index["binary_sha256"]

    def test_repeated_writes_do_not_corrupt(self, registry_path):
        index = _make_index()
        sha = index["binary_sha256"]
        index_store.write_index(index, registry_path)

        index2 = _make_index()
        index2["function_count"] = 99
        index2["binary_name"] = "updated.exe"
        index_store.write_index(index2, registry_path)

        loaded = index_store.read_index(sha, registry_path)
        assert loaded is not None
        assert loaded["function_count"] == 99
        assert loaded["binary_name"] == "updated.exe"
        # Exactly one meta file remains (no orphan/temp/corrupt left behind).
        assert len(index_store.list_indexes(registry_path)) == 1


# ---------------------------------------------------------------------------
# Key validation (path-traversal guard)
# ---------------------------------------------------------------------------

class TestKeyValidation:
    def test_rejects_path_separator(self, registry_path):
        bad = os.path.join("..", "escape")
        with pytest.raises(ValueError):
            index_store.has_index(bad, registry_path)

    def test_rejects_empty(self, registry_path):
        with pytest.raises(ValueError):
            index_store.read_index("", registry_path)

    def test_rejects_colon_key(self, registry_path):
        # ':' enables a Windows drive-relative / ADS escape; must be rejected.
        with pytest.raises(ValueError):
            index_store.has_index("C:evil", registry_path)
