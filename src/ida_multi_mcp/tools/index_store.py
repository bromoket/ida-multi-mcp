"""Persistent storage for per-binary function-similarity indexes.

Indexes are JSON files keyed by binary content sha256, stored under an
``index/`` directory next to the instance registry file. Reads and writes are
guarded by the registry's :class:`FileLock` and committed atomically (write a
temp file, then ``os.replace``), mirroring ``registry.py``.

Large indexes shard their ``functions`` map to a sibling ``.functions.jsonl``
file so the meta document (df/zstats/lsh/params) stays small; the loader
transparently reassembles both layouts. Corrupt meta files are quarantined to
``<name>.corrupt-<epoch>`` and treated as absent, matching the registry's
recovery contract.

Pure standard library plus the repo's ``FileLock`` — no ``idaapi``.
"""

import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable, TextIO

from ..filelock import FileLock

# Environment override for the registry file location (see registry.py). Its
# directory anchors the sibling ``index/`` directory.
REGISTRY_PATH_ENV = "IDA_MULTI_MCP_REGISTRY_PATH"

# Above this many functions, the ``functions`` map is written to a sibling
# ``<sha256>.functions.jsonl`` shard instead of inline in the meta file.
SHARD_THRESHOLD = 20000

# Content errors that mean a stored file is corrupt/unusable and should be
# quarantined rather than surfaced. ``json.JSONDecodeError`` and
# ``UnicodeDecodeError`` are subclasses of ``ValueError``; ``OSError`` (incl.
# a file vanishing mid-read) degrades gracefully to "absent".
_CORRUPT_ERRORS = (OSError, ValueError, KeyError, TypeError)


# Characters that must never appear in an index key: path separators (both
# platforms), the Windows drive/ADS colon, and NUL. The key becomes a filename,
# so any of these could redirect a write/read outside index_dir.
_UNSAFE_KEY_CHARS = re.compile(r"[\\/:\x00]")


def _validate_key(sha256: str) -> None:
    """Reject index keys that could escape the index directory.

    The key becomes a filename, so it must be a non-empty string containing no
    path separator, drive/ADS colon, or NUL, and must not be ``.``/``..``.
    """
    if not isinstance(sha256, str) or not sha256:
        raise ValueError("index key (binary_sha256) must be a non-empty string")
    if sha256 in (".", "..") or _UNSAFE_KEY_CHARS.search(sha256):
        raise ValueError(f"invalid index key: {sha256!r}")


def _lock_path(index_dir: str, sha256: str) -> str:
    """Path of the per-index lock file (one lock per binary sha256)."""
    return os.path.join(index_dir, f"{sha256}.lock")


def _meta_path(index_dir: str, sha256: str) -> str:
    """Path of the meta JSON file for *sha256*."""
    return os.path.join(index_dir, f"{sha256}.json")


def _shard_path(index_dir: str, sha256: str) -> str:
    """Legacy fixed-name shard for *sha256* (read for back-compat only)."""
    return os.path.join(index_dir, f"{sha256}.functions.jsonl")


def _new_shard_name(sha256: str) -> str:
    """A unique shard filename so a rebuild never overwrites the live shard."""
    return f"{sha256}.functions.{uuid.uuid4().hex}.jsonl"


def _shard_paths(index_dir: str, sha256: str) -> list[str]:
    """Every shard file for *sha256* (unique-named + the legacy fixed name)."""
    prefix = f"{sha256}.functions."
    try:
        names = os.listdir(index_dir)
    except OSError:
        return []
    return [
        os.path.join(index_dir, n)
        for n in names
        if n.startswith(prefix) and n.endswith(".jsonl")
    ]


def _prune_shards(index_dir: str, sha256: str, keep: str | None) -> None:
    """Delete every shard for *sha256* except basename *keep*.

    Called only AFTER the meta commit, so at worst it orphans a shard the next
    successful write cleans up — it never removes the live shard before its
    referencing meta is durable.
    """
    for path in _shard_paths(index_dir, sha256):
        if keep is not None and os.path.basename(path) == keep:
            continue
        try:
            os.remove(path)
        except OSError:
            pass


def _atomic_write(path: str, write_body: Callable[[TextIO], None]) -> None:
    """Write *path* atomically: fill a temp file, then ``os.replace`` it.

    Never leaves a half-written file at *path*: the destination only appears
    once the fully written temp file is renamed over it.
    """
    directory = os.path.dirname(path) or "."
    temp_fd, temp_path = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
        dir=directory,
    )
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            temp_fd = None  # fdopen owns the fd now.
            write_body(f)
        os.replace(temp_path, path)
        temp_path = None  # Rename succeeded; nothing to clean up.
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _dump_jsonl(functions: dict, f: TextIO) -> None:
    """Write a ``functions`` map as one ``{"addr":..,"feat":..}`` object per line."""
    for addr, feat in functions.items():
        f.write(json.dumps({"addr": addr, "feat": feat}) + "\n")


def _read_jsonl(path: str) -> dict:
    """Reassemble a ``functions`` map from a ``.functions.jsonl`` shard."""
    functions: dict = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            functions[record["addr"]] = record["feat"]
    return functions


def _load_json_object(path: str) -> dict:
    """Load a JSON object from *path*, raising ``ValueError`` if it is not one."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("index meta must be a JSON object")
    return data


def _quarantine(path: str) -> None:
    """Move a corrupt file aside to ``<path>.corrupt-<epoch_int>`` (best effort)."""
    try:
        os.replace(path, f"{path}.corrupt-{int(time.time())}")
    except OSError:
        pass


def resolve_index_dir(registry_path: str | None = None) -> str:
    """Resolve (and create) the index directory.

    If *registry_path* is given, the index directory is ``<its dir>/index``.
    Otherwise the registry's default resolution is mirrored: the directory of
    ``IDA_MULTI_MCP_REGISTRY_PATH`` if set, else ``~/.ida-mcp``, plus ``/index``.
    The directory (and parents) is created if missing.
    """
    if registry_path is not None:
        base = os.path.dirname(registry_path)
    else:
        override = os.environ.get(REGISTRY_PATH_ENV, "").strip()
        if override:
            base = os.path.dirname(override)
        else:
            base = str(Path.home() / ".ida-mcp")
    index_dir = os.path.join(base, "index")
    os.makedirs(index_dir, exist_ok=True)
    return index_dir


def index_path(sha256: str, registry_path: str | None = None) -> str:
    """Return the meta file path for *sha256* (creates the index dir)."""
    _validate_key(sha256)
    return _meta_path(resolve_index_dir(registry_path), sha256)


def write_index(index: dict, registry_path: str | None = None) -> str:
    """Persist *index* atomically under a per-binary lock; return the meta path.

    The file is keyed by ``index["binary_sha256"]``. When the ``functions`` map
    exceeds :data:`SHARD_THRESHOLD`, it is written to a sibling
    ``<sha256>.functions.jsonl`` shard and the meta file records
    ``"functions_sharded": true``; otherwise the functions are stored inline.
    """
    try:
        sha256 = index["binary_sha256"]
    except (KeyError, TypeError):
        raise ValueError("index dict must contain 'binary_sha256'")
    _validate_key(sha256)

    index_dir = resolve_index_dir(registry_path)
    meta_path = _meta_path(index_dir, sha256)

    functions = index.get("functions", {})
    sharded = isinstance(functions, dict) and len(functions) > SHARD_THRESHOLD

    with FileLock(_lock_path(index_dir, sha256)):
        if sharded:
            meta = {k: v for k, v in index.items() if k != "functions"}
            meta["functions_sharded"] = True
            # Write the shard under a UNIQUE name and reference it from the meta,
            # so the previous shard stays intact until the new meta commits. An
            # interrupted rebuild then leaves old-meta -> old-shard consistent,
            # rather than old-meta merged with a half-written/new shard.
            shard_name = _new_shard_name(sha256)
            meta["functions_shard"] = shard_name
            _atomic_write(
                os.path.join(index_dir, shard_name),
                lambda f: _dump_jsonl(functions, f),
            )
            _atomic_write(meta_path, lambda f: json.dump(meta, f, indent=2))
            _prune_shards(index_dir, sha256, keep=shard_name)  # after commit
        else:
            meta = {k: v for k, v in index.items()
                    if k not in ("functions_sharded", "functions_shard")}
            _atomic_write(meta_path, lambda f: json.dump(meta, f, indent=2))
            _prune_shards(index_dir, sha256, keep=None)  # drop any prior shard(s)
    return meta_path


def read_index(sha256: str, registry_path: str | None = None) -> dict | None:
    """Load the index for *sha256*, or ``None`` if absent or corrupt.

    A corrupt meta (or shard) file is quarantined to ``*.corrupt-<epoch>`` and
    ``None`` is returned. Sharded functions are transparently reassembled.
    """
    _validate_key(sha256)
    index_dir = resolve_index_dir(registry_path)
    meta_path = _meta_path(index_dir, sha256)

    with FileLock(_lock_path(index_dir, sha256)):
        if not os.path.exists(meta_path):
            return None
        try:
            meta = _load_json_object(meta_path)
        except _CORRUPT_ERRORS:
            _quarantine(meta_path)
            return None

        if not meta.get("functions_sharded"):
            return meta

        shard_name = meta.get("functions_shard")
        if shard_name and os.path.basename(shard_name) != shard_name:
            # Meta references a shard outside index_dir: treat as corrupt.
            _quarantine(meta_path)
            return None
        shard_path = (
            os.path.join(index_dir, shard_name) if shard_name
            else _shard_path(index_dir, sha256)  # back-compat: pre-fix fixed name
        )
        try:
            functions = _read_jsonl(shard_path)
        except _CORRUPT_ERRORS:
            _quarantine(meta_path)
            _quarantine(shard_path)
            return None

        index = {k: v for k, v in meta.items()
                 if k not in ("functions_sharded", "functions_shard")}
        index["functions"] = functions
        return index


def has_index(sha256: str, registry_path: str | None = None) -> bool:
    """Return ``True`` if a meta file exists for *sha256*."""
    _validate_key(sha256)
    return os.path.exists(_meta_path(resolve_index_dir(registry_path), sha256))


# --- neural vectors sidecar -------------------------------------------------
# Neural embeddings live in an append-only ``<sha256>.vectors.jsonl`` sidecar,
# separate from the (possibly huge, sharded) meta/functions. Append-only so
# incremental background embedding persists progress cheaply and resumably, and
# so a crash mid-append at worst loses the torn last line (skipped on read).

def _vectors_path(index_dir: str, sha256: str) -> str:
    return os.path.join(index_dir, f"{sha256}.vectors.jsonl")


def append_vectors(sha256: str, vectors: dict, registry_path: str | None = None) -> None:
    """Append ``{addr: vec}`` rows to the vectors sidecar (one JSON object/line)."""
    _validate_key(sha256)
    if not vectors:
        return
    index_dir = resolve_index_dir(registry_path)
    path = _vectors_path(index_dir, sha256)
    with FileLock(_lock_path(index_dir, sha256)):
        with open(path, "a", encoding="utf-8") as f:
            for addr, vec in vectors.items():
                f.write(json.dumps({"addr": addr, "vec": vec}) + "\n")


def read_vectors(sha256: str, registry_path: str | None = None) -> dict:
    """Read the vectors sidecar -> ``{addr: vec}`` (``{}`` if absent).

    Tolerates a torn final line from a crash mid-append (that row is skipped).
    """
    _validate_key(sha256)
    index_dir = resolve_index_dir(registry_path)
    path = _vectors_path(index_dir, sha256)
    out: dict = {}
    if not os.path.exists(path):
        return out
    with FileLock(_lock_path(index_dir, sha256)):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue  # torn last line from an interrupted append
                    out[rec["addr"]] = rec["vec"]
        except OSError:
            return {}
    return out


def clear_vectors(sha256: str, registry_path: str | None = None) -> None:
    """Delete the vectors sidecar (e.g. before a forced re-embed)."""
    _validate_key(sha256)
    index_dir = resolve_index_dir(registry_path)
    with FileLock(_lock_path(index_dir, sha256)):
        try:
            os.remove(_vectors_path(index_dir, sha256))
        except OSError:
            pass


def delete_index(sha256: str, registry_path: str | None = None) -> bool:
    """Remove the meta file and any shard for *sha256*.

    Returns ``True`` if at least one file was removed.
    """
    _validate_key(sha256)
    index_dir = resolve_index_dir(registry_path)
    removed = False
    with FileLock(_lock_path(index_dir, sha256)):
        targets = ([_meta_path(index_dir, sha256), _vectors_path(index_dir, sha256)]
                   + _shard_paths(index_dir, sha256))
        for path in targets:
            try:
                os.remove(path)
                removed = True
            except FileNotFoundError:
                pass
    return removed


def list_indexes(registry_path: str | None = None) -> list[dict]:
    """Summarize every stored index; corrupt/unreadable metas are skipped.

    Each entry is ``{"sha256","binary_name","function_count","built_at","path"}``.
    """
    index_dir = resolve_index_dir(registry_path)
    try:
        names = os.listdir(index_dir)
    except OSError:
        return []

    entries: list[dict] = []
    for name in sorted(names):
        if not name.endswith(".json"):
            continue
        path = os.path.join(index_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            meta = _load_json_object(path)
        except _CORRUPT_ERRORS:
            continue  # Skip corrupt entries; do not quarantine on a scan.
        entries.append(
            {
                "sha256": meta.get("binary_sha256") or name[: -len(".json")],
                "binary_name": meta.get("binary_name"),
                "function_count": meta.get("function_count"),
                "built_at": meta.get("built_at"),
                "path": path,
            }
        )
    return entries
