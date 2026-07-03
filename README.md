# ida-multi-mcp (bromoket fork)

Multi-instance [IDA Pro](https://hex-rays.com/ida-pro) MCP server — drive several IDA
instances (GUI or headless idalib) through a single MCP endpoint, so your LLM client
can decompile, cross-reference, rename, and **now generate signatures** across many
binaries at once.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.x%20fixed-orange.svg)
![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)

## Lineage

This fork stands on two projects:

- **[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)** — the original
  single-instance IDA Pro MCP server, and the source of the sigmaker engine.
- **[MeroZemory/ida-multi-mcp](https://github.com/MeroZemory/ida-multi-mcp)** — the
  multi-instance fork (router / registry / instance routing / idalib lifecycle) this
  repo is based on.
- The signature engine is vendored from
  **[mahmoudimus/ida-sigmaker](https://github.com/mahmoudimus/ida-sigmaker)** (via
  ida-pro-mcp); it emits the same four formats as the canonical
  [A200K/IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker).

## What this fork changes

### Fixed — pattern/string search on IDA 9.x
`find_bytes` and `find(type=string|immediate)` silently returned **0 matches** on
IDA 9.x for content that provably exists (a hard blocker on packer-dumped IDBs).
Root cause, confirmed empirically on IDA 9.3 — `ida_bytes.bin_search` drift:

1. the `compiled_binpat_vec_t` overload now returns a tuple `(ea, index)` instead of a
   scalar — old code did `hex(ea)` on the tuple, raising `TypeError` that a bare
   `except` swallowed into `n=0`;
2. the raw `bytes+mask` overload — still in the docstring — raises `TypeError` from the
   SWIG layer on 9.3, killing the string/immediate paths.

Searches now route through a small `compat` shim (`ida_bytes.find_bytes` on 9.0+, legacy
`bin_search` with tuple-unwrapping on 8.x). *(The popular "`parse_binpat_str` changed its
return" theory was tested and disproven — it returns `''`/falsy on success.)*

### Added — signature generation (sigmaker)
Four tools, forward-ported and adapted to the multi-instance layer:

| Tool | Purpose |
|------|---------|
| `make_signature` | shortest **unique** signature at an address/name |
| `make_signature_for_function` | resolve to function start, then signature it |
| `make_signature_for_range` | signature a byte range (e.g. a selection) |
| `find_xref_signatures` | unique signatures at each code xref to an address |

Output formats: **`ida`**, **`x64dbg`**, **`mask`** (bytes + `xxx?`), **`bitmask`**
(bytes + `0b…`). Uniqueness is **verified, non-optional** for the single/range makers.

### Fixed — GUI-safe `idb_save`
Cherry-picked [ida-pro-mcp#446](https://github.com/mrexodia/ida-pro-mcp/issues/446):
in the GUI, saving no longer `DBFL_KILL`s the live loose working files (which corrupts
the DB on reopen); only headless idalib packs into a single compressed file.

Everything above was verified against a live IDA 9.3 instance; the router / registry /
instance-routing / idalib layer is untouched.

## Quick start

Install into the **same Python IDA uses**, then (re)start IDA:

```bash
git clone https://github.com/bromoket/ida-multi-mcp
cd ida-multi-mcp
python -m pip install --force-reinstall --no-deps .
```

Full install/registration steps (IDA plugin placement, MCP client config) live in
[docs/installation.md](docs/installation.md). Once installed, open your binaries in IDA
(instances auto-register) and ask your LLM, e.g.:

> *"Make a unique x64dbg signature for `GetItemDataPointer` in sirius (btqu), then find
> its xrefs."*

This is a **100% Python** package — it runs inside IDA's embedded CPython (or via the
`idapro` idalib package). There is no native component to compile.

## License

MIT, inheriting the licenses of all upstream projects credited above.
