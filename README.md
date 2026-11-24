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

### Fixed — modal dialogs no longer wedge the server
A modal dialog used to stall **every** MCP call until someone clicked it away, past the
tool timeout. Two cases, handled differently:

- **Raised by a tool** (`warning()`, `ask_yn()`, SDK prompts): IDA's batch mode is set
  and restored on the main thread around the tool's own run, so the prompt is answered
  with its default instead of shown, as in headless IDA. No user dialog can be
  auto-answered: nothing else runs on the main thread meanwhile. Message boxes that
  still appear are auto-dismissed and logged.
- **Opened by you or by IDA** (Jump, Options, ...): IDA defers every request while it is
  open. Calls now fail after a few seconds with *"IDA is blocked by a modal dialog
  'Jump!' ... NOT executed"* instead of hanging, and the abandoned request never runs
  late. Your dialog is never touched automatically.

New tool **`ui_dialogs`** (`list` / `dismiss` / `accept` / `unstick`) works even while IDA
is blocked. Knobs: `IDA_MCP_SUPPRESS_DIALOGS=0` (keep interactive prompts during tools),
`IDA_MCP_DIALOG_POLICY=report` (never auto-dismiss), `IDA_MCP_MODAL_WAIT_SEC` (default 3).

### Fixed — IDA no longer dies when a client gives up
On Linux/macOS, if an MCP client timed out or cancelled while a tool was still running,
the late reply hit a closed socket and `SIGPIPE` killed IDA outright: no save, no log.
The plugin now ignores `SIGPIPE`. The router also stopped printing a cleanup line onto
the stdio JSON-RPC stream after an IDA crash.

### Added — `struct_member_upsert`
Offset-addressed struct editing (fill a hole or `gapNN`, retype a member in place without
shifting neighbours), ported from ida-pro-mcp PR #473 with two guard bugs fixed.

### Fixed — tools that returned wrong answers
Found by calling every tool live with valid and edge-case arguments:

- `insn_query` failed on every call; operand filters now accept `"0x10"` strings.
- `func_query` with an invalid regex returned every function; `find(type=immediate)` searched
  for `0` when given a non-number. Both now report the bad argument.
- `get_bytes` returned `0xff` filler for unmapped addresses and `patch`/`put_int` reported
  success there; both now say the address is not mapped.
- `export_funcs(format=c_header)` declarations now include the function name.
- `declare_stack` accepts negative (frame-pointer relative) offsets, so locals can be declared.
- Unknown options (`xref_query` direction, `export_funcs` format) are rejected instead of
  silently returning nothing.
- Tool `outputSchema`s no longer declare `Any`-typed values objects, which made schema-validating
  clients reject valid results (`analyze_function`, `ui_dialogs`).

### Upstream
The fork tracks [MeroZemory/ida-multi-mcp](https://github.com/MeroZemory/ida-multi-mcp) `main`.
Sigmaker and `struct_member_upsert` are fork-only, and upstream already has its own GUI-safe
`idb_save`. Everything else above is proposed upstream as
[#46](https://github.com/MeroZemory/ida-multi-mcp/pull/46)–[#52](https://github.com/MeroZemory/ida-multi-mcp/pull/52).

Verified live on IDA 9.5 (GUI and headless idalib).

## Quick start

Install into the **same Python IDA uses**, then (re)start IDA:

```bash
git clone https://github.com/bromoket/ida-multi-mcp
cd ida-multi-mcp
python -m pip install --force-reinstall --no-deps .
# Python without pip (e.g. Arch's python3.13): uv into the user site instead
uv pip install --python python3.13 --prefix ~/.local --break-system-packages --no-deps --reinstall .
ida-multi-mcp --verify   # checks the installed IDA plugin loader matches the package
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
