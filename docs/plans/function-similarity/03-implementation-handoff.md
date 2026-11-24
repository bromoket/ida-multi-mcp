# 03 — Implementation Handoff (for the implementing session)

Last updated: 2026-07-07
Status: Draft — ready to execute

Audience: the implementing (Sonnet) session. Read `README.md` → `01-v1-production-design.md` → `02-evaluation-design.md` first. This doc slices the design into small work packages (WP) with acceptance criteria and a test plan. It does **not** contain the code; it tells you exactly what to build, in what order, and how to know each piece is done.

## Ground Rules
1. **Zero runtime dependencies.** stdlib only. Do not add anything to `pyproject.toml`. If you reach for numpy, stop — the math in `01` §5 is deliberately stdlib.
2. **Reuse, don't reimplement.** Extraction goes through `_analyze_function_internal`, `basic_blocks`, `extract_function_strings`, `extract_function_constants`, `callees`, `imports_query`. Mirror existing tool patterns: `@tool @idasync @tool_timeout` for IDA-side (see `func_profile`), and the `compare_binaries` server-side pattern (`tools/management.py`).
3. **Never full-scan under one call.** The reference test binary has ~150K functions and 15s-class tools time out (project memory). `func_features(addrs='*')` MUST paginate; `index_functions` MUST page + background (`01` §8). No single blocking pass over all functions.
4. **Live changes require a reload.** IDA plugin / MCP-server edits only take effect after reload/restart (project memory). Plan integration tests accordingly; a running instance runs the pre-change build.
5. **Do NOT implement the neural backend (Track C).** Only leave the `EmbeddingBackend` seam (`01` §9). No torch/onnx in v1.
6. **TDD the pure math.** The scoring/minhash/lsh/cfg logic (`01` §5) is pure and stdlib → write tests first (`tests/`, pytest), no IDA needed. Target ≥80% on these modules.

## Work Packages

### WP0 — Scaffolding & storage  *(no IDA)*
- `tools/index_store.py`: locate/read/write `<registry_base>/index/<sha256>.json`, `FileLock`-guarded (reuse `filelock.py`), atomic write, corrupt-quarantine (`*.corrupt-<ts>` → rebuild), sharded `functions.jsonl` support.
- `tools/similarity.py` skeleton: module constants (`01` §11), `set_registry`/`set_router`, empty tool fns.
- Helper: content-hash. Add IDA-side `binary_fingerprint` later (WP1); `index_store` just consumes the sha256 string.
- **Acceptance:** round-trip write/read of a synthetic index dict; corrupt file is quarantined and a fresh default returned; concurrent writers serialized (reuse the registry's lock test style).

### WP1 — IDA-side extraction  *(needs live IDA to verify)*
- `ida_mcp/api_similarity.py`:
  - `func_features(addrs='*', offset, count=500)` → paginated `FunctionFeature[]` (`01` §4.1). Compute: `is_named`, `size`, `cfg` (from `basic_blocks` succ/pred + `func_profile` fields), `minhash` (`01` §5.1), `apis` (external `callees` + `imports_query`), `strings`, `consts` (drop trivial), `pseudo_tokens` **only if `is_named`**.
  - `binary_fingerprint()` → `{sha256, md5, function_count, arch}` wrapping `ida_nalt.retrieve_input_file_sha256()`/`_md5()` (hex); §12 fallback.
- Wire module import so `@tool`s register; add both to `ida_tool_schemas.json`.
- **Acceptance (live):** `func_features(addr_of_known_func)` returns a well-formed record; `minhash` length 64 for a non-trivial function and `[]` for a thunk; `binary_fingerprint().sha256` is stable across two calls; pagination cursor advances and terminates.

### WP2 — Indexer  *(server-side; needs live IDA for end-to-end)*
- `tools/similarity.py`: `index_functions(instance_id, rebuild, background)` pulls `func_features` pages via `router.route_request`, accumulates, then computes binary-wide `df` (IDF), `zstats` (cfg z-norm), and `lsh` buckets (`01` §5.2), writes via `index_store`. `index_status` reports progress/stale.
- Background thread + per-index cancel flag + progress fraction (`01` §8).
- **Acceptance (live):** indexing a small real binary produces an index whose `function_count` matches `list_funcs`; `index_status.progress` monotonically reaches 1.0; a second `index_functions(rebuild=False)` is a no-op/fast; stale detection flips when the binary sha changes.

### WP3 — Scoring & search  *(pure core + server glue)*
- Pure module (`tools/sim_score.py`, no IDA): `jaccard_ngram`, `widf_jaccard`, `cfg_sim`, `score` (with symbol-gating + renormalization), `confidence`, LSH bucket key, candidate union + cap (`01` §5).
- `similar_functions` / `compare_functions` in `tools/similarity.py`: load index(es) per `scope`, generate candidates, score, sort, attach breakdown + confidence; cross-instance tags `instance_id`; auto-index-miss returns a hint (no silent full-scan).
- **Acceptance:** see Test Plan WP3 (unit) + a live smoke (`similar_functions` on a function finds its known duplicate/sibling with a sane breakdown).

### WP4 — Server wiring  *(no new logic)*
- `server.py`: import `similarity`; `set_registry`/`set_router` in `_setup` (~L119); dispatch branch for the 4 tools in `custom_tools_call` (~L217, beside `compare_binaries`); `_tool_cache` schema entries (~L574). Confirm `tools/list` shows them and `structuredContent` is returned.
- **Acceptance (live, after reload):** `refresh_tools` then `tools/list` shows the 4 server tools + 2 IDA tools; each returns structured output; a large `similar_functions` result is preview+cached automatically (existing `_schema_preserving_preview`).

### WP5 — Unit tests (TDD, run first where possible)  *(no IDA)*
Author these RED before the WP3 pure code. See Test Plan.

### WP6 — Live integration  *(needs a Pro/GUI IDA instance)*
End-to-end on a real binary: `index_functions` → `similar_functions` → sane top-k; cross-instance search across two instances of related binaries. Document the reload step.

### WP7 — Evaluation track (separable; do after v1 smoke)
Implement `bench/similarity/` per `02` §5: `build_static_lib.py`, revised `corpus/` + `build_corpus.py`, `harness/{mcp_client,run_eval,metrics,report}.py`. Produce the objective report and set the frozen gate thresholds (`02` §4). This validates v1 and is the gate for any Track-C work.

## Test Plan
**Pure/unit (pytest, no IDA — the bulk of coverage):**
- `jaccard_ngram`: identical minhash → 1.0; disjoint → ~0.0 (tolerance for 64 perms); empty sig → 0.0.
- `widf_jaccard`: a shared **rare** anchor scores higher than a shared **common** anchor; empty union → 0.0; identical sets → 1.0.
- `cfg_sim`: identical feature vectors → 1.0; strictly decreasing as one feature diverges; std==0 handled.
- `lsh`: two signatures agreeing on ≥1 full band are candidates; fully-disjoint are (almost surely) not; band math covers M==BANDS*ROWS.
- `score` + gating: `text` present only when both `is_named`; weights renormalize to a proper weighted mean when `text` gated off; breakdown dict returned; `confidence` thresholds (`01` §11).
- candidate cap: `> CAND_CAP` candidates are trimmed by blocking-hit count deterministically.
- `index_store`: write/read round-trip; corrupt quarantine; lock serialization.

**Live/integration (needs IDA, after reload):** WP1/WP2/WP4/WP6 acceptance items above. Keep these separate from the pure suite (they can't run in CI without IDA).

**Global-state caution:** if any test redirects process-global state, disable xUnit-style parallelism for that module (mirror the registry tests). Pure sim-math tests are isolated and parallel-safe.

## Sequencing / Critical Path
```
WP0 ─┬─ WP1 ─ WP2 ─┐
     │             ├─ WP4 ─ WP6 ─ WP7
WP5(pure) ─ WP3 ───┘
```
- Start WP5+WP3 (pure, TDD) and WP0 in parallel — no IDA needed, fastest feedback.
- WP1/WP2 need a live instance; do after WP0.
- WP4 wires everything; WP6 is the live end-to-end; WP7 (eval) validates and gates Track C.

## Risks & Mitigations
- **150K-function indexing latency** → paging + background + progress/cancel (`01` §8); `func_features` excludes `decompile` for unnamed functions (pseudo_tokens only when `is_named`), keeping per-function cost to disasm/CFG/anchor level.
- **Main-thread freeze** → one page per `@idasync` call; never one call over all functions.
- **ICF / inlining corrupting eval ground truth** → detected & labeled in `build_static_lib.py` (`02` §1.1), not silently trusted.
- **`retrieve_input_file_sha256` empty** → md5 → path+size fallback with `key_fallback=true` (`01` §12).
- **Stale index after binary change** → sha mismatch → `index_status.stale`, warn in `similar_functions`.

## Definition of Done (v1)
- The 6 tools exist, federate, and return structured output after reload.
- Pure suite ≥80% on `sim_score.py` + `index_store.py`; all green.
- Live smoke: index a real binary, `similar_functions` returns a correct known sibling in top-3 with a coherent breakdown; cross-instance search works across two instances.
- `pyproject.toml` unchanged (still zero-dep).
- WP7 report produced and gate thresholds frozen (may follow v1 ship as a fast follow).
