# 01 — v1 Production Design (implementation-ready)

Last updated: 2026-07-07
Status: Draft — ready for implementation

This is the build spec for the **zero-dependency v1 similarity feature**. It is written so an implementer can execute it without further design decisions. Every parameter has a default; every integration point cites the exact file.

## 1. Scope & Principles
- **Zero runtime dependencies.** Standard library only: `hashlib`, `json`, `math`, `statistics`, `threading`, `os`, `time`. `pyproject.toml: dependencies = []` stays intact. No numpy.
- **Reuse existing extraction.** Do not re-implement disassembly/CFG/strings/constants; call the primitives in §6.1.
- **IDA-side computes per-function features; server-side owns the index and search.** Per-function features are self-contained (no binary-wide stats) so they can be produced page-by-page; binary-wide statistics (document frequencies, z-norm, LSH buckets) are computed by the server indexer.
- **Two-stage retrieval.** Cheap candidate generation (LSH + anchor inverted index) → weighted scoring/rerank over candidates. This *is* the rerank stage a future neural recall (Track C) plugs into (§9).
- **Explainable.** Every result returns a per-signal score breakdown and a confidence label.

## 2. Architecture
```
similar_functions / compare_functions / index_functions / index_status   (server tools)
        │                                   ▲
        ▼                                   │ router.route_request("tools/call", {name:"func_features"...})
  tools/similarity.py  ── reads/writes ──►  ~/.ida-mcp/index/<binary_sha256>.json
        │                                   │
        └───────────────── HTTP JSON-RPC ───┘
                                            ▼
                              ida_mcp/api_similarity.py  (func_features, binary_fingerprint)
                              reuses _analyze_function_internal / basic_blocks / extract_* / callees
```

## 3. Signals (all name-independent; survive stripping)
| Signal | Source primitive | Normalization |
|---|---|---|
| `ngram` — instruction-shingle MinHash | decode insns via `idautils.FuncItems` | mnemonic + operand-type classes, 4-gram shingles, 64-perm MinHash (§5.1) |
| `api` — external callee / import set | `callees` (external) + `imports_query` | canonical import name; weighted by IDF (§5.3) |
| `str` — referenced string set | `extract_function_strings` | raw bytes → utf-8(replace); IDF-weighted |
| `const` — immediate constant set | `extract_function_constants` | drop trivial (0, 1, -1, small stack offsets); IDF-weighted |
| `cfg` — structural feature vector | `basic_blocks` (succ/pred edges) + `func_profile` | z-normalized per binary (§5.4) |
| `text` — pseudocode identifier tokens | `_analyze_function_internal.decompiled` | **only extracted when `is_named`**; symbol-gated (§5.5) |

`is_named` = the function has a meaningful symbol (name does **not** match `^(sub|loc|nullsub|unknown|j_|__imp_|off_|unk)_` and is not empty). Gate for the `text` signal.

## 4. Data Schemas

### 4.1 FunctionFeature (produced IDA-side by `func_features`)
```jsonc
{
  "addr": "0x140001000",
  "name": "sub_140001000",
  "is_named": false,
  "size": 213,
  "cfg": {                       // from basic_blocks + func_profile
    "bb_count": 7, "edge_count": 9, "complexity": 4,
    "loops": 1,                  // back-edge count (succ.start <= block.start)
    "callee_count": 3, "caller_count": 2,
    "out_deg_seq": [2,2,1,1,1,0,0]   // sorted desc; for optional shape blocking
  },
  "minhash": [12, 883, 41, ...], // 64 uint32 (§5.1); [] if < shingle_min insns
  "apis": ["CreateFileW", "WriteFile"],   // external callees + imports
  "strings": ["%s.enc", "Locked"],
  "consts": ["0xedb88320", "0x1000"],
  "pseudo_tokens": ["decrypt","key","ctx"]  // present only when is_named
}
```

### 4.2 Index file `~/.ida-mcp/index/<binary_sha256>.json`
```jsonc
{
  "schema_version": 1,
  "binary_sha256": "…", "binary_name": "malware.exe", "arch": "x86_64",
  "built_at": "2026-07-07T…Z", "function_count": 152341,
  "params": { "M":64, "k":4, "bands":16, "rows":4 },     // provenance for compatibility checks
  "df": { "apis": {"CreateFileW": 812, …}, "strings": {…}, "consts": {…} },  // document freq for IDF
  "zstats": { "bb_count": {"mean":…, "std":…}, … },       // per-cfg-feature mean/std for z-norm
  "functions": { "0x140001000": { …FunctionFeature… }, … },
  "lsh": { "0": {"a1b2c3d4": ["0x1000","0x2400"], …}, … } // band_index -> bucket_hash -> [addrs]
}
```
Large binaries: the `functions` map may be sharded to `<sha256>.functions.jsonl` with `<sha256>.json` holding meta+df+zstats+lsh; the loader supports both. Access is guarded by the same `FileLock` used by the registry.

## 5. Algorithms (stdlib pseudocode)

### 5.1 Instruction-shingle MinHash (IDA-side)
```python
K = 4; M = 64
# Fixed, stored (a_j, b_j) constants seeded once so signatures compare across binaries.
A, B, P = _SEEDED_A, _SEEDED_B, (1<<61)-1     # module constants, len 64
def token(insn):                              # normalization
    m = insn.get_canon_mnem()                 # e.g. "mov"
    cls = "".join(op_class(op) for op in insn.ops if op.type != o_void)  # r/i/m/c
    return f"{m}.{cls}"
seq = [token(decode(ea)) for ea in FuncItems(f)]
shingles = { hash64("|".join(seq[i:i+K])) for i in range(len(seq)-K+1) }  # blake2b 8-byte
if len(shingles) == 0: return []              # too small; ngram signal unavailable
sig = [min(((A[j]*s + B[j]) % P) for s in shingles) for j in range(M)]
```
`jaccard_ngram(x,y) = mean(1 for j if x.minhash[j]==y.minhash[j]) / M`, `0.0` if either sig is empty.

### 5.2 LSH blocking (server-side, built at index time)
```python
BANDS=16; ROWS=4                              # BANDS*ROWS == M
for band in range(BANDS):
    key = hash64(tuple(sig[band*ROWS:(band+1)*ROWS]))
    lsh[band][key].append(addr)
# candidates(query) = { a for band in BANDS for a in lsh[band][key(query,band)] }
```
Threshold ≈ s where `1-(1-s^ROWS)^BANDS = 0.5` → ~0.55 with (16,4); tune via `params`.

### 5.3 IDF-weighted Jaccard for anchors
```python
def widf_jaccard(sa, sb, df, N):
    inter = sa & sb; union = sa | sb
    if not union: return 0.0
    w = lambda x: math.log(N/(1+df.get(x,0)))          # rare anchors weigh more
    return sum(w(x) for x in inter) / sum(w(x) for x in union)
```
Anchor inverted index (blocking): `anchor_index[type][anchor] -> [addrs]`; candidates include functions sharing any anchor with `df <= rare_df` (default `rare_df = max(2, 0.01*N)`).

### 5.4 CFG similarity
```python
FEATS = ["bb_count","edge_count","complexity","loops","size","callee_count","caller_count"]
def z(v, f): s=zstats[f]; return 0.0 if s["std"]==0 else (v-s["mean"])/s["std"]
def cfg_sim(a,b):
    d = sum(abs(z(a[f],f)-z(b[f],f)) for f in FEATS) / len(FEATS)
    return math.exp(-d)                                # bounded (0,1], 1.0 == identical profile
```

### 5.5 Final score, symbol-gating, confidence
```python
W = {"ngram":.30,"api":.25,"cfg":.20,"str":.15,"const":.10,"text":.15}  # env/param override
def score(a,b):
    s = {"ngram":jaccard_ngram(a,b), "api":widf_jaccard(a.apis,b.apis,df.apis,N),
         "str":widf_jaccard(a.strings,b.strings,df.str,N),
         "const":widf_jaccard(a.consts,b.consts,df.const,N), "cfg":cfg_sim(a,b)}
    active = dict(W)
    if a.is_named and b.is_named: s["text"] = jaccard(a.pseudo_tokens, b.pseudo_tokens)
    else: active.pop("text")                           # renormalize when gated off
    final = sum(active[k]*s[k] for k in active) / sum(active.values())
    return final, s
# confidence: "high" if final>=.75 and >=2 signals>.5; "medium" if final>=.5; else "low"
```

### 5.6 Search
```python
def similar(query_feat, gallery_index, top_k, min_score):
    cand = lsh_candidates(query_feat) | anchor_candidates(query_feat)
    cand.discard(query_feat.addr)
    if len(cand) > CAND_CAP(=2000): cand = top_by_blocking_hits(cand, CAND_CAP)
    scored = [(score(query_feat, gallery_index[a])) for a in cand]
    return sorted(scored, key=final, desc)[:top_k]  # filter final>=min_score
```

## 6. MCP Tool Contracts

### 6.1 IDA-side (new `ida_mcp/api_similarity.py`) — proxied through the router
```
func_features(addrs='*', offset=0, count=500) -> { "functions":[FunctionFeature...],
    "total": int, "cursor": {"next":int}|{"done":true} }
    # @tool @idasync @tool_timeout(180). Reuses FuncItems/basic_blocks/extract_*/callees.
    # Computes minhash + is_named + cfg + anchors per function. pseudo_tokens only if is_named.
binary_fingerprint() -> { "sha256": str|None, "md5": str|None, "function_count": int, "arch": str }
    # @tool @idasync. Wraps ida_nalt.retrieve_input_file_sha256()/_md5() (hex). See §8 fallback.
```
Register in `ida_tool_schemas.json` (static visibility) and the module import list so they federate.

### 6.2 Server-side (new `tools/similarity.py`) — local, not proxied
```
index_functions(instance_id, rebuild=False, background=True)
  -> { "index_id": sha256, "function_count": int, "status": "building"|"ready"|"error",
       "elapsed_s": float, "pages": int }
index_status(instance_id)
  -> { "indexed": bool, "index_id": sha256|None, "function_count": int,
       "built_at": iso|None, "path": str|None, "stale": bool, "progress": 0..1|null }
similar_functions(instance_id, func, top_k=20, scope="binary", instances=[],
                  min_score=0.0, weights={}, include_self=false)
  -> { "query": {"instance_id","addr","name"}, "gallery_size": int,
       "results": [ {"instance_id","addr","name","score",
                     "signals":{"ngram","api","str","const","cfg","text"?},
                     "confidence":"high"|"medium"|"low"} ... ] }
compare_functions(a={instance_id,func}, b={instance_id,func}, weights={})
  -> { "score": float, "signals": {...}, "confidence": str,
       "a":{"addr","name"}, "b":{"addr","name"} }
```
`scope`: `"binary"` (query's own index), `"instances"` (union of `instances`), `"all"` (every registered instance holding an index). Cross-instance results are tagged with their `instance_id`. `func` accepts an address or a name (resolved via the target instance). Auto-index-on-miss: if the query's binary has no index, `similar_functions` computes just the query's features live and errors with a hint to run `index_functions` for the gallery (do **not** silently full-scan — respects the 15s-timeout lesson).

## 7. Storage & Incremental Indexing
- Location: `<registry_base>/index/<binary_sha256>.json` where `registry_base` follows the registry's path resolution (`IDA_MULTI_MCP_REGISTRY_PATH` dir or `~/.ida-mcp/`). One `index_store.py` module owns locate/read/write with the existing `FileLock`.
- Keying by **content sha256** means the same binary reused across GUI and idalib instances shares one index.
- v1 indexing is **full rebuild on request** (`index_functions`). Incremental update is a documented enhancement: store a per-function `feat_hash`; on re-index, diff the live `{name|addr→feat_hash}` against the stored map and recompute only changed functions. Ship full-rebuild first; incremental behind the same tool with `rebuild=False` semantics.
- Corrupt/again-partial index → treat like the registry contract: quarantine `*.corrupt-<ts>` and rebuild.

## 8. Background Job, Main-Thread, Cancel/Progress
- The indexer pulls `func_features` **page by page** via `router.route_request`. Each page is one HTTP call → IDA processes it under `@idasync` on its main thread and returns, so the IDA UI is not frozen for the whole binary (only per-page).
- `background=True` runs the page loop in a server-side `threading.Thread`; `index_status.progress` = pages_done / pages_total; a per-index cancel flag is checked between pages. This satisfies AP-P2-03 (cap/progress/cancel) for the similarity path.
- Page size default 500 functions; `IDA_MCP_SIM_PAGE`. A hard cap and a "this binary has N functions, ETA…" note are returned on the first `index_functions` call.

## 9. Neural Seam (Track C — do not implement in v1, but do not preclude)
Design the recall stage behind one interface so a neural backend slots in with **no tool or storage rework**:
```python
class EmbeddingBackend(Protocol):
    name: str; dim: int
    def embed_batch(self, feats: list[FunctionFeature]) -> list[list[float]]: ...
```
- Index gains optional `"vectors": {addr:[float,…]}` and `"backend": name`. Absent in v1.
- When a backend is configured: candidate generation adds cosine top-K over `vectors` (brute-force is fine at single-binary scale; swap in `hnswlib` behind the same call if needed) unioned with LSH/anchor candidates; §5.5 scoring becomes the **reranker**. `similar_functions` gains an optional `backend=` arg; default keeps v1 behavior.
- Neural extraction consumes the **same IDA-extracted** features/normalized asm returned by `func_features` (fixes review finding T1-2: evaluate/serve neural models on the production extractor, not an IDA-free one).

## 10. Module / File Breakdown & Exact Integration Points
| File | New/Edit | Change |
|---|---|---|
| `ida_mcp/api_similarity.py` | **new** | `func_features`, `binary_fingerprint` (`@tool @idasync @tool_timeout`). MinHash/normalization helpers. |
| `ida_mcp/__init__.py` | edit | import `api_similarity` so its `@tool`s register (mirror how other `api_*` modules are wired). |
| `ida_tool_schemas.json` | edit | add static schemas for `func_features`, `binary_fingerprint`. |
| `tools/similarity.py` | **new** | server-side `index_functions/index_status/similar_functions/compare_functions`; module-level `set_registry/set_router`; scoring (§5); candidate gen. |
| `tools/index_store.py` | **new** | locate/read/write index files under `<registry_base>/index/`, `FileLock`-guarded; corrupt-quarantine. |
| `server.py` | edit | (a) `from .tools import similarity`; (b) in `_setup` (~L119) `similarity.set_registry(self.registry); similarity.set_router(self.router)`; (c) in `custom_tools_call` (~L217, beside `compare_binaries`) add the 4-tool dispatch branch returning `structuredContent`; (d) in the tool-cache builder (~L574) add `_tool_cache` schema entries for the 4 server tools. |
| `pyproject.toml` | none | v1 adds no dependency. |

## 11. Config Defaults (`tools/similarity.py` module constants, `IDA_MCP_SIM_*` env overrides)
```
M=64  K=4  BANDS=16  ROWS=4  CAND_CAP=2000  PAGE=500
WEIGHTS = ngram .30 / api .25 / cfg .20 / str .15 / const .10 / text .15
rare_df = max(2, 0.01 * N)   trivial_consts = {0,1,-1, and |v|<0x10 stack-ish}
confidence: high >=.75 & >=2 signals>.5 ; medium >=.5 ; else low
```

## 12. Edge Cases & Error Handling
- **Tiny/thunk functions** (`minhash==[]`, bb_count<=1): still indexable; `ngram` signal 0; matched mainly by anchors/cfg. `include_self=false` and optional thunk exclusion in gallery.
- **No anchors** (leaf math): rely on `ngram`+`cfg`; expected lower confidence — reflected in the label, not hidden.
- **Stale index** (`binary_fingerprint.sha256` ≠ index key): `index_status.stale=true`; `similar_functions` returns a `warning` and suggests `index_functions(rebuild=True)`.
- **Cross-arch** union: if instances' `arch` differ, tag results with a `cross_arch` warning (scores unreliable) but do not block.
- **sha256 unavailable** (`retrieve_input_file_sha256` returns empty on some inputs): fall back to md5; if both empty, key by `sha256(normalized_input_path + size)` and mark `key_fallback=true` in the index meta.
- **Instance errors mid-index**: `route_request` error on a page → mark index `status:"error"`, keep partial off disk (atomic write only on success), surface in `index_status`.
