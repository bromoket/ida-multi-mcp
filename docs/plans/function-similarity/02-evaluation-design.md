# 02 — Evaluation Design (oracle + microscope)

Last updated: 2026-07-07
Status: Draft — ready for implementation

Two instruments with different jobs:
- **Oracle** (real binaries, IDA-extracted, production scale) → decides what ships and whether a neural upgrade is justified. This is the authority.
- **Microscope** (revised synthetic corpus) → explains *why* a method fails on a controlled confound. Diagnostic only; never the ship gate.

**Foundational choice (fixes review finding T1-2): the harness drives the shipped MCP tools.** All feature extraction and ranking go through the real `index_functions` / `similar_functions` / `compare_functions` against a real IDA instance. The evaluation therefore measures the production extractor and the production scorer end-to-end — not a parallel reimplementation. A future neural backend plugs into the same tools and is evaluated by the same harness unchanged.

---

## 1. The Oracle (Track B-1)

### 1.1 Method 1 — same static library in two host programs (primary ship gate)
Real code, real scale, real strip condition, free symbol-verified ground truth.

1. Build a mid-size C library `libL.a` (candidate: a self-contained real library such as `miniz`/`mbedtls-subset`, or our corpus compiled as a static lib). Build **with symbols**.
2. Build two *different* host programs `progA`, `progB` that each statically link `libL.a` and exercise different entry points (so the linker pulls in overlapping-but-not-identical subsets, with per-program inlining/DCE). Build with symbols.
3. Capture ground truth **before stripping**: for each host, `name → address` from the symbol table (pyelftools for ELF / `dumpbin`/map for PE).
   - **Inlining:** a library function absent as a discrete symbol in a host is dropped from that host's set (can't match what isn't there).
   - **ICF/folding:** if two names share one address, record the fold cluster; either exclude or treat the cluster as a known positive group. Never silently mislabel.
   - Positive set = names present as *discrete, non-folded* functions in **both** hosts.
4. Strip `progA` (query side) — or evaluate both stripped; keep the captured maps.
5. Open `progA`, `progB` in IDA; `index_functions` on both; for each positive `L::foo`, call `similar_functions(instance=progA_at_foo, scope="instances", instances=[progB])` and record the **rank of `progB::foo`** in the results. Gallery = *all* functions of `progB` (production scale).
6. Variation axes: build progA/progB with {gcc,clang} × {-O0,-O2,-O3}; same-vs-cross toolchain/opt are reported as slices.

### 1.2 Method 2 — whole-program recompile of the microscope corpus (controlled, fixes leaf-isolation)
The revised corpus (§3) is compiled as a **whole program** with a driver `main` that calls every function (so inlining actually happens — the leaf-isolation flaw is removed). Build across gcc/clang × -O0..-O3 × strip. Ground truth = symbol name before strip. Query `F@configX` vs gallery `all functions@configY`. Reports gallery size honestly; used for cross-opt/compiler diagnosis, not as the primary gate.

### 1.3 Method 3 — symbolized-vs-stripped twin / patch-diff (secondary, optional)
Compile an OSS lib with symbols vs match against a stripped distro build; or two adjacent versions (v1.0 vs v1.1) mapped by name for patch-diff realism. Adds external validity; optional.

### 1.4 Extraction environment
Extraction runs against **any registered IDA instance** via the MCP tools. The dev host has IDA Home (no idalib) → run against a GUI instance with the plugin, or against a Pro/idalib host for batch. The harness is an MCP client; it does not require idalib itself. This is a deliberate constraint acceptance: the oracle needs *an* IDA, matching what users actually run.

## 2. Metrics & Protocol
- **Retrieval:** Recall@1, Recall@{5,10}, MRR (per query = rank of the true twin).
- **Threshold/precision:** feed labeled positive & hard-negative pairs to `compare_functions` → PR-AUC, and the operating threshold that yields a target precision.
- **Always report gallery size** with every metric; Method 1 is evaluated at full-binary gallery (never a toy subset — fixes T1-1). A metric at N=200 and N=150K are reported separately and never conflated.
- **Slices:** function-size bucket (`<50` / `50–300` / `>300` insns), opt-gap (`O0↔O2`, `O2↔O3`), compiler-pair (`gcc↔gcc`, `gcc↔clang`), and `is_named` (symbol vs stripped → the headline ΔRecall@1).
- **Statistics (fixes T2-2):** bootstrap 95% CI over the query set for every headline metric; method-vs-method comparison is **paired** (same queries) via bootstrap difference CI or McNemar on Recall@1 hits. "A beats B" requires a significant, non-overlapping gap — a raw 0.82 vs 0.85 is reported as "not distinguishable at N=…".
- **Baselines for sanity:** a shuffled-label floor and an `ngram`-only / `anchor`-only ablation, so each signal's contribution is measured (not assumed).

## 3. The Microscope (Track B-2) — revised synthetic corpus
Fixes the flaws the adversarial review verified.

- **Separate three tasks into three labeled sets** (do not lump into one "positive"):
  - `T-recompile`: same source across opt/compiler (the achievable, common case).
  - `T-refactor`: hand-authored equivalents — but each pair's label is the **measured post-compile relationship** (disasm-diff → Type-1 identical / Type-2 renamed / Type-3 near-miss), computed by the build step, not asserted by source intent. (Recall the seed evidence: `sum_array`≡`sum_array_while` at gcc -O2 → correctly labeled Type-1, not "refactor".)
  - `T-semantic`: same identity, different algorithm (e.g. `crc32_bitwise` vs `crc32_lut`) — the hardest, reported on its own; not counted in the headline.
- **Whole-program with callers** (driver `main`) so inlining occurs; `-O0..-O3`.
- **Size up:** add medium/large functions (a tiny bytecode interpreter, a recursive-descent parser, a state machine) so methods are actually differentiated (the 12–49-insn seed was too small — verified).
- **Per-confound diagnostics:** keep the signal-targeted hard-negatives (`xor_array` for structure, `parse_csv` for API, `adler32` for constant). The microscope's output is "method M false-matches confound C at rate r," feeding back into weight tuning — *not* an aggregate leaderboard.

## 4. Acceptance Gates (numeric)
Calibrate the exact thresholds on the **first** Method-1 oracle run, then freeze them as a regression gate. Proposed starting bars:
- **v1 ships** if, on Method 1 (real lib, stripped, full-binary gallery):
  - same-toolchain / same-opt: Recall@1 ≥ 0.60 and Recall@10 ≥ 0.85, lower-CI clearly above the shuffled floor; and
  - cross-opt (O0↔O2): Recall@10 ≥ 0.40.
  (If real numbers land lower, that is a finding — v1 still ships as the transparent baseline, but the bar for "useful" is set from data, and the tool's confidence labels are calibrated to it.)
- **Neural (Track C) is justified** only if it beats v1 on the *same* oracle by ≥ +10 pp Recall@1 on the cross-opt slice, significant under the paired test — enough to warrant the ONNX-runtime + model-file dependency and the air-gap/forensic cost. Otherwise v1 stays as the shipped feature.

## 5. Harness Module Breakdown (`bench/similarity/`, NOT part of the pip package)
| File | Role |
|---|---|
| `oracle/build_static_lib.py` | build `libL.a` + `progA`/`progB` across {gcc,clang}×{O0,O2,O3}×strip; emit ground-truth manifest with inlined/folded flags (pyelftools ELF; dumpbin/map PE). |
| `corpus/` + `oracle/build_corpus.py` | revised microscope corpus; whole-program build; post-compile relationship labeling via objdump disasm-diff. |
| `harness/mcp_client.py` | minimal MCP stdio client to call `index_functions`/`similar_functions`/`compare_functions` on registered instances. |
| `harness/run_eval.py` | drive queries, collect ranks/scores, write `results.jsonl`. |
| `harness/metrics.py` | Recall@k, MRR, PR-AUC, bootstrap CIs, paired significance, slicing. |
| `harness/report.py` | comparison table + charts → Artifact for review. |
| `requirements.txt` | study-only deps (matplotlib, pyelftools). Harness core is stdlib + the MCP client. |

## 6. What is manual vs automated
- **Automated:** builds, extraction (via tools), querying, metrics, report.
- **Manual (one-time):** choosing/vendoring `libL` source; opening `progA`/`progB` in an IDA instance (or scripting idalib on a Pro host); setting the frozen gate thresholds after the first run.

## 7. Deliverable of this track
A single objective report (table + charts) comparing: shuffled floor → `anchor`-only → `ngram`-only → **v1 (full)** → (later) neural, each with CIs, per slice, at production gallery size — and a one-line verdict per acceptance gate in §4.
