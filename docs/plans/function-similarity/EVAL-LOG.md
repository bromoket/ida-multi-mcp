# Function Similarity — Evaluation Log (iterative)

Last updated: 2026-07-07
Status: Active (feedback loop)

Living record of the empirical technique-comparison loop: redesign techniques +
corpus → build binary → load in IDA → ablation → document → derive next
improvement → repeat.

## Where the data lives
Structured results are persisted by `bench/similarity/harness/run_ablation.py`:
- `bench/similarity/results/runs.jsonl` — append-only history, one JSON object per run.
- `bench/similarity/results/latest/<corpus>.json` — latest run per corpus version.

Each record (schema_version 1) carries: `timestamp_utc`, `corpus_version`,
`binary`, `binary_sha256`, `git_sha` (source that produced it, `-dirty` if
uncommitted), `sim_score_params` (M/K/bands/rows/weights), `gallery`
(function_count, is_named, gallery_size, base_delta, truth matched), a
`product_check` (real `similar_functions` tool), and `techniques[]` with
`recall_at_1/3`, `mrr`, and a `per_class_recall_at_3` map. This is the source
for the planned consolidated HTML(+SVG) report.

## Method
- Corpus = hand-authored C, MinGW `gcc -O2`, then **stripped** (no PDB, no
  symbols) so IDA analyses without name crutches (`is_named=False` for targets).
  Ground truth is **address-based** (`*.gt.json`, VA→name from the symbolized
  twin), so it survives stripping.
- Gallery = every function IDA finds (targets + CRT/library distractors).
- Metrics: Recall@1/@3, MRR over query set; per-class Recall@3; analytic random floor.
- Two views: **product check** (real tool w/ LSH+anchor candidate-gen) and
  **brute-force ablation** (each technique = a weight vector or a custom scorer,
  scored over the full gallery — isolates the scoring signal from blocking).

---

## Iteration v1 — corpus `simbench_stripped.exe` (112 functions, 7 queries)

Classes: REDUCE {sum_array, sum_array_while, sum_array_ptr}, PARSE {parse_kv,
parse_kv_r}, CRC/T4 {crc32_bitwise, crc32_lut}.

**Findings (verified against live disassembly / feature dumps):**
1. **Structure (cfg) is the strongest single signal** on stripped (R@3 0.71);
   **text/pseudocode collapses to the random floor** (R@1 0.00 ≈ 0.01) — quantitatively
   confirms "text embedding is useless without symbols."
2. **struct+anchors is the best combination.** 
3. **v1 corpus artifacts** (fixed in v2): `api`/`str` signals were inert — libc
   calls (strchr/strtol/memcpy) are ubiquitous here (high df → low IDF), and the
   target functions referenced no strings.
4. **Score dilution bug** — identical `sum_array`/`sum_array_while` scored only
   **0.50** ("medium"), because the empty api/str/const weights stayed in the
   denominator. This also let a hard-negative (`adler32`, cfg 0.81) outrank a
   true Type-4 twin (`crc32_lut`, 0.156 with const 0.16).
5. **Constant sign-extension** — the CRC polynomial `0xEDB88320` was stored as
   `0xffffffffedb88320` (sign-extended) in `crc32_bitwise` and absent (folded into
   the table) in `crc32_lut`; their only shared const was the common
   `0xffffffffffffffff` (df 11), so candidate-gen returned **0 candidates** for
   the crc query — a Type-4 recall limitation, not a ranking one.

## Iteration v1.5 — technique fixes (code, unit-tested)
- **Applicability-gated denominator** (`sim_score.score`): a signal's weight is
  dropped from the denominator when neither side has that feature → two identical
  anchor-less functions now score **~1.0** (was 0.5). Unit tests:
  `test_score_anchorless_identical_not_diluted`, `..._one_sided_anchor_still_penalizes`,
  `..._empty_minhash_drops_ngram_from_denom`.
- **Constant normalization** (`api_similarity._nontrivial_consts`): a sign-extended
  32-bit immediate also contributes its unsigned 32-bit form, so the same logical
  constant matches regardless of sign/zero extension (verified live once v2 reloads).

**v1 re-run with the denom fix (extraction still pre-const-norm):** cfg unchanged
(0.57/0.71/0.68). struct+anchors R@3 moved 0.86 → 0.71 and MRR 0.73 → 0.65.
Interpretation: the fix is **correct for interpretability** (identical→1.0,
meaningful confidence — proven by unit tests) but it uniformly lifts anchor-less
functions, so on a **7-query** eval the ranking shift (±1 query) is **within
noise** — exactly the statistical-power limit of a tiny gallery. v2 (10 queries,
signal-targeted classes) gives a firmer read; more queries / a real-scale oracle
are the eventual fix for power.

## Iteration v2 — corpus `simbench_v2_stripped.exe` (awaiting live load)
Redesigned so each signal is actually exercised, plus a realistic cross-opt pair:

| Class | Members | Targets signal |
|---|---|---|
| STR | parse_ipv4_a / parse_ipv4_b | shared distinctive literal `"%u.%u.%u.%u"` |
| API | sort_asc / sort_desc | both call `qsort` (rare here) |
| CONST/T4 | fnv_loop / fnv_unrolled | different structure, shared immediate `0x01000193` |
| CROSS-OPT | mix_o2 / mix_o0 | identical source, `-O2` vs `-O0` (`optimize("O0")`) |
| STRUCT | sum_array / sum_array_while | anchor-less (tests the denom fix live) |
| — | xor_array (hard-neg), vm_exec (large switch-VM) | distractors |

**New experimental technique introduced:** `cfg_shape (out_deg)` — uses the
`out_deg_seq` that is extracted but currently **unused by `sim_score`**; measured
in-harness (alongside `struct+anchors+shape`) to decide whether to promote it to
a core signal. (v1: cfg_shape alone 0.57 R@3, no lift when added — inconclusive on
tiny corpus; re-judge on v2.)

**v2 RESULTS (live, 114 fns, 10 queries):** corpus artifacts fixed — `str` now
1.00 (was 0.00), and CONST/CROSS-OPT classes are testable. Real
`similar_functions` tool: **4/7 → 8/10** (only the API class missed — `sort_asc`/
`sort_desc` are near-thunks and a single shared *common* `qsort` isn't
discriminating; structure links them instead). Best v2-scoring core:
`struct+anchors` (R@3 0.80, MRR 0.83). **Key discovery:** the experimental
`shape` signal (out-degree distribution, previously unused) blended in at ~0.3
hit a **perfect 1.00** — it recovers the **cross-optimization** twins
(`mix_o2`/`mix_o0`, -O2 vs -O0) that structure+anchors misses. And
`v2 rebal (const up)` (0.81) beat the default (0.71) → **const was
underweighted**.

## Iteration v3 — promote `shape` to a core signal (code, unit-tested)
Added `shape` (out-degree histogram similarity) as a first-class signal in
`sim_score.score` (applicability-gated, like `text`), raised `const`, lowered
`text`. Tests: `test_score_shape_signal_applies_with_out_deg_seq`,
`..._inapplicable_without_out_deg_seq`, `test_shape_sim_decreases_with_divergent_shape`.
**Result:** equal-weight promotion (~1/6 ≈ 17 %) did **not** recover cross-opt
(CROSS-OPT 0.00) — shape is drowned out by the disagreeing ngram/cfg. Default MRR
0.83 (tie with struct+anchors). **Lesson:** a signal's discovery ≠ its value; the
value depends on giving it enough weight.

## Iteration v4 — tune the shape weight
Ablation candidate `shape-heavy (shape 0.30)` → **R@3 0.90, MRR 0.88**, CROSS-OPT
0.00 → 0.50 — clearly the best. Promoted to the default (`SCORING_VERSION=v4`).
**Progression of the shipped default on the v2 corpus: MRR 0.71 (v1 weights) →
0.83 (v3) → 0.88 (v4); R@3 0.70 → 0.90.**
**Caveat (honest):** tuned on a 10-query corpus — overfitting risk. The exact
shape weight (0.28–0.30) and the residual cross-opt gap (0.50, not the blend's
1.00) must be re-tuned on the production-scale oracle (design doc `02`) before
being called final.

Data for all of the above: `results/latest/{simbench_stripped__v2, simbench_v2__v2,
simbench_v2__v3, simbench_v2__v4}.json` + `results/runs.jsonl`; rendered in
`results/report.html`.

## Iteration v5 — GROUPED two-stage production scoring
Resumed after a premature stop. Diagnosis: the earlier perfect cross-opt result
came from a two-stage *blend* (renormalized structure+anchor consensus, THEN
shape), not a flat weighting. Verified live: `grouped struct→shape` reaches
**Recall@1 = R@3 = MRR = 1.00** on the v2 corpus (all classes, no regression)
where the best flat weighting plateaus at 0.88 — grouping lets a discriminative
anchor (shared rare constant) dominate before shape modulates, which flat
weighting dilutes. Promoted to production as `sim_score.score_grouped`
(`SHAPE_LAMBDA=0.30`); `similar_functions`/`compare_functions` use it by default.
Unit-tested (`test_score_grouped_*`), 330 tests green. **Caveat:** 1.00 is on ≤12
queries — the mechanism is principled but generalization needs the bigger corpus.

Also diagnosed the **API-class product-check miss**: `qsort` is statically linked
(classified "internal", missed by the external-only `api` anchor) AND `sort_*`
are 2-BB thunks (empty minhash), so candidate generation never surfaces them —
a *blocking* limit, not a scoring one.

## Iteration v3 (corpus) — `simbench_v3_stripped.exe` (116 fns, 12 queries) — RESULTS
Made the API class real (`alloc_zero`/`alloc_zero_r` call the Win32 IAT import
`VirtualAlloc` in non-thunk bodies) and grew STR/STRUCT to 3 members.

**Findings — the bigger corpus corrected v2's optimism (the loop working):**
1. **API class fixed** ✓ — both `alloc_zero*` now rank #1 (product tool 10/12 R@3).
   v2's API failure was corpus-specific (statically-linked `qsort` = "internal",
   plus 2-BB thunks), not a fundamental gap.
2. **`grouped` does NOT stay perfect.** grouped 0.92/0.92/**0.92** vs the flat
   `default` (shape-heavy) 0.83/**1.00**/0.917 — a **near tie on MRR**. grouped
   keeps the better **R@1** (top-hit precision) on both corpora; flat keeps the
   better **R@3** (recall) on v3. The v2 "grouped = 1.00" was small-corpus
   optimism — exactly the ±1-query statistical-power limit flagged earlier.
   Decision: **keep `grouped` in production** (MRR ≥ flat on both corpora, R@1
   consistently better), but its superiority is *not* settled — it needs the
   production-scale oracle.
3. **Structurally-divergent semantic clones stay hard**: `sum_array_ptr` (pointer
   refactor) and `parse_ipv4_c` (loop-form variant) are missed by the product
   tool and drag grouped's STRUCT to 0.67 — shape modulation can even *hurt* a
   refactor whose branching shape also shifted. → the microcode/neural backlog.

Cross-corpus (grouped | flat-default): v2 `1.00/1.00/1.00 | .80/.90/.875`;
v3 `.92/.92/.92 | .83/1.00/.917`.

## Iteration — cross-instance × cross-compiler (live, first time)
Tested the project's **headline multi-instance capability** and the
**cross-compiler** axis for the first time: matched functions of a gcc build
against a clang build of the same sources via `similar_functions(scope='instances')`
(gcc `simbench_v3` 116 fns × clang `simbench_v2` 114 fns; 10 shared identical-source
twins; clang codegen is very different, e.g. `fnv_loop` gcc 16 vs clang 43 insns).

- **Cross-instance routing works live** ✓ — the flagship feature validated.
- **Cross-compiler ceiling: Recall@1 = 4/10, Recall@3 = 6/10** (grouped == flat —
  the misses are *candidate generation*, not scoring). Survivors all carry an
  anchor that crosses compilers: `fnv_*`/`mix_o2` (shared **constant**),
  `parse_ipv4_*` (shared **string**), `vm_exec` (large + constant).
- **The 4 misses (`sum_array`, `sum_array_while`, `xor_array`, `mix_o0`) are
  anchor-less pure loops** — their instruction lexicon and CFG diverge completely
  across gcc/clang AND they have no anchor to block on, so candidate generation
  never surfaces them (rank = None, not merely low).
- **Conclusion:** structure+anchors has a hard cross-compiler ceiling; anchor-less
  functions are unmatchable without a **semantic** signal. This is the concrete,
  live-quantified justification for the deferred **neural / microcode track**
  (design `01` §9, `02`). grouped-vs-flat remains unresolved on this axis (both
  are candidate-generation-bound, not scoring-bound).

## Frontier map (where "optimal" stands)
- **Same-toolchain / recompile / clone**: strong — `grouped` reaches Recall@1
  0.8–1.0 (v2/v3 corpora); anchors + shape carry it.
- **Cross-compiler**: capped at ~0.6 Recall@3 by candidate generation; the
  anchor-less ~40% need a learned semantic signal.
- **Structurally-divergent semantic clones** (pointer/loop refactors, Type-4):
  hard even same-compiler — the same neural/microcode frontier.

## Iteration — neural P0 probe (design `04`, live)
Tested the neural-recall hypothesis empirically before building it: disassembled
the shared functions from the gcc & clang builds, normalised to
`mnemonic_operandclass` tokens, embedded with a **general** sentence model
(all-MiniLM — a deliberate *lexical lower bound*), and ranked cross-compiler twins.
- **Small set (10 fns): Recall@3 = 8/10** — anchor-less misses reach top-3
  (`xor_array` #1, `sum_array` #3). Looked like a win.
- **Full gallery (111 fns): Recall@1 = 0/10, Recall@3 = 5/10 — *worse* than
  non-neural (6/10).** A general embedder finds *all* normalised asm broadly
  similar (MinGW CRT distractors score 0.90+), so it lacks discrimination and the
  true twin is buried.
- **Net (measured, not assumed):** the *recall* hypothesis holds — neural gives
  anchor-less functions a vector so they become retrievable (they reach top-4 vs
  rank=None non-neural) — BUT a **general** model is insufficient. You need a
  **purpose-trained, compiler-invariant BCSD model** (jTrans-class) that both
  *discriminates* and is *toolchain-robust*. (The small-vs-full-gallery gap also
  re-confirms the statistical-power discipline: never trust a tiny gallery.)
- **P0b — real BCSD model (jTrans):** obtained live from HF (`PurCL/jtrans-mfc`,
  a jump-aware BERT: hidden 768, vocab 2898, position table tied to vocab at 2902).
  Reproduced its tokenisation *approximately* from objdump Intel syntax — but hit a
  hard wall: **~37% [UNK]** after fixing operand-scale normalisation and mapping
  AT&T→IDA mnemonics (`jne→jnz`, `ret→retn`, …). The residual UNK is the **memory
  operands**: jTrans uses IDA's stack-variable normalisation (`[rsp+var_xxx+CONST]`)
  which objdump cannot produce. Plus a vanilla `BertModel` load does **not**
  reproduce jTrans's jump-aware forward (its innovation). So the approximate result
  (R@3 4/10) is **invalid, not evidence about jTrans** — it confirms *exactly* what
  design `04` predicted: **jTrans requires IDA-based preprocessing + its own model
  code.** That is a real P1 engineering build, not a probe.
- **Established:** neural is the right direction and jTrans the leading model, but a
  fair test/use needs (a) **IDA-side tokenisation in jTrans's exact format** and
  (b) **jTrans's jump-aware encoder** (from its repo), then wire **neural recall →
  grouped rerank**. This is design `04` P1/P2 — the next substantial build.

## Iteration — neural P1 (built the tokeniser; isolated the real blocker)
Built and unit-tested the tokenisation half of P1, then ran a fair test:
- **`func_tokens` plugin tool** (`api_similarity`) + pure `tools/jtrans_norm`
  (unit-tested) emit jTrans tokens using IDA's own operand normalisation; a
  `neural_backend.py` (lazy torch, on-demand weights) loads the HF jTrans
  checkpoint; harnesses `neural_cross_instance.py` / `neural_xc_disasm.py`. 333
  tests green.
- **Tokenisation is SOLVED for real functions**: via the live `disasm` tool
  (no reload needed) our target functions tokenise at **~0 % [UNK]** (`sum_array`
  0/32, `xor_array` 2/51). The ~40 % overall [UNK] is entirely the CRT/library
  distractors, not our functions. So an objdump/byte reproduction's 37 % was a
  parsing artefact, not fundamental — IDA-native tokens match jTrans's vocab.
- **The real blocker is the ENCODER.** The HF checkpoint `PurCL/jtrans-mfc` ships
  **weights + tokenizer only — no model code** (repo has no `.py`;
  `trust_remote_code` falls back to BERT). Loaded as a vanilla `BertModel` (even
  with the position table widened to 2902 so its weights load), it does **not**
  reproduce jTrans's jump-aware forward and scores **R@3 4/10 — worse than a
  general embedder (5/10)**. jTrans's whole point (a JUMP_ADDR token sharing the
  target's position embedding) is in its **GitHub `models.py`**, not on HF.
- **Sharpened P1 (precise, bounded):** vendor jTrans's jump-aware encoder from
  `github.com/vul337/jTrans` (map its checkpoint keys to the HF weights), feed it
  the already-built `func_tokens`, then wire cosine-recall → `score_grouped`
  rerank and re-run the cross-compiler gate. Tokenisation and plumbing are done;
  the remaining piece is the encoder.

## Iteration — neural P1 BREAKTHROUGH (right model + jump-aware tie)
Two fixes turned the neural track from "worse than baseline" to **beating it**:
1. **Right checkpoint.** Every `PurCL/jtrans-*` on HF is a *malware-family
   classification* finetune — the wrong task; it scored R@3 4/10. The similarity
   model is **`jTrans-finetune`** (contrastive on BinaryCorp), distributed as
   `models.tar.gz` (1.23 GB) from the authors' cloud, with the tokenizer in the
   repo's `jtrans_tokenizer/`. Downloaded on demand (owner waived zero-dep).
2. **Jump-aware tie.** jTrans's `BinBertModel` is a BERT with
   `position_embeddings = word_embeddings` (one line, `eval_save.py:105`) so a
   `JUMP_ADDR_k` token resonates with the target instruction's position. Loaded
   as vanilla BERT it is not jump-aware.
- **Result (fair, full gallery, IDA disasm tokens):** **Recall@1 4/10,
  Recall@3 8/10 — beats grouped's 6/10**, and crucially **recovers the anchor-less
  cross-compiler twins the non-neural pipeline could never match** (`sum_array` #2,
  `sum_array_while` **#1**, `xor_array` #3 — all top-3, vs rank=None for grouped).
  The one hold-out is `mix_o0` (#106): that is cross-**optimization** (O0↔O2), the
  hardest regime, not cross-compiler.
- **This validates the whole design:** a semantic embedding surfaces anchor-less
  functions that lexical+structural signals cannot, exactly as predicted. R@1 is
  held back by the reduce-family (sum/xor) look-alikes and a gallery still carrying
  46 % [UNK] CRT distractors.
- **Infra built & reusable:** `neural_backend` now loads `BinBertModel` from a
  local/HF path with a separate tokenizer (`JTRANS_MODEL`/`JTRANS_TOKENIZER` env),
  `func_tokens` (IDA-side, ~0 % UNK on real functions), harnesses, tests green.
- **Next:** wire **neural recall (top-K) → `score_grouped` rerank** to fix R@1
  (grouped disambiguates sum vs xor by mnemonic once neural has surfaced them),
  and drop/annotate the high-UNK distractors. The recall stage is now proven.

## Iteration — neural recall INTEGRATED into similar_functions (production path)
Wired the neural stage into the shipped pipeline (opt-in `IDA_MCP_SIM_NEURAL=1`):
- `index_functions` now also pulls `func_tokens` + embeds (jTrans) and stores
  `vectors`/`neural` in the index; `similar_functions` adds **cosine-recall
  top-K over those vectors** (∪ LSH/anchor) and **blends the neural cosine** into
  the final score: `final = (1-λ)·grouped + λ·neural`, `λ=NEURAL_LAMBDA`.
  Off by default → byte-identical to the zero-dep pipeline (336 tests green,
  incl. 3 new mock-backend tests proving an anchor-less twin is surfaced only with
  neural on, and missed with it off).
- **End-to-end live validation** (real jTrans-finetune, both instances, tokens via
  the proven `disasm` path): `index_functions` built a 114-fn neural index
  (`neural=True`); integrated `similar_functions` recovers the anchor-less
  cross-compiler twins. **λ sweep (10 targets): λ=0.7–1.0 → integrated Recall@3
  8/10** (=the pure-neural ceiling), λ=0.5 → 7/10, λ=0.3 → 5/10. Default set to
  **λ=0.7** (recovers anchor-less, keeps 30% grouped for same-toolchain; env-tunable,
  small-sample caveat noted).
- **Status:** the design's neural-recall→grouped-rerank is **built, tested, tuned,
  and validated** — the original request ("per-function embedding + CFG/callgraph
  rerank") is realised. Remaining: confirm the clean `func_tokens` source live
  (needs a plugin reload; `disasm` was used as an equivalent token source for
  validation), and package the model (on-demand download to `~/.ida-mcp/models/`).

## Technique backlog (next levers, roughly by effort)
- **Candidate-gen for anchor-less functions**: a coarse CFG-shape / degree-sequence
  blocking key so anchor-less loops become candidates (cheap; may lift cross-compiler).
- **API anchor (static-link)**: a **callee-set overlap** signal (internal *named*
  callees, e.g. FLIRT-recovered `qsort`) + thunk-aware candidate gen (extraction
  change + reload).
- **Neural / microcode semantic embedding** (design Track C): the only lever that
  can break the cross-compiler / semantic-clone ceiling — now *justified by live
  evidence*, but a major addition (ONNX/optional-extra, model artifacts).
- **Production-scale oracle** (static-lib-in-two-binaries, design `02`): the only
  way to finally settle grouped-vs-flat and any weight tuning at statistical power.
- **Auto weight-tuning** (grid/greedy) on the oracle instead of hand-picking.
- **Statistical power / external validity**: the static-lib-in-two-binaries oracle
  at production scale (design doc `02`) — a 10-query gallery cannot separate
  ±1-query effects, and every weight above is tuned on toys.
- **Microcode / decompiler-pseudocode neural** (deferred track) for the hardest
  Type-4 / cross-opt cases where structure diverges and no anchor links them.
