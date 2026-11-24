# 04 — Neural Semantic Track (design)

Last updated: 2026-07-07
Status: Draft — implementation-ready design (empirically motivated)

This design adds a **learned semantic embedding** to break the ceiling the
non-neural work hit. The zero-runtime-dependency constraint is **lifted** (owner
decision): torch/ONNX may be added as an **optional extra** and model weights
**downloaded on demand** and cached. It builds directly on the existing
`EmbeddingBackend` seam (`01` §9), the two-stage grouped scoring (`sim_score`),
the per-binary index, and the evaluation harness (`bench/similarity/`).

## 1. Why (grounded in live measurement, not assertion)
The empirical loop (see `EVAL-LOG.md`) converged the **non-neural** design space:
- Same-toolchain / recompile / clone: **solved-ish** — `grouped` (structure+anchor
  consensus, then shape) reaches Recall@1 0.8–1.0.
- **Cross-compiler (gcc↔clang, live cross-instance): Recall@3 = 6/10, and it is
  a hard ceiling.** The 4 misses (`sum_array`, `sum_array_while`, `xor_array`,
  `mix_o0`) are **anchor-less pure loops** whose instruction lexicon and CFG
  diverge completely across compilers (`fnv_loop`: gcc 16 vs clang 43 insns) AND
  which carry no import/string/constant anchor — so **candidate generation never
  even surfaces them** (rank = None, not merely low). `grouped == flat` on these,
  because the failure is *recall/blocking*, not scoring.

So the neural signal must do two specific things the measurements demand:
1. **Be a universal recall/blocking key** — every function gets a vector, so an
   anchor-less function becomes retrievable (fixes the measured candidate-gen gap).
2. **Place cross-compiler / cross-opt / semantic twins close** even when lexicon
   and CFG diverge — i.e. a *semantic* embedding, learned to be invariant to
   toolchain, not a lexical one (our MinHash already covers lexical and fails here).

**Concrete smoking gun** (from the live gcc/clang builds): `sum_array`
(`s += a[i]`) is compiled by **gcc to a 16-instruction scalar loop**
(`add`/`cmp`/`jne`) and by **clang to an auto-vectorized SSE2 loop**
(`movdqu`/`paddd`/`pshufd`, ~40 insns) plus a scalar remainder — near-disjoint
instruction sets, different CFGs, no shared anchor. No lexical (MinHash) or
structural (CFG) signal can bridge that; only an embedding *trained* to place
`scalar-sum ≈ vectorized-sum` can. This is exactly **binary code similarity
detection (BCSD)** — a learned, compiler-invariant per-function embedding.

**Environment is ready** for it (probed): torch 2.6+cu124 on a GTX 1080,
`transformers` + `capstone` installed, `sentence_transformers`/`onnxruntime`
pip-installable — so disassembly + GPU embedding can run locally today.

## 2. Architecture — neural recall, structural rerank
The neural embedding is the **recall stage**; the existing `grouped` structural+
anchor+shape score is the **rerank stage**. This realizes the original feature
request ("maintain per-function embeddings, rerank with CFG/call-graph") and
reuses everything already built.

```
similar_functions(scope=..., neural=True)
   │
   ├─ recall:  cosine top-K over neural vectors   (NEW — universal blocking key,
   │           ∪ existing LSH + anchor candidates)   surfaces anchor-less functions
   │
   └─ rerank:  sim_score.score_grouped(...)  on the top-K, optionally blended with
               the neural cosine  →  final ranked results + per-signal breakdown
```
- **Backward compatible**: no backend configured → today's behavior exactly.
- The neural cosine may be added as one more term in the final blend (a new
  weight `neural`, tuned empirically like every other weight).

## 3. Where it runs & how it's obtained (on-demand)
- New optional extra: `pip install ida-multi-mcp[neural]` → installs
  `torch`/`onnxruntime` + tokenizer deps. Absent → similarity works in its
  current non-neural form; neural tools report "install the [neural] extra".
- Model weights are **downloaded on first use** (HuggingFace hub or a pinned URL)
  and cached under `<registry_base>/models/<model_id>/`. A checksum is verified.
  Air-gapped users can pre-place the cache dir (documented).
- Inference runs in a **lazy-loaded module** `tools/neural_backend.py` (imports
  torch only when first used), GPU if available (`torch.cuda`), CPU fallback. For
  isolation and to keep the stdio server light, it may run as a **subprocess
  worker** (mirror `idalib_manager`'s spawn/health pattern); v1 may lazy-load
  in-process and move to a worker only if it hurts responsiveness.

## 4. Model input & extraction (decouple IDA from model specifics)
BCSD models each have their own normalization/tokenization. Keep that inside the
backend, not IDA:
- `func_features` (or the existing `get_bytes`) supplies each function's **raw
  bytes + start VA + arch** (add a `bytes` field / reuse `get_bytes(range)`).
- The neural backend disassembles+normalizes the bytes with the **model's own
  preprocessing** (e.g. jTrans's tokenizer) and embeds. This keeps model-specific
  logic out of the IDA plugin and lets us swap models without changing extraction.
- Index gains `"vectors": {addr: [float,…]}` and `"backend": {name, dim, version}`
  (absent for non-neural indexes; loader tolerates both — `01` §9).

## 5. Candidate models — BENCHMARK, don't assert
Consistent with the whole methodology, pick the model by measuring it on our
missed cases, not by reputation. Candidates, in priority order:

| Model | Why | Cost |
|---|---|---|
| **jTrans** (jump-aware transformer, BinaryCorp-pretrained) | trained *contrastively on the same function across optimizations* → single vector, compiler/opt-robust; the leading practical BCSD model for exactly our gap | repo + weights, 512-token cap, x86/64, tokenizer to wire |
| **PalmTree** / **Trex** / **CLAP** | alt pretrained asm encoders | similar wiring |
| **ACFG + GNN (Gemini-style)** | structure embedding; cheap/CPU | but our misses have *divergent* CFG → likely weaker cross-compiler; keep as a baseline |
| general code embedder (CodeBERT/UniXcoder) on decompiler pseudocode | works when symbols exist | weak on stripped anchor-less loops (generic pseudocode) — expected low; include as a control |

**Gate:** a model earns promotion only if it materially lifts Recall@k on the
**anchor-less cross-compiler misses** (and the semantic-clone cases) over
`grouped`, measured by §7. Expect jTrans-class models to help most; the general
code embedder is a control that should *fail* the anchor-less cases (confirming
you need a purpose-trained BCSD model, not any embedding).

## 6. Integration points (concrete)
| File | Change |
|---|---|
| `tools/neural_backend.py` (new) | `EmbeddingBackend` impls; lazy torch import; on-demand download+cache+checksum; `embed_batch(func_bytes[]) -> vectors`; GPU/CPU. |
| `tools/index_store.py` | already versioned; store/load `vectors` + `backend` meta (no schema break). |
| `tools/similarity.py` | `index_functions(..., backend=)` also computes+stores vectors; `similar_functions(..., neural=True/backend=)` adds cosine-ANN recall ∪ existing candidates, then `score_grouped` rerank + optional neural blend. |
| `sim_score.py` | optional `neural` term in the grouped blend (a weight); pure cosine helper. |
| `ida_mcp/api_similarity.py` / `get_bytes` | supply per-function bytes+VA+arch for the backend. |
| `pyproject.toml` | `[project.optional-dependencies] neural = ["torch", "onnxruntime", …]`. |

Recall ANN: brute-force cosine is fine at eval/single-binary scale; swap in
`hnswlib`/`faiss` behind the same call for production 150K-function indexes.

## 7. Evaluation & tests (extend what exists — the gate)
Reuse the harness; add the neural path as measured techniques:
- `run_ablation.py`: add `neural (recall)` and `neural→grouped (rerank)` as
  scorers/techniques; per-class Recall as today. Persisted to `runs.jsonl` with
  the model id + `scoring_version` so neural runs are comparable.
- `run_cross_instance.py`: add neural recall — **the primary gate**: does it
  surface & rank the 4 anchor-less cross-compiler misses that `grouped` cannot?
- Expand ground truth for statistical power: build the **static-lib-in-two-binaries
  oracle** (design `02`) and a **cross-compiler / cross-opt matrix** (gcc/clang ×
  -O0..-O3) so the model is judged on real cross-toolchain pairs, not 10 toys.
- **Acceptance gate:** ship neural only if, on the cross-compiler + semantic-clone
  sets, `neural→grouped` beats `grouped` by a clear, significant margin (bootstrap
  CI / paired test) — enough to justify the dependency + model download.

Unit/integration tests:
- `EmbeddingBackend` contract test with a **deterministic mock backend** (fixed
  vectors) — no torch needed; verifies recall-union, cosine ANN, rerank blend,
  and backward-compat (no backend → unchanged).
- Index round-trips `vectors`/`backend` (extend `test_index_store`).
- `similar_functions(neural=True)` with the mock backend surfaces a
  no-anchor/empty-minhash function that the non-neural path misses (the exact gap).
- Model-specific tests (tokenizer, download-cache, checksum) live with the backend.

## 8. Honest limits (what neural will and won't fix)
- **Tiny functions stay hard.** `sum_array` is ~5–16 instructions; even a strong
  model has little to embed. Neural should help medium/large functions most; report
  Recall sliced by function size.
- **Cross-compiler is the hardest BCSD regime** (harder than cross-optimization);
  even SOTA is moderate — expect improvement, not saturation.
- **jTrans preprocessing is IDA/x86-specific**; adapting its tokenizer to our byte
  extraction is real work, and non-x86 targets are out of scope initially.
- Model size / first-use download latency / GPU memory are new operational
  surfaces (documented; CPU fallback; cache reuse).

## 9. Phased plan
- **P0 — probe (DONE; see `EVAL-LOG.md`):** validated that neural embedding gives
  anchor-less functions a vector so they become retrievable (a general model
  surfaced them into top-K where the non-neural pipeline had rank=None) — but a
  **general** model lacks discrimination (full-gallery R@3 5/10, worse than
  grouped's 6/10). Then obtained jTrans (`PurCL/jtrans-mfc`); an *approximate*
  objdump-based tokenisation hit **~37% [UNK]** (its memory operands need IDA
  stack-variable normalisation) and a vanilla `BertModel` load omits its
  jump-aware forward → the approximate number is invalid. **Conclusion: the recall
  hypothesis holds; a fair jTrans test needs its exact IDA-based tokenisation + its
  own encoder** (below).
- **P1 — jTrans, done right:**
  1. **IDA-side tokenisation** — extend the plugin (`api_similarity`) to emit each
     function in jTrans's token format using IDA's own operand normalisation
     (registers kept, imm/disp→CONST, memory `[base+idx*scale+var_xxx+CONST]` via
     IDA stack-var names, `JUMP_ADDR_k` for intra-function jumps). This is why the
     tokeniser must live IDA-side for jTrans, not on raw bytes (P0b proof).
  2. **jTrans encoder** — vendor its jump-aware model code (position/word embedding
     tied at vocab size 2902; per-jump position sharing) rather than vanilla BERT.
  3. **Backend + index** — `neural_backend.py` (lazy torch, on-demand weights,
     GPU); store `vectors` in the index; wire cosine-ANN recall ∪ existing
     candidates → `score_grouped` rerank behind `neural=True`; mock-backend tests.
  4. **Re-run** the full-gallery cross-compiler eval; gate = lift over grouped on
     the anchor-less twins.
- **P2 — benchmark candidates** through the harness on the cross-compiler / oracle
  sets; pick the winner by the §7 gate.
- **P3 — integrate + tune** the neural blend weight; production ANN (hnswlib);
  packaging (`[neural]` extra, download/cache/checksum, docs, air-gap path).
- **P4 — ship** behind the gate; keep grouped as the zero-dep default so the core
  stays usable without the extra.

## 9b. Status — BUILT & VALIDATED (2026-07-07)
The neural recall stage is implemented, tested, tuned, and validated end-to-end.
- **Model:** `jTrans-finetune` (NOT the HF `jtrans-mfc` malware finetune) + the
  jump-aware tie (`position_embeddings = word_embeddings`). Loaded by
  `neural_backend` via `JTRANS_MODEL`/`JTRANS_TOKENIZER`. See EVAL-LOG "BREAKTHROUGH".
- **Tokeniser:** `func_tokens` (IDA-side, ~0% UNK on real functions) + pure
  `tools/jtrans_norm` (unit-tested); registered in `ida_tool_schemas.json`.
- **Integration:** `similar_functions` does cosine recall (∪ LSH/anchor) + blends
  `final = (1-λ)·grouped + λ·neural` (λ=NEURAL_LAMBDA=0.7). Opt-in via
  `IDA_MCP_SIM_NEURAL=1`; off → unchanged.
- **Non-blocking incremental embedding** (required for 150K-function binaries):
  `index_functions` builds features first (index **immediately usable** for
  non-neural search), then embeds vectors in the background in `EMBED_BATCH`
  batches to an **append-only sidecar** (`<sha>.vectors.jsonl`). It is
  **resumable** (skips already-embedded; a cached-but-incomplete index resumes),
  **cancelable** (between batches), and **partially usable** — `similar_functions`
  uses whatever vectors exist so far, and `index_status` reports
  `embed_done`/`embed_total`/`embed_progress` (from the durable sidecar, so it is
  accurate across a server restart). Verified live: non-blocking return (0.01 s),
  progress 16→114, and a query mid-embed (16/114) returns results.
- **Tests:** 336 green incl. `test_similarity_neural` (surfaced-only-with-neural)
  and `test_jtrans_norm`.
- **Result:** integrated cross-compiler **Recall@3 8/10** (λ 0.7–1.0), recovering
  anchor-less twins (`sum_array`, `xor_array`) that non-neural grouped (6/10)
  cannot match at all.
- **Remaining (deployment):** package the model as an **on-demand download to
  `~/.ida-mcp/models/`** (1.23 GB, `models.tar.gz` from the vul337 cloud) with a
  checksum + `[neural]` extra; confirm the shipped `func_tokens` path live (a
  plugin reload — `disasm` was used as an equivalent token source for validation).

## 10. Traceability
- Seam & storage: `01` §9, `tools/index_store.py` (`vectors`/`backend`).
- Recall→rerank: `tools/similarity.py`, `sim_score.score_grouped`.
- Evidence/gate: `EVAL-LOG.md` (cross-compiler ceiling), `bench/similarity/harness/*`.
- Byte extraction: `ida_mcp/api_similarity.py`, `get_bytes`.
