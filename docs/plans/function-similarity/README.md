# Function Similarity — Plan Overview

Last updated: 2026-07-07
Status: Draft (active plan) — revised after adversarial design review
Change class: B (scope/architecture) — feeds a future ADR

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` → `docs/.ssot/PRD.md` → `docs/.ssot/decisions/*` → `docs/.ssot/architectures/*` → this plan.
- This plan does not redefine any contract. It produces (a) a shippable v1 feature and (b) an evidence base that gates any neural upgrade via an ADR.

## Document Map (read in order)
1. `README.md` (this file) — goal, strategy, sequencing, honest limits.
2. `01-v1-production-design.md` — **implementation-ready** spec for the zero-dependency v1 feature.
3. `02-evaluation-design.md` — the real-binary **oracle** + synthetic **microscope**, metrics, and numeric acceptance gates.
4. `03-implementation-handoff.md` — task breakdown, sequencing, per-task acceptance criteria, and test plan for the implementer.

Implementation and testing are delegated (to a Sonnet session). These documents are written to be executed without further design decisions; every open choice has a stated default and rationale.

---

## 1. Goal
Add **local, per-function similarity search** to ida-multi-mcp: given a function, rank the most similar functions within the same binary or **across instances** (dropper ↔ payload ↔ C2), with CFG / call-graph structural signals. Primary use cases: patch diffing, library-function identification, cross-binary variant hunting, and "is this the same function?" spot checks.

## 2. Strategy (revised after adversarial review)
The original plan was "synthetic corpus → pick a neural embedding → productionize on IDA." An adversarial review (recorded in §4) found that path measures toy functions, in a toy-scale gallery, with a non-IDA extractor — so its "winner" may not transfer to real 150K-function IDA/PE targets, and the apparatus risks becoming the project instead of shipping a feature (contradicting the repo's KISS/YAGNI stance and its `dependencies = []` identity).

Revised sequencing — **real → simple-first → neural-only-if-justified**:

| Track | What | Why first |
|---|---|---|
| **A. v1 feature (ships)** | Zero-dependency similarity: instruction-shingle MinHash + high-precision anchors (imported-API / string / constant sets) + CFG/call-graph structural scoring, on the **real IDA extractor**, cross-instance. See `01`. | Immediately useful, matches the project's zero-dep/localhost/air-gap identity, and *is* the rerank stage + baseline for any future neural recall. Nothing is wasted. |
| **B. evaluation** | A **real-binary, IDA-extracted, production-scale oracle** (same static library linked into two binaries → free symbol-verified ground truth on real code) that gates ship/upgrade decisions; plus a **revised synthetic corpus** demoted to a *diagnostic microscope*. See `02`. | The oracle, not the toy corpus, decides what ships. Real conditions, real scale, real tool. |
| **C. neural extra (conditional)** | A pluggable `EmbeddingBackend` seam (see `01` §9) so a local neural embedding (ONNX / optional extra) can be added later **without reworking tools or storage** — justified only if it beats v1 on track B's real oracle by a margin worth the dependency/model cost. | Preserves the zero-dep core; avoids over-investing to justify a model before evidence exists. |

The user's original intent (local neural embeddings) is preserved as the track-C target; the review only moved the **decision gate** from a synthetic toy benchmark to a real-binary one.

## 3. Environment Capability (probed 2026-07-07)
| Capability | Status | Consequence |
|---|---|---|
| Compilers | MinGW gcc 13.2, clang 22.1, MSVC (VS 2026), WSL Ubuntu/fedora gcc/clang | Rich compiler × opt matrix for the oracle/corpus |
| Torch / GPU | torch 2.6+cu124, GTX 1080, transformers 5.12, sklearn | Track-C candidates run in torch now (no ONNX needed to *study*) |
| Extraction (study) | capstone 4.0.2, networkx 3.4.2, objdump 2.39; pip for pyelftools/pypcode | Local study extraction available, **but see §4 T1-2** |
| IDA on dev host | IDA Home 9.3 — **no idalib** | v1 + oracle target IDA; batch extraction on this host needs the GUI plugin or a Pro host. Track A/B are designed to run against any registered IDA instance. |
| v1 runtime deps | **none** (stdlib only: `hashlib`, `json`, `math`, `statistics`) | v1 keeps `dependencies = []` intact |

## 4. Adversarial Review Findings (the reason for the revision)
Verified against real disassembly of the seed corpus (gcc/clang × -O0..-O3):

- **T1-1 Gallery-scale mismatch:** Recall@1 on a 10–40 function gallery does not predict (and may rank-invert) behavior on a 150K gallery. → Track B evaluates at **production-scale galleries**, not toy subsets.
- **T1-2 Extractor mismatch + "IDA-free" self-own:** a study on capstone/pypcode-ELF can misrank methods for IDA-microcode-PE production; and SOTA candidates (e.g. jTrans) are pretrained on **IDA-extracted** asm, so an IDA-free study handicaps them. → Track B/C extract via the **same IDA path** production uses (`func_features`).
- **T1-3 Ground-truth breaks under inlining/ICF, and leaf-function corpus can't test it:** isolated leaf functions are never inlined. → Track B uses **whole programs** (callers present) and computes ground truth from symbols *before* stripping; the corpus is relabeled by *actual* post-compile relationship.
- **T2/T3 Fairness & calibration:** unequal prior knowledge (pretrained vs trained-on-toys), no statistical-significance plan, three different tasks lumped as one "positive," and functions too small (12–49 insns, verified) to differentiate methods. → Track B separates tasks, sizes functions up, and reports **bootstrap CIs + paired significance**.
- **T4 YAGNI / identity:** a multi-week neural benchmark to ship one feature, and a 100MB+ model conflicts with the zero-dep/air-gap identity. → v1 ships zero-dep first; neural is a conditional optional extra.

Evidence sample: `sum_array` and `sum_array_while` compile **byte-identical at gcc -O2** (the "refactor invariance" test was void — they were Type-1 clones post-compile), while `xor_array` diverged structurally only because gcc unrolled it. This is why Track B labels pairs by measured post-compile relationship, not by source intent.

## 5. Honest Limits
- v1 is same-toolchain-strong, cross-compiler/-optimization-weaker by design (no learned semantics). That is acceptable for the headline use cases and is stated in the tool output (confidence + per-signal breakdown).
- Cross-architecture matching is out of scope.
- The synthetic corpus has limited external validity and is used only as a diagnostic; the real-binary oracle is the decision authority.
- A future neural backend does not change the tool surface or storage (see `01` §9); it only adds a recall stage and a vector field.

## 6. Traceability (production reuse)
- Extraction: `ida_mcp/api_composite.py::_analyze_function_internal:223`, `api_analysis.py::basic_blocks:667`, `utils.py::extract_function_strings:1173` / `extract_function_constants:1202`, `api_analysis.py::callees:510`, `api_core.py::imports_query:622`.
- Server-side aggregation + cross-instance routing pattern: `tools/management.py::compare_binaries:83`, `router.py::route_request:32`, `server.py::custom_tools_call` dispatch.
- Background job pattern: `idalib_manager.py::IdalibManager`.
- Large-job execution control policy: `docs/.ssot/architectures/21_architecture_problems_spec.md` (AP-P2-03), SSOT TODO.
- Index keying requires a new helper wrapping `ida_nalt.retrieve_input_file_sha256()` (does not yet exist in the codebase).
