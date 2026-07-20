#!/usr/bin/env python3
"""All-techniques comparison (ablation) for function similarity, on a live IDA.

Version-aware: auto-detects which simbench binary is loaded and uses the matching
ground truth + equivalence classes, so the same harness drives every iteration
(v1, v2, ...). Reports, per technique: overall Recall@1 / Recall@3 / MRR and a
per-class Recall@3 matrix (which technique captures which relationship kind).
Also runs the real ``similar_functions`` tool as a product check, and includes
EXPERIMENTAL in-harness techniques (e.g. an out-degree "cfg shape" signal not yet
in ``sim_score``) so new signals can be measured before promotion to the core.

Results are PERSISTED as structured JSON under ``bench/similarity/results/`` for
later HTML(+SVG) reporting:
  - ``results/runs.jsonl``           -- append-only history (one object per run)
  - ``results/latest/<corpus>.json`` -- latest run per corpus version

Run (with a simbench_*_stripped.exe open in a reloaded IDA):
    python bench/similarity/harness/run_ablation.py
"""

from __future__ import annotations

import datetime
import json
import math
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
LIVE = Path(__file__).resolve().parents[1] / "livetest"
RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"

from ida_multi_mcp.registry import InstanceRegistry          # noqa: E402
from ida_multi_mcp.router import InstanceRouter               # noqa: E402
from ida_multi_mcp.tools import similarity, index_store, sim_score  # noqa: E402

CONFIGS = {
    "simbench_v3": {
        "gt": LIVE / "simbench_v3.gt.json",
        "classes": [
            ("API",       ["alloc_zero", "alloc_zero_r"]),          # Win32 IAT import anchor
            ("STR",       ["parse_ipv4_a", "parse_ipv4_b", "parse_ipv4_c"]),
            ("CONST/T4",  ["fnv_loop", "fnv_unrolled"]),
            ("CROSS-OPT", ["mix_o2", "mix_o0"]),
            ("STRUCT",    ["sum_array", "sum_array_while", "sum_array_ptr"]),
        ],
    },
    "simbench_v2": {
        "gt": LIVE / "simbench_v2.gt.json",
        "classes": [
            ("STR",       ["parse_ipv4_a", "parse_ipv4_b"]),
            ("API",       ["sort_asc", "sort_desc"]),
            ("CONST/T4",  ["fnv_loop", "fnv_unrolled"]),
            ("CROSS-OPT", ["mix_o2", "mix_o0"]),
            ("STRUCT",    ["sum_array", "sum_array_while"]),
        ],
    },
    "simbench_stripped": {   # v1
        "gt": LIVE / "simbench.gt.json",
        "classes": [
            ("REDUCE", ["sum_array", "sum_array_while", "sum_array_ptr"]),
            ("PARSE",  ["parse_kv", "parse_kv_r"]),
            ("CRC/T4", ["crc32_bitwise", "crc32_lut"]),
        ],
    },
}

TECHNIQUES = {
    "ngram (MinHash asm)":        {"ngram": 1.0},
    "cfg (structure)":            {"cfg": 1.0},
    "api (imports)":              {"api": 1.0},
    "str (strings)":              {"str": 1.0},
    "const (constants)":          {"const": 1.0},
    "anchors (api+str+const)":    {"api": 1.0, "str": 1.0, "const": 1.0},
    "structure (ngram+cfg)":      {"ngram": 1.0, "cfg": 1.0},
    "struct+anchors":             {"ngram": 1.0, "cfg": 1.0, "api": 1.0, "str": 1.0, "const": 1.0},
    "shape (out_deg)":            {"shape": 1.0},                       # v3 promoted signal
    "struct+anchors+shape":       {"ngram": 1.0, "cfg": 1.0, "shape": 1.0, "api": 1.0, "str": 1.0, "const": 1.0},
    "default (current)":          dict(sim_score.DEFAULT_WEIGHTS),     # tracks sim_score default
    "v2 rebal (const up)":        {"ngram": 0.28, "cfg": 0.20, "api": 0.20, "str": 0.12, "const": 0.20},
    "v2 rebal (struct up)":       {"ngram": 0.30, "cfg": 0.35, "api": 0.13, "str": 0.10, "const": 0.12},
    # v4 hypothesis: shape needs ~0.30 weight to recover cross-opt twins that
    # disagreeing lexical/scalar-structure signals otherwise drown out.
    "shape-heavy (.30)":          {"ngram": 0.14, "cfg": 0.14, "shape": 0.30, "api": 0.14, "str": 0.14, "const": 0.14},
}


def _pick_config(binary_name):
    m = [(k, c) for k, c in CONFIGS.items() if k in binary_name]
    if not m:
        return None, None
    k, c = max(m, key=lambda kc: len(kc[0]))
    return k, c


def _git_sha():
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                    capture_output=True, text=True).stdout.strip())
        return (sha or "unknown") + ("-dirty" if dirty else "")
    except Exception:
        return "unknown"


def _persist(record):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "latest").mkdir(exist_ok=True)
    with open(RESULTS_DIR / "runs.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    sv = record.get("scoring_version", "v?")
    latest = RESULTS_DIR / "latest" / f"{record['corpus_version']}__{sv}.json"
    json.dump(record, open(latest, "w", encoding="utf-8"), indent=2)
    return latest


def _deg_hist(feat):
    seq = (feat.get("cfg") or {}).get("out_deg_seq") or []
    h = [0, 0, 0, 0]
    for d in seq:
        h[min(int(d), 3)] += 1
    t = sum(h) or 1
    return [x / t for x in h]


def _cfg_shape_sim(a, b):
    """Experimental: similarity of out-degree distribution (unused by sim_score)."""
    ha, hb = _deg_hist(a), _deg_hist(b)
    return 1.0 - 0.5 * sum(abs(x - y) for x, y in zip(ha, hb))


def _random_floor(per_q_p, gallery):
    r1 = r3 = 0.0
    o = gallery - 1
    for p in per_q_p:
        r1 += p / o
        r3 += 1 - math.comb(o - p, 3) / math.comb(o, 3)
    return r1 / len(per_q_p), r3 / len(per_q_p)


def main() -> int:
    reg = InstanceRegistry()
    router = InstanceRouter(reg)
    similarity.set_registry(reg)
    similarity.set_router(router)
    insts = reg.list_instances()
    if not insts:
        print("FAIL: no IDA instance. Open a simbench_*_stripped.exe in a reloaded IDA.")
        return 1
    # Optional arg selects a specific binary substring (e.g. "simbench_v2") so
    # v1 and v2 can be open at once without ambiguity.
    want = sys.argv[1].lower() if len(sys.argv) > 1 else "simbench"
    iid = next((i for i, v in insts.items() if want in v.get("binary_name", "").lower()),
               next((i for i, v in insts.items() if "simbench" in v.get("binary_name", "").lower()),
                    next(iter(insts))))
    binary = insts[iid].get("binary_name", "")
    ckey, cfg = _pick_config(binary)
    if cfg is None:
        print(f"FAIL: no config for binary '{binary}'. Known: {list(CONFIGS)}")
        return 1
    print(f"== instance {iid} ({binary}) [corpus={ckey}] ==\n")

    res = similarity.index_functions({"instance_id": iid, "background": False})
    if not isinstance(res, dict) or "error" in res:
        print(f"FAIL: index_functions -> {res}")
        return 1
    idx = index_store.read_index(res["index_id"], reg.registry_path) or {}
    funcs = idx.get("functions", {})
    df, zstats = idx.get("df", {}), idx.get("zstats", {})
    n = idx.get("function_count", len(funcs)) or 1

    va2name = {int(k, 16): v for k, v in json.load(open(cfg["gt"], encoding="utf-8"))["va2name"].items()}
    name2va = {v: k for k, v in va2name.items()}
    ida_set = {int(a, 16) for a in funcs}
    delta = 0 if sum(1 for va in va2name if va in ida_set) >= len(va2name) // 2 else \
        next((a - min(va2name) for a in ida_set
              if sum(1 for va in va2name if va + (a - min(va2name)) in ida_set) > len(va2name) // 2), 0)

    def addr(name):
        va = name2va.get(name)
        a = hex(va + delta) if va is not None else None
        return a if a in funcs else None

    named = sum(1 for f in funcs.values() if f.get("is_named"))
    matched = sum(1 for va in va2name if (va + delta) in ida_set)
    gallery = len(funcs)
    print(f"[gallery] functions={res.get('function_count')} skipped={res.get('skipped_count')} "
          f"is_named={named}  delta={hex(delta)}  truth matched {matched}/{len(va2name)}\n")

    queries = []
    for label, members in cfg["classes"]:
        addrs = [addr(m) for m in members if addr(m)]
        for qa in addrs:
            pos = set(addrs) - {qa}
            if pos:
                queries.append((label, qa, pos))
    per_q_p = [len(p) for _, _, p in queries]
    labels = [lbl for lbl, _ in cfg["classes"]]

    # ---- Part A: real similar_functions tool --------------------------------
    print("== A. product check: similar_functions (v1 tool, LSH+anchor candidates) ==")
    a1 = a3 = 0
    product_queries = []
    for label, qa, pos in queries:
        out = similarity.similar_functions({"instance_id": iid, "func": qa, "top_k": 8})
        ranks = [r["addr"] for r in out.get("results", [])]
        rk = next((i + 1 for i, x in enumerate(ranks) if x in pos), None)
        a1 += rk == 1
        a3 += bool(rk and rk <= 3)
        qn = va2name.get(int(qa, 16) - delta, qa)
        product_queries.append({"label": label, "name": qn, "rank": rk})
        print(f"  [{'OK' if (rk and rk <= 3) else 'MISS'}] {label:10s} {qn:16s} rank={rk}")
    print(f"  Recall@1={a1}/{len(queries)}  Recall@3={a3}/{len(queries)}\n")

    # ---- Part B: technique ablation (brute force) ---------------------------
    random.seed(1234)
    order = list(funcs)
    random.shuffle(order)
    tie = {a: i for i, a in enumerate(order)}

    def eval_scorer(scorer):
        R1 = R3 = 0
        rr = 0.0
        by = {lbl: [0, 0] for lbl in labels}
        for label, qa, pos in queries:
            qf = funcs[qa]
            scored = sorted(((scorer(qf, funcs[a]), a) for a in funcs if a != qa),
                            key=lambda x: (-x[0], tie[x[1]]))
            rk = next((i + 1 for i, (s, a) in enumerate(scored) if a in pos), None)
            R1 += rk == 1
            R3 += bool(rk and rk <= 3)
            rr += 1.0 / rk if rk else 0.0
            by[label][1] += 1
            by[label][0] += bool(rk and rk <= 3)
        q = len(queries)
        return (R1 / q, R3 / q, rr / q), by

    def weight_scorer(w):
        return lambda qf, bf: sim_score.score(qf, bf, df, zstats, n, w)[0]

    scorers = {name: weight_scorer(w) for name, w in TECHNIQUES.items()}
    scorers["cfg_shape (harness)  *exp"] = _cfg_shape_sim  # cross-check vs core shape

    # v5 production: two-stage GROUPED scoring (structure+anchor consensus, then
    # shape modulation) -- the real sim_score.score_grouped used by the tools.
    scorers["grouped (production)"] = lambda qf, bf: sim_score.score_grouped(qf, bf, df, zstats, n)[0]

    f1, f3 = _random_floor(per_q_p, gallery)
    hdr = "  {:28s} {:>7s} {:>7s} {:>6s}  ".format("technique", "R@1", "R@3", "MRR") + \
          " ".join(f"{l:>9s}" for l in labels)
    print(f"== B. technique ablation ({len(queries)} queries, gallery={gallery}) ==")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    print("  {:28s} {:7.2f} {:7.2f} {:>6s}".format("random floor (analytic)", f1, f3, "-"))
    results = {}
    for name, scorer in scorers.items():
        (r1, r3, mrr), by = eval_scorer(scorer)
        results[name] = (r1, r3, mrr, by)
        per = " ".join(f"{(by[l][0] / by[l][1] if by[l][1] else 0):9.2f}" for l in labels)
        print("  {:28s} {:7.2f} {:7.2f} {:6.2f}  {}".format(name, r1, r3, mrr, per))

    # ---- persist structured results -----------------------------------------
    record = {
        "schema_version": 1,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "corpus_version": ckey,
        "scoring_version": sim_score.SCORING_VERSION,
        "binary": binary,
        "binary_sha256": res.get("index_id"),
        "git_sha": _git_sha(),
        "sim_score_params": {"M": sim_score.M, "K": sim_score.K, "BANDS": sim_score.BANDS,
                             "ROWS": sim_score.ROWS, "default_weights": sim_score.DEFAULT_WEIGHTS},
        "gallery": {"function_count": res.get("function_count"), "skipped": res.get("skipped_count"),
                    "is_named": named, "base_delta": hex(delta),
                    "truth_matched": matched, "truth_total": len(va2name), "gallery_size": gallery},
        "random_floor": {"recall_at_1": round(f1, 4), "recall_at_3": round(f3, 4)},
        "classes": [{"label": l, "members": m} for l, m in cfg["classes"]],
        "num_queries": len(queries),
        "product_check": {"recall_at_1_num": a1, "recall_at_3_num": a3, "denom": len(queries),
                          "queries": product_queries},
        "techniques": [
            {"name": name.replace("*exp", "").strip(),
             "kind": "experimental" if "*exp" in name else "core",
             "recall_at_1": round(r1, 4), "recall_at_3": round(r3, 4), "mrr": round(mrr, 4),
             "per_class_recall_at_3": {l: round(by[l][0] / by[l][1], 4) if by[l][1] else 0.0
                                       for l in labels}}
            for name, (r1, r3, mrr, by) in results.items()
        ],
    }
    path = _persist(record)

    core = {k: v for k, v in results.items() if "*exp" not in k}
    best = max(core, key=lambda k: (core[k][2], core[k][1]))
    print("\n== findings ==")
    print(f"  * best CORE technique by MRR: '{best.strip()}' "
          f"(R@1={core[best][0]:.2f} R@3={core[best][1]:.2f} MRR={core[best][2]:.2f})")
    for exp in [k for k in results if "*exp" in k]:
        r1, r3, mrr, _ = results[exp]
        print(f"  * experimental '{exp.replace('*exp','').strip()}': R@1={r1:.2f} R@3={r3:.2f} MRR={mrr:.2f}")
    print(f"\n[saved] {path}\n[saved] {RESULTS_DIR / 'runs.jsonl'} (appended)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
