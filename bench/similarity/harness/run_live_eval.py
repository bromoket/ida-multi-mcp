#!/usr/bin/env python3
"""Live smoke-test / mini-eval for the function-similarity feature.

Reuses the REAL InstanceRegistry + InstanceRouter (no MCP server needed): it
reads ``~/.ida-mcp/instances.json``, connects to the running IDA plugin's HTTP
endpoint, builds the similarity index via ``func_features``, then runs
``similar_functions`` / ``compare_functions``.

Ground truth is **address-based** (``simbench.gt.json``: VA -> true name, captured
from the symbolized build), so it works on the fully STRIPPED binary where IDA
reports every function as ``sub_*`` -- i.e. the realistic no-symbol scenario the
feature is designed for (``is_named=False`` -> structure + anchors only, no text
signal). The IDA load base is auto-aligned to the ground-truth VAs.

Prereqs:
  1. Reload the IDA plugin so ``func_features`` / ``binary_fingerprint`` are
     registered (restart IDA; a running instance uses the pre-change build).
  2. Open ``bench/similarity/livetest/simbench_stripped.exe`` in IDA.

Run:
    python bench/similarity/harness/run_live_eval.py [instance_id_or_binary_substring]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from ida_multi_mcp.registry import InstanceRegistry          # noqa: E402
from ida_multi_mcp.router import InstanceRouter               # noqa: E402
from ida_multi_mcp.tools import similarity, index_store       # noqa: E402

GT_PATH = Path(__file__).resolve().parents[1] / "livetest" / "simbench.gt.json"

# Designed ground truth for simbench: (query, expected twins, expected non-matches)
GROUND_TRUTH = [
    ("sum_array", ["sum_array_while", "sum_array_ptr"], ["xor_array", "parse_kv", "fib"]),
    ("parse_kv", ["parse_kv_r"], ["parse_csv", "sum_array", "crc32_bitwise"]),
    ("crc32_bitwise", ["crc32_lut"], ["adler32", "fnv1a", "fib"]),
]
COMPARE = [
    ("sum_array", "sum_array_while", ">=", 0.55),   # refactor twin -> high
    ("sum_array", "fib", "<=", 0.40),               # unrelated -> low
]


def _err(resp):
    return isinstance(resp, dict) and "error" in resp


def _load_gt():
    if not GT_PATH.exists():
        return {}, {}
    raw = json.load(open(GT_PATH, encoding="utf-8"))["va2name"]
    va2name = {int(k, 16): v for k, v in raw.items()}
    name2va = {v: k for k, v in va2name.items()}
    return va2name, name2va


def _detect_delta(gt_vas, ida_addrs):
    """Offset between ground-truth VAs and IDA function addresses (0 if same base)."""
    ida_set = set(ida_addrs)

    def hits(d):
        return sum(1 for va in gt_vas if (va + d) in ida_set)

    if not gt_vas:
        return 0
    if hits(0) >= max(1, len(gt_vas) // 2):
        return 0
    best_d, best_c = 0, 0
    gt_min = min(gt_vas)
    for a in ida_addrs:                       # candidate: some IDA func == gt_min
        d = a - gt_min
        c = hits(d)
        if c > best_c:
            best_c, best_d = c, d
    return best_d


def _select_instance(registry, want):
    insts = registry.list_instances()
    if not insts:
        return None, insts
    for iid, info in insts.items():
        if iid == want or want.lower() in info.get("binary_name", "").lower():
            return iid, insts
    return next(iter(insts)), insts


def main() -> int:
    want = sys.argv[1] if len(sys.argv) > 1 else "simbench"
    va2name, name2va = _load_gt()

    registry = InstanceRegistry()
    router = InstanceRouter(registry)
    similarity.set_registry(registry)
    similarity.set_router(router)

    iid, insts = _select_instance(registry, want)
    if iid is None:
        print("FAIL: no IDA instances registered.")
        print("  -> Reload the plugin, then open simbench_stripped.exe in IDA.")
        return 1
    print(f"== instance {iid}  ({insts[iid].get('binary_name', '?')}) ==\n")

    # --- 1. build index ----------------------------------------------------
    res = similarity.index_functions({"instance_id": iid, "background": False})
    if _err(res):
        print(f"FAIL: index_functions -> {res['error']}")
        print("  -> Is the plugin reloaded? 'func_features' must be a registered tool.")
        return 1
    key = res.get("index_id")
    rp = registry.registry_path
    idx = index_store.read_index(key, rp) or {}
    funcs = idx.get("functions", {})
    ida_addrs = [int(a, 16) for a in funcs]
    delta = _detect_delta(list(va2name), ida_addrs)
    named = sum(1 for f in funcs.values() if f.get("is_named"))
    matched = sum(1 for va in va2name if (va + delta) in set(ida_addrs))
    print(f"[index] functions={res.get('function_count')} skipped={res.get('skipped_count')}")
    print(f"[index] is_named={named}/{len(funcs)}  (stripped => expect ~0 for our funcs)")
    print(f"[gt]    base delta={hex(delta)}  matched {matched}/{len(va2name)} truth functions\n")

    def resolve(addr_hex, ida_name):
        return va2name.get(int(addr_hex, 16) - delta, ida_name)

    def addr_for(name):
        va = name2va.get(name)
        return hex(va + delta) if va is not None else None

    # --- 2. retrieval ------------------------------------------------------
    r1 = r3 = total = 0
    print("== similar_functions (rank of designed twins; names via ground truth) ==")
    for q, twins, negs in GROUND_TRUTH:
        qaddr = addr_for(q)
        if not qaddr:
            print(f"  [skip] '{q}' not in ground truth")
            continue
        out = similarity.similar_functions(
            {"instance_id": iid, "func": qaddr, "top_k": 8})
        if _err(out):
            print(f"  [{q}] ERROR: {out['error']}")
            continue
        ranked = [(resolve(r["addr"], r["name"]), r["score"], r["signals"]) for r in out["results"]]
        rankpos = {nm: i + 1 for i, (nm, _, _) in enumerate(ranked)}
        total += 1
        best = min((rankpos[t] for t in twins if t in rankpos), default=None)
        r1 += (best == 1)
        r3 += (best is not None and best <= 3)
        twin_str = ", ".join(f"{t}@#{rankpos[t]}" if t in rankpos else f"{t}=MISS" for t in twins)
        neg_str = ", ".join(f"{n}@#{rankpos[n]}" if n in rankpos else f"{n}=absent" for n in negs)
        print(f"  [{'OK' if (best and best <= 3) else 'MISS'}] {q:14s} twins: {twin_str}"
              f"   | non-matches: {neg_str}")
        if ranked:
            nm, sc, sig = ranked[0]
            sigs = ", ".join(f"{k}={v:.2f}" for k, v in sig.items())
            print(f"                    top={nm} score={sc:.2f}  signals: {sigs}")

    print(f"\n[retrieval] Recall@1 = {r1}/{total}   Recall@3 = {r3}/{total}\n")

    # --- 3. pairwise -------------------------------------------------------
    print("== compare_functions (pairwise separation) ==")
    cmp_ok = 0
    for a, b, op, thr in COMPARE:
        aa, ba = addr_for(a), addr_for(b)
        if not aa or not ba:
            print(f"  [skip] {a} vs {b}")
            continue
        out = similarity.compare_functions(
            {"a": {"instance_id": iid, "func": aa}, "b": {"instance_id": iid, "func": ba}})
        if _err(out):
            print(f"  [{a} vs {b}] ERROR: {out['error']}")
            continue
        sc = out["score"]
        ok = (sc >= thr) if op == ">=" else (sc <= thr)
        cmp_ok += ok
        print(f"  [{'OK' if ok else 'FAIL'}] {a} vs {b}: score={sc:.2f} (want {op} {thr})")

    passed = total > 0 and r3 == total and cmp_ok == len(COMPARE)
    print(f"\n=== {'PASS' if passed else 'REVIEW'}: retrieval {r3}/{total} @3, "
          f"pairwise {cmp_ok}/{len(COMPARE)} ===")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
