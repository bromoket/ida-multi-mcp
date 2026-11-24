#!/usr/bin/env python3
"""Cross-instance (cross-compiler) similarity eval.

Matches functions across TWO live IDA instances via
``similar_functions(scope='instances')`` -- the project's headline multi-instance
capability AND the cross-compiler axis, both previously untested live. Any two
registered ``simbench*`` instances work; each is mapped to its own ground truth,
and the shared function names (identical source, different build) are the
cross-compiler twin set. Reports Recall@1/@3 for the production grouped scorer
and for the flat shape-heavy weights.

Prereqs: two simbench instances open (e.g. a gcc build and a clang build).
Run:
    python bench/similarity/harness/run_cross_instance.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
LIVE = Path(__file__).resolve().parents[1] / "livetest"

from ida_multi_mcp.registry import InstanceRegistry          # noqa: E402
from ida_multi_mcp.router import InstanceRouter               # noqa: E402
from ida_multi_mcp.tools import similarity, index_store, sim_score  # noqa: E402

# Binary-name substring -> ground-truth file (longest match wins).
GT_BY_BINARY = {
    "simbench_v2_clang": "simbench_v2_clang.gt.json",
    "simbench_v3":       "simbench_v3.gt.json",
    "simbench_v2":       "simbench_v2.gt.json",
    "simbench_stripped": "simbench.gt.json",
}


def _gt_for(binary_name):
    m = [k for k in GT_BY_BINARY if k in binary_name.lower()]
    return GT_BY_BINARY[max(m, key=len)] if m else None


def _load_gt(fname):
    return {int(k, 16): v for k, v in
            json.load(open(LIVE / fname, encoding="utf-8"))["va2name"].items()}


def _delta(gt_vas, ida_addrs):
    s = set(ida_addrs)
    hit = lambda d: sum(1 for va in gt_vas if va + d in s)
    if not gt_vas or hit(0) >= len(gt_vas) // 2:
        return 0
    gmin = min(gt_vas)
    best_d, best_c = 0, 0
    for a in ida_addrs:
        c = hit(a - gmin)
        if c > best_c:
            best_d, best_c = a - gmin, c
    return best_d


def _prep(reg, iid):
    """Index an instance and return (functions, name->addr, addr->name)."""
    rp = reg.registry_path
    idx = index_store.read_index(
        similarity.index_functions({"instance_id": iid, "background": False})["index_id"], rp)
    funcs = idx["functions"]
    binary = reg.get_instance(iid).get("binary_name", "")
    gt = _load_gt(_gt_for(binary))
    d = _delta(list(gt), [int(a, 16) for a in funcs])
    return funcs, {v: hex(k + d) for k, v in gt.items()}, {hex(k + d): v for k, v in gt.items()}, binary


def main() -> int:
    reg = InstanceRegistry()
    similarity.set_registry(reg)
    similarity.set_router(InstanceRouter(reg))
    sims = [i for i, v in reg.list_instances().items() if "simbench" in v.get("binary_name", "").lower()]
    if len(sims) < 2:
        print(f"Need two simbench instances open; found {len(sims)}: "
              f"{[reg.get_instance(i).get('binary_name') for i in sims]}")
        return 1
    # query side = the non-clang instance; gallery side = the clang one (or 2nd)
    clang = next((i for i in sims if "clang" in reg.get_instance(i).get("binary_name", "").lower()), None)
    gal = clang or sims[1]
    qry = next(i for i in sims if i != gal)

    fq, q_name2addr, _, qbin = _prep(reg, qry)
    fg, _, g_addr2name, gbin = _prep(reg, gal)
    shared = sorted((set(q_name2addr) & set(g_addr2name.values())) - {"main"})

    print(f"query  = {qry} ({qbin}, {len(fq)} fns)")
    print(f"gallery= {gal} ({gbin}, {len(fg)} fns)")
    print(f"shared (cross-build twins) = {len(shared)}: {shared}\n")
    print("== match a query-binary function to its twin in the gallery binary ==")

    for label, weights in (("grouped (production)", None),
                           ("flat shape-heavy", dict(sim_score.DEFAULT_WEIGHTS))):
        r1 = r3 = tot = 0
        misses = []
        for name in shared:
            qa = q_name2addr.get(name)
            if qa not in fq:
                continue
            args = {"instance_id": qry, "func": qa, "scope": "instances",
                    "instances": [gal], "top_k": 8}
            if weights:
                args["weights"] = weights
            out = similarity.similar_functions(args)
            ranks = [g_addr2name.get(r["addr"]) for r in out.get("results", [])]
            rk = next((i + 1 for i, nm in enumerate(ranks) if nm == name), None)
            tot += 1
            r1 += rk == 1
            r3 += bool(rk and rk <= 3)
            if not (rk and rk <= 3):
                misses.append(f"{name}(#{rk})")
        tail = f"  misses: {', '.join(misses)}" if misses else ""
        print(f"  [{label:22s}] Recall@1={r1}/{tot}  Recall@3={r3}/{tot}{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
