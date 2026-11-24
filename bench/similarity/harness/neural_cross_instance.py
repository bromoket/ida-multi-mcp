#!/usr/bin/env python3
"""Fair cross-compiler jTrans eval (design 04 P1).

Pulls IDA-native jTrans tokens (the new ``func_tokens`` plugin tool) from two live
instances, embeds them with the neural backend, and measures cross-compiler
nearest-neighbour recall over the full gallery. This is the FAIR version of the
P0b probe: IDA tokenisation instead of objdump, so the [UNK] rate should collapse
from ~37% and the jTrans result becomes valid.

Prereqs: the plugin RELOADED (so ``func_tokens`` exists), two simbench instances
open, and the ``[neural]`` extra installed.
Run:
    python bench/similarity/harness/neural_cross_instance.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
LIVE = Path(__file__).resolve().parents[1] / "livetest"

from ida_multi_mcp.registry import InstanceRegistry          # noqa: E402
from ida_multi_mcp.router import InstanceRouter               # noqa: E402
from ida_multi_mcp.tools import neural_backend                # noqa: E402

GT = {"simbench_v2_clang": "simbench_v2_clang.gt.json", "simbench_v3": "simbench_v3.gt.json",
      "simbench_v2": "simbench_v2.gt.json", "simbench_stripped": "simbench.gt.json"}
ANCHORLESS = {"sum_array", "sum_array_while", "xor_array", "mix_o0"}


def _gt_for(binary):
    m = [k for k in GT if k in binary.lower()]
    return GT[max(m, key=len)] if m else None


def _tokens(router, iid):
    toks, off = {}, 0
    while True:
        resp = router.route_request("tools/call", {"name": "func_tokens",
                "arguments": {"instance_id": iid, "addrs": "*", "offset": off, "count": 500}})
        if not isinstance(resp, dict) or "error" in resp:
            return None
        c = resp.get("content", [])
        page = json.loads(c[0]["text"]) if c else resp.get("structuredContent")
        if not isinstance(page, dict) or "tokens" not in page:
            return None
        toks.update(page["tokens"])
        cur = page.get("cursor", {})
        if cur.get("done"):
            break
        off = cur.get("next", off + 500)
    return toks


def main() -> int:
    reg = InstanceRegistry()
    router = InstanceRouter(reg)
    bins = {i: reg.get_instance(i).get("binary_name", "") for i in reg.list_instances()}
    sims = [i for i, b in bins.items() if "simbench" in b.lower()]
    if len(sims) < 2:
        print(f"need two simbench instances; found {len(sims)}")
        return 1
    clang = next((i for i in sims if "clang" in bins[i].lower()), None)
    gal = clang or sims[1]
    qry = next(i for i in sims if i != gal)

    tq = _tokens(router, qry)
    tg = _tokens(router, gal)
    if tq is None or tg is None:
        print("func_tokens unavailable -- RELOAD the IDA plugin (it is a new tool).")
        return 1
    if not neural_backend.is_available():
        print("install the [neural] extra: pip install torch transformers")
        return 1

    be = neural_backend.get_backend()
    print(f"query={qry} ({bins[qry]}, {len(tq)} fns)  gallery={gal} ({bins[gal]}, {len(tg)} fns)")
    print(f"[UNK] rate: query={be.unk_rate(list(tq.values())):.1%}  gallery={be.unk_rate(list(tg.values())):.1%}")

    qn, gn = list(tq), list(tg)
    qv = dict(zip(qn, be.embed_batch([tq[a] for a in qn])))
    gv = dict(zip(gn, be.embed_batch([tg[a] for a in gn])))

    gtq = {int(k, 16): v for k, v in json.load(open(LIVE / _gt_for(bins[qry])))["va2name"].items()}
    gtg = {int(k, 16): v for k, v in json.load(open(LIVE / _gt_for(bins[gal])))["va2name"].items()}
    q_name2addr = {v: hex(k) for k, v in gtq.items()}
    g_addr2name = {hex(k): v for k, v in gtg.items()}
    shared = sorted((set(q_name2addr) & set(gtg.values())) - {"main"})

    def cos(a, b):
        return sum(x * y for x, y in zip(a, b))

    r1 = r3 = 0
    print(f"\n== fair jTrans cross-compiler (IDA tokens), shared twins = {len(shared)} ==")
    for nm in shared:
        qa = q_name2addr.get(nm)
        if qa not in qv:
            continue
        ranked = sorted(((cos(qv[qa], gv[a]), a) for a in gv), reverse=True)
        rank = next((k + 1 for k, (s, a) in enumerate(ranked) if g_addr2name.get(a) == nm), None)
        r1 += rank == 1
        r3 += bool(rank and rank <= 3)
        mark = "  <-- anchor-less" if nm in ANCHORLESS else ""
        print(f"  {nm:16s} twin rank #{rank}{mark}")
    print(f"\njTrans (fair, IDA tokens): Recall@1={r1}/{len(shared)}  Recall@3={r3}/{len(shared)}")
    print("baselines: non-neural grouped R@3=6/10 ; objdump-jTrans (invalid, 37% UNK) R@3=4/10")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
