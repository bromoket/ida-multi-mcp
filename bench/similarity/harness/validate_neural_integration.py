#!/usr/bin/env python3
"""End-to-end validation of the neural-recall integration in `similar_functions`.

Exercises the REAL production path -- index_functions stores jTrans vectors, then
similar_functions does neural cosine recall + blends it into the grouped score --
against the two live instances and the real jTrans-finetune model. Token source is
swapped to the `disasm` tool (proven, no plugin reload) by patching
`similarity._fetch_tokens` / `_query_vector`; everything else is the shipped code.

Env: JTRANS_MODEL / JTRANS_TOKENIZER must point at jTrans-finetune + jtrans_tokenizer.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
LIVE = Path(__file__).resolve().parents[1] / "livetest"

import json  # noqa: E402
from ida_multi_mcp.registry import InstanceRegistry  # noqa: E402
from ida_multi_mcp.router import InstanceRouter  # noqa: E402
from ida_multi_mcp.tools import similarity, neural_backend  # noqa: E402
import neural_xc_disasm as nx  # noqa: E402

os.environ["IDA_MCP_SIM_NEURAL"] = "1"

reg = InstanceRegistry()
router = InstanceRouter(reg)
similarity.set_registry(reg)
similarity.set_router(router)
similarity._NEURAL = True


def _tokens_via_disasm(iid):
    return {a: nx._toks(nx._disasm(router, iid, a))
            for a in nx._addrs(reg, router, iid) if nx._disasm(router, iid, a)}


def _query_vec_via_disasm(iid, addr):
    ln = nx._disasm(router, iid, addr)
    if not ln:
        return None
    vecs = neural_backend.get_backend().embed_batch([nx._toks(ln)])
    return vecs[0] if vecs else None


# USE_FUNC_TOKENS=1 exercises the shipped func_tokens path (needs a plugin reload);
# otherwise fall back to the proven disasm token source (no reload needed).
if os.environ.get("USE_FUNC_TOKENS") != "1":
    similarity._fetch_tokens = _tokens_via_disasm
    similarity._query_vector = lambda iid, addr: _query_vec_via_disasm(iid, addr) if similarity._neural_enabled() else None
else:
    print("(using shipped func_tokens path)")


def main():
    bins = {i: reg.get_instance(i).get("binary_name", "") for i in reg.list_instances()}
    sims = [i for i, b in bins.items() if "simbench" in b.lower()]
    if len(sims) < 2:
        print("need two simbench instances")
        return 1
    clang = next((i for i in sims if "clang" in bins[i].lower()), None)
    gcc = next(i for i in sims if i != clang)
    print(f"query={gcc} ({bins[gcc]})  gallery={clang} ({bins[clang]})")

    print("building neural index for gallery (clang)...")
    r = similarity.index_functions({"instance_id": clang, "background": False, "rebuild": True})
    print(f"  index: status={r.get('status')} funcs={r.get('function_count')} neural={r.get('neural')}")

    gt = {v: int(k, 16) for k, v in json.load(open(LIVE / nx._gt_for(bins[gcc])))["va2name"].items()}
    targets = ["sum_array", "sum_array_while", "xor_array", "fnv_loop", "parse_ipv4_a"]
    print("\n== integrated similar_functions (neural recall -> grouped+neural rerank) ==")
    hits = 0
    for nm in targets:
        va = gt.get(nm)
        if va is None:
            continue
        out = similarity.similar_functions({
            "instance_id": gcc, "func": hex(va), "scope": "instances",
            "instances": [clang], "top_k": 3})
        res = out.get("results", [])
        # rank of the true twin (same name) in clang
        gtg = {int(k, 16): v for k, v in json.load(open(LIVE / nx._gt_for(bins[clang])))["va2name"].items()}
        rank = next((i + 1 for i, r in enumerate(res)
                     if gtg.get(int(r["addr"], 16)) == nm), None)
        top = res[0] if res else {}
        ncos = top.get("signals", {}).get("neural")
        hits += bool(rank and rank <= 3)
        print(f"  {nm:16s} twin@top3=#{rank}  top={gtg.get(int(top.get('addr','0x0'),16),'?')}"
              f"  neural={ncos}")
    print(f"\nintegrated recall@3 (top3 contains twin): {hits}/{len(targets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
