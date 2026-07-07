#!/usr/bin/env python3
"""Fair jTrans cross-compiler eval via the EXISTING `disasm` tool (NO plugin reload).

IDA's `disasm` output already uses IDA-canonical mnemonics (jnz/retn), Intel
memory operands, IDA stack-var names and `loc_`/jump labels -- exactly what jTrans
was trained on. We tokenise that into jTrans tokens (so [UNK] collapses vs the
objdump approximation), embed both live binaries, and measure cross-compiler
nearest-neighbour recall over the full gallery.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
LIVE = Path(__file__).resolve().parents[1] / "livetest"

from ida_multi_mcp.registry import InstanceRegistry          # noqa: E402
from ida_multi_mcp.router import InstanceRouter               # noqa: E402
from ida_multi_mcp.tools import neural_backend, index_store   # noqa: E402
from ida_multi_mcp.tools.jtrans_norm import norm_op           # noqa: E402

GT = {"simbench_v2_clang": "simbench_v2_clang.gt.json", "simbench_v3": "simbench_v3.gt.json",
      "simbench_v2": "simbench_v2.gt.json", "simbench_stripped": "simbench.gt.json"}
ANCHORLESS = {"sum_array", "sum_array_while", "xor_array", "mix_o0"}
_SIZE = re.compile(r"\b(short|near|far|byte|word|dword|qword|xmmword|ymmword|tbyte)\b")


def _toks(lines):
    insns = []
    for ln in lines.split("\n"):
        m = re.match(r"^([0-9a-fA-F]+)\s+(\S+)\s*(.*)$", ln)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3)))
    a2i = {a: i for i, (a, _, _) in enumerate(insns)}
    out = []
    for a, mnem, ops in insns:
        out.append(mnem)
        if mnem[0] == "j" or mnem.startswith("loop"):
            mm = re.search(r"loc_([0-9A-Fa-f]+)", ops)
            if mm and int(mm.group(1), 16) in a2i:
                out.append("JUMP_ADDR_" + str(a2i[int(mm.group(1), 16)]))
                continue
        if mnem == "call":
            out.append("CONST")
            continue
        ops = _SIZE.sub("", ops).replace("ptr", "")
        for op in ops.split(","):
            op = op.strip()
            if op:
                out.append(norm_op(op))
    return out


def _parse(resp):
    if not isinstance(resp, dict) or resp.get("isError"):
        return None
    sc = resp.get("structuredContent")
    if sc is None:
        c = resp.get("content", [])
        try:
            sc = json.loads(c[0]["text"]) if c else None
        except Exception:
            return None
    return sc


def _disasm(router, iid, addr):
    sc = _parse(router.route_request("tools/call",
          {"name": "disasm", "arguments": {"addr": addr, "instance_id": iid}}))
    return (sc or {}).get("asm", {}).get("lines", "") if sc else ""


def _addrs(reg, router, iid):
    fp = _parse(router.route_request("tools/call",
          {"name": "binary_fingerprint", "arguments": {"instance_id": iid}}))
    if not fp:
        return []
    idx = index_store.read_index(fp["sha256"], reg.registry_path)
    return list(idx["functions"].keys()) if idx else []


def _gt_for(b):
    m = [k for k in GT if k in b.lower()]
    return GT[max(m, key=len)] if m else None


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
    print(f"query={qry} ({bins[qry]})  gallery={gal} ({bins[gal]})  disassembling...")

    def gather(iid):
        out = {}
        for a in _addrs(reg, router, iid):
            ln = _disasm(router, iid, a)
            if ln:
                out[a] = _toks(ln)
        return out

    tq, tg = gather(qry), gather(gal)
    if not tq or not tg:
        print("no functions/indexes found; run an ablation first to build indexes")
        return 1
    if not neural_backend.is_available():
        print("install the [neural] extra")
        return 1
    be = neural_backend.get_backend()
    print(f"[UNK] rate: query={be.unk_rate(list(tq.values())):.1%}  gallery={be.unk_rate(list(tg.values())):.1%}"
          f"   ({len(tq)} x {len(tg)} fns)")
    qn, gn = list(tq), list(tg)
    qv = dict(zip(qn, be.embed_batch([tq[a] for a in qn])))
    gv = dict(zip(gn, be.embed_batch([tg[a] for a in gn])))
    gtq = {int(k, 16): v for k, v in json.load(open(LIVE / _gt_for(bins[qry])))["va2name"].items()}
    gtg = {int(k, 16): v for k, v in json.load(open(LIVE / _gt_for(bins[gal])))["va2name"].items()}
    q_n2a = {v: hex(k) for k, v in gtq.items()}
    g_a2n = {hex(k): v for k, v in gtg.items()}
    shared = sorted((set(q_n2a) & set(gtg.values())) - {"main"})

    def cos(a, b):
        return sum(x * y for x, y in zip(a, b))

    r1 = r3 = 0
    print(f"\n== fair jTrans cross-compiler (IDA disasm tokens), shared twins = {len(shared)} ==")
    for nm in shared:
        qa = q_n2a.get(nm)
        if qa not in qv:
            continue
        ranked = sorted(((cos(qv[qa], gv[a]), a) for a in gv), reverse=True)
        rank = next((k + 1 for k, (s, a) in enumerate(ranked) if g_a2n.get(a) == nm), None)
        r1 += rank == 1
        r3 += bool(rank and rank <= 3)
        print(f"  {nm:16s} twin rank #{rank}{'  <-- anchor-less' if nm in ANCHORLESS else ''}")
    print(f"\njTrans (fair, IDA tokens): Recall@1={r1}/{len(shared)}  Recall@3={r3}/{len(shared)}")
    print("baselines: grouped R@3=6/10 ; objdump-jTrans (invalid, 37% UNK) R@3=4/10 ; general R@3=5/10")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
