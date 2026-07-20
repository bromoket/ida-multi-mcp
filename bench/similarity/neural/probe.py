#!/usr/bin/env python3
"""P0 neural probe (design 04, Phase 0).

Question: can an embedding place cross-compiler function twins as nearest
neighbours -- ESPECIALLY the anchor-less ones (e.g. sum_array: gcc scalar loop vs
clang SSE2-vectorised) that the non-neural pipeline provably cannot match
(candidate-gen never surfaces them)?

Self-contained: disassembles the shared functions from the on-disk gcc & clang
builds (objdump, by symbol), normalises each to a `mnemonic_operandclasses` token
stream, embeds with a pluggable model, and reports cross-compiler nearest-neighbour
recall over the shared set.

The default model (a small general sentence embedder) is a LEXICAL LOWER BOUND: it
should match the anchored / lexically-similar functions but FAIL the anchor-less
vectorised ones -- which would confirm that a purpose-trained BCSD model (jTrans)
is required, not any embedding. Set SIM_PROBE_MODEL to try another HF model.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

LIVE = Path(__file__).resolve().parents[1] / "livetest"
GCC = LIVE / "simbench_v3.exe"
CLANG = LIVE / "simbench_v2_clang.exe"
SHARED = ["fnv_loop", "fnv_unrolled", "mix_o0", "mix_o2", "parse_ipv4_a",
          "parse_ipv4_b", "sum_array", "sum_array_while", "vm_exec", "xor_array"]
ANCHORLESS = {"sum_array", "sum_array_while", "xor_array", "mix_o0"}  # the live misses
MODEL = os.environ.get("SIM_PROBE_MODEL", "sentence-transformers/all-MiniLM-L6-v2")


def disasm_funcs(exe):
    out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                         capture_output=True, text=True).stdout
    funcs, cur, toks = {}, None, []
    for line in out.splitlines():
        h = re.match(r"^[0-9a-f]+ <(\w+)>:", line)
        if h:
            if cur:
                funcs[cur] = toks
            cur, toks = h.group(1), []
            continue
        m = re.match(r"^\s+[0-9a-f]+:\s+(\S+)\s*(.*)$", line)
        if m and cur is not None:
            mnem, ops = m.group(1), m.group(2)
            cls = []
            for op in ops.split(","):
                op = op.strip()
                if not op:
                    continue
                if op.startswith("%"):
                    cls.append("r")
                elif op.startswith("$"):
                    cls.append("i")
                elif "(" in op:
                    cls.append("m")
                elif re.match(r"^[0-9a-fx]+$", op):
                    cls.append("a")
                else:
                    cls.append("x")
            toks.append(mnem + ("_" + "".join(cls) if cls else ""))
    if cur:
        funcs[cur] = toks
    return funcs


def embed_texts(texts):
    import torch
    from transformers import AutoTokenizer, AutoModel
    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModel.from_pretrained(MODEL)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(dev).eval()
    vecs = []
    with torch.no_grad():
        for t in texts:
            enc = tok(t, return_tensors="pt", truncation=True, max_length=512).to(dev)
            v = model(**enc).last_hidden_state.mean(1)[0]
            vecs.append(torch.nn.functional.normalize(v, dim=0).cpu())
    return vecs


def main():
    gf, cf = disasm_funcs(GCC), disasm_funcs(CLANG)
    shared = [f for f in SHARED if f in gf and f in cf]
    print(f"model = {MODEL}")
    print(f"shared functions = {len(shared)}: {shared}")
    print("insn counts (gcc / clang):",
          {f: (len(gf[f]), len(cf[f])) for f in shared})
    import torch
    gv = embed_texts([" ".join(gf[f]) for f in shared])
    cv = embed_texts([" ".join(cf[f]) for f in shared])
    r1 = r3 = 0
    print("\n== cross-compiler nearest neighbour (gcc func -> clang func) ==")
    for i, f in enumerate(shared):
        sims = sorted(((float(torch.dot(gv[i], cv[j])), shared[j])
                       for j in range(len(shared))), reverse=True)
        rank = next((k + 1 for k, (s, nm) in enumerate(sims) if nm == f), None)
        r1 += rank == 1
        r3 += rank <= 3
        mark = "  <-- ANCHOR-LESS (the miss)" if f in ANCHORLESS else ""
        print(f"  {f:16s} twin rank #{rank}  nn={sims[0][1]}({sims[0][0]:.2f}){mark}")
    print(f"\ncross-compiler NN  Recall@1 = {r1}/{len(shared)}   Recall@3 = {r3}/{len(shared)}")
    al = [f for f in shared if f in ANCHORLESS]
    print("anchor-less subset (the functions the non-neural pipeline cannot match): "
          + ", ".join(al))
    return 0


if __name__ == "__main__":
    sys.exit(main())
