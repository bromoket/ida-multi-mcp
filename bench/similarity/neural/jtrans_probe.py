#!/usr/bin/env python3
"""P0b: probe a REAL BCSD model (jTrans) on the cross-compiler task.

The general embedder (probe.py) validated that neural recall surfaces anchor-less
functions but lacks discrimination. jTrans is a jump-aware BERT trained
contrastively to be optimisation/compiler-invariant. This reproduces (approximately)
its input normalisation from objdump Intel syntax:
  - Intel mnemonics + registers kept
  - immediates / displacements -> CONST
  - memory -> [base+index*scale+CONST]
  - intra-function jumps -> JUMP_ADDR_<target-instruction-index>
then embeds each function (mean-pooled last hidden state) and reports the
cross-compiler full-gallery nearest-neighbour recall. Prints the [UNK] token rate
so we can see how well our normalisation matches jTrans's vocabulary.
"""

import re
import subprocess
import sys
from pathlib import Path

LIVE = Path(__file__).resolve().parents[1] / "livetest"
GCC = LIVE / "simbench_v3.exe"
CLANG = LIVE / "simbench_v2_clang.exe"
SHARED = ["fnv_loop", "fnv_unrolled", "mix_o0", "mix_o2", "parse_ipv4_a",
          "parse_ipv4_b", "sum_array", "sum_array_while", "vm_exec", "xor_array"]
ANCHORLESS = {"sum_array", "sum_array_while", "xor_array", "mix_o0"}
MODEL = "PurCL/jtrans-mfc"
_JCC = re.compile(r"^(jmp|je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|js|jns|jo|jno|jp|jnp|jc|jnc|jnb|jnbe|jnl|jnle|loop\w*)$")
# objdump (AT&T/GAS) mnemonic -> IDA canonical form that jTrans's vocab uses.
_MNEM_MAP = {"je": "jz", "jne": "jnz", "jae": "jnb", "jnae": "jb", "jc": "jb",
             "jnc": "jnb", "jna": "jbe", "jnbe": "ja", "jng": "jle", "jnge": "jl",
             "jnl": "jge", "jnle": "jg", "ret": "retn", "retq": "retn"}
_SKIP = {"data16"}  # padding prefixes jTrans drops


def _norm_mem(inner):
    # jTrans keeps the index *scale (2/4/8); only the displacement becomes CONST.
    inner = re.sub(r"0x[0-9a-fA-F]+", "CONST", inner)     # hex displacement
    inner = re.sub(r"([+\-])\s*\d+\b", r"\1CONST", inner)  # decimal displacement, keep *scale
    return f"[{inner}]"


def _norm_op(op):
    op = op.strip()
    op = re.sub(r"\b(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD|TBYTE) PTR ", "", op)
    op = op.replace("PTR ", "")
    m = re.search(r"\[(.*)\]", op)
    if m:
        return _norm_mem(m.group(1))
    if re.match(r"^(0x[0-9a-fA-F]+|\d+)$", op):
        return "CONST"
    return op


def func_tokens(exe):
    """name -> list of jTrans-style tokens."""
    out = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", str(exe)],
                         capture_output=True, text=True).stdout
    funcs = {}
    cur = None
    insns = []  # (addr, mnem, operand_str)
    order = []

    def flush():
        if not cur:
            return
        addr2idx = {a: i for i, (a, _, _) in enumerate(insns)}
        toks = []
        for a, mnem, ops in insns:
            if mnem in _SKIP:
                continue
            mnem = _MNEM_MAP.get(mnem, mnem)
            toks.append(mnem)
            if _JCC.match(mnem):
                t = re.match(r"^([0-9a-f]+)", ops.strip())
                if t and int(t.group(1), 16) in addr2idx:
                    toks.append(f"JUMP_ADDR_{addr2idx[int(t.group(1), 16)]}")
                else:
                    toks.append("CONST")
            elif mnem == "call":
                toks.append("CONST")
            else:
                for op in ops.split(","):
                    if op.strip():
                        toks.append(_norm_op(op))
        funcs[cur] = toks

    for line in out.splitlines():
        h = re.match(r"^[0-9a-f]+ <(\w+)>:", line)
        if h:
            flush()
            cur, insns = h.group(1), []
            continue
        m = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*?)(?:\s+<.*>)?$", line)
        if m and cur is not None:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3)))
    flush()
    return funcs


def main():
    import torch
    from transformers import AutoTokenizer, AutoConfig, BertModel
    tok = AutoTokenizer.from_pretrained(MODEL)
    cfg = AutoConfig.from_pretrained(MODEL)
    cfg.max_position_embeddings = 2902   # jTrans ties positions to vocab (jump-aware)
    model = BertModel.from_pretrained(MODEL, config=cfg, ignore_mismatched_sizes=True,
                                      add_pooling_layer=False)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(dev).eval()

    gf, cf = func_tokens(GCC), func_tokens(CLANG)

    def embed(funcs):
        names = [n for n, t in funcs.items() if len(t) >= 2]
        vecs, unk, tot = {}, 0, 0
        with torch.no_grad():
            for n in names:
                text = " ".join(funcs[n])
                enc = tok(text, return_tensors="pt", truncation=True, max_length=512)
                ids = enc["input_ids"][0]
                unk += int((ids == tok.unk_token_id).sum())
                tot += len(ids)
                v = model(**{k: x.to(dev) for k, x in enc.items()}).last_hidden_state[0, 0]  # [CLS]
                vecs[n] = torch.nn.functional.normalize(v, dim=0).cpu()
        return vecs, unk, tot

    gv, gu, gt = embed(gf)
    cv, cu, ct = embed(cf)
    print(f"model={MODEL}  [UNK] rate: gcc {gu}/{gt}={gu/gt:.1%}  clang {cu}/{ct}={cu/ct:.1%}")
    shared = [f for f in SHARED if f in gv and f in cv]
    print(f"full gallery: gcc {len(gv)} fns x clang {len(cv)} fns; shared twins={len(shared)}\n")
    r1 = r3 = 0
    for f in shared:
        sims = sorted(((float(torch.dot(gv[f], cv[n])), n) for n in cv), reverse=True)
        rank = next((k + 1 for k, (s, n) in enumerate(sims) if n == f), None)
        r1 += rank == 1
        r3 += rank <= 3
        mark = "  <-- anchor-less" if f in ANCHORLESS else ""
        print(f"  {f:16s} twin rank #{rank}  nn={sims[0][1]}({sims[0][0]:.2f}){mark}")
    print(f"\njTrans full-gallery cross-compiler: Recall@1={r1}/{len(shared)} Recall@3={r3}/{len(shared)}")
    print("baselines: non-neural grouped R@3=6/10 ; general-embedder R@3=5/10")
    return 0


if __name__ == "__main__":
    sys.exit(main())
