"""Function-similarity feature extraction (IDA-side).

Produces the per-function ``FunctionFeature`` records consumed by the
server-side similarity indexer/search (see
``docs/plans/function-similarity/01-v1-production-design.md`` §3–§6). Every
signal here is name-independent so it survives stripping; the only exception,
``pseudo_tokens``, is gated on ``is_named`` (§5.5) so no decompilation cost is
paid for unnamed functions.

Reuses existing extraction primitives rather than re-implementing them:
- CFG metrics mirror ``func_profile`` (api_analysis) — ``idaapi.FlowChart`` +
  single-pass call-type xref counting.
- ``apis``/``strings``/``consts`` reuse ``get_callees`` /
  ``extract_function_strings`` / ``extract_function_constants`` (utils).
- instruction decoding reuses ``_decode_insn_at`` (api_analysis).

The MinHash signature is computed by the pure, stdlib ``sim_score.compute_minhash``
module (shared with the server so signatures compare across binaries).
"""

from __future__ import annotations

import re
from typing import Annotated, TypedDict

import ida_nalt
import idaapi
import idautils
import idc

from . import compat
from .api_analysis import _decode_insn_at
from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import (
    decompile_function_safe,
    extract_function_constants,
    extract_function_strings,
    get_callees,
    normalize_list_input,
    parse_address,
)
from ..tools.sim_score import compute_minhash
from ..tools.jtrans_norm import norm_op as _norm_op


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Page size cap for func_features. The expensive per-function extraction only
# runs over the page slice, never the whole binary (project memory: ~150K-func
# binaries time out on full scans).
_MAX_COUNT = 2000
_DEFAULT_COUNT = 500

# A name is "meaningful" unless it is empty or an auto-generated placeholder.
_UNNAMED_RE = re.compile(
    r"^(?:sub_|loc_|nullsub_|unknown_|j_|__imp_|off_|unk_|byte_|word_|dword_|qword_|locret_)"
)

# pseudo_tokens: identifier extraction from decompiled pseudocode.
_IDENT_RE = re.compile(r"[A-Za-z_]\w+")
_MAX_PSEUDO_TOKENS = 100
_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
    "int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
    "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "_Bool", "bool", "true", "false",
})

# Trivial immediate constants dropped from the const signal: 0/1/-1 and small
# values (|v| < 0x10) that are usually stack offsets, not distinguishing data.
_TRIVIAL_CONSTS = frozenset({0, 1, -1})
_SMALL_CONST_ABS = 0x10

# Processor names IDA reports for the x86/x64 family (arch derivation).
_X86_PROCS = frozenset({
    "metapc", "8086", "80286r", "80286p", "80386r", "80386p", "80486r",
    "80486p", "80586r", "80586p", "80686p", "p2", "p3", "p4", "athlon",
})


# ---------------------------------------------------------------------------
# Result schemas
# ---------------------------------------------------------------------------


class CfgFeatures(TypedDict):
    bb_count: int
    edge_count: int
    complexity: int
    loops: int
    callee_count: int
    caller_count: int
    out_deg_seq: list[int]


class FunctionFeature(TypedDict, total=False):
    addr: str
    name: str
    is_named: bool
    size: int
    cfg: CfgFeatures
    minhash: list[int]
    apis: list[str]
    strings: list[str]
    consts: list[str]
    pseudo_tokens: list[str]
    error: str


class FuncFeaturesResult(TypedDict):
    functions: list[FunctionFeature]
    total: int
    cursor: dict


class BinaryFingerprintResult(TypedDict):
    sha256: str | None
    md5: str | None
    function_count: int
    arch: str


# ---------------------------------------------------------------------------
# Internal helpers (called from within @idasync context)
# ---------------------------------------------------------------------------


def _is_named(name: str) -> bool:
    """True if the function has a meaningful symbol (§3 gate for pseudo_tokens)."""
    if not name:
        return False
    return _UNNAMED_RE.match(name) is None


def _op_class(op_type: int) -> str:
    """Map an operand type to its single-char normalization class (§5.1)."""
    if op_type == idaapi.o_reg:
        return "r"
    if op_type == idaapi.o_imm:
        return "i"
    if op_type == idaapi.o_mem:
        return "m"
    if op_type in (idaapi.o_displ, idaapi.o_phrase):
        return "d"
    if op_type in (idaapi.o_near, idaapi.o_far):
        return "c"
    return "x"


def _instruction_tokens(ea: int) -> list[str]:
    """Normalized instruction tokens ``mnem.opclasses`` for MinHash (§5.1)."""
    tokens: list[str] = []
    for iea in idautils.FuncItems(ea):
        insn = _decode_insn_at(iea)
        if insn is None:
            continue
        try:
            mnem = insn.get_canon_mnem()
        except Exception:
            mnem = ""
        classes: list[str] = []
        for op in insn.ops:
            if op.type == idaapi.o_void:
                break
            classes.append(_op_class(op.type))
        tokens.append(f"{mnem}.{''.join(classes)}")
    return tokens


def _cfg_features(ea: int, func: "idaapi.func_t") -> CfgFeatures:
    """Structural CFG feature vector (mirrors func_profile + §4.1 extras)."""
    fc = idaapi.FlowChart(func)
    bb_count = 0
    edge_count = 0
    loops = 0
    out_degs: list[int] = []
    for block in fc:
        bb_count += 1
        succ_count = 0
        for succ in block.succs():
            succ_count += 1
            # Back edge: successor at or before this block => a loop.
            if succ.start_ea <= block.start_ea:
                loops += 1
        edge_count += succ_count
        out_degs.append(succ_count)
    complexity = edge_count - bb_count + 2

    # Single pass over XrefsTo for call-type callers (mirrors func_profile).
    caller_count = 0
    for x in idautils.XrefsTo(ea, 0):
        if x.type in (idaapi.fl_CF, idaapi.fl_CN):
            caller_count += 1

    # Call-type xrefs from each instruction => callee edge count.
    callee_count = 0
    for item_ea in idautils.FuncItems(ea):
        for xref in idautils.XrefsFrom(item_ea, 0):
            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                callee_count += 1

    return {
        "bb_count": bb_count,
        "edge_count": edge_count,
        "complexity": complexity,
        "loops": loops,
        "callee_count": callee_count,
        "caller_count": caller_count,
        "out_deg_seq": sorted(out_degs, reverse=True),
    }


def _external_apis(ea: int) -> list[str]:
    """External (import/non-IDB) callee names, sorted and de-duplicated."""
    names = {
        c.get("name")
        for c in get_callees(hex(ea))
        if c.get("type") == "external" and c.get("name")
    }
    return sorted(names)


def _referenced_strings(ea: int) -> list[str]:
    """Referenced string contents, de-duplicated (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for s in extract_function_strings(ea):
        val = s.get("string")
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def _nontrivial_consts(ea: int) -> list[str]:
    """Non-trivial immediate constants as hex strings, de-duplicated.

    A sign-extended 32-bit immediate (``0xffffffff________`` with the low dword's
    high bit set) also contributes its unsigned 32-bit form, so the same logical
    constant matches whether a compiler sign- or zero-extended it -- v1 found the
    CRC polynomial 0xEDB88320 stored as 0xffffffffedb88320 in one function and
    absent in its Type-4 twin, so anchor matching missed it.
    """
    seen: set[str] = set()
    out: list[str] = []

    def add(v: int) -> None:
        h = hex(v)
        if h not in seen:
            seen.add(h)
            out.append(h)

    for c in extract_function_constants(ea):
        val = c.get("decimal")
        if not isinstance(val, int):
            continue
        if val in _TRIVIAL_CONSTS or abs(val) < _SMALL_CONST_ABS:
            continue
        add(val)
        if (val >> 32) == 0xFFFFFFFF and (val & 0x80000000):
            add(val & 0xFFFFFFFF)
    return out


def _pseudo_tokens(ea: int, own_name: str) -> list[str]:
    """Identifier tokens from pseudocode, minus C keywords and the own name.

    Gated on is_named by the caller; guards decompile failures by returning [].
    """
    try:
        code = decompile_function_safe(ea)
    except Exception:
        return []
    if not code:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for tok in _IDENT_RE.findall(code):
        if tok in _C_KEYWORDS or tok == own_name:
            continue
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
            if len(out) >= _MAX_PSEUDO_TOKENS:
                break
    return out


def _build_feature(ea: int, func: "idaapi.func_t") -> FunctionFeature:
    """Assemble the full FunctionFeature for a resolved function."""
    name = idaapi.get_func_name(ea) or ""
    named = _is_named(name)

    feature: FunctionFeature = {
        "addr": hex(ea),
        "name": name,
        "is_named": named,
        "size": func.end_ea - func.start_ea,
        "cfg": _cfg_features(ea, func),
        "minhash": compute_minhash(_instruction_tokens(ea)),
        "apis": _external_apis(ea),
        "strings": _referenced_strings(ea),
        "consts": _nontrivial_consts(ea),
    }

    if named:
        tokens = _pseudo_tokens(ea, name)
        if tokens:
            feature["pseudo_tokens"] = tokens

    return feature


def _feature_for_target(target) -> FunctionFeature:
    """Resolve a target (ea int or addr/name string) and extract its feature.

    Returns a per-item ``{"addr", "error"}`` record on any failure; never raises.
    """
    try:
        ea = target if isinstance(target, int) else parse_address(target)
    except Exception as exc:
        return {"addr": str(target), "error": str(exc)}

    func = idaapi.get_func(ea)
    if func is None:
        addr = hex(ea) if isinstance(target, int) else str(target)
        return {"addr": addr, "error": "No function found"}

    # Canonicalize to the function entry so features key on the entry point.
    ea = func.start_ea
    try:
        return _build_feature(ea, func)
    except Exception as exc:
        return {"addr": hex(ea), "error": str(exc)}


def _procname() -> str:
    """Processor name, across IDA 8.x/9.x. Returns '' on failure (never raises)."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_procname"):
            val = ida_ida.inf_get_procname()
            if isinstance(val, bytes):
                val = val.decode("utf-8", "replace")
            return val or ""
    except Exception:
        pass
    try:
        val = idaapi.get_inf_structure().procname
        if isinstance(val, bytes):
            val = val.decode("utf-8", "replace")
        return val or ""
    except Exception:
        return ""


def _arch() -> str:
    """Derive an arch label (e.g. 'x86_64', 'arm64', '<proc><bits>')."""
    proc = _procname().lower()
    is_64 = compat.inf_is_64bit()
    if proc in _X86_PROCS:
        return "x86_64" if is_64 else "x86"
    if proc.startswith("arm") or proc.startswith("aarch"):
        return "arm64" if is_64 else "arm"
    if proc:
        return f"{proc}{'64' if is_64 else '32'}"
    return "unknown64" if is_64 else "unknown32"


# ---------------------------------------------------------------------------
# Tool 1 — func_features
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0)
def func_features(
    addrs: Annotated[
        list[str] | str, "Function addresses (comma-separated or list), or '*' for all"
    ] = "*",
    offset: Annotated[int, "Skip first N functions (default: 0)"] = 0,
    count: Annotated[int, "Max functions per page (default: 500, max: 2000)"] = 500,
) -> FuncFeaturesResult:
    """Extract name-independent similarity features for functions, page by page.

    Per function returns: size, is_named, CFG metrics (bb/edge/complexity/loops/
    callee/caller counts + out-degree sequence), a 64-perm instruction-shingle
    MinHash, external API (import) callees, referenced strings, non-trivial
    immediate constants, and — only for named functions — pseudocode identifier
    tokens. Feed pages into the server-side similarity indexer. Use '*' to iterate
    all functions; only the page slice is analyzed so large binaries stay bounded.
    """
    if offset < 0:
        offset = 0
    if count <= 0 or count > _MAX_COUNT:
        count = _MAX_COUNT

    if isinstance(addrs, str) and addrs.strip() == "*":
        targets: list = list(idautils.Functions())
    else:
        targets = normalize_list_input(addrs)

    total = len(targets)
    page = targets[offset : offset + count]
    functions = [_feature_for_target(t) for t in page]

    next_off = offset + count
    cursor = {"next": next_off} if next_off < total else {"done": True}
    return {"functions": functions, "total": total, "cursor": cursor}


# ---------------------------------------------------------------------------
# Tool 2 — binary_fingerprint
# ---------------------------------------------------------------------------


@tool
@idasync
def binary_fingerprint() -> BinaryFingerprintResult:
    """Content fingerprint of the loaded binary for similarity index keying.

    Returns the input file's sha256 and md5 (hex, or null if unavailable), the
    total function count, and an arch label (e.g. 'x86_64'). The sha256 keys the
    per-binary similarity index so the same binary shares one index across
    instances; md5 is the fallback when sha256 is unavailable.
    """
    try:
        raw_sha = ida_nalt.retrieve_input_file_sha256()
        sha256 = raw_sha.hex() if raw_sha else None
    except Exception:
        sha256 = None

    try:
        raw_md5 = ida_nalt.retrieve_input_file_md5()
        md5 = raw_md5.hex() if raw_md5 else None
    except Exception:
        md5 = None

    function_count = sum(1 for _ in idautils.Functions())

    return {
        "sha256": sha256,
        "md5": md5,
        "function_count": function_count,
        "arch": _arch(),
    }


# ---------------------------------------------------------------------------
# Tool 3 — func_tokens (jTrans-style token streams for a neural BCSD backend)
# ---------------------------------------------------------------------------

# jTrans token stream = IDA-native mnemonics + normalised operands (see
# tools/jtrans_norm) + JUMP_ADDR_<idx> for intra-function jumps. P0b proved an
# objdump/byte reproduction cannot match jTrans's vocabulary (~37% [UNK]).
def _func_jtrans_tokens(ea: int) -> list[str]:
    """jTrans token stream for one function using IDA-native disassembly."""
    out: list[str] = []
    items = list(idautils.FuncItems(ea))
    a2i = {a: i for i, a in enumerate(items)}
    for a in items:
        mnem = idc.print_insn_mnem(a)
        if not mnem:
            continue
        out.append(mnem)
        if mnem[0] == "j" or mnem.startswith("loop"):
            tgt = idc.get_operand_value(a, 0)
            if tgt in a2i:
                out.append("JUMP_ADDR_" + str(a2i[tgt]))
                continue
        if mnem == "call":
            out.append("CONST")
            continue
        for i in range(8):
            op = idc.print_operand(a, i)
            if not op:
                break
            out.append(_norm_op(op))
    return out


@tool
@idasync
@tool_timeout(180.0)
def func_tokens(
    addrs: Annotated[
        list[str] | str, "Function addresses (comma-separated or list), or '*' for all"
    ] = "*",
    offset: Annotated[int, "Skip first N functions (default: 0)"] = 0,
    count: Annotated[int, "Max functions per page (default: 500, max: 2000)"] = 500,
) -> dict:
    """Emit jTrans-style normalized instruction token streams per function, for a
    neural BCSD embedding backend. Uses IDA's own operand normalization (registers
    kept, stack vars -> var_xxx/arg_xxx, imm/disp -> CONST, intra-function jumps ->
    JUMP_ADDR_<idx>) -- which a byte/objdump reproduction cannot match. Paginated
    like func_features; returns ``{addr: [token, ...]}``."""
    if offset < 0:
        offset = 0
    if count <= 0 or count > _MAX_COUNT:
        count = _MAX_COUNT
    if isinstance(addrs, str) and addrs.strip() == "*":
        targets: list = list(idautils.Functions())
    else:
        targets = normalize_list_input(addrs)
    total = len(targets)
    tokens: dict = {}
    for t in targets[offset:offset + count]:
        try:
            ea = t if isinstance(t, int) else parse_address(t)
            func = idaapi.get_func(ea)
            if func is None:
                continue
            tokens[hex(func.start_ea)] = _func_jtrans_tokens(func.start_ea)
        except Exception:
            continue
    next_off = offset + count
    cursor = {"next": next_off} if next_off < total else {"done": True}
    return {"tokens": tokens, "total": total, "cursor": cursor}
