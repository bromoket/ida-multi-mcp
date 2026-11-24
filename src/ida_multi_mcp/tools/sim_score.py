"""Pure-stdlib similarity scoring core for ida-multi-mcp.

Implements the name-independent function-similarity math from
``docs/plans/function-similarity/01-v1-production-design.md`` (sections 4, 5,
11): instruction-shingle MinHash, IDF-weighted anchor Jaccard, CFG
z-normalized similarity, symbol-gated final scoring, and LSH + anchor
candidate generation.

This module is deliberately dependency-free (stdlib only: ``hashlib``,
``math``, ``statistics``) and free of any ``idaapi`` / server imports, so it is
importable and unit-testable standalone.  All hashing uses blake2b and is
therefore reproducible across processes -- the builtin ``hash()`` (which is
salted per process) is never used, so MinHash/LSH signatures compare across
binaries and runs.

A "feature record" is a ``FunctionFeature`` dict (design section 4.1)::

    {"addr": "0x401000", "name": "sub_401000", "is_named": False,
     "size": 213,
     "cfg": {"bb_count": 7, "edge_count": 9, "complexity": 4, "loops": 1,
             "callee_count": 3, "caller_count": 2, "out_deg_seq": [...]},
     "minhash": [<64 ints>],          # or [] when the function is too small
     "apis": [...], "strings": [...], "consts": [...],
     "pseudo_tokens": [...]}          # present only when is_named
"""

from __future__ import annotations

import hashlib
import math
import statistics

# --- Config defaults (design section 11) --------------------------------
M = 64
K = 4
BANDS = 16
ROWS = 4
CAND_CAP = 2000

# Scoring version (bumped when the signal set or default weights change);
# recorded in eval results so runs are comparable across iterations.
SCORING_VERSION = "v5"

DEFAULT_WEIGHTS = {
    "ngram": 0.13,
    "cfg": 0.13,
    "shape": 0.28,   # v4: shape needs ~0.30 weight to recover cross-opt twins that
                     #     disagreeing lexical/scalar-structure signals drown out
                     #     (v3's 0.14 under-weighted it). Tuned on a small corpus;
                     #     re-tune on the production-scale oracle before finalizing.
    "api": 0.13,
    "str": 0.13,
    "const": 0.13,   # raised from v1's 0.10 (v2 showed const underweighted for Type-4)
    "text": 0.07,    # low (usually gated off on stripped binaries)
}

# Grouped (production) scoring: an equal-weight, applicability-gated content
# consensus (structure + anchors), then modulated by CFG shape at SHAPE_LAMBDA.
SHAPE_LAMBDA = 0.30
_CONTENT_WEIGHTS = {"ngram": 1.0, "cfg": 1.0, "api": 1.0, "str": 1.0, "const": 1.0, "text": 1.0}

CFG_FEATS = [
    "bb_count",
    "edge_count",
    "complexity",
    "loops",
    "size",
    "callee_count",
    "caller_count",
]

# MinHash affine-permutation modulus (Mersenne prime 2**61 - 1).
P = (1 << 61) - 1


def hash64(s: str | bytes) -> int:
    """Return the 8-byte blake2b digest of ``s`` as an unsigned integer."""
    data = s.encode("utf-8") if isinstance(s, str) else s
    return int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")


# Deterministic per-permutation coefficients, derived once at import time from
# the permutation index so signatures are comparable across binaries/processes.
# a[j] in [1, P-1] (never 0 -> a valid multiplier); b[j] in [0, P-1].
_A: list[int] = [1 + (hash64(f"a{j}") % (P - 1)) for j in range(M)]
_B: list[int] = [hash64(f"b{j}") % P for j in range(M)]


def shingles(tokens: list[str], k: int = K) -> set[int]:
    """Return the set of ``hash64`` values of every contiguous ``k``-gram.

    Each k-gram is joined with ``"|"`` before hashing.  Returns an empty set
    when there are fewer than ``k`` tokens (the ngram signal is unavailable).
    """
    if len(tokens) < k:
        return set()
    return {
        hash64("|".join(tokens[i:i + k]))
        for i in range(len(tokens) - k + 1)
    }


def compute_minhash(tokens: list[str]) -> list[int]:
    """Return the ``M``-length MinHash signature of ``tokens``.

    Returns ``[]`` when the token stream is too short to produce any shingle.
    """
    sh = shingles(tokens)
    if not sh:
        return []
    return [min((_A[j] * s + _B[j]) % P for s in sh) for j in range(M)]


def jaccard_minhash(sig_a: list[int], sig_b: list[int]) -> float:
    """Estimate Jaccard similarity as the fraction of matching positions.

    Returns ``0.0`` if either signature is empty or the lengths differ.
    """
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for x, y in zip(sig_a, sig_b) if x == y)
    # Divide by the actual signature length (== M for current indexes) rather
    # than the module constant, so a future M change or an older on-disk
    # signature cannot silently skew the estimate.
    return matches / len(sig_a)


def widf_jaccard(
    sa: set[str], sb: set[str], df: dict[str, int], n: int
) -> float:
    """IDF-weighted Jaccard over two anchor sets.

    Weight of an anchor ``x`` is ``max(0, log(n / (1 + df[x])))`` so rare anchors
    (low document frequency) weigh more and non-discriminative anchors (df ~ n)
    contribute nothing. Returns ``0.0`` when the union is empty. When every union
    weight is zero (degenerate: tiny corpus, or all anchors are ubiquitous), falls
    back to plain set Jaccard so identical anchor sets still score 1.0 instead of
    dividing by zero.
    """
    n = max(1, n)  # guard math.log domain; real callers pass >=1, but be safe.
    union = sa | sb
    if not union:
        return 0.0
    inter = sa & sb

    def w(x: str) -> float:
        return max(0.0, math.log(n / (1 + df.get(x, 0))))

    denom = sum(w(x) for x in union)
    if denom <= 0.0:
        return len(inter) / len(union)
    return sum(w(x) for x in inter) / denom


def _cfg_feat(rec: dict, feat: str) -> float:
    """Read a single CFG feature value from a record (``size`` is top-level)."""
    if feat == "size":
        return float(rec["size"])
    return float(rec["cfg"][feat])


def zstats_of(records: list[dict]) -> dict:
    """Compute per-feature ``{"mean", "std"}`` over ``CFG_FEATS``.

    ``size`` is read from ``rec["size"]``; the remaining features from
    ``rec["cfg"]``.  Uses population standard deviation, so a single record (or
    a constant feature) yields ``std == 0.0`` rather than raising.
    """
    stats: dict = {}
    for feat in CFG_FEATS:
        values = [_cfg_feat(rec, feat) for rec in records]
        if values:
            mean = statistics.fmean(values)
            std = statistics.pstdev(values)
        else:
            mean = 0.0
            std = 0.0
        stats[feat] = {"mean": float(mean), "std": float(std)}
    return stats


def cfg_sim(rec_a: dict, rec_b: dict, zstats: dict) -> float:
    """Structural CFG similarity: ``exp(-mean(|z_a - z_b|))`` over ``CFG_FEATS``.

    Identical profiles score ``1.0``.  A feature whose ``std == 0`` contributes
    ``0`` (both z-scores are treated as ``0``), which also avoids a divide by
    zero.
    """
    def z(rec: dict, feat: str) -> float:
        s = zstats[feat]
        if s["std"] == 0:
            return 0.0
        return (_cfg_feat(rec, feat) - s["mean"]) / s["std"]

    d = sum(abs(z(rec_a, f) - z(rec_b, f)) for f in CFG_FEATS) / len(CFG_FEATS)
    return math.exp(-d)


def _deg_hist(feat: dict) -> list[float]:
    """Normalized out-degree histogram [deg0, deg1, deg2, deg>=3] of a CFG."""
    seq = (feat.get("cfg") or {}).get("out_deg_seq") or []
    h = [0, 0, 0, 0]
    for d in seq:
        h[min(int(d), 3)] += 1
    total = sum(h) or 1
    return [x / total for x in h]


def shape_sim(rec_a: dict, rec_b: dict) -> float:
    """CFG branching-shape similarity from out-degree distributions, in [0, 1].

    More robust to optimization-level codegen differences than scalar CFG metrics
    or the instruction lexicon: the v2 ablation showed it recovers cross-opt
    (-O0 vs -O2) twins that structure+anchors alone miss. ``1.0`` == identical
    out-degree distribution.
    """
    ha, hb = _deg_hist(rec_a), _deg_hist(rec_b)
    return 1.0 - 0.5 * sum(abs(x - y) for x, y in zip(ha, hb))


def df_of(records: list[dict], field: str) -> dict[str, int]:
    """Document frequency of each anchor in ``field`` (one count per record).

    ``field`` is one of ``"apis"``, ``"strings"``, ``"consts"``.
    """
    df: dict[str, int] = {}
    for rec in records:
        for item in set(rec[field]):
            df[item] = df.get(item, 0) + 1
    return df


def _plain_jaccard(sa: set[str], sb: set[str]) -> float:
    """Plain (unweighted) set Jaccard; ``0.0`` when both sets are empty."""
    union = sa | sb
    if not union:
        return 0.0
    return len(sa & sb) / len(union)


# Feature field each anchor signal reads; a signal is "applicable" to a pair
# only when at least one side actually has that feature (else comparing 0 is
# meaningless and would only dilute the score).
_SIGNAL_FIELD = {"api": "apis", "str": "strings", "const": "consts"}


def _applicable(signal: str, a: dict, b: dict) -> bool:
    """Whether *signal* is meaningful for this pair (drives denominator gating)."""
    if signal == "cfg":
        return True                                  # every function has a CFG
    if signal == "ngram":
        return bool(a["minhash"]) and bool(b["minhash"])
    if signal == "shape":
        return bool((a.get("cfg") or {}).get("out_deg_seq")) and \
            bool((b.get("cfg") or {}).get("out_deg_seq"))
    if signal == "text":
        return bool(a.get("is_named")) and bool(b.get("is_named"))
    field = _SIGNAL_FIELD[signal]
    return bool(a.get(field)) or bool(b.get(field))


def score(
    a: dict,
    b: dict,
    df: dict,
    zstats: dict,
    n: int,
    weights: dict = DEFAULT_WEIGHTS,
) -> tuple[float, dict]:
    """Score two feature records, returning ``(final, signals)``.

    ``signals`` always carries ``ngram/api/str/const/cfg``.  ``text`` (plain
    Jaccard of pseudocode tokens) is added -- and weighted -- only when BOTH
    records are named; otherwise its weight is dropped and the remaining
    weights renormalize.  ``df`` is a dict with keys ``apis``/``strings``/
    ``consts``, each mapping to a document-frequency dict.
    """
    signals = {
        "ngram": jaccard_minhash(a["minhash"], b["minhash"]),
        "api": widf_jaccard(set(a["apis"]), set(b["apis"]), df["apis"], n),
        "str": widf_jaccard(
            set(a["strings"]), set(b["strings"]), df["strings"], n
        ),
        "const": widf_jaccard(
            set(a["consts"]), set(b["consts"]), df["consts"], n
        ),
        "cfg": cfg_sim(a, b, zstats),
    }

    if _applicable("shape", a, b):
        signals["shape"] = shape_sim(a, b)
    if a["is_named"] and b["is_named"]:
        signals["text"] = _plain_jaccard(
            set(a.get("pseudo_tokens", [])),
            set(b.get("pseudo_tokens", [])),
        )

    # Weight only signals that are both requested AND applicable to this pair.
    # Applicability drops a signal's weight from the denominator when neither
    # side has that feature, so anchor-less functions are not diluted (two
    # identical anchor-free functions score ~1.0, not 0.5). It also gates "text"
    # off when unnamed and ignores unrecognized weight keys (a typo'd "string").
    active = {k: v for k, v in weights.items()
              if k in signals and _applicable(k, a, b)}
    denom = sum(active.values())
    if denom == 0:
        final = 0.0
    else:
        final = sum(active[k] * signals[k] for k in active) / denom
    return final, signals


def score_grouped(a, b, df, zstats, n, shape_lambda: float = SHAPE_LAMBDA) -> tuple[float, dict]:
    """Two-stage production scoring: an equal-weight, applicability-gated
    structure+anchor *content* consensus, then modulated by CFG shape.

    Keeping the content signals in their own renormalized group lets a
    discriminative anchor (e.g. a shared rare constant) dominate before shape
    adjusts -- which recovers cross-optimization twins that a single flat
    weighting dilutes (v2 corpus ablation: grouped reaches Recall@1 1.0 where
    the best flat weighting plateaus at 0.8). Returns ``(final, signals)`` with
    the same breakdown as :func:`score`, plus ``shape`` when applicable.
    """
    content, signals = score(a, b, df, zstats, n, _CONTENT_WEIGHTS)
    if "shape" in signals:                       # applicable -> modulate
        final = (1.0 - shape_lambda) * content + shape_lambda * signals["shape"]
    else:
        final = content
    return final, signals


def confidence(final: float, signals: dict) -> str:
    """Map a final score + signal breakdown to ``"high"``/``"medium"``/``"low"``.

    ``high`` when ``final >= 0.75`` and at least two signals exceed ``0.5``;
    else ``medium`` when ``final >= 0.5``; else ``low``.
    """
    strong = sum(1 for v in signals.values() if v > 0.5)
    if final >= 0.75 and strong >= 2:
        return "high"
    if final >= 0.5:
        return "medium"
    return "low"


def _band_key(sig: list[int], band: int) -> str:
    """Bucket key for one LSH band of a signature (hex of the band's hash)."""
    rows = tuple(sig[band * ROWS:(band + 1) * ROWS])
    return format(hash64(str(rows)), "x")


def build_lsh(records: list[dict]) -> dict:
    """Build the LSH index ``{str(band): {bucket_key: [addr, ...]}}``.

    Records with an empty ``minhash`` are skipped (they contribute no buckets).
    """
    lsh: dict = {}
    for rec in records:
        sig = rec["minhash"]
        if not sig:
            continue
        addr = rec["addr"]
        for band in range(BANDS):
            key = _band_key(sig, band)
            lsh.setdefault(str(band), {}).setdefault(key, []).append(addr)
    return lsh


def lsh_candidates(sig: list[int], lsh: dict) -> set[str]:
    """Union of addresses sharing any LSH band bucket with ``sig``.

    Returns an empty set when ``sig`` is empty.
    """
    if not sig:
        return set()
    cands: set[str] = set()
    for band in range(BANDS):
        key = _band_key(sig, band)
        cands.update(lsh.get(str(band), {}).get(key, []))
    return cands


def build_anchor_index(records: list[dict]) -> dict:
    """Build the anchor inverted index ``{type: {anchor: [addr, ...]}}``.

    ``type`` is one of ``"apis"``, ``"strings"``, ``"consts"``.
    """
    index: dict = {"apis": {}, "strings": {}, "consts": {}}
    for rec in records:
        addr = rec["addr"]
        for field in ("apis", "strings", "consts"):
            for anchor in set(rec[field]):
                index[field].setdefault(anchor, []).append(addr)
    return index


def anchor_candidates(
    feat: dict, anchor_index: dict, df: dict, rare_df: int
) -> set[str]:
    """Addresses that share any *rare* anchor with ``feat``.

    An anchor is rare when its document frequency is ``<= rare_df``.  Common
    anchors are ignored so blocking stays cheap and specific.
    """
    cands: set[str] = set()
    for t in ("apis", "strings", "consts"):
        for anchor in feat[t]:
            if df[t].get(anchor, 0) <= rare_df:
                cands.update(anchor_index[t].get(anchor, []))
    return cands
