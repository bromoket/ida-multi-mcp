"""Unit tests for the pure similarity core (``tools/sim_score.py``).

These tests are stdlib-only and need no IDA; they cover MinHash, IDF-weighted
anchor Jaccard, CFG z-normalized similarity, symbol-gated scoring, confidence
labels, and LSH / anchor candidate generation.
"""

import sys
import math
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ida_multi_mcp.tools import sim_score


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def make_record(
    addr="0x1000",
    is_named=False,
    size=200,
    bb_count=7,
    edge_count=9,
    complexity=4,
    loops=1,
    callee_count=3,
    caller_count=2,
    minhash=None,
    apis=None,
    strings=None,
    consts=None,
    pseudo_tokens=None,
):
    """Build a schema-conformant FunctionFeature record (design section 4.1)."""
    rec = {
        "addr": addr,
        "name": "fn_" + addr,
        "is_named": is_named,
        "size": size,
        "cfg": {
            "bb_count": bb_count,
            "edge_count": edge_count,
            "complexity": complexity,
            "loops": loops,
            "callee_count": callee_count,
            "caller_count": caller_count,
            "out_deg_seq": [],
        },
        "minhash": [] if minhash is None else minhash,
        "apis": [] if apis is None else apis,
        "strings": [] if strings is None else strings,
        "consts": [] if consts is None else consts,
    }
    if pseudo_tokens is not None:
        rec["pseudo_tokens"] = pseudo_tokens
    return rec


def empty_df():
    return {"apis": {}, "strings": {}, "consts": {}}


# --------------------------------------------------------------------------
# hash64 / constants
# --------------------------------------------------------------------------

def test_hash64_deterministic_and_str_bytes_equivalent():
    assert sim_score.hash64("abc") == sim_score.hash64("abc")
    assert sim_score.hash64("abc") == sim_score.hash64(b"abc")
    assert sim_score.hash64("abc") != sim_score.hash64("abd")
    assert 0 <= sim_score.hash64("abc") < (1 << 64)


def test_module_constants_are_frozen():
    assert sim_score.M == 64
    assert sim_score.K == 4
    assert sim_score.BANDS == 16
    assert sim_score.ROWS == 4
    assert sim_score.BANDS * sim_score.ROWS == sim_score.M
    assert sim_score.CAND_CAP == 2000
    assert sim_score.SCORING_VERSION == "v5"
    assert sim_score.DEFAULT_WEIGHTS == {
        "ngram": 0.13, "cfg": 0.13, "shape": 0.28,
        "api": 0.13, "str": 0.13, "const": 0.13, "text": 0.07,
    }
    assert sim_score.CFG_FEATS == [
        "bb_count", "edge_count", "complexity", "loops",
        "size", "callee_count", "caller_count",
    ]
    assert len(sim_score._A) == sim_score.M
    assert len(sim_score._B) == sim_score.M
    assert all(1 <= a < sim_score.P for a in sim_score._A)
    assert all(0 <= b < sim_score.P for b in sim_score._B)


# --------------------------------------------------------------------------
# shingles / compute_minhash / jaccard_minhash
# --------------------------------------------------------------------------

def test_shingles_empty_when_too_few_tokens():
    assert sim_score.shingles(["a", "b", "c"]) == set()  # < K (4)
    assert sim_score.shingles([]) == set()


def test_shingles_count_matches_kgram_windows():
    tokens = ["a", "b", "c", "d", "e"]
    sh = sim_score.shingles(tokens)  # windows: abcd, bcde -> 2 distinct
    assert len(sh) == 2


def test_compute_minhash_identical_lists_identical_sig():
    tokens = ["mov", "add", "sub", "xor", "mov", "push", "pop", "ret"]
    sig1 = sim_score.compute_minhash(tokens)
    sig2 = sim_score.compute_minhash(list(tokens))
    assert len(sig1) == sim_score.M
    assert sig1 == sig2


def test_compute_minhash_too_few_tokens_returns_empty():
    assert sim_score.compute_minhash(["a", "b", "c"]) == []


def test_jaccard_minhash_self_is_one():
    tokens = ["mov", "add", "sub", "xor", "mov", "push", "pop", "ret", "call"]
    sig = sim_score.compute_minhash(tokens)
    assert sim_score.jaccard_minhash(sig, sig) == 1.0


def test_jaccard_minhash_disjoint_is_near_zero():
    a = sim_score.compute_minhash(
        ["mov", "add", "sub", "xor", "mov", "push", "pop", "ret", "inc"]
    )
    b = sim_score.compute_minhash(
        ["jmp", "lea", "test", "cmp", "jz", "jnz", "nop", "shl", "shr"]
    )
    j = sim_score.jaccard_minhash(a, b)
    assert j < 0.2  # disjoint shingles -> only rare random collisions


def test_jaccard_minhash_empty_and_mismatch_zero():
    sig = sim_score.compute_minhash(["a", "b", "c", "d", "e", "f", "g"])
    assert sim_score.jaccard_minhash([], sig) == 0.0
    assert sim_score.jaccard_minhash(sig, []) == 0.0
    assert sim_score.jaccard_minhash([], []) == 0.0
    assert sim_score.jaccard_minhash([1, 2, 3], [1, 2]) == 0.0  # len mismatch


# --------------------------------------------------------------------------
# widf_jaccard
# --------------------------------------------------------------------------

def test_widf_jaccard_identical_sets_is_one():
    s = {"X", "Y"}
    df = {"X": 1, "Y": 1}
    assert math.isclose(sim_score.widf_jaccard(s, set(s), df, 100), 1.0)


def test_widf_jaccard_empty_union_is_zero():
    assert sim_score.widf_jaccard(set(), set(), {}, 100) == 0.0


def test_widf_jaccard_rare_shared_anchor_beats_common():
    # Both cases: sa/sb share exactly one anchor plus one unique element each.
    sa = {"shared", "a"}
    sb = {"shared", "b"}
    n = 1000
    rare_df = {"shared": 1, "a": 1, "b": 1}
    common_df = {"shared": 900, "a": 1, "b": 1}
    rare = sim_score.widf_jaccard(sa, sb, rare_df, n)
    common = sim_score.widf_jaccard(sa, sb, common_df, n)
    assert rare > common
    assert 0.0 < rare <= 1.0
    assert 0.0 < common <= 1.0


# --------------------------------------------------------------------------
# zstats_of / cfg_sim
# --------------------------------------------------------------------------

def _population():
    # Varied records so every CFG feature has std > 0 (except where noted).
    return [
        make_record(addr="0x1", size=100, bb_count=3, edge_count=4,
                    complexity=2, loops=0, callee_count=1, caller_count=1),
        make_record(addr="0x2", size=200, bb_count=7, edge_count=9,
                    complexity=4, loops=1, callee_count=3, caller_count=2),
        make_record(addr="0x3", size=400, bb_count=15, edge_count=20,
                    complexity=8, loops=3, callee_count=6, caller_count=5),
    ]


def test_zstats_of_shape_and_values():
    zs = sim_score.zstats_of(_population())
    assert set(zs.keys()) == set(sim_score.CFG_FEATS)
    for feat in sim_score.CFG_FEATS:
        assert set(zs[feat].keys()) == {"mean", "std"}
        assert zs[feat]["std"] > 0.0  # population is varied on every feature
    # size mean over [100, 200, 400]
    assert math.isclose(zs["size"]["mean"], (100 + 200 + 400) / 3)


def test_zstats_of_single_record_zero_std_no_error():
    zs = sim_score.zstats_of([make_record()])
    for feat in sim_score.CFG_FEATS:
        assert zs[feat]["std"] == 0.0


def test_cfg_sim_identical_is_one():
    zs = sim_score.zstats_of(_population())
    rec = _population()[1]
    assert math.isclose(sim_score.cfg_sim(rec, rec, zs), 1.0)


def test_cfg_sim_strictly_decreases_with_divergence():
    pop = _population()
    zs = sim_score.zstats_of(pop)
    base = make_record(addr="0xA", bb_count=7)
    near = make_record(addr="0xB", bb_count=9)   # small divergence
    far = make_record(addr="0xC", bb_count=15)   # larger divergence
    s_self = sim_score.cfg_sim(base, base, zs)
    s_near = sim_score.cfg_sim(base, near, zs)
    s_far = sim_score.cfg_sim(base, far, zs)
    assert s_self == 1.0
    assert s_self > s_near > s_far
    assert 0.0 < s_far < 1.0


def test_cfg_sim_zero_std_feature_no_zerodivision():
    # All records share loops=0 -> loops std == 0 -> must not raise.
    pop = [
        make_record(addr="0x1", loops=0, bb_count=3),
        make_record(addr="0x2", loops=0, bb_count=7),
    ]
    zs = sim_score.zstats_of(pop)
    assert zs["loops"]["std"] == 0.0
    a = make_record(addr="0xA", loops=0, bb_count=5)
    b = make_record(addr="0xB", loops=99, bb_count=5)  # differ only on loops
    # loops has std==0 so it contributes 0; all else identical -> sim == 1.0
    assert math.isclose(sim_score.cfg_sim(a, b, zs), 1.0)


# --------------------------------------------------------------------------
# df_of
# --------------------------------------------------------------------------

def test_df_of_counts_documents_with_dedup():
    records = [
        make_record(addr="0x1", apis=["A", "B", "A"]),  # dup A -> counts once
        make_record(addr="0x2", apis=["A"]),
        make_record(addr="0x3", apis=["C"]),
    ]
    df = sim_score.df_of(records, "apis")
    assert df == {"A": 2, "B": 1, "C": 1}


def test_df_of_strings_and_consts_fields():
    records = [
        make_record(addr="0x1", strings=["s1"], consts=["0x10"]),
        make_record(addr="0x2", strings=["s1", "s2"], consts=["0x10", "0x20"]),
    ]
    assert sim_score.df_of(records, "strings") == {"s1": 2, "s2": 1}
    assert sim_score.df_of(records, "consts") == {"0x10": 2, "0x20": 1}


# --------------------------------------------------------------------------
# score + symbol gating + renormalization
# --------------------------------------------------------------------------

def _score_fixture(named_a, named_b):
    sig = sim_score.compute_minhash(
        ["mov", "add", "sub", "xor", "push", "pop", "ret", "call"]
    )
    a = make_record(addr="0xA", is_named=named_a, minhash=list(sig),
                    apis=["CreateFileW"], strings=["%s.enc"], consts=["0xedb88320"],
                    pseudo_tokens=["decrypt", "key"])
    b = make_record(addr="0xB", is_named=named_b, minhash=list(sig),
                    apis=["CreateFileW"], strings=["%s.enc"], consts=["0xedb88320"],
                    pseudo_tokens=["decrypt", "iv"])
    records = [a, b]
    df = {
        "apis": sim_score.df_of(records, "apis"),
        "strings": sim_score.df_of(records, "strings"),
        "consts": sim_score.df_of(records, "consts"),
    }
    zs = sim_score.zstats_of(records)
    return a, b, df, zs, len(records)


def test_score_text_gated_off_when_one_unnamed():
    a, b, df, zs, n = _score_fixture(named_a=True, named_b=False)
    final, signals = sim_score.score(a, b, df, zs, n)
    assert "text" not in signals
    assert set(signals.keys()) == {"ngram", "api", "str", "const", "cfg"}
    assert 0.0 <= final <= 1.0


def test_score_gated_off_is_weighted_mean_of_applicable_signals():
    a, b, df, zs, n = _score_fixture(named_a=False, named_b=False)  # unnamed, empty out_deg_seq
    final, signals = sim_score.score(a, b, df, zs, n)
    assert "text" not in signals and "shape" not in signals  # both inapplicable here
    w = sim_score.DEFAULT_WEIGHTS
    active = {k: w[k] for k in signals if k in w}   # ngram/api/cfg/str/const
    expected = sum(active[k] * signals[k] for k in active) / sum(active.values())
    assert math.isclose(final, expected)


def test_score_text_present_when_both_named():
    a, b, df, zs, n = _score_fixture(named_a=True, named_b=True)
    final, signals = sim_score.score(a, b, df, zs, n)
    assert "text" in signals
    # pseudo_tokens {decrypt,key} vs {decrypt,iv}: inter=1, union=3
    assert math.isclose(signals["text"], 1 / 3)
    # weighted mean over the applicable computed signals (∩ weights); shape is
    # inapplicable here (fixture has empty out_deg_seq).
    w = sim_score.DEFAULT_WEIGHTS
    active = {k: w[k] for k in signals if k in w}
    expected = sum(active[k] * signals[k] for k in active) / sum(active.values())
    assert math.isclose(final, expected)
    assert 0.0 <= final <= 1.0


def test_score_both_named_empty_pseudo_tokens_text_zero():
    a = make_record(addr="0xA", is_named=True, pseudo_tokens=[])
    b = make_record(addr="0xB", is_named=True, pseudo_tokens=[])
    df = empty_df()
    zs = sim_score.zstats_of([a, b])
    _, signals = sim_score.score(a, b, df, zs, 2)
    assert signals["text"] == 0.0


def test_score_does_not_mutate_default_weights():
    before = dict(sim_score.DEFAULT_WEIGHTS)
    a, b, df, zs, n = _score_fixture(named_a=True, named_b=False)
    sim_score.score(a, b, df, zs, n)  # gates off -> pops "text" from a COPY
    assert sim_score.DEFAULT_WEIGHTS == before


# --------------------------------------------------------------------------
# confidence
# --------------------------------------------------------------------------

def test_confidence_high():
    signals = {"ngram": 0.9, "api": 0.8, "cfg": 0.1, "str": 0.0, "const": 0.0}
    assert sim_score.confidence(0.8, signals) == "high"
    # boundary: final == 0.75 with two strong signals
    assert sim_score.confidence(0.75, signals) == "high"


def test_confidence_high_needs_two_strong_signals():
    signals = {"ngram": 0.9, "api": 0.1, "cfg": 0.1, "str": 0.0, "const": 0.0}
    # only one signal > 0.5 -> not high; final >= 0.5 -> medium
    assert sim_score.confidence(0.8, signals) == "medium"


def test_confidence_medium_and_low_boundaries():
    weak = {"ngram": 0.1, "api": 0.1, "cfg": 0.1, "str": 0.0, "const": 0.0}
    assert sim_score.confidence(0.6, weak) == "medium"
    assert sim_score.confidence(0.5, weak) == "medium"    # boundary
    assert sim_score.confidence(0.499, weak) == "low"
    assert sim_score.confidence(0.0, weak) == "low"


# --------------------------------------------------------------------------
# build_lsh / lsh_candidates
# --------------------------------------------------------------------------

def test_lsh_identical_minhash_are_mutual_candidates():
    sig = sim_score.compute_minhash(
        ["mov", "add", "sub", "xor", "push", "pop", "ret", "call", "lea"]
    )
    r1 = make_record(addr="0x1", minhash=list(sig))
    r2 = make_record(addr="0x2", minhash=list(sig))
    lsh = sim_score.build_lsh([r1, r2])
    cand1 = sim_score.lsh_candidates(r1["minhash"], lsh)
    cand2 = sim_score.lsh_candidates(r2["minhash"], lsh)
    assert "0x2" in cand1
    assert "0x1" in cand2


def test_lsh_empty_minhash_contributes_no_buckets():
    sig = sim_score.compute_minhash(
        ["mov", "add", "sub", "xor", "push", "pop", "ret", "call"]
    )
    r1 = make_record(addr="0x1", minhash=list(sig))
    r_empty = make_record(addr="0x2", minhash=[])
    lsh = sim_score.build_lsh([r1, r_empty])
    # The empty-minhash addr never appears in any bucket.
    all_addrs = {a for band in lsh.values() for lst in band.values() for a in lst}
    assert "0x2" not in all_addrs
    assert "0x1" in all_addrs
    # And an empty query signature yields no candidates.
    assert sim_score.lsh_candidates([], lsh) == set()


def test_lsh_distinct_minhash_not_candidates():
    sig = sim_score.compute_minhash(
        ["mov", "add", "sub", "xor", "push", "pop", "ret", "call"]
    )
    other = [v + 1 for v in sig]  # every band tuple differs -> different buckets
    r1 = make_record(addr="0x1", minhash=list(sig))
    r2 = make_record(addr="0x2", minhash=other)
    lsh = sim_score.build_lsh([r1, r2])
    assert "0x2" not in sim_score.lsh_candidates(r1["minhash"], lsh)


# --------------------------------------------------------------------------
# build_anchor_index / anchor_candidates
# --------------------------------------------------------------------------

def _anchor_fixture():
    r1 = make_record(addr="0x1", apis=["RareAPI", "CommonAPI"])
    r2 = make_record(addr="0x2", apis=["RareAPI"])           # shares rare anchor
    r3 = make_record(addr="0x3", apis=["CommonAPI"])         # shares common only
    r4 = make_record(addr="0x4", apis=["CommonAPI"])
    r5 = make_record(addr="0x5", apis=["CommonAPI"])
    records = [r1, r2, r3, r4, r5]
    df = {
        "apis": sim_score.df_of(records, "apis"),   # RareAPI:2, CommonAPI:4
        "strings": sim_score.df_of(records, "strings"),
        "consts": sim_score.df_of(records, "consts"),
    }
    index = sim_score.build_anchor_index(records)
    return r1, records, df, index


def test_build_anchor_index_shape():
    _, records, _, index = _anchor_fixture()
    assert set(index.keys()) == {"apis", "strings", "consts"}
    assert sorted(index["apis"]["CommonAPI"]) == ["0x1", "0x3", "0x4", "0x5"]
    assert sorted(index["apis"]["RareAPI"]) == ["0x1", "0x2"]


def test_anchor_candidates_rare_shared_anchor_makes_candidate():
    r1, _, df, index = _anchor_fixture()
    # rare_df = 2: RareAPI(df=2) is rare (included); CommonAPI(df=4) is not.
    cands = sim_score.anchor_candidates(r1, index, df, rare_df=2)
    assert "0x2" in cands          # reached via the shared rare anchor
    assert "0x3" not in cands      # only shares the common anchor
    assert "0x4" not in cands
    assert "0x5" not in cands


def test_anchor_candidates_common_only_anchor_yields_nothing():
    _, records, df, index = _anchor_fixture()
    r3 = records[2]  # apis = ["CommonAPI"] only
    cands = sim_score.anchor_candidates(r3, index, df, rare_df=2)
    assert cands == set()  # its sole anchor is common (df=4 > 2)


# --- hardening regressions (reviewer findings) -------------------------------

def test_score_ignores_unknown_weight_key():
    # An unrecognized/typo'd weights key (user-facing tool param) must be
    # ignored, not raise KeyError.
    a, b, df, zs, n = _score_fixture(named_a=True, named_b=True)
    final, signals = sim_score.score(a, b, df, zs, n,
                                     weights={"ngram": 1.0, "typo_key": 2.0})
    assert 0.0 <= final <= 1.0
    assert "typo_key" not in signals
    # only the recognized 'ngram' weight contributes -> final == its signal
    assert math.isclose(final, signals["ngram"])


def test_widf_jaccard_nonpositive_n_no_domain_error():
    # n <= 0 must be clamped (math.log domain guard), not raise ValueError.
    s = {"CreateFileW", "WriteFile"}
    assert sim_score.widf_jaccard(s, set(s), {}, 0) == 1.0
    assert sim_score.widf_jaccard(s, set(s), {}, -5) == 1.0


def test_score_nonpositive_n_no_crash():
    a, b, df, zs, _ = _score_fixture(named_a=False, named_b=False)
    final, _ = sim_score.score(a, b, df, zs, 0)  # n<=0 must not raise
    assert 0.0 <= final <= 1.0


# --- applicability-gated denominator (v2: fixes score dilution) ---------------

def test_score_anchorless_identical_not_diluted():
    # Two identical anchor-free functions must score ~1.0, not be halved by the
    # (inapplicable) api/str/const weights sitting in the denominator.
    sig = sim_score.compute_minhash(["mov", "add", "sub", "xor", "push", "pop", "ret", "cmp"])
    a = make_record(addr="0xA", minhash=list(sig))   # no apis/strings/consts
    b = make_record(addr="0xB", minhash=list(sig))
    zs = sim_score.zstats_of([a, b])
    final, signals = sim_score.score(a, b, empty_df(), zs, 2)
    assert signals["ngram"] == 1.0 and signals["cfg"] == 1.0
    assert final > 0.99, f"anchor-less identical pair diluted to {final}"


def test_score_one_sided_anchor_still_penalizes():
    # One side HAS an api, the other does not -> they differ on APIs, so the api
    # signal is applicable (0) and should pull the score below the anchor-less case.
    sig = sim_score.compute_minhash(["mov", "add", "sub", "xor", "push", "pop", "ret", "cmp"])
    b = make_record(addr="0xB", minhash=list(sig))
    zs = sim_score.zstats_of([b, b])
    with_api = sim_score.score(make_record(addr="0xA", minhash=list(sig), apis=["RareAPI"]),
                               b, {"apis": {"RareAPI": 1}, "strings": {}, "consts": {}}, zs, 2)[0]
    without = sim_score.score(make_record(addr="0xA", minhash=list(sig)),
                              b, empty_df(), zs, 2)[0]
    assert with_api < without


def test_score_empty_minhash_drops_ngram_from_denom():
    # A tiny function (empty minhash) -> ngram inapplicable -> not in denominator,
    # so the score is driven by the applicable signals (cfg + shared const) instead
    # of being dragged down by the .30 ngram weight over a 0 value.
    a = make_record(addr="0xA", minhash=[], consts=["0xdead"])
    b = make_record(addr="0xB", minhash=[], consts=["0xdead"])
    zs = sim_score.zstats_of([a, b])
    final, signals = sim_score.score(a, b, {"apis": {}, "strings": {}, "consts": {"0xdead": 2}}, zs, 2)
    assert signals["ngram"] == 0.0
    assert final > 0.9, f"inapplicable ngram weight dragged score to {final}"


# --- shape signal (v3: out-degree distribution) ------------------------------

def test_score_shape_signal_applies_with_out_deg_seq():
    a = make_record(addr="0xA", minhash=[1, 2, 3, 4])
    b = make_record(addr="0xB", minhash=[1, 2, 3, 4])
    a["cfg"]["out_deg_seq"] = [2, 1, 1, 0]
    b["cfg"]["out_deg_seq"] = [2, 1, 1, 0]
    zs = sim_score.zstats_of([a, b])
    _, signals = sim_score.score(a, b, empty_df(), zs, 2, {"shape": 1.0})
    assert math.isclose(signals["shape"], 1.0)      # identical out-degree distribution


def test_score_shape_inapplicable_without_out_deg_seq():
    a = make_record(addr="0xA", minhash=[1, 2, 3, 4])
    b = make_record(addr="0xB", minhash=[1, 2, 3, 4])
    a["cfg"]["out_deg_seq"] = [2, 1, 0]
    b["cfg"]["out_deg_seq"] = []                     # one side has no CFG shape
    zs = sim_score.zstats_of([a, b])
    _, signals = sim_score.score(a, b, empty_df(), zs, 2, {"shape": 1.0, "cfg": 1.0})
    assert "shape" not in signals                   # gated off -> only cfg contributes


def test_shape_sim_decreases_with_divergent_shape():
    a = make_record(addr="0xA")
    b = make_record(addr="0xB")
    a["cfg"]["out_deg_seq"] = [2, 2, 2, 0]           # branchy
    b["cfg"]["out_deg_seq"] = [1, 1, 1, 0]           # linear
    same = sim_score.shape_sim(a, a)
    diff = sim_score.shape_sim(a, b)
    assert math.isclose(same, 1.0)
    assert diff < same


# --- grouped (v5 production) two-stage scoring -------------------------------

def test_score_grouped_identical_is_one():
    sig = sim_score.compute_minhash(["mov", "add", "sub", "xor", "push", "pop", "ret", "cmp"])
    a = make_record(addr="0xA", minhash=list(sig))
    b = make_record(addr="0xB", minhash=list(sig))
    a["cfg"]["out_deg_seq"] = [2, 1, 0]
    b["cfg"]["out_deg_seq"] = [2, 1, 0]
    zs = sim_score.zstats_of([a, b])
    final, signals = sim_score.score_grouped(a, b, empty_df(), zs, 2)
    assert final > 0.99 and "shape" in signals


def test_score_grouped_shape_modulates_divergent_shape():
    # identical content, different CFG shape -> grouped < 1.0 (shape pulls it down)
    sig = sim_score.compute_minhash(["mov", "add", "sub", "xor", "push", "pop", "ret", "cmp"])
    a = make_record(addr="0xA", minhash=list(sig))
    b = make_record(addr="0xB", minhash=list(sig))
    a["cfg"]["out_deg_seq"] = [2, 2, 2, 0]
    b["cfg"]["out_deg_seq"] = [1, 1, 1, 0]
    zs = sim_score.zstats_of([a, b])
    final, _ = sim_score.score_grouped(a, b, empty_df(), zs, 2)
    assert final < 1.0


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
