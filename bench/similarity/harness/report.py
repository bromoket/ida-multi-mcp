#!/usr/bin/env python3
"""Render the persisted ablation results into a self-contained HTML(+inline SVG)
report -- automates the "document results" step of the evaluation loop.

Reads every ``bench/similarity/results/latest/<corpus>.json`` and writes
``bench/similarity/results/report.html``: per corpus version a metadata card, a
technique table (Recall@1/@3, MRR, per-class Recall@3), an SVG bar chart of MRR
by technique (core vs experimental), and an SVG per-class Recall@3 heatmap.

Pure standard library; no external assets (all CSS + SVG inline), matching the
project's zero-dependency ethos and producing an HTML+SVG artifact.

Run:
    python bench/similarity/harness/report.py
"""

from __future__ import annotations

import datetime
import glob
import html
import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "results"
OUT = RESULTS / "report.html"


def _esc(s):
    return html.escape(str(s))


def _lerp(c0, c1, t):
    return tuple(round(a + (b - a) * t) for a, b in zip(c0, c1))


def _heat_color(v):
    """0 -> pale slate, 1 -> green."""
    r, g, b = _lerp((241, 245, 249), (22, 163, 74), max(0.0, min(1.0, v)))
    return f"rgb({r},{g},{b})"


def bar_chart_svg(rows, title):
    """rows: list of (label, value, kind) with kind in core/experimental/floor."""
    label_w, bar_w, row_h, pad_top = 210, 360, 24, 34
    val_w = 46
    width = label_w + bar_w + val_w + 20
    height = pad_top + len(rows) * row_h + 12
    maxv = max((v for _, v, _ in rows), default=1.0) or 1.0
    color = {"core": "#3b82f6", "experimental": "#8b5cf6", "floor": "#94a3b8"}
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
             f'style="max-width:{width}px" font-family="ui-monospace,monospace" font-size="12">']
    parts.append(f'<text x="8" y="20" font-size="13" font-weight="700" fill="#0f172a">{_esc(title)}</text>')
    for i, (label, val, kind) in enumerate(rows):
        y = pad_top + i * row_h
        w = max(1, bar_w * val / maxv)
        parts.append(f'<text x="{label_w - 6}" y="{y + 16}" text-anchor="end" fill="#334155">{_esc(label)}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{w:.1f}" height="{row_h - 10}" '
                     f'rx="3" fill="{color.get(kind, "#3b82f6")}"/>')
        parts.append(f'<text x="{label_w + w + 6:.1f}" y="{y + 16}" fill="#0f172a">{val:.2f}</text>')
    parts.append("</svg>")
    return "".join(parts)


def heatmap_svg(techniques, class_labels):
    label_w, cell_w, cell_h, pad_top = 210, 74, 22, 40
    width = label_w + len(class_labels) * cell_w + 20
    height = pad_top + len(techniques) * cell_h + 12
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
             f'style="max-width:{width}px" font-family="ui-monospace,monospace" font-size="11">']
    parts.append(f'<text x="8" y="18" font-size="13" font-weight="700" fill="#0f172a">'
                 f'per-class Recall@3</text>')
    for j, cl in enumerate(class_labels):
        x = label_w + j * cell_w
        parts.append(f'<text x="{x + cell_w / 2:.0f}" y="{pad_top - 8}" text-anchor="middle" '
                     f'fill="#475569">{_esc(cl)}</text>')
    for i, t in enumerate(techniques):
        y = pad_top + i * cell_h
        name = t["name"] + (" *" if t["kind"] == "experimental" else "")
        parts.append(f'<text x="{label_w - 6}" y="{y + 15}" text-anchor="end" fill="#334155">{_esc(name)}</text>')
        for j, cl in enumerate(class_labels):
            v = t.get("per_class_recall_at_3", {}).get(cl, 0.0)
            x = label_w + j * cell_w
            fill = _heat_color(v)
            tx = "#0f172a" if v < 0.6 else "#f8fafc"
            parts.append(f'<rect x="{x + 2}" y="{y + 2}" width="{cell_w - 4}" height="{cell_h - 4}" '
                         f'rx="2" fill="{fill}"/>')
            parts.append(f'<text x="{x + cell_w / 2:.0f}" y="{y + 15}" text-anchor="middle" '
                         f'fill="{tx}">{v:.2f}</text>')
    parts.append("</svg>")
    return "".join(parts)


def technique_table(techniques, class_labels):
    head = "".join(f"<th>{_esc(c)}</th>" for c in class_labels)
    rows = []
    for t in sorted(techniques, key=lambda x: (x["kind"] != "core", -x["mrr"])):
        cls = "".join(f'<td>{t.get("per_class_recall_at_3", {}).get(c, 0):.2f}</td>' for c in class_labels)
        badge = "" if t["kind"] == "core" else ' <span class="exp">exp</span>'
        rows.append(
            f'<tr><td class="name">{_esc(t["name"])}{badge}</td>'
            f'<td>{t["recall_at_1"]:.2f}</td><td>{t["recall_at_3"]:.2f}</td>'
            f'<td class="mrr">{t["mrr"]:.2f}</td>{cls}</tr>')
    return (f'<table><thead><tr><th>technique</th><th>R@1</th><th>R@3</th>'
            f'<th>MRR</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def version_section(rec):
    g = rec.get("gallery", {})
    classes = [c["label"] for c in rec.get("classes", [])]
    techs = rec.get("techniques", [])
    pc = rec.get("product_check", {})
    floor = rec.get("random_floor", {})
    bar_rows = [("random floor", floor.get("recall_at_3", 0), "floor")]
    bar_rows += [(t["name"] + (" *" if t["kind"] == "experimental" else ""), t["mrr"], t["kind"])
                 for t in sorted(techs, key=lambda x: -x["mrr"])]
    meta = (
        f'<div class="meta">'
        f'<span><b>binary</b> {_esc(rec.get("binary"))}</span>'
        f'<span><b>git</b> {_esc(rec.get("git_sha"))}</span>'
        f'<span><b>gallery</b> {g.get("gallery_size")} fns ({g.get("is_named")} named)</span>'
        f'<span><b>truth</b> {g.get("truth_matched")}/{g.get("truth_total")}</span>'
        f'<span><b>queries</b> {rec.get("num_queries")}</span>'
        f'<span><b>product tool</b> R@1 {pc.get("recall_at_1_num")}/{pc.get("denom")}, '
        f'R@3 {pc.get("recall_at_3_num")}/{pc.get("denom")}</span>'
        f'<span><b>run</b> {_esc(rec.get("timestamp_utc", "")[:19])}Z</span>'
        f'</div>')
    return (
        f'<section><h2>{_esc(rec.get("corpus_version"))} '
        f'<span class="sv">scoring {_esc(rec.get("scoring_version"))}</span></h2>{meta}'
        f'{technique_table(techs, classes)}'
        f'<div class="charts"><div class="chart">{bar_chart_svg(bar_rows, "MRR by technique")}</div>'
        f'<div class="chart">{heatmap_svg(techs, classes)}</div></div></section>')


CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f1f5f9;color:#0f172a}
header{background:#0f172a;color:#f8fafc;padding:20px 28px}
header h1{margin:0 0 4px;font-size:20px}
header p{margin:0;color:#94a3b8;font-size:13px}
main{max-width:1000px;margin:0 auto;padding:24px}
section{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;margin-bottom:24px}
h2{margin:0 0 12px;font-size:17px}
h2 .sv{font-size:12px;color:#7c3aed;font-weight:600;background:#f3e8ff;padding:2px 8px;border-radius:6px}
.meta{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12px;color:#475569;margin-bottom:16px}
.meta b{color:#0f172a;font-weight:600}
table{border-collapse:collapse;width:100%;font:12px ui-monospace,monospace;margin-bottom:18px}
th,td{padding:5px 8px;text-align:right;border-bottom:1px solid #eef2f7}
th{color:#64748b;font-weight:600;border-bottom:2px solid #e2e8f0}
td.name,th:first-child{text-align:left}
td.mrr{font-weight:700}
tbody tr:hover{background:#f8fafc}
.exp{background:#ede9fe;color:#6d28d9;font-size:10px;padding:1px 5px;border-radius:4px}
.charts{display:flex;flex-wrap:wrap;gap:24px}
.chart{flex:1;min-width:300px;overflow-x:auto}
"""


def main() -> int:
    files = sorted(glob.glob(str(RESULTS / "latest" / "*.json")))
    if not files:
        print(f"no results in {RESULTS/'latest'}; run run_ablation.py first")
        return 1
    recs = []
    for f in files:
        r = json.load(open(f, encoding="utf-8"))
        if "scoring_version" not in r:            # back-compat with pre-tag files
            stem = Path(f).stem
            r["scoring_version"] = stem.split("__")[1] if "__" in stem else "v2"
        recs.append(r)
    recs.sort(key=lambda r: (r.get("corpus_version", ""), r.get("scoring_version", "")))
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()[:19]
    sections = "".join(version_section(r) for r in recs)
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>Function Similarity — Technique Ablation</title><style>{CSS}</style></head>'
           f'<body><header><h1>Function Similarity — Technique Ablation</h1>'
           f'<p>{len(recs)} corpus version(s) · generated {now}Z · source: results/latest/*.json</p>'
           f'</header><main>{sections}'
           f'<p style="color:#64748b;font-size:12px">Bars = MRR (blue core, purple experimental, '
           f'grey random floor). Heatmap = per-class Recall@3.</p></main></body></html>')
    OUT.write_text(doc, encoding="utf-8")
    print(f"wrote {OUT}  ({len(recs)} version(s), {OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
