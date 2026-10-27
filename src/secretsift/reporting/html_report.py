"""Self-contained HTML report: inline CSS and SVG, no scripts, no external resources.

Every dynamic string goes through :func:`_e` (``printable`` then ``html.escape(quote=True)``).
"""

from __future__ import annotations

import html
import math
import re
from collections import Counter

from secretsift.contracts import Reporter
from secretsift.models import (
    Action,
    Category,
    Finding,
    Report,
    ScenarioStatus,
    Severity,
)
from secretsift.reporting.safe_io import printable
from secretsift.reporting.terminal import verdict

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)
_EVIDENCE_OPEN_LIMIT = 300
_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
_STATUS_ORDER = (
    ScenarioStatus.PASSED,
    ScenarioStatus.WARNED,
    ScenarioStatus.FAILED,
    ScenarioStatus.ERRORED,
    ScenarioStatus.SKIPPED,
)
_STATUS_LABEL = {
    ScenarioStatus.PASSED: "Passed",
    ScenarioStatus.WARNED: "Warned",
    ScenarioStatus.FAILED: "Failed",
    ScenarioStatus.ERRORED: "Errored",
    ScenarioStatus.SKIPPED: "Skipped",
}
_VERDICT_CLASS = {
    "FAILED": "failed",
    "ERRORED": "errored",
    "PASSED WITH WARNINGS": "warned",
    "PASSED": "passed",
}

_CSS = """
:root{
  --bg:#f1f1f2;--card:#fff;--ink:#111113;--ink2:#55555c;--muted:#8a8a92;--line:#e7e7ea;
  --soft:#f5f5f6;--fill:#111113;--on-fill:#fff;--shadow:0 18px 40px -22px rgba(0,0,0,.28);
  --mark-a:#e6e6e9;--mark-b:#fff;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#09090a;--card:#141416;--ink:#f3f3f5;--ink2:#b4b4bb;--muted:#82828a;--line:#27272b;
  --soft:#1b1b1e;--fill:#f3f3f5;--on-fill:#09090a;--shadow:0 18px 40px -22px rgba(0,0,0,.8);
  --mark-a:#222226;--mark-b:#141416;color-scheme:dark;}}
:root[data-theme="dark"]{
  --bg:#09090a;--card:#141416;--ink:#f3f3f5;--ink2:#b4b4bb;--muted:#82828a;--line:#27272b;
  --soft:#1b1b1e;--fill:#f3f3f5;--on-fill:#09090a;--shadow:0 18px 40px -22px rgba(0,0,0,.8);
  --mark-a:#222226;--mark-b:#141416;color-scheme:dark;}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,
  sans-serif;-webkit-font-smoothing:antialiased;
  padding-block:16px 40px;
  padding-left:max(14px,env(safe-area-inset-left,0px));
  padding-right:max(14px,env(safe-area-inset-right,0px))}
.wrap{max-width:1080px;margin:0 auto;display:grid;gap:14px}
.wrap>*{min-width:0}
h1,h2,h3,p{margin:0}
h2{font-size:1.15rem;letter-spacing:-.01em;font-weight:650}
h3{font-size:1rem}
.mono,pre,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.card{background:var(--card);border-radius:28px;padding:28px;box-shadow:var(--shadow);
  border:1px solid var(--line)}
a{color:inherit}
a:focus-visible,summary:focus-visible{outline:2px solid var(--ink);outline-offset:3px;
  border-radius:8px}
.nav{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:12px 14px 12px 22px;border-radius:999px}
.brand{font-weight:700;text-decoration:none;letter-spacing:-.02em}
.links{display:flex;gap:22px;font-size:.88rem;color:var(--ink2)}
.links a{text-decoration:none}
.links a:hover{color:var(--ink)}
.chip{display:inline-flex;align-items:center;gap:8px;font-size:.78rem;color:var(--ink2);
  background:var(--soft);border:1px solid var(--line);border-radius:999px;padding:5px 12px}
.chip.run{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.hero{text-align:center;padding:44px 24px 36px;display:grid;justify-items:center;gap:18px}
.hero h1{font-size:clamp(2.3rem,8.4vw,5rem);line-height:.98;letter-spacing:-.05em;
  font-weight:600;max-width:15ch;text-wrap:balance}
.sub{color:var(--ink2);max-width:46ch;text-wrap:balance}
.pill{display:inline-block;padding:9px 20px;border-radius:999px;font-weight:600;font-size:.88rem;
  background:var(--fill);color:var(--on-fill);border:1px solid var(--fill)}
.pill.passed{background:transparent;color:var(--ink);border-color:var(--ink)}
.pill.warned{background:transparent;color:var(--ink);border:1px dashed var(--ink)}
.pill.errored{background:var(--ink2);border-color:var(--ink2);color:var(--card)}
.clock{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;padding:8px;margin-top:6px;
  border-radius:26px;background:linear-gradient(#2a2a2c,#121213);
  box-shadow:0 22px 40px -18px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.12)}
.tile{min-width:104px;padding:14px 18px 10px;border-radius:18px;color:#fff;text-align:center;
  background:linear-gradient(#303033,#1b1b1d);box-shadow:inset 0 1px 0 rgba(255,255,255,.1)}
.tile b{display:block;font-size:2.1rem;line-height:1.1;letter-spacing:-.03em;font-weight:650;
  font-variant-numeric:tabular-nums}
.tile span{font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;color:#a6a6ad}
.dark{color:#fff;border-color:#232326;
  background:radial-gradient(120% 60% at 50% 0%,#3d3d41 0%,#101011 58%,#09090a 100%);
  --passed:#6d6d75;--warned:#a2a2aa;--failed:#fff;--errored:#d2d2d8;--skipped:#37373b;
  --sev-critical:#fff;--sev-high:#d6d6db;--sev-medium:#a4a4ac;--sev-low:#74747c;--sev-info:#4b4b51;
  --track:#2a2a2e;--bar:#fff;--c-ink:#fff;--c-ink2:#b9b9c1;--c-muted:#8b8b93}
.dark h2{color:#fff;margin-bottom:14px}
.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:26px 34px}
.grid3>*{min-width:0}
.summary{display:flex;flex-wrap:wrap;gap:18px 26px;align-items:center}
.legend{list-style:none;margin:0;padding:0;display:grid;gap:6px;min-width:0;
  color:var(--c-ink2);font-size:.9rem}
.legend li{display:flex;align-items:center;gap:8px}
.sw{width:11px;height:11px;border-radius:3px;display:inline-block;flex:none;
  border:1px solid rgba(255,255,255,.25)}
.num{font-variant-numeric:tabular-nums;margin-left:auto;padding-left:16px;font-weight:650;
  color:var(--c-ink)}
svg{max-width:100%;height:auto;display:block}
.donut-track{fill:none;stroke:var(--track)}
.donut-seg{fill:none}
.donut-n{font-size:22px;font-weight:700;fill:#fff;text-anchor:middle}
.donut-l{font-size:9px;fill:var(--c-muted);text-anchor:middle}
.bar-label{font-size:12px;fill:var(--c-ink2)}
.bar-val{font-size:12px;fill:var(--c-ink);font-weight:650}
.bar-track{fill:var(--track)}
.bar-cat{fill:var(--bar)}
.note{color:var(--muted);font-size:.9rem}
.dark .note{color:var(--c-muted)}
.sec-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px;margin-bottom:14px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  font-weight:600}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
td.name{overflow-wrap:anywhere;min-width:160px;font-weight:600}
tr:last-child td{border-bottom:0}
.st{display:inline-block;font-weight:600;font-size:.8rem;padding:3px 11px;border-radius:999px;
  border:1px solid var(--ink)}
.st::before{margin-right:6px}
.st.failed{background:var(--fill);color:var(--on-fill)}
.st.failed::before{content:"\\25A0"}
.st.passed::before{content:"\\2713"}
.st.warned{border-style:dashed}.st.warned::before{content:"\\25B2"}
.st.errored{background:var(--soft);border-style:double;border-width:3px}
.st.errored::before{content:"\\2715"}
.st.skipped{border-color:var(--line);color:var(--muted)}.st.skipped::before{content:"\\2013"}
.cards{display:grid;gap:14px}
.finding{display:grid;gap:18px;padding:24px}
.card-head{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center}
.fid{font-weight:700;font-size:1.15rem;letter-spacing:-.01em}
.tag{font-size:.78rem;color:var(--ink2);background:var(--soft);border:1px solid var(--line);
  border-radius:999px;padding:3px 11px}
.finding dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px 22px;
  margin:0}
.finding dl>div,.meta>div{min-width:0}
dt{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;
  margin-bottom:2px}
dd{margin:0;overflow-wrap:anywhere}
pre{margin:6px 0 0;padding:16px 18px;background:#0c0c0d;color:#f1f1f3;border-radius:16px;
  white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem}
details>summary{cursor:pointer;font-weight:600;padding:6px 0}
.fix{margin:6px 0 0;padding:14px 16px;background:var(--soft);border-radius:16px;
  overflow-wrap:anywhere;border:1px solid var(--line)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px 22px;margin:0}
ul.lim{margin:10px 0 0;padding-left:20px;display:grid;gap:8px;color:var(--ink2)}
ul.lim li{overflow-wrap:anywhere}
.empty{color:var(--muted)}
.foot{overflow:hidden;padding-bottom:0;display:grid;gap:6px}
.foot p{color:var(--muted);font-size:.85rem;max-width:60ch}
.mark{font-size:clamp(3.4rem,19vw,12.5rem);font-weight:700;letter-spacing:-.06em;line-height:.82;
  margin:22px 0 -.1em;user-select:none;white-space:nowrap;overflow:hidden;color:transparent;
  background:linear-gradient(var(--mark-a),var(--mark-b) 88%);
  -webkit-background-clip:text;background-clip:text}
@media (max-width:640px){
  .links{display:none}
  .card{padding:20px;border-radius:24px}
  .hero{padding:32px 16px 26px}
  .tile{min-width:calc(50% - 6px);flex:1 1 calc(50% - 6px)}
  thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
  table,tbody,tr,td,caption{display:block;width:100%}
  tr{padding:12px 0;border-bottom:1px solid var(--line)}
  tr:last-child{border-bottom:0}
  td{display:flex;justify-content:space-between;gap:14px;border:0;padding:5px 0;text-align:right}
  td::before{content:attr(data-label);color:var(--muted);font-size:.72rem;
    text-transform:uppercase;letter-spacing:.09em;text-align:left;flex:none;padding-top:3px}
  td.name{display:block;text-align:left;min-width:0}
  td.name::before{display:none}
}
@media print{body{background:#fff}.card{box-shadow:none}.clock{box-shadow:none}}
"""


def _e(text: object, limit: int = 2000) -> str:
    """Escape any value for HTML text or attribute context."""
    return html.escape(printable(str(text), limit=limit), quote=True)


def _donut(report: Report) -> str:
    counts = {
        ScenarioStatus.PASSED: report.summary.passed,
        ScenarioStatus.WARNED: report.summary.warned,
        ScenarioStatus.FAILED: report.summary.failed,
        ScenarioStatus.ERRORED: report.summary.errored,
        ScenarioStatus.SKIPPED: report.summary.skipped,
    }
    total = sum(counts.values())
    radius = 40.0
    circ = 2 * math.pi * radius
    desc = ", ".join(f"{counts[s]} {_STATUS_LABEL[s].lower()}" for s in _STATUS_ORDER)
    parts = [
        f'<svg viewBox="0 0 120 120" width="150" height="150" role="img" '
        f'aria-label="Scenario outcomes: {_e(desc)}"><title>Scenario outcomes</title>',
        f'<circle class="donut-track" cx="60" cy="60" r="{radius}" stroke-width="14"/>',
    ]
    offset = 0.0
    for status in _STATUS_ORDER:
        count = counts[status]
        if not count or not total:
            continue
        length = circ * count / total
        gap = 1.5 if len([c for c in counts.values() if c]) > 1 else 0.0
        parts.append(
            f'<circle class="donut-seg" cx="60" cy="60" r="{radius}" stroke-width="14" '
            f'stroke="var(--{status.value})" stroke-dasharray="{max(length - gap, 0.1):.2f} '
            f'{circ:.2f}" stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 60 60)"/>'
        )
        offset += length
    parts.append(f'<text class="donut-n" x="60" y="62">{total}</text>')
    parts.append('<text class="donut-l" x="60" y="76">scenarios</text></svg>')
    legend = "".join(
        f'<li><span class="sw" style="background:var(--{s.value})"></span>'
        f'{_STATUS_LABEL[s]}<span class="num">{counts[s]}</span></li>'
        for s in _STATUS_ORDER
    )
    return f'<div class="summary">{"".join(parts)}<ul class="legend">{legend}</ul></div>'


def _bars(title: str, rows: list[tuple[str, int, str]], empty: str) -> str:
    """Horizontal bar chart. ``rows`` are (label, value, css fill value)."""
    peak = max((v for _, v, _ in rows), default=0)
    if peak == 0:
        return f'<h2>{_e(title)}</h2><p class="note">{_e(empty)}</p>'
    row_h, label_w, bar_w, width = 26, 92, 190, 340
    height = row_h * len(rows) + 4
    out = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_e(title)}">'
        f"<title>{_e(title)}</title>"
    ]
    for i, (label, value, fill) in enumerate(rows):
        y = 2 + i * row_h
        w = bar_w * value / peak
        out.append(f'<text class="bar-label" x="0" y="{y + 15}">{_e(label, 40)}</text>')
        out.append(
            f'<rect class="bar-track" x="{label_w}" y="{y + 4}" width="{bar_w}" height="12" '
            'rx="3"/>'
        )
        if value:
            out.append(
                f'<rect x="{label_w}" y="{y + 4}" width="{max(w, 4):.1f}" height="12" rx="3" '
                f'style="fill:{fill}"/>'
            )
        out.append(f'<text class="bar-val" x="{label_w + bar_w + 10}" y="{y + 15}">{value}</text>')
    out.append("</svg>")
    return f"<h2>{_e(title)}</h2>{''.join(out)}"


def _charts(report: Report) -> str:
    findings = report.findings
    by_cat = Counter(f.category for f in findings)
    by_sev = Counter(f.severity for f in findings)
    cat_rows = [
        (c.value.replace("_", " "), by_cat.get(c, 0), "var(--bar)")
        for c in Category
        if c is not Category.REGRESSION or by_cat.get(c, 0)
    ]
    sev_rows = [(s.value, by_sev.get(s, 0), f"var(--sev-{s.value})") for s in _SEVERITIES]
    return (
        f"<div>{_bars('Findings by category', cat_rows, 'No findings.')}</div>"
        f"<div>{_bars('Findings by severity', sev_rows, 'No findings.')}</div>"
    )


def _scenario_table(report: Report) -> str:
    if not report.results:
        return '<p class="empty">No scenarios were run.</p>'
    rows: list[str] = []
    for r in report.results:
        status = _STATUS_LABEL[r.status]
        note = r.error or r.skipped_reason
        extra = f'<div class="note">{_e(note, 600)}</div>' if note else ""
        rows.append(
            f'<tr><td class="name" data-label="Scenario">{_e(r.name, 300)}{extra}</td>'
            f'<td data-label="Category">{_e(r.category.value)}</td>'
            f'<td data-label="Status"><span class="st {r.status.value}">{status}</span></td>'
            f'<td class="n" data-label="Findings">{len(r.findings)}</td>'
            f'<td class="n" data-label="Events">{r.events_observed}</td>'
            f'<td class="n" data-label="Duration">{r.duration_ms:.0f} ms</td></tr>'
        )
    head = (
        "<tr><th>Scenario</th><th>Category</th><th>Status</th>"
        '<th class="n">Findings</th><th class="n">Events</th><th class="n">Duration</th></tr>'
    )
    return (
        f'<div class="scroll"><table><caption class="note" style="text-align:left">'
        f"Outcome of each scenario</caption><thead>{head}</thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _card(f: Finding) -> str:
    where = f.component + (f" @ {f.location}" if f.location else "")
    occ = f" &times;{f.occurrences}" if f.occurrences > 1 else ""
    evidence = _e(f.evidence, 4000)
    pre = f'<pre class="mono">{evidence}</pre>'
    if len(f.evidence) > _EVIDENCE_OPEN_LIMIT:
        pre = f"<details><summary>Show redacted evidence</summary>{pre}</details>"
    fields = (
        ("Scenario", f.scenario),
        ("Destination", f.destination.value),
        ("Component", where),
        ("Data", f"{f.data_type.value} ({f.value_id}), matched as {f.variant.value}"),
        ("Confidence", f"{f.confidence}; detected by {f.detection_method}"),
        ("Policy rule", f.rule_id or "default action"),
    )
    dl = "".join(f"<div><dt>{_e(k)}</dt><dd>{_e(v, 600)}</dd></div>" for k, v in fields)
    cls = "failed" if f.action is Action.DENY else "warned"
    label = "Denied" if f.action is Action.DENY else "Warned"
    anchor = re.sub(r"[^A-Za-z0-9_-]", "-", f.id)[:60]
    return (
        f'<article class="card finding" id="{anchor}" aria-label="Finding {_e(f.id, 60)}">'
        f'<div class="card-head"><h3 class="fid mono">{_e(f.id, 60)}</h3>'
        f'<span class="st {cls}">{label}</span>'
        f'<span class="tag">{_e(f.severity.value)} severity</span>'
        f'<span class="tag">{_e(f.category.value.replace("_", " "))}{occ}</span></div>'
        f"<dl>{dl}"
        f"<div><dt>Expected</dt><dd>{_e(f.expected, 800)}</dd></div>"
        f"<div><dt>Observed</dt><dd>{_e(f.observed, 800)}</dd></div></dl>"
        f"<div><dt>Redacted evidence</dt>{pre}</div>"
        f'<div><dt>Remediation</dt><p class="fix">{_e(f.remediation, 1200)}</p></div>'
        "</article>"
    )


def _findings(report: Report) -> str:
    items = sorted(
        report.findings,
        key=lambda f: (f.action is not Action.DENY, _SEVERITIES.index(f.severity), f.id),
    )
    body = "".join(_card(f) for f in items) or (
        '<div class="card"><p class="empty">No findings observed.</p></div>'
    )
    return (
        '<section id="findings"><div class="sec-head"><h2>Findings '
        f'({len(items)})</h2><span class="note">Evidence is redacted; severity reflects policy, '
        "not a real breach.</span></div>"
        f'<div class="cards">{body}</div></section>'
    )


def _coverage(report: Report) -> str:
    cov = report.coverage
    dests = ", ".join(_e(d.value) for d in cov.destinations_observed) or "none"
    insp = ", ".join(_e(i, 80) for i in cov.inspectors_active) or "none"
    lims = "".join(f"<li>{_e(x, 800)}</li>" for x in cov.limitations)
    lim_block = f'<ul class="lim">{lims}</ul>' if lims else '<p class="empty">None declared.</p>'
    return (
        '<section class="card" id="coverage"><h2>Coverage and limitations</h2>'
        '<dl class="meta" style="margin-top:14px">'
        f"<div><dt>Inspectors active</dt><dd>{insp}</dd></div>"
        f"<div><dt>Destinations observed</dt><dd>{dests}</dd></div>"
        f"<div><dt>Offline mode</dt><dd>{'yes' if cov.offline else 'no'}</dd></div></dl>"
        f'<h3 style="margin-top:20px">Limitations</h3>{lim_block}'
        '<p class="note" style="margin-top:12px">A clean result only covers what secretsift '
        "observed.</p></section>"
    )


def _headline(report: Report) -> str:
    denied = sum(1 for f in report.findings if f.action is Action.DENY)
    warned = len(report.findings) - denied
    if denied:
        return f"{denied} privacy leak{'s' if denied != 1 else ''} found."
    if report.summary.errored:
        return "Some scenarios could not finish."
    if warned:
        return f"{warned} warning{'s' if warned != 1 else ''}, no denied leaks."
    return "No leaks observed."


def _clock(report: Report) -> str:
    s = report.summary
    seconds = (report.finished_at - report.started_at).total_seconds()
    duration = f"{seconds * 1000:.0f} ms" if seconds < 1 else f"{seconds:.1f} s"
    tiles = (
        (s.passed, "Passed"),
        (s.failed + s.warned + s.errored, "Not clean"),
        (s.findings, "Findings"),
        (duration, "Duration"),
    )
    body = "".join(
        f'<div class="tile"><b>{_e(v, 40)}</b><span>{_e(k)}</span></div>' for v, k in tiles
    )
    return f'<div class="clock" role="group" aria-label="Run summary">{body}</div>'


def _header(report: Report) -> str:
    outcome = verdict(report)
    duration = (report.finished_at - report.started_at).total_seconds()
    seed = "random" if report.seed is None else str(report.seed)
    s = report.summary
    counts = (
        f"{s.total} scenarios: {s.passed} passed, {s.failed} failed, {s.warned} warned, "
        f"{s.errored} errored, {s.skipped} skipped; {s.findings} findings"
    )
    fields = [
        ("Run", report.run_id),
        ("Started", report.started_at.isoformat(timespec="seconds")),
        ("Duration", f"{duration * 1000:.0f} ms" if duration < 1 else f"{duration:.1f} s"),
        ("Seed", seed),
        ("Version", f"secretsift {report.tool_version}"),
    ]
    if report.config_path:
        fields.append(("Config", report.config_path))
    meta = "".join(f"<div><dt>{_e(k)}</dt><dd>{_e(v, 400)}</dd></div>" for k, v in fields)
    return (
        '<header class="card hero" id="top">'
        f'<span class="chip">Privacy leak rehearsal &middot; seed {_e(seed, 20)}</span>'
        f"<h1>{_e(_headline(report), 120)}</h1>"
        f'<p class="sub">{_e(counts)}</p>'
        f'<span class="pill {_VERDICT_CLASS[outcome]}">{_e(outcome)}</span>'
        f"{_clock(report)}"
        f'<dl class="meta" style="width:100%;margin-top:18px;text-align:left">{meta}</dl></header>'
    )


def _nav(report: Report) -> str:
    return (
        '<nav class="card nav" aria-label="Report sections"><a class="brand" href="#top">'
        'secretsift</a><div class="links"><a href="#overview">Overview</a>'
        '<a href="#scenarios">Scenarios</a><a href="#findings">Findings</a>'
        '<a href="#coverage">Coverage</a></div>'
        f'<span class="chip run">run {_e(report.run_id[:10], 20)}</span></nav>'
    )


def render_html(report: Report) -> str:
    """Return the complete HTML document for ``report``."""
    body = (
        _nav(report)
        + _header(report)
        + '<section class="card dark" id="overview"><h2>Scenario outcomes</h2>'
        + f'<div class="grid3"><div>{_donut(report)}</div>{_charts(report)}</div></section>'
        + f'<section class="card" id="scenarios"><h2 class="sec-head">Scenarios</h2>'
        f"{_scenario_table(report)}</section>"
        + _findings(report)
        + _coverage(report)
        + '<footer class="card foot"><p>Generated by secretsift. Self-contained file: no scripts, '
        "no external resources. Synthetic values never appear here.</p>"
        '<div class="mark" aria-hidden="true">secretsift</div></footer>'
    )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(_CSP, quote=True)}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>secretsift report {_e(report.run_id, 80)}</title><style>{_CSS}</style></head>"
        f'<body><main class="wrap">{body}</main></body></html>\n'
    )


class HtmlReporter(Reporter):
    """Reporter producing one self-contained HTML file."""

    format_name = "html"

    def render(self, report: Report) -> str:
        return render_html(report)
