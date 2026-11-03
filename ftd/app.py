"""
app.py — 🌳 Family Tree Detective

Pick a user.name, see every process they launched as a family tree, and let
the suspicious branches float to the top.

    streamlit run app.py                                         # mock data
    FTD_MODE=elastic ES_URL=... ES_API_KEY=... streamlit run app.py
"""
from __future__ import annotations

import html
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from data_source import DataSource
from detections import SEVERITY_STYLE, context_findings, decode_powershell, score_process, severity
from query_dict import TIME_RANGES, live_since

st.set_page_config(page_title="Family Tree Detective", page_icon="🌳", layout="wide")

MAX_FETCH = 20_000   # cap on raw docs pulled per user (paged with search_after)
MAX_PATH_DEPTH = 7   # the pattern view folds anything deeper into "… deeper"
INDIGO = ["#4F46E5", "#6366F1", "#818CF8", "#A5B4FC", "#C7D2FE", "#E0E7FF", "#EEF2FF"]

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] { font-family: 'Inter', system-ui, sans-serif; }
.block-container { padding-top: 3.2rem; padding-bottom: 3rem; max-width: 1440px; }
h1, h2, h3, h4, h5 { letter-spacing: -0.02em; }
[data-testid="stMetric"] { background: rgba(99,102,241,.06); border: 1px solid rgba(99,102,241,.16);
                           border-radius: 14px; padding: 14px 18px; }
[data-testid="stMetricLabel"] p { font-size: .74rem; text-transform: uppercase; letter-spacing: .07em; opacity: .7; }
.brand { font-size: 1.25rem; font-weight: 800; letter-spacing: -0.02em; }
.hero .eyebrow { font-size: .72rem; text-transform: uppercase; letter-spacing: .14em; color: #6366F1; font-weight: 700; }
.hero h1 { font-size: 2.3rem; font-weight: 800; margin: 0; padding: 0; }
.hero .sub { opacity: .62; margin: .1rem 0 1.1rem 0; }
.pill { display: inline-block; padding: 1px 10px; border-radius: 999px; font-size: .72rem; font-weight: 700;
        text-transform: uppercase; letter-spacing: .04em; }
.mono { font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: .78rem; word-break: break-all; }
.muted { opacity: .6; }
.small { font-size: .8rem; }
.chain-title { font-weight: 700; font-size: 1.02rem; margin: .25rem 0 .15rem 0; }
.kv { display: grid; grid-template-columns: 110px 1fr; gap: 7px 14px; font-size: .86rem; margin-top: .4rem; }
.kv .k { opacity: .55; }
.legend { font-size: .78rem; margin-top: .2rem; }
.legend .pill { margin-right: 6px; }
.feed-row { padding: 7px 12px; border-radius: 10px; margin-bottom: 4px; border: 1px solid rgba(128,128,128,.14);
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: .86rem; }
.feed-row.hot { border-color: rgba(220,38,38,.45); background: rgba(220,38,38,.07); }
.stTabs [data-baseweb="tab-list"] { gap: 6px; }
.stTabs [data-baseweb="tab"] { padding: 8px 14px; }
</style>
""",
    unsafe_allow_html=True,
)

esc = html.escape


# ───────────────────────── small helpers ─────────────────────────
def pill(sev: str, text: str | None = None) -> str:
    fg, bg = SEVERITY_STYLE[sev]
    return f'<span class="pill" style="color:{fg};background:{bg};border:1px solid {fg}40">{esc(text or sev)}</span>'


def kv(pairs: list[tuple[str, str]]) -> str:
    return '<div class="kv">' + "".join(f'<div class="k">{esc(k)}</div><div>{v}</div>' for k, v in pairs) + "</div>"


def fmt_dur(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} s"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def iso(ts) -> str:
    return pd.Timestamp(ts).tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ───────────────────────── Elastic hits → DataFrame ─────────────────────────
COLS = ["entity_id", "pid", "name", "executable", "command_line", "args_count", "working_directory",
        "start", "end", "exit_code", "sha256", "trusted", "signer", "parent_entity_id", "parent_pid",
        "parent_name", "parent_executable", "parent_command_line", "host"]


def flatten(hits: list[dict]) -> pd.DataFrame:
    rows = []
    for h in hits:
        s = h.get("_source", {})
        p = s.get("process", {}) or {}
        pa = p.get("parent", {}) or {}
        cs = p.get("code_signature", {}) or {}
        rows.append({
            "entity_id": p.get("entity_id") or h.get("_id"),
            "pid": p.get("pid"),
            "name": (p.get("name") or "?").lower(),
            "executable": p.get("executable") or "",
            "command_line": p.get("command_line") or "",
            "args_count": p.get("args_count"),
            "working_directory": p.get("working_directory") or "",
            "start": p.get("start") or s.get("@timestamp"),
            "end": p.get("end"),
            "exit_code": p.get("exit_code"),
            "sha256": (p.get("hash") or {}).get("sha256"),
            "trusted": cs.get("trusted"),
            "signer": cs.get("subject_name"),
            "parent_entity_id": pa.get("entity_id"),
            "parent_pid": pa.get("pid"),
            "parent_name": (pa.get("name") or "").lower(),
            "parent_executable": pa.get("executable") or "",
            "parent_command_line": pa.get("command_line") or "",
            "host": (s.get("host") or {}).get("name"),
        })
    df = pd.DataFrame(rows, columns=COLS)
    df["start"] = pd.to_datetime(df["start"], utc=True, format="ISO8601")
    df["end"] = pd.to_datetime(df["end"], utc=True, format="ISO8601", errors="coerce")
    return df.drop_duplicates("entity_id").reset_index(drop=True)


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    """Add depth, name-path from the root, findings, risk score and severity."""
    extra = ["base_score", "depth", "path", "findings", "score", "severity", "rules"]
    if df.empty:
        for c in extra:
            df[c] = pd.Series(dtype=object)
        return df
    recs = df.to_dict("records")
    idx = {r["entity_id"]: r for r in recs}
    for r in recs:
        r["_base"] = score_process(r)
        r["base_score"] = sum(f.points for f in r["_base"])
    for r in recs:
        anc, cur, seen = [], r["parent_entity_id"], set()
        while cur in idx and cur not in seen and len(anc) < 64:
            seen.add(cur)
            anc.append(idx[cur])
            cur = idx[cur]["parent_entity_id"]
        r["depth"] = len(anc)
        names = [a["name"] for a in reversed(anc)] + [r["name"]]
        if len(names) > MAX_PATH_DEPTH:
            names = names[: MAX_PATH_DEPTH - 1] + ["… deeper"]
        r["path"] = tuple(names)
        r["findings"] = r["_base"] + context_findings(r, anc)
        r["score"] = min(100, sum(f.points for f in r["findings"]))
    out = pd.DataFrame(recs).drop(columns=["_base"])
    out["severity"] = out["score"].map(severity)
    out["rules"] = out["findings"].map(lambda fs: ", ".join(f.rule for f in fs))
    return out


# ───────────────────────── cached loaders ─────────────────────────
@st.cache_resource(show_spinner="Warming up the data source…")
def get_source() -> DataSource:
    return DataSource()


@st.cache_data(ttl=300, show_spinner=False)
def load_users(since: str):
    req, resp = get_source().search("users_overview", since=since)
    return req, resp["aggregations"]["users"]["buckets"]


@st.cache_data(ttl=300, show_spinner=False)
def load_summary(user: str, since: str):
    req, resp = get_source().search("user_summary", user=user, since=since)
    return req, resp["hits"]["total"]["value"], resp["aggregations"]


@st.cache_data(ttl=300, show_spinner="Pulling process events…")
def load_processes(user: str, since: str):
    reqs, hits, truncated = get_source().fetch_all("user_processes", max_docs=MAX_FETCH, user=user, since=since)
    return reqs, enrich(flatten(hits)), truncated


@st.cache_data(ttl=300, show_spinner=False)
def build_index(user: str, since: str):
    _, df, _ = load_processes(user, since)
    rows = df.set_index("entity_id", drop=False).to_dict("index") if not df.empty else {}
    children: dict[str, list[str]] = defaultdict(list)
    for eid, r in rows.items():
        children[r["parent_entity_id"]].append(eid)
    for k in children:
        children[k].sort(key=lambda e: rows[e]["start"])
    return rows, dict(children)


# ───────────────────────── tree logic ─────────────────────────
def ancestors_of(rows: dict, eid: str) -> list[str]:
    out, cur = [], rows[eid]["parent_entity_id"]
    while cur in rows and len(out) < 32:
        out.append(cur)
        cur = rows[cur]["parent_entity_id"]
    return out[::-1]


def build_chains(rows: dict, flag_min: int) -> list[dict]:
    """Group flagged processes under their top-most flagged ancestor → one card per 'incident'."""
    flagged = {e for e, r in rows.items() if r["score"] >= flag_min}
    groups: dict[str, list[str]] = defaultdict(list)
    for e in flagged:
        top, cur, hops = e, rows[e]["parent_entity_id"], 0
        while cur in rows and hops < 64:
            if cur in flagged:
                top = cur
            cur, hops = rows[cur]["parent_entity_id"], hops + 1
        groups[top].append(e)
    chains = []
    for root, members in groups.items():
        members.sort(key=lambda e: rows[e]["start"])
        scores = [rows[m]["score"] for m in members]
        chains.append({
            "root": root, "members": members, "peak": int(max(scores)), "total": int(sum(scores)),
            "rules": sorted({f.rule for m in members for f in rows[m]["findings"]}),
        })
    return sorted(chains, key=lambda c: (-c["peak"], -c["total"]))


def _node(eid: str, r: dict, focus: bool = False) -> str:
    fg, bg = SEVERITY_STYLE[r["severity"]]
    when = r["start"].strftime("%b %d %H:%M:%S")
    risk = f'<br/><font point-size="9" color="{fg}"><b>RISK {int(r["score"])}</b></font>' if r["score"] else ""
    label = f'<<b>{esc(r["name"])}</b><br/><font point-size="9" color="#64748B">pid {r["pid"]} · {when}</font>{risk}>'
    border = "#4F46E5" if focus else fg
    return f'"{eid}" [label={label}, style="rounded,filled", fillcolor="{bg}", color="{border}", penwidth={3 if focus else 1.2}];'


def lineage_dot(rows: dict, children: dict, focus: str, flag_min: int,
                max_nodes: int = 60, max_depth: int = 4, group_over: int = 3) -> str:
    """Ancestors of `focus` as a straight line, then its descendants.
    Boring siblings with the same name collapse into one 'name ×N' node, so a
    process with 2,000 children still draws as a handful of boxes. Anything
    flagged (or leading to something flagged) is always drawn individually."""
    hot_path = set()
    for e, r in rows.items():
        if r["score"] >= flag_min:
            hot_path.add(e)
            hot_path.update(ancestors_of(rows, e))

    out = [
        "digraph L {",
        'graph [rankdir=TB, bgcolor="transparent", nodesep=0.25, ranksep=0.4];',
        'node [shape=box, fontname="Helvetica", fontsize=11, margin="0.16,0.07"];',
        'edge [color="#94A3B8", arrowsize=0.6];',
    ]
    chain = ancestors_of(rows, focus) + [focus]
    top = rows[chain[0]]
    out.append(f'"ghost" [label=<<i>{esc(top["parent_name"] or "unknown")}</i><br/>'
               f'<font point-size="9" color="#94A3B8">parent outside this data</font>>, '
               f'style="rounded,dashed", color="#CBD5E1", fontcolor="#64748B"];')
    out.append(f'"ghost" -> "{chain[0]}" [style=dashed];')
    for e in chain:
        out.append(_node(e, rows[e], focus=e == focus))
    for a, b in zip(chain, chain[1:]):
        out.append(f'"{a}" -> "{b}" [color="#475569", penwidth=1.6];')

    budget, queue = max_nodes, [(focus, 0)]
    while queue:
        eid, depth = queue.pop(0)
        kids = children.get(eid, [])
        if not kids:
            continue
        if depth >= max_depth:
            out.append(f'"more:{eid}" [label="+{len(kids)} more below", shape=plaintext, fontsize=9, fontcolor="#94A3B8"];')
            out.append(f'"{eid}" -> "more:{eid}" [style=dotted];')
            continue
        by_name: dict[str, list[str]] = defaultdict(list)
        for k in kids:
            by_name[rows[k]["name"]].append(k)
        for name, ks in by_name.items():
            hot = [k for k in ks if k in hot_path]
            cold = [k for k in ks if k not in hot_path]
            for k in hot:
                out += [_node(k, rows[k]), f'"{eid}" -> "{k}";']
                queue.append((k, depth + 1))
                budget -= 1
            if not cold:
                continue
            if len(cold) > group_over or budget < len(cold):
                gid = f"grp:{eid}:{name}"
                t0 = min(rows[k]["start"] for k in cold)
                t1 = max(rows[k]["start"] for k in cold)
                grandkids = sum(len(children.get(k, [])) for k in cold)
                sub = f"{t0:%b %d %H:%M} → {t1:%b %d %H:%M}" + (f" · {grandkids:,} children" if grandkids else "")
                out.append(f'"{gid}" [label=<<b>{esc(name)}</b>  ×{len(cold):,}<br/><font point-size="9" color="#64748B">{sub}</font>>, '
                           f'style="rounded,filled,dashed", fillcolor="#F8FAFC", color="#94A3B8"];')
                out.append(f'"{eid}" -> "{gid}" [style=dashed];')
                budget -= 1
            else:
                for k in cold:
                    out += [_node(k, rows[k]), f'"{eid}" -> "{k}";']
                    queue.append((k, depth + 1))
                    budget -= 1
    out.append("}")
    return "\n".join(out)


def edge_dot(pairs: Counter, flagged_pairs: set, min_count: int) -> str | None:
    shown = {k: n for k, n in pairs.items() if n >= min_count or k in flagged_pairs}
    if not shown:
        return None
    mx = max(shown.values())
    q = lambda s: (s or "?").replace('"', '\\"')  # noqa: E731
    out = [
        "digraph E {",
        'graph [rankdir=LR, bgcolor="transparent", nodesep=0.18, ranksep=0.55];',
        'node [shape=box, style="rounded,filled", fillcolor="#EEF2FF", color="#C7D2FE", fontname="Helvetica", fontsize=10, margin="0.12,0.05"];',
        'edge [fontname="Helvetica", fontsize=9, fontcolor="#64748B", arrowsize=0.5];',
    ]
    for p, c in flagged_pairs:
        if (p, c) in shown:
            out.append(f'"{q(c)}" [fillcolor="#FEE2E2", color="#DC2626"];')
    for (p, c), n in sorted(shown.items(), key=lambda kv: -kv[1]):
        w = 0.8 + 3.5 * math.log1p(n) / math.log1p(mx)
        col = "#DC2626" if (p, c) in flagged_pairs else "#94A3B8"
        out.append(f'"{q(p)}" -> "{q(c)}" [label=" {n:,}", penwidth={w:.2f}, color="{col}"];')
    out.append("}")
    return "\n".join(out)


def icicle_fig(df: pd.DataFrame, flag_min: int) -> go.Figure:
    """Every process folded by its name-path from the root (explorer › chrome › chrome …).
    10,000 processes usually collapse into a few dozen branches."""
    totals: Counter = Counter()
    own_risk: dict = defaultdict(int)
    for path, score in zip(df["path"], df["score"]):
        own_risk[path] = max(own_risk[path], int(score))
        for i in range(1, len(path) + 1):
            totals[path[:i]] += 1
    keys = list(totals)

    def colour(k):
        r = own_risk.get(k, 0)
        return SEVERITY_STYLE[severity(r)][0] if r >= flag_min else INDIGO[min(len(k) - 1, len(INDIGO) - 1)]

    def text_colour(k):
        return "#FFFFFF" if own_risk.get(k, 0) >= flag_min or len(k) <= 3 else "#1E1B4B"

    fig = go.Figure(go.Icicle(
        ids=["›".join(k) for k in keys],
        labels=[k[-1] for k in keys],
        parents=["›".join(k[:-1]) for k in keys],
        values=[totals[k] for k in keys],
        branchvalues="total",
        marker=dict(colors=[colour(k) for k in keys], line=dict(width=1, color="rgba(255,255,255,.7)")),
        textfont=dict(color=[text_colour(k) for k in keys], family="Inter, sans-serif"),
        texttemplate="<b>%{label}</b><br>%{value:,}",
        customdata=[" › ".join(k) for k in keys],
        hovertemplate="<b>%{label}</b> · %{value:,} processes<br>%{customdata}<extra></extra>",
        tiling=dict(orientation="h"),
        maxdepth=min(5, max(len(k) for k in keys)),
    ))
    fig.update_layout(margin=dict(t=4, l=0, r=0, b=0), height=540, paper_bgcolor="rgba(0,0,0,0)")
    return fig


# ───────────────────────── UI pieces ─────────────────────────
def legend() -> None:
    st.markdown(
        '<div class="legend">' + "".join(pill(s) for s in ("critical", "high", "medium", "low"))
        + '<span class="muted">· dashed box = siblings grouped · purple border = focus</span></div>',
        unsafe_allow_html=True,
    )


def render_details(r: dict) -> None:
    sev = r["severity"]
    badge = pill(sev, f"{sev} · {int(r['score'])}") if r["score"] else pill("none", "no findings")
    st.markdown(f'<div class="chain-title">{esc(r["name"])} &nbsp;{badge}</div>', unsafe_allow_html=True)
    st.code(r["command_line"] or "(no command line)", language="powershell", wrap_lines=True)

    decoded = decode_powershell(r["command_line"])
    if decoded:
        st.markdown("**🔓 Decoded `-enc` payload**")
        st.code(decoded, language="powershell", wrap_lines=True)

    for f in r["findings"]:
        st.markdown(f"**+{f.points}** &nbsp;`{f.rule}` — {f.why}")

    if pd.notna(r["end"]):
        runtime = fmt_dur((r["end"] - r["start"]).total_seconds())
    else:
        runtime = "still running"
    exit_code = "—" if pd.isna(r["exit_code"]) else str(int(r["exit_code"]))
    signer = r["signer"] if isinstance(r["signer"], str) else None
    trusted = r["trusted"] if isinstance(r["trusted"], bool) else None
    if signer:
        sig = f"✅ {esc(signer)}"
    elif trusted is False:
        sig = "⚠️ unsigned"
    else:
        sig = "—"
    st.markdown(kv([
        ("Executable", f'<span class="mono">{esc(r["executable"])}</span>'),
        ("Working dir", f'<span class="mono">{esc(r["working_directory"])}</span>'),
        ("Signature", sig),
        ("Started", r["start"].strftime("%a %b %d %Y · %H:%M:%S UTC")),
        ("Runtime", f"{runtime} · exit {exit_code}"),
        ("Parent", f'{esc(r["parent_name"])} <span class="muted">(pid {r["parent_pid"]})</span>'),
        ("Host", esc(str(r["host"]))),
        ("SHA-256", f'<span class="mono">{esc(str(r["sha256"])[:32])}…</span>'),
        ("entity_id", f'<span class="mono">{esc(r["entity_id"])}</span>'),
    ]), unsafe_allow_html=True)


def feed_row(r: dict, flag_min: int) -> str:
    hot = r["score"] >= flag_min
    badge = pill(r["severity"], str(int(r["score"]))) if r["score"] else pill("none", "ok")
    cls = "feed-row hot" if hot else "feed-row"
    return (f'<div class="{cls}"><span class="mono muted">{r["start"]:%H:%M:%S}</span> &nbsp;{badge} &nbsp;'
            f'<b>{esc(r["parent_name"])}</b> → <b>{esc(r["name"])}</b> &nbsp;'
            f'<span class="mono muted">{esc(r["command_line"][:120])}</span></div>')


@st.fragment(run_every="3s")
def live_panel(user: str, flag_min: int) -> None:
    key = f"live::{user}"
    if key not in st.session_state:
        st.session_state[key] = {"cursor": datetime.now(timezone.utc) - timedelta(seconds=60),
                                 "seen": set(), "events": [], "polls": 0, "flagged": 0}
    state = st.session_state[key]
    # ask with a 10 s overlap (ingest isn't instant), then de-dupe by entity_id
    _, resp = get_source().search("live_since", user=user, since_ts=iso(state["cursor"] - timedelta(seconds=10)))
    state["polls"] += 1
    batch = enrich(flatten(resp["hits"]["hits"]))
    fresh = [r for r in batch.to_dict("records") if r["entity_id"] not in state["seen"]]
    for r in fresh:
        state["seen"].add(r["entity_id"])
        if r["score"] >= flag_min:
            state["flagged"] += 1
            st.toast(f"{r['parent_name']} → {r['name']} · risk {int(r['score'])}", icon="🚨")
    if fresh:
        newest = max(r["start"] for r in fresh).to_pydatetime()
        state["cursor"] = max(state["cursor"], newest)
        state["events"] = sorted(fresh, key=lambda r: r["start"], reverse=True) + state["events"]
        del state["events"][300:]

    c = st.columns(4)
    c[0].metric("Events received", len(state["seen"]))
    c[1].metric("Flagged", state["flagged"])
    c[2].metric("New this poll", len(fresh))
    c[3].metric("Polls", state["polls"])
    if not state["events"]:
        st.caption("Waiting for the first events…")
    else:
        st.markdown("".join(feed_row(r, flag_min) for r in state["events"][:40]), unsafe_allow_html=True)


def _set(key: str, value) -> None:
    st.session_state[key] = value


# ───────────────────────── page ─────────────────────────
source = get_source()

with st.sidebar:
    st.markdown('<div class="brand">🌳 Family Tree Detective</div>', unsafe_allow_html=True)
    st.caption("Who launched what, from where — built on ECS `process.*` fields.")
    window = st.selectbox("Time window", list(TIME_RANGES), index=2)
    since = TIME_RANGES[window]
    users_req, user_buckets = load_users(since)
    if not user_buckets:
        st.warning("No process events in this window.")
        st.stop()
    counts = {b["key"]: b["doc_count"] for b in user_buckets}
    user = st.selectbox("user.name", list(counts), format_func=lambda u: f"{u}  ·  {counts[u]:,} processes",
                        help="Type to search.")
    flag_min = st.slider("Flag at risk ≥", 5, 80, 15, 5,
                         help="Processes at or above this score are flagged and grouped into chains.")
    show_queries = st.toggle("Show the Elastic queries", value=False)
    st.divider()
    st.caption("🧪 Running on mock data" if source.is_mock else f"🔌 Live cluster · {source.target}")

sum_req, total, aggs = load_summary(user, since)
proc_reqs, df, truncated = load_processes(user, since)
rows, children = build_index(user, since)
chains = build_chains(rows, flag_min)
flagged_n = int((df["score"] >= flag_min).sum()) if not df.empty else 0

hosts = ", ".join(b["key"] for b in aggs["hosts"]["buckets"]) or "—"
st.markdown(f'<div class="hero"><div class="eyebrow">Investigating</div><h1>{esc(user)}</h1>'
            f'<div class="sub">{esc(hosts)} · {esc(window.lower())}</div></div>', unsafe_allow_html=True)

m = st.columns(5)
m[0].metric("Processes", f"{total:,}")
m[1].metric("Unique executables", f"{aggs['unique_executables']['value']:,}")
m[2].metric("Deepest lineage", f"{int(df['depth'].max()) + 1 if len(df) else 0} levels")
m[3].metric("Flagged processes", f"{flagged_n:,}")
m[4].metric("Suspicious chains", len(chains))
if truncated:
    st.info(f"Showing the first {MAX_FETCH:,} processes. Aggregate views (counts, edge map) still cover everything.")

if show_queries:
    with st.expander("🔍 The queries behind this page", expanded=True):
        qt = st.tabs(["users_overview", "user_summary", "user_processes", "live_since"])
        qt[0].json(users_req["body"], expanded=2)
        qt[1].json(sum_req["body"], expanded=2)
        qt[2].caption(f"{len(proc_reqs)} page(s) fetched with search_after — showing the last one")
        qt[2].json(proc_reqs[-1]["body"], expanded=2)
        qt[3].json(live_since(user, "<newest @timestamp seen>")["body"], expanded=2)

tab_chains, tab_patterns, tab_explore, tab_live = st.tabs(
    [f"🚨 Suspicious chains ({len(chains)})", "🧬 Family patterns", "🔎 Process explorer", "📡 Live"]
)

# ── 🚨 chains ──
with tab_chains:
    if not chains:
        st.success(f"Nothing crossed risk {flag_min} for {user} in this window. 🎉  "
                   "Try the patterns tab to see what normal looks like, or lower the threshold.")
    else:
        sel_key = f"chain::{user}::{since}"
        if st.session_state.get(sel_key) not in {c["root"] for c in chains}:
            st.session_state[sel_key] = chains[0]["root"]
        left, right = st.columns([0.36, 0.64], gap="large")
        with left:
            st.markdown("##### Ranked by peak risk")
            for c in chains:
                root = rows[c["root"]]
                sev = severity(c["peak"])
                stages = " → ".join(dict.fromkeys(rows[x]["name"] for x in c["members"]))
                active = st.session_state[sel_key] == c["root"]
                with st.container(border=True):
                    when = root["start"].strftime("%a %b %d · %H:%M")
                    badge = pill(sev, f"{sev} · peak {c['peak']}")
                    st.markdown(f'{badge} '
                                f'<span class="muted small">{when} · {esc(str(root["host"]))}</span>',
                                unsafe_allow_html=True)
                    st.markdown(f'<div class="chain-title">{esc(root["parent_name"])} → {esc(root["name"])}</div>'
                                f'<div class="mono muted">{esc(stages)}</div>', unsafe_allow_html=True)
                    st.caption(f'{len(c["members"])} flagged · ' + " · ".join(c["rules"][:4]))
                    st.button("Investigating" if active else "Investigate →", key=f"btn::{c['root']}",
                              type="primary" if active else "secondary", width="stretch",
                              on_click=_set, args=(sel_key, c["root"]))
        with right:
            chain = next(c for c in chains if c["root"] == st.session_state[sel_key])
            st.markdown("##### Lineage")
            st.graphviz_chart(lineage_dot(rows, children, chain["root"], flag_min), width="stretch")
            legend()
            st.divider()
            options = ancestors_of(rows, chain["root"]) + chain["members"]
            pick = st.selectbox(
                "Inspect a process in this chain", options, index=len(options) - len(chain["members"]),
                format_func=lambda e: f'{rows[e]["start"]:%H:%M:%S}   {rows[e]["name"]}   (risk {int(rows[e]["score"])})',
                key=f"pick::{chain['root']}",
            )
            render_details(rows[pick])

# ── 🧬 patterns ──
with tab_patterns:
    st.markdown("##### When did things run?")
    ph = pd.DataFrame(aggs["per_hour"]["buckets"])
    if not ph.empty:
        ph["t"] = pd.to_datetime(ph["key"], unit="ms", utc=True)
        fig = go.Figure(go.Bar(x=ph["t"], y=ph["doc_count"], name="processes", marker_color="#818CF8",
                               hovertemplate="%{x|%b %d %H:00}<br>%{y:,} processes<extra></extra>"))
        hot = df[df["score"] >= flag_min]
        if not hot.empty:
            hh = hot.groupby(hot["start"].dt.floor("h")).size()
            fig.add_bar(x=hh.index, y=hh.values, name="flagged", marker_color="#DC2626",
                        hovertemplate="%{x|%b %d %H:00}<br>%{y} flagged<extra></extra>")
        fig.update_layout(height=200, margin=dict(l=0, r=0, t=6, b=0), barmode="overlay", bargap=0.1,
                          showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          xaxis=dict(showgrid=False), yaxis=dict(gridcolor="rgba(128,128,128,.15)"))
        st.plotly_chart(fig, width="stretch")

    st.markdown("##### Lineage map")
    st.caption("Every process folded by its name-path from the root. Click a block to zoom in, "
               "click the left edge to zoom out. Red = flagged.")
    if df.empty:
        st.caption("No processes.")
    else:
        st.plotly_chart(icicle_fig(df, flag_min), width="stretch")

    st.markdown("##### Who spawns whom")
    st.caption("From the `multi_terms` aggregation, so it covers every event, not just the fetched ones. "
               "Line thickness = how often; red = a flagged link.")
    pairs: Counter = Counter()
    for b in aggs["edges"]["buckets"]:
        p, ch = b["key"]
        pairs[(str(p).lower(), str(ch).lower())] += b["doc_count"]
    hot = df[df["score"] >= flag_min]
    flagged_pairs = set(zip(hot["parent_name"], hot["name"]))
    top_count = max(pairs.values()) if pairs else 1
    min_count = st.slider("Hide links seen fewer than", 1, max(2, min(100, top_count)), 1, key="edge_min")
    dot = edge_dot(pairs, flagged_pairs, min_count)
    if dot:
        st.graphviz_chart(dot, width="stretch")

# ── 🔎 explorer ──
with tab_explore:
    f1, f2, f3 = st.columns([0.55, 0.3, 0.15])
    q = f1.text_input("Search name or command line", placeholder="e.g. powershell, -enc, \\Temp\\, certutil")
    sev_pick = f2.multiselect("Severity", ["critical", "high", "medium", "low", "none"])
    only_flagged = f3.toggle("Only flagged", value=False)
    view = df
    if q:
        view = view[view["name"].str.contains(q, case=False, regex=False)
                    | view["command_line"].str.contains(q, case=False, regex=False)]
    if sev_pick:
        view = view[view["severity"].isin(sev_pick)]
    if only_flagged:
        view = view[view["score"] >= flag_min]
    view = view.sort_values("start", ascending=False).reset_index(drop=True)
    st.caption(f"{len(view):,} of {len(df):,} processes · select a row to see its family tree")
    event = st.dataframe(
        view[["start", "name", "parent_name", "score", "command_line", "pid", "host"]],
        column_config={
            "start": st.column_config.DatetimeColumn("Started (UTC)", format="MMM D, HH:mm:ss"),
            "name": "Process",
            "parent_name": "Parent",
            "score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
            "command_line": st.column_config.TextColumn("Command line", width="large"),
            "pid": st.column_config.NumberColumn("PID", format="%d"),
            "host": "Host",
        },
        hide_index=True, width="stretch", height=360,
        on_select="rerun", selection_mode="single-row", key=f"grid::{user}::{since}",
    )
    if event.selection.rows:
        eid = view.iloc[event.selection.rows[0]]["entity_id"]
        g, d = st.columns([0.6, 0.4], gap="large")
        with g:
            st.markdown("##### Lineage")
            st.graphviz_chart(lineage_dot(rows, children, eid, flag_min), width="stretch")
            legend()
        with d:
            st.markdown("##### Details")
            render_details(rows[eid])

# ── 📡 live ──
with tab_live:
    st.markdown("##### Live feed")
    st.caption("Polls Elastic every 3 s for anything this user started after the newest event already seen "
               "(with a 10 s overlap + de-dup, because ingest isn't instant). Flagged events pop a toast.")
    if st.toggle("Go live", key=f"live_on::{user}"):
        live_panel(user, flag_min)
