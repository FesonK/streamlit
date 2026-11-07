"""
app.py — Deep String Finder 🔎  (Streamlit)

    pip install -r requirements.txt
    streamlit run app.py

Flow: UI widgets -> query_dict.build_search_request() -> mock_search() -> render.
Going live = replace `mock_search(...)` with `es.search(index=..., body=...)`.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, time as dtime, timedelta, timezone

import altair as alt
import pandas as pd
import streamlit as st

from mock_data import NOW, QueryParseError, mock_search
from query_dict import (
    ALL_INDICES,
    FIELD_SCOPES,
    INDEX_PATTERNS,
    TIME_PRESETS,
    build_search_request,
    kibana_doc_url,
    query_warnings,
)

st.set_page_config(page_title="Deep String Finder", page_icon="🔎", layout="wide")

# --------------------------------------------------------------------------- #
# Styling — dark SOC console
# --------------------------------------------------------------------------- #
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;800&family=JetBrains+Mono:wght@400;600&display=swap');
:root { --cyan:#22d3ee; --violet:#a78bfa; --pink:#f472b6; --amber:#fbbf24; --panel:#0f172a; --edge:#1e293b; --muted:#94a3b8; }
html, body, p, label, button, input, .stMarkdown { font-family: 'Inter', sans-serif; }
[data-testid="stIconMaterial"] { font-family: 'Material Symbols Rounded' !important; }
.block-container { padding-top: 2.2rem; max-width: 1180px; }
.hero { text-align:center; margin-bottom: 1.2rem; }
.hero h1 { font-size: 2.7rem; font-weight: 800; letter-spacing:-0.02em; margin: 0;
  background: linear-gradient(90deg, var(--cyan), var(--violet) 55%, var(--pink)); -webkit-background-clip: text; color: transparent; }
.hero p { color: var(--muted); margin: .3rem 0 0; font-size: 1.02rem; }
.stTextInput input { font-family: 'JetBrains Mono', monospace !important; font-size: 1.05rem !important;
  padding: .85rem 1rem !important; border-radius: 12px !important; }
div[data-testid="stForm"] { background: var(--panel); border: 1px solid var(--edge); border-radius: 18px; padding: 1.1rem 1.2rem .4rem; }
.chips-label { color: var(--muted); font-size: .8rem; margin: .7rem 0 .2rem; }
.warn-row { display:flex; flex-wrap:wrap; gap:6px; margin:.6rem 0 .2rem; }
.warn { font-size:.75rem; color: var(--amber); border:1px solid #fbbf2440; background:#fbbf240d; padding:3px 9px; border-radius:999px; }
.hit { background: var(--panel); border: 1px solid var(--edge); border-radius: 14px; padding: 14px 18px 12px; margin: 12px 0 2px; transition: border-color .15s; }
.hit:hover { border-color: #22d3ee66; }
.hit-head { display:flex; flex-wrap:wrap; gap:8px 12px; align-items:center; font-size:.82rem; color: var(--muted); }
.badge { font-family:'JetBrains Mono', monospace; font-size:.72rem; padding:2px 8px; border-radius:6px; border:1px solid; }
.badge.idx { color: var(--violet); border-color:#a78bfa55; background:#a78bfa10; }
.badge.ds  { color: var(--cyan);   border-color:#22d3ee55; background:#22d3ee10; }
.doc-link { margin-left:auto; font-family:'JetBrains Mono', monospace; font-size:.75rem; color: var(--cyan) !important; text-decoration:none; }
.doc-link:hover { text-decoration: underline; }
.hl { margin-top: 10px; }
.hl-field { font-family:'JetBrains Mono', monospace; font-size:.72rem; color: var(--pink); margin-bottom: 2px; }
.hl-frag { font-family:'JetBrains Mono', monospace; font-size:.8rem; color:#cbd5e1; line-height:1.55; word-break: break-all; }
.hl-frag .sep { color:#475569; padding: 0 4px; }
.hit mark { background: var(--amber); color:#0b1020; border-radius:3px; padding:0 2px; font-weight:600; }
.summary { font-family:'JetBrains Mono', monospace; font-size:.8rem; color:#cbd5e1; margin-top:10px; word-break: break-all; }
.summary .k { color: var(--muted); }
.toplist { display:flex; flex-wrap:wrap; gap:6px; align-items:center; font-size:.8rem; color: var(--muted); margin:.2rem 0 .4rem; }
.toplist .pill { font-family:'JetBrains Mono', monospace; background:#1e293b; color:#e2e8f0; padding:2px 8px; border-radius:999px; font-size:.75rem; }
.empty { background: var(--panel); border:1px dashed var(--edge); border-radius:16px; padding:1.3rem 1.5rem; color:#cbd5e1; margin-top:1rem; }
.empty code { color: var(--cyan); background:#22d3ee12; padding:1px 6px; border-radius:5px; }
.empty .tip { color: var(--muted); font-size:.85rem; }
</style>
""",
    unsafe_allow_html=True,
)

EXAMPLES = [
    "*sekurlsa*",
    "x7k2-update.com",
    "process.command_line:*-enc*",
    "*Invoke-Mimikatz*",
    "url.full:*password=*",
    "dns.question.name:*exfil*",
    '"authorized_keys"',
    "*minexmr* OR *kworkerd*",
]

SUMMARY_FIELDS = ["process.command_line", "url.full", "dns.question.name", "registry.path", "file.path", "message"]

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _get(src: dict, path: str):
    cur = src
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur[0] if isinstance(cur, list) and cur else cur


def _clean(fragment: str) -> str:
    """One line (so markdown keeps it as one HTML block) and no `$` (Streamlit would render LaTeX)."""
    return re.sub(r"\s+", " ", fragment).replace("$", "&#36;")


def _esc(text) -> str:
    return _clean(html.escape(str(text)))


def _index_group(name: str) -> str:
    name = name[4:] if name.startswith(".ds-") else name
    return re.sub(r"-\d{4}\.\d{2}\.\d{2}(-\d+)?$", "", name)


def _set_example(q: str) -> None:
    st.session_state.q = q
    st.session_state.auto_run = True


def _pretty_ts(iso: str) -> str:
    return iso.replace("T", " ")[:19] + " UTC"


# --------------------------------------------------------------------------- #
# Rendering pieces
# --------------------------------------------------------------------------- #
def render_hit(hit: dict) -> None:
    src = hit["_source"]
    head = (
        f'<span>🕒 {_esc(_pretty_ts(src.get("@timestamp", "")))}</span>'
        f'<span class="badge idx">{_esc(_index_group(hit["_index"]))}</span>'
        f'<span class="badge ds">{_esc(_get(src, "event.dataset") or "—")}</span>'
        f'<span>🖥 {_esc(_get(src, "host.name") or "—")}</span>'
        f'<span>👤 {_esc(_get(src, "user.name") or "—")}</span>'
        f'<a class="doc-link" href="{html.escape(kibana_doc_url(hit["_index"], hit["_id"]))}" target="_blank">🔗 {_esc(hit["_id"])}</a>'
    )
    highlight = hit.get("highlight") or {}
    if highlight:
        sep = ' <span class="sep">⋯</span> '
        body = "".join(
            f'<div class="hl"><div class="hl-field">{_esc(field)}</div>'
            f'<div class="hl-frag">{sep.join(_clean(f) for f in frags)}</div></div>'
            for field, frags in highlight.items()
        )
    else:  # match-all query: show the most telling field instead
        field = next((f for f in SUMMARY_FIELDS if _get(src, f)), None)
        value = str(_get(src, field))[:220] if field else ""
        body = f'<div class="summary"><span class="k">{_esc(field or "")}</span> {_esc(value)}</div>' if field else ""
    st.markdown(f'<div class="hit"><div class="hit-head">{head}</div>{body}</div>', unsafe_allow_html=True)
    with st.expander(f"Raw document · {hit['_id']}", expanded=False):
        st.json(src, expanded=True)


def histogram_chart(buckets: list[dict]) -> alt.Chart:
    keys = [b["key"] for b in buckets]
    step = (keys[1] - keys[0]) if len(keys) > 1 else 60_000
    span_ms = (keys[-1] - keys[0]) if keys else 0
    df = pd.DataFrame({
        "time": pd.to_datetime(keys, unit="ms", utc=True),
        "end": pd.to_datetime([k + step for k in keys], unit="ms", utc=True),
        "hits": [b["doc_count"] for b in buckets],
    })
    label_fmt = "%b %d" if span_ms > 2 * 86_400_000 else "%H:%M"
    return (
        alt.Chart(df, height=170, title=alt.Title("Hits over time", anchor="start", fontSize=13, color="#94a3b8"))
        .mark_bar(color="#22d3ee", cornerRadiusTopLeft=2, cornerRadiusTopRight=2, opacity=0.9)
        .encode(
            x=alt.X("time:T", title=None, axis=alt.Axis(grid=False, format=label_fmt, labelColor="#64748b",
                                                       tickColor="#1e293b", domainColor="#1e293b")),
            x2="end:T",
            y=alt.Y("hits:Q", title=None, axis=alt.Axis(gridColor="#1e293b", labelColor="#64748b", domain=False,
                                                       format="d", tickMinStep=1, tickCount=4)),
            y2=alt.datum(0),   # ranged x + explicit baseline => vertical bars
            tooltip=[alt.Tooltip("time:T", title="Bucket", format="%b %d %H:%M"), alt.Tooltip("hits:Q", title="Hits")],
        )
        .configure_view(strokeWidth=0)
        .configure(background="transparent")
    )


def index_chart(buckets: list[dict]) -> alt.Chart:
    grouped: dict[str, int] = {}
    for b in buckets:
        g = _index_group(b["key"])
        grouped[g] = grouped.get(g, 0) + b["doc_count"]
    df = pd.DataFrame({"index": list(grouped), "hits": list(grouped.values())})
    return (
        alt.Chart(df, height=170, title=alt.Title("Hits by index", anchor="start", fontSize=13, color="#94a3b8"))
        .mark_bar(cornerRadiusEnd=4, color="#a78bfa", height=14)
        .encode(
            y=alt.Y("index:N", sort="-x", title=None, axis=alt.Axis(labelColor="#cbd5e1", labelLimit=220, domain=False, ticks=False)),
            x=alt.X("hits:Q", title=None, axis=alt.Axis(gridColor="#1e293b", labelColor="#64748b", domain=False,
                                                       format="d", tickMinStep=1, tickCount=3)),
            tooltip=["index", "hits"],
        )
        .configure_view(strokeWidth=0)
        .configure(background="transparent")
    )


def results_csv(hits: list[dict]) -> bytes:
    rows = [{
        "@timestamp": h["_source"].get("@timestamp"),
        "_index": h["_index"],
        "_id": h["_id"],
        "event.dataset": _get(h["_source"], "event.dataset"),
        "host.name": _get(h["_source"], "host.name"),
        "user.name": _get(h["_source"], "user.name"),
        "matched_fields": ";".join((h.get("highlight") or {}).keys()),
        "link": kibana_doc_url(h["_index"], h["_id"]),
    } for h in hits]
    return pd.DataFrame(rows).to_csv(index=False).encode()


def toplist(label: str, buckets: list[dict]) -> str:
    pills = "".join(f'<span class="pill">{_esc(b["key"])} · {b["doc_count"]}</span>' for b in buckets)
    return f'<div class="toplist"><span>{label}</span>{pills or "—"}</div>'


def render_results(res: dict) -> None:
    req, resp = res["req"], res["resp"]
    total = resp["hits"]["total"]["value"]
    aggs = resp["aggregations"]
    body = req["body"]

    if res["warnings"]:
        st.markdown('<div class="warn-row">' + "".join(f'<span class="warn">⚠ {_esc(w)}</span>' for w in res["warnings"]) + "</div>",
                    unsafe_allow_html=True)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hits", f"{total:,}")
    m2.metric("Hosts", aggs["unique_hosts"]["value"])
    m3.metric("Users", aggs["unique_users"]["value"])
    m4.metric("Took", f'{resp["took"]} ms')

    if total:
        c1, c2 = st.columns([3, 2])
        c1.altair_chart(histogram_chart(aggs["hits_over_time"]["buckets"]), width="stretch")
        c2.altair_chart(index_chart(aggs["by_index"]["buckets"]), width="stretch")

    tab_hits, tab_dsl, tab_raw = st.tabs(["📄 Results", "🧾 Query DSL", "📦 Raw response"])

    with tab_hits:
        if not total:
            st.info("No needles in this haystack. Try a wider time range, more indices, or wrap your term in *wildcards*.")
        else:
            hits = resp["hits"]["hits"]
            frm = body["from"]
            st.markdown(toplist("Top hosts", aggs["top_hosts"]["buckets"]) + toplist("Top datasets", aggs["top_datasets"]["buckets"]),
                        unsafe_allow_html=True)
            left, right = st.columns([3, 1], vertical_alignment="center")
            left.caption(f"Showing {frm + 1}–{frm + len(hits)} of {total:,} · newest first" if body["sort"][0]["@timestamp"]["order"] == "desc"
                         else f"Showing {frm + 1}–{frm + len(hits)} of {total:,} · oldest first")
            right.download_button("⬇ Export CSV", results_csv(hits), file_name="deep_string_finder_results.csv",
                                  mime="text/csv", width="stretch")
            if not hits:
                st.warning("This page is past the last result — lower the page number in Advanced.")
            for hit in hits:
                render_hit(hit)

    with tab_dsl:
        st.caption("This is exactly what query_dict.py built. Paste it into Kibana Dev Tools as `GET <index>/_search`.")
        st.code(f"GET {req['index']}/_search\n" + json.dumps(body, indent=2), language="json")
        st.caption("Or from Python (elasticsearch-py):")
        st.code(f'resp = es.search(index="{req["index"]}", body=body)', language="python")

    with tab_raw:
        st.caption("The mock cluster's response, shaped like the real thing.")
        st.json(resp, expanded=False)


def render_empty_state() -> None:
    st.markdown(
        """<div class="empty">
<b>Lucene cheat-sheet for needle hunting</b><br><br>
<code>*mimikatz*</code> substring anywhere &nbsp;·&nbsp; <code>"exact phrase"</code> &nbsp;·&nbsp;
<code>process.command_line:*-enc*</code> one field &nbsp;·&nbsp; <code>process.*:*rundll32*</code> field wildcard<br>
<code>a AND b</code> &nbsp;·&nbsp; <code>a OR b</code> &nbsp;·&nbsp; <code>NOT user.name:svc_backup</code> &nbsp;·&nbsp;
<code>-term</code> &nbsp;·&nbsp; <code>( … )</code> grouping &nbsp;·&nbsp; <code>/regex/</code> &nbsp;·&nbsp; <code>registry.path:*</code> field exists<br><br>
<span class="tip">💡 On real clusters, keyword fields such as <code>process.command_line</code> only match whole values,
so wrap terms in <code>*wildcards*</code>. Quote anything containing <code>/</code> or <code>:</code>, and escape backslashes as <code>\\\\</code>.<br>
🧪 The mock cluster's clock is frozen at startup ("""
        + _esc(NOW.strftime("%Y-%m-%d %H:%M UTC"))
        + """), so the recent needles stay findable.</span>
</div>""",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #
for key, default in {"q": "", "auto_run": False, "result": None, "error": None}.items():
    st.session_state.setdefault(key, default)

st.markdown('<div class="hero"><h1>🔎 Deep String Finder</h1>'
            "<p>Find the needle buried 4KB deep in your ECS haystack.</p></div>", unsafe_allow_html=True)

with st.form("search", border=False):
    c_q, c_btn = st.columns([7, 1], vertical_alignment="bottom")
    c_q.text_input("Lucene query", key="q", label_visibility="collapsed",
                   placeholder='*mimikatz*   ·   process.command_line:*-enc*   ·   "authorized_keys"')
    submitted = c_btn.form_submit_button("Search", type="primary", width="stretch")

    f_idx, f_time, f_scope = st.columns([3, 2, 2])
    indices = f_idx.multiselect("Indices", [ALL_INDICES] + INDEX_PATTERNS, default=[ALL_INDICES], key="indices")
    preset = f_time.selectbox("Time range", list(TIME_PRESETS), index=3, key="preset")
    scope = f_scope.selectbox("Search in", list(FIELD_SCOPES), index=0, key="scope",
                              help="Narrow the haystack to the fields strings love to hide in.")

    with st.expander("⚙️ Advanced: custom range, paging, sort"):
        a1, a2, a3, a4 = st.columns(4)
        start_d = a1.date_input("Custom start (UTC)", value=(NOW - timedelta(days=1)).date(), key="start_d")
        start_t = a1.time_input("Start time", value=dtime(0, 0), key="start_t")
        end_d = a2.date_input("Custom end (UTC)", value=NOW.date(), key="end_d")
        end_t = a2.time_input("End time", value=dtime(23, 59), key="end_t")
        size = a3.select_slider("Results per page", [10, 25, 50, 100], value=25, key="size")
        page = a3.number_input("Page", min_value=1, max_value=1000, value=1, key="page")
        sort = a4.radio("Sort", ["Newest first", "Oldest first"], key="sort")
        a4.caption("Custom dates apply when Time range = Custom.")

st.markdown('<div class="chips-label">Try a planted needle →</div>', unsafe_allow_html=True)
chip_cols = st.columns(4)
for i, ex in enumerate(EXAMPLES):
    label = re.sub(r"([*_`])", r"\\\1", ex)  # button labels are Markdown: keep the literal *stars*
    chip_cols[i % 4].button(label, key=f"ex{i}", on_click=_set_example, args=(ex,), width="stretch")

run = submitted or st.session_state.auto_run
st.session_state.auto_run = False

if run:
    start = datetime.combine(start_d, start_t, tzinfo=timezone.utc)
    end = datetime.combine(end_d, end_t, tzinfo=timezone.utc)
    st.session_state.error = None
    if preset == "Custom" and end <= start:
        st.session_state.error = "Custom range: end must be after start."
    else:
        fields = FIELD_SCOPES[scope]
        req = build_search_request(
            indices=indices, query=st.session_state.q, time_preset=preset, start=start, end=end,
            fields=fields, size=size, from_=(page - 1) * size,
            sort_order="desc" if sort == "Newest first" else "asc",
        )
        try:
            resp = mock_search(req["index"], req["body"])   # ← swap for es.search(index=..., body=...)
            st.session_state.result = {"req": req, "resp": resp,
                                       "warnings": query_warnings(st.session_state.q, fields, req["index"])}
        except QueryParseError as exc:
            st.session_state.error = f"query_shard_exception: {exc}"

st.divider()
if st.session_state.error:
    st.error(st.session_state.error, icon="🚫")
if st.session_state.result:
    render_results(st.session_state.result)
else:
    render_empty_state()
