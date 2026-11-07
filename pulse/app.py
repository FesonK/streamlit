"""
app.py — 💓 Pulse: what the fleet is quietly telling you.

Six exhibits built on plain ECS process-creation telemetry. Each finds a pattern
that is invisible event by event and only appears across the fleet over time.

    streamlit run app.py                                         # mock data
    FTD_MODE=elastic ES_URL=... ES_API_KEY=... streamlit run app.py
"""
from __future__ import annotations

import html
import math
import zlib
from collections import deque
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import exhibits as E
from data_source import DataSource
from query_dict import AT_SCALE, TIME_RANGES, fleet_processes, live_since

st.set_page_config(page_title="Pulse", page_icon="💓", layout="wide")
esc = html.escape

INK, MUTED, GRID = "#E6EAF2", "#8B95AD", "rgba(255,255,255,.06)"
PINK, CYAN, VIOLET, AMBER, RED, GREEN, SLATE, BLUE = ("#FF4D8D", "#22D3EE", "#A78BFA", "#F59E0B", "#F43F5E",
                                                       "#34D399", "#64748B", "#60A5FA")
DEPT_COLOR = {"FIN": BLUE, "SAL": PINK, "HR": GREEN, "DEV": AMBER, "IT": VIOLET, "MKT": "#FB923C", "OTHER": SLATE}
CLASS_COLOR = {"Worm-like": RED, "Phishing-like": AMBER, "Organic adoption": GREEN, "Managed rollout": BLUE,
               "Unclear": SLATE}

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] {{ font-family:'Inter',system-ui,sans-serif; }}
[data-testid="stAppViewContainer"] {{ background:
   radial-gradient(1200px 500px at 85% -10%, rgba(255,77,141,.10), transparent 60%),
   radial-gradient(900px 400px at -10% 10%, rgba(34,211,238,.07), transparent 60%), #0A0E1A; }}
.block-container {{ padding-top:2.6rem; padding-bottom:4rem; max-width:1460px; }}
h1,h2,h3,h4 {{ font-family:'Space Grotesk','Inter',system-ui,-apple-system,sans-serif; letter-spacing:-.02em; }}
.eyebrow {{ font-size:.72rem; letter-spacing:.22em; text-transform:uppercase; color:{PINK}; font-weight:700; }}
.hero-title {{ font-family:'Space Grotesk','Inter',system-ui,-apple-system,sans-serif; font-size:2.6rem; font-weight:700; line-height:1.08; margin:.25rem 0 .4rem 0; }}
.hero-sub {{ color:{MUTED}; font-size:1rem; margin-bottom:1.2rem; }}
.beat {{ display:inline-block; width:10px; height:10px; border-radius:50%; background:{PINK}; margin-right:8px;
        box-shadow:0 0 0 0 rgba(255,77,141,.7); animation:beat 1.6s infinite; vertical-align:middle; }}
@keyframes beat {{ 0% {{box-shadow:0 0 0 0 rgba(255,77,141,.6)}} 70% {{box-shadow:0 0 0 12px rgba(255,77,141,0)}} 100% {{box-shadow:0 0 0 0 rgba(255,77,141,0)}} }}
.stat {{ display:inline-block; margin-right:26px; color:{MUTED}; font-size:.86rem; }}
.stat b {{ color:{INK}; font-family:'Space Grotesk','Inter',system-ui,-apple-system,sans-serif; font-size:1.25rem; margin-right:4px; }}
.grid {{ display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:14px; margin:.4rem 0 1.6rem 0; }}
@media (max-width: 900px) {{ .grid {{ grid-template-columns:1fr; }} }}
.fcard {{ display:block; text-decoration:none !important; color:{INK} !important; border-radius:16px; padding:16px 18px;
         background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.08); transition:.15s; }}
.fcard:hover {{ border-color:rgba(255,77,141,.5); background:rgba(255,255,255,.06); transform:translateY(-1px); }}
.fcard .k {{ font-size:.7rem; letter-spacing:.16em; text-transform:uppercase; color:{MUTED}; }}
.fcard .h {{ font-family:'Space Grotesk','Inter',system-ui,-apple-system,sans-serif; font-size:1.08rem; font-weight:600; margin:.35rem 0 .3rem 0; line-height:1.3; }}
.fcard .s {{ font-size:.82rem; color:{MUTED}; }}
.sev-hi {{ border-left:3px solid {RED}; }} .sev-md {{ border-left:3px solid {AMBER}; }} .sev-ok {{ border-left:3px solid {GREEN}; }}
.exh {{ margin-top:2.6rem; padding-top:1.2rem; border-top:1px solid rgba(255,255,255,.07); }}
.exh .num {{ font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; color:{PINK}; font-size:.8rem; letter-spacing:.1em; }}
.exh .t {{ font-family:'Space Grotesk','Inter',system-ui,-apple-system,sans-serif; font-size:1.75rem; font-weight:700; margin:.1rem 0; }}
.exh .q {{ color:{MUTED}; font-size:.98rem; max-width:900px; }}
.note {{ background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.07); border-radius:12px;
        padding:10px 14px; font-size:.85rem; color:#C9D1E4; margin:.4rem 0; }}
.card {{ background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.08); border-radius:14px;
        padding:12px 14px; margin-bottom:10px; }}
.badge {{ display:inline-block; padding:1px 9px; border-radius:999px; font-size:.7rem; font-weight:700;
         letter-spacing:.04em; margin-right:6px; }}
.mono {{ font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.78rem; word-break:break-all; }}
.muted {{ color:{MUTED}; }}
.chip {{ display:inline-block; padding:3px 9px; border-radius:8px; font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.76rem;
        background:rgba(255,255,255,.05); margin:3px 0; }}
.arrow {{ color:{MUTED}; margin:0 5px; font-size:.8rem; }}
.why {{ font-size:.84rem; color:#C9D1E4; margin-top:6px; }}
.why b {{ color:{INK}; }}
[data-testid="stMetric"] {{ background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:10px 14px; }}
</style>
""", unsafe_allow_html=True)


def layout(fig, h=380, **kw):
    fig.update_layout(height=h, margin=dict(l=8, r=8, t=24, b=8), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#C9D1E4", family="Inter, system-ui, sans-serif"),
                      legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)), **kw)
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def badge(text, color):
    return f'<span class="badge" style="color:{color};background:{color}22;border:1px solid {color}55">{esc(text)}</span>'


# ───────────────────────── privacy ─────────────────────────
if "audit" not in st.session_state:
    st.session_state.audit = []


def revealed() -> bool:
    return st.session_state.get("reveal_ok", False)


def who(u) -> str:
    u = str(u)
    if revealed() or u.upper() == "SYSTEM" or u == "?":
        return u
    return f"{u.split('.')[0][:1].upper()}·{zlib.crc32(u.encode()) % 65536:04x}"


def scrub(text: str, users) -> str:
    if revealed():
        return text
    for u in sorted(users, key=len, reverse=True):
        if u and u != "SYSTEM":
            text = text.replace(u, who(u))
    return text


# ───────────────────────── data ─────────────────────────
@st.cache_resource(show_spinner="Taking the fleet's pulse…")
def get_source():
    return DataSource()


@st.cache_data(ttl=600, show_spinner="Pulling process telemetry…")
def load(since):
    reqs, hits, trunc = get_source().fetch_all("fleet_processes", since=since)
    return E.frame(hits), len(reqs), trunc


@st.cache_data(ttl=600, show_spinner="Running the exhibits…")
def analyze(since):
    df, _, _ = load(since)
    hb = E.heartbeat(df)
    mk = set(hb.loc[hb["cls"] == "machine", "key"]) if not hb.empty else set()
    gr = E.grammar(df, mk)
    return {
        "heartbeat": hb, "machine_keys": mk,
        "outbreaks": E.outbreaks(df),
        "grammar": gr,
        "org": E.org_chart(df, gr["sessions"], mk),
        "novelty": E.novelty(df),
        "physics": E.physics(df),
    }


src = get_source()
with st.sidebar:
    st.markdown(f'<div style="font-family:&#39;Space Grotesk&#39;,&#39;Inter&#39;,system-ui,-apple-system,sans-serif;font-size:1.5rem;font-weight:700"><span class="beat"></span>Pulse</div>',
                unsafe_allow_html=True)
    st.caption("A fleet lab: patterns you only see across everyone, over time.")
    window = st.selectbox("Time window", list(TIME_RANGES), index=2)
    since = TIME_RANGES[window]
    st.divider()
    st.markdown("**Privacy mode**")
    st.caption("People are pseudonymized by default. Revealing names is a deliberate, logged action.")
    want = st.toggle("Reveal names", value=revealed())
    if want and not revealed():
        reason = st.text_input("Why do you need names?", placeholder="e.g. investigating ticket INC-4812")
        if reason.strip():
            st.session_state.reveal_ok = True
            st.session_state.audit.append((datetime.now().strftime("%H:%M:%S"), reason.strip()))
            st.rerun()
        else:
            st.warning("Give a reason to reveal names.")
    elif not want and revealed():
        st.session_state.reveal_ok = False
        st.rerun()
    if st.session_state.audit:
        with st.expander(f"Reveal log ({len(st.session_state.audit)})"):
            for t, r in st.session_state.audit:
                st.caption(f"{t} — {r}")
    st.divider()
    show_q = st.toggle("Show the Elastic queries", value=False)
    st.caption("🧪 Mock fleet" if src.is_mock else f"🔌 {src.target}")

df, pages, trunc = load(since)
R = analyze(since)
users_all = sorted(df["user"].unique())
hb, ob, gr, org, nv, ph = R["heartbeat"], R["outbreaks"], R["grammar"], R["org"], R["novelty"], R["physics"]

# ───────────────────────── hero ─────────────────────────
days = max(1, (df["ts"].max() - df["ts"].min()).days)
st.markdown(
    f'<div class="eyebrow"><span class="beat"></span>Fleet lab · {esc(window.lower())}</div>'
    f'<div class="hero-title">What the fleet is quietly telling you</div>'
    f'<div class="hero-sub">Six patterns that never show up event by event, only across everyone, over time. '
    f'Built from nothing but process-creation logs.</div>'
    f'<span class="stat"><b>{df["host"].nunique()}</b>machines</span>'
    f'<span class="stat"><b>{df.loc[df["human"], "user"].nunique()}</b>people</span>'
    f'<span class="stat"><b>{len(df):,}</b>process launches</span>'
    f'<span class="stat"><b>{days}</b>days</span>'
    f'<span class="stat"><b>{df["sha256"].nunique():,}</b>distinct binaries</span>',
    unsafe_allow_html=True)

if trunc:
    st.info("Hit the raw-event cap; on a big fleet use the at-scale aggregations (see queries).")
if show_q:
    with st.expander("🔍 The queries behind this page", expanded=True):
        qt = st.tabs(["fleet_processes", "live_since", "at scale: rhythm", "at scale: first seen", "at scale: app mix"])
        qt[0].caption(f"{pages} page(s) via search_after")
        qt[0].json(fleet_processes(since)["body"], expanded=2)
        qt[1].json(live_since("<newest seen>")["body"], expanded=2)
        qt[2].json(AT_SCALE["rhythm_streams"](since)["body"], expanded=2)
        qt[3].json(AT_SCALE["first_seen"]()["body"], expanded=2)
        qt[4].json(AT_SCALE["app_mix"](since)["body"], expanded=2)

# ───────────────────────── findings grid ─────────────────────────
cards = []
mach = hb[hb["cls"] == "machine"] if not hb.empty else hb
unexp = mach[mach["level"] == "high"] if not mach.empty else mach
if len(unexp):
    b = unexp.iloc[0]
    cards.append(("01 · Heartbeat", f"A {b['period']} rhythm nobody scheduled", f"{b['name']} on {b['host']} — fires {b['offhours']:.0%} at night/weekends", "sev-hi", "ex1"))
else:
    cards.append(("01 · Heartbeat", f"{len(mach)} machine rhythms, all explained", "No hidden automation", "sev-ok", "ex1"))
bad = [o for o in ob if o["cls"] in ("Worm-like", "Phishing-like")]
if bad:
    o = bad[0]
    cards.append(("02 · Outbreaks", f"{o['cls']} spread: {o['names'][0]}", f"{o['hosts']} machines · half within {E.human_period(o['t50_h'] * 3600)}", "sev-hi", "ex2"))
else:
    cards.append(("02 · Outbreaks", f"{len(ob)} new binaries spread", "All managed or organic", "sev-ok", "ex2"))
if gr["sessions"]:
    s0 = gr["sessions"][0]
    cards.append(("03 · Grammar of work", f"A sentence that doesn't fit: {s0['worst_from']} → {s0['worst_to']}",
                  f"{who(s0['user'])} · odds 1 in {s0['odds']:,}", "sev-hi" if s0["surprising_steps"] >= 3 else "sev-md", "ex3"))
if org:
    p = org["people"]
    mis = p[p["misfit"]]
    tk = org["takeovers"]
    if len(tk):
        t = tk[0]
        cards.append(("04 · Shadow org chart", f"A session on {who(t['user'])}'s account works like {who(t['like'])}",
                      f"{t['like_sim']:.0%} like them · {t['self_sim']:.0%} like the account owner", "sev-hi", "ex4"))
    elif len(mis):
        m = mis.iloc[0]
        cards.append(("04 · Shadow org chart", f"{who(m['user'])} sits in {E.DEPT_NAMES[m['dept']]} but works like {E.DEPT_NAMES[m['best']]}", "", "sev-md", "ex4"))
sp = [s for s in nv["spikes"] if not s["explained"]]
if sp:
    s = sp[-1]
    cards.append(("05 · Novelty frontier", f"{s['day']:%b %d}: {s['count']} first-ever things", scrub(s["label"].split("— ", 1)[-1], users_all)[:90], "sev-hi", "ex5"))
fl = ph["orphans"][ph["orphans"]["vanish"] & ph["orphans"]["flag"]]
if len(fl):
    r = fl.iloc[0]
    cards.append(("06 · Process physics", f"{r['p_name']} vanished in {r['parent_life']:.1f}s; its child is still alive",
                  f"{r['name']} · {r['child_life'] / 86400:.1f} days · unsigned", "sev-hi", "ex6"))
html_cards = "".join(
    f'<a class="fcard {sev}" href="#{a}"><div class="k">{esc(k)}</div><div class="h">{esc(h)}</div><div class="s">{esc(sub)}</div></a>'
    for k, h, sub, sev, a in cards)
st.markdown(f'<div class="grid">{html_cards}</div>', unsafe_allow_html=True)


def exhibit(anchor, num, title, question):
    st.markdown(f'<div id="{anchor}" class="exh"><div class="num">EXHIBIT {num}</div><div class="t">{esc(title)}</div>'
                f'<div class="q">{question}</div></div>', unsafe_allow_html=True)


# ═════════════════════════ 01 · HEARTBEAT ═════════════════════════
exhibit("ex1", "01", "The Heartbeat Detector 💓",
        "People are bursty: a flurry of clicks, then nothing for twenty minutes. Machines are periodic: the same thing "
        "every 300 seconds, give or take. Every (machine, program, command) stream is placed by its rhythm. "
        "Anything regular that nobody can explain floats to the top.")
if hb.empty:
    st.info("Not enough repeated launches to measure rhythm.")
else:
    def hb_color(r):
        if r["cls"] == "machine":
            return {"high": RED, "low": AMBER}.get(r["level"], CYAN)
        return {"human routine": VIOLET, "human": SLATE, "mixed": "#475569"}[r["cls"]]
    pl = hb.assign(color=hb.apply(hb_color, axis=1),
                   label=hb.apply(lambda r: f"{r['name']} · {r['host']}", axis=1),
                   size=np.clip(np.log1p(hb["n"]) * 4, 6, 26))
    groups = [("Unexplained machine (high)", RED), ("Unexplained machine (low)", AMBER), ("Explained machine", CYAN),
              ("Human routine", VIOLET), ("Human (bursty)", SLATE), ("Mixed", "#475569")]
    fig = go.Figure()
    for name, col in groups:
        d = pl[pl["color"] == col]
        if d.empty:
            continue
        fig.add_trace(go.Scatter(
            x=d["period_s"], y=d["regularity"], mode="markers", name=name,
            marker=dict(color=col, size=d["size"], opacity=.85 if col in (RED, AMBER) else .5,
                        line=dict(width=1.5 if col == RED else 0, color="white")),
            customdata=np.stack([d["label"], d["period"], (d["jitter"] * 100).round(1),
                                 (d["offhours"] * 100).round(0), d["n"], d["user"].map(who)], axis=-1),
            hovertemplate="<b>%{customdata[0]}</b><br>every %{customdata[1]} ± %{customdata[2]}%<br>"
                          "%{customdata[4]} launches · %{customdata[3]}% off-hours · %{customdata[5]}<extra></extra>"))
    for sec, lab in [(60, "1 min"), (300, "5 min"), (3600, "1 h"), (86400, "1 day")]:
        fig.add_vline(x=sec, line=dict(color="rgba(255,255,255,.12)", dash="dot"))
        fig.add_annotation(x=math.log10(sec), y=1.06, text=lab, showarrow=False, font=dict(size=10, color=MUTED), yref="y")
    hi = pl[pl["color"] == RED]
    for _, r in hi.iterrows():
        fig.add_annotation(x=math.log10(r["period_s"]), y=r["regularity"], text=f"  {r['name']} on {r['host']}",
                           showarrow=True, arrowcolor=RED, ax=60, ay=40, font=dict(color=RED, size=12))
    layout(fig, 430, xaxis=dict(type="log", title="typical gap between launches"),
           yaxis=dict(title="regularity (share of gaps within ±25%)", range=[-0.03, 1.1]))
    c1, c2 = st.columns([0.63, 0.37], gap="large")
    with c1:
        st.plotly_chart(fig, width="stretch")
        st.markdown('<div class="note">Top of the chart = clockwork. Bottom = human. The cyan cloud is ordinary '
                    'background automation (updaters, Defender, telemetry). The interesting dots are regular <b>and</b> '
                    'unexplained.</div>', unsafe_allow_html=True)
    with c2:
        st.markdown("##### Rhythms nobody can explain")
        flagged = mach[mach["level"] != "explained"].sort_values("suspicion", ascending=False)
        for _, r in flagged.head(4).iterrows():
            col = RED if r["level"] == "high" else AMBER
            reasons = "".join(f"<li>{esc(scrub(x, users_all))}</li>" for x in r["reasons"])
            st.markdown(
                f'<div class="card" style="border-left:3px solid {col}">{badge(r["level"].upper(), col)}'
                f'<b>{esc(r["name"])}</b> <span class="muted">on {esc(r["host"])}</span><br>'
                f'<span class="muted">every <b style="color:{INK}">{esc(r["period"])}</b> ± {r["jitter"]:.0%}, '
                f'{int(r["n"]):,} times since {r["first"]:%b %d}</span>'
                f'<div class="mono muted" style="margin-top:4px">{esc(scrub(r["cmd"], users_all)[:110])}</div>'
                f'<ul class="why" style="margin:6px 0 0 -6px">{reasons}</ul></div>', unsafe_allow_html=True)
        st.caption(f"{len(mach[mach['level'] == 'explained'])} explained machine rhythms (signed, system account, "
                   f"scheduler-launched) hidden.")

    streams = pd.concat([flagged, mach[mach["level"] == "explained"]]).head(40)
    if not streams.empty:
        pick = st.selectbox("Listen to one stream", range(len(streams)),
                            format_func=lambda i: f"{streams.iloc[i]['name']} on {streams.iloc[i]['host']} — every "
                                                  f"{streams.iloc[i]['period']} ({streams.iloc[i]['level']})")
        r = streams.iloc[pick]
        t = pd.Series(sorted(r["times"]))
        gaps = t.diff().dt.total_seconds()
        a, b2 = st.columns([0.6, 0.4], gap="large")
        with a:
            f2 = go.Figure(go.Scattergl(x=t[1:], y=gaps[1:], mode="markers",
                                        marker=dict(size=4, color=RED if r["level"] == "high" else CYAN, opacity=.7),
                                        hovertemplate="%{x|%b %d %H:%M:%S}<br>%{y:.0f}s since previous<extra></extra>"))
            layout(f2, 270, yaxis=dict(type="log", title="seconds since previous launch"), xaxis=dict(title=None),
                   title=dict(text="Rhythm strip — a flat band is a clock", font=dict(size=13)))
            st.plotly_chart(f2, width="stretch")
        with b2:
            wk = pd.DataFrame({"d": t.dt.weekday, "h": t.dt.hour}).value_counts().unstack(fill_value=0)
            wk = wk.reindex(index=range(7), columns=range(24), fill_value=0)
            f3 = go.Figure(go.Heatmap(z=wk.to_numpy(), x=list(range(24)), y=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                                      colorscale=[[0, "rgba(255,255,255,.02)"], [1, RED if r["level"] == "high" else CYAN]],
                                      showscale=False, hovertemplate="%{y} %{x}:00 — %{z} launches<extra></extra>"))
            layout(f3, 270, title=dict(text="When does it fire? (UTC)", font=dict(size=13)), xaxis=dict(dtick=3))
            st.plotly_chart(f3, width="stretch")
    rout = hb[hb["cls"] == "human routine"].copy()
    if len(rout):
        with st.expander(f"⏰ People's clockwork — {len(rout)} human routines (same thing, same time, every day)"):
            rout["typical time (UTC)"] = rout["tod_median"].map(lambda m: f"{int(m // 60):02d}:{int(m % 60):02d}") + \
                rout["tod_mad"].map(lambda m: f" ± {m:.0f} min")
            rout["person"] = rout["user"].map(who)
            st.dataframe(rout[["person", "name", "host", "typical time (UTC)", "n"]].rename(columns={"name": "what", "n": "days"}),
                         hide_index=True, width="stretch")

# ═════════════════════════ 02 · OUTBREAKS ═════════════════════════
exhibit("ex2", "02", "Outbreak Curves 🦠",
        "Every binary new to the fleet is treated like a new virus entering a population: who was patient zero, how fast "
        "it spread, and <i>through which channel</i>. A deployment, a phishing campaign and a worm leave three very "
        "different shapes.")
if not ob:
    st.info("No new binaries reached several machines in this window.")
else:
    fig = go.Figure()
    for o in ob:
        c = o["curve"]
        x = np.maximum(c["hours"].to_numpy(), 1 / 60)
        col = CLASS_COLOR.get(o["cls"], SLATE)
        lab = o["names"][0] + (f" +{len(o['names']) - 1}" if len(o["names"]) > 1 else "")
        fig.add_trace(go.Scatter(x=x, y=c["hosts"], mode="lines+markers", name=f"{lab} · {o['cls']}",
                                 line=dict(color=col, width=3 if o["cls"] in ("Worm-like", "Phishing-like") else 1.6,
                                           shape="hv"),
                                 marker=dict(size=6, color=col),
                                 customdata=np.stack([c["host"], c["pname"]], axis=-1),
                                 hovertemplate="%{customdata[0]} via %{customdata[1]}<br>%{x:.2f} h after patient zero"
                                               "<br>%{y} machines<extra>" + esc(lab) + "</extra>"))
    layout(fig, 400, xaxis=dict(type="log", title="hours since patient zero (log)"),
           yaxis=dict(title="machines reached"))
    c1, c2 = st.columns([0.6, 0.4], gap="large")
    with c1:
        st.plotly_chart(fig, width="stretch")
        st.markdown('<div class="note"><b>Managed</b> rollouts climb in one even burst from an update service. '
                    '<b>Organic</b> adoption is a slow staircase over days. <b>Phishing</b> is a steep wall from Outlook. '
                    '<b>Worms</b> arrive through remote services and <i>accelerate</i>.</div>', unsafe_allow_html=True)
    with c2:
        for o in ob[:5]:
            col = CLASS_COLOR.get(o["cls"], SLATE)
            pz = o["patient_zero"]
            names = ", ".join(o["names"][:3]) + (f" +{len(o['names']) - 3} more" if len(o["names"]) > 3 else "")
            st.markdown(
                f'<div class="card" style="border-left:3px solid {col}">{badge(o["cls"], col)}'
                f'<b>{esc(names)}</b><br><span class="muted">{o["hosts"]} machines · half within '
                f'{E.human_period(o["t50_h"] * 3600)} · all within {E.human_period(max(o["duration_h"], 1/60) * 3600)}</span>'
                f'<div class="why">{esc(o["why"])}.</div>'
                f'<div class="why muted">Patient zero: <b>{esc(pz["host"])}</b> ({esc(who(pz["user"]))}) via '
                f'{esc(pz["pname"])}, {pz["ts"]:%b %d %H:%M}</div></div>', unsafe_allow_html=True)
    pick = st.selectbox("Trace one outbreak", range(len(ob)),
                        format_func=lambda i: f"{ob[i]['cls']} — {ob[i]['names'][0]} ({ob[i]['hosts']} machines)")
    o = ob[pick]
    c = o["curve"].copy()
    c["gap"] = c["hours"].diff().fillna(0) * 60
    f2 = go.Figure()
    f2.add_trace(go.Scatter(x=c["ts"], y=c["host"], mode="lines+markers+text", text=[f"#{i + 1}" for i in range(len(c))],
                            textposition="middle right", line=dict(color=CLASS_COLOR.get(o["cls"], SLATE), width=1, dash="dot"),
                            marker=dict(size=11, color=CLASS_COLOR.get(o["cls"], SLATE)),
                            hovertemplate="%{y}<br>%{x|%b %d %H:%M}<extra></extra>"))
    layout(f2, 120 + 26 * len(c), yaxis=dict(autorange="reversed", title=None), xaxis=dict(title=None),
           title=dict(text="Order of infection" + (" — each hop faster than the last" if (o["accel"] or 0) > 1.5 and o["cls"] == "Worm-like" else ""),
                      font=dict(size=13)))
    st.plotly_chart(f2, width="stretch")

# ═════════════════════════ 03 · GRAMMAR ═════════════════════════
exhibit("ex3", "03", "The Grammar of Work 📖",
        "Each person's day reads like sentences of program launches. Pulse learns everyone's personal grammar "
        "(their own habits, backed off to their team's and the company's) and scores each sentence leaving that "
        "day out. These are the sentences that didn't fit.")
sess = gr["sessions"]
if not sess:
    st.info("Not enough interactive launches.")
else:
    def chip_color(bits):
        return RED if bits >= 9 else (AMBER if bits >= 5 else "rgba(255,255,255,.18)")
    top = sess[:6]
    for s in top:
        chips = []
        for i, (tok, bits) in enumerate(zip(s["tokens"][:14], s["bits"][:14])):
            col = chip_color(bits)
            chips.append((f'<span class="arrow">→</span>' if i else "") +
                         f'<span class="chip" style="border:1px solid {col};color:{INK if bits < 9 else col}" '
                         f'title="{bits:.1f} bits">{esc(tok.replace(".exe", ""))}</span>')
        more = f' <span class="muted">+{len(s["tokens"]) - 14}</span>' if len(s["tokens"]) > 14 else ""
        usual = (f'usually opens <b>{esc(s["usual"].replace(".exe", ""))}</b> ({s["usual_p"]:.0%})' if s["usual"]
                 else "has <b>never</b> been followed by anything before")
        sev_col = RED if s["surprising_steps"] >= 3 else AMBER
        st.markdown(
            f'<div class="card" style="border-left:3px solid {sev_col}">'
            f'<span class="muted">{esc(who(s["user"]))} · {esc(s["host"])} · {s["start"]:%a %b %d, %H:%M}</span> '
            f'{badge(str(s["surprising_steps"]) + " surprising step" + ("s" if s["surprising_steps"] != 1 else ""), sev_col)}<br>'
            f'{"".join(chips)}{more}'
            f'<div class="why">After <b>{esc(s["worst_from"].replace(".exe", "").replace("<s>", "logging on"))}</b> '
            f'this person {usual}. Here: <b style="color:{RED}">{esc(s["worst_to"].replace(".exe", ""))}</b> — '
            f'odds about <b>1 in {s["odds"]:,}</b> under their own habits.</div></div>', unsafe_allow_html=True)
    st.markdown('<div class="note">Red chips are steps rarer than 1 in 512 for that person. One red chip is a new habit; '
                'several in a row is a story worth reading.</div>', unsafe_allow_html=True)
    st.markdown("##### How each team actually works")
    depts = sorted(gr["bigrams"])
    dsel = st.radio("Team", depts, horizontal=True, format_func=lambda d: E.DEPT_NAMES.get(d, d), label_visibility="collapsed")
    bg = gr["bigrams"][dsel]
    if bg:
        lefts = sorted({a for (a, b), n in bg})
        rights = sorted({b for (a, b), n in bg})
        labels = [x.replace(".exe", "") for x in lefts] + [x.replace(".exe", "") + " " for x in rights]
        li = {x: i for i, x in enumerate(lefts)}
        ri = {x: len(lefts) + i for i, x in enumerate(rights)}
        col = DEPT_COLOR.get(dsel, SLATE)
        sk = go.Figure(go.Sankey(
            node=dict(label=labels, pad=14, thickness=12, color=col, line=dict(width=0)),
            link=dict(source=[li[a] for (a, b), n in bg], target=[ri[b] for (a, b), n in bg], value=[n for _, n in bg],
                      color=col + "44")))
        layout(sk, 420, title=dict(text="what follows what (left → right)", font=dict(size=13)))
        c1, c2 = st.columns([0.66, 0.34], gap="large")
        c1.plotly_chart(sk, width="stretch")
        with c2:
            st.markdown("**Signature workflows**")
            for (a, b, c3), n in gr["workflows"][dsel][:7]:
                st.markdown(f'<div class="chip">{esc(a[:-4])}</div><span class="arrow">→</span>'
                            f'<div class="chip">{esc(b[:-4])}</div><span class="arrow">→</span>'
                            f'<div class="chip">{esc(c3[:-4])}</div> <span class="muted">×{n}</span>',
                            unsafe_allow_html=True)

# ═════════════════════════ 04 · ORG CHART ═════════════════════════
exhibit("ex4", "04", "The Shadow Org Chart 🗺️",
        "Everyone gets a behavioural fingerprint: which programs they use (weighted by how distinctive they are) and "
        "when in the day they work. People who work alike land close together. Then that map is compared to the real "
        "departments, and every session is compared to its account owner.")
if not org:
    st.info("Not enough people with activity.")
else:
    P = org["people"].copy()
    P["who"] = P["user"].map(who)
    notable = set(P.loc[P["misfit"], "user"]) | {t["user"] for t in org["takeovers"][:3]} | {t["like"] for t in org["takeovers"][:3]}
    P["label"] = np.where(P["user"].isin(notable), P["who"], "")
    fig = go.Figure()
    for d in sorted(P["dept"].unique()):
        q = P[P["dept"] == d]
        core = q[~q["misfit"]]
        if len(core):
            fig.add_annotation(x=core["x"].mean(), y=core["y"].max(), yshift=26, showarrow=False,
                               text=f"<b>{E.DEPT_NAMES.get(d, d)}</b>", font=dict(color=DEPT_COLOR.get(d, SLATE), size=13))
        fig.add_trace(go.Scatter(
            x=q["x"], y=q["y"], mode="markers+text", name=E.DEPT_NAMES.get(d, d), text=q["label"],
            textposition="top center", textfont=dict(size=10, color=MUTED),
            marker=dict(size=np.where(q["misfit"], 20, 13), color=DEPT_COLOR.get(d, SLATE),
                        symbol=np.where(q["misfit"], "star", "circle"), line=dict(width=np.where(q["misfit"], 2, 0), color="white")),
            customdata=np.stack([q["who"], q["top_apps"].map(lambda a: ", ".join(x[:-4] for x in a[:4])),
                                 q["best"].map(lambda b: E.DEPT_NAMES.get(b, b))], axis=-1),
            hovertemplate="<b>%{customdata[0]}</b><br>%{customdata[1]}<br>works most like: %{customdata[2]}<extra></extra>"))
    for _, r in P[P["misfit"]].iterrows():
        fig.add_annotation(x=r["x"], y=r["y"], text=f"{r['who']}: sits in {E.DEPT_NAMES[r['dept']]}, works like {E.DEPT_NAMES[r['best']]}",
                           showarrow=True, ax=-110, ay=60, arrowcolor=PINK, font=dict(color=PINK, size=11),
                           bgcolor="rgba(10,14,26,.85)")
    layout(fig, 470, xaxis=dict(showticklabels=False, title=None, showgrid=False),
           yaxis=dict(showticklabels=False, title=None, showgrid=False))
    c1, c2 = st.columns([0.62, 0.38], gap="large")
    with c1:
        st.plotly_chart(fig, width="stretch")
    with c2:
        st.markdown("##### Sessions that look like someone else")
        if not org["takeovers"]:
            st.caption("Every session looks like its account owner.")
        for t in org["takeovers"][:3]:
            chips = "".join((f'<span class="arrow">→</span>' if i else "") + f'<span class="chip">{esc(x[:-4])}</span>'
                            for i, x in enumerate(t["tokens"][:9]))
            st.markdown(
                f'<div class="card" style="border-left:3px solid {RED}">{badge("ACCOUNT MISMATCH", RED)}'
                f'<span class="muted">{esc(who(t["user"]))}\'s account · {t["start"]:%a %b %d, %H:%M}</span><br>{chips}'
                f'<div class="why">This session is <b style="color:{RED}">{t["like_sim"]:.0%}</b> similar to '
                f'<b>{esc(who(t["like"]))}</b> and only <b>{t["self_sim"]:.0%}</b> similar to how the account owner '
                f'normally works. Shared credentials, or someone else at the keyboard.</div></div>', unsafe_allow_html=True)
        st.markdown("##### People who work like another team")
        mis = P[P["misfit"]]
        if mis.empty:
            st.caption("Everyone works like their own department.")
        for _, r in mis.iterrows():
            st.markdown(
                f'<div class="card" style="border-left:3px solid {AMBER}"><b>{esc(r["who"])}</b> '
                f'<span class="muted">· {E.DEPT_NAMES[r["dept"]]}</span><div class="why">Works '
                f'<b>{r["best_sim"]:.0%}</b> like {E.DEPT_NAMES[r["best"]]}, {r["own_sim"]:.0%} like their own team. '
                f'Top tools: {esc(", ".join(a[:-4] for a in r["top_apps"][:4]))}. Often a sign of mismatched access '
                f'rights or a shadow-IT hotspot.</div></div>', unsafe_allow_html=True)
    labels = P["who"].tolist()
    wi = st.selectbox("Who works most like…", range(len(P)), format_func=lambda i: labels[i])
    r = P.iloc[wi]
    st.markdown(" ".join(f'<span class="chip">{esc(who(u))} · {s:.0%}</span>' for s, u in r["nearest"]),
                unsafe_allow_html=True)

# ═════════════════════════ 05 · NOVELTY ═════════════════════════
exhibit("ex5", "05", "The Novelty Frontier 🌅",
        "Count the first time anything is ever seen: a new binary, a new parent → child pair, a new command shape. "
        "A healthy fleet <i>learns</i>, so novelty decays to a trickle. Spikes after that are either explained (a managed "
        "update) or they aren't.")
cv = nv["curve"]
if cv.empty:
    st.info("Nothing to show.")
else:
    fig = go.Figure()
    for kind, col in [("binary (hash)", PINK), ("parent → child", CYAN), ("command shape", VIOLET)]:
        if kind in cv:
            fig.add_trace(go.Scatter(x=cv.index, y=cv[kind], name=kind, stackgroup="one", mode="lines",
                                     line=dict(width=.5, color=col), fillcolor=col + "88"))
    fig.add_vrect(x0=cv.index.min(), x1=nv["burn"], fillcolor="rgba(255,255,255,.04)", line_width=0,
                  annotation_text="learning what normal is", annotation_position="top left",
                  annotation_font=dict(color=MUTED, size=11))
    tot = cv.sum(axis=1)
    after_max = float(tot[tot.index >= nv["burn"]].max() or 1)
    ytop = after_max * 1.9
    for s in nv["spikes"]:
        col = GREEN if s["explained"] else RED
        fig.add_annotation(x=s["day"] + pd.Timedelta(hours=12), y=ytop * .93, text=("✓" if s["explained"] else "⚠"),
                           showarrow=False, font=dict(color=col, size=15), hovertext=s["label"])
        fig.add_vrect(x0=s["day"], x1=s["day"] + pd.Timedelta(days=1), fillcolor=col, opacity=.08, line_width=0)
    if float(tot.max()) > ytop:
        fig.add_annotation(x=tot.idxmax(), y=ytop * .78, text=f"↑ {int(tot.max())} while learning", showarrow=False,
                           font=dict(color=MUTED, size=10), xanchor="left")
    layout(fig, 360, yaxis=dict(title="first-ever things per 6 h", range=[0, ytop]), xaxis=dict(title=None))
    st.plotly_chart(fig, width="stretch")
    st.markdown(f'<div class="note">{nv["learned"]:,} things were learned during the first days. After that, only '
                f'{nv["after"]:,} more were ever new, and most of them arrived on a handful of days.</div>',
                unsafe_allow_html=True)
    if nv["spikes"]:
        spk = nv["spikes"]
        cols = st.columns(3)
        for i, s in enumerate(spk):
            col = GREEN if s["explained"] else RED
            cols[i % 3].markdown(
                f'<div class="card" style="border-left:3px solid {col}">{badge("EXPLAINED" if s["explained"] else "UNEXPLAINED", col)}'
                f'<b>{s["day"]:%a %b %d}</b><br><span class="muted">{s["count"]} first-ever things '
                f'(usual ≈ {s["baseline"]:.0f})</span><div class="why">{esc(scrub(s["label"].split("— ", 1)[-1], users_all))}</div></div>',
                unsafe_allow_html=True)
        spi = st.selectbox("What was new that day?", range(len(nv["spikes"])),
                           format_func=lambda i: f"{nv['spikes'][i]['day']:%a %b %d} — {nv['spikes'][i]['count']} new things")
        it = nv["spikes"][spi]["items"].copy()
        it["who"] = it["user"].map(who)
        it["signed"] = it["signed"].map({True: "✓", False: "✗ unsigned"})
        it["what"] = np.where(it["kind"] == "binary (hash)", it["name"] + "  ·  sha256 " + it["thing"].str.slice(0, 12) + "…",
                              it["thing"].str.slice(0, 110))
        st.dataframe(it[["kind", "what", "host", "who", "signed", "hosts"]].rename(columns={"hosts": "machines so far"}),
            hide_index=True, width="stretch", height=280)

# ═════════════════════════ 06 · PHYSICS ═════════════════════════
exhibit("ex6", "06", "Process Physics ⚛️",
        "Processes have a natural life cycle: parents start children and usually outlive them. Each dot is a parent → "
        "child pair, placed by how long each lived. Children that outlive a parent which died instantly sit in the top-left "
        "corner. That's the classic way to cut a process loose from where it came from.")
sc = ph["scatter"]
orph = ph["orphans"]
if sc.empty:
    st.info("No parent/child pairs with lifetimes.")
else:
    fig = go.Figure()
    normal = sc[~sc.index.isin(orph.index)]
    fig.add_trace(go.Scattergl(x=normal["parent_life"].clip(lower=0.05), y=normal["child_life"].clip(lower=0.05),
                               mode="markers", name="normal pairs",
                               marker=dict(size=4, color="rgba(148,163,184,.25)"),
                               hovertemplate="%{text}<extra></extra>",
                               text=normal["p_name"] + " → " + normal["name"]))
    for flag, col, nm in [(False, CYAN, "outlived parent (signed)"), (True, RED, "outlived parent (unsigned / odd path)")]:
        q = orph[orph["flag"] == flag]
        if q.empty:
            continue
        fig.add_trace(go.Scatter(x=q["parent_life"].clip(lower=0.05), y=q["child_life"], mode="markers", name=nm,
                                 marker=dict(size=12 if flag else 9, color=col, line=dict(width=1, color="white")),
                                 text=q["p_name"] + " → " + q["name"] + " · " + q["host"],
                                 hovertemplate="%{text}<br>parent lived %{x:.1f}s, child %{y:.0f}s<extra></extra>"))
        if flag:
            for _, r in q.head(3).iterrows():
                fig.add_annotation(x=math.log10(max(r["parent_life"], .05)), y=math.log10(r["child_life"]),
                                   text=f"  {r['p_name']} → {r['name']}", showarrow=True, ax=90, ay=10,
                                   arrowcolor=RED, font=dict(color=RED, size=12))
    fig.add_shape(type="rect", x0=0.05, x1=3, y0=300, y1=float(sc["child_life"].max()) * 2, fillcolor=RED, opacity=.06,
                  line_width=0)
    fig.add_annotation(x=math.log10(0.1), y=math.log10(float(sc["child_life"].max())), text="spawn-and-vanish zone",
                       showarrow=False, font=dict(color=RED, size=11), xanchor="left")
    mx = float(max(sc["parent_life"].max(), sc["child_life"].max()))
    fig.add_trace(go.Scatter(x=[0.05, mx], y=[0.05, mx], mode="lines", line=dict(color="rgba(255,255,255,.15)", dash="dot"),
                             name="lived equally long", hoverinfo="skip"))
    layout(fig, 440, xaxis=dict(type="log", title="parent lifetime (s)"), yaxis=dict(type="log", title="child lifetime (s)"))
    c1, c2 = st.columns([0.6, 0.4], gap="large")
    with c1:
        st.plotly_chart(fig, width="stretch")
    with c2:
        st.markdown("##### Spawn-and-vanish")
        sv = orph[orph["vanish"]].copy()
        sv["n_same"] = sv.groupby(["p_name", "name"])["host"].transform("nunique")
        sv = pd.concat([sv[sv["flag"]], sv[~sv["flag"]].drop_duplicates(["p_name", "name"])])
        for _, r in sv.head(5).iterrows():
            col = RED if r["flag"] else CYAN
            st.markdown(
                f'<div class="card" style="border-left:3px solid {col}">{badge("SUSPICIOUS" if r["flag"] else "LOOKS LEGIT", col)}'
                f'<b>{esc(r["p_name"])}</b> <span class="arrow">→</span> <b>{esc(r["name"])}</b><br>'
                f'<span class="muted">{esc(r["host"]) if r["flag"] or r["n_same"] == 1 else str(r["n_same"]) + " machines"} · parent lived {r["parent_life"]:.1f}s, child '
                f'{"still running after " if r["running"] else "lived "}{E.human_period(r["child_life"])}</span>'
                f'<div class="mono muted" style="margin-top:4px">{esc(scrub(r["exe"], users_all))}</div>'
                f'<div class="why">{"Unsigned, from a user-writable folder." if r["flag"] else ("Signed by " + esc(str(r["signer"])) + " — an installer or launcher handing off.")}</div></div>',
                unsafe_allow_html=True)
    imm = ph["immortals"].copy()
    if len(imm):
        st.markdown("##### Immortals — running for 3+ days")
        imm["who"] = imm["user"].map(who)
        imm["running for"] = imm["life"].map(E.human_period)
        imm["signature"] = np.where(imm["signed"], "✓ " + imm["signer"].fillna(""), "✗ unsigned")
        st.dataframe(imm[["name", "host", "who", "running for", "signature", "exe"]].head(30).assign(
            exe=lambda x: x["exe"].map(lambda e: scrub(e, users_all))),
            hide_index=True, width="stretch", height=260)

# ═════════════════════════ LIVE ═════════════════════════
exhibit("live", "∞", "Live pulse", "New launches across the fleet as they arrive. Anything matching an unexplained "
        "rhythm from Exhibit 01 lights up.")
if st.toggle("Listen", key="live_on"):
    bad_keys = set(hb.loc[(hb["cls"] == "machine") & (hb["level"] == "high"), "key"]) if not hb.empty else set()

    @st.fragment(run_every="2s")
    def live():
        stt = st.session_state.setdefault("live_state", {"cursor": datetime.now(timezone.utc) - timedelta(seconds=30),
                                                          "series": deque(maxlen=90), "seen": set(), "rows": deque(maxlen=14),
                                                          "pings": 0})
        cur = stt["cursor"] - timedelta(seconds=5)
        _, resp = get_source().search("live_since", since_ts=cur.isoformat(timespec="milliseconds").replace("+00:00", "Z"))
        hits = [h for h in resp["hits"]["hits"] if h["_source"]["process"]["entity_id"] not in stt["seen"]]
        for h in hits:
            stt["seen"].add(h["_source"]["process"]["entity_id"])
        n_ping = 0
        if hits:
            d = E.frame(hits)
            keys = d["host"] + "|" + d["exe"].str.lower() + "|" + d["cshape"]
            d = d.assign(ping=keys.isin(bad_keys))
            n_ping = int(d["ping"].sum())
            for _, r in d.iterrows():
                stt["rows"].appendleft((r["ts"], r["host"], r["name"], bool(r["ping"])))
            stt["cursor"] = max(stt["cursor"], d["ts"].max().to_pydatetime())
            if n_ping:
                stt["pings"] += n_ping
                st.toast(f"Beacon rhythm heard again on {d.loc[d['ping'], 'host'].iloc[0]}", icon="💓")
        stt["series"].append((datetime.now(timezone.utc), len(hits), n_ping))
        s = pd.DataFrame(stt["series"], columns=["t", "n", "p"])
        f = go.Figure()
        f.add_trace(go.Scatter(x=s["t"], y=s["n"], mode="lines", line=dict(color=PINK, width=2, shape="spline"),
                               fill="tozeroy", fillcolor="rgba(255,77,141,.12)", name="launches"))
        pk = s[s["p"] > 0]
        f.add_trace(go.Scatter(x=pk["t"], y=pk["n"], mode="markers", marker=dict(color=RED, size=11, symbol="diamond"),
                               name="beacon heard"))
        layout(f, 200, showlegend=False, yaxis=dict(title=None), xaxis=dict(title=None))
        a, b = st.columns([0.68, 0.32])
        a.plotly_chart(f, width="stretch")
        b.metric("Beacon pings heard", stt["pings"])
        b.markdown("".join(
            f'<div class="mono" style="color:{RED if p else MUTED}">{t:%H:%M:%S} {esc(h)} {esc(n)}{"  ← beacon" if p else ""}</div>'
            for t, h, n, p in list(stt["rows"])[:8]), unsafe_allow_html=True)
    live()

st.markdown(f'<div class="note" style="margin-top:2.5rem">Methods, briefly: rhythm = median gap, share of gaps within ±25 %, '
            f'and absolute jitter. Outbreaks = first launch per (hash, host) after a 3-day burn-in, classified by the parent '
            f'that started it. Grammar = interpolated bigram model (person → team → company → app frequency), scored '
            f'leaving the day out. Org chart = TF-IDF app mix + hour profile, SVD to 2-D, leave-one-out team centroids. '
            f'Novelty = first-seen hash / pair / command shape with a 4-day burn-in. Physics = process.start/end joined to the '
            f'parent by entity_id.</div>', unsafe_allow_html=True)
