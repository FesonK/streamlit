"""
User Network Intelligence - type a user.name, get the full network story.

    streamlit run app.py
"""
from __future__ import annotations

import copy
import html
import json
import re

import numpy as np
import pandas as pd
import streamlit as st

import analysis as A
import charts as C
import data_source as D
import query_dict as Q

st.set_page_config(page_title="User Network Intelligence", page_icon=":material/hub:", layout="wide")

TZS = ["America/New_York", "UTC", "Europe/London", "America/Los_Angeles", "Asia/Singapore"]
WINDOWS = {"24h": 1, "3d": 3, "7d": 7}
OFFICE = (40.7128, -74.0060)  # HQ, used as the 'source' end of the geo arcs
SEV_BADGE = {"critical": ("red", ":material/emergency_home:"), "high": ("orange", ":material/warning:"),
             "medium": ("yellow", ":material/error:"), "low": ("blue", ":material/info:"),
             "info": ("gray", ":material/info:")}

st.html("""
<style>
  .block-container {padding-top: 3.6rem; max-width: 1500px;}
  [data-testid="stMetricValue"] {font-size: 1.55rem;}
  .uni-card {border:1px solid #2f2f2c; border-radius:12px; padding:18px 20px; background:#1a1a19; height:100%;}
  .uni-eyebrow {color:#8f8e86; font-size:.74rem; letter-spacing:.08em; text-transform:uppercase; margin-bottom:6px;}
  .uni-name {color:#f0efec; font-size:1.5rem; font-weight:650; line-height:1.15;}
  .uni-sub {color:#c3c2b7; font-size:.9rem; margin-top:2px;}
  .uni-kv {display:grid; grid-template-columns:auto 1fr; gap:4px 14px; margin-top:12px; font-size:.85rem;}
  .uni-kv span:nth-child(odd) {color:#8f8e86;} .uni-kv span:nth-child(even) {color:#f0efec; font-family:ui-monospace,monospace;}
  .uni-risk {display:flex; gap:18px; align-items:center;}
  .uni-ring {width:104px; height:104px; border-radius:50%; display:grid; place-items:center; flex:none;}
  .uni-ring > div {width:84px; height:84px; border-radius:50%; background:#1a1a19; display:grid; place-items:center;
                   color:#f0efec; font-size:2rem; font-weight:700;}
  .uni-verdict {font-size:1.15rem; font-weight:650; color:#f0efec;}
  .uni-sevrow {display:flex; gap:8px; flex-wrap:wrap; margin-top:10px;}
  .uni-pill {font-size:.78rem; padding:2px 9px; border-radius:999px; border:1px solid #3a3a37; color:#c3c2b7;}
  .uni-pill b {color:#f0efec;}
  .uni-dot {display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:5px;}
  .uni-story p {margin:0 0 8px 0; color:#c3c2b7; font-size:.92rem; line-height:1.45;}
  .uni-story b, .uni-story strong {color:#f0efec;}
</style>
""")


# ---------------------------------------------------------------- caching
@st.cache_data(ttl=600, show_spinner=False)
def cached_search(text: str) -> pd.DataFrame:
    return A.user_search(text)


@st.cache_data(ttl=600, show_spinner=False)
def cached_investigation(user: str, start: pd.Timestamp, end: pd.Timestamp, tz: str):
    return A.investigate(user, start, end, tz)


@st.cache_data(ttl=600, show_spinner=False)
def cached_watchlist(start: pd.Timestamp, end: pd.Timestamp, tz: str) -> pd.DataFrame:
    rows = []
    users = cached_search("")
    for r in users.itertuples():
        inv = A.investigate(r.user, start, end, tz)
        if inv is None:
            continue
        top = inv.findings[0] if inv.findings else None
        rows.append({"user": r.user, "full_name": r.full_name, "dept": r.dept, "risk": inv.risk,
                     "verdict": inv.verdict, "findings": sum(f.severity in ("critical", "high", "medium") for f in inv.findings),
                     "top_finding": top.title if top and top.severity != "low" else "-",
                     "data_out": inv.kpi["bytes_out"], "connections": inv.kpi["sessions"]})
    return pd.DataFrame(rows).sort_values(["risk", "data_out"], ascending=False, ignore_index=True)


def fmt_dur(seconds: float) -> str:
    if seconds is None or pd.isna(seconds):
        return "-"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def delta_pct(cur, prev):
    if not prev:
        return None
    ch = (cur - prev) / prev * 100
    return f"×{cur / prev:,.0f} vs prev" if ch >= 900 else f"{ch:+.0f}% vs prev"


def mitre_url(tid: str) -> str | None:
    if not tid.startswith("T"):
        return f"https://attack.mitre.org/tactics/{tid}/" if tid.startswith("TA") else None
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def trim(obj, n=3):
    """Shorten bucket/hit lists so a response is readable in the inspector."""
    if isinstance(obj, dict):
        return {k: trim(v, n) for k, v in obj.items()}
    if isinstance(obj, list):
        out = [trim(v, n) for v in obj[:n]]
        if len(obj) > n:
            out.append(f"... {len(obj) - n} more")
        return out
    return obj


# ---------------------------------------------------------------- sidebar
if "_goto" in st.session_state:
    st.session_state["user_pick"] = st.session_state.pop("_goto")
elif "user_pick" not in st.session_state and st.query_params.get("user"):
    st.session_state["user_pick"] = st.query_params["user"]

users_df = cached_search("")
label = {r.user: f"{r.user}  ·  {r.full_name}  ·  {r.dept}" for r in users_df.itertuples()}

with st.sidebar:
    st.markdown("### :material/hub: User Network Intelligence")
    st.caption("Search a `user.name` to see everything their network traffic says about them.")
    user = st.selectbox("User", options=list(label), index=None, key="user_pick",
                        format_func=lambda u: label.get(u, u), placeholder="Search user.name…",
                        accept_new_options=True)
    window = st.segmented_control("Time window", list(WINDOWS), default="7d", required=True, key="window")
    tz = st.selectbox("Display timezone", TZS, index=0, key="tz")
    st.divider()
    with st.expander(":material/science: Demo stories in the mock data"):
        st.markdown(
            "- **jdoe** - 2 a.m. upload to a brand-new domain + impossible travel\n"
            "- **asmith** - C2 beaconing, DGA lookups, DNS tunnelling\n"
            "- **bwayne** - internal port scan → lateral movement\n"
            "- **mlopez** - clean baseline user\n\n"
            "Everyone else is ordinary department traffic.")
    st.caption(f"Data source: **{D.MODE}**" + (" (synthetic ECS events, queried through `query_dict.py`)" if D.MODE == "mock" else ""))
    if st.button(":material/home: Back to watchlist", width="stretch", disabled=user is None):
        st.session_state["_goto"] = None
        st.query_params.clear()
        st.rerun()

now = D.now()
end = now.floor("min")
start = end - pd.Timedelta(days=WINDOWS[window])


# ---------------------------------------------------------------- landing
def landing():
    st.title("Who should I look at first?")
    st.caption(f"Every user active in the last {window}, ranked by network risk score. "
               "Pick a row (or search in the sidebar) to open the full investigation.")
    with st.spinner("Scoring every user…"):
        wl = cached_watchlist(start, end, tz)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Users analysed", len(wl), border=True)
    c2.metric("Need action (≥ 55)", int((wl["risk"] >= 55).sum()), border=True)
    c3.metric("Elevated (25-54)", int(((wl["risk"] >= 25) & (wl["risk"] < 55)).sum()), border=True)
    c4.metric("Data uploaded (all users)", A.fmt_bytes(wl["data_out"].sum()), border=True)
    view = wl.assign(data_out=wl["data_out"].map(A.fmt_bytes))
    ev = st.dataframe(
        view, hide_index=True, on_select="rerun", selection_mode="single-row", key="watchlist",
        column_order=["user", "full_name", "dept", "risk", "verdict", "findings", "top_finding", "data_out", "connections"],
        column_config={
            "user": st.column_config.TextColumn("user.name"),
            "full_name": "Name", "dept": "Department",
            "risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
            "verdict": "Verdict", "findings": st.column_config.NumberColumn("Findings", help="medium or worse"),
            "top_finding": "Top finding", "data_out": "Uploaded", "connections": st.column_config.NumberColumn("Connections", format="%,d"),
        })
    if ev.selection.rows:
        st.session_state["_goto"] = wl.iloc[ev.selection.rows[0]]["user"]
        st.rerun()
    with st.container(border=True):
        st.markdown("**How the score works.** Each detector that fires adds weight by severity "
                    "(critical 0.45, high 0.30, medium 0.15, low 0.05), combined as `1 − Π(1 − w)`. "
                    "Any critical finding floors the score at 80 and any high at 55, so one serious finding is never diluted.")


if not user:
    landing()
    st.stop()

st.query_params["user"] = user
with st.spinner(f"Running {len(Q.ALL_QUERIES)} queries for {user}…"):
    inv = cached_investigation(user, start, end, tz)

if inv is None:
    st.warning(f"No network activity for **{user}** in the last {window}. Check the spelling or widen the time window.",
               icon=":material/person_search:")
    near = users_df[users_df["user"].str.contains(user[:3], case=False, na=False)]
    if len(near):
        st.caption("Did you mean: " + ", ".join(f"`{u}`" for u in near["user"]))
    st.stop()

ident, k, kp, F = inv.identity, inv.kpi, inv.kpi_prev, inv.findings
flag_ips = {ip for f in F if f.key in ("exfil", "beacon") and f.evidence is not None for ip in f.evidence.get("ip", [])}
dest = inv.destinations
flag_orgs = set(dest[dest["ip"].isin(flag_ips)]["org"]) if not dest.empty else set()
flag_cc = set(dest[dest["ip"].isin(flag_ips)]["country"]) if not dest.empty else set()
if not inv.beacons.empty:
    bad_b = inv.beacons[inv.beacons["pair"].isin([p for f in F if f.key == "beacon" for p in f.evidence["pair"]])]
    flag_orgs |= set(bad_b["org"])
flag_dns = {f.title.split(" via ")[-1] for f in F if f.key == "dns_tunnel"}

# ---------------------------------------------------------------- header
risk_col = (C.STATUS["critical"] if inv.risk >= 80 else C.STATUS["serious"] if inv.risk >= 55
            else C.STATUS["warning"] if inv.risk >= 25 else C.STATUS["good"])
sev_counts = {s: sum(f.severity == s for f in F) for s in A.SEVERITY_ORDER[:4]}
hosts_html = "<br>".join(f"{h['host']} <span style='color:#8f8e86'>({h['os']})</span>" for h in ident["hosts"])
ips_html = "<br>".join(f"{i['ip']}<br><span style='color:#8f8e86;font-size:.78rem'>{i['mac']}</span>" for i in ident["ips"])
vpn_html = "<br>".join(f"{i['ip']} <span style='color:#8f8e86'>{i['city']}, {i['cc']} ×{i['logins']}</span>"
                       for i in ident["remote_ips"]) or "<span style='color:#8f8e86'>none</span>"

h1, h2, h3 = st.columns([1.1, 1.05, 1.5], gap="medium")
with h1:
    st.html(f"""<div class="uni-card">
      <div class="uni-eyebrow">Subject · user.name</div>
      <div class="uni-name">{ident['full_name']}</div>
      <div class="uni-sub">{ident['name']} · {ident['department']} · {ident['email']}</div>
      <div class="uni-kv">
        <span>host.name</span><span>{hosts_html}</span>
        <span>source.ip / mac</span><span>{ips_html}</span>
        <span>VPN from</span><span>{vpn_html}</span>
        <span>first seen</span><span>{ident['first_seen'].tz_convert(tz):%a %d %b %H:%M}</span>
        <span>last seen</span><span>{ident['last_seen'].tz_convert(tz):%a %d %b %H:%M}</span>
        <span>events</span><span>{ident['total_events']:,} ({', '.join(f"{v:,} {k.split('.')[-1]}" for k, v in ident['datasets'].items())})</span>
      </div></div>""")
with h2:
    pills = "".join(f"<span class='uni-pill'><span class='uni-dot' style='background:{C.SEV_COLOR[s]}'></span>"
                    f"<b>{n}</b> {s}</span>" for s, n in sev_counts.items())
    st.html(f"""<div class="uni-card">
      <div class="uni-eyebrow">Network risk · last {window}</div>
      <div class="uni-risk">
        <div class="uni-ring" style="background:conic-gradient({risk_col} {inv.risk * 3.6:.0f}deg, #2f2f2c 0);"
             role="img" aria-label="risk {inv.risk} of 100"><div>{inv.risk}</div></div>
        <div><div class="uni-verdict">{inv.verdict}</div>
             <div class="uni-sub">{len(F)} finding{'s' if len(F) != 1 else ''} from 10 detectors</div></div>
      </div>
      <div class="uni-sevrow">{pills}</div></div>""")
with h3:
    story = "".join("<p>" + re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", html.escape(s, quote=False)) + "</p>"
                    for s in inv.narrative)
    st.html(f"""<div class="uni-card uni-story"><div class="uni-eyebrow">What you need to know</div>{story}</div>""")

# ---------------------------------------------------------------- KPIs
daily = k["daily"]
m = st.columns(6)
m[0].metric("Connections", f"{k['sessions']:,}", delta_pct(k["sessions"], kp["sessions"]), delta_color="off",
            chart_data=daily["sessions"].tolist(), chart_type="bar", border=True, help="network_traffic.flow events vs previous window")
m[1].metric("Uploaded", A.fmt_bytes(k["bytes_out"]), delta_pct(k["bytes_out"], kp["bytes_out"]), delta_color="inverse",
            chart_data=(daily["bytes_out"] / 1e6).round(1).tolist(), chart_type="area", border=True, help="sum(source.bytes)")
m[2].metric("Downloaded", A.fmt_bytes(k["bytes_in"]), delta_pct(k["bytes_in"], kp["bytes_in"]), delta_color="off",
            border=True, help="sum(destination.bytes)")
m[3].metric("Distinct destinations", f"{k['uniq_dest_ip']:,}", delta_pct(k["uniq_dest_ip"], kp["uniq_dest_ip"]),
            delta_color="inverse", chart_data=daily["uniq_dest_ip"].tolist(), border=True,
            help=f"cardinality(destination.ip) · {k['uniq_dest_port']} ports · {k['uniq_domains']} domains")
m[4].metric("Failed / denied", f"{k['denied_pct']:.1f}%", f"{k['denied']:,} connections", delta_color="off",
            chart_data=daily["denied"].tolist(), chart_type="bar", border=True, help="event.outcome = failure")
m[5].metric("Open right now", f"{k['open_sessions']}", f"p99 {fmt_dur(k['p99_duration_s'])} long", delta_color="off",
            border=True, help="flows with no event.end yet")

# ---------------------------------------------------------------- findings
st.subheader("Findings", anchor=False)
if not F:
    st.success("No detector fired for this user in the selected window. Traffic looks like normal business-hours use.",
               icon=":material/verified_user:")
for f in F:
    color, icon = SEV_BADGE[f.severity]
    with st.container(border=True):
        top = st.columns([0.78, 0.22], vertical_alignment="center")
        with top[0]:
            st.markdown(f":{color}-badge[{icon} {f.severity.upper()}] &nbsp; **{f.title}**")
        with top[1]:
            url = mitre_url(f.mitre[0])
            tag = f"[{f.mitre[0]} · {f.mitre[1]}]({url})" if url else f.mitre[1]
            st.caption(f":material/target: {tag}  \n:material/tab: see **{f.tab}** tab")
        st.markdown(f.summary)
        with st.expander("Evidence, next steps & the query behind it"):
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown("**Next steps**\n" + "\n".join(f"1. {s}" for s in f.next_steps))
            with c2:
                st.markdown("**ECS fields** " + " ".join(f"`{x}`" for x in f.fields))
                st.markdown(f"**Produced by** `query_dict.{f.query.split(' ')[0]}()`")
            if f.evidence is not None and len(f.evidence):
                ev = f.evidence.copy()
                for c in ev.columns:
                    if pd.api.types.is_datetime64_any_dtype(ev[c]):
                        ev[c] = ev[c].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M:%S")
                st.dataframe(ev, hide_index=True, height=min(38 * (len(ev) + 1), 300))

# ---------------------------------------------------------------- tabs
tabs = st.tabs([":material/timeline: Timeline", ":material/call_split: Destinations", ":material/public: Geo & sessions",
                ":material/dns: DNS", ":material/radar: Detections", ":material/groups: Peers",
                ":material/data_object: Query inspector"])

events = [(f.when, f.title, f.severity) for f in F if f.when is not None and start <= f.when <= end]

# ---- Timeline
with tabs[0]:
    st.markdown("##### Traffic over time")
    st.caption(f"Hourly upload vs download in {tz}. Shaded bands are off-hours (before 07:00, after 20:00). "
               "Dotted lines mark when findings started.")
    st.plotly_chart(C.traffic_timeline(inv.timeline, tz, events), config={"displayModeBar": False})
    st.plotly_chart(C.connections_bar(inv.timeline, tz), config={"displayModeBar": False})
    a, b = st.columns(2)
    from parsers import hour_weekday_matrix
    with a:
        st.markdown("##### When does this user connect?")
        st.caption("Connections by weekday × local hour. A person makes a block in office hours; malware fills every cell.")
        st.plotly_chart(C.week_heatmap(hour_weekday_matrix(inv.timeline, tz, "sessions"), "connections"),
                        config={"displayModeBar": False})
    with b:
        st.markdown("##### When does data leave?")
        st.caption("MB uploaded by weekday × local hour. Bright cells at night are worth a question.")
        tl = inv.timeline.assign(mb_out=inv.timeline["bytes_out"] / 1024 ** 2)
        st.plotly_chart(C.week_heatmap(hour_weekday_matrix(tl, tz, "mb_out"), "MB up"), config={"displayModeBar": False})
    if not inv.long_sessions.empty:
        st.markdown("##### Longest connections")
        ls = inv.long_sessions.copy()
        ls["duration"] = (ls["event.duration"] / 1e9).map(fmt_dur)
        ls["started"] = ls["@timestamp"].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M")
        ls["up"], ls["down"] = ls["source.bytes"].map(A.fmt_bytes), ls["destination.bytes"].map(A.fmt_bytes)
        st.dataframe(ls, hide_index=True, column_order=["started", "duration", "destination.domain", "destination.ip",
                                                         "destination.port", "network.protocol", "up", "down"])

# ---- Destinations
with tabs[1]:
    st.markdown("##### Where the bytes go")
    sk = st.segmented_control("Weight flows by", ["Uploaded", "Downloaded", "Connections"], default="Uploaded",
                              required=True, key="sankey_metric")
    st.caption("host.name → network.protocol → destination.as.organization.name. Red = involved in a finding. "
               "Switch the weighting: one huge upload can hide everything else, and connections show habits.")
    if not inv.flow.empty:
        metric = {"Uploaded": "bytes_out", "Downloaded": "bytes_in", "Connections": "sessions"}[sk]
        st.plotly_chart(C.sankey(inv.flow, flag_orgs, metric), config={"displayModeBar": False})
    st.markdown("##### Destinations ranked by data sent")
    if not dest.empty:
        d = dest.copy()
        d["flag"] = np.where(d["ip"].isin(flag_ips), "🔴", np.where(d["is_new"], "🆕", ""))
        d["first_seen"] = d["first_seen"].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M")
        d["last_seen"] = d["last_seen"].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M")
        d["mb_out"], d["mb_in"] = d["bytes_out"] / 1024 ** 2, d["bytes_in"] / 1024 ** 2
        st.dataframe(d, hide_index=True, height=460,
                     column_order=["flag", "domain", "ip", "org", "country", "protocol", "ports", "sessions",
                                   "mb_out", "mb_in", "ratio", "denied", "first_seen", "last_seen"],
                     column_config={
                         "flag": st.column_config.TextColumn("", width=36, help="🔴 part of a finding · 🆕 first contact in window"),
                         "domain": "destination.domain", "ip": "destination.ip", "org": "AS organization",
                         "mb_out": st.column_config.ProgressColumn("Uploaded (MB)", min_value=0,
                                                                   max_value=float(d["mb_out"].max() or 1), format="%.1f"),
                         "mb_in": st.column_config.NumberColumn("Downloaded (MB)", format="%.1f"),
                         "ratio": st.column_config.NumberColumn("Up:down", format="%.2f",
                                                                help="> 1 means more sent than received - unusual for browsing"),
                         "sessions": st.column_config.NumberColumn("Sessions", format="%,d"),
                     })
    if not inv.new_domains.empty:
        st.markdown("##### First contact in this window")
        nd = inv.new_domains.copy()
        nd["first_seen_ever"] = nd["first_seen_ever"].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M")
        nd["uploaded"] = nd["bytes_out_lookback"].map(A.fmt_bytes)
        st.dataframe(nd, hide_index=True, column_order=["registered_domain", "first_seen_ever", "uploaded"],
                     column_config={"registered_domain": "destination.registered_domain", "first_seen_ever": "First ever contact"})

# ---- Geo & sessions
with tabs[2]:
    st.markdown("##### Traffic around the world")
    st.caption("Arcs from HQ to each destination country (destination.geo), width ∝ bytes uploaded. "
               "Diamonds are VPN login origins (source.geo). Red = involved in a finding.")
    vpn_win = inv.vpn[inv.vpn["@timestamp"] >= start] if not inv.vpn.empty else inv.vpn
    st.plotly_chart(C.world_map(inv.geo, OFFICE, flag_cc, vpn_win), config={"displayModeBar": False})
    g1, g2 = st.columns([1.25, 1])
    with g1:
        st.markdown("##### VPN logins (source.geo)")
        if inv.vpn.empty:
            st.caption("No remote-access sessions in the last 30 days.")
        else:
            v = inv.vpn.copy()
            v["login"] = v["@timestamp"].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M")
            v["duration"] = (v["event.duration"] / 1e9).map(fmt_dur) if "event.duration" in v else "-"
            v.loc[v.get("event.end", pd.Series(index=v.index)).isna(), "duration"] = "open"
            v["check"] = np.where(v["speed_kmh"].fillna(0) > 900, "🔴", "")
            st.dataframe(v.iloc[::-1], hide_index=True, height=320,
                         column_order=["check", "login", "source.geo.city_name", "source.geo.country_iso_code", "source.ip",
                                       "source.as.organization.name", "duration", "distance_km", "speed_kmh"],
                         column_config={"check": st.column_config.TextColumn("", width=36, help="🔴 impossible travel from previous login"),
                                        "source.geo.city_name": "City", "source.geo.country_iso_code": "CC",
                                        "source.ip": "source.ip", "source.as.organization.name": "ISP",
                                        "distance_km": st.column_config.NumberColumn("km from prev", format="%,.0f"),
                                        "speed_kmh": st.column_config.NumberColumn("implied km/h", format="%,.0f")})
    with g2:
        st.markdown("##### Open sessions right now")
        if inv.open_sessions.empty:
            st.caption("Nothing open.")
        else:
            o = inv.open_sessions.copy()
            o["open_for"] = ((end - o["@timestamp"]).dt.total_seconds()).map(fmt_dur)
            o["since"] = o["@timestamp"].dt.tz_convert(tz).dt.strftime("%a %H:%M")
            o["target"] = o.get("destination.domain", pd.Series(index=o.index)).fillna(o["destination.ip"])
            st.dataframe(o, hide_index=True, column_order=["since", "open_for", "event.dataset", "target",
                                                           "destination.port", "network.protocol"],
                         column_config={"event.dataset": "Dataset", "target": "Destination"})

# ---- DNS
with tabs[3]:
    dns = inv.dns
    n = inv.dns_names
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("DNS queries", f"{dns['total']:,}", border=True)
    d2.metric("Unique names", f"{dns['uniq_names']:,}", f"{dns['uniq_domains']} registered domains", delta_color="off", border=True)
    d3.metric("NXDOMAIN rate", f"{dns['nx_rate']:.1f}%", "baseline ~1%", delta_color="off", border=True)
    sus = int((n["class"] != "Normal").sum()) if not n.empty else 0
    d4.metric("Suspicious names", f"{sus:,}", border=True)
    a, b = st.columns([1.2, 1])
    with a:
        st.markdown("##### Does this name look random?")
        st.caption("Each dot is a distinct dns.question.name. Top-right = long, random labels "
                   "(tunnelling); NXDOMAIN with random labels = DGA.")
        if not n.empty:
            st.plotly_chart(C.dns_scatter(n), config={"displayModeBar": False})
    with b:
        st.markdown("##### Most-queried domains")
        st.caption("dns.question.registered_domain")
        if not dns["top"].empty:
            st.plotly_chart(C.dns_top_domains(dns["top"], flag_dns), config={"displayModeBar": False})
    st.markdown("##### Queries over time")
    st.plotly_chart(C.dns_timeline(dns["over_time"], tz), config={"displayModeBar": False})
    if sus:
        st.markdown("##### Suspicious names")
        s_df = n[n["class"] != "Normal"].sort_values(["class", "entropy"], ascending=[True, False])
        st.dataframe(s_df, hide_index=True, height=300,
                     column_order=["class", "name", "qtype", "rcode", "queries", "max_label", "entropy"],
                     column_config={"name": "dns.question.name", "qtype": "type", "rcode": "response",
                                    "entropy": st.column_config.NumberColumn("entropy", format="%.2f")})

# ---- Detections
with tabs[4]:
    st.markdown("##### Beaconing")
    st.caption("Malware checks in on a timer; people don't. For each busy external destination:port we take the "
               "per-minute connection histogram and measure how regular the gaps are (coefficient of variation - "
               "near 0 = metronome).")
    bc = inv.beacons
    if bc.empty:
        st.caption("Not enough repeated external connections to assess.")
    else:
        st.plotly_chart(C.beacon_gaps(inv.beacon_series, bc["pair"].tolist(), tz), config={"displayModeBar": False})
        st.caption("A flat horizontal band = beacon. Scattered points spanning minutes to hours = human use.")
        st.dataframe(bc, hide_index=True, height=260,
                     column_order=["beacon_score", "pair", "domain", "org", "connections", "median_gap_s", "cv",
                                   "span_h", "avg_bytes_out"],
                     column_config={"beacon_score": st.column_config.ProgressColumn("Beacon score", min_value=0, max_value=1, format="%.2f"),
                                    "median_gap_s": st.column_config.NumberColumn("Median gap (s)", format="%.0f"),
                                    "cv": st.column_config.NumberColumn("Gap CV", format="%.2f"),
                                    "span_h": st.column_config.NumberColumn("Span (h)", format="%.0f"),
                                    "avg_bytes_out": st.column_config.NumberColumn("Avg bytes up", format="%.0f")})
    st.divider()
    st.markdown("##### Fan-out (scanning)")
    st.caption("Distinct destination hosts and ports touched per 5 minutes. A person rarely exceeds a handful.")
    if not inv.fanout.empty:
        st.plotly_chart(C.fanout_chart(inv.fanout, tz), config={"displayModeBar": False})
    scanned = any(f.key == "scan" for f in F)
    if scanned and not inv.scan_matrix.empty:
        st.markdown("##### What the scan found")
        st.caption("Every probe to 10.10.20.0/24 by port. Gray = refused, orange = the port answered. "
                   "The orange columns are the hosts the user went on to log into.")
        st.plotly_chart(C.scan_matrix(inv.scan_matrix), config={"displayModeBar": False})
    if not inv.admin.empty:
        st.markdown("##### Admin-protocol sessions (SSH / SMB / RDP / WinRM)")
        ad = inv.admin.copy()
        ad["first_seen"] = ad["first_seen"].dt.tz_convert(tz).dt.strftime("%a %d %b %H:%M")
        ad["pulled"] = ad["bytes_in"].map(A.fmt_bytes)
        st.dataframe(ad, hide_index=True, column_order=["ip", "protocols", "sessions", "pulled", "first_seen"])

# ---- Peers
with tabs[5]:
    st.markdown(f"##### {ident['full_name']} vs the rest of {ident['department']}")
    st.caption("Each bar is this user's value as a multiple of the department median for the same window. "
               "1× = typical; orange bars are 3× or more. Hover for the raw numbers.")
    if inv.peers.empty or len(inv.peers) < 2:
        st.caption("Not enough peers in this department.")
    else:
        st.plotly_chart(C.peer_ratio(inv.peers, user), config={"displayModeBar": False})
        pv = inv.peers.copy()
        pv["ext_bytes_out"] = pv["ext_bytes_out"].map(A.fmt_bytes)
        st.dataframe(pv.sort_values("sessions", ascending=False), hide_index=True,
                     column_config={"offhours_sessions_pct": st.column_config.NumberColumn("off-hours conn %", format="%.1f"),
                                    "offhours_bytes_pct": st.column_config.NumberColumn("off-hours bytes %", format="%.1f")})

# ---- Query inspector
with tabs[6]:
    st.markdown("##### Every query this page ran")
    st.caption("Bodies come from `query_dict.py`; responses come from `data_source.search()`. "
               f"In **{D.MODE}** mode the mock engine executes them, so editing a query changes the result.")
    qlog = inv.queries
    summary = pd.DataFrame([{"query": n_, "hits": r["hits"]["total"]["value"],
                             "aggs": ", ".join((r.get("aggregations") or {}).keys()) or "(hits)", "ms": round(ms, 1)}
                            for n_, (b_, r, ms) in qlog.items()])
    st.dataframe(summary, hide_index=True, height=260)
    pick = st.selectbox("Inspect", list(qlog), key="qpick")
    body, resp, ms = qlog[pick]
    fn = pick.split(" ")[0]
    st.code(f"from query_dict import {fn}\nfrom data_source import search\n\n"
            f"body = {fn}(...)  # user={user!r}, start/end = the selected window\nresp = search(body)", language="python")
    q1, q2 = st.columns(2)
    with q1:
        st.markdown("**Request body**")
        st.code(json.dumps(body, indent=2), language="json", height=520)
    with q2:
        st.markdown(f"**Response** · {resp['hits']['total']['value']:,} hits · {resp['took']} ms · lists trimmed to 3")
        st.json(trim(copy.deepcopy(resp)), expanded=3)
    st.markdown("##### Playground")
    st.caption("Edit the body and run it against the same data source.")
    txt = st.text_area("Query body (JSON)", json.dumps(body, indent=2), height=260, key=f"play_{pick}")
    if st.button(":material/play_arrow: Run", type="primary"):
        try:
            r = D.search(json.loads(txt))
            st.success(f"{r['hits']['total']['value']:,} hits in {r['took']} ms")
            st.json(trim(r, 5), expanded=3)
        except Exception as e:  # noqa: BLE001 - show any query error to the user
            st.error(f"{type(e).__name__}: {e}")
