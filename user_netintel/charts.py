"""
charts.py - every Plotly figure on the page, styled as one system.

Palette: the validated dark-mode reference palette (categorical slots in fixed
order, one-hue blue sequential ramp, reserved status colours). Status colours
are only used for severity, always next to a text label.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ---- tokens (dark) -------------------------------------------------------
TEXT, TEXT_2, MUTED = "#f0efec", "#c3c2b7", "#8f8e86"
GRID, SURFACE, SURFACE_2 = "#2f2f2c", "#1a1a19", "#232321"
S = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
SEV_COLOR = {"critical": STATUS["critical"], "high": STATUS["serious"], "medium": STATUS["warning"],
             "low": "#6da7ec", "info": MUTED}
SEQ = [[0.0, "#20201e"], [0.12, "#0d366b"], [0.35, "#1c5cab"], [0.6, "#3987e5"], [0.82, "#86b6ef"], [1.0, "#cde2fb"]]
FAILED = "#57564f"


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or u == "TB":
            return f"{n:,.0f} {u}" if u in ("B", "KB") else f"{n:,.1f} {u}"
        n /= 1024


def base(fig: go.Figure, height=320, legend=True, margin=None) -> go.Figure:
    fig.update_layout(
        height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, system-ui, sans-serif", size=12, color=TEXT_2),
        margin=margin or dict(l=8, r=8, t=8, b=8), showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, bgcolor="rgba(0,0,0,0)", font=dict(color=TEXT_2)),
        hoverlabel=dict(bgcolor=SURFACE_2, bordercolor=GRID, font=dict(color=TEXT, size=12)),
        hovermode="closest",
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=MUTED), showspikes=False)
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=MUTED))
    return fig


# ---- timeline -----------------------------------------------------------
def traffic_timeline(tl: pd.DataFrame, tz: str, events: list[tuple[pd.Timestamp, str, str]]) -> go.Figure:
    t = tl["time"].dt.tz_convert(tz)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=t, y=tl["bytes_out"] / 1024 ** 2, name="Uploaded (source.bytes)", mode="lines",
                             line=dict(color=S[1], width=2), fill="tozeroy", fillcolor="rgba(217,89,38,0.12)",
                             hovertemplate="%{x|%a %d %b %H:%M}<br>Uploaded %{y:,.1f} MB<extra></extra>"))
    fig.add_trace(go.Scatter(x=t, y=tl["bytes_in"] / 1024 ** 2, name="Downloaded (destination.bytes)", mode="lines",
                             line=dict(color=S[0], width=2),
                             hovertemplate="%{x|%a %d %b %H:%M}<br>Downloaded %{y:,.1f} MB<extra></extra>"))
    _shade_off_hours(fig, t)
    for i, (ts, label, sev) in enumerate(sorted(events, key=lambda e: e[0])):
        x = ts.tz_convert(tz)
        fig.add_vline(x=x, line=dict(color=SEV_COLOR[sev], width=1.5, dash="dot"))
        fig.add_annotation(x=x, y=1 - 0.13 * (i % 3), yref="paper", text=label, showarrow=False,
                           xanchor="right" if x > t.iloc[len(t) // 2] else "left", yanchor="top",
                           font=dict(color=TEXT, size=11), bgcolor=SURFACE_2, bordercolor=SEV_COLOR[sev], borderpad=3)
    fig.update_yaxes(title_text="MB per hour", title_font=dict(color=MUTED), rangemode="tozero")
    fig.update_layout(hovermode="x unified")
    return base(fig, 330)


def _shade_off_hours(fig, t: pd.Series):
    if t.empty:
        return
    days = pd.date_range(t.min().normalize(), t.max().normalize() + pd.Timedelta(days=1), freq="D")
    for d in days:
        fig.add_vrect(x0=d, x1=d + pd.Timedelta(hours=7), fillcolor="#ffffff", opacity=0.035, line_width=0, layer="below")
        fig.add_vrect(x0=d + pd.Timedelta(hours=20), x1=d + pd.Timedelta(hours=24), fillcolor="#ffffff",
                      opacity=0.035, line_width=0, layer="below")


def connections_bar(tl: pd.DataFrame, tz: str) -> go.Figure:
    t = tl["time"].dt.tz_convert(tz)
    ok = tl["sessions"] - tl["denied"]
    fig = go.Figure()
    fig.add_trace(go.Bar(x=t, y=ok, name="Succeeded", marker=dict(color=S[0], line=dict(width=0)),
                         hovertemplate="%{x|%a %H:%M}<br>%{y:,} succeeded<extra></extra>"))
    fig.add_trace(go.Bar(x=t, y=tl["denied"], name="Failed / denied", marker=dict(color=S[3], line=dict(width=0)),
                         hovertemplate="%{x|%a %H:%M}<br>%{y:,} failed or denied<extra></extra>"))
    fig.update_layout(barmode="stack", bargap=0.15)
    fig.update_yaxes(title_text="connections / hour", title_font=dict(color=MUTED))
    return base(fig, 230)


def week_heatmap(m: pd.DataFrame, title_value="connections") -> go.Figure:
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    z = m.values.astype(float)
    fig = go.Figure(go.Heatmap(
        z=z, x=[f"{h:02d}" for h in range(24)], y=days, colorscale=SEQ, xgap=2, ygap=2,
        colorbar=dict(thickness=10, outlinewidth=0, tickfont=dict(color=MUTED), title=dict(text=title_value, side="right", font=dict(color=MUTED))),
        hovertemplate="%{y} %{x}:00<br>%{z:,.0f} " + title_value + "<extra></extra>"))
    for x0, x1 in ((-0.5, 6.5), (19.5, 23.5)):
        fig.add_shape(type="rect", x0=x0, x1=x1, y0=-0.5, y1=6.5, line=dict(color=MUTED, width=1, dash="dot"))
    fig.add_annotation(x=3, y=6.5, text="off-hours", showarrow=False, yanchor="bottom", font=dict(color=MUTED, size=11))
    fig.add_annotation(x=21.5, y=6.5, text="off-hours", showarrow=False, yanchor="bottom", font=dict(color=MUTED, size=11))
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(showgrid=False, title_text="local hour", title_font=dict(color=MUTED))
    return base(fig, 270, legend=False, margin=dict(l=8, r=8, t=24, b=8))


# ---- destinations ---------------------------------------------------------
def sankey(flow: pd.DataFrame, flagged_orgs: set[str], metric: str = "bytes_out") -> go.Figure:
    f = flow[flow[metric] > 0].copy().assign(bytes_out=lambda d: d[metric])
    unit = "B" if metric.startswith("bytes") else " connections"
    hosts, protos = sorted(f["host"].unique()), list(f.groupby("protocol")["bytes_out"].sum().sort_values(ascending=False).index)
    orgs = list(f.groupby("org")["bytes_out"].sum().sort_values(ascending=False).index)
    labels = hosts + [p.upper() for p in protos] + orgs
    idx = {("h", h): i for i, h in enumerate(hosts)}
    idx |= {("p", p): len(hosts) + i for i, p in enumerate(protos)}
    idx |= {("o", o): len(hosts) + len(protos) + i for i, o in enumerate(orgs)}
    node_col = [MUTED] * len(hosts) + [S[0]] * len(protos) + \
               [STATUS["critical"] if o in flagged_orgs else (S[2] if o == "Corporate network" else S[6]) for o in orgs]
    hp = f.groupby(["host", "protocol"])["bytes_out"].sum().reset_index()
    po = f.groupby(["protocol", "org"])["bytes_out"].sum().reset_index()
    src = [idx[("h", r.host)] for r in hp.itertuples()] + [idx[("p", r.protocol)] for r in po.itertuples()]
    tgt = [idx[("p", r.protocol)] for r in hp.itertuples()] + [idx[("o", r.org)] for r in po.itertuples()]
    val = list(hp["bytes_out"]) + list(po["bytes_out"])
    link_col = ["rgba(143,142,134,0.25)"] * len(hp) + \
               ["rgba(208,59,59,0.55)" if r.org in flagged_orgs else "rgba(57,135,229,0.22)" for r in po.itertuples()]
    fig = go.Figure(go.Sankey(
        arrangement="snap", valueformat=".3s" if unit == "B" else ",.0f", valuesuffix=unit,
        node=dict(label=labels, color=node_col, pad=14, thickness=12, line=dict(width=0),
                  hovertemplate="%{label}<br>%{value}<extra></extra>"),
        link=dict(source=src, target=tgt, value=val, color=link_col,
                  hovertemplate="%{source.label} → %{target.label}<br>%{value}<extra></extra>")))
    fig.update_layout(font=dict(color=TEXT, size=12))
    return base(fig, 380, legend=False)


# ---- geo -------------------------------------------------------------------
def world_map(geo: pd.DataFrame, office: tuple[float, float], flagged: set[str], vpn: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    olat, olon = office
    g = geo.dropna(subset=["lat"])
    mx = max(g["bytes_out"].max(), 1) if len(g) else 1
    for r in g.itertuples():
        bad = r.country in flagged
        w = 1 + 6 * np.log1p(r.bytes_out) / np.log1p(mx)
        fig.add_trace(go.Scattergeo(lon=[olon, r.lon], lat=[olat, r.lat], mode="lines",
                                    line=dict(width=w, color=STATUS["critical"] if bad else "rgba(57,135,229,0.55)"),
                                    hoverinfo="skip", showlegend=False))
    if len(g):
        bad = g["country"].isin(flagged)
        for mask, name, col in ((~bad, "Destination country", S[0]), (bad, "Flagged destination", STATUS["critical"])):
            d = g[mask]
            if d.empty:
                continue
            fig.add_trace(go.Scattergeo(
                lon=d["lon"], lat=d["lat"], mode="markers+text", name=name, text=d["country"], textposition="top center",
                textfont=dict(color=TEXT, size=11),
                marker=dict(size=9 + 16 * np.sqrt(d["bytes_out"] / mx), color=col, line=dict(color=SURFACE, width=2)),
                customdata=np.stack([d["country_name"], d["bytes_out"].map(_fmt_bytes), d["sessions"], d["orgs"]], axis=1),
                hovertemplate="<b>%{customdata[0]}</b><br>%{customdata[1]} uploaded · %{customdata[2]:,} sessions"
                              "<br>%{customdata[3]}<extra></extra>"))
    if not vpn.empty:
        bad_login = vpn["speed_kmh"].fillna(0) > 900
        fig.add_trace(go.Scattergeo(
            lon=vpn["source.geo.location.lon"], lat=vpn["source.geo.location.lat"], mode="markers", name="VPN login origin",
            marker=dict(size=11, symbol="diamond", color=[STATUS["critical"] if b else S[2] for b in bad_login],
                        line=dict(color=SURFACE, width=2)),
            customdata=np.stack([vpn["source.geo.city_name"], vpn["source.ip"], vpn["@timestamp"].dt.strftime("%a %d %b %H:%M UTC")], axis=1),
            hovertemplate="VPN login from <b>%{customdata[0]}</b><br>%{customdata[1]}<br>%{customdata[2]}<extra></extra>"))
    fig.add_trace(go.Scattergeo(lon=[olon], lat=[olat], mode="markers", name="Office (source)",
                                marker=dict(size=12, color=TEXT, symbol="star", line=dict(color=SURFACE, width=1)),
                                hovertemplate="Office / user location<extra></extra>"))
    fig.update_geos(projection_type="natural earth", showcountries=True, countrycolor="#3a3a37", showcoastlines=False,
                    showland=True, landcolor="#262624", showocean=True, oceancolor=SURFACE, bgcolor="rgba(0,0,0,0)",
                    showframe=False, lataxis_range=[-50, 75])
    return base(fig, 420, margin=dict(l=0, r=0, t=30, b=0))


# ---- DNS -------------------------------------------------------------------
def dns_scatter(names: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    cls = names["class"]
    for label, col, sym in (("Normal", S[0], "circle"), ("Possible tunnelling", S[1], "diamond"),
                            ("Possible DGA", S[6], "x")):
        d = names[cls == label]
        if d.empty:
            continue
        fig.add_trace(go.Scattergl(
            x=d["max_label"], y=d["entropy"], mode="markers", name=f"{label} ({len(d):,})",
            marker=dict(color=col, size=8, symbol=sym, opacity=0.8, line=dict(width=0)),
            customdata=np.stack([d["name"], d["rcode"], d["qtype"], d["queries"]], axis=1),
            hovertemplate="%{customdata[0]}<br>%{customdata[2]} → %{customdata[1]} · %{customdata[3]} queries"
                          "<br>longest label %{x} chars · entropy %{y:.2f}<extra></extra>"))
    fig.add_vline(x=30, line=dict(color=MUTED, dash="dot", width=1))
    fig.add_hline(y=3.5, line=dict(color=MUTED, dash="dot", width=1))
    fig.update_xaxes(title_text="longest label (chars)", title_font=dict(color=MUTED))
    fig.update_yaxes(title_text="Shannon entropy (bits/char)", title_font=dict(color=MUTED))
    return base(fig, 360)


def dns_top_domains(top: pd.DataFrame, flagged: set[str]) -> go.Figure:
    d = top.head(15).iloc[::-1]
    fig = go.Figure(go.Bar(
        x=d["queries"], y=d["domain"], orientation="h",
        marker=dict(color=[STATUS["critical"] if x in flagged else S[0] for x in d["domain"]], line=dict(width=0)),
        customdata=np.stack([d["uniq_names"], d["nxdomain"]], axis=1),
        hovertemplate="%{y}<br>%{x:,} queries · %{customdata[0]:,} unique names · %{customdata[1]:,} NXDOMAIN<extra></extra>"))
    fig.update_xaxes(title_text="queries", title_font=dict(color=MUTED))
    fig.update_yaxes(showgrid=False, tickfont=dict(color=TEXT_2))
    return base(fig, 380, legend=False)


def dns_timeline(over: pd.DataFrame, tz: str) -> go.Figure:
    t = over["time"].dt.tz_convert(tz)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=t, y=over["queries"] - over["nxdomain"], name="Resolved", marker=dict(color=S[0], line=dict(width=0))))
    fig.add_trace(go.Bar(x=t, y=over["nxdomain"], name="NXDOMAIN", marker=dict(color=S[3], line=dict(width=0))))
    fig.update_layout(barmode="stack", bargap=0.15, hovermode="x unified")
    fig.update_yaxes(title_text="queries / hour", title_font=dict(color=MUTED))
    return base(fig, 230)


# ---- detections ------------------------------------------------------------
def beacon_gaps(series: dict, pairs: list[str], tz: str) -> go.Figure:
    fig = go.Figure()
    for i, p in enumerate(pairs[:3]):
        t = series[p]
        gaps = np.diff(t) / 60
        x = pd.to_datetime(t[1:], unit="s", utc=True).tz_convert(tz)
        fig.add_trace(go.Scattergl(x=x, y=gaps, mode="markers", name=p, marker=dict(color=S[i], size=6, opacity=0.75),
                                   hovertemplate="%{x|%a %H:%M}<br>%{y:.0f} min since previous<extra>" + p + "</extra>"))
    fig.update_yaxes(type="log", title_text="minutes between connections (log)", title_font=dict(color=MUTED))
    return base(fig, 320)


def fanout_chart(fan: pd.DataFrame, tz: str) -> go.Figure:
    t = fan["time"].dt.tz_convert(tz)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=t, y=fan["uniq_ip"], name="distinct hosts / 5 min", mode="lines",
                             line=dict(color=S[0], width=2), hovertemplate="%{x|%a %H:%M}<br>%{y} hosts<extra></extra>"))
    fig.add_trace(go.Scatter(x=t, y=fan["uniq_port"], name="distinct ports / 5 min", mode="lines",
                             line=dict(color=S[1], width=2), hovertemplate="%{x|%a %H:%M}<br>%{y} ports<extra></extra>"))
    fig.update_layout(hovermode="x unified")
    fig.update_yaxes(title_text="distinct count", title_font=dict(color=MUTED), rangemode="tozero")
    return base(fig, 280)


def scan_matrix(m: pd.DataFrame) -> go.Figure:
    m = m.copy()
    m["octet"] = m["ip"].str.split(".").str[-1].astype(int)
    m = m[m["ip"].str.startswith("10.10.20.")]
    ports = sorted(m["port"].unique())
    piv = m.assign(state=np.where(m["ok"] > 0, 2, 1)).pivot_table(index="port", columns="octet", values="state",
                                                                    aggfunc="max", fill_value=0)
    piv = piv.reindex(index=ports, columns=range(1, 255), fill_value=0)
    fig = go.Figure(go.Heatmap(
        z=piv.values, x=piv.columns, y=[str(p) for p in piv.index], xgap=1, ygap=2, showscale=False,
        zmin=0, zmax=2, colorscale=[[0, SURFACE], [0.33, SURFACE], [0.34, FAILED], [0.66, FAILED], [0.67, S[1]], [1, S[1]]],
        hovertemplate="10.10.20.%{x} : %{y}<br>%{z}<extra></extra>",
        text=np.where(piv.values == 2, "open - connected", np.where(piv.values == 1, "probed - refused", "not probed")),
        texttemplate=""))
    fig.data[0].hovertemplate = "10.10.20.%{x} : port %{y}<br>%{text}<extra></extra>"
    fig.update_xaxes(title_text="target 10.10.20.x", title_font=dict(color=MUTED), showgrid=False)
    fig.update_yaxes(title_text="port", title_font=dict(color=MUTED), showgrid=False, type="category")
    return base(fig, 300, legend=False)


# ---- peers -----------------------------------------------------------------
PEER_METRICS = [("ext_bytes_out", "Uploaded to internet", _fmt_bytes),
                ("uniq_dest_ip", "Distinct destination IPs", lambda v: f"{v:,.0f}"),
                ("uniq_dest_port", "Distinct destination ports", lambda v: f"{v:,.0f}"),
                ("uniq_domains", "Distinct domains", lambda v: f"{v:,.0f}"),
                ("offhours_sessions_pct", "Off-hours connections %", lambda v: f"{v:.0f}%"),
                ("offhours_bytes_pct", "Off-hours upload %", lambda v: f"{v:.0f}%"),
                ("denied", "Failed / denied", lambda v: f"{v:,.0f}")]


def peer_ratio(peers: pd.DataFrame, user: str) -> go.Figure:
    """User's value as a multiple of the department median, one bar per metric (log scale)."""
    others, me = peers[peers["user"] != user], peers[peers["user"] == user]
    rows = []
    for col, label, f in PEER_METRICS:
        med = float(others[col].median()) if len(others) else 0.0
        val = float(me[col].iloc[0]) if len(me) else 0.0
        floor = 1.0 if col in ("denied", "uniq_dest_port") else (1e6 if col == "ext_bytes_out" else 1.0)
        ratio = max(val, 0.0) / max(med, floor) if (val or med) else 1.0
        rows.append((label, max(ratio, 0.1), f(val), f(med)))
    rows = rows[::-1]
    hot = [r[1] >= 3 for r in rows]
    fig = go.Figure(go.Bar(
        x=[r[1] for r in rows], y=[r[0] for r in rows], orientation="h", base=0,
        marker=dict(color=[STATUS["serious"] if h else S[0] for h in hot], line=dict(width=0)),
        text=[f"×{r[1]:,.1f}" + ("  ▲ unusual" if h else "") for r, h in zip(rows, hot)],
        textposition="outside", textfont=dict(color=TEXT, size=12), cliponaxis=False,
        customdata=[[r[2], r[3]] for r in rows],
        hovertemplate="%{y}<br>this user: %{customdata[0]}<br>dept median: %{customdata[1]}<extra></extra>"))
    fig.add_vline(x=1, line=dict(color=MUTED, dash="dot", width=1))
    fig.add_annotation(x=0, xref="x", y=1.02, yref="paper", text="= dept median", showarrow=False,
                       xanchor="left", yanchor="bottom", font=dict(color=MUTED, size=11))
    mx = max(r[1] for r in rows)
    fig.update_xaxes(type="log", range=[-1, np.log10(max(mx, 10)) + 0.6], title_text="× department median (log)",
                     title_font=dict(color=MUTED), tickvals=[0.1, 1, 10, 100, 1000], ticktext=["0.1×", "1×", "10×", "100×", "1000×"])
    fig.update_yaxes(showgrid=False, tickfont=dict(color=TEXT_2, size=12))
    fig.update_layout(bargap=0.35)
    return base(fig, 360, legend=False, margin=dict(l=8, r=8, t=28, b=8))
