"""
analysis.py - run every query for one user, parse, detect, score, narrate.

    investigate(user, start, end, tz) -> Investigation

Detections are deliberately explainable: each Finding carries the evidence
that triggered it, the ECS fields involved, a MITRE ATT&CK mapping, the
query that produced it, and concrete next steps for the analyst.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

import data_source as D
import parsers as P
import query_dict as Q

SEVERITY_WEIGHT = {"critical": 0.45, "high": 0.30, "medium": 0.15, "low": 0.05, "info": 0.0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
GB = 1024 ** 3
MB = 1024 ** 2


@dataclass
class Finding:
    key: str
    title: str
    severity: str
    summary: str
    mitre: tuple[str, str]  # (technique id, name)
    fields: list[str]
    next_steps: list[str]
    query: str
    tab: str
    when: pd.Timestamp | None = None
    evidence: pd.DataFrame | None = None


@dataclass
class Investigation:
    user: str
    start: pd.Timestamp
    end: pd.Timestamp
    tz: str
    identity: dict
    kpi: dict
    kpi_prev: dict
    timeline: pd.DataFrame
    destinations: pd.DataFrame
    new_domains: pd.DataFrame
    flow: pd.DataFrame
    geo: pd.DataFrame
    vpn: pd.DataFrame
    open_sessions: pd.DataFrame
    long_sessions: pd.DataFrame
    dns: dict
    dns_names: pd.DataFrame
    beacons: pd.DataFrame
    beacon_series: dict
    fanout: pd.DataFrame
    scan_matrix: pd.DataFrame
    admin: pd.DataFrame
    peers: pd.DataFrame
    findings: list[Finding]
    risk: int
    verdict: str
    narrative: list[str]
    queries: dict = field(default_factory=dict)   # name -> (body, response, ms)


def fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit in ("B", "KB") else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _iso(t: pd.Timestamp) -> str:
    return t.tz_convert("UTC").isoformat().replace("+00:00", "Z")


def user_search(text: str) -> pd.DataFrame:
    return P.parse_user_search(D.search(Q.user_search_query(text)))


def investigate(user: str, start: pd.Timestamp, end: pd.Timestamp, tz: str) -> Investigation | None:
    s, e = _iso(start), _iso(end)
    prev_s = _iso(start - (end - start))
    lookback_s = _iso(end - pd.Timedelta(days=30))
    log: dict = {}

    def run(name, body):
        t = time.perf_counter()
        r = D.search(body)
        log[name] = (body, r, (time.perf_counter() - t) * 1000)
        return r

    ident_r = run("user_identity_query", Q.user_identity_query(user, s, e))
    if ident_r["hits"]["total"]["value"] == 0:
        return None
    identity = P.parse_identity(ident_r)
    kpi = P.parse_kpis(run("user_kpi_query", Q.user_kpi_query(user, s, e)))
    kpi_prev = P.parse_kpis(run("user_kpi_query (previous window)", Q.user_kpi_query(user, prev_s, s)))
    span_h = (end - start).total_seconds() / 3600
    timeline = P.parse_timeline(run("activity_timeline_query",
                                    Q.activity_timeline_query(user, s, e, "1h" if span_h <= 24 * 8 else "3h")))
    dest = P.parse_destinations(run("top_destinations_query", Q.top_destinations_query(user, s, e)))
    first = P.parse_first_seen(run("destination_first_seen_query", Q.destination_first_seen_query(user, lookback_s, e)))
    flow = P.parse_flow(run("traffic_flow_query", Q.traffic_flow_query(user, s, e)))
    geo = P.parse_geo(run("geo_destinations_query", Q.geo_destinations_query(user, s, e)))
    vpn = P.hits_df(run("vpn_sessions_query", Q.vpn_sessions_query(user, lookback_s, e)))
    open_s = P.hits_df(run("open_sessions_query", Q.open_sessions_query(user, lookback_s, e)))
    long_s = P.hits_df(run("long_sessions_query", Q.long_sessions_query(user, s, e)))
    dns = P.parse_dns_overview(run("dns_overview_query", Q.dns_overview_query(user, s, e)))
    names = P.parse_dns_names(run("dns_names_query", Q.dns_names_query(user, s, e)))
    if not names.empty:
        tunnel = (names["max_label"] >= 30) & (names["entropy"] >= 3.5)
        dga = (names["rcode"] == "NXDOMAIN") & (names["subdomain"] == "") & (names["entropy"] >= 3.0)
        names["class"] = np.select([tunnel, dga], ["Possible tunnelling", "Possible DGA"], "Normal")
    beacons, bseries = P.parse_beacons(run("beacon_candidates_query", Q.beacon_candidates_query(user, s, e)))
    fan = P.parse_fanout(run("fanout_query", Q.fanout_query(user, s, e)))
    scan = P.parse_scan_matrix(run("scan_matrix_query", Q.scan_matrix_query(user, s, e)))
    admin = P.parse_admin(run("admin_protocol_query", Q.admin_protocol_query(user, s, e)))
    peers = P.parse_peers(run("peer_baseline_query", Q.peer_baseline_query(identity["department"] or "", s, e, tz)))

    # ---- enrich destinations with "new" flag (first contact inside window)
    data_start = identity["first_seen"]
    new_domains = first[(first["first_seen_ever"] >= start)] if not first.empty else first
    if not dest.empty:
        first_map = dict(zip(first["registered_domain"], first["first_seen_ever"])) if not first.empty else {}
        dest["first_seen_ever"] = dest["registered_domain"].map(first_map)
        dest["is_new"] = dest["first_seen_ever"].notna() & (dest["first_seen_ever"] >= start)
        local_first = dest["first_seen"].dt.tz_convert(tz)
        dest["first_seen_local"] = local_first

    # ---- VPN: travel speed between consecutive logins
    if not vpn.empty:
        vpn = vpn.sort_values("@timestamp", ignore_index=True)
        km, kmh = [np.nan], [np.nan]
        for i in range(1, len(vpn)):
            a, b = vpn.iloc[i - 1], vpn.iloc[i]
            d = P.haversine_km(a["source.geo.location.lat"], a["source.geo.location.lon"],
                               b["source.geo.location.lat"], b["source.geo.location.lon"])
            hrs = max((b["@timestamp"] - a["@timestamp"]).total_seconds() / 3600, 1 / 60)
            km.append(d)
            kmh.append(d / hrs)
        vpn["distance_km"], vpn["speed_kmh"] = km, kmh

    findings = detect(user, start, end, tz, identity, kpi, dest, new_domains, vpn, dns, names,
                      beacons, fan, scan, admin, peers, timeline)
    risk = risk_score(findings)
    verdict = ("Critical - act now" if risk >= 80 else "High - investigate today" if risk >= 55
               else "Elevated - review" if risk >= 25 else "Normal")
    inv = Investigation(user, start, end, tz, identity, kpi, kpi_prev, timeline, dest, new_domains, flow, geo,
                        vpn, open_s, long_s, dns, names, beacons, bseries, fan, scan, admin, peers,
                        findings, risk, verdict, [], log)
    inv.narrative = narrate(inv)
    return inv


# ======================================================================
# Detections
# ======================================================================
def detect(user, start, end, tz, identity, kpi, dest, new_domains, vpn, dns, names, beacons, fan,
           scan, admin, peers, timeline) -> list[Finding]:
    F: list[Finding] = []
    peer_others = peers[peers["user"] != user] if not peers.empty else peers
    me = peers[peers["user"] == user].iloc[0] if not peers.empty and (peers["user"] == user).any() else None

    # 1. Large outbound transfer (exfiltration lens)
    if not dest.empty:
        ext = dest[dest["direction"] == "outbound"]
        big = ext[(ext["bytes_out"] >= 1 * GB) | ((ext["bytes_out"] >= 200 * MB) & (ext["ratio"] >= 20))]
        for _, r in big.iterrows():
            local = r["first_seen"].tz_convert(tz)
            off = local.hour < 7 or local.hour >= 20 or local.dayofweek >= 5
            sev = "critical" if (r["is_new"] or off) else "high"
            ctx = []
            if r["is_new"]:
                ctx.append("a domain this user had **never contacted before**")
            if off:
                ctx.append(f"**outside working hours** ({local:%a %H:%M} local)")
            F.append(Finding(
                "exfil", f"Large upload to {r['domain'] or r['ip']}", sev,
                f"{fmt_bytes(r['bytes_out'])} sent to {r['ip']} ({r['org']}, {r['country_name'] or r['country']}) "
                f"over {r['sessions']} sessions; upload/download ratio {r['ratio']:,.0f}:1"
                + (" - " + " and ".join(ctx) if ctx else "") + ".",
                ("T1048", "Exfiltration Over Alternative Protocol"),
                ["destination.ip", "destination.domain", "source.bytes", "destination.bytes", "destination.as.organization.name"],
                ["Identify the process that opened these connections on " + ", ".join(h["host"] for h in identity["hosts"]) + " (EDR).",
                 f"Block {r['domain'] or r['ip']} at the proxy/firewall and search for other users contacting it.",
                 "Check which files were read from internal shares in the hour before the upload."],
                "top_destinations_query", "Destinations", r["first_seen"], ext[ext["ip"] == r["ip"]]))

    # 2. Impossible travel
    if not vpn.empty and "speed_kmh" in vpn:
        bad = vpn[(vpn["speed_kmh"] > 900) & (vpn["distance_km"] > 500)]
        for i, r in bad.iterrows():
            p = vpn.iloc[i - 1]
            mins = (r["@timestamp"] - p["@timestamp"]).total_seconds() / 60
            F.append(Finding(
                "travel", "Impossible travel between VPN logins", "critical",
                f"Logged in from **{p['source.geo.city_name']}** ({p['source.ip']}) then **{r['source.geo.city_name']}, "
                f"{r['source.geo.country_iso_code']}** ({r['source.ip']}, {r.get('source.as.organization.name', '')}) "
                f"{mins:.0f} min later - {r['distance_km']:,.0f} km apart, i.e. {r['speed_kmh']:,.0f} km/h.",
                ("T1078", "Valid Accounts"),
                ["source.ip", "source.geo.city_name", "source.geo.location", "source.as.organization.name"],
                ["Force a password reset and revoke active sessions/tokens for this account.",
                 "Confirm with the user whether they are travelling or use a personal VPN.",
                 f"Search all users for logins from {r['source.ip']}."],
                "vpn_sessions_query", "Geo & Sessions", r["@timestamp"], vpn.iloc[[i - 1, i]]))

    # 3. Beaconing
    if not beacons.empty:
        hits = beacons[(beacons["cv"] < 0.35) & (beacons["active_minutes"] >= 30) & (beacons["span_h"] >= 6)]
        for _, r in hits.iterrows():
            new = r["domain"] and not new_domains.empty and \
                  (r["domain"].split(".")[-2:] == [] or ".".join(r["domain"].split(".")[-2:]) in set(new_domains["registered_domain"]))
            F.append(Finding(
                "beacon", f"Beaconing to {r['domain'] or r['ip']}", "critical" if new else "high",
                f"{r['connections']:,} connections to {r['pair']} ({r['org']}) every **~{r['median_gap_s']:.0f}s** "
                f"(regularity CV {r['cv']:.2f}; humans are > 1) for {r['span_h']:.0f}h straight, "
                f"~{r['avg_bytes_out']:.0f} bytes each. Looks like automated check-ins, not a person.",
                ("T1071.001", "Application Layer Protocol: Web Protocols (C2)"),
                ["destination.ip", "destination.port", "@timestamp", "source.bytes"],
                ["Isolate the host and pull the process tree for the connecting binary.",
                 f"Look up {r['ip']} / {r['domain']} in threat intel; block at egress.",
                 "Hunt for the same destination across all hosts (it is rarely just one)."],
                "beacon_candidates_query", "Detections", None, hits[hits["pair"] == r["pair"]]))

    # 4. DNS tunnelling
    if not names.empty:
        g = names.groupby("registered_domain").agg(names_=("name", "nunique"), avg_label=("max_label", "mean"),
                                                   ent=("entropy", "mean"), txt=("qtype", lambda s: (s == "TXT").mean()),
                                                   q=("queries", "sum")).reset_index()
        tun = g[(g["names_"] >= 50) & (g["avg_label"] >= 30)]
        for _, r in tun.iterrows():
            F.append(Finding(
                "dns_tunnel", f"DNS tunnelling via {r['registered_domain']}", "high",
                f"{int(r['names_']):,} unique sub-domains under {r['registered_domain']} with ~{r['avg_label']:.0f}-char "
                f"random labels (entropy {r['ent']:.1f} bits/char), {r['txt']:.0%} TXT lookups. "
                "Data is likely being smuggled out inside DNS queries.",
                ("T1071.004", "Application Layer Protocol: DNS"),
                ["dns.question.name", "dns.question.subdomain", "dns.question.type", "dns.question.registered_domain"],
                ["Sinkhole the domain on internal resolvers.",
                 "Decode a few labels (often base32/base64) to see what was sent.",
                 "Alert on hosts sending > 20 queries/min to one domain."],
                "dns_names_query", "DNS", None, names[names["registered_domain"] == r["registered_domain"]].head(25)))

    # 5. DGA / NXDOMAIN storm
    if not names.empty:
        nx = names[(names["rcode"] == "NXDOMAIN") & (names["subdomain"] == "") & (names["entropy"] >= 3.0)]
        if nx["registered_domain"].nunique() >= 25:
            F.append(Finding(
                "dga", "Algorithmically-generated domain lookups (DGA)", "high",
                f"{nx['registered_domain'].nunique()} random-looking domains failed to resolve (NXDOMAIN), "
                f"e.g. `{nx['name'].iloc[0]}`. Overall NXDOMAIN rate {dns['nx_rate']:.1f}%. "
                "Malware uses DGAs to find its command server.",
                ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
                ["dns.question.name", "dns.response_code"],
                ["Correlate the burst times with process launches on the host.",
                 "Check whether any generated name DID resolve - that is the live C2."],
                "dns_names_query", "DNS", nx["first_seen"].min(), nx.head(25)))

    # 6. Internal port scan
    if not fan.empty:
        peak = fan[(fan["uniq_ip"] >= 40) | ((fan["uniq_port"] >= 8) & (fan["uniq_ip"] >= 15))]
        if not peak.empty:
            p = peak.sort_values("uniq_ip", ascending=False).iloc[0]
            fail = peak["failed"].sum() / max(peak["connections"].sum(), 1)
            F.append(Finding(
                "scan", "Internal network scan", "high",
                f"In {len(peak) * 5} minutes starting {peak['time'].min().tz_convert(tz):%a %H:%M} local, "
                f"touched up to **{int(p['uniq_ip'])} hosts** and **{int(p['uniq_port'])} ports** per 5 min "
                f"({fail:.0%} failed). Normal for this user: {int(fan['uniq_ip'].median())} hosts per 5 min.",
                ("T1046", "Network Service Discovery"),
                ["destination.ip", "destination.port", "event.outcome"],
                ["Ask whether an approved vulnerability scan was scheduled for this user/host.",
                 "If not, treat the host as compromised and check what happened right after (lateral movement)."],
                "fanout_query", "Detections", peak["time"].min(), peak))

    # 7. Admin-protocol fan-out (lateral movement)
    if not admin.empty:
        tgt = admin[~admin["ip"].isin(["10.10.5.30"])]  # known CI server
        if len(tgt) >= 4:
            scanned = any(f.key == "scan" for f in F)
            F.append(Finding(
                "lateral", "Remote admin sessions to many internal hosts", "critical" if scanned else "medium",
                f"Successful SMB/RDP/WinRM/SSH sessions to **{len(tgt)} internal hosts**, pulling "
                f"{fmt_bytes(tgt['bytes_in'].sum())}" + (" - **right after the scan above**." if scanned else "."),
                ("T1021", "Remote Services"),
                ["destination.ip", "destination.port", "network.protocol", "destination.bytes"],
                ["Review authentication logs on the targets for this account.",
                 "Check the open RDP session to the domain controller first."],
                "admin_protocol_query", "Detections", tgt["first_seen"].min(), tgt))

    # 8. Peer outlier: external upload volume
    if me is not None and len(peer_others):
        med = peer_others["ext_bytes_out"].median()
        if med and me["ext_bytes_out"] > 5 * med and me["ext_bytes_out"] > 200 * MB:
            F.append(Finding(
                "peer_bytes", "Uploads far above department peers", "medium",
                f"{fmt_bytes(me['ext_bytes_out'])} sent to the internet vs a {identity['department']} median of "
                f"{fmt_bytes(med)} (**{me['ext_bytes_out'] / med:,.0f}x**).",
                ("TA0010", "Exfiltration"), ["source.bytes", "network.direction", "user.group.name"],
                ["See Destinations tab for where it went."], "peer_baseline_query", "Peers", None, None))
        med_off = peer_others["offhours_sessions_pct"].median()
        med_offb = peer_others["offhours_bytes_pct"].median()
        sess_hit = me["offhours_sessions_pct"] > max(3 * med_off, 15)
        bytes_hit = me["offhours_bytes_pct"] > max(3 * med_offb, 40)
        if sess_hit or bytes_hit:
            what = (f"{me['offhours_sessions_pct']:.0f}% of connections happen nights/weekends vs {med_off:.0f}% "
                    f"for {identity['department']} peers" if sess_hit else
                    f"{me['offhours_bytes_pct']:.0f}% of all uploaded bytes moved nights/weekends vs {med_offb:.0f}% "
                    f"for {identity['department']} peers")
            F.append(Finding(
                "offhours", "Unusual off-hours activity", "medium",
                what + " - something is active when the user normally is not.",
                ("T1029", "Scheduled Transfer"), ["@timestamp"],
                ["Compare with badge/VPN logs: was the user actually working?"],
                "peer_baseline_query", "Timeline", None, None))

    # 9. New destinations (context)
    if not new_domains.empty and len(new_domains):
        F.append(Finding(
            "new_dest", f"{len(new_domains)} domain(s) contacted for the first time", "low" if len(new_domains) <= 3 else "medium",
            "First contact in this window (vs the last 30 days): " + ", ".join(f"`{d}`" for d in new_domains["registered_domain"].head(6)) + ".",
            ("-", "Context"), ["destination.registered_domain"],
            ["New + high-volume or new + regular = worth a look."], "destination_first_seen_query", "Destinations",
            None, new_domains))

    # 10. Policy blocks
    if (kpi["denied"] >= 15 or kpi["denied_pct"] > 3) and not any(f.key == "scan" for f in F):
        F.append(Finding(
            "denied", "Many failed or blocked connections", "low",
            f"{kpi['denied']:,} connections failed or were denied by policy ({kpi['denied_pct']:.1f}%).", ("-", "Policy"),
            ["event.outcome", "event.action"], ["Review which categories were blocked."], "user_kpi_query", "Timeline"))

    F.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return F


def risk_score(findings: list[Finding]) -> int:
    """Noisy-OR of finding weights, floored by the worst severity present."""
    p = 1.0
    for f in findings:
        p *= 1 - SEVERITY_WEIGHT[f.severity]
    score = 100 * (1 - p)
    sev = {f.severity for f in findings}
    if "critical" in sev:
        score = max(score, 80)
    elif "high" in sev:
        score = max(score, 55)
    return int(round(min(score, 99)))


# ======================================================================
# Narrative
# ======================================================================
def narrate(inv: Investigation) -> list[str]:
    k, kp, ident = inv.kpi, inv.kpi_prev, inv.identity
    days = (inv.end - inv.start).total_seconds() / 86400
    hosts = ", ".join(h["host"] for h in ident["hosts"])
    out = [f"**{ident['full_name']}** ({ident['department']}) made **{k['sessions']:,} connections** over the last "
           f"{days:.0f} day{'s' if days != 1 else ''} from {hosts}, to {k['uniq_dest_ip']} distinct IPs "
           f"across {k['uniq_domains']} domains."]
    if kp["sessions"]:
        ch = (k["bytes_out"] - kp["bytes_out"]) / max(kp["bytes_out"], 1) * 100
        if abs(ch) >= 50:
            out.append(f"Upload volume is **{'up' if ch > 0 else 'down'} {abs(ch):,.0f}%** on the previous period "
                       f"({fmt_bytes(kp['bytes_out'])} → {fmt_bytes(k['bytes_out'])}).")
    if not inv.destinations.empty:
        top = inv.destinations[inv.destinations["direction"] == "outbound"].head(1)
        if len(top):
            t = top.iloc[0]
            out.append(f"Most data went to **{t['domain'] or t['ip']}** ({t['org']}, {t['country_name'] or t['country']}).")
    crit = [f for f in inv.findings if f.severity in ("critical", "high")]
    if crit:
        out.append(f"**{len(crit)} high-severity finding{'s' if len(crit) > 1 else ''}**: "
                   + "; ".join(f.title.lower() for f in crit) + ".")
    else:
        out.append("No high-severity behaviour detected - traffic matches business-hours SaaS use typical of the department.")
    if k["open_sessions"]:
        out.append(f"{k['open_sessions']} session(s) are **open right now**.")
    return out
