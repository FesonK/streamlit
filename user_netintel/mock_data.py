"""
mock_data.py - synthetic ECS network telemetry.

Generates ~14 days of flow, DNS and VPN events for a small company and plants
a realistic incident "story" on a few users so the detectors have something
to find:

    jdoe     Finance      data exfiltration at 2am to a brand-new domain + impossible travel
    asmith   Engineering  C2 beaconing, DGA lookups and DNS tunnelling (compromised laptop)
    bwayne   IT           internal port scan followed by SMB/RDP lateral movement
    mlopez   Marketing    clean, normal user (the control case)

Everything else is background traffic from department peers. The events are
stored as one flat DataFrame with dotted ECS column names ("source.ip", ...),
which `es_mock_engine.py` queries exactly like Elasticsearch would.

Malicious infrastructure deliberately uses documentation IP ranges
(198.51.100.0/24, 203.0.113.0/24) and invented domains.
"""
from __future__ import annotations

import string
from dataclasses import dataclass

import numpy as np
import pandas as pd

DAYS = 14
OFFICE = {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060}
LOCAL_TZ = "America/New_York"

DNS_SERVER = "10.10.1.53"
VPN_GW = "10.10.0.1"


@dataclass(frozen=True)
class User:
    name: str
    full_name: str
    group: str
    host: str
    os: str
    ip: str
    mac: str
    home_city: str
    home_country: str
    home_lat: float
    home_lon: float
    home_ip: str
    activity: float = 1.0  # traffic multiplier


FEATURED = [
    User("jdoe", "Jane Doe", "Finance", "FIN-LT-0142", "Windows 11", "10.10.40.142", "00-1A-2B-3C-4D-42",
         "Jersey City", "US", 40.7178, -74.0431, "100.36.12.88"),
    User("asmith", "Alex Smith", "Engineering", "ENG-MBP-0217", "macOS 15", "10.10.50.217", "00-1A-2B-3C-5E-17",
         "Brooklyn", "US", 40.6782, -73.9442, "72.229.31.140"),
    User("bwayne", "Bruce Wayne", "IT", "IT-WS-0007", "Windows 11", "10.10.30.7", "00-1A-2B-3C-1F-07",
         "Hoboken", "US", 40.7440, -74.0324, "108.6.88.21"),
    User("mlopez", "Maria Lopez", "Marketing", "MKT-LT-0311", "macOS 15", "10.10.60.111", "00-1A-2B-3C-6A-11",
         "Queens", "US", 40.7282, -73.7949, "74.101.9.207"),
]

_PEER_NAMES = {
    "Finance": ["kchen", "rpatel", "lnguyen"],
    "Engineering": ["dkim", "sgarcia", "tbrown", "ewilson"],
    "IT": ["jmartin", "plee"],
    "Marketing": ["avasquez", "cmoore", "nharris"],
}
_PREFIX = {"Finance": "FIN-LT", "Engineering": "ENG-MBP", "IT": "IT-WS", "Marketing": "MKT-LT"}
_SUBNET = {"Finance": 40, "Engineering": 50, "IT": 30, "Marketing": 60}


def _peers() -> list[User]:
    out = []
    for g, names in _PEER_NAMES.items():
        for i, n in enumerate(names):
            k = 100 + i * 7 + len(n)
            out.append(User(n, n[0].upper() + ". " + n[1:].title(), g, f"{_PREFIX[g]}-0{k}",
                            "macOS 15" if g == "Engineering" else "Windows 11",
                            f"10.10.{_SUBNET[g]}.{k}", f"00-1A-2B-3C-{_SUBNET[g]:02X}-{k:02X}",
                            "New York", "US", 40.73 + i * 0.01, -73.99 - i * 0.01,
                            f"71.{180 + i}.{k}.{10 + i}", activity=float(0.75 + 0.15 * i)))
    return out


ALL_USERS = FEATURED + _peers()

# ---------------------------------------------------------------------------
# Destination catalogue: domain, ip, port, protocol, transport, org, asn,
# country iso/name, city, lat, lon, typical bytes out/in (median), weight per group
# ---------------------------------------------------------------------------
_EXT = [
    # domain                       ip               port proto  org                        asn     cc   country          city         lat      lon       out    in       F  E  I  M
    ("outlook.office365.com",     "52.96.164.18",   443, "tls", "Microsoft Corporation",   8075,  "US", "United States", "Redmond",     47.674, -122.121, 9e3,  6e4,    9, 7, 8, 8),
    ("teams.microsoft.com",       "52.113.194.132", 443, "tls", "Microsoft Corporation",   8075,  "US", "United States", "Redmond",     47.674, -122.121, 2e4,  9e4,    6, 4, 6, 6),
    ("sharepoint.com",            "13.107.136.9",   443, "tls", "Microsoft Corporation",   8075,  "IE", "Ireland",       "Dublin",      53.349,  -6.260,  3e4,  2e5,    7, 2, 4, 5),
    ("www.google.com",            "142.250.80.36",  443, "tls", "Google LLC",              15169, "US", "United States", "Mountain View", 37.386, -122.084, 2e3,  4e4,  5, 6, 5, 6),
    ("slack.com",                 "54.230.11.62",   443, "tls", "Amazon.com, Inc.",        16509, "US", "United States", "Ashburn",     39.044, -77.488,  4e3,  2e4,    3, 8, 6, 5),
    ("zoom.us",                   "170.114.52.2",   443, "tls", "Zoom Video Communications", 30103, "US", "United States", "San Jose", 37.338, -121.886, 6e4,  8e4,    3, 3, 3, 4),
    ("salesforce.com",            "136.147.46.190", 443, "tls", "Salesforce.com, Inc.",    14340, "US", "United States", "San Francisco", 37.775, -122.418, 1e4, 9e4,   6, 0, 0, 5),
    ("netsuite.com",              "199.68.217.10",  443, "tls", "Oracle Corporation",      31898, "US", "United States", "Austin",      30.267, -97.743,  1e4,  7e4,    6, 0, 0, 0),
    ("github.com",                "140.82.112.4",   443, "tls", "GitHub, Inc.",            36459, "US", "United States", "San Francisco", 37.775, -122.418, 3e4, 4e5,   0, 9, 3, 0),
    ("pypi.org",                  "151.101.0.223",  443, "tls", "Fastly, Inc.",            54113, "GB", "United Kingdom", "London",     51.507,  -0.128,  2e3,  9e5,    0, 5, 1, 0),
    ("registry-1.docker.io",      "44.205.64.79",   443, "tls", "Amazon.com, Inc.",        16509, "US", "United States", "Ashburn",     39.044, -77.488,  3e3,  2e6,    0, 4, 2, 0),
    ("s3.eu-central-1.amazonaws.com", "52.219.170.9", 443, "tls", "Amazon.com, Inc.",      16509, "DE", "Germany",       "Frankfurt",   50.110,   8.682,  5e4,  3e5,    1, 4, 2, 1),
    ("cdnjs.cloudflare.com",      "104.17.24.14",   443, "tls", "Cloudflare, Inc.",        13335, "US", "United States", "San Francisco", 37.775, -122.418, 1e3, 6e4,   3, 4, 3, 4),
    ("www.linkedin.com",          "13.107.42.14",   443, "tls", "Microsoft Corporation",   8075,  "US", "United States", "Redmond",     47.674, -122.121, 3e3,  8e4,    2, 2, 1, 6),
    ("hubspot.com",               "104.16.249.5",   443, "tls", "Cloudflare, Inc.",        13335, "US", "United States", "Boston",      42.360, -71.058,  8e3,  6e4,    0, 0, 0, 7),
    ("canva.com",                 "104.16.103.112", 443, "tls", "Canva Pty Ltd",           133877, "AU", "Australia",    "Sydney",     -33.869, 151.209,  4e4,  5e5,    0, 0, 0, 5),
    ("okta.com",                  "44.193.215.2",   443, "tls", "Okta, Inc.",              393427, "US", "United States", "Ashburn",    39.044, -77.488,  2e3,  1e4,    3, 3, 4, 3),
    ("update.microsoft.com",      "13.107.4.50",    80,  "http", "Microsoft Corporation",  8075,  "US", "United States", "Redmond",     47.674, -122.121, 1e3,  5e5,    1, 1, 2, 1),
    ("api.datadoghq.eu",          "3.233.158.24",   443, "tls", "Amazon.com, Inc.",        16509, "NL", "Netherlands",   "Amsterdam",   52.370,   4.895,  2e4,  3e3,    0, 3, 2, 0),
    ("app.box.com",               "74.112.186.144", 443, "tls", "Box, Inc.",               33011, "SG", "Singapore",     "Singapore",    1.352, 103.820,  2e4,  1e5,    2, 0, 0, 1),
]
EXT = pd.DataFrame(_EXT, columns=["domain", "ip", "port", "proto", "org", "asn", "cc", "country", "city", "lat", "lon",
                                  "out", "in", "Finance", "Engineering", "IT", "Marketing"])
EXT["dir"], EXT["transport"] = "outbound", "tcp"

_INT = [
    ("dc01.corp.local",  "10.10.1.10", 389,  "ldap",     "tcp", 2e3, 6e3,   5, 5, 8, 5),
    ("dc01.corp.local",  "10.10.1.10", 88,   "kerberos", "tcp", 1e3, 2e3,   4, 4, 6, 4),
    ("fs01.corp.local",  "10.10.2.20", 445,  "smb",      "tcp", 2e4, 3e5,   6, 2, 5, 4),
    ("intranet.corp.local", "10.10.3.5", 443, "http",    "tcp", 2e3, 4e4,   3, 2, 3, 3),
    ("print01.corp.local", "10.10.3.40", 631, "ipp",     "tcp", 8e4, 1e3,   1, 0, 1, 1),
    ("jira.corp.local",  "10.10.3.15", 443,  "http",     "tcp", 5e3, 7e4,   1, 6, 4, 1),
    ("ci01.corp.local",  "10.10.5.30", 22,   "ssh",      "tcp", 2e4, 2e4,   0, 3, 2, 0),
    ("sccm.corp.local",  "10.10.1.30", 443,  "http",     "tcp", 1e3, 1e5,   1, 1, 3, 1),
]
INT = pd.DataFrame(_INT, columns=["domain", "ip", "port", "proto", "transport", "out", "in",
                                  "Finance", "Engineering", "IT", "Marketing"])
INT["dir"] = "internal"

BLOCKED = [("thepiratebay.org", "198.51.100.200", 443), ("crypto-miner-pool.cc", "198.51.100.201", 3333),
           ("free-vpn-proxy.net", "198.51.100.202", 1194)]

_SUBS = ["www", "api", "cdn", "static", "login", "img", "assets", "edge"]


def _now() -> pd.Timestamp:
    return pd.Timestamp.now(tz="UTC").floor("h") + pd.Timedelta(hours=1)


def registered_domain(name: str) -> str:
    # Mock approximation: last two labels. (Real data should use the public
    # suffix list - see the ECS docs note on co.uk.)
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def _work_times(rng, start: pd.Timestamp, days: int, per_day: float, offhours_share=0.04) -> pd.DatetimeIndex:
    """Business-hours-shaped timestamps in New York local time, returned in UTC."""
    out = []
    local0 = start.tz_convert(LOCAL_TZ).normalize()
    for d in range(days + 1):
        day = local0 + pd.Timedelta(days=d)
        weekend = day.dayofweek >= 5
        n = rng.poisson(per_day * (0.06 if weekend else 1.0))
        hours = np.clip(rng.normal(13.0, 2.6, n), 7.5, 19.5)
        lunch = rng.random(n) < 0.12
        hours[lunch] = rng.uniform(12.0, 13.0, lunch.sum())
        off = rng.random(n) < offhours_share
        hours[off] = rng.uniform(19.5, 23.5, off.sum())
        secs = hours * 3600 + rng.uniform(0, 60, n)
        out.append(day + pd.to_timedelta(np.sort(secs), unit="s"))
    ts = pd.DatetimeIndex(np.concatenate([o.tz_convert("UTC").values for o in out])).tz_localize("UTC") \
        if out else pd.DatetimeIndex([], tz="UTC")
    return ts


def _user_cols(u: User, n: int) -> dict:
    return {
        "user.name": [u.name] * n, "user.full_name": [u.full_name] * n,
        "user.email": [f"{u.name}@corp.example"] * n, "user.group.name": [u.group] * n,
        "user.domain": ["CORP"] * n,
        "host.name": [u.host] * n, "host.os.name": [u.os] * n,
        "source.ip": [u.ip] * n, "source.mac": [u.mac] * n,
        "source.geo.city_name": [OFFICE["city"]] * n, "source.geo.country_iso_code": ["US"] * n,
        "source.geo.location.lat": [OFFICE["lat"]] * n, "source.geo.location.lon": [OFFICE["lon"]] * n,
    }


def _flows(u: User, rng, ts: pd.DatetimeIndex, cat: pd.DataFrame) -> pd.DataFrame:
    n = len(ts)
    if n == 0:
        return pd.DataFrame()
    w = cat[u.group].to_numpy(float)
    idx = rng.choice(len(cat), size=n, p=w / w.sum())
    c = cat.iloc[idx].reset_index(drop=True)
    sb = np.round(c["out"].to_numpy() * rng.lognormal(0, 0.7, n)).astype("int64")
    db = np.round(c["in"].to_numpy() * rng.lognormal(0, 0.8, n)).astype("int64")
    dur = (rng.lognormal(1.2, 1.1, n) * 1e9).astype("int64")  # ns
    d = _user_cols(u, n)
    d.update({
        "@timestamp": ts, "event.dataset": "network_traffic.flow", "event.category": "network",
        "event.outcome": "success",
        "source.port": rng.integers(49152, 65535, n), "destination.ip": c["ip"].values,
        "destination.port": c["port"].values, "destination.domain": c["domain"].values,
        "destination.registered_domain": [registered_domain(x) if not x.endswith(".local") else None
                                          for x in c["domain"]],
        "network.protocol": c["proto"].values, "network.transport": c["transport"].values,
        "network.direction": c["dir"].values, "network.type": "ipv4",
        "source.bytes": sb, "destination.bytes": db,
        "source.packets": np.maximum(1, sb // 900), "destination.packets": np.maximum(1, db // 1200),
        "event.duration": dur,
    })
    if "org" in c:
        d.update({"destination.as.organization.name": c["org"].values, "destination.as.number": c["asn"].values,
                  "destination.geo.country_iso_code": c["cc"].values,
                  "destination.geo.country_name": c["country"].values,
                  "destination.geo.city_name": c["city"].values,
                  "destination.geo.location.lat": c["lat"].values, "destination.geo.location.lon": c["lon"].values})
    return pd.DataFrame(d)


def _dns_for(flows: pd.DataFrame, rng, frac=0.5) -> pd.DataFrame:
    """A DNS lookup shortly before a share of the external flows."""
    f = flows[flows["network.direction"] == "outbound"]
    f = f[rng.random(len(f)) < frac]
    n = len(f)
    if n == 0:
        return pd.DataFrame()
    names = []
    for dom in f["destination.domain"]:
        names.append(dom if dom.count(".") >= 2 or rng.random() < 0.5 else f"{rng.choice(_SUBS)}.{dom}")
    d = {k: f[k].values for k in ["user.name", "user.full_name", "user.email", "user.group.name", "user.domain",
                                   "host.name", "host.os.name", "source.ip", "source.mac", "source.geo.city_name",
                                   "source.geo.country_iso_code", "source.geo.location.lat", "source.geo.location.lon"]}
    d.update(_dns_cols(f["@timestamp"] - pd.to_timedelta(rng.uniform(0.05, 0.6, n), unit="s"),
                       names, ["NOERROR"] * n, ["A"] * n, rng))
    return pd.DataFrame(d)


def _dns_cols(ts, names, rcodes, qtypes, rng):
    n = len(names)
    return {
        "@timestamp": pd.DatetimeIndex(ts), "event.dataset": "network_traffic.dns", "event.category": "network",
        "event.outcome": "success", "source.port": rng.integers(49152, 65535, n),
        "destination.ip": DNS_SERVER, "destination.port": 53, "destination.domain": "dns01.corp.local",
        "network.protocol": "dns", "network.transport": "udp", "network.direction": "internal",
        "network.type": "ipv4", "source.bytes": rng.integers(60, 110, n), "destination.bytes": rng.integers(90, 400, n),
        "source.packets": 1, "destination.packets": 1, "event.duration": rng.integers(2_000_000, 40_000_000, n),
        "dns.question.name": list(names), "dns.question.registered_domain": [registered_domain(x) for x in names],
        "dns.question.subdomain": [".".join(x.split(".")[:-2]) or None for x in names],
        "dns.question.type": list(qtypes), "dns.response_code": list(rcodes), "dns.type": "answer",
    }


def _denied(u: User, rng, start, end, k) -> pd.DataFrame:
    ts = pd.DatetimeIndex(np.sort(rng.uniform(start.value, end.value, k)).astype("int64")).tz_localize("UTC")
    rows = [BLOCKED[i] for i in rng.integers(0, len(BLOCKED), k)]
    d = _user_cols(u, k)
    d.update({"@timestamp": ts, "event.dataset": "network_traffic.flow", "event.category": "network",
              "event.outcome": "failure", "event.action": "deny", "source.port": rng.integers(49152, 65535, k),
              "destination.ip": [r[1] for r in rows], "destination.port": [r[2] for r in rows],
              "destination.domain": [r[0] for r in rows],
              "destination.registered_domain": [registered_domain(r[0]) for r in rows],
              "network.protocol": "tls", "network.transport": "tcp", "network.direction": "outbound",
              "network.type": "ipv4", "source.bytes": rng.integers(60, 200, k), "destination.bytes": 0,
              "source.packets": 1, "destination.packets": 0, "event.duration": 0,
              "destination.as.organization.name": "Unknown / Blocklisted", "destination.geo.country_iso_code": "NL",
              "destination.geo.country_name": "Netherlands", "destination.geo.city_name": "Amsterdam",
              "destination.geo.location.lat": 52.37, "destination.geo.location.lon": 4.895})
    return pd.DataFrame(d)


def _vpn(u: User, rng, start: pd.Timestamp, now: pd.Timestamp) -> pd.DataFrame:
    """Remote-access sessions on ~45% of days (morning, from home)."""
    rows = []
    local0 = start.tz_convert(LOCAL_TZ).normalize()
    for d in range(DAYS + 1):
        day = local0 + pd.Timedelta(days=d)
        if rng.random() > 0.45:
            continue
        t = (day + pd.Timedelta(hours=float(rng.uniform(7.0, 9.5)))).tz_convert("UTC")
        if t > now:
            continue
        dur = pd.Timedelta(hours=float(rng.uniform(1.5, 8)))
        rows.append(dict(ts=t, ip=u.home_ip, city=u.home_city, cc=u.home_country, lat=u.home_lat, lon=u.home_lon,
                         dur=dur, isp="Verizon Business" if u.home_ip.startswith(("100", "108", "71", "74")) else
                         "Charter Communications"))
    return _vpn_df(u, rows, now)


def _vpn_df(u: User, rows, now) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame()
    n = len(rows)
    ts = pd.DatetimeIndex([r["ts"] for r in rows])
    ends = [r["ts"] + r["dur"] if r["ts"] + r["dur"] < now else None for r in rows]
    d = {"user.name": [u.name] * n, "user.full_name": [u.full_name] * n, "user.email": [f"{u.name}@corp.example"] * n,
         "user.group.name": [u.group] * n, "user.domain": ["CORP"] * n,
         "host.name": [u.host] * n, "host.os.name": [u.os] * n,
         "@timestamp": ts, "event.start": ts, "event.end": pd.DatetimeIndex(ends),
         "event.dataset": "vpn.session", "event.category": "session", "event.action": "vpn-login",
         "event.outcome": "success",
         "source.ip": [r["ip"] for r in rows], "source.port": [51820] * n,
         "source.geo.city_name": [r["city"] for r in rows], "source.geo.country_iso_code": [r["cc"] for r in rows],
         "source.geo.location.lat": [r["lat"] for r in rows], "source.geo.location.lon": [r["lon"] for r in rows],
         "source.as.organization.name": [r["isp"] for r in rows],
         "destination.ip": [VPN_GW] * n, "destination.port": [443] * n, "destination.domain": ["vpn.corp.example"] * n,
         "network.protocol": ["tls"] * n, "network.transport": ["udp"] * n, "network.direction": ["inbound"] * n,
         "network.type": ["ipv4"] * n,
         "source.bytes": [int(r["dur"].total_seconds() * 9e3) for r in rows],
         "destination.bytes": [int(r["dur"].total_seconds() * 4e4) for r in rows],
         "event.duration": [None if e is None else int(r["dur"].value) for r, e in zip(rows, ends)]}
    return pd.DataFrame(d)


def _open_now(u: User, rng, now, n=2) -> pd.DataFrame:
    """A couple of long-lived sessions that are still open (no event.end)."""
    ts = pd.DatetimeIndex([now - pd.Timedelta(minutes=float(m)) for m in rng.uniform(20, 140, n)])
    pick = EXT[EXT["domain"].isin(["teams.microsoft.com", "zoom.us", "slack.com"])].sample(n, random_state=int(rng.integers(1e6)))
    f = _flows(u, rng, ts, pick.assign(**{u.group: 1.0}))
    f["event.duration"] = None
    f["event.end"] = pd.NaT
    f["event.start"] = f["@timestamp"]
    f["session.state"] = "open"
    return f


# ---------------------------------------------------------------------------
# Planted stories
# ---------------------------------------------------------------------------
def _story_jdoe(u: User, rng, now) -> list[pd.DataFrame]:
    out = []
    # 1. Exfiltration: ~4.7 GB to a never-seen domain, 02:05-03:40 New York time, yesterday.
    night = (now.tz_convert(LOCAL_TZ).normalize() - pd.Timedelta(days=1) + pd.Timedelta(hours=2, minutes=5)).tz_convert("UTC")
    k = 42
    ts = night + pd.to_timedelta(np.sort(rng.uniform(0, 95 * 60, k)), unit="s")
    exf = pd.DataFrame([dict(domain="sync.files-vault.top", ip="203.0.113.47", port=443, proto="tls",
                             org="Nordvale Hosting Ltd", asn=64512, cc="RO", country="Romania", city="Bucharest",
                             lat=44.4268, lon=26.1025, out=1.1e8, **{"in": 4e4}, dir="outbound", transport="tcp",
                             **{u.group: 1.0})])
    f = _flows(u, rng, ts, exf)
    f["event.duration"] = (rng.uniform(60, 240, k) * 1e9).astype("int64")
    out.append(f)
    out.append(pd.DataFrame(_user_cols(u, 3) | _dns_cols(ts[:3] - pd.Timedelta(seconds=1),
                                                          ["sync.files-vault.top"] * 3, ["NOERROR"] * 3, ["A"] * 3, rng)))
    # Staging: big pulls from the finance share right before (download from fs01).
    stg = INT[INT["domain"] == "fs01.corp.local"].assign(**{u.group: 1.0, "in": 9e7})
    out.append(_flows(u, rng, night - pd.to_timedelta(np.sort(rng.uniform(5, 50, 18)), unit="min"), stg))
    # 2. Impossible travel: VPN login from Jersey City, then Bucharest 47 minutes later.
    t1 = (now.tz_convert(LOCAL_TZ).normalize() - pd.Timedelta(days=1) + pd.Timedelta(hours=8, minutes=5)).tz_convert("UTC")
    rows = [dict(ts=t1, ip=u.home_ip, city=u.home_city, cc="US", lat=u.home_lat, lon=u.home_lon,
                 dur=pd.Timedelta(hours=6), isp="Verizon Business"),
            dict(ts=t1 + pd.Timedelta(minutes=47), ip="198.51.100.77", city="Bucharest", cc="RO", lat=44.4268,
                 lon=26.1025, dur=pd.Timedelta(minutes=38), isp="Nordvale Hosting Ltd")]
    out.append(_vpn_df(u, rows, now))
    return out


def _b32(rng, n):
    alpha = np.array(list(string.ascii_lowercase + "234567"))
    return "".join(rng.choice(alpha, n))


def _story_asmith(u: User, rng, now) -> list[pd.DataFrame]:
    out = []
    start = now - pd.Timedelta(days=3, hours=7)
    # 1. Beacon: every 180s +/- 4s, around the clock, tiny symmetric payloads.
    gaps = rng.normal(180, 4, 1700)
    ts = start + pd.to_timedelta(np.cumsum(gaps), unit="s")
    ts = ts[ts < now]
    c2 = pd.DataFrame([dict(domain="cdn-telemetry-update.xyz", ip="203.0.113.66", port=8443, proto="tls",
                            org="Kestrel Bulletproof VPS", asn=64513, cc="SC", country="Seychelles", city="Victoria",
                            lat=-4.6191, lon=55.4513, out=320, **{"in": 1100}, dir="outbound", transport="tcp",
                            **{u.group: 1.0})])
    f = _flows(u, rng, ts, c2)
    f["source.bytes"] = rng.integers(290, 360, len(f))
    f["destination.bytes"] = rng.integers(1000, 1250, len(f))
    f["event.duration"] = rng.integers(200_000_000, 900_000_000, len(f))
    out.append(f)
    # 2. DGA bursts: random-looking domains that mostly don't exist.
    names, tss, rc = [], [], []
    for b in range(9):
        t0 = start + pd.Timedelta(hours=float(rng.uniform(2, 75)))
        for _ in range(int(rng.integers(18, 32))):
            names.append(_b32(rng, int(rng.integers(11, 17))).replace("2", "x") + str(rng.choice([".info", ".biz", ".top", ".xyz"])))
            tss.append(t0 + pd.Timedelta(seconds=float(rng.uniform(0, 90))))
            rc.append("NXDOMAIN" if rng.random() < 0.94 else "NOERROR")
    out.append(pd.DataFrame(_user_cols(u, len(names)) | _dns_cols(sorted(tss), names, rc, ["A"] * len(names), rng)))
    # 3. DNS tunnelling: long base32 labels under one domain, TXT queries.
    k = 640
    t_tun = now - pd.Timedelta(hours=30) + pd.to_timedelta(np.sort(rng.uniform(0, 5 * 3600, k)), unit="s")
    names = [f"{_b32(rng, int(rng.integers(38, 58)))}.{i % 97}.t.dnsx-relay.net" for i in range(k)]
    out.append(pd.DataFrame(_user_cols(u, k) | _dns_cols(t_tun, names, ["NOERROR"] * k, ["TXT"] * k, rng)))
    return out


def _story_bwayne(u: User, rng, now) -> list[pd.DataFrame]:
    out = []
    t0 = (now.tz_convert(LOCAL_TZ).normalize() - pd.Timedelta(days=2) + pd.Timedelta(hours=10, minutes=20)).tz_convert("UTC")
    ports = [22, 135, 139, 445, 3389, 5985, 1433, 3306, 80, 443, 8080, 5900]
    proto = {22: "ssh", 135: "dcerpc", 139: "netbios", 445: "smb", 3389: "rdp", 5985: "winrm", 1433: "tds",
             3306: "mysql", 80: "http", 443: "tls", 8080: "http", 5900: "vnc"}
    tgts = [f"10.10.20.{i}" for i in range(1, 255)]
    live = {"10.10.20.31", "10.10.20.45", "10.10.20.12", "10.10.20.88", "10.10.20.140", "10.10.20.201"}
    rows = [(ip, p) for ip in tgts for p in ports]
    rng.shuffle(rows)
    k = len(rows)
    ts = t0 + pd.to_timedelta(np.sort(rng.uniform(0, 17 * 60, k)), unit="s")
    d = _user_cols(u, k)
    ok = [ip in live and p in (445, 3389, 5985, 22, 135) for ip, p in rows]
    d.update({"@timestamp": ts, "event.dataset": "network_traffic.flow", "event.category": "network",
              "event.outcome": ["success" if o else "failure" for o in ok],
              "source.port": rng.integers(49152, 65535, k),
              "destination.ip": [r[0] for r in rows], "destination.port": [r[1] for r in rows],
              "destination.domain": None, "destination.registered_domain": None,
              "network.protocol": [proto[r[1]] for r in rows], "network.transport": "tcp",
              "network.direction": "internal", "network.type": "ipv4",
              "source.bytes": rng.integers(54, 74, k), "destination.bytes": [int(rng.integers(40, 120)) if o else 0 for o in ok],
              "source.packets": 1, "destination.packets": [1 if o else 0 for o in ok],
              "event.duration": rng.integers(100_000, 3_000_000, k)})
    out.append(pd.DataFrame(d))
    # Lateral movement: SMB pulls + WinRM + RDP into the live hosts after the scan.
    lat_rows = []
    t = t0 + pd.Timedelta(minutes=25)
    for ip in sorted(live):
        for p, bi, bo, dur in [(445, 4e6, 6e8, 900), (5985, 6e4, 2e5, 120), (3389, 3e6, 4e7, 2400)]:
            lat_rows.append((t, ip, p, bo, bi, dur))
            t += pd.Timedelta(minutes=float(rng.uniform(3, 9)))
    n = len(lat_rows)
    d = _user_cols(u, n)
    d.update({"@timestamp": pd.DatetimeIndex([r[0] for r in lat_rows]), "event.dataset": "network_traffic.flow",
              "event.category": "network", "event.outcome": "success", "source.port": rng.integers(49152, 65535, n),
              "destination.ip": [r[1] for r in lat_rows], "destination.port": [r[2] for r in lat_rows],
              "destination.domain": None, "destination.registered_domain": None,
              "network.protocol": [proto[r[2]] for r in lat_rows], "network.transport": "tcp",
              "network.direction": "internal", "network.type": "ipv4",
              "source.bytes": [int(r[4]) for r in lat_rows], "destination.bytes": [int(r[3]) for r in lat_rows],
              "source.packets": 100, "destination.packets": 1000,
              "event.duration": [int(r[5] * 1e9) for r in lat_rows]})
    out.append(pd.DataFrame(d))
    # An RDP session to the domain controller that is still open right now.
    d = _user_cols(u, 1)
    d.update({"@timestamp": pd.DatetimeIndex([now - pd.Timedelta(hours=3, minutes=12)]),
              "event.start": pd.DatetimeIndex([now - pd.Timedelta(hours=3, minutes=12)]), "event.end": pd.NaT,
              "session.state": "open",
              "event.dataset": "network_traffic.flow", "event.category": "network", "event.outcome": "success",
              "source.port": 50111, "destination.ip": "10.10.1.10", "destination.port": 3389,
              "destination.domain": "dc01.corp.local", "network.protocol": "rdp", "network.transport": "tcp",
              "network.direction": "internal", "network.type": "ipv4", "source.bytes": 9_400_000,
              "destination.bytes": 88_000_000, "event.duration": None})
    out.append(pd.DataFrame(d))
    return out


STORIES = {"jdoe": _story_jdoe, "asmith": _story_asmith, "bwayne": _story_bwayne}
PER_DAY = {"Finance": 230, "Engineering": 330, "IT": 260, "Marketing": 210}


def build_events(seed: int = 7) -> pd.DataFrame:
    """The whole mock 'index' as one flat DataFrame."""
    now = _now()
    start = now - pd.Timedelta(days=DAYS)
    frames = []
    for i, u in enumerate(ALL_USERS):
        rng = np.random.default_rng(seed * 1000 + i)
        ts = _work_times(rng, start, DAYS, PER_DAY[u.group] * u.activity)
        ts = ts[(ts >= start) & (ts < now)]
        is_int = rng.random(len(ts)) < 0.35
        ext = _flows(u, rng, ts[~is_int], EXT)
        itn = _flows(u, rng, ts[is_int], INT)
        frames += [ext, itn, _dns_for(ext, rng)]
        # Ambient NXDOMAIN noise (typos, stale bookmarks)
        k = int(rng.integers(3, 12))
        tt = pd.DatetimeIndex(np.sort(rng.choice(ts.asi8, k))).tz_localize("UTC") if len(ts) else ts
        frames.append(pd.DataFrame(_user_cols(u, k) | _dns_cols(tt, [f"{rng.choice(_SUBS)}.intranet-old.corp.local"] * k,
                                                               ["NXDOMAIN"] * k, ["A"] * k, rng)))
        frames.append(_denied(u, rng, start, now, int(rng.integers(2, 9))))
        frames.append(_vpn(u, rng, start, now))
        if rng.random() < 0.7:
            frames.append(_open_now(u, rng, now, n=int(rng.integers(1, 3))))
        if u.name in STORIES:
            frames += STORIES[u.name](u, rng, now)
    df = pd.concat([f for f in frames if len(f)], ignore_index=True)
    df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True)
    for c in ("event.start", "event.end"):
        df[c] = pd.to_datetime(df[c], utc=True)
    # Closed flows get event.end = start + duration
    m = df["event.end"].isna() & df["event.duration"].notna() & df.get("session.state", pd.Series(index=df.index)).isna()
    df.loc[m, "event.end"] = df.loc[m, "@timestamp"] + pd.to_timedelta(df.loc[m, "event.duration"].astype("int64"), unit="ns")
    df["event.start"] = df["event.start"].fillna(df["@timestamp"])
    df["network.community_id"] = None
    df = df.sort_values("@timestamp", ignore_index=True)
    df.attrs["now"] = now
    return df


if __name__ == "__main__":
    import time
    t = time.time()
    e = build_events()
    print(f"{len(e):,} events in {time.time() - t:.1f}s; cols={len(e.columns)}")
    print(e.groupby("user.name").size().sort_values())
    print(e["event.dataset"].value_counts())
