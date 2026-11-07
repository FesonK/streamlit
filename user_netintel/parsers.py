"""
parsers.py - Elasticsearch response dicts -> tidy pandas DataFrames.

These functions only know the *shape* of an ES response, never whether it
came from the mock engine or a real cluster.
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np
import pandas as pd


def _ts(ms) -> pd.Timestamp | None:
    return None if ms is None else pd.Timestamp(int(ms), unit="ms", tz="UTC")


def _v(agg: dict, default=0.0):
    if not agg:
        return default
    v = agg.get("value")
    return default if v is None else v


def _top_key(agg: dict, default=None):
    b = (agg or {}).get("buckets") or []
    return b[0]["key"] if b else default


def hits_df(resp: dict) -> pd.DataFrame:
    rows = [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
    df = pd.json_normalize(rows) if rows else pd.DataFrame()
    for c in ("@timestamp", "event.start", "event.end"):
        if c in df:
            df[c] = pd.to_datetime(df[c], utc=True, format="ISO8601")
    return df


# --------------------------------------------------------------- search box
def parse_user_search(resp: dict) -> pd.DataFrame:
    rows = [{"user": b["key"], "events": b["doc_count"], "dept": _top_key(b["dept"], "-"),
             "full_name": _top_key(b["full_name"], ""), "last_seen": _ts(_v(b["last_seen"], None))}
            for b in resp["aggregations"]["users"]["buckets"]]
    return pd.DataFrame(rows)


# ----------------------------------------------------------------- identity
def parse_identity(resp: dict) -> dict:
    a = resp["aggregations"]
    latest = (a["latest"]["hits"]["hits"] or [{"_source": {}}])[0]["_source"]
    u, h = latest.get("user", {}), latest.get("host", {})
    return {
        "name": u.get("name"), "full_name": u.get("full_name"), "email": u.get("email"),
        "department": (u.get("group") or {}).get("name"), "domain": u.get("domain"),
        "hosts": [{"host": b["key"], "os": _top_key(b["os"], ""), "events": b["doc_count"],
                   "last_seen": _ts(_v(b["last_seen"], None))} for b in a["hosts"]["buckets"]],
        "ips": [{"ip": b["key"], "mac": _top_key(b["mac"], ""), "events": b["doc_count"]}
                for b in a["internal_ips"]["ip"]["buckets"]],
        "remote_ips": [{"ip": b["key"], "city": _top_key(b["city"], ""), "cc": _top_key(b["cc"], ""),
                        "logins": b["doc_count"]} for b in a["remote_ips"]["ip"]["buckets"]],
        "first_seen": _ts(_v(a["first_seen"], None)), "last_seen": _ts(_v(a["last_seen"], None)),
        "datasets": {b["key"]: b["doc_count"] for b in a["datasets"]["buckets"]},
        "total_events": resp["hits"]["total"]["value"],
    }


# --------------------------------------------------------------------- KPIs
def parse_kpis(resp: dict) -> dict:
    a = resp["aggregations"]
    sessions = int(_v(a["sessions"]))
    pct = a["duration"]["values"]
    daily = pd.DataFrame([{"day": _ts(b["key"]), "sessions": b["doc_count"], "bytes_out": _v(b["bytes_out"]),
                           "uniq_dest_ip": _v(b["uniq_dest_ip"]), "denied": b["denied"]["doc_count"]}
                          for b in a["daily"]["buckets"]])
    return {
        "sessions": sessions, "bytes_out": _v(a["bytes_out"]), "bytes_in": _v(a["bytes_in"]),
        "uniq_dest_ip": int(_v(a["uniq_dest_ip"])), "uniq_dest_port": int(_v(a["uniq_dest_port"])),
        "uniq_domains": int(_v(a["uniq_domains"])), "denied": a["denied"]["doc_count"],
        "denied_pct": 100 * a["denied"]["doc_count"] / sessions if sessions else 0.0,
        "ext_bytes_out": _v(a["external"]["bytes_out"]), "open_sessions": a["open_sessions"]["doc_count"],
        "p50_duration_s": (pct.get("50.0") or 0) / 1e9, "p99_duration_s": (pct.get("99.0") or 0) / 1e9,
        "daily": daily,
    }


# ----------------------------------------------------------------- timeline
def parse_timeline(resp: dict) -> pd.DataFrame:
    rows = [{"time": _ts(b["key"]), "sessions": b["doc_count"], "bytes_out": _v(b["bytes_out"]),
             "bytes_in": _v(b["bytes_in"]), "denied": b["denied"]["doc_count"],
             "uniq_dest_ip": _v(b["uniq_dest_ip"])} for b in resp["aggregations"]["over_time"]["buckets"]]
    return pd.DataFrame(rows)


def hour_weekday_matrix(timeline: pd.DataFrame, tz: str, value: str = "sessions") -> pd.DataFrame:
    """7x24 matrix (weekday x local hour), averaged over the window."""
    if timeline.empty:
        return pd.DataFrame(0, index=range(7), columns=range(24))
    t = timeline.assign(local=timeline["time"].dt.tz_convert(tz))
    t["dow"], t["hour"] = t["local"].dt.dayofweek, t["local"].dt.hour
    m = t.pivot_table(index="dow", columns="hour", values=value, aggfunc="sum", fill_value=0)
    return m.reindex(index=range(7), columns=range(24), fill_value=0)


def is_off_hours(local: pd.Series) -> pd.Series:
    return (local.dt.hour < 7) | (local.dt.hour >= 20) | (local.dt.dayofweek >= 5)


# ------------------------------------------------------------- destinations
def parse_destinations(resp: dict) -> pd.DataFrame:
    rows = []
    for b in resp["aggregations"]["dest"]["buckets"]:
        src = (b["info"]["hits"]["hits"] or [{"_source": {}}])[0]["_source"]
        d, net = src.get("destination", {}), src.get("network", {})
        geo, asn = d.get("geo", {}), d.get("as", {})
        out, inn = _v(b["bytes_out"]), _v(b["bytes_in"])
        rows.append({
            "ip": b["key"], "domain": d.get("domain") or "", "registered_domain": d.get("registered_domain"),
            "org": (asn.get("organization") or {}).get("name") or ("Corporate network" if net.get("direction") == "internal" else "Unknown"),
            "asn": asn.get("number"), "country": geo.get("country_iso_code") or "", "country_name": geo.get("country_name") or "",
            "city": geo.get("city_name") or "", "protocol": net.get("protocol"), "direction": net.get("direction"),
            "sessions": b["doc_count"], "bytes_out": out, "bytes_in": inn,
            "ratio": out / max(inn, 1.0), "ports": ", ".join(str(p["key"]) for p in b["ports"]["buckets"]),
            "denied": b["denied"]["doc_count"],
            "first_seen": _ts(_v(b["first_seen"], None)), "last_seen": _ts(_v(b["last_seen"], None)),
        })
    return pd.DataFrame(rows)


def parse_first_seen(resp: dict) -> pd.DataFrame:
    return pd.DataFrame([{"registered_domain": b["key"], "first_seen_ever": _ts(_v(b["first_seen"], None)),
                          "bytes_out_lookback": _v(b["bytes_out"])} for b in resp["aggregations"]["domains"]["buckets"]])


def parse_flow(resp: dict) -> pd.DataFrame:
    rows = []
    for h in resp["aggregations"]["host"]["buckets"]:
        for p in h["proto"]["buckets"]:
            for o in p["org"]["buckets"]:
                rows.append({"host": h["key"], "protocol": p["key"], "org": o["key"],
                             "bytes_out": _v(o["bytes"]), "bytes_in": _v(o["bytes_in"]), "sessions": o["doc_count"]})
    return pd.DataFrame(rows)


def parse_geo(resp: dict) -> pd.DataFrame:
    rows = []
    for b in resp["aggregations"]["country"]["buckets"]:
        loc = b["centroid"].get("location") or {}
        rows.append({"country": b["key"], "country_name": _top_key(b["name"], b["key"]),
                     "lat": loc.get("lat"), "lon": loc.get("lon"), "sessions": b["doc_count"],
                     "bytes_out": _v(b["bytes_out"]), "bytes_in": _v(b["bytes_in"]), "uniq_ip": _v(b["uniq_ip"]),
                     "orgs": ", ".join(o["key"] for o in b["orgs"]["buckets"])})
    return pd.DataFrame(rows)


# --------------------------------------------------------------------- DNS
def parse_dns_overview(resp: dict) -> dict:
    a = resp["aggregations"]
    top = pd.DataFrame([{"domain": b["key"], "queries": b["doc_count"], "uniq_names": _v(b["uniq_names"]),
                         "nxdomain": b["nxdomain"]["doc_count"], "qtype": _top_key(b["qtype"], "")}
                        for b in a["top_domains"]["buckets"]])
    over = pd.DataFrame([{"time": _ts(b["key"]), "queries": b["doc_count"], "nxdomain": b["nxdomain"]["doc_count"]}
                         for b in a["over_time"]["buckets"]])
    rcode = {b["key"]: b["doc_count"] for b in a["rcode"]["buckets"]}
    total = resp["hits"]["total"]["value"]
    return {"total": total, "top": top, "over_time": over, "rcode": rcode,
            "qtype": {b["key"]: b["doc_count"] for b in a["qtype"]["buckets"]},
            "uniq_names": int(_v(a["uniq_names"])), "uniq_domains": int(_v(a["uniq_domains"])),
            "nx_rate": 100 * rcode.get("NXDOMAIN", 0) / total if total else 0.0}


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def parse_dns_names(resp: dict) -> pd.DataFrame:
    rows = []
    for b in resp["aggregations"]["names"]["buckets"]:
        name = b["key"]
        labels = name.split(".")
        reg = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        # score the most "random" part: the subdomain if present, else the domain label itself
        probe = max(labels[:-1], key=len) if len(labels) > 1 else name
        rows.append({"name": name, "registered_domain": reg, "subdomain": sub, "queries": b["doc_count"],
                     "rcode": _top_key(b["rcode"], ""), "qtype": _top_key(b["qtype"], ""),
                     "first_seen": _ts(_v(b["first_seen"], None)),
                     "length": len(name), "max_label": max(len(l) for l in labels),
                     "entropy": round(shannon(probe), 3),
                     "digit_ratio": sum(ch.isdigit() for ch in probe) / max(len(probe), 1)})
    return pd.DataFrame(rows)


# --------------------------------------------------------------- detectors
def parse_beacons(resp: dict) -> tuple[pd.DataFrame, dict[str, np.ndarray]]:
    """Per dest:port pair: interval regularity. Returns (stats, {pair: bucket times})."""
    rows, series = [], {}
    for b in resp["aggregations"]["pairs"]["buckets"]:
        ip, port = b["key"]
        t = np.array([x["key"] for x in b["per_minute"]["buckets"]], dtype="int64") // 1000  # seconds
        if len(t) < 10:
            continue
        gaps = np.diff(t).astype(float)
        mean = gaps.mean()
        cv = gaps.std() / mean if mean else math.inf
        span_h = (t[-1] - t[0]) / 3600
        hours_active = len(np.unique(t // 3600))
        key = f"{ip}:{port}"
        series[key] = t
        st = b["bytes_out"]
        rows.append({"pair": key, "ip": ip, "port": port, "domain": _top_key(b["domain"], ""),
                     "org": _top_key(b["org"], ""), "connections": b["doc_count"], "active_minutes": len(t),
                     "median_gap_s": float(np.median(gaps)), "cv": round(float(cv), 3),
                     "span_h": round(span_h, 1), "coverage": hours_active / max(span_h, 1.0),
                     "avg_bytes_out": st.get("avg") or 0, "bytes_out_spread": (st.get("max") or 0) - (st.get("min") or 0)})
    df = pd.DataFrame(rows)
    if not df.empty:
        # 0..1: regular gaps, long span, active across the clock
        df["beacon_score"] = (np.clip(1 - df["cv"], 0, 1) * 0.6
                              + np.clip(df["coverage"], 0, 1) * 0.25
                              + np.clip(df["span_h"] / 24, 0, 1) * 0.15).round(3)
        df = df.sort_values("beacon_score", ascending=False, ignore_index=True)
    return df, series


def parse_fanout(resp: dict) -> pd.DataFrame:
    return pd.DataFrame([{"time": _ts(b["key"]), "connections": b["doc_count"], "uniq_ip": _v(b["uniq_ip"]),
                          "uniq_port": _v(b["uniq_port"]), "failed": b["failed"]["doc_count"]}
                         for b in resp["aggregations"]["over_time"]["buckets"]])


def parse_scan_matrix(resp: dict) -> pd.DataFrame:
    rows = []
    for t in resp["aggregations"]["target"]["buckets"]:
        for p in t["port"]["buckets"]:
            rows.append({"ip": t["key"], "port": p["key"], "attempts": p["doc_count"],
                         "ok": p["ok"]["doc_count"], "bytes_in": _v(p["bytes_in"])})
    return pd.DataFrame(rows)


def parse_admin(resp: dict) -> pd.DataFrame:
    return pd.DataFrame([{"ip": b["key"], "sessions": b["doc_count"],
                          "protocols": ", ".join(p["key"] for p in b["protocols"]["buckets"]),
                          "bytes_in": _v(b["bytes_in"]), "first_seen": _ts(_v(b["first_seen"], None))}
                         for b in resp["aggregations"]["target"]["buckets"]])


def parse_peers(resp: dict) -> pd.DataFrame:
    rows = []
    for b in resp["aggregations"]["users"]["buckets"]:
        h = pd.DataFrame([{"t": pd.Timestamp(x["key_as_string"]), "n": x["doc_count"], "bytes": _v(x["bytes_out"])}
                          for x in b["hourly"]["buckets"]])
        if h.empty:
            off_s = off_b = 0.0
        else:
            hr = h["t"].map(lambda t: t.hour)
            dow = h["t"].map(lambda t: t.dayofweek)
            off = (hr < 7) | (hr >= 20) | (dow >= 5)
            off_s = 100 * h.loc[off, "n"].sum() / max(h["n"].sum(), 1)
            off_b = 100 * h.loc[off, "bytes"].sum() / max(h["bytes"].sum(), 1)
        rows.append({"user": b["key"], "sessions": b["doc_count"],
                     "ext_bytes_out": _v(b["bytes_out_ext"]["v"]), "uniq_dest_ip": _v(b["uniq_dest_ip"]),
                     "uniq_dest_port": _v(b["uniq_dest_port"]), "uniq_domains": _v(b["uniq_domains"]),
                     "denied": b["denied"]["doc_count"], "offhours_sessions_pct": off_s, "offhours_bytes_pct": off_b})
    return pd.DataFrame(rows)


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
