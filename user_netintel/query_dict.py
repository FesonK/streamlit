"""
query_dict.py - every Elasticsearch request the User Network Intelligence page makes.

Each function returns a plain dict (the request body). Nothing here talks to
Elasticsearch; data_source.search(index, body) does that (mock or real).

Conventions
-----------
* `user`   -> value of ECS `user.name`
* `start` / `end` -> ISO-8601 strings (UTC) or ES date math ("now-7d")
* Every query is `size: 0` + aggs unless it needs raw documents (hits).
* Field names are ECS: source.*, destination.*, network.*, dns.*, event.*, host.*, user.*
"""
from __future__ import annotations

INDEX = "logs-network_traffic.*,logs-vpn.*"

# Datasets (event.dataset)
FLOW = "network_traffic.flow"
DNS = "network_traffic.dns"
VPN = "vpn.session"

ADMIN_PORTS = [22, 135, 445, 3389, 5985, 5986]


# --------------------------------------------------------------------- helpers
def _base(user: str, start: str, end: str, *extra: dict) -> dict:
    """bool filter: this user, this time window, plus any extra clauses."""
    return {"bool": {"filter": [
        {"term": {"user.name": user}},
        {"range": {"@timestamp": {"gte": start, "lt": end}}},
        *extra,
    ]}}


def _dataset(name: str) -> dict:
    return {"term": {"event.dataset": name}}


# ------------------------------------------------------------------ 0. search
def user_search_query(text: str, size: int = 200) -> dict:
    """Autocomplete for the search box: users whose name contains `text`,
    with their department and the last time we saw them."""
    pattern = f".*{text.lower()}.*" if text else ".*"
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
        "aggs": {
            "users": {
                "terms": {"field": "user.name", "size": size, "include": pattern, "order": {"_key": "asc"}},
                "aggs": {
                    "dept": {"terms": {"field": "user.group.name", "size": 1}},
                    "full_name": {"terms": {"field": "user.full_name", "size": 1}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                },
            }
        },
    }


# ---------------------------------------------------------------- 1. identity
def user_identity_query(user: str, start: str, end: str) -> dict:
    """Who is this user and which devices/addresses do they use?"""
    return {
        "size": 0,
        "query": _base(user, start, end),
        "aggs": {
            "latest": {"top_hits": {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": {"includes": ["user.*", "host.*"]}}},
            "hosts": {"terms": {"field": "host.name", "size": 10},
                      "aggs": {"os": {"terms": {"field": "host.os.name", "size": 1}},
                               "last_seen": {"max": {"field": "@timestamp"}}}},
            "internal_ips": {"filter": {"term": {"event.dataset": FLOW}}, "aggs": {
                "ip": {"terms": {"field": "source.ip", "size": 10},
                       "aggs": {"mac": {"terms": {"field": "source.mac", "size": 3}}}}}},
            "remote_ips": {"filter": {"term": {"event.dataset": VPN}}, "aggs": {
                "ip": {"terms": {"field": "source.ip", "size": 10},
                       "aggs": {"city": {"terms": {"field": "source.geo.city_name", "size": 1}},
                                "cc": {"terms": {"field": "source.geo.country_iso_code", "size": 1}}}}}},
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen": {"max": {"field": "@timestamp"}},
            "datasets": {"terms": {"field": "event.dataset", "size": 10}},
        },
    }


# ---------------------------------------------------------------- 2. KPIs
def user_kpi_query(user: str, start: str, end: str) -> dict:
    """Headline numbers. Run it twice (this window + the previous one) for deltas."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW)),
        "aggs": {
            "sessions": {"value_count": {"field": "@timestamp"}},
            "bytes_out": {"sum": {"field": "source.bytes"}},
            "bytes_in": {"sum": {"field": "destination.bytes"}},
            "uniq_dest_ip": {"cardinality": {"field": "destination.ip"}},
            "uniq_dest_port": {"cardinality": {"field": "destination.port"}},
            "uniq_domains": {"cardinality": {"field": "destination.registered_domain"}},
            "denied": {"filter": {"term": {"event.outcome": "failure"}}},
            "external": {"filter": {"term": {"network.direction": "outbound"}},
                         "aggs": {"bytes_out": {"sum": {"field": "source.bytes"}}}},
            "open_sessions": {"filter": {"bool": {"must_not": [{"exists": {"field": "event.end"}}]}}},
            "duration": {"percentiles": {"field": "event.duration", "percents": [50, 95, 99]}},
            "daily": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1d",
                                         "extended_bounds": {"min": start, "max": end}, "min_doc_count": 0},
                      "aggs": {"bytes_out": {"sum": {"field": "source.bytes"}},
                               "uniq_dest_ip": {"cardinality": {"field": "destination.ip"}},
                               "denied": {"filter": {"term": {"event.outcome": "failure"}}}}},
        },
    }


# ---------------------------------------------------------------- 3. timeline
def activity_timeline_query(user: str, start: str, end: str, interval: str = "1h") -> dict:
    """Traffic over time: bytes up/down, connection count, denied, fan-out."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW)),
        "aggs": {
            "over_time": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0,
                                   "extended_bounds": {"min": start, "max": end}},
                "aggs": {
                    "bytes_out": {"sum": {"field": "source.bytes"}},
                    "bytes_in": {"sum": {"field": "destination.bytes"}},
                    "denied": {"filter": {"term": {"event.outcome": "failure"}}},
                    "uniq_dest_ip": {"cardinality": {"field": "destination.ip"}},
                }
            }
        },
    }


# ------------------------------------------------------------ 4. destinations
def top_destinations_query(user: str, start: str, end: str, size: int = 40) -> dict:
    """Who does the user talk to? Ranked by bytes *sent* (exfil lens)."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW)),
        "aggs": {
            "dest": {
                "terms": {"field": "destination.ip", "size": size, "order": {"bytes_out": "desc"}},
                "aggs": {
                    "bytes_out": {"sum": {"field": "source.bytes"}},
                    "bytes_in": {"sum": {"field": "destination.bytes"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "ports": {"terms": {"field": "destination.port", "size": 5}},
                    "denied": {"filter": {"term": {"event.outcome": "failure"}}},
                    "info": {"top_hits": {"size": 1, "_source": {"includes": [
                        "destination.domain", "destination.registered_domain", "destination.as.*",
                        "destination.geo.*", "network.protocol", "network.direction"]}}},
                },
            }
        },
    }


def destination_first_seen_query(user: str, lookback_start: str, end: str) -> dict:
    """When did this user FIRST contact each domain, over a longer lookback?
    Anything whose first contact falls inside the analysis window is 'new'."""
    return {
        "size": 0,
        "query": _base(user, lookback_start, end, _dataset(FLOW),
                       {"exists": {"field": "destination.registered_domain"}}),
        "aggs": {
            "domains": {"terms": {"field": "destination.registered_domain", "size": 500},
                        "aggs": {"first_seen": {"min": {"field": "@timestamp"}},
                                 "bytes_out": {"sum": {"field": "source.bytes"}}}}
        },
    }


def traffic_flow_query(user: str, start: str, end: str) -> dict:
    """host -> protocol -> destination org, weighted by bytes (feeds the Sankey)."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW)),
        "aggs": {
            "host": {"terms": {"field": "host.name", "size": 5}, "aggs": {
                "proto": {"terms": {"field": "network.protocol", "size": 12}, "aggs": {
                    "org": {"terms": {"field": "destination.as.organization.name", "size": 8,
                                      "missing": "Corporate network", "order": {"bytes": "desc"}},
                            "aggs": {"bytes": {"sum": {"field": "source.bytes"}},
                                     "bytes_in": {"sum": {"field": "destination.bytes"}}}}}}}},
        },
    }


# --------------------------------------------------------------------- 5. geo
def geo_destinations_query(user: str, start: str, end: str) -> dict:
    """Where in the world does the user's traffic go?"""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW), {"term": {"network.direction": "outbound"}}),
        "aggs": {
            "country": {
                "terms": {"field": "destination.geo.country_iso_code", "size": 60},
                "aggs": {
                    "centroid": {"geo_centroid": {"field": "destination.geo.location"}},
                    "bytes_out": {"sum": {"field": "source.bytes"}},
                    "bytes_in": {"sum": {"field": "destination.bytes"}},
                    "uniq_ip": {"cardinality": {"field": "destination.ip"}},
                    "name": {"terms": {"field": "destination.geo.country_name", "size": 1}},
                    "orgs": {"terms": {"field": "destination.as.organization.name", "size": 3}},
                },
            }
        },
    }


def vpn_sessions_query(user: str, start: str, end: str) -> dict:
    """Remote-access logins in time order -> impossible-travel analysis."""
    return {
        "size": 500,
        "query": _base(user, start, end, _dataset(VPN)),
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": {"includes": ["@timestamp", "event.start", "event.end", "event.duration", "source.ip",
                                 "source.geo.*", "source.as.organization.name", "host.name"]},
    }


def open_sessions_query(user: str, start: str, end: str) -> dict:
    """Sessions that have started but not ended (no event.end) - i.e. open right now."""
    return {
        "size": 50,
        "query": _base(user, start, end, {"bool": {"must_not": [{"exists": {"field": "event.end"}}]}}),
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": {"includes": ["@timestamp", "event.dataset", "source.ip", "destination.ip",
                                 "destination.port", "destination.domain", "network.protocol",
                                 "source.bytes", "destination.bytes", "source.geo.city_name"]},
    }


def long_sessions_query(user: str, start: str, end: str, size: int = 15) -> dict:
    """Longest completed connections (event.duration is nanoseconds in ECS)."""
    return {
        "size": size,
        "query": _base(user, start, end, _dataset(FLOW), {"exists": {"field": "event.duration"}}),
        "sort": [{"event.duration": {"order": "desc"}}],
        "_source": {"includes": ["@timestamp", "event.duration", "destination.ip", "destination.port",
                                 "destination.domain", "network.protocol", "source.bytes", "destination.bytes"]},
    }


# --------------------------------------------------------------------- 6. DNS
def dns_overview_query(user: str, start: str, end: str) -> dict:
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(DNS)),
        "aggs": {
            "top_domains": {"terms": {"field": "dns.question.registered_domain", "size": 25},
                            "aggs": {"uniq_names": {"cardinality": {"field": "dns.question.name"}},
                                     "nxdomain": {"filter": {"term": {"dns.response_code": "NXDOMAIN"}}},
                                     "qtype": {"terms": {"field": "dns.question.type", "size": 3}}}},
            "rcode": {"terms": {"field": "dns.response_code", "size": 10}},
            "qtype": {"terms": {"field": "dns.question.type", "size": 10}},
            "uniq_names": {"cardinality": {"field": "dns.question.name"}},
            "uniq_domains": {"cardinality": {"field": "dns.question.registered_domain"}},
            "over_time": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                                             "extended_bounds": {"min": start, "max": end}},
                          "aggs": {"nxdomain": {"filter": {"term": {"dns.response_code": "NXDOMAIN"}}}}},
        },
    }


def dns_names_query(user: str, start: str, end: str, size: int = 3000) -> dict:
    """Every distinct name queried -> entropy / label-length scoring in Python."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(DNS)),
        "aggs": {"names": {"terms": {"field": "dns.question.name", "size": size},
                           "aggs": {"rcode": {"terms": {"field": "dns.response_code", "size": 1}},
                                    "qtype": {"terms": {"field": "dns.question.type", "size": 1}},
                                    "first_seen": {"min": {"field": "@timestamp"}}}}},
    }


# --------------------------------------------------------------- 7. detectors
def beacon_candidates_query(user: str, start: str, end: str, pairs: int = 25) -> dict:
    """For the busiest external dest:port pairs, a per-minute histogram of
    connections. Python then measures how *regular* the gaps are."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW), {"term": {"network.direction": "outbound"}}),
        "aggs": {
            "pairs": {
                "multi_terms": {"terms": [{"field": "destination.ip"}, {"field": "destination.port"}],
                                "size": pairs, "min_doc_count": 20},
                "aggs": {
                    "per_minute": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1m",
                                                      "min_doc_count": 1}},
                    "bytes_out": {"stats": {"field": "source.bytes"}},
                    "domain": {"terms": {"field": "destination.domain", "size": 1}},
                    "org": {"terms": {"field": "destination.as.organization.name", "size": 1}},
                },
            }
        },
    }


def fanout_query(user: str, start: str, end: str, interval: str = "5m") -> dict:
    """How many distinct hosts/ports does the user touch per 5 minutes?
    A sudden spike = scanning."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW)),
        "aggs": {
            "over_time": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 1},
                          "aggs": {"uniq_ip": {"cardinality": {"field": "destination.ip"}},
                                   "uniq_port": {"cardinality": {"field": "destination.port"}},
                                   "failed": {"filter": {"term": {"event.outcome": "failure"}}}}},
        },
    }


def scan_matrix_query(user: str, start: str, end: str) -> dict:
    """Internal target x port grid with outcomes (what did the scan find?)."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW), {"term": {"network.direction": "internal"}}),
        "aggs": {"target": {"terms": {"field": "destination.ip", "size": 300},
                            "aggs": {"port": {"terms": {"field": "destination.port", "size": 20},
                                              "aggs": {"ok": {"filter": {"term": {"event.outcome": "success"}}},
                                                       "bytes_in": {"sum": {"field": "destination.bytes"}}}}}}},
    }


def admin_protocol_query(user: str, start: str, end: str) -> dict:
    """Successful admin-protocol sessions (SSH/SMB/RDP/WinRM) to internal hosts."""
    return {
        "size": 0,
        "query": _base(user, start, end, _dataset(FLOW),
                       {"term": {"network.direction": "internal"}},
                       {"term": {"event.outcome": "success"}},
                       {"terms": {"destination.port": ADMIN_PORTS}}),
        "aggs": {"target": {"terms": {"field": "destination.ip", "size": 50},
                            "aggs": {"protocols": {"terms": {"field": "network.protocol", "size": 6}},
                                     "bytes_in": {"sum": {"field": "destination.bytes"}},
                                     "first_seen": {"min": {"field": "@timestamp"}}}}},
    }


# ----------------------------------------------------------------- 8. peers
def peer_baseline_query(group: str, start: str, end: str, tz: str = "America/New_York") -> dict:
    """Same metrics for everyone in the user's department -> 'is this normal?'"""
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"user.group.name": group}},
                                      {"range": {"@timestamp": {"gte": start, "lt": end}}},
                                      _dataset(FLOW)]}},
        "aggs": {
            "users": {"terms": {"field": "user.name", "size": 200}, "aggs": {
                "bytes_out_ext": {"filter": {"term": {"network.direction": "outbound"}},
                                  "aggs": {"v": {"sum": {"field": "source.bytes"}}}},
                "uniq_dest_ip": {"cardinality": {"field": "destination.ip"}},
                "uniq_dest_port": {"cardinality": {"field": "destination.port"}},
                "uniq_domains": {"cardinality": {"field": "destination.registered_domain"}},
                "denied": {"filter": {"term": {"event.outcome": "failure"}}},
                # hour-of-day profile in the office timezone -> off-hours share
                "hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h",
                                              "time_zone": tz, "min_doc_count": 1},
                           "aggs": {"bytes_out": {"sum": {"field": "source.bytes"}}}},
            }},
        },
    }


# Registry used by the "Query inspector" tab
ALL_QUERIES = {
    "user_search_query": user_search_query,
    "user_identity_query": user_identity_query,
    "user_kpi_query": user_kpi_query,
    "activity_timeline_query": activity_timeline_query,
    "top_destinations_query": top_destinations_query,
    "destination_first_seen_query": destination_first_seen_query,
    "traffic_flow_query": traffic_flow_query,
    "geo_destinations_query": geo_destinations_query,
    "vpn_sessions_query": vpn_sessions_query,
    "open_sessions_query": open_sessions_query,
    "long_sessions_query": long_sessions_query,
    "dns_overview_query": dns_overview_query,
    "dns_names_query": dns_names_query,
    "beacon_candidates_query": beacon_candidates_query,
    "fanout_query": fanout_query,
    "scan_matrix_query": scan_matrix_query,
    "admin_protocol_query": admin_protocol_query,
    "peer_baseline_query": peer_baseline_query,
}
