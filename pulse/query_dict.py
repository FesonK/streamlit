"""
query_dict.py — every Elasticsearch request Pulse makes.

Pulse reads plain process-creation telemetry (Sysmon 1 / Security 4688 in ECS)
and does its thinking client-side. Two kinds of query live here:

  • what the app runs:        fleet_overview, fleet_processes (paged), live_since
  • what you'd run at scale:  the *_at_scale builders. On a large fleet you
    don't pull every raw event — you pre-aggregate with composite aggs (or an
    Elastic transform) and only pull raw events for the streams that matter.

ECS fields used: @timestamp, host.name, user.name, process.entity_id / pid / name /
executable / command_line / start / end / exit_code / hash.sha256 /
code_signature.trusted / code_signature.subject_name, process.parent.entity_id /
name / executable.
"""
from __future__ import annotations

INDEX = "logs-windows.sysmon_operational-*,logs-system.security-*"

TIME_RANGES = {"Last 7 days": "now-7d", "Last 14 days": "now-14d", "Last 21 days": "now-21d"}

SOURCE = [
    "@timestamp", "host.name", "user.name",
    "process.entity_id", "process.pid", "process.name", "process.executable", "process.command_line",
    "process.start", "process.end", "process.exit_code", "process.hash.sha256",
    "process.code_signature.trusted", "process.code_signature.subject_name",
    "process.parent.entity_id", "process.parent.name", "process.parent.executable",
]


def _starts(since=None):
    f = [{"term": {"event.category": "process"}}, {"term": {"event.type": "start"}}]
    if since:
        f.append({"range": {"@timestamp": {"gte": since, "lte": "now"}}})
    return f


def fleet_overview(since="now-21d"):
    return {"index": INDEX, "body": {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": _starts(since)}},
        "aggs": {"hosts": {"cardinality": {"field": "host.name"}},
                 "users": {"cardinality": {"field": "user.name"}},
                 "first": {"min": {"field": "@timestamp"}},
                 "last": {"max": {"field": "@timestamp"}}}}}


def fleet_processes(since="now-21d", page_size=5000, search_after=None):
    body = {"size": page_size, "query": {"bool": {"filter": _starts(since)}}, "_source": SOURCE,
            "sort": [{"@timestamp": "asc"}, {"process.entity_id": "asc"}], "track_total_hits": search_after is None}
    if search_after:
        body["search_after"] = search_after
    return {"index": INDEX, "body": body}


def live_since(since_ts, size=500):
    return {"index": INDEX, "body": {
        "size": size, "_source": SOURCE, "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": _starts() + [{"range": {"@timestamp": {"gt": since_ts}}}]}}}}


# ───────────── at scale: pre-aggregate instead of pulling everything ─────────────
def rhythm_streams_at_scale(since="now-21d", after=None):
    """💓 Candidate machine streams: every (host, executable, command) with enough launches.
    Pull raw timestamps only for streams with ≥ 10 launches."""
    comp = {"size": 1000, "sources": [{"host": {"terms": {"field": "host.name"}}},
                                      {"exe": {"terms": {"field": "process.executable"}}},
                                      {"cmd": {"terms": {"field": "process.command_line"}}}]}
    if after:
        comp["after"] = after
    return {"index": INDEX, "body": {"size": 0, "query": {"bool": {"filter": _starts(since)}},
            "aggs": {"streams": {"composite": comp, "aggs": {
                "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                "keep": {"bucket_selector": {"buckets_path": {"n": "_count"}, "script": "params.n >= 10"}}}}}}}


def first_seen_at_scale(field="process.hash.sha256", since="now-21d", after=None):
    """🦠 🌅 First time each hash / parent→child pair was seen, and how many hosts it reached."""
    comp = {"size": 2000, "sources": [{"thing": {"terms": {"field": field}}}]}
    if after:
        comp["after"] = after
    return {"index": INDEX, "body": {"size": 0, "query": {"bool": {"filter": _starts(since)}},
            "aggs": {"things": {"composite": comp, "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "hosts": {"cardinality": {"field": "host.name"}},
                "patient_zero": {"top_hits": {"size": 1, "sort": [{"@timestamp": "asc"}],
                                              "_source": ["host.name", "user.name", "process.parent.name"]}}}}}}}


def app_mix_at_scale(since="now-21d"):
    """📖 🗺️ Per-user app mix + hour-of-day profile (the fingerprint inputs)."""
    return {"index": INDEX, "body": {"size": 0, "query": {"bool": {"filter": _starts(since)}},
            "aggs": {"users": {"terms": {"field": "user.name", "size": 5000}, "aggs": {
                "apps": {"terms": {"field": "process.name", "size": 200}},
                "hours": {"histogram": {"script": "doc['@timestamp'].value.getHour()", "interval": 1}}}}}}}


QUERIES = {"fleet_overview": fleet_overview, "fleet_processes": fleet_processes, "live_since": live_since}
AT_SCALE = {"rhythm_streams": rhythm_streams_at_scale, "first_seen": first_seen_at_scale, "app_mix": app_mix_at_scale}
