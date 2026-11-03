"""
query_dict.py — every Elasticsearch request the Family Tree Detective makes.

Each builder returns {"index": ..., "body": {...}}. The body keys map 1:1 onto
the Python client's keyword arguments, so a real call is simply:

    es.search(index=req["index"], **req["body"])

ECS fields used:
  @timestamp, user.name, host.name, event.category, event.type,
  process.entity_id / pid / name / executable / command_line / args_count /
  working_directory / start / end / exit_code / hash.sha256 / code_signature.*,
  process.parent.entity_id / pid / name / executable / command_line
"""
from __future__ import annotations

# Sysmon event 1 and Security 4688 both land in ECS as process "start" events.
INDEX = "logs-windows.sysmon_operational-*,logs-system.security-*"

TIME_RANGES = {
    "Last 24 hours": "now-24h",
    "Last 3 days": "now-3d",
    "Last 7 days": "now-7d",
    "Last 14 days": "now-14d",
}

PROCESS_SOURCE = [
    "@timestamp", "host.name", "user.name",
    "process.entity_id", "process.pid", "process.name", "process.executable",
    "process.command_line", "process.args_count", "process.working_directory",
    "process.start", "process.end", "process.exit_code",
    "process.hash.sha256",
    "process.code_signature.trusted", "process.code_signature.subject_name",
    "process.parent.entity_id", "process.parent.pid", "process.parent.name",
    "process.parent.executable", "process.parent.command_line",
]


def _process_starts(user: str | None = None, since: str | None = None) -> list[dict]:
    """Filter clauses shared by every query: process-start events, optionally scoped."""
    filters: list[dict] = [
        {"term": {"event.category": "process"}},
        {"term": {"event.type": "start"}},
    ]
    if since:
        filters.append({"range": {"@timestamp": {"gte": since, "lte": "now"}}})
    if user:
        filters.append({"term": {"user.name": user}})
    return filters


def users_overview(since: str = "now-7d") -> dict:
    """Sidebar picker: who launched processes, how many, on which hosts, last seen."""
    return {
        "index": INDEX,
        "body": {
            "size": 0,
            "query": {"bool": {"filter": _process_starts(since=since)}},
            "aggs": {
                "users": {
                    "terms": {"field": "user.name", "size": 500, "order": {"_count": "desc"}},
                    "aggs": {
                        "hosts": {"terms": {"field": "host.name", "size": 3}},
                        "last_seen": {"max": {"field": "@timestamp"}},
                    },
                }
            },
        },
    }


def user_summary(user: str, since: str = "now-7d") -> dict:
    """Header metrics, hourly activity and the parent→child 'who spawns whom' edges.
    Pure aggregations, so it stays cheap no matter how many processes the user has."""
    return {
        "index": INDEX,
        "body": {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": _process_starts(user, since)}},
            "aggs": {
                "unique_executables": {"cardinality": {"field": "process.executable"}},
                "hosts": {"terms": {"field": "host.name", "size": 20}},
                "per_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                        "extended_bounds": {"min": since, "max": "now"},
                    }
                },
                "edges": {
                    "multi_terms": {
                        "terms": [{"field": "process.parent.name"}, {"field": "process.name"}],
                        "size": 300,
                    }
                },
            },
        },
    }


def user_processes(user: str, since: str = "now-7d", page_size: int = 2000,
                   search_after: list | None = None) -> dict:
    """Raw process docs for one user, paged with search_after (from/size stops at 10k).
    For very large pulls on a live cluster, add a point-in-time (PIT) so pages stay consistent."""
    body: dict = {
        "size": page_size,
        "query": {"bool": {"filter": _process_starts(user, since)}},
        "_source": PROCESS_SOURCE,
        "sort": [{"@timestamp": "asc"}, {"process.entity_id": "asc"}],
        "track_total_hits": search_after is None,
    }
    if search_after:
        body["search_after"] = search_after
    return {"index": INDEX, "body": body}


def live_since(user: str, since_ts: str, size: int = 200) -> dict:
    """Live mode: everything this user started after `since_ts` (absolute ISO time).
    Poll every few seconds; the app re-asks with a small overlap and de-dupes by entity_id."""
    return {
        "index": INDEX,
        "body": {
            "size": size,
            "query": {
                "bool": {
                    "filter": _process_starts(user)
                    + [{"range": {"@timestamp": {"gt": since_ts}}}]
                }
            },
            "_source": PROCESS_SOURCE,
            "sort": [{"@timestamp": "asc"}],
        },
    }


QUERIES = {
    "users_overview": users_overview,
    "user_summary": user_summary,
    "user_processes": user_processes,
    "live_since": live_since,
}
