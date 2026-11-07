"""
query_dict.py — Elasticsearch request builders for the Deep String Finder.

Everything in here is *pure*: plain Python values in, plain dicts out.
That keeps the DSL easy to read, test and practise with. To go live, the
Streamlit app only has to swap one line:

    resp = mock_search(req["index"], req["body"])            # today (mock)
    resp = es.search(index=req["index"], body=req["body"])   # later (elasticsearch-py)
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import quote

# --------------------------------------------------------------------------- #
# Options the UI offers
# --------------------------------------------------------------------------- #
ALL_INDICES = "All indices (*)"

INDEX_PATTERNS = [
    "logs-endpoint.events.*",   # Elastic Defend: process / registry / file
    "winlogbeat-*",             # Windows Security + PowerShell logs
    "packetbeat-*",             # DNS traffic
    "logs-proxy.*",             # Web proxy access logs
    "auditbeat-*",              # Linux auditd
]

# Where strings like to hide. None = every field (default_field: "*").
FIELD_SCOPES: dict[str, list[str] | None] = {
    "All fields": None,
    "Command lines": [
        "process.command_line",
        "process.parent.command_line",
        "process.args",
        "powershell.file.script_block_text",
    ],
    "Messages": ["message", "event.original"],
    "URLs & DNS": ["url.full", "url.query", "url.domain", "dns.question.name", "destination.domain"],
    "Files & registry": ["file.path", "file.name", "registry.path", "registry.data.strings"],
    "Users & hosts": ["user.name", "host.name"],
}

# label -> (gte date-math, histogram interval). "Custom" is computed.
TIME_PRESETS: dict[str, tuple[str, str] | None] = {
    "Last 15 minutes": ("now-15m", "30s"),
    "Last 1 hour": ("now-1h", "1m"),
    "Last 24 hours": ("now-24h", "30m"),
    "Last 7 days": ("now-7d", "3h"),
    "Last 30 days": ("now-30d", "12h"),
    "Custom": None,
}

KIBANA_BASE = "https://kibana.local"     # mock
DATA_VIEW_ID = "mock-all-logs"           # mock data view id

_INTERVAL_LADDER = [
    ("1s", 1), ("10s", 10), ("30s", 30), ("1m", 60), ("5m", 300), ("10m", 600),
    ("30m", 1800), ("1h", 3600), ("3h", 10800), ("12h", 43200), ("1d", 86400), ("7d", 604800),
]


# --------------------------------------------------------------------------- #
# Small building blocks
# --------------------------------------------------------------------------- #
def resolve_indices(selected: list[str] | None) -> str:
    """UI selection -> the `index` argument of _search ('*' or 'a-*,b-*')."""
    if not selected or ALL_INDICES in selected:
        return "*"
    return ",".join(selected)


def auto_interval(span_seconds: float, target_buckets: int = 60) -> str:
    """Pick a fixed_interval that gives roughly `target_buckets` bars."""
    for name, secs in _INTERVAL_LADDER:
        if secs * target_buckets >= span_seconds:
            return name
    return _INTERVAL_LADDER[-1][0]


def build_time_filter(preset: str, start: datetime | None = None, end: datetime | None = None) -> dict:
    """Range filter on @timestamp — relative date math or an absolute window."""
    if preset == "Custom":
        if start is None or end is None:
            raise ValueError("Custom time range needs both start and end")
        return {
            "range": {
                "@timestamp": {
                    "gte": start.isoformat(),
                    "lte": end.isoformat(),
                    "format": "strict_date_optional_time",
                }
            }
        }
    gte, _ = TIME_PRESETS[preset]
    return {"range": {"@timestamp": {"gte": gte, "lte": "now"}}}


def build_query_string(query: str, fields: list[str] | None = None, default_operator: str = "AND") -> dict:
    """
    Lucene syntax via query_string. Tuned for *finding buried strings*:
      - allow_leading_wildcard lets you write *mimikatz*
      - analyze_wildcard lowercases/analyses wildcard terms on text fields
      - lenient stops "all fields" searches failing on numeric/ip/date fields
    """
    qs: dict = {
        "query": query.strip() or "*",
        "analyze_wildcard": True,
        "allow_leading_wildcard": True,
        "default_operator": default_operator,
        "lenient": True,
    }
    if fields:
        qs["fields"] = list(fields)
    else:
        qs["default_field"] = "*"
    return {"query_string": qs}


def build_highlight(fragment_size: int = 160, number_of_fragments: int = 3) -> dict:
    """Ask ES *where* the match happened. encoder=html escapes the doc text for safe rendering."""
    return {
        "pre_tags": ["<mark>"],
        "post_tags": ["</mark>"],
        "encoder": "html",
        "fragment_size": fragment_size,
        "number_of_fragments": number_of_fragments,
        "fields": {"*": {}},   # require_field_match (default true) keeps it to queried fields
    }


def build_aggs(interval: str, bounds: tuple[str, str] | None = None) -> dict:
    """The little dashboard strip above the results."""
    hist: dict = {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0}
    if bounds:
        hist["extended_bounds"] = {"min": bounds[0], "max": bounds[1]}
    return {
        "hits_over_time": {"date_histogram": hist},
        "by_index": {"terms": {"field": "_index", "size": 50}},
        "top_hosts": {"terms": {"field": "host.name", "size": 5}},
        "top_datasets": {"terms": {"field": "event.dataset", "size": 5}},
        "unique_hosts": {"cardinality": {"field": "host.name"}},
        "unique_users": {"cardinality": {"field": "user.name"}},
    }


# --------------------------------------------------------------------------- #
# The main entry point
# --------------------------------------------------------------------------- #
def build_search_request(
    indices: list[str] | None,
    query: str,
    time_preset: str = "Last 7 days",
    start: datetime | None = None,
    end: datetime | None = None,
    fields: list[str] | None = None,
    size: int = 25,
    from_: int = 0,
    sort_order: str = "desc",
) -> dict:
    """
    Returns {"index": "...", "body": {...}} ready for es.search(**request).

    Example body:
    {
      "query": {"bool": {
          "must":   [{"query_string": {"query": "*mimikatz*", "default_field": "*", ...}}],
          "filter": [{"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}]}},
      "sort": [{"@timestamp": {"order": "desc"}}],
      "highlight": {...}, "aggs": {...}
    }
    """
    time_filter = build_time_filter(time_preset, start, end)

    if time_preset == "Custom":
        interval = auto_interval((end - start).total_seconds())
        bounds = (start.isoformat(), end.isoformat())
    else:
        gte, interval = TIME_PRESETS[time_preset]
        bounds = (gte, "now")

    body = {
        "track_total_hits": True,
        "size": size,
        "from": from_,
        "_source": True,
        "sort": [{"@timestamp": {"order": sort_order}}],
        "query": {
            "bool": {
                "must": [build_query_string(query, fields)],
                "filter": [time_filter],
            }
        },
        "highlight": build_highlight(),
        "aggs": build_aggs(interval, bounds),
    }
    return {"index": resolve_indices(indices), "body": body}


# --------------------------------------------------------------------------- #
# Helpers for the UI
# --------------------------------------------------------------------------- #
def query_warnings(query: str, fields: list[str] | None, index: str) -> list[str]:
    """Friendly nudges about things that are fine on mock data but costly on a real cluster."""
    q = query or ""
    warnings = []
    if re.search(r"(^|[\s(:])[*?][^\s*)]", q):
        warnings.append("Leading wildcard: great for deep strings, slow on big clusters")
    if re.search(r"(^|[\s(:])/[^/]+/", q):
        warnings.append("Regex query: powerful, can be expensive")
    if not fields:
        warnings.append("All fields (default_field: *): can hit max_clause_count on wide mappings")
    if index == "*":
        warnings.append("Every index (*): narrow it down in production")
    return warnings


def kibana_doc_url(index: str, doc_id: str) -> str:
    """Mock deep link to Kibana's single-document view."""
    return f"{KIBANA_BASE}/app/discover#/doc/{DATA_VIEW_ID}/{quote(index, safe='')}?id={quote(doc_id, safe='')}"


if __name__ == "__main__":
    import json

    print(json.dumps(build_search_request(["winlogbeat-*"], "*mimikatz*", "Last 24 hours"), indent=2))
