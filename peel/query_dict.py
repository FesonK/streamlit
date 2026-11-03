"""
query_dict.py — every Elasticsearch request Peel makes.

Each builder returns {"index": ..., "body": {...}}; the body maps 1:1 onto the
Python client kwargs, so a real call is  es.search(index=req["index"], **req["body"]).

Sources (Windows PowerShell + Microsoft-Windows-PowerShell/Operational, plus
process-creation for cmd.exe), all normalized to ECS + the `powershell.*`
fieldset:
  @timestamp, host.name, user.name,
  event.code (4104 script block, 4103 module, 400/403 engine, 4688/1 process),
  powershell.file.script_block_id / script_block_text,
  powershell.sequence / total, powershell.runspace_id, powershell.pipeline_id,
  powershell.engine.version, powershell.command.value / .name / .path,
  powershell.command.invocation_details[], powershell.connected_user.name,
  process.command_line / entity_id / parent.* (for cmd.exe + powershell.exe launches).
"""
from __future__ import annotations

INDEX = "logs-windows.powershell*-*,logs-windows.sysmon_operational-*,logs-system.security-*"

TIME_RANGES = {
    "Last 24 hours": "now-24h",
    "Last 3 days": "now-3d",
    "Last 7 days": "now-7d",
    "Last 14 days": "now-14d",
}

# event.code values we care about
SCRIPTBLOCK, MODULE, ENGINE_START, ENGINE_STOP = "4104", "4103", "400", "403"
PROC_SYSMON, PROC_SECURITY = "1", "4688"

SB_SOURCE = [
    "@timestamp", "host.name", "user.name", "event.code",
    "powershell.file.script_block_id", "powershell.file.script_block_text",
    "powershell.sequence", "powershell.total",
    "powershell.runspace_id", "powershell.pipeline_id", "powershell.process.executable_version",
    "powershell.engine.version", "powershell.connected_user.name", "powershell.connected_user.domain",
    "process.pid", "process.entity_id",
]
CMD_SOURCE = [
    "@timestamp", "host.name", "user.name", "event.code",
    "powershell.command.value", "powershell.command.name", "powershell.command.path",
    "powershell.command.invocation_details", "powershell.runspace_id", "powershell.pipeline_id",
    "powershell.sequence",
]
PROC_SOURCE = [
    "@timestamp", "host.name", "user.name", "event.code",
    "process.name", "process.command_line", "process.entity_id", "process.pid",
    "process.parent.name", "process.parent.entity_id",
]


def _base(user=None, since=None, codes=None):
    f = []
    if codes:
        f.append({"terms": {"event.code": list(codes)}})
    if since:
        f.append({"range": {"@timestamp": {"gte": since, "lte": "now"}}})
    if user:
        f.append({"term": {"user.name": user}})
    return f


def users_overview(since="now-7d"):
    """Sidebar: who ran PowerShell/cmd, how many script blocks, which hosts, last seen."""
    return {"index": INDEX, "body": {
        "size": 0,
        "query": {"bool": {"filter": _base(since=since, codes=[SCRIPTBLOCK, MODULE, PROC_SYSMON])}},
        "aggs": {"users": {"terms": {"field": "user.name", "size": 500, "order": {"_count": "desc"}},
                           "aggs": {"hosts": {"terms": {"field": "host.name", "size": 3}},
                                    "scriptblocks": {"filter": {"term": {"event.code": SCRIPTBLOCK}}},
                                    "last_seen": {"max": {"field": "@timestamp"}}}}}}}


def user_summary(user, since="now-7d"):
    """Header metrics + per-hour activity + engine versions seen (for the v2-downgrade blind spot)."""
    return {"index": INDEX, "body": {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": _base(user, since, [SCRIPTBLOCK, MODULE, ENGINE_START, PROC_SYSMON, PROC_SECURITY])}},
        "aggs": {
            "hosts": {"terms": {"field": "host.name", "size": 20}},
            "runspaces": {"cardinality": {"field": "powershell.runspace_id"}},
            "engine_versions": {"terms": {"field": "powershell.engine.version", "size": 20}},
            "by_code": {"terms": {"field": "event.code", "size": 10}},
            "connected_users": {"terms": {"field": "powershell.connected_user.name", "size": 20}},
            "per_hour": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h",
                                            "min_doc_count": 0, "extended_bounds": {"min": since, "max": "now"}},
                         "aggs": {"codes": {"terms": {"field": "event.code", "size": 6}}}},
        }}}


def user_events(user, since="now-7d", page_size=2000, search_after=None):
    """All script-block / module / engine / process-launch events for one user, time-sorted,
    paged with search_after. The app stitches, groups into sessions and peels client-side."""
    body = {
        "size": page_size,
        "query": {"bool": {"filter": _base(user, since,
                                           [SCRIPTBLOCK, MODULE, ENGINE_START, ENGINE_STOP, PROC_SYSMON, PROC_SECURITY])}},
        "_source": sorted(set(SB_SOURCE) | set(CMD_SOURCE) | set(PROC_SOURCE)),
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
        "track_total_hits": search_after is None,
    }
    if search_after:
        body["search_after"] = search_after
    return {"index": INDEX, "body": body}


def fleet_fingerprints(since="now-14d"):
    """Fleet-wide count per normalized command fingerprint — powers Rare Command Radar.
    In a real cluster this is a terms agg over a runtime/ingest field `powershell.fingerprint`
    (computed at ingest with the same normalizer the app uses); here the mock fills it in."""
    return {"index": INDEX, "body": {
        "size": 0,
        "query": {"bool": {"filter": _base(since=since, codes=[SCRIPTBLOCK])}},
        "aggs": {"fingerprints": {"terms": {"field": "powershell.fingerprint", "size": 2000},
                                  "aggs": {"users": {"cardinality": {"field": "user.name"}},
                                           "hosts": {"cardinality": {"field": "host.name"}}}}}}}


def live_since(user, since_ts, size=200):
    """Live mode: new PowerShell/process events after since_ts (absolute ISO)."""
    return {"index": INDEX, "body": {
        "size": size,
        "query": {"bool": {"filter": _base(user, codes=[SCRIPTBLOCK, MODULE, PROC_SYSMON])
                           + [{"range": {"@timestamp": {"gt": since_ts}}}]}},
        "_source": sorted(set(SB_SOURCE) | set(CMD_SOURCE) | set(PROC_SOURCE)),
        "sort": [{"@timestamp": "asc"}],
    }}


def sample_for_doctor(size=500):
    """Grab a recent sample of raw docs so the data doctor can report field coverage."""
    return {"index": INDEX, "body": {
        "size": size,
        "query": {"bool": {"filter": _base(codes=[SCRIPTBLOCK, MODULE, ENGINE_START, PROC_SYSMON])}},
        "sort": [{"@timestamp": "desc"}],
    }}


QUERIES = {
    "users_overview": users_overview,
    "user_summary": user_summary,
    "user_events": user_events,
    "fleet_fingerprints": fleet_fingerprints,
    "live_since": live_since,
    "sample_for_doctor": sample_for_doctor,
}
