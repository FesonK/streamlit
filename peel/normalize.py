"""
normalize.py — shape whatever your cluster sends into the flat record Peel uses.

This is the piece that makes "morph real data into the mock shape" a config
change, not a rewrite. Real PowerShell logs vary: some fields sit under
`winlog.event_data.*`, some use Elastic's `powershell.*` ECS set, some are
missing. `normalize()` reads a source doc through a list of candidate paths per
field and returns one flat dict. `data_doctor()` samples docs and reports how
well each field is populated, so you know what to map before you trust the UI.

Edit FIELD_PATHS to fit your pipeline; nothing else needs to change.
"""
from __future__ import annotations

from collections import defaultdict

# target field  ->  candidate dotted paths in the source _source, best first.
FIELD_PATHS = {
    "timestamp": ["@timestamp"],
    "host": ["host.name", "host.hostname", "winlog.computer_name", "beat.hostname"],
    "user": ["user.name", "winlog.event_data.User", "winlog.user.name"],
    "event_code": ["event.code", "winlog.event_id", "event.id"],
    "script_block_id": ["powershell.file.script_block_id", "winlog.event_data.ScriptBlockId"],
    "script_block_text": ["powershell.file.script_block_text", "winlog.event_data.ScriptBlockText", "message"],
    "sequence": ["powershell.sequence", "winlog.event_data.MessageNumber"],
    "total": ["powershell.total", "winlog.event_data.MessageTotal"],
    "runspace_id": ["powershell.runspace_id", "winlog.event_data.RunspaceId"],
    "pipeline_id": ["powershell.pipeline_id", "winlog.event_data.PipelineId"],
    "engine_version": ["powershell.engine.version", "powershell.process.executable_version",
                       "winlog.event_data.EngineVersion"],
    "connected_user": ["powershell.connected_user.name", "winlog.event_data.ConnectedUser"],
    "command_value": ["powershell.command.value", "winlog.event_data.Payload"],
    "command_name": ["powershell.command.name"],
    "command_path": ["powershell.command.path"],
    "invocation_details": ["powershell.command.invocation_details"],
    "process_name": ["process.name", "winlog.event_data.NewProcessName"],
    "command_line": ["process.command_line", "winlog.event_data.CommandLine"],
    "entity_id": ["process.entity_id"],
    "pid": ["process.pid", "winlog.event_data.NewProcessId"],
    "parent_name": ["process.parent.name", "winlog.event_data.ParentProcessName"],
    "parent_entity_id": ["process.parent.entity_id"],
    "fingerprint": ["powershell.fingerprint"],
}

# Every field Peel can use, with a one-line meaning + which event it comes from,
# for the data doctor's report. Fields marked critical gate whole features.
FIELD_INFO = {
    "timestamp":        ("all",            True,  "When the event happened"),
    "host":             ("all",            True,  "Machine name"),
    "user":             ("all",            True,  "Account the code ran as"),
    "event_code":       ("all",            True,  "4104 / 4103 / 400 / 4688 — tells the sources apart"),
    "script_block_id":  ("4104",           True,  "Groups split script-block pieces back together"),
    "script_block_text":("4104",           True,  "The actual code that ran (the heart of Peel)"),
    "sequence":         ("4104",           False, "Piece number within a split block"),
    "total":            ("4104",           False, "How many pieces the block was split into"),
    "runspace_id":      ("4104/4103",      True,  "Groups commands into one session"),
    "pipeline_id":      ("4104/4103",      False, "Groups commands into one pipeline"),
    "engine_version":   ("400",            False, "PowerShell version — flags v2 downgrades"),
    "connected_user":   ("4103",           False, "Who connected remotely (WinRM) — flags lateral movement"),
    "command_value":    ("4103",           False, "Module-logged command text"),
    "command_name":     ("4103",           False, "Module-logged command name"),
    "command_path":     ("4103",           False, "Path of the module-logged command"),
    "invocation_details":("4103",          False, "Parameters bound to each command"),
    "process_name":     ("4688/1",         False, "Process name (for cmd.exe / powershell.exe launches)"),
    "command_line":     ("4688/1",         True,  "Full command line — the only source for cmd.exe + -enc"),
    "entity_id":        ("4688/1",         False, "Unique process id, links to Family Tree"),
    "pid":              ("all",            False, "Process id"),
    "parent_name":      ("4688/1",         False, "Parent process name"),
    "parent_entity_id": ("4688/1",         False, "Parent unique id"),
    "fingerprint":      ("derived",        False, "Normalized command shape (computed here if absent)"),
}


def _dig(doc: dict, dotted: str):
    cur = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _first(src: dict, paths: list[str]):
    for p in paths:
        v = _dig(src, p)
        if v is not None and v != "":
            return v
    return None


def normalize(hit: dict) -> dict:
    """One Elastic hit -> one flat record with Peel's field names."""
    src = hit.get("_source", hit)
    rec = {field: _first(src, paths) for field, paths in FIELD_PATHS.items()}
    code = rec.get("event_code")
    rec["event_code"] = str(code) if code is not None else None
    rec["_id"] = hit.get("_id")
    return rec


def normalize_all(hits: list[dict]) -> list[dict]:
    return [normalize(h) for h in hits]


def _present(v) -> bool:
    return v is not None and v != "" and v != []


def data_doctor(hits: list[dict]) -> dict:
    """Field-coverage report. For each target field: % of the events that *should*
    carry it (by event.code) where it's actually populated. Flags criticals."""
    recs = [normalize(h) for h in hits]
    by_code = defaultdict(int)
    for r in recs:
        by_code[r.get("event_code") or "?"] += 1

    def relevant(field) -> list[dict]:
        src_codes = FIELD_INFO[field][0]
        if src_codes in ("all", "derived"):
            return recs
        wanted = src_codes.replace("/1", "/4688").split("/")  # e.g. "4104/4103"
        wanted = set(FIELD_INFO[field][0].replace("/", " ").split())
        return [r for r in recs if (r.get("event_code") or "") in wanted] or recs

    rows = []
    for field, (src, critical, desc) in FIELD_INFO.items():
        rel = relevant(field)
        have = sum(1 for r in rel if _present(r.get(field)))
        pct = (have / len(rel)) if rel else 0.0
        status = "ok" if pct >= 0.9 else ("partial" if pct >= 0.2 else "missing")
        rows.append({"field": field, "source": src, "critical": critical, "desc": desc,
                     "coverage": pct, "have": have, "of": len(rel), "status": status})

    crit_missing = [r["field"] for r in rows if r["critical"] and r["status"] == "missing"]
    return {"total": len(recs), "by_code": dict(by_code), "rows": rows,
            "critical_missing": crit_missing,
            "healthy": not crit_missing}
