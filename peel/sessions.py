"""
sessions.py — turn normalized events into something you can investigate.

Three jobs, in order:
  1. stitch()   — reassemble split 4104 script blocks (sequence/total) by
                  script_block_id into one text per block.
  2. link_layers() — Peel job #1: chain executed layers. When a block runs a
                  decoded payload (IEX / ScriptBlock::Create), PowerShell logs
                  that payload as its *own* new 4104. We connect parent→child by
                  (host, runspace, tight time window) AND by content: the child's
                  text matches a string the parent's peeled code handed to IEX.
  3. build_sessions() — group everything by runspace into a replayable timeline
                  of entries (script blocks, module commands, process launches),
                  each enriched with peel result, tags, obfuscation score, risk.

Everything is pure data; the app just renders it.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from detections import fingerprint, risk_score, severity, tag
from psparse import FEATURES, features, peel, script_from_command_line, requested_version

_MODEL = None


def _model():
    global _MODEL
    if _MODEL is None:
        path = os.path.join(os.path.dirname(__file__), "score_model.json")
        try:
            _MODEL = json.load(open(path))
        except FileNotFoundError:
            _MODEL = {"features": FEATURES, "w": [0] * len(FEATURES), "b": -2.0,
                      "mu": [0] * len(FEATURES), "sd": [1] * len(FEATURES), "missing": True}
    return _MODEL


def obfuscation_prob(src: str, peeled=None) -> float:
    """Probability (0..1) that a script is obfuscated, from the trained model."""
    m = _model()
    feats = features(src, peeled)
    z = m["b"]
    for i, f in enumerate(m["features"]):
        z += m["w"][i] * ((feats[f] - m["mu"][i]) / (m["sd"][i] or 1))
    z = max(-30, min(30, z))
    return 1 / (1 + 2.718281828 ** (-z))


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("`", "")).strip().lower()


# ───────────────────────── stitch split blocks ─────────────────────────
def stitch(events: list[dict]) -> list[dict]:
    """Merge 4104 pieces sharing a script_block_id into one block record.
    Returns a new list: one entry per script block, module event, engine or process."""
    blocks: dict[str, dict] = {}
    out: list[dict] = []
    for e in events:
        code = e.get("event_code")
        if code == "4104":
            sbid = e.get("script_block_id") or e.get("_id")
            b = blocks.get(sbid)
            if b is None:
                b = blocks[sbid] = {
                    "kind": "block", "sbid": sbid, "pieces": {}, "total": e.get("total") or 1,
                    "timestamp": e.get("timestamp"), "host": e.get("host"), "user": e.get("user"),
                    "runspace": e.get("runspace_id"), "pid": e.get("pid"),
                    "connected_user": e.get("connected_user"),
                    "fingerprint": e.get("fingerprint"),
                }
                out.append(b)
            try:
                seq = int(e.get("sequence") or 1)
            except (TypeError, ValueError):
                seq = 1
            b["pieces"][seq] = e.get("script_block_text") or ""
            if e.get("total"):
                try:
                    b["total"] = int(e["total"])
                except (TypeError, ValueError):
                    pass
            if e.get("timestamp") and (not b["timestamp"] or e["timestamp"] < b["timestamp"]):
                b["timestamp"] = e["timestamp"]
        elif code == "4103":
            out.append({"kind": "module", "timestamp": e.get("timestamp"), "host": e.get("host"),
                        "user": e.get("user"), "runspace": e.get("runspace_id"),
                        "name": e.get("command_name"), "path": e.get("command_path"),
                        "value": e.get("command_value"), "details": e.get("invocation_details") or [],
                        "connected_user": e.get("connected_user")})
        elif code in ("400", "403"):
            out.append({"kind": "engine", "timestamp": e.get("timestamp"), "host": e.get("host"),
                        "user": e.get("user"), "runspace": e.get("runspace_id"),
                        "version": e.get("engine_version"), "code": code})
        elif code in ("1", "4688"):
            out.append({"kind": "process", "timestamp": e.get("timestamp"), "host": e.get("host"),
                        "user": e.get("user"), "name": e.get("process_name"),
                        "command_line": e.get("command_line"), "entity_id": e.get("entity_id"),
                        "parent_name": e.get("parent_name"), "pid": e.get("pid")})
    for b in blocks.values():
        b["text"] = "".join(b["pieces"][k] for k in sorted(b["pieces"]))
        b["split"] = b["total"] > 1
        b.pop("pieces", None)
    out.sort(key=lambda r: r.get("timestamp") or "")
    return out


# ───────────────────────── peel + enrich one block ─────────────────────────
def enrich_block(b: dict) -> dict:
    text = b.get("text", "")
    pr = peel(text)
    b["peeled"] = pr.text
    b["inner"] = pr.inner
    b["passes"] = pr.passes
    b["changed"] = _norm_text(text) != _norm_text(pr.text)
    b["dyn"] = pr.dyn_invokes
    b["obf_prob"] = obfuscation_prob(text, pr)
    tags = tag(pr.text)
    b["tags"] = tags
    b["risk"] = risk_score(tags, b["obf_prob"])
    b["severity"] = severity(b["risk"])
    if not b.get("fingerprint"):
        b["fingerprint"] = fingerprint(pr.text)
    return b


def enrich_process(p: dict) -> dict:
    """A process launch (cmd.exe / powershell.exe). Pull a script out of -enc / -Command."""
    cmd = p.get("command_line") or ""
    script, how = script_from_command_line(cmd)
    p["decoded_from_cmdline"] = script
    p["decode_how"] = how
    target = script if script else cmd
    pr = peel(target)
    p["peeled"] = pr.text
    p["inner"] = pr.inner
    p["changed"] = bool(script) or _norm_text(target) != _norm_text(pr.text)
    p["obf_prob"] = obfuscation_prob(target, pr) if target else 0.0
    tags = tag(pr.text)
    # version downgrade lives only on the command line
    v = requested_version(cmd)
    p["requested_version"] = v
    p["tags"] = tags
    p["risk"] = risk_score(tags, p["obf_prob"])
    p["severity"] = severity(p["risk"])
    return p


# ───────────────────────── link executed layers ─────────────────────────
@dataclass
class LayerLink:
    parent: dict
    child: dict
    reason: str


def link_layers(blocks: list[dict], window_s: float = 20.0) -> dict[str, str]:
    """Map child block sbid -> parent block sbid where the child is an executed
    layer of the parent. Match on (host, runspace, time window) + content:
    the parent peeled to code that handed `child.text` to IEX/Create."""
    from datetime import datetime

    def t(x):
        try:
            return datetime.fromisoformat((x or "").replace("Z", "+00:00"))
        except ValueError:
            return None

    bl = [b for b in blocks if b["kind"] == "block"]
    parent_of: dict[str, str] = {}
    for child in bl:
        ct, ctext = t(child["timestamp"]), _norm_text(child["text"])
        if not ctext:
            continue
        best = None
        for parent in bl:
            if parent is child or child["sbid"] == parent["sbid"]:
                continue
            if parent.get("host") != child.get("host"):
                continue
            pt = t(parent["timestamp"])
            if pt is None or ct is None or not (0 <= (ct - pt).total_seconds() <= window_s):
                continue
            if parent.get("runspace") and child.get("runspace") and parent["runspace"] != child["runspace"]:
                # executed layers usually share a runspace; allow mismatch only with strong content match
                strong = True
            else:
                strong = False
            inners = [_norm_text(s) for s in parent.get("inner", [])]
            hit = any(ctext == s or (len(ctext) > 20 and ctext in s) or (len(s) > 20 and s in ctext)
                      for s in inners)
            if hit and not (strong and parent.get("runspace") != child.get("runspace") and not hit):
                if best is None or (pt and t(best["timestamp"]) and pt > t(best["timestamp"])):
                    best = parent
        if best is not None:
            parent_of[child["sbid"]] = best["sbid"]

    # Second pass: a child with no content-matched parent, but which appears in
    # the same runspace moments after a block that executed *dynamic*/downloaded
    # code (a cradle / dynamic IEX we couldn't resolve to a constant), is very
    # likely the next executed layer fetched over the wire.
    by_rs: dict = {}
    for b in bl:
        by_rs.setdefault(b.get("runspace"), []).append(b)
    for rs, group in by_rs.items():
        if not rs:
            continue
        group.sort(key=lambda b: b["timestamp"] or "")
        for i, child in enumerate(group):
            if child["sbid"] in parent_of or i == 0:
                continue
            ct = t(child["timestamp"])
            for parent in reversed(group[:i]):
                pt = t(parent["timestamp"])
                if pt is None or ct is None or not (0 < (ct - pt).total_seconds() <= window_s):
                    continue
                dynamic = parent.get("dyn", 0) > 0 or any(
                    tg.id in ("download_cradle", "inmemory_exec") for tg in parent.get("tags", []))
                unresolved = not any(_norm_text(child["text"]) == _norm_text(s2) for s2 in parent.get("inner", []))
                if dynamic and unresolved:
                    parent_of[child["sbid"]] = parent["sbid"]
                    break
    return parent_of


# ───────────────────────── assemble sessions ─────────────────────────
@dataclass
class Session:
    runspace: str
    host: str
    user: str
    connected_user: str | None
    start: str
    end: str
    entries: list = field(default_factory=list)   # enriched blocks / modules / processes / engine
    versions: list = field(default_factory=list)
    risk: int = 0
    severity: str = "none"
    tag_ids: set = field(default_factory=set)
    remote: bool = False


def build_sessions(events: list[dict]) -> tuple[list[Session], dict[str, str]]:
    stitched = stitch(events)
    for r in stitched:
        if r["kind"] == "block":
            enrich_block(r)
        elif r["kind"] == "process":
            enrich_process(r)
    links = link_layers(stitched)
    # group by runspace; processes with no runspace go to a per-host "launches" bucket
    groups: dict[str, list[dict]] = {}
    for r in stitched:
        key = r.get("runspace") or f"__proc__/{r.get('host')}"
        groups.setdefault(key, []).append(r)

    sessions = []
    for key, rows in groups.items():
        rows.sort(key=lambda r: r.get("timestamp") or "")
        hosts = {r.get("host") for r in rows if r.get("host")}
        users = {r.get("user") for r in rows if r.get("user")}
        conn = next((r.get("connected_user") for r in rows if r.get("connected_user")), None)
        versions = [r.get("version") for r in rows if r["kind"] == "engine" and r.get("version")]
        risky = [r for r in rows if r.get("risk")]
        peak = max((r["risk"] for r in risky), default=0)
        tag_ids = {t.id for r in rows for t in r.get("tags", [])}
        user = next(iter(users), "?")
        remote = bool(conn and conn.lower() != (user or "").lower())
        if remote:
            tag_ids.add("lateral_remote")
            peak = max(peak, 35)
        s = Session(
            runspace="(launches)" if key.startswith("__proc__") else key,
            host=next(iter(hosts), "?"), user=user, connected_user=conn,
            start=rows[0].get("timestamp"), end=rows[-1].get("timestamp"),
            entries=rows, versions=versions, risk=peak, severity=severity(peak),
            tag_ids=tag_ids, remote=remote,
        )
        sessions.append(s)
    sessions.sort(key=lambda s: (-s.risk, s.start or ""))
    return sessions, links
