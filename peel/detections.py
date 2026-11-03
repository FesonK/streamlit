"""
detections.py — explainable technique tags over (deobfuscated) PowerShell, the
command fingerprint used by Rare Command Radar, and the overall risk score.

Tags are plain substring/keyword rules applied to the PEELED text, so obfuscated
tradecraft gets caught after Peel undoes the disguise. Each tag carries its
MITRE ATT&CK technique id. This is a teaching/triage aid, not an EDR.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_STYLE = {
    "critical": ("#DC2626", "#FEE2E2"),
    "high": ("#EA580C", "#FFEDD5"),
    "medium": ("#CA8A04", "#FEF9C3"),
    "low": ("#2563EB", "#DBEAFE"),
    "info": ("#64748B", "#F1F5F9"),
    "none": ("#94A3B8", "#F8FAFC"),
}


@dataclass(frozen=True)
class Tag:
    id: str            # short slug
    label: str         # human name
    attck: str         # MITRE ATT&CK id
    points: int
    why: str


@dataclass
class Rule:
    id: str
    label: str
    attck: str
    points: int
    why: str
    any_of: tuple = ()          # lowercase substrings
    regex: tuple = ()           # regex patterns (searched case-insensitive)

    def match(self, low: str, raw: str):
        if any(s in low for s in self.any_of):
            return True
        return any(re.search(p, raw, re.I) for p in self.regex)


# Rules run against the peeled script text. Kept readable so you can tune them.
RULES = [
    Rule("download_cradle", "Download cradle", "T1059.001", 40,
         "Downloads code from the internet and runs it in memory.",
         any_of=("downloadstring", "downloaddata", "downloadfile", "net.webclient", "start-bitstransfer"),
         regex=(r"invoke-webrequest.*-outfile", r"invoke-restmethod.*\|\s*i?ex\b",
                r"\biwr\b.*-outfile", r"(?:iex|invoke-expression)\s*\(\s*(?:new-object|iwr|invoke-)")),
    Rule("inmemory_exec", "In-memory execution", "T1059.001", 20,
         "Runs text as code (Invoke-Expression / ScriptBlock::Create), the usual last step of a cradle.",
         any_of=("invoke-expression", "[scriptblock]::create", ".invoke(", "iex "),
         regex=(r"\|\s*iex\b",)),
    Rule("amsi_bypass", "AMSI tampering", "T1562.001", 45,
         "Disables Windows' in-memory script scanner (AMSI) so malicious code isn't inspected.",
         any_of=("amsiutils", "amsiinitfailed", "amsicontext", "amsiscanbuffer")),
    Rule("etw_bypass", "ETW tampering", "T1562.006", 40,
         "Blinds Event Tracing for Windows so later activity isn't logged.",
         any_of=("etweventwrite", "eventpipe"),
         regex=(r"\[.*tracing\.eventprovider\]",)),
    Rule("defender_tamper", "Defender tampering", "T1562.001", 45,
         "Turns off Microsoft Defender protections.",
         any_of=("disablerealtimemonitoring", "disablescriptscanning", "disablebehaviormonitoring",
                 "add-mppreference -exclusionpath", "set-mppreference", "disableioavprotection"),
         regex=(r"-exclusion(?:path|process|extension)",)),
    Rule("hidden_window", "Hidden / encoded launch", "T1564.003", 15,
         "Runs with a hidden window and/or a Base64-encoded command — hides activity from the user.",
         regex=(r"-w(?:in(?:dowstyle)?)?\s+hidden", r"-e(?:nc(?:odedcommand)?)?\s+[a-z0-9+/=]{20,}",
                r"-nop(?:rofile)?\b")),
    Rule("exec_policy", "Execution-policy bypass", "T1059.001", 10,
         "Bypasses the script execution policy.",
         regex=(r"-ep\s+bypass", r"-exec(?:utionpolicy)?\s+bypass", r"set-executionpolicy\s+(?:bypass|unrestricted)")),
    Rule("v2_downgrade", "PowerShell v2 downgrade", "T1059.001", 35,
         "Forces the old PowerShell v2 engine, which has no script-block logging and no AMSI.",
         regex=(r"-v(?:er(?:sion)?)?\s+2(?:\.0)?\b",)),
    Rule("cred_access", "Credential access", "T1003", 55,
         "Touches LSASS or well-known credential-dumping tooling.",
         any_of=("invoke-mimikatz", "sekurlsa", "lsadump", "mimikatz", "-ma lsass", "comsvcs.dll, minidump",
                 "get-credential | export"),
         regex=(r"lsass.*minidump", r"minidump.*lsass", r"procdump.*lsass")),
    Rule("persistence_task", "Persistence: scheduled task", "T1053.005", 30,
         "Installs a scheduled task to survive reboots.",
         any_of=("register-scheduledtask", "new-scheduledtaskaction"),
         regex=(r"schtasks\s+/create",)),
    Rule("persistence_run", "Persistence: Run key / startup", "T1547.001", 30,
         "Adds an autostart entry in the registry Run keys or Startup folder.",
         regex=(r"currentversion\\run", r"\\start menu\\programs\\startup")),
    Rule("persistence_wmi", "Persistence: WMI subscription", "T1546.003", 35,
         "Installs a WMI event subscription for stealthy persistence.",
         any_of=("__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding")),
    Rule("recon", "Discovery / recon", "T1087", 10,
         "Enumerates users, groups, domain or host details.",
         any_of=("get-aduser", "get-adgroupmember", "get-adcomputer", "get-netgroup", "get-domain"),
         regex=(r"\bwhoami\b", r"\bnet\s+(?:group|user|localgroup)\b", r"\bnltest\b", r"\bget-net\w+")),
    Rule("lateral_remote", "Lateral movement / remoting", "T1021.006", 35,
         "Runs commands on other machines over WinRM/WMI.",
         any_of=("enter-pssession", "new-pssession", "invoke-wmimethod"),
         regex=(r"invoke-command\s+.*-computername", r"wmic\s+/node:")),
    Rule("clear_logs", "Log clearing", "T1070.001", 40,
         "Deletes Windows event logs to cover tracks.",
         any_of=("clear-eventlog", "remove-eventlog"),
         regex=(r"wevtutil\s+cl\b", r"\.clear\(\)\s*$")),
    Rule("shellcode_alloc", "Shellcode / injection APIs", "T1055", 50,
         "Allocates executable memory or calls injection APIs from PowerShell.",
         any_of=("virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex",
                 "memcpy", "[reflection.assembly]::load(", "getdelegateforfunctionpointer")),
    Rule("encoded_payload", "Encoded payload blob", "T1027", 20,
         "Carries a large Base64 blob — often a packed payload.",
         regex=(r"frombase64string", r"[a-z0-9+/]{200,}={0,2}")),
]

# ATT&CK tactic for nicer grouping in the UI.
TACTIC = {
    "T1059.001": "Execution", "T1562.001": "Defense Evasion", "T1562.006": "Defense Evasion",
    "T1564.003": "Defense Evasion", "T1027": "Defense Evasion", "T1070.001": "Defense Evasion",
    "T1003": "Credential Access", "T1053.005": "Persistence", "T1547.001": "Persistence",
    "T1546.003": "Persistence", "T1087": "Discovery", "T1021.006": "Lateral Movement",
    "T1055": "Execution",
}


def tag(script: str) -> list[Tag]:
    """Technique tags for one peeled script (plus its command line if folded in)."""
    raw = script or ""
    low = raw.lower()
    out = []
    for r in RULES:
        if r.match(low, raw):
            out.append(Tag(r.id, r.label, r.attck, r.points, r.why))
    return out


def severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def risk_score(tags: list[Tag], obf_prob: float, extra: int = 0) -> int:
    """Combine technique points with the obfuscation probability.
    Obfuscation alone can't make something critical, but it amplifies real findings."""
    base = sum(t.points for t in tags) + extra
    obf_bonus = int(round(obf_prob * 25))
    # if there are real findings, obfuscation multiplies the concern a little
    mult = 1.0 + (0.4 * obf_prob if tags else 0.0)
    return max(0, min(100, int(round(base * mult)) + obf_bonus))


# ───────────────────────── command fingerprint (Rare Command Radar) ─────────────────────────
_SUBS = [
    (re.compile(r"[a-z]:\\\\[^\s'\"]+|\\\\\\\\[^\s'\"]+", re.I), "<path>"),
    (re.compile(r"https?://[^\s'\")]+", re.I), "<url>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<guid>"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "<b64>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\b\d+\b"), "<n>"),
    (re.compile(r"'[^']*'|\"[^\"]*\""), "<s>"),
    (re.compile(r"\$[A-Za-z_]\w*"), "$v"),
]


def fingerprint(script: str) -> str:
    """Normalize a script to its shape: paths, URLs, IPs, GUIDs, numbers, strings
    and variables replaced by placeholders, so variants of the same command collapse
    to one key. Used to find rare/first-seen commands across the fleet."""
    s = (script or "").strip().lower()
    for rx, rep in _SUBS:
        s = rx.sub(rep, s)
    s = re.sub(r"\s+", " ", s)
    return s[:300]
