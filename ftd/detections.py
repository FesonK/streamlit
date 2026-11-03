"""
detections.py — simple, explainable risk rules over ECS process fields.

Every rule returns a Finding (rule id, points, plain-English why). A process's
risk score is the sum of its findings, capped at 100. Rules are intentionally
readable so you can tune them, not a replacement for a real detection engine.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
LOLBINS = {"certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
           "msiexec.exe", "installutil.exe", "wmic.exe"}
PROXY_EXEC = {"rundll32.exe", "regsvr32.exe", "mshta.exe"}
RECON = {"whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "ipconfig.exe",
         "quser.exe", "tasklist.exe", "arp.exe"}
SYSTEM_PATHS = {
    "svchost.exe": r"c:\windows\system32\svchost.exe",
    "lsass.exe": r"c:\windows\system32\lsass.exe",
    "services.exe": r"c:\windows\system32\services.exe",
    "csrss.exe": r"c:\windows\system32\csrss.exe",
    "winlogon.exe": r"c:\windows\system32\winlogon.exe",
    "smss.exe": r"c:\windows\system32\smss.exe",
    "taskhostw.exe": r"c:\windows\system32\taskhostw.exe",
    "explorer.exe": r"c:\windows\explorer.exe",
}
USER_WRITABLE = (r"\appdata\local\temp", r"\users\public", r"\downloads", r"\windows\temp", r"\programdata")

_ENC = re.compile(r"\s-(?:e|ec|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I)
_HIDDEN = re.compile(r"\s-(?:w|win|window|windowstyle)\s+hidden", re.I)
_URL = re.compile(r"https?://", re.I)

# (text colour, background) per severity
SEVERITY_STYLE = {
    "critical": ("#DC2626", "#FEE2E2"),
    "high": ("#EA580C", "#FFEDD5"),
    "medium": ("#CA8A04", "#FEF9C3"),
    "low": ("#64748B", "#F1F5F9"),
    "none": ("#94A3B8", "#F8FAFC"),
}


@dataclass(frozen=True)
class Finding:
    rule: str
    points: int
    why: str


def severity(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def score_process(p: dict) -> list[Finding]:
    """Rules that only need the process itself and its direct parent."""
    name = (p.get("name") or "").lower()
    parent = (p.get("parent_name") or "").lower()
    exe = (p.get("executable") or "").lower()
    cmd = p.get("command_line") or ""
    lcmd = cmd.lower()
    out: list[Finding] = []

    if parent in OFFICE and name in SHELLS | LOLBINS:
        out.append(Finding("office_spawned_shell", 45,
                           f"{parent} started {name}. Office apps almost never launch shells — classic malicious-macro behaviour."))
    if name in OFFICE and r"\content.outlook" in lcmd:
        out.append(Finding("opened_from_email", 10, "Document opened straight from Outlook's attachment cache."))
    if name in {"powershell.exe", "pwsh.exe"} and _ENC.search(f" {cmd} "):
        out.append(Finding("encoded_powershell", 35, "PowerShell ran a Base64-encoded command, which hides what it really does."))
    if name in {"powershell.exe", "pwsh.exe"} and _HIDDEN.search(f" {cmd}"):
        out.append(Finding("hidden_window", 10, "PowerShell asked for a hidden window."))
    if name in LOLBINS and _URL.search(cmd):
        out.append(Finding("lolbin_download", 30, f"{name} was handed a URL — a built-in Windows tool used as a downloader."))
    if name in LOLBINS and any(d in lcmd for d in USER_WRITABLE):
        out.append(Finding("lolbin_user_path", 20, f"{name} touched a file in a user-writable folder (Temp/Public/Downloads)."))
    if parent in PROXY_EXEC and (name in SHELLS or name in LOLBINS):
        out.append(Finding("proxy_spawned_shell", 30, f"{parent} spawned {name} — DLL/script hosts shouldn't start shells."))
    expected = SYSTEM_PATHS.get(name)
    if expected and exe and exe != expected:
        out.append(Finding("masquerading", 50,
                           f"Named like a Windows system binary but runs from {p.get('executable')} (expected {expected})."))
    if any(d in exe for d in USER_WRITABLE):
        out.append(Finding("runs_from_user_writable", 20, "The executable itself lives in a user-writable folder."))
    trusted = p.get("trusted")
    if trusted is not None and trusted == False:  # noqa: E712  (None/NaN = unknown, don't flag)
        out.append(Finding("unsigned", 10, "Binary has no trusted code signature."))
    return out


def context_findings(p: dict, ancestors: list[dict]) -> list[Finding]:
    """Rules that need the lineage. `ancestors` carry a precomputed base_score."""
    if (p.get("name") or "").lower() in RECON and any(a.get("base_score", 0) >= 30 for a in ancestors):
        return [Finding("recon_in_suspicious_chain", 15,
                        f"{p['name']} ran underneath an already-suspicious process — looks like hands-on-keyboard recon.")]
    return []


def decode_powershell(cmd: str) -> str | None:
    """Decode a PowerShell -EncodedCommand payload (UTF-16LE Base64), if present."""
    m = _ENC.search(f" {cmd or ''} ")
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except Exception:
        return None
