"""
corpus.py — realistic *clean* PowerShell that normal admins and developers type.

This is the raw material for two things:
  1. the benign background traffic in the mock data, and
  2. training the obfuscation score — which learns *form* (is this written to
     hide what it is?), not *intent*. So we train on clean scripts in two
     forms: plain (label 0) and machine-obfuscated (label 1). No attack code
     is needed for that, and none is kept here.

The handful of malicious demo scripts used by the planted incidents live in
mock_responses.py as a small, fixed set, kept deliberately generic.
"""

# PowerShell itself emits these in almost every session — fleet-wide noise.
NOISE = [
    'function prompt { "PS $($executionContext.SessionState.Path.CurrentLocation)> " }',
    "Import-LocalizedData LocalizedData -filename ArchiveResources",
    "Set-StrictMode -Version 1",
    "Set-PSReadLineOption -PredictionSource History",
    "$ExecutionContext.SessionState.LanguageMode",
    "Get-Command -Module Microsoft.PowerShell.Management | Out-Null",
]

# Everyday IT / office automation.
ADMIN = [
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
    "Get-ChildItem -Path C:\\Logs -Recurse -Filter *.log | Where-Object Length -gt 1MB",
    "Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName",
    "Get-EventLog -LogName System -Newest 50 | Where-Object EntryType -eq 'Error'",
    "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}}",
    "Restart-Service -Name Spooler -Verbose",
    "Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName, TaskPath",
    "Test-Connection -ComputerName fs01.contoso.local -Count 2",
    "$cred = Get-Credential; Enter-PSSession -ComputerName dc01 -Credential $cred",
    "Copy-Item -Path '\\\\fs01\\share\\report.xlsx' -Destination $env:USERPROFILE\\Documents",
    "Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate | Select-Object Name, LastLogonDate",
    "Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture",
    "Export-Csv -Path C:\\temp\\services.csv -NoTypeInformation -InputObject (Get-Service)",
    "Invoke-WebRequest -Uri 'https://intranet.contoso.local/api/health' -UseBasicParsing | Select-Object StatusCode",
    "New-Item -ItemType Directory -Path C:\\temp\\build -Force | Out-Null",
    "Get-Content .\\servers.txt | ForEach-Object { Test-NetConnection $_ -Port 443 }",
    "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name Wallpaper -Value C:\\brand\\bg.jpg",
    "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object NotAfter -lt (Get-Date).AddDays(30)",
]

# Developer / build-pipeline PowerShell.
DEV = [
    "dotnet build .\\Contoso.Platform.sln -c Release",
    "git status; git fetch --prune; git log --oneline -n 20",
    "npm ci; npm run build",
    "$env:PATH += ';C:\\tools'; python -m pytest tests -q",
    "Invoke-Pester -Path .\\tests -Output Detailed",
    "Measure-Command { Get-ChildItem -Recurse C:\\src | Measure-Object }",
    "Compress-Archive -Path .\\dist\\* -DestinationPath .\\artifacts\\build.zip -Force",
    "Get-Content package.json | ConvertFrom-Json | Select-Object name, version",
    "$files = Get-ChildItem -Recurse -Filter *.cs; \"$($files.Count) source files\"",
    "foreach ($p in 3000..3005) { Test-NetConnection localhost -Port $p -WarningAction SilentlyContinue }",
]

# Longer, multi-line but legitimate — tests that the score doesn't just react to length.
LONG_CLEAN = [
    """$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
foreach ($d in $disks) {
    $pct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
    "{0}  {1,5:N1}% free ({2:N0} GB of {3:N0} GB)" -f $d.DeviceID, $pct, ($d.FreeSpace/1GB), ($d.Size/1GB)
}""",
    """$results = foreach ($name in (Get-Content .\\servers.txt)) {
    $ok = Test-Connection -ComputerName $name -Count 1 -Quiet
    [pscustomobject]@{ Server = $name; Online = $ok; Checked = Get-Date }
}
$results | Export-Csv -Path C:\\reports\\uptime.csv -NoTypeInformation""",
    """try {
    $svc = Get-Service -Name 'W3SVC' -ErrorAction Stop
    if ($svc.Status -ne 'Running') { Start-Service $svc; Write-Host 'Started IIS' }
} catch {
    Write-Warning "W3SVC not found: $($_.Exception.Message)"
}""",
]

CLEAN_ALL = NOISE + ADMIN + DEV + LONG_CLEAN


def clean_samples() -> list[str]:
    return list(CLEAN_ALL)
