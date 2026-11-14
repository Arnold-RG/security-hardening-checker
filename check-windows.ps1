<#
.SYNOPSIS
    Read-only security hardening audit for Windows.

.DESCRIPTION
    check-windows.ps1 inspects common Windows security settings and prints
    PASS / WARN / FAIL / INFO results with a summary score:

      Firewall profiles, Microsoft Defender, UAC, SMBv1, Remote Desktop / NLA,
      Guest account, password & lockout policy (net accounts), Windows Update
      service, risky services, BitLocker on the system drive.

    The script NEVER changes a setting; it only reads cmdlets, the registry and
    `net accounts`. Run it from an elevated PowerShell for the most complete
    result (Defender, SMB, BitLocker and some policies need admin rights).

    Exit codes: 0 = all PASS, 1 = warnings only, 2 = at least one FAIL,
    3 = not running on Windows / usage error.

    Author : Arnold Rurangwa - MIT License

.PARAMETER ReportPath
    Also write the results to a file: .json gives JSON, anything else a text report.

.PARAMETER Quiet
    Only print WARN/FAIL lines and the summary.

.EXAMPLE
    .\check-windows.ps1

.EXAMPLE
    .\check-windows.ps1 -ReportPath .\hardening-report.json -Quiet

.NOTES
    Requirements: Windows 10/11 or Windows Server 2016+, Windows PowerShell 5.1
    or PowerShell 7+. Modules used when present: NetSecurity, Defender,
    SmbShare, BitLocker, Microsoft.PowerShell.LocalAccounts (all built in).
#>
[CmdletBinding()]
param(
    [string]$ReportPath,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Results = New-Object System.Collections.Generic.List[object]
$script:QuietMode = [bool]$Quiet

function Add-Result {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level,
        [string]$Category,
        [string]$Message
    )
    $script:Results.Add([pscustomobject]@{ Level = $Level; Category = $Category; Message = $Message })
    if (-not $script:QuietMode -or $Level -in 'WARN', 'FAIL') {
        $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
        Write-Host ('[{0,-4}] ' -f $Level) -ForegroundColor $color -NoNewline
        Write-Host ('{0,-10} {1}' -f $Category, $Message)
    }
}

function Write-Section([string]$Name) { if (-not $script:QuietMode) { Write-Host "`n== $Name ==" } }

# Read a registry value; returns $null when the key/value does not exist.
function Get-RegValue([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Test-Command([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# Parse `net accounts` text (English output) into a hashtable.
function ConvertFrom-NetAccount([string[]]$Lines) {
    $map = @{}
    foreach ($line in $Lines) {
        if ($line -match '^\s*([^:]+?):\s+(.+?)\s*$') { $map[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    return $map
}

# Score: PASS = 100, WARN = 50, FAIL = 0, averaged over scored checks.
function Get-Score($Items) {
    $scored = @($Items | Where-Object { $_.Level -ne 'INFO' })
    if ($scored.Count -eq 0) { return 0 }
    $points = 0
    foreach ($r in $scored) { if ($r.Level -eq 'PASS') { $points += 100 } elseif ($r.Level -eq 'WARN') { $points += 50 } }
    return [int][math]::Floor($points / $scored.Count)
}

# Allows the helper functions above to be dot-sourced by the tests on any OS.
if ($env:HARDENING_CHECKER_TEST -eq '1') { return }

if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
    Write-Error 'check-windows.ps1 audits Windows. On Linux use check-linux.sh.' -ErrorAction Continue
    exit 3
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue)
$osName = 'Windows'; if ($os) { $osName = "$($os.Caption) $($os.Version)" }
$adminNote = ''; if (-not $isAdmin) { $adminNote = ' (not elevated: some checks are limited)' }
Write-Host "Windows hardening audit - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Write-Host "$osName   Running as: $env:USERNAME$adminNote"

# ------------------------------------------------------------------------------
Write-Section 'Firewall'
if (Test-Command Get-NetFirewallProfile) {
    foreach ($p in Get-NetFirewallProfile) {
        if ($p.Enabled) { Add-Result PASS Firewall "$($p.Name) profile enabled (inbound default: $($p.DefaultInboundAction))" }
        else { Add-Result FAIL Firewall "$($p.Name) profile is DISABLED" }
    }
}
else {
    $text = (netsh advfirewall show allprofiles state) -join "`n"
    $off = ([regex]::Matches($text, 'State\s+OFF')).Count
    if ($off -eq 0) { Add-Result PASS Firewall 'All firewall profiles ON (netsh)' } else { Add-Result FAIL Firewall "$off firewall profile(s) OFF (netsh)" }
}

# ------------------------------------------------------------------------------
Write-Section 'Microsoft Defender'
if (Test-Command Get-MpComputerStatus) {
    try {
        $mp = Get-MpComputerStatus
        if ($mp.AntivirusEnabled) { Add-Result PASS Defender 'Antivirus enabled' } else { Add-Result FAIL Defender 'Antivirus disabled (or another AV is active - check it)' }
        if ($mp.RealTimeProtectionEnabled) { Add-Result PASS Defender 'Real-time protection on' } else { Add-Result FAIL Defender 'Real-time protection OFF' }
        if ($mp.AntivirusSignatureAge -le 7) { Add-Result PASS Defender "Signatures $($mp.AntivirusSignatureAge) day(s) old" }
        else { Add-Result WARN Defender "Signatures are $($mp.AntivirusSignatureAge) days old" }
    }
    catch { Add-Result INFO Defender "Defender status unavailable: $($_.Exception.Message)" }
}
else { Add-Result INFO Defender 'Defender module not present (third-party AV or Server Core?) - check AV manually' }

# ------------------------------------------------------------------------------
Write-Section 'User Account Control'
$sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lua = Get-RegValue $sysPol 'EnableLUA'
if ($lua -eq 0) { Add-Result FAIL UAC 'UAC is disabled (EnableLUA = 0)' } else { Add-Result PASS UAC 'UAC enabled' }
$consent = Get-RegValue $sysPol 'ConsentPromptBehaviorAdmin'
if ($consent -eq 0) { Add-Result WARN UAC 'Admins are elevated WITHOUT a prompt (ConsentPromptBehaviorAdmin = 0)' }
elseif ($null -ne $consent) { Add-Result PASS UAC "Admin elevation prompts (ConsentPromptBehaviorAdmin = $consent)" }
$secure = Get-RegValue $sysPol 'PromptOnSecureDesktop'
if ($secure -eq 0) { Add-Result WARN UAC 'UAC prompt not on the secure desktop' } else { Add-Result PASS UAC 'UAC prompt on the secure desktop' }

# ------------------------------------------------------------------------------
Write-Section 'SMBv1'
$smb1 = $null
if (Test-Command Get-SmbServerConfiguration) {
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
}
if ($null -eq $smb1) { $smb1 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' }
if ($smb1 -eq $true -or $smb1 -eq 1) { Add-Result FAIL SMB 'SMBv1 server protocol is ENABLED (WannaCry-era protocol)' }
elseif ($smb1 -eq $false -or $smb1 -eq 0) { Add-Result PASS SMB 'SMBv1 server protocol disabled' }
else { Add-Result INFO SMB 'Could not read SMBv1 state (run elevated)' }

$smb1Client = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
if ($null -ne $smb1Client -and $smb1Client -ne 4) { Add-Result WARN SMB 'SMBv1 client driver (mrxsmb10) is not disabled' }

# ------------------------------------------------------------------------------
Write-Section 'Remote Desktop'
$deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($deny -eq 1 -or $null -eq $deny) { Add-Result PASS RDP 'Remote Desktop is disabled' }
else {
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($nla -eq 1) { Add-Result WARN RDP 'Remote Desktop ENABLED (NLA required) - restrict it to trusted networks / VPN' }
    else { Add-Result FAIL RDP 'Remote Desktop ENABLED without Network Level Authentication' }
}

# ------------------------------------------------------------------------------
Write-Section 'Accounts and password policy'
if (Test-Command Get-LocalUser) {
    # The built-in Guest account always has a SID ending in -501, even if renamed.
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
    if ($guest -and $guest.Enabled) { Add-Result FAIL Accounts "Guest account '$($guest.Name)' is ENABLED" }
    elseif ($guest) { Add-Result PASS Accounts "Guest account '$($guest.Name)' disabled" }
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
    if ($admin -and $admin.Enabled) { Add-Result WARN Accounts "Built-in Administrator '$($admin.Name)' is enabled" }
}
else { Add-Result INFO Accounts 'Get-LocalUser unavailable - check the Guest account manually' }

$na = ConvertFrom-NetAccount (net accounts 2>$null)
if ($na.ContainsKey('Minimum password length')) {
    $min = [int]$na['Minimum password length']
    if ($min -ge 12) { Add-Result PASS Policy "Minimum password length $min" }
    elseif ($min -ge 8) { Add-Result WARN Policy "Minimum password length $min (12+ recommended)" }
    else { Add-Result FAIL Policy "Minimum password length $min" }

    $lock = $na['Lockout threshold']
    if ($lock -match '^\d+$' -and [int]$lock -gt 0 -and [int]$lock -le 10) { Add-Result PASS Policy "Account lockout after $lock bad attempts" }
    else { Add-Result WARN Policy "Account lockout threshold: $lock (set 5-10 to slow password guessing)" }

    Add-Result INFO Policy "Maximum password age: $($na['Maximum password age (days)'])"
}
else { Add-Result INFO Policy "Could not parse 'net accounts' (non-English Windows?) - run it manually" }

# ------------------------------------------------------------------------------
Write-Section 'Windows Update'
$wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if (-not $wu) { Add-Result WARN Updates 'Windows Update service (wuauserv) not found' }
elseif ($wu.StartType -eq 'Disabled') { Add-Result FAIL Updates 'Windows Update service is DISABLED' }
else { Add-Result PASS Updates "Windows Update service start type: $($wu.StartType)" }
$noAuto = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
if ($noAuto -eq 1) { Add-Result FAIL Updates 'Automatic updates turned off by policy (NoAutoUpdate = 1)' }

# ------------------------------------------------------------------------------
Write-Section 'Risky services'
$risky = [ordered]@{
    TlntSvr        = @('FAIL', 'Telnet server (clear-text logins)')
    ftpsvc         = @('WARN', 'IIS FTP server')
    RemoteRegistry = @('WARN', 'Remote Registry')
    SNMP           = @('WARN', 'SNMP service (often default community strings)')
    SSDPSRV        = @('INFO', 'SSDP discovery (UPnP)')
    upnphost       = @('WARN', 'UPnP device host')
    W3SVC          = @('INFO', 'IIS web server')
}
$found = 0
foreach ($name in $risky.Keys) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Add-Result $risky[$name][0] Services "$($risky[$name][1]) is running ($name)"
        if ($risky[$name][0] -ne 'INFO') { $found++ }
    }
}
if ($found -eq 0) { Add-Result PASS Services 'No high-risk services running (Telnet, FTP, Remote Registry, SNMP, UPnP host)' }

# ------------------------------------------------------------------------------
Write-Section 'BitLocker'
if ((Test-Command Get-BitLockerVolume) -and $isAdmin) {
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ("$($bl.ProtectionStatus)" -eq 'On') { Add-Result PASS BitLocker "$env:SystemDrive encrypted ($($bl.EncryptionMethod))" }
        else { Add-Result WARN BitLocker "$env:SystemDrive is not protected by BitLocker (status: $($bl.VolumeStatus))" }
    }
    catch { Add-Result INFO BitLocker "BitLocker status unavailable: $($_.Exception.Message)" }
}
elseif (-not $isAdmin) { Add-Result INFO BitLocker 'BitLocker check needs an elevated prompt' }
else { Add-Result INFO BitLocker 'BitLocker not available on this edition (Windows Home uses Device Encryption)' }

# ------------------------------------------------------------------------------
$pass = @($script:Results | Where-Object Level -eq 'PASS').Count
$warn = @($script:Results | Where-Object Level -eq 'WARN').Count
$fail = @($script:Results | Where-Object Level -eq 'FAIL').Count
$info = @($script:Results | Where-Object Level -eq 'INFO').Count
$score = Get-Score $script:Results
$summary = "Summary: $pass PASS, $warn WARN, $fail FAIL, $info INFO  ->  score $score/100"
Write-Host "`n$summary"
Write-Host '(Score: PASS = 100, WARN = 50, FAIL = 0 points, averaged; INFO lines are not scored.)'

if ($ReportPath) {
    if ($ReportPath -like '*.json') {
        [pscustomobject]@{
            Computer = $env:COMPUTERNAME; Date = (Get-Date).ToString('o'); Elevated = $isAdmin
            Score = $score; Pass = $pass; Warn = $warn; Fail = $fail; Info = $info; Results = $script:Results
        } | ConvertTo-Json -Depth 4 | Set-Content -Path $ReportPath -Encoding UTF8
    }
    else {
        $lines = $script:Results | ForEach-Object { '[{0,-4}] {1,-10} {2}' -f $_.Level, $_.Category, $_.Message }
        @("Windows hardening audit - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')") + $lines + @('', $summary) |
            Set-Content -Path $ReportPath -Encoding UTF8
    }
    Write-Host "Report written to $ReportPath"
}

if ($fail -gt 0) { exit 2 } elseif ($warn -gt 0) { exit 1 } else { exit 0 }
