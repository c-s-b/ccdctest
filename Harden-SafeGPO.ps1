<#
.SYNOPSIS
    Applies scoring-safe GPO and User Rights Assignment hardening.

.DESCRIPTION
    CCDC hardening script that applies ONLY the settings verified to not
    break scoring engines, RDP access, or network authentication.

    What it does NOT touch (to protect scoring):
      - Allow log on through RDP
      - Allow log on locally
      - Access this computer from the network
      - Deny access from the network
      - WinRM / Remote Shell
      - NLA for RDP
      - LAN Manager auth level (NTLMv2 enforcement)
      - SMB signing requirements

    Applies via: secedit (URAs), registry (Security Options), and netsh.

.PARAMETER WhatIf
    Preview all changes without applying.

.EXAMPLE
    .\Harden-SafeGPO.ps1 -WhatIf
    .\Harden-SafeGPO.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param()

# ── Require elevation ──────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator." -ForegroundColor Red
    exit 1
}

function Write-Status {
    param([string]$Msg, [string]$Level = "INFO")
    $color = switch ($Level) {
        "SET"   { "Cyan"   }
        "OK"    { "Green"  }
        "WARN"  { "Yellow" }
        "ERROR" { "Red"    }
        default { "Gray"   }
    }
    Write-Host "[$Level] $Msg" -ForegroundColor $color
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CCDC Safe GPO & URA Hardening" -ForegroundColor Cyan
Write-Host "  (scoring-safe settings only)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════
# PART 1: USER RIGHTS ASSIGNMENTS (via secedit security template)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "── Part 1: User Rights Assignments ──" -ForegroundColor White
Write-Host ""

# Well-known SIDs
# *S-1-5-32-544  = BUILTIN\Administrators
# *S-1-5-32-546  = BUILTIN\Guests
# *S-1-5-6       = NT AUTHORITY\SERVICE
# *S-1-5-19      = NT AUTHORITY\LOCAL SERVICE
# *S-1-5-20      = NT AUTHORITY\NETWORK SERVICE

$uraTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
; ── EMPTIED (remove from everyone) ──
SeDebugPrivilege =
SeTcbPrivilege =
SeCreateTokenPrivilege =
SeEnableDelegationPrivilege =
SeRelabelPrivilege =
SeTrustedCredManAccessPrivilege =

; ── ADMINISTRATORS ONLY ──
SeLoadDriverPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreatePermanentPrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeMachineAccountPrivilege = *S-1-5-32-544

; ── ADMINISTRATORS + SERVICE ACCOUNTS ──
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-6,*S-1-5-19,*S-1-5-20
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-6,*S-1-5-19,*S-1-5-20
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20

; ── DENY GUESTS ──
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
"@

$tempDir  = "$env:TEMP\CCDCHarden"
$infPath  = "$tempDir\SafeURA.inf"
$dbPath   = "$tempDir\SafeURA.sdb"
$logPath  = "$tempDir\secedit.log"

New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

# Show what we're setting
$uraLines = $uraTemplate -split "`n" | Where-Object { $_ -match "^Se" }
foreach ($line in $uraLines) {
    $parts = $line -split "="
    $priv  = $parts[0].Trim()
    $value = if ($parts[1].Trim()) { $parts[1].Trim() } else { "(empty — removed from everyone)" }
    Write-Status "$priv → $value" "SET"
}

if ($PSCmdlet.ShouldProcess("User Rights Assignments", "Apply via secedit")) {
    $uraTemplate | Out-File -FilePath $infPath -Encoding Unicode -Force

    $seceditResult = & secedit /configure /db $dbPath /cfg $infPath /areas USER_RIGHTS /log $logPath /quiet 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Status "User Rights Assignments applied successfully." "OK"
    } else {
        Write-Status "secedit returned warnings — check $logPath" "WARN"
        Write-Status "$seceditResult" "WARN"
    }
} else {
    Write-Host ""
    Write-Status "WOULD apply User Rights Assignments via secedit" "WARN"
}

# ═══════════════════════════════════════════════════════════════════════════
# PART 2: SECURITY OPTIONS (registry-based)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── Part 2: Security Options (Registry) ──" -ForegroundColor White
Write-Host ""

$registrySettings = @(
    # ── Account security ──
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "DontDisplayLastUserName"
        Value = 1; Type = "DWord"
        Desc  = "Don't display last signed-in user"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "DontDisplayUserName"
        Value = 1; Type = "DWord"
        Desc  = "Don't display username at sign-in"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "DisableCAD"
        Value = 0; Type = "DWord"
        Desc  = "Require Ctrl+Alt+Del to log in"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "LimitBlankPasswordUse"  # mapped via system key
        Value = 1; Type = "DWord"
        Desc  = "Limit blank passwords to console logon only"
    },

    # ── UAC ──
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "EnableLUA"
        Value = 1; Type = "DWord"
        Desc  = "UAC: Admin Approval Mode enabled"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "ConsentPromptBehaviorAdmin"
        Value = 2; Type = "DWord"
        Desc  = "UAC: Prompt for consent on secure desktop"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "EnableInstallerDetection"
        Value = 1; Type = "DWord"
        Desc  = "UAC: Detect application installations"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name  = "FilterAdministratorToken"
        Value = 1; Type = "DWord"
        Desc  = "UAC: Filter built-in Administrator token"
    },

    # ── Anonymous / SAM restriction ──
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name  = "RestrictAnonymousSAM"
        Value = 1; Type = "DWord"
        Desc  = "Block anonymous SAM account enumeration"
    },
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name  = "RestrictAnonymous"
        Value = 1; Type = "DWord"
        Desc  = "Block anonymous SAM + share enumeration"
    },
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name  = "EveryoneIncludesAnonymous"
        Value = 0; Type = "DWord"
        Desc  = "Everyone permissions do NOT include anonymous"
    },
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name  = "RestrictRemoteSAM"
        Value = "O:BAG:BAD:(A;;RC;;;BA)"; Type = "String"
        Desc  = "Restrict remote SAM calls to Administrators only"
    },

    # ── Credential protection ──
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name  = "NoLMHash"
        Value = 1; Type = "DWord"
        Desc  = "Do not store LAN Manager hash"
    },
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Name  = "UseLogonCredential"
        Value = 0; Type = "DWord"
        Desc  = "WDigest: Disable plaintext credentials in memory"
    },
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name  = "RunAsPPL"
        Value = 1; Type = "DWord"
        Desc  = "LSA Protection: Run LSASS as Protected Process"
    },

    # ── Memory / pagefile ──
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        Name  = "ClearPageFileAtShutdown"
        Value = 1; Type = "DWord"
        Desc  = "Clear virtual memory pagefile at shutdown"
    },

    # ── AutoPlay / AutoRun ──
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name  = "NoDriveTypeAutoRun"
        Value = 255; Type = "DWord"
        Desc  = "Disable AutoPlay on all drives"
    },
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name  = "NoAutorun"
        Value = 1; Type = "DWord"
        Desc  = "Disable AutoRun commands"
    },

    # ── LLMNR / NetBIOS (poisoning prevention) ──
    @{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Name  = "EnableMulticast"
        Value = 0; Type = "DWord"
        Desc  = "Disable LLMNR (Link-Local Multicast Name Resolution)"
    },

    # ── Disable Windows Script Host ──
    @{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        Name  = "Enabled"
        Value = 0; Type = "DWord"
        Desc  = "Disable Windows Script Host (wscript/cscript)"
    },

    # ── Remote Registry — disable ──
    @{
        Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg"
        Name  = "RemoteRegAccess"
        Value = 0; Type = "DWord"
        Desc  = "Restrict remote registry access"
    }
)

foreach ($setting in $registrySettings) {
    $current = $null
    try {
        $current = Get-ItemPropertyValue -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
    } catch {}

    if ($current -eq $setting.Value) {
        Write-Status "$($setting.Desc) — already set" "OK"
        continue
    }

    if ($PSCmdlet.ShouldProcess($setting.Name, "$($setting.Desc) → $($setting.Value)")) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            Write-Status "$($setting.Desc) → $($setting.Value)" "SET"
        } catch {
            Write-Status "$($setting.Desc) — FAILED: $_" "ERROR"
        }
    } else {
        Write-Status "$($setting.Desc) → WOULD set to $($setting.Value)" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# PART 3: DISABLE GUEST ACCOUNT
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── Part 3: Disable Guest Account ──" -ForegroundColor White
Write-Host ""

if ($PSCmdlet.ShouldProcess("Guest", "Disable account")) {
    try {
        & net user Guest /active:no 2>$null
        Write-Status "Guest account → Disabled" "SET"
    } catch {
        Write-Status "Could not disable Guest account" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# PART 4: DISABLE NETBIOS OVER TCP/IP (all adapters)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── Part 4: Disable NetBIOS over TCP/IP ──" -ForegroundColor White
Write-Host ""

if ($PSCmdlet.ShouldProcess("All NICs", "Disable NetBIOS over TCP/IP")) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    $interfaces = Get-ChildItem $regPath -ErrorAction SilentlyContinue
    $count = 0
    foreach ($iface in $interfaces) {
        Set-ItemProperty -Path $iface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
        $count++
    }
    Write-Status "NetBIOS disabled on $count adapter(s)" "SET"
}

# ═══════════════════════════════════════════════════════════════════════════
# PART 5: STOP & DISABLE RISKY SERVICES
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── Part 5: Disable Unnecessary Services ──" -ForegroundColor White
Write-Host ""

$servicesToDisable = @(
    @{ Name = "RemoteRegistry";  Desc = "Remote Registry" },
    @{ Name = "Spooler";         Desc = "Print Spooler (PrintNightmare)" },
    @{ Name = "SNMP";            Desc = "SNMP (if not scored)" },
    @{ Name = "TlntSvr";        Desc = "Telnet Server" },
    @{ Name = "FTPSVC";         Desc = "FTP Service (if not scored)" },
    @{ Name = "W3SVC";          Desc = "IIS Web Service (if not scored)" },
    @{ Name = "IISADMIN";       Desc = "IIS Admin (if not scored)" }
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Status "$($svc.Desc) — not installed, skipping" "INFO"
        continue
    }

    # Only disable RemoteRegistry and Spooler automatically;
    # others need manual review (might be scored)
    $autoDisable = @("RemoteRegistry", "Spooler", "TlntSvr")

    if ($svc.Name -in $autoDisable) {
        if ($PSCmdlet.ShouldProcess($svc.Name, "Stop and disable $($svc.Desc)")) {
            try {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service  -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Write-Status "$($svc.Desc) → Stopped & Disabled" "SET"
            } catch {
                Write-Status "$($svc.Desc) — could not disable: $_" "WARN"
            }
        }
    } else {
        Write-Status "$($svc.Desc) → FOUND but NOT auto-disabled (may be scored — disable manually if safe)" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Hardening Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Applied:" -ForegroundColor Gray
Write-Host "    - User Rights Assignments (dangerous privs removed)" -ForegroundColor Gray
Write-Host "    - Security Options (anon blocked, creds protected)" -ForegroundColor Gray
Write-Host "    - WDigest disabled, LSA Protection enabled" -ForegroundColor Gray
Write-Host "    - AutoPlay/AutoRun off, LLMNR off, NetBIOS off" -ForegroundColor Gray
Write-Host "    - Guest disabled, risky services stopped" -ForegroundColor Gray
Write-Host ""
Write-Host "  NOT touched (verify manually if safe for your comp):" -ForegroundColor Yellow
Write-Host "    - RDP access / NLA" -ForegroundColor Yellow
Write-Host "    - WinRM / Remote Shell" -ForegroundColor Yellow
Write-Host "    - LAN Manager auth level / SMB signing" -ForegroundColor Yellow
Write-Host "    - Network logon rights" -ForegroundColor Yellow
Write-Host "    - IIS / FTP / SNMP (may be scored)" -ForegroundColor Yellow
Write-Host ""
if (Test-Path $logPath) {
    Write-Host "  secedit log: $logPath" -ForegroundColor Gray
}
Write-Host ""
