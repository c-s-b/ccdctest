<#
.SYNOPSIS
    Enables comprehensive audit logging for CCDC blue-team visibility.

.DESCRIPTION
    Turns on all critical Windows audit policies, PowerShell logging,
    process creation logging, firewall logging, and more. Outputs a
    summary of all log file paths and Event Log channels to monitor.

.PARAMETER TranscriptPath
    Directory for PowerShell transcription logs. Default: C:\Logs\PSTranscripts

.PARAMETER FirewallLogPath
    Path for Windows Firewall log. Default: C:\Logs\Firewall\pfirewall.log

.PARAMETER WhatIf
    Preview changes without applying.

.EXAMPLE
    .\Enable-AllLogging.ps1 -WhatIf
    .\Enable-AllLogging.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TranscriptPath  = "C:\Logs\PSTranscripts",
    [string]$FirewallLogPath = "C:\Logs\Firewall\pfirewall.log"
)

# ── Require elevation ──────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator." -ForegroundColor Red
    exit 1
}

# Track all log locations for the final summary
$logLocations = @()

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
Write-Host "  CCDC Comprehensive Logging Enablement" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════
# 1. ADVANCED AUDIT POLICY (auditpol) — Success and Failure for everything
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "── 1. Advanced Audit Policies (auditpol) ──" -ForegroundColor White

$auditCategories = @(
    # Account Logon
    "Credential Validation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "Other Account Logon Events",

    # Account Management
    "Application Group Management",
    "Computer Account Management",
    "Distribution Group Management",
    "Other Account Management Events",
    "Security Group Management",
    "User Account Management",

    # Detailed Tracking
    "DPAPI Activity",
    "PNP Activity",
    "Process Creation",
    "Process Termination",
    "RPC Events",
    "Token Right Adjusted",

    # DS Access
    "Detailed Directory Service Replication",
    "Directory Service Access",
    "Directory Service Changes",
    "Directory Service Replication",

    # Logon/Logoff
    "Account Lockout",
    "Group Membership",
    "IPsec Extended Mode",
    "IPsec Main Mode",
    "IPsec Quick Mode",
    "Logoff",
    "Logon",
    "Network Policy Server",
    "Other Logon/Logoff Events",
    "Special Logon",
    "User / Device Claims",

    # Object Access
    "Application Generated",
    "Certification Services",
    "Detailed File Share",
    "File Share",
    "File System",
    "Filtering Platform Connection",
    "Filtering Platform Packet Drop",
    "Handle Manipulation",
    "Kernel Object",
    "Other Object Access Events",
    "Registry",
    "Removable Storage",
    "SAM",
    "Central Policy Staging",

    # Policy Change
    "Audit Policy Change",
    "Authentication Policy Change",
    "Authorization Policy Change",
    "Filtering Platform Policy Change",
    "MPSSVC Rule-Level Policy Change",
    "Other Policy Change Events",

    # Privilege Use
    "Non Sensitive Privilege Use",
    "Other Privilege Use Events",
    "Sensitive Privilege Use",

    # System
    "IPsec Driver",
    "Other System Events",
    "Security State Change",
    "Security System Extension",
    "System Integrity"
)

foreach ($cat in $auditCategories) {
    if ($PSCmdlet.ShouldProcess($cat, "Enable Success+Failure auditing")) {
        $result = & auditpol /set /subcategory:"$cat" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status "$cat → Success+Failure" "SET"
        } else {
            Write-Status "$cat → Failed: $result" "WARN"
        }
    } else {
        Write-Status "$cat → WOULD enable Success+Failure" "WARN"
    }
}

$logLocations += [PSCustomObject]@{
    Source = "Audit Policies"
    Type   = "Event Log"
    Path   = "Event Viewer → Windows Logs → Security"
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. INCREASE SECURITY LOG SIZE
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 2. Event Log Sizes ──" -ForegroundColor White

$eventLogs = @(
    @{ Name = "Security";                       MaxSizeMB = 1024 },
    @{ Name = "System";                         MaxSizeMB = 256  },
    @{ Name = "Application";                    MaxSizeMB = 256  },
    @{ Name = "Microsoft-Windows-PowerShell/Operational";   MaxSizeMB = 512  },
    @{ Name = "Microsoft-Windows-Sysmon/Operational";       MaxSizeMB = 512  },
    @{ Name = "Microsoft-Windows-TaskScheduler/Operational"; MaxSizeMB = 128  },
    @{ Name = "Microsoft-Windows-WMI-Activity/Operational";  MaxSizeMB = 128  },
    @{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; MaxSizeMB = 128 },
    @{ Name = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"; MaxSizeMB = 128 }
)

foreach ($log in $eventLogs) {
    $maxBytes = $log.MaxSizeMB * 1MB
    if ($PSCmdlet.ShouldProcess($log.Name, "Set max size to $($log.MaxSizeMB) MB")) {
        try {
            wevtutil sl $log.Name /ms:$maxBytes 2>$null
            Write-Status "$($log.Name) → $($log.MaxSizeMB) MB" "SET"
        } catch {
            Write-Status "$($log.Name) — may not exist on this system" "WARN"
        }
    }
    $logLocations += [PSCustomObject]@{
        Source = $log.Name
        Type   = "Event Log"
        Path   = "Event Viewer → $($log.Name)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# 3. POWERSHELL SCRIPT BLOCK LOGGING
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 3. PowerShell Script Block Logging ──" -ForegroundColor White

$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if ($PSCmdlet.ShouldProcess("ScriptBlockLogging", "Enable")) {
    New-Item -Path $psLogPath -Force | Out-Null
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
    Write-Status "PowerShell Script Block Logging → Enabled" "SET"
}

$logLocations += [PSCustomObject]@{
    Source = "PS Script Block Logging"
    Type   = "Event Log"
    Path   = "Event Viewer → Applications and Services → Microsoft → Windows → PowerShell → Operational (Event ID 4104)"
}

# ═══════════════════════════════════════════════════════════════════════════
# 4. POWERSHELL MODULE LOGGING
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 4. PowerShell Module Logging ──" -ForegroundColor White

$psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$psModNames = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if ($PSCmdlet.ShouldProcess("ModuleLogging", "Enable for all modules")) {
    New-Item -Path $psModPath -Force | Out-Null
    Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    New-Item -Path $psModNames -Force | Out-Null
    Set-ItemProperty -Path $psModNames -Name "*" -Value "*" -Type String -Force
    Write-Status "PowerShell Module Logging → Enabled (all modules)" "SET"
}

$logLocations += [PSCustomObject]@{
    Source = "PS Module Logging"
    Type   = "Event Log"
    Path   = "Event Viewer → Applications and Services → Microsoft → Windows → PowerShell → Operational (Event ID 4103)"
}

# ═══════════════════════════════════════════════════════════════════════════
# 5. POWERSHELL TRANSCRIPTION
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 5. PowerShell Transcription ──" -ForegroundColor White

$psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if ($PSCmdlet.ShouldProcess("Transcription", "Enable to $TranscriptPath")) {
    New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
    New-Item -Path $psTransPath -Force | Out-Null
    Set-ItemProperty -Path $psTransPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $psTransPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $psTransPath -Name "OutputDirectory" -Value $TranscriptPath -Type String -Force
    Write-Status "PowerShell Transcription → $TranscriptPath" "SET"
}

$logLocations += [PSCustomObject]@{
    Source = "PS Transcription"
    Type   = "File"
    Path   = $TranscriptPath
}

# ═══════════════════════════════════════════════════════════════════════════
# 6. COMMAND LINE IN PROCESS CREATION EVENTS
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 6. Command Line Process Auditing ──" -ForegroundColor White

$cmdLinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if ($PSCmdlet.ShouldProcess("ProcessCreationIncludeCmdLine", "Enable")) {
    New-Item -Path $cmdLinePath -Force | Out-Null
    Set-ItemProperty -Path $cmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-Status "Command line in process creation events (4688) → Enabled" "SET"
}

$logLocations += [PSCustomObject]@{
    Source = "Process Cmd Line"
    Type   = "Event Log"
    Path   = "Security Log → Event ID 4688 (now includes full command line)"
}

# ═══════════════════════════════════════════════════════════════════════════
# 7. WINDOWS FIREWALL LOGGING
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 7. Windows Firewall Logging ──" -ForegroundColor White

$fwLogDir = Split-Path $FirewallLogPath -Parent
if ($PSCmdlet.ShouldProcess("Firewall", "Enable logging to $FirewallLogPath")) {
    New-Item -Path $fwLogDir -ItemType Directory -Force | Out-Null

    $profiles = @("Domain", "Private", "Public")
    foreach ($profile in $profiles) {
        & netsh advfirewall set $profile logging filename $FirewallLogPath 2>$null
        & netsh advfirewall set $profile logging maxfilesize 32768 2>$null
        & netsh advfirewall set $profile logging droppedconnections enable 2>$null
        & netsh advfirewall set $profile logging allowedconnections enable 2>$null
        Write-Status "Firewall $profile profile → log drops + allows" "SET"
    }
}

$logLocations += [PSCustomObject]@{
    Source = "Firewall Log"
    Type   = "File"
    Path   = $FirewallLogPath
}

# ═══════════════════════════════════════════════════════════════════════════
# 8. NTLM AUDITING
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 8. NTLM Auditing ──" -ForegroundColor White

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ($PSCmdlet.ShouldProcess("NTLM Audit", "Enable")) {
    # Audit all NTLM auth in this domain
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord -Force
    # Audit all NTLM auth to remote servers
    Set-ItemProperty -Path $lsaPath `
        -Name "AuditExternalNTLMTraffic" -Value 2 -Type DWord -Force
    # Restrict NTLM: audit all
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -Name "AuditNTLMInDomain" -Value 7 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Status "NTLM Auditing → Audit all incoming + outgoing NTLM" "SET"
}

$logLocations += [PSCustomObject]@{
    Source = "NTLM Auditing"
    Type   = "Event Log"
    Path   = "Event Viewer → Applications and Services → Microsoft → Windows → NTLM → Operational (Event IDs 8001-8004)"
}

# ═══════════════════════════════════════════════════════════════════════════
# 9. TASK SCHEDULER HISTORY
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 9. Task Scheduler Logging ──" -ForegroundColor White

if ($PSCmdlet.ShouldProcess("TaskScheduler", "Enable history")) {
    try {
        wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true 2>$null
        Write-Status "Task Scheduler operational log → Enabled" "SET"
    } catch {
        Write-Status "Task Scheduler log — could not enable" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# 10. WINDOWS DEFENDER / ANTIMALWARE LOGGING
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 10. Windows Defender Logging ──" -ForegroundColor White

if ($PSCmdlet.ShouldProcess("Defender", "Enable enhanced logging")) {
    try {
        wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /e:true /ms:268435456 2>$null
        Write-Status "Defender Operational log → Enabled (256 MB)" "SET"
    } catch {
        Write-Status "Defender log — may not exist" "WARN"
    }
}

$logLocations += [PSCustomObject]@{
    Source = "Windows Defender"
    Type   = "Event Log"
    Path   = "Event Viewer → Applications and Services → Microsoft → Windows → Windows Defender → Operational"
}

# ═══════════════════════════════════════════════════════════════════════════
# 11. DNS SERVER ANALYTICAL LOG (if DC with DNS)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 11. DNS Server Logging ──" -ForegroundColor White

$dnsLogExists = wevtutil el 2>$null | Select-String "DNS-Server"
if ($dnsLogExists) {
    if ($PSCmdlet.ShouldProcess("DNS Server", "Enable audit logging")) {
        try {
            wevtutil sl "Microsoft-Windows-DNSServer/Audit" /e:true /ms:134217728 2>$null
            Write-Status "DNS Server Audit log → Enabled (128 MB)" "SET"
            $logLocations += [PSCustomObject]@{
                Source = "DNS Server Audit"
                Type   = "Event Log"
                Path   = "Event Viewer → Applications and Services → Microsoft → Windows → DNS-Server → Audit"
            }
        } catch {
            Write-Status "DNS Server audit log — could not enable" "WARN"
        }
    }
} else {
    Write-Status "DNS Server role not detected — skipping" "INFO"
}

# ═══════════════════════════════════════════════════════════════════════════
# 12. LDAP DIAGNOSTICS (if DC)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 12. LDAP Interface Diagnostics ──" -ForegroundColor White

$ntdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
if (Test-Path $ntdsPath) {
    if ($PSCmdlet.ShouldProcess("NTDS Diagnostics", "Enable LDAP interface events")) {
        Set-ItemProperty -Path $ntdsPath -Name "16 LDAP Interface Events" -Value 2 -Type DWord -Force
        Write-Status "LDAP Interface Events → Level 2 (Event ID 2889 for insecure binds)" "SET"
        $logLocations += [PSCustomObject]@{
            Source = "LDAP Bind Audit"
            Type   = "Event Log"
            Path   = "Event Viewer → Directory Service (Event ID 2889)"
        }
    }
} else {
    Write-Status "NTDS not found — not a Domain Controller, skipping" "INFO"
}

# ═══════════════════════════════════════════════════════════════════════════
# 13. WMI ACTIVITY LOG
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "── 13. WMI Activity Logging ──" -ForegroundColor White

if ($PSCmdlet.ShouldProcess("WMI-Activity", "Enable operational log")) {
    try {
        wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /e:true 2>$null
        Write-Status "WMI Activity Operational log → Enabled" "SET"
    } catch {
        Write-Status "WMI Activity log — could not enable" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY — ALL LOG LOCATIONS
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  LOG LOCATIONS SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$logLocations | Format-Table -Property Source, Type, Path -AutoSize -Wrap

# Also export to file
$summaryPath = "C:\Logs\LogLocations.txt"
New-Item -Path (Split-Path $summaryPath) -ItemType Directory -Force | Out-Null
$logLocations | Format-Table -Property Source, Type, Path -AutoSize -Wrap | Out-String | Out-File $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KEY EVENT IDs TO MONITOR" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4624  - Successful logon"                    -ForegroundColor Gray
Write-Host "  4625  - Failed logon"                        -ForegroundColor Gray
Write-Host "  4648  - Logon with explicit credentials"     -ForegroundColor Gray
Write-Host "  4672  - Special privileges assigned"         -ForegroundColor Gray
Write-Host "  4688  - Process creation (with cmd line)"    -ForegroundColor Gray
Write-Host "  4697  - Service installed"                   -ForegroundColor Gray
Write-Host "  4698  - Scheduled task created"              -ForegroundColor Gray
Write-Host "  4720  - User account created"                -ForegroundColor Gray
Write-Host "  4724  - Password reset attempted"            -ForegroundColor Gray
Write-Host "  4728  - Member added to security group"      -ForegroundColor Gray
Write-Host "  4732  - Member added to local group"         -ForegroundColor Gray
Write-Host "  4756  - Member added to universal group"     -ForegroundColor Gray
Write-Host "  4104  - PowerShell script block"             -ForegroundColor Gray
Write-Host "  2889  - Insecure LDAP bind"                  -ForegroundColor Gray
Write-Host "  8004  - NTLM auth blocked/audited"           -ForegroundColor Gray
Write-Host ""
Write-Host "  Summary saved to: $summaryPath" -ForegroundColor Cyan
Write-Host ""
