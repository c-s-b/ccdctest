<#
.SYNOPSIS
    CCDC Minute-Zero master script. Runs all hardening scripts in priority order.

.DESCRIPTION
    Executes the following in sequence:
      1. Reset all domain passwords
      2. Remove non-admins from admin groups
      3. Enable comprehensive logging
      4. Enable Kerberos AES256
      5. Apply safe GPO/URA hardening

    All scripts must be in the same directory as this file.
    Accepts -WhatIf to dry-run everything, and -SkipConfirm to suppress
    per-script confirmation prompts (auto-answers YES).

.PARAMETER Password
    Password for domain reset. Default: SecureccdcPass1!

.PARAMETER Scope
    "Local" or "Domain" for admin group cleanup. Default: Domain

.PARAMETER SkipConfirm
    Auto-confirm all prompts (no typing YES for each script).

.PARAMETER WhatIf
    Dry-run all scripts.

.EXAMPLE
    # Dry-run everything
    .\Minute-Zero.ps1 -WhatIf

    # Full send — no prompts
    .\Minute-Zero.ps1 -SkipConfirm

    # Custom password, local scope only
    .\Minute-Zero.ps1 -Password "Comp2026!" -Scope Local -SkipConfirm
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Password    = "SecureccdcPass1!",
    [ValidateSet("Local", "Domain")]
    [string]$Scope       = "Domain",
    [switch]$SkipConfirm
)

# ── Require elevation ──────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$totalStart = Get-Date

# ── Banner ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║              CCDC MINUTE-ZERO HARDENING                     ║" -ForegroundColor Red
Write-Host "║          Locking down in priority order...                  ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

if (-not $SkipConfirm -and -not $WhatIfPreference) {
    Write-Host "This will:" -ForegroundColor Yellow
    Write-Host "  1. Reset ALL domain passwords to: $Password" -ForegroundColor Yellow
    Write-Host "  2. Remove all non-admin users from admin groups ($Scope)" -ForegroundColor Yellow
    Write-Host "  3. Enable comprehensive audit logging" -ForegroundColor Yellow
    Write-Host "  4. Enforce Kerberos AES256 on all accounts" -ForegroundColor Yellow
    Write-Host "  5. Apply safe GPO/URA hardening" -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Type YES to begin"
    if ($confirm -ne "YES") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# ── Helper: run a child script ─────────────────────────────────────────────
function Invoke-Phase {
    param(
        [int]$Number,
        [string]$Name,
        [string]$Script,
        [hashtable]$Params = @{}
    )

    $scriptPath = Join-Path $scriptDir $Script

    if (-not (Test-Path $scriptPath)) {
        Write-Host ""
        Write-Host "[$Number/5] SKIPPED: $Name" -ForegroundColor Red
        Write-Host "       File not found: $scriptPath" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " [$Number/5] $Name" -ForegroundColor Cyan
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $phaseStart = Get-Date

    # Build parameter splat
    $splat = @{}
    foreach ($key in $Params.Keys) {
        $splat[$key] = $Params[$key]
    }

    if ($WhatIfPreference) {
        $splat["WhatIf"] = $true
    }

    try {
        & $scriptPath @splat
    } catch {
        Write-Host "ERROR in $Name : $_" -ForegroundColor Red
    }

    $elapsed = (Get-Date) - $phaseStart
    Write-Host ""
    Write-Host " [$Number/5] $Name completed in $($elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: RESET ALL DOMAIN PASSWORDS
# ═══════════════════════════════════════════════════════════════════════════

# If SkipConfirm, pipe YES into the script's own confirmation prompt
if ($SkipConfirm -and -not $WhatIfPreference) {
    $env:CCDC_AUTO_CONFIRM = "YES"
}

# For the password reset script, we need to handle its Read-Host prompt.
# We'll call it with -Confirm:$false and feed input if needed.
$phase1Script = Join-Path $scriptDir "Reset-DomainPasswords.ps1"
if (Test-Path $phase1Script) {
    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " [1/5] RESET ALL DOMAIN PASSWORDS" -ForegroundColor Cyan
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $p1Start = Get-Date
    $p1Params = @{ Password = $Password; ExcludeUsers = @("krbtgt") }
    if ($WhatIfPreference) { $p1Params["WhatIf"] = $true }

    if ($SkipConfirm -and -not $WhatIfPreference) {
        # Temporarily override Read-Host to auto-confirm
        $funcOverride = 'function Read-Host { return "YES" }'
        $scriptContent = Get-Content $phase1Script -Raw
        $wrappedScript = "$funcOverride`n$scriptContent"
        $sb = [ScriptBlock]::Create($wrappedScript)
        & {
            param($Params)
            foreach ($key in $Params.Keys) {
                Set-Variable -Name $key -Value $Params[$key]
            }
            . $sb
        } -Params $p1Params
    } else {
        & $phase1Script @p1Params
    }

    $p1Elapsed = (Get-Date) - $p1Start
    Write-Host ""
    Write-Host " [1/5] Password Reset completed in $($p1Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
} else {
    Write-Host "[1/5] SKIPPED: Reset-DomainPasswords.ps1 not found" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: REMOVE NON-ADMINS FROM ADMIN GROUPS
# ═══════════════════════════════════════════════════════════════════════════
$phase2Script = Join-Path $scriptDir "Remove-NonAdminUsers.ps1"
if (Test-Path $phase2Script) {
    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " [2/5] REMOVE NON-ADMINS FROM ADMIN GROUPS" -ForegroundColor Cyan
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $p2Start = Get-Date
    $p2Params = @{ Scope = $Scope }
    if ($WhatIfPreference) { $p2Params["WhatIf"] = $true }

    if ($SkipConfirm -and -not $WhatIfPreference) {
        $funcOverride = 'function Read-Host { return "YES" }'
        $scriptContent = Get-Content $phase2Script -Raw
        $wrappedScript = "$funcOverride`n$scriptContent"
        $sb = [ScriptBlock]::Create($wrappedScript)
        & {
            param($Params)
            foreach ($key in $Params.Keys) {
                Set-Variable -Name $key -Value $Params[$key]
            }
            . $sb
        } -Params $p2Params
    } else {
        & $phase2Script @p2Params
    }

    $p2Elapsed = (Get-Date) - $p2Start
    Write-Host ""
    Write-Host " [2/5] Admin Group Cleanup completed in $($p2Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
} else {
    Write-Host "[2/5] SKIPPED: Remove-NonAdminUsers.ps1 not found" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: ENABLE ALL LOGGING
# ═══════════════════════════════════════════════════════════════════════════
$phase3Script = Join-Path $scriptDir "Enable-AllLogging.ps1"
if (Test-Path $phase3Script) {
    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " [3/5] ENABLE COMPREHENSIVE LOGGING" -ForegroundColor Cyan
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $p3Start = Get-Date
    $p3Params = @{}
    if ($WhatIfPreference) { $p3Params["WhatIf"] = $true }

    & $phase3Script @p3Params

    $p3Elapsed = (Get-Date) - $p3Start
    Write-Host ""
    Write-Host " [3/5] Logging completed in $($p3Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
} else {
    Write-Host "[3/5] SKIPPED: Enable-AllLogging.ps1 not found" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: KERBEROS AES256
# ═══════════════════════════════════════════════════════════════════════════
$phase4Script = Join-Path $scriptDir "Enable-KerberosAES256.ps1"
if (Test-Path $phase4Script) {
    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " [4/5] ENABLE KERBEROS AES256" -ForegroundColor Cyan
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $p4Start = Get-Date
    $p4Params = @{}
    if ($WhatIfPreference) { $p4Params["WhatIf"] = $true }

    if ($SkipConfirm -and -not $WhatIfPreference) {
        $funcOverride = 'function Read-Host { return "YES" }'
        $scriptContent = Get-Content $phase4Script -Raw
        $wrappedScript = "$funcOverride`n$scriptContent"
        $sb = [ScriptBlock]::Create($wrappedScript)
        & $sb
    } else {
        & $phase4Script @p4Params
    }

    $p4Elapsed = (Get-Date) - $p4Start
    Write-Host ""
    Write-Host " [4/5] Kerberos AES256 completed in $($p4Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
} else {
    Write-Host "[4/5] SKIPPED: Enable-KerberosAES256.ps1 not found" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: SAFE GPO / URA HARDENING
# ═══════════════════════════════════════════════════════════════════════════
$phase5Script = Join-Path $scriptDir "Harden-SafeGPO.ps1"
if (Test-Path $phase5Script) {
    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " [5/5] SAFE GPO & URA HARDENING" -ForegroundColor Cyan
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $p5Start = Get-Date
    $p5Params = @{}
    if ($WhatIfPreference) { $p5Params["WhatIf"] = $true }

    & $phase5Script @p5Params

    $p5Elapsed = (Get-Date) - $p5Start
    Write-Host ""
    Write-Host " [5/5] GPO Hardening completed in $($p5Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
} else {
    Write-Host "[5/5] SKIPPED: Harden-SafeGPO.ps1 not found" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
$totalElapsed = (Get-Date) - $totalStart

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              MINUTE-ZERO HARDENING COMPLETE                 ║" -ForegroundColor Green
Write-Host "║          Total time: $($totalElapsed.TotalSeconds.ToString('F1'))s                                     ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  What was done:" -ForegroundColor Gray
Write-Host "    [1] All domain passwords → $Password" -ForegroundColor Gray
Write-Host "    [2] Admin groups cleaned ($Scope)" -ForegroundColor Gray
Write-Host "    [3] Full audit logging enabled" -ForegroundColor Gray
Write-Host "    [4] Kerberos AES256 enforced" -ForegroundColor Gray
Write-Host "    [5] Safe GPO/URA hardening applied" -ForegroundColor Gray
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    - Run 'gpresult /r' to check for conflicting domain GPOs" -ForegroundColor Yellow
Write-Host "    - Verify scored services still work" -ForegroundColor Yellow
Write-Host "    - Check Event Viewer for red team activity" -ForegroundColor Yellow
Write-Host "    - Run this on EVERY domain-joined server" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Password roster: .\DomainPasswordRoster.csv" -ForegroundColor Cyan
Write-Host "  Log locations:   C:\Logs\LogLocations.txt" -ForegroundColor Cyan
Write-Host ""
