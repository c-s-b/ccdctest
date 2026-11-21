<#
.SYNOPSIS
    Resets all domain user passwords to a known value and outputs a CSV roster.

.DESCRIPTION
    CCDC blue-team hardening script. Changes every domain user's password to
    the specified string, then prints a comma-separated list of each user and
    the new password for the team's records.

    Requires the ActiveDirectory PowerShell module (RSAT or run on a DC).

.PARAMETER Password
    The new password to set for all accounts. Defaults to SecureccdcPass1!

.PARAMETER ExcludeUsers
    Optional array of SamAccountNames to skip (e.g. krbtgt, service accounts).

.PARAMETER WhatIf
    Preview which accounts would be changed without modifying anything.

.PARAMETER OutFile
    Path to save the CSV roster. Defaults to .\DomainPasswordRoster.csv

.EXAMPLE
    # Dry-run — see who would be affected
    .\Reset-DomainPasswords.ps1 -WhatIf

    # Reset all passwords except krbtgt
    .\Reset-DomainPasswords.ps1 -ExcludeUsers @("krbtgt")

    # Reset with a custom password
    .\Reset-DomainPasswords.ps1 -Password "MyC0mp3t1t10n!"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Password = "SecureccdcPass1!",

    [string[]]$ExcludeUsers = @("krbtgt"),

    [string]$OutFile = ".\DomainPasswordRoster.csv"
)

# ── Require elevation ───────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Run this script as Administrator." -ForegroundColor Red
    exit 1
}

# ── Require AD module ──────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ERROR: ActiveDirectory module not found. Install RSAT or run on a DC." -ForegroundColor Red
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# ── Convert password to secure string ──────────────────────────────────────
$securePass = ConvertTo-SecureString -String $Password -AsPlainText -Force

# ── Get all domain users ───────────────────────────────────────────────────
$allUsers = Get-ADUser -Filter * -Properties SamAccountName, Enabled |
    Sort-Object SamAccountName

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  CCDC Domain Password Reset" -ForegroundColor Cyan
Write-Host "  Total accounts found: $($allUsers.Count)" -ForegroundColor Cyan
Write-Host "  Excluded accounts:    $($ExcludeUsers -join ', ')" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── Confirmation gate ──────────────────────────────────────────────────────
if (-not $WhatIfPreference) {
    Write-Host "WARNING: This will reset ALL domain user passwords." -ForegroundColor Red
    $confirm = Read-Host "Type YES to continue"
    if ($confirm -ne "YES") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# ── Process each user ──────────────────────────────────────────────────────
$results = @()

foreach ($user in $allUsers) {
    $sam = $user.SamAccountName

    # Skip excluded accounts
    if ($ExcludeUsers -contains $sam) {
        Write-Host "SKIP   : $sam (excluded)" -ForegroundColor DarkGray
        continue
    }

    if ($PSCmdlet.ShouldProcess($sam, "Reset password")) {
        try {
            Set-ADAccountPassword -Identity $sam `
                -Reset `
                -NewPassword $securePass `
                -ErrorAction Stop

            # Optionally clear "must change password at next logon"
            Set-ADUser -Identity $sam -ChangePasswordAtLogon $false -ErrorAction SilentlyContinue

            Write-Host "RESET  : $sam" -ForegroundColor Green
            $results += [PSCustomObject]@{
                Username = $sam
                Password = $Password
                Status   = "Reset"
                Enabled  = $user.Enabled
            }
        } catch {
            Write-Host "FAILED : $sam — $_" -ForegroundColor Red
            $results += [PSCustomObject]@{
                Username = $sam
                Password = ""
                Status   = "FAILED: $_"
                Enabled  = $user.Enabled
            }
        }
    } else {
        Write-Host "WOULD RESET: $sam (dry-run)" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Username = $sam
            Password = $Password
            Status   = "WhatIf"
            Enabled  = $user.Enabled
        }
    }
}

# ── Output CSV roster ──────────────────────────────────────────────────────
$results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

# ── Print plain-text comma-separated list ──────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PASSWORD ROSTER (Username, Password)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

foreach ($r in $results) {
    if ($r.Status -eq "Reset" -or $r.Status -eq "WhatIf") {
        Write-Host "$($r.Username), $($r.Password)"
    }
}

Write-Host ""
Write-Host "Total processed : $($results.Count)" -ForegroundColor Cyan
Write-Host "CSV saved to    : $OutFile" -ForegroundColor Cyan
Write-Host ""
