<#
.SYNOPSIS
    Enables AES 256-bit Kerberos authentication for all domain user accounts.

.DESCRIPTION
    CCDC hardening script. Sets the msDS-SupportedEncryptionTypes attribute on
    each domain user to enable AES256 (and optionally AES128). Can also strip
    weak encryption types (DES, RC4).

    Encryption type flags:
        0x01  DES_CBC_CRC
        0x02  DES_CBC_MD5
        0x04  RC4_HMAC
        0x08  AES128_CTS_HMAC_SHA1
        0x10  AES256_CTS_HMAC_SHA1

.PARAMETER DisableWeak
    Also removes DES and RC4 flags, leaving only AES. Default: $true

.PARAMETER IncludeAES128
    Include AES128 alongside AES256. Default: $true (safest for compatibility)

.PARAMETER ExcludeUsers
    SamAccountNames to skip. Defaults to @("krbtgt").

.PARAMETER WhatIf
    Preview changes without applying.

.EXAMPLE
    # Dry-run
    .\Enable-KerberosAES256.ps1 -WhatIf

    # Enable AES256 + AES128, remove DES/RC4 for all users
    .\Enable-KerberosAES256.ps1

    # AES256 only (no AES128) — stricter but may break older clients
    .\Enable-KerberosAES256.ps1 -IncludeAES128:$false
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [bool]$DisableWeak   = $true,
    [bool]$IncludeAES128 = $true,
    [string[]]$ExcludeUsers = @("krbtgt")
)

# ── Encryption type flags ──────────────────────────────────────────────────
$DES_CBC_CRC  = 0x1
$DES_CBC_MD5  = 0x2
$RC4_HMAC     = 0x4
$AES128       = 0x8
$AES256       = 0x10

# Build desired encryption type value
$desired = $AES256
if ($IncludeAES128) { $desired = $desired -bor $AES128 }  # 0x18 = AES128 + AES256

function Describe-EncTypes([int]$val) {
    $flags = @()
    if ($val -band $DES_CBC_CRC) { $flags += "DES_CRC" }
    if ($val -band $DES_CBC_MD5) { $flags += "DES_MD5" }
    if ($val -band $RC4_HMAC)    { $flags += "RC4" }
    if ($val -band $AES128)      { $flags += "AES128" }
    if ($val -band $AES256)      { $flags += "AES256" }
    if ($flags.Count -eq 0)      { $flags += "None/Default" }
    return ($flags -join ", ")
}

# ── Require elevation ──────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator." -ForegroundColor Red
    exit 1
}

# ── Require AD module ─────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ERROR: ActiveDirectory module not found. Install RSAT or run on a DC." -ForegroundColor Red
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# ── Get all users ──────────────────────────────────────────────────────────
$allUsers = Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes, SamAccountName |
    Sort-Object SamAccountName

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Kerberos AES 256-bit Encryption Enforcement" -ForegroundColor Cyan
Write-Host "  Target enc types : $(Describe-EncTypes $desired) (0x$($desired.ToString('X2')))" -ForegroundColor Cyan
Write-Host "  Strip weak (DES/RC4) : $DisableWeak" -ForegroundColor Cyan
Write-Host "  Total accounts   : $($allUsers.Count)" -ForegroundColor Cyan
Write-Host "  Excluded         : $($ExcludeUsers -join ', ')" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ── Confirmation ───────────────────────────────────────────────────────────
if (-not $WhatIfPreference) {
    Write-Host "This will modify Kerberos encryption settings for ALL domain users." -ForegroundColor Yellow
    $confirm = Read-Host "Type YES to continue"
    if ($confirm -ne "YES") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# ── Process each user ──────────────────────────────────────────────────────
$changed  = 0
$skipped  = 0
$already  = 0
$failed   = 0

foreach ($user in $allUsers) {
    $sam = $user.SamAccountName

    if ($ExcludeUsers -contains $sam) {
        Write-Host "SKIP    : $sam (excluded)" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    $current = $user.'msDS-SupportedEncryptionTypes'
    if ($null -eq $current) { $current = 0 }

    # Build new value: start with desired AES flags
    $newVal = $desired

    # If NOT stripping weak, preserve any existing DES/RC4 flags
    if (-not $DisableWeak) {
        $newVal = $newVal -bor ($current -band ($DES_CBC_CRC -bor $DES_CBC_MD5 -bor $RC4_HMAC))
    }

    if ($current -eq $newVal) {
        Write-Host "OK      : $sam — already $(Describe-EncTypes $current)" -ForegroundColor Green
        $already++
        continue
    }

    $desc = "$(Describe-EncTypes $current) → $(Describe-EncTypes $newVal)"

    if ($PSCmdlet.ShouldProcess($sam, "Set encryption types: $desc")) {
        try {
            Set-ADUser -Identity $sam -Replace @{ 'msDS-SupportedEncryptionTypes' = $newVal } -ErrorAction Stop
            Write-Host "CHANGED : $sam — $desc" -ForegroundColor Cyan
            $changed++
        } catch {
            Write-Host "FAILED  : $sam — $_" -ForegroundColor Red
            $failed++
        }
    } else {
        Write-Host "WOULD   : $sam — $desc" -ForegroundColor Yellow
    }
}

# ── Summary ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Results" -ForegroundColor Cyan
Write-Host "  Changed  : $changed" -ForegroundColor Cyan
Write-Host "  Already  : $already" -ForegroundColor Green
Write-Host "  Skipped  : $skipped" -ForegroundColor DarkGray
Write-Host "  Failed   : $failed" -ForegroundColor $(if ($failed -gt 0) {"Red"} else {"Green"})
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "TIP: After changing enc types, users may need to log off/on or" -ForegroundColor Gray
Write-Host "     run 'klist purge' to get new Kerberos tickets." -ForegroundColor Gray
Write-Host ""
