<#
.SYNOPSIS
    Removes all users except the built-in Administrator from specified admin groups.

.DESCRIPTION
    Cleans up membership of local or Active Directory administrative groups by
    removing every member that is NOT the built-in Administrator account.
    Supports -WhatIf (dry-run) mode and logs all actions.

.PARAMETER Scope
    "Local"  - targets the local Administrators group (default)
    "Domain" - targets Domain Admins, Enterprise Admins, and Schema Admins (requires RSAT / AD module)

.PARAMETER WhatIf
    Preview changes without actually removing anyone.

.PARAMETER LogPath
    Path to the log file. Defaults to .\AdminGroupCleanup.log

.EXAMPLE
    # Dry-run against local Administrators group
    .\Remove-NonAdminUsers.ps1 -Scope Local -WhatIf

    # Actually clean up local Administrators group
    .\Remove-NonAdminUsers.ps1 -Scope Local

    # Clean up domain admin groups (requires AD module)
    .\Remove-NonAdminUsers.ps1 -Scope Domain -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Local", "Domain")]
    [string]$Scope = "Local",

    [string]$LogPath = ".\AdminGroupCleanup.log"
)

# ── Logging helper ──────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(
        switch ($Level) {
            "WARN"    { "Yellow" }
            "ERROR"   { "Red"    }
            "REMOVED" { "Cyan"   }
            "SKIP"    { "Green"  }
            default   { "Gray"   }
        }
    )
    $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

# ── Require elevation ───────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Log "This script must be run as Administrator. Exiting." "ERROR"
    exit 1
}

# ── Local Administrators group cleanup ──────────────────────────────────────
function Remove-LocalAdminGroupMembers {
    $groupName = "Administrators"
    Write-Log "Processing local group: $groupName"

    try {
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
    } catch {
        Write-Log "Failed to enumerate local group '$groupName': $_" "ERROR"
        return
    }

    foreach ($member in $members) {
        # Keep the built-in Administrator (SID ends with -500)
        if ($member.SID -like "S-1-5-*-500") {
            Write-Log "KEPT  : $($member.Name) (built-in Administrator)" "SKIP"
            continue
        }

        if ($PSCmdlet.ShouldProcess($member.Name, "Remove from local $groupName")) {
            try {
                Remove-LocalGroupMember -Group $groupName -Member $member.SID -ErrorAction Stop
                Write-Log "REMOVED: $($member.Name) from $groupName" "REMOVED"
            } catch {
                Write-Log "FAILED to remove $($member.Name): $_" "ERROR"
            }
        } else {
            Write-Log "WOULD REMOVE: $($member.Name) from $groupName (dry-run)" "WARN"
        }
    }
}

# ── Domain admin groups cleanup (requires ActiveDirectory module) ───────────
function Remove-DomainAdminGroupMembers {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory module not found. Install RSAT or run on a DC." "ERROR"
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $domainAdminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $builtinAdmin = (Get-ADUser -Filter { SamAccountName -eq "Administrator" }).DistinguishedName

    if (-not $builtinAdmin) {
        Write-Log "Could not locate the domain Administrator account." "ERROR"
        return
    }

    foreach ($groupName in $domainAdminGroups) {
        Write-Log "Processing AD group: $groupName"
        try {
            $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
        } catch {
            Write-Log "Failed to enumerate AD group '$groupName': $_" "ERROR"
            continue
        }

        foreach ($member in $members) {
            if ($member.DistinguishedName -eq $builtinAdmin) {
                Write-Log "KEPT  : $($member.SamAccountName) (built-in Administrator)" "SKIP"
                continue
            }

            if ($PSCmdlet.ShouldProcess($member.SamAccountName, "Remove from AD group $groupName")) {
                try {
                    Remove-ADGroupMember -Identity $groupName -Members $member -Confirm:$false -ErrorAction Stop
                    Write-Log "REMOVED: $($member.SamAccountName) from $groupName" "REMOVED"
                } catch {
                    Write-Log "FAILED to remove $($member.SamAccountName): $_" "ERROR"
                }
            } else {
                Write-Log "WOULD REMOVE: $($member.SamAccountName) from $groupName (dry-run)" "WARN"
            }
        }
    }
}

# ── Main ────────────────────────────────────────────────────────────────────
Write-Log "===== Admin Group Cleanup Started (Scope: $Scope) ====="

# Confirmation gate (skipped when -WhatIf is active)
if (-not $WhatIfPreference) {
    Write-Host ""
    Write-Host "WARNING: This will REMOVE users from admin groups." -ForegroundColor Red
    Write-Host "Only the built-in Administrator account will be kept." -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "Type YES to continue, or anything else to abort"
    if ($confirm -ne "YES") {
        Write-Log "Aborted by user." "WARN"
        exit 0
    }
}

switch ($Scope) {
    "Local"  { Remove-LocalAdminGroupMembers }
    "Domain" { Remove-DomainAdminGroupMembers }
}

Write-Log "===== Admin Group Cleanup Finished ====="
Write-Host "`nLog saved to: $LogPath" -ForegroundColor Gray
