# check_id: system_info
# check_name: System Information
# category: identity
# description: Collects system information, local users, groups, and environment
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 5

function Invoke-CheckSystemInfo {
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $findings = @()
    $checkId  = "system_info"

    # --- whoami + systeminfo ---
    $whoamiOut    = (whoami) 2>&1 | Out-String
    $systeminfoOut = ""
    try {
        $systeminfoOut = (systeminfo) 2>&1 | Out-String
    } catch {
        $systeminfoOut = "systeminfo failed: $_"
    }

    # --- Environment variables ---
    $envVars = (Get-ChildItem Env: | Format-Table -AutoSize | Out-String)

    $sysEvidence = @"
=== WHOAMI ===
$whoamiOut

=== SYSTEMINFO ===
$systeminfoOut

=== ENVIRONMENT VARIABLES ===
$envVars
"@

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "system_info_raw" `
        -Severity    "info" `
        -Title       "System Information" `
        -Description "Raw system information including whoami, systeminfo output, and environment variables." `
        -Evidence    $sysEvidence `
        -Tags        @("system", "identity", "recon")

    # --- Local users ---
    $localUsersOut = ""
    try {
        $localUsersOut = (net user) 2>&1 | Out-String
        # Attempt detail on each account
        $userList = Get-LocalUser -ErrorAction SilentlyContinue
        if ($userList) {
            $localUsersOut += "`n=== Get-LocalUser ===`n"
            $localUsersOut += ($userList | Select-Object Name, Enabled, PasswordRequired, LastLogon, Description | Format-Table -AutoSize | Out-String)
        }
    } catch {
        $localUsersOut = "net user failed: $_"
    }

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "local_users_raw" `
        -Severity    "info" `
        -Title       "Local Users" `
        -Description "Enumeration of local user accounts on this system." `
        -Evidence    $localUsersOut `
        -Tags        @("users", "identity", "recon")

    # --- Local groups + admin group members ---
    $localGroupsOut = ""
    try {
        $localGroupsOut = (net localgroup) 2>&1 | Out-String

        # Administrators membership
        $localGroupsOut += "`n=== Administrators Group Members ===`n"
        $adminMembers = (net localgroup Administrators) 2>&1 | Out-String
        $localGroupsOut += $adminMembers

        # Try Get-LocalGroup for full listing
        $groups = Get-LocalGroup -ErrorAction SilentlyContinue
        if ($groups) {
            $localGroupsOut += "`n=== Get-LocalGroup ===`n"
            foreach ($g in $groups) {
                $localGroupsOut += "`nGroup: $($g.Name)`n"
                try {
                    $members = Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue
                    if ($members) {
                        $localGroupsOut += ($members | Select-Object Name, ObjectClass | Format-Table -AutoSize | Out-String)
                    } else {
                        $localGroupsOut += "  (no members or access denied)`n"
                    }
                } catch {
                    $localGroupsOut += "  (error enumerating members: $_)`n"
                }
            }
        }
    } catch {
        $localGroupsOut = "Group enumeration failed: $_"
    }

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "local_groups_raw" `
        -Severity    "info" `
        -Title       "Local Groups and Memberships" `
        -Description "Enumeration of local groups and their members, including the Administrators group." `
        -Evidence    $localGroupsOut `
        -Tags        @("groups", "identity", "recon")

    return $findings
}
