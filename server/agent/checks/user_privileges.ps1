# check_id: user_privileges
# check_name: User Privileges
# category: identity
# description: Enumerates current user privileges and detects dangerous token privileges
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 2

function Invoke-CheckUserPrivileges {
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $findings = @()
    $checkId  = "user_privileges"

    # --- Raw privilege output ---
    $privOut = ""
    try {
        $privOut = (whoami /priv) 2>&1 | Out-String
    } catch {
        $privOut = "whoami /priv failed: $_"
    }

    # --- Raw group output ---
    $groupOut = ""
    try {
        $groupOut = (whoami /groups) 2>&1 | Out-String
    } catch {
        $groupOut = "whoami /groups failed: $_"
    }

    # Always emit raw findings first
    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "privileges_raw" `
        -Severity    "info" `
        -Title       "Current User Privileges (whoami /priv)" `
        -Description "Raw output of whoami /priv listing all token privileges for the current user." `
        -Evidence    $privOut `
        -Tags        @("privileges", "identity", "token")

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "groups_raw" `
        -Severity    "info" `
        -Title       "Current User Groups (whoami /groups)" `
        -Description "Raw output of whoami /groups listing all group memberships for the current user." `
        -Evidence    $groupOut `
        -Tags        @("groups", "identity", "token")

    # --- Analytical: detect dangerous enabled privileges ---
    # Parse lines: privilege name followed by state column containing "Enabled"
    $potatoTools = @("GodPotato", "PrintSpoofer", "JuicyPotato", "SweetPotato")

    # SeImpersonatePrivilege
    if ($privOut -match "SeImpersonatePrivilege\s+[^\r\n]+Enabled") {
        $findings += New-Finding `
            -CheckId     $checkId `
            -FindingId   "se_impersonate_enabled" `
            -Severity    "critical" `
            -Title       "SeImpersonatePrivilege is Enabled" `
            -Description "The current user token has SeImpersonatePrivilege in the Enabled state. This privilege allows impersonating any authenticated user and is routinely abused for local privilege escalation to SYSTEM via token potato attacks." `
            -Evidence    ($privOut | Select-String "SeImpersonatePrivilege" | Out-String).Trim() `
            -Remediation "Remove SeImpersonatePrivilege from service accounts that do not require it. Review IIS application pool identities, SQL Server service accounts, and other service contexts. If escalation occurred, rotate all credentials and investigate lateral movement." `
            -Tags        @("token", "privilege-escalation", "critical", "potato") `
            -ToolHint    $potatoTools
    }

    # SeAssignPrimaryTokenPrivilege
    if ($privOut -match "SeAssignPrimaryTokenPrivilege\s+[^\r\n]+Enabled") {
        $findings += New-Finding `
            -CheckId     $checkId `
            -FindingId   "se_assign_primary_token_enabled" `
            -Severity    "critical" `
            -Title       "SeAssignPrimaryTokenPrivilege is Enabled" `
            -Description "The current user token has SeAssignPrimaryTokenPrivilege in the Enabled state. Combined with or instead of SeImpersonatePrivilege, this privilege allows replacing a process primary token and is a core enabler for potato-class privilege escalation attacks." `
            -Evidence    ($privOut | Select-String "SeAssignPrimaryTokenPrivilege" | Out-String).Trim() `
            -Remediation "Audit and restrict which service accounts hold SeAssignPrimaryTokenPrivilege. This privilege is rarely needed outside LocalSystem and network service contexts. Remove it wherever possible via Group Policy (User Rights Assignment)." `
            -Tags        @("token", "privilege-escalation", "critical", "potato") `
            -ToolHint    $potatoTools
    }

    # Secondary interesting privileges (non-critical but worth flagging)
    $interestingPrivs = @{
        "SeDebugPrivilege"              = @{ Severity = "high";   Title = "SeDebugPrivilege is Enabled";              Desc = "Allows debugging any process including LSASS. Can be used to dump credentials or inject into privileged processes." }
        "SeBackupPrivilege"             = @{ Severity = "high";   Title = "SeBackupPrivilege is Enabled";             Desc = "Allows reading any file regardless of ACL by opening with FILE_FLAG_BACKUP_SEMANTICS. Can be used to read SAM, SYSTEM, NTDS.dit." }
        "SeRestorePrivilege"            = @{ Severity = "high";   Title = "SeRestorePrivilege is Enabled";            Desc = "Allows writing any file regardless of ACL. Can be used to overwrite system binaries or registry hives." }
        "SeTakeOwnershipPrivilege"      = @{ Severity = "high";   Title = "SeTakeOwnershipPrivilege is Enabled";      Desc = "Allows taking ownership of any object. Can be used to gain write access to any file or registry key." }
        "SeLoadDriverPrivilege"         = @{ Severity = "high";   Title = "SeLoadDriverPrivilege is Enabled";         Desc = "Allows loading and unloading kernel drivers. Can be abused to load a malicious driver for kernel-level code execution." }
        "SeCreateTokenPrivilege"        = @{ Severity = "critical"; Title = "SeCreateTokenPrivilege is Enabled";      Desc = "Allows creating arbitrary access tokens. Extremely dangerous - permits creating a token with any group memberships or privileges." }
        "SeTcbPrivilege"                = @{ Severity = "critical"; Title = "SeTcbPrivilege is Enabled";              Desc = "Act as part of the operating system. Allows calling LsaLogonUser to obtain a token for any user without knowing their password." }
        "SeManageVolumePrivilege"       = @{ Severity = "medium";  Title = "SeManageVolumePrivilege is Enabled";      Desc = "Allows raw volume access. Can be used to read SAM/SYSTEM hives or write to protected disk regions." }
    }

    foreach ($priv in $interestingPrivs.Keys) {
        if ($privOut -match "$priv\s+[^\r\n]+Enabled") {
            $info = $interestingPrivs[$priv]
            $findings += New-Finding `
                -CheckId     $checkId `
                -FindingId   ($priv.ToLower() + "_enabled") `
                -Severity    $info.Severity `
                -Title       $info.Title `
                -Description $info.Desc `
                -Evidence    ($privOut | Select-String $priv | Out-String).Trim() `
                -Remediation 'Review whether this privilege is required. Remove via Group Policy > User Rights Assignment if not needed.' `
                -Tags        @("token", "privilege-escalation", $priv.ToLower())
        }
    }

    return $findings
}
