# check_id: quick_wins
# check_name: Quick Wins
# category: credentials
# description: Checks PowerShell history, saved credentials, and autologon registry
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 2

function Invoke-CheckQuickWins {
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $findings = @()
    $checkId  = "quick_wins"

    # =========================================================
    # 1. PowerShell History
    # =========================================================
    $psHistoryEvidence = ""
    $psHistoryFiles    = @()

    # Current user history
    $currentHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $currentHistoryPath -ErrorAction SilentlyContinue) {
        $psHistoryFiles += $currentHistoryPath
    }

    # All user profiles (requires read access)
    try {
        $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $userProfiles) {
            $histPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if ((Test-Path $histPath -ErrorAction SilentlyContinue) -and ($histPath -ne $currentHistoryPath)) {
                $psHistoryFiles += $histPath
            }
        }
    } catch {}

    $credPatterns = @(
        "-Password\s",
        "ConvertTo-SecureString",
        "[Cc]redential",
        "\-p\s+\S",
        "net\s+use.*\/user",
        "net\s+user.*\/add",
        "runas.*\/user",
        "Invoke-WebRequest.*\-Credential",
        "\$pass\b",
        "\$pw\b",
        "\$cred\b",
        "passwd",
        "password\s*=",
        "BasicAuth",
        "Authorization.*Basic"
    )

    $historyCredLines    = @()
    $psHistoryEvidenceParts = @()

    foreach ($histFile in $psHistoryFiles) {
        try {
            $content = Get-Content $histFile -ErrorAction Stop
            $psHistoryEvidenceParts += "=== $histFile ===`n" + ($content -join "`n") + "`n"

            foreach ($line in $content) {
                foreach ($pattern in $credPatterns) {
                    if ($line -match $pattern) {
                        $historyCredLines += "[$histFile] $line"
                        break
                    }
                }
            }
        } catch {
            $psHistoryEvidenceParts += "=== $histFile === (read error: $_)`n"
        }
    }

    if ($psHistoryFiles.Count -eq 0) {
        $psHistoryEvidence = "(No PSReadLine history files found)"
    } else {
        $psHistoryEvidence = $psHistoryEvidenceParts -join "`n"
    }

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "ps_history_raw" `
        -Severity    "info" `
        -Title       "PowerShell Command History" `
        -Description "Raw PowerShell PSReadLine history from all accessible user profiles." `
        -Evidence    $psHistoryEvidence `
        -Tags        @("credentials", "history", "recon")

    if ($historyCredLines.Count -gt 0) {
        $findings += New-Finding `
            -CheckId     $checkId `
            -FindingId   "ps_history_credentials" `
            -Severity    "high" `
            -Title       "Credential Patterns Detected in PowerShell History" `
            -Description "PowerShell command history contains lines matching credential-related patterns such as -Password, ConvertTo-SecureString, -Credential, or similar. These may contain plaintext or encoded credentials." `
            -Evidence    ($historyCredLines -join "`n") `
            -Remediation "Review and remove sensitive commands from PSReadLine history. Set `$MaximumHistoryCount = 0` or configure PSReadLine to not log sensitive commands. Rotate any credentials found in history." `
            -Tags        @("credentials", "history", "cleartext")
    }

    # =========================================================
    # 2. Saved Credentials (cmdkey)
    # =========================================================
    $cmdkeyOut = ""
    try {
        $cmdkeyOut = (cmdkey /list) 2>&1 | Out-String
    } catch {
        $cmdkeyOut = "cmdkey /list failed: $_"
    }

    $savedCredsEvidence = "=== CMDKEY /LIST ===`n$cmdkeyOut"

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "saved_creds_raw" `
        -Severity    "info" `
        -Title       "Saved Credentials (cmdkey /list)" `
        -Description "Output of cmdkey /list showing all credentials stored in Windows Credential Manager." `
        -Evidence    $savedCredsEvidence `
        -Tags        @("credentials", "credential-manager", "recon")

    # Detect actual stored entries: cmdkey reports entries with "Target:" lines
    # An empty result or error message does not contain "Target:"
    $cmdkeyHasEntries = ($cmdkeyOut -match "Target\s*:") -or
                        ($cmdkeyOut -match "TERMSRV")     -or
                        ($cmdkeyOut -match "Domain:Password") -or
                        ($cmdkeyOut -match "MicrosoftOffice") -or
                        ($cmdkeyOut -match "WindowsLive") -or
                        ($cmdkeyOut -match "Generic:")

    # Exclude the empty/no-entries response
    $noEntriesPattern = "Currently stored credentials\s*:`r?`n\s*\*\s*NONE|no credentials|0 credentials|No credentials"
    if ($cmdkeyHasEntries -and $cmdkeyOut -notmatch $noEntriesPattern) {
        $findings += New-Finding `
            -CheckId     $checkId `
            -FindingId   "saved_credentials_cmdkey" `
            -Severity    "high" `
            -Title       "Saved Credentials Found in Windows Credential Manager" `
            -Description "Windows Credential Manager contains saved credential entries. These can be extracted using tools like Mimikatz (sekurlsa::credman) or accessed via runas /savecred for privilege escalation." `
            -Evidence    $cmdkeyOut.Trim() `
            -Remediation 'Review and remove unnecessary saved credentials from Windows Credential Manager. Ensure service accounts do not cache domain admin credentials. Use: cmdkey /delete:<target> to remove entries.' `
            -Tags        @("credentials", "credential-manager", "privesc") `
            -ToolHint    @("Mimikatz", "LaZagne", "SharpDPAPI")
    }

    # =========================================================
    # 3. Autologon Registry (quick-win indicator only)
    # NOTE: Detailed autologon credential detection - including evidence collection,
    # severity rating, and remediation - is handled by the registry_secrets check
    # (finding ID: registry_password_found_winlogon). This section only emits a
    # lightweight indicator to flag autologon as enabled, avoiding duplicate findings.
    # =========================================================
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    try {
        $winlogon       = Get-ItemProperty -Path $winlogonPath -ErrorAction Stop
        $autologonPass  = $winlogon.DefaultPassword -as [string]
        $autoAdminLogon = $winlogon.AutoAdminLogon  -as [string]
        $autologonUser  = $winlogon.DefaultUserName -as [string]

        # Only emit a finding here when DefaultPassword is set; the full credential
        # exposure finding (severity high) is raised by registry_secrets.
        if ($autologonPass -and $autologonPass.Trim() -ne "") {
            $findings += New-Finding `
                -CheckId     $checkId `
                -FindingId   "autologon_enabled_indicator" `
                -Severity    "info" `
                -Title       "Autologon Enabled with Stored Password (Indicator)" `
                -Description "AutoAdminLogon is configured and a DefaultPassword value is present in the Winlogon registry key for account '$autologonUser'. See the registry_secrets check (registry_password_found_winlogon) for the full credential exposure finding and remediation details." `
                -Evidence    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`nAutoAdminLogon : $autoAdminLogon`nDefaultUserName: $autologonUser`nDefaultPassword: (present - see registry_secrets finding)" `
                -Tags        @("credentials", "autologon", "registry", "indicator")
        }
    } catch {
        # Registry read failed - no finding emitted; registry_secrets will handle it.
    }

    return $findings
}
