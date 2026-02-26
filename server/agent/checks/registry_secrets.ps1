# check_id: registry_secrets
# check_name: Registry Secrets
# category: credentials
# description: Searches registry for stored passwords, keys, and sensitive data
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 5

function Invoke-CheckRegistrySecrets {
    [CmdletBinding()]
    param(
        [hashtable]$Config = @{}
    )

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    # -------------------------------------------------------------------------
    # Helper: mask a password value for safe evidence output
    # -------------------------------------------------------------------------
    function mask-value {
        param([string]$v)
        if ([string]::IsNullOrEmpty($v)) { return "(empty)" }
        if ($v.Length -le 4) { return "***" }
        return $v.Substring(0, 2) + ("*" * ($v.Length - 2))
    }

    $checkedLocations = @()
    $passwordFindings = @()
    $vncFindings      = @()
    $puttyFindings    = @()

    # =========================================================================
    # 1. Winlogon autologon credentials
    # =========================================================================
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $checkedLocations += $winlogonPath

    $winlogon = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
    if ($winlogon) {
        $autoLogon   = $winlogon.AutoAdminLogon
        $defPass     = $winlogon.DefaultPassword
        $defUser     = $winlogon.DefaultUserName
        $defDomain   = $winlogon.DefaultDomainName

        if ($autoLogon -eq "1" -or -not [string]::IsNullOrEmpty($defPass)) {
            $maskedPass = mask-value $defPass
            $evidence = @"
Registry path : $winlogonPath
AutoAdminLogon   : $autoLogon
DefaultUserName  : $defUser
DefaultDomainName: $defDomain
DefaultPassword  : $maskedPass
"@
            $passwordFindings += New-Finding `
                -CheckId     "registry_secrets" `
                -FindingId   "registry_password_found_winlogon" `
                -Severity    "high" `
                -Title       "Autologon Credentials in Winlogon Registry Key" `
                -Description "The Winlogon registry key contains autologon credentials. DefaultPassword stores the plaintext password used for automatic logon. Any local user or process with registry read access can retrieve this value." `
                -Evidence    $evidence `
                -Remediation "Disable AutoAdminLogon or use the LSA secret store instead of DefaultPassword. Remove or rotate the stored credential. Consider whether autologon is necessary for the system's role." `
                -Tags        @("credentials", "registry", "autologon", "plaintext") `
                -ToolHint    @("Mimikatz", "LaZagne")
        }
    }

    # =========================================================================
    # 2. ORL WinVNC3 default password
    # =========================================================================
    $vncOrlPath = "HKLM:\SOFTWARE\ORL\WinVNC3\Default"
    $checkedLocations += $vncOrlPath

    $vncOrl = Get-ItemProperty -Path $vncOrlPath -ErrorAction SilentlyContinue
    if ($vncOrl -and $vncOrl.Password) {
        $maskedPass = mask-value ($vncOrl.Password | Out-String).Trim()
        $evidence = @"
Registry path : $vncOrlPath
Password      : $maskedPass (raw bytes - obfuscated DES)
"@
        $vncFindings += New-Finding `
            -CheckId     "registry_secrets" `
            -FindingId   "vnc_password_found_orl_winvnc3_default" `
            -Severity    "high" `
            -Title       "VNC Password Found: ORL WinVNC3 Default Hive" `
            -Description "A VNC password entry was found under HKLM\SOFTWARE\ORL\WinVNC3\Default. WinVNC3 stores passwords with weak DES obfuscation using a hardcoded key; the value can be trivially decrypted offline." `
            -Evidence    $evidence `
            -Remediation "Remove or rotate VNC credentials. Restrict VNC access to known IPs. Consider migrating to a modern remote access solution with stronger authentication." `
            -Tags        @("credentials", "registry", "vnc", "remote-access") `
            -ToolHint    @("vncpwd", "Metasploit")
    }

    # =========================================================================
    # 3. RealVNC WinVNC4
    # =========================================================================
    $realVncPath = "HKLM:\SOFTWARE\RealVNC\WinVNC4"
    $checkedLocations += $realVncPath

    $realVnc = Get-ItemProperty -Path $realVncPath -ErrorAction SilentlyContinue
    if ($realVnc -and $realVnc.Password) {
        $maskedPass = mask-value ($realVnc.Password | Out-String).Trim()
        $evidence = @"
Registry path : $realVncPath
Password      : $maskedPass (raw bytes - obfuscated DES)
"@
        $vncFindings += New-Finding `
            -CheckId     "registry_secrets" `
            -FindingId   "vnc_password_found_realvnc4" `
            -Severity    "high" `
            -Title       "VNC Password Found: RealVNC WinVNC4" `
            -Description "A VNC password entry was found under HKLM\SOFTWARE\RealVNC\WinVNC4. RealVNC stores passwords with weak DES obfuscation using a hardcoded key and can be decrypted offline." `
            -Evidence    $evidence `
            -Remediation "Remove or rotate VNC credentials. Restrict VNC access to known IPs. Consider migrating to a modern remote access solution with stronger authentication." `
            -Tags        @("credentials", "registry", "vnc", "remote-access") `
            -ToolHint    @("vncpwd", "Metasploit")
    }

    # =========================================================================
    # 4. TightVNC Server
    # =========================================================================
    $tightVncPath = "HKLM:\SOFTWARE\TightVNC\Server"
    $checkedLocations += $tightVncPath

    $tightVnc = Get-ItemProperty -Path $tightVncPath -ErrorAction SilentlyContinue
    if ($tightVnc) {
        $foundVncVal = $false
        $tightEvidence = "Registry path : $tightVncPath`n"

        if ($tightVnc.Password) {
            $tightEvidence += "Password         : " + (mask-value ($tightVnc.Password | Out-String).Trim()) + " (raw bytes)`n"
            $foundVncVal = $true
        }
        if ($tightVnc.PasswordViewOnly) {
            $tightEvidence += "PasswordViewOnly : " + (mask-value ($tightVnc.PasswordViewOnly | Out-String).Trim()) + " (raw bytes)`n"
            $foundVncVal = $true
        }

        if ($foundVncVal) {
            $vncFindings += New-Finding `
                -CheckId     "registry_secrets" `
                -FindingId   "vnc_password_found_tightvnc" `
                -Severity    "high" `
                -Title       "VNC Password Found: TightVNC Server" `
                -Description "VNC password entries were found under HKLM\SOFTWARE\TightVNC\Server. TightVNC uses the same weak DES obfuscation scheme as WinVNC; values can be decrypted offline with freely available tools." `
                -Evidence    $tightEvidence `
                -Remediation "Remove or rotate VNC credentials. Restrict VNC access to known IPs. Consider migrating to a modern remote access solution with stronger authentication." `
                -Tags        @("credentials", "registry", "vnc", "remote-access") `
                -ToolHint    @("vncpwd", "Metasploit")
        }
    }

    # =========================================================================
    # 5. HKCU ORL WinVNC3 Password
    # =========================================================================
    $vncHkcuPath = "HKCU:\Software\ORL\WinVNC3\Password"
    $checkedLocations += $vncHkcuPath

    $vncHkcu = Get-ItemProperty -Path $vncHkcuPath -ErrorAction SilentlyContinue
    if ($vncHkcu -and $vncHkcu.Password) {
        $maskedPass = mask-value ($vncHkcu.Password | Out-String).Trim()
        $evidence = @"
Registry path : $vncHkcuPath
Password      : $maskedPass (raw bytes - obfuscated DES)
"@
        $vncFindings += New-Finding `
            -CheckId     "registry_secrets" `
            -FindingId   "vnc_password_found_orl_hkcu" `
            -Severity    "high" `
            -Title       "VNC Password Found: HKCU ORL WinVNC3" `
            -Description "A VNC password was found in the current user's registry hive under HKCU\Software\ORL\WinVNC3\Password. This credential can be decrypted offline." `
            -Evidence    $evidence `
            -Remediation "Remove or rotate VNC credentials. Restrict VNC access to known IPs." `
            -Tags        @("credentials", "registry", "vnc", "remote-access") `
            -ToolHint    @("vncpwd", "Metasploit")
    }

    # Consolidate VNC findings into single finding_id if multiple VNC entries exist
    if ($vncFindings.Count -gt 0) {
        $findings += $vncFindings

        # Emit a single aggregated vnc_password_found finding as well
        $vncSummary = $vncFindings | ForEach-Object { "  - $($_.title)" }
        $findings += New-Finding `
            -CheckId     "registry_secrets" `
            -FindingId   "vnc_password_found" `
            -Severity    "high" `
            -Title       "VNC Password Entries Found in Registry ($($vncFindings.Count) location(s))" `
            -Description "One or more VNC password entries were located in the registry. VNC passwords stored in the registry use weak DES obfuscation with a hardcoded key and can be cracked offline in seconds." `
            -Evidence    ($vncSummary -join "`n") `
            -Remediation "Audit all VNC installations. Remove plaintext/obfuscated credentials from the registry. Enforce VNC authentication policies and restrict network access." `
            -Tags        @("credentials", "registry", "vnc", "remote-access") `
            -ToolHint    @("vncpwd", "Metasploit", "LaZagne")
    }

    # Add winlogon findings after VNC
    $findings += $passwordFindings

    # =========================================================================
    # 6. PuTTY sessions
    # =========================================================================
    $puttyBase = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
    $checkedLocations += $puttyBase

    $puttySessions = Get-ChildItem -Path $puttyBase -ErrorAction SilentlyContinue
    if ($puttySessions) {
        $sessionDetails = @()
        $sessionsWithCreds = 0

        foreach ($session in $puttySessions) {
            $sessionName = $session.PSChildName
            $sessionProps = Get-ItemProperty -Path $session.PSPath -ErrorAction SilentlyContinue

            $proxyPass = $sessionProps.ProxyPassword
            $pubKeyFile = $sessionProps.PublicKeyFile
            $hostname   = $sessionProps.HostName
            $username   = $sessionProps.UserName

            $hasCred = (-not [string]::IsNullOrEmpty($proxyPass)) -or (-not [string]::IsNullOrEmpty($pubKeyFile))

            if ($hasCred) { $sessionsWithCreds++ }

            $entry = "Session: $sessionName | Host: $hostname | User: $username"
            if ($proxyPass)  { $entry += " | ProxyPassword: " + (mask-value $proxyPass) }
            if ($pubKeyFile) { $entry += " | PublicKeyFile: $pubKeyFile" }
            $sessionDetails += $entry
        }

        if ($sessionsWithCreds -gt 0 -or $puttySessions.Count -gt 0) {
            $evidence = @"
PuTTY Sessions Registry Base: $puttyBase
Total sessions found: $($puttySessions.Count)
Sessions with stored credentials: $sessionsWithCreds

Session Details:
$($sessionDetails -join "`n")
"@
            $puttyFindings += New-Finding `
                -CheckId     "registry_secrets" `
                -FindingId   "putty_sessions_found" `
                -Severity    "high" `
                -Title       "PuTTY Sessions with Stored Credentials Found ($sessionsWithCreds of $($puttySessions.Count) sessions)" `
                -Description "PuTTY session entries were found in the registry. Sessions may store proxy passwords in plaintext and reference private key files on disk. These paths can reveal SSH infrastructure and private key locations." `
                -Evidence    $evidence `
                -Remediation "Remove stored PuTTY credentials. Avoid storing proxy passwords in PuTTY sessions. Protect private key files with passphrases. Review the referenced key files for sensitivity." `
                -Tags        @("credentials", "registry", "ssh", "putty", "lateral-movement") `
                -ToolHint    @("LaZagne", "SharpDPAPI")

            $findings += $puttyFindings
        }
    }

    # =========================================================================
    # 7. SNMP community strings
    # =========================================================================
    $snmpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
    $checkedLocations += $snmpPath

    $snmpKey = Get-Item -Path $snmpPath -ErrorAction SilentlyContinue
    if ($snmpKey) {
        $communities = $snmpKey.GetValueNames()
        if ($communities.Count -gt 0) {
            $communityList = $communities | ForEach-Object {
                $perms = $snmpKey.GetValue($_)
                "  Community: $(mask-value $_) | Permissions: $perms"
            }
            $evidence = @"
Registry path : $snmpPath
Communities found: $($communities.Count)

$($communityList -join "`n")
"@
            $findings += New-Finding `
                -CheckId     "registry_secrets" `
                -FindingId   "registry_password_found_snmp" `
                -Severity    "high" `
                -Title       "SNMP Community Strings Found in Registry" `
                -Description "SNMP community strings were found in the registry. Default or weak community strings (e.g., 'public', 'private') allow unauthenticated SNMP enumeration and in some configurations write access to network devices." `
                -Evidence    $evidence `
                -Remediation "Replace default SNMP community strings with long random values. Restrict SNMP access by IP. Prefer SNMPv3 with authentication and encryption over SNMPv1/v2c." `
                -Tags        @("credentials", "registry", "snmp", "network") `
                -ToolHint    @("snmpwalk", "onesixtyone")
        }
    }

    # =========================================================================
    # 8. Broad registry password search via reg.exe (limited to 50 matches)
    # =========================================================================
    $regSearchRaw = ""
    try {
        $regSearchLines = @()
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo.FileName  = "reg.exe"
        $proc.StartInfo.Arguments = "query HKLM /f password /t REG_SZ /s"
        $proc.StartInfo.UseShellExecute        = $false
        $proc.StartInfo.RedirectStandardOutput = $true
        $proc.StartInfo.RedirectStandardError  = $true
        $proc.StartInfo.CreateNoWindow         = $true
        $null = $proc.Start()

        $lineCount = 0
        $maxLines  = 200  # ~50 matches with surrounding context
        while (-not $proc.StandardOutput.EndOfStream -and $lineCount -lt $maxLines) {
            $regSearchLines += $proc.StandardOutput.ReadLine()
            $lineCount++
        }

        # Don't wait forever - give it 10 seconds then kill
        if (-not $proc.WaitForExit(10000)) {
            $proc.Kill()
            $regSearchLines += "[TRUNCATED - reg.exe search exceeded 10s timeout]"
        }

        $regSearchRaw = $regSearchLines -join "`n"
    } catch {
        $regSearchRaw = "[reg.exe broad search failed: $_]"
    }

    # =========================================================================
    # 9. WiFi profile passwords via netsh
    # =========================================================================
    $wifiFindings = @()

    $profilesRaw = (& netsh wlan show profiles 2>&1) | Out-String
    $profileNames = [regex]::Matches($profilesRaw, "(?:All User Profile|User Profile)\s*:\s*(.+)") |
                    ForEach-Object { $_.Groups[1].Value.Trim() }

    if ($profileNames.Count -gt 0) {
        foreach ($profileName in $profileNames) {
            $profileDetail = (& netsh wlan show profile name=$profileName key=clear 2>&1) | Out-String

            # Key Content line: "Key Content : SomePassword"
            $keyMatch = [regex]::Match($profileDetail, "Key Content\s*:\s*(.+)")
            if ($keyMatch.Success) {
                $wifiPass = $keyMatch.Groups[1].Value.Trim()
                $maskedWifi = mask-value $wifiPass

                # Extract auth type for context
                $authMatch = [regex]::Match($profileDetail, "Authentication\s*:\s*(.+)")
                $authType  = if ($authMatch.Success) { $authMatch.Groups[1].Value.Trim() } else { "Unknown" }

                $evidence = @"
WiFi Profile  : $profileName
Authentication: $authType
Key Content   : $maskedWifi
"@
                $wifiFindings += New-Finding `
                    -CheckId     "registry_secrets" `
                    -FindingId   "wifi_password_found_$([regex]::Replace($profileName, '[^a-zA-Z0-9]', '_').ToLower())" `
                    -Severity    "medium" `
                    -Title       "WiFi Password Stored for Profile: $profileName" `
                    -Description "The Windows WLAN profile '$profileName' has a stored network key recoverable in cleartext via netsh. This can reveal the passphrase for the wireless network, potentially enabling lateral movement or network access." `
                    -Evidence    $evidence `
                    -Remediation "Audit stored WiFi profiles and remove credentials for networks no longer required. Ensure corporate WiFi uses certificate-based authentication (EAP-TLS) rather than shared keys." `
                    -Tags        @("credentials", "wifi", "wireless", "cleartext") `
                    -ToolHint    @("LaZagne")
            }
        }

        if ($wifiFindings.Count -gt 0) {
            $findings += $wifiFindings
        }
    }

    # =========================================================================
    # 10. Raw summary info finding
    # =========================================================================
    $summaryLines = @(
        "=== Registry Locations Checked ===",
        ($checkedLocations -join "`n"),
        "",
        "=== HKLM Broad Password Search (reg query HKLM /f password /t REG_SZ /s) [first 50 matches] ===",
        $regSearchRaw,
        "",
        "=== WiFi Profiles Found ===",
        "Total profiles : $($profileNames.Count)",
        "Profiles with stored keys : $($wifiFindings.Count)",
        ($profileNames -join ", ")
    )

    $findings += New-Finding `
        -CheckId     "registry_secrets" `
        -FindingId   "registry_secrets_raw" `
        -Severity    "info" `
        -Title       "Registry Secrets Check - Locations Checked and Raw Output" `
        -Description "Summary of all registry locations and commands checked during the registry secrets enumeration. Includes raw output from a broad HKLM password search and WiFi profile discovery." `
        -Evidence    ($summaryLines -join "`n") `
        -Tags        @("credentials", "registry", "raw", "summary")

    return $findings
}
