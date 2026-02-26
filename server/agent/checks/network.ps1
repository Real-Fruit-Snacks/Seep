# check_id: network
# check_name: Network Configuration
# category: network
# description: Enumerates network configuration, ports, connections, firewall state
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 3

function Invoke-CheckNetwork {
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $findings = @()
    $checkId  = "network"

    # --- ipconfig /all ---
    $ipconfigOut = ""
    try {
        $ipconfigOut = (ipconfig /all) 2>&1 | Out-String
    } catch {
        $ipconfigOut = "ipconfig /all failed: $_"
    }

    # --- Listening ports ---
    $listeningOut = ""
    try {
        $listeningOut = (netstat -ano) 2>&1 | Out-String
        # Filter to LISTENING for focused view
        $listeningFiltered = ($listeningOut -split "`n" | Where-Object { $_ -match "LISTENING" }) -join "`n"
        $listeningOut = "=== ALL LISTENING PORTS ===`n$listeningFiltered`n`n=== FULL NETSTAT -ANO ===`n$listeningOut"
    } catch {
        $listeningOut = "netstat failed: $_"
    }

    # --- Established connections ---
    $establishedOut = ""
    try {
        $rawNetstat = (netstat -ano) 2>&1 | Out-String
        $establishedOut = ($rawNetstat -split "`n" | Where-Object { $_ -match "ESTABLISHED" }) -join "`n"
    } catch {
        $establishedOut = "netstat ESTABLISHED failed: $_"
    }

    # --- Route table ---
    $routeOut = ""
    try {
        $routeOut = (route print) 2>&1 | Out-String
    } catch {
        $routeOut = "route print failed: $_"
    }

    # --- ARP cache ---
    $arpOut = ""
    try {
        $arpOut = (arp -a) 2>&1 | Out-String
    } catch {
        $arpOut = "arp -a failed: $_"
    }

    # --- DNS cache (first 100 lines) ---
    $dnsOut = ""
    try {
        $dnsRaw = (ipconfig /displaydns) 2>&1 | Out-String
        $dnsLines = $dnsRaw -split "`n" | Select-Object -First 100
        $dnsOut = $dnsLines -join "`n"
        if (($dnsRaw -split "`n").Count -gt 100) {
            $dnsOut += "`n[... truncated to 100 lines ...]"
        }
    } catch {
        try {
            $dnsCache = Get-DnsClientCache -ErrorAction Stop | Select-Object -First 100
            $dnsOut = ($dnsCache | Format-Table -AutoSize | Out-String)
        } catch {
            $dnsOut = "DNS cache enumeration failed: $_"
        }
    }

    # --- Net shares ---
    $sharesOut = ""
    try {
        $sharesOut = (net share) 2>&1 | Out-String
    } catch {
        $sharesOut = "net share failed: $_"
    }

    # --- Net use (mapped drives / UNC connections) ---
    $netUseOut = ""
    try {
        $netUseOut = (net use) 2>&1 | Out-String
    } catch {
        $netUseOut = "net use failed: $_"
    }

    # --- Firewall state ---
    $firewallOut = ""
    try {
        $firewallOut = (netsh advfirewall show allprofiles state) 2>&1 | Out-String
    } catch {
        $firewallOut = "netsh advfirewall failed: $_"
    }

    # --- Localhost-only ports (potential internal services) ---
    $localhostPorts = ""
    try {
        $rawNetstat2 = (netstat -ano) 2>&1 | Out-String
        $localhostPorts = ($rawNetstat2 -split "`n" | Where-Object {
            $_ -match "127\.0\.0\.1:\d+" -or $_ -match "\[::1\]:\d+"
        }) -join "`n"
        if (-not $localhostPorts.Trim()) {
            $localhostPorts = "(none detected)"
        }
    } catch {
        $localhostPorts = "localhost port detection failed: $_"
    }

    # === Build evidence blocks ===

    $networkEvidence = @"
=== IPCONFIG /ALL ===
$ipconfigOut

=== ROUTE TABLE ===
$routeOut

=== ARP CACHE ===
$arpOut

=== DNS CACHE (first 100 entries) ===
$dnsOut

=== NET SHARE ===
$sharesOut

=== NET USE ===
$netUseOut

=== ESTABLISHED CONNECTIONS ===
$establishedOut

=== LOCALHOST-ONLY LISTENING PORTS ===
$localhostPorts
"@

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "network_config_raw" `
        -Severity    "info" `
        -Title       "Network Configuration" `
        -Description "Full network configuration including IP addresses, routes, ARP cache, DNS cache, shares, mapped drives, and established connections." `
        -Evidence    $networkEvidence `
        -Tags        @("network", "recon", "configuration")

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "listening_ports_raw" `
        -Severity    "info" `
        -Title       "Listening Ports (netstat -ano)" `
        -Description "All listening TCP/UDP ports with associated PIDs. Includes full netstat output and filtered LISTENING entries." `
        -Evidence    $listeningOut `
        -Tags        @("network", "ports", "recon")

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "firewall_state" `
        -Severity    "info" `
        -Title       "Windows Firewall State" `
        -Description 'Windows Firewall profile states (Domain, Private, Public) via netsh advfirewall.' `
        -Evidence    $firewallOut `
        -Tags        @("network", "firewall", "configuration")

    # Analytical: firewall disabled
    if ($firewallOut -match "State\s+OFF") {
        $findings += New-Finding `
            -CheckId     $checkId `
            -FindingId   "firewall_disabled" `
            -Severity    "medium" `
            -Title       "Windows Firewall Disabled on One or More Profiles" `
            -Description "One or more Windows Firewall profiles are in the OFF state. This reduces network-layer defenses and may allow unexpected inbound connections." `
            -Evidence    ($firewallOut | Select-String "State" | Out-String).Trim() `
            -Remediation "Enable Windows Firewall on all profiles unless a third-party firewall is confirmed active. Use: netsh advfirewall set allprofiles state on" `
            -Tags        @("network", "firewall", "misconfiguration")
    }

    return $findings
}
