# check_id: web_configs
# check_name: Web Config Files
# category: credentials
# description: Searches for web.config files and connection strings
# requires_admin: false
# opsec_impact: medium
# estimated_time_seconds: 5

function Invoke-CheckWebConfigs {
    [CmdletBinding()]
    param([hashtable]$Config)

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    $webConfigFiles = [System.Collections.Generic.List[string]]::new()
    $connectionStringsFound = [System.Collections.Generic.List[hashtable]]::new()
    $rawLines = [System.Collections.Generic.List[string]]::new()

    # Helper: scan a file for connectionString patterns
    function Search-ConnectionStrings {
        param([string]$FilePath)
        $hits = @()
        try {
            $lines = Get-Content $FilePath -ErrorAction Stop
            $lineNum = 0
            foreach ($line in $lines) {
                $lineNum++
                if ($line -imatch 'connectionString\s*=') {
                    $hits += "Line $lineNum`: $($line.Trim())"
                }
            }
        } catch {}
        return $hits
    }

    # --- IIS / inetpub ---
    $inetpubRoot = "C:\inetpub"
    if (Test-Path $inetpubRoot) {
        $rawLines.Add("[SCAN] $inetpubRoot (recursive for web.config)")
        try {
            $iisConfigs = Get-ChildItem -Path $inetpubRoot -Recurse -Include "web.config","*.config" -File -ErrorAction SilentlyContinue
            foreach ($f in $iisConfigs) {
                $webConfigFiles.Add($f.FullName)
                $rawLines.Add("[FOUND] $($f.FullName)")

                $csHits = Search-ConnectionStrings -FilePath $f.FullName
                foreach ($hit in $csHits) {
                    $connectionStringsFound.Add(@{ File = $f.FullName; Match = $hit })
                }
            }
        } catch {
            $rawLines.Add("[ERROR] inetpub scan: $($_.Exception.Message)")
        }
    } else {
        $rawLines.Add("[SKIP] C:\inetpub not present")
    }

    # --- .NET framework machine.config / web.config paths ---
    $dotnetPaths = @(
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config",
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config",
        "C:\Windows\Microsoft.NET\Framework\v2.0.50727\Config\web.config",
        "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Config\web.config"
    )
    foreach ($p in $dotnetPaths) {
        if (Test-Path $p -PathType Leaf) {
            $webConfigFiles.Add($p)
            $rawLines.Add("[FOUND .NET] $p")
            $csHits = Search-ConnectionStrings -FilePath $p
            foreach ($hit in $csHits) {
                $connectionStringsFound.Add(@{ File = $p; Match = $hit })
            }
        }
    }

    # --- Common third-party web server paths ---
    $commonWebRoots = @(
        "C:\xampp\apache\conf",
        "C:\xampp\htdocs",
        "C:\wamp\www",
        "C:\wamp64\www",
        "C:\Apache24\conf",
        "C:\nginx\conf",
        "C:\nginx\html",
        "C:\Program Files\Apache Software Foundation",
        "C:\Program Files (x86)\Apache Software Foundation"
    )
    foreach ($root in $commonWebRoots) {
        if (Test-Path $root) {
            $rawLines.Add("[SCAN] $root")
            try {
                $hits = Get-ChildItem -Path $root -Recurse -Include "web.config","*.config","httpd.conf","nginx.conf" -File -ErrorAction SilentlyContinue
                foreach ($f in $hits) {
                    $webConfigFiles.Add($f.FullName)
                    $rawLines.Add("[FOUND] $($f.FullName)")
                    $csHits = Search-ConnectionStrings -FilePath $f.FullName
                    foreach ($hit in $csHits) {
                        $connectionStringsFound.Add(@{ File = $f.FullName; Match = $hit })
                    }
                }
            } catch {
                $rawLines.Add("[ERROR] $root scan: $($_.Exception.Message)")
            }
        }
    }

    # --- Emit HIGH finding for each connection string match ---
    foreach ($cs in $connectionStringsFound) {
        $evidence = "File: $($cs.File)`nMatch: $($cs.Match)"
        $findings += New-Finding `
            -CheckId    "web_configs" `
            -FindingId  "web_config_connection_string" `
            -Severity   "high" `
            -Title      "Connection String Found in Web Config: $($cs.File)" `
            -Description "A connectionString attribute was identified in a web configuration file. Connection strings frequently contain database credentials (username/password), server hostnames, and may grant direct access to backend data stores." `
            -Evidence   $evidence `
            -Remediation "Remove plaintext credentials from web.config files. Use encrypted config sections (aspnet_regiis -pe), Windows Integrated Security, or a secrets manager. Rotate any exposed credentials immediately." `
            -Tags       @("credentials", "web-config", "connection-string", "database") `
            -ToolHint   @()
    }

    # --- INFO finding for each web.config file found ---
    foreach ($wcf in ($webConfigFiles | Select-Object -Unique)) {
        $findings += New-Finding `
            -CheckId    "web_configs" `
            -FindingId  "web_config_found" `
            -Severity   "info" `
            -Title      "Web Config File Located: $wcf" `
            -Description "A web configuration file was found. Review it manually for hardcoded credentials, debug settings, custom errors disabled, or other sensitive configuration." `
            -Evidence   "Path: $wcf" `
            -Remediation "Review file contents. Ensure sensitive settings are encrypted or moved to secure stores." `
            -Tags       @("web-config", "iis", "credentials") `
            -ToolHint   @()
    }

    # --- Always: raw context ---
    $rawEvidence = "Web config files found: $($webConfigFiles.Count)`n"
    $rawEvidence += "Connection strings found: $($connectionStringsFound.Count)`n`n"
    $rawEvidence += "Scan log:`n" + ($rawLines -join "`n")

    $findings += New-Finding `
        -CheckId    "web_configs" `
        -FindingId  "web_configs_raw" `
        -Severity   "info" `
        -Title      "Web Config File Search Results (Raw)" `
        -Description "Raw output from the web configuration file scan across IIS, .NET framework directories, and common third-party web server paths." `
        -Evidence   $rawEvidence `
        -Remediation "" `
        -Tags       @("raw", "web-config", "credentials")

    return $findings
}
