#Requires -Version 3.0

function Invoke-Seep {
    [CmdletBinding()]
    param(
        [string]$Server = "",
        [string]$Upload = "",
        [string]$OutputDir = ".\SeepOutput",
        [switch]$SaveLocal,
        [string[]]$Checks = @(),
        [string[]]$ExcludeChecks = @(),
        [string]$Category = "",
        [switch]$Quiet,
        [switch]$Shuffle,
        [int]$Jitter = 0,
        [switch]$Cleanup,
        [string]$RemoteHost = "",
        [string]$DownloadTools = "",
        [string]$ToolsDir = "",
        [string]$Token = ""
    )

    $ErrorActionPreference = "SilentlyContinue"
    $ProgressPreference    = "SilentlyContinue"

    # Resolve auth token: explicit parameter overrides script-level variable
    $authToken = $Token
    if ($authToken -eq "" -and $script:SeepAuthToken) {
        $authToken = $script:SeepAuthToken
    }

    $startTime = Get-Date

    # =========================================================================
    # 1. Setup
    # =========================================================================
    $script:SeepQuiet = $Quiet.IsPresent

    # Determine upload URL
    $uploadUrl = ""
    if ($Server -ne "") {
        $uploadUrl = $Server.TrimEnd("/") + "/api/results"
    } elseif ($Upload -ne "") {
        $uploadUrl = $Upload
    }

    # Fileless mode: upload target set and user has not forced disk mode
    $filelessMode = ($uploadUrl -ne "") -and (-not $SaveLocal.IsPresent)

    # =========================================================================
    # 2. System context
    # =========================================================================
    $ctx = Get-SystemContext

    # =========================================================================
    # 3. Banner
    # =========================================================================
    if (-not $script:SeepQuiet) {
        $modeLabel  = if ($filelessMode) { "FILELESS" } else { "DISK" }
        $adminLabel = if ($ctx.is_admin) { "ADMIN" } else { "LOW-PRIV" }
        $domLabel   = if ($ctx.is_domain) { "DOMAIN" } else { "WORKGROUP" }

        Write-Host ""
        Write-Host "   ____  _____ _____ ____  " -ForegroundColor Cyan
        Write-Host "  / ___|| ____| ____|  _ \ " -ForegroundColor Cyan
        Write-Host "  \___ \|  _| |  _| | |_) |" -ForegroundColor Cyan
        Write-Host "   ___) | |___| |___|  __/ " -ForegroundColor Cyan
        Write-Host "  |____/|_____|_____|_|    " -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Seep v$($script:AgentVersion) | Windows Privilege Escalation Enumerator" -ForegroundColor White
        Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Host     : $($ctx.hostname)  ($($ctx.os_name))" -ForegroundColor Gray
        Write-Host "  User     : $($ctx.username)" -ForegroundColor Gray
        Write-Host "  Context  : $adminLabel  |  $domLabel" -ForegroundColor $(if ($ctx.is_admin) { "Yellow" } else { "Gray" })
        Write-Host "  Mode     : $modeLabel" -ForegroundColor $(if ($filelessMode) { "Green" } else { "Yellow" })
        if ($uploadUrl -ne "") {
            Write-Host "  Upload   : $uploadUrl" -ForegroundColor Gray
        }
        Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
        Write-Host ""
    }

    # =========================================================================
    # 4. Check discovery and filtering
    # =========================================================================
    $allCheckFunctions = Get-Command -Name "Invoke-Check*" -CommandType Function |
                         Sort-Object Name

    # Apply include filter ($Checks)
    if ($Checks.Count -gt 0) {
        $allCheckFunctions = $allCheckFunctions | Where-Object {
            $id = $_.Name -replace "^Invoke-Check", ""
            # Case-insensitive match against any element of $Checks
            $Checks | Where-Object { $_ -ieq $id }
        }
    }

    # Apply exclude filter ($ExcludeChecks)
    if ($ExcludeChecks.Count -gt 0) {
        $allCheckFunctions = $allCheckFunctions | Where-Object {
            $id = $_.Name -replace "^Invoke-Check", ""
            -not ($ExcludeChecks | Where-Object { $_ -ieq $id })
        }
    }

    # Randomise order if requested
    if ($Shuffle.IsPresent) {
        $allCheckFunctions = $allCheckFunctions | Sort-Object { Get-Random }
    }

    $CheckFunctions = @($allCheckFunctions)

    # =========================================================================
    # 5. Set progress counters
    # =========================================================================
    $script:TotalChecks     = $CheckFunctions.Count
    $script:CompletedChecks = 0

    if (-not $script:SeepQuiet) {
        Write-Host "  Checks loaded : $($script:TotalChecks)" -ForegroundColor Gray
        Write-Host ""
    }

    # =========================================================================
    # 6. Execution loop
    # =========================================================================
    $AllFindings = @()
    $checksRun   = @()

    foreach ($fn in $CheckFunctions) {
        # Derive a readable check ID from the function name
        $checkId = $fn.Name -replace "^Invoke-Check", ""
        # Convert PascalCase to snake_case for consistency with metadata headers
        $checkId = [regex]::Replace($checkId, "(?<!^)([A-Z])", "_`$1").ToLower()

        $checksRun += $checkId

        Write-Status "Running check: $checkId" -Type "INFO"

        # Optional inter-check jitter (milliseconds, random within [0, Jitter])
        if ($Jitter -gt 0) {
            $sleepMs = Get-Random -Minimum 0 -Maximum $Jitter
            Start-Sleep -Milliseconds $sleepMs
        }

        try {
            $result = & $fn.Name -Config @{}
            if ($result) {
                $AllFindings += $result
            }
        } catch {
            # Capture execution failure as an error finding so it surfaces in results
            $AllFindings += New-Finding `
                -CheckId     $checkId `
                -FindingId   "${checkId}_execution_error" `
                -Severity    "error" `
                -Title       "Check Execution Failed: $checkId" `
                -Description "An unhandled exception occurred while running check '$checkId'. This may indicate a compatibility issue, missing dependency, or unexpected system state." `
                -Evidence    "Exception: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)" `
                -Tags        @("error", "check-failure")
        }

        $script:CompletedChecks++
    }

    # =========================================================================
    # 7. Build result document
    # =========================================================================
    $endTime         = Get-Date
    $durationSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)

    # Severity grouping for summary
    $bySeverity = @{}
    foreach ($f in $AllFindings) {
        $sev = if ($f.severity) { $f.severity } else { "unknown" }
        if (-not $bySeverity.ContainsKey($sev)) { $bySeverity[$sev] = 0 }
        $bySeverity[$sev]++
    }

    $result = @{
        meta = @{
            agent_version          = $script:AgentVersion
            timestamp              = (Get-Date -Format "o")
            hostname               = $ctx.hostname
            domain                 = $ctx.domain
            username               = $ctx.username
            is_admin               = $ctx.is_admin
            is_domain_joined       = $ctx.is_domain
            os_version             = $ctx.os_version
            os_name                = $ctx.os_name
            ps_version             = $ctx.ps_version
            architecture           = $ctx.architecture
            execution_mode         = if ($filelessMode) { "fileless" } else { "disk" }
            checks_run             = $checksRun
            total_duration_seconds = $durationSeconds
        }
        findings = $AllFindings
        summary  = @{
            total_findings = $AllFindings.Count
            by_severity    = $bySeverity
        }
    }

    # =========================================================================
    # 8. JSON conversion
    # =========================================================================
    $json = $result | ConvertTo-Json -Depth 10 -Compress

    # =========================================================================
    # 9. Output delivery
    # =========================================================================
    $uploadSuccess = $false

    if ($filelessMode) {
        # --- Fileless: build in-memory zip and POST to server ---
        try {
            $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)

            $memStream = New-Object System.IO.MemoryStream
            $zipStream = New-Object System.IO.Compression.GZipStream(
                $memStream,
                [System.IO.Compression.CompressionMode]::Compress,
                $true
            )
            $zipStream.Write($jsonBytes, 0, $jsonBytes.Length)
            $zipStream.Close()
            $compressedBytes = $memStream.ToArray()
            $memStream.Close()

            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Content-Type", "application/octet-stream")
            $wc.Headers.Add("X-Seep-Hostname", $ctx.hostname)
            $wc.Headers.Add("X-Seep-Version",  $script:AgentVersion)
            $wc.Headers.Add("X-Seep-Encoding", "gzip")
            if ($authToken -ne "") {
                $wc.Headers.Add("X-Seep-Token", $authToken)
            }
            $null = $wc.UploadData($uploadUrl, "POST", $compressedBytes)

            $uploadSuccess = $true
            Write-Status "Results uploaded (fileless) to $uploadUrl" -Type "SUCCESS"
        } catch {
            Write-Status "Fileless upload failed ($_) - falling back to disk mode" -Type "WARNING"
            $filelessMode = $false
        }
    }

    # Disk mode (explicit, or fallback from failed fileless)
    if (-not $filelessMode -or -not $uploadSuccess) {
        try {
            if (-not (Test-Path $OutputDir)) {
                $null = New-Item -ItemType Directory -Path $OutputDir -Force
            }
            $jsonPath = Join-Path $OutputDir "results.json"
            [System.IO.File]::WriteAllText($jsonPath, $json, [System.Text.Encoding]::UTF8)
            Write-Status "Results written to $jsonPath" -Type "SUCCESS"

            # Upload zip if a target was specified
            if ($uploadUrl -ne "") {
                try {
                    $zipPath = Join-Path $OutputDir "results.zip"

                    # Build zip via .NET - compatible with PS 3+
                    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

                    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

                    $zipMemStream  = New-Object System.IO.MemoryStream
                    $archive       = New-Object System.IO.Compression.ZipArchive(
                        $zipMemStream,
                        [System.IO.Compression.ZipArchiveMode]::Create,
                        $true
                    )
                    $entry         = $archive.CreateEntry("results.json")
                    $entryStream   = $entry.Open()
                    $jsonBytesZip  = [System.Text.Encoding]::UTF8.GetBytes($json)
                    $entryStream.Write($jsonBytesZip, 0, $jsonBytesZip.Length)
                    $entryStream.Close()
                    $archive.Dispose()

                    [System.IO.File]::WriteAllBytes($zipPath, $zipMemStream.ToArray())
                    $zipMemStream.Close()

                    $wc2 = New-Object System.Net.WebClient
                    $wc2.Headers.Add("Content-Type",      "application/zip")
                    $wc2.Headers.Add("X-Seep-Hostname",   $ctx.hostname)
                    $wc2.Headers.Add("X-Seep-Version",    $script:AgentVersion)
                    if ($authToken -ne "") {
                        $wc2.Headers.Add("X-Seep-Token", $authToken)
                    }
                    $null = $wc2.UploadFile($uploadUrl, "POST", $zipPath)

                    $uploadSuccess = $true
                    Write-Status "Results uploaded (disk) to $uploadUrl" -Type "SUCCESS"
                } catch {
                    Write-Status "Upload failed: $_" -Type "ERROR"
                }
            }
        } catch {
            Write-Status "Failed to write results to disk: $_" -Type "ERROR"
        }

        # Cleanup disk artefacts if requested and upload succeeded
        if ($Cleanup.IsPresent -and $uploadSuccess) {
            try {
                Remove-Item -Path $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Output directory removed (cleanup)" -Type "INFO"
            } catch {
                Write-Status "Cleanup failed: $_" -Type "WARNING"
            }
        }
    }

    # =========================================================================
    # 10. Summary output
    # =========================================================================
    if (-not $script:SeepQuiet) {
        Write-Host ""
        Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Run complete  : $($checksRun.Count) check(s) in ${durationSeconds}s" -ForegroundColor White
        Write-Host "  Total findings: $($AllFindings.Count)" -ForegroundColor White

        # Severity breakdown
        $sevOrder = @("critical", "high", "medium", "low", "info", "error", "unknown")
        $sevColors = @{
            critical = "Magenta"
            high     = "Red"
            medium   = "Yellow"
            low      = "Cyan"
            info     = "Gray"
            error    = "DarkRed"
            unknown  = "DarkGray"
        }
        foreach ($sev in $sevOrder) {
            if ($bySeverity.ContainsKey($sev) -and $bySeverity[$sev] -gt 0) {
                $color = if ($sevColors.ContainsKey($sev)) { $sevColors[$sev] } else { "White" }
                Write-Host ("    {0,-10}: {1}" -f $sev.ToUpper(), $bySeverity[$sev]) -ForegroundColor $color
            }
        }

        # Highlight critical findings by title
        $criticals = $AllFindings | Where-Object { $_.severity -eq "critical" }
        if ($criticals) {
            Write-Host ""
            Write-Host "  [!] CRITICAL FINDINGS:" -ForegroundColor Magenta
            foreach ($c in $criticals) {
                Write-Host "      * $($c.title)" -ForegroundColor Magenta
            }
        }

        Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# =============================================================================
# Auto-run when executed directly (not dot-sourced or IEX'd as library)
# =============================================================================
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -ne '') {
    $params = @{}
    for ($i = 0; $i -lt $args.Count; $i++) {
        switch -Regex ($args[$i]) {
            '^-Server$'        { $params['Server']        = $args[++$i] }
            '^-Upload$'        { $params['Upload']        = $args[++$i] }
            '^-OutputDir$'     { $params['OutputDir']     = $args[++$i] }
            '^-SaveLocal$'     { $params['SaveLocal']     = $true }
            '^-Checks$'        { $params['Checks']        = $args[++$i] -split ',' }
            '^-ExcludeChecks$' { $params['ExcludeChecks'] = $args[++$i] -split ',' }
            '^-Category$'      { $params['Category']      = $args[++$i] }
            '^-Quiet$'         { $params['Quiet']         = $true }
            '^-Shuffle$'       { $params['Shuffle']       = $true }
            '^-Jitter$'        { $params['Jitter']        = [int]$args[++$i] }
            '^-Cleanup$'       { $params['Cleanup']       = $true }
            '^-RemoteHost$'    { $params['RemoteHost']    = $args[++$i] }
            '^-DownloadTools$' { $params['DownloadTools'] = $args[++$i] }
            '^-ToolsDir$'      { $params['ToolsDir']      = $args[++$i] }
            '^-Token$'         { $params['Token']         = $args[++$i] }
        }
    }
    Invoke-Seep @params
}
