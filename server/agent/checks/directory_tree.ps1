# check_id: directory_tree
# check_name: Directory Tree
# category: filesystem
# description: Enumerates directory trees for common paths
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 5

function Invoke-CheckDirectoryTree {
    [CmdletBinding()]
    param(
        [hashtable]$Config = @{}
    )

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    # Helper: run tree.com and capture first N lines
    function Get-TreeOutput {
        param([string]$Path, [int]$MaxLines = 200)
        if (-not (Test-Path -Path $Path -PathType Container)) {
            return "[PATH NOT FOUND] $Path"
        }
        $out = (& tree $Path /F /A 2>&1) | Select-Object -First $MaxLines | Out-String
        if (-not $out -or $out.Trim() -eq "") {
            # tree.com may not be available - fall back to Get-ChildItem recursive
            $out = try {
                Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                    Select-Object -First $MaxLines |
                    ForEach-Object { $_.FullName } |
                    Out-String
            } catch {
                "[tree and Get-ChildItem both failed for $Path]: $_"
            }
        }
        return $out
    }

    # Helper: flat directory listing (non-recursive, one level)
    function Get-DirListing {
        param([string]$Path)
        if (-not (Test-Path -Path $Path -PathType Container)) {
            return "[PATH NOT FOUND] $Path"
        }
        try {
            Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue |
                Format-Table -AutoSize Name, LastWriteTime, Length, Attributes |
                Out-String
        } catch {
            "[Failed to list $Path]: $_"
        }
    }

    # C:\Users - tree, first 200 lines
    $usersTree = Get-TreeOutput -Path "C:\Users" -MaxLines 200

    # C:\Program Files - flat listing (can be enormous as a tree)
    $progFiles = Get-DirListing -Path "C:\Program Files"

    # C:\Program Files (x86) - flat listing
    $progFiles86 = Get-DirListing -Path "C:\Program Files (x86)"

    # C:\inetpub - tree only if it exists, first 150 lines
    $inetpubSection = ""
    if (Test-Path -Path "C:\inetpub" -PathType Container) {
        $inetpubTree = Get-TreeOutput -Path "C:\inetpub" -MaxLines 150
        $inetpubSection = @"

=== C:\inetpub (tree, first 150 lines) ===
$inetpubTree
"@
    } else {
        $inetpubSection = "`n=== C:\inetpub ===`n[NOT FOUND - IIS may not be installed]`n"
    }

    $evidence = @"
=== C:\Users (tree, first 200 lines) ===
$usersTree

=== C:\Program Files (directory listing) ===
$progFiles

=== C:\Program Files (x86) (directory listing) ===
$progFiles86
$inetpubSection
"@

    $findings += New-Finding `
        -CheckId    "directory_tree" `
        -FindingId  "directory_tree_raw" `
        -Severity   "info" `
        -Title      "Directory Tree Enumeration" `
        -Description 'Directory tree and listing for C:\Users (tree), C:\Program Files, C:\Program Files (x86) (flat listing), and C:\inetpub (tree, if present). Useful for identifying user profiles, installed software layout, and web root contents.' `
        -Evidence   $evidence `
        -Tags       @("filesystem", "directory", "inetpub", "raw")

    return $findings
}
