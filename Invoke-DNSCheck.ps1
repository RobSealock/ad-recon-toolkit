<#
.SYNOPSIS
    Standalone one-shot DNS assessment. Runs the DNS collector in isolation.

.DESCRIPTION
    Executes only the DNS collector (zone enumeration, WPAD/wildcard/ISATAP
    detection, 24-hour new-record alert, orphaned record detection, DnsAdmins
    membership, and ADIDNS zone write-rights DACL walk) without triggering the
    full assessment pipeline or any other collector.

    Output is written to output\runs\<RunId>\ using the same normalized JSON
    schema as a full run, so the diff engine and report scripts work against it.
    A concise text summary is printed to the console on completion.

    Use this for:
      - One-time or ad-hoc DNS posture checks outside the weekly schedule
      - Post-change verification after DNS configuration changes
      - DNS-only runs in environments where the full pipeline is too noisy

.PARAMETER RepoRoot
    Root of the toolkit checkout. Defaults to the script's own directory.

.PARAMETER RunId
    Override the generated RunId. Useful when attaching DNS output to an
    existing run (e.g. the current week's scheduled run ID).

.PARAMETER NoGitCommit
    Do not commit the run output to git after collection.

.PARAMETER ShowFindings
    Print each finding to the console after collection (default: summary only).

.EXAMPLE
    # Standard one-shot run
    .\Invoke-DNSCheck.ps1

.EXAMPLE
    # Attach to an existing run, skip git commit
    .\Invoke-DNSCheck.ps1 -RunId '3f2a1b...' -NoGitCommit

.EXAMPLE
    # Print all findings inline
    .\Invoke-DNSCheck.ps1 -ShowFindings
#>
[CmdletBinding()]
param(
    [string]$RepoRoot    = $PSScriptRoot,
    [string]$RunId       = $null,
    [switch]$NoGitCommit,
    [switch]$ShowFindings
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2

# Prepend repo-local modules directory so Save-Module'd modules are found first
$_localModules = Join-Path $RepoRoot 'tools\modules'
if (Test-Path $_localModules) {
    $env:PSModulePath = "$_localModules$([System.IO.Path]::PathSeparator)$env:PSModulePath"
}

Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════════╗'
Write-Host '║        ad-recon-toolkit  —  DNS Check (standalone)          ║'
Write-Host '╚══════════════════════════════════════════════════════════════╝'
Write-Host ''

# ── Framework ─────────────────────────────────────────────────────────────────
foreach ($module in @('Schema','CollectorRegistry','RunContext','Repository','Connection')) {
    . (Join-Path $RepoRoot "framework\$module.ps1")
}

# ── Settings ──────────────────────────────────────────────────────────────────
$settingsPath      = Join-Path $RepoRoot 'config\settings.psd1'
$settingsLocalPath = Join-Path $RepoRoot 'config\settings.local.psd1'
$settings = if (Test-Path $settingsPath) { Import-PowerShellDataFile $settingsPath } else { @{} }
if (Test-Path $settingsLocalPath) {
    $local = Import-PowerShellDataFile $settingsLocalPath
    foreach ($k in $local.Keys) { $settings[$k] = $local[$k] }
}

# ── RunContext ─────────────────────────────────────────────────────────────────
# DNS collector only requires AnyAuthUser — no elevation needed.
$ctx = New-RunContext -RepoRoot $RepoRoot -HeldPrivileges @('AnyAuthUser') -ExistingRunId $RunId
Initialize-RemoteConnection -RunContext $ctx -Settings $settings

Write-Host "[DNS Check] RunId    : $($ctx.RunId)"
Write-Host "[DNS Check] Operator : $($ctx.Operator)"
Write-Host "[DNS Check] Host     : $($ctx.RunHost)  ($($ctx.Domain))"
Write-Host ''

# ── Load and register DNS collector only ──────────────────────────────────────
$collectorPath = Join-Path $RepoRoot 'collectors\DNS.collector.ps1'
if (-not (Test-Path $collectorPath)) {
    Write-Error "DNS collector not found at: $collectorPath"
    exit 1
}
. $collectorPath

$collectors = @(Get-RegisteredCollectors | Where-Object { $_.Name -eq 'DNS' })
if ($collectors.Count -eq 0) {
    Write-Error 'DNS collector did not register — check collectors\DNS.collector.ps1'
    exit 1
}

# ── Initialize run repository ─────────────────────────────────────────────────
$paths = Initialize-RunRepository -RepoRoot $ctx.RepoRoot -RunId $ctx.RunId

# ── Run ───────────────────────────────────────────────────────────────────────
Write-Host '[DNS Check] Running DNS collector...'
Write-Host ''

$startTime = Get-Date
$records   = @()
try {
    $records = @(& $collectors[0].Invoke -RunContext $ctx -Settings $settings -RunRoot $paths.RunRoot)
    foreach ($r in $records) {
        if ($null -ne $r) { Save-ReconRecord -Record $r -RunRoot $paths.RunRoot }
    }
} catch {
    Write-Warning "[DNS Check] Collector failed: $_"
}
$elapsed = [int]((Get-Date) - $startTime).TotalSeconds

Update-RunIndex -RepoRoot $ctx.RepoRoot -RunId $ctx.RunId -RunRoot $paths.RunRoot

# ── Console summary ───────────────────────────────────────────────────────────
Write-Host ''
Write-Host '─────────────────────────────────────────────────────────────────'
Write-Host '  DNS Check Results'
Write-Host '─────────────────────────────────────────────────────────────────'

$allFindings   = @($records | Where-Object { $_.findings } | ForEach-Object { $_.findings } | Where-Object { $_ })
$errors        = @($records | Where-Object { $_.recordType -eq 'collection-error' })
$zoneRecords   = @($records | Where-Object { $_.objectType -eq 'zone' })
$summaryRecord = $records   | Where-Object { $_.objectType -eq 'summary' } | Select-Object -First 1

if ($summaryRecord) {
    $a = $summaryRecord.attributes
    Write-Host "  Zones assessed : $($a.totalZones)"
    Write-Host "  New (24h)      : $($a.totalNew24h)"
    Write-Host "  Orphaned       : $($a.totalOrphaned)"
    Write-Host "  ADIDNS writers : $($a.adidnsWriters.Count) non-Tier-0 ACE(s)"
    Write-Host "  DnsAdmins      : $($a.dnsAdminMembers.Count) member(s)"
}

$sevOrder = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
$sorted   = $allFindings | Sort-Object { $sevOrder[$_.severity] ?? 9 }

Write-Host ''
Write-Host "  Findings: $($allFindings.Count)"

if ($allFindings.Count -gt 0) {
    Write-Host ''
    $sorted | Group-Object severity | Sort-Object { $sevOrder[$_.Name] ?? 9 } | ForEach-Object {
        Write-Host "    $($_.Name.ToUpper().PadRight(13)) $($_.Count) finding(s)"
    }

    if ($ShowFindings) {
        Write-Host ''
        Write-Host '  Detail:'
        foreach ($f in $sorted) {
            Write-Host ''
            Write-Host "  [$($f.severity.ToUpper())]  $($f.id)"
            Write-Host "  $($f.description)"
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Host ''
    Write-Host "  Collection errors: $($errors.Count)"
    $errors | ForEach-Object { Write-Host "    - $($_.target): $($_.errorMessage)" }
}

Write-Host ''
Write-Host '─────────────────────────────────────────────────────────────────'
Write-Host "  Elapsed  : ${elapsed}s"
Write-Host "  Output   : $($paths.RunRoot)"
Write-Host '─────────────────────────────────────────────────────────────────'
Write-Host ''

# ── Git commit ────────────────────────────────────────────────────────────────
if (-not $NoGitCommit -and $settings['GitCommitRuns']) {
    Invoke-GitCommitRun -RepoRoot $RepoRoot -RunId $ctx.RunId
}
