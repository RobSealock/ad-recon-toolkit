<#
.SYNOPSIS
    Compares two assessment runs and reports configuration drift.

.DESCRIPTION
    Reads normalized JSON records from two run directories, compares `config`
    category records by (collector, objectType, stableId), and reports:
      - Added records (present in RunB, absent in RunA)
      - Removed records (present in RunA, absent in RunB)
      - Changed records (present in both; attribute-level diff)

    `state` category records are excluded by default (volatile: sessions,
    replication status, etc.) to produce clean drift reports.

.PARAMETER RunAPath
    Path to the first run directory (baseline). Accepts a full path or
    a run ID (resolved from output\run-index.json).

.PARAMETER RunBPath
    Path to the second run directory (comparison). Same format.

.PARAMETER RepoRoot
    Root of the toolkit repo. Used to resolve run IDs from the index.

.PARAMETER IncludeState
    Include `state` category records in the comparison (noisy).

.PARAMETER OutputPath
    Write the diff report to this file (Markdown). Defaults to
    output\diffs\diff-<RunA>-vs-<RunB>.md.

.PARAMETER AutoSelectPrevious
    When supplied (pipeline mode), RunAPath is not required. The script
    automatically selects the most recent previous run from run-index.json
    as the baseline, and uses NewRunId as the comparison run.

.PARAMETER NewRunId
    Used with -AutoSelectPrevious. The run ID to use as the comparison (RunB).
#>
[CmdletBinding(DefaultParameterSetName='Explicit')]
param(
    [Parameter(Mandatory, ParameterSetName='Explicit')][string]$RunAPath,
    [Parameter(Mandatory, ParameterSetName='Explicit')][string]$RunBPath,
    [Parameter(Mandatory, ParameterSetName='Auto')][switch]$AutoSelectPrevious,
    [Parameter(Mandatory, ParameterSetName='Auto')][string]$NewRunId,
    [string]$RepoRoot    = (Split-Path $PSScriptRoot -Parent),
    [switch]$IncludeState,
    [string]$OutputPath  = $null
)

$ErrorActionPreference = 'Stop'

# Auto-select previous run from index (pipeline mode)
if ($AutoSelectPrevious) {
    $indexPath = Join-Path $RepoRoot 'output\run-index.json'
    if (-not (Test-Path $indexPath)) {
        Write-Host "[Diff] No run index found — skipping drift comparison."
        return $null
    }
    $index = @(Get-Content $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    $prior = @($index | Where-Object { $_.runId -ne $NewRunId } | Sort-Object runId -Descending | Select-Object -First 1)
    if (-not $prior) {
        Write-Host "[Diff] Only one run in index — no baseline for comparison. Skipping."
        return $null
    }
    $RunAPath = $prior[0].runRoot
    $RunBPath = Join-Path $RepoRoot "output\runs\$NewRunId"
}

function Resolve-RunPath {
    param([string]$PathOrId, [string]$RepoRoot)
    if (Test-Path $PathOrId) { return $PathOrId }
    $indexPath = Join-Path $RepoRoot 'output\run-index.json'
    if (-not (Test-Path $indexPath)) { throw "Cannot resolve run '$PathOrId' — index not found at $indexPath" }
    $index = Get-Content $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $entry = $index | Where-Object { $_.runId -eq $PathOrId } | Select-Object -Last 1
    if (-not $entry) { throw "Run ID '$PathOrId' not found in run index" }
    return $entry.runRoot
}

function Load-RunRecords {
    param([string]$RunPath, [bool]$IncludeState)
    $records = @{}
    Get-ChildItem -Path $RunPath -Filter '*.json' -Exclude 'run-manifest.json' |
        ForEach-Object {
            $items = @(Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)
            foreach ($r in $items) {
                if (-not $IncludeState -and $r.category -eq 'state') { continue }
                if ($r.recordType -in @('collection-error','review-required')) { continue }
                $key = "$($r.collector)|$($r.objectType)|$($r.stableId)"
                $records[$key] = $r
            }
        }
    return $records
}

function Get-AttributeDiff {
    param($ObjA, $ObjB)
    $changes = @{}
    $allKeys = (@($ObjA.PSObject.Properties.Name) + @($ObjB.PSObject.Properties.Name)) | Select-Object -Unique
    foreach ($k in $allKeys) {
        $va = $ObjA.$k
        $vb = $ObjB.$k
        $sa = if ($va -is [array]) { ($va | ConvertTo-Json -Compress) } else { "$va" }
        $sb = if ($vb -is [array]) { ($vb | ConvertTo-Json -Compress) } else { "$vb" }
        if ($sa -ne $sb) { $changes[$k] = @{ Before = $sa; After = $sb } }
    }
    return $changes
}

# ── Resolve paths ─────────────────────────────────────────────────────────────
$resolvedA = Resolve-RunPath -PathOrId $RunAPath -RepoRoot $RepoRoot
$resolvedB = Resolve-RunPath -PathOrId $RunBPath -RepoRoot $RepoRoot

$manifestA = Join-Path $resolvedA 'run-manifest.json'
$manifestB = Join-Path $resolvedB 'run-manifest.json'
$runIdA    = if (Test-Path $manifestA) { (Get-Content $manifestA -Raw | ConvertFrom-Json).runId } else { Split-Path $resolvedA -Leaf }
$runIdB    = if (Test-Path $manifestB) { (Get-Content $manifestB -Raw | ConvertFrom-Json).runId } else { Split-Path $resolvedB -Leaf }

Write-Host "[Diff] Baseline : $runIdA  ($resolvedA)"
Write-Host "[Diff] Compare  : $runIdB  ($resolvedB)"

# ── Load records ──────────────────────────────────────────────────────────────
$recA = Load-RunRecords -RunPath $resolvedA -IncludeState $IncludeState.IsPresent
$recB = Load-RunRecords -RunPath $resolvedB -IncludeState $IncludeState.IsPresent

$keysA = [System.Collections.Generic.HashSet[string]]$recA.Keys
$keysB = [System.Collections.Generic.HashSet[string]]$recB.Keys

$added   = $keysB | Where-Object { $_ -notin $keysA }
$removed = $keysA | Where-Object { $_ -notin $keysB }
$common  = $keysA | Where-Object { $_ -in $keysB }

# ── Compute diffs ─────────────────────────────────────────────────────────────
$changed = foreach ($key in $common) {
    $attrA = $recA[$key].attributes
    $attrB = $recB[$key].attributes
    $diff  = Get-AttributeDiff -ObjA $attrA -ObjB $attrB
    if ($diff.Count -gt 0) {
        @{ Key = $key; Diff = $diff }
    }
}

# ── Report ────────────────────────────────────────────────────────────────────
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# Config Drift Report")
$lines.Add("")
$lines.Add("| | |")
$lines.Add("|---|---|")
$lines.Add("| **Baseline** | $runIdA |")
$lines.Add("| **Compare**  | $runIdB |")
$lines.Add("| **Generated**| $(Get-Date -Format 'o') |")
$lines.Add("")
$lines.Add("## Summary")
$lines.Add("")
$lines.Add("| Change | Count |")
$lines.Add("|---|---|")
$lines.Add("| Added (new in compare) | $($added.Count) |")
$lines.Add("| Removed (absent in compare) | $($removed.Count) |")
$lines.Add("| Changed (attribute drift) | $($changed.Count) |")
$lines.Add("")

if ($added) {
    $lines.Add("## Added Records")
    $lines.Add("")
    foreach ($k in $added | Sort-Object) {
        $r = $recB[$k]
        $lines.Add("- **$($r.collector) / $($r.objectType)** `— ``$($r.stableId)``  [Tier: $($r.tier)]")
    }
    $lines.Add("")
}

if ($removed) {
    $lines.Add("## Removed Records")
    $lines.Add("")
    foreach ($k in $removed | Sort-Object) {
        $r = $recA[$k]
        $lines.Add("- **$($r.collector) / $($r.objectType)** `— ``$($r.stableId)``  [Tier: $($r.tier)]")
    }
    $lines.Add("")
}

if ($changed) {
    $lines.Add("## Changed Records")
    $lines.Add("")
    foreach ($item in $changed | Sort-Object { $_.Key }) {
        $r = $recA[$item.Key]
        $lines.Add("### $($r.collector) / $($r.objectType) — ``$($r.stableId)``")
        $lines.Add("")
        $lines.Add("| Attribute | Before | After |")
        $lines.Add("|---|---|---|")
        foreach ($attr in $item.Diff.Keys | Sort-Object) {
            $before = $item.Diff[$attr].Before
            $after  = $item.Diff[$attr].After
            $lines.Add("| $attr | $before | $after |")
        }
        $lines.Add("")
    }
}

if (-not $added -and -not $removed -and -not $changed) {
    $lines.Add("_No configuration drift detected between these two runs._")
    $lines.Add("")
}

$report = $lines -join "`n"

# ── Write output ──────────────────────────────────────────────────────────────
if (-not $OutputPath) {
    $diffDir    = Join-Path $RepoRoot 'output\diffs'
    New-Item -ItemType Directory -Force -Path $diffDir | Out-Null
    $OutputPath = Join-Path $diffDir "diff-$runIdA-vs-$runIdB.md"
}
$report | Set-Content $OutputPath -Encoding UTF8
Write-Host "[Diff] Report → $OutputPath"
Write-Host "[Diff] Added: $($added.Count)  Removed: $($removed.Count)  Changed: $($changed.Count)"

return [PSCustomObject]@{
    AddedCount   = $added.Count
    RemovedCount = $removed.Count
    ChangedCount = $changed.Count
    ReportPath   = $OutputPath
}
