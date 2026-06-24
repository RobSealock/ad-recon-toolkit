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
    # Two-step assign-then-wrap: under PS5.1, @(Cmd | ConvertFrom-Json) does not
    # reliably flatten a multi-element array (see framework\Repository.ps1).
    $indexParsed = ConvertFrom-Json (Get-Content $indexPath -Raw -Encoding UTF8)
    $index = @($indexParsed)
    # Sort by the run's actual timestamp, not runId -- runId is a random GUID,
    # so sorting by it picks whichever run has the lexicographically largest
    # GUID, not the most recent one. Cast to [datetime] rather than relying on
    # string sort of the ISO-8601 value to stay correct regardless of timezone
    # offset formatting.
    $prior = @($index | Where-Object { $_.runId -ne $NewRunId } |
        Sort-Object { [datetime]$_.time } -Descending | Select-Object -First 1)
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
    # -Filter combined with -Exclude on Get-ChildItem returns zero results under
    # PowerShell 5.1 (provider-level -Filter and client-side -Exclude don't compose) --
    # filter with -Filter alone and exclude via Where-Object instead.
    Get-ChildItem -Path $RunPath -Filter '*.json' | Where-Object { $_.Name -ne 'run-manifest.json' } |
        ForEach-Object {
            # NDJSON format: one JSON object per line (see framework\Repository.ps1).
            $items = @(Get-Content $_.FullName -Encoding UTF8 |
                Where-Object { $_.Trim() } | ForEach-Object { ConvertFrom-Json $_ })
            foreach ($r in $items) {
                # collection-error/review-required records have no 'category' field, and
                # normal records have no 'recordType' field -- check property existence
                # before dot-access so Set-StrictMode (inherited from Start-Assessment.ps1)
                # doesn't throw "property cannot be found" on the absent one.
                $propNames = $r.PSObject.Properties.Name
                if ($propNames -contains 'recordType' -and $r.recordType -in @('collection-error','review-required')) { continue }
                if (-not $IncludeState -and $propNames -contains 'category' -and $r.category -eq 'state') { continue }
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
        if ($va -is [array] -and $vb -is [array]) {
            # Arrays of objects (services, shares, scheduled tasks...) used to be
            # stringified whole-array-to-whole-array, so changing ONE element (e.g.
            # one service's state) dumped the entire array as Before/After -- often
            # hundreds of identical entries either side of the one real change.
            # Diff element-by-element via a recognizable key field instead, when
            # one exists, and report only what actually changed/added/removed.
            $keyField = $null
            if ($va.Count -gt 0) {
                foreach ($cand in @('name', 'id', 'stableId', 'samAccount')) {
                    if (@($va[0].PSObject.Properties.Name) -contains $cand) { $keyField = $cand; break }
                }
            }
            if ($keyField) {
                $mapA = @{}; foreach ($item in $va) { $mapA[[string]$item.$keyField] = $item }
                $mapB = @{}; foreach ($item in $vb) { $mapB[[string]$item.$keyField] = $item }
                $added       = @($mapB.Keys | Where-Object { -not $mapA.ContainsKey($_) })
                $removed     = @($mapA.Keys | Where-Object { -not $mapB.ContainsKey($_) })
                $changedKeys = @($mapA.Keys | Where-Object {
                    $mapB.ContainsKey($_) -and
                    (($mapA[$_] | ConvertTo-Json -Compress) -ne ($mapB[$_] | ConvertTo-Json -Compress))
                })
                if ($added.Count -eq 0 -and $removed.Count -eq 0 -and $changedKeys.Count -eq 0) {
                    $sa = $sb = $null
                } else {
                    $beforeParts = [System.Collections.Generic.List[string]]::new()
                    $afterParts  = [System.Collections.Generic.List[string]]::new()
                    foreach ($ck in $changedKeys) {
                        $beforeParts.Add("$ck=$($mapA[$ck] | ConvertTo-Json -Compress)")
                        $afterParts.Add("$ck=$($mapB[$ck] | ConvertTo-Json -Compress)")
                    }
                    foreach ($rk in $removed) { $beforeParts.Add("$rk=$($mapA[$rk] | ConvertTo-Json -Compress)") }
                    foreach ($ak in $added)   { $afterParts.Add("$ak=$($mapB[$ak] | ConvertTo-Json -Compress)") }
                    $sa = $beforeParts -join '; '
                    $sb = $afterParts -join '; '
                }
            } else {
                $sa = ($va | ConvertTo-Json -Compress)
                $sb = ($vb | ConvertTo-Json -Compress)
            }
        } else {
            $sa = if ($va -is [array]) { ($va | ConvertTo-Json -Compress) } else { "$va" }
            $sb = if ($vb -is [array]) { ($vb | ConvertTo-Json -Compress) } else { "$vb" }
        }
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

# Casting Hashtable.Keys directly to HashSet[string] does not enumerate the
# keys -- PowerShell has no element-wise converter for the untyped KeyCollection,
# so it stringifies the whole collection (joining all keys with $OFS) and wraps
# that single string as the only HashSet element. Going through [string[]] first
# forces proper element-wise enumeration.
$keysA = [System.Collections.Generic.HashSet[string]]([string[]]$recA.Keys)
$keysB = [System.Collections.Generic.HashSet[string]]([string[]]$recB.Keys)

# Wrapped in @() throughout -- Where-Object/foreach collecting expressions yield
# $null (zero matches) or a bare scalar (one match) rather than an array, and
# Set-StrictMode disables the usual "any object responds to .Count" convenience,
# so an unwrapped single-match result breaks every .Count check below.
$added   = @($keysB | Where-Object { $_ -notin $keysA })
$removed = @($keysA | Where-Object { $_ -notin $keysB })
$common  = @($keysA | Where-Object { $_ -in $keysB })

# ── Compute diffs ─────────────────────────────────────────────────────────────
$changed = @(foreach ($key in $common) {
    $attrA = $recA[$key].attributes
    $attrB = $recB[$key].attributes
    $diff  = Get-AttributeDiff -ObjA $attrA -ObjB $attrB
    if ($diff.Count -gt 0) {
        @{ Key = $key; Diff = $diff }
    }
})

# ── Finding-level diff ────────────────────────────────────────────────────────
# Compares finding IDs on records common to both runs — surfaces findings that
# appeared (new) or resolved (gone) between runs. Attribute drift alone does not
# capture this because findings live in record.findings[], not record.attributes.
$findingChanges = @(foreach ($key in $common) {
    $idsA = @($recA[$key].findings | Where-Object { $_ } | ForEach-Object { $_.id })
    $idsB = @($recB[$key].findings | Where-Object { $_ } | ForEach-Object { $_.id })
    $newF      = @($idsB | Where-Object { $_ -notin $idsA })
    $resolvedF = @($idsA | Where-Object { $_ -notin $idsB })
    if ($newF.Count -gt 0 -or $resolvedF.Count -gt 0) {
        @{ Key = $key; New = $newF; Resolved = $resolvedF; Record = $recA[$key] }
    }
})

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
$lines.Add("| Finding changes (new/resolved) | $($findingChanges.Count) record(s) |")
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

if ($findingChanges) {
    $lines.Add("## Finding Changes")
    $lines.Add("")
    $lines.Add("_Finding IDs that appeared or resolved on records common to both runs._")
    $lines.Add("_Findings on newly added or removed records are implied by the Added/Removed sections above._")
    $lines.Add("")
    foreach ($fc in $findingChanges | Sort-Object { $_.Key }) {
        $r = $fc.Record
        $lines.Add("### $($r.collector) / $($r.objectType) — ``$($r.stableId)``")
        $lines.Add("")
        foreach ($fid in $fc.New)      { $lines.Add("- **NEW** ``$fid``") }
        foreach ($fid in $fc.Resolved) { $lines.Add("- ~~``$fid``~~ resolved") }
        $lines.Add("")
    }
}

if (-not $added -and -not $removed -and -not $changed -and -not $findingChanges) {
    $lines.Add("_No configuration drift or finding changes detected between these two runs._")
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
Write-Host "[Diff] Added: $($added.Count)  Removed: $($removed.Count)  Changed: $($changed.Count)  FindingChanges: $($findingChanges.Count)"

return [PSCustomObject]@{
    AddedCount          = $added.Count
    RemovedCount        = $removed.Count
    ChangedCount        = $changed.Count
    FindingChangesCount = $findingChanges.Count
    ReportPath          = $OutputPath
}
