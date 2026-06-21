<#
.SYNOPSIS
    Generates a Markdown risk register from a completed run's JSON records.
    Milestone 1 stub — full implementation in Milestone 6 (Report layer).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$RepoRoot,
    [string]$OutputPath = $null
)

if (-not $OutputPath) {
    $reportsDir = Join-Path $RepoRoot 'output\reports'
    New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null
    $runId      = Split-Path $RunRoot -Leaf
    $OutputPath = Join-Path $reportsDir "risk-register-$runId.md"
}

# Collect all findings from all record files in the run
$allFindings = [System.Collections.Generic.List[hashtable]]::new()

Get-ChildItem -Path $RunRoot -Filter '*.json' -Exclude 'run-manifest.json' |
    ForEach-Object {
        $items = @(Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)
        foreach ($r in $items) {
            if ($r.findings) {
                foreach ($f in $r.findings) {
                    $allFindings.Add(@{
                        Collector  = $r.collector
                        ObjectType = $r.objectType
                        StableId   = $r.stableId
                        Tier       = $r.tier
                        Severity   = $f.severity
                        FindingId  = $f.id
                        Technique  = $f.technique
                        Description= $f.description
                        Reference  = $f.reference
                    })
                }
            }
        }
    }

$order = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
$sorted = $allFindings | Sort-Object { $order[$_.Severity] }, Tier, FindingId

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# Risk Register")
$lines.Add("")
$lines.Add("Run: ``$(Split-Path $RunRoot -Leaf)``  Generated: $(Get-Date -Format 'o')")
$lines.Add("")
$lines.Add("> This is a Milestone-1 stub register. Full severity x tier prioritization,")
$lines.Add("> ATT&CK cross-references, and validation card links are implemented in")
$lines.Add("> the Report layer milestone (Milestone 6).")
$lines.Add("")
$lines.Add("| # | Severity | Tier | Collector | Finding ID | Technique | Description |")
$lines.Add("|---|---|---|---|---|---|---|")

$i = 1
foreach ($f in $sorted) {
    $tech = if ($f.Technique) { $f.Technique } else { '—' }
    $lines.Add("| $i | $($f.Severity) | $($f.Tier) | $($f.Collector) | $($f.FindingId) | $tech | $($f.Description) |")
    $i++
}

if ($allFindings.Count -eq 0) {
    $lines.Add("| — | — | — | — | No findings collected in this run | — | — |")
}

$lines.Add("")
$lines.Add("**Total findings: $($allFindings.Count)**")

$lines -join "`n" | Set-Content $OutputPath -Encoding UTF8
Write-Host "[Report] Risk register → $OutputPath  ($($allFindings.Count) finding(s))"
