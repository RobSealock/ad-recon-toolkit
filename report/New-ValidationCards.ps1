<#
.SYNOPSIS
    Generates change-management-ready validation cards for each finding.

.DESCRIPTION
    For every finding in the completed run, produces a standalone Markdown
    validation card containing:
      - Finding context (collector, tier, description)
      - ATT&CK technique and sub-technique name
      - Non-destructive Atomic Red Team test to confirm the finding is real
      - Blast radius (what the test does, what it does NOT do)
      - Windows Event IDs to check post-test
      - Change management note (read-only; no approval required by default)

    Output: one .md file per finding ID under output\validation\<RunId>\.
    Also generates a combined index card at validation-index.md.

    All Atomic test references in the mappings file use non-destructive,
    read-only variants only — safe to run under change-control observation.

.PARAMETER RunRoot
    Path to the specific run directory (output\runs\<RunId>\).

.PARAMETER RepoRoot
    Path to the repository root.

.PARAMETER OutputDir
    Optional override for the output directory.

.PARAMETER AttackMappingsPath
    Path to finding-attack-atomic.psd1.

.EXAMPLE
    .\report\New-ValidationCards.ps1 -RunRoot .\output\runs\2024-01-15T09-00-00Z -RepoRoot .
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$RepoRoot,
    [string]$OutputDir          = $null,
    [string]$AttackMappingsPath = $null
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $RunRoot)) { throw "RunRoot not found: $RunRoot" }
$runId = Split-Path $RunRoot -Leaf

if (-not $OutputDir)          { $OutputDir          = Join-Path $RepoRoot "output\validation\$runId" }
if (-not $AttackMappingsPath) { $AttackMappingsPath  = Join-Path $RepoRoot 'mappings\finding-attack-atomic.psd1' }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ── Load mappings ─────────────────────────────────────────────────────────────
$attackMappings = @{}
if (Test-Path $AttackMappingsPath) {
    try { $attackMappings = Import-PowerShellDataFile $AttackMappingsPath }
    catch { Write-Warning "[ValidationCards] Could not load ATT&CK mappings: $_" }
}

$severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }

# ── Load findings from run ────────────────────────────────────────────────────
$allFindings = [System.Collections.Generic.List[hashtable]]::new()
Get-ChildItem -Path $RunRoot -Filter '*.json' -Depth 0 |
    Where-Object { $_.Name -ne 'run-manifest.json' } |
    ForEach-Object {
        try {
            @(Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) | ForEach-Object {
                $r = $_
                if ($r.findings) {
                    foreach ($f in $r.findings) {
                        $allFindings.Add(@{
                            Collector  = $r.collector
                            StableId   = $r.stableId
                            Tier       = if ($r.tier) { $r.tier } else { 'unclassified' }
                            Severity   = if ($f.severity) { $f.severity } else { 'Informational' }
                            FindingId  = $f.id
                            Technique  = if ($f.technique) { $f.technique } else { '' }
                            Description= if ($f.description) { $f.description } else { '' }
                            Reference  = if ($f.reference) { $f.reference } else { '' }
                        })
                    }
                }
            }
        } catch {}
    }

# Deduplicate by FindingId (one card per finding type)
$byFindingId = @{}
foreach ($f in $allFindings | Sort-Object { $severityOrder[$_.Severity] }) {
    if (-not $byFindingId.ContainsKey($f.FindingId)) {
        $byFindingId[$f.FindingId] = [System.Collections.Generic.List[hashtable]]::new()
    }
    [void]$byFindingId[$f.FindingId].Add($f)
}

Write-Host "[ValidationCards] $($byFindingId.Count) unique finding type(s) found"

# ── Change management header block ───────────────────────────────────────────
$changeMgmtNote = @'
> **Change Management Classification:** Read-Only Assessment
> **Approval Required:** None — all validation steps are passive/read-only.
> **Rollback Required:** None (or as specified per test).
> **Impact:** Informational — no production state is modified.
> **Observer Required:** Yes (change control observer recommended for audit trail).
'@

# ── Per-finding card ──────────────────────────────────────────────────────────

$indexEntries = [System.Collections.Generic.List[hashtable]]::new()

foreach ($findingId in $byFindingId.Keys | Sort-Object) {
    $instances = $byFindingId[$findingId]
    $primary   = $instances[0]
    $mapping   = if ($attackMappings.ContainsKey($findingId)) { $attackMappings[$findingId] } else { $null }

    $sb = [System.Text.StringBuilder]::new()
    function a { param([string]$l='') $sb.AppendLine($l) | Out-Null }

    # Header
    a "# Validation Card: $findingId"
    a ""
    a "| | |"
    a "|--|--|"
    a "| **Finding ID** | $findingId |"
    a "| **Severity** | $($primary.Severity) |"
    a "| **Tier** | $($primary.Tier) |"
    a "| **Collector** | $($primary.Collector) |"
    if ($primary.Technique) {
        a "| **ATT&CK Technique** | [$($primary.Technique)](https://attack.mitre.org/techniques/$($primary.Technique.Replace('.','/'))/)) |"
    }
    a "| **Run ID** | $runId |"
    a ""

    # Technique names
    if ($mapping -and $mapping.TechniqueNames) {
        a "## ATT&CK Context"
        a ""
        foreach ($tn in $mapping.TechniqueNames) { a "- $tn" }
        a ""
    }

    # Description
    a "## Finding Description"
    a ""
    a $primary.Description
    a ""

    # All affected objects (if multiple instances)
    if ($instances.Count -gt 1) {
        a "## Affected Objects ($($instances.Count))"
        a ""
        foreach ($inst in $instances | Select-Object -First 30) {
            a "- ``$($inst.StableId)``"
        }
        if ($instances.Count -gt 30) { a "_… and $($instances.Count - 30) more_" }
        a ""
    }

    # Change management block
    a "## Change Management"
    a ""
    a $changeMgmtNote
    a ""

    # Validation steps (Atomic test)
    a "## Validation Steps"
    a ""
    if ($mapping -and $mapping.AtomicTests -and $mapping.AtomicTests.Count -gt 0) {
        $i = 1
        foreach ($test in $mapping.AtomicTests) {
            a "### Test $i — $($test.Name)"
            a ""
            if ($test.Guid -and $test.Guid -ne 'N/A') {
                a "**Atomic Red Team GUID:** ``$($test.Guid)``"
                a ""
                a "**Run with:**"
                a '```powershell'
                a "Invoke-AtomicTest $($primary.Technique) -TestGuids $($test.Guid) -WhatIf"
                a "# Review the WhatIf output first, then run without -WhatIf when approved."
                a '```'
                a ""
            } else {
                a "**Manual test (no Atomic GUID — perform manually):**"
                a ""
                a "``$($test.Name)``"
                a ""
            }
            a "**Destructive:** $(if($test.Destructive){'⚠️ YES — requires additional approval'}else{'No'})"
            a ""
            a "**Rollback:** $($test.Rollback)"
            a ""
            $i++
        }
    } else {
        a "_No automated Atomic test mapped for this finding. Perform manual verification per the description above._"
        a ""
    }

    # Blast radius
    if ($mapping) {
        a "## Blast Radius"
        a ""
        a "| | |"
        a "|--|--|"
        a "| **What this test does** | $($mapping.BlastRadius) |"
        a "| **Minimum privilege** | $($mapping.MinPriv) |"
        a ""
    }

    # Confirmation events
    if ($mapping -and $mapping.ConfirmationEvents -and $mapping.ConfirmationEvents.Count -gt 0) {
        a "## Confirmation — Event IDs to Check"
        a ""
        a "After running the validation, check Windows Security Event Log for:"
        a ""
        a "| Event ID | Expected |"
        a "|----------|---------|"
        foreach ($evId in $mapping.ConfirmationEvents) {
            $evDesc = switch ($evId) {
                4624  { "Logon Success" }
                4625  { "Logon Failure" }
                4662  { "Object operation (AD)" }
                4698  { "Scheduled task created" }
                4702  { "Scheduled task modified" }
                4719  { "Audit policy change" }
                4741  { "Computer account created" }
                4768  { "Kerberos TGT request" }
                4769  { "Kerberos service ticket request" }
                4771  { "Kerberos pre-auth failed" }
                4886  { "Certificate requested" }
                4887  { "Certificate issued" }
                5136  { "AD object modified" }
                5140  { "Network share access" }
                5156  { "Network connection permitted" }
                5157  { "Network connection blocked" }
                7036  { "Service state change" }
                2003  { "Firewall rule changed" }
                2004  { "Firewall rule added" }
                2889  { "Unsigned LDAP connection" }
                3000  { "SMBv1 used" }
                770   { "DNS zone update" }
                771   { "DNS record created" }
                default { "See Microsoft documentation" }
            }
            a "| $evId | $evDesc |"
        }
        a ""
    }

    # Reference
    if ($primary.Reference) {
        a "## References"
        a ""
        a "- ATT&CK: $($primary.Reference)"
        if ($mapping -and $mapping.AtomicTests.Count -gt 0 -and $mapping.AtomicTests[0].Guid -ne 'N/A') {
            a "- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/$($primary.Technique)/$($primary.Technique).md"
        }
        a ""
    }

    a "---"
    a "_Generated by ad-recon-toolkit · Run: $runId_"

    # Write card
    $safeId  = $findingId -replace '[^a-zA-Z0-9\-]','-'
    $cardPath = Join-Path $OutputDir "card-$safeId.md"
    $sb.ToString() | Set-Content $cardPath -Encoding UTF8

    $indexEntries.Add(@{
        FindingId  = $findingId
        Severity   = $primary.Severity
        Tier       = $primary.Tier
        Collector  = $primary.Collector
        Count      = $instances.Count
        File       = "card-$safeId.md"
    })
    Write-Host "[ValidationCards] → card-$safeId.md ($($instances.Count) instance(s))"
}

# ── Index page ────────────────────────────────────────────────────────────────
$idxSb = [System.Text.StringBuilder]::new()
function ai { param([string]$l='') $idxSb.AppendLine($l) | Out-Null }

ai "# Validation Cards Index — $runId"
ai ""
ai "Non-destructive validation procedures for each finding in this assessment run."
ai ""
ai $changeMgmtNote
ai ""
ai "| Finding | Severity | Tier | Collector | Instances | Card |"
ai "|---------|----------|------|-----------|-----------|------|"

foreach ($e in $indexEntries | Sort-Object { $severityOrder[$_.Severity] }, { $_.Tier }, { $_.FindingId }) {
    ai "| $($e.FindingId) | $($e.Severity) | $($e.Tier) | $($e.Collector) | $($e.Count) | [$($e.FindingId)]($($e.File)) |"
}

$idxPath = Join-Path $OutputDir 'validation-index.md'
$idxSb.ToString() | Set-Content $idxPath -Encoding UTF8
Write-Host "[ValidationCards] Index → validation-index.md"
Write-Host "[ValidationCards] Complete — $($byFindingId.Count) card(s) in $OutputDir"
return $OutputDir
