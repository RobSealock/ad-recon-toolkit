<#
.SYNOPSIS
    Generates a comprehensive Markdown risk register from a completed run's JSON records.

.DESCRIPTION
    Loads all ReconRecord findings from the run directory, applies severity-tier priority
    scoring, cross-references ATT&CK mappings, and emits a structured Markdown document
    suitable for stakeholder reporting and AI-assisted analysis.

.PARAMETER RunRoot
    Path to the specific run directory (output\runs\<RunId>\).

.PARAMETER RepoRoot
    Path to the repository root.

.PARAMETER OutputPath
    Optional override for the output file path. Defaults to output\reports\risk-register-<RunId>.md.

.PARAMETER AttackMappingsPath
    Path to finding-attack-atomic.psd1. Defaults to <RepoRoot>\mappings\finding-attack-atomic.psd1.

.EXAMPLE
    .\report\New-RiskRegister.ps1 -RunRoot .\output\runs\2024-01-15T09-00-00Z -RepoRoot .
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$RepoRoot,
    [string]$OutputPath       = $null,
    [string]$AttackMappingsPath = $null
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# ── Resolve paths ─────────────────────────────────────────────────────────────
if (-not (Test-Path $RunRoot))  { throw "RunRoot not found: $RunRoot" }
$runId      = Split-Path $RunRoot -Leaf
$reportsDir = Join-Path $RepoRoot 'output\reports'
New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null

if (-not $OutputPath)         { $OutputPath         = Join-Path $reportsDir "risk-register-$runId.md" }
if (-not $AttackMappingsPath) { $AttackMappingsPath  = Join-Path $RepoRoot  'mappings\finding-attack-atomic.psd1' }

# ── Load ATT&CK mappings ──────────────────────────────────────────────────────
$attackMappings = @{}
if (Test-Path $AttackMappingsPath) {
    try { $attackMappings = Import-PowerShellDataFile $AttackMappingsPath }
    catch { Write-Warning "[RiskRegister] Could not load ATT&CK mappings: $_" }
}

# ── Severity priority (lower = more critical) ─────────────────────────────────
$severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
$tierOrder     = @{ T0=0; T1=1; T2=2; T3=3; unclassified=4 }

# Severity badge HTML-ish text for Markdown
$severityBadge = @{
    Critical     = '**CRITICAL**'
    High         = '**HIGH**'
    Medium       = 'MEDIUM'
    Low          = 'Low'
    Informational= '*Info*'
}

# ── Load all records and extract findings ─────────────────────────────────────
$allFindings  = [System.Collections.Generic.List[hashtable]]::new()
$runManifest  = $null
$collectorSet = [System.Collections.Generic.HashSet[string]]::new()
$errorCount   = 0
$recordCount  = 0

# Load run manifest for metadata
$manifestPath = Join-Path $RunRoot 'run-manifest.json'
if (Test-Path $manifestPath) {
    try { $runManifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
}

# Enumerate all JSON files in run root (not subdirs)
Get-ChildItem -Path $RunRoot -Filter '*.json' -Depth 0 |
    Where-Object { $_.Name -notin @('run-manifest.json') } |
    ForEach-Object {
        $currentFile = $_
        try {
            # Two-step assign-then-wrap: under PS5.1, @(Cmd | ConvertFrom-Json)
            # does not reliably flatten a multi-element array (see
            # framework\Repository.ps1 for the full explanation).
            $itemsParsed = ConvertFrom-Json (Get-Content $currentFile.FullName -Raw -Encoding UTF8)
            $items = @($itemsParsed)
            foreach ($r in $items) {
                $recordCount++
                $collector = if ($r.collector) { $r.collector } else { 'unknown' }
                [void]$collectorSet.Add($collector)

                if ($r.category -eq 'error') { $errorCount++ }

                if ($r.findings) {
                    foreach ($f in $r.findings) {
                        $mapping = if ($attackMappings.ContainsKey($f.id)) { $attackMappings[$f.id] } else { $null }
                        $techNames = if ($mapping) { $mapping.TechniqueNames -join '; ' } else { '' }
                        $atomicTest= if ($mapping -and $mapping.AtomicTests.Count -gt 0) { $mapping.AtomicTests[0].Name } else { '—' }
                        $blastRadius = if ($mapping) { $mapping.BlastRadius } else { '—' }
                        $severityValue = if ($f.severity) { $f.severity } else { 'Informational' }
                        $tierValue     = if ($r.tier)      { $r.tier      } else { 'unclassified' }

                        $allFindings.Add(@{
                            Collector      = $collector
                            ObjectType     = if ($r.objectType) { $r.objectType } else { '' }
                            StableId       = if ($r.stableId)   { $r.stableId   } else { '' }
                            Tier           = $tierValue
                            Severity       = $severityValue
                            SeverityRank   = $severityOrder[$severityValue]
                            TierRank       = $tierOrder[$tierValue]
                            FindingId      = if ($f.id)          { $f.id         } else { '?' }
                            Technique      = if ($f.technique)   { $f.technique  } else { '—' }
                            TechniqueName  = $techNames
                            Description    = if ($f.description) { $f.description} else { '' }
                            Reference      = if ($f.reference)   { $f.reference  } else { '' }
                            AtomicTest     = $atomicTest
                            BlastRadius    = $blastRadius
                        })
                    }
                }
            }
        } catch { Write-Warning "[RiskRegister] Failed to parse $($currentFile.Name): $_" }
    }

$sorted = $allFindings | Sort-Object { $_.SeverityRank }, { $_.TierRank }, { $_.FindingId }

# ── Summary stats ─────────────────────────────────────────────────────────────
$critCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical'     }).Count
$highCount = @($allFindings | Where-Object { $_.Severity -eq 'High'         }).Count
$medCount  = @($allFindings | Where-Object { $_.Severity -eq 'Medium'       }).Count
$lowCount  = @($allFindings | Where-Object { $_.Severity -eq 'Low'          }).Count
$infoCount = @($allFindings | Where-Object { $_.Severity -eq 'Informational'}).Count

$t0Count   = @($allFindings | Where-Object { $_.Tier -eq 'T0' }).Count
$t1Count   = @($allFindings | Where-Object { $_.Tier -eq 'T1' }).Count

# ── Build Markdown ────────────────────────────────────────────────────────────
$sb = [System.Text.StringBuilder]::new()

function Add { param([string]$line = '') $sb.AppendLine($line) | Out-Null }

# Header
Add "# AD Blue-Team Risk Register"
Add ""
Add "> **Assessment Run:** ``$runId``"
if ($runManifest) {
    Add "> **Domain:** $($runManifest.domain)"
    Add "> **Run Host:** $($runManifest.runHost)"
    Add "> **Operator:** $($runManifest.operator)"
    Add "> **Start Time:** $($runManifest.startTime)"
    Add "> **Collectors Run:** $(($runManifest.collectorStatus | ForEach-Object { $_.collector }) -join ', ')"
}
Add "> **Generated:** $(Get-Date -Date ([DateTime]::UtcNow) -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Add ""

# ── Executive Summary ─────────────────────────────────────────────────────────
Add "## Executive Summary"
Add ""
Add "| Metric | Value |"
Add "|--------|-------|"
Add "| Total Findings | $($allFindings.Count) |"
Add "| Critical | $critCount |"
Add "| High | $highCount |"
Add "| Medium | $medCount |"
Add "| Low | $lowCount |"
Add "| Informational | $infoCount |"
Add "| Tier-0 Findings | $t0Count |"
Add "| Tier-1 Findings | $t1Count |"
Add "| Records Collected | $recordCount |"
Add "| Collection Errors | $errorCount |"
Add "| Collectors Active | $($collectorSet.Count) ($(($collectorSet | Sort-Object) -join ', ')) |"
Add ""

if ($critCount -gt 0 -or $highCount -gt 0) {
    Add "> :warning: **Immediate Action Required** — $critCount Critical and $highCount High findings detected."
    Add "> Prioritize Tier-0 remediation to prevent domain compromise."
    Add ""
}

# ── Tier-0 Critical/High Focus ────────────────────────────────────────────────
$tier0CritHigh = @($sorted | Where-Object { $_.Tier -eq 'T0' -and $_.Severity -in @('Critical','High') })
if ($tier0CritHigh.Count -gt 0) {
    Add "## Tier-0 Critical and High Findings"
    Add ""
    Add "These findings represent the highest risk to domain integrity and should be remediated first."
    Add ""
    Add "| # | ID | Severity | Collector | Technique | Description |"
    Add "|---|----|----|----|----|-----|"
    $i = 1
    foreach ($f in $tier0CritHigh) {
        $tech = if ($f.Technique -ne '—') { "[$($f.Technique)](https://attack.mitre.org/techniques/$($f.Technique.Replace('.','/'))/)" } else { '—' }
        $desc = $f.Description -replace '\|', '\\|' -replace '\n',' '
        Add "| $i | $($f.FindingId) | $($severityBadge[$f.Severity]) | $($f.Collector) | $tech | $desc |"
        $i++
    }
    Add ""
}

# ── Complete Risk Register ────────────────────────────────────────────────────
Add "## Complete Risk Register"
Add ""
Add "_Sorted by severity then tier. Click ATT&CK technique IDs for MITRE documentation._"
Add ""
Add "| # | ID | Severity | Tier | Collector | Technique | ATT&CK Name | Description | Validation |"
Add "|---|----|----------|------|-----------|-----------|-------------|-------------|------------|"

$i = 1
foreach ($f in $sorted) {
    $tech     = if ($f.Technique -ne '—') { "[$($f.Technique)](https://attack.mitre.org/techniques/$($f.Technique.Replace('.','/')))/" } else { '—' }
    $desc     = ($f.Description -replace '\|', '\\|' -replace '\n',' ').Substring(0, [Math]::Min(200, $f.Description.Length))
    $techName = if ($f.TechniqueName) { $f.TechniqueName } else { '—' }
    $atomic   = if ($f.AtomicTest -ne '—') { $f.AtomicTest -replace '\|','\\|' } else { '—' }
    Add "| $i | $($f.FindingId) | $($severityBadge[$f.Severity]) | $($f.Tier) | $($f.Collector) | $tech | $techName | $desc | $atomic |"
    $i++
}
if ($allFindings.Count -eq 0) {
    Add "| — | — | — | — | — | — | No findings collected in this run | — | — |"
}
Add ""

# ── Per-Collector Breakdown ───────────────────────────────────────────────────
Add "## Findings by Collector"
Add ""
foreach ($collector in ($collectorSet | Sort-Object)) {
    $cFindings = @($sorted | Where-Object { $_.Collector -eq $collector })
    if ($cFindings.Count -eq 0) { continue }
    Add "### $collector ($($cFindings.Count))"
    Add ""
    foreach ($f in $cFindings) {
        $badge = $severityBadge[$f.Severity]
        Add "- **$($f.FindingId)** [$badge] $($f.Description)"
        if ($f.Technique -ne '—') {
            Add "  - ATT&CK: $($f.Technique) — $($f.TechniqueName)"
        }
        if ($f.Reference) {
            Add "  - Reference: $($f.Reference)"
        }
    }
    Add ""
}

# ── ATT&CK Technique Frequency ────────────────────────────────────────────────
# Group-Object -Property <name> (string form) does not resolve hashtable keys
# under Windows PowerShell 5.1 -- $allFindings is a List[hashtable], so this
# silently grouped everything into one blank-named group. The script-block
# form ({ $_.Technique }) resolves correctly on both PS5.1 and pwsh.
$techniqueGroups = $allFindings |
    Where-Object { $_.Technique -ne '—' } |
    Group-Object -Property { $_.Technique } |
    Sort-Object Count -Descending |
    Select-Object -First 20

if ($techniqueGroups) {
    Add "## ATT&CK Technique Frequency"
    Add ""
    Add "_Top techniques by finding count — prioritize detection coverage for high-frequency techniques._"
    Add ""
    Add "| Technique | Name | Count |"
    Add "|-----------|------|-------|"
    foreach ($tg in $techniqueGroups) {
        $techName = ($allFindings | Where-Object { $_.Technique -eq $tg.Name } | Select-Object -First 1).TechniqueName
        Add "| [$($tg.Name)](https://attack.mitre.org/techniques/$($tg.Name.Replace('.','/'))/) | $techName | $($tg.Count) |"
    }
    Add ""
}

# ── AI-Consumable JSON block ──────────────────────────────────────────────────
Add "## AI-Consumable Finding Summary"
Add ""
Add "_Structured JSON for LLM-assisted remediation planning. Paste into your AI assistant._"
Add ""
Add '```json'
$aiPayload = @{
    runId    = $runId
    domain   = if ($runManifest) { $runManifest.domain } else { 'unknown' }
    generated= (Get-Date -Format 'o')
    counts   = @{
        critical     = $critCount
        high         = $highCount
        medium       = $medCount
        low          = $lowCount
        informational= $infoCount
        tier0        = $t0Count
    }
    findings = @(
        $sorted | Select-Object -First 50 | ForEach-Object {
            @{
                id          = $_.FindingId
                severity    = $_.Severity
                tier        = $_.Tier
                collector   = $_.Collector
                technique   = $_.Technique
                description = if ($_.Description.Length -gt 300) { $_.Description.Substring(0,300) + '...' } else { $_.Description }
            }
        }
    )
}
Add ($aiPayload | ConvertTo-Json -Depth 5 -Compress)
Add '```'
Add ""
Add "---"
Add "_Generated by ad-recon-toolkit · https://github.com/RobSealock/ad-recon-toolkit_"

# ── Write output ──────────────────────────────────────────────────────────────
$sb.ToString() | Set-Content $OutputPath -Encoding UTF8
Write-Host "[RiskRegister] → $OutputPath"
Write-Host "[RiskRegister] $($allFindings.Count) finding(s) · $critCount Critical · $highCount High · $medCount Medium · $lowCount Low"
return $OutputPath
