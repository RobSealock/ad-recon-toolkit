<#
.SYNOPSIS
    Manifest-driven collector orchestrator.

.DESCRIPTION
    Loads all *.collector.ps1 files, runs each against the supplied RunContext
    based on held privileges, and persists normalized JSON output.
    Called by Start-Assessment.ps1 — not intended to be run directly.

.PARAMETER RunContext
    PSCustomObject from New-RunContext.

.PARAMETER CollectorsPath
    Path to the collectors directory. Defaults to .\collectors.

.PARAMETER Settings
    Hashtable from config/settings.psd1.

.PARAMETER CollectorFilter
    Optional array of collector names to run. When supplied, only collectors
    whose Name matches an entry are executed. Case-insensitive. Supports
    partial matches (e.g., 'AD-Core','DNS'). Leave $null to run all eligible.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][PSCustomObject]$RunContext,
    [string]$CollectorsPath  = (Join-Path $PSScriptRoot 'collectors'),
    [hashtable]$Settings     = @{},
    [string[]]$CollectorFilter = $null
)

$ErrorActionPreference = 'Continue'

# Load framework modules (idempotent — functions are just redefined if already loaded)
foreach ($module in @('Schema','CollectorRegistry','RunContext','Repository','Connection')) {
    . (Join-Path $PSScriptRoot "framework\$module.ps1")
}

Initialize-RemoteConnection -RunContext $RunContext -Settings $Settings

# Register all collectors found in the collectors directory
Get-ChildItem -Path $CollectorsPath -Filter '*.collector.ps1' -ErrorAction Stop |
    Sort-Object Name |
    ForEach-Object {
        Write-Verbose "[Orchestrator] Loading: $($_.Name)"
        . $_.FullName
    }

$collectors = @(Get-RegisteredCollectors)
$statusLog  = [System.Collections.Generic.List[hashtable]]::new()
$paths      = Initialize-RunRepository -RepoRoot $RunContext.RepoRoot -RunId $RunContext.RunId

Write-Host ""
Write-Host "[Orchestrator] Run $($RunContext.RunId)"
Write-Host "[Orchestrator] $($collectors.Count) collector(s) registered"
Write-Host "[Orchestrator] Held privileges: $($RunContext.HeldPrivileges -join ', ')"
Write-Host ""

foreach ($c in $collectors) {
    # Apply collector filter (pipeline mode or partial run)
    if ($CollectorFilter -and $CollectorFilter.Count -gt 0) {
        $matched = $CollectorFilter | Where-Object { $c.Name -ieq $_ -or $c.Name -ilike "*$_*" }
        if (-not $matched) {
            $statusLog.Add(@{ collector = $c.Name; status = 'filtered'; reason = 'not in CollectorFilter' })
            continue
        }
    }

    if (-not (Test-CollectorEligible -Collector $c -HeldPrivileges $RunContext.HeldPrivileges)) {
        Write-Host "  [SKIP] $($c.Name)  — requires $($c.MinPrivilege)"
        $statusLog.Add(@{
            collector = $c.Name
            status    = 'skipped'
            reason    = "requires $($c.MinPrivilege); held: $($RunContext.HeldPrivileges -join ',')"
        })
        continue
    }

    Write-Host "  [RUN ] $($c.Name)"
    try {
        $records = @(& $c.Invoke -RunContext $RunContext -Settings $Settings -RunRoot $paths.RunRoot)
        $count   = 0
        foreach ($r in $records) {
            if ($null -ne $r) {
                Save-ReconRecord -Record $r -RunRoot $paths.RunRoot
                $count++
            }
        }
        Write-Host "         $count record(s)"
        $statusLog.Add(@{ collector = $c.Name; status = 'completed'; records = $count })
    } catch {
        Write-Warning "  [FAIL] $($c.Name): $_"
        $err = New-CollectionError -Collector $c.Name -Target $RunContext.RunHost `
            -ErrorMessage $_.ToString() -RunId $RunContext.RunId
        Save-ReconRecord -Record $err -RunRoot $paths.RunRoot
        $statusLog.Add(@{ collector = $c.Name; status = 'failed'; error = $_.ToString() })
    }
}

Save-RunManifest  -RunContext $RunContext -RunRoot $paths.RunRoot -CollectorStatus $statusLog.ToArray()
Update-RunIndex   -RepoRoot $RunContext.RepoRoot -RunId $RunContext.RunId -RunRoot $paths.RunRoot

# Auto drift comparison — compares against the previous run if one exists
$diffScript = Join-Path $PSScriptRoot 'diff\Compare-ReconRuns.ps1'
if (Test-Path $diffScript) {
    try {
        & $diffScript -AutoSelectPrevious -NewRunId $RunContext.RunId -RepoRoot $RunContext.RepoRoot | Out-Null
    } catch {
        Write-Warning "[Orchestrator] Drift comparison skipped: $_"
    }
}

Write-Host ""
Write-Host "[Orchestrator] Complete — $($paths.RunRoot)"
Write-Host ""

return $paths
