# JSON-per-run storage: initialize paths, save records, write manifest, update index.

function Initialize-RunRepository {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$RunId
    )
    $paths = [PSCustomObject]@{
        RunRoot   = Join-Path $RepoRoot "output\runs\$RunId"
        Artifacts = Join-Path $RepoRoot "output\runs\$RunId\artifacts"
        Diffs     = Join-Path $RepoRoot "output\diffs"
        Reports   = Join-Path $RepoRoot "output\reports"
    }
    foreach ($p in @($paths.RunRoot, $paths.Artifacts, $paths.Diffs, $paths.Reports)) {
        New-Item -ItemType Directory -Force -Path $p | Out-Null
    }
    return $paths
}

function Save-ReconRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Record,
        [Parameter(Mandatory)][string]$RunRoot
    )
    # One file per (collector, objectType) pair — append to JSON array.
    $fileName = "$($Record.collector).$($Record.objectType).json"
    $filePath  = Join-Path $RunRoot $fileName
    $existing  = if (Test-Path $filePath) {
        @(Get-Content $filePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } else { @() }
    ($existing + $Record) | ConvertTo-Json -Depth 20 -Compress | Set-Content $filePath -Encoding UTF8
}

function Save-RunManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$RunContext,
        [Parameter(Mandatory)][string]$RunRoot,
        [hashtable[]]$CollectorStatus = @()
    )
    [PSCustomObject]@{
        runId           = $RunContext.RunId
        startTime       = $RunContext.StartTime
        endTime         = (Get-Date -Format 'o')
        operator        = $RunContext.Operator
        runHost         = $RunContext.RunHost
        domain          = $RunContext.Domain
        isElevated      = $RunContext.IsElevated
        heldPrivileges  = @($RunContext.HeldPrivileges)
        collectorStatus = $CollectorStatus
    } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $RunRoot 'run-manifest.json') -Encoding UTF8
}

function Update-RunIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RunRoot
    )
    $indexPath = Join-Path $RepoRoot 'output\run-index.json'
    $index = if (Test-Path $indexPath) {
        @(Get-Content $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } else { @() }
    ($index + [PSCustomObject]@{
        runId   = $RunId
        runRoot = $RunRoot
        time    = (Get-Date -Format 'o')
    }) | ConvertTo-Json -Depth 5 | Set-Content $indexPath -Encoding UTF8
}

function Invoke-GitCommitRun {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$RunId
    )
    Push-Location $RepoRoot
    try {
        git add "output\runs\$RunId" "output\run-index.json" 2>&1 | Out-Null
        git commit -m "run: $RunId" 2>&1 | Out-Null
        Write-Host "[Repository] Git commit created for run $RunId"
    } catch {
        Write-Warning "[Repository] Git commit skipped: $_"
    } finally {
        Pop-Location
    }
}
