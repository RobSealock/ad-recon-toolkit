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
    # Under Windows PowerShell 5.1, @(if (...) { Cmd } else { ... }) does not
    # reliably flatten a command's array output -- ConvertFrom-Json emits its
    # parsed array via a single (non-enumerated) WriteObject call, so @()
    # wraps that one call's result as ONE element instead of unrolling it,
    # nesting the existing array a level deeper on every save after the 2nd.
    # (Not an issue under pwsh/.NET Core, where this enumerates correctly.)
    # Assigning to a plain variable first, then @()-wrapping that variable
    # separately, avoids it -- @() reliably flattens an already-materialized
    # array sitting in a variable.
    if (Test-Path $filePath) {
        $parsed   = ConvertFrom-Json (Get-Content $filePath -Raw -Encoding UTF8)
        $existing = @($parsed)
    } else {
        $existing = @()
    }
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
    # See Save-ReconRecord above for why this is a two-step assign-then-wrap
    # rather than @(if (...) { Cmd } else { ... }) -- the latter doesn't
    # reliably flatten ConvertFrom-Json's array output under PS5.1.
    if (Test-Path $indexPath) {
        $parsed = ConvertFrom-Json (Get-Content $indexPath -Raw -Encoding UTF8)
        $index  = @($parsed)
    } else {
        $index = @()
    }
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
