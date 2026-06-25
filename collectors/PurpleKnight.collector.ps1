# PurpleKnight collector — ingests an exported PurpleKnight HTML or CSV report.
# MinPrivilege: AnyAuthUser (ingestion only — PurpleKnight itself is GUI-driven).
# PurpleKnight is GUI-only; this collector does NOT execute it.
# Set PurpleKnightExport in settings.psd1 to point at the exported file.

function _PurpleKnight_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records    = [System.Collections.Generic.List[object]]::new()
    $runId      = $RunContext.RunId
    $artDir     = Join-Path $RunRoot 'artifacts'
    $pkExportDir= Join-Path $RunContext.RepoRoot 'output\purpleknight'

    # Resolve export path: explicit setting > auto-scan output\purpleknight\ > prompt
    $exportPath = $Settings['PurpleKnightExport']

    if (-not $exportPath) {
        $latest = Get-ChildItem -Path $pkExportDir -ErrorAction SilentlyContinue |
                  Where-Object { $_.Extension -in @('.csv', '.html') } |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            $exportPath = $latest.FullName
            Write-Host "         [PurpleKnight] Auto-discovered export: $($latest.Name)"
        }
    }

    if (-not $exportPath) {
        Write-Host "         [PurpleKnight] No export found — continuing without PurpleKnight data."
        Write-Host "         Save a PurpleKnight CSV export to: $pkExportDir"
        $records.Add((New-ReconRecord `
            -Collector  'PurpleKnight' `
            -ObjectType 'collection-status' `
            -StableId   'PurpleKnight:no-export' `
            -Category   'config' `
            -Tier       'T0' `
            -Attributes @{
                status     = 'no-export'
                exportDir  = $pkExportDir
                instruction= 'Run PurpleKnight manually on a DC, export CSV (preferred) or HTML, save to output\purpleknight\'
            } `
            -RunId $runId))
        return $records
    }

    if (-not (Test-Path $exportPath)) {
        $records.Add((New-CollectionError -Collector 'PurpleKnight' `
            -Target $exportPath `
            -ErrorMessage "Export file not found at: $exportPath" `
            -RunId $runId))
        return $records
    }

    try {
        # Copy artifact
        $destFile = Join-Path $artDir (Split-Path $exportPath -Leaf)
        Copy-Item $exportPath $destFile -Force

        $ext = (Split-Path $exportPath -Extension).ToLower()
        $pkFindings = [System.Collections.Generic.List[object]]::new()
        $indicatorCount = 0

        if ($ext -eq '.csv') {
            $rows = Import-Csv $exportPath
            $indicatorCount = $rows.Count
            foreach ($row in $rows) {
                if ($row.Severity -match 'Critical|High') {
                    $pkFindings.Add((New-Finding `
                        -Id          "PK-$($row.ControlId)" `
                        -Severity    $(if ($row.Severity -eq 'Critical') { 'Critical' } else { 'High' }) `
                        -Technique   $row.MitreTechnique `
                        -Description $row.Description `
                        -Reference   'https://purple-knight.com/'))
                }
            }
        } else {
            $indicatorCount = 'unknown (HTML — CSV export recommended for structured ingestion)'
        }

        $records.Add((New-ReconRecord `
            -Collector      'PurpleKnight' `
            -ObjectType     'indicator-summary' `
            -StableId       "PurpleKnight:$($RunContext.Domain)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                exportFile     = Split-Path $exportPath -Leaf
                indicatorCount = $indicatorCount
                exportFormat   = $ext.TrimStart('.')
                collectionNote = 'Full indicator-level normalization implemented in PurpleKnight extension milestone'
            } `
            -Findings       $pkFindings.ToArray() `
            -RawArtifactRef (Split-Path $exportPath -Leaf) `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'PurpleKnight' `
            -Target $exportPath -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'PurpleKnight' `
    -Description 'Ingests PurpleKnight exported report (CSV or HTML) — does not execute PurpleKnight' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _PurpleKnight_Collect @PSBoundParameters }
