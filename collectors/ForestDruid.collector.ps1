# ForestDruid collector — ingests Forest Druid exported CSV report(s).
# MinPrivilege: AnyAuthUser (ingestion only — Forest Druid itself is GUI-driven).
# Forest Druid is GUI-only; this collector does NOT execute it or Backend\Collector.exe.
# Set ForestDruidExport in settings.psd1 to point at a specific export, or drop
# CSV exports (Defense Perimeter and/or Attack Paths) into output\forestdruid\.
#
# Schema note: Forest Druid's Export feature (Defense Perimeter / Attack Paths)
# has no documented CSV column reference — the User Guide describes the two
# export types but not their field names. Until a real export has been seen,
# this collector ingests generically (row count + discovered column names as
# a raw record) rather than guessing at severity/technique mappings the way
# the PurpleKnight collector does for its documented schema. Revisit once a
# live export confirms the real column layout.

function _ForestDruid_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records   = [System.Collections.Generic.List[object]]::new()
    $runId     = $RunContext.RunId
    $artDir    = Join-Path $RunRoot 'artifacts'
    $fdExportDir = Join-Path $RunContext.RepoRoot 'output\forestdruid'

    # Resolve export path(s): explicit setting > auto-scan output\forestdruid\
    $exportPaths = [System.Collections.Generic.List[string]]::new()
    if ($Settings['ForestDruidExport']) {
        $exportPaths.Add($Settings['ForestDruidExport'])
    } else {
        $found = Get-ChildItem -Path $fdExportDir -Filter '*.csv' -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending
        foreach ($f in $found) { $exportPaths.Add($f.FullName) }
        if ($found) {
            Write-Host "         [ForestDruid] Auto-discovered $($found.Count) export(s): $($found.Name -join ', ')"
        }
    }

    if ($exportPaths.Count -eq 0) {
        Write-Host "         [ForestDruid] No export found — continuing without Forest Druid data."
        Write-Host "         Save Forest Druid CSV export(s) (Defense Perimeter / Attack Paths) to: $fdExportDir"
        $records.Add((New-ReconRecord `
            -Collector  'ForestDruid' `
            -ObjectType 'collection-status' `
            -StableId   'ForestDruid:no-export' `
            -Category   'config' `
            -Tier       'T0' `
            -Attributes @{
                status     = 'no-export'
                exportDir  = $fdExportDir
                instruction= 'Run Forest Druid manually, classify security zone objects, export Defense Perimeter/Attack Paths CSV, save to output\forestdruid\'
            } `
            -RunId $runId))
        return $records
    }

    foreach ($exportPath in $exportPaths) {
        if (-not (Test-Path $exportPath)) {
            $records.Add((New-CollectionError -Collector 'ForestDruid' `
                -Target $exportPath -ErrorMessage "Export file not found at: $exportPath" -RunId $runId))
            continue
        }

        try {
            $destFile = Join-Path $artDir (Split-Path $exportPath -Leaf)
            Copy-Item $exportPath $destFile -Force

            $rows = Import-Csv $exportPath
            $columns = if ($rows.Count -gt 0) { @($rows[0].PSObject.Properties.Name) } else { @() }

            $records.Add((New-ReconRecord `
                -Collector      'ForestDruid' `
                -ObjectType     'export-summary' `
                -StableId       "ForestDruid:$(Split-Path $exportPath -Leaf)" `
                -Category       'config' `
                -Tier           'T0' `
                -CollectedAtPriv $false `
                -Attributes     @{
                    exportFile     = Split-Path $exportPath -Leaf
                    rowCount       = $rows.Count
                    columns        = $columns
                    collectionNote = 'Generic ingestion — Forest Druid CSV schema is undocumented; finding-level normalization (severity/technique mapping) pending a real export to validate column layout against'
                } `
                -RawArtifactRef (Split-Path $exportPath -Leaf) `
                -RunId          $runId))

        } catch {
            $records.Add((New-CollectionError -Collector 'ForestDruid' `
                -Target $exportPath -ErrorMessage $_.ToString() -RunId $runId))
        }
    }

    return $records
}

Register-Collector `
    -Name        'ForestDruid' `
    -Description 'Ingests Forest Druid exported CSV report(s) — does not execute Forest Druid or Backend\Collector.exe' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _ForestDruid_Collect @PSBoundParameters }
