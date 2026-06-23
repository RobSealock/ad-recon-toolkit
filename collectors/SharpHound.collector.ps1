# SharpHound collector — BloodHound CE data collection (attack-path graph).
# MinPrivilege: T0 (needs domain user at minimum; T0 held = run elevated).
# Binary: tools\bin\SharpHound.exe  (fetched by Install-Prereqs.ps1)

function _SharpHound_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId
    $binPath = Join-Path $RunContext.RepoRoot 'tools\bin\SharpHound.exe'
    $artDir  = Join-Path $RunRoot 'artifacts'

    if ($Settings['EnableSharpHound'] -eq $false) {
        $records.Add((New-ReconRecord `
            -Collector 'SharpHound' -ObjectType 'collection-status' `
            -StableId 'SharpHound:disabled' -Category 'config' -Tier 'T0' `
            -Attributes @{ status = 'disabled'; reason = 'EnableSharpHound = $false in settings.psd1' } `
            -RunId $runId))
        return $records
    }

    if (-not (Test-Path $binPath)) {
        $records.Add((New-CollectionError -Collector 'SharpHound' `
            -Target 'tools\bin\SharpHound.exe' `
            -ErrorMessage 'Binary not found. Run Install-Prereqs.ps1 or pre-stage tools\bin\SharpHound.exe.' `
            -RunId $runId))
        return $records
    }

    try {
        Write-Host "         Running SharpHound against $($RunContext.Domain)..."
        $zipFile = $null

        # CollectAll for CtF; production may subset (e.g., --CollectionMethods Default)
        & $binPath --CollectionMethods All --Domain $RunContext.Domain --OutputDirectory $artDir `
            --ZipFilename "sharphound-$runId.zip" --NoSaveCache 2>&1 | Out-Null

        $zipFile = Get-ChildItem -Path $artDir -Filter 'sharphound-*.zip' | Select-Object -First 1

        $attrs = @{
            domain         = $RunContext.Domain
            zipFile        = if ($zipFile) { $zipFile.Name } else { 'not produced' }
            collectionNote = 'Import the zip into BloodHound CE for attack-path analysis. API upload not yet implemented.'
        }

        # BloodHound CE API upload (optional)
        if ($Settings['BloodHoundApiUrl'] -and $zipFile) {
            $attrs['uploadStatus'] = 'not-implemented — see New-BHUpload.ps1 in a future milestone'
        }

        $records.Add((New-ReconRecord `
            -Collector      'SharpHound' `
            -ObjectType     'bloodhound-collection' `
            -StableId       "SharpHound:$($RunContext.Domain)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     $attrs `
            -RawArtifactRef $(if ($zipFile) { $zipFile.Name } else { $null }) `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'SharpHound' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'SharpHound' `
    -Description 'BloodHound CE data collection (attack paths, ACLs, sessions) via SharpHound' `
    -MinPrivilege 'T0' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _SharpHound_Collect @PSBoundParameters }
