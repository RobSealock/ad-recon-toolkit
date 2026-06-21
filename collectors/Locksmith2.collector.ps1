# Locksmith2 collector — AD CS / PKI vulnerabilities ESC1-ESC16.
# MinPrivilege: CARead (Locksmith needs to read CA enrollment services and templates).
# Module: Locksmith (installed from PSGallery by Install-Prereqs.ps1)

function _Locksmith_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId
    $artDir  = Join-Path $RunRoot 'artifacts'

    if ($Settings['EnableLocksmith'] -eq $false) {
        $records.Add((New-ReconRecord `
            -Collector 'Locksmith2' -ObjectType 'collection-status' `
            -StableId 'Locksmith:disabled' -Category 'config' -Tier 'T0' `
            -Attributes @{ status = 'disabled'; reason = 'EnableLocksmith = $false in settings.psd1' } `
            -RunId $runId))
        return $records
    }

    if (-not (Get-Module -ListAvailable -Name Locksmith)) {
        $records.Add((New-CollectionError -Collector 'Locksmith2' `
            -Target 'PSGallery:Locksmith' `
            -ErrorMessage 'Locksmith module not installed. Run Install-Prereqs.ps1.' `
            -RunId $runId))
        return $records
    }

    try {
        Import-Module Locksmith -ErrorAction Stop

        Write-Host "         Running Locksmith against $($RunContext.Domain)..."
        $locksmithOutput = Join-Path $artDir 'locksmith-output.json'

        # Locksmith returns finding objects; output to JSON artifact
        $findings = Invoke-Locksmith -Domain $RunContext.Domain -OutputPath $artDir `
            -Scans All 2>&1

        $lockFindings = [System.Collections.Generic.List[object]]::new()
        $count = 0
        foreach ($f in $findings) {
            if ($f.Technique) {
                $lockFindings.Add((New-Finding `
                    -Id        "LOCKSMITH-$($f.Technique)" `
                    -Severity  $(if ($f.Severity) { $f.Severity } else { 'High' }) `
                    -Technique $f.Technique `
                    -Description $f.Description `
                    -Reference 'https://github.com/TrimarcJake/Locksmith'))
                $count++
            }
        }

        $records.Add((New-ReconRecord `
            -Collector      'Locksmith2' `
            -ObjectType     'adcs-findings' `
            -StableId       "Locksmith:$($RunContext.Domain)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     @{
                domain         = $RunContext.Domain
                findingCount   = $count
                artifactDir    = $artDir
                collectionNote = 'Raw Locksmith output in artifacts\; finding normalization extended in CA-Config milestone'
            } `
            -Findings       $lockFindings.ToArray() `
            -RawArtifactRef 'locksmith-*' `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'Locksmith2' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'Locksmith2' `
    -Description 'AD CS / PKI vulnerability scan (ESC1-ESC16) via Locksmith module' `
    -MinPrivilege 'CARead' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _Locksmith_Collect @PSBoundParameters }
