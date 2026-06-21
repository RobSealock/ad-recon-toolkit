# PingCastle collector — ingests PingCastle XML report and normalizes findings.
# MinPrivilege: T0 (PingCastle requires domain-level read access; run elevated).
# Binary: tools\bin\PingCastle.exe  (fetched by Install-Prereqs.ps1)

function _PingCastle_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId
    $binPath  = Join-Path $RunContext.RepoRoot 'tools\bin\PingCastle.exe'
    $artDir   = Join-Path $RunRoot 'artifacts'

    # Toggle check
    if ($Settings['EnablePingCastle'] -eq $false) {
        $records.Add((New-ReconRecord `
            -Collector 'PingCastle' -ObjectType 'collection-status' `
            -StableId 'PingCastle:disabled' -Category 'config' -Tier 'T0' `
            -Attributes @{ status = 'disabled'; reason = 'EnablePingCastle = $false in settings.psd1' } `
            -RunId $runId))
        return $records
    }

    if (-not (Test-Path $binPath)) {
        $records.Add((New-CollectionError -Collector 'PingCastle' `
            -Target 'tools\bin\PingCastle.exe' `
            -ErrorMessage 'Binary not found. Run Install-Prereqs.ps1 or pre-stage tools\bin\PingCastle.exe.' `
            -RunId $runId))
        return $records
    }

    try {
        Write-Host "         Running PingCastle against $($RunContext.Domain)..."
        $outputXml = Join-Path $artDir 'ad_hc_report.xml'

        # PingCastle writes output to its working directory; run from artDir
        Push-Location $artDir
        try {
            & $binPath --healthcheck --server $RunContext.Domain --no-enum-limit 2>&1 | Out-Null
        } finally {
            Pop-Location
        }

        # Locate the generated report (PingCastle names it ad_hc_<domain>.xml)
        $reportFile = Get-ChildItem -Path $artDir -Filter 'ad_hc_*.xml' | Select-Object -First 1
        if (-not $reportFile) { throw 'PingCastle did not produce an output XML' }

        [xml]$report = Get-Content $reportFile.FullName -Raw -Encoding UTF8

        $score = $report.HealthcheckData.GlobalScore
        $attrs = @{
            domain         = $report.HealthcheckData.DomainFQDN
            globalScore    = $score
            maturityLevel  = $report.HealthcheckData.MaturityLevel
            reportFile     = $reportFile.Name
            collectionNote = 'Full rule-level finding normalization implemented in PingCastle extension milestone'
        }

        $pcFindings = [System.Collections.Generic.List[object]]::new()
        if ([int]$score -gt 50) {
            $pcFindings.Add((New-Finding -Id 'PC-001' -Severity 'High' `
                -Description "PingCastle global risk score is $score (>50). Review the full report for individual rule findings." `
                -Reference 'https://www.pingcastle.com/PingCastleFiles/ad_hc_guide.pdf'))
        }

        $records.Add((New-ReconRecord `
            -Collector      'PingCastle' `
            -ObjectType     'healthcheck' `
            -StableId       "PingCastle:$($RunContext.Domain)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     $attrs `
            -Findings       $pcFindings.ToArray() `
            -RawArtifactRef $reportFile.Name `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'PingCastle' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'PingCastle' `
    -Description 'AD health check and risk score via PingCastle; ingests XML report' `
    -MinPrivilege 'T0' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _PingCastle_Collect @PSBoundParameters }
