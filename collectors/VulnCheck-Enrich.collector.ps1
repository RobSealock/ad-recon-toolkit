# VulnCheck-Enrich collector — correlates software versions from Host-OS records
# against the CISA KEV dataset (or VulnCheck API) for known-exploited CVEs.
# MinPrivilege: AnyAuthUser (reads local KEV JSON file; no network auth required for CISA KEV).
# Depends on: Host-OS collector records (runs after Host-OS in a later milestone).

function _VulnCheckEnrich_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId
    $kevPath  = Join-Path $RunContext.RepoRoot 'tools\kev\known_exploited_vulnerabilities.json'

    if (-not (Test-Path $kevPath)) {
        $records.Add((New-ReconRecord `
            -Collector  'VulnCheck-Enrich' `
            -ObjectType 'collection-status' `
            -StableId   'KEV:not-staged' `
            -Category   'config' `
            -Tier       'unclassified' `
            -Attributes @{
                status  = 'skipped'
                reason  = 'CISA KEV dataset not found. Run Install-Prereqs.ps1 to download it.'
                kevPath = $kevPath
            } `
            -RunId $runId))
        return $records
    }

    try {
        $kev         = Get-Content $kevPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $kevCount    = $kev.vulnerabilities.Count
        $catalogDate = $kev.catalogVersion

        # Milestone 1 stub: KEV is staged; enrichment against Host-OS software records
        # is implemented once Host-OS collector (Milestone 2) is in place.
        $records.Add((New-ReconRecord `
            -Collector      'VulnCheck-Enrich' `
            -ObjectType     'kev-status' `
            -StableId       'KEV:dataset' `
            -Category       'config' `
            -Tier           'unclassified' `
            -CollectedAtPriv $false `
            -Attributes     @{
                catalogVersion = $catalogDate
                entryCount     = $kevCount
                kevPath        = $kevPath
                collectionNote = 'KEV dataset staged and validated. CVE-to-software correlation implemented once Host-OS collector is available (Milestone 2).'
            } `
            -RunId $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'VulnCheck-Enrich' `
            -Target $kevPath -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'VulnCheck-Enrich' `
    -Description 'Correlates installed software versions against CISA KEV / VulnCheck for known-exploited CVEs' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _VulnCheckEnrich_Collect @PSBoundParameters }
