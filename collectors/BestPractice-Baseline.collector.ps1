# BestPractice-Baseline collector — HardeningKitty integration.
# MinPrivilege: LocalAdmin (HardeningKitty requires local admin for registry/policy reads).
#
# Disabled by default (EnableHardeningKitty = $false in settings.psd1).
# Enable in settings.local.psd1 for environments where a formal CIS/DISA baseline
# comparison is required.
#
# HardeningKitty runs in audit mode only — it does NOT change any settings.
# Findings: BP-001 through BP-004

function _BPBaseline_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId
    $artDir  = Join-Path $RunRoot 'artifacts'

    if ($Settings['EnableHardeningKitty'] -eq $false) {
        Write-Host "         [BestPractice-Baseline] Disabled (EnableHardeningKitty = `$false). Enable in settings.psd1."
        return $records
    }

    if (-not (Get-Module -ListAvailable -Name HardeningKitty)) {
        Write-Warning "[BestPractice-Baseline] HardeningKitty module not found. Run bootstrap\Install-Prereqs.ps1."
        $records.Add((New-CollectionError -Collector 'BestPractice-Baseline' `
            -Target $RunContext.Domain `
            -ErrorMessage 'HardeningKitty module not installed — run Install-Prereqs.ps1' `
            -RunId $runId))
        return $records
    }

    Write-Host "         [BestPractice-Baseline] Running HardeningKitty in audit mode..."

    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # Invoke-HardeningKitty in audit mode — reads settings only, no changes
        $hkResults = Invoke-HardeningKitty -Mode Audit -FileFindingList (
            # Use the built-in finding list if no custom one specified
            Join-Path (Split-Path (Get-Module -Name HardeningKitty -ListAvailable | Select-Object -First 1).Path) 'lists\finding_list_0x6d69636b_machine.csv'
        ) -SkipRestorePoint -PassThru -ErrorAction Stop

        # Save full results as artifact
        $hkResults | Export-Csv (Join-Path $artDir 'hardeningkitty-audit.csv') -NoTypeInformation -Encoding UTF8

        # Count by result category
        $compliant    = @($hkResults | Where-Object { $_.Result -eq 'Passed' }).Count
        $lowSeverity  = @($hkResults | Where-Object { $_.Severity -in @('Low') -and $_.Result -ne 'Passed' }).Count
        $medSeverity  = @($hkResults | Where-Object { $_.Severity -in @('Medium') -and $_.Result -ne 'Passed' }).Count
        $highSeverity = @($hkResults | Where-Object { $_.Severity -in @('High') -and $_.Result -ne 'Passed' }).Count

        # Emit findings for High-severity deviations
        $highFailed = @($hkResults | Where-Object { $_.Severity -eq 'High' -and $_.Result -ne 'Passed' })
        foreach ($item in $highFailed | Select-Object -First 20) {
            $findings.Add((New-Finding -Id 'BP-001' -Severity 'High' `
                -Technique 'T1562' `
                -Description "[HardeningKitty] $($item.Name) — Expected: $($item.RecommendedValue) / Found: $($item.CurrentValue). Category: $($item.Category)" `
                -Reference 'https://github.com/scipag/HardeningKitty'))
        }
        if ($highFailed.Count -gt 20) {
            $findings.Add((New-Finding -Id 'BP-002' -Severity 'Medium' `
                -Technique 'T1562' `
                -Description "[HardeningKitty] $($highFailed.Count - 20) additional High-severity deviations not listed individually. See artifact hardeningkitty-audit.csv for full list." `
                -Reference 'https://github.com/scipag/HardeningKitty'))
        }

        if ($medSeverity -gt 0) {
            $findings.Add((New-Finding -Id 'BP-003' -Severity 'Medium' `
                -Technique 'T1562' `
                -Description "[HardeningKitty] $medSeverity Medium-severity setting deviation(s) detected. See artifact hardeningkitty-audit.csv for details." `
                -Reference 'https://github.com/scipag/HardeningKitty'))
        }

        if ($lowSeverity -gt 0) {
            $findings.Add((New-Finding -Id 'BP-004' -Severity 'Low' `
                -Technique 'T1562' `
                -Description "[HardeningKitty] $lowSeverity Low-severity setting deviation(s) detected. See artifact hardeningkitty-audit.csv for details." `
                -Reference 'https://github.com/scipag/HardeningKitty'))
        }

        $records.Add((New-ReconRecord `
            -Collector      'BestPractice-Baseline' `
            -ObjectType     'hardening-audit' `
            -StableId       "BPBaseline:$($RunContext.Domain)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     @{
                domain        = $RunContext.Domain
                runHost       = $RunContext.RunHost
                totalChecks   = $hkResults.Count
                passed        = $compliant
                highFailed    = $highSeverity
                mediumFailed  = $medSeverity
                lowFailed     = $lowSeverity
                artifact      = 'hardeningkitty-audit.csv'
            } `
            -Findings       $findings.ToArray() `
            -RawArtifactRef 'hardeningkitty-audit.csv' `
            -RunId          $runId))

        Write-Host "         [BestPractice-Baseline] $($hkResults.Count) checks · $compliant passed · $highSeverity High · $medSeverity Medium · $lowSeverity Low deviations"

    } catch {
        $records.Add((New-CollectionError -Collector 'BestPractice-Baseline' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'BestPractice-Baseline' `
    -Description 'HardeningKitty audit-mode baseline check (CIS/DISA). Disabled by default — set EnableHardeningKitty=$true to activate.' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _BPBaseline_Collect @PSBoundParameters }
