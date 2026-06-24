#Requires -Module Pester
<#
.SYNOPSIS
    Unit tests for ad-recon-toolkit framework functions.

.DESCRIPTION
    Tests Schema.ps1, CollectorRegistry.ps1, and Repository.ps1 factory functions
    without requiring an AD environment or domain connectivity.

.EXAMPLE
    Invoke-Pester .\tests\framework.tests.ps1 -Output Detailed
#>

$repoRoot = Split-Path $PSScriptRoot -Parent

# Dot-source framework modules under test
. (Join-Path $repoRoot 'framework\Schema.ps1')
. (Join-Path $repoRoot 'framework\CollectorRegistry.ps1')
. (Join-Path $repoRoot 'framework\Repository.ps1')

# ── Schema.ps1 ────────────────────────────────────────────────────────────────

Describe 'New-Finding' {
    It 'returns an object with all required fields' {
        $f = New-Finding -Id 'ADC-001' -Severity 'High' -Technique 'T1558.003' `
            -Description 'Test finding' -Reference 'https://example.com'
        $f.id          | Should -Be 'ADC-001'
        $f.severity    | Should -Be 'High'
        $f.technique   | Should -Be 'T1558.003'
        $f.description | Should -Be 'Test finding'
        $f.reference   | Should -Be 'https://example.com'
    }

    It 'does not emit collector or objectType fields (bare finding)' {
        $f = New-Finding -Id 'ADC-002' -Severity 'Medium' -Technique 'T1078' `
            -Description 'bare' -Reference ''
        $f.PSObject.Properties.Name | Should -Not -Contain 'collector'
        $f.PSObject.Properties.Name | Should -Not -Contain 'objectType'
    }
}

Describe 'New-ReconRecord' {
    It 'returns a record with collector and objectType' {
        $r = New-ReconRecord -Collector 'TestCollector' -ObjectType 'test-object' `
            -StableId 'Test:obj1' -Category 'config' -Tier 'T0' `
            -CollectedAtPriv $false -Attributes @{ key = 'value' } -RunId 'run-001'
        $r.collector   | Should -Be 'TestCollector'
        $r.objectType  | Should -Be 'test-object'
        $r.stableId    | Should -Be 'Test:obj1'
        $r.category    | Should -Be 'config'
        $r.tier        | Should -Be 'T0'
        $r.attributes.key | Should -Be 'value'
    }

    It 'attaches findings array when -Findings is provided' {
        $f1 = New-Finding -Id 'ADC-001' -Severity 'High' -Technique 'T1003' -Description 'd' -Reference 'r'
        $f2 = New-Finding -Id 'ADC-002' -Severity 'Low'  -Technique 'T1078' -Description 'd' -Reference 'r'
        $r = New-ReconRecord -Collector 'C' -ObjectType 'o' -StableId 's' -Category 'config' `
            -Tier 'T1' -CollectedAtPriv $false -Attributes @{} -RunId 'r1' -Findings @($f1, $f2)
        $r.findings.Count | Should -Be 2
        $r.findings[0].id | Should -Be 'ADC-001'
    }

    It 'has empty findings array when none are provided' {
        $r = New-ReconRecord -Collector 'C' -ObjectType 'o' -StableId 's' -Category 'config' `
            -Tier 'T1' -CollectedAtPriv $false -Attributes @{} -RunId 'r1'
        $r.findings | Should -BeNullOrEmpty
    }
}

Describe 'New-CollectionError' {
    It 'returns a record with recordType collection-error' {
        $e = New-CollectionError -Collector 'C' -Target 'dc1.corp.com' `
            -ErrorMessage 'Access denied' -RunId 'r1'
        $e.recordType  | Should -Be 'collection-error'
        $e.collector   | Should -Be 'C'
        $e.target      | Should -Be 'dc1.corp.com'
        $e.errorMessage| Should -Be 'Access denied'
    }
}

Describe 'New-ReviewRequired' {
    It 'returns a record with recordType review-required' {
        $r = New-ReviewRequired -Collector 'C' -StableId 's' -Reason 'Manual check needed' -RunId 'r1'
        $r.recordType | Should -Be 'review-required'
        $r.reason     | Should -Be 'Manual check needed'
    }
}

# ── CollectorRegistry.ps1 ─────────────────────────────────────────────────────

Describe 'Register-Collector and Test-CollectorEligible' {
    BeforeEach {
        # Reset registry between tests
        $script:_CollectorRegistry = [System.Collections.Generic.List[hashtable]]::new()
    }

    It 'registers a collector and retrieves it' {
        Register-Collector -Name 'TestCol' -Description 'desc' `
            -MinPrivilege 'AnyAuthUser' -Invoke { 'invoked' }
        $cols = @(Get-RegisteredCollectors)
        $cols.Count       | Should -Be 1
        $cols[0].Name     | Should -Be 'TestCol'
        $cols[0].MinPrivilege | Should -Be 'AnyAuthUser'
    }

    It 'does not register duplicates' {
        Register-Collector -Name 'DupCol' -Description 'a' -MinPrivilege 'AnyAuthUser' -Invoke {}
        Register-Collector -Name 'DupCol' -Description 'b' -MinPrivilege 'AnyAuthUser' -Invoke {}
        @(Get-RegisteredCollectors).Count | Should -Be 1
    }

    It 'grants AnyAuthUser collector to AnyAuthUser caller' {
        Register-Collector -Name 'C1' -Description 'd' -MinPrivilege 'AnyAuthUser' -Invoke {}
        $col = (Get-RegisteredCollectors)[0]
        Test-CollectorEligible -Collector $col -HeldPrivileges @('AnyAuthUser') | Should -BeTrue
    }

    It 'grants LocalAdmin collector to LocalAdmin caller' {
        Register-Collector -Name 'C2' -Description 'd' -MinPrivilege 'LocalAdmin' -Invoke {}
        $col = (Get-RegisteredCollectors)[0]
        Test-CollectorEligible -Collector $col -HeldPrivileges @('AnyAuthUser','LocalAdmin') | Should -BeTrue
    }

    It 'denies LocalAdmin collector to AnyAuthUser-only caller' {
        Register-Collector -Name 'C3' -Description 'd' -MinPrivilege 'LocalAdmin' -Invoke {}
        $col = (Get-RegisteredCollectors)[0]
        Test-CollectorEligible -Collector $col -HeldPrivileges @('AnyAuthUser') | Should -BeFalse
    }

    It 'grants T0 collector to T0 caller' {
        Register-Collector -Name 'C4' -Description 'd' -MinPrivilege 'T0' -Invoke {}
        $col = (Get-RegisteredCollectors)[0]
        Test-CollectorEligible -Collector $col -HeldPrivileges @('AnyAuthUser','LocalAdmin','T0') | Should -BeTrue
    }

    It 'denies T0 collector to LocalAdmin-only caller' {
        Register-Collector -Name 'C5' -Description 'd' -MinPrivilege 'T0' -Invoke {}
        $col = (Get-RegisteredCollectors)[0]
        Test-CollectorEligible -Collector $col -HeldPrivileges @('AnyAuthUser','LocalAdmin') | Should -BeFalse
    }
}

# ── Repository.ps1 ────────────────────────────────────────────────────────────

Describe 'Save-ReconRecord and NDJSON round-trip' {
    $tmpDir = $null

    BeforeEach {
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "adr-test-$([System.IO.Path]::GetRandomFileName())"
        New-Item -ItemType Directory -Path $tmpDir | Out-Null
    }

    AfterEach {
        if ($tmpDir -and (Test-Path $tmpDir)) { Remove-Item $tmpDir -Recurse -Force }
    }

    It 'creates a NDJSON file with one line per record' {
        $r1 = New-ReconRecord -Collector 'TC' -ObjectType 'obj' -StableId 's1' `
            -Category 'config' -Tier 'T1' -CollectedAtPriv $false -Attributes @{ v=1 } -RunId 'r1'
        $r2 = New-ReconRecord -Collector 'TC' -ObjectType 'obj' -StableId 's2' `
            -Category 'config' -Tier 'T1' -CollectedAtPriv $false -Attributes @{ v=2 } -RunId 'r1'
        Save-ReconRecord -Record $r1 -RunRoot $tmpDir
        Save-ReconRecord -Record $r2 -RunRoot $tmpDir

        $filePath = Join-Path $tmpDir 'TC.obj.json'
        Test-Path $filePath | Should -BeTrue

        $lines = @(Get-Content $filePath | Where-Object { $_.Trim() })
        $lines.Count | Should -Be 2
    }

    It 'each line is valid JSON that round-trips correctly' {
        $r = New-ReconRecord -Collector 'TC' -ObjectType 'obj' -StableId 's1' `
            -Category 'config' -Tier 'T0' -CollectedAtPriv $true -Attributes @{ name='dc1'; domain='corp.com' } -RunId 'r1'
        Save-ReconRecord -Record $r -RunRoot $tmpDir

        $line   = Get-Content (Join-Path $tmpDir 'TC.obj.json') | Select-Object -First 1
        $parsed = ConvertFrom-Json $line
        $parsed.collector  | Should -Be 'TC'
        $parsed.stableId   | Should -Be 's1'
        $parsed.tier       | Should -Be 'T0'
        $parsed.attributes.name | Should -Be 'dc1'
    }

    It 'appends without corrupting existing records' {
        for ($i = 1; $i -le 5; $i++) {
            $r = New-ReconRecord -Collector 'TC' -ObjectType 'obj' -StableId "s$i" `
                -Category 'config' -Tier 'T1' -CollectedAtPriv $false -Attributes @{ seq=$i } -RunId 'r1'
            Save-ReconRecord -Record $r -RunRoot $tmpDir
        }
        $lines = @(Get-Content (Join-Path $tmpDir 'TC.obj.json') | Where-Object { $_.Trim() })
        $lines.Count | Should -Be 5
        $parsed = $lines | ForEach-Object { ConvertFrom-Json $_ }
        ($parsed | ForEach-Object { $_.attributes.seq }) | Should -Be @(1,2,3,4,5)
    }

    It 'uses separate files per (collector, objectType) pair' {
        $r1 = New-ReconRecord -Collector 'C1' -ObjectType 'typeA' -StableId 's1' `
            -Category 'config' -Tier 'T1' -CollectedAtPriv $false -Attributes @{} -RunId 'r'
        $r2 = New-ReconRecord -Collector 'C1' -ObjectType 'typeB' -StableId 's2' `
            -Category 'config' -Tier 'T1' -CollectedAtPriv $false -Attributes @{} -RunId 'r'
        $r3 = New-ReconRecord -Collector 'C2' -ObjectType 'typeA' -StableId 's3' `
            -Category 'config' -Tier 'T1' -CollectedAtPriv $false -Attributes @{} -RunId 'r'
        Save-ReconRecord -Record $r1 -RunRoot $tmpDir
        Save-ReconRecord -Record $r2 -RunRoot $tmpDir
        Save-ReconRecord -Record $r3 -RunRoot $tmpDir

        @(Get-ChildItem $tmpDir -Filter '*.json').Count | Should -Be 3
        Test-Path (Join-Path $tmpDir 'C1.typeA.json') | Should -BeTrue
        Test-Path (Join-Path $tmpDir 'C1.typeB.json') | Should -BeTrue
        Test-Path (Join-Path $tmpDir 'C2.typeA.json') | Should -BeTrue
    }
}
