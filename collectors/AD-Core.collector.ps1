# AD-Core collector — forest/domain, accounts, groups, Kerberos, delegation, ACLs.
# MinPrivilege: AnyAuthUser (uses raw LDAP via System.DirectoryServices — no AD module required).
# Milestone 1: stub with basic domain info. Full implementation in Milestone 5 (AD-Core extensions).

function _ADCore_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # Basic domain info via raw LDAP (no AD module dependency)
        $rootDse  = [adsi]'LDAP://RootDSE'
        $domainDn = $rootDse.defaultNamingContext.ToString()
        $domain   = [adsi]"LDAP://$domainDn"

        $attrs = @{
            distinguishedName      = $domainDn
            dnsRoot                = $domain.dNSRoot.ToString()
            domainFunctionalLevel  = $domain.msDS-Behavior-Version
            forestRoot             = $rootDse.rootDomainNamingContext.ToString()
            pdcEmulator            = $rootDse.dnsHostName.ToString()
            collectionNote         = 'Milestone-1 stub — extended attributes added in AD-Core extension milestone'
        }

        # ms-DS-MachineAccountQuota (unauthenticated machine join risk)
        try {
            $maq = $domain.'ms-DS-MachineAccountQuota'
            $attrs['machineAccountQuota'] = [int]$maq
            if ([int]$maq -gt 0) {
                $findings.Add((New-Finding -Id 'ADC-001' -Severity 'Medium' `
                    -Technique 'T1136.002' `
                    -Description "ms-DS-MachineAccountQuota is $maq. Any authenticated user can join up to $maq machines to the domain, enabling resource-based constrained delegation attacks." `
                    -Reference 'https://attack.mitre.org/techniques/T1136/002/'))
            }
        } catch { $attrs['machineAccountQuota'] = 'collection-error' }

        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'domain' `
            -StableId       $domainDn `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     $attrs `
            -Findings       $findings.ToArray() `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'AD-Core' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'AD-Core' `
    -Description 'Core AD: forest/domain, accounts, groups, Kerberos, delegation, ACLs' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _ADCore_Collect @PSBoundParameters }
