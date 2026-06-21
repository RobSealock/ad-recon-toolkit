# DHCP collector — authorized servers, scopes, options, dynamic-update credentials, failover, audit logging.
# MinPrivilege: DHCPRead (netsh dhcp or DhcpServer module).
# Milestone 1: stub. Full implementation in later milestone.

function _DHCP_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId

    try {
        # Authorized DHCP servers are stored in AD: CN=NetServices,CN=Services,CN=Configuration,...
        $rootDse  = [adsi]'LDAP://RootDSE'
        $configDn = $rootDse.configurationNamingContext.ToString()
        $dhcpDn   = "CN=NetServices,CN=Services,$configDn"

        $records.Add((New-ReconRecord `
            -Collector      'DHCP' `
            -ObjectType     'collection-status' `
            -StableId       "DHCP:$configDn" `
            -Category       'config' `
            -Tier           'T1' `
            -CollectedAtPriv $false `
            -Attributes     @{
                status          = 'stub'
                dhcpContainerDn = $dhcpDn
                collectionNote  = 'Milestone-1 stub — DHCP authorized-server and scope enumeration implemented in DHCP collector milestone'
            } `
            -RunId $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'DHCP' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'DHCP' `
    -Description 'DHCP: authorized servers, scopes/options, dynamic-update creds, failover, audit logging' `
    -MinPrivilege 'DHCPRead' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _DHCP_Collect @PSBoundParameters }
