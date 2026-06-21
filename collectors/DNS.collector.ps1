# DNS collector — zones, dynamic update policy, wildcard/WPAD, ACLs, forwarders, DnsAdmins.
# MinPrivilege: AnyAuthUser (basic zone enumeration via LDAP/WMI; full ACL check needs DNSAdmin).
# Milestone 1: stub. Full implementation in later milestone.

function _DNS_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId

    try {
        # Identify DNS servers from AD (SRV records in _msdcs zone)
        $rootDse    = [adsi]'LDAP://RootDSE'
        $domainDn   = $rootDse.defaultNamingContext.ToString()
        $dnsZonesDn = "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn"

        $records.Add((New-ReconRecord `
            -Collector      'DNS' `
            -ObjectType     'collection-status' `
            -StableId       "DNS:$domainDn" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                status         = 'stub'
                domainDn       = $domainDn
                dnsZonesPath   = $dnsZonesDn
                collectionNote = 'Milestone-1 stub — DNS zone enumeration implemented in DNS collector milestone'
            } `
            -RunId $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'DNS' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'DNS' `
    -Description 'DNS zones, dynamic update policy, wildcard/WPAD records, ACLs, forwarders, DnsAdmins overlap' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _DNS_Collect @PSBoundParameters }
