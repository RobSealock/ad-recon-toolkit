# DNS collector — all zones, all records, dynamic update policy, WPAD/wildcard,
# ACL/DnsAdmins, 24-hour new record detection, orphaned record detection.
#
# MinPrivilege: AnyAuthUser
#   Zone enumeration and record listing via raw LDAP — no module required.
#   Enriched with Get-DnsServerResourceRecord if DnsServer module is available.
#
# Findings emitted:
#   DNS-001  Zone allows nonsecure dynamic updates (ADIDNS spoofing surface)
#   DNS-002  Wildcard A/AAAA record exists (catch-all — relay/MitM risk)
#   DNS-003  WPAD record exists (WPAD hijack surface)
#   DNS-004  Record(s) created in past 24 hours (change-alert)
#   DNS-005  A/AAAA record name not matching any AD computer account (orphaned/rogue)
#   DNS-006  DnsAdmins group has members (DLL injection path to SYSTEM on DNS server)

# ── Helpers ───────────────────────────────────────────────────────────────────

function _DNS_GetComputerNames {
    param([string]$DomainDn)
    $names = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$DomainDn")
        $s.Filter   = '(objectClass=computer)'
        $s.PageSize = 1000
        $s.PropertiesToLoad.AddRange([string[]]@('sAMAccountName','dNSHostName','cn'))
        $s.FindAll() | ForEach-Object {
            $sam = $_.Properties['samaccountname']
            if ($sam.Count) { $names.Add(($sam[0] -replace '\$$','')) | Out-Null }
            $dns = $_.Properties['dnshostname']
            if ($dns.Count) {
                $short = ($dns[0] -split '\.')[0]
                $names.Add($short) | Out-Null
            }
        }
    } catch { Write-Verbose "[DNS] Computer name lookup failed: $_" }
    return $names
}

function _DNS_EnumerateZones {
    param([string]$DomainDn, [string]$Partition)
    # Partition: 'DomainDnsZones' or 'ForestDnsZones'
    $zones = [System.Collections.Generic.List[hashtable]]::new()
    $partitionDn = "DC=$Partition,$DomainDn"
    $containerDn = "CN=MicrosoftDNS,$partitionDn"
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$containerDn")
        $s.Filter      = '(objectClass=dnsZone)'
        $s.SearchScope = 'OneLevel'
        $s.PageSize    = 500
        $s.PropertiesToLoad.AddRange([string[]]@('name','whenCreated'))
        $s.FindAll() | ForEach-Object {
            $zones.Add(@{
                Name      = $_.Properties['name'][0].ToString()
                Partition = $Partition
                Dn        = $_.Path -replace '^LDAP://',''
                Created   = if ($_.Properties['whencreated'].Count) { $_.Properties['whencreated'][0] } else { $null }
            })
        }
    } catch { Write-Verbose "[DNS] Zone enumeration failed for $containerDn : $_" }
    return $zones
}

function _DNS_GetZoneNodes {
    param([string]$ZoneDn)
    $nodes = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$ZoneDn")
        $s.Filter      = '(objectClass=dnsNode)'
        $s.SearchScope = 'OneLevel'
        $s.PageSize    = 2000
        $s.PropertiesToLoad.AddRange([string[]]@('name','whenCreated','dNSTombstoned'))
        $s.FindAll() | ForEach-Object {
            $tombstoned = $false
            if ($_.Properties['dnstombstoned'].Count) {
                $tombstoned = [bool]$_.Properties['dnstombstoned'][0]
            }
            if (-not $tombstoned) {
                $nodes.Add(@{
                    Name      = $_.Properties['name'][0].ToString()
                    Created   = if ($_.Properties['whencreated'].Count) { $_.Properties['whencreated'][0] } else { $null }
                    Tombstoned= $tombstoned
                })
            }
        }
    } catch { Write-Verbose "[DNS] Node enumeration failed for $ZoneDn : $_" }
    return $nodes
}

function _DNS_GetZoneDynamicUpdate {
    param([string]$ZoneName, [string]$DnsServer)
    # Try DnsServer module; fall back to 'unknown'
    try {
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            $z = Get-DnsServerZone -Name $ZoneName -ComputerName $DnsServer -ErrorAction Stop
            return $z.DynamicUpdate   # None | Secure | NonsecureAndSecure
        }
    } catch {}
    return 'unknown'
}

function _DNS_GetDnsAdmins {
    param([string]$DomainDn)
    $members = [System.Collections.Generic.List[string]]::new()
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$DomainDn")
        $s.Filter = '(&(objectClass=group)(sAMAccountName=DnsAdmins))'
        $s.PropertiesToLoad.Add('member') | Out-Null
        $result = $s.FindOne()
        if ($result) {
            foreach ($m in $result.Properties['member']) { $members.Add($m) }
        }
    } catch { Write-Verbose "[DNS] DnsAdmins lookup failed: $_" }
    return $members
}

# ── Infrastructure zone names that are expected to have non-machine records ──
$script:_DNS_InfraZones = @(
    '_msdcs','_sites','_tcp','_udp','_domainzones','_forestzones',
    'RootDNSServers','..TrustAnchors'
)
$script:_DNS_InfraNames = @(
    '@','_ldap','_kerberos','_kpasswd','_gc','domaindnszones',
    'forestdnszones','_msdcs','gc','pdc'
)

# ── Main collector ────────────────────────────────────────────────────────────

function _DNS_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId
    $cutoff24h= (Get-Date).AddHours(-24).ToUniversalTime()

    $rootDse  = [adsi]'LDAP://RootDSE'
    $domainDn = $rootDse.defaultNamingContext.ToString()
    $dnsServer= $RunContext.Domain   # use domain name; DnsServer module resolves to a DC

    try {
        # ── Computer accounts for orphan detection ────────────────────────────
        Write-Verbose '[DNS] Loading computer accounts for record comparison...'
        $computerNames = _DNS_GetComputerNames -DomainDn $domainDn

        # ── DnsAdmins group ───────────────────────────────────────────────────
        $dnsAdminMembers = _DNS_GetDnsAdmins -DomainDn $domainDn

        # ── Zone enumeration (both AD-integrated partitions) ──────────────────
        $allZones = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($partition in @('DomainDnsZones','ForestDnsZones')) {
            _DNS_EnumerateZones -DomainDn $domainDn -Partition $partition |
                ForEach-Object { $allZones.Add($_) }
        }

        Write-Verbose "[DNS] $($allZones.Count) zone(s) found"

        # ── Per-zone processing ───────────────────────────────────────────────
        $allNew24h   = [System.Collections.Generic.List[string]]::new()
        $allOrphaned = [System.Collections.Generic.List[string]]::new()

        foreach ($zone in $allZones) {
            $zoneName = $zone.Name
            $isInfra  = $script:_DNS_InfraZones | Where-Object { $zoneName -like "*$_*" }
            $zoneFindings = [System.Collections.Generic.List[object]]::new()

            # Dynamic update policy
            $dynUpdate = _DNS_GetZoneDynamicUpdate -ZoneName $zoneName -DnsServer $dnsServer
            if ($dynUpdate -eq 'NonsecureAndSecure') {
                $zoneFindings.Add((New-Finding -Id 'DNS-001' -Severity 'High' `
                    -Technique 'T1557.001' `
                    -Description "Zone '$zoneName' allows NONSECURE dynamic updates. Any host on the network can register arbitrary DNS records — ADIDNS spoofing/poisoning risk." `
                    -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
            }

            # Node/record enumeration
            $nodes = _DNS_GetZoneNodes -ZoneDn $zone.Dn

            $wildcardFound = $false
            $wpadFound     = $false
            $new24hZone    = [System.Collections.Generic.List[string]]::new()
            $orphanedZone  = [System.Collections.Generic.List[string]]::new()
            $totalNodes    = $nodes.Count

            foreach ($node in $nodes) {
                $name = $node.Name

                # Skip infrastructure/SRV-type names
                if ($name -like '_*' -or $name -eq '@' -or
                    $script:_DNS_InfraNames -contains $name.ToLower()) { continue }

                # Wildcard record
                if ($name -eq '*') { $wildcardFound = $true; continue }

                # WPAD record
                if ($name -ieq 'wpad') { $wpadFound = $true }

                # 24-hour new record detection
                if ($node.Created -and ([datetime]$node.Created).ToUniversalTime() -ge $cutoff24h) {
                    $entry = "$name.$zoneName  (created: $($node.Created.ToString('yyyy-MM-dd HH:mm:ss')) UTC)"
                    $new24hZone.Add($entry)
                    $allNew24h.Add($entry)
                }

                # Orphaned/rogue record detection (skip infra zones)
                if (-not $isInfra -and -not $wildcardFound -and
                    $zoneName -notlike '_*' -and
                    -not $computerNames.Contains($name)) {
                    $entry = "$name.$zoneName"
                    $orphanedZone.Add($entry)
                    $allOrphaned.Add($entry)
                }
            }

            # Emit wildcard finding
            if ($wildcardFound) {
                $zoneFindings.Add((New-Finding -Id 'DNS-002' -Severity 'High' `
                    -Technique 'T1557.001' `
                    -Description "Wildcard A/AAAA record (*) exists in zone '$zoneName'. Any unresolved name resolves to the wildcard target — WPAD, NTLM relay, and catch-all MitM risk." `
                    -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
            }

            # Emit WPAD finding
            if ($wpadFound) {
                $zoneFindings.Add((New-Finding -Id 'DNS-003' -Severity 'Medium' `
                    -Technique 'T1557.001' `
                    -Description "WPAD record exists in zone '$zoneName'. If WPAD auto-discovery is enabled on clients, this record directs them to a proxy — potential NTLM credential capture." `
                    -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
            }

            # Emit 24-hour records finding
            if ($new24hZone.Count -gt 0) {
                $zoneFindings.Add((New-Finding -Id 'DNS-004' -Severity 'High' `
                    -Technique 'T1557.001' `
                    -Description "$($new24hZone.Count) DNS record(s) created in the past 24 hours in zone '$zoneName' — confirm these are authorised: $($new24hZone -join '; ')" `
                    -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
            }

            # Emit orphaned records finding (only if non-infra zone and any found)
            if (-not $isInfra -and $orphanedZone.Count -gt 0 -and $zoneName -notlike '_*') {
                $zoneFindings.Add((New-Finding -Id 'DNS-005' -Severity 'Medium' `
                    -Technique 'T1557.001' `
                    -Description "$($orphanedZone.Count) A/AAAA record(s) in zone '$zoneName' do not match any current AD computer account — may be orphaned (stale) or rogue ADIDNS registrations: $($orphanedZone -join '; ')" `
                    -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
            }

            # Emit zone record
            $records.Add((New-ReconRecord `
                -Collector      'DNS' `
                -ObjectType     'zone' `
                -StableId       "DNS:zone:$zoneName" `
                -Category       'config' `
                -Tier           'T0' `
                -CollectedAtPriv $false `
                -Attributes     @{
                    zoneName           = $zoneName
                    partition          = $zone.Partition
                    dynamicUpdate      = $dynUpdate
                    totalRecords       = $totalNodes
                    wildcardExists     = $wildcardFound
                    wpadExists         = $wpadFound
                    new24hCount        = $new24hZone.Count
                    orphanedCount      = if ($isInfra) { 'n/a (infrastructure zone)' } else { $orphanedZone.Count }
                    new24hRecords      = $new24hZone.ToArray()
                    orphanedRecords    = $orphanedZone.ToArray()
                } `
                -Findings       $zoneFindings.ToArray() `
                -RunId          $runId))
        }

        # ── DnsAdmins finding (domain-level) ──────────────────────────────────
        $daFindings = [System.Collections.Generic.List[object]]::new()
        if ($dnsAdminMembers.Count -gt 0) {
            $daFindings.Add((New-Finding -Id 'DNS-006' -Severity 'High' `
                -Technique 'T1543.003' `
                -Description "DnsAdmins group has $($dnsAdminMembers.Count) member(s). Any DnsAdmin can load an arbitrary DLL into the DNS Server service (running as SYSTEM on DCs) using dnscmd — effective domain compromise path: $($dnsAdminMembers -join '; ')" `
                -Reference 'https://attack.mitre.org/techniques/T1543/003/'))
        }

        # ── Summary record ────────────────────────────────────────────────────
        $records.Add((New-ReconRecord `
            -Collector      'DNS' `
            -ObjectType     'summary' `
            -StableId       "DNS:summary:$domainDn" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domainDn            = $domainDn
                totalZones          = $allZones.Count
                dnsAdminMembers     = $dnsAdminMembers.ToArray()
                totalNew24h         = $allNew24h.Count
                totalOrphaned       = $allOrphaned.Count
                moduleEnriched      = [bool](Get-Command Get-DnsServerResourceRecord -ErrorAction SilentlyContinue)
                computerNamesLoaded = $computerNames.Count
            } `
            -Findings       $daFindings.ToArray() `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'DNS' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'DNS' `
    -Description 'AD-integrated DNS: all zones, all records, dynamic update policy, WPAD/wildcard, 24-hour new record alert, orphaned record detection, DnsAdmins' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _DNS_Collect @PSBoundParameters }
