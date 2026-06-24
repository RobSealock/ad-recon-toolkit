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
#   DNS-003  WPAD or ISATAP record exists (WPAD/ISATAP hijack surface)
#   DNS-004  Record(s) created in past 24 hours (change-alert)
#   DNS-005  A/AAAA record name not matching any AD computer account (orphaned/rogue)
#   DNS-006  DnsAdmins group has members (DLL injection path to SYSTEM on DNS server)
#   DNS-007  Non-Tier-0 principal has CreateChild/WriteProperty on MicrosoftDNS or zone (ADIDNS write)
#   DNS-008  Zone allows AXFR (zone transfer) to any IP (full zone data exposure)
#   DNS-009  DNS forwarders include public/external IP addresses
#   DNS-010  DNS scavenging not enabled for primary zone (stale record accumulation)

# ── Helpers ───────────────────────────────────────────────────────────────────

function _DNS_GetComputerNames {
    param([string]$DomainDn)
    $names = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
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
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$containerDn"))
        $s.Filter      = '(objectClass=dnsZone)'
        $s.SearchScope = 'OneLevel'
        $s.PageSize    = 500
        $s.PropertiesToLoad.AddRange([string[]]@('name','whenCreated'))
        $s.FindAll() | ForEach-Object {
            $zones.Add(@{
                Name      = $_.Properties['name'][0].ToString()
                Partition = $Partition
                Dn        = ($_.Path -replace '^LDAP://','')
                Created   = if ($_.Properties['whencreated'].Count) { $_.Properties['whencreated'][0] } else { $null }
            })
        }
    } catch { Write-Verbose "[DNS] Zone enumeration failed for $containerDn : $_" }
    # Bare return -- the only call site pipes this (| ForEach-Object), and a
    # comma-protected return breaks piping the same way it protects assignment:
    # the consumer's $_ becomes the whole List instead of each element.
    return $zones
}

function _DNS_GetZoneNodes {
    param([string]$ZoneDn)
    $nodes = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$ZoneDn"))
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
    return ,$nodes
}

function _DNS_GetZoneDynamicUpdate {
    param([string]$ZoneName, [string]$DnsServer)
    # Try DnsServer module; fall back to 'unknown'
    try {
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            $cimArgs = Get-RemoteCimArgs -ComputerName $DnsServer
            $z = Get-DnsServerZone -Name $ZoneName @cimArgs -ErrorAction Stop
            return $z.DynamicUpdate   # None | Secure | NonsecureAndSecure
        }
    } catch {}
    return 'unknown'
}

function _DNS_CollectZoneWriteRights {
    param([string]$DomainDn)
    # Returns list of hashtables: {dn, sid, name, rights, scope}
    # Scope: 'MicrosoftDNS-container' or 'zone:<zoneName>'
    # Checks CreateChild and WriteProperty (and GenericWrite/GenericAll) for non-Tier-0 principals.
    $writers = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $domSid = try {
            (New-Object System.Security.Principal.SecurityIdentifier(
                ((New-AdsiEntry "LDAP://$DomainDn")).objectSid.Value, 0)).ToString()
        } catch { '' }

        $tier0Patterns = @(
            '^S-1-5-32-544$'                                      # BUILTIN\Administrators
            '^S-1-5-18$'                                          # SYSTEM
            '^S-1-3-0$'                                           # Creator Owner
            '^S-1-5-9$'                                           # Enterprise DCs
            "^$([regex]::Escape($domSid))-512$"                   # Domain Admins
            "^$([regex]::Escape($domSid))-519$"                   # Enterprise Admins
            "^$([regex]::Escape($domSid))-516$"                   # Domain Controllers
        )

        # Rights mask covering "can write DNS records". Deliberately just
        # CreateChild|WriteProperty -- GenericWrite/GenericAll are composite
        # flag values that also carry the ReadControl bit, which ReadControl
        # shares with GenericRead. OR-ing those composites into a -band mask
        # made any ACE with a plain GenericRead grant (read-only) match as a
        # "writer". GenericAll/GenericWrite grants still match here since both
        # composites inherently include the CreateChild/WriteProperty bits.
        $writeRightsMask = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
                           [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

        # Scriptblock (not nested function) so it closes over $writers/$tier0Patterns/$writeRightsMask
        # without leaking into the enclosing script scope.
        $checkDACL = {
            param([string]$Dn, [string]$Scope)
            try {
                $obj = (New-AdsiEntry "LDAP://$Dn")
                $sd  = $obj.psbase.ObjectSecurity
                foreach ($ace in $sd.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if (-not ($ace.ActiveDirectoryRights -band $writeRightsMask)) { continue }
                    $sid  = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                    $isTier0 = $tier0Patterns | Where-Object { $sid -match $_ }
                    if (-not $isTier0 -and $sid) {
                        $name = try { $ace.IdentityReference.ToString() } catch { $sid }
                        [void]$writers.Add(@{
                            dn        = $Dn
                            scope     = $Scope
                            sid       = $sid
                            name      = $name
                            rights    = $ace.ActiveDirectoryRights.ToString()
                            inherited = $ace.IsInherited
                        })
                    }
                }
            } catch {}
        }

        # Check both AD-integrated DNS partitions' MicrosoftDNS containers
        foreach ($part in @('DomainDnsZones','ForestDnsZones')) {
            $containerDn = "CN=MicrosoftDNS,DC=$part,$DomainDn"
            & $checkDACL -Dn $containerDn -Scope "MicrosoftDNS-container ($part)"

            # Also check each zone object directly
            $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$containerDn"))
            $s.Filter      = '(objectClass=dnsZone)'
            $s.SearchScope = 'OneLevel'
            $s.PageSize    = 100
            $s.PropertiesToLoad.Add('name') | Out-Null
            $s.FindAll() | ForEach-Object {
                $zDn   = $_.Path -replace '^LDAP://',''
                $zName = if ($_.Properties['name'].Count) { $_.Properties['name'][0].ToString() } else { $zDn }
                & $checkDACL -Dn $zDn -Scope "zone:$zName"
            }
        }
    } catch { Write-Verbose "[DNS] Zone write-rights DACL walk failed: $_" }
    return ,$writers
}

function _DNS_GetDnsAdmins {
    param([string]$DomainDn)
    $members = [System.Collections.Generic.List[string]]::new()
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter = '(&(objectClass=group)(sAMAccountName=DnsAdmins))'
        $s.PropertiesToLoad.Add('member') | Out-Null
        $result = $s.FindOne()
        if ($result) {
            foreach ($m in $result.Properties['member']) { $members.Add($m) }
        }
    } catch { Write-Verbose "[DNS] DnsAdmins lookup failed: $_" }
    return ,$members
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

    $rootDse  = (New-AdsiEntry 'LDAP://RootDSE')
    $domainDn = $rootDse.defaultNamingContext.ToString()
    # In remote mode there's no implicit domain membership to resolve the bare
    # domain name to a DC, and it isn't covered by WinRM TrustedHosts either —
    # target the configured DC directly. Falls back to the domain name for the
    # normal domain-joined case, where DnsServer module resolution to a DC works.
    $dnsServer= if ($Settings['TargetDC']) { $Settings['TargetDC'] } else { $RunContext.Domain }

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

                # WPAD / ISATAP records (both are well-known ADIDNS spoofing targets)
                if ($name -ieq 'wpad' -or $name -ieq 'isatap') { $wpadFound = $true }

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

            # Emit WPAD/ISATAP finding
            if ($wpadFound) {
                $zoneFindings.Add((New-Finding -Id 'DNS-003' -Severity 'Medium' `
                    -Technique 'T1557.001' `
                    -Description "WPAD or ISATAP record exists in zone '$zoneName'. If WPAD auto-discovery is enabled on clients, this record directs them to an attacker-controlled proxy (NTLM credential capture). ISATAP enables IPv6 transition and can be used for relay attacks. Both names are blocked by default in recent Windows but the AD DNS record itself should be removed." `
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

            # DNS-008: Zone transfer restriction; DNS-010: Scavenging not configured
            try {
                $cimArgs = Get-RemoteCimArgs -ComputerName $dnsServer
                $dnsZone = Get-DnsServerZone -Name $zoneName @cimArgs -EA SilentlyContinue
                if ($dnsZone) {
                    if ($dnsZone.SecureSecondaries -eq 'NoSecureSecondaries') {
                        $zoneFindings.Add((New-Finding -Id 'DNS-008' -Severity 'High' `
                            -Technique 'T1590.002' `
                            -Description "DNS zone '$zoneName' allows unrestricted AXFR zone transfers (SecureSecondaries=NoSecureSecondaries). Any host can request a full zone transfer and enumerate all DNS records — including internal hostnames, IP ranges, and service names. Restrict zone transfers to authorized secondary servers only, or disable AXFR if not needed." `
                            -Reference 'https://attack.mitre.org/techniques/T1590/002/'))
                    }
                    # DNS-010: Scavenging not enabled for primary (non-auto-created) zones
                    if ($dnsZone.ZoneType -eq 'Primary' -and -not $dnsZone.IsAutoCreated -and -not $dnsZone.Aging) {
                        $zoneFindings.Add((New-Finding -Id 'DNS-010' -Severity 'Low' `
                            -Technique 'T1557.001' `
                            -Description "DNS scavenging is not enabled for zone '$zoneName' (Aging=False). Without scavenging, stale A/AAAA records from decommissioned servers accumulate indefinitely. When IP addresses are reused, old records point to attacker-controlled infrastructure — or stale records can be re-registered via ADIDNS dynamic update by any authenticated user (if the record is tombstoned). Enable: Set-DnsServerZoneAging -ZoneName '$zoneName' -Aging `$true -NoRefreshInterval 7.00:00:00 -RefreshInterval 7.00:00:00; also enable server-level scavenging via Set-DnsServerScavenging -ScavengingState `$true." `
                            -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
                    }
                }
            } catch { Write-Verbose "[DNS] Zone transfer/scavenging check failed for $zoneName`: $_" }

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

        # DNS-009: External forwarders
        # Local (not script-scoped) and initialized unconditionally -- under
        # Set-StrictMode -Version 2, referencing a variable that was never
        # assigned at all (e.g. this try block fails before reaching the
        # assignment below) throws, and script-scope would risk a stale
        # value leaking into a later, unrelated call within the same session.
        $dns009Finding = $null
        try {
            $cimArgs = Get-RemoteCimArgs -ComputerName $dnsServer
            $forwarders = Get-DnsServerForwarder @cimArgs -EA SilentlyContinue
            if ($forwarders -and $forwarders.IPAddress) {
                $publicForwarders = @($forwarders.IPAddress | Where-Object {
                    $ip = $_.ToString()
                    # Exclude RFC1918 and common private ranges
                    -not ($ip -match '^10\.' -or $ip -match '^192\.168\.' -or
                          $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
                          $ip -match '^127\.' -or $ip -match '^::1$' -or
                          $ip -match '^fd' -or $ip -match '^169\.254\.')
                })
                if ($publicForwarders.Count -gt 0) {
                    $allNew24h.Add("DNS-009: $dnsServer has public forwarders: $($publicForwarders -join ', ')") | Out-Null
                    # Forwarder finding goes into the domain-level summary findings (daFindings)
                    # We store it for later use since daFindings is built below
                    $dns009Finding = New-Finding -Id 'DNS-009' -Severity 'Medium' `
                        -Technique 'T1590.002' `
                        -Description "DNS server '$dnsServer' has forwarders pointing to public/external IPs: $($publicForwarders -join ', '). Forwarding internal DNS queries to external resolvers exposes internal hostnames and query patterns externally, and may bypass internal split-brain DNS. Consider using internal forwarders or conditional forwarding only. External forwarders also expose the environment to DNS-based data exfiltration (covert channel via DNS queries)." `
                        -Reference 'https://attack.mitre.org/techniques/T1590/002/'
                }
            }
        } catch { Write-Verbose "[DNS] Forwarder check failed: $_" }

        # ── ADIDNS zone write rights ──────────────────────────────────────────
        Write-Verbose '[DNS] Checking ADIDNS zone write rights (DACL walk)...'
        $zoneWriters = _DNS_CollectZoneWriteRights -DomainDn $domainDn

        # ── DnsAdmins + ADIDNS findings (domain-level) ───────────────────────
        $daFindings = [System.Collections.Generic.List[object]]::new()
        if ($dnsAdminMembers.Count -gt 0) {
            $daFindings.Add((New-Finding -Id 'DNS-006' -Severity 'High' `
                -Technique 'T1543.003' `
                -Description "DnsAdmins group has $($dnsAdminMembers.Count) member(s). Any DnsAdmin can load an arbitrary DLL into the DNS Server service (running as SYSTEM on DCs) using dnscmd — effective domain compromise path: $($dnsAdminMembers -join '; ')" `
                -Reference 'https://attack.mitre.org/techniques/T1543/003/'))
        }

        if ($zoneWriters.Count -gt 0) {
            # Deduplicate to unique (sid, scope) pairs for the summary
            $uniqueWriters = $zoneWriters | Sort-Object { "$($_.sid)|$($_.scope)" } -Unique
            $preview = ($uniqueWriters | Select-Object -First 5 |
                ForEach-Object { "$($_.name) → $($_.scope)" }) -join '; '
            $daFindings.Add((New-Finding -Id 'DNS-007' -Severity 'High' `
                -Technique 'T1557.001' `
                -Description "$($uniqueWriters.Count) non-Tier-0 ACE(s) grant CreateChild/WriteProperty on the MicrosoftDNS container or individual zone objects: $preview. Direct LDAP write to ADIDNS bypasses the DNS server's secure dynamic update check — any principal with CreateChild can register arbitrary DNS records (including WPAD, wildcard, or spoofed entries) regardless of zone dynamic-update policy." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # DNS-009: add forwarder finding if detected
        if ($dns009Finding) {
            $daFindings.Add($dns009Finding)
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
                adidnsWriters       = @(if ($zoneWriters.Count -gt 0) { $zoneWriters.ToArray() } else { @() })
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
    -Description 'AD-integrated DNS: all zones, all records, dynamic update policy, WPAD/wildcard, 24-hour new record alert, orphaned record detection, DnsAdmins, zone transfer restrictions (DNS-008), external forwarders (DNS-009), scavenging not configured (DNS-010)' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _DNS_Collect @PSBoundParameters }
