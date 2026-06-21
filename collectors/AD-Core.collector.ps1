# AD-Core collector — forest/domain, accounts, groups, Kerberos, delegation, ACLs.
# MinPrivilege: AnyAuthUser (uses raw LDAP via System.DirectoryServices — no AD module required).
#
# Collects:
#   Domain metadata      — functional level, ms-DS-MachineAccountQuota, dsHeuristics,
#                          tombstone lifetime, recycling bin state
#   Forest metadata      — forest functional level, cross-forest trusts
#   Privileged accounts  — Domain Admins, Enterprise Admins, Schema Admins, Administrators,
#                          Protected Users, AdminSDHolder-protected accounts
#   Kerberos config      — krbtgt age, des-only accounts, DES/RC4 GPO, no-preauth accounts,
#                          AS-REP roastable, Kerberoastable (SPNs), constrained/unconstrained
#                          delegation, RBCD (resource-based constrained delegation)
#   Domain trusts        — direction, transitivity, SID filtering state
#   ACL risks            — accounts with DCSync rights (Replicating Directory Changes All)
#   Password policy      — default domain password policy, Fine-Grained Password Policies
#
# Findings:
#   ADC-001   ms-DS-MachineAccountQuota > 0
#   ADC-002   Domain functional level below 2016
#   ADC-003   krbtgt password older than 180 days
#   ADC-004   User accounts with no Kerberos pre-authentication (AS-REP roastable)
#   ADC-005   Kerberoastable accounts (SPN + enabled + not gMSA/computer)
#   ADC-006   Unconstrained delegation on non-DC computer object
#   ADC-007   DCSsync rights granted to non-default account
#   ADC-008   Accounts in AdminSDHolder-protected groups not cleaned up
#   ADC-009   Default password policy too weak (min length < 14)
#   ADC-010   SID filtering disabled on external/forest trust
#   ADC-011   Protected Users group empty or unused
#   ADC-012   Recycling Bin not enabled (irrecoverable AD deletions)
#   ADC-013   DES encryption enabled on user account
#   ADC-014   RBCD configured on sensitive objects

# =============================================================================
# LDAP HELPERS
# =============================================================================

function _ADC_Searcher {
    param([string]$BaseDn, [string]$Filter, [string[]]$Props, [int]$PageSize = 500, [string]$Scope = 'Subtree')
    $base    = [adsi]"LDAP://$BaseDn"
    $s       = New-Object System.DirectoryServices.DirectorySearcher($base)
    $s.Filter      = $Filter
    $s.PageSize    = $PageSize
    $s.SearchScope = $Scope
    if ($Props) { $s.PropertiesToLoad.AddRange([string[]]$Props) }
    return $s
}

function _ADC_IntProp {
    param($Props, [string]$Name, [int]$Default = 0)
    if ($Props[$Name].Count) { return [int]$Props[$Name][0] } else { return $Default }
}

function _ADC_StrProp {
    param($Props, [string]$Name, [string]$Default = '')
    if ($Props[$Name].Count) { return $Props[$Name][0].ToString() } else { return $Default }
}

function _ADC_DateProp {
    param($Props, [string]$Name)
    if ($Props[$Name].Count) {
        try { return $Props[$Name][0] } catch {}
    }
    return $null
}

# Converts AD large integer (FileTime / interval) to DateTime
function _ADC_LargeIntToDate {
    param($LargeInt)
    try {
        $val = [long]($LargeInt.HighPart -shl 32 -bor [uint32]$LargeInt.LowPart)
        if ($val -le 0) { return $null }
        return [DateTime]::FromFileTime($val)
    } catch { return $null }
}

# =============================================================================
# DOMAIN / FOREST METADATA
# =============================================================================

function _ADC_CollectDomainInfo {
    param([string]$DomainDn, $RootDse)
    try {
        $d   = [adsi]"LDAP://$DomainDn"
        $p   = $d.Properties

        # Functional level — msDS-Behavior-Version
        $fl  = try { [int]$p['msDS-Behavior-Version'][0] } catch { -1 }

        # dsHeuristics — fDoListObject, fAnonNTLM, etc.
        $dsh = try { $p['dSHeuristics'][0].ToString() } catch { '' }

        # Tombstone lifetime
        $tsl = try {
            $configDn = $RootDse.configurationNamingContext.ToString()
            $dir = [adsi]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configDn"
            if ($dir.Properties['tombstoneLifetime'].Count) { [int]$dir.Properties['tombstoneLifetime'][0] } else { 60 }
        } catch { 60 }

        # Recycle Bin
        $recycleEnabled = $false
        try {
            $configDn = $RootDse.configurationNamingContext.ToString()
            $rb = [adsi]"LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configDn"
            $recycleEnabled = ($rb.Properties['enabledScopes'].Count -gt 0)
        } catch {}

        # MAQ
        $maq = try { [int]$p['ms-DS-MachineAccountQuota'][0] } catch { 10 }

        # PDC
        $pdc = try { ($d.fsmoroleowner) } catch { '' }

        return @{
            distinguishedName     = $DomainDn
            dnsRoot               = try { $p['dNSRoot'][0].ToString() } catch { '' }
            functionalLevel       = $fl
            machineAccountQuota   = $maq
            dsHeuristics          = $dsh
            tombstoneLifetimeDays = $tsl
            recycleBinEnabled     = $recycleEnabled
            pdcEmulator           = try { $RootDse.dnsHostName.ToString() } catch { '' }
            error                 = $null
        }
    } catch {
        return @{ distinguishedName=$DomainDn; error=$_.ToString() }
    }
}

function _ADC_CollectForestInfo {
    param($RootDse)
    try {
        $forestDn = $RootDse.rootDomainNamingContext.ToString()
        $configDn = $RootDse.configurationNamingContext.ToString()

        # Forest functional level from Partitions container
        $partsDn  = "CN=Partitions,$configDn"
        $parts    = [adsi]"LDAP://$partsDn"
        $forestFL = try { [int]$parts.Properties['msDS-Behavior-Version'][0] } catch { -1 }

        # Cross-forest trusts
        $trusts   = [System.Collections.Generic.List[hashtable]]::new()
        try {
            $systemDn = "CN=System,$($RootDse.defaultNamingContext)"
            $ts = _ADC_Searcher -BaseDn $systemDn -Filter '(objectClass=trustedDomain)' `
                -Props @('cn','trustDirection','trustType','trustAttributes','trustPartner','securityIdentifier','whenCreated')
            $ts.SearchScope = 'OneLevel'
            $ts.FindAll() | ForEach-Object {
                $tp = $_.Properties
                $trusts.Add(@{
                    partner        = _ADC_StrProp $tp 'trustpartner'
                    direction      = _ADC_IntProp $tp 'trustdirection'
                    trustType      = _ADC_IntProp $tp 'trusttype'
                    trustAttributes= _ADC_IntProp $tp 'trustattributes'
                    sidFiltering   = ((_ADC_IntProp $tp 'trustattributes') -band 0x00000004) -ne 0  # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
                    isTransitive   = ((_ADC_IntProp $tp 'trustattributes') -band 0x00000008) -ne 0  # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                    whenCreated    = if ($tp['whencreated'].Count) { $tp['whencreated'][0].ToString('o') } else { '' }
                })
            }
        } catch {}

        return @{
            forestRootDn    = $forestDn
            functionalLevel = $forestFL
            trusts          = $trusts.ToArray()
        }
    } catch { return @{ forestRootDn=''; functionalLevel=-1; trusts=@() } }
}

# =============================================================================
# PRIVILEGED GROUPS
# =============================================================================

function _ADC_GetGroupMembers {
    param([string]$GroupDn)
    $members = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $g   = [adsi]"LDAP://$GroupDn"
        $raw = @($g.Properties['member'])
        foreach ($memberDn in $raw) {
            try {
                $m   = [adsi]"LDAP://$memberDn"
                $mp  = $m.Properties
                $members.Add(@{
                    dn          = $memberDn.ToString()
                    samAccount  = _ADC_StrProp $mp 'samaccountname'
                    objectClass = if ($mp['objectclass'].Count) { $mp['objectclass'][-1].ToString() } else { '' }
                    enabled     = if ($mp['useraccountcontrol'].Count) { (([int]$mp['useraccountcontrol'][0]) -band 2) -eq 0 } else { $true }
                })
            } catch {}
        }
    } catch {}
    return $members
}

# =============================================================================
# ACCOUNT ENUMERATION
# =============================================================================

function _ADC_EnumerateAccounts {
    param([string]$DomainDn)

    $result = @{
        asrepRoastable  = [System.Collections.Generic.List[string]]::new()
        kerberoastable  = [System.Collections.Generic.List[hashtable]]::new()
        desOnly         = [System.Collections.Generic.List[string]]::new()
        unconstrainedDelegation = [System.Collections.Generic.List[hashtable]]::new()
        rbcd            = [System.Collections.Generic.List[hashtable]]::new()
        adminSdHolder   = [System.Collections.Generic.List[string]]::new()
        totalUsers      = 0
        enabledUsers    = 0
        staleUsers      = 0  # no logon in 90+ days
    }

    try {
        # UAC flags
        $UAC_ACCOUNTDISABLE    = 0x0002
        $UAC_DONT_REQ_PREAUTH  = 0x400000
        $UAC_USE_DES_KEY_ONLY  = 0x200000
        $UAC_TRUSTED_FOR_DELEGATION     = 0x80000    # unconstrained
        $UAC_NOT_DELEGATED     = 0x100000
        $UAC_WORKSTATION_TRUST_ACCOUNT  = 0x1000
        $UAC_SERVER_TRUST_ACCOUNT       = 0x2000

        $staleThreshold = (Get-Date).AddDays(-90).ToFileTime()

        # One broad pass over enabled user accounts
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Props @('samaccountname','useraccountcontrol','servicePrincipalName','adminCount','lastLogonTimestamp','distinguishedname')

        $s.FindAll() | ForEach-Object {
            $p   = $_.Properties
            $uac = _ADC_IntProp $p 'useraccountcontrol'
            $sam = _ADC_StrProp $p 'samaccountname'
            $result.totalUsers++
            $result.enabledUsers++

            # Stale logon
            if ($p['lastlogontimestamp'].Count -and $p['lastlogontimestamp'][0] -is [long]) {
                if ([long]$p['lastlogontimestamp'][0] -lt $staleThreshold) { $result.staleUsers++ }
            }

            # AS-REP roastable
            if ($uac -band $UAC_DONT_REQ_PREAUTH) {
                [void]$result.asrepRoastable.Add($sam)
            }

            # Kerberoastable (has SPN, not a computer, not gMSA)
            if ($p['serviceprincipalname'].Count) {
                $spns = @($p['serviceprincipalname'] | ForEach-Object { $_.ToString() })
                [void]$result.kerberoastable.Add(@{ samAccount=$sam; spns=$spns })
            }

            # DES-only
            if ($uac -band $UAC_USE_DES_KEY_ONLY) { [void]$result.desOnly.Add($sam) }

            # AdminSDHolder-protected
            if (_ADC_IntProp $p 'admincount' -gt 0) { [void]$result.adminSdHolder.Add($sam) }
        }

        # Unconstrained delegation — computers (non-DCs)
        $su = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' `
            -Props @('cn','dNSHostName','useraccountcontrol')
        $su.FindAll() | ForEach-Object {
            $p = $_.Properties
            [void]$result.unconstrainedDelegation.Add(@{
                cn      = _ADC_StrProp $p 'cn'
                fqdn    = _ADC_StrProp $p 'dnshostname'
            })
        }

        # RBCD — objects with msDS-AllowedToActOnBehalfOfOtherIdentity set
        $sr = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
            -Props @('cn','samaccountname','objectclass')
        $sr.FindAll() | ForEach-Object {
            $p = $_.Properties
            [void]$result.rbcd.Add(@{
                cn         = _ADC_StrProp $p 'cn'
                samAccount = _ADC_StrProp $p 'samaccountname'
            })
        }

    } catch { Write-Warning "[AD-Core] Account enumeration error: $_" }

    return $result
}

# =============================================================================
# KERBEROS / KRBTGT
# =============================================================================

function _ADC_CollectKerberos {
    param([string]$DomainDn)
    $result = @{ krbtgtPasswordAge=-1; krbtgtLastChanged=''; supportedEncTypes=@() }
    try {
        $s = _ADC_Searcher -BaseDn $DomainDn -Filter '(samaccountname=krbtgt)' `
            -Props @('pwdLastSet','msDS-SupportedEncryptionTypes')
        $r = $s.FindOne()
        if ($r) {
            $p    = $r.Properties
            $pwdSet = $null
            if ($p['pwdlastset'].Count) {
                try {
                    $ft  = [long]$p['pwdlastset'][0]
                    $pwdSet = [DateTime]::FromFileTime($ft)
                } catch {}
            }
            if ($pwdSet) {
                $result.krbtgtPasswordAge    = [int]((Get-Date) - $pwdSet).TotalDays
                $result.krbtgtLastChanged    = $pwdSet.ToString('o')
            }
            if ($p['msds-supportedencryptiontypes'].Count) {
                $enc = [int]$p['msds-supportedencryptiontypes'][0]
                $types = @()
                if ($enc -band 0x01) { $types += 'DES-CRC' }
                if ($enc -band 0x02) { $types += 'DES-MD5' }
                if ($enc -band 0x04) { $types += 'RC4' }
                if ($enc -band 0x08) { $types += 'AES128' }
                if ($enc -band 0x10) { $types += 'AES256' }
                $result.supportedEncTypes = $types
            }
        }
    } catch { Write-Warning "[AD-Core] krbtgt query failed: $_" }
    return $result
}

# =============================================================================
# DCSYNC RIGHTS (Replicating Directory Changes All)
# =============================================================================

function _ADC_CollectDCSyncRights {
    param([string]$DomainDn)
    $holders = [System.Collections.Generic.List[string]]::new()
    try {
        # DCSync requires both "Replicating Directory Changes" and "Replicating Directory Changes All"
        # Extended right GUIDs:
        $RDC_ALL_GUID  = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # Replicating Directory Changes All
        $RDC_GUID      = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # Replicating Directory Changes

        $dom  = [adsi]"LDAP://$DomainDn"
        $sd   = $dom.psbase.ObjectSecurity
        $rules= $sd.Access | Where-Object { $_.ActiveDirectoryRights -match 'ExtendedRight' }
        foreach ($rule in $rules) {
            if ($rule.ObjectType -eq $RDC_ALL_GUID -or $rule.ObjectType -eq $RDC_GUID) {
                $id = try { $rule.IdentityReference.ToString() } catch { 'unknown' }
                # Exclude well-known replication accounts
                if ($id -notmatch '(?i)(Domain Controllers|Enterprise Domain Controllers|ENTERPRISE DOMAIN CONTROLLERS|Administrators|NT AUTHORITY)') {
                    [void]$holders.Add($id)
                }
            }
        }
    } catch { Write-Warning "[AD-Core] DCSync ACL read failed: $_" }
    return $holders
}

# =============================================================================
# PASSWORD POLICY
# =============================================================================

function _ADC_CollectPasswordPolicy {
    param([string]$DomainDn)
    try {
        $d = [adsi]"LDAP://$DomainDn"
        $p = $d.Properties
        return @{
            minPasswordLength    = _ADC_IntProp $p 'minPwdLength'
            passwordHistoryLength= _ADC_IntProp $p 'pwdHistoryLength'
            complexityEnabled    = ((_ADC_IntProp $p 'pwdProperties') -band 1) -ne 0
            maxPasswordAge       = _ADC_IntProp $p 'maxPwdAge'
            lockoutThreshold     = _ADC_IntProp $p 'lockoutThreshold'
            lockoutDuration      = _ADC_IntProp $p 'lockoutDuration'
        }
    } catch { return @{ minPasswordLength=0; error='collection-failed' } }
}

# =============================================================================
# PRIVILEGED GROUP INVENTORY
# =============================================================================

function _ADC_CollectPrivGroups {
    param([string]$DomainDn, [string]$ForestRootDn)
    $groups = @{}
    $domainSid = try {
        $d = [adsi]"LDAP://$DomainDn"
        (New-Object System.Security.Principal.SecurityIdentifier($d.objectSid.Value, 0)).ToString()
    } catch { '' }

    $wellKnownGroups = @{
        'Domain Admins'    = "CN=Domain Admins,CN=Users,$DomainDn"
        'Schema Admins'    = "CN=Schema Admins,CN=Users,$ForestRootDn"
        'Enterprise Admins'= "CN=Enterprise Admins,CN=Users,$ForestRootDn"
        'Administrators'   = "CN=Administrators,CN=Builtin,$DomainDn"
        'Protected Users'  = "CN=Protected Users,CN=Users,$DomainDn"
        'Backup Operators' = "CN=Backup Operators,CN=Builtin,$DomainDn"
        'Account Operators'= "CN=Account Operators,CN=Builtin,$DomainDn"
        'Print Operators'  = "CN=Print Operators,CN=Builtin,$DomainDn"
        'DnsAdmins'        = "CN=DnsAdmins,CN=Users,$DomainDn"
    }
    foreach ($g in $wellKnownGroups.GetEnumerator()) {
        try {
            $members = _ADC_GetGroupMembers -GroupDn $g.Value
            $groups[$g.Key] = $members.ToArray()
        } catch {
            $groups[$g.Key] = @()
        }
    }
    return $groups
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _ADCore_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId

    $rootDse    = [adsi]'LDAP://RootDSE'
    $domainDn   = $rootDse.defaultNamingContext.ToString()
    $configDn   = $rootDse.configurationNamingContext.ToString()
    $domainFQDN = $RunContext.Domain

    # ── Collect all sections ──────────────────────────────────────────────────
    Write-Host "         [AD-Core] Domain and forest metadata..."
    $domainInfo  = _ADC_CollectDomainInfo  -DomainDn $domainDn -RootDse $rootDse
    $forestInfo  = _ADC_CollectForestInfo  -RootDse $rootDse
    $forestRootDn = $forestInfo.forestRootDn

    Write-Host "         [AD-Core] Privileged group inventory..."
    $privGroups  = _ADC_CollectPrivGroups -DomainDn $domainDn -ForestRootDn $forestRootDn

    Write-Host "         [AD-Core] Account enumeration (kerberoastable, AS-REP, delegation, RBCD)..."
    $accounts    = _ADC_EnumerateAccounts -DomainDn $domainDn

    Write-Host "         [AD-Core] Kerberos / krbtgt..."
    $kerberos    = _ADC_CollectKerberos -DomainDn $domainDn

    Write-Host "         [AD-Core] DCSync rights (ACL)..."
    $dcSyncHolders = _ADC_CollectDCSyncRights -DomainDn $domainDn

    Write-Host "         [AD-Core] Default password policy..."
    $pwdPolicy   = _ADC_CollectPasswordPolicy -DomainDn $domainDn

    # ── Evaluate findings ─────────────────────────────────────────────────────
    $findings = [System.Collections.Generic.List[object]]::new()

    # ADC-001: MAQ
    if ($domainInfo.machineAccountQuota -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-001' -Severity 'Medium' `
            -Technique 'T1136.002' `
            -Description "ms-DS-MachineAccountQuota is $($domainInfo.machineAccountQuota). Any authenticated user can join up to $($domainInfo.machineAccountQuota) machines, enabling RBCD attacks (MachineAccountQuota + GenericWrite → silver ticket path)." `
            -Reference 'https://attack.mitre.org/techniques/T1136/002/'))
    }

    # ADC-002: Domain functional level
    if ($domainInfo.functionalLevel -lt 7) {
        $levelName = @{0='2000'; 1='2003 Mixed'; 2='2003'; 3='2008'; 4='2008 R2'; 5='2012'; 6='2012 R2'; 7='2016'}[$domainInfo.functionalLevel]
        $findings.Add((New-Finding -Id 'ADC-002' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "Domain functional level is $domainInfo.functionalLevel ($levelName). Level 2016 (7) is required for Protected Users enhancements, PAC validation improvements, and credential guard compatibility." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-003: krbtgt password age
    if ($kerberos.krbtgtPasswordAge -gt 180) {
        $findings.Add((New-Finding -Id 'ADC-003' -Severity 'High' `
            -Technique 'T1558.001' `
            -Description "krbtgt account password last changed $($kerberos.krbtgtPasswordAge) days ago (last: $($kerberos.krbtgtLastChanged)). A stolen krbtgt hash can forge Golden Tickets valid until the password is rotated. Recommended: rotate every 180 days (two rotations to invalidate old hashes)." `
            -Reference 'https://attack.mitre.org/techniques/T1558/001/'))
    }

    # ADC-004: AS-REP roastable
    if ($accounts.asrepRoastable.Count -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-004' -Severity 'High' `
            -Technique 'T1558.004' `
            -Description "$($accounts.asrepRoastable.Count) account(s) have Kerberos pre-authentication disabled: $($accounts.asrepRoastable -join ', '). AS-REP roasting extracts crackable encrypted blobs without authentication." `
            -Reference 'https://attack.mitre.org/techniques/T1558/004/'))
    }

    # ADC-005: Kerberoastable
    if ($accounts.kerberoastable.Count -gt 0) {
        $preview = ($accounts.kerberoastable | Select-Object -First 5 | ForEach-Object { $_.samAccount }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-005' -Severity 'High' `
            -Technique 'T1558.003' `
            -Description "$($accounts.kerberoastable.Count) Kerberoastable account(s): $preview. Any authenticated user can request service tickets and crack them offline. Severity increases if SPNs belong to privileged accounts." `
            -Reference 'https://attack.mitre.org/techniques/T1558/003/'))
    }

    # ADC-006: Unconstrained delegation on non-DC
    if ($accounts.unconstrainedDelegation.Count -gt 0) {
        $names = ($accounts.unconstrainedDelegation | Select-Object -First 5 | ForEach-Object { $_.cn }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-006' -Severity 'Critical' `
            -Technique 'T1558' `
            -Description "$($accounts.unconstrainedDelegation.Count) non-DC computer(s) have unconstrained Kerberos delegation: $names. Compromise of these hosts allows capturing TGTs from any privileged user who authenticates, enabling full domain compromise via coercion attacks (PrinterBug, PetitPotam)." `
            -Reference 'https://attack.mitre.org/techniques/T1558/'))
    }

    # ADC-007: DCSync rights
    if ($dcSyncHolders.Count -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-007' -Severity 'Critical' `
            -Technique 'T1003.006' `
            -Description "Non-standard account(s) hold DCSync rights (Replicating Directory Changes / All): $($dcSyncHolders -join ', '). These accounts can use mimikatz lsadump::dcsync to extract any account's NTLM hash from AD replication." `
            -Reference 'https://attack.mitre.org/techniques/T1003/006/'))
    }

    # ADC-008: AdminSDHolder orphans (non-DA accounts with adminCount=1)
    $daMembers = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($group in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Backup Operators','Account Operators','Print Operators')) {
        foreach ($m in @($privGroups[$group])) { if ($m.samAccount) { [void]$daMembers.Add($m.samAccount) } }
    }
    $orphanAdminSdHolder = @($accounts.adminSdHolder | Where-Object { -not $daMembers.Contains($_) })
    if ($orphanAdminSdHolder.Count -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-008' -Severity 'Medium' `
            -Technique 'T1098' `
            -Description "$($orphanAdminSdHolder.Count) account(s) have adminCount=1 but are not current members of privileged groups: $($orphanAdminSdHolder -join ', '). These accounts may have been removed from privileged groups but retain their ACL protection, masking their past privilege history. Verify and clear adminCount if no longer needed." `
            -Reference 'https://attack.mitre.org/techniques/T1098/'))
    }

    # ADC-009: Default password policy
    if ($pwdPolicy.minPasswordLength -lt 14) {
        $findings.Add((New-Finding -Id 'ADC-009' -Severity 'Medium' `
            -Technique 'T1110.001' `
            -Description "Default domain password minimum length is $($pwdPolicy.minPasswordLength) characters (recommended: 14+). Short passwords increase offline cracking success after NTLM hash extraction." `
            -Reference 'https://attack.mitre.org/techniques/T1110/001/'))
    }

    # ADC-010: SID filtering disabled on trusts
    foreach ($trust in $forestInfo.trusts) {
        if (-not $trust.sidFiltering -and $trust.direction -ne 1) {  # Not inbound-only
            $findings.Add((New-Finding -Id 'ADC-010' -Severity 'High' `
                -Technique 'T1134.005' `
                -Description "SID filtering is DISABLED on trust with '$($trust.partner)' (direction: $($trust.direction), transitive: $($trust.isTransitive)). An attacker who compromises the trusted domain can forge SIDs with Enterprise Admins or Domain Admins group memberships in the SID history." `
                -Reference 'https://attack.mitre.org/techniques/T1134/005/'))
        }
    }

    # ADC-011: Protected Users group empty
    $puMembers = @($privGroups['Protected Users'])
    if ($puMembers.Count -eq 0) {
        $findings.Add((New-Finding -Id 'ADC-011' -Severity 'Medium' `
            -Technique 'T1003.001' `
            -Description "Protected Users group is empty. Domain Admins and other Tier 0 accounts should be members — membership prevents NTLM auth, DES/RC4 Kerberos, credential caching (CredSSP/WDigest), and forces AES Kerberos with short ticket lifetime." `
            -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
    }

    # ADC-012: Recycle Bin not enabled
    if (-not $domainInfo.recycleBinEnabled) {
        $findings.Add((New-Finding -Id 'ADC-012' -Severity 'Low' `
            -Technique 'T1485' `
            -Description "AD Recycle Bin is not enabled. Deleted AD objects are permanently lost after tombstone lifetime ($($domainInfo.tombstoneLifetimeDays) days). Ransomware or malicious deletion cannot be rolled back." `
            -Reference 'https://attack.mitre.org/techniques/T1485/'))
    }

    # ADC-013: DES-only accounts
    if ($accounts.desOnly.Count -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-013' -Severity 'High' `
            -Technique 'T1558.003' `
            -Description "$($accounts.desOnly.Count) account(s) use DES-only Kerberos encryption: $($accounts.desOnly -join ', '). DES is cryptographically broken (56-bit key). These accounts produce downgrade-exploitable service tickets." `
            -Reference 'https://attack.mitre.org/techniques/T1558/003/'))
    }

    # ADC-014: RBCD on non-trivial objects
    if ($accounts.rbcd.Count -gt 0) {
        $preview = ($accounts.rbcd | Select-Object -First 5 | ForEach-Object { $_.samAccount }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-014' -Severity 'High' `
            -Technique 'T1098' `
            -Description "$($accounts.rbcd.Count) object(s) have msDS-AllowedToActOnBehalfOfOtherIdentity set: $preview. RBCD allows the listed principals to impersonate any user to the target service. Verify these are intentional and not attacker-planted." `
            -Reference 'https://attack.mitre.org/techniques/T1098/'))
    }

    # ── Emit records ──────────────────────────────────────────────────────────

    # Domain record
    $records.Add((New-ReconRecord `
        -Collector      'AD-Core' `
        -ObjectType     'domain' `
        -StableId       $domainDn `
        -Category       'config' `
        -Tier           'T0' `
        -CollectedAtPriv $false `
        -Attributes     @{
            domain        = $domainInfo
            forest        = @{
                functionalLevel = $forestInfo.functionalLevel
                rootDn          = $forestInfo.forestRootDn
            }
            trusts           = $forestInfo.trusts
            kerberos         = $kerberos
            passwordPolicy   = $pwdPolicy
            accountsSummary  = @{
                totalUsers           = $accounts.totalUsers
                enabledUsers         = $accounts.enabledUsers
                staleUsers           = $accounts.staleUsers
                kerberoastableCount  = $accounts.kerberoastable.Count
                asrepRoastableCount  = $accounts.asrepRoastable.Count
                desOnlyCount         = $accounts.desOnly.Count
                unconstrainedDelegationCount = $accounts.unconstrainedDelegation.Count
                rbcdCount            = $accounts.rbcd.Count
                adminSdHolderCount   = $accounts.adminSdHolder.Count
            }
            dcSyncHolders    = $dcSyncHolders.ToArray()
        } `
        -Findings       $findings.ToArray() `
        -RunId          $runId))

    # Privileged groups record
    $records.Add((New-ReconRecord `
        -Collector      'AD-Core' `
        -ObjectType     'privileged-groups' `
        -StableId       "ADCore:privgroups:$domainFQDN" `
        -Category       'config' `
        -Tier           'T0' `
        -CollectedAtPriv $false `
        -Attributes     @{
            domain = $domainFQDN
            groups = @(
                $privGroups.GetEnumerator() | Sort-Object Name | ForEach-Object {
                    @{ groupName=$_.Key; members=@($_.Value) }
                }
            )
        } `
        -RunId $runId))

    # Kerberoastable accounts record (separate — can be large)
    if ($accounts.kerberoastable.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'kerberoastable-accounts' `
            -StableId       "ADCore:kerberoastable:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain   = $domainFQDN
                accounts = $accounts.kerberoastable.ToArray()
                total    = $accounts.kerberoastable.Count
            } `
            -RunId $runId))
    }

    # Delegation record
    if ($accounts.unconstrainedDelegation.Count -gt 0 -or $accounts.rbcd.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'delegation' `
            -StableId       "ADCore:delegation:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain                = $domainFQDN
                unconstrainedNonDC    = $accounts.unconstrainedDelegation.ToArray()
                rbcdObjects           = $accounts.rbcd.ToArray()
            } `
            -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'AD-Core' `
    -Description 'Core AD: domain/forest metadata, Kerberos (krbtgt, roasting, delegation, RBCD), privileged groups, ACL risks, password policy, trusts' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _ADCore_Collect @PSBoundParameters }
