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
#   ADC-015   Constrained delegation (S4U2Self/protocol-transition flag)
#   ADC-016   Shadow credentials (msDS-KeyCredentialLink populated)
#   ADC-017   Secrets found in description/info/comment attributes
#   ADC-018   gMSA retrieval rights over-broad
#   ADC-019   AdminSDHolder non-Tier-0 control ACEs (SDProp persistence)
#   ADC-020   LAPS read rights granted to non-Tier-0 principals
#   ADC-021   sIDHistory populated on accounts
#   ADC-022   PASSWD_NOTREQD UAC flag set
#   ADC-023   Reversible encryption (ENCRYPTED_TEXT_PASSWORD_ALLOWED)
#   ADC-024   altSecurityIdentities weak certificate mapping (ESC14)
#   ADC-025   Pre-Windows 2000 Compatible Access group has Authenticated Users or Everyone
#   ADC-026   Anonymous LDAP bind allowed (dsHeuristics bit 7)
#   ADC-027   DA/EA/Schema Admin accounts not enrolled in Protected Users
#   ADC-028   Privileged accounts with DONT_EXPIRE_PASSWORD flag
#   ADC-029   Disabled accounts in DA/EA/Schema Admin groups (ghost accounts)
#   ADC-030   Tombstone lifetime below 180 days
#   ADC-031   Forest functional level below 2016
#   ADC-032   Fine-Grained Password Policy grants weaker policy to privileged group
#   ADC-033   Stale DC computer objects (no logon > 90 days)
#   ADC-034   LAPS not deployed (schema absent or no computers enrolled)
#   ADC-035   RC4 Kerberos encryption still allowed at domain level
#   ADC-036   Built-in Guest account enabled
#   ADC-037   Built-in Administrator account not renamed (and enabled)
#   ADC-038   Schema Admins group has active members
#   ADC-039   Entra Connect sync account password age > 365 days
#   ADC-040   AZUREADSSOACC$ Kerberos key not rotated (Seamless SSO silver ticket path)
#   ADC-041   RODC Password Replication Policy — sensitive groups in reveal set
#   ADC-042   EXCHANGE WINDOWS PERMISSIONS has WriteDACL on domain root
#
# Review-Required records (not findings — presence flagged for manual review):
#   RODC, Exchange, SCCM/MECM, ADFS, Entra Connect, WSUS

# =============================================================================
# LDAP HELPERS
# =============================================================================

function _ADC_Searcher {
    param([string]$BaseDn, [string]$Filter, [string[]]$Props, [int]$PageSize = 500, [string]$Scope = 'Subtree')
    $base    = (New-AdsiEntry "LDAP://$BaseDn")
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
        $d   = (New-AdsiEntry "LDAP://$DomainDn")
        $p   = $d.Properties

        # Functional level — msDS-Behavior-Version
        $fl  = try { [int]$p['msDS-Behavior-Version'][0] } catch { -1 }

        # dsHeuristics — fDoListObject, fAnonNTLM, etc.
        $dsh = try { $p['dSHeuristics'][0].ToString() } catch { '' }

        # Tombstone lifetime
        $tsl = try {
            $configDn = $RootDse.configurationNamingContext.ToString()
            $dir = (New-AdsiEntry "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configDn")
            if ($dir.Properties['tombstoneLifetime'].Count) { [int]$dir.Properties['tombstoneLifetime'][0] } else { 60 }
        } catch { 60 }

        # Recycle Bin
        $recycleEnabled = $false
        try {
            $configDn = $RootDse.configurationNamingContext.ToString()
            $rb = (New-AdsiEntry "LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configDn")
            $recycleEnabled = ($rb.Properties['enabledScopes'].Count -gt 0)
        } catch {}

        # MAQ
        $maq = try { [int]$p['ms-DS-MachineAccountQuota'][0] } catch { 10 }

        # PDC
        $pdc = try { ($d.fsmoroleowner) } catch { '' }

        $dnsRoot     = try { $p['dNSRoot'][0].ToString() } catch { '' }
        $pdcEmulator = try { $RootDse.dnsHostName.ToString() } catch { '' }

        return @{
            distinguishedName     = $DomainDn
            dnsRoot               = $dnsRoot
            functionalLevel       = $fl
            machineAccountQuota   = $maq
            dsHeuristics          = $dsh
            tombstoneLifetimeDays = $tsl
            recycleBinEnabled     = $recycleEnabled
            pdcEmulator           = $pdcEmulator
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
        $parts    = (New-AdsiEntry "LDAP://$partsDn")
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
        $g   = (New-AdsiEntry "LDAP://$GroupDn")
        $raw = @($g.Properties['member'])
        foreach ($memberDn in $raw) {
            try {
                $m   = (New-AdsiEntry "LDAP://$memberDn")
                $mp  = $m.Properties
                $uacVal = if ($mp['useraccountcontrol'].Count) { [int]$mp['useraccountcontrol'][0] } else { 0 }
                $members.Add(@{
                    dn          = $memberDn.ToString()
                    samAccount  = _ADC_StrProp $mp 'samaccountname'
                    objectClass = if ($mp['objectclass'].Count) { $mp['objectclass'][-1].ToString() } else { '' }
                    enabled     = ($uacVal -band 2) -eq 0
                    uac         = $uacVal
                })
            } catch {}
        }
    } catch {}
    return ,$members
}

# =============================================================================
# ACCOUNT ENUMERATION
# =============================================================================

function _ADC_EnumerateAccounts {
    param([string]$DomainDn)

    $result = @{
        asrepRoastable          = [System.Collections.Generic.List[string]]::new()
        kerberoastable          = [System.Collections.Generic.List[hashtable]]::new()
        desOnly                 = [System.Collections.Generic.List[string]]::new()
        passwdNotRequired       = [System.Collections.Generic.List[string]]::new()
        reversibleEncryption    = [System.Collections.Generic.List[string]]::new()
        unconstrainedDelegation = [System.Collections.Generic.List[hashtable]]::new()
        rbcd                    = [System.Collections.Generic.List[hashtable]]::new()
        adminSdHolder           = [System.Collections.Generic.List[string]]::new()
        sidHistoryAccounts      = [System.Collections.Generic.List[hashtable]]::new()
        totalUsers              = 0
        enabledUsers            = 0
        staleUsers              = 0  # no logon in 90+ days
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

        $UAC_PASSWD_NOTREQD              = 0x0020
        $UAC_ENCRYPTED_TEXT_PASSWORD     = 0x0080  # Reversible encryption

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
            if ($uac -band $UAC_DONT_REQ_PREAUTH) { [void]$result.asrepRoastable.Add($sam) }

            # Kerberoastable (has SPN, not a computer, not gMSA)
            if ($p['serviceprincipalname'].Count) {
                $spns = @($p['serviceprincipalname'] | ForEach-Object { $_.ToString() })
                [void]$result.kerberoastable.Add(@{ samAccount=$sam; spns=$spns })
            }

            # DES-only
            if ($uac -band $UAC_USE_DES_KEY_ONLY) { [void]$result.desOnly.Add($sam) }

            # Password not required
            if ($uac -band $UAC_PASSWD_NOTREQD) { [void]$result.passwdNotRequired.Add($sam) }

            # Reversible encryption (plaintext-equivalent storage)
            if ($uac -band $UAC_ENCRYPTED_TEXT_PASSWORD) { [void]$result.reversibleEncryption.Add($sam) }

            # AdminSDHolder-protected
            if (_ADC_IntProp $p 'admincount' -gt 0) { [void]$result.adminSdHolder.Add($sam) }
        }

        # sIDHistory — accounts with legacy SID history (can grant silent privilege via trust)
        try {
            $ss = _ADC_Searcher -BaseDn $DomainDn -Filter '(sIDHistory=*)' `
                -Props @('samaccountname','objectclass','sIDHistory')
            $ss.FindAll() | ForEach-Object {
                $p = $_.Properties
                [void]$result.sidHistoryAccounts.Add(@{
                    samAccount  = _ADC_StrProp $p 'samaccountname'
                    objectClass = if ($p['objectclass'].Count) { $p['objectclass'][-1].ToString() } else { '' }
                    sidCount    = $p['sidhistory'].Count
                })
            }
        } catch { Write-Verbose "[AD-Core] sIDHistory query failed: $_" }

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
    $holders = [System.Collections.Generic.List[hashtable]]::new()
    try {
        # All three replication extended-right GUIDs (locale-independent)
        $REPL_CHANGES_GUID          = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
        $REPL_CHANGES_ALL_GUID      = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
        $REPL_CHANGES_FILTERED_GUID = '1131f6a2-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-In-Filtered-Set
        $replGuids = @($REPL_CHANGES_GUID, $REPL_CHANGES_ALL_GUID, $REPL_CHANGES_FILTERED_GUID)

        # Well-known SIDs that legitimately hold replication rights (SID-based, not name-based)
        $domSid    = try { (New-Object System.Security.Principal.SecurityIdentifier(((New-AdsiEntry "LDAP://$DomainDn")).objectSid.Value,0)).ToString() } catch { '' }
        $safeREs   = @(
            '^S-1-5-32-544$'                              # BUILTIN\Administrators
            '^S-1-5-18$'                                  # SYSTEM
            "^$([regex]::Escape($domSid))-516$"           # Domain Controllers
            "^$([regex]::Escape($domSid))-498$"           # Enterprise Read-Only DCs
            '^S-1-5-9$'                                   # Enterprise Domain Controllers
        )

        $dom   = (New-AdsiEntry "LDAP://$DomainDn")
        $sd    = $dom.psbase.ObjectSecurity
        $rules = $sd.Access | Where-Object { $_.ActiveDirectoryRights -match 'ExtendedRight' -and $_.AccessControlType -eq 'Allow' }
        foreach ($rule in $rules) {
            if ($replGuids -notcontains $rule.ObjectType.ToString()) { continue }
            $sid  = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rule.IdentityReference.ToString() }
            $name = try { $rule.IdentityReference.ToString() } catch { $sid }
            $isSafe = $safeREs | Where-Object { $sid -match $_ }
            if (-not $isSafe) {
                $right = switch ($rule.ObjectType.ToString()) {
                    $REPL_CHANGES_GUID          { 'DS-Replication-Get-Changes' }
                    $REPL_CHANGES_ALL_GUID      { 'DS-Replication-Get-Changes-All' }
                    $REPL_CHANGES_FILTERED_GUID { 'DS-Replication-Get-Changes-In-Filtered-Set' }
                    default                     { $rule.ObjectType.ToString() }
                }
                [void]$holders.Add(@{ sid=$sid; name=$name; right=$right })
            }
        }
    } catch { Write-Warning "[AD-Core] DCSync ACL read failed: $_" }
    return ,$holders
}

# =============================================================================
# PASSWORD POLICY
# =============================================================================

function _ADC_CollectPasswordPolicy {
    param([string]$DomainDn)
    try {
        $d = (New-AdsiEntry "LDAP://$DomainDn")
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
# CONSTRAINED DELEGATION
# =============================================================================

function _ADC_CollectConstrainedDelegation {
    param([string]$DomainDn)
    $result = [System.Collections.Generic.List[hashtable]]::new()
    try {
        # Any object (user or computer) with msDS-AllowedToDelegateTo set
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(msDS-AllowedToDelegateTo=*)' `
            -Props @('cn','samaccountname','objectclass','useraccountcontrol','msDS-AllowedToDelegateTo')
        $s.FindAll() | ForEach-Object {
            $p   = $_.Properties
            $uac = _ADC_IntProp $p 'useraccountcontrol'
            # TrustedToAuthForDelegation (0x1000000) means protocol transition (S4U2Self) is enabled
            $protoTransition = ($uac -band 0x1000000) -ne 0
            $spns = @($p['msds-allowedtodelegateto'] | ForEach-Object { $_.ToString() })
            [void]$result.Add(@{
                cn                = _ADC_StrProp $p 'cn'
                samAccount        = _ADC_StrProp $p 'samaccountname'
                objectClass       = if ($p['objectclass'].Count) { $p['objectclass'][-1].ToString() } else { '' }
                protocolTransition= $protoTransition
                allowedTo         = $spns
            })
        }
    } catch { Write-Verbose "[AD-Core] Constrained delegation query failed: $_" }
    return ,$result
}

# =============================================================================
# SHADOW CREDENTIALS
# =============================================================================

function _ADC_CollectShadowCredentials {
    param([string]$DomainDn)
    $result = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(msDS-KeyCredentialLink=*)' `
            -Props @('cn','samaccountname','objectclass','msDS-KeyCredentialLink')
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            [void]$result.Add(@{
                cn           = _ADC_StrProp $p 'cn'
                samAccount   = _ADC_StrProp $p 'samaccountname'
                objectClass  = if ($p['objectclass'].Count) { $p['objectclass'][-1].ToString() } else { '' }
                keyCount     = $p['msds-keycredentiallink'].Count
            })
        }
    } catch { Write-Verbose "[AD-Core] Shadow credentials query failed: $_" }
    return ,$result
}

# =============================================================================
# SECRETS IN AD ATTRIBUTES
# =============================================================================

$script:_ADC_SecretPatterns = @(
    '(?i)(password|passwd|pwd)\s*[:=]\s*\S+'
    '(?i)p@ss'
    '(?i)pass\s*(?:word|wd)?\s*(?:is|:)\s*\S+'
    '(?i)cred(?:ential)?\s*[:=]\s*\S+'
)

function _ADC_CollectSecretsInAttributes {
    param([string]$DomainDn)
    $hits = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Props @('samaccountname','description','info','comment')
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $sam = _ADC_StrProp $p 'samaccountname'
            foreach ($attr in @('description','info','comment')) {
                if (-not $p[$attr].Count) { continue }
                $val = $p[$attr][0].ToString()
                foreach ($pat in $script:_ADC_SecretPatterns) {
                    if ($val -match $pat) {
                        [void]$hits.Add(@{
                            samAccount = $sam
                            attribute  = $attr
                            # Truncate value — we record that a secret is present, not the secret itself
                            preview    = $val.Substring(0,[Math]::Min(60,$val.Length)) + '...'
                        })
                        break  # one hit per attribute per account is enough
                    }
                }
            }
        }
        # Also check computer objects
        $sc = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(objectCategory=computer)' `
            -Props @('cn','description','comment')
        $sc.FindAll() | ForEach-Object {
            $p = $_.Properties
            $cn = _ADC_StrProp $p 'cn'
            foreach ($attr in @('description','comment')) {
                if (-not $p[$attr].Count) { continue }
                $val = $p[$attr][0].ToString()
                foreach ($pat in $script:_ADC_SecretPatterns) {
                    if ($val -match $pat) {
                        [void]$hits.Add(@{
                            samAccount = $cn
                            attribute  = $attr
                            objectClass= 'computer'
                            preview    = $val.Substring(0,[Math]::Min(60,$val.Length)) + '...'
                        })
                        break
                    }
                }
            }
        }
    } catch { Write-Verbose "[AD-Core] Secrets-in-attributes scan failed: $_" }
    return ,$hits
}

# =============================================================================
# gMSA RETRIEVAL RIGHTS
# =============================================================================

function _ADC_CollectGMSARights {
    param([string]$DomainDn)
    $result = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(objectClass=msDS-GroupManagedServiceAccount)' `
            -Props @('cn','samaccountname','msDS-GroupMSAMembership','msDS-ManagedPasswordInterval')
        $s.FindAll() | ForEach-Object {
            $p  = $_.Properties
            $cn = _ADC_StrProp $p 'cn'
            $principals = [System.Collections.Generic.List[string]]::new()
            if ($p['msds-groupmsamembership'].Count) {
                # Parse the security descriptor to extract allowed principals
                try {
                    $sdBytes = [byte[]]$p['msds-groupmsamembership'][0]
                    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
                    foreach ($ace in $sd.DiscretionaryAcl) {
                        $name = try { $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.SecurityIdentifier.ToString() }
                        [void]$principals.Add($name)
                    }
                } catch {}
            }
            [void]$result.Add(@{
                cn                    = $cn
                samAccount            = _ADC_StrProp $p 'samaccountname'
                passwordIntervalDays  = _ADC_IntProp $p 'msds-managedpasswordinterval'
                allowedPrincipals     = $principals.ToArray()
                allowedCount          = $principals.Count
            })
        }
    } catch { Write-Verbose "[AD-Core] gMSA rights query failed: $_" }
    return ,$result
}

# =============================================================================
# ADMINSDHOLDER DACL SNAPSHOT
# Snapshot approach: emit full DACL as config record so drift engine catches
# planted ACEs across runs. Heuristically flag non-Tier-0 control rights.
# =============================================================================

function _ADC_CollectAdminSDHolderDACL {
    param([string]$DomainDn)
    $result = @{ dn=''; aces=@(); controlRightFlags=@() }
    try {
        $sdholderDn = "CN=AdminSDHolder,CN=System,$DomainDn"
        $sdh = (New-AdsiEntry "LDAP://$sdholderDn")
        $sd  = $sdh.psbase.ObjectSecurity
        $result.dn = $sdholderDn

        # Well-known Tier-0 SID patterns — principals that legitimately appear here
        $domSid = try { (New-Object System.Security.Principal.SecurityIdentifier(((New-AdsiEntry "LDAP://$DomainDn")).objectSid.Value,0)).ToString() } catch { '' }
        $tier0SidPatterns = @(
            '^S-1-5-32-544$'                                      # BUILTIN\Administrators
            '^S-1-5-18$'                                          # SYSTEM
            '^S-1-3-0$'                                           # Creator Owner
            "^$([regex]::Escape($domSid))-512$"                   # Domain Admins
            "^$([regex]::Escape($domSid))-519$"                   # Enterprise Admins
            "^$([regex]::Escape($domSid))-516$"                   # Domain Controllers
            '^S-1-5-9$'                                           # Enterprise Domain Controllers
            "^$([regex]::Escape($domSid))-518$"                   # Schema Admins
        )

        # Control rights mask (GenericAll, WriteDACL, WriteOwner, GenericWrite, CreateChild)
        $controlMask = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor
                       [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl  -bor
                       [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor
                       [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite

        $aces    = [System.Collections.Generic.List[hashtable]]::new()
        $suspect = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($ace in $sd.Access) {
            $sid  = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
            $name = try { $ace.IdentityReference.ToString() } catch { $sid }
            $aceEntry = @{
                sid     = $sid
                name    = $name
                rights  = $ace.ActiveDirectoryRights.ToString()
                type    = $ace.AccessControlType.ToString()
                inherit = $ace.IsInherited
            }
            [void]$aces.Add($aceEntry)

            # Heuristic: Allow ACE with control rights AND not a Tier-0 well-known principal
            if ($ace.AccessControlType -eq 'Allow' -and ($ace.ActiveDirectoryRights -band $controlMask)) {
                $isTier0 = $tier0SidPatterns | Where-Object { $sid -match $_ }
                if (-not $isTier0) {
                    [void]$suspect.Add($aceEntry)
                }
            }
        }
        $result.aces             = $aces.ToArray()
        $result.suspectAces      = $suspect.ToArray()
        $result.totalAces        = $aces.Count
        $result.suspectAceCount  = $suspect.Count
    } catch { Write-Verbose "[AD-Core] AdminSDHolder DACL read failed: $_" }
    return $result
}

# =============================================================================
# LAPS READ RIGHTS
# Walks the domain and top-level OUs for inheritable ACEs granting ReadProperty
# on the LAPS password attribute GUIDs. Lists non-Tier-0 principals.
# =============================================================================

function _ADC_CollectLAPSReadRights {
    param([string]$DomainDn)
    $readers = [System.Collections.Generic.List[hashtable]]::new()
    try {
        # LAPS attribute schema GUIDs (both v1 and v2)
        $LAPS_V1_GUID = '1.2.840.113556.1.4.1.160'  # ms-Mcs-AdmPwd (schema attr)
        # Use the actual extended-right/property GUIDs for LAPS v1 and v2
        # These are schema attribute GUIDs — ReadProperty ACE ObjectType matches them
        $lapsGuids = @(
            [guid]'ms-Mcs-AdmPwd'       # LAPS v1 (schema attribute name → GUID varies by schema)
        )

        $domSid = try { (New-Object System.Security.Principal.SecurityIdentifier(((New-AdsiEntry "LDAP://$DomainDn")).objectSid.Value,0)).ToString() } catch { '' }
        $tier0Patterns = @(
            '^S-1-5-32-544$'
            '^S-1-5-18$'
            "^$([regex]::Escape($domSid))-512$"
            "^$([regex]::Escape($domSid))-516$"
            '^S-1-5-9$'
        )

        # Check domain object and each first-level OU for inheritable LAPS read ACEs
        $targets = [System.Collections.Generic.List[string]]::new()
        [void]$targets.Add($DomainDn)
        $ouS = _ADC_Searcher -BaseDn $DomainDn -Filter '(objectClass=organizationalUnit)' `
            -Props @('distinguishedname') -Scope 'OneLevel'
        $ouS.SearchScope = 'OneLevel'
        $ouS.FindAll() | ForEach-Object { [void]$targets.Add($_.Properties['distinguishedname'][0].ToString()) }

        foreach ($dn in $targets) {
            try {
                $obj = (New-AdsiEntry "LDAP://$dn")
                $sd  = $obj.psbase.ObjectSecurity
                foreach ($ace in $sd.Access) {
                    # ReadProperty on all properties or on a specific LAPS property
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $rights = $ace.ActiveDirectoryRights
                    $hasRead = $rights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                    if (-not $hasRead) { continue }
                    # Flag all-property reads (no ObjectType restriction) as potential LAPS readers
                    $isAllProps = ($ace.ObjectType -eq [guid]::Empty)
                    if ($isAllProps -or $ace.PropagationFlags -ne 'NoPropagateInherit') {
                        $sid  = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                        $name = try { $ace.IdentityReference.ToString() } catch { $sid }
                        $isTier0 = $tier0Patterns | Where-Object { $sid -match $_ }
                        if (-not $isTier0 -and $sid) {
                            [void]$readers.Add(@{
                                dn          = $dn
                                sid         = $sid
                                name        = $name
                                allProperties = $isAllProps
                                inherited   = $ace.IsInherited
                            })
                        }
                    }
                }
            } catch {}
        }
    } catch { Write-Verbose "[AD-Core] LAPS read rights query failed: $_" }
    return ,$readers
}

# =============================================================================
# PRIVILEGED GROUP INVENTORY
# =============================================================================

function _ADC_CollectPrivGroups {
    param([string]$DomainDn, [string]$ForestRootDn)
    $groups = @{}
    $domainSid = try {
        $d = (New-AdsiEntry "LDAP://$DomainDn")
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
# FINE-GRAINED PASSWORD POLICIES
# =============================================================================

function _ADC_CollectFineGrainedPolicies {
    param([string]$DomainDn)
    $results = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $psoContainer = "CN=Password Settings Container,CN=System,$DomainDn"
        $s = _ADC_Searcher -BaseDn $psoContainer `
            -Filter '(objectClass=msDS-PasswordSettings)' `
            -Props @('cn','msDS-MinimumPasswordLength','msDS-PasswordHistoryLength',
                     'msDS-MaximumPasswordAge','msDS-LockoutThreshold',
                     'msDS-PSOAppliesTo','msDS-PasswordSettingsPrecedence')
        $s.SearchScope = 'OneLevel'
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $minLen    = if ($p['msds-minimumpasswordlength'].Count) { [int]$p['msds-minimumpasswordlength'][0] } else { 0 }
            $lockout   = if ($p['msds-lockoutthreshold'].Count) { [int]$p['msds-lockoutthreshold'][0] } else { 0 }
            $precedence= if ($p['msds-passwordsettingsprecedence'].Count) { [int]$p['msds-passwordsettingsprecedence'][0] } else { 999 }
            $appliesTo = @($p['msds-psoappliestodn'] | ForEach-Object { $_.ToString() })
            $results.Add(@{
                cn          = if ($p['cn'].Count) { $p['cn'][0].ToString() } else { '' }
                minLength   = $minLen
                lockout     = $lockout
                precedence  = $precedence
                appliesTo   = $appliesTo
                weakMinLen  = ($minLen -lt 14)
                weakLockout = ($lockout -eq 0)
            })
        }
    } catch { Write-Verbose "[AD-Core] Fine-grained password policy query failed: $_" }
    return ,$results
}

function _ADC_CollectStaleDCs {
    param([string]$DomainDn)
    $staleDCs = [System.Collections.Generic.List[hashtable]]::new()
    try {
        # Domain Controllers have primaryGroupID=516
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(&(objectCategory=computer)(primaryGroupID=516))' `
            -Props @('cn','dNSHostName','lastLogonTimestamp','operatingSystem','operatingSystemVersion')
        $cutoff = (Get-Date).AddDays(-90)
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $cn  = if ($p['cn'].Count) { $p['cn'][0].ToString() } else { '?' }
            $dns = if ($p['dnshostname'].Count) { $p['dnshostname'][0].ToString() } else { '' }
            $llt = $null
            if ($p['lastlogontimestamp'].Count) {
                try { $llt = [DateTime]::FromFileTime($p['lastlogontimestamp'][0]) } catch {}
            }
            $os  = if ($p['operatingsystem'].Count) { $p['operatingsystem'][0].ToString() } else { '' }
            # Flag if never logged on or not logged on in 90+ days
            if ($null -eq $llt -or $llt -lt $cutoff) {
                $staleDCs.Add(@{
                    cn              = $cn
                    dnsHostName     = $dns
                    lastLogon       = if ($llt) { $llt.ToString('o') } else { 'never' }
                    operatingSystem = $os
                    daysSinceLogon  = if ($llt) { [int]((Get-Date) - $llt).TotalDays } else { -1 }
                })
            }
        }
    } catch { Write-Verbose "[AD-Core] Stale DC query failed: $_" }
    return ,$staleDCs
}

# =============================================================================
# ESC14 — ALT SECURITY IDENTITIES (weak certificate mapping)
# Accounts with altSecurityIdentities values using weak binding forms
# (X509RFC822: email, X509IssuerSubject: issuer+subject) can be targeted by
# ESC14: an attacker who can obtain or forge a matching certificate can
# authenticate as that account. Strong forms (X509SKI:, X509PublicKey:,
# Kerberos:) are acceptable and are NOT flagged.
# =============================================================================

function _ADC_CollectAltSecurityIdentities {
    param([string]$DomainDn)

    # Prefixes considered weak — attacker-controlled or forgeable
    $weakPrefixes = @('X509RFC822:', 'X509IssuerSubject:')

    $results = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = _ADC_Searcher -BaseDn $DomainDn `
            -Filter '(&(|(objectClass=user)(objectClass=computer))(altSecurityIdentities=*))' `
            -Props @('cn','distinguishedname','altSecurityIdentities','objectClass','userAccountControl')
        $s.FindAll() | ForEach-Object {
            $props     = $_.Properties
            $cn        = if ($props['cn'].Count) { $props['cn'][0].ToString() } else { '?' }
            $dn        = if ($props['distinguishedname'].Count) { $props['distinguishedname'][0].ToString() } else { '' }
            $uac       = if ($props['useraccountcontrol'].Count) { [int]$props['useraccountcontrol'][0] } else { 0 }
            $isEnabled = -not ($uac -band 2)   # ACCOUNTDISABLE bit
            $isComputer= ($props['objectclass'] | Where-Object { $_ -eq 'computer' }).Count -gt 0

            $weakValues  = [System.Collections.Generic.List[string]]::new()
            $strongValues= [System.Collections.Generic.List[string]]::new()
            foreach ($v in $props['altsecurityidentities']) {
                $vs = $v.ToString()
                if ($weakPrefixes | Where-Object { $vs.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }) {
                    [void]$weakValues.Add($vs)
                } else {
                    [void]$strongValues.Add($vs)
                }
            }

            if ($weakValues.Count -gt 0) {
                [void]$results.Add(@{
                    cn          = $cn
                    dn          = $dn
                    enabled     = $isEnabled
                    isComputer  = $isComputer
                    weakMappings= $weakValues.ToArray()
                    totalMappings = $props['altsecurityidentities'].Count
                })
            }
        }
    } catch { Write-Verbose "[AD-Core] altSecurityIdentities query failed: $_" }
    return ,$results
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

# =============================================================================
# ADJACENT INFRASTRUCTURE ROLE PRESENCE
# Lightweight LDAP presence check only — these roles are explicitly out of scope
# for automated assessment. Emitted as review-required records, not findings,
# so the post-run pass knows to assess them manually.
# =============================================================================

function _ADC_CollectRolePresence {
    param([string]$DomainDn, [string]$ConfigDn)

    $roles = [System.Collections.Generic.List[hashtable]]::new()

    function Add-Role {
        param([string]$Name, [string]$Category, [string]$Evidence, [string]$Reason)
        [void]$roles.Add(@{ name=$Name; category=$Category; evidence=$Evidence; reason=$Reason })
    }

    function LDAP-Exists {
        param([string]$BaseDn, [string]$Filter, [string[]]$Props)
        try {
            $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$BaseDn"))
            $s.Filter   = $Filter
            $s.PageSize = 10
            $s.SizeLimit= 1
            if ($Props) { $s.PropertiesToLoad.AddRange($Props) }
            $r = $s.FindOne()
            return if ($r) { $r } else { $null }
        } catch { return $null }
    }

    # ── RODC (Read-Only Domain Controllers) ──────────────────────────────────
    # primaryGroupID=521 = the Read-Only Domain Controllers group
    $rodcResult = LDAP-Exists -BaseDn $DomainDn `
        -Filter '(&(objectCategory=computer)(primaryGroupID=521))' -Props @('cn','dNSHostName')
    if ($rodcResult) {
        $cn = if ($rodcResult.Properties['cn'].Count) { $rodcResult.Properties['cn'][0].ToString() } else { '(unknown)' }
        Add-Role -Name 'RODC' -Category 'infrastructure' `
            -Evidence "First RODC detected: $cn" `
            -Reason 'RODCs have separate password replication policy and filtered attribute sets that require manual review. Assess: which accounts replicate to the RODC, msDS-RevealedList, and physical security of the RODC location.'
    }

    # ── Exchange ──────────────────────────────────────────────────────────────
    # The Exchange organization container lives in the Configuration partition.
    $exchResult = LDAP-Exists -BaseDn $ConfigDn `
        -Filter '(objectClass=msExchOrganization)' -Props @('name')
    if ($exchResult) {
        $orgName = if ($exchResult.Properties['name'].Count) { $exchResult.Properties['name'][0].ToString() } else { '(unknown)' }
        Add-Role -Name 'Exchange' -Category 'infrastructure' `
            -Evidence "Exchange organization: $orgName" `
            -Reason 'Exchange extends AD schema and grants elevated AD permissions to EXCHANGE WINDOWS PERMISSIONS and EXCHANGE TRUSTED SUBSYSTEM groups. Assess: these groups'' AD rights, whether Exchange is co-located with AD DS, and Organization Management membership.'
    }

    # ── SCCM/MECM (SMS_SiteServer SCP) ───────────────────────────────────────
    $sccmResult = LDAP-Exists -BaseDn $DomainDn `
        -Filter '(&(objectClass=serviceConnectionPoint)(keywords=SMSVersion*))' `
        -Props @('cn','bindingInformation')
    if ($sccmResult) {
        $cn = if ($sccmResult.Properties['cn'].Count) { $sccmResult.Properties['cn'][0].ToString() } else { '(unknown)' }
        Add-Role -Name 'SCCM/MECM' -Category 'infrastructure' `
            -Evidence "SCCM/MECM SCP detected: $cn" `
            -Reason 'SCCM/MECM can execute arbitrary code on all managed systems — compromise of the site server is equivalent to domain compromise. Assess: NAA account rights, site server admin group, client push account permissions, and whether PKI enrollment is secured.'
    }

    # ── ADFS ─────────────────────────────────────────────────────────────────
    $adfsResult = LDAP-Exists -BaseDn "CN=Program Data,$DomainDn" `
        -Filter '(&(objectClass=serviceConnectionPoint)(serviceClassName=ADFS*))' `
        -Props @('cn','serviceBindingInformation')
    if ($adfsResult) {
        $cn = if ($adfsResult.Properties['cn'].Count) { $adfsResult.Properties['cn'][0].ToString() } else { '(unknown)' }
        Add-Role -Name 'ADFS' -Category 'federation' `
            -Evidence "ADFS SCP detected: $cn" `
            -Reason 'ADFS trusts and token-signing certificates are high-value targets. Assess: relying party trust configuration, token-signing key hygiene, primary ADFS server isolation, and whether ADFS Admin console is restricted to Tier 0.'
    }

    # ── Entra Connect / Azure AD Connect ─────────────────────────────────────
    # AAD Connect registers a SCP under the Device Registration Configuration container.
    # Filter on well-known azureADName keyword that ADConnect writes.
    $entraResult = LDAP-Exists -BaseDn "CN=Services,$ConfigDn" `
        -Filter '(&(objectClass=serviceConnectionPoint)(keywords=azureADName:*))' `
        -Props @('cn','keywords')
    if ($entraResult) {
        $cn = if ($entraResult.Properties['cn'].Count) { $entraResult.Properties['cn'][0].ToString() } else { '(unknown)' }
        Add-Role -Name 'Entra Connect (Azure AD Connect)' -Category 'hybrid-identity' `
            -Evidence "Entra Connect SCP detected: $cn" `
            -Reason 'The ADSync service account has privileged AD rights (replication rights or local admin on DC depending on sync mode). Assess: sync account permissions (especially if using AD DS Connector account with DCSync rights), PHS password hash sync, PTA agent, seamless SSO (AZUREADSSOACC account), and whether the sync server is Tier 0.'
    }

    # ── WSUS ─────────────────────────────────────────────────────────────────
    # WSUS does not reliably register an SCP, but domain-joined WSUS servers
    # are typically referenced in GPO registry paths. Check for the WSUS
    # computer group in AD or the iisadmpwd/wuserver SCP pattern.
    $wsusResult = LDAP-Exists -BaseDn $DomainDn `
        -Filter '(&(objectClass=serviceConnectionPoint)(keywords=wuserver*))' `
        -Props @('cn')
    if (-not $wsusResult) {
        # Fallback: look for a computer named *wsus* (heuristic, non-exhaustive)
        $wsusResult = LDAP-Exists -BaseDn $DomainDn `
            -Filter '(&(objectCategory=computer)(cn=*wsus*))' -Props @('cn','dNSHostName')
    }
    if ($wsusResult) {
        $cn = if ($wsusResult.Properties['cn'].Count) { $wsusResult.Properties['cn'][0].ToString() } else { '(unknown)' }
        Add-Role -Name 'WSUS' -Category 'infrastructure' `
            -Evidence "WSUS presence inferred: $cn" `
            -Reason 'A compromised WSUS server can deliver malicious updates to all managed Windows systems. Assess: WSUS server accounts, who can approve updates, whether SSL is required, and network isolation of the WSUS server.'
    }

    return ,$roles
}

# =============================================================================
# SPRINT 5 — BUILTIN HYGIENE / LAPS / KERBEROS ENC / ENTRA / RODC / EXCHANGE
# =============================================================================

function _ADC_CheckBuiltinAccounts {
    param([string]$DomainDn)
    $result = @{ guestEnabled=$false; adminNotRenamed=$false; adminEnabled=$false }
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter = '(samaccountname=Guest)'
        $s.PropertiesToLoad.AddRange([string[]]@('useraccountcontrol'))
        $s.SizeLimit = 1
        $g = $s.FindOne()
        if ($g) { $result.guestEnabled = -not ([int]$g.Properties['useraccountcontrol'][0] -band 0x02) }

        $s2 = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s2.Filter = '(samaccountname=Administrator)'
        $s2.PropertiesToLoad.AddRange([string[]]@('useraccountcontrol'))
        $s2.SizeLimit = 1
        $a = $s2.FindOne()
        if ($a) {
            $result.adminEnabled    = -not ([int]$a.Properties['useraccountcontrol'][0] -band 0x02)
            $result.adminNotRenamed = $true
        }
    } catch { Write-Verbose "[AD-Core] Builtin account check failed: $_" }
    return $result
}

function _ADC_CheckLAPSDeployment {
    param([string]$DomainDn, [string]$SchemaDn)
    $result = @{ schemaPresent=$false; lapsVersion='none'; anyComputerEnrolled=$false }
    try {
        $lapsV1 = $false; $lapsV2 = $false
        try { $v1 = (New-AdsiEntry "LDAP://CN=ms-Mcs-AdmPwd,$SchemaDn"); $lapsV1 = ($v1 -and $v1.Properties['cn'].Count -gt 0) } catch {}
        try { $v2 = (New-AdsiEntry "LDAP://CN=msLAPS-Password,$SchemaDn"); $lapsV2 = ($v2 -and $v2.Properties['cn'].Count -gt 0) } catch {}
        $result.schemaPresent = $lapsV1 -or $lapsV2
        $result.lapsVersion   = if ($lapsV2) { 'v2' } elseif ($lapsV1) { 'v1' } else { 'none' }
        if ($result.schemaPresent) {
            $attr = if ($lapsV2) { 'msLAPS-PasswordExpirationTime' } else { 'ms-Mcs-AdmPwdExpirationTime' }
            $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
            $s.Filter = "(&(objectCategory=computer)($attr=*))"; $s.PageSize = 1; $s.SizeLimit = 1
            $s.PropertiesToLoad.Add('cn') | Out-Null
            $result.anyComputerEnrolled = ($null -ne $s.FindOne())
        }
    } catch { Write-Verbose "[AD-Core] LAPS deployment check failed: $_" }
    return $result
}

function _ADC_CheckKerberosEncryption {
    param([string]$DomainDn)
    # Bits: 1=DES-CRC, 2=DES-MD5, 4=RC4-HMAC, 8=AES128, 16=AES256; 0/absent = OS default (RC4 allowed)
    try {
        $d = (New-AdsiEntry "LDAP://$DomainDn")
        $enc = try { [int]$d.Properties['msDS-SupportedEncryptionTypes'][0] } catch { 0 }
        return @{ encryptionTypes=$enc; rc4Allowed=[bool](($enc -eq 0) -or ($enc -band 0x04)) }
    } catch { return @{ encryptionTypes=0; rc4Allowed=$true } }
}

function _ADC_CollectEntraHybrid {
    param([string]$DomainDn)
    $result = @{ hasSyncAccount=$false; syncAccountName=''; syncAccountPwdAgeDays=-1; hasSsoComputer=$false }
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter = '(&(objectClass=user)(|(samaccountname=MSOL_*)(samaccountname=AZUREAD_*)))'
        $s.PropertiesToLoad.AddRange([string[]]@('samaccountname','pwdlastset')); $s.SizeLimit = 1
        $sync = $s.FindOne()
        if ($sync) {
            $result.hasSyncAccount  = $true
            $result.syncAccountName = $sync.Properties['samaccountname'][0].ToString()
            $raw = if ($sync.Properties['pwdlastset'].Count) { [long]$sync.Properties['pwdlastset'][0] } else { 0 }
            if ($raw -gt 0) { $result.syncAccountPwdAgeDays = [int]((Get-Date) - [datetime]::FromFileTime($raw)).TotalDays }
        }
        $s2 = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s2.Filter = '(samaccountname=AZUREADSSOACC$)'; $s2.PropertiesToLoad.Add('cn') | Out-Null; $s2.SizeLimit = 1
        $result.hasSsoComputer = ($null -ne $s2.FindOne())
    } catch { Write-Verbose "[AD-Core] Entra hybrid check failed: $_" }
    return $result
}

function _ADC_CollectRODCPRP {
    param([string]$DomainDn)
    $issues = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter  = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))'
        $s.PageSize = 100
        $s.PropertiesToLoad.AddRange([string[]]@('cn','msDS-RevealOnDemandGroup'))
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $cn = if ($p['cn'].Count) { $p['cn'][0].ToString() } else { 'unknown' }
            $revealSet = @($p['msds-revealondemandgroup'] | Where-Object { $_ } | ForEach-Object { $_.ToString() })
            $sensitive = @($revealSet | Where-Object {
                $_ -match '(?i)CN=(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Domain Controllers),'
            })
            if ($sensitive.Count -gt 0) { $issues.Add(@{ rodcCN=$cn; sensitiveGroupsInReveal=$sensitive }) }
        }
    } catch { Write-Verbose "[AD-Core] RODC PRP check failed: $_" }
    return ,$issues
}

function _ADC_CheckExchangeDACL {
    param([string]$DomainDn)
    $result = @{ exchangeWriteDacl=$false; exchangeGroupDn='' }
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter = '(samaccountname=Exchange Windows Permissions)'
        $s.PropertiesToLoad.Add('distinguishedname') | Out-Null; $s.SizeLimit = 1
        $exGrp = $s.FindOne()
        if (-not $exGrp) { return $result }
        $result.exchangeGroupDn = $exGrp.Properties['distinguishedname'][0].ToString()
        $domObj = (New-AdsiEntry "LDAP://$DomainDn")
        foreach ($ace in $domObj.psbase.ObjectSecurity.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $trustee = try { $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.IdentityReference.Value }
            if ($trustee -imatch 'Exchange Windows Permissions') {
                if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) {
                    $result.exchangeWriteDacl = $true; break
                }
            }
        }
    } catch { Write-Verbose "[AD-Core] Exchange DACL check failed: $_" }
    return $result
}

function _ADCore_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId

    $rootDse    = (New-AdsiEntry 'LDAP://RootDSE')
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

    Write-Host "         [AD-Core] Constrained delegation..."
    $constrainedDelegation = _ADC_CollectConstrainedDelegation -DomainDn $domainDn

    Write-Host "         [AD-Core] Shadow credentials (msDS-KeyCredentialLink)..."
    $shadowCreds = _ADC_CollectShadowCredentials -DomainDn $domainDn

    Write-Host "         [AD-Core] Secrets in AD attributes..."
    $secretsInAttrs = _ADC_CollectSecretsInAttributes -DomainDn $domainDn

    Write-Host "         [AD-Core] gMSA retrieval rights..."
    $gmsaRights = _ADC_CollectGMSARights -DomainDn $domainDn

    Write-Host "         [AD-Core] AdminSDHolder DACL snapshot..."
    $adminSdHolder = _ADC_CollectAdminSDHolderDACL -DomainDn $domainDn

    Write-Host "         [AD-Core] LAPS read rights..."
    $lapsReadRights = _ADC_CollectLAPSReadRights -DomainDn $domainDn

    Write-Host "         [AD-Core] Fine-grained password policies..."
    $fgppList    = _ADC_CollectFineGrainedPolicies -DomainDn $domainDn

    Write-Host "         [AD-Core] Stale DC objects..."
    $staleDCs    = _ADC_CollectStaleDCs -DomainDn $domainDn

    Write-Host "         [AD-Core] Builtin account hygiene (Guest, Administrator)..."
    $builtinAccts = _ADC_CheckBuiltinAccounts -DomainDn $domainDn

    Write-Host "         [AD-Core] LAPS deployment coverage..."
    $schemaDn     = $rootDse.schemaNamingContext.ToString()
    $lapsDeployment = _ADC_CheckLAPSDeployment -DomainDn $domainDn -SchemaDn $schemaDn

    Write-Host "         [AD-Core] Kerberos encryption types (RC4 at domain level)..."
    $kerberosEnc  = _ADC_CheckKerberosEncryption -DomainDn $domainDn

    Write-Host "         [AD-Core] Entra hybrid identity checks..."
    $entraHybrid  = _ADC_CollectEntraHybrid -DomainDn $domainDn

    Write-Host "         [AD-Core] RODC Password Replication Policy..."
    $rodcPRP      = _ADC_CollectRODCPRP -DomainDn $domainDn

    Write-Host "         [AD-Core] Exchange Windows Permissions DACL check..."
    $exchangeDACL = _ADC_CheckExchangeDACL -DomainDn $domainDn

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

    # ADC-015: Constrained delegation with protocol transition (S4U2Self)
    $protoTransitionDelegates = @($constrainedDelegation | Where-Object { $_.protocolTransition })
    if ($protoTransitionDelegates.Count -gt 0) {
        $names = ($protoTransitionDelegates | Select-Object -First 5 | ForEach-Object { $_.samAccount }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-015' -Severity 'High' `
            -Technique 'T1134.001' `
            -Description "$($protoTransitionDelegates.Count) account(s) have constrained delegation with protocol transition (S4U2Self — TrustedToAuthForDelegation flag): $names. Protocol transition allows the service to impersonate any user to delegated SPNs without requiring the original Kerberos ticket, enabling lateral movement without prior authentication." `
            -Reference 'https://attack.mitre.org/techniques/T1134/001/'))
    } elseif ($constrainedDelegation.Count -gt 0) {
        # Standard constrained delegation without protocol transition is lower risk — informational
        $names = ($constrainedDelegation | Select-Object -First 5 | ForEach-Object { $_.samAccount }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-015' -Severity 'Informational' `
            -Technique 'T1134.001' `
            -Description "$($constrainedDelegation.Count) account(s) have standard constrained delegation (msDS-AllowedToDelegateTo): $names. Constrained delegation limits impersonation to specific SPNs. Verify delegation targets are appropriate and accounts are secured." `
            -Reference 'https://attack.mitre.org/techniques/T1134/001/'))
    }

    # ADC-016: Shadow credentials (msDS-KeyCredentialLink populated on unexpected objects)
    if ($shadowCreds.Count -gt 0) {
        $preview = ($shadowCreds | Select-Object -First 5 | ForEach-Object { "$($_.samAccount)($($_.keyCount) key(s))" }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-016' -Severity 'Critical' `
            -Technique 'T1556' `
            -Description "$($shadowCreds.Count) object(s) have msDS-KeyCredentialLink populated: $preview. This attribute binds a Kerberos certificate credential — an attacker with write access can add a shadow credential to maintain persistent privileged access (PKINIT authentication) even after password resets." `
            -Reference 'https://attack.mitre.org/techniques/T1556/'))
    }

    # ADC-017: Secrets in AD attributes
    if ($secretsInAttrs.Count -gt 0) {
        $preview = ($secretsInAttrs | Select-Object -First 3 | ForEach-Object { "$($_.samAccount):$($_.attribute)" }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-017' -Severity 'High' `
            -Technique 'T1552.004' `
            -Description "$($secretsInAttrs.Count) account(s)/computer(s) have password-like strings in AD description/info/comment attributes: $preview. These attributes are readable by all authenticated users and are a common plaintext credential exposure vector." `
            -Reference 'https://attack.mitre.org/techniques/T1552/004/'))
    }

    # ADC-018: gMSA over-broad retrieval rights
    $broadGmsa = @($gmsaRights | Where-Object { $_.allowedCount -gt 5 })
    if ($gmsaRights.Count -gt 0) {
        $preview = ($gmsaRights | Select-Object -First 5 | ForEach-Object { "$($_.samAccount)($($_.allowedCount) principal(s))" }) -join ', '
        $sev = if ($broadGmsa.Count -gt 0) { 'Medium' } else { 'Informational' }
        $findings.Add((New-Finding -Id 'ADC-018' -Severity $sev `
            -Technique 'T1003' `
            -Description "$($gmsaRights.Count) Group Managed Service Account(s) present. $($broadGmsa.Count) have more than 5 principals authorized to retrieve their managed password: $preview. Over-broad gMSA read rights can allow credential theft from any authorized principal." `
            -Reference 'https://attack.mitre.org/techniques/T1003/'))
    }

    # ADC-019: AdminSDHolder — non-Tier-0 ACEs
    if ($adminSdHolder.suspectAceCount -gt 0) {
        $names = ($adminSdHolder.suspectAces | Select-Object -First 5 | ForEach-Object { "$($_.name)($($_.rights))" }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-019' -Severity 'Critical' `
            -Technique 'T1098' `
            -Description "$($adminSdHolder.suspectAceCount) non-Tier-0 principal(s) have control rights on CN=AdminSDHolder: $names. SDProp runs every 60 min and propagates AdminSDHolder ACEs to all adminCount=1 objects — a planted ACE here grants persistent privileged access to all protected accounts across the domain." `
            -Reference 'https://attack.mitre.org/techniques/T1098/'))
    }

    # ADC-020: LAPS over-broad read rights
    if ($lapsReadRights.Count -gt 0) {
        $preview = ($lapsReadRights | Select-Object -Unique -First 5 | ForEach-Object { $_.name }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-020' -Severity 'High' `
            -Technique 'T1555' `
            -Description "$($lapsReadRights.Count) ACE(s) on domain/OU objects grant non-Tier-0 principals inheritable ReadProperty: $preview. These principals may be able to read LAPS-managed local administrator passwords, enabling lateral movement to any LAPS-managed workstation." `
            -Reference 'https://attack.mitre.org/techniques/T1555/'))
    }

    # ADC-021: sIDHistory populated
    if ($accounts.sidHistoryAccounts.Count -gt 0) {
        $preview = ($accounts.sidHistoryAccounts | Select-Object -First 5 | ForEach-Object { $_.samAccount }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-021' -Severity 'High' `
            -Technique 'T1134.005' `
            -Description "$($accounts.sidHistoryAccounts.Count) account(s) have sIDHistory populated: $preview. SID history allows an account to carry SIDs from previous domains; attackers abuse this for silent privilege escalation across trusts. Each entry should be reviewed and cleared if migration is complete." `
            -Reference 'https://attack.mitre.org/techniques/T1134/005/'))
    }

    # ADC-022: PASSWD_NOTREQD accounts
    if ($accounts.passwdNotRequired.Count -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-022' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "$($accounts.passwdNotRequired.Count) account(s) have PASSWD_NOTREQD UAC flag set: $($accounts.passwdNotRequired -join ', '). These accounts may have blank or empty passwords. Verify they are not enabled or that authentication is restricted to MFA/Kerberos-only channels." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-023: Reversible encryption (cleartext password storage)
    if ($accounts.reversibleEncryption.Count -gt 0) {
        $findings.Add((New-Finding -Id 'ADC-023' -Severity 'High' `
            -Technique 'T1555.003' `
            -Description "$($accounts.reversibleEncryption.Count) account(s) have ENCRYPTED_TEXT_PASSWORD_ALLOWED (reversible encryption) set: $($accounts.reversibleEncryption -join ', '). AD stores these passwords in a reversibly encrypted form — anyone with domain replication rights or DCSync access can recover the plaintext password." `
            -Reference 'https://attack.mitre.org/techniques/T1555/003/'))
    }

    # ADC-025: Pre-Windows 2000 Compatible Access group has broad members
    # This built-in group historically included Everyone/Authenticated Users for NT4 compat.
    # Its presence grants broad read access to AD objects without explicit ACEs.
    $preWin2kDn = "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$domainDn"
    try {
        $preWin2kGrp = (New-AdsiEntry "LDAP://$preWin2kDn")
        $memberSids = @($preWin2kGrp.Properties['member'] | ForEach-Object { $_.ToString() })
        $broad = $memberSids | Where-Object { $_ -match 'Everyone|Authenticated Users|World|S-1-1-0|S-1-5-11' }
        if ($broad.Count -gt 0) {
            $findings.Add((New-Finding -Id 'ADC-025' -Severity 'High' `
                -Technique 'T1135' `
                -Description "Pre-Windows 2000 Compatible Access group contains broad identity: $($broad -join '; '). This built-in group grants read access to various AD objects via legacy NT4 compatibility semantics. Having 'Everyone' or 'Authenticated Users' here effectively allows any domain user (or anonymous on older configs) to enumerate user and group objects. Remove broad identities; the group should be empty on all modern domains." `
                -Reference 'https://attack.mitre.org/techniques/T1135/'))
        }
    } catch {}

    # ADC-026: Anonymous LDAP bind allowed (dsHeuristics bit 7 = 1)
    # dsHeuristics is a string where the 7th character (0-indexed: position 6) controls anonymous access.
    # Character '2' at position 6 (1-indexed: position 7) enables unauthenticated LDAP bind.
    $dsh = $domainInfo.dsHeuristics
    $anonBind = $false
    if ($dsh.Length -ge 7) {
        $anonBind = ($dsh[6] -eq '2')
    }
    if ($anonBind) {
        $findings.Add((New-Finding -Id 'ADC-026' -Severity 'Critical' `
            -Technique 'T1087.002' `
            -Description "Anonymous LDAP bind is ENABLED (dsHeuristics position 7 = '2'). An unauthenticated attacker can enumerate users, groups, computers, and trusts via LDAP without any credentials. dsHeuristics value: '$dsh'. To remediate: set position 7 to '0' or '1' in the dsHeuristics attribute on the domain object in CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,..." `
            -Reference 'https://attack.mitre.org/techniques/T1087/002/'))
    }

    # ADC-027: DA/EA/Schema Admin accounts NOT enrolled in Protected Users
    $puSet = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in @($privGroups['Protected Users'])) { if ($m.samAccount) { [void]$puSet.Add($m.samAccount) } }
    $tier0NotProtected = [System.Collections.Generic.List[string]]::new()
    foreach ($grp in @('Domain Admins','Enterprise Admins','Schema Admins')) {
        foreach ($m in @($privGroups[$grp])) {
            if ($m.samAccount -and $m.enabled -and -not $puSet.Contains($m.samAccount)) {
                [void]$tier0NotProtected.Add("$($m.samAccount) [$grp]")
            }
        }
    }
    if ($tier0NotProtected.Count -gt 0) {
        $preview = ($tier0NotProtected | Select-Object -First 8) -join ', '
        $findings.Add((New-Finding -Id 'ADC-027' -Severity 'High' `
            -Technique 'T1003.001' `
            -Description "$($tier0NotProtected.Count) enabled Tier 0 account(s) are NOT members of Protected Users: $preview. Protected Users membership prevents NTLM authentication, DES/RC4 Kerberos, credential caching (CredSSP/WDigest/Digest), and enforces AES Kerberos with a 4-hour TGT lifetime. Accounts must support Kerberos-only auth before adding (test in a non-prod environment first)." `
            -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
    }

    # ADC-028: Privileged accounts with DONT_EXPIRE_PASSWORD
    $neverExpirePriv = [System.Collections.Generic.List[string]]::new()
    foreach ($grp in @('Domain Admins','Enterprise Admins','Schema Admins','Backup Operators','Account Operators')) {
        foreach ($m in @($privGroups[$grp])) {
            if ($m.samAccount -and $m.enabled -and ($m.uac -band 65536)) {   # 0x10000 = DONT_EXPIRE_PASSWORD
                [void]$neverExpirePriv.Add("$($m.samAccount) [$grp]")
            }
        }
    }
    if ($neverExpirePriv.Count -gt 0) {
        $preview = ($neverExpirePriv | Select-Object -First 8) -join ', '
        $findings.Add((New-Finding -Id 'ADC-028' -Severity 'Medium' `
            -Technique 'T1098' `
            -Description "$($neverExpirePriv.Count) privileged account(s) have DONT_EXPIRE_PASSWORD set: $preview. Non-expiring passwords on privileged accounts means a compromised credential remains valid indefinitely. Privileged accounts should have passwords rotated regularly (90 days or less) and ideally be Just-In-Time accounts that are disabled when not in use." `
            -Reference 'https://attack.mitre.org/techniques/T1098/'))
    }

    # ADC-029: Disabled accounts in DA/EA/Schema Admin groups (ghost accounts)
    $ghostPriv = [System.Collections.Generic.List[string]]::new()
    foreach ($grp in @('Domain Admins','Enterprise Admins','Schema Admins')) {
        foreach ($m in @($privGroups[$grp])) {
            if ($m.samAccount -and -not $m.enabled) {
                [void]$ghostPriv.Add("$($m.samAccount) [$grp]")
            }
        }
    }
    if ($ghostPriv.Count -gt 0) {
        $preview = ($ghostPriv | Select-Object -First 8) -join ', '
        $findings.Add((New-Finding -Id 'ADC-029' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "$($ghostPriv.Count) DISABLED account(s) remain in privileged groups: $preview. Disabled accounts in DA/EA/Schema Admin retain all group memberships and ACL-derived rights. An attacker who re-enables a disabled privileged account (e.g., after compromising an admin with account-management rights) instantly gains full domain privilege without creating a new account. Remove disabled accounts from all privileged groups." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-030: Tombstone lifetime < 180 days
    $tslDays = $domainInfo.tombstoneLifetimeDays
    if ($tslDays -lt 180) {
        $findings.Add((New-Finding -Id 'ADC-030' -Severity 'Medium' `
            -Technique 'T1485' `
            -Description "Active Directory tombstone lifetime is $tslDays days (recommended: 180+). Short tombstone lifetime means deleted objects are permanently unrecoverable sooner, limiting incident-response ability to reconstruct malicious AD changes after a security incident. Also reduces the viable backup window — backups older than the tombstone lifetime cannot be used for authoritative restore. Configure via CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,... tombstoneLifetime attribute." `
            -Reference 'https://attack.mitre.org/techniques/T1485/'))
    }

    # ADC-031: Forest functional level < 2016
    if ($forestInfo.functionalLevel -lt 7) {
        $fflName = @{0='2000'; 1='2003'; 2='2003'; 3='2008'; 4='2008 R2'; 5='2012'; 6='2012 R2'; 7='2016'}[[int]$forestInfo.functionalLevel]
        $findings.Add((New-Finding -Id 'ADC-031' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "Forest functional level is $($forestInfo.functionalLevel) ($fflName). Forest functional level 2016 (7) enables PAM trust (Privileged Access Management), selective authentication for forest trusts, and is a prerequisite for some Protected Users behaviors across inter-forest trust scenarios. Raise requires all domains in the forest to be at 2016 DFL first." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-032: Fine-Grained Password Policy too weak (applied to any object)
    if ($fgppList.Count -gt 0) {
        $weakFgpp = @($fgppList | Where-Object { $_.weakMinLen -or $_.weakLockout })
        if ($weakFgpp.Count -gt 0) {
            $names = ($weakFgpp | ForEach-Object { "$($_.cn)(minLen=$($_.minLength),lockout=$($_.lockout))" }) -join '; '
            $findings.Add((New-Finding -Id 'ADC-032' -Severity 'Medium' `
                -Technique 'T1110.001' `
                -Description "$($weakFgpp.Count) Fine-Grained Password Policy/policies are weaker than baseline: $names. A PSO with minLength < 14 or lockout = 0 (disabled) applied to any group weakens password requirements below the domain minimum. Verify that PSOs applied to privileged groups enforce STRONGER (not weaker) policies. CN=Password Settings Container,CN=System,..." `
                -Reference 'https://attack.mitre.org/techniques/T1110/001/'))
        }
    }

    # ADC-033: Stale DC computer objects
    if ($staleDCs.Count -gt 0) {
        $preview = ($staleDCs | Select-Object -First 5 | ForEach-Object {
            "$($_.cn)(last=$($_.lastLogon))"
        }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-033' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "$($staleDCs.Count) DC computer object(s) have not authenticated in 90+ days: $preview. Stale DC objects may represent decommissioned DCs whose computer accounts were not cleaned up. An attacker who can reuse or control a stale DC computer account (e.g., via Kerberos S4U or RBCD) may be able to perform Kerberos ticket forgery against the replication service. Verify these DCs are truly decommissioned and remove computer objects from AD." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-034: LAPS not deployed (schema absent or no computers enrolled)
    if (-not $lapsDeployment.schemaPresent) {
        $findings.Add((New-Finding -Id 'ADC-034' -Severity 'High' `
            -Technique 'T1078.002' `
            -Description "LAPS schema extension is NOT present — LAPS is not deployed in this domain. Without LAPS, local Administrator passwords are manually managed and frequently reused across machines. A single compromised local admin credential grants pass-the-hash access to all machines sharing that password. Deploy Windows LAPS (built into Server 2019+/Win11) or legacy LAPS; schema extension is required before GPO enrollment can occur." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    } elseif (-not $lapsDeployment.anyComputerEnrolled) {
        $findings.Add((New-Finding -Id 'ADC-034' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "LAPS schema ($($lapsDeployment.lapsVersion)) is present but NO computer objects have LAPS expiry time populated — LAPS is not actively managing any local Administrator passwords. Verify the LAPS GPO/policy is deployed and that the LAPS CSE (v1) or Windows LAPS client-side extension (v2) is installed on target machines. Schema presence alone does not protect endpoints." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-035: RC4 Kerberos encryption still allowed at domain level
    if ($kerberosEnc.rc4Allowed) {
        $findings.Add((New-Finding -Id 'ADC-035' -Severity 'Medium' `
            -Technique 'T1558.003' `
            -Description "RC4 Kerberos encryption is allowed at the domain level (msDS-SupportedEncryptionTypes = $($kerberosEnc.encryptionTypes); value 0 = OS default which includes RC4). RC4 TGS tickets for Kerberoastable service accounts can be cracked offline far faster than AES128/256 equivalents. Enforce AES-only: set msDS-SupportedEncryptionTypes to 24 (0x18 = AES128+AES256) on the domain object and all service accounts with SPNs. Verify all services support AES before enforcing to prevent auth breakage." `
            -Reference 'https://attack.mitre.org/techniques/T1558/003/'))
    }

    # ADC-036: Built-in Guest account enabled
    if ($builtinAccts.guestEnabled) {
        $findings.Add((New-Finding -Id 'ADC-036' -Severity 'High' `
            -Technique 'T1078.001' `
            -Description "The built-in domain Guest account is ENABLED. The Guest account has no password requirement by default and can provide unauthenticated or low-friction access to domain resources. It should always be disabled. Disable via: Disable-ADAccount -Identity Guest." `
            -Reference 'https://attack.mitre.org/techniques/T1078/001/'))
    }

    # ADC-037: Built-in Administrator not renamed (and currently enabled)
    if ($builtinAccts.adminNotRenamed -and $builtinAccts.adminEnabled) {
        $findings.Add((New-Finding -Id 'ADC-037' -Severity 'Medium' `
            -Technique 'T1078.002' `
            -Description "The built-in domain Administrator account is ENABLED and still named 'Administrator'. This well-known SID-500 account is targeted in every password-spray campaign. Rename the account (samAccountName) to an obscure value, optionally creating a decoy named 'Administrator' (enabled, complex password, no logon rights, with alerting). Consider restricting interactive logon via Deny logon locally GPO." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-038: Schema Admins non-empty (active members)
    $schemaAdminsActive = @($privGroups['Schema Admins'] | Where-Object { $_.enabled })
    if ($schemaAdminsActive.Count -gt 0) {
        $names = ($schemaAdminsActive | Select-Object -First 5 | ForEach-Object { $_.samAccount }) -join ', '
        $findings.Add((New-Finding -Id 'ADC-038' -Severity 'High' `
            -Technique 'T1098' `
            -Description "Schema Admins has $($schemaAdminsActive.Count) active member(s): $names. Schema Admins should have zero permanent members — add accounts only during schema update operations (e.g., Exchange prep, LAPS extension), then remove immediately. Permanent Schema Admin membership allows unauthorized modification of AD attribute and class definitions, affecting every object in the forest." `
            -Reference 'https://attack.mitre.org/techniques/T1098/'))
    }

    # ADC-039: Entra Connect sync account password age > 365 days
    if ($entraHybrid.hasSyncAccount -and $entraHybrid.syncAccountPwdAgeDays -gt 365) {
        $findings.Add((New-Finding -Id 'ADC-039' -Severity 'High' `
            -Technique 'T1078.002' `
            -Description "Entra Connect sync account '$($entraHybrid.syncAccountName)' password has not been rotated in $($entraHybrid.syncAccountPwdAgeDays) days. This account has broad AD read rights (all objects, attributes including hashes in pass-through hybrid flows) and can be used to enumerate the entire directory. Rotate via Entra Connect configuration wizard — it handles both on-prem and cloud credentials atomically. Target: rotate every 90 days." `
            -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
    }

    # ADC-040: AZUREADSSOACC$ present — static Kerberos key silver ticket risk
    if ($entraHybrid.hasSsoComputer) {
        $findings.Add((New-Finding -Id 'ADC-040' -Severity 'Medium' `
            -Technique 'T1558.002' `
            -Description "Seamless SSO computer account (AZUREADSSOACC\$) is present — hybrid identity with Seamless SSO is active. AZUREADSSOACC\$'s Kerberos key is static and does not auto-rotate. An attacker with DCSync rights can extract this key and forge Kerberos service tickets for any on-premises identity to Microsoft Online Services, bypassing MFA. Remediate: rotate the AZUREADSSOACC\$ Kerberos key every 30 days via the Seamless SSO PowerShell refresh script (Update-AzureADSSOForest)." `
            -Reference 'https://attack.mitre.org/techniques/T1558/002/'))
    }

    # ADC-041: RODC Password Replication Policy — sensitive groups in reveal set
    if ($rodcPRP.Count -gt 0) {
        $preview = ($rodcPRP | Select-Object -First 3 | ForEach-Object {
            "$($_.rodcCN): $($_.sensitiveGroupsInReveal -join '; ')"
        }) -join ' | '
        $findings.Add((New-Finding -Id 'ADC-041' -Severity 'High' `
            -Technique 'T1552.004' `
            -Description "$($rodcPRP.Count) RODC(s) have Tier 0 security groups in their Password Replication Policy allowed-reveal set: $preview. If the RODC is compromised, its cached passwords include all accounts in the reveal set — effectively granting domain compromise via the RODC. Remove all Tier 0 groups from msDS-RevealOnDemandGroup and add them to msDS-NeverRevealGroup on each affected RODC." `
            -Reference 'https://attack.mitre.org/techniques/T1552/004/'))
    }

    # ADC-042: Exchange Windows Permissions WriteDACL on domain root (DCSync path)
    if ($exchangeDACL.exchangeWriteDacl) {
        $findings.Add((New-Finding -Id 'ADC-042' -Severity 'High' `
            -Technique 'T1222.001' `
            -Description "EXCHANGE WINDOWS PERMISSIONS ($($exchangeDACL.exchangeGroupDn)) has WriteDACL on the domain root object. Any member of this Exchange group can add DCSync rights (Replicating Directory Changes All) to any account on the domain root DACL — a well-documented path from Exchange Server compromise to full domain credential theft. Remediate via Microsoft Exchange Health Checker DACL remediation script or remove the WriteDACL ACE manually using ADSIEdit/Set-Acl." `
            -Reference 'https://attack.mitre.org/techniques/T1222/001/'))
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
                totalUsers                   = $accounts.totalUsers
                enabledUsers                 = $accounts.enabledUsers
                staleUsers                   = $accounts.staleUsers
                kerberoastableCount          = $accounts.kerberoastable.Count
                asrepRoastableCount          = $accounts.asrepRoastable.Count
                desOnlyCount                 = $accounts.desOnly.Count
                unconstrainedDelegationCount = $accounts.unconstrainedDelegation.Count
                rbcdCount                    = $accounts.rbcd.Count
                adminSdHolderCount           = $accounts.adminSdHolder.Count
                passwdNotRequiredCount       = $accounts.passwdNotRequired.Count
                reversibleEncryptionCount    = $accounts.reversibleEncryption.Count
                sidHistoryCount              = $accounts.sidHistoryAccounts.Count
                shadowCredentialCount        = $shadowCreds.Count
                secretsInAttrsCount          = $secretsInAttrs.Count
                constrainedDelegationCount   = $constrainedDelegation.Count
                gmsaCount                    = $gmsaRights.Count
                fgppCount                    = $fgppList.Count
                staleDCCount                 = $staleDCs.Count
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

    # Delegation record (unconstrained + RBCD + constrained)
    if ($accounts.unconstrainedDelegation.Count -gt 0 -or $accounts.rbcd.Count -gt 0 -or $constrainedDelegation.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'delegation' `
            -StableId       "ADCore:delegation:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain                  = $domainFQDN
                unconstrainedNonDC      = $accounts.unconstrainedDelegation.ToArray()
                rbcdObjects             = $accounts.rbcd.ToArray()
                constrainedDelegation   = $constrainedDelegation.ToArray()
            } `
            -RunId $runId))
    }

    # Shadow credentials record
    if ($shadowCreds.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'shadow-credentials' `
            -StableId       "ADCore:shadow-creds:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain   = $domainFQDN
                accounts = $shadowCreds.ToArray()
                total    = $shadowCreds.Count
            } `
            -RunId $runId))
    }

    # AdminSDHolder DACL snapshot (config record — diff engine tracks ACE changes across runs)
    if ($adminSdHolder.dn) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'adminsdholder-dacl' `
            -StableId       "ADCore:adminsdholder:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain          = $domainFQDN
                dn              = $adminSdHolder.dn
                totalAces       = $adminSdHolder.totalAces
                suspectAceCount = $adminSdHolder.suspectAceCount
                suspectAces     = $adminSdHolder.suspectAces
                allAces         = $adminSdHolder.aces
            } `
            -RunId $runId))
    }

    # gMSA record
    if ($gmsaRights.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'gmsa-rights' `
            -StableId       "ADCore:gmsa:$domainFQDN" `
            -Category       'config' `
            -Tier           'T1' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain   = $domainFQDN
                accounts = $gmsaRights.ToArray()
                total    = $gmsaRights.Count
            } `
            -RunId $runId))
    }

    # Stale DC computer objects record
    if ($staleDCs.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'stale-dcs' `
            -StableId       "ADCore:stale-dcs:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain   = $domainFQDN
                staleDCs = $staleDCs.ToArray()
                total    = $staleDCs.Count
            } `
            -RunId $runId))
    }

    # UAC hygiene accounts (passwd-not-required, reversible encryption, sIDHistory)
    $uacHygieneData = @{
        domain               = $domainFQDN
        passwdNotRequired    = $accounts.passwdNotRequired.ToArray()
        reversibleEncryption = $accounts.reversibleEncryption.ToArray()
        sidHistoryAccounts   = $accounts.sidHistoryAccounts.ToArray()
        secretsInAttributes  = $secretsInAttrs.ToArray()
        lapsReadRights       = $lapsReadRights.ToArray()
    }
    $hasUacIssues = $accounts.passwdNotRequired.Count -gt 0 -or
                    $accounts.reversibleEncryption.Count -gt 0 -or
                    $accounts.sidHistoryAccounts.Count -gt 0 -or
                    $secretsInAttrs.Count -gt 0 -or
                    $lapsReadRights.Count -gt 0
    if ($hasUacIssues) {
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'account-hygiene' `
            -StableId       "ADCore:account-hygiene:$domainFQDN" `
            -Category       'config' `
            -Tier           'T1' `
            -CollectedAtPriv $false `
            -Attributes     $uacHygieneData `
            -RunId $runId))
    }

    # ── ESC14: altSecurityIdentities weak certificate mapping ─────────────────
    Write-Host "         [AD-Core] Checking altSecurityIdentities (ESC14)..."
    $altSecIds = _ADC_CollectAltSecurityIdentities -DomainDn $domainDn
    if ($altSecIds.Count -gt 0) {
        $enabledWeak = @($altSecIds | Where-Object { $_.enabled })
        if ($enabledWeak.Count -gt 0) {
            $sample = ($enabledWeak | Select-Object -First 3 | ForEach-Object { $_.cn }) -join ', '
            if ($enabledWeak.Count -gt 3) { $sample += " (and $($enabledWeak.Count - 3) more)" }
            $findings.Add((New-Finding `
                -Id          'ADC-024' `
                -Severity    'High' `
                -Technique   'T1649' `
                -Description "$($enabledWeak.Count) enabled account(s) have altSecurityIdentities with weak certificate mapping forms (ESC14): $sample. Weak forms X509RFC822 (email) and X509IssuerSubject (issuer+subject) are attacker-controllable — a certificate matching these values authenticates as the target account. Action: convert to strong mapping forms (X509SKI, X509PublicKey, Kerberos) or remove unused altSecurityIdentities attributes." `
                -Reference   'https://attack.mitre.org/techniques/T1649/'))
        }
        $records.Add((New-ReconRecord `
            -Collector      'AD-Core' `
            -ObjectType     'alt-security-identities' `
            -StableId       "ADCore:alt-security-identities:$domainFQDN" `
            -Category       'config' `
            -Tier           'T1' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain          = $domainFQDN
                totalAffected   = $altSecIds.Count
                enabledAffected = $enabledWeak.Count
                accounts        = $altSecIds
            } `
            -RunId $runId))
    }

    # ── Sprint 4: Adjacent infrastructure role presence ───────────────────────
    # Emitted as review-required records — not findings. These roles are out of
    # scope for automated assessment; the record flags their presence so a
    # post-run manual review can address them.
    Write-Host "         [AD-Core] Adjacent infrastructure role detection..."
    $rolePresence = _ADC_CollectRolePresence -DomainDn $domainDn -ConfigDn $configDn
    foreach ($role in $rolePresence) {
        $records.Add((New-ReviewRequired `
            -Collector 'AD-Core' `
            -Id     "ADCore:role:$($role.name):$domainFQDN" `
            -Topic  "$($role.name) detected in $($role.category) scope" `
            -Reason $role.reason `
            -RunId  $runId))
    }

    # Emit a role-presence record regardless (so the diff engine and report can
    # show what roles were seen even when none require review)
    $records.Add((New-ReconRecord `
        -Collector      'AD-Core' `
        -ObjectType     'adjacent-roles' `
        -StableId       "ADCore:adjacent-roles:$domainFQDN" `
        -Category       'config' `
        -Tier           'T0' `
        -CollectedAtPriv $false `
        -Attributes     @{
            domain  = $domainFQDN
            detected= $rolePresence.ToArray()
            count   = $rolePresence.Count
        } `
        -RunId $runId))

    return $records
}

Register-Collector `
    -Name        'AD-Core' `
    -Description 'Core AD: domain/forest metadata, Kerberos (krbtgt, roasting, delegation, constrained/RBCD, RC4 enc level), shadow credentials, AdminSDHolder DACL, gMSA rights, LAPS read rights + deployment, account hygiene (sIDHistory, PASSWD_NOTREQD, reversible encryption, secrets-in-attrs, builtin Guest/Admin), privileged groups (Schema Admins non-empty), DCSync rights, password policy, trusts, fine-grained PSOs, stale DCs, pre-Win2k group, anonymous LDAP, Protected Users gaps, ghost accounts, DONT_EXPIRE_PASSWORD, forest functional level, tombstone lifetime, Entra hybrid (sync acct, AZUREADSSOACC$), RODC PRP, Exchange WriteDACL' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _ADCore_Collect @PSBoundParameters }
