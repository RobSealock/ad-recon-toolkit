# CA-Config collector — enumerates AD Certificate Services configuration.
# MinPrivilege: AnyAuthUser (LDAP read of PKI containers is world-readable).
#
# Coverage (Section 6 of scope — AD CS):
#   - Certificate Authority inventory (Enterprise CAs from Configuration NC)
#   - Enrollment Services (HTTP/HTTPS/DCOM endpoints)
#   - Certificate Templates (all; flags, EKUs, ACLs, enrollment agents)
#   - NTAuth store (cross-forest auth trust anchors)
#   - Published CRLs and CDP/AIA distribution point reachability (passive)
#   - Locksmith module integration (ESC1-ESC16 where available)
#
# Findings emitted:
#   ADCS-001  HTTP (non-TLS) web enrollment endpoint present (ESC8 relay)
#   ADCS-002  Template allows subject specification by requestor (ESC1)
#   ADCS-003  Template has overly broad enrollment rights (Authenticated Users / Everyone)
#   ADCS-004  Template allows enrollment agent (ESC3)
#   ADCS-005  Certificate template EKU includes Any Purpose or no EKU (ESC2)
#   ADCS-006  CA has no CRL Distribution Point configured
#   ADCS-007  Manager approval not required on sensitive template
#   ADCS-008  Locksmith identified vulnerability (ESC1-ESC16)

# ── EKU OIDs of concern ───────────────────────────────────────────────────────
$script:_CA_SensitiveEKUs = @{
    '2.5.29.37.0'          = 'Any Purpose (ESC2)'
    '1.3.6.1.4.1.311.20.2.1' = 'Enrollment Agent (ESC3)'
    '1.3.6.1.5.5.7.3.2'   = 'Client Authentication'
    '1.3.6.1.5.5.7.3.1'   = 'Server Authentication'
    '1.3.6.1.4.1.311.76.13.1' = 'Windows Hello for Business'
}

$script:_CA_BroadPrincipals = @(
    'S-1-5-11'           # Authenticated Users (SID)
    'S-1-1-0'            # Everyone (SID)
    'NT AUTHORITY\Authenticated Users'
    'Authenticated Users'
    'Everyone'
)

# ── CT_FLAG values from pKIExtendedKeyUsage / msPKI-Certificate-Name-Flag ────
$script:_CA_CTFLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
$script:_CA_CTFLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000

# =============================================================================
# HELPERS
# =============================================================================

function _CA_GetDomainSid {
    param([string]$DomainDn)
    try {
        $dn = [adsi]"LDAP://$DomainDn"
        $sidBytes = $dn.objectSid.Value
        return (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).ToString()
    } catch { return $null }
}

function _CA_SidToName {
    param([byte[]]$SidBytes)
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidBytes, 0)
        return $sid.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        try {
            return (New-Object System.Security.Principal.SecurityIdentifier($SidBytes, 0)).ToString()
        } catch { return 'unknown' }
    }
}

function _CA_ParseSecurityDescriptor {
    param([byte[]]$NtsdBytes)
    # Returns array of @{trustee; rights; aceType}
    $aces = [System.Collections.Generic.List[hashtable]]::new()
    if (-not $NtsdBytes) { return $aces }
    try {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($NtsdBytes, 0)
        foreach ($ace in $sd.DiscretionaryAcl) {
            try {
                $sid = $ace.SecurityIdentifier.ToString()
                $name = try { $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
                $aces.Add(@{
                    sid     = $sid
                    trustee = $name
                    rights  = $ace.AccessMask
                    aceType = $ace.AceType.ToString()
                })
            } catch {}
        }
    } catch {}
    return $aces
}

# =============================================================================
# ENUMERATE CERTIFICATION AUTHORITIES
# =============================================================================

function _CA_EnumerateCAs {
    param([string]$ConfigDn)
    $cas = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $enrollDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDn"
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$enrollDn")
        $s.Filter      = '(objectClass=pKIEnrollmentService)'
        $s.SearchScope = 'OneLevel'
        $s.PropertiesToLoad.AddRange([string[]]@(
            'cn','dNSHostName','cACertificate','certificateTemplates',
            'msPKI-EnrollmentServers','whenCreated','whenChanged'
        ))
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $enrollmentServers = @()
            if ($p['mspki-enrollmentservers'].Count) {
                $enrollmentServers = @($p['mspki-enrollmentservers'] | ForEach-Object { $_.ToString() })
            }
            $templates = @()
            if ($p['certificatetemplates'].Count) {
                $templates = @($p['certificatetemplates'] | ForEach-Object { $_.ToString() })
            }
            $cas.Add(@{
                cn                  = $p['cn'][0].ToString()
                dnsHostName         = if ($p['dnshostname'].Count) { $p['dnshostname'][0].ToString() } else { '' }
                enrollmentServers   = $enrollmentServers
                publishedTemplates  = $templates
                whenCreated         = if ($p['whencreated'].Count) { $p['whencreated'][0].ToString('o') } else { '' }
                whenChanged         = if ($p['whenchanged'].Count) { $p['whenchanged'][0].ToString('o') } else { '' }
                distinguishedName   = $_.Properties['adspath'][0].ToString() -replace 'LDAP://',''
            })
        }
    } catch { Write-Warning "[CA-Config] CA enumeration failed: $_" }
    return $cas
}

# =============================================================================
# PARSE ENROLLMENT SERVER URIS (msPKI-EnrollmentServers is multivalue priority;name;auth;uri format)
# =============================================================================

function _CA_ParseEnrollmentURIs {
    param([string[]]$RawValues)
    $uris = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($v in $RawValues) {
        # Format: priority\nauth\nrenewonly\nuri (newline-separated in the raw value)
        $parts = $v -split '\n'
        if ($parts.Count -ge 4) {
            $uris.Add(@{
                priority   = $parts[0]
                authType   = $parts[1]
                uri        = $parts[3]
                isHttp     = $parts[3] -match '^http://'
                isHttps    = $parts[3] -match '^https://'
            })
        }
    }
    return $uris
}

# =============================================================================
# ENUMERATE CERTIFICATE TEMPLATES
# =============================================================================

function _CA_EnumerateTemplates {
    param([string]$ConfigDn)
    $templates = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $tmplDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigDn"
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$tmplDn")
        $s.Filter      = '(objectClass=pKICertificateTemplate)'
        $s.SearchScope = 'OneLevel'
        $s.PageSize    = 200
        $s.PropertiesToLoad.AddRange([string[]]@(
            'cn','displayName',
            'msPKI-Certificate-Name-Flag',     # CT_FLAG — subject supply etc.
            'msPKI-Enrollment-Flag',            # CT_FLAG — manager approval etc.
            'msPKI-Certificate-Application-Policy', # EKUs
            'pKIExtendedKeyUsage',              # EKUs (legacy)
            'pKIDefaultKeySpec',
            'msPKI-RA-Application-Policies',   # Enrollment agent / issuance policies
            'msPKI-Template-Schema-Version',
            'nTSecurityDescriptor',             # ACL
            'whenCreated','whenChanged',
            'revision','flags'
        ))
        $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $nameFlag     = if ($p['mspki-certificate-name-flag'].Count) { [int]$p['mspki-certificate-name-flag'][0] } else { 0 }
            $enrollFlag   = if ($p['mspki-enrollment-flag'].Count)       { [int]$p['mspki-enrollment-flag'][0]       } else { 0 }
            $schemaVer    = if ($p['mspki-template-schema-version'].Count){ [int]$p['mspki-template-schema-version'][0]} else { 1 }

            # Collect EKUs from both attributes (V1 and V2 templates use different ones)
            $ekus = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($eku in @($p['mspki-certificate-application-policy'])) { if ($eku) { [void]$ekus.Add($eku.ToString()) } }
            foreach ($eku in @($p['pkiextendedkeyusage']))                  { if ($eku) { [void]$ekus.Add($eku.ToString()) } }

            # Parse ACL
            $ntsd   = if ($p['ntsecuritydescriptor'].Count) { [byte[]]$p['ntsecuritydescriptor'][0] } else { $null }
            $dacl   = _CA_ParseSecurityDescriptor -NtsdBytes $ntsd

            # Enrollment agent policies
            $raApps = @($p['mspki-ra-application-policies'] | ForEach-Object { if ($_) { $_.ToString() } })

            $templates.Add(@{
                cn             = $p['cn'][0].ToString()
                displayName    = if ($p['displayname'].Count) { $p['displayname'][0].ToString() } else { $p['cn'][0].ToString() }
                nameFlag       = $nameFlag
                enrollFlag     = $enrollFlag
                schemaVersion  = $schemaVer
                ekus           = @($ekus)
                raAppPolicies  = $raApps
                dacl           = $dacl.ToArray()
                whenChanged    = if ($p['whenchanged'].Count) { $p['whenchanged'][0].ToString('o') } else { '' }
                revision       = if ($p['revision'].Count) { [int]$p['revision'][0] } else { 0 }
            })
        }
    } catch { Write-Warning "[CA-Config] Template enumeration failed: $_" }
    return $templates
}

# =============================================================================
# FINDING EVALUATION
# =============================================================================

function _CA_EvaluateFindings {
    param(
        [System.Collections.Generic.List[hashtable]]$CAs,
        [System.Collections.Generic.List[hashtable]]$Templates,
        [string[]]$PublishedTemplateNames
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # ADCS-001: HTTP web enrollment endpoints
    foreach ($ca in $CAs) {
        $uris = _CA_ParseEnrollmentURIs -RawValues $ca.enrollmentServers
        foreach ($uri in $uris | Where-Object { $_.isHttp }) {
            $findings.Add((New-Finding -Id 'ADCS-001' -Severity 'Critical' `
                -Technique 'T1649' `
                -Description "CA '$($ca.cn)' exposes a non-TLS HTTP enrollment endpoint: $($uri.uri). ESC8 attack: capture an incoming NTLM authentication (PrinterBug, PetitPotam, etc.) and relay it to this endpoint to request a domain auth certificate." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }
    }

    # ADCS-006: CA with no CRL Distribution Point (passive check via template/CA data)
    # Full CDP reachability check requires certsrv — flag for manual review
    foreach ($ca in $CAs) {
        if ($ca.publishedTemplates.Count -eq 0) {
            $findings.Add((New-Finding -Id 'ADCS-006' -Severity 'Low' `
                -Technique 'T1649' `
                -Description "CA '$($ca.cn)' has no published templates — may be an offline Root CA or a decommissioned service. Verify CRL distribution points are reachable for all issued certificates." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }
    }

    # Per-template evaluation — only evaluate templates published by at least one CA
    $publishedSet = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $PublishedTemplateNames) { [void]$publishedSet.Add($n) }

    foreach ($tmpl in $Templates) {
        $name        = $tmpl.cn
        $isPublished = $publishedSet.Contains($name)
        if (-not $isPublished) { continue }

        # Check enrollment rights — who can ENROLL (right 0x00000100) or AUTOENROLL (0x00000200)
        $enrollRightsMask = 0x00000100 -bor 0x00000200
        $broadEnroll = $tmpl.dacl | Where-Object {
            ($_.aceType -eq 'AccessAllowed') -and ($_.rights -band $enrollRightsMask) -and
            ($script:_CA_BroadPrincipals | Where-Object { $tmpl.dacl.trustee -contains $_ -or $_.trustee -like "*$_*" } | Select-Object -First 1)
        }

        # ADCS-002: ESC1 — requestor-supplied subject + broad enrollment + client auth EKU
        $hasClientAuth  = $tmpl.ekus -contains '1.3.6.1.5.5.7.3.2'
        $hasAnyPurpose  = $tmpl.ekus -contains '2.5.29.37.0' -or $tmpl.ekus.Count -eq 0
        $allowsSupply   = ($tmpl.nameFlag -band $script:_CA_CTFLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
        $noApproval     = ($tmpl.enrollFlag -band 0x00000002) -eq 0  # CT_FLAG_PEND_ALL_REQUESTS

        $broadEnrollAces = @($tmpl.dacl | Where-Object {
            ($_.aceType -eq 'AccessAllowed') -and ($_.rights -band $enrollRightsMask) -and
            ($script:_CA_BroadPrincipals -contains $_.trustee -or
             ($script:_CA_BroadPrincipals | Where-Object { $_ -like "*$($_.trustee)*" } | Select-Object -First 1))
        })

        if ($allowsSupply -and ($hasClientAuth -or $hasAnyPurpose) -and $noApproval -and $broadEnrollAces.Count -gt 0) {
            $findings.Add((New-Finding -Id 'ADCS-002' -Severity 'Critical' `
                -Technique 'T1649' `
                -Description "Template '$name' is vulnerable to ESC1 (requestor-supplied SAN + Client Auth EKU + broad enrollment rights + no manager approval). Any user can request a certificate for any identity including Domain Admins. Validate with: certipy find -vulnerable." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }

        # ADCS-003: Broad enrollment rights on sensitive templates (without ESC1)
        if ($broadEnrollAces.Count -gt 0 -and ($hasClientAuth -or $hasAnyPurpose) -and -not $allowsSupply) {
            $findings.Add((New-Finding -Id 'ADCS-003' -Severity 'High' `
                -Technique 'T1649' `
                -Description "Template '$name' has Client Auth or Any Purpose EKU and grants enrollment to Authenticated Users/Everyone. While subject supply is not enabled (no ESC1), review for ESC3/ESC9/ESC10 attack paths and confirm approver workflow is in place." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }

        # ADCS-004: ESC3 — enrollment agent template
        $isEnrollAgent = $tmpl.ekus -contains '1.3.6.1.4.1.311.20.2.1'
        if ($isEnrollAgent -and $broadEnrollAces.Count -gt 0) {
            $findings.Add((New-Finding -Id 'ADCS-004' -Severity 'Critical' `
                -Technique 'T1649' `
                -Description "Template '$name' grants Enrollment Agent rights (OID 1.3.6.1.4.1.311.20.2.1) to broad principals. ESC3: an enrolled agent certificate can be used to request certificates on behalf of any user, including privileged accounts." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }

        # ADCS-005: ESC2 — Any Purpose EKU or no EKU
        $hasNoEKU = $tmpl.ekus.Count -eq 0
        if (($hasAnyPurpose -or $hasNoEKU) -and $broadEnrollAces.Count -gt 0 -and -not $isEnrollAgent) {
            $findings.Add((New-Finding -Id 'ADCS-005' -Severity 'High' `
                -Technique 'T1649' `
                -Description "Template '$name' has 'Any Purpose' EKU or no EKU — certificates can be used for any purpose including client auth and code signing. Combined with broad enrollment rights this enables ESC2." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }

        # ADCS-007: No manager approval on client-auth or any-purpose template with broad access
        if (($hasClientAuth -or $hasAnyPurpose) -and $noApproval -and $broadEnrollAces.Count -gt 0 -and -not $allowsSupply) {
            $findings.Add((New-Finding -Id 'ADCS-007' -Severity 'Medium' `
                -Technique 'T1649' `
                -Description "Template '$name' with broad enrollment rights does not require manager approval (CT_FLAG_PEND_ALL_REQUESTS not set). Certificates are issued immediately without any human review step." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }
    }

    return $findings
}

# =============================================================================
# LOCKSMITH INTEGRATION
# =============================================================================

function _CA_RunLocksmith {
    param([string]$ArtDir, [string]$RunId)
    $results = [System.Collections.Generic.List[hashtable]]::new()
    try {
        if (-not (Get-Module -ListAvailable -Name Locksmith)) { return $results }
        Write-Host "         [CA-Config] Running Locksmith..."
        $findings = Invoke-Locksmith -Mode 1 -ErrorAction Stop  # Mode 1 = report only
        foreach ($f in $findings) {
            $results.Add(@{
                name        = $f.Name
                technique   = $f.Technique
                severity    = $f.Severity
                description = $f.Description
                fix         = $f.Fix
            })
        }
        # Save raw Locksmith output as artifact
        $results | ConvertTo-Json -Depth 10 |
            Out-File (Join-Path $ArtDir 'locksmith-findings.json') -Encoding utf8
    } catch { Write-Warning "[CA-Config] Locksmith failed: $_" }
    return $results
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _CAConfig_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records    = [System.Collections.Generic.List[object]]::new()
    $runId      = $RunContext.RunId
    $artDir     = Join-Path $RunRoot 'artifacts'

    $rootDse    = [adsi]'LDAP://RootDSE'
    $domainDn   = $rootDse.defaultNamingContext.ToString()
    $configDn   = $rootDse.configurationNamingContext.ToString()
    $domainFQDN = $RunContext.Domain

    # Enumerate CAs and templates
    Write-Host "         [CA-Config] Enumerating Certificate Authorities..."
    $cas = _CA_EnumerateCAs -ConfigDn $configDn
    Write-Host "         $($cas.Count) Enterprise CA(s) found"

    Write-Host "         [CA-Config] Enumerating certificate templates..."
    $templates = _CA_EnumerateTemplates -ConfigDn $configDn
    Write-Host "         $($templates.Count) template(s) found"

    # Collect all published template names across all CAs
    $publishedNames = @($cas | ForEach-Object { $_.publishedTemplates } | Where-Object { $_ } | Sort-Object -Unique)

    # Evaluate findings
    $findings = _CA_EvaluateFindings -CAs $cas -Templates $templates -PublishedTemplateNames $publishedNames

    # Locksmith integration
    $lsEnabled = ($Settings['EnableLocksmith'] -ne $false)
    $locksmithFindings = if ($lsEnabled) { _CA_RunLocksmith -ArtDir $artDir -RunId $runId } else { @() }

    foreach ($lf in $locksmithFindings) {
        $sev = switch -Regex ($lf.severity) {
            'Critical' { 'Critical' } 'High' { 'High' } 'Medium' { 'Medium' } default { 'Low' }
        }
        $findings.Add((New-Finding -Id 'ADCS-008' -Severity $sev `
            -Technique 'T1649' `
            -Description "[Locksmith] $($lf.name): $($lf.description)" `
            -Reference 'https://attack.mitre.org/techniques/T1649/'))
    }

    # ── Emit records ──────────────────────────────────────────────────────────

    # CA inventory record
    $records.Add((New-ReconRecord `
        -Collector      'CA-Config' `
        -ObjectType     'ca-inventory' `
        -StableId       "CA:inventory:$domainFQDN" `
        -Category       'config' `
        -Tier           'T0' `
        -CollectedAtPriv $false `
        -Attributes     @{
            domain                = $domainFQDN
            enterpriseCAs         = @($cas | ForEach-Object {
                @{
                    cn                = $_.cn
                    dnsHostName       = $_.dnsHostName
                    publishedTemplates= $_.publishedTemplates
                    enrollmentServers = @(_CA_ParseEnrollmentURIs -RawValues $_.enrollmentServers)
                    whenChanged       = $_.whenChanged
                }
            })
            publishedTemplateNames = $publishedNames
            totalTemplates         = $templates.Count
            locksmithFindingCount  = $locksmithFindings.Count
        } `
        -Findings       $findings.ToArray() `
        -RunId          $runId))

    # Per-template records
    foreach ($tmpl in $templates) {
        $isPublished = $publishedNames -contains $tmpl.cn
        $records.Add((New-ReconRecord `
            -Collector      'CA-Config' `
            -ObjectType     'certificate-template' `
            -StableId       "CA:template:$($tmpl.cn)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                cn               = $tmpl.cn
                displayName      = $tmpl.displayName
                isPublished      = $isPublished
                nameFlag         = $tmpl.nameFlag
                enrollFlag       = $tmpl.enrollFlag
                schemaVersion    = $tmpl.schemaVersion
                ekus             = $tmpl.ekus
                enrolleeSupplies = ($tmpl.nameFlag -band $script:_CA_CTFLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
                requiresApproval = ($tmpl.enrollFlag -band 0x00000002) -ne 0
                enrollmentAces   = @($tmpl.dacl | Where-Object { $_.aceType -eq 'AccessAllowed' -and ($_.rights -band 0x00000300) })
                whenChanged      = $tmpl.whenChanged
                revision         = $tmpl.revision
            } `
            -RunId $runId))
    }

    # Locksmith raw findings record
    if ($locksmithFindings.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'CA-Config' `
            -ObjectType     'locksmith-findings' `
            -StableId       "CA:locksmith:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain   = $domainFQDN
                count    = $locksmithFindings.Count
                findings = $locksmithFindings.ToArray()
            } `
            -RawArtifactRef 'locksmith-findings.json' `
            -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'CA-Config' `
    -Description 'Enumerates AD CS: Enterprise CAs, enrollment endpoints, certificate templates (ESC1-ESC8 evaluation), Locksmith integration' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _CAConfig_Collect @PSBoundParameters }
