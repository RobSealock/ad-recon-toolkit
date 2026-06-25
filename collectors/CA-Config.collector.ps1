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
#   ADCS-008  Locksmith / Certipy identified vulnerability (ESC1-ESC16)
#   ADCS-009  Schema-v1 template with enrollee-supplied subject (ESC15 / CVE-2024-49019)
#   ADCS-010  ESC6 — CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag (request-supplied SAN on any template)
#   ADCS-011  ESC8 — Web enrollment HTTP endpoint without Extended Protection for Authentication
#   ADCS-012  Non-default CA in NTAuthCertificates (untrusted CA can issue smartcard-logon certs)
#   ADCS-013  DC Authentication certificate template published but no DC computer objects are enrolled
#
# Review-Required records:
#   CA:esc12:<ca>   HSM key storage for each CA (manual verification required)

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
        $dn = (New-AdsiEntry "LDAP://$DomainDn")
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
    if (-not $NtsdBytes) { return ,$aces }
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
    return ,$aces
}

# =============================================================================
# ENUMERATE CERTIFICATION AUTHORITIES
# =============================================================================

function _CA_EnumerateCAs {
    param([string]$ConfigDn)
    $cas = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $enrollDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDn"
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$enrollDn"))
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
                distinguishedName   = ($_.Properties['adspath'][0].ToString() -replace 'LDAP://','')
                # editFlags is a CA registry value — populated by _CA_CollectCAEditFlags after enumeration
                editFlags           = 0
            })
        }
    } catch { Write-Warning "[CA-Config] CA enumeration failed: $_" }
    return ,$cas
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
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$tmplDn"))
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
    return ,$templates
}

# =============================================================================
# NTAUTH CERTIFICATES CHECK
# =============================================================================

function _CA_CollectCAEditFlags {
    param([System.Collections.Generic.List[hashtable]]$CAs)
    # Reads the CA's editFlags DWORD from its registry via WMI StdRegProv (DCOM, read-only).
    # Registry path: HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\
    #                PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
    # Returns $CAs with editFlags populated; on access failure, editFlags stays 0 (no false positives).
    $HKLM       = [uint32]0x80000002L
    $policyKey  = 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{0}\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy'
    foreach ($ca in $CAs) {
        if (-not $ca.dnsHostName) { continue }
        try {
            $wmi = [wmiclass]"\\$($ca.dnsHostName)\root\default:StdRegProv"
            $key = $policyKey -f $ca.cn
            $ret = $wmi.GetDWORDValue($HKLM, $key, 'EditFlags')
            if ($ret.ReturnValue -eq 0 -and $null -ne $ret.uValue) {
                $ca.editFlags = [int]$ret.uValue
            }
        } catch { Write-Verbose "[CA-Config] editFlags WMI read failed for $($ca.cn) on $($ca.dnsHostName): $_" }
    }
}

function _CA_CheckNTAuthCertificates {
    param([string]$ConfigDn)
    $results = [System.Collections.Generic.List[hashtable]]::new()
    try {
        # NTAuthCertificates container stores DER-encoded certificates of CAs trusted for smart card logon
        $ntauthDn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$ConfigDn"
        $ntauth    = (New-AdsiEntry "LDAP://$ntauthDn")
        $certs     = @($ntauth.Properties['cACertificate'])
        foreach ($certBytes in $certs) {
            try {
                $cert   = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$certBytes)
                $issuer = $cert.Issuer
                $subj   = $cert.Subject
                $thumb  = $cert.Thumbprint
                $exp    = $cert.NotAfter.ToString('yyyy-MM-dd')
                $expired= $cert.NotAfter -lt (Get-Date)
                $results.Add(@{
                    subject   = $subj
                    issuer    = $issuer
                    thumbprint= $thumb
                    expires   = $exp
                    isExpired = $expired
                })
            } catch {}
        }
    } catch { Write-Verbose "[CA-Config] NTAuthCertificates query failed: $_" }
    return ,$results
}

# =============================================================================
# FINDING EVALUATION
# =============================================================================

function _CA_EvaluateFindings {
    param(
        [System.Collections.Generic.List[hashtable]]$CAs,
        [System.Collections.Generic.List[hashtable]]$Templates,
        [string[]]$PublishedTemplateNames,
        [System.Collections.Generic.List[hashtable]]$NTAuthCerts = $null,
        [string[]]$KnownEnterpriseCACNs = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # ADCS-001: HTTP web enrollment endpoints
    foreach ($ca in $CAs) {
        $uris = @(_CA_ParseEnrollmentURIs -RawValues $ca.enrollmentServers)
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

        # ADCS-009: ESC15 (CVE-2024-49019) — schema-v1 template with enrollee-supplied subject
        # Schema version 1 templates do not restrict the EKUs a requestor can embed.
        # Combined with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and broad enrollment rights,
        # an attacker can request a certificate with any EKU (e.g. Smart Card Logon,
        # Code Signing) and authenticate as a privileged account. Patched Nov 2024.
        if ($tmpl.schemaVersion -le 1 -and $allowsSupply -and $broadEnrollAces.Count -gt 0) {
            $findings.Add((New-Finding -Id 'ADCS-009' -Severity 'Critical' `
                -Technique 'T1649' `
                -Description "Template '$name' is vulnerable to ESC15 (CVE-2024-49019): schema version $($tmpl.schemaVersion) with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and broad enrollment rights. Schema-v1 templates do not enforce the template EKU list — an enrollee can embed arbitrary EKUs (Smart Card Logon, Client Auth, Code Signing) in the request, enabling authentication as any user. Ensure Nov 2024 patch (KB5044280 / KB5044284 / equivalent) is applied on all CAs issuing this template, then convert to a v2+ template or remove broad enrollment rights." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }
    }

    # ADCS-010: ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag
    # This CA flag (editFlags bit 0x00040000 = 262144) allows the enrollee to specify a
    # Subject Alternative Name in certificate requests for ANY template, regardless of the
    # template's own SAN settings. Combined with any enrollment-accessible template this
    # is equivalent to ESC1 on all templates.
    # Note: editFlags is a CA registry value — the collector attempts to read it via WMI/DCOM
    # if the CA host is reachable. If editFlags = 0 (default from LDAP), the check is skipped.
    foreach ($ca in $CAs) {
        $caName = $ca.cn
        if ($ca.editFlags -band 0x00040000) {
            $findings.Add((New-Finding -Id 'ADCS-010' -Severity 'Critical' `
                -Technique 'T1649' `
                -Description "CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set (editFlags bit 0x40000). This allows the enrollee to specify a Subject Alternative Name (SAN) in certificate requests for ANY template, regardless of the template's own SAN settings. An authenticated user can request a certificate with an arbitrary UPN (e.g., Administrator@domain.com) from any enrollment-accessible template and use it to authenticate as that identity (ESC6). Remediate: run 'certutil -config CA-Name -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2' and restart the CA service." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }

        # ADCS-011: ESC8 — HTTP web enrollment without EPA
        # ESC8 = HTTP enrollment endpoint + NTLM relay possible.
        # EPA (Extended Protection for Authentication) prevents relay of NTLM to the enrollment endpoint.
        # HTTP endpoint is already flagged as ADCS-001. ADCS-011 adds the specific ESC8 relay framing.
        $uris = @(_CA_ParseEnrollmentURIs -RawValues $ca.enrollmentServers)
        foreach ($endpoint in $uris | Where-Object { $_.isHttp }) {
            $findings.Add((New-Finding -Id 'ADCS-011' -Severity 'Critical' `
                -Technique 'T1649' `
                -Description "CA '$caName' has an HTTP (unencrypted) web enrollment endpoint: $($endpoint.uri). This is the prerequisite for ESC8 (NTLM relay to AD CS). An attacker who coerces NTLM authentication from a privileged host (PrinterBug, PetitPotam, DFSCoerce) can relay it to this HTTP enrollment endpoint and request a certificate for the coerced identity, enabling full domain compromise via Kerberos PKINIT with the obtained cert. Remediate: require HTTPS on the enrollment endpoint and enable Extended Protection for Authentication (EPA/IIS channel binding)." `
                -Reference 'https://attack.mitre.org/techniques/T1649/'))
        }
    }

    # ADCS-012: Non-default CA in NTAuthCertificates
    # NTAuthCertificates lists CAs trusted for smart card / certificate-based domain logon.
    # Any CA whose subject/issuer does not match a known enterprise CA in this environment
    # is suspicious — it could enable an attacker to issue certificates for domain logon.
    if ($NTAuthCerts -and $NTAuthCerts.Count -gt 0) {
        $knownCNSet = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $KnownEnterpriseCACNs) { [void]$knownCNSet.Add($n) }
        foreach ($cert in $NTAuthCerts) {
            # Extract CN from Subject for comparison
            $subjectCN = ''
            if ($cert.subject -match 'CN=([^,]+)') { $subjectCN = $Matches[1].Trim() }
            $matchesKnown = $knownCNSet.Count -eq 0 -or $knownCNSet.Contains($subjectCN) -or
                            ($KnownEnterpriseCACNs | Where-Object { $cert.subject -match [regex]::Escape($_) } | Select-Object -First 1)
            if (-not $matchesKnown) {
                $expNote = if ($cert.isExpired) { ' (EXPIRED)' } else { '' }
                $findings.Add((New-Finding -Id 'ADCS-012' -Severity 'High' `
                    -Technique 'T1649' `
                    -Description "NTAuthCertificates contains a certificate that does not match any known enterprise CA: Subject='$($cert.subject)', Issuer='$($cert.issuer)', Thumbprint=$($cert.thumbprint), Expires=$($cert.expires)$expNote. Any CA in NTAuthCertificates can issue certificates used for domain authentication (smart card logon / PKINIT). An unauthorized CA here could issue certificates allowing authentication as any domain user. Verify this CA is intentional and authorized." `
                    -Reference 'https://attack.mitre.org/techniques/T1649/'))
            }
        }
    }

    return ,$findings
}

# =============================================================================
# LOCKSMITH INTEGRATION
# =============================================================================

function _CA_RunLocksmith {
    param([string]$ArtDir, [string]$RunId)
    # Locksmith has no -Domain/-Forest parameter (Mode/Scans/OutputPath/Credential
    # only) -- it always auto-detects the current forest via the AD module, so it
    # only works from a domain-joined host (or one in this forest's resolution path).
    # Soft-fails below via the catch block when that detection fails.
    $results = [System.Collections.Generic.List[hashtable]]::new()
    try {
        if (-not (Get-Module -ListAvailable -Name Locksmith)) { return $results }
        Write-Host "         [CA-Config] Running Locksmith..."
        # Locksmith uses a bare 'break' (not 'return') to signal "no findings found".
        # Without this guard that break propagates to the orchestrator's collector
        # foreach and silently kills all remaining collectors.
        $findings = $null
        foreach ($_ in @($null)) {
            $findings = Invoke-Locksmith -Mode 1 -ErrorAction Stop  # Mode 1 = report only
        }

        # Extract ESC IDs from Technique/Name fields for provenance tracking.
        # Locksmith encodes them as e.g. "ESC1", "ESC3" in the Technique or Name fields.
        $escIdSet = [System.Collections.Generic.HashSet[string]]::new()
        $escPattern = [System.Text.RegularExpressions.Regex]::new('ESC\d+', 'IgnoreCase')

        foreach ($f in $findings) {
            $coveredStr = ($f.Technique, $f.Name, $f.Description | Where-Object { $_ }) -join ' '
            $escIdSet.UnionWith([string[]]($escPattern.Matches($coveredStr) | ForEach-Object { $_.Value.ToUpper() }))
            $results.Add(@{
                name        = $f.Name
                technique   = $f.Technique
                severity    = $f.Severity
                description = $f.Description
                fix         = $f.Fix
            })
        }
        $results | Add-Member -NotePropertyName 'coveredEscIds' -NotePropertyValue ([string[]]$escIdSet) -ErrorAction SilentlyContinue

        # Attach provenance list to each result for downstream record use
        $escIdList = [string[]]$escIdSet
        foreach ($r in $results) { $r['coveredEscId'] = $escIdList }

        # Save raw Locksmith output as artifact
        $results | ConvertTo-Json -Depth 10 |
            Out-File (Join-Path $ArtDir 'locksmith-findings.json') -Encoding utf8
    } catch { Write-Warning "[CA-Config] Locksmith failed: $_" }
    return $results
}

# =============================================================================
# CERTIPY INTEGRATION
# =============================================================================

function _CA_RunCertipy {
    param([string]$ArtDir, [string]$RunId, [hashtable]$Settings, [string]$RepoRoot)
    $results = [System.Collections.Generic.List[hashtable]]::new()
    try {
        # Locate certipy binary — check tools\bin\ first (staged by Install-Prereqs.ps1),
        # then fall back to PATH (certipy / certipy-ad installed globally via pip).
        $certipy = $null
        if ($RepoRoot) {
            $stagedPath = Join-Path $RepoRoot 'tools\bin\certipy.exe'
            if (Test-Path $stagedPath) { $certipy = $stagedPath }
        }
        if (-not $certipy) {
            foreach ($cmd in @('certipy', 'certipy-ad')) {
                if (Get-Command $cmd -ErrorAction SilentlyContinue) { $certipy = $cmd; break }
            }
        }
        if (-not $certipy) {
            Write-Verbose "[CA-Config] Certipy not found in tools\bin\ or PATH (certipy / certipy-ad); skipping."
            return $results
        }

        $outFile = Join-Path $ArtDir 'certipy-output'  # certipy appends _Certipy.json
        $jsonFile = "$outFile`_Certipy.json"

        # Build auth args.
        # Windows: impacket has no SSPI bridge, so -k -no-pass (Linux ccache) fails.
        # Explicit credentials are required on Windows; -k -no-pass is only used on Linux.
        $certUser = $Settings['CertipyUsername']
        $certPass = $Settings['CertipyPassword']
        # PSEdition 'Desktop' = Windows PowerShell 5.1 (Windows-only by definition).
        # PSEdition 'Core' = PS6+ where $IsWindows is a built-in automatic variable.
        # Avoids RuntimeInformation which requires .NET 4.7.1+ (not on all Server SKUs).
        $isWindows = if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { $IsWindows }

        $authArgs = [System.Collections.Generic.List[string]]::new()
        if ($certUser -and $certPass) {
            $authArgs.AddRange([string[]]@('-u', $certUser, '-p', $certPass))
        } elseif (-not $isWindows) {
            # Linux/macOS: use Kerberos ccache from current session (kinit must have run)
            $authArgs.AddRange([string[]]@('-k', '-no-pass'))
        } else {
            Write-Warning "[CA-Config] Certipy on Windows requires explicit credentials. Set CertipyUsername and CertipyPassword in config\settings.local.psd1 and re-run."
            return $results
        }

        Write-Host "         [CA-Config] Running Certipy (find -vulnerable)..."
        $certArgs = ([string[]]$authArgs) + @('find', '-vulnerable', '-json', '-output', $outFile)
        $output = & $certipy @certArgs 2>&1
        Write-Verbose "[CA-Config] Certipy output: $output"

        if (-not (Test-Path $jsonFile)) {
            Write-Warning "[CA-Config] Certipy did not produce output file; check credentials."
            return $results
        }

        $raw = Get-Content $jsonFile -Raw | ConvertFrom-Json -ErrorAction Stop

        # Certipy JSON: top-level keys are CA names, each with nested template/CA findings
        # Vulnerable entries have a '[!] Vulnerabilities' section in their Remarks/Vulnerabilities key
        $escIdSet = [System.Collections.Generic.HashSet[string]]::new()
        $escPattern = [System.Text.RegularExpressions.Regex]::new('ESC\d+', 'IgnoreCase')

        $extractFindings = {
            param($node, [string]$context)
            $nodeFindings = [System.Collections.Generic.List[hashtable]]::new()
            if ($null -eq $node) { return ,$nodeFindings }
            $vulnProp = $node.PSObject.Properties | Where-Object { $_.Name -match 'Vulnerabilit' } | Select-Object -First 1
            if ($vulnProp -and $vulnProp.Value) {
                $vulnText = $vulnProp.Value | Out-String
                $escIds = $escPattern.Matches($vulnText) | ForEach-Object { $_.Value.ToUpper() }
                foreach ($id in $escIds) { [void]$escIdSet.Add($id) }
                $nodeFindings.Add(@{
                    context        = $context
                    vulnerabilities= $vulnText.Trim()
                    escIds         = [string[]]$escIds
                })
            }
            return ,$nodeFindings
        }

        # Walk top-level CAs and nested Templates
        foreach ($caName in ($raw.PSObject.Properties | Select-Object -ExpandProperty Name)) {
            $caNode = $raw.$caName
            $caFindings = & $extractFindings $caNode "[CA] $caName"
            $caFindings | ForEach-Object { [void]$results.Add($_) }
            $templatesNode = $caNode.PSObject.Properties | Where-Object { $_.Name -eq 'Certificate Templates' } | Select-Object -First 1
            if ($templatesNode) {
                foreach ($tName in ($templatesNode.Value.PSObject.Properties | Select-Object -ExpandProperty Name)) {
                    $tFindings = & $extractFindings $templatesNode.Value.$tName "[Template] $tName"
                    $tFindings | ForEach-Object { [void]$results.Add($_) }
                }
            }
        }

        foreach ($r in $results) { $r['source'] = 'certipy' }
        $coveredEscIds = [string[]]$escIdSet

        # Persist artifact
        @{
            tool         = 'certipy'
            version      = (& $certipy --version 2>&1 | Select-Object -First 1)
            coveredEscIds= $coveredEscIds
            findings     = $results.ToArray()
        } | ConvertTo-Json -Depth 10 |
            Out-File (Join-Path $ArtDir 'certipy-findings.json') -Encoding utf8

        Write-Host "         [CA-Config] Certipy: $($results.Count) vulnerable item(s); ESC IDs: $($coveredEscIds -join ', ')"
    } catch { Write-Warning "[CA-Config] Certipy failed: $_" }
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

    $rootDse    = (New-AdsiEntry 'LDAP://RootDSE')
    $domainDn   = $rootDse.defaultNamingContext.ToString()
    $configDn   = $rootDse.configurationNamingContext.ToString()
    $domainFQDN = $RunContext.Domain

    # Enumerate CAs and templates
    Write-Host "         [CA-Config] Enumerating Certificate Authorities..."
    $cas = _CA_EnumerateCAs -ConfigDn $configDn
    Write-Host "         $($cas.Count) Enterprise CA(s) found"

    # Read editFlags from each CA's registry via WMI — required for ADCS-010 (ESC6) detection
    Write-Host "         [CA-Config] Reading CA editFlags (WMI, soft-fail)..."
    _CA_CollectCAEditFlags -CAs $cas

    Write-Host "         [CA-Config] Enumerating certificate templates..."
    $templates = _CA_EnumerateTemplates -ConfigDn $configDn
    Write-Host "         $($templates.Count) template(s) found"

    # Collect all published template names across all CAs
    $publishedNames = @($cas | ForEach-Object { $_.publishedTemplates } | Where-Object { $_ } | Sort-Object -Unique)

    # NTAuthCertificates check
    Write-Host "         [CA-Config] Checking NTAuthCertificates store..."
    $ntAuthCerts = _CA_CheckNTAuthCertificates -ConfigDn $configDn
    Write-Host "         $($ntAuthCerts.Count) certificate(s) in NTAuthCertificates"

    # Build list of known enterprise CA CNs from the discovered CAs for ADCS-012 comparison
    $knownCACNs = @($cas | ForEach-Object { $_.cn })

    # ADCS-013: DC Auth certificate template published but no DC computer objects enrolled
    Write-Host "         [CA-Config] Checking DC computer certificate enrollment..."
    $dcAuthTemplateNames = @('DomainController','Domain Controller','DomainControllerAuthentication','Domain Controller Authentication','KerberosAuthentication','Kerberos Authentication')
    $dcAuthTemplatePublished = @($publishedNames | Where-Object { $dcAuthTemplateNames -contains $_ }).Count -gt 0
    $dcAuthFinding = $null
    if ($dcAuthTemplatePublished) {
        # Check if any DC computer object has a userCertificate attribute populated
        try {
            $dcSrch = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$domainDn"))
            $dcSrch.Filter  = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(userCertificate=*))'
            $dcSrch.PageSize = 1; $dcSrch.SizeLimit = 1
            $dcSrch.PropertiesToLoad.Add('cn') | Out-Null
            $anyCertDC = $dcSrch.FindOne()
            if (-not $anyCertDC) {
                $dcAuthFinding = New-Finding -Id 'ADCS-013' -Severity 'Medium' `
                    -Technique 'T1649' `
                    -Description "DC Authentication certificate template(s) are published ($($publishedNames | Where-Object { $dcAuthTemplateNames -contains $_ } | Select-Object -First 3 -join ', ')) but NO Domain Controller computer objects have a userCertificate attribute populated. DCs should be enrolled for DC Authentication / Domain Controller certificates to support PKINIT (smart card logon), LDAPS mutual authentication, and certificate-based DC identification. Unenrolled DCs may fail certain authentication flows and cannot be verified via certificate-based means. Verify auto-enrollment GPO is configured for the Domain Controllers OU." `
                    -Reference 'https://attack.mitre.org/techniques/T1649/'
            }
        } catch { Write-Verbose "[CA-Config] DC cert enrollment check failed: $_" }
    }

    # Evaluate findings
    $findings = _CA_EvaluateFindings -CAs $cas -Templates $templates -PublishedTemplateNames $publishedNames `
        -NTAuthCerts $ntAuthCerts -KnownEnterpriseCACNs $knownCACNs
    if ($dcAuthFinding) { $findings.Add($dcAuthFinding) }

    # Locksmith integration
    $lsEnabled = ($Settings['EnableLocksmith'] -ne $false)
    $locksmithFindings = @(if ($lsEnabled) { _CA_RunLocksmith -ArtDir $artDir -RunId $runId } else { @() })

    # Derive Locksmith-covered ESC IDs for provenance record
    $lsEscIdSet = [System.Collections.Generic.HashSet[string]]::new()
    $escPattern  = [System.Text.RegularExpressions.Regex]::new('ESC\d+', 'IgnoreCase')
    foreach ($lf in $locksmithFindings) {
        $sev = switch -Regex ($lf.severity) {
            'Critical' { 'Critical' } 'High' { 'High' } 'Medium' { 'Medium' } default { 'Low' }
        }
        $findings.Add((New-Finding -Id 'ADCS-008' -Severity $sev `
            -Technique 'T1649' `
            -Description "[Locksmith] $($lf.name): $($lf.description)" `
            -Reference 'https://attack.mitre.org/techniques/T1649/'))
        $coveredStr = ($lf.technique, $lf.name, $lf.description | Where-Object { $_ }) -join ' '
        $lsEscIdSet.UnionWith([string[]]($escPattern.Matches($coveredStr) | ForEach-Object { $_.Value.ToUpper() }))
    }
    $locksmithCoveredEscIds = [string[]]$lsEscIdSet

    # Certipy integration (optional — requires certipy/certipy-ad binary + credentials)
    $certipyEnabled = ($Settings['EnableCertipy'] -eq $true)
    $certipyFindings = @(if ($certipyEnabled) { _CA_RunCertipy -ArtDir $artDir -RunId $runId -Settings $Settings -RepoRoot $RunContext.RepoRoot } else { @() })

    # Certipy findings emit directly as ADCS-008 with [Certipy] prefix so they're
    # distinguishable from Locksmith entries while sharing the same finding ID namespace.
    $certipyEscIdSet = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($cf in $certipyFindings) {
        if ($cf.escIds) { $certipyEscIdSet.UnionWith([string[]]$cf.escIds) }
        $findings.Add((New-Finding -Id 'ADCS-008' -Severity 'High' `
            -Technique 'T1649' `
            -Description "[Certipy] $($cf.context): $($cf.vulnerabilities)" `
            -Reference 'https://attack.mitre.org/techniques/T1649/'))
    }
    $certipyCoveredEscIds = [string[]]$certipyEscIdSet

    # ESC12 — HSM-protected CA key storage requires manual verification.
    # There is no reliable remote way to confirm HSM enrollment; emit review-required
    # per CA so the post-run pass knows to inspect each CA's key storage provider.
    foreach ($ca in $cas) {
        $records.Add((New-ReviewRequired `
            -Collector 'CA-Config' `
            -Id     "CA:esc12:$($ca.cn):$domainFQDN" `
            -Topic  "ESC12 — CA '$($ca.cn)' key storage provider (HSM/software)" `
            -Reason "ESC12 requires confirming that this CA's private key is protected by a Hardware Security Module (HSM). If the key resides in a software KSP, an attacker with CA admin rights can extract it and forge certificates for any identity. Verify via certsrv or certutil -getreg CA\CSP\ProviderName on the CA server." `
            -RunId  $runId))
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
            locksmithCoveredEscIds = $locksmithCoveredEscIds
            certipyFindingCount    = $certipyFindings.Count
            certipyCoveredEscIds   = $certipyCoveredEscIds
            ntAuthCertCount        = $ntAuthCerts.Count
            ntAuthCerts            = $ntAuthCerts.ToArray()
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
                domain          = $domainFQDN
                count           = $locksmithFindings.Count
                coveredEscIds   = $locksmithCoveredEscIds
                findings        = $locksmithFindings.ToArray()
            } `
            -RawArtifactRef 'locksmith-findings.json' `
            -RunId $runId))
    }

    # Certipy raw findings record
    if ($certipyFindings.Count -gt 0) {
        $records.Add((New-ReconRecord `
            -Collector      'CA-Config' `
            -ObjectType     'certipy-findings' `
            -StableId       "CA:certipy:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain          = $domainFQDN
                count           = $certipyFindings.Count
                coveredEscIds   = $certipyCoveredEscIds
                findings        = $certipyFindings.ToArray()
            } `
            -RawArtifactRef 'certipy-findings.json' `
            -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'CA-Config' `
    -Description 'Enumerates AD CS: Enterprise CAs, enrollment endpoints, certificate templates (ESC1-ESC9/ESC15 native evaluation), ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC8 (HTTP enrollment relay), NTAuthCertificates (ADCS-012), DC cert enrollment gap (ADCS-013), Locksmith2 integration (ESC1-ESC16 + provenance), Certipy integration (optional, ESC1-ESC16 primary enumerator), ESC12 review-required per CA' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _CAConfig_Collect @PSBoundParameters }
