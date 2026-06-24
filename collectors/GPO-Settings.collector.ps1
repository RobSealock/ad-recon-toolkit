# GPO-Settings collector — enumerates Group Policy Objects and checks for
# dangerous configurations, credential exposure, and missing hardening.
# MinPrivilege: AnyAuthUser (SYSVOL + LDAP); enriched by GPMC (no extra priv).
#
# Collection strategy (layered — each layer is additive, not blocking):
#   Layer 1 — LDAP: enumerate all GPO container objects from AD
#   Layer 2 — SYSVOL: read GPP XML files for cpassword entries (any auth user)
#   Layer 3 — Get-GPOReport (GPMC): full XML for each GPO, parsed for key settings
#   Layer 4 — Group3r: optional external analysis; ingested from stdout
#
# Findings emitted:
#   GPO-001  GPP cpassword credential found in SYSVOL
#   GPO-002  Screensaver/inactivity lock not enforced via GPO
#   GPO-003  WDigest credential caching not explicitly disabled via GPO
#   GPO-004  LLMNR not disabled via GPO
#   GPO-005  NBT-NS not disabled via GPO
#   GPO-006  LSA RunAsPPL not enforced via GPO
#   GPO-007  SMBv1 not explicitly disabled via GPO
#   GPO-008  Print Spooler not disabled on DCs via GPO
#   GPO-009  Advanced Audit Policy not configured via GPO (missing SIEM telemetry)
#   GPO-010  Group3r flagged issues (high/critical from external analysis)
#   GPO-011  AppLocker or WDAC not configured for Domain Controllers
#   GPO-012  Restricted Groups / Group Policy Preferences Groups not configured for Domain Admins membership
#   GPO-013  Non-Tier-0 principals have write rights on DC-linked GPOs
#   GPO-014  No deny-logon user rights configured in DC-scoped GPOs
#   GPO-015  Orphaned GPOs (not linked to any container)

# ── XML namespaces used in GPO reports ───────────────────────────────────────
$script:_GPO_NS = @{ gp = 'http://www.microsoft.com/GroupPolicy/Settings' }

# =============================================================================
# LAYER 1 — LDAP enumeration of GPO objects
# =============================================================================

function _GPO_EnumerateFromLDAP {
    param([string]$DomainDn)

    $gpos = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $policiesDn = "CN=Policies,CN=System,$DomainDn"
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$policiesDn"))
        $s.Filter      = '(objectClass=groupPolicyContainer)'
        $s.SearchScope = 'OneLevel'
        $s.PageSize    = 200
        $s.PropertiesToLoad.AddRange([string[]]@(
            'displayName','cn','gPCFileSysPath','whenCreated','whenChanged',
            'versionNumber','flags','gPCMachineExtensionNames','gPCUserExtensionNames'
        ))
        $s.FindAll() | ForEach-Object {
            $p = $_.Properties
            $gpos.Add(@{
                guid            = $p['cn'][0].ToString()
                displayName     = if ($p['displayname'].Count) { $p['displayname'][0].ToString() } else { '' }
                sysvolPath      = if ($p['gpcfilesyspath'].Count) { $p['gpcfilesyspath'][0].ToString() } else { '' }
                whenCreated     = if ($p['whencreated'].Count) { $p['whencreated'][0].ToString('o') } else { '' }
                whenChanged     = if ($p['whenchanged'].Count) { $p['whenchanged'][0].ToString('o') } else { '' }
                versionNumber   = if ($p['versionnumber'].Count) { $p['versionnumber'][0] } else { 0 }
                flags           = if ($p['flags'].Count) { $p['flags'][0] } else { 0 }
                machineCSEs     = if ($p['gpcmachineextensionnames'].Count) { $p['gpcmachineextensionnames'][0].ToString() } else { '' }
                userCSEs        = if ($p['gpcuserextensionnames'].Count) { $p['gpcuserextensionnames'][0].ToString() } else { '' }
            })
        }
    } catch { Write-Warning "[GPO] LDAP enumeration failed: $_" }
    return ,$gpos
}

# =============================================================================
# LAYER 2 — SYSVOL scan for GPP cpassword attributes
# =============================================================================

# GPP XML files that can contain cpassword
$script:_GPO_GPPFiles = @(
    'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml',
    'Printers.xml','Drives.xml','Registry.xml'
)

function _GPO_ScanSysvolGPP {
    param([string[]]$SysvolPaths)

    $hits = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($sysvolRoot in $SysvolPaths) {
        if (-not (Test-Path $sysvolRoot)) { continue }
        foreach ($file in $script:_GPO_GPPFiles) {
            try {
                Get-ChildItem -Path $sysvolRoot -Recurse -Filter $file -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match 'cpassword="([^"]+)"') {
                        # Extract context — element type and userName if present
                        $userName = if ($content -match 'userName="([^"]+)"') { $Matches[1] } else { 'unknown' }
                        $hits.Add(@{
                            file     = $_.FullName
                            gpoGuid  = (($_.FullName -split [regex]::Escape('\Policies\'))[1] -replace '\\.*','')
                            gppFile  = $file
                            userName = $userName
                        })
                    }
                }
            } catch { Write-Verbose "[GPO] SYSVOL scan error on $sysvolRoot\$file : $_" }
        }
    }
    return ,$hits
}

# =============================================================================
# LAYER 3 — Get-GPOReport XML parsing (GPMC required)
# =============================================================================

# Checks run against each GPO's XML report (machine settings only for now)
# Returns @{ settingKey = value } for known security settings
function _GPO_ParseGPOReport {
    param([string]$GpoGuid, [string]$DomainFQDN)

    # Default every key the caller reads, so a setting this GPO doesn't configure
    # -- or a report that fails to parse at all (early return, or an exception
    # below, e.g. no AD Web Services reachable) -- is $false/empty rather than
    # entirely absent (StrictMode throws on dot-access to a missing hashtable
    # key, not just $null). Set unconditionally, before any return path.
    $result = @{
        parsed   = $false
        settings = @{
            wdigestDisabledByGPO    = $false
            llmnrDisabledByGPO      = $false
            smb1DisabledByGPO       = $false
            lsaPPLByGPO             = $false
            screensaverLockByGPO    = $false
            screensaverTimeoutSec   = -1
            advancedAuditConfigured = $false
            auditPolicies           = @()
            spoolerStartupTypeByGPO = ''
        }
    }
    try {
        if (-not (Get-Command Get-GPOReport -ErrorAction SilentlyContinue)) { return $result }

        [xml]$xml = Get-GPOReport -Guid $GpoGuid -ReportType Xml -Domain $DomainFQDN -ErrorAction Stop
        $result.parsed = $true
        $s = $result.settings

        # Helper: find registry policy value by key+name
        function _RegVal([string]$key, [string]$valueName) {
            $nodes = $xml.SelectNodes(
                "//q1:RegistrySettings/q1:Registry[q1:Properties[@key='$key' and @name='$valueName']]",
                (New-Object System.Xml.XmlNamespaceManager($xml.NameTable) | % { $_.AddNamespace('q1','http://www.microsoft.com/GroupPolicy/Settings/Registry'); $_ })
            )
            if ($nodes.Count) { return $nodes[0].SelectSingleNode("q1:Properties/@value", $_).Value }
            return $null
        }

        # WDigest (UseLogonCredential = 0 means disabled)
        $wdigVal = _RegVal 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        if ($null -ne $wdigVal) { $s.wdigestDisabledByGPO = ($wdigVal -eq '0') }

        # LLMNR (EnableMulticast = 0 means disabled)
        $llmnrVal = _RegVal 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        if ($null -ne $llmnrVal) { $s.llmnrDisabledByGPO = ($llmnrVal -eq '0') }

        # SMBv1 server
        $smb1Val = _RegVal 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
        if ($null -ne $smb1Val) { $s.smb1DisabledByGPO = ($smb1Val -eq '0') }

        # LSA RunAsPPL
        $pplVal = _RegVal 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
        if ($null -ne $pplVal) { $s.lsaPPLByGPO = ([int]$pplVal -ge 1) }

        # Screensaver enforcement
        $ssActive = _RegVal 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaverIsSecure'
        $ssTime   = _RegVal 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaveTimeOut'
        if ($null -ne $ssActive) {
            $s.screensaverLockByGPO    = ($ssActive -eq '1')
            $s.screensaverTimeoutSec   = if ($null -ne $ssTime) { [int]$ssTime } else { -1 }
        }

        # Audit policy — check Advanced Audit Policies (AccountLogon, LogonLogoff, ObjectAccess)
        $auditNodes = $xml.SelectNodes('//*[local-name()="AuditSetting"]')
        if ($auditNodes.Count -gt 0) {
            $s.advancedAuditConfigured = $true
            $s.auditPolicies = @(
                $auditNodes | ForEach-Object {
                    @{ category=$_.SubcategoryName; setting=$_.SettingValue }
                }
            )
        }

        # Print Spooler disabled for DCs (service start type = 4 = Disabled)
        $spoolerNodes = $xml.SelectNodes('//*[local-name()="ServiceSetting"][*[local-name()="Name" and text()="Spooler"]]')
        if ($spoolerNodes.Count -gt 0) {
            $startMode = $spoolerNodes[0].SelectSingleNode('*[local-name()="StartupType"]')
            if ($startMode) { $s.spoolerStartupTypeByGPO = $startMode.InnerText }
        }

    } catch { Write-Verbose "[GPO] Get-GPOReport failed for $GpoGuid : $_" }

    return $result
}

# =============================================================================
# LAYER 4 — Group3r optional external analysis
# =============================================================================

function _GPO_RunGroup3r {
    param([string]$Group3rPath, [string]$ArtDir)

    if (-not (Test-Path $Group3rPath)) { return $null }
    try {
        Write-Host "         Running Group3r..."
        $outFile = Join-Path $ArtDir 'group3r-output.txt'
        $proc = Start-Process -FilePath $Group3rPath `
            -ArgumentList '-f', $outFile `
            -Wait -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $ArtDir 'group3r-stdout.txt') `
            -RedirectStandardError  (Join-Path $ArtDir 'group3r-stderr.txt') `
            -ErrorAction Stop
        if (Test-Path $outFile) {
            $lines = Get-Content $outFile -ErrorAction SilentlyContinue
            return @{
                exitCode = $proc.ExitCode
                lineCount = $lines.Count
                artifact  = 'group3r-output.txt'
                criticalHigh = @($lines | Where-Object { $_ -match '\[(CRITICAL|HIGH)\]' })
            }
        }
        return @{ exitCode=$proc.ExitCode; lineCount=0; artifact=$null; criticalHigh=@() }
    } catch {
        Write-Warning "[GPO] Group3r failed: $_"
        return $null
    }
}

# =============================================================================
# GPO LINK HELPERS — identify GPOs linked to specific OUs
# =============================================================================

function _GPO_GetLinkedGPOs {
    param([string]$OuDn)
    # Returns GUIDs of GPOs linked to a specific DN object (OU or domain)
    $guids = [System.Collections.Generic.List[string]]::new()
    try {
        $ou = (New-AdsiEntry "LDAP://$OuDn")
        $links = @($ou.Properties['gPLink'])
        foreach ($linkStr in $links) {
            if (-not $linkStr) { continue }
            # gPLink format: [LDAP://cn={GUID},cn=policies,...;flags]...
            $matches = [System.Text.RegularExpressions.Regex]::Matches($linkStr.ToString(), '\{([0-9A-Fa-f\-]+)\}')
            foreach ($m in $matches) { [void]$guids.Add($m.Value) }
        }
    } catch { Write-Verbose "[GPO] GPO link read failed for $OuDn : $_" }
    return ,$guids
}

function _GPO_CheckAppLockerWDAC {
    param([string]$GpoGuid, [string]$DomainFQDN)
    # Returns $true if the GPO contains an AppLocker or WDAC policy
    try {
        if (-not (Get-Command Get-GPOReport -ErrorAction SilentlyContinue)) { return $false }
        [xml]$xml = Get-GPOReport -Guid $GpoGuid -ReportType Xml -Domain $DomainFQDN -ErrorAction Stop
        # AppLocker: look for AppLockerPolicy element
        $appLocker = $xml.SelectNodes('//*[local-name()="AppLockerPolicy"]')
        if ($appLocker.Count -gt 0) { return $true }
        # WDAC / Windows Defender Application Control: look for CodeIntegrity registry key
        $wdacNodes = $xml.SelectNodes('//*[local-name()="Registry"][*[local-name()="Properties"][@key="HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"]]')
        if ($wdacNodes.Count -gt 0) { return $true }
        # Also check for WDAC via SiPolicy binary reference
        $siPolicy = $xml.SelectNodes('//*[local-name()="File"][contains(@name,"SiPolicy")]')
        if ($siPolicy.Count -gt 0) { return $true }
    } catch {}
    return $false
}

function _GPO_CheckRestrictedGroups {
    param([string]$GpoGuid, [string]$DomainFQDN)
    # Returns $true if the GPO has a Restricted Groups or GPP Groups policy for Domain Admins
    try {
        if (-not (Get-Command Get-GPOReport -ErrorAction SilentlyContinue)) { return $false }
        [xml]$xml = Get-GPOReport -Guid $GpoGuid -ReportType Xml -Domain $DomainFQDN -ErrorAction Stop
        # Restricted Groups: RestrictedGroups element
        $rg = $xml.SelectNodes('//*[local-name()="RestrictedGroup"]')
        if ($rg.Count -gt 0) { return $true }
        # GPP Groups: Group element under Preferences
        $gppGroups = $xml.SelectNodes('//*[local-name()="Group"][@name]')
        if ($gppGroups.Count -gt 0) { return $true }
    } catch {}
    return $false
}

function _GPO_CheckGPOModificationRights {
    param([string[]]$GpoGuids, [string]$DomainDn)
    $issues = [System.Collections.Generic.List[hashtable]]::new()
    $policiesDn = "CN=Policies,CN=System,$DomainDn"
    $safePatterns = @('CREATOR OWNER','SYSTEM','Enterprise Admins','Domain Admins',
                      'Administrators','Group Policy Creator Owners','NT AUTHORITY')

    # SID-based fallback for the same well-known Tier-0 principals. Translate([NTAccount])
    # resolves a SID to a name by looking it up against a domain controller using the
    # CURRENT PROCESS token -- in remote mode (non-domain-joined host, alternate creds
    # used only for the explicit LDAP/CIM connections elsewhere) that token has no trust
    # to the target domain, so the translation silently fails and falls back to the raw
    # SID string, which never matches the name-based $safePatterns above. This caused
    # Domain Admins/Enterprise Admins/Domain Controllers ACEs on DC-OU GPOs to be
    # flagged as "non-Tier-0" attackers on every remote-mode run.
    $domSid = try {
        (New-Object System.Security.Principal.SecurityIdentifier(
            ((New-AdsiEntry "LDAP://$DomainDn")).objectSid.Value, 0)).ToString()
    } catch { '' }
    $tier0SidPatterns = @(
        '^S-1-5-32-544$'                                      # BUILTIN\Administrators
        '^S-1-5-18$'                                          # SYSTEM
        '^S-1-3-0$'                                           # Creator Owner
        '^S-1-5-9$'                                           # Enterprise DCs
        "^$([regex]::Escape($domSid))-512$"                   # Domain Admins
        "^$([regex]::Escape($domSid))-519$"                   # Enterprise Admins
        "^$([regex]::Escape($domSid))-516$"                   # Domain Controllers
        "^$([regex]::Escape($domSid))-520$"                   # Group Policy Creator Owners
    )
    # Built from atomic bits, not the GenericAll/GenericWrite composite VALUES --
    # those composites also carry the ReadControl bit, which ReadControl shares
    # with GenericRead, so OR-ing the composites into a -band mask matched plain
    # read-only GenericRead grants too. GenericAll/GenericWrite still match here
    # since both inherently include WriteProperty (and GenericAll CreateChild) as
    # constituent bits.
    $dangerous = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl     -bor
                 [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner    -bor
                 [System.DirectoryServices.ActiveDirectoryRights]::CreateChild   -bor
                 [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor
                 [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild   -bor
                 [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree
    foreach ($guid in $GpoGuids) {
        try {
            $gpoObj = (New-AdsiEntry "LDAP://CN=$guid,$policiesDn")
            foreach ($ace in $gpoObj.psbase.ObjectSecurity.Access) {
                if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                if (-not ($ace.ActiveDirectoryRights -band $dangerous)) { continue }
                $sidValue = $ace.IdentityReference.Value
                $trustee  = try { $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $sidValue }
                $isSafe   = $false
                foreach ($p in $safePatterns) { if ($trustee -imatch [regex]::Escape($p)) { $isSafe = $true; break } }
                if (-not $isSafe) {
                    foreach ($p in $tier0SidPatterns) { if ($sidValue -match $p) { $isSafe = $true; break } }
                }
                if (-not $isSafe) { $issues.Add(@{ gpoGuid=$guid; trustee=$trustee; rights=$ace.ActiveDirectoryRights.ToString() }) }
            }
        } catch { Write-Verbose "[GPO] DACL check failed for ${guid}: $_" }
    }
    return ,$issues
}

function _GPO_CheckTier0LogonRestrictions {
    param([string[]]$GpoGuids, [string]$DomainFQDN)
    foreach ($guid in $GpoGuids) {
        try {
            if (-not (Get-Command Get-GPOReport -ErrorAction SilentlyContinue)) { return $false }
            [xml]$xml = Get-GPOReport -Guid $guid -ReportType Xml -Domain $DomainFQDN -EA Stop
            $denyNodes = $xml.SelectNodes(
                '//*[local-name()="UserRightsAssignment"][*[local-name()="Name" and (text()="SeDenyInteractiveLogonRight" or text()="SeDenyRemoteInteractiveLogonRight" or text()="SeDenyNetworkLogonRight")]]')
            if ($denyNodes.Count -gt 0) { return $true }
        } catch { Write-Verbose "[GPO] Logon restriction check failed for ${guid}: $_" }
    }
    return $false
}

function _GPO_FindOrphanedGPOs {
    param([hashtable[]]$AllGpos, [string]$DomainDn)
    $linked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter = '(|(objectClass=organizationalUnit)(objectClass=domainDNS))'
        $s.PageSize = 500; $s.SearchScope = 'Subtree'
        $s.PropertiesToLoad.Add('gPLink') | Out-Null
        $s.FindAll() | ForEach-Object {
            $gpl = $_.Properties['gplink']
            if ($gpl.Count -and $gpl[0]) {
                [regex]::Matches($gpl[0].ToString(), '\{([0-9A-Fa-f\-]+)\}') |
                    ForEach-Object { [void]$linked.Add("{$($_.Groups[1].Value.ToUpper())}") }
            }
        }
        # Also walk Sites container for site-linked GPOs
        try {
            $cfgDn = ((New-AdsiEntry 'LDAP://RootDSE')).configurationNamingContext.ToString()
            $s2 = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://CN=Sites,$cfgDn"))
            $s2.Filter = '(gPLink=*)'; $s2.PageSize = 200
            $s2.PropertiesToLoad.Add('gPLink') | Out-Null
            $s2.FindAll() | ForEach-Object {
                $gpl = $_.Properties['gplink']
                if ($gpl.Count -and $gpl[0]) {
                    [regex]::Matches($gpl[0].ToString(), '\{([0-9A-Fa-f\-]+)\}') |
                        ForEach-Object { [void]$linked.Add("{$($_.Groups[1].Value.ToUpper())}") }
                }
            }
        } catch {}
    } catch { Write-Verbose "[GPO] Orphaned GPO detection failed: $_" }
    return @($AllGpos | Where-Object { -not $linked.Contains($_.guid.ToUpper()) -and ($_.flags -band 3) -ne 3 })
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _GPO_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId
    $artDir  = Join-Path $RunRoot 'artifacts'

    $rootDse    = (New-AdsiEntry 'LDAP://RootDSE')
    $domainDn   = $rootDse.defaultNamingContext.ToString()
    $domainFQDN = $RunContext.Domain

    # ── Layer 1: LDAP enumeration ─────────────────────────────────────────────
    Write-Host "         [GPO] Enumerating GPOs via LDAP..."
    $gpos = _GPO_EnumerateFromLDAP -DomainDn $domainDn
    Write-Host "         $($gpos.Count) GPO(s) found"

    # ── Layer 2: SYSVOL GPP scan ──────────────────────────────────────────────
    Write-Host "         [GPO] Scanning SYSVOL for GPP credentials..."
    $sysvolRoots = @("\\$domainFQDN\SYSVOL\$domainFQDN\Policies")
    $gppHits = _GPO_ScanSysvolGPP -SysvolPaths $sysvolRoots

    # ── Layer 3: Get-GPOReport per GPO ───────────────────────────────────────
    $gpoParsed   = @{}
    $hasGPMC     = [bool](Get-Command Get-GPOReport -ErrorAction SilentlyContinue)
    $settingsAgg = @{
        wdigestDisabledByGPO   = $false
        llmnrDisabledByGPO     = $false
        smb1DisabledByGPO      = $false
        lsaPPLByGPO            = $false
        screensaverLockByGPO   = $false
        spoolerDisabledByGPO   = $false
        advancedAuditConfigured= $false
    }
    if ($hasGPMC) {
        Write-Host "         [GPO] Parsing GPO reports via GPMC (Get-GPOReport)..."
        foreach ($gpo in $gpos) {
            $parsed = _GPO_ParseGPOReport -GpoGuid $gpo.guid -DomainFQDN $domainFQDN
            $gpoParsed[$gpo.guid] = $parsed
            # Aggregate — any GPO that sets the flag counts as "covered"
            if ($parsed.settings.wdigestDisabledByGPO)    { $settingsAgg.wdigestDisabledByGPO    = $true }
            if ($parsed.settings.llmnrDisabledByGPO)       { $settingsAgg.llmnrDisabledByGPO      = $true }
            if ($parsed.settings.smb1DisabledByGPO)        { $settingsAgg.smb1DisabledByGPO       = $true }
            if ($parsed.settings.lsaPPLByGPO)              { $settingsAgg.lsaPPLByGPO             = $true }
            if ($parsed.settings.screensaverLockByGPO)     { $settingsAgg.screensaverLockByGPO    = $true }
            if ($parsed.settings.advancedAuditConfigured)  { $settingsAgg.advancedAuditConfigured = $true }
            if ($parsed.settings.spoolerStartupTypeByGPO -eq 'Disabled') { $settingsAgg.spoolerDisabledByGPO = $true }
        }
    } else {
        Write-Host "         [GPO] Get-GPOReport unavailable — install GPMC (RSAT) for full analysis"
    }

    # ── Layer 4: Group3r ──────────────────────────────────────────────────────
    $g3rResult = $null
    $g3rEnabled = ($Settings['EnableGroup3r'] -ne $false)
    if ($g3rEnabled) {
        $g3rPath = Join-Path $RunContext.RepoRoot 'tools\bin\Group3r.exe'
        $g3rResult = _GPO_RunGroup3r -Group3rPath $g3rPath -ArtDir $artDir
    }

    # ── Build findings ────────────────────────────────────────────────────────
    $findings = [System.Collections.Generic.List[object]]::new()

    # GPO-001: cpassword in SYSVOL
    foreach ($hit in $gppHits) {
        $gpoName = ($gpos | Where-Object { $_.guid -eq $hit.gpoGuid } | Select-Object -First 1).displayName
        $findings.Add((New-Finding -Id 'GPO-001' -Severity 'Critical' `
            -Technique 'T1552.006' `
            -Description "GPP cpassword found in $($hit.gppFile) under GPO '$gpoName' ($($hit.gpoGuid)). Account: $($hit.userName). AES-256-CBC key is public (MS14-025) — decrypt with Get-DecryptedCpassword or gpp-decrypt." `
            -Reference 'https://attack.mitre.org/techniques/T1552/006/'))
    }

    if ($hasGPMC) {
        # GPO-002: No screensaver lock policy
        if (-not $settingsAgg.screensaverLockByGPO) {
            $findings.Add((New-Finding -Id 'GPO-002' -Severity 'Medium' `
                -Technique 'T1078' `
                -Description "No GPO enforces screensaver-triggered lock (ScreenSaverIsSecure=1). Unattended workstations on domain are accessible without re-authentication." `
                -Reference 'https://attack.mitre.org/techniques/T1078/'))
        }

        # GPO-003: WDigest not disabled via GPO
        if (-not $settingsAgg.wdigestDisabledByGPO) {
            $findings.Add((New-Finding -Id 'GPO-003' -Severity 'High' `
                -Technique 'T1003.001' `
                -Description "No GPO explicitly sets UseLogonCredential=0 (disable WDigest). Without a GPO, endpoints rely on the OS default (disabled on Win8.1+/2012R2+, but not enforced — can be re-enabled by malware or GPO override)." `
                -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
        }

        # GPO-004: LLMNR not disabled via GPO
        if (-not $settingsAgg.llmnrDisabledByGPO) {
            $findings.Add((New-Finding -Id 'GPO-004' -Severity 'High' `
                -Technique 'T1557.001' `
                -Description "No GPO disables LLMNR (EnableMulticast=0 in Policies\Microsoft\Windows NT\DNSClient). LLMNR is enabled by default on all clients and DCs unless explicitly suppressed." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # GPO-005: NBT-NS via GPO (registry path check)
        # NBT-NS cannot be fully disabled via pure registry GPO on all Windows versions;
        # flag if no GPO sets TcpipNetbiosOptions. This is a best-effort check.
        $findings.Add((New-Finding -Id 'GPO-005' -Severity 'Medium' `
            -Technique 'T1557.001' `
            -Description "NBT-NS must be disabled per-adapter (TcpipNetbiosOptions=2) and is not manageable via standard registry GPO on all versions. Verify via WMI or use third-party GPO extension / startup script. Review Host-OS HOST-013 findings for per-host state." `
            -Reference 'https://attack.mitre.org/techniques/T1557/001/'))

        # GPO-006: LSA RunAsPPL not via GPO
        if (-not $settingsAgg.lsaPPLByGPO) {
            $findings.Add((New-Finding -Id 'GPO-006' -Severity 'High' `
                -Technique 'T1003.001' `
                -Description "No GPO sets RunAsPPL=1 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa. LSA Protection relies on local configuration only — a single misconfigured host provides credential access." `
                -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
        }

        # GPO-007: SMBv1 not disabled via GPO
        if (-not $settingsAgg.smb1DisabledByGPO) {
            $findings.Add((New-Finding -Id 'GPO-007' -Severity 'High' `
                -Technique 'T1210' `
                -Description "No GPO explicitly disables SMBv1 (SMB1=0 in LanmanServer\Parameters). Older hosts or any new provisioned host not patched to disable SMBv1 by default remain vulnerable to EternalBlue-class exploits." `
                -Reference 'https://attack.mitre.org/techniques/T1210/'))
        }

        # GPO-008: Print Spooler not disabled on DCs via GPO
        if (-not $settingsAgg.spoolerDisabledByGPO) {
            $findings.Add((New-Finding -Id 'GPO-008' -Severity 'High' `
                -Technique 'T1187' `
                -Description "No GPO disables the Print Spooler service on Domain Controllers. Print Spooler must be set to Disabled in a DC-scoped GPO or it will restart on reboot even if manually stopped. Correlate with HOST-004 per-DC state." `
                -Reference 'https://attack.mitre.org/techniques/T1187/'))
        }

        # GPO-009: Advanced audit policy not configured
        if (-not $settingsAgg.advancedAuditConfigured) {
            $findings.Add((New-Finding -Id 'GPO-009' -Severity 'Medium' `
                -Technique 'T1562.002' `
                -Description "No GPO configures Advanced Audit Policy (Security\Advanced Audit Policy Configuration). Without this, security event generation is relying on legacy basic auditing or OS defaults, which may produce insufficient SIEM telemetry." `
                -Reference 'https://attack.mitre.org/techniques/T1562/002/'))
        }
    }

    # GPO-010: Group3r findings
    if ($g3rResult -and $g3rResult.criticalHigh.Count -gt 0) {
        $preview = $g3rResult.criticalHigh | Select-Object -First 10
        $findings.Add((New-Finding -Id 'GPO-010' -Severity 'High' `
            -Technique 'T1484.001' `
            -Description "Group3r identified $($g3rResult.criticalHigh.Count) Critical/High issues in GPO analysis. First 10: $($preview -join ' | '). Full output in artifact group3r-output.txt." `
            -Reference 'https://attack.mitre.org/techniques/T1484/001/'))
    }

    # GPO-011: AppLocker or WDAC not configured for Domain Controllers
    # Check GPOs linked to the Domain Controllers OU
    if ($hasGPMC) {
        $dcOuDn = "OU=Domain Controllers,$domainDn"
        $dcLinkedGuids = _GPO_GetLinkedGPOs -OuDn $dcOuDn
        # Also check domain-level links (policies linked to domain root apply to DCs)
        $domainLinkedGuids = _GPO_GetLinkedGPOs -OuDn $domainDn
        $allDcGuids = @($dcLinkedGuids) + @($domainLinkedGuids) | Select-Object -Unique

        $hasAppLockerWDAC = $false
        foreach ($guid in $allDcGuids) {
            if (_GPO_CheckAppLockerWDAC -GpoGuid $guid -DomainFQDN $domainFQDN) {
                $hasAppLockerWDAC = $true
                break
            }
        }
        if (-not $hasAppLockerWDAC) {
            $findings.Add((New-Finding -Id 'GPO-011' -Severity 'Medium' `
                -Technique 'T1059.001' `
                -Description "No GPO linked to the Domain Controllers OU or domain root configures AppLocker or Windows Defender Application Control (WDAC). Without application control on DCs, an attacker with local admin rights can execute arbitrary binaries (Mimikatz, impacket tools, custom payloads) without restriction. AppLocker in Audit mode is insufficient — require Enforce mode. WDAC is preferred on Windows Server 2019+ for kernel-enforced policy. Reference: CIS Benchmark DC baseline includes AppLocker/WDAC as a hardening requirement." `
                -Reference 'https://attack.mitre.org/techniques/T1059/001/'))
        }

        # GPO-012: Restricted Groups / GPP Groups not configured for Domain Admins
        $hasRestrictedGroups = $false
        foreach ($guid in $allDcGuids) {
            if (_GPO_CheckRestrictedGroups -GpoGuid $guid -DomainFQDN $domainFQDN) {
                $hasRestrictedGroups = $true
                break
            }
        }
        if (-not $hasRestrictedGroups) {
            $findings.Add((New-Finding -Id 'GPO-012' -Severity 'Medium' `
                -Technique 'T1098' `
                -Description "No GPO linked to Domain Controllers or domain root configures Restricted Groups (Computer Configuration > Windows Settings > Security Settings > Restricted Groups) or GPP Groups for the Domain Admins group. Without a Restricted Groups policy, unauthorized additions to Domain Admins will not be automatically removed on next Group Policy application — a persistence mechanism for attackers who have added themselves. Configure Restricted Groups with the approved DA membership list." `
                -Reference 'https://attack.mitre.org/techniques/T1098/'))
        }

        # GPO-013: Non-Tier-0 write rights on GPOs linked to Domain Controllers OU
        $gpoModIssues = _GPO_CheckGPOModificationRights -GpoGuids $dcLinkedGuids -DomainDn $domainDn
        if ($gpoModIssues.Count -gt 0) {
            $preview = ($gpoModIssues | Select-Object -First 5 |
                ForEach-Object { "$($_.trustee) on $($_.gpoGuid): $($_.rights)" }) -join '; '
            $findings.Add((New-Finding -Id 'GPO-013' -Severity 'Critical' `
                -Technique 'T1484.001' `
                -Description "$($gpoModIssues.Count) non-Tier-0 ACE(s) grant write rights (WriteDACL/WriteOwner/GenericAll/GenericWrite) on GPO(s) linked to the Domain Controllers OU: $preview. A principal with GPO write rights on a DC OU GPO can deploy arbitrary registry settings, startup scripts, or software to every DC at next refresh — direct domain compromise path. Investigate each ACE immediately." `
                -Reference 'https://attack.mitre.org/techniques/T1484/001/'))
        }

        # GPO-014: No deny-logon user rights in DC-scoped GPOs
        $hasDenyLogon = _GPO_CheckTier0LogonRestrictions -GpoGuids $allDcGuids -DomainFQDN $domainFQDN
        if (-not $hasDenyLogon) {
            $findings.Add((New-Finding -Id 'GPO-014' -Severity 'High' `
                -Technique 'T1078.002' `
                -Description "No GPO linked to the Domain Controllers OU or domain root configures any Deny logon user rights (SeDenyInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight, or SeDenyNetworkLogonRight). Without explicit deny rights, any account inadvertently granted local-admin access to a DC can log on interactively, and non-Tier-0 accounts can be used to authenticate to DCs over the network. Configure deny logon for Tier 1/2 admin groups and service accounts in a DC-scoped GPO." `
                -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
        }

        # GPO-015: Orphaned GPOs
        $orphanedGPOs = @(_GPO_FindOrphanedGPOs -AllGpos $gpos -DomainDn $domainDn)
        if ($orphanedGPOs.Count -gt 0) {
            $names = ($orphanedGPOs | Select-Object -First 8 | ForEach-Object { $_.displayName }) -join ', '
            $findings.Add((New-Finding -Id 'GPO-015' -Severity 'Low' `
                -Technique 'T1484.001' `
                -Description "$($orphanedGPOs.Count) GPO(s) are not linked to any container (OU, domain, or site): $names. Orphaned GPOs accumulate stale configuration and create governance risk — an attacker who can re-link an orphaned GPO to a sensitive OU gains policy-execution rights over that OU without creating a new GPO (evades monitoring for new GPO creation). Review and delete all unlinked GPOs that are no longer required." `
                -Reference 'https://attack.mitre.org/techniques/T1484/001/'))
        }
    }

    # ── Emit records ──────────────────────────────────────────────────────────

    # GPO inventory record
    $records.Add((New-ReconRecord `
        -Collector      'GPO-Settings' `
        -ObjectType     'gpo-inventory' `
        -StableId       "GPO:inventory:$domainFQDN" `
        -Category       'config' `
        -Tier           'T0' `
        -CollectedAtPriv $false `
        -Attributes     @{
            domain        = $domainFQDN
            totalGPOs     = $gpos.Count
            hasGPMC       = $hasGPMC
            gpoList       = @($gpos | ForEach-Object {
                @{
                    guid        = $_.guid
                    displayName = $_.displayName
                    versionNumber = $_.versionNumber
                    whenChanged = $_.whenChanged
                    disabled    = ($_.flags -eq 3)
                }
            })
            settingsAgg   = $settingsAgg
            gppCpasswordHits = $gppHits.Count
        } `
        -Findings       $findings.ToArray() `
        -RunId          $runId))

    # Per-GPO report records (only when GPMC available)
    foreach ($gpo in $gpos) {
        $parsed = if ($gpoParsed.ContainsKey($gpo.guid)) { $gpoParsed[$gpo.guid] } else { @{ parsed=$false; settings=@{} } }
        $records.Add((New-ReconRecord `
            -Collector      'GPO-Settings' `
            -ObjectType     'gpo-detail' `
            -StableId       "GPO:$($gpo.guid)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                guid          = $gpo.guid
                displayName   = $gpo.displayName
                sysvolPath    = $gpo.sysvolPath
                versionNumber = $gpo.versionNumber
                whenCreated   = $gpo.whenCreated
                whenChanged   = $gpo.whenChanged
                disabled      = ($gpo.flags -eq 3)
                reportParsed  = $parsed.parsed
                settings      = $parsed.settings
            } `
            -RunId $runId))
    }

    # Group3r artifact record
    if ($g3rResult) {
        $records.Add((New-ReconRecord `
            -Collector      'GPO-Settings' `
            -ObjectType     'group3r-analysis' `
            -StableId       "GPO:group3r:$domainFQDN" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain            = $domainFQDN
                exitCode          = $g3rResult.exitCode
                outputLineCount   = $g3rResult.lineCount
                criticalHighCount = $g3rResult.criticalHigh.Count
                artifact          = $g3rResult.artifact
            } `
            -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'GPO-Settings' `
    -Description 'Enumerates GPOs via LDAP, scans SYSVOL for GPP credentials, parses security settings via Get-GPOReport (GPMC), checks AppLocker/WDAC on DC OU (GPO-011), Restricted Groups for DA (GPO-012), GPO modification rights on DC-linked GPOs (GPO-013), Tier 0 logon restrictions (GPO-014), orphaned GPOs (GPO-015), optionally runs Group3r' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _GPO_Collect @PSBoundParameters }
