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
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$policiesDn")
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
    return $gpos
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
                            gpoGuid  = ($_.FullName -split [regex]::Escape('\Policies\'))[1] -replace '\\.*',''
                            gppFile  = $file
                            userName = $userName
                        })
                    }
                }
            } catch { Write-Verbose "[GPO] SYSVOL scan error on $sysvolRoot\$file : $_" }
        }
    }
    return $hits
}

# =============================================================================
# LAYER 3 — Get-GPOReport XML parsing (GPMC required)
# =============================================================================

# Checks run against each GPO's XML report (machine settings only for now)
# Returns @{ settingKey = value } for known security settings
function _GPO_ParseGPOReport {
    param([string]$GpoGuid, [string]$DomainFQDN)

    $result = @{ parsed = $false; settings = @{} }
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
# MAIN COLLECTOR
# =============================================================================

function _GPO_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId
    $artDir  = Join-Path $RunRoot 'artifacts'

    $rootDse    = [adsi]'LDAP://RootDSE'
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
    -Description 'Enumerates GPOs via LDAP, scans SYSVOL for GPP credentials, parses security settings via Get-GPOReport (GPMC), optionally runs Group3r' `
    -MinPrivilege 'AnyAuthUser' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _GPO_Collect @PSBoundParameters }
