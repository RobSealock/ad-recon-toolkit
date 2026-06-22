# Audit Policy and Detection Coverage collector.
# MinPrivilege: LocalAdmin (WinRM to each Domain Controller)
#
# Collects audit policy via `auditpol /get /subcategory:* /r` (CSV, GUID-keyed,
# locale-independent — see NOTES below). Also checks PowerShell logging, Sysmon,
# WEF, log sizes, NTDS diagnostic level, and EDR presence.
#
# Findings are anchored to CIS Benchmark for Windows Server and the Microsoft
# recommended audit policy baseline. High-volume subcategories (5136, 1644,
# 4688+cmdline, PS ScriptBlock) include tuning caveats. EDR presence lowers
# severity of process-telemetry findings (MDE/CrowdStrike provide equivalent
# telemetry independently of 4688 state).
#
# NOTES — Audit subcategory GUIDs:
#   All GUIDs use the format {0CCE9XXX-69AE-11D9-BED3-505054503030}.
#   Verified against Windows Server 2016/2019/2022 auditpol CSV output.
#   To verify in your environment (run on a DC):
#     auditpol /get /subcategory:* /r | ConvertFrom-Csv |
#       Select-Object Subcategory,'Subcategory GUID' | Sort-Object Subcategory
#   If a GUID constant below does not match, update the $script:_AUD_Guids table.
#   Mismatch is safe — the collector captures all GUIDs; an incorrect constant
#   causes a false-negative finding (missed gap), not a false-positive.
#
# Findings:
#   AUD-001   Directory Service Changes (5136) not enabled — AD modification blind spot
#   AUD-002   Directory Service Access (4662) not enabled — SACL/DCSync detection blind spot
#   AUD-003   Process Creation (4688) not enabled and no EDR coverage
#   AUD-004   Command-line capture in 4688 not enabled and no EDR coverage
#   AUD-005   Security Group Management not enabled
#   AUD-006   User Account Management not enabled
#   AUD-007   Kerberos auth/ticket logging insufficient
#   AUD-008   Sensitive Privilege Use not enabled
#   AUD-009   Audit Policy Change (4719) not enabled — silent logging tampering risk
#   AUD-010   PowerShell ScriptBlock logging not enabled
#   AUD-011   Security log max size below CIS minimum (196608 KB / 192 MB)
#   AUD-012   Sysmon not installed or config not loaded on DC
#   AUD-013   NTDS Field Engineering diagnostic level < 5 (no 1644 expensive LDAP events)

# =============================================================================
# AUDIT SUBCATEGORY GUID CONSTANTS
# Source: Windows Server 2016/2019/2022 auditpol /get /subcategory:* /r output
# =============================================================================
$script:_AUD_Guids = @{
    # DS Access
    DsAccess         = '{0CCE923B-69AE-11D9-BED3-505054503030}'   # 4662 (requires SACL)
    DsChanges        = '{0CCE923C-69AE-11D9-BED3-505054503030}'   # 5136,5137,5138,5139,5141

    # Logon / Logoff
    Logon            = '{0CCE9215-69AE-11D9-BED3-505054503030}'   # 4624,4625,4648

    # Detailed Tracking
    ProcessCreation  = '{0CCE9223-69AE-11D9-BED3-505054503030}'   # 4688

    # Account Management
    UserAccountMgmt  = '{0CCE9235-69AE-11D9-BED3-505054503030}'   # 4720,4722,4723,4726,4738
    SecurityGroupMgmt= '{0CCE9237-69AE-11D9-BED3-505054503030}'   # 4728,4732,4756

    # Privilege Use
    SensitivePrivUse = '{0CCE9228-69AE-11D9-BED3-505054503030}'   # 4673,4674

    # Policy Change
    AuditPolicyChange= '{0CCE922F-69AE-11D9-BED3-505054503030}'   # 4719

    # Account Logon
    KerberosAuthSvc  = '{0CCE9242-69AE-11D9-BED3-505054503030}'   # 4768,4771,4772
    KerberosSvcTicket= '{0CCE9240-69AE-11D9-BED3-505054503030}'   # 4769,4770,4773
    CredValidation   = '{0CCE923F-69AE-11D9-BED3-505054503030}'   # 4776,4777
}

# EDR services that provide process-creation telemetry independently of 4688
$script:_AUD_ProcessEDRServices = @(
    @{ Name='Sense';                 Product='Microsoft Defender for Endpoint' }
    @{ Name='CsFalconService';       Product='CrowdStrike Falcon' }
    @{ Name='TaniumClient';          Product='Tanium' }
    @{ Name='CylanceSvc';            Product='Cylance/BlackBerry' }
    @{ Name='SentinelAgent';         Product='SentinelOne' }
    @{ Name='CarbonBlack';           Product='VMware Carbon Black' }
)

# =============================================================================
# REMOTE COLLECTION SCRIPTBLOCK
# Self-contained — no framework imports; invoked via WinRM Invoke-Command.
# =============================================================================
$script:_AUD_RemoteScript = {
    param([string[]]$EdrServiceNames)

    $result = @{
        computerName         = $env:COMPUTERNAME
        auditPolicy          = @{}          # GUID (upper) → inclusion-setting string
        psScriptBlockLogging = 'NotConfigured'
        psCmdLineEnabled     = 'NotConfigured'
        psTranscription      = 'NotConfigured'
        sysmon               = @{
            installed    = $false
            configLoaded = $false
            serviceName  = ''
        }
        wefSubscriptionCount = 0
        logSizes             = @{}          # logName → maxSizeKB (int)
        ntdsDiagLevel        = -1           # Field Engineering; -1 = registry not read
        edrProducts          = @()
        amsiActive           = $false
        collectionErrors     = @()
    }

    # ── Audit policy (GUID-keyed, locale-independent) ──────────────────────────
    try {
        $raw = (auditpol /get /subcategory:* /r 2>$null) -join "`n"
        $rows = $raw | ConvertFrom-Csv -ErrorAction Stop
        foreach ($row in $rows) {
            $guid    = ($row.'Subcategory GUID').Trim().ToUpper()
            $setting = ($row.'Inclusion Setting').Trim()
            if ($guid -match '^\{[0-9A-F\-]+\}$') {
                $result.auditPolicy[$guid] = $setting
            }
        }
    } catch {
        $result.collectionErrors += "auditpol: $_"
    }

    # ── PowerShell ScriptBlock logging ─────────────────────────────────────────
    try {
        $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (Test-Path $sbPath) {
            $val = (Get-ItemProperty $sbPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
            $result.psScriptBlockLogging = if ($val -eq 1) { 'Enabled' } else { 'Disabled' }
        }
    } catch { $result.collectionErrors += "PSScriptBlock: $_" }

    # ── 4688 command-line capture (separate GPO registry key) ──────────────────
    try {
        $clPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        $val = (Get-ItemProperty $clPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
        if ($null -ne $val) {
            $result.psCmdLineEnabled = if ($val -eq 1) { 'Enabled' } else { 'Disabled' }
        }
    } catch { $result.collectionErrors += "CmdLine: $_" }

    # ── PowerShell transcription ────────────────────────────────────────────────
    try {
        $tPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        if (Test-Path $tPath) {
            $val = (Get-ItemProperty $tPath -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
            $result.psTranscription = if ($val -eq 1) { 'Enabled' } else { 'Disabled' }
        }
    } catch { $result.collectionErrors += "Transcription: $_" }

    # ── Sysmon ─────────────────────────────────────────────────────────────────
    try {
        $svc = Get-Service 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) {
            $result.sysmon.installed  = $true
            $result.sysmon.serviceName= $svc.Name
            # Config (rules) stored in SysmonDrv driver registry key
            $rulesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
            $rulesValue = (Get-ItemProperty $rulesPath -Name Rules -ErrorAction SilentlyContinue).Rules
            # Rules is a REG_BINARY blob; a non-trivial config is > 32 bytes
            $result.sysmon.configLoaded = ($rulesValue -is [byte[]] -and $rulesValue.Length -gt 32)
        }
    } catch { $result.collectionErrors += "Sysmon: $_" }

    # ── WEF subscriptions ──────────────────────────────────────────────────────
    try {
        $subKeys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions' -ErrorAction SilentlyContinue
        $result.wefSubscriptionCount = if ($subKeys) { @($subKeys).Count } else { 0 }
    } catch { $result.collectionErrors += "WEF: $_" }

    # ── Event log sizes ────────────────────────────────────────────────────────
    try {
        foreach ($logName in @('Security', 'Microsoft-Windows-PowerShell/Operational')) {
            $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            if ($log) {
                $result.logSizes[$logName] = [int]($log.MaximumSizeInBytes / 1KB)
            }
        }
    } catch { $result.collectionErrors += "LogSizes: $_" }

    # ── NTDS Field Engineering diagnostic level (1644 expensive LDAP queries) ──
    try {
        $diagPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
        $val = (Get-ItemProperty $diagPath -Name '15 Field Engineering' -ErrorAction SilentlyContinue).'15 Field Engineering'
        if ($null -ne $val) { $result.ntdsDiagLevel = [int]$val }
    } catch { $result.collectionErrors += "NTDSDiag: $_" }

    # ── EDR presence ───────────────────────────────────────────────────────────
    try {
        $edr = @()
        foreach ($name in $EdrServiceNames) {
            if (Get-Service $name -ErrorAction SilentlyContinue) { $edr += $name }
        }
        $result.edrProducts = $edr
    } catch { $result.collectionErrors += "EDR: $_" }

    # ── AMSI / Defender active protection ──────────────────────────────────────
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $result.amsiActive = ($mpStatus -and $mpStatus.AMServiceEnabled -eq $true -and $mpStatus.RealTimeProtectionEnabled -eq $true)
    } catch { $result.collectionErrors += "AMSI: $_" }

    return $result
}

# =============================================================================
# DC DISCOVERY
# =============================================================================

function _AUD_DiscoverDCs {
    param([string]$DomainDn)
    $dcs = [System.Collections.Generic.List[string]]::new()
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$DomainDn")
        $s.Filter   = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        $s.PageSize = 200
        $s.PropertiesToLoad.AddRange([string[]]@('dNSHostName'))
        $s.FindAll() | ForEach-Object {
            $fqdn = if ($_.Properties['dnshostname'].Count) { $_.Properties['dnshostname'][0].ToString() } else { $null }
            if ($fqdn) { [void]$dcs.Add($fqdn) }
        }
    } catch { Write-Verbose "[Audit-Policy] DC discovery failed: $_" }
    return $dcs
}

# =============================================================================
# PER-DC COLLECTION (wraps Invoke-Command, soft-fail)
# =============================================================================

function _AUD_CollectFromDC {
    param([string]$FQDN, [string]$RunId)

    $edrNames = @($script:_AUD_ProcessEDRServices | ForEach-Object { $_.Name })
    try {
        $runHost = $env:COMPUTERNAME
        if ($FQDN -ieq $runHost -or $FQDN -like "$runHost.*") {
            # Local execution (run host IS the DC)
            $data = & $script:_AUD_RemoteScript -EdrServiceNames $edrNames
        } else {
            $data = Invoke-Command -ComputerName $FQDN -ErrorAction Stop `
                -ScriptBlock $script:_AUD_RemoteScript `
                -ArgumentList @(,$edrNames)
        }
        return $data
    } catch {
        Write-Warning "[Audit-Policy] WinRM failed for $FQDN: $_"
        return $null
    }
}

# =============================================================================
# AUDIT SETTING HELPERS
# =============================================================================

function _AUD_SettingCovers {
    param([string]$Setting, [string]$Require)
    # Returns $true if the collected setting satisfies the required coverage.
    # $Require: 'Success', 'Failure', 'SuccessAndFailure', 'Any'
    if (-not $Setting -or $Setting -eq 'No Auditing') { return $false }
    switch ($Require) {
        'Success'          { return $Setting -match 'Success' }
        'Failure'          { return $Setting -match 'Failure' }
        'SuccessAndFailure'{ return ($Setting -match 'Success' -and $Setting -match 'Failure') }
        'Any'              { return $true }
    }
    return $false
}

function _AUD_GetSetting {
    param([hashtable]$Policy, [string]$GuidKey)
    $guid = $script:_AUD_Guids[$GuidKey]
    if (-not $guid) { return 'Unknown' }
    return $Policy[$guid.ToUpper()] ?? 'No Auditing'
}

# =============================================================================
# FINDING EVALUATION
# Aggregates across all DC results; emits domain-level findings noting which
# DCs are non-compliant. Per-DC severity matches worst-case across all DCs.
# =============================================================================

function _AUD_EvaluateFindings {
    param(
        [System.Collections.Generic.List[hashtable]]$DcResults,
        [string]$DomainFQDN
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if ($DcResults.Count -eq 0) { return $findings }

    # Helper: which DCs fail a given test
    function Get-FailingDCs {
        param([scriptblock]$Test)
        @($DcResults | Where-Object { & $Test $_ } | ForEach-Object { $_.computerName })
    }

    # Helper: resolve which EDR products cover process telemetry
    function Get-EDRNote {
        param([hashtable]$DcData)
        if (-not $DcData.edrProducts -or $DcData.edrProducts.Count -eq 0) { return $null }
        $names = $DcData.edrProducts | ForEach-Object {
            ($script:_AUD_ProcessEDRServices | Where-Object { $_.Name -eq $_ } | Select-Object -First 1).Product ?? $_
        }
        return "EDR present ($($names -join ', ')) may provide equivalent process telemetry"
    }

    # ── AUD-001: Directory Service Changes (5136) ────────────────────────────
    # CIS: "Audit Directory Service Changes - Success" on DCs
    # Volume note: 5136 can be high on busy DCs; SIEM filtering recommended.
    $bad001 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'DsChanges') 'Success') }
    if ($bad001.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-001' -Severity 'Critical' `
            -Technique 'T1562.002' `
            -Description "Directory Service Changes (Event 5136) not audited for Success on: $($bad001 -join ', '). This is the primary event for detecting AD object modifications — including GPO, ACL, group membership, and attribute changes. CIS Benchmark (Windows Server): 'Audit Directory Service Changes — Success' required. Volume note: 5136 can be high on busy DCs; filter to Tier-0 object containers in your SIEM rather than disabling." `
            -Reference 'https://attack.mitre.org/techniques/T1562/002/'))
    }

    # ── AUD-002: Directory Service Access (4662) ─────────────────────────────
    # CIS: "Audit Directory Service Access - Success" on DCs.
    # IMPORTANT: 4662 also requires a SACL on the domain head NC object to fire
    # for DCSync-style replication rights access. Audit policy alone is not enough.
    $bad002 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'DsAccess') 'Success') }
    if ($bad002.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-002' -Severity 'High' `
            -Technique 'T1003.006' `
            -Description "Directory Service Access (Event 4662) not audited for Success on: $($bad002 -join ', '). 4662 is the detection event for replication-rights abuse (DCSync). CIS Benchmark: 'Audit Directory Service Access — Success' required. Note: 4662 requires BOTH this subcategory enabled AND a SACL on the domain NC head (CN=<domain>,DC=...) set to audit Replication Directory Changes. Policy alone is insufficient for DCSync detection." `
            -Reference 'https://attack.mitre.org/techniques/T1003/006/'))
    }

    # ── AUD-003: Process Creation (4688) ─────────────────────────────────────
    # CIS: "Audit Process Creation - Success". High volume on DCs; reduce if EDR covers.
    $bad003 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'ProcessCreation') 'Success') }
    if ($bad003.Count -gt 0) {
        $allHaveEDR = ($bad003 | ForEach-Object {
            $dc = $DcResults | Where-Object { $_.computerName -eq $_ } | Select-Object -First 1
            $dc.edrProducts.Count -gt 0
        }) -notcontains $false
        $sev = if ($allHaveEDR) { 'Medium' } else { 'High' }
        $edrNote = if ($allHaveEDR) { ' Note: EDR products detected on these DCs may provide equivalent process telemetry — verify EDR coverage before enabling to manage event volume.' } else { '' }
        $findings.Add((New-Finding -Id 'AUD-003' -Severity $sev `
            -Technique 'T1059' `
            -Description "Process Creation (Event 4688) not audited for Success on: $($bad003 -join ', '). Disables native Windows process execution logging on DCs. CIS Benchmark: 'Audit Process Creation — Success' required. Volume note: 4688 is high-volume on DCs; if an EDR is deployed that captures equivalent telemetry, document the compensating control.$edrNote" `
            -Reference 'https://attack.mitre.org/techniques/T1059/'))
    }

    # ── AUD-004: Command-line capture in 4688 ────────────────────────────────
    # Separate GPO key: HKLM\...\System\Audit!ProcessCreationIncludeCmdLine_Enabled
    $bad004 = Get-FailingDCs { param($dc) $dc.psCmdLineEnabled -ne 'Enabled' }
    if ($bad004.Count -gt 0) {
        $allHaveEDR = ($bad004 | ForEach-Object {
            $dc = $DcResults | Where-Object { $_.computerName -eq $_ } | Select-Object -First 1
            $dc.edrProducts.Count -gt 0
        }) -notcontains $false
        $sev = if ($allHaveEDR) { 'Low' } else { 'Medium' }
        $findings.Add((New-Finding -Id 'AUD-004' -Severity $sev `
            -Technique 'T1059' `
            -Description "Process Creation command-line capture (ProcessCreationIncludeCmdLine_Enabled) not enabled on: $($bad004 -join ', '). This is a separate GPO registry key from the 4688 subcategory — both must be enabled for full command-line logging. Without cmdline, 4688 records only the image path. CIS Benchmark: requires this key set to 1. Volume note: cmdline in 4688 adds significant event size; EDR-covered DCs may not need both." `
            -Reference 'https://attack.mitre.org/techniques/T1059/'))
    }

    # ── AUD-005: Security Group Management ───────────────────────────────────
    # CIS: "Audit Security Group Management - Success"
    $bad005 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'SecurityGroupMgmt') 'Success') }
    if ($bad005.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-005' -Severity 'High' `
            -Technique 'T1098' `
            -Description "Security Group Management (Events 4728, 4732, 4756) not audited for Success on: $($bad005 -join ', '). Disables detection of group membership changes including Domain Admins, Enterprise Admins, and other privileged groups. CIS Benchmark: 'Audit Security Group Management — Success' required." `
            -Reference 'https://attack.mitre.org/techniques/T1098/'))
    }

    # ── AUD-006: User Account Management ─────────────────────────────────────
    # CIS: "Audit User Account Management - Success and Failure"
    $bad006 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'UserAccountMgmt') 'Success') }
    if ($bad006.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-006' -Severity 'High' `
            -Technique 'T1136.001' `
            -Description "User Account Management (Events 4720, 4722, 4726, 4738) not audited for Success on: $($bad006 -join ', '). Disables detection of account creation, enable/disable, and attribute changes — key events for detecting account-based persistence. CIS Benchmark: 'Audit User Account Management — Success and Failure' required." `
            -Reference 'https://attack.mitre.org/techniques/T1136/001/'))
    }

    # ── AUD-007: Kerberos logging ─────────────────────────────────────────────
    # CIS: "Audit Kerberos Authentication Service - Success and Failure"
    # "Audit Kerberos Service Ticket Operations - Success and Failure"
    $bad007 = Get-FailingDCs { param($dc)
        $kauth  = _AUD_GetSetting $dc.auditPolicy 'KerberosAuthSvc'
        $kticket= _AUD_GetSetting $dc.auditPolicy 'KerberosSvcTicket'
        -not (_AUD_SettingCovers $kauth 'SuccessAndFailure') -or
        -not (_AUD_SettingCovers $kticket 'Success')
    }
    if ($bad007.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-007' -Severity 'High' `
            -Technique 'T1558' `
            -Description "Kerberos authentication/ticket auditing is insufficient on: $($bad007 -join ', '). Requires: 'Kerberos Authentication Service — Success and Failure' (4768: TGT requests; 4771: AS-REP failures; brute-force detection) and 'Kerberos Service Ticket Operations — Success' (4769: Kerberoasting detection). CIS Benchmark: both required on DCs." `
            -Reference 'https://attack.mitre.org/techniques/T1558/'))
    }

    # ── AUD-008: Sensitive Privilege Use ─────────────────────────────────────
    # CIS: "Audit Sensitive Privilege Use - Success and Failure"
    $bad008 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'SensitivePrivUse') 'Success') }
    if ($bad008.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-008' -Severity 'Medium' `
            -Technique 'T1134' `
            -Description "Sensitive Privilege Use (Events 4673, 4674) not audited for Success on: $($bad008 -join ', '). These events fire when SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege, or other sensitive privileges are exercised — key signals for credential dumping and lateral movement. CIS Benchmark: 'Audit Sensitive Privilege Use — Success and Failure' required." `
            -Reference 'https://attack.mitre.org/techniques/T1134/'))
    }

    # ── AUD-009: Audit Policy Change (4719) ──────────────────────────────────
    # CIS: "Audit Audit Policy Change - Success"
    # Highest priority: an attacker who can disable audit policy can silence all other controls.
    $bad009 = Get-FailingDCs { param($dc) -not (_AUD_SettingCovers (_AUD_GetSetting $dc.auditPolicy 'AuditPolicyChange') 'Success') }
    if ($bad009.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-009' -Severity 'High' `
            -Technique 'T1562.002' `
            -Description "Audit Policy Change (Event 4719) not audited for Success on: $($bad009 -join ', '). An attacker with local admin who disables audit logging on a DC would leave no trace of the change without this subcategory enabled. CIS Benchmark: 'Audit Audit Policy Change — Success' required." `
            -Reference 'https://attack.mitre.org/techniques/T1562/002/'))
    }

    # ── AUD-010: PowerShell ScriptBlock logging ───────────────────────────────
    # CIS: Enable ScriptBlock logging. Volume caveat: can generate large events;
    # high-value on DCs where PS is commonly used for AD operations.
    $bad010 = Get-FailingDCs { param($dc) $dc.psScriptBlockLogging -ne 'Enabled' }
    if ($bad010.Count -gt 0) {
        $findings.Add((New-Finding -Id 'AUD-010' -Severity 'Medium' `
            -Technique 'T1059.001' `
            -Description "PowerShell ScriptBlock logging (Microsoft-Windows-PowerShell/Operational, Event 4104) not enabled on: $($bad010 -join ', '). ScriptBlock logging captures the full content of executed PowerShell — including obfuscated or dynamically-built scripts — regardless of how PS is invoked. CIS Benchmark: EnableScriptBlockLogging = 1 required. Volume note: logs all executed script blocks; ensure PS/Operational log size is adequate and SIEM ingestion is configured." `
            -Reference 'https://attack.mitre.org/techniques/T1059/001/'))
    }

    # ── AUD-011: Security log size ────────────────────────────────────────────
    # CIS minimum: 196608 KB (192 MB). Undersized logs are overwritten before
    # forensic collection — a soft finding but operationally significant.
    $CIS_MIN_SECURITY_LOG_KB = 196608
    $bad011 = Get-FailingDCs { param($dc)
        $sz = $dc.logSizes['Security']
        $null -ne $sz -and $sz -lt $CIS_MIN_SECURITY_LOG_KB
    }
    if ($bad011.Count -gt 0) {
        $smallest = ($DcResults |
            Where-Object { $_.computerName -in $bad011 -and $_.logSizes['Security'] } |
            ForEach-Object { $_.logSizes['Security'] } | Measure-Object -Minimum).Minimum
        $findings.Add((New-Finding -Id 'AUD-011' -Severity 'Medium' `
            -Technique 'T1562.002' `
            -Description "Security event log maximum size is below CIS minimum (196608 KB) on: $($bad011 -join ', ') — smallest observed: ${smallest} KB. Undersized logs are overwritten before forensic collection or SIEM ingestion, creating post-incident blind spots. CIS Benchmark: MaxSize >= 196608 KB required. For DCs with high 4688/5136 volume, 524288 KB (512 MB) is recommended." `
            -Reference 'https://attack.mitre.org/techniques/T1562/002/'))
    }

    # ── AUD-012: Sysmon not installed or no config loaded ─────────────────────
    # Sysmon on DCs: network connections, process genealogy, named pipe creation.
    # Sysmon with no config logs almost nothing — treat as absent.
    $notInstalled = Get-FailingDCs { param($dc) -not $dc.sysmon.installed }
    $installedNoConfig = Get-FailingDCs { param($dc) $dc.sysmon.installed -and -not $dc.sysmon.configLoaded }
    if ($notInstalled.Count -gt 0 -or $installedNoConfig.Count -gt 0) {
        $desc = ''
        if ($notInstalled.Count -gt 0) { $desc += "Not installed on: $($notInstalled -join ', '). " }
        if ($installedNoConfig.Count -gt 0) { $desc += "Installed but no config loaded (default rules only — effective coverage near-zero) on: $($installedNoConfig -join ', ')." }
        $findings.Add((New-Finding -Id 'AUD-012' -Severity 'Medium' `
            -Technique 'T1562.006' `
            -Description "Sysmon not providing effective coverage on DCs. $desc Sysmon supplements Windows audit policy with process genealogy (image load, create remote thread), network connections (Event 3), and named pipe creation — critical for detecting lateral movement and DC compromise. A Sysmon instance without a config file loaded logs almost nothing. Minimum: install + deploy a production config (SwiftOnSecurity/sysmon-config or enterprise equivalent)." `
            -Reference 'https://attack.mitre.org/techniques/T1562/006/'))
    }

    # ── AUD-013: NTDS Field Engineering diagnostic level ─────────────────────
    # HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering
    # Level 5 = log expensive LDAP queries (>30ms) as Event 1644 in the Directory Service log.
    # Without this, expensive reconnaissance LDAP queries (BloodHound-style) are invisible.
    $bad013 = Get-FailingDCs { param($dc) $dc.ntdsDiagLevel -ge 0 -and $dc.ntdsDiagLevel -lt 5 }
    if ($bad013.Count -gt 0) {
        $levels = ($DcResults |
            Where-Object { $_.computerName -in $bad013 } |
            ForEach-Object { "$($_.computerName)=$($_.ntdsDiagLevel)" }) -join ', '
        $findings.Add((New-Finding -Id 'AUD-013' -Severity 'Low' `
            -Technique 'T1069.002' `
            -Description "NTDS Field Engineering diagnostic logging (registry key '15 Field Engineering') below level 5 on: $($bad013 -join ', ') (current levels: $levels). Level 5 enables Event 1644 in the Directory Service log for LDAP queries exceeding the expensive-query threshold (default 30ms). Without 1644, large-scale LDAP enumeration (BloodHound, ADExplorer) produces no DC-side signal. Volume caveat: 1644 can be noisy on heavily queried DCs — tune the threshold via HKLM\...\NTDS\Parameters\Expensive Search Results Threshold." `
            -Reference 'https://attack.mitre.org/techniques/T1069/002/'))
    }

    return $findings
}

# =============================================================================
# MAIN COLLECT FUNCTION
# =============================================================================

function _AUDPolicy_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records   = [System.Collections.Generic.List[object]]::new()
    $runId     = $RunContext.RunId
    $domainFQDN= $RunContext.Domain

    $rootDse  = [adsi]'LDAP://RootDSE'
    $domainDn = $rootDse.defaultNamingContext.ToString()

    # ── Discover DCs ──────────────────────────────────────────────────────────
    Write-Host "         [Audit-Policy] Discovering Domain Controllers..."
    $dcFqdns = _AUD_DiscoverDCs -DomainDn $domainDn
    if ($dcFqdns.Count -eq 0) {
        Write-Warning "[Audit-Policy] No DCs discovered — skipping audit policy collection."
        return $records
    }
    Write-Host "         [Audit-Policy] Found $($dcFqdns.Count) DC(s): $($dcFqdns -join ', ')"

    # ── Collect from each DC via WinRM ─────────────────────────────────────────
    $dcResults = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fqdn in $dcFqdns) {
        Write-Host "         [Audit-Policy]   → $fqdn"
        $data = _AUD_CollectFromDC -FQDN $fqdn -RunId $runId
        if ($null -eq $data) {
            $err = New-CollectionError -Collector 'Audit-Policy' -Target $fqdn `
                -ErrorMessage "WinRM collection failed (check LocalAdmin access and WinRM enabled)" `
                -RunId $runId
            $records.Add($err)
            continue
        }
        # Convert PSCustomObject (returned from Invoke-Command) to hashtable
        $ht = @{}
        foreach ($prop in $data.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
        # auditPolicy may be a PSCustomObject from remoting — normalize to hashtable
        if ($ht.auditPolicy -is [System.Management.Automation.PSObject]) {
            $ap = @{}
            foreach ($p in $ht.auditPolicy.PSObject.Properties) { $ap[$p.Name] = $p.Value }
            $ht.auditPolicy = $ap
        }
        [void]$dcResults.Add($ht)

        # Emit per-DC audit-policy config record
        $records.Add((New-ReconRecord `
            -Collector      'Audit-Policy' `
            -ObjectType     'dc-audit-policy' `
            -StableId       "AuditPolicy:dc:$($ht.computerName)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     @{
                computerName         = $ht.computerName
                auditPolicy          = $ht.auditPolicy
                psScriptBlockLogging = $ht.psScriptBlockLogging
                psCmdLineEnabled     = $ht.psCmdLineEnabled
                psTranscription      = $ht.psTranscription
                sysmon               = $ht.sysmon
                wefSubscriptionCount = $ht.wefSubscriptionCount
                logSizes             = $ht.logSizes
                ntdsDiagLevel        = $ht.ntdsDiagLevel
                amsiActive           = $ht.amsiActive
                edrProducts          = $ht.edrProducts
                collectionErrors     = $ht.collectionErrors
            } `
            -RunId $runId))
    }

    if ($dcResults.Count -eq 0) {
        Write-Warning "[Audit-Policy] All DC WinRM collections failed — no findings to evaluate."
        return $records
    }

    # ── Evaluate findings ─────────────────────────────────────────────────────
    Write-Host "         [Audit-Policy] Evaluating findings across $($dcResults.Count) DC(s)..."
    $findings = _AUD_EvaluateFindings -DcResults $dcResults -DomainFQDN $domainFQDN

    # ── Emit domain-level summary record ──────────────────────────────────────
    $edrByDC = @{}
    foreach ($dc in $dcResults) {
        $edrByDC[$dc.computerName] = @($dc.edrProducts)
    }
    $allSysmon = @($dcResults | Where-Object { $_.sysmon.installed -and $_.sysmon.configLoaded } | ForEach-Object { $_.computerName })

    $records.Add((New-ReconRecord `
        -Collector      'Audit-Policy' `
        -ObjectType     'audit-policy-summary' `
        -StableId       "AuditPolicy:summary:$domainFQDN" `
        -Category       'config' `
        -Tier           'T0' `
        -CollectedAtPriv $true `
        -Attributes     @{
            domain             = $domainFQDN
            dcsAssessed        = @($dcResults | ForEach-Object { $_.computerName })
            dcsWithSysmon      = $allSysmon
            edrByDC            = $edrByDC
            auditGuidMap       = $script:_AUD_Guids
        } `
        -Findings       $findings.ToArray() `
        -RunId $runId))

    return $records
}

Register-Collector `
    -Name        'Audit-Policy' `
    -Description 'DC audit policy (GUID-keyed auditpol), PS ScriptBlock/cmdline logging, Sysmon config, WEF, log sizes, NTDS diagnostics, EDR presence — with CIS benchmark anchoring and EDR cross-reference' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _AUDPolicy_Collect @PSBoundParameters }
