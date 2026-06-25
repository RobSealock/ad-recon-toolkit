# Host-Roles collector — Windows Server role/feature inventory with risky-role flagging.
# MinPrivilege: LocalAdmin
# Requires RunContext.OverrideTargets (set by Start-HostAssessment.ps1).
#
# Finding IDs:
#   ROLE-001  Risky server role installed (IIS, Print Services, RDS Session Host, WSUS, FSRM, Telnet)
#   ROLE-002  Risky optional feature enabled (SMBv1, Telnet client, TFTP, WSL, PS v2)

$script:_HostRoles_RiskyRoles = @(
    @{ Name='Web-Server';          Display='IIS (Web-Server)';   Severity='High';   Technique='T1190'
       Reason='Web application attack surface on a non-web-server. Common webshell deployment target.' }
    @{ Name='Print-Services';      Display='Print Services';     Severity='High';   Technique='T1187'
       Reason='Print Spooler (required by this role) is the coercion vector for PrinterBug and PrintNightmare (CVE-2021-1675). Remove unless a dedicated print server.' }
    @{ Name='RDS-RD-Server';       Display='RDS Session Host';   Severity='High';   Technique='T1078'
       Reason='Allows multiple concurrent RDP sessions. All logged-on user tokens and credentials reside in memory simultaneously — credential harvesting and session-pivoting risk.' }
    @{ Name='RDS-Licensing';       Display='RDS Licensing';      Severity='Medium'; Technique='T1078'
       Reason='Unnecessary unless this is a dedicated RD licensing server. Unexplained presence warrants review.' }
    @{ Name='WSUS-Services';       Display='WSUS';               Severity='Medium'; Technique='T1072'
       Reason='WSUS approval rights enable domain-wide code execution via malicious update push. Verify this is the intended WSUS server and review who holds approval rights.' }
    @{ Name='FS-Resource-Manager'; Display='FSRM';               Severity='Medium'; Technique='T1574'
       Reason='FSRM email-notification DLL loading can be abused for DLL side-load privilege escalation. Remove unless actively managing file quotas or screens.' }
    @{ Name='Fax';                 Display='Fax Server';         Severity='Low';    Technique='T1210'
       Reason='Legacy service, unnecessary attack surface on modern infrastructure.' }
    @{ Name='Telnet-Server';       Display='Telnet Server';      Severity='High';   Technique='T1021'
       Reason='Telnet transmits credentials and session data in plaintext. No legitimate use case on modern infrastructure.' }
)

$script:_HostRoles_RiskyFeatures = @(
    @{ Name='FS-SMB1';                              Display='SMB1 (FS-SMB1)';    Severity='Critical'; Technique='T1210'
       Reason='SMBv1 enables EternalBlue (MS17-010). Remove: Remove-WindowsFeature FS-SMB1' }
    @{ Name='SMB1Protocol';                         Display='SMB1 Protocol';     Severity='Critical'; Technique='T1210'
       Reason='SMBv1 enabled. Disable: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' }
    @{ Name='TelnetClient';                         Display='Telnet Client';      Severity='Medium';   Technique='T1105'
       Reason='LOL binary for unauthenticated file transfer. Not required on servers.' }
    @{ Name='TFTP';                                 Display='TFTP Client';        Severity='Medium';   Technique='T1105'
       Reason='LOL binary for unauthenticated file transfer. Commonly used for payload download in post-exploitation.' }
    @{ Name='Microsoft-Windows-Subsystem-Linux';    Display='WSL';               Severity='Medium';   Technique='T1202'
       Reason='Provides a Linux environment that bypasses Windows security controls (AMSI, Defender behavioral, AppLocker). Unusual on a server.' }
    @{ Name='MicrosoftWindowsPowerShellV2Root';     Display='PowerShell v2';     Severity='Medium';   Technique='T1059'
       Reason='PowerShell v2 bypasses ScriptBlock logging and AMSI. Remove: Remove-WindowsFeature PowerShell-V2 (server) or Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (client).' }
    @{ Name='PowerShell-V2';                        Display='PowerShell v2';     Severity='Medium';   Technique='T1059'
       Reason='PowerShell v2 bypasses ScriptBlock logging and AMSI. Remove: Remove-WindowsFeature PowerShell-V2' }
)

# =============================================================================
# REMOTE-SAFE COLLECTION SCRIPTBLOCK
# =============================================================================

$script:_HostRoles_Script = {
    $r = @{ sections = @{}; errors = [System.Collections.Generic.List[string]]::new() }

    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $installed = @(Get-WindowsFeature -ErrorAction Stop |
                Where-Object { $_.InstallState -in @('Installed','InstallPending') })
            $r.sections.isServerOS       = $true
            $r.sections.installedRoles   = @($installed | ForEach-Object {
                @{ name=$_.Name; displayName=$_.DisplayName; depth=[int]$_.Depth }
            })
            $r.sections.installedFeatures = @()
        } else {
            $enabled = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                Where-Object { $_.State -in @('Enabled','EnablePending') })
            $r.sections.isServerOS        = $false
            $r.sections.installedRoles    = @()
            $r.sections.installedFeatures = @($enabled | ForEach-Object {
                @{ name=$_.FeatureName; state=$_.State.ToString() }
            })
        }
    } catch { $r.errors.Add("roles: $_"); $r.sections.installedRoles = @(); $r.sections.installedFeatures = @() }

    return $r
}

# =============================================================================
# FINDING EVALUATION
# =============================================================================

function _HostRoles_EvaluateFindings {
    param([hashtable]$Raw, [hashtable]$Target, [array]$RiskyRoles, [array]$RiskyFeatures)

    $findings = [System.Collections.Generic.List[object]]::new()
    $s        = $Raw.sections
    $hostName = $Target.FQDN

    $installedNames = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)

    $roleList    = if ($s.PSObject.Properties['installedRoles'])    { $s.installedRoles    } else { @() }
    $featureList = if ($s.PSObject.Properties['installedFeatures']) { $s.installedFeatures } else { @() }
    $isServer    = if ($s.PSObject.Properties['isServerOS'])        { $s.isServerOS        } else { $false }

    foreach ($item in @($roleList) + @($featureList)) {
        $n = if ($item -is [hashtable]) { $item['name'] } else { $item.name }
        if ($n) { [void]$installedNames.Add($n) }
    }

    if ($isServer) {
        foreach ($role in $RiskyRoles) {
            if ($installedNames.Contains($role.Name)) {
                $findings.Add((New-Finding -Id 'ROLE-001' -Severity $role.Severity `
                    -Technique $role.Technique `
                    -Description "$($role.Display) is installed on $hostName. $($role.Reason)" `
                    -Reference "https://attack.mitre.org/techniques/$($role.Technique)/"))
            }
        }
    }

    foreach ($feat in $RiskyFeatures) {
        if ($installedNames.Contains($feat.Name)) {
            $findings.Add((New-Finding -Id 'ROLE-002' -Severity $feat.Severity `
                -Technique $feat.Technique `
                -Description "$($feat.Display) is $(if ($isServer) { 'installed' } else { 'enabled' }) on $hostName. $($feat.Reason)" `
                -Reference "https://attack.mitre.org/techniques/$($feat.Technique)/"))
        }
    }

    return ,$findings
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _HostRoles_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId

    $overrideProp = $RunContext.PSObject.Properties['OverrideTargets']
    if (-not $overrideProp -or -not $overrideProp.Value) {
        $records.Add((New-CollectionError -Collector 'Host-Roles' -Target 'RunContext' `
            -ErrorMessage 'Host-Roles requires RunContext.OverrideTargets. Run via Start-HostAssessment.ps1.' `
            -RunId $runId))
        return $records
    }
    $targets = @($overrideProp.Value)
    Write-Host "         $($targets.Count) target(s) for Host-Roles scan"

    foreach ($target in $targets) {
        $fqdn = $target.FQDN
        Write-Host "         Scanning $fqdn"

        $raw = $null
        try {
            if ($fqdn -ieq $env:COMPUTERNAME -or $fqdn -ieq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") {
                $raw = & $script:_HostRoles_Script
            } else {
                $icParams = @{ ComputerName=$fqdn; ScriptBlock=$script:_HostRoles_Script; ErrorAction='Stop' }
                $cred = Get-RemoteCredential
                if ($cred) { $icParams.Credential = $cred }
                $raw = Invoke-Command @icParams
            }
        } catch {
            $records.Add((New-CollectionError -Collector 'Host-Roles' `
                -Target $fqdn -ErrorMessage $_.ToString() -RunId $runId))
            continue
        }

        if ($raw.errors -and $raw.errors.Count -gt 0) {
            Write-Warning "  [Host-Roles] $fqdn — $($raw.errors -join '; ')"
        }

        $findings = _HostRoles_EvaluateFindings -Raw $raw -Target $target `
            -RiskyRoles $script:_HostRoles_RiskyRoles `
            -RiskyFeatures $script:_HostRoles_RiskyFeatures

        $records.Add((New-ReconRecord `
            -Collector      'Host-Roles' `
            -ObjectType     'os-roles' `
            -StableId       "HostRoles:$fqdn" `
            -Category       'config' `
            -Tier           $target.Tier `
            -CollectedAtPriv $true `
            -Attributes     @{
                fqdn             = $fqdn
                isServerOS       = $raw.sections.isServerOS
                installedRoles   = $raw.sections.installedRoles
                installedFeatures= $raw.sections.installedFeatures
                roleCount        = if ($raw.sections.installedRoles)    { $raw.sections.installedRoles.Count    } else { 0 }
                featureCount     = if ($raw.sections.installedFeatures) { $raw.sections.installedFeatures.Count } else { 0 }
            } `
            -Findings  $findings.ToArray() `
            -RunId     $runId))
    }

    return $records
}

Register-Collector `
    -Name        'Host-Roles' `
    -Description 'Windows Server role and optional feature inventory with risky-role flagging. Host-assessment mode only (requires RunContext.OverrideTargets from Start-HostAssessment.ps1). Findings: ROLE-001 (risky server role), ROLE-002 (risky optional feature).' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _HostRoles_Collect @PSBoundParameters }
