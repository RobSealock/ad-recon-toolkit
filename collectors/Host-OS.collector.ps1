# Host-OS collector — per-server OS posture for DCs and AD-role servers.
# MinPrivilege: LocalAdmin
#
# Target discovery (automatic):
#   DCs          — LDAP (userAccountControl SERVER_TRUST_ACCOUNT bit)
#   CA hosts     — CN=Enrollment Services in the Configuration partition
#   DNS servers  — DCs carry DNS; additional DNS-only servers flagged if found
#   DHCP servers — CN=NetServices in the Configuration partition
#   Additional   — config\targets.psd1 (optional, workstation extension)
#
# Execution model:
#   Remote — Invoke-Command via WinRM (preferred)
#   Local  — direct scriptblock invoke when target == run host
#   Soft-fail per target — CollectionError record, run continues
#
# Findings emitted:
#   HOST-001  Unexpected role installed on DC
#   HOST-002  Service running as a domain-privileged account
#   HOST-003  Unquoted service binary path (privilege escalation)
#   HOST-004  Print Spooler running on DC (PrinterBug / PrintNightmare)
#   HOST-005  WebClient (WebDAV) running — ESC8 / NTLM relay enabler
#   HOST-006  SMBv1 enabled
#   HOST-007  RDP enabled without Network Level Authentication
#   HOST-008  LSA Protection (RunAsPPL) not enabled
#   HOST-009  WDigest credential caching enabled (plaintext creds in LSASS)
#   HOST-010  LAPS not deployed on this host
#   HOST-011  LDAP signing not required (DC only)
#   HOST-012  SMB signing not required
#   HOST-013  LLMNR or NBT-NS enabled
#   HOST-014  Local Administrator account enabled with stale password (>90 days)
#   HOST-015  SMB share accessible by Everyone / Authenticated Users (write)
#   HOST-016  Scheduled task running as domain-privileged identity
#   HOST-017  DSRM admin logon behavior not restricted (value >= 1 on DC)
#   HOST-018  EFS service running on DC (PetitPotam / MS-EFSRPC coercion surface)
#   HOST-019  DFS Namespace service on DC (DFSCoerce / MS-DFSNM coercion surface)
#   HOST-020  ESC10 — StrongCertificateBindingEnforcement not at full enforcement on DC
#   HOST-021  NTLMv1/LM authentication enabled (LmCompatibilityLevel < 5)
#   HOST-022  Credential Guard not enabled
#   HOST-023  PowerShell v2 not removed (bypasses ScriptBlock logging)
#   HOST-024  LDAP channel binding not required (DC only)
#   HOST-025  WinRM HTTP unencrypted allowed
#   HOST-026  Remote Registry service running on DC
#   HOST-027  BitLocker not enabled on DC volumes (DC only)
#   HOST-028  IPv6 active without management controls (mitm6 attack surface)
#   HOST-029  SMB client signing not required (LanmanWorkstation)
#   HOST-030  Cached domain credentials allowed on DC (CachedLogonsCount > 0)
#   HOST-031  Netlogon secure channel signing/sealing not enforced
#   HOST-032  No recent AD backup detected on DC (>30 days)

# ── Roles considered unexpected on a Domain Controller ───────────────────────
$script:_HostOS_UnexpectedDCRoles = @(
    'Web-Server'             # IIS
    'FS-Resource-Manager'    # File Server Resource Manager
    'Print-Services'         # Print Services role (Spooler checked separately)
    'RDS-RD-Server'          # Remote Desktop Session Host
    'RDS-Licensing'          # RD Licensing
    'WSUS-Services'          # Windows Server Update Services
    'Application-Server'     # COM+ / IIS hosting
    'Fax'                    # Fax Server
    'Telnet-Server'          # Telnet (deprecated)
)

# ── Identities that are NOT flagged for HOST-002 (expected service accounts) ──
$script:_HostOS_SafeServiceAccounts = @(
    'LocalSystem','NT AUTHORITY\SYSTEM',
    'LocalService','NT AUTHORITY\LOCAL SERVICE',
    'NetworkService','NT AUTHORITY\NETWORK SERVICE',
    'NT SERVICE\*'
)

# =============================================================================
# TARGET DISCOVERY
# =============================================================================

function _HostOS_DiscoverTargets {
    param([string]$DomainDn, [string]$ConfigDn, [string]$TargetsFile)

    $seen    = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    $targets = [System.Collections.Generic.List[hashtable]]::new()

    function Add-Target {
        param([string]$FQDN, [string]$Name, [string[]]$Roles, [string]$Tier)
        if ($FQDN -and $seen.Add($FQDN)) {
            $targets.Add(@{ FQDN=$FQDN; Name=$Name; Roles=$Roles; Tier=$Tier })
        }
    }

    # Domain Controllers
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$DomainDn"))
        $s.Filter   = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        $s.PageSize = 200
        $s.PropertiesToLoad.AddRange([string[]]@('dNSHostName','cn'))
        $s.FindAll() | ForEach-Object {
            $fqdn = if ($_.Properties['dnshostname'].Count) { $_.Properties['dnshostname'][0].ToString() } else { $null }
            $name = if ($_.Properties['cn'].Count)          { $_.Properties['cn'][0].ToString()          } else { $fqdn }
            Add-Target -FQDN $fqdn -Name $name -Roles @('DomainController') -Tier 'T0'
        }
    } catch { Write-Verbose "[Host-OS] DC discovery failed: $_" }

    # CA hosts (Enrollment Services)
    try {
        $caDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDn"
        $s    = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$caDn"))
        $s.Filter      = '(objectClass=pKIEnrollmentService)'
        $s.SearchScope = 'OneLevel'
        $s.PropertiesToLoad.AddRange([string[]]@('dNSHostName','cn'))
        $s.FindAll() | ForEach-Object {
            $fqdn = if ($_.Properties['dnshostname'].Count) { $_.Properties['dnshostname'][0].ToString() } else { $null }
            $name = if ($_.Properties['cn'].Count)          { $_.Properties['cn'][0].ToString()          } else { $fqdn }
            if ($seen.Contains($fqdn)) {
                # Already a DC — add CA role
                $t = $targets | Where-Object { $_.FQDN -ieq $fqdn }
                if ($t) { $t.Roles = @($t.Roles) + 'CertificationAuthority' }
            } else {
                Add-Target -FQDN $fqdn -Name $name -Roles @('CertificationAuthority') -Tier 'T0'
            }
        }
    } catch { Write-Verbose "[Host-OS] CA discovery failed: $_" }

    # DHCP servers (authorized servers in NetServices)
    try {
        $dhcpDn = "CN=NetServices,CN=Services,$ConfigDn"
        $s      = New-Object System.DirectoryServices.DirectorySearcher((New-AdsiEntry "LDAP://$dhcpDn"))
        $s.Filter      = '(objectClass=dhcpClass)'
        $s.SearchScope = 'OneLevel'
        $s.PropertiesToLoad.AddRange([string[]]@('cn'))
        $s.FindAll() | ForEach-Object {
            # cn is the FQDN of the authorized DHCP server
            $fqdn = $_.Properties['cn'][0].ToString()
            $name = ($fqdn -split '\.')[0]
            if ($seen.Contains($fqdn)) {
                $t = $targets | Where-Object { $_.FQDN -ieq $fqdn }
                if ($t) { $t.Roles = @($t.Roles) + 'DHCPServer' }
            } else {
                Add-Target -FQDN $fqdn -Name $name -Roles @('DHCPServer') -Tier 'T1'
            }
        }
    } catch { Write-Verbose "[Host-OS] DHCP server discovery failed: $_" }

    # Additional targets from targets.psd1
    if ($TargetsFile -and (Test-Path $TargetsFile)) {
        try {
            $extra = Import-PowerShellDataFile $TargetsFile
            foreach ($h in $extra.AdditionalHosts) {
                Add-Target -FQDN $h.FQDN -Name $h.Name -Roles @($h.Role) -Tier $h.Tier
            }
        } catch { Write-Verbose "[Host-OS] targets.psd1 load failed: $_" }
    }

    return ,$targets
}

# =============================================================================
# REMOTE-SAFE COLLECTION SCRIPTBLOCK
# Self-contained — no external function dependencies.
# Returns a hashtable of raw data; normalized to ReconRecords on the caller side.
# =============================================================================

$script:_HostOS_Script = {
    $r = @{ sections = @{}; errors = [System.Collections.Generic.List[string]]::new() }

    # OS and patch state
    try {
        $os  = Get-CimInstance Win32_OperatingSystem  -ErrorAction Stop
        $cs  = Get-CimInstance Win32_ComputerSystem   -ErrorAction Stop
        $pendingReboot = $false
        $rebootSources = @()
        @{
            WU  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            CBS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        }.GetEnumerator() | ForEach-Object {
            if (Test-Path $_.Value) { $pendingReboot = $true; $rebootSources += $_.Key }
        }
        if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) {
            $pendingReboot = $true; $rebootSources += 'FileRename'
        }
        $r.sections.os = @{
            caption       = $os.Caption
            version       = $os.Version
            buildNumber   = $os.BuildNumber.ToString()
            installDate   = $os.InstallDate.ToString('o')
            lastBoot      = $os.LastBootUpTime.ToString('o')
            totalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            pendingReboot = $pendingReboot
            rebootSources = $rebootSources
        }
    } catch { $r.errors.Add("os: $_") }

    # Windows roles and features (Server only)
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $installed = Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.InstallState -eq 'Installed' }
            $r.sections.roles = @($installed | Select-Object -ExpandProperty Name)
        } else {
            $r.sections.roles = @('_CLIENT_OS')
        }
    } catch { $r.errors.Add("roles: $_"); $r.sections.roles = @() }

    # Services
    try {
        $r.sections.services = @(
            Get-CimInstance Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
            ForEach-Object {
                @{
                    name        = $_.Name
                    displayName = $_.DisplayName
                    state       = $_.State
                    startMode   = $_.StartMode
                    startName   = $_.StartName
                    pathName    = $_.PathName
                }
            }
        )
    } catch { $r.errors.Add("services: $_"); $r.sections.services = @() }

    # Installed software (registry uninstall keys)
    try {
        $sw = foreach ($p in @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
            Get-ItemProperty $p -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
        $r.sections.software = @(
            $sw | Sort-Object DisplayName -Unique | ForEach-Object {
                @{ name=$_.DisplayName; version=$_.DisplayVersion; publisher=$_.Publisher; installDate=$_.InstallDate }
            }
        )
    } catch { $r.errors.Add("software: $_"); $r.sections.software = @() }

    # SMB shares and permissions
    try {
        $r.sections.shares = @(
            Get-SmbShare -ErrorAction Stop | ForEach-Object {
                $access = @(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue |
                    ForEach-Object { @{ account=$_.AccountName; rights=$_.AccessRight.ToString(); type=$_.AccessControlType.ToString() } })
                @{ name=$_.Name; path=$_.Path; description=$_.Description; access=$access }
            }
        )
    } catch { $r.errors.Add("shares: $_"); $r.sections.shares = @() }

    # Local group membership
    try {
        $r.sections.localGroups = @{}
        foreach ($grp in @('Administrators','Remote Desktop Users','Remote Management Users','Backup Operators')) {
            try {
                $r.sections.localGroups[$grp] = @(
                    Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue |
                    ForEach-Object { @{ name=$_.Name; type=$_.ObjectClass; source=$_.PrincipalSource.ToString() } }
                )
            } catch { $r.sections.localGroups[$grp] = @() }
        }
    } catch { $r.errors.Add("localGroups: $_") }

    # Scheduled tasks (non-Microsoft namespace)
    try {
        $r.sections.scheduledTasks = @(
            Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            ForEach-Object {
                $info   = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                $action = $_.Actions | Select-Object -First 1
                @{
                    name      = $_.TaskName
                    path      = $_.TaskPath
                    state     = $_.State.ToString()
                    runAs     = $_.Principal.UserId
                    runLevel  = $_.Principal.RunLevel.ToString()
                    lastRun   = if ($info -and $info.LastRunTime) { $info.LastRunTime.ToString('o') } else { '' }
                    execute   = if ($action) { $action.Execute } else { '' }
                    arguments = if ($action) { $action.Arguments } else { '' }
                }
            }
        )
    } catch { $r.errors.Add("scheduledTasks: $_"); $r.sections.scheduledTasks = @() }

    # Hotfixes
    try {
        $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
        $r.sections.hotfixes = @{
            total  = $hf.Count
            latest = @($hf | Select-Object -First 20 | ForEach-Object {
                @{ id=$_.HotFixID; description=$_.Description; installedOn=if ($_.InstalledOn){$_.InstalledOn.ToString('o')}else{''} }
            })
        }
    } catch { $r.errors.Add("hotfixes: $_"); $r.sections.hotfixes = @{ total=0; latest=@() } }

    # Security configuration flags (registry + service state)
    try {
        $f = @{}
        $rp = 'Get-ItemProperty'

        # SMBv1
        $smb1val = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -EA SilentlyContinue).SMB1
        $f.smb1Enabled = if ($null -eq $smb1val) { $true } else { $smb1val -ne 0 }

        # RDP
        $rdpDeny = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
        $f.rdpEnabled = ($rdpDeny -eq 0)

        # NLA
        $nla = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthenticationRequired -EA SilentlyContinue).UserAuthenticationRequired
        $f.rdpNLARequired = ($nla -eq 1)

        # LSA Protection (RunAsPPL)
        $ppl = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
        $f.lsaRunAsPPL = ($ppl -ge 1)

        # Credential Guard
        $vbs  = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -EA SilentlyContinue).EnableVirtualizationBasedSecurity
        $cgfl = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name LsaCfgFlags -EA SilentlyContinue).LsaCfgFlags
        $f.credentialGuardEnabled = ($vbs -eq 1 -and $cgfl -ge 1)

        # WDigest
        $wdig = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential
        $f.wdigestCaching = ($wdig -eq 1)

        # LAPS
        $f.lapsV1     = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
        $f.lapsV2     = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        $f.lapsVersion = if ($f.lapsV2) { 'v2' } elseif ($f.lapsV1) { 'v1' } else { 'none' }

        # LLMNR
        $llmnr = (& $rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -EA SilentlyContinue).EnableMulticast
        $f.llmnrEnabled = ($null -eq $llmnr -or $llmnr -ne 0)

        # NBT-NS (per adapter)
        $f.nbtNSEnabled = [bool](Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -EA SilentlyContinue |
            Where-Object { $_.TcpipNetbiosOptions -ne 2 } | Select-Object -First 1)

        # LDAP signing (DC-specific registry key)
        $ldapSign = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -EA SilentlyContinue).LDAPServerIntegrity
        $f.ldapSigning         = if ($null -eq $ldapSign) { 1 } else { [int]$ldapSign }
        $f.ldapSigningRequired = ($f.ldapSigning -ge 2)

        # SMB signing
        $smbSign = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -EA SilentlyContinue).RequireSecuritySignature
        $f.smbSigningRequired = ($smbSign -eq 1)

        # Key service states
        $f.printSpoolerRunning = [bool](Get-Service Spooler  -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
        $f.webClientRunning    = [bool](Get-Service WebClient -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' })

        # DSRM admin logon behavior (DC-specific registry key)
        # 0 = DSRM account can only log in when DC is in DSRM (safe default)
        # 1 = DSRM account can log in when DC AD services are stopped
        # 2 = DSRM account can always log in over the network (unsafe)
        $dsrm = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior -EA SilentlyContinue).DsrmAdminLogonBehavior
        $f.dsrmLogonBehavior = if ($null -eq $dsrm) { 0 } else { [int]$dsrm }

        # EFS service state (MS-EFSRPC coercion surface — PetitPotam)
        $efsSvc = Get-Service 'EFS' -EA SilentlyContinue
        $f.efsServiceRunning = [bool]($efsSvc -and $efsSvc.Status -eq 'Running')

        # DFS Namespace service state (DFSCoerce coercion surface)
        $dfsSvc = Get-Service 'Dfs' -EA SilentlyContinue
        $f.dfsNamespaceRunning = [bool]($dfsSvc -and $dfsSvc.Status -eq 'Running')

        # ESC10: Strong certificate binding enforcement (DC KDC registry key)
        # 0 = disabled, 1 = compatibility/audit only, 2 = full enforcement (required Feb 2025+)
        # Absent = pre-patch behavior (treated as 1 — still exploitable by ESC6/9/10)
        $kdcEnf = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -EA SilentlyContinue).StrongCertificateBindingEnforcement
        $f.kcbEnforcement = if ($null -eq $kdcEnf) { -1 } else { [int]$kdcEnf }

        # ESC10: Schannel certificate mapping methods (UPN bit 0x4 indicates weak mapping allowed)
        $schMapping = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -Name CertificateMappingMethods -EA SilentlyContinue).CertificateMappingMethods
        $f.schannelCertMappingMethods = if ($null -eq $schMapping) { -1 } else { [int]$schMapping }

        # NTLM LmCompatibilityLevel (controls LM/NTLMv1/NTLMv2 acceptance)
        # 0-4 = allow NTLMv1 or LM; 5 = NTLMv2 only + refuse LM/NTLMv1 (best practice)
        $lmCompat = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel
        $f.lmCompatibilityLevel = if ($null -eq $lmCompat) { 3 } else { [int]$lmCompat }

        # LDAP channel binding (enforced separately from LDAP signing)
        # 0 = never, 1 = if supported, 2 = always (required for full LDAP relay protection)
        $lcb = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -EA SilentlyContinue).LdapEnforceChannelBinding
        $f.ldapChannelBinding = if ($null -eq $lcb) { 0 } else { [int]$lcb }

        # WinRM unencrypted traffic allowed (HTTP without HTTPS)
        $winrmUnenc = (& $rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencrypted -EA SilentlyContinue).AllowUnencrypted
        $f.winrmAllowUnencrypted = ($winrmUnenc -eq 1)

        # PowerShell v2 presence (enables ScriptBlock logging bypass)
        $psv2feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -EA SilentlyContinue
        if (-not $psv2feature) {
            # Server OS — use Get-WindowsFeature
            $psv2feature = Get-WindowsFeature -Name 'PowerShell-V2' -EA SilentlyContinue
        }
        $f.psV2Present = ($null -ne $psv2feature -and $psv2feature.State -in @('Enabled','Installed','InstallPending'))

        # Remote Registry service
        $remReg = Get-Service 'RemoteRegistry' -EA SilentlyContinue
        $f.remoteRegistryRunning = ($remReg -and $remReg.Status -eq 'Running')

        # BitLocker on OS volume (DC only check — use manage-bde or Get-BitLockerVolume)
        $f.bitlockerOsVolumeProtected = $false
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -EA SilentlyContinue
            $f.bitlockerOsVolumeProtected = ($bl -and $bl.VolumeStatus -eq 'FullyEncrypted' -and $bl.ProtectionStatus -eq 'On')
        } catch {}

        # SMB client signing (LanmanWorkstation — distinct from server-side LanmanServer check)
        $smbCli = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -EA SilentlyContinue).RequireSecuritySignature
        $f.smbClientSigningRequired = ($smbCli -eq 1)

        # IPv6 DisabledComponents bitmask; 0 or absent = IPv6 fully enabled
        $ipv6dc = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -EA SilentlyContinue).DisabledComponents
        $f.ipv6DisabledComponents = if ($null -eq $ipv6dc) { 0 } else { [int]$ipv6dc }
        $f.ipv6FullyDisabled = (($f.ipv6DisabledComponents -band 0xFF) -eq 0xFF)

        # Cached domain credential count (DCs should be 0)
        $cacheVal = (& $rp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -EA SilentlyContinue).CachedLogonsCount
        $f.cachedLogonsCount = if ($null -eq $cacheVal) { 10 } else { try { [int]$cacheVal } catch { 10 } }

        # Netlogon secure channel (Zerologon hardening)
        $reqSign = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name RequireSignOrSeal -EA SilentlyContinue).RequireSignOrSeal
        $sealSC  = (& $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name SealSecureChannel -EA SilentlyContinue).SealSecureChannel
        $f.netlogonRequireSignOrSeal = ($reqSign -eq 1)
        $f.netlogonSealSecureChannel = ($sealSC  -eq 1)

        # AD backup recency (Windows Server Backup event log or VSS shadow copy)
        $f.backupInfo = @{ method='none'; lastBackupDate=''; daysSinceBackup=-1 }
        try {
            $wbSvc = Get-Service 'wbengine' -EA SilentlyContinue
            if ($wbSvc) {
                $bkEvt = Get-WinEvent -LogName 'Microsoft-Windows-Backup' -EA SilentlyContinue |
                    Where-Object { $_.Id -eq 4 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($bkEvt) {
                    $f.backupInfo = @{
                        method         = 'WBS'
                        lastBackupDate = $bkEvt.TimeCreated.ToString('o')
                        daysSinceBackup= [int]((Get-Date) - $bkEvt.TimeCreated).TotalDays
                    }
                } else { $f.backupInfo = @{ method='WBS-no-jobs'; lastBackupDate=''; daysSinceBackup=-1 } }
            } else {
                $shadows = Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue |
                    Where-Object { $_.VolumeName -like "$env:SystemDrive*" }
                if ($shadows) {
                    $latest = $shadows |
                        Sort-Object { [Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate) } -Descending |
                        Select-Object -First 1
                    $ts = [Management.ManagementDateTimeConverter]::ToDateTime($latest.InstallDate)
                    $f.backupInfo = @{
                        method         = 'VSS'
                        lastBackupDate = $ts.ToString('o')
                        daysSinceBackup= [int]((Get-Date) - $ts).TotalDays
                    }
                }
            }
        } catch {}

        # Local Administrator account
        $la = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        $f.localAdminEnabled        = if ($la) { [bool]$la.Enabled } else { $false }
        $f.localAdminPwdLastSet     = if ($la -and $la.PasswordLastSet) { $la.PasswordLastSet.ToString('o') } else { '' }
        $f.localAdminPwdAgeDays     = if ($la -and $la.PasswordLastSet) { [int]((Get-Date) - $la.PasswordLastSet).TotalDays } else { -1 }

        $r.sections.securityFlags = $f
    } catch { $r.errors.Add("securityFlags: $_"); $r.sections.securityFlags = @{} }

    return $r
}

# =============================================================================
# FINDING EVALUATION (runs locally on normalized data)
# =============================================================================

function _HostOS_EvaluateFindings {
    param([hashtable]$Raw, [hashtable]$Target)

    $findings = [System.Collections.Generic.List[object]]::new()
    $s        = $Raw.sections
    $host     = $Target.FQDN
    $isDC     = $Target.Roles -contains 'DomainController'

    # HOST-001 Unexpected roles on DC
    if ($isDC -and $s.roles -and $s.roles -notcontains '_CLIENT_OS') {
        foreach ($role in $script:_HostOS_UnexpectedDCRoles) {
            if ($s.roles -contains $role) {
                $findings.Add((New-Finding -Id 'HOST-001' -Severity 'High' `
                    -Technique 'T1072' `
                    -Description "Unexpected role '$role' is installed on DC $host. DCs should have only AD DS, DNS, and minimal required roles." `
                    -Reference 'https://attack.mitre.org/techniques/T1072/'))
            }
        }
    }

    # HOST-002 Services running as domain accounts
    if ($s.services) {
        foreach ($svc in $s.services | Where-Object { $_.state -eq 'Running' }) {
            $account = $svc.startName
            if (-not $account) { continue }
            $isSafe  = $false
            foreach ($pattern in $script:_HostOS_SafeServiceAccounts) {
                if ($account -like $pattern) { $isSafe = $true; break }
            }
            if (-not $isSafe -and $account -match '\\') {
                $findings.Add((New-Finding -Id 'HOST-002' -Severity 'Medium' `
                    -Technique 'T1543.003' `
                    -Description "Service '$($svc.name)' on $host runs as '$account' (domain account). If this account has elevated AD privileges it is a lateral-movement risk. Cross-reference with AD service account inventory." `
                    -Reference 'https://attack.mitre.org/techniques/T1543/003/'))
            }
        }
    }

    # HOST-003 Unquoted service binary paths
    if ($s.services) {
        foreach ($svc in $s.services) {
            $path = $svc.pathName
            if ($path -and -not $path.TrimStart().StartsWith('"') -and $path -match '\s') {
                # Strip known benign Windows paths
                if ($path -notmatch '(?i)^(C:\\Windows\\|C:\\Program Files\\Windows )') {
                    $findings.Add((New-Finding -Id 'HOST-003' -Severity 'Medium' `
                        -Technique 'T1574.009' `
                        -Description "Service '$($svc.name)' on $host has an unquoted binary path containing spaces: '$path'. An attacker with write access to an intermediate directory can plant a malicious executable." `
                        -Reference 'https://attack.mitre.org/techniques/T1574/009/'))
                }
            }
        }
    }

    # Security flags — check only if section populated
    $fl = $s.securityFlags
    if ($fl -and $fl.Count -gt 0) {

        # HOST-004 Print Spooler on DC
        if ($isDC -and $fl.printSpoolerRunning) {
            $findings.Add((New-Finding -Id 'HOST-004' -Severity 'High' `
                -Technique 'T1187' `
                -Description "Print Spooler service is RUNNING on DC $host. Exposes PrinterBug (SpoolSample) coercion — an attacker can force the DC to authenticate to an arbitrary host, enabling credential relay or unconstrained delegation abuse." `
                -Reference 'https://attack.mitre.org/techniques/T1187/'))
        }

        # HOST-005 WebClient on DC
        if ($fl.webClientRunning) {
            $findings.Add((New-Finding -Id 'HOST-005' -Severity 'High' `
                -Technique 'T1187' `
                -Description "WebClient (WebDAV) service is RUNNING on $host. Enables HTTP-based NTLM relay and is an ESC8 (AD CS web enrollment relay) attack enabler." `
                -Reference 'https://attack.mitre.org/techniques/T1187/'))
        }

        # HOST-006 SMBv1
        if ($fl.smb1Enabled) {
            $findings.Add((New-Finding -Id 'HOST-006' -Severity 'Critical' `
                -Technique 'T1210' `
                -Description "SMBv1 is ENABLED on $host. SMBv1 is exploited by EternalBlue (MS17-010) and related exploits. Disable immediately." `
                -Reference 'https://attack.mitre.org/techniques/T1210/'))
        }

        # HOST-007 RDP without NLA
        if ($fl.rdpEnabled -and -not $fl.rdpNLARequired) {
            $findings.Add((New-Finding -Id 'HOST-007' -Severity 'Medium' `
                -Technique 'T1021.001' `
                -Description "RDP is enabled on $host without Network Level Authentication (NLA). Unauthenticated users reach the login screen — enables credential spraying and BlueKeep-class pre-auth exploits." `
                -Reference 'https://attack.mitre.org/techniques/T1021/001/'))
        }

        # HOST-008 LSA Protection
        if (-not $fl.lsaRunAsPPL) {
            $findings.Add((New-Finding -Id 'HOST-008' -Severity 'High' `
                -Technique 'T1003.001' `
                -Description "LSA Protection (RunAsPPL) is NOT enabled on $host. LSASS is not a Protected Process — credential dumping tools (Mimikatz, ProcDump) can read LSASS memory without a kernel driver." `
                -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
        }

        # HOST-009 WDigest
        if ($fl.wdigestCaching) {
            $findings.Add((New-Finding -Id 'HOST-009' -Severity 'Critical' `
                -Technique 'T1003.001' `
                -Description "WDigest credential caching is ENABLED on $host (UseLogonCredential=1). Plaintext passwords are stored in LSASS memory and retrievable by Mimikatz sekurlsa::wdigest." `
                -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
        }

        # HOST-010 LAPS
        if ($fl.lapsVersion -eq 'none') {
            $findings.Add((New-Finding -Id 'HOST-010' -Severity 'Medium' `
                -Technique 'T1078.003' `
                -Description "LAPS is NOT deployed on $host. The local Administrator password is unmanaged — likely shared or static across machines (pass-the-hash lateral movement risk)." `
                -Reference 'https://attack.mitre.org/techniques/T1078/003/'))
        }

        # HOST-011 LDAP signing (DC only)
        if ($isDC -and -not $fl.ldapSigningRequired) {
            $sev = if ($fl.ldapSigning -eq 0) { 'Critical' } else { 'High' }
            $findings.Add((New-Finding -Id 'HOST-011' -Severity $sev `
                -Technique 'T1557.001' `
                -Description "LDAP signing is not REQUIRED on DC $host (current level: $($fl.ldapSigning) — 0=None, 1=Negotiate, 2=Required). Enables LDAP relay attacks (e.g., ntlmrelayx to ldap://)." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # HOST-012 SMB signing
        if (-not $fl.smbSigningRequired) {
            $findings.Add((New-Finding -Id 'HOST-012' -Severity 'High' `
                -Technique 'T1557.001' `
                -Description "SMB signing is not REQUIRED on $host. Enables SMB relay attacks — captured NTLM authentication can be relayed to this host." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # HOST-013 LLMNR / NBT-NS
        if ($fl.llmnrEnabled -or $fl.nbtNSEnabled) {
            $proto = @()
            if ($fl.llmnrEnabled)  { $proto += 'LLMNR' }
            if ($fl.nbtNSEnabled)  { $proto += 'NBT-NS' }
            $findings.Add((New-Finding -Id 'HOST-013' -Severity 'High' `
                -Technique 'T1557.001' `
                -Description "$($proto -join ' and ') is enabled on $host. Enables name-poisoning attacks (Responder) to capture NTLMv2 hashes from any machine on the subnet." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # HOST-014 Local Administrator stale password
        if ($fl.localAdminEnabled -and $fl.localAdminPwdAgeDays -gt 90) {
            $findings.Add((New-Finding -Id 'HOST-014' -Severity 'Medium' `
                -Technique 'T1078.003' `
                -Description "Local Administrator is ENABLED on $host with password last set $($fl.localAdminPwdAgeDays) days ago. LAPS may not be managing this account (LAPS: $($fl.lapsVersion))." `
                -Reference 'https://attack.mitre.org/techniques/T1078/003/'))
        }
    }

    # HOST-015 Shares with broad write access
    if ($s.shares) {
        $broadAccounts = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users','Authenticated Users')
        foreach ($share in $s.shares) {
            foreach ($ace in $share.access) {
                if ($broadAccounts | Where-Object { $ace.account -like "*$_*" }) {
                    if ($ace.rights -in @('Change','Full')) {
                        $findings.Add((New-Finding -Id 'HOST-015' -Severity 'High' `
                            -Technique 'T1039' `
                            -Description "Share '$($share.name)' ($($share.path)) on $host grants '$($ace.rights)' to '$($ace.account)'. Broad write access enables data staging and potential code execution." `
                            -Reference 'https://attack.mitre.org/techniques/T1039/'))
                    }
                }
            }
        }
    }

    # HOST-016 Scheduled tasks running as privileged domain account
    if ($s.scheduledTasks) {
        foreach ($task in $s.scheduledTasks) {
            $runAs = $task.runAs
            if ($runAs -and $runAs -match '\\' -and $runAs -notmatch '(?i)SYSTEM|NT AUTHORITY') {
                if ($task.runLevel -eq 'Highest') {
                    $findings.Add((New-Finding -Id 'HOST-016' -Severity 'Medium' `
                        -Technique 'T1053.005' `
                        -Description "Scheduled task '$($task.name)' on $host runs as '$runAs' at highest privilege. If the task script/binary is writable, this is a privilege escalation path." `
                        -Reference 'https://attack.mitre.org/techniques/T1053/005/'))
                }
            }
        }
    }

    $sf = $s.securityFlags
    if ($sf) {
        # HOST-017 DSRM admin logon behavior (DC-specific)
        # Value 2 allows the DSRM local Administrator to authenticate over the network —
        # a stealthy DC backdoor that survives domain credential resets.
        if ($isDC -and $sf.dsrmLogonBehavior -ge 1) {
            $sev  = if ($sf.dsrmLogonBehavior -ge 2) { 'Critical' } else { 'High' }
            $mode = if ($sf.dsrmLogonBehavior -ge 2) { 'network logon always allowed (value=2)' } else { 'logon allowed when AD services stopped (value=1)' }
            $findings.Add((New-Finding -Id 'HOST-017' -Severity $sev `
                -Technique 'T1078.002' `
                -Description "DSRM admin logon behavior on DC $host is set to $mode. The DSRM local Administrator account has a separate password that survives domain-wide password resets. Value 0 (default) is the only safe setting: DSRM login restricted to Directory Services Restore Mode only. An attacker who has extracted the DSRM hash (via secretsdump or NTDS backup) can use value 2 to authenticate to the DC over the network as local Administrator indefinitely." `
                -Reference 'https://attack.mitre.org/techniques/T1078/002/'))
        }

        # HOST-018 EFS service running on DC (MS-EFSRPC / PetitPotam coercion surface)
        # EFS on DCs is generally unnecessary; its RPC interface is used by PetitPotam
        # to coerce DC authentication to attacker-controlled listener.
        if ($isDC -and $sf.efsServiceRunning) {
            $findings.Add((New-Finding -Id 'HOST-018' -Severity 'Medium' `
                -Technique 'T1187' `
                -Description "EFS (Encrypting File System) service is running on DC $host. The MS-EFSRPC interface (used by EFS) is the coercion vector for PetitPotam — an unauthenticated attacker can trigger the DC to authenticate outbound to any host, enabling NTLM relay to ADCS (ESC8) or other relay targets. EFS provides no operational value on a DC. Recommended: disable the EFS service on all DCs. Note: patched Windows servers may block unauthenticated PetitPotam but the authenticated variant remains viable." `
                -Reference 'https://attack.mitre.org/techniques/T1187/'))
        }

        # HOST-019 DFS Namespace service on DC (DFSCoerce coercion surface)
        # DFS Namespace (MS-DFSNM) can be used by DFSCoerce to coerce DC authentication.
        if ($isDC -and $sf.dfsNamespaceRunning) {
            $findings.Add((New-Finding -Id 'HOST-019' -Severity 'Medium' `
                -Technique 'T1187' `
                -Description "DFS Namespace service (Dfs) is running on DC $host. The MS-DFSNM RPC interface is the coercion vector for DFSCoerce — an authenticated attacker can trigger the DC to authenticate to an arbitrary SMB listener, enabling NTLM relay attacks (to ADCS, another DC, or any service not requiring signing). Recommended: disable DFS Namespace on DCs that are not serving DFS namespaces; enable SMB signing and EPA on all relay targets." `
                -Reference 'https://attack.mitre.org/techniques/T1187/'))
        }

        # HOST-020 ESC10 — StrongCertificateBindingEnforcement not at full enforcement
        # This key gates whether ESC6, ESC9, and ESC10 are exploitable even after patching.
        # Microsoft moved to full enforcement (value=2) in February 2025. Any DC below
        # value=2 is still vulnerable to certificate-based privilege escalation attacks.
        if ($isDC) {
            $kcb = $sf.kcbEnforcement
            if ($kcb -lt 2) {
                $modeDesc = switch ($kcb) {
                    -1  { 'key absent (pre-patch default — equivalent to compatibility mode)' }
                    0   { 'disabled (value=0 — no certificate binding enforcement)' }
                    1   { 'compatibility mode (value=1 — audit only, still exploitable)' }
                    default { "value=$kcb" }
                }
                $findings.Add((New-Finding -Id 'HOST-020' -Severity 'High' `
                    -Technique 'T1649' `
                    -Description "StrongCertificateBindingEnforcement on DC $host is $modeDesc. Must be 2 (full enforcement) — Microsoft enforced this by default from February 2025. Below 2, ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC9 (no security extension), and ESC10 (weak UPN certificate mapping) remain exploitable against this DC regardless of template-level mitigations. Registry path: HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement. Set to 2 and validate Kerberos auth before removing the override." `
                    -Reference 'https://attack.mitre.org/techniques/T1649/'))
            }
        }

        # HOST-021 NTLMv1/LM enabled
        if ($sf.lmCompatibilityLevel -lt 5) {
            $lvlDesc = switch ($sf.lmCompatibilityLevel) {
                0 { 'value=0 — sends LM and NTLM responses, never NTLMv2' }
                1 { 'value=1 — sends LM and NTLM, NTLMv2 if negotiated' }
                2 { 'value=2 — sends NTLM only' }
                3 { 'value=3 — sends NTLMv2 only' }
                4 { 'value=4 — DCs refuse LM' }
                default { "value=$($sf.lmCompatibilityLevel)" }
            }
            $findings.Add((New-Finding -Id 'HOST-021' -Severity 'High' `
                -Technique 'T1557.001' `
                -Description "LmCompatibilityLevel on $host is $lvlDesc. Value must be 5 (NTLMv2 only — refuse LM and NTLMv1 challenge/response) to prevent capture and relay of weak authentication material. Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # HOST-022 Credential Guard not enabled
        if (-not $sf.credentialGuardEnabled) {
            $sev = if ($isDC) { 'High' } else { 'Medium' }
            $findings.Add((New-Finding -Id 'HOST-022' -Severity $sev `
                -Technique 'T1003.001' `
                -Description "Credential Guard (Virtualization Based Security / LSASS isolation) is NOT enabled on $host. Without Credential Guard, LSASS memory can be read by a local admin to extract NTLM hashes and Kerberos tickets (pass-the-hash / pass-the-ticket). Requires: VBS enabled (EnableVirtualizationBasedSecurity=1) + LsaCfgFlags >= 1. Registry: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard." `
                -Reference 'https://attack.mitre.org/techniques/T1003/001/'))
        }

        # HOST-023 PowerShell v2 present (bypasses ScriptBlock logging)
        if ($sf.psV2Present) {
            $findings.Add((New-Finding -Id 'HOST-023' -Severity 'Medium' `
                -Technique 'T1059.001' `
                -Description "PowerShell version 2 is present on $host. PS v2 does not support ScriptBlock logging, AMSI, or Constrained Language Mode — an attacker can invoke 'powershell.exe -Version 2' to bypass all modern PowerShell security controls. Remove via: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (client) or Remove-WindowsFeature PowerShell-V2 (server)." `
                -Reference 'https://attack.mitre.org/techniques/T1059/001/'))
        }

        # HOST-024 LDAP channel binding not required (DC only)
        if ($isDC -and $sf.ldapChannelBinding -lt 2) {
            $cbDesc = switch ($sf.ldapChannelBinding) {
                0 { 'never required (value=0)' }
                1 { 'required only if client supports it (value=1)' }
                default { "value=$($sf.ldapChannelBinding)" }
            }
            $findings.Add((New-Finding -Id 'HOST-024' -Severity 'High' `
                -Technique 'T1557' `
                -Description "LDAP channel binding on DC $host is $cbDesc. Without value=2 (always required), an attacker can relay LDAP authentication even when LDAP signing is enforced — the relay session omits the channel binding token and the DC accepts it. This allows NTLM relay to LDAP for ACL modifications (e.g., granting DCSync rights). Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding. Set to 2; test with ldp.exe before enforcing." `
                -Reference 'https://attack.mitre.org/techniques/T1557/'))
        }

        # HOST-025 WinRM HTTP unencrypted allowed
        if ($sf.winrmAllowUnencrypted) {
            $findings.Add((New-Finding -Id 'HOST-025' -Severity 'High' `
                -Technique 'T1557' `
                -Description "WinRM AllowUnencrypted is enabled on $host (policy: HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencrypted=1). WinRM over HTTP (port 5985) without encryption exposes PowerShell remoting traffic — credentials and session content — to network eavesdropping. Require HTTPS (port 5986) or at minimum disable unencrypted transport and enforce Kerberos auth." `
                -Reference 'https://attack.mitre.org/techniques/T1557/'))
        }

        # HOST-026 Remote Registry running on DC
        if ($isDC -and $sf.remoteRegistryRunning) {
            $findings.Add((New-Finding -Id 'HOST-026' -Severity 'Medium' `
                -Technique 'T1012' `
                -Description "Remote Registry service is running on DC $host. Remote Registry allows authenticated users (with appropriate permissions) to read and modify the registry over the network — a common lateral-movement enumeration vector. DCs do not require this service for standard AD operations. Recommended: disable or set to Manual/Disabled on all DCs." `
                -Reference 'https://attack.mitre.org/techniques/T1012/'))
        }

        # HOST-027 BitLocker not enabled on DC OS volume (DC only)
        if ($isDC -and -not $sf.bitlockerOsVolumeProtected) {
            $findings.Add((New-Finding -Id 'HOST-027' -Severity 'Medium' `
                -Technique 'T1005' `
                -Description "BitLocker is NOT enabled on the OS volume of DC $host. An attacker with physical access (or a malicious hypervisor snapshot) can mount the NTDS.dit and SYSTEM hive offline to extract all domain credentials without any authentication. All DC volumes should be BitLocker-protected with a TPM PIN or startup key stored in a PAM system." `
                -Reference 'https://attack.mitre.org/techniques/T1005/'))
        }

        # HOST-028 IPv6 active without management controls (DC only — mitm6 attack surface)
        if ($isDC -and -not $sf.ipv6FullyDisabled) {
            $findings.Add((New-Finding -Id 'HOST-028' -Severity 'High' `
                -Technique 'T1557' `
                -Description "IPv6 is active on DC $host without full disable (DisabledComponents=0x$([Convert]::ToString($sf.ipv6DisabledComponents,16).ToUpper())). Unmanaged IPv6 enables the mitm6 attack: a rogue DHCPv6 server can advertise itself as the default IPv6 gateway and DNS resolver, intercept WPAD lookup traffic, and capture NTLM authentication for relay. Remediate: deploy DHCPv6/RA Guard on network switches, OR disable IPv6 on DCs via GPO registry key (HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents=0xFF) if IPv6 is not operationally required." `
                -Reference 'https://attack.mitre.org/techniques/T1557/'))
        }

        # HOST-029 SMB client signing not required
        if (-not $sf.smbClientSigningRequired) {
            $findings.Add((New-Finding -Id 'HOST-029' -Severity 'Medium' `
                -Technique 'T1557.001' `
                -Description "SMB client signing is NOT required on $host (LanmanWorkstation\RequireSecuritySignature is not 1). Even if the SERVER enforces signing (HOST-012), a client that does not require signing can be coerced into an unsigned SMB session toward resources it connects to, enabling SMB relay against those targets. Set RequireSecuritySignature=1 in LanmanWorkstation\Parameters via GPO. This is the client-side control; HOST-012 checks the separate server-side (LanmanServer) setting." `
                -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
        }

        # HOST-030 Cached domain credentials on DC (DCs should cache 0)
        if ($isDC -and $sf.cachedLogonsCount -gt 0) {
            $findings.Add((New-Finding -Id 'HOST-030' -Severity 'High' `
                -Technique 'T1003.005' `
                -Description "Cached domain credential logon is ENABLED on DC $host (CachedLogonsCount=$($sf.cachedLogonsCount)). Cached credentials (MSCacheV2 hashes) are stored in the SECURITY registry hive and can be extracted by an attacker with SYSTEM access and cracked offline. DCs are always connected and never require cached credentials. Set to 0 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive Logon: Number of previous logons to cache." `
                -Reference 'https://attack.mitre.org/techniques/T1003/005/'))
        }

        # HOST-031 Netlogon secure channel not fully enforced (DC only)
        if ($isDC -and (-not $sf.netlogonRequireSignOrSeal -or -not $sf.netlogonSealSecureChannel)) {
            $missing = @()
            if (-not $sf.netlogonRequireSignOrSeal) { $missing += 'RequireSignOrSeal=0' }
            if (-not $sf.netlogonSealSecureChannel)  { $missing += 'SealSecureChannel=0'  }
            $findings.Add((New-Finding -Id 'HOST-031' -Severity 'High' `
                -Technique 'T1557' `
                -Description "Netlogon secure channel signing/sealing is NOT fully enforced on DC ${host}: $($missing -join ', '). Both RequireSignOrSeal=1 and SealSecureChannel=1 must be set to cryptographically protect all Netlogon RPC traffic and prevent downgrade attacks. Enforce via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain member: Digitally encrypt or sign secure channel data (always)' and 'Domain member: Digitally sign secure channel data (when possible)'." `
                -Reference 'https://attack.mitre.org/techniques/T1557/'))
        }

        # HOST-032 No recent AD backup (DC only)
        if ($isDC -and $sf.backupInfo) {
            $bk = $sf.backupInfo
            $days = if ($bk -is [hashtable]) { $bk.daysSinceBackup } else { -1 }
            if ($days -lt 0 -or $days -gt 30) {
                $reason = if ($days -lt 0) {
                    "No backup detected on DC $host via Windows Server Backup or VSS shadow copies (method checked: $($bk.method))."
                } else { "Last detected backup on DC $host is $days days old." }
                $findings.Add((New-Finding -Id 'HOST-032' -Severity 'High' `
                    -Technique 'T1490' `
                    -Description "$reason Without a recent, tested backup, ransomware or malicious deletion of NTDS.dit may make domain recovery impossible. All DCs require a verified system-state backup (NTDS.dit + SYSTEM hive) at least every 30 days, stored offline or in immutable storage. Use Windows Server Backup system-state backup or a PAM-integrated AD backup solution." `
                    -Reference 'https://attack.mitre.org/techniques/T1490/'))
            }
        }
    }

    return ,$findings
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _HostOS_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records   = [System.Collections.Generic.List[object]]::new()
    $runId     = $RunContext.RunId
    $rootDse   = (New-AdsiEntry 'LDAP://RootDSE')
    $domainDn  = $rootDse.defaultNamingContext.ToString()
    $configDn  = $rootDse.configurationNamingContext.ToString()
    $targetsFile = if ($Settings['TargetsFile']) { Join-Path $RunContext.RepoRoot $Settings['TargetsFile'] } else { '' }

    # Discover targets
    Write-Verbose '[Host-OS] Discovering targets...'
    $targets = _HostOS_DiscoverTargets -DomainDn $domainDn -ConfigDn $configDn -TargetsFile $targetsFile
    Write-Host "         $($targets.Count) target(s) discovered for Host-OS scan"

    foreach ($target in $targets) {
        $fqdn  = $target.FQDN
        $tier  = $target.Tier
        Write-Host "         Scanning $fqdn  [Roles: $($target.Roles -join ',')]  [Tier: $tier]"

        $raw = $null
        try {
            if ($fqdn -ieq $env:COMPUTERNAME -or $fqdn -ieq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") {
                # Local fallback — same machine
                $raw = & $script:_HostOS_Script
            } else {
                # Remote via WinRM
                $icParams = @{ ComputerName = $fqdn; ScriptBlock = $script:_HostOS_Script; ErrorAction = 'Stop' }
                $remoteCred = Get-RemoteCredential
                if ($remoteCred) { $icParams.Credential = $remoteCred }
                $raw = Invoke-Command @icParams
            }
        } catch {
            $records.Add((New-CollectionError -Collector 'Host-OS' `
                -Target $fqdn -ErrorMessage $_.ToString() -RunId $runId))
            continue
        }

        if (-not $raw) {
            $records.Add((New-CollectionError -Collector 'Host-OS' `
                -Target $fqdn -ErrorMessage 'Collection returned no data' -RunId $runId))
            continue
        }

        # Log any per-section errors from the remote run
        if ($raw.errors -and $raw.errors.Count -gt 0) {
            Write-Warning "  [Host-OS] $fqdn — $($raw.errors.Count) section error(s): $($raw.errors -join '; ')"
        }

        # Evaluate findings
        $findings = _HostOS_EvaluateFindings -Raw $raw -Target $target

        # Emit OS record
        $records.Add((New-ReconRecord `
            -Collector      'Host-OS' `
            -ObjectType     'os-posture' `
            -StableId       "HostOS:$fqdn" `
            -Category       'config' `
            -Tier           $tier `
            -CollectedAtPriv $true `
            -Attributes     @{
                fqdn            = $fqdn
                roles           = $target.Roles
                os              = $raw.sections.os
                roleList        = $raw.sections.roles
                hotfixes        = $raw.sections.hotfixes
                securityFlags   = $raw.sections.securityFlags
                softwareCount   = if ($raw.sections.software) { $raw.sections.software.Count } else { 0 }
                serviceCount    = if ($raw.sections.services)  { $raw.sections.services.Count  } else { 0 }
                shareCount      = if ($raw.sections.shares)    { $raw.sections.shares.Count    } else { 0 }
                collectionErrors= @($raw.errors)
            } `
            -Findings       $findings.ToArray() `
            -RunId          $runId))

        # Emit software list as separate record (can be large)
        if ($raw.sections.software -and $raw.sections.software.Count -gt 0) {
            $records.Add((New-ReconRecord `
                -Collector      'Host-OS' `
                -ObjectType     'software-inventory' `
                -StableId       "HostOS:software:$fqdn" `
                -Category       'config' `
                -Tier           $tier `
                -CollectedAtPriv $true `
                -Attributes     @{
                    fqdn     = $fqdn
                    software = $raw.sections.software
                } `
                -RunId $runId))
        }

        # Emit services as separate record
        if ($raw.sections.services -and $raw.sections.services.Count -gt 0) {
            $records.Add((New-ReconRecord `
                -Collector      'Host-OS' `
                -ObjectType     'services' `
                -StableId       "HostOS:services:$fqdn" `
                -Category       'config' `
                -Tier           $tier `
                -CollectedAtPriv $true `
                -Attributes     @{
                    fqdn     = $fqdn
                    services = $raw.sections.services
                } `
                -RunId $runId))
        }
    }

    return $records
}

Register-Collector `
    -Name        'Host-OS' `
    -Description 'Per-server OS posture: roles, services, software, shares, local groups, scheduled tasks, security flags — DCs and AD-role servers via WinRM. Findings: HOST-001 through HOST-032 (NTLMv1/LM, Credential Guard, PSv2, LDAP channel binding, WinRM, Remote Registry, BitLocker, IPv6 unmanaged, SMB client signing, cached logons on DC, Netlogon signing, AD backup recency)' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _HostOS_Collect @PSBoundParameters }
