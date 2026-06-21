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
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$DomainDn")
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
        $s    = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$caDn")
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
        $s      = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$dhcpDn")
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

    return $targets
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

    return $findings
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _HostOS_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records   = [System.Collections.Generic.List[object]]::new()
    $runId     = $RunContext.RunId
    $rootDse   = [adsi]'LDAP://RootDSE'
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
                $raw = Invoke-Command -ComputerName $fqdn -ScriptBlock $script:_HostOS_Script `
                    -ErrorAction Stop
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
    -Description 'Per-server OS posture: roles, services, software, shares, local groups, scheduled tasks, security flags — DCs and AD-role servers via WinRM' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _HostOS_Collect @PSBoundParameters }
