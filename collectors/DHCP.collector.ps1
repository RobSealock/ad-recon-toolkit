# DHCP collector — authorized servers, scopes, options, audit logging.
# MinPrivilege: DHCPRead (DhcpServer module or netsh dhcp).
#
# Findings emitted:
#   DHCP-001  DHCP scope has WPAD proxy URL (option 252) configured — NTLM relay enabler
#   DHCP-002  DHCP scope has PXE boot server options (66/67) — potential network boot attack surface
#   DHCP-003  DHCP audit logging disabled on server

# =============================================================================
# AUTHORIZED SERVER DISCOVERY
# =============================================================================

function _DHCP_GetAuthorizedServers {
    param([string]$ConfigDn)
    $servers = [System.Collections.Generic.List[string]]::new()
    try {
        $dhcpDn = "CN=NetServices,CN=Services,$ConfigDn"
        $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$dhcpDn")
        $s.Filter   = '(objectClass=dhcpClass)'
        $s.PageSize = 200
        $s.PropertiesToLoad.Add('dhcpServers') | Out-Null
        $r = $s.FindOne()
        if ($r -and $r.Properties['dhcpservers'].Count) {
            foreach ($entry in $r.Properties['dhcpservers']) {
                # Entry format: "192.168.1.1$hostname" or just hostname
                $ip = ($entry.ToString() -split '\$')[0]
                if ($ip) { [void]$servers.Add($ip) }
            }
        }
    } catch { Write-Verbose "[DHCP] Authorized server lookup failed: $_" }
    return $servers
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _DHCP_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId

    try {
        $rootDse  = [adsi]'LDAP://RootDSE'
        $configDn = $rootDse.configurationNamingContext.ToString()
        $domainFQDN = $RunContext.Domain

        # Discover authorized DHCP servers from AD
        Write-Host "         [DHCP] Discovering authorized servers from AD..."
        $servers = _DHCP_GetAuthorizedServers -ConfigDn $configDn
        Write-Host "         [DHCP] $($servers.Count) authorized server(s) found"

        if ($servers.Count -eq 0) {
            $records.Add((New-ReconRecord `
                -Collector      'DHCP' `
                -ObjectType     'collection-status' `
                -StableId       "DHCP:$configDn" `
                -Category       'config' `
                -Tier           'T1' `
                -CollectedAtPriv $false `
                -Attributes     @{
                    status          = 'no-servers'
                    dhcpContainerDn = "CN=NetServices,CN=Services,$configDn"
                    collectionNote  = 'No authorized DHCP servers found in AD'
                } `
                -RunId $runId))
            return $records
        }

        foreach ($server in $servers) {
            $serverFindings = [System.Collections.Generic.List[object]]::new()
            $scopeData      = [System.Collections.Generic.List[hashtable]]::new()
            Write-Host "         [DHCP] Processing server: $server"

            # Check audit logging
            $auditLoggingEnabled = $true
            try {
                $auditSetting = Get-DhcpServerSetting -ComputerName $server -EA SilentlyContinue
                if ($auditSetting) {
                    $auditLoggingEnabled = [bool]$auditSetting.IsConflictDetectionEnabled -or $true
                    # DhcpServerSetting does not expose audit logging directly;
                    # check via Get-DhcpServerAuditLog
                    $auditLog = Get-DhcpServerAuditLog -ComputerName $server -EA SilentlyContinue
                    if ($auditLog) {
                        $auditLoggingEnabled = [bool]$auditLog.Enable
                    }
                }
            } catch { Write-Verbose "[DHCP] Audit logging check failed for $server`: $_" }

            if (-not $auditLoggingEnabled) {
                $serverFindings.Add((New-Finding -Id 'DHCP-003' -Severity 'Medium' `
                    -Technique 'T1562.002' `
                    -Description "DHCP audit logging is DISABLED on server '$server'. DHCP audit logs record lease assignments, renewals, and releases — disabling them removes visibility into which IP address was assigned to which host at a given time, impeding incident response and forensic correlation. Enable via: Set-DhcpServerAuditLog -ComputerName '$server' -Enable \$true." `
                    -Reference 'https://attack.mitre.org/techniques/T1562/002/'))
            }

            # Enumerate scopes and check options
            try {
                $scopes = Get-DhcpServerv4Scope -ComputerName $server -EA SilentlyContinue
                if ($scopes) {
                    foreach ($scope in $scopes) {
                        $scopeId   = $scope.ScopeId.ToString()
                        $scopeName = $scope.Name
                        $scopeEntry = @{
                            scopeId   = $scopeId
                            name      = $scopeName
                            subnetMask= $scope.SubnetMask.ToString()
                            startRange= $scope.StartRange.ToString()
                            endRange  = $scope.EndRange.ToString()
                            state     = $scope.State.ToString()
                            options   = @()
                        }

                        try {
                            $opts = Get-DhcpServerv4OptionValue -ComputerName $server -ScopeId $scopeId -EA SilentlyContinue
                            if ($opts) {
                                $scopeEntry.options = @($opts | ForEach-Object {
                                    @{ optionId=$_.OptionId; name=$_.Name; value=($_.Value -join ', ') }
                                })

                                # DHCP-001: WPAD proxy URL (option 252)
                                $wpadOpt = $opts | Where-Object { $_.OptionId -eq 252 }
                                if ($wpadOpt -and $wpadOpt.Value) {
                                    $wpadUrl = $wpadOpt.Value -join ', '
                                    $serverFindings.Add((New-Finding -Id 'DHCP-001' -Severity 'High' `
                                        -Technique 'T1557.001' `
                                        -Description "DHCP scope '$scopeName' ($scopeId) on server '$server' has WPAD proxy URL configured (option 252): '$wpadUrl'. An attacker controlling the WPAD URL host can intercept all web traffic from WPAD-enabled clients (Internet Explorer, Edge in compatibility mode, apps using WinHTTP with auto-proxy detection) to capture credentials via NTLM authentication to the proxy. Remove option 252 or point to a controlled, hardened PAC file server." `
                                        -Reference 'https://attack.mitre.org/techniques/T1557/001/'))
                                }

                                # DHCP-002: PXE boot server options (66 = TFTP server name, 67 = bootfile name)
                                $tftpOpt     = $opts | Where-Object { $_.OptionId -eq 66 }
                                $bootfileOpt = $opts | Where-Object { $_.OptionId -eq 67 }
                                if ($tftpOpt -or $bootfileOpt) {
                                    $tftpVal     = if ($tftpOpt)     { $tftpOpt.Value -join ', ' }     else { 'not set' }
                                    $bootfileVal = if ($bootfileOpt) { $bootfileOpt.Value -join ', ' } else { 'not set' }
                                    $serverFindings.Add((New-Finding -Id 'DHCP-002' -Severity 'Medium' `
                                        -Technique 'T1200' `
                                        -Description "DHCP scope '$scopeName' ($scopeId) on server '$server' has PXE boot options configured — TFTP server (option 66): '$tftpVal'; boot file (option 67): '$bootfileVal'. PXE boot infrastructure can be abused for network boot attacks: an attacker who compromises the TFTP server or gains DHCP access can serve a malicious boot image to any machine that PXE-boots, achieving pre-OS execution. Verify PXE is required, restrict TFTP access, and sign boot images." `
                                        -Reference 'https://attack.mitre.org/techniques/T1200/'))
                                }
                            }
                        } catch { Write-Verbose "[DHCP] Option enumeration failed for scope $scopeId on $server`: $_" }

                        [void]$scopeData.Add($scopeEntry)
                    }
                }
            } catch { Write-Verbose "[DHCP] Scope enumeration failed for $server`: $_" }

            # Emit per-server record
            $records.Add((New-ReconRecord `
                -Collector      'DHCP' `
                -ObjectType     'dhcp-server' `
                -StableId       "DHCP:server:$server" `
                -Category       'config' `
                -Tier           'T1' `
                -CollectedAtPriv $false `
                -Attributes     @{
                    server              = $server
                    scopeCount          = $scopeData.Count
                    scopes              = $scopeData.ToArray()
                    auditLoggingEnabled = $auditLoggingEnabled
                } `
                -Findings       $serverFindings.ToArray() `
                -RunId $runId))
        }

        # Emit summary record
        $records.Add((New-ReconRecord `
            -Collector      'DHCP' `
            -ObjectType     'dhcp-summary' `
            -StableId       "DHCP:summary:$domainFQDN" `
            -Category       'config' `
            -Tier           'T1' `
            -CollectedAtPriv $false `
            -Attributes     @{
                domain          = $domainFQDN
                authorizedServers = $servers.ToArray()
                serverCount     = $servers.Count
            } `
            -RunId $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'DHCP' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'DHCP' `
    -Description 'DHCP: authorized servers (from AD), scopes, WPAD proxy option (DHCP-001), PXE boot options (DHCP-002), audit logging (DHCP-003)' `
    -MinPrivilege 'DHCPRead' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _DHCP_Collect @PSBoundParameters }
