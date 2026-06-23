# Host-Firewall collector — Windows Defender Firewall profiles, default actions,
# logging config, key inbound rules on sensitive ports, policy source (GPO vs local).
#
# MinPrivilege: LocalAdmin
#   Get-NetFirewallProfile works without admin on most builds, but reading the
#   full rule set reliably requires admin. Runs on the LOCAL machine only at
#   this milestone; Host-OS (Milestone 2) extends this to remote DCs via WinRM.
#
# Findings emitted:
#   FW-001  Firewall profile disabled on DC (all ports exposed in that network category)
#   FW-002  Default inbound action = Allow on any profile (deny-by-default not enforced)
#   FW-003  Firewall logging disabled for a profile (no visibility into blocked/allowed)
#   FW-004  Inbound allow rule on high-risk port open to Any source address
#   FW-005  Telnet (23) or legacy management port inbound rule exists
#   FW-006  Firewall policy source is local-only — no GPO enforcement detected

# ── Port risk table ───────────────────────────────────────────────────────────
$script:_FW_SensitivePorts = @{
    23   = @{ Name='Telnet';      Severity='Critical'; Note='Legacy plaintext protocol — should never be allowed inbound on a DC' }
    3389 = @{ Name='RDP';         Severity='Medium';   Note='RDP inbound — confirm restricted to jump-host or management subnet' }
    5985 = @{ Name='WinRM-HTTP';  Severity='Medium';   Note='WinRM HTTP inbound — confirm restricted to management subnet' }
    5986 = @{ Name='WinRM-HTTPS'; Severity='Low';      Note='WinRM HTTPS inbound — confirm restricted to management subnet' }
    5900 = @{ Name='VNC';         Severity='High';     Note='VNC inbound — remote desktop protocol with historically weak auth' }
    4899 = @{ Name='Radmin';      Severity='High';     Note='Radmin inbound — legacy remote admin tool' }
    22   = @{ Name='SSH';         Severity='Medium';   Note='SSH inbound on DC — confirm required and source-restricted' }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function _FW_GetProfiles {
    try {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
                          LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes,
                          DisabledInterfaceAliases
    } catch {
        Write-Verbose "[FW] Get-NetFirewallProfile failed: $_"
        return $null
    }
}

function _FW_GetInboundRules {
    # Returns enabled inbound allow rules only — what's actually permitting traffic
    try {
        $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True `
                    -ErrorAction Stop
        $result = foreach ($rule in $rules) {
            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name          = $rule.DisplayName
                Group         = $rule.DisplayGroup
                PolicyStore   = $rule.PolicyStore
                Profile       = $rule.Profile.ToString()
                Protocol      = $portFilter.Protocol
                LocalPorts    = $portFilter.LocalPort
                RemoteAddress = $addrFilter.RemoteAddress
                Owner         = $rule.Owner
            }
        }
        return @($result)
    } catch {
        Write-Verbose "[FW] Get-NetFirewallRule failed: $_"
        return @()
    }
}

function _FW_IsAnySource {
    param([string[]]$RemoteAddress)
    if (-not $RemoteAddress) { return $true }
    $anyValues = @('Any','*','0.0.0.0/0','::/0')
    foreach ($a in $RemoteAddress) {
        if ($anyValues -contains $a) { return $true }
    }
    return $false
}

function _FW_PortsFromRule {
    param($LocalPorts)
    if (-not $LocalPorts) { return @() }
    $ports = [System.Collections.Generic.List[int]]::new()
    foreach ($p in $LocalPorts) {
        if ($p -eq 'Any' -or $p -eq '*') { return @(-1) }   # -1 = wildcard
        if ($p -match '^\d+$') { $ports.Add([int]$p) }
        elseif ($p -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            foreach ($n in $script:_FW_SensitivePorts.Keys) {
                if ($n -ge $lo -and $n -le $hi) { $ports.Add($n) }
            }
        }
    }
    return ,$ports
}

# ── Main collector ────────────────────────────────────────────────────────────

function _HostFirewall_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records  = [System.Collections.Generic.List[object]]::new()
    $runId    = $RunContext.RunId
    $target   = $RunContext.RunHost

    try {
        $fwFindings = [System.Collections.Generic.List[object]]::new()

        # ── Profiles ──────────────────────────────────────────────────────────
        $profiles    = _FW_GetProfiles
        $profileData = @{}
        $anyGpoRule  = $false

        if ($profiles) {
            foreach ($p in $profiles) {
                $profileData[$p.Name] = @{
                    enabled              = [bool]$p.Enabled
                    defaultInbound       = $p.DefaultInboundAction.ToString()
                    defaultOutbound      = $p.DefaultOutboundAction.ToString()
                    logAllowed           = [bool]$p.LogAllowed
                    logBlocked           = [bool]$p.LogBlocked
                    logFile              = $p.LogFileName
                    logMaxSizeKB         = $p.LogMaxSizeKilobytes
                    disabledInterfaces   = @($p.DisabledInterfaceAliases)
                }

                # FW-001: Profile disabled
                if (-not $p.Enabled) {
                    $fwFindings.Add((New-Finding -Id 'FW-001' -Severity 'Critical' `
                        -Description "Windows Firewall '$($p.Name)' profile is DISABLED on $target. All ports in this network category are unfiltered." `
                        -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
                }

                # FW-002: Default inbound = Allow
                if ($p.DefaultInboundAction -eq 'Allow' -and $p.Enabled) {
                    $fwFindings.Add((New-Finding -Id 'FW-002' -Severity 'High' `
                        -Description "Windows Firewall '$($p.Name)' profile default inbound action is ALLOW on $target. Deny-by-default is not enforced — all ports without an explicit block rule are open." `
                        -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
                }

                # FW-003: Logging disabled
                if ($p.Enabled -and (-not $p.LogBlocked)) {
                    $fwFindings.Add((New-Finding -Id 'FW-003' -Severity 'Medium' `
                        -Description "Windows Firewall '$($p.Name)' profile has dropped-packet logging DISABLED on $target. Blocked connection attempts are not recorded." `
                        -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
                }
            }

            # Emit profile record
            $records.Add((New-ReconRecord `
                -Collector      'Host-Firewall' `
                -ObjectType     'fw-profiles' `
                -StableId       "FW:profiles:$target" `
                -Category       'config' `
                -Tier           'T0' `
                -CollectedAtPriv $true `
                -Attributes     $profileData `
                -Findings       $fwFindings.ToArray() `
                -RunId          $runId))
        } else {
            $records.Add((New-CollectionError -Collector 'Host-Firewall' `
                -Target $target -ErrorMessage 'Get-NetFirewallProfile returned no data' -RunId $runId))
        }

        # ── Inbound allow rules ───────────────────────────────────────────────
        $inboundRules = _FW_GetInboundRules
        $ruleFindings = [System.Collections.Generic.List[object]]::new()
        $ruleData     = [System.Collections.Generic.List[hashtable]]::new()
        $gpoRuleCount = 0
        $localRuleCount = 0

        foreach ($rule in $inboundRules) {
            # Track policy source
            if ($rule.PolicyStore -and $rule.PolicyStore -ne 'PersistentStore' -and
                $rule.PolicyStore -ne $target) {
                $anyGpoRule = $true
                $gpoRuleCount++
            } else {
                $localRuleCount++
            }

            $ports    = _FW_PortsFromRule -LocalPorts $rule.LocalPorts
            $anySource= _FW_IsAnySource -RemoteAddress $rule.RemoteAddress

            foreach ($port in $ports) {
                if ($port -eq -1) {
                    # Wildcard port rule — only flag if Any source
                    if ($anySource) {
                        $ruleFindings.Add((New-Finding -Id 'FW-004' -Severity 'Medium' `
                            -Description "Inbound allow rule '$($rule.Name)' permits ALL ports from ANY source on $target. Review for necessity." `
                            -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
                    }
                    continue
                }

                if ($script:_FW_SensitivePorts.ContainsKey($port)) {
                    $portInfo = $script:_FW_SensitivePorts[$port]
                    $severity = $portInfo.Severity
                    $id       = if ($port -eq 23 -or $port -eq 4899) { 'FW-005' } else { 'FW-004' }

                    if ($anySource) {
                        $ruleFindings.Add((New-Finding -Id $id -Severity $severity `
                            -Description "$($portInfo.Name) ($port) inbound allow rule '$($rule.Name)' is open to ANY source on $target. $($portInfo.Note)" `
                            -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
                    } else {
                        $ruleFindings.Add((New-Finding -Id $id -Severity 'Informational' `
                            -Description "$($portInfo.Name) ($port) inbound allow rule '$($rule.Name)' exists on $target (source-restricted to: $($rule.RemoteAddress -join ', ')). Confirm restriction is appropriate." `
                            -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
                    }
                }
            }

            $ruleData.Add(@{
                name          = $rule.Name
                group         = $rule.Group
                profile       = $rule.Profile
                protocol      = $rule.Protocol
                localPorts    = @($rule.LocalPorts)
                remoteAddress = @($rule.RemoteAddress)
                policyStore   = $rule.PolicyStore
            })
        }

        # FW-006: No GPO-enforced rules detected
        if (-not $anyGpoRule -and $inboundRules.Count -gt 0) {
            $ruleFindings.Add((New-Finding -Id 'FW-006' -Severity 'Medium' `
                -Description "No GPO-sourced firewall rules detected on $target — all $($inboundRules.Count) inbound allow rules are locally defined. Firewall policy is not centrally enforced via Group Policy." `
                -Reference 'https://attack.mitre.org/techniques/T1562/004/'))
        }

        $records.Add((New-ReconRecord `
            -Collector      'Host-Firewall' `
            -ObjectType     'fw-rules' `
            -StableId       "FW:rules:$target" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     @{
                host              = $target
                totalInboundAllow = $inboundRules.Count
                gpoEnforcedRules  = $gpoRuleCount
                localOnlyRules    = $localRuleCount
                gpoEnforced       = $anyGpoRule
                rules             = $ruleData.ToArray()
            } `
            -Findings       $ruleFindings.ToArray() `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'Host-Firewall' `
            -Target $target -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'Host-Firewall' `
    -Description 'Windows Defender Firewall: profiles, default actions, logging, inbound rules on sensitive ports, GPO vs local policy source' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _HostFirewall_Collect @PSBoundParameters }
