# Host-Persistence collector — LOL and persistence location audit.
# MinPrivilege: LocalAdmin
# Requires RunContext.OverrideTargets (set by Start-HostAssessment.ps1).
#
# Locations audited:
#   Run/RunOnce registry keys (HKLM + WOW64)
#   All-Users and per-user Startup folders
#   Scheduled tasks (non-Microsoft namespace)
#   WMI event subscriptions
#   AppInit_DLLs (code injection into all user32.dll consumers)
#   LSA Security and Notification packages (lsass.exe injection)
#   Running services with suspicious binary paths
#
# Finding IDs:
#   PERSIST-001  Run/RunOnce registry entry (Medium) or in suspicious location (High)
#   PERSIST-002  Startup folder item (Medium) or in suspicious location (High)
#   PERSIST-003  Non-Microsoft scheduled task with suspicious action or SYSTEM+Highest privilege
#   PERSIST-004  WMI event subscription (any non-default — High)
#   PERSIST-005  AppInit_DLLs populated (Critical)
#   PERSIST-006  Non-default LSA Security or Notification package (Critical/High)
#   PERSIST-007  Running service with binary in temp/appdata/downloads or using LOL binary (High)

# =============================================================================
# REMOTE-SAFE COLLECTION SCRIPTBLOCK
# Self-contained — no external function dependencies.
# =============================================================================

$script:_HostPersist_Script = {
    $r = @{ sections = @{}; errors = [System.Collections.Generic.List[string]]::new() }

    # Run / RunOnce registry keys (HKLM + WOW64, user-context keys not accessible for other users)
    try {
        $runEntries = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($kDef in @(
            @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';              Hive='HKLM';       Type='Run'     }
            @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';          Hive='HKLM';       Type='RunOnce' }
            @{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';  Hive='HKLM-WOW64'; Type='Run'     }
            @{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';Hive='HKLM-WOW64';Type='RunOnce'}
        )) {
            $props = Get-ItemProperty $kDef.Path -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object {
                        $runEntries.Add(@{
                            hive    = $kDef.Hive
                            type    = $kDef.Type
                            name    = $_.Name
                            command = [string]$_.Value
                            keyPath = $kDef.Path
                        })
                    }
            }
        }
        $r.sections.runKeys = $runEntries.ToArray()
    } catch { $r.errors.Add("runKeys: $_"); $r.sections.runKeys = @() }

    # Startup folders — All Users + per-user profiles
    try {
        $startupItems = [System.Collections.Generic.List[hashtable]]::new()
        $folders = [System.Collections.Generic.List[string]]::new()

        $allUsers = [System.Environment]::GetFolderPath('CommonStartup')
        if ($allUsers) { $folders.Add($allUsers) }

        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            if (Test-Path $p) { $folders.Add($p) }
        }

        foreach ($folder in $folders) {
            Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object {
                $startupItems.Add(@{
                    name     = $_.Name
                    fullPath = $_.FullName
                    folder   = $folder
                    modified = $_.LastWriteTime.ToString('o')
                })
            }
        }
        $r.sections.startupItems = $startupItems.ToArray()
    } catch { $r.errors.Add("startupItems: $_"); $r.sections.startupItems = @() }

    # Scheduled tasks — non-Microsoft namespace
    try {
        $tasks = [System.Collections.Generic.List[hashtable]]::new()
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            ForEach-Object {
                $info   = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                $action = $_.Actions | Select-Object -First 1
                $tasks.Add(@{
                    name      = $_.TaskName
                    path      = $_.TaskPath
                    state     = $_.State.ToString()
                    runAs     = [string]$_.Principal.UserId
                    runLevel  = $_.Principal.RunLevel.ToString()
                    lastRun   = if ($info -and $info.LastRunTime) { $info.LastRunTime.ToString('o') } else { '' }
                    execute   = if ($action -and $action.PSObject.Properties['Execute'])   { [string]$action.Execute   } else { '' }
                    arguments = if ($action -and $action.PSObject.Properties['Arguments']) { [string]$action.Arguments } else { '' }
                })
            }
        $r.sections.scheduledTasks = $tasks.ToArray()
    } catch { $r.errors.Add("scheduledTasks: $_"); $r.sections.scheduledTasks = @() }

    # WMI event subscriptions
    try {
        $wmiSubs = [System.Collections.Generic.List[hashtable]]::new()
        $filters  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter'            -ErrorAction SilentlyContinue)
        $consumers= @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer'           -ErrorAction SilentlyContinue)
        $bindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)
        foreach ($f in $filters) {
            if ($f.Name -match '(?i)^(SCM Event Log|BVTFilter)') { continue }
            $wmiSubs.Add(@{
                filterName    = [string]$f.Name
                query         = [string]$f.Query
                language      = [string]$f.QueryLanguage
                consumerCount = $consumers.Count
                bindingCount  = $bindings.Count
            })
        }
        $r.sections.wmiSubscriptions = $wmiSubs.ToArray()
    } catch { $r.errors.Add("wmiSubscriptions: $_"); $r.sections.wmiSubscriptions = @() }

    # AppInit_DLLs
    try {
        $appInit = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($kp in @(
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            $val = (Get-ItemProperty $kp -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
            if ($val -and $val.Trim() -and $val.Trim() -ne '""') {
                $appInit.Add(@{ keyPath=$kp; value=$val.Trim() })
            }
        }
        $r.sections.appInitDlls = $appInit.ToArray()
    } catch { $r.errors.Add("appInitDlls: $_"); $r.sections.appInitDlls = @() }

    # LSA Security and Notification packages
    try {
        $lsaPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $defaultSec   = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','""','')
        $defaultNotif = @('scecli','rassfm','')

        $secPkgsRaw   = (Get-ItemProperty $lsaPath -Name 'Security Packages'     -ErrorAction SilentlyContinue).'Security Packages'
        $notifPkgsRaw = (Get-ItemProperty $lsaPath -Name 'Notification Packages' -ErrorAction SilentlyContinue).'Notification Packages'

        $secPkgs  = @($secPkgsRaw  | Where-Object { $_ })
        $notifPkgs= @($notifPkgsRaw| Where-Object { $_ })

        $r.sections.lsaPackages = @{
            securityPackages     = $secPkgs
            notificationPackages = $notifPkgs
            nonDefaultSecPkgs    = @($secPkgs  | Where-Object { $_ -and $_ -notin $defaultSec   })
            nonDefaultNotifPkgs  = @($notifPkgs| Where-Object { $_ -and $_ -notin $defaultNotif })
        }
    } catch { $r.errors.Add("lsaPackages: $_"); $r.sections.lsaPackages = @{} }

    # Running services with suspicious binary paths
    try {
        $suspSvcs = [System.Collections.Generic.List[hashtable]]::new()
        $suspPaths= @('\temp\','\tmp\','\appdata\','\downloads\','\users\public\')
        $lolBins  = @('mshta.exe','wscript.exe','cscript.exe','regsvr32.exe','rundll32.exe',
                      'certutil.exe','bitsadmin.exe','msiexec.exe','installutil.exe','regasm.exe','regsvcs.exe')

        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -and $_.State -eq 'Running' } |
            ForEach-Object {
                $p = $_.PathName.ToLower()
                $susp = $false
                foreach ($pat in $suspPaths) { if ($p -match [regex]::Escape($pat)) { $susp = $true; break } }
                if (-not $susp) {
                    foreach ($b in $lolBins) {
                        if ($p -match [regex]::Escape($b) -and
                            $p -notmatch '^["\s]*c:\\windows\\(system32|syswow64)') { $susp = $true; break }
                    }
                }
                if ($susp) {
                    $suspSvcs.Add(@{
                        name        = $_.Name
                        displayName = $_.DisplayName
                        pathName    = $_.PathName
                        startName   = $_.StartName
                    })
                }
            }
        $r.sections.suspiciousServices = $suspSvcs.ToArray()
    } catch { $r.errors.Add("suspiciousServices: $_"); $r.sections.suspiciousServices = @() }

    return $r
}

# =============================================================================
# FINDING EVALUATION
# =============================================================================

function _HostPersist_ClassifyCmd {
    param(
        [string]  $Cmd,
        [string[]]$SuspPaths,
        [string[]]$LolBins
    )
    if (-not $Cmd) { return 'clean' }
    $c = $Cmd.ToLower().Trim('"')
    foreach ($p in $SuspPaths) { if ($c -match [regex]::Escape($p)) { return 'suspicious-path' } }
    foreach ($b in $LolBins) {
        if ($c -match [regex]::Escape($b) -and
            $c -notmatch '^["\s]*c:\\windows\\(system32|syswow64)') { return 'lolbin' }
    }
    return 'clean'
}

function _HostPersist_EvaluateFindings {
    param([hashtable]$Raw, [hashtable]$Target)

    $findings = [System.Collections.Generic.List[object]]::new()
    $s        = $Raw.sections
    $h        = $Target.FQDN

    $suspPaths = @('\temp\','\tmp\','\appdata\','\downloads\','\users\public\')
    $lolBins   = @('mshta.exe','wscript.exe','cscript.exe','regsvr32.exe','rundll32.exe',
                   'certutil.exe','bitsadmin.exe','installutil.exe','regasm.exe','regsvcs.exe')

    # PERSIST-001 Run/RunOnce registry entries
    foreach ($entry in $s.runKeys) {
        $cmd = if ($entry -is [hashtable]) { $entry['command'] } else { $entry.command }
        $cls = _HostPersist_ClassifyCmd -Cmd $cmd -SuspPaths $suspPaths -LolBins $lolBins
        $sev = if ($cls -ne 'clean') { 'High' } else { 'Medium' }
        $note = switch ($cls) {
            'suspicious-path' { ' — path is in a suspicious/writable location' }
            'lolbin'          { ' — uses a LOL binary outside System32/SysWOW64' }
            default           { '' }
        }
        $name    = if ($entry -is [hashtable]) { $entry['name']    } else { $entry.name    }
        $hive    = if ($entry -is [hashtable]) { $entry['hive']    } else { $entry.hive    }
        $type    = if ($entry -is [hashtable]) { $entry['type']    } else { $entry.type    }
        $findings.Add((New-Finding -Id 'PERSIST-001' -Severity $sev `
            -Technique 'T1547.001' `
            -Description "Registry $type entry '$name' on $h ($hive$note): '$cmd'. Registry run keys execute at logon/boot — verify this entry is expected and the binary has not been replaced." `
            -Reference 'https://attack.mitre.org/techniques/T1547/001/'))
    }

    # PERSIST-002 Startup folder items
    foreach ($item in $s.startupItems) {
        $fp  = if ($item -is [hashtable]) { $item['fullPath'] } else { $item.fullPath }
        $nm  = if ($item -is [hashtable]) { $item['name']     } else { $item.name     }
        $fld = if ($item -is [hashtable]) { $item['folder']   } else { $item.folder   }
        $mod = if ($item -is [hashtable]) { $item['modified'] } else { $item.modified }
        $cls = _HostPersist_ClassifyCmd -Cmd $fp -SuspPaths $suspPaths -LolBins $lolBins
        $sev = if ($cls -ne 'clean') { 'High' } else { 'Medium' }
        $findings.Add((New-Finding -Id 'PERSIST-002' -Severity $sev `
            -Technique 'T1547.001' `
            -Description "Startup folder item '$nm' on $h at '$fp' (modified: $mod, folder: $fld). Startup items run at user logon — verify this is an expected application." `
            -Reference 'https://attack.mitre.org/techniques/T1547/001/'))
    }

    # PERSIST-003 Scheduled tasks — only flag suspicious action or SYSTEM+Highest
    foreach ($task in $s.scheduledTasks) {
        $exe  = if ($task -is [hashtable]) { $task['execute']   } else { $task.execute   }
        $args = if ($task -is [hashtable]) { $task['arguments'] } else { $task.arguments }
        $name = if ($task -is [hashtable]) { $task['name']      } else { $task.name      }
        $path = if ($task -is [hashtable]) { $task['path']      } else { $task.path      }
        $ra   = if ($task -is [hashtable]) { $task['runAs']     } else { $task.runAs     }
        $rl   = if ($task -is [hashtable]) { $task['runLevel']  } else { $task.runLevel  }

        $cls      = _HostPersist_ClassifyCmd -Cmd $exe -SuspPaths $suspPaths -LolBins $lolBins
        $isSystem = $ra -match '(?i)^(SYSTEM|NT AUTHORITY\\SYSTEM)$'
        $isHighest= $rl -eq 'Highest'

        if ($cls -ne 'clean' -or ($isSystem -and $isHighest)) {
            $sev  = if ($cls -ne 'clean') { 'High' } else { 'Medium' }
            $note = @()
            if ($cls -eq 'suspicious-path') { $note += 'action in suspicious path' }
            if ($cls -eq 'lolbin')          { $note += 'action uses LOL binary' }
            if ($isSystem)                  { $note += 'runs as SYSTEM' }
            if ($isHighest)                 { $note += 'runs at highest privilege' }
            $findings.Add((New-Finding -Id 'PERSIST-003' -Severity $sev `
                -Technique 'T1053.005' `
                -Description "Scheduled task '$name' ($path) on $h — $($note -join ', '). Action: '$exe$(if ($args) { " $args" })'. RunAs: $ra. Verify the task and binary are legitimate." `
                -Reference 'https://attack.mitre.org/techniques/T1053/005/'))
        }
    }

    # PERSIST-004 WMI event subscriptions
    foreach ($sub in $s.wmiSubscriptions) {
        $fname = if ($sub -is [hashtable]) { $sub['filterName'] } else { $sub.filterName }
        $query = if ($sub -is [hashtable]) { $sub['query']      } else { $sub.query      }
        $findings.Add((New-Finding -Id 'PERSIST-004' -Severity 'High' `
            -Technique 'T1546.003' `
            -Description "WMI event subscription '$fname' on $h. Query: '$query'. WMI subscriptions survive reboots, are invisible to scheduled-task enumeration, and are a known stealthy persistence mechanism. Any non-default subscription warrants immediate investigation." `
            -Reference 'https://attack.mitre.org/techniques/T1546/003/'))
    }

    # PERSIST-005 AppInit_DLLs
    foreach ($entry in $s.appInitDlls) {
        $kp  = if ($entry -is [hashtable]) { $entry['keyPath'] } else { $entry.keyPath }
        $val = if ($entry -is [hashtable]) { $entry['value']   } else { $entry.value   }
        $findings.Add((New-Finding -Id 'PERSIST-005' -Severity 'Critical' `
            -Technique 'T1546.010' `
            -Description "AppInit_DLLs is populated on $h at '$kp': '$val'. Every DLL listed here is injected into all processes that load user32.dll — a code injection mechanism used by rootkits and credential-theft implants (e.g., mimilib). This key should be empty in all standard configurations." `
            -Reference 'https://attack.mitre.org/techniques/T1546/010/'))
    }

    # PERSIST-006 Non-default LSA packages
    $lsa = $s.lsaPackages
    if ($lsa) {
        $ndSec   = if ($lsa -is [hashtable]) { $lsa['nonDefaultSecPkgs']   } else { $lsa.nonDefaultSecPkgs   }
        $ndNotif = if ($lsa -is [hashtable]) { $lsa['nonDefaultNotifPkgs'] } else { $lsa.nonDefaultNotifPkgs }
        if ($ndSec -and @($ndSec).Count -gt 0) {
            $findings.Add((New-Finding -Id 'PERSIST-006' -Severity 'Critical' `
                -Technique 'T1547.005' `
                -Description "Non-default LSA Security Package(s) on $h: $($ndSec -join ', '). LSA security packages are DLLs loaded into lsass.exe — used by credential-theft implants (e.g., mimilib.dll). Default set: kerberos, msv1_0, schannel, wdigest, tspkg, pku2u. Remove unexpected entries from HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages." `
                -Reference 'https://attack.mitre.org/techniques/T1547/005/'))
        }
        if ($ndNotif -and @($ndNotif).Count -gt 0) {
            $findings.Add((New-Finding -Id 'PERSIST-006' -Severity 'High' `
                -Technique 'T1547.005' `
                -Description "Non-default LSA Notification Package(s) on $h: $($ndNotif -join ', '). Notification packages receive plaintext credentials during logon — a credential-harvesting implant vector. Default: scecli. Remove unexpected entries from HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages." `
                -Reference 'https://attack.mitre.org/techniques/T1547/005/'))
        }
    }

    # PERSIST-007 Services with suspicious binary paths
    foreach ($svc in $s.suspiciousServices) {
        $name = if ($svc -is [hashtable]) { $svc['name']        } else { $svc.name        }
        $path = if ($svc -is [hashtable]) { $svc['pathName']    } else { $svc.pathName    }
        $acct = if ($svc -is [hashtable]) { $svc['startName']   } else { $svc.startName   }
        $findings.Add((New-Finding -Id 'PERSIST-007' -Severity 'High' `
            -Technique 'T1543.003' `
            -Description "Service '$name' on $h has a suspicious binary path: '$path' (account: $acct). Services in temp/appdata/downloads or using LOL binaries outside System32 are a persistence and privilege-escalation indicator — verify the service is legitimate and the binary is unmodified." `
            -Reference 'https://attack.mitre.org/techniques/T1543/003/'))
    }

    return ,$findings
}

# =============================================================================
# MAIN COLLECTOR
# =============================================================================

function _HostPersist_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId

    $overrideProp = $RunContext.PSObject.Properties['OverrideTargets']
    if (-not $overrideProp -or -not $overrideProp.Value) {
        $records.Add((New-CollectionError -Collector 'Host-Persistence' -Target 'RunContext' `
            -ErrorMessage 'Host-Persistence requires RunContext.OverrideTargets. Run via Start-HostAssessment.ps1.' `
            -RunId $runId))
        return $records
    }
    $targets = @($overrideProp.Value)
    Write-Host "         $($targets.Count) target(s) for Host-Persistence scan"

    foreach ($target in $targets) {
        $fqdn = $target.FQDN
        Write-Host "         Scanning $fqdn"

        $raw = $null
        try {
            if ($fqdn -ieq $env:COMPUTERNAME -or $fqdn -ieq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") {
                $raw = & $script:_HostPersist_Script
            } else {
                $icParams = @{ ComputerName=$fqdn; ScriptBlock=$script:_HostPersist_Script; ErrorAction='Stop' }
                $cred = Get-RemoteCredential
                if ($cred) { $icParams.Credential = $cred }
                $raw = Invoke-Command @icParams
            }
        } catch {
            $records.Add((New-CollectionError -Collector 'Host-Persistence' `
                -Target $fqdn -ErrorMessage $_.ToString() -RunId $runId))
            continue
        }

        if ($raw.errors -and $raw.errors.Count -gt 0) {
            Write-Warning "  [Host-Persistence] $fqdn — $($raw.errors -join '; ')"
        }

        $findings = _HostPersist_EvaluateFindings -Raw $raw -Target $target

        $records.Add((New-ReconRecord `
            -Collector      'Host-Persistence' `
            -ObjectType     'persistence-audit' `
            -StableId       "HostPersist:$fqdn" `
            -Category       'config' `
            -Tier           $target.Tier `
            -CollectedAtPriv $true `
            -Attributes     @{
                fqdn                 = $fqdn
                runKeyCount          = if ($raw.sections.runKeys)            { $raw.sections.runKeys.Count            } else { 0 }
                startupItemCount     = if ($raw.sections.startupItems)       { $raw.sections.startupItems.Count       } else { 0 }
                scheduledTaskCount   = if ($raw.sections.scheduledTasks)     { $raw.sections.scheduledTasks.Count     } else { 0 }
                wmiSubscriptionCount = if ($raw.sections.wmiSubscriptions)   { $raw.sections.wmiSubscriptions.Count   } else { 0 }
                suspiciousServiceCount=if ($raw.sections.suspiciousServices) { $raw.sections.suspiciousServices.Count } else { 0 }
                runKeys              = $raw.sections.runKeys
                startupItems         = $raw.sections.startupItems
                scheduledTasks       = $raw.sections.scheduledTasks
                wmiSubscriptions     = $raw.sections.wmiSubscriptions
                appInitDlls          = $raw.sections.appInitDlls
                lsaPackages          = $raw.sections.lsaPackages
                suspiciousServices   = $raw.sections.suspiciousServices
                collectionErrors     = @($raw.errors)
            } `
            -Findings  $findings.ToArray() `
            -RunId     $runId))
    }

    return $records
}

Register-Collector `
    -Name        'Host-Persistence' `
    -Description 'LOL and persistence location audit: Run/RunOnce registry keys, startup folders, non-Microsoft scheduled tasks, WMI subscriptions, AppInit_DLLs, LSA packages, suspicious service paths. Host-assessment mode only (requires RunContext.OverrideTargets). Findings: PERSIST-001 through PERSIST-007.' `
    -MinPrivilege 'LocalAdmin' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _HostPersist_Collect @PSBoundParameters }
