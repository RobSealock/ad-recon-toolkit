<#
.SYNOPSIS
    Generates a structured set of Markdown wiki pages from a completed run.

.DESCRIPTION
    Produces tiered wiki documentation from the run's JSON records. Output
    is suitable for import into GitHub Wiki, Confluence, or any Markdown wiki.
    Pages are written to output\wiki\<RunId>\ by default.

    Pages generated:
      index.md          — Run overview, stats, finding summary
      tier-0.md         — All Tier-0 (Domain/Forest) findings and config
      tier-1.md         — Tier-1 (DC-adjacent) findings
      collector-*.md    — Per-collector detail pages
      ad-core.md        — AD domain/forest inventory
      host-os.md        — Host security posture per server
      ca-config.md      — AD CS / PKI configuration
      dns-records.md    — DNS zone summary and anomalies
      gpo-settings.md   — GPO inventory and security findings

.PARAMETER RunRoot
    Path to the specific run directory (output\runs\<RunId>\).

.PARAMETER RepoRoot
    Path to the repository root.

.PARAMETER OutputDir
    Optional override for the output directory. Defaults to output\wiki\<RunId>\.

.EXAMPLE
    .\report\New-WikiPages.ps1 -RunRoot .\output\runs\2024-01-15T09-00-00Z -RepoRoot .
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$RepoRoot,
    [string]$OutputDir = $null
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $RunRoot)) { throw "RunRoot not found: $RunRoot" }
$runId = Split-Path $RunRoot -Leaf

if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot "output\wiki\$runId"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Page {
    param([string]$Name, [string]$Content)
    $path = Join-Path $OutputDir $Name
    $Content | Set-Content $path -Encoding UTF8
    Write-Host "[WikiPages] → $Name"
}

function Load-RunRecords {
    $records = [System.Collections.Generic.List[object]]::new()
    Get-ChildItem -Path $RunRoot -Filter '*.json' -Depth 0 |
        Where-Object { $_.Name -ne 'run-manifest.json' } |
        ForEach-Object {
            try {
                # Two-step assign-then-wrap: under PS5.1, @(Cmd | ConvertFrom-Json)
                # does not reliably flatten a multi-element array (see
                # framework\Repository.ps1 for the full explanation).
                $itemsParsed = ConvertFrom-Json (Get-Content $_.FullName -Raw -Encoding UTF8)
                @($itemsParsed) | ForEach-Object { $records.Add($_) }
            } catch {}
        }
    return $records
}

$severityBadge = @{
    Critical     = '🔴 **CRITICAL**'
    High         = '🟠 **HIGH**'
    Medium       = '🟡 MEDIUM'
    Low          = '🟢 Low'
    Informational= 'ℹ️ Info'
}
$severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }

# ── Load data ─────────────────────────────────────────────────────────────────
$allRecords  = Load-RunRecords
$runManifest = $null
$manifestPath = Join-Path $RunRoot 'run-manifest.json'
if (Test-Path $manifestPath) {
    try { $runManifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
}

# Extract all findings
$allFindings = [System.Collections.Generic.List[hashtable]]::new()
foreach ($r in $allRecords) {
    if ($r.findings) {
        foreach ($f in $r.findings) {
            $allFindings.Add(@{
                Collector   = $r.collector
                StableId    = $r.stableId
                ObjectType  = $r.objectType
                Tier        = if ($r.tier) { $r.tier } else { 'unclassified' }
                Severity    = if ($f.severity) { $f.severity } else { 'Informational' }
                FindingId   = $f.id
                Technique   = if ($f.technique) { $f.technique } else { '' }
                Description = if ($f.description) { $f.description } else { '' }
                Reference   = if ($f.reference)   { $f.reference   } else { '' }
            })
        }
    }
}

$critCount = @($allFindings | Where-Object Severity -eq 'Critical').Count
$highCount = @($allFindings | Where-Object Severity -eq 'High').Count
$medCount  = @($allFindings | Where-Object Severity -eq 'Medium').Count
$lowCount  = @($allFindings | Where-Object Severity -eq 'Low').Count
$domain    = if ($runManifest) { $runManifest.domain } else { 'unknown' }
$runHost   = if ($runManifest) { $runManifest.runHost } else { 'unknown' }

# =============================================================================
# INDEX PAGE
# =============================================================================

$indexSb = [System.Text.StringBuilder]::new()
function ai { param([string]$l='') $indexSb.AppendLine($l) | Out-Null }

ai "# AD Assessment Wiki — $domain"
ai ""
ai "| | |"
ai "|--|--|"
ai "| **Run ID** | ``$runId`` |"
ai "| **Domain** | $domain |"
ai "| **Run Host** | $runHost |"
if ($runManifest) {
    ai "| **Start Time** | $($runManifest.startTime) |"
    ai "| **Operator** | $($runManifest.operator) |"
}
ai "| **Generated** | $(Get-Date -Date ([DateTime]::UtcNow) -Format 'yyyy-MM-dd HH:mm:ss UTC') |"
ai ""
ai "## Finding Summary"
ai ""
ai "| Severity | Count |"
ai "|----------|-------|"
ai "| 🔴 Critical | $critCount |"
ai "| 🟠 High | $highCount |"
ai "| 🟡 Medium | $medCount |"
ai "| 🟢 Low | $lowCount |"
ai "| **Total** | **$($allFindings.Count)** |"
ai ""
ai "## Pages"
ai ""
ai "| Page | Description |"
ai "|------|-------------|"
ai "| [Tier-0 Findings](tier-0.md) | Domain Controllers, AD DS, CA hosts — highest impact |"
ai "| [Tier-1 Findings](tier-1.md) | DC-adjacent servers (DNS, DHCP) |"
ai "| [AD Core](ad-core.md) | Domain/forest metadata, accounts, Kerberos, trusts |"
ai "| [Host OS Posture](host-os.md) | Per-server security flags, roles, services |"
ai "| [CA / AD CS](ca-config.md) | Certificate Authority configuration and templates |"
ai "| [DNS](dns-records.md) | DNS zone summary and anomalies |"
ai "| [GPO Settings](gpo-settings.md) | Group Policy inventory and security gaps |"
ai ""
ai "## Top Priority Findings"
ai ""
$topFindings = @($allFindings | Sort-Object { $severityOrder[$_.Severity] }, Tier, FindingId | Select-Object -First 15)
foreach ($f in $topFindings) {
    $badge = $severityBadge[$f.Severity]
    ai "- [$($f.FindingId)] $badge **[$($f.Tier)]** $($f.Collector): $($f.Description.Substring(0, [Math]::Min(150, $f.Description.Length)))"
}
ai ""

Write-Page 'index.md' $indexSb.ToString()

# =============================================================================
# TIER PAGES — helper
# =============================================================================

function New-TierPage {
    param([string]$Tier, [string]$Filename, [string]$Description)
    $sb = [System.Text.StringBuilder]::new()
    function a { param([string]$l='') $sb.AppendLine($l) | Out-Null }

    $tierFindings = @($allFindings | Where-Object { $_.Tier -eq $Tier } |
        Sort-Object { $severityOrder[$_.Severity] }, FindingId)
    $tierRecords  = @($allRecords  | Where-Object { $_.tier -eq $Tier })

    a "# $Tier Findings — $domain"
    a ""
    a "> $Description"
    a ""
    a "**$($tierFindings.Count) finding(s) in this tier.**"
    a ""

    if ($tierFindings.Count -gt 0) {
        a "## Findings"
        a ""
        a "| ID | Severity | Collector | Technique | Description |"
        a "|----|----|----|----|-----|"
        foreach ($f in $tierFindings) {
            $tech = if ($f.Technique) { $f.Technique } else { '—' }
            $desc = ($f.Description -replace '\|','\\|' -replace '\n',' ').Substring(0,[Math]::Min(200,$f.Description.Length))
            a "| $($f.FindingId) | $($severityBadge[$f.Severity]) | $($f.Collector) | $tech | $desc |"
        }
        a ""
    } else {
        a "_No findings for this tier in this run._"
        a ""
    }

    a "## Records ($($tierRecords.Count))"
    a ""
    $byType = $tierRecords | Group-Object objectType | Sort-Object Name
    foreach ($grp in $byType) {
        a "### $($grp.Name) ($($grp.Count))"
        a ""
        foreach ($r in $grp.Group | Select-Object -First 20) {
            a "- ``$($r.stableId)`` — collected: $($r.collectedAt)"
        }
        if ($grp.Count -gt 20) { a "_… and $($grp.Count - 20) more_" }
        a ""
    }

    Write-Page $Filename $sb.ToString()
}

New-TierPage -Tier 'T0' -Filename 'tier-0.md' `
    -Description 'Domain Controllers, CA hosts, AD DS infrastructure — compromise = full domain compromise.'

New-TierPage -Tier 'T1' -Filename 'tier-1.md' `
    -Description 'DC-adjacent servers: DNS, DHCP, management hosts — compromise enables significant lateral movement.'

# =============================================================================
# AD CORE PAGE
# =============================================================================

$adCoreSb = [System.Text.StringBuilder]::new()
function aa { param([string]$l='') $adCoreSb.AppendLine($l) | Out-Null }

$domainRec = $allRecords | Where-Object { $_.collector -eq 'AD-Core' -and $_.objectType -eq 'domain' } | Select-Object -First 1
$privGroups= $allRecords | Where-Object { $_.collector -eq 'AD-Core' -and $_.objectType -eq 'privileged-groups' } | Select-Object -First 1
$kerbRoast = $allRecords | Where-Object { $_.collector -eq 'AD-Core' -and $_.objectType -eq 'kerberoastable-accounts' } | Select-Object -First 1
$delegRec  = $allRecords | Where-Object { $_.collector -eq 'AD-Core' -and $_.objectType -eq 'delegation' } | Select-Object -First 1

aa "# AD Core — $domain"
aa ""
aa "## Domain Information"
aa ""
if ($domainRec -and $domainRec.attributes) {
    $di = $domainRec.attributes.domain
    $ki = $domainRec.attributes.kerberos
    $pw = $domainRec.attributes.passwordPolicy
    $acc= $domainRec.attributes.accountsSummary
    $fl = $domainRec.attributes.forest

    aa "| Attribute | Value |"
    aa "|-----------|-------|"
    aa "| Distinguished Name | ``$($di.distinguishedName)`` |"
    aa "| DNS Root | $($di.dnsRoot) |"
    aa "| Domain Functional Level | $($di.functionalLevel) |"
    aa "| Forest Functional Level | $($fl.functionalLevel) |"
    aa "| Machine Account Quota | $($di.machineAccountQuota) |"
    aa "| AD Recycle Bin | $(if($di.recycleBinEnabled){'✅ Enabled'}else{'❌ NOT enabled'}) |"
    aa "| Tombstone Lifetime | $($di.tombstoneLifetimeDays) days |"
    aa ""
    aa "## Kerberos"
    aa ""
    aa "| | |"
    aa "|--|--|"
    aa "| krbtgt Password Age | $($ki.krbtgtPasswordAge) days (last changed: $($ki.krbtgtLastChanged)) |"
    aa "| Supported Encryption | $($ki.supportedEncTypes -join ', ') |"
    aa ""
    aa "## Account Summary"
    aa ""
    aa "| Metric | Count |"
    aa "|--------|-------|"
    aa "| Total Users | $($acc.totalUsers) |"
    aa "| Enabled Users | $($acc.enabledUsers) |"
    aa "| Stale (90+ days no logon) | $($acc.staleUsers) |"
    aa "| Kerberoastable | $($acc.kerberoastableCount) |"
    aa "| AS-REP Roastable | $($acc.asrepRoastableCount) |"
    aa "| DES-Only | $($acc.desOnlyCount) |"
    aa "| Unconstrained Delegation (non-DC) | $($acc.unconstrainedDelegationCount) |"
    aa "| RBCD Configured | $($acc.rbcdCount) |"
    aa "| AdminSDHolder Protected | $($acc.adminSdHolderCount) |"
    aa ""
    aa "## Password Policy"
    aa ""
    aa "| Setting | Value |"
    aa "|---------|-------|"
    aa "| Minimum Length | $($pw.minPasswordLength) |"
    aa "| History Length | $($pw.passwordHistoryLength) |"
    aa "| Complexity Required | $(if($pw.complexityEnabled){'Yes'}else{'No'}) |"
    aa "| Lockout Threshold | $(if($pw.lockoutThreshold -eq 0){'Never'}else{$pw.lockoutThreshold}) |"
    aa ""
}

if ($domainRec.attributes.dcSyncHolders -and $domainRec.attributes.dcSyncHolders.Count -gt 0) {
    aa "## ⚠️ Non-Standard DCSync Rights"
    aa ""
    foreach ($holder in $domainRec.attributes.dcSyncHolders) {
        aa "- ``$holder``"
    }
    aa ""
}

if ($privGroups -and $privGroups.attributes.groups) {
    aa "## Privileged Group Membership"
    aa ""
    foreach ($grp in $privGroups.attributes.groups) {
        aa "### $($grp.groupName) ($($grp.members.Count))"
        if ($grp.members.Count -eq 0) {
            aa "_Empty_"
        } else {
            foreach ($m in $grp.members) {
                $status = if ($m.enabled) { '✅' } else { '❌ disabled' }
                aa "- $($m.samAccount) [$($m.objectClass)] $status"
            }
        }
        aa ""
    }
}

if ($domainRec.attributes.trusts -and $domainRec.attributes.trusts.Count -gt 0) {
    aa "## Domain Trusts"
    aa ""
    aa "| Partner | Direction | Transitive | SID Filtering |"
    aa "|---------|-----------|------------|---------------|"
    foreach ($t in $domainRec.attributes.trusts) {
        $dir = @{1='Inbound';2='Outbound';3='Bidirectional'}[[int]$t.direction]
        $sid = if ($t.sidFiltering) { '✅ Enabled' } else { '❌ Disabled' }
        aa "| $($t.partner) | $dir | $(if($t.isTransitive){'Yes'}else{'No'}) | $sid |"
    }
    aa ""
}

# AD-Core findings
$adcFindings = @($allFindings | Where-Object Collector -eq 'AD-Core' | Sort-Object { $severityOrder[$_.Severity] })
if ($adcFindings.Count -gt 0) {
    aa "## Findings"
    aa ""
    foreach ($f in $adcFindings) {
        aa "### $($f.FindingId) — $($severityBadge[$f.Severity])"
        aa ""
        aa $f.Description
        if ($f.Technique) { aa "" ; aa "_ATT&CK: $($f.Technique) — $($f.TechniqueName)_" }
        aa ""
    }
}

Write-Page 'ad-core.md' $adCoreSb.ToString()

# =============================================================================
# HOST OS PAGE
# =============================================================================

$hostSb = [System.Text.StringBuilder]::new()
function ah { param([string]$l='') $hostSb.AppendLine($l) | Out-Null }

ah "# Host OS Posture — $domain"
ah ""
$hostRecords = @($allRecords | Where-Object { $_.collector -eq 'Host-OS' -and $_.objectType -eq 'os-posture' })
if ($hostRecords.Count -eq 0) {
    ah "_No Host-OS records collected (requires LocalAdmin privilege via WinRM)._"
} else {
    ah "| Host | OS | Tier | Roles | Pending Reboot | Findings |"
    ah "|------|----|----|------|--|--|"
    foreach ($r in $hostRecords | Sort-Object { $r.tier }, { $r.attributes.fqdn }) {
        $a   = $r.attributes
        $os  = if ($a.os) { $a.os.caption + ' (' + $a.os.buildNumber + ')' } else { '?' }
        $fc  = if ($r.findings) { $r.findings.Count } else { 0 }
        $rb  = if ($a.os -and $a.os.pendingReboot) { '⚠️ YES' } else { '—' }
        $roles = if ($a.roles) { $a.roles -join ', ' } else { '—' }
        ah "| $($a.fqdn) | $os | $($r.tier) | $roles | $rb | $fc |"
    }
    ah ""

    # Per-host detail
    foreach ($r in $hostRecords | Sort-Object { $r.tier }) {
        $a  = $r.attributes
        $fl = $a.securityFlags
        ah "## $($a.fqdn) [$($r.tier)]"
        ah ""
        if ($fl -and $fl.Count -gt 0) {
            ah "| Security Control | State |"
            ah "|------------------|-------|"
            ah "| LSA RunAsPPL | $(if($fl.lsaRunAsPPL){'✅'}else{'❌'}) |"
            ah "| Credential Guard | $(if($fl.credentialGuardEnabled){'✅'}else{'❌'}) |"
            ah "| WDigest Caching | $(if($fl.wdigestCaching){'❌ ENABLED'}else{'✅ Disabled'}) |"
            ah "| SMBv1 | $(if($fl.smb1Enabled){'❌ ENABLED'}else{'✅ Disabled'}) |"
            ah "| SMB Signing Required | $(if($fl.smbSigningRequired){'✅'}else{'❌'}) |"
            ah "| LDAP Signing Required | $(if($fl.ldapSigningRequired){'✅'}else{'❌'}) |"
            ah "| LAPS | $(if($fl.lapsVersion -eq 'none'){'❌ Not deployed'}else{$fl.lapsVersion}) |"
            ah "| Print Spooler | $(if($fl.printSpoolerRunning){'❌ Running'}else{'✅ Stopped'}) |"
            ah "| WebClient | $(if($fl.webClientRunning){'❌ Running'}else{'✅ Stopped'}) |"
            ah "| RDP | $(if($fl.rdpEnabled){'Enabled'}else{'Disabled'}) $(if($fl.rdpEnabled -and -not $fl.rdpNLARequired){'❌ NO NLA'}elseif($fl.rdpEnabled){'✅ NLA'}else{''}) |"
            ah "| LLMNR | $(if($fl.llmnrEnabled){'❌ Enabled'}else{'✅ Disabled'}) |"
            ah "| NBT-NS | $(if($fl.nbtNSEnabled){'❌ Enabled'}else{'✅ Disabled'}) |"
            ah ""
        }
        if ($r.findings -and $r.findings.Count -gt 0) {
            ah "**Findings:**"
            ah ""
            foreach ($f in $r.findings | Sort-Object { $severityOrder[$_.severity] }) {
                ah "- [$($f.id)] $($severityBadge[$f.severity]) $($f.description.Substring(0,[Math]::Min(200,$f.description.Length)))"
            }
            ah ""
        }
    }
}

Write-Page 'host-os.md' $hostSb.ToString()

# =============================================================================
# CA CONFIG PAGE
# =============================================================================

$caSb = [System.Text.StringBuilder]::new()
function ac { param([string]$l='') $caSb.AppendLine($l) | Out-Null }

ac "# AD Certificate Services — $domain"
ac ""
$caInv = $allRecords | Where-Object { $_.collector -eq 'CA-Config' -and $_.objectType -eq 'ca-inventory' } | Select-Object -First 1
if (-not $caInv) {
    ac "_No CA-Config records collected._"
} else {
    $a = $caInv.attributes
    ac "**$($a.enterpriseCAs.Count) Enterprise CA(s) · $($a.totalTemplates) templates · $($a.publishedTemplateNames.Count) published**"
    ac ""
    foreach ($ca in $a.enterpriseCAs) {
        ac "## CA: $($ca.cn)"
        ac ""
        ac "- Host: ``$($ca.dnsHostName)``"
        ac "- Published templates: $($ca.publishedTemplates.Count)"
        ac ""
        if ($ca.enrollmentServers) {
            ac "**Enrollment URIs:**"
            foreach ($uri in $ca.enrollmentServers) {
                $httpWarn = if ($uri.isHttp) { ' ⚠️ HTTP (ESC8 risk)' } else { '' }
                ac "- ``$($uri.uri)`` (auth: $($uri.authType))$httpWarn"
            }
            ac ""
        }
    }

    # Template table
    $tmplRecords = @($allRecords | Where-Object { $_.collector -eq 'CA-Config' -and $_.objectType -eq 'certificate-template' -and $_.attributes.isPublished })
    if ($tmplRecords.Count -gt 0) {
        ac "## Published Templates ($($tmplRecords.Count))"
        ac ""
        ac "| Template | Schema | Enrollee Supplies Subject | Requires Approval | EKUs |"
        ac "|----------|--------|--------------------------|-------------------|------|"
        foreach ($tr in $tmplRecords | Sort-Object { $tr.attributes.cn }) {
            $ta = $tr.attributes
            $ess = if ($ta.enrolleeSupplies) { '⚠️ YES' } else { 'No' }
            $appr= if ($ta.requiresApproval) { '✅ Yes' } else { 'No' }
            $ekus= if ($ta.ekus) { $ta.ekus -join ', ' } else { 'none' }
            ac "| $($ta.displayName) | v$($ta.schemaVersion) | $ess | $appr | $ekus |"
        }
        ac ""
    }

    # CA findings
    $caFindings = @($allFindings | Where-Object Collector -eq 'CA-Config' | Sort-Object { $severityOrder[$_.Severity] })
    if ($caFindings.Count -gt 0) {
        ac "## Findings"
        ac ""
        foreach ($f in $caFindings) {
            ac "### $($f.FindingId) — $($severityBadge[$f.Severity])"
            ac ""
            ac $f.Description
            if ($f.Technique) { ac "" ; ac "_ATT&CK: $($f.Technique)_" }
            ac ""
        }
    }
}

Write-Page 'ca-config.md' $caSb.ToString()

# =============================================================================
# DNS PAGE
# =============================================================================

$dnsSb = [System.Text.StringBuilder]::new()
function ad { param([string]$l='') $dnsSb.AppendLine($l) | Out-Null }

ad "# DNS Zones — $domain"
ad ""
$dnsZones = @($allRecords | Where-Object { $_.collector -eq 'DNS' -and $_.objectType -eq 'dns-zone' })
if ($dnsZones.Count -eq 0) {
    ad "_No DNS records collected._"
} else {
    ad "| Zone | Dynamic Updates | Record Count | Orphan Records | New Records (24h) |"
    ad "|------|----------------|--------------|----------------|------------------|"
    foreach ($z in $dnsZones | Sort-Object { $z.attributes.zoneName }) {
        $za = $z.attributes
        $dynWarn = if ($za.dynamicUpdate -eq 'Nonsecure') { '⚠️ Nonsecure' } elseif ($za.dynamicUpdate) { $za.dynamicUpdate } else { '—' }
        $orphans = if ($za.orphanRecordCount) { $za.orphanRecordCount } else { '—' }
        $new24h  = if ($za.newRecordsLast24h)  { $za.newRecordsLast24h  } else { '0' }
        ad "| $($za.zoneName) | $dynWarn | $($za.recordCount) | $orphans | $new24h |"
    }
    ad ""
}

$dnsFindings = @($allFindings | Where-Object Collector -eq 'DNS' | Sort-Object { $severityOrder[$_.Severity] })
if ($dnsFindings.Count -gt 0) {
    ad "## DNS Findings"
    ad ""
    foreach ($f in $dnsFindings) {
        ad "- [$($f.FindingId)] $($severityBadge[$f.Severity]) $($f.Description)"
    }
    ad ""
}

Write-Page 'dns-records.md' $dnsSb.ToString()

# =============================================================================
# GPO SETTINGS PAGE
# =============================================================================

$gpoSb = [System.Text.StringBuilder]::new()
function ag { param([string]$l='') $gpoSb.AppendLine($l) | Out-Null }

ag "# GPO Settings — $domain"
ag ""
$gpoInv = $allRecords | Where-Object { $_.collector -eq 'GPO-Settings' -and $_.objectType -eq 'gpo-inventory' } | Select-Object -First 1
if (-not $gpoInv) {
    ag "_No GPO-Settings records collected._"
} else {
    $ga = $gpoInv.attributes
    $sa = $ga.settingsAgg
    ag "**$($ga.totalGPOs) GPO(s) · GPMC available: $($ga.hasGPMC) · GPP cpassword hits: $($ga.gppCpasswordHits)**"
    ag ""

    if ($sa) {
        ag "## Security Setting Coverage (via GPO)"
        ag ""
        ag "| Control | GPO Coverage |"
        ag "|---------|-------------|"
        ag "| WDigest Disabled | $(if($sa.wdigestDisabledByGPO){'✅'}else{'❌ No GPO'}) |"
        ag "| LLMNR Disabled | $(if($sa.llmnrDisabledByGPO){'✅'}else{'❌ No GPO'}) |"
        ag "| SMBv1 Disabled | $(if($sa.smb1DisabledByGPO){'✅'}else{'❌ No GPO'}) |"
        ag "| LSA RunAsPPL | $(if($sa.lsaPPLByGPO){'✅'}else{'❌ No GPO'}) |"
        ag "| Screensaver Lock | $(if($sa.screensaverLockByGPO){'✅'}else{'❌ No GPO'}) |"
        ag "| Print Spooler Disabled (DCs) | $(if($sa.spoolerDisabledByGPO){'✅'}else{'❌ No GPO'}) |"
        ag "| Advanced Audit Policy | $(if($sa.advancedAuditConfigured){'✅'}else{'❌ No GPO'}) |"
        ag ""
    }

    # GPO list
    ag "## GPO Inventory"
    ag ""
    ag "| GPO Name | GUID | Version | Last Changed | Disabled |"
    ag "|----------|------|---------|--------------|---------|"
    foreach ($gpo in $ga.gpoList | Sort-Object displayName) {
        $dis = if ($gpo.disabled) { '❌ Disabled' } else { '' }
        ag "| $($gpo.displayName) | ``$($gpo.guid)`` | $($gpo.versionNumber) | $($gpo.whenChanged) | $dis |"
    }
    ag ""
}

$gpoFindings = @($allFindings | Where-Object Collector -eq 'GPO-Settings' | Sort-Object { $severityOrder[$_.Severity] })
if ($gpoFindings.Count -gt 0) {
    ag "## Findings"
    ag ""
    foreach ($f in $gpoFindings) {
        ag "### $($f.FindingId) — $($severityBadge[$f.Severity])"
        ag ""
        ag $f.Description
        ag ""
    }
}

Write-Page 'gpo-settings.md' $gpoSb.ToString()

# =============================================================================
# DONE
# =============================================================================

Write-Host "[WikiPages] Complete → $OutputDir"
Write-Host "[WikiPages] Pages: index.md, tier-0.md, tier-1.md, ad-core.md, host-os.md, ca-config.md, dns-records.md, gpo-settings.md"
return $OutputDir
