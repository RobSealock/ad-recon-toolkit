<#
.SYNOPSIS
    Self-bootstrapping interactive entry point for ad-recon-toolkit.

.DESCRIPTION
    Run this script to perform an AD and Server-OS assessment.

    Pass 1 (user context): runs all AnyAuthUser-privilege collectors.
    Pass 2 (elevated):     prompts for UAC/RunAs, then runs LocalAdmin/T0 collectors.

    Output lands in output\runs\<RunId>\ as normalized JSON plus a Markdown
    risk register under output\reports\.

.PARAMETER RepoRoot
    Root of the toolkit checkout. Defaults to the script's own directory.

.PARAMETER ElevatedPass
    Switch set automatically when re-launched elevated. Do not pass manually.

.PARAMETER RunId
    Carry the RunId from Pass 1 into the elevated Pass 2 so both passes
    write to the same run directory.

.PARAMETER SkipBootstrap
    Skip Install-Prereqs.ps1 (useful when re-launching elevated).

.PARAMETER NoGitCommit
    Do not commit run output to git after collection.

.PARAMETER NonInteractive
    Skip post-run option prompts. Use for scheduled tasks or CI pipelines.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot        = $PSScriptRoot,
    [switch]$ElevatedPass,
    [string]$RunId           = $null,
    [switch]$SkipBootstrap,
    [switch]$NoGitCommit,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2

# ── Local module path — prepend tools\modules\ so repo-local modules are found
# before any system-wide or user-profile installs. Install-Prereqs.ps1 saves
# all PSGallery modules here via Save-Module rather than Install-Module.
$localModulesDir = Join-Path $RepoRoot 'tools\modules'
if (Test-Path $localModulesDir) {
    $env:PSModulePath = "$localModulesDir$([System.IO.Path]::PathSeparator)$env:PSModulePath"
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════════╗'
Write-Host '║        ad-recon-toolkit  —  Blue-Team Assessment            ║'
Write-Host '╚══════════════════════════════════════════════════════════════╝'
Write-Host ''

# ── Config ────────────────────────────────────────────────────────────────────
$settingsPath      = Join-Path $RepoRoot 'config\settings.psd1'
$settingsLocalPath = Join-Path $RepoRoot 'config\settings.local.psd1'
$settings = if (Test-Path $settingsPath) { Import-PowerShellDataFile $settingsPath } else { @{} }
if (Test-Path $settingsLocalPath) {
    $local = Import-PowerShellDataFile $settingsLocalPath
    foreach ($k in $local.Keys) { $settings[$k] = $local[$k] }
}

# ── Setup wizard — domain check and settings.local.psd1 ──────────────────────
# Skipped on -NonInteractive (CI / scheduled task) and -ElevatedPass (continuation).
if (-not $NonInteractive -and -not $ElevatedPass) {

    # WMI domain membership check — WMI preferred (PS5.1); CIM fallback (PS7)
    $isDomainHost = $false
    $hostDomain   = $null
    try {
        $wmi          = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        $isDomainHost = [bool]$wmi.PartOfDomain
        $hostDomain   = $wmi.Domain
    } catch {
        try {
            $cim          = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $isDomainHost = [bool]$cim.PartOfDomain
            $hostDomain   = $cim.Domain
        } catch {
            Write-Warning '[Setup] WMI/CIM query failed — domain membership cannot be determined.'
        }
    }

    $hasLocal    = Test-Path $settingsLocalPath
    $hasTargetDC = ($settings['TargetDC'] -and $settings['TargetDC'] -ne '')

    Write-Host "[Setup] Domain-joined  : $(if ($isDomainHost) { $hostDomain } else { 'No (workgroup / standalone)' })"
    Write-Host "[Setup] settings.local : $(if ($hasLocal) { 'exists' } else { 'not found' })"
    Write-Host "[Setup] Remote mode    : $(if ($hasTargetDC) { "TargetDC = $($settings['TargetDC'])" } else { 'off' })"
    Write-Host ''

    if (-not $isDomainHost) {
        # These external tools shell out to third-party EXEs/modules that resolve their
        # own target via implicit Windows-auth domain membership rather than the
        # TargetDC/credential plumbing in framework\Connection.ps1 -- they degrade or
        # fail when there's no domain join to fall back on. Severity varies: some fail
        # loudly (a WARNING and a collection-error record), others soft-fail SILENTLY
        # with a clean-looking 0-findings result that is not actually a clean scan.
        Write-Host '[Setup] Non-domain-joined — the following will NOT run correctly:'
        Write-Host '  - Locksmith (ADCS ESC1-ESC16)      : HARD FAILS. Auto-detects the forest via the AD module; no -Domain override exists.'
        Write-Host '  - SharpHound (BloodHound data)     : SILENT. Only --Domain is passed (no -d/--LdapUsername/--LdapPassword) — produces an empty zip with no warning.'
        Write-Host '  - PingCastle (risk-rule scan)       : FAILS. Passes --server but no --user/--password — needs explicit creds when not domain-joined.'
        Write-Host '  - Group3r (GPO/RSOP analysis)       : SILENT. Analyzes THIS host''s local RSOP, not the target domain''s GPOs — a clean 0-findings result is not reassuring.'
        if ($settings['EnableCertipy']) {
            Write-Host '  - Certipy (ADCS, EnableCertipy=on)  : requires CertipyUsername/CertipyPassword in settings.local.psd1 (already warns if missing).'
        }
        if ($settings['EnableHardeningKitty']) {
            Write-Host '  - HardeningKitty (EnableHardeningKitty=on) : SILENT. Audits THIS host''s local policy, not the target DC — no warning if enabled.'
        }
        Write-Host '  Unaffected: AD-Core, DNS, Audit-Policy, Host-OS, GPO inventory/report (LDAP- and WinRM-based, fully remote-aware).'
        Write-Host ''
    }

    # Helper: wrap a string in PS single-quote syntax, escaping embedded quotes
    function _PSD1Str { param([string]$s) "'$($s -replace "'","''")'" }

    if (-not $isDomainHost -and -not $hasTargetDC) {
        # Not joined + no remote target → collectors will fail without configuration
        Write-Host '  This host is not domain-joined and TargetDC is not configured.'
        Write-Host '  Remote assessment requires a target DC, domain FQDN, and credentials.'
        Write-Host ''
        $ans = (Read-Host '  Configure remote settings in settings.local.psd1 now? [Y/N]').Trim().ToUpper()
        if ($ans -eq 'Y') {
            $tDC   = (Read-Host '  Target DC hostname or IP').Trim()
            $tDom  = (Read-Host '  Target domain FQDN (e.g. corp.example.com)').Trim()
            $tUser = (Read-Host '  Username (e.g. CORP\svc-assess or user@corp.com)').Trim()
            $tSec  = Read-Host '  Password' -AsSecureString
            $tPass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                         [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tSec))
            @(
                "# settings.local.psd1 — git-ignored. Created by setup wizard $(Get-Date -Format 'yyyy-MM-dd').",
                "@{",
                "    # Remote / cross-domain assessment",
                "    TargetDC       = $(_PSD1Str $tDC)",
                "    TargetDomain   = $(_PSD1Str $tDom)",
                "    TargetUsername = $(_PSD1Str $tUser)",
                "    TargetPassword = $(_PSD1Str $tPass)   # plaintext — this file is git-ignored",
                "",
                "    # Optional: BloodHound CE API (tokenId:tokenKey from BH CE Administration -> API Keys)",
                "    BloodHoundApiUrl  = ''",
                "    BloodHoundApiKey  = ''",
                "",
                "    # Optional: VulnCheck enrichment token",
                "    VulnCheckApiToken = ''",
                "}"
            ) | Set-Content $settingsLocalPath -Encoding UTF8
            Write-Host "  Written: $settingsLocalPath"
        } else {
            Write-Host '  Skipped. AD collectors will fail without domain access.'
            Write-Host "  Create config\settings.local.psd1 manually — see config\settings.psd1 for keys."
        }
        Write-Host ''
    } elseif (-not $hasLocal) {
        # Domain-joined (or TargetDC set) but no local file → offer blank template
        Write-Host '  config\settings.local.psd1 does not exist.'
        Write-Host '  Recommended for API tokens (BloodHound CE, VulnCheck) and per-machine overrides.'
        $ans = (Read-Host '  Create a blank template now? [Y/N]').Trim().ToUpper()
        if ($ans -eq 'Y') {
            @(
                "# settings.local.psd1 — git-ignored. Created by setup wizard $(Get-Date -Format 'yyyy-MM-dd').",
                "@{",
                "    # Optional: BloodHound CE API (tokenId:tokenKey from BH CE Administration -> API Keys)",
                "    BloodHoundApiUrl  = ''",
                "    BloodHoundApiKey  = ''",
                "",
                "    # Optional: VulnCheck enrichment token",
                "    VulnCheckApiToken = ''",
                "",
                "    # Remote / cross-domain assessment (uncomment and fill in if targeting a non-joined domain)",
                "    # TargetDC       = ''   # DC hostname or IP",
                "    # TargetDomain   = ''   # e.g. corp.example.com",
                "    # TargetUsername = ''   # e.g. CORP\svc-assess",
                "    # TargetPassword = ''   # plaintext — this file is git-ignored",
                "}"
            ) | Set-Content $settingsLocalPath -Encoding UTF8
            Write-Host "  Written: $settingsLocalPath"
        }
        Write-Host ''
    }

    # Reload settings so any newly written settings.local.psd1 takes effect this run
    $settings = if (Test-Path $settingsPath) { Import-PowerShellDataFile $settingsPath } else { @{} }
    if (Test-Path $settingsLocalPath) {
        $local = Import-PowerShellDataFile $settingsLocalPath
        foreach ($k in $local.Keys) { $settings[$k] = $local[$k] }
    }
}

# ── Bootstrap ─────────────────────────────────────────────────────────────────
if (-not $SkipBootstrap) {
    Write-Host '[Bootstrap] Verifying prerequisites...'
    & (Join-Path $RepoRoot 'bootstrap\Install-Prereqs.ps1') -RepoRoot $RepoRoot `
        -SkipRSAT:($settings['InstallRSATFeatures'] -eq $false) `
        -SkipPortablePython:($settings['InstallPortablePython'] -eq $false)
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Warning '[Bootstrap] Prerequisites check reported errors. Review output above.'
    }
}

# ── Load framework ────────────────────────────────────────────────────────────
foreach ($module in @('Schema','CollectorRegistry','RunContext','Repository')) {
    . (Join-Path $RepoRoot "framework\$module.ps1")
}

# ── Privilege detection ───────────────────────────────────────────────────────
$principal = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$heldPrivs = [System.Collections.Generic.List[string]]@('AnyAuthUser')
if ($isAdmin) {
    $heldPrivs.Add('LocalAdmin')
    $heldPrivs.Add('T0')
    Write-Host '[Context] Running elevated — all collectors eligible.'
} else {
    Write-Host '[Context] Running as standard user — user-context pass only.'
}

# ── RunContext ────────────────────────────────────────────────────────────────
$ctx = New-RunContext -RepoRoot $RepoRoot -HeldPrivileges $heldPrivs -ExistingRunId $RunId
Write-Host "[Context] RunId    : $($ctx.RunId)"
Write-Host "[Context] Operator : $($ctx.Operator)"
Write-Host "[Context] Host     : $($ctx.RunHost)  ($($ctx.Domain))"
Write-Host "[Context] Elevated : $($ctx.IsElevated)"
Write-Host ''

# ── Collector pass ────────────────────────────────────────────────────────────
$paths = & (Join-Path $RepoRoot 'Invoke-ADRecon.ps1') `
    -RunContext $ctx `
    -CollectorsPath (Join-Path $RepoRoot 'collectors') `
    -Settings $settings

# ── Elevation prompt (user-context run only) ──────────────────────────────────
if (-not $isAdmin -and -not $ElevatedPass) {
    Write-Host '────────────────────────────────────────────────────────────────'
    Write-Host '  Privileged collectors were SKIPPED (requires LocalAdmin / T0).'
    Write-Host '  These include: services, shares, local groups, CA registry,'
    Write-Host '  GPO content, PingCastle, SharpHound.'
    Write-Host '────────────────────────────────────────────────────────────────'
    $ans = Read-Host 'Launch elevated pass now? (UAC prompt will appear) [y/N]'
    if ($ans -match '^[Yy]') {
        $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" " +
                "-RepoRoot `"$RepoRoot`" -ElevatedPass -RunId `"$($ctx.RunId)`" -SkipBootstrap"
        if ($NoGitCommit) { $args += ' -NoGitCommit' }
        Start-Process powershell.exe -Verb RunAs -ArgumentList $args
        Write-Host '[Elevation] Elevated process launched. This window may be closed.'
        exit 0
    }
}

# ── Reports ───────────────────────────────────────────────────────────────────
Write-Host '[Reports] Generating risk register...'
$registerScript = Join-Path $RepoRoot 'report\New-RiskRegister.ps1'
if (Test-Path $registerScript) {
    & $registerScript -RunRoot $paths.RunRoot -RepoRoot $RepoRoot
}

Write-Host '[Reports] Generating validation cards...'
$validationScript = Join-Path $RepoRoot 'report\New-ValidationCards.ps1'
if (Test-Path $validationScript) {
    & $validationScript -RunRoot $paths.RunRoot -RepoRoot $RepoRoot
}

# ── Git commit ────────────────────────────────────────────────────────────────
if (-not $NoGitCommit -and $settings['GitCommitRuns']) {
    Invoke-GitCommitRun -RepoRoot $RepoRoot -RunId $ctx.RunId
}

# ── Assessment complete banner ────────────────────────────────────────────────
Write-Host ''
Write-Host '════════════════════════════════════════════════════════════════'
Write-Host '  Assessment complete'
Write-Host "  Run ID     : $($ctx.RunId)"
Write-Host "  Run output : $($paths.RunRoot)"
Write-Host "  Reports    : $($paths.Reports)"
Write-Host "  Validation : $(Join-Path $RepoRoot "output\validation\$($ctx.RunId)")"
Write-Host '════════════════════════════════════════════════════════════════'
Write-Host ''

# ── PurpleKnight reminder ─────────────────────────────────────────────────────
Write-Host '  REMINDER — PurpleKnight (manual step required)'
Write-Host '  Run PurpleKnight against this domain and save the CSV/HTML'
Write-Host "  export to:  $(Join-Path $RepoRoot 'output\purpleknight\')"
Write-Host '  The PurpleKnight collector will pick it up on the next full run.'
Write-Host ''

# ── SharpHound / BloodHound CE reminder ───────────────────────────────────────
# SharpHound.exe runs automatically, but the resulting zip is only USED
# automatically if BloodHoundApiUrl/BloodHoundApiKey are configured and the
# upload succeeds. Otherwise it just sits on disk until someone imports it.
$shRecordFile = Join-Path $paths.RunRoot 'SharpHound.bloodhound-collection.json'
if (Test-Path $shRecordFile) {
    $shRecord = Get-Content $shRecordFile -Encoding UTF8 | Where-Object { $_.Trim() } |
        ForEach-Object { ConvertFrom-Json $_ } | Select-Object -Last 1
    $shAttrs  = $shRecord.attributes
    # uploadStatus is only added to attributes when BloodHoundApiUrl is configured --
    # check property existence before dot-access (Set-StrictMode is active here).
    $shHasUploadStatus = $shAttrs.PSObject.Properties.Name -contains 'uploadStatus'
    $shUploaded = $shHasUploadStatus -and $shAttrs.uploadStatus -like 'uploaded*'
    if ($shAttrs.zipFile -and $shAttrs.zipFile -ne 'not produced' -and -not $shUploaded) {
        Write-Host '  REMINDER — SharpHound / BloodHound CE (manual step required)'
        Write-Host "  Zip collected but not auto-uploaded: $($shAttrs.zipFile)"
        Write-Host "  Import it into BloodHound CE manually, or set BloodHoundApiUrl"
        Write-Host '  and BloodHoundApiKey in settings.local.psd1 to automate this.'
        Write-Host ''
    }
}

# ── Post-run options ──────────────────────────────────────────────────────────
# Suppressed when -NonInteractive is set, -ElevatedPass is set (UAC window),
# or the host cannot accept keyboard input.
$canPrompt = -not $NonInteractive -and -not $ElevatedPass -and [Environment]::UserInteractive
if ($canPrompt) {
    $loop = $true
    while ($loop) {
        Write-Host '────────────────────────────────────────────────────────────────'
        Write-Host '  Post-run options:'
        Write-Host '    [W]  Generate wiki pages'
        Write-Host '    [T]  Run Pester framework self-tests'
        Write-Host '    [D]  Show drift summary'
        Write-Host '    [Enter]  Exit'
        Write-Host '────────────────────────────────────────────────────────────────'
        $choice = (Read-Host '  Choice').Trim().ToUpper()
        Write-Host ''
        switch ($choice) {
            'W' {
                $wikiScript = Join-Path $RepoRoot 'report\New-WikiPages.ps1'
                if (Test-Path $wikiScript) {
                    & $wikiScript -RunRoot $paths.RunRoot -RepoRoot $RepoRoot
                } else {
                    Write-Warning 'report\New-WikiPages.ps1 not found.'
                }
            }
            'T' {
                $testFile = Join-Path $RepoRoot 'tests\framework.tests.ps1'
                if (-not (Test-Path $testFile)) {
                    Write-Warning "Test file not found: $testFile"
                } elseif (-not (Get-Module -ListAvailable -Name Pester)) {
                    Write-Warning 'Pester not found. Install with: Install-Module Pester -Scope CurrentUser'
                } else {
                    Invoke-Pester $testFile -Output Detailed
                }
            }
            'D' {
                $diffDir = Join-Path $RepoRoot 'output\diffs'
                $latest  = Get-ChildItem $diffDir -Filter '*.md' -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latest) {
                    $inSummary = $false
                    foreach ($l in (Get-Content $latest.FullName)) {
                        if ($l -match '^## Summary')                            { $inSummary = $true }
                        if ($inSummary -and $l -match '^## ' -and $l -notmatch '^## Summary') { break }
                        if ($inSummary)                                         { Write-Host "  $l" }
                    }
                    Write-Host ''
                    Write-Host "  Full report: $($latest.FullName)"
                } else {
                    Write-Host '  No drift report found — a prior run is needed as a baseline.'
                }
            }
            ''  { $loop = $false }
            default { Write-Host "  Unknown option. Enter W, T, D, or press Enter to exit." }
        }
        Write-Host ''
    }
}
