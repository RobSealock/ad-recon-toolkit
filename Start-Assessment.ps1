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
#>
[CmdletBinding()]
param(
    [string]$RepoRoot      = $PSScriptRoot,
    [switch]$ElevatedPass,
    [string]$RunId         = $null,
    [switch]$SkipBootstrap,
    [switch]$NoGitCommit
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

Write-Host ''
Write-Host "[Done] Assessment complete."
Write-Host "  Run output : $($paths.RunRoot)"
Write-Host "  Reports    : $($paths.Reports)"
Write-Host ''
