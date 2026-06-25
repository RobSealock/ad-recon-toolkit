<#
.SYNOPSIS
    Per-host OS configuration and persistence assessment.

.DESCRIPTION
    Runs targeted OS hardening and persistence checks against one or more Windows
    hosts via WinRM. Designed for member servers and workstations — does not require
    or perform AD LDAP discovery. Targets are supplied explicitly rather than
    discovered from Active Directory.

    Collectors run:
      Host-OS          OS hardening checks (DC-role findings suppressed automatically)
      Host-Roles       Server role/feature inventory with risky-role flagging
      Host-Persistence LOL persistence location audit

    Audit-Policy and Host-Firewall are excluded until they gain OverrideTargets
    support — they currently do AD LDAP discovery internally.

.PARAMETER Target
    Single target hostname, FQDN, or IP address.

.PARAMETER TargetList
    Path to a plain-text file with one hostname/FQDN per line.
    Lines beginning with # are treated as comments and skipped.

.PARAMETER RunId
    Reuse an existing RunId to merge output into an existing run directory.
    Omit to generate a new RunId automatically.

.PARAMETER RepoRoot
    Path to the ad-recon-toolkit root. Defaults to the directory containing
    this script.

.PARAMETER Tier
    Security tier to assign all supplied targets. Default: T1.

.PARAMETER SkipElevationPrompt
    Suppress the elevation warning. Useful in automated/scheduled contexts.

.EXAMPLE
    .\Start-HostAssessment.ps1 -Target fs01.corp.example.com

.EXAMPLE
    .\Start-HostAssessment.ps1 -TargetList .\config\servers.txt -Tier T1

.EXAMPLE
    .\Start-HostAssessment.ps1 -Target ws01.corp.local -RunId 'abc12345'
#>
[CmdletBinding()]
param(
    [string] $Target              = '',
    [string] $TargetList          = '',
    [string] $RunId               = '',
    [string] $RepoRoot            = $PSScriptRoot,
    [ValidateSet('T0','T1','T2')]
    [string] $Tier                = 'T1',
    [switch] $SkipElevationPrompt
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

foreach ($m in @('Schema','CollectorRegistry','RunContext','Repository','Connection')) {
    . (Join-Path $RepoRoot "framework\$m.ps1")
}

$Settings = Import-PowerShellDataFile (Join-Path $RepoRoot 'config\settings.psd1')
$localPath = Join-Path $RepoRoot 'config\settings.local.psd1'
if (Test-Path $localPath) {
    $local = Import-PowerShellDataFile $localPath
    foreach ($k in $local.Keys) { $Settings[$k] = $local[$k] }
}

# Build explicit target list
$rawTargets = [System.Collections.Generic.List[string]]::new()
if ($Target)     { $rawTargets.Add($Target.Trim()) }
if ($TargetList -and (Test-Path $TargetList)) {
    Get-Content $TargetList |
        Where-Object { $_ -and $_ -notmatch '^\s*#' } |
        ForEach-Object { $rawTargets.Add($_.Trim()) }
}
if ($rawTargets.Count -eq 0) {
    Write-Error 'No targets specified. Use -Target <hostname> or -TargetList <path>.'
    exit 1
}

$targetObjects = @($rawTargets | ForEach-Object {
    @{ FQDN=$_; Name=($_ -split '\.')[0]; Roles=@('MemberServer'); Tier=$Tier }
})

# Build RunContext
$ctxParams = @{ RepoRoot=$RepoRoot; HeldPrivileges=@('AnyAuthUser') }
if ($RunId) { $ctxParams['ExistingRunId'] = $RunId }
$RunContext = New-RunContext @ctxParams

# Inject targets and mode flag — collectors check for OverrideTargets to skip
# their own AD LDAP discovery. TargetType='Member' is informational for future use.
$RunContext | Add-Member -NotePropertyName 'OverrideTargets' -NotePropertyValue $targetObjects
$RunContext | Add-Member -NotePropertyName 'TargetType'      -NotePropertyValue 'Member'

$principal = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-HeldPrivilege -RunContext $RunContext -Privilege 'LocalAdmin'
    Add-HeldPrivilege -RunContext $RunContext -Privilege 'T0'
}

Write-Host ''
Write-Host '[ Host Assessment  -  ad-recon-toolkit ]'
Write-Host ''
Write-Host "  RunId     : $($RunContext.RunId)"
Write-Host "  Operator  : $($RunContext.Operator)"
Write-Host "  Elevated  : $($RunContext.IsElevated)"
Write-Host "  Tier      : $Tier"
Write-Host "  Targets   : $($targetObjects.Count)"
$targetObjects | ForEach-Object { Write-Host "              $($_.FQDN)" }
Write-Host ''

if (-not $RunContext.IsElevated -and -not $SkipElevationPrompt) {
    Write-Warning 'Not running as Administrator. WinRM checks require local admin on target(s).'
    Write-Warning 'Re-run elevated (Run as Administrator) for full collection.'
    Write-Host ''
}

$filter = @('Host-OS','Host-Roles','Host-Persistence')

$paths = & (Join-Path $RepoRoot 'Invoke-ADRecon.ps1') `
    -RunContext      $RunContext `
    -Settings        $Settings `
    -CollectorFilter $filter

$reportScript = Join-Path $RepoRoot 'report\New-RiskRegister.ps1'
if ($paths -and (Test-Path $reportScript)) {
    & $reportScript -RunRoot $paths.RunRoot -RepoRoot $RepoRoot
}
