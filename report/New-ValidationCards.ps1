<#
.SYNOPSIS
    Generates change-management-ready validation cards for each finding.
    Stub — full implementation in Milestone 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$RepoRoot
)

Write-Host '[ValidationCards] Milestone-1 stub — validation card generation implemented in Milestone 7.'
Write-Host "[ValidationCards] Mappings source: $RepoRoot\mappings\finding-attack-atomic.psd1"
