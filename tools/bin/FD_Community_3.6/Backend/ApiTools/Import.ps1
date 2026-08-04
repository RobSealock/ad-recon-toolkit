<#
.SYNOPSIS
    Makes all modules in current folder discoverable by PowerShell
#>
$env:PSModulePath += ";$PSScriptRoot"

Import-Module -Name 'DruidApi'
Add-Type -AssemblyName 'Microsoft.Extensions.Diagnostics', 'Collector.Core'