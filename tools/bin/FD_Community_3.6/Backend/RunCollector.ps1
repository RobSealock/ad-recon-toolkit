# Ex: Powershell.exe -ExeuctionPolicy Bypass -File <Location>/RunCollector.ps1 (collector arguments)

Set-Location $PSScriptRoot

Write-Host "Running Collector"
$log = Join-Path $PSScriptRoot "/Log-CollectorExecutable.txt"
./Collector.exe @args 2>&1> $log
Write-Host "Done. Output to $log"