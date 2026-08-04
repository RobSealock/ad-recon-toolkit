$Script:DruidInstallPath = "C:\Raptor\ForestDruid-Community"
$Script:DruidBackendPath = Join-Path $Script:DruidInstallPath -ChildPath 'Backend'
$Script:DruidBackendLogPath = Join-Path $Script:DruidBackendPath -ChildPath 'backend.log'
$Script:DruidBackendApiLogPath = Join-Path $Script:DruidBackendPath -ChildPath 'backend.api.log'

function Retry {
    [CmdletBinding()]
    param(
        [scriptblock] $func,
        $timeoutSec = 180,
        $intervalSec = 1
    )

    $stopwatch = [system.diagnostics.stopwatch]::StartNew()

    while ($stopwatch.ElapsedMilliseconds -lt $timeoutSec * 1000) {
        try {
            & $func
            break
        }
        catch {
            Write-Host $($_.Exception.Message)
            Start-Sleep $intervalSec
        }
    }
}

function ForceReplication {
    param($dc)

    Write-Host (repadmin /replsummary)

    (Get-ADDomainController -Filter *).Hostname | Foreach-Object { repadmin /syncall $_ (Get-ADDomain).DistinguishedName /e /A }

    $status = Get-ADReplicationPartnerMetadata -Target $dc -PartnerType Both -Partition *

    if ( ($status.Count -ne 6) -or (($status | where LastReplicationResult -ne 0 ).Count -ne 0) ) {
        Write-Host $status
        throw "Replication errors"
    }
}

function WaitLowCpuUsage {
    param($timeoutSec = 600)

    $intervalSec = 10
    $cpuLevelPercent = 10

    while ($stopwatch.ElapsedMilliseconds -lt $timeoutSec * 1000) {

        $stopwatch = [system.diagnostics.stopwatch]::StartNew()
        Write-Host "wait CPU usage < $cpuLevelPercent% for $intervalSec sec"

        if ( (1 .. $intervalSec | % { (Get-CimInstance Win32_Processor).LoadPercentage -lt $cpuLevelPercent }).where({ -not $_ }).Count -eq 0 ) {
            break
        }

        Start-Sleep 5
    }
}

#region Logging

function Copy-TestLog {
    <#
    .SYNOPSIS
        Copies test log entries to specified path starting from moment, specified in $Start parameter
    .PARAMETER Start
        Indicates point in time from which
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(Position = 1)]
        [ValidateNotNull()]
        [DateTime] $From = '0001-01-01T00:00:00.0000000'
    )

    if (-not(Test-Path $Script:DruidBackendLogPath)) {
        Write-Error "[$($Script:DruidBackendLogPath)] does not exist"
        return
    }

    $testFolderPath = Split-Path $Path -Parent
    if (-not(Test-Path $testFolderPath)) {
        Write-Verbose "Test log path folder does not exist [$testFolderPath]. Creating"
        New-Item -ItemType 'Directory' -Path $testFolderPath | Out-Null
        Set-Content $Path -Value ''
    }

    $timeWindowStarted = $false
    $logContent = Get-Content $Script:DruidBackendLogPath
    if(Test-Path $Script:DruidBackendApiLogPath){
        $logContent += Get-Content $Script:DruidBackendApiLogPath
        Remove-Item -Path $Script:DruidBackendApiLogPath
    }

    $logDateFormat = 'dd/MM/yy HH:mm:ss:fff'
    foreach ($logEntry in $logContent) {
        if (-not $timeWindowStarted -and $logEntry -match '^\[(?<date>[\d\s:/]+)\]\s') {
            $entryTime = [DateTime]::ParseExact($Matches.date, $logDateFormat, $null, [Globalization.DateTimeStyles]::AssumeLocal)

            Write-Debug "entryTime: $entryTime"
            if ($entryTime -ge $From) {
                $timeWindowStarted = $true
            }
        }

        if ($timeWindowStarted) {
            $logEntry | Add-Content $Path
        }
    }

    if (-not $timeWindowStarted) {
        Write-Error "No backend log entries found later than [$From]"
    }
}

#endregion
