$Script:BackendAssemblyName = 'Raptor.Automation.dll'

function Test-IsBackendAvailable {
    [CmdletBinding()]
    param()

    $request = @{}

    try {
        Invoke-DruidBackend 'Ping' $request
    } catch {
        return $false;
    }

    return $true;
}

function New-Zone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ZoneName,
        [string] $Colour = '0,153,255',
        [float] $Criticality = 1.0
    )

    $request = @{
        ZoneName    = $ZoneName
        Criticality = $Criticality
        Colour      = $Colour
    }

    Invoke-DruidBackend 'CreateZone' $request
}

function Remove-Zone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ZoneId
    )

    $request = @{
        ZoneId = $ZoneId
    }

    Invoke-DruidBackend 'RemoveZone' $request
}

function Update-Zone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ZoneId,
        [Parameter(Mandatory)]
        [string] $ZoneName,
        [Parameter(Mandatory)]
        [float] $Criticality,
        [Parameter(Mandatory)]
        [string] $Colour
    )
    $request = @{
        ZoneId      = $ZoneId
        ZoneName    = $ZoneName
        Criticality = $Criticality
        Colour      = $Colour
    }
    Invoke-DruidBackend 'EditZone' $request
}

function Get-Zones {
    [CmdletBinding()]
    param()

    Invoke-DruidBackend 'GetZones'
}

function Get-ZoneData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ZoneId
    )
    $request = @{
        ZoneId = $ZoneId
        ZoneName = ''
        Criticality = 1.0
        Colour = ''
    }

    Invoke-DruidBackend 'GetZoneData' $request
}

function Reset-Graph {
    [CmdletBinding()]
    param()

    Invoke-DruidBackend 'ResetGraph'
}

function Export-Graph {
    [CmdletBinding()]
    param(
        [int] $NumLayers = 1,
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null
    )

    $request = @{
        NumLayers = $NumLayers
        DomainFilter = $Domainfilter
        ZoneFilter = $ZoneFilter
    }
    Invoke-DruidBackend 'ExportGraph' $request
}

function Sync-Graph {
    <#
    .SYNOPSIS
        Performs full data synchronization
    #>
    [CmdletBinding()]
    param(
        [bool] $OnPremiseCollectionEnabled = $true,
        [bool] $AzureCollectionEnabled = $false,
        [string[]] $AzureAccessTokens
    )
    $request = @{
        AzureCollectionEnabled     = $AzureCollectionEnabled
        AzureAccessTokens          = $AzureAccessTokens
    }
    if ($OnPremiseCollectionEnabled) {
        $request.CustomCollectors = @( @{ Name = "AD" } )
    }
    Invoke-DruidBackend 'SyncGraph' $request
}

function Set-Zone {
    [CmdletBinding()]
    <#
    .Description
    API to update Zone values of nodes given node OID or SID.
    .PARAMETER nodeIds
    List of node ids to update
    .PARAMETER ZoneId
    Use -Zone to indicate the zone in which you want to add to, or leave blank declassify
    .PARAMETER Declassify
    Use this flag to declassify objects
    .EXAMPLE
    PS> Set-Zone -NodeIds @(S-1-5-32-20335525-255552-5003) -Declassify (Declassifies node with SID "S-1-5-32-20335525-255552-5003")
    .EXAMPLE
    PS> Set-Zone -NodeIds @(S-1-5-32-20335525-255552-5003,S-1-5-32-20335525-255552-5004) -ZoneId "T0" (Sets nodes with SID S-1-5-32-20335525-255552-5003 and S-1-5-32-20335525-255552-5004 to zone T0)
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$NodeIds,
        [string] $ZoneId = '',
        [switch] $Declassify
    )

    if ($Declassify) {
        $ZoneId = ""
    }

    $query = @{
        Nodes  = $NodeIds
        ZoneID = $ZoneId
    }

    Invoke-DruidBackend 'UpdateGraph' $query
}

function Set-ZeroCost {
    [CmdletBinding()]
    param(
        [int] $BlowoutPaths = 250
    )

    $request = @{
        BlowoutPaths = $BlowoutPaths
    }
    Invoke-DruidBackend 'FindAndClassifyZeroCostPaths' $request
}

function Get-EnvironmentMetadata {
    [CmdletBinding()]
    param(
    )

    Invoke-DruidBackend 'GetEnvironmentMetadata'
}

function Get-Graph {
    [CmdletBinding()]
    param(
        [int] $NumLayers = 1,
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null,
        [string] $ExpansionNodeId = $null,
        [switch] $ShowWholeGraph
    )

    if ($ShowWholeGraph) {
        $query = @{
            ShowWholeGraph = $true
        }
    } else {
        $query = @{
            NumLayers    = $NumLayers
            DomainFilter = $Domainfilter
            ZoneFilter   = $ZoneFilter
            ExpansionNodeId = $ExpansionNodeId
        }
    }
    $query = $query

    Invoke-DruidBackend 'QueryGraph' $query
}

function Get-Node {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OID
    )

    $query = @{
        OID = $OID
    }
    $result = Invoke-DruidBackend 'QueryByOID' $query

    $result.QueryByOIDResult
}

function Get-AllNodes {
	[CmdletBinding()]
	param()

	Invoke-DruidBackend 'QueryAllNodes'
}

function Get-AttackPaths {
    [CmdletBinding()]
    param(
        [int] $BlowoutPaths = 250,
        [string] $AttackerId = '',
        [string] $TargetId = '',
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null,
        [switch] $GetZeroCostPaths,
		[switch] $ReturnNonPrincipals,
		[switch] $SkipBlowoutPaths,
		[switch] $ZeroCostOnly
    )

    $request = @{
        BlowoutPaths  = $BlowoutPaths
        AttackerID    = $AttackerId
        TargetID      = $TargetId
        DomainFilter  = $Domainfilter
        ZoneFilter    = $ZoneFilter
        ZeroCostPaths = $GetZeroCostPaths.ToBool()
		ReturnPrincipalsOnly = (-not $ReturnNonPrincipals)
        IncludeBlowoutPaths = (-not $SkipBlowoutPaths)
        ZeroCostOnly = $ZeroCostOnly.ToBool()
    }

    Invoke-DruidBackend 'DetermineAttackPaths' $request
}

function Export-AttackPaths {
    [CmdletBinding()]
    param(
        [int] $BlowoutPaths = 250,
        [string] $AttackerId = '',
        [string] $TargetId = '',
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null,
        [switch] $GetZeroCostPaths,
		[switch] $ReturnNonPrincipals,
		[switch] $IncludeBlowoutPaths,
		[switch] $ZeroCostOnly
    )

    $request = @{
        BlowoutPaths  = $BlowoutPaths
        AttackerID    = $AttackerId
        TargetID      = $TargetId
        DomainFilter  = $Domainfilter
        ZoneFilter    = $ZoneFilter
        ZeroCostPaths = $GetZeroCostPaths.ToBool()
		ReturnPrincipalsOnly = (-not $ReturnNonPrincipals)
        IncludeBlowoutPaths = $IncludeBlowoutPaths.ToBool()
        ZeroCostOnly = $ZeroCostOnly.ToBool()
    }

    Invoke-DruidBackend 'ExportAttackPaths' $request
}

function Get-ProtoByOid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $OIDs
    )

    $query = @{
        Oids = $OIDs
    }

    Invoke-DruidBackend 'GetByOID' $query
}

function Get-ProtoAll {
    [CmdletBinding()]
    param()

    Invoke-DruidBackend 'QueryAll'
}

function Get-ReachabilityReport {
    [CmdletBinding()]
    param(
        [int] $BlowoutPaths = 250,
        [string] $AttackerId = '',
        [string] $TargetId = '',
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null,
        [switch] $GetZeroCostPaths,
		[switch] $ByGroup
    )

    $request = @{
        BlowoutPaths  = $BlowoutPaths
        AttackerID    = $AttackerId
        TargetID      = $TargetId
        DomainFilter  = $Domainfilter
        ZoneFilter    = $ZoneFilter
        ZeroCostPaths = $GetZeroCostPaths.ToBool()
		ReachabilityByGroup = $ByGroup.ToBool()
		ReachabilityNode = $null
    }
    Invoke-DruidBackend 'ReachabilityReport' $request
}

function Find-NodeReachability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Oid,
        [int] $BlowoutPaths = 250,
		[string] $AttackerId = '',
        [string] $TargetId = '',
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null,
        [switch] $GetZeroCostPaths,
		[switch] $ByGroup
    )

    $request = @{
        BlowoutPaths  = $BlowoutPaths
        AttackerID    = $AttackerId
        TargetID      = $TargetId
        DomainFilter  = $Domainfilter
        ZoneFilter    = $ZoneFilter
        ZeroCostPaths = $GetZeroCostPaths.ToBool()
		ReachabilityByGroup = $ByGroup.ToBool()
		ReachabilityNode = $Oid
    }
    Invoke-DruidBackend 'NodeReachability' $request
}

function Find-RiskReduction {
    [CmdletBinding()]
    param(
		[int] $BlowoutPaths = 250,
        [string] $AttackerId = '',
        [string] $TargetId = '',
        [string[]] $DomainFilter = $null,
        [string[]] $ZoneFilter = $null,
        [switch] $GetZeroCostPaths,
		[string] $ZoneId = '',
        [switch] $ByNode,
		[switch] $ByRight
    )

    $request = @{
        ByRight = $ByRight.ToBool()
		ByNode = $ByNode.ToBool()
		BlowoutPaths  = $BlowoutPaths
        AttackerID    = $AttackerId
        TargetID      = $TargetId
        DomainFilter  = $Domainfilter
        ZoneFilter    = $ZoneFilter
        ZeroCostPaths = $GetZeroCostPaths.ToBool()
		ZoneId = $ZoneId
    }
    Invoke-DruidBackend 'FindRiskReduction' $request
}

function Import-Zones{
	[CmdletBinding()]
    param(
		[Parameter(Mandatory)]
        [string] $path
	)

	$request = @{
        MigrationPath  = $path
    }

    Invoke-DruidBackend 'MigratePreviousData' $request
}

function Get-AllEdgeTypes {
    [CmdletBinding()]
    param()

    $nodes = Get-ProtoAll
    $edges = $nodes.Incoming

    $counts = @{}
    # Iterate through the objects
    foreach ($edge in $edges.Type) {

        # If the type is not in the hashtable, add it with a count of 1
        if (-not $counts.ContainsKey($edge)) {
            $counts[$edge] = 1
        }
        # If the type is in the hashtable, increment the count
        else {
            $counts[$edge]++
        }
    }

    # Output the counts
    $sum = $counts.GetEnumerator() | Measure-Object -Property Value -Sum | Select-Object -ExpandProperty Sum
    $counts['Total Edges'] = $sum

    $totalCount = $counts.Keys | ForEach-Object {
        [PSCustomObject]@{
            'Edge Name' = $_
            'Count'     = $counts[$_]
        }
    }

    return $totalCount
}

function Get-ZoneIsolationScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ZoneId,
        [string[]] $DomainFilter = $null
    )

    $query = @{
        ZoneFilter = @($ZoneId)
        DomainFilter = $DomainFilter
    }
    $result = Invoke-DruidBackend 'GetZoneIsolationScores' $query
}

$Script:BackendAccessMode = 'Direct'
$Script:BackendEndpoint = $null
$Script:BackendAccessToken = $null
function Set-DruidBackend {
    <#
    .SYNOPSIS
        Specifies the desired backend access mode
    .PARAMETER Direct
        Loads backend libraries in the current process and provides fast and direct access to its classes and properties
    .PARAMETER Endpoint
        Switches to backend REST endpoint and transfers serialized data over http
    #>
    param (
        [Parameter(Mandatory, ParameterSetName = 'Http')]
        [Uri] $Endpoint,

        [Parameter(ParameterSetName = 'Http')]
        [string] $AccessToken = $env:RAPTOR_TOKEN,

        [Parameter(Mandatory, ParameterSetName = 'Direct')]
        [switch] $Direct
    )
    if ($Direct) {
        $Script:BackendAccessMode = 'Direct'
        $Script:BackendEndpoint = $null
        $Script:BackendAccessToken = $null
        Write-Host "Switched to Direct Backend Access Mode"
    } else {
        $Script:BackendAccessMode = 'Http'
        $Script:BackendEndpoint = $Endpoint
        $Script:BackendAccessToken = $AccessToken
        Write-Host "Switched to Rest Endpoint [$Endpoint]"
        if (-not $AccessToken) {
            Write-Warning "Access token was not specified"
        }
    }
}

function Start-DruidBackend {
    [CmdletBinding()]
    param()

    switch ($Script:BackendAccessMode) {
        Http {
            $process = Get-Process -Name 'raptor.backend' -ErrorAction 'SilentlyContinue'
            if (-not $process) {
                Write-Warning "Druid Backend not running on local machine"
                return
            }
        }
        Direct {
            $workingDirectory = Split-Path $Script:BackendAssemblyPath -Parent
            [System.IO.Directory]::SetCurrentDirectory($workingDirectory)

            try {
                Add-Type -AssemblyName $Script:BackendAssemblyPath -Verbose -ErrorAction 'SilentlyContinue'
            } catch [System.IO.FileNotFoundException] {
                # PowerShell version < 6.0
            }
            if (-not ('Semperis.Raptor.Automation.BackendLoader' -as [type])) {
                Write-Error "Cannot use Direct backend access mode in PS version [$($PSVersionTable.PSVersion)]. Use Set-DruidBackend cmdlet to cofigure http access"
            } else {
                $Script:Backend = [Semperis.Raptor.Automation.BackendLoader]::Load()
                $Script:Backend.InitializeGraphServices()
                $Script:Backend.ReadLogOutput() | Out-Null # Clear console output, captured before Backend calls
            }
        }
    }
}

function Invoke-DruidBackend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Method,

        [Parameter(Position = 1)]
        [object] $Request
    )
    $requestLevels = 4
    switch ($Script:BackendAccessMode) {
        Direct {
            Start-DruidBackend
            if ($null -eq $Script:Backend) {
                return
            }
            try {
                if ($null -ne $Request) {
                    $argument = ConvertTo-Json $Request -Depth $requestLevels -Compress

                    Write-Verbose "$Method($argument)"
                    $Script:Backend."$Method"($argument)
                } else {
                    Write-Verbose "$Method()"
                    $Script:Backend."$Method"()
                }
            } catch {
                throw $_.Exception.InnerException
            } finally {
                Stop-DruidBackend
            }
        }
        Http {
            $httpEndpoint = [Uri]::new([Uri]$Script:BackendEndpoint, "/v1/$($Method)")
            $webRequest = @{
                Uri     = $httpEndpoint
                Headers = @{
                    access_token = $Script:BackendAccessToken
                }
            }
            if ($null -ne $Request) {
                $webRequest += @{
                    Method      = 'POST'
                    Body        = $Request
                    ContentType = 'application/json'
                }
            }
            $webRequest | ConvertTo-Json -Depth ($requestLevels + 1) | Write-Verbose

            if ($webRequest.Body) {
                $webRequest.Body = ConvertTo-Json $webRequest.Body -Depth $requestLevels -Compress
            }
            Invoke-RestMethod @webRequest
        }
    }
}

function Stop-DruidBackend {
    [CmdletBinding()]
    param()

    if ($null -eq $Script:Backend) {
        return
    }
    $backendLog = $Script:Backend.ReadLogOutput()

    $Script:Backend.Dispose()
    $Script:Backend = $null

    if (-not(Test-Path $Script:BackendLogPath)) {
        '' | Out-File $Script:BackendLogPath
    }

    try {
        $backendLog | Out-File $Script:BackendLogPath -Append -ErrorAction 'Stop'
    } catch {
        if ($_ -like '*The process cannot access the file*') {
            Write-Warning "Cannot write to [$($Script:BackendLogPath)]. Using [$($Script:BackendApiLogPath)]"
            $backendLog | Out-File $Script:BackendApiLogPath -Append
            return
        }
        throw
    }
}

$Script:BackendAssemblyPath = Resolve-Path -Path @(
    "$PSScriptRoot\..\..\$($BackendAssemblyName)"
    "$PSScriptRoot\..\..\..\ForestDruid-Community\Backend\$($BackendAssemblyName)"
) -ErrorAction 'SilentlyContinue' | Select-Object -First 1
if ($null -eq $Script:BackendAssemblyPath) {
    Write-Warning "$($Script:BackendAssemblyName) was not found. Cannot use Direct backend access mode"

    Set-DruidBackend -Endpoint 'http://localhost/' -AccessToken ($env:RAPTOR_TOKEN) -Verbose
    return
} else {
    Write-Verbose "$($Script:BackendAssemblyPath) was successfully loaded"
}

$Script:BackendFolderPath = Split-Path $Script:BackendAssemblyPath -Parent
$Script:BackendLogPath = Join-Path $Script:BackendFolderPath -ChildPath 'backend.log'
$Script:BackendApiLogPath = Join-Path $Script:BackendFolderPath -ChildPath 'backend.api.log'
