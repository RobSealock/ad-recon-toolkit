# Collector self-registration and privilege gating.
# Dot-source this file once before loading collector files.

$script:_CollectorRegistry = [System.Collections.Generic.List[hashtable]]::new()

# Privilege rank table — higher rank = more privileged.
# A held privilege satisfies any requirement at equal or lower rank.
$script:_PrivRank = @{
    AnyAuthUser = 0
    DHCPRead    = 1
    DNSAdmin    = 1
    CARead      = 1
    LocalAdmin  = 2
    T0          = 3
}

function Register-Collector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)]
        [ValidateSet('AnyAuthUser','LocalAdmin','DHCPRead','DNSAdmin','CARead','T0')]
        [string]$MinPrivilege,
        [Parameter(Mandatory)][scriptblock]$Invoke
    )
    if ($script:_CollectorRegistry | Where-Object { $_.Name -eq $Name }) {
        Write-Warning "[Registry] Collector '$Name' already registered — skipping duplicate."
        return
    }
    $script:_CollectorRegistry.Add(@{
        Name         = $Name
        Description  = $Description
        MinPrivilege = $MinPrivilege
        Invoke       = $Invoke
    })
    Write-Verbose "[Registry] Registered: $Name  (MinPriv=$MinPrivilege)"
}

function Get-RegisteredCollectors {
    return $script:_CollectorRegistry
}

function Test-CollectorEligible {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][string[]]$HeldPrivileges
    )
    $required = $script:_PrivRank[$Collector.MinPrivilege]
    foreach ($held in $HeldPrivileges) {
        if ($script:_PrivRank.ContainsKey($held) -and $script:_PrivRank[$held] -ge $required) {
            return $true
        }
    }
    return $false
}
