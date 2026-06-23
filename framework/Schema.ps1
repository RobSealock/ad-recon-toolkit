# Record and finding factory functions used by every collector.
# All output normalization flows through these — do not bypass them.

function New-ReconRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$StableId,
        [Parameter(Mandatory)][ValidateSet('config','state')][string]$Category,
        [ValidateSet('T0','T1','T2','T3','unclassified')][string]$Tier = 'unclassified',
        [bool]$CollectedAtPriv = $false,
        [hashtable]$Attributes = @{},
        [array]$Findings = @(),
        [string]$RawArtifactRef = $null,
        [Parameter(Mandatory)][string]$RunId
    )
    [PSCustomObject]@{
        collector       = $Collector
        objectType      = $ObjectType
        stableId        = $StableId
        category        = $Category
        tier            = $Tier
        collectedAtPriv = $CollectedAtPriv
        attributes      = $Attributes
        findings        = $Findings
        rawArtifactRef  = $RawArtifactRef
        runId           = $RunId
        timestamp       = (Get-Date -Format 'o')
    }
}

function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [string]$Technique = $null,
        [Parameter(Mandatory)][string]$Description,
        [string]$Reference = $null
    )
    [PSCustomObject]@{
        id          = $Id
        severity    = $Severity
        technique   = $Technique
        description = $Description
        reference   = $Reference
    }
}

function New-ReviewRequired {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Topic,
        [Parameter(Mandatory)][string]$Reason,
        [string]$RunId = ''
    )
    [PSCustomObject]@{
        recordType = 'review-required'
        collector  = $Collector
        objectType = 'review-required'
        id         = $Id
        topic      = $Topic
        reason     = $Reason
        runId      = $RunId
        timestamp  = (Get-Date -Format 'o')
    }
}

function New-CollectionError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$ErrorMessage,
        [string]$RunId = ''
    )
    [PSCustomObject]@{
        recordType   = 'collection-error'
        collector    = $Collector
        objectType   = 'collection-error'
        target       = $Target
        errorMessage = $ErrorMessage
        runId        = $RunId
        timestamp    = (Get-Date -Format 'o')
    }
}
