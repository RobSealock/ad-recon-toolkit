# Run identity, held-privilege set, and repo root.
# New-RunContext is called once per pass (user-context and elevated).

function New-RunContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [string[]]$HeldPrivileges = @('AnyAuthUser'),
        [string]$ExistingRunId = $null
    )
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]$identity
    $isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    [PSCustomObject]@{
        RunId          = if ($ExistingRunId) { $ExistingRunId } else { [System.Guid]::NewGuid().ToString() }
        StartTime      = Get-Date -Format 'o'
        Operator       = $identity.Name
        RunHost        = $env:COMPUTERNAME
        Domain         = $env:USERDNSDOMAIN
        IsElevated     = $isAdmin
        HeldPrivileges = [System.Collections.Generic.List[string]]$HeldPrivileges
        RepoRoot       = (Resolve-Path $RepoRoot).Path
    }
}

function Add-HeldPrivilege {
    param(
        [Parameter(Mandatory)][PSCustomObject]$RunContext,
        [Parameter(Mandatory)]
        [ValidateSet('AnyAuthUser','LocalAdmin','DHCPRead','DNSAdmin','CARead','T0')]
        [string]$Privilege
    )
    if ($RunContext.HeldPrivileges -notcontains $Privilege) {
        $RunContext.HeldPrivileges.Add($Privilege)
    }
}
