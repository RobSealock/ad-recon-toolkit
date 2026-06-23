# Remote/cross-domain connection context — lets the toolkit run from a host
# that is NOT joined to the target domain, by binding LDAP/WinRM/CIM against
# an explicit DC with alternate credentials instead of implicit current-user
# Windows auth. Inert (zero behavior change) unless Settings.TargetDC is set.

$script:_Conn         = $null
$script:_CimSessions  = @{}

function Initialize-RemoteConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$RunContext,
        [Parameter(Mandatory)][hashtable]$Settings
    )
    if (-not $Settings['TargetDC']) {
        $script:_Conn = $null
        return
    }

    $cred = $null
    if ($Settings['TargetUsername']) {
        $securePass = ConvertTo-SecureString ([string]$Settings['TargetPassword']) -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($Settings['TargetUsername'], $securePass)
    }

    $script:_Conn = @{
        Server     = $Settings['TargetDC']
        Credential = $cred
    }

    if ($Settings['TargetDomain']) {
        $RunContext.Domain = $Settings['TargetDomain']
    } else {
        Write-Warning "[Connection] TargetDC is set but TargetDomain is empty — collectors that label records or call external tools by domain name (PingCastle, SharpHound, Locksmith, GPO SYSVOL path) will use the wrong value."
    }

    Write-Host "[Connection] Remote mode — targeting $($Settings['TargetDC']) ($($RunContext.Domain))"
    if ($cred) {
        Write-Host "[Connection] Using alternate credential: $($cred.UserName)"
    }

    $trusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if ($trusted -ne '*' -and $trusted -notlike "*$($Settings['TargetDC'])*") {
        Write-Warning "[Connection] WinRM TrustedHosts does not include $($Settings['TargetDC']) — cross-domain WinRM can't use Kerberos, so it needs NTLM via TrustedHosts. Host-OS/Audit-Policy collectors will fail to reach the DC until you run: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$($Settings['TargetDC'])' -Concatenate -Force"
    }
}

# Drop-in replacement for the [adsi] cast — inserts the configured DC and
# credentials into the LDAP path when remote mode is active, otherwise
# behaves identically to [adsi]$Path.
function New-AdsiEntry {
    param([Parameter(Mandatory)][string]$Path)
    if (-not $script:_Conn) { return [adsi]$Path }

    $remotePath = $Path -replace '^LDAP://', "LDAP://$($script:_Conn.Server)/"
    if ($script:_Conn.Credential) {
        $cred = $script:_Conn.Credential
        return New-Object System.DirectoryServices.DirectoryEntry(
            $remotePath, $cred.UserName, $cred.GetNetworkCredential().Password,
            [System.DirectoryServices.AuthenticationTypes]::Secure)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($remotePath)
}

# PSCredential for the configured target, or $null in default (domain-joined) mode.
function Get-RemoteCredential {
    if ($script:_Conn) { return $script:_Conn.Credential }
    return $null
}

# Splat for *Server-module cmdlets (Get-DnsServerZone, Get-DhcpServerv4Scope, etc.)
# that take -ComputerName by default, or -CimSession when remote mode is active.
# CIM sessions are cached per computer name for the life of the run.
function Get-RemoteCimArgs {
    param([Parameter(Mandatory)][string]$ComputerName)
    if (-not $script:_Conn) { return @{ ComputerName = $ComputerName } }

    if (-not $script:_CimSessions.ContainsKey($ComputerName)) {
        $cimParams = @{ ComputerName = $ComputerName }
        if ($script:_Conn.Credential) { $cimParams.Credential = $script:_Conn.Credential }
        $script:_CimSessions[$ComputerName] = New-CimSession @cimParams
    }
    return @{ CimSession = $script:_CimSessions[$ComputerName] }
}
