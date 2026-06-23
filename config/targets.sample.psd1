# Optional explicit target list for the Host-OS collector.
# Copy to config\targets.psd1 (git-ignored) and populate.
#
# Default behaviour (no targets.psd1): Host-OS scans all DCs and discovered
# AD-role servers (CA hosts, DNS servers, DHCP authorized servers) automatically.
#
# Use this file to:
#   - Add workstations or member servers to extend the scan.
#   - Override auto-discovery and specify an explicit list.
#   - Assign non-default Tier labels to specific hosts.

@{
    # Explicit hosts to scan IN ADDITION to auto-discovered DCs/role servers.
    AdditionalHosts = @(
        # @{ Name = 'WS01'; FQDN = 'ws01.corp.example.com'; Tier = 'T2'; Role = 'Workstation' }
        # @{ Name = 'APPSRV01'; FQDN = 'appsrv01.corp.example.com'; Tier = 'T2'; Role = 'MemberServer' }
    )

    # Set to $true to DISABLE auto-discovery and scan only AdditionalHosts above.
    DisableAutoDiscovery = $false
}
