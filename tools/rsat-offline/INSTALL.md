# RSAT offline install package

Consolidated offline installer for all four RSAT client capabilities this
toolkit needs, plus the `Rsat.ServerManager.Tools` dependency, for use when the
target host has no internet/WSUS access.

Built from: `CLIENT_FOD_LP_X64FRE_MULTI_DV9` (Windows 11 24H2/25H2 client FoD
ISO). Only the language-neutral and en-US packages are included, for both
amd64 and wow64 (wow64 is a declared requirement in each tool's manifest, not
optional) — not all 40+ languages, to keep this bundle small.

Capabilities covered:

| Capability | Used by |
|---|---|
| `Rsat.ServerManager.Tools~~~~0.0.1.0` | Dependency of the AD capability below (not a collector dependency itself) |
| `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` | ActiveDirectory PowerShell module |
| `Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0` | GPO-Settings collector (`Get-GPOReport`) |
| `Rsat.Dns.Tools~~~~0.0.1.0` | DNS collector (`DnsServer` module) |
| `Rsat.DHCP.Tools~~~~0.0.1.0` | DHCP collector (`DhcpServer` module) |

`FoDMetadata_Client.cab` and `metadata\` are included because they carry the
FoD capability/dependency metadata for this ISO — one shared copy here covers
all five capabilities (verified byte-identical across the three original
per-capability exports this bundle was consolidated from).

This is normally invoked automatically by `bootstrap\Install-Prereqs.ps1`
(falls back to this source when the online `Add-WindowsCapability` call fails,
or immediately when run with `-OfflineOnly`). The manual steps below are for
running it by hand, or on a build outside 24H2/25H2 where the automatic path
warns instead of assuming compatibility.

---

## Manual install

On the OFFLINE Windows 11 target, elevated PowerShell, from the repo root:

```powershell
# Dependency first (required only for the AD capability; DISM resolves this
# automatically from Windows Update online, but not from a local -Source):
Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0 `
  -Source .\tools\rsat-offline\source -LimitAccess

Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 `
  -Source .\tools\rsat-offline\source -LimitAccess

Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 `
  -Source .\tools\rsat-offline\source -LimitAccess

Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0 `
  -Source .\tools\rsat-offline\source -LimitAccess

Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0 `
  -Source .\tools\rsat-offline\source -LimitAccess

# Verify:
Get-WindowsCapability -Online -Name Rsat.* | ft Name, State
Import-Module ActiveDirectory, GroupPolicy, DnsServer, DhcpServer
```

## Notes

- **Do not rename any file in `source\`** — DISM matches packages by identity
  embedded in the cab, not by filename.
- **Capability name/version string**: the exact string DISM/`Add-WindowsCapability`
  expects is the `~~~~0.0.1.0` form used above. If `Get-WindowsCapability` on a
  given build reports a different exact name, use that instead.
- **Build scope**: these cabs were exported from a 24H2/25H2 client FoD ISO. On
  other Windows 11 (or Windows 10) builds the capability packaging can differ
  even when the capability name matches — `Install-Prereqs.ps1` warns rather
  than blocking in that case, but a clean install isn't guaranteed off that
  ISO's target builds.
- **Cleaner alternative** (if a Windows host is available to mount the ISO):
  `DISM /Export-Source` against the mounted ISO's `LanguagesAndOptionalFeatures`
  folder will resolve all dependencies itself rather than relying on this
  hand-picked, pre-resolved set — see Microsoft's FoD documentation.
