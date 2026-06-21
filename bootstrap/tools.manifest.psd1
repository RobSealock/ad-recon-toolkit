# Tool download manifest — all third-party binaries used by collectors.
#
# BEFORE FIRST RUN:
#   1. Download each tool and note its exact version.
#   2. Compute SHA256:  (Get-FileHash .\tool.exe -Algorithm SHA256).Hash
#   3. Replace PLACEHOLDER_VERIFY with the actual hash.
#   4. Update Version fields.
#
# Binary execution is toggled per-tool via settings.psd1 (EnableXxx keys).
# Set Enabled = $false to disable a tool for environments where running
# third-party binaries on DCs requires change control approval.

@{

    # ── Required binaries ──────────────────────────────────────────────────

    Binaries = @(

        @{
            Name        = 'PingCastle'
            Description = 'AD risk assessment and scoring tool (Netwrix)'
            # Download:   https://github.com/netwrix/pingcastle/releases/latest
            # File:       PingCastle_X.X.X.X.zip  →  extract PingCastle.exe
            Url         = 'https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip'
            Version     = '3.3.0.1'
            Sha256      = 'PLACEHOLDER_VERIFY_AFTER_DOWNLOAD'
            TargetPath  = 'tools\bin\PingCastle.exe'
            ZipEntry    = 'PingCastle.exe'
            Enabled     = $true
            ToggleKey   = 'EnablePingCastle'
            Optional    = $false
        },

        @{
            Name        = 'SharpHound'
            Description = 'BloodHound CE data collector — version-match to your BloodHound CE instance'
            # Download:   https://github.com/SpecterOps/SharpHound/releases/latest
            # File:       SharpHound.exe  (direct exe, no zip)
            Url         = 'https://github.com/SpecterOps/SharpHound/releases/latest/download/SharpHound.exe'
            Version     = 'CONFIRM_FROM_RELEASE'
            Sha256      = 'PLACEHOLDER_VERIFY_AFTER_DOWNLOAD'
            TargetPath  = 'tools\bin\SharpHound.exe'
            ZipEntry    = $null
            Enabled     = $true
            ToggleKey   = 'EnableSharpHound'
            Optional    = $false
        }
    )

    # ── Optional binaries ──────────────────────────────────────────────────

    OptionalBinaries = @(

        @{
            Name        = 'Group3r'
            Description = 'GPO security analyzer — corroborates GPO-Settings collector'
            # Download:   https://github.com/Group3r/Group3r/releases/latest
            # File:       Group3r.exe
            Url         = 'https://github.com/Group3r/Group3r/releases/latest/download/Group3r.exe'
            Version     = 'CONFIRM_FROM_RELEASE'
            Sha256      = 'PLACEHOLDER_VERIFY_AFTER_DOWNLOAD'
            TargetPath  = 'tools\bin\Group3r.exe'
            ZipEntry    = $null
            Enabled     = $true
            ToggleKey   = 'EnableGroup3r'
            Optional    = $true
        },

        @{
            Name        = 'Grouper2'
            Description = 'GPO and SYSVOL security auditor (alternative to Group3r)'
            # Download:   https://github.com/l0ss/Grouper2/releases/latest
            # File:       Grouper2.exe
            Url         = 'https://github.com/l0ss/Grouper2/releases/latest/download/Grouper2.exe'
            Version     = 'CONFIRM_FROM_RELEASE'
            Sha256      = 'PLACEHOLDER_VERIFY_AFTER_DOWNLOAD'
            TargetPath  = 'tools\bin\Grouper2.exe'
            ZipEntry    = $null
            Enabled     = $false
            ToggleKey   = 'EnableGrouper2'
            Optional    = $true
        }
    )

    # ── PowerShell modules (installed from PSGallery) ─────────────────────

    PSModules = @(

        @{
            Name        = 'Locksmith'
            Description = 'AD CS / PKI vulnerability scanner (ESC1-ESC16) — WIP, pin version'
            # PSGallery:  https://www.powershellgallery.com/packages/Locksmith
            # GitHub:     https://github.com/TrimarcJake/Locksmith
            Source      = 'PSGallery'
            MinVersion  = '2024.9.9'
            Required    = $true
            ToggleKey   = 'EnableLocksmith'
        },

        @{
            Name        = 'HardeningKitty'
            Description = 'Windows hardening baseline checker — used by BestPractice-Baseline collector'
            # PSGallery:  https://www.powershellgallery.com/packages/HardeningKitty
            # GitHub:     https://github.com/scipag/HardeningKitty
            Source      = 'PSGallery'
            MinVersion  = '0.9.0'
            Required    = $false
            ToggleKey   = 'EnableHardeningKitty'
        }
    )

    # ── RSAT Windows features (enabled via DISM / Add-WindowsCapability) ──
    # Install-Prereqs.ps1 handles Server vs Client detection automatically.

    RSATFeatures = @{
        # Windows Server (Install-WindowsFeature)
        Server = @(
            'RSAT-AD-PowerShell'    # ActiveDirectory module (optional — collectors use raw LDAP)
            'RSAT-DNS-Server'       # DnsServer module
            'RSAT-DHCP'             # DhcpServer module
            'GPMC'                  # GroupPolicy module (Get-GPOReport)
        )
        # Windows Client (Add-WindowsCapability)
        Client = @(
            'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            'Rsat.Dns.Tools~~~~0.0.1.0'
            'Rsat.DHCP.Tools~~~~0.0.1.0'
            'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
        )
    }

    # ── CISA KEV dataset (no auth required) ───────────────────────────────

    KEVDataset = @{
        Description = 'CISA Known Exploited Vulnerabilities catalog (JSON)'
        # Download:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        Url         = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        TargetPath  = 'tools\kev\known_exploited_vulnerabilities.json'
        # Optional: VulnCheck enrichment (set token in settings.local.psd1)
        VulnCheckApiEndpoint = 'https://api.vulncheck.com/v3/index/initial-access'
    }

}
