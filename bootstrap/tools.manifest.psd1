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
            # File:       PingCastle_3.5.1.33.zip  →  extract PingCastle.exe
            Url         = 'https://github.com/netwrix/pingcastle/releases/download/3.5.1.33/PingCastle_3.5.1.33.zip'
            Version     = '3.5.1.33'
            Sha256      = 'C328AED079954A949C9ED53751DC8A88720ACF2D87811B905F7B9234C9848696'
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
            # File:       SharpHound_v2.13.0_windows_x86.zip  →  extract SharpHound.exe
            Url         = 'https://github.com/SpecterOps/SharpHound/releases/download/v2.13.0/SharpHound_v2.13.0_windows_x86.zip'
            Version     = 'v2.13.0'
            Sha256      = '2A6B515DC1908F33C3BFE887347270D429496113102D5DE9F74E9063CD5567AA'
            TargetPath  = 'tools\bin\SharpHound.exe'
            ZipEntry    = 'SharpHound.exe'
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
            # File:       Group3r.exe  (direct exe)
            Url         = 'https://github.com/Group3r/Group3r/releases/download/1.0.69/Group3r.exe'
            Version     = '1.0.69'
            Sha256      = '8F71CF000B5092E214F6E52470B702CE662AD2ED0DEFF86C26728A0E3532EF25'
            TargetPath  = 'tools\bin\Group3r.exe'
            ZipEntry    = $null
            Enabled     = $true
            ToggleKey   = 'EnableGroup3r'
            Optional    = $true
        }
        # Grouper2 removed — no releases published on GitHub (repo: l0ss/Grouper2)
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
