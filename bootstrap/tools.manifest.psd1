#Requires -Version 5.1
# =============================================================================
# tools.manifest.psd1  —  FIELD REFERENCE AND USAGE GUIDE
# =============================================================================
#
# READ THIS FIRST
# ───────────────
# This file is the single source of truth for every third-party binary,
# PowerShell module, Windows feature, and dataset used by ad-recon-toolkit.
# Install-Prereqs.ps1 reads it on every run and acts on it automatically.
#
# ── ENTRY TYPES ──────────────────────────────────────────────────────────────
#
#   Binaries          Required auto-fetch binaries. SHA256-verified. Collectors
#                     that depend on these will soft-fail if absent.
#
#   OptionalBinaries  Optional auto-fetch binaries. Enabled by default but
#                     collectors degrade gracefully if absent.
#
#   ManualBinaries    Tools that cannot be auto-fetched (registration wall,
#                     GUI-only, or licence restriction). Install-Prereqs.ps1
#                     prints instructions and checks if the file is staged;
#                     it never attempts a download for these.
#
#   PSModules         PowerShell modules installed from PSGallery automatically.
#
#   RSATFeatures      Windows RSAT features enabled via DISM or
#                     Add-WindowsCapability. Server vs Client detected at runtime.
#
#   KEVDataset        CISA Known Exploited Vulnerabilities JSON. Auto-fetched
#                     and refreshed if older than 7 days.
#
# ── BINARY ENTRY FIELDS ──────────────────────────────────────────────────────
#
#   Name              Display name used in log output and collector references.
#
#   Description       What the tool does and which collector consumes it.
#
#   Url               Direct download URL (zip or exe).
#                     Set to $null for ManualBinaries entries.
#
#   RegistrationUrl   For ManualBinaries — URL where the operator registers
#                     and obtains the download. Printed by Install-Prereqs.ps1.
#
#   Version           Pinned version string used for version comparison.
#                     Leading 'v' and build metadata (+...) are stripped at
#                     runtime. Both semver and Windows file versions work.
#                     Use 'CONFIRM_FROM_DOWNLOAD' as a placeholder.
#
#   Sha256            SHA256 hash of the extracted/final file (uppercase hex).
#                     Use 'PLACEHOLDER_VERIFY_AFTER_DOWNLOAD' until pinned.
#                     Compute with:
#                       (Get-FileHash .\tools\bin\<file>.exe -Algorithm SHA256).Hash
#                     Install-Prereqs.ps1 verifies this on every run when pinned.
#                     Skipped for ManualBinaries (operator is responsible).
#
#   TargetPath        Destination path relative to RepoRoot.
#                     Convention: tools\bin\<ToolName>.exe
#
#   ZipEntry          If Url points to a zip, the filename to extract from it.
#                     Set to $null when the Url is a direct exe download.
#
#   Enabled           Master on/off switch for this tool.
#                     Can be overridden per-environment via ToggleKey in
#                     settings.psd1 or settings.local.psd1.
#
#   ToggleKey         The key name in settings.psd1 that controls this tool.
#                     Example: EnablePingCastle = $false disables PingCastle
#                     without editing this manifest.
#
#   Optional          $true  → soft-fail; collector skips gracefully if absent.
#                     $false → warn and continue; collector emits an error record.
#
#   ManualDownload    $true  → Install-Prereqs.ps1 skips auto-fetch and prints
#                     setup instructions instead.
#                     $false → normal auto-fetch behaviour (default).
#
#   ExportSetting     For ManualBinaries tools that produce an export file:
#                     the key in settings.psd1 the collector reads to find the
#                     exported file path (e.g. PurpleKnightExport).
#
#   ExportFormats     Supported export formats for ingestion by the collector.
#
#   Notes             Free-text guidance printed by Install-Prereqs.ps1 for
#                     manual tools. Use this to document the exact export steps.
#
# ── VERSION COMPARISON BEHAVIOUR (Install-Prereqs.ps1) ───────────────────────
#
#   existing >= manifest  →  keep existing, skip download
#   existing <  manifest  →  download to upgrade
#   download fails + file present  →  warn, use existing as fallback
#   download fails + file absent, Optional=$true   →  warn, skip
#   download fails + file absent, Optional=$false  →  warn, collector soft-fails
#
# ── OFFLINE PRE-STAGING ──────────────────────────────────────────────────────
#
#   Set OfflineMode = $true in config\settings.psd1 (or settings.local.psd1).
#   Pre-stage binaries to tools\bin\ and KEV to tools\kev\ before running.
#   Version comparison still runs; SHA256 verification is skipped in offline mode.
#
# ── ADDING A NEW AUTO-FETCH TOOL ─────────────────────────────────────────────
#
#   1. Add an entry to Binaries or OptionalBinaries below.
#   2. Add a matching EnableXxx = $true key in config\settings.psd1.
#   3. Run bootstrap\Install-Prereqs.ps1 to fetch and verify.
#   4. Pin Sha256 with:
#        (Get-FileHash .\tools\bin\<tool>.exe -Algorithm SHA256).Hash
#   5. Reference tools\bin\<tool>.exe in the relevant collector.
#
# ── ADDING A NEW MANUAL TOOL ─────────────────────────────────────────────────
#
#   1. Add an entry to ManualBinaries with ManualDownload = $true.
#   2. Set Url = $null and populate RegistrationUrl and Notes.
#   3. Add a matching ExportSetting key to config\settings.psd1.
#   4. The collector reads that settings key to locate the exported file.
#
# =============================================================================

@{

    # =========================================================================
    # REQUIRED BINARIES  —  auto-fetched, SHA256-verified
    # =========================================================================

    Binaries = @(

        @{
            Name           = 'PingCastle'
            Description    = 'AD risk assessment and scoring tool (Netwrix). Used by PingCastle collector.'
            Url            = 'https://github.com/netwrix/pingcastle/releases/download/3.5.1.33/PingCastle_3.5.1.33.zip'
            RegistrationUrl= $null
            Version        = '3.5.1.33'
            Sha256         = 'C328AED079954A949C9ED53751DC8A88720ACF2D87811B905F7B9234C9848696'
            TargetPath     = 'tools\bin\PingCastle.exe'
            ZipEntry       = 'PingCastle.exe'
            Enabled        = $true
            ToggleKey      = 'EnablePingCastle'
            Optional       = $false
            ManualDownload = $false
            ExportSetting  = $null
            ExportFormats  = $null
            Notes          = $null
        },

        @{
            Name           = 'SharpHound'
            Description    = 'BloodHound CE data collector. Version must match your BloodHound CE instance. Used by SharpHound collector.'
            Url            = 'https://github.com/SpecterOps/SharpHound/releases/download/v2.13.0/SharpHound_v2.13.0_windows_x86.zip'
            RegistrationUrl= $null
            Version        = 'v2.13.0'
            Sha256         = '2A6B515DC1908F33C3BFE887347270D429496113102D5DE9F74E9063CD5567AA'
            TargetPath     = 'tools\bin\SharpHound.exe'
            ZipEntry       = 'SharpHound.exe'
            Enabled        = $true
            ToggleKey      = 'EnableSharpHound'
            Optional       = $false
            ManualDownload = $false
            ExportSetting  = $null
            ExportFormats  = $null
            Notes          = $null
        }
    )

    # =========================================================================
    # OPTIONAL BINARIES  —  auto-fetched, soft-fail if absent
    # =========================================================================

    OptionalBinaries = @(

        @{
            Name           = 'Group3r'
            Description    = 'GPO security analyzer. Corroborates GPO-Settings collector findings. Used by GPO-Settings collector.'
            Url            = 'https://github.com/Group3r/Group3r/releases/download/1.0.69/Group3r.exe'
            RegistrationUrl= $null
            Version        = '1.0.69'
            Sha256         = '8F71CF000B5092E214F6E52470B702CE662AD2ED0DEFF86C26728A0E3532EF25'
            TargetPath     = 'tools\bin\Group3r.exe'
            ZipEntry       = $null
            Enabled        = $true
            ToggleKey      = 'EnableGroup3r'
            Optional       = $true
            ManualDownload = $false
            ExportSetting  = $null
            ExportFormats  = $null
            Notes          = $null
        }
        # Grouper2 removed — no releases published on GitHub (repo: l0ss/Grouper2)
    )

    # =========================================================================
    # MANUAL BINARIES  —  registration-gated or GUI-only; never auto-fetched
    # Install-Prereqs.ps1 checks if the file is staged and prints instructions.
    # =========================================================================

    ManualBinaries = @(

        @{
            Name           = 'PurpleKnight'
            Description    = 'Semperis AD security assessment tool (125+ indicators). GUI-only — run manually on a DC, then export CSV for ingestion by the PurpleKnight collector.'
            Url            = $null
            RegistrationUrl= 'https://www.semperis.com/purple-knight/'
            Version        = '5.0.2506.11001'
            Sha256         = $null    # operator-verified; not auto-checked
            TargetPath     = 'tools\bin\PK_Community_5.0\PurpleKnight.exe'
            ZipEntry       = $null
            Enabled        = $true
            ToggleKey      = 'EnablePurpleKnight'
            Optional       = $true
            ManualDownload = $true
            ExportSetting  = 'PurpleKnightExport'
            ExportFormats  = @('csv', 'html')
            Notes          = @(
                '1. Register and download at: https://www.semperis.com/purple-knight/'
                '2. Extract to tools\bin\PK_Community_<version>\ (already staged if present).'
                '3. Run PurpleKnight.exe on a domain-joined machine (DA rights recommended).'
                '4. When complete, export BOTH formats:'
                '     CSV  → save to output\purpleknight\  (auto-ingested by collector)'
                '     HTML → save to output\purpleknight\  (kept as raw artifact for stakeholder review)'
                '5. Re-run Start-Assessment.ps1 — the collector auto-scans output\purpleknight\ for the latest CSV.'
                '6. To override auto-scan, set PurpleKnightExport = <path> in config\settings.psd1.'
                ''
                'NOTE: output\purpleknight\ is git-ignored (sensitive AD security data).'
                '      Do not commit exports to a shared or public repository.'
            )
        }
    )

    # =========================================================================
    # PIP PACKAGES  —  Python packages installed via pip by Install-Prereqs.ps1
    #
    # After installation Install-Prereqs.ps1 locates the installed executable
    # in the Python Scripts directory and copies it to tools\bin\ so the
    # collector can find it without relying on PATH.
    #
    # Fields:
    #   Name          Display name for log output.
    #   PipName       Package name as published on PyPI (pip install <PipName>).
    #   ExeName       Expected executable filename after install (e.g. certipy.exe).
    #   MinVersion    Minimum acceptable version string.
    #   TargetPath    Destination in tools\bin\ (relative to RepoRoot).
    #   Optional      $true → soft-fail if pip unavailable or install fails.
    #   ToggleKey     Key in settings.psd1 that enables/disables this tool.
    # =========================================================================

    PipPackages = @(

        @{
            Name        = 'Certipy'
            Description = 'AD CS / ADCS vulnerability enumerator (ESC1-ESC16). Primary authoritative scanner for certificate template and CA misconfigurations. Used by CA-Config collector when EnableCertipy = $true in settings.'
            PipName     = 'certipy-ad'
            ExeName     = 'certipy.exe'
            MinVersion  = '4.8.2'
            TargetPath  = 'tools\bin\certipy.exe'
            Optional    = $true
            ToggleKey   = 'EnableCertipy'
            Notes       = @(
                'Requires Python 3.8+ and pip. On the run host:'
                '  pip install certipy-ad'
                'Or use Install-Prereqs.ps1 which will install and stage certipy.exe automatically.'
                'Credentials: set CertipyUsername / CertipyPassword in config\settings.local.psd1,'
                'or use Kerberos (-k -no-pass) on a domain-joined host (default).'
                'Enable with: EnableCertipy = $true in config\settings.psd1 or settings.local.psd1.'
            )
        }
    )

    # =========================================================================
    # POWERSHELL MODULES  —  installed from PSGallery by Install-Prereqs.ps1
    # =========================================================================

    PSModules = @(

        @{
            Name       = 'Locksmith'
            Description= 'AD CS / PKI vulnerability scanner (ESC1-ESC16). Used by Locksmith2 collector.'
            Source     = 'PSGallery'
            MinVersion = '2024.9.9'
            Required   = $true
            ToggleKey  = 'EnableLocksmith'
            # PSGallery: https://www.powershellgallery.com/packages/Locksmith
            # GitHub:    https://github.com/TrimarcJake/Locksmith
        },

        @{
            Name       = 'HardeningKitty'
            Description= 'Windows hardening baseline checker. Used by BestPractice-Baseline collector (optional).'
            Source     = 'PSGallery'
            MinVersion = '0.9.0'
            Required   = $false
            ToggleKey  = 'EnableHardeningKitty'
            # PSGallery: https://www.powershellgallery.com/packages/HardeningKitty
            # GitHub:    https://github.com/scipag/HardeningKitty
        }
    )

    # =========================================================================
    # RSAT FEATURES  —  Windows features enabled via DISM / Add-WindowsCapability
    # Install-Prereqs.ps1 detects Server vs Client OS automatically.
    # =========================================================================

    RSATFeatures = @{

        # Windows Server — Install-WindowsFeature
        Server = @(
            'RSAT-AD-PowerShell'    # ActiveDirectory module (optional; collectors use raw LDAP by default)
            'RSAT-DNS-Server'       # DnsServer module — required by DNS collector
            'RSAT-DHCP'             # DhcpServer module — required by DHCP collector
            'GPMC'                  # GroupPolicy module — required by GPO-Settings collector (Get-GPOReport)
        )

        # Windows Client — Add-WindowsCapability
        Client = @(
            'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            'Rsat.Dns.Tools~~~~0.0.1.0'
            'Rsat.DHCP.Tools~~~~0.0.1.0'
            'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
        )
    }

    # =========================================================================
    # CISA KEV DATASET  —  auto-fetched, refreshed if older than 7 days
    # =========================================================================

    KEVDataset = @{
        Description          = 'CISA Known Exploited Vulnerabilities catalog (JSON). Used by VulnCheck-Enrich collector.'
        Url                  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        TargetPath           = 'tools\kev\known_exploited_vulnerabilities.json'
        RefreshAfterDays     = 7
        # Optional VulnCheck API enrichment — set token in config\settings.local.psd1
        VulnCheckApiEndpoint = 'https://api.vulncheck.com/v3/index/initial-access'
    }

}
