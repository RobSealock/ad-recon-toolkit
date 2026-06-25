# ad-recon-toolkit global settings.
# Override locally in config\settings.local.psd1 (git-ignored).

@{
    # Tool toggles
    # Set to $false to disable a third-party binary where change-control
    # approval is required before running unsigned tools on DCs.
    EnablePingCastle    = $true
    EnableSharpHound    = $true
    EnableLocksmith     = $true
    EnableGroup3r       = $true
    EnablePurpleKnight  = $true
    EnableHardeningKitty= $false   # optional — enable for BestPractice-Baseline collector
    EnableCertipy       = $false   # optional — requires Python + pip install certipy-ad; set CertipyUsername/CertipyPassword in settings.local.psd1 or use Kerberos on domain-joined host

    # BloodHound CE
    # URI of the BloodHound CE API for upload (optional — leave empty to skip).
    BloodHoundApiUrl    = ''
    BloodHoundApiKey    = ''   # set in settings.local.psd1

    # VulnCheck enrichment
    # API token for VulnCheck (optional — CISA KEV used if empty).
    VulnCheckApiToken   = ''   # set in settings.local.psd1

    # Output / git
    # Commit each run's JSON output to git automatically.
    GitCommitRuns       = $false

    # Workstation extension
    # Point to config\targets.psd1 to scan additional hosts beyond DCs and
    # AD-role servers. See config\targets.sample.psd1 for format.
    TargetsFile         = ''

    # PurpleKnight export path
    # Leave empty to auto-scan output\purpleknight\ for the latest *.csv or *.html file.
    # Set an explicit path only if the export lives outside that directory.
    # >>> Save all PurpleKnight CSV/HTML exports to: <RepoRoot>\output\purpleknight\ <<<
    PurpleKnightExport  = ''

    # Offline mode
    # Set to $true to skip all downloads (binaries and KEV must be pre-staged).
    OfflineMode         = $false

    # RSAT features (DnsServer/DhcpServer/GroupPolicy modules)
    # On a Windows client OS (not Server), installing these via Add-WindowsCapability
    # can take 10-30+ minutes PER capability on first run on a given machine — a known
    # Windows DISM behavior, not specific to this toolkit. Not required: DNS/DHCP/
    # GPO-Settings collectors soft-fail their RSAT-specific checks and still run the
    # rest of their checks without it. Set to $false to skip the install attempt
    # entirely (e.g. on a fresh machine where you don't want to wait).
    InstallRSATFeatures = $true

    # Portable Python (fallback only)
    # If no real Python/pip is on PATH, Install-Prereqs.ps1 downloads the
    # official Windows embeddable Python package to tools\python\ (no installer,
    # no registry changes) so pip-based tools (currently Certipy) install
    # automatically. Inert -- has zero effect -- if a real system Python is
    # already on PATH. Set to $false to skip and rely on manual Python setup.
    InstallPortablePython = $true

    # Remote / cross-domain assessment
    # Run from a host that is NOT joined to the target domain by pointing
    # directly at a DC and supplying alternate credentials. Leave TargetDC
    # empty to use the current host's implicit domain membership (default).
    # Set these in settings.local.psd1 (git-ignored), not here.
    TargetDC            = ''   # explicit DC hostname or IP — non-empty activates remote mode
    TargetDomain        = ''   # target domain FQDN, e.g. 'corp.example.com' — required when TargetDC is set
    TargetUsername      = ''   # e.g. 'CORP\svc-assess' or 'user@corp.example.com'
    TargetPassword      = ''   # plaintext — settings.local.psd1 only
}
