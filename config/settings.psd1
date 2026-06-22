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
    # Leave empty to auto-scan output\purpleknight\ for the latest *.csv file.
    # Set an explicit path only if the export lives outside that directory.
    # >>> Save all PurpleKnight CSV/HTML exports to: <RepoRoot>\output\purpleknight\ <<<
    PurpleKnightExport  = ''

    # Offline mode
    # Set to $true to skip all downloads (binaries and KEV must be pre-staged).
    OfflineMode         = $false
}
