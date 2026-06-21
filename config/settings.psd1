# ad-recon-toolkit global settings.
# Override locally in config\settings.local.psd1 (git-ignored).

@{
    # ── Tool toggles ───────────────────────────────────────────────────────
    # Set to $false to disable a third-party binary in environments where
    # running unsigned tools on DCs requires change-control approval.
    EnablePingCastle    = $true
    EnableSharpHound    = $true
    EnableLocksmith     = $true
    EnableGroup3r       = $true
    EnableHardeningKitty= $false   # optional — enable for BestPractice-Baseline collector

    # ── BloodHound CE ──────────────────────────────────────────────────────
    # URI of the BloodHound CE API for upload (optional — leave empty to skip).
    BloodHoundApiUrl    = ''
    BloodHoundApiKey    = ''   # set in settings.local.psd1

    # ── VulnCheck enrichment ───────────────────────────────────────────────
    # API token for VulnCheck (optional — CISA KEV used if empty).
    VulnCheckApiToken   = ''   # set in settings.local.psd1

    # ── Output / git ──────────────────────────────────────────────────────
    # Commit each run's JSON output to git automatically.
    GitCommitRuns       = $false

    # ── Workstation extension ──────────────────────────────────────────────
    # Point to config\targets.psd1 to scan additional hosts beyond DCs and
    # AD-role servers. See config\targets.sample.psd1 for format.
    TargetsFile         = ''

    # ── PurpleKnight ──────────────────────────────────────────────────────
    # Path to a PurpleKnight HTML or CSV export to ingest.
    # PurpleKnight is GUI-only; the collector ingests its exported report.
    PurpleKnightExport  = ''

    # ── Offline mode ──────────────────────────────────────────────────────
    # Set to $true to skip all downloads (binaries and KEV must be pre-staged).
    OfflineMode         = $false
}
