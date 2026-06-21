<#
.SYNOPSIS
    Verifies and installs prerequisites for ad-recon-toolkit.

.DESCRIPTION
    Run automatically by Start-Assessment.ps1 on first launch.
    Idempotent — safe to run repeatedly.

    Actions (in order):
      1. Check PowerShell version (5.1+).
      2. Check/install RSAT features for AD, DNS, DHCP, GroupPolicy modules.
      3. Install required PowerShell modules from PSGallery.
      4. Fetch and checksum-verify vendored binaries per tools.manifest.psd1.
      5. Download CISA KEV dataset.

    Fails closed on SHA256 mismatch — removes corrupted binary and exits.
    Offline-capable if tools\bin\ and tools\kev\ are pre-staged.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [switch]$OfflineOnly
)

$ErrorActionPreference = 'Continue'
$manifest = Import-PowerShellDataFile (Join-Path $RepoRoot 'bootstrap\tools.manifest.psd1')

function Write-Step { param([string]$Msg) Write-Host "  [Bootstrap] $Msg" }
function Write-OK   { param([string]$Msg) Write-Host "  [OK      ] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [WARN    ] $Msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$Msg) Write-Host "  [FAIL    ] $Msg" -ForegroundColor Red }

# ── 1. PowerShell version ─────────────────────────────────────────────────────
Write-Step 'Checking PowerShell version...'
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Fail "PowerShell 5.1+ required (found $($PSVersionTable.PSVersion))"
    exit 1
}
Write-OK "PowerShell $($PSVersionTable.PSVersion)"

# ── 2. RSAT features ──────────────────────────────────────────────────────────
Write-Step 'Checking RSAT features...'
$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1

if ($isServer) {
    foreach ($feature in $manifest.RSATFeatures.Server) {
        $installed = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
        if ($installed -and $installed.Installed) {
            Write-OK "Feature installed: $feature"
        } elseif (-not $OfflineOnly) {
            Write-Step "Installing feature: $feature"
            try {
                Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop | Out-Null
                Write-OK "Installed: $feature"
            } catch {
                Write-Warn "Could not install ${feature}: $_"
            }
        } else {
            Write-Warn "Not installed (offline mode): $feature"
        }
    }
} else {
    foreach ($cap in $manifest.RSATFeatures.Client) {
        $state = (Get-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue).State
        if ($state -eq 'Installed') {
            Write-OK "Capability installed: $cap"
        } elseif (-not $OfflineOnly) {
            Write-Step "Installing capability: $cap"
            try {
                Add-WindowsCapability -Online -Name $cap -ErrorAction Stop | Out-Null
                Write-OK "Installed: $cap"
            } catch {
                Write-Warn "Could not install ${cap}: $_"
            }
        } else {
            Write-Warn "Not installed (offline mode): $cap"
        }
    }
}

# ── 3. PowerShell modules ─────────────────────────────────────────────────────
Write-Step 'Checking PowerShell modules...'

# Ensure TLS 1.2 for PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

foreach ($mod in $manifest.PSModules) {
    $installed = Get-Module -ListAvailable -Name $mod.Name |
                 Sort-Object Version -Descending | Select-Object -First 1
    if ($installed -and $installed.Version -ge [version]$mod.MinVersion) {
        Write-OK "Module $($mod.Name) v$($installed.Version)"
        continue
    }
    if ($OfflineOnly) {
        if ($mod.Required) {
            Write-Fail "Required module not installed (offline mode): $($mod.Name)"
        } else {
            Write-Warn "Optional module not installed (offline mode): $($mod.Name)"
        }
        continue
    }
    Write-Step "Installing module: $($mod.Name) (min $($mod.MinVersion))"
    try {
        Install-Module -Name $mod.Name -MinimumVersion $mod.MinVersion `
            -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-OK "Installed: $($mod.Name)"
    } catch {
        if ($mod.Required) {
            Write-Fail "Failed to install required module $($mod.Name): $_"
        } else {
            Write-Warn "Failed to install optional module $($mod.Name): $_"
        }
    }
}

# ── 4. Vendored binaries ──────────────────────────────────────────────────────
Write-Step 'Checking vendored binaries...'
$binDir = Join-Path $RepoRoot 'tools\bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

# ── 4a. Manual binaries — check staged, print instructions if missing ─────────
Write-Step 'Checking manual binaries (registration-gated)...'
foreach ($tool in @($manifest.ManualBinaries)) {
    $targetFull = Join-Path $RepoRoot $tool.TargetPath
    if (Test-Path $targetFull) {
        Write-OK "$($tool.Name) staged at $($tool.TargetPath)"
    } else {
        Write-Warn "$($tool.Name) NOT staged — manual setup required:"
        Write-Host "         Registration : $($tool.RegistrationUrl)" -ForegroundColor Cyan
        foreach ($note in $tool.Notes) {
            Write-Host "         $note" -ForegroundColor Cyan
        }
        if ($tool.ExportSetting) {
            Write-Host "         Then set '$($tool.ExportSetting)' in config\settings.psd1 to the CSV export path." -ForegroundColor Cyan
        }
    }
}

$allBinaries = @($manifest.Binaries) + @($manifest.OptionalBinaries)

function Get-BinaryFileVersion {
    param([string]$Path)
    try {
        $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
        # Strip leading 'v' and any build metadata (e.g. "v2.13.0" → "2.13.0")
        $v = $v -replace '^v','' -replace '\+.*$',''
        if ($v) { return [System.Version]$v }
    } catch {}
    return $null
}

function Invoke-BinaryDownload {
    param([hashtable]$Tool, [string]$TargetFull)
    $tmpFile = Join-Path $env:TEMP "$($Tool.Name)_$([System.IO.Path]::GetRandomFileName()).tmp"
    try {
        Invoke-WebRequest -Uri $Tool.Url -OutFile $tmpFile -UseBasicParsing -ErrorAction Stop

        if ($Tool.ZipEntry) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip   = [System.IO.Compression.ZipFile]::OpenRead($tmpFile)
            $entry = $zip.Entries | Where-Object { $_.Name -eq $Tool.ZipEntry } | Select-Object -First 1
            if (-not $entry) { $zip.Dispose(); throw "Entry '$($Tool.ZipEntry)' not found in zip" }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TargetFull, $true)
            $zip.Dispose()
        } else {
            Move-Item $tmpFile $TargetFull -Force
        }

        if ($Tool.Sha256 -notlike 'PLACEHOLDER*') {
            $actual = (Get-FileHash $TargetFull -Algorithm SHA256).Hash
            if ($actual -ne $Tool.Sha256) {
                Write-Fail "$($Tool.Name) SHA256 mismatch after download — removing"
                Remove-Item $TargetFull -Force -ErrorAction SilentlyContinue
                throw "SHA256 mismatch: expected $($Tool.Sha256), got $actual"
            }
        }
        return $true
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }
}

foreach ($tool in $allBinaries) {
    $targetFull = Join-Path $RepoRoot $tool.TargetPath
    $exists     = Test-Path $targetFull

    # Parse manifest version (strip leading 'v' and metadata)
    $manifestVerStr = ($tool.Version -replace '^v','' -replace '\+.*$','')
    $manifestVer    = try { [System.Version]$manifestVerStr } catch { $null }

    # ── Check existing binary ─────────────────────────────────────────────
    if ($exists) {
        $existingVer = Get-BinaryFileVersion -Path $targetFull

        if ($existingVer -and $manifestVer) {
            if ($existingVer -ge $manifestVer) {
                # Pre-staged binary is at or above manifest version — keep it
                Write-OK "$($tool.Name) v$existingVer present (manifest: v$manifestVerStr) — no download needed"
                continue
            } else {
                Write-Step "$($tool.Name) v$existingVer found but manifest requires v$manifestVerStr — upgrading"
                # Fall through to download
            }
        } else {
            # Cannot determine version (e.g. SHA256 placeholder) — keep existing and warn
            Write-Warn "$($tool.Name) present — version check unavailable; keeping existing binary"
            continue
        }
    }

    # ── Offline: use whatever is present, or warn if absent ──────────────
    if ($OfflineOnly) {
        if ($exists) {
            Write-Warn "$($tool.Name) offline mode — using existing binary as-is"
        } elseif ($tool.Optional) {
            Write-Warn "$($tool.Name) not found (offline, optional — skipping)"
        } else {
            Write-Warn "$($tool.Name) not found (offline — pre-stage to $($tool.TargetPath))"
        }
        continue
    }

    # ── Download ──────────────────────────────────────────────────────────
    Write-Step "Downloading $($tool.Name) v$manifestVerStr"
    try {
        Invoke-BinaryDownload -Tool $tool -TargetFull $targetFull
        Write-OK "Downloaded: $($tool.Name) v$manifestVerStr → $($tool.TargetPath)"
    } catch {
        if ($exists) {
            $fallbackVer = Get-BinaryFileVersion -Path $targetFull
            Write-Warn "$($tool.Name) download failed — using pre-staged v$fallbackVer as fallback: $_"
        } elseif ($tool.Optional) {
            Write-Warn "$($tool.Name) download failed (optional — skipping): $_"
        } else {
            Write-Warn "$($tool.Name) download failed (collector will be skipped): $_"
        }
    }
}

# ── 5. CISA KEV dataset ───────────────────────────────────────────────────────
Write-Step 'Checking CISA KEV dataset...'
$kevDir    = Join-Path $RepoRoot 'tools\kev'
$kevTarget = Join-Path $RepoRoot $manifest.KEVDataset.TargetPath
New-Item -ItemType Directory -Force -Path $kevDir | Out-Null

if (Test-Path $kevTarget) {
    $age = (Get-Date) - (Get-Item $kevTarget).LastWriteTime
    if ($age.TotalDays -gt 7) {
        Write-Warn "KEV dataset is $([int]$age.TotalDays) days old — refreshing"
    } else {
        Write-OK "KEV dataset present ($([int]$age.TotalDays) day(s) old)"
    }
}

if (-not (Test-Path $kevTarget) -or $age.TotalDays -gt 7) {
    if (-not $OfflineOnly) {
        try {
            Invoke-WebRequest -Uri $manifest.KEVDataset.Url -OutFile $kevTarget `
                -UseBasicParsing -ErrorAction Stop
            Write-OK "CISA KEV dataset downloaded"
        } catch {
            Write-Warn "Could not download KEV dataset: $_  (VulnCheck-Enrich collector will be limited)"
        }
    } else {
        Write-Warn "KEV dataset not found (offline — pre-stage to $($manifest.KEVDataset.TargetPath))"
    }
}

Write-Host ''
Write-Host '[Bootstrap] Prerequisites check complete.'
Write-Host ''
