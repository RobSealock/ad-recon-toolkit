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

$allBinaries = @($manifest.Binaries) + @($manifest.OptionalBinaries)

foreach ($tool in $allBinaries) {
    $targetFull = Join-Path $RepoRoot $tool.TargetPath

    if (Test-Path $targetFull) {
        # Verify existing binary checksum
        if ($tool.Sha256 -notlike 'PLACEHOLDER*') {
            $actual = (Get-FileHash $targetFull -Algorithm SHA256).Hash
            if ($actual -eq $tool.Sha256) {
                Write-OK "$($tool.Name) present and verified"
            } else {
                Write-Fail "$($tool.Name) SHA256 MISMATCH — removing corrupted file"
                Remove-Item $targetFull -Force
            }
        } else {
            Write-Warn "$($tool.Name) present — SHA256 not yet pinned in manifest (update tools.manifest.psd1)"
        }
        continue
    }

    if ($OfflineOnly) {
        if ($tool.Optional) {
            Write-Warn "$($tool.Name) not found (offline, optional — skipping)"
        } else {
            Write-Warn "$($tool.Name) not found (offline — pre-stage to $($tool.TargetPath))"
        }
        continue
    }

    Write-Step "Downloading $($tool.Name) from $($tool.Url)"
    try {
        $tmpFile = Join-Path $env:TEMP "$($tool.Name).tmp"
        Invoke-WebRequest -Uri $tool.Url -OutFile $tmpFile -UseBasicParsing -ErrorAction Stop

        if ($tool.ZipEntry) {
            # Extract single file from zip
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($tmpFile)
            $entry = $zip.Entries | Where-Object { $_.Name -eq $tool.ZipEntry } | Select-Object -First 1
            if (-not $entry) { throw "Entry '$($tool.ZipEntry)' not found in zip" }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $targetFull, $true)
            $zip.Dispose()
        } else {
            Move-Item $tmpFile $targetFull -Force
        }

        if ($tool.Sha256 -notlike 'PLACEHOLDER*') {
            $actual = (Get-FileHash $targetFull -Algorithm SHA256).Hash
            if ($actual -ne $tool.Sha256) {
                Write-Fail "$($tool.Name) SHA256 mismatch after download — ABORTING"
                Remove-Item $targetFull -Force -ErrorAction SilentlyContinue
                exit 1
            }
        }
        Write-OK "Downloaded: $($tool.Name) → $($tool.TargetPath)"
    } catch {
        if ($tool.Optional) {
            Write-Warn "Could not download optional tool $($tool.Name): $_"
        } else {
            Write-Warn "Could not download $($tool.Name): $_  (collector will be skipped)"
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
