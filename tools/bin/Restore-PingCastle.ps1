<#
.SYNOPSIS
    Reassembles PingCastle.exe and PingCastleAutoUpdater.exe from their
    split/zipped parts.

.DESCRIPTION
    PingCastle.exe (232 MB) and PingCastleAutoUpdater.exe (153 MB) exceed
    GitHub's 100 MB per-file limit.

    PingCastle.exe.zip was split into two binary parts (partaa/partab).
    This script reassembles them into PingCastle.exe.zip, then extracts it.

    PingCastleAutoUpdater.exe.zip (49 MB) is stored as a single zip and is
    extracted directly.

    Safe to re-run — skips any step where the target already exists and
    SHA256-matches.
#>
[CmdletBinding()]
param(
    [string]$Dir = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

function Verify-Hash {
    param([string]$Path, [string]$Expected)
    $actual = (Get-FileHash $Path -Algorithm SHA256).Hash
    return $actual -eq $Expected.ToUpper()
}

# ── PingCastle.exe ────────────────────────────────────────────────────────────
$pcExe      = Join-Path $Dir 'PingCastle.exe'
$pcZip      = Join-Path $Dir 'PingCastle.exe.zip'
$pcZipHash  = '4C3EB6D8748E94C4086E96E8D321E5737428CAF730FAD5B06CFAF9E6079D5640'
$pcParts    = @('partaa','partab') | ForEach-Object { Join-Path $Dir "PingCastle.exe.zip.$_" }

# Reassemble zip from parts if needed
if (-not (Test-Path $pcZip) -or -not (Verify-Hash $pcZip $pcZipHash)) {
    foreach ($p in $pcParts) {
        if (-not (Test-Path $p)) {
            Write-Error "Missing part: $p"
            exit 1
        }
    }
    Write-Host "Reassembling PingCastle.exe.zip from parts..."
    $stream = [System.IO.File]::OpenWrite($pcZip)
    try {
        foreach ($p in $pcParts) {
            $bytes = [System.IO.File]::ReadAllBytes($p)
            $stream.Write($bytes, 0, $bytes.Length)
        }
    } finally { $stream.Close() }

    if (-not (Verify-Hash $pcZip $pcZipHash)) {
        Write-Error "SHA256 mismatch on reassembled PingCastle.exe.zip"
        Remove-Item $pcZip -Force; exit 1
    }
    Write-Host "[OK] PingCastle.exe.zip reassembled and verified."
} else {
    Write-Host "[OK] PingCastle.exe.zip already present and verified."
}

# Extract PingCastle.exe from zip
if (-not (Test-Path $pcExe)) {
    Write-Host "Extracting PingCastle.exe..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip   = [System.IO.Compression.ZipFile]::OpenRead($pcZip)
    $entry = $zip.Entries | Where-Object { $_.Name -eq 'PingCastle.exe' } | Select-Object -First 1
    if (-not $entry) { $zip.Dispose(); Write-Error "PingCastle.exe not found in zip"; exit 1 }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $pcExe, $true)
    $zip.Dispose()
    Write-Host "[OK] PingCastle.exe extracted."
} else {
    Write-Host "[OK] PingCastle.exe already present."
}

# ── PingCastleAutoUpdater.exe ─────────────────────────────────────────────────
$pcauExe     = Join-Path $Dir 'PingCastleAutoUpdater.exe'
$pcauZip     = Join-Path $Dir 'PingCastleAutoUpdater.exe.zip'
$pcauZipHash = 'A17844EF39B20F89116B4EC565DD50F12E01540D005FC7B0D7EB9675DF4B8468'

if (-not (Test-Path $pcauZip)) {
    Write-Warning "PingCastleAutoUpdater.exe.zip not found — skipping."
} elseif (-not (Test-Path $pcauExe)) {
    if (-not (Verify-Hash $pcauZip $pcauZipHash)) {
        Write-Warning "PingCastleAutoUpdater.exe.zip hash mismatch — skipping extraction."
    } else {
        Write-Host "Extracting PingCastleAutoUpdater.exe..."
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip   = [System.IO.Compression.ZipFile]::OpenRead($pcauZip)
        $entry = $zip.Entries | Where-Object { $_.Name -eq 'PingCastleAutoUpdater.exe' } | Select-Object -First 1
        if ($entry) {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $pcauExe, $true)
            Write-Host "[OK] PingCastleAutoUpdater.exe extracted."
        } else {
            Write-Warning "PingCastleAutoUpdater.exe not found inside zip — skipping."
        }
        $zip.Dispose()
    }
} else {
    Write-Host "[OK] PingCastleAutoUpdater.exe already present."
}
