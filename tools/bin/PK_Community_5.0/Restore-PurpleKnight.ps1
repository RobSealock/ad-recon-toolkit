<#
.SYNOPSIS
    Reassembles PurpleKnight.exe from its split parts.

.DESCRIPTION
    PurpleKnight.exe (245 MB) exceeds GitHub's 100 MB per-file limit and is
    stored as four binary chunks (PurpleKnight.exe.partaa through .partad).
    Run this script once after cloning or extracting the repo to reassemble
    the executable before running an assessment.

    Verifies the SHA256 of the reassembled file. Safe to re-run — skips
    reassembly if PurpleKnight.exe is already present and hash-matches.
#>
[CmdletBinding()]
param(
    [string]$Dir = $PSScriptRoot
)

$target   = Join-Path $Dir 'PurpleKnight.exe'
$expected = '6276034DA45C5A05B334EE9C80DD05B246BA133B81B504EFBF84A2068F92D886'
$parts    = @('partaa','partab','partac','partad') | ForEach-Object { Join-Path $Dir "PurpleKnight.exe.$_" }

foreach ($p in $parts) {
    if (-not (Test-Path $p)) {
        Write-Error "Missing part: $p — ensure all four .part* files are present."
        exit 1
    }
}

if (Test-Path $target) {
    $existing = (Get-FileHash $target -Algorithm SHA256).Hash
    if ($existing -eq $expected) {
        Write-Host "[OK] PurpleKnight.exe already present and verified — nothing to do."
        exit 0
    }
    Write-Host "[INFO] PurpleKnight.exe present but hash mismatch — reassembling."
}

Write-Host "Reassembling PurpleKnight.exe from parts..."
$stream = [System.IO.File]::OpenWrite($target)
try {
    foreach ($p in $parts) {
        $bytes = [System.IO.File]::ReadAllBytes($p)
        $stream.Write($bytes, 0, $bytes.Length)
    }
} finally {
    $stream.Close()
}

$actual = (Get-FileHash $target -Algorithm SHA256).Hash
if ($actual -eq $expected) {
    Write-Host "[OK] PurpleKnight.exe reassembled and verified (SHA256 $actual)."
} else {
    Write-Error "SHA256 mismatch after reassembly — expected $expected, got $actual. File may be corrupt."
    Remove-Item $target -Force
    exit 1
}
