<#
.SYNOPSIS
    Reassembles ForestDruid.exe from its split parts.

.DESCRIPTION
    ForestDruid.exe (201 MB) exceeds GitHub's 100 MB per-file limit and is
    stored as three binary chunks (ForestDruid.exe.partaa through .partac).
    Run this script once after cloning or extracting the repo to reassemble
    the executable before launching Forest Druid.

    Verifies the SHA256 of the reassembled file. Safe to re-run — skips
    reassembly if ForestDruid.exe is already present and hash-matches.
#>
[CmdletBinding()]
param(
    [string]$Dir = $PSScriptRoot
)

$target   = Join-Path $Dir 'ForestDruid.exe'
$expected = '291BBA1C6B4A47A9F8A396860A02440B1215C7B13A008CBBF28620E6FB3A6404'
$parts    = @('partaa','partab','partac') | ForEach-Object { Join-Path $Dir "ForestDruid.exe.$_" }

foreach ($p in $parts) {
    if (-not (Test-Path $p)) {
        Write-Error "Missing part: $p — ensure all three .part* files are present."
        exit 1
    }
}

if (Test-Path $target) {
    $existing = (Get-FileHash $target -Algorithm SHA256).Hash
    if ($existing -eq $expected) {
        Write-Host "[OK] ForestDruid.exe already present and verified — nothing to do."
        exit 0
    }
    Write-Host "[INFO] ForestDruid.exe present but hash mismatch — reassembling."
}

Write-Host "Reassembling ForestDruid.exe from parts..."
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
    Write-Host "[OK] ForestDruid.exe reassembled and verified (SHA256 $actual)."
} else {
    Write-Error "SHA256 mismatch after reassembly — expected $expected, got $actual. File may be corrupt."
    Remove-Item $target -Force
    exit 1
}
