# SharpHound collector — BloodHound CE data collection (attack-path graph).
# MinPrivilege: T0 (needs domain user at minimum; T0 held = run elevated).
# Binary: tools\bin\SharpHound.exe  (fetched by Install-Prereqs.ps1)

# BloodHound CE API key format in settings: "tokenId:tokenKey"
# tokenId and tokenKey are generated from the BH CE UI (Administration → API Keys).
function _BHCE_SignedHeaders {
    param([string]$Method, [string]$UriPath, [string]$TokenId, [string]$TokenKey, [byte[]]$Body = @())
    $dateStr = (Get-Date).ToUniversalTime().ToString('o')
    $sha256   = [System.Security.Cryptography.SHA256]::Create()
    $digest   = [BitConverter]::ToString($sha256.ComputeHash($Body)).Replace('-','').ToLower()
    $signStr  = "$dateStr`n$($Method.ToUpper())`n$UriPath`n$digest"
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($TokenKey)
    $hmac     = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    $sig      = [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signStr)))
    return @{
        'Authorization' = "bhesignature $TokenId"
        'RequestDate'   = $dateStr
        'Signature'     = $sig
    }
}

function _BHCE_Upload {
    param([string]$ApiUrl, [string]$ApiKey, [string]$ZipPath)
    $parts = $ApiKey -split ':', 2
    if ($parts.Count -ne 2) { throw "BloodHoundApiKey must be 'tokenId:tokenKey' format" }
    $tokenId  = $parts[0]
    $tokenKey = $parts[1]
    $base     = $ApiUrl.TrimEnd('/')

    # Start upload job
    $startPath = '/api/v2/file-upload/start'
    $h = _BHCE_SignedHeaders -Method 'POST' -UriPath $startPath -TokenId $tokenId -TokenKey $tokenKey
    $resp = Invoke-RestMethod -Uri "$base$startPath" -Method POST -Headers $h -ContentType 'application/json' -Body '{}'
    $jobId = $resp.data.id

    # Upload zip
    $zipBytes   = [System.IO.File]::ReadAllBytes($ZipPath)
    $uploadPath = "/api/v2/file-upload/$jobId"
    $h = _BHCE_SignedHeaders -Method 'POST' -UriPath $uploadPath -TokenId $tokenId -TokenKey $tokenKey -Body $zipBytes
    $h['Content-Type'] = 'application/zip'
    Invoke-RestMethod -Uri "$base$uploadPath" -Method POST -Headers $h -Body $zipBytes | Out-Null

    # Finalise
    $endPath = "/api/v2/file-upload/$jobId/end"
    $h = _BHCE_SignedHeaders -Method 'POST' -UriPath $endPath -TokenId $tokenId -TokenKey $tokenKey
    Invoke-RestMethod -Uri "$base$endPath" -Method POST -Headers $h | Out-Null

    return $jobId
}

function _SharpHound_Collect {
    param($RunContext, $Settings, $RunRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $runId   = $RunContext.RunId
    $binPath = Join-Path $RunContext.RepoRoot 'tools\bin\SharpHound.exe'
    $artDir  = Join-Path $RunRoot 'artifacts'

    if ($Settings['EnableSharpHound'] -eq $false) {
        $records.Add((New-ReconRecord `
            -Collector 'SharpHound' -ObjectType 'collection-status' `
            -StableId 'SharpHound:disabled' -Category 'config' -Tier 'T0' `
            -Attributes @{ status = 'disabled'; reason = 'EnableSharpHound = $false in settings.psd1' } `
            -RunId $runId))
        return $records
    }

    if (-not (Test-Path $binPath)) {
        $records.Add((New-CollectionError -Collector 'SharpHound' `
            -Target 'tools\bin\SharpHound.exe' `
            -ErrorMessage 'Binary not found. Run Install-Prereqs.ps1 or pre-stage tools\bin\SharpHound.exe.' `
            -RunId $runId))
        return $records
    }

    try {
        Write-Host "         Running SharpHound against $($RunContext.Domain)..."
        $zipFile = $null

        # CollectAll for CtF; production may subset (e.g., --CollectionMethods Default)
        $shOutput = & $binPath --CollectionMethods All --Domain $RunContext.Domain --OutputDirectory $artDir `
            --ZipFilename "sharphound-$runId.zip" 2>&1
        $shOutput | ForEach-Object { Write-Host "         [SharpHound] $_" }
        $shOutput | Out-File (Join-Path $artDir "sharphound-$runId.log") -Encoding UTF8

        $zipFile = Get-ChildItem -Path $artDir -Filter 'sharphound-*.zip' | Select-Object -First 1

        $attrs = @{
            domain         = $RunContext.Domain
            zipFile        = if ($zipFile) { $zipFile.Name } else { 'not produced' }
            collectionNote = 'Import the zip into BloodHound CE for attack-path analysis, or configure BloodHoundApiUrl/BloodHoundApiKey to upload automatically.'
        }

        # BloodHound CE API upload (optional — requires BloodHoundApiUrl and BloodHoundApiKey in settings)
        if ($Settings['BloodHoundApiUrl'] -and $Settings['BloodHoundApiKey'] -and $zipFile) {
            try {
                Write-Host "         Uploading to BloodHound CE at $($Settings['BloodHoundApiUrl'])..."
                $jobId = _BHCE_Upload -ApiUrl $Settings['BloodHoundApiUrl'] `
                                      -ApiKey $Settings['BloodHoundApiKey'] `
                                      -ZipPath $zipFile.FullName
                $attrs['uploadStatus']   = "uploaded — job $jobId"
                $attrs['collectionNote'] = 'Uploaded to BloodHound CE automatically — no manual import needed.'
                Write-Host "         BloodHound CE upload complete (job $jobId)"
            } catch {
                $attrs['uploadStatus'] = "upload failed: $_"
                Write-Warning "[SharpHound] BloodHound CE upload failed: $_"
            }
        } elseif ($Settings['BloodHoundApiUrl'] -and $zipFile) {
            $attrs['uploadStatus'] = 'skipped — BloodHoundApiKey not set in settings.local.psd1'
        }

        $records.Add((New-ReconRecord `
            -Collector      'SharpHound' `
            -ObjectType     'bloodhound-collection' `
            -StableId       "SharpHound:$($RunContext.Domain)" `
            -Category       'config' `
            -Tier           'T0' `
            -CollectedAtPriv $true `
            -Attributes     $attrs `
            -RawArtifactRef $(if ($zipFile) { $zipFile.Name } else { $null }) `
            -RunId          $runId))

    } catch {
        $records.Add((New-CollectionError -Collector 'SharpHound' `
            -Target $RunContext.Domain -ErrorMessage $_.ToString() -RunId $runId))
    }

    return $records
}

Register-Collector `
    -Name        'SharpHound' `
    -Description 'BloodHound CE data collection (attack paths, ACLs, sessions) via SharpHound' `
    -MinPrivilege 'T0' `
    -Invoke      { param($RunContext, $Settings, $RunRoot) _SharpHound_Collect @PSBoundParameters }
