# ad-recon-toolkit

Blue-team documentation and assessment toolkit for on-premises Active Directory and Server OS.

**Passive, non-destructive, AI-consumable output.**

## Quick Start

```powershell
# Clone on a domain-joined member server or workstation
git clone https://github.com/RobSealock/ad-recon-toolkit.git
cd ad-recon-toolkit

# Run (bootstraps prerequisites automatically)
powershell.exe -ExecutionPolicy Bypass -File .\Start-Assessment.ps1
```

The script runs a user-context pass first, then prompts to re-launch elevated for privileged collectors.

## Output

```
output\
  runs\<RunId>\           ← normalized JSON records + run manifest
  reports\                ← Markdown risk register
  diffs\                  ← config drift between runs
```

## Compare two runs

```powershell
.\diff\Compare-ReconRuns.ps1 -RunAPath <RunId-A> -RunBPath <RunId-B>
```

## Tool downloads

See `bootstrap\tools.manifest.psd1` for the full list of required and optional tool downloads with URLs.
Run `Install-Prereqs.ps1` to fetch and verify all binaries automatically (requires internet access on first run).

## Scope

See `SCOPE.md` for the full build brief and collector catalog.
