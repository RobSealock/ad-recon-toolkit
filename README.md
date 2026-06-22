# ad-recon-toolkit

Blue-team documentation and assessment toolkit for on-premises Active Directory and Server OS.

**Passive, non-destructive, AI-consumable output.**

## Deployment

Git is not available on most Windows servers and is rarely present on domain controllers. The standard deployment method is zip-and-copy, not `git clone`.

**Typical run host:** a domain-joined member server or admin workstation — not a DC. The toolkit connects to DCs remotely over LDAP and WinRM; it does not need to run on one.

### Option A — zip and copy (recommended for hardened environments)

1. On your dev machine, download or export the repo as a zip
2. Copy the zip to the run host via fileshare, USB, or RDP file transfer
3. Extract and run:

```powershell
# Extract the zip, then:
powershell.exe -ExecutionPolicy Bypass -File .\Start-Assessment.ps1
```

### Option B — git clone (if Git is available on the run host)

```powershell
git clone https://github.com/RobSealock/ad-recon-toolkit.git
cd ad-recon-toolkit
powershell.exe -ExecutionPolicy Bypass -File .\Start-Assessment.ps1
```

The script runs a user-context pass first, then prompts to re-launch elevated for privileged collectors. Prerequisites (binaries and PowerShell modules) are downloaded automatically on first run and cached in `tools\` for subsequent runs.

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

## Optional: Certipy (AD CS / ESC1–ESC16)

Certipy is an optional Python-based AD CS enumerator. When enabled it runs alongside Locksmith and acts as the primary authoritative scanner for certificate template and CA misconfigurations (ESC1–ESC16).

**Prerequisites**

- Python 3.8+ with pip installed on the run host
- Domain credentials with read access to AD CS (standard user is sufficient for enumeration)

**Install**

`Install-Prereqs.ps1` handles this automatically — it runs `pip install certipy-ad`, locates the installed `certipy.exe`, and copies it to `tools\bin\`. To do it manually:

```powershell
pip install certipy-ad
# Then copy certipy.exe from your Python Scripts directory to tools\bin\
```

**Configure credentials**

Certipy requires explicit credentials on Windows (the Linux Kerberos ccache is not available). Add the following to `config\settings.local.psd1` (git-ignored — never commit this file):

```powershell
@{
    EnableCertipy      = $true
    CertipyUsername    = 'DOMAIN\serviceaccount'   # or UPN: user@domain.com
    CertipyPassword    = 'password'
}
```

Alternatively, merge into an existing `settings.local.psd1` block. On Linux/macOS, `CertipyUsername`/`CertipyPassword` can be omitted if a valid Kerberos ticket is present (`kinit` has run for the assessment account).

**Enable**

Set `EnableCertipy = $true` in `config\settings.psd1` (applies to all runs) or in `config\settings.local.psd1` (local override only). It is disabled by default.

**What it produces**

- `output\runs\<RunId>\artifacts\certipy-findings.json` — raw Certipy output
- `certipy-findings` record in the run JSON — lists vulnerable CAs/templates with ESC IDs
- ADCS-008 findings (prefixed `[Certipy]`) in the CA-Config collector results
- `certipyCoveredEscIds` field in the `ca-inventory` record — provenance of which ESC IDs were evaluated this run

## Scope

See `SCOPE.md` for the full build brief and collector catalog.
