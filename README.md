# ad-recon-toolkit

Blue-team documentation and assessment toolkit for on-premises Active Directory and Server OS.

**Passive, non-destructive, AI-consumable output.**

---

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

---

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

---

## Configuration switches

All switches live in `config\settings.psd1`. Local overrides (API tokens, credentials, per-machine flags) go in `config\settings.local.psd1` — that file is git-ignored and never committed.

| Switch | Default | Effect |
|---|---|---|
| `EnablePingCastle` | `$true` | Run PingCastle AD risk assessment; produces `pingcastle-*.xml` artifact |
| `EnableSharpHound` | `$true` | Run SharpHound BloodHound ingestor; produces `bloodhound-*.zip` artifact |
| `EnableLocksmith` | `$true` | Run Locksmith AD CS ESC1–ESC16 enumeration; findings feed into CA-Config collector |
| `EnableGroup3r` | `$true` | Run Group3r GPO sensitive-data scanner; findings feed into GPO-Settings collector (GPO-010) |
| `EnablePurpleKnight` | `$true` | Run Purple Knight assessment; raw export goes to `output\purpleknight\` (git-ignored) |
| `EnableHardeningKitty` | `$false` | Run HardeningKitty CIS/DISA benchmark in audit mode; produces BestPractice-Baseline findings (BP-001–004) |
| `EnableCertipy` | `$false` | Run Certipy AD CS scanner (requires Python + `pip install certipy-ad`); findings supplement Locksmith in CA-Config |

`EnableCertipy` also requires `CertipyUsername` and `CertipyPassword` in `settings.local.psd1` (or a valid Kerberos ticket on a Linux/macOS run host). See the [Certipy section](#optional-certipy-ad-cs--esc1esc16) below.

---

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

---

## Findings catalog

All findings are passive reads — no configuration is changed. Each finding maps to a MITRE ATT&CK technique and references the enabling condition, not the attack itself.

Severity: **Critical** → **High** → **Medium** → **Low** → **Informational**

---

### AD-Core — domain, accounts, Kerberos, ACLs

| ID | Finding | Severity |
|---|---|---|
| ADC-001 | `ms-DS-MachineAccountQuota > 0` — any authenticated user can join machines, enabling RBCD attacks | Medium |
| ADC-002 | Domain functional level below 2016 | Medium |
| ADC-003 | `krbtgt` password not rotated in 180+ days — Golden Ticket window | High |
| ADC-004 | AS-REP roastable accounts (`DONT_REQ_PREAUTH`) | High |
| ADC-005 | Kerberoastable accounts (enabled user with SPN) | High |
| ADC-006 | Unconstrained Kerberos delegation on non-DC computer | Critical |
| ADC-007 | Non-default account holds DCSync rights (`Replicating Directory Changes All`) | Critical |
| ADC-008 | `adminCount=1` accounts not in any protected group (AdminSDHolder orphans) | Medium |
| ADC-009 | Default domain password minimum length < 14 characters | Medium |
| ADC-010 | SID filtering disabled on external/forest trust | High |
| ADC-011 | Protected Users group is empty | Medium |
| ADC-012 | AD Recycle Bin not enabled — deleted objects permanently lost after tombstone lifetime | Low |
| ADC-013 | Accounts with DES-only Kerberos encryption | High |
| ADC-014 | Resource-Based Constrained Delegation (RBCD) configured on non-trivial objects | High |
| ADC-015 | Constrained delegation with protocol transition (S4U2Self — `TrustedToAuthForDelegation`) | High |
| ADC-016 | `msDS-KeyCredentialLink` populated on unexpected objects (shadow credentials) | Critical |
| ADC-017 | Password-like strings in `description`/`info`/`comment` AD attributes | High |
| ADC-018 | gMSA password retrieval rights granted to over-broad principals | Medium |
| ADC-019 | Non-Tier-0 principals with control ACEs on `CN=AdminSDHolder` (SDProp persistence) | Critical |
| ADC-020 | Non-Tier-0 principals with inheritable ReadProperty on LAPS password attributes | High |
| ADC-021 | `sIDHistory` populated on accounts | High |
| ADC-022 | `PASSWD_NOTREQD` UAC flag set — potentially blank passwords | Medium |
| ADC-023 | `ENCRYPTED_TEXT_PASSWORD_ALLOWED` (reversible encryption) — plaintext-recoverable passwords | High |
| ADC-024 | `altSecurityIdentities` with weak mapping forms (`X509RFC822`, `X509IssuerSubject`) — ESC14 | High |
| ADC-025 | Pre-Windows 2000 Compatible Access group contains `Everyone` or `Authenticated Users` | High |
| ADC-026 | Anonymous LDAP bind enabled (`dsHeuristics` position 7 = `2`) | Critical |
| ADC-027 | Enabled DA/EA/Schema Admin accounts not enrolled in Protected Users | High |
| ADC-028 | Privileged accounts with `DONT_EXPIRE_PASSWORD` flag | Medium |
| ADC-029 | Disabled accounts remaining in DA/EA/Schema Admin groups (ghost accounts) | Medium |
| ADC-030 | Tombstone lifetime below 180 days — short incident-response and backup window | Medium |
| ADC-031 | Forest functional level below 2016 | Medium |
| ADC-032 | Fine-Grained Password Policy with `minLength < 14` or no lockout threshold | Medium |
| ADC-033 | DC computer objects with no logon in 90+ days (stale/undecommissioned DCs) | Medium |
| ADC-034 | LAPS not deployed — local admin passwords not managed (schema absent or no enrolled computers) | High/Medium |
| ADC-035 | RC4 Kerberos encryption allowed on domain (`msDS-SupportedEncryptionTypes` includes RC4) | Medium |
| ADC-036 | Built-in Guest account enabled | High |
| ADC-037 | Built-in Administrator account not renamed and still enabled | Medium |
| ADC-038 | Schema Admins group has permanent members | High |
| ADC-039 | Entra Connect sync account (`MSOL_*`/`AZUREAD_*`) password age exceeds 365 days | High |
| ADC-040 | `AZUREADSSOACC$` Seamless SSO computer account present — static Kerberos key risk | Medium |
| ADC-041 | RODC Password Replication Policy includes Tier 0 groups in the reveal (allow) list | High |
| ADC-042 | `EXCHANGE WINDOWS PERMISSIONS` group has WriteDACL on domain root — DCSync escalation path | High |

---

### Host-OS — per-server OS posture (DCs and CA hosts)

Runs over WinRM. Each server is scanned independently; collection errors are soft-fail.

| ID | Finding | Severity |
|---|---|---|
| HOST-001 | Unexpected role installed on DC (IIS, FSRM, RDS, WSUS, etc.) | High |
| HOST-002 | Service running as a domain-privileged account | Medium |
| HOST-003 | Unquoted service binary path containing spaces | Medium |
| HOST-004 | Print Spooler running on DC — PrinterBug / PrintNightmare coercion surface | High |
| HOST-005 | WebClient (WebDAV) service running on DC — NTLM relay enabler | High |
| HOST-006 | SMBv1 enabled | Critical |
| HOST-007 | RDP enabled without Network Level Authentication | Medium |
| HOST-008 | LSA Protection (`RunAsPPL`) not enabled | High |
| HOST-009 | WDigest credential caching enabled — plaintext credentials in LSASS | Critical |
| HOST-010 | LAPS not deployed on this host | Medium |
| HOST-011 | LDAP signing not required on DC (`LDAPServerIntegrity < 2`) | High |
| HOST-012 | SMB signing not required | High |
| HOST-013 | LLMNR or NBT-NS enabled — name-resolution poisoning surface | High |
| HOST-014 | Built-in local Administrator account enabled with password older than 90 days | Medium |
| HOST-015 | SMB share accessible by Everyone or Authenticated Users (write) | High |
| HOST-016 | Scheduled task running as a domain-privileged identity | Medium |
| HOST-017 | DSRM admin logon behavior not restricted to DSRM mode (`DsrmAdminLogonBehavior >= 1`) | High/Critical |
| HOST-018 | EFS service running on DC — MS-EFSRPC / PetitPotam coercion surface | Medium |
| HOST-019 | DFS Namespace service running on DC — MS-DFSNM / DFSCoerce coercion surface | Medium |
| HOST-020 | `StrongCertificateBindingEnforcement < 2` on DC — ESC6/ESC9/ESC10 still exploitable | High |
| HOST-021 | `LmCompatibilityLevel < 5` — NTLMv1 or LM responses accepted | High |
| HOST-022 | Credential Guard (VBS + `LsaCfgFlags`) not enabled | High/Medium |
| HOST-023 | PowerShell v2 feature installed — bypasses ScriptBlock logging and AMSI | Medium |
| HOST-024 | LDAP channel binding not required on DC (`LdapEnforceChannelBinding < 2`) — LDAP relay path | High |
| HOST-025 | WinRM `AllowUnencrypted = 1` — plaintext PowerShell remoting traffic | High |
| HOST-026 | Remote Registry service running on DC | Medium |
| HOST-027 | BitLocker not enabled on DC OS volume — offline NTDS.dit theft risk | Medium |
| HOST-028 | IPv6 not fully disabled on DC — mitm6 DHCPv6 relay attack surface | High |
| HOST-029 | SMB client signing not required — SMB relay from workstations to DC | Medium |
| HOST-030 | Cached domain logons count > 0 on DC (`CachedLogonsCount`) — offline credential theft | High |
| HOST-031 | Netlogon secure channel signing/sealing not required (`RequireSignOrSeal`/`SealSecureChannel`) | High |
| HOST-032 | AD/DC system-state backup not found or older than 30 days | High |

---

### CA-Config — AD Certificate Services

Includes native template/CA evaluation, Locksmith integration (ESC1–ESC16), optional Certipy integration, and ESC12 review-required records per CA.

| ID | Finding | Severity |
|---|---|---|
| ADCS-001 | HTTP (non-TLS) web enrollment endpoint present — ESC8 relay prerequisite | Critical |
| ADCS-002 | Template allows requestor-supplied SAN + Client Auth EKU + broad enrollment (ESC1) | Critical |
| ADCS-003 | Template has over-broad enrollment rights (`Authenticated Users`/`Everyone`) | High |
| ADCS-004 | Template allows enrollment agent (`Certificate Request Agent` EKU) — ESC3 | High |
| ADCS-005 | Template EKU includes Any Purpose or no EKU — ESC2 | High |
| ADCS-006 | CA has no CRL Distribution Point configured | Low |
| ADCS-007 | Manager approval not required on Client Auth or Any Purpose template with broad access | Medium |
| ADCS-008 | Locksmith or Certipy identified ESC1–ESC16 vulnerability (see finding detail for ESC ID) | Varies |
| ADCS-009 | Schema-v1 template with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + broad enrollment — ESC15 / CVE-2024-49019 | Critical |
| ADCS-010 | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag — any template allows requestor-supplied SAN (ESC6) | Critical |
| ADCS-011 | HTTP enrollment endpoint without Extended Protection for Authentication — NTLM relay to CA (ESC8) | Critical |
| ADCS-012 | Non-default CA present in `NTAuthCertificates` — can issue domain authentication certificates | High |
| ADCS-013 | DC Authentication template published but no DC has a certificate enrolled (`userCertificate` unset) | Medium |

---

### GPO-Settings — Group Policy

| ID | Finding | Severity |
|---|---|---|
| GPO-001 | `cpassword` (encrypted GPP credential) found in SYSVOL | Critical |
| GPO-002 | No screensaver lock policy (idle session timeout) | Low |
| GPO-003 | WDigest not disabled via GPO (`UseLogonCredential` not set to 0) | High |
| GPO-004 | LLMNR not disabled via GPO | High |
| GPO-005 | NBT-NS not disabled via GPO | Medium |
| GPO-006 | LSA `RunAsPPL` not enforced via GPO | High |
| GPO-007 | SMBv1 not explicitly disabled via GPO | Critical |
| GPO-008 | Print Spooler not disabled on DCs via GPO | High |
| GPO-009 | Advanced audit policy not configured via GPO | High |
| GPO-010 | Group3r findings (sensitive data in GPO settings) | Varies |
| GPO-011 | No AppLocker or WDAC policy linked to the Domain Controllers OU | Medium |
| GPO-012 | No Restricted Groups or GPP Groups policy enforcing Domain Admins membership | Medium |
| GPO-013 | Non-Tier-0 principal has write rights (WriteDACL/WriteOwner/GenericAll/GenericWrite) on a DC-linked GPO | Critical |
| GPO-014 | No deny-logon user rights (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`) configured in DC OU GPO | High |
| GPO-015 | Orphaned GPOs exist in AD (defined but not linked to any OU, domain root, or site) | Low |

---

### DNS — AD-integrated DNS

| ID | Finding | Severity |
|---|---|---|
| DNS-001 | DNS zone allows nonsecure dynamic updates — ADIDNS spoofing/poisoning | High |
| DNS-002 | Wildcard A/AAAA record present — catch-all relay/MitM risk | High |
| DNS-003 | `wpad` or `isatap` record present — WPAD hijack / ISATAP routing attack | High |
| DNS-004 | DNS record created in the last 24 hours (change alert) | Informational |
| DNS-005 | DNS record name does not match any AD computer account (orphaned/rogue record) | Medium |
| DNS-006 | `DnsAdmins` group has members — DLL injection path to SYSTEM on DNS server | High |
| DNS-007 | Non-Tier-0 principal has `CreateChild`/`WriteProperty` on `MicrosoftDNS` or a zone (ADIDNS write) | High |
| DNS-008 | DNS zone allows AXFR zone transfer to any IP — full zone data exposed | High |
| DNS-009 | DNS server has forwarders pointing to public/external IP addresses | Medium |
| DNS-010 | DNS scavenging not enabled on primary zone — stale records accumulate, enabling ADIDNS spoofing | Medium |

---

### Audit-Policy — logging and detection baseline

| ID | Finding | Severity |
|---|---|---|
| AUD-001 | Directory Service Changes (Event 4136) not enabled — AD modifications unlogged | High |
| AUD-002 | Directory Service Access (Event 4662) not enabled — SACL/DCSync detection blind spot | High |
| AUD-003 | Process Creation (Event 4688) not enabled and no EDR detected | High |
| AUD-004 | Command-line capture in 4688 not enabled and no EDR detected | High |
| AUD-005 | Security Group Management auditing not enabled | Medium |
| AUD-006 | User Account Management auditing not enabled | Medium |
| AUD-007 | Kerberos authentication/ticket logging insufficient | Medium |
| AUD-008 | Sensitive Privilege Use auditing not enabled | High |
| AUD-009 | Audit Policy Change (Event 4719) not enabled — silent logging tampering risk | High |
| AUD-010 | PowerShell ScriptBlock logging not enabled | High |
| AUD-011 | Security log maximum size below CIS minimum (192 MB) | Medium |
| AUD-012 | Sysmon not installed or configuration not loaded on DC | Medium |
| AUD-013 | NTDS Field Engineering diagnostic level < 5 — expensive LDAP query logging (1644) not active | Low |
| AUD-014 | Windows Event Forwarding (WEC) subscription not configured on DC — no centralized log collection | Medium |
| AUD-015 | NTLM authentication auditing not enabled on DC (`AuditReceivingNTLMTraffic = 0`) — Event 8004 blind | Medium |

---

### Host-Firewall — Windows Firewall posture

| ID | Finding | Severity |
|---|---|---|
| FW-001 | Windows Firewall profile disabled on DC | High |
| FW-002 | Default inbound action is `Allow` on any profile — deny-by-default not enforced | High |
| FW-003 | Firewall logging disabled for a profile | Medium |
| FW-004 | Inbound allow rule on high-risk port open to `Any` source address | High |
| FW-005 | Telnet (23) or other legacy management port inbound rule exists | High |
| FW-006 | Firewall policy is local-only — no GPO enforcement detected | Medium |

---

### DHCP — authorized DHCP servers

| ID | Finding | Severity |
|---|---|---|
| DHCP-001 | DHCP scope has WPAD proxy URL configured (option 252) — NTLM relay enabler | High |
| DHCP-002 | DHCP scope has PXE boot server options (66/67) — network boot attack surface | Medium |
| DHCP-003 | DHCP audit logging disabled on server | Medium |

---

### BestPractice-Baseline — CIS/DISA benchmark (optional)

Disabled by default. Enable with `EnableHardeningKitty = $true` in `config\settings.psd1`.
Runs HardeningKitty in audit mode — reads settings only, changes nothing.

| ID | Finding | Severity |
|---|---|---|
| BP-001 | High-severity CIS/DISA deviation (up to 20 listed individually) | High |
| BP-002 | Additional high-severity deviations beyond the first 20 (see artifact) | Medium |
| BP-003 | Medium-severity CIS/DISA deviations detected | Medium |
| BP-004 | Low-severity CIS/DISA deviations detected | Low |

---

## Review-required records

Some conditions cannot be assessed remotely or automatically. These are emitted as `review-required` records rather than findings, so the post-run pass knows to investigate them manually:

| Record | Reason |
|---|---|
| `CA:esc12:<ca>` | HSM key storage for each CA private key (ESC12) — requires physical/console confirmation |
| RODC presence | Password replication policy and msDS-RevealedList require manual review |
| Exchange presence | EXCHANGE WINDOWS PERMISSIONS AD rights require review |
| SCCM/MECM presence | NAA account and client push account permissions require review |
| ADFS presence | Token-signing certificate and relying party trust configuration |
| Entra Connect presence | ADSync/MSOL account AD permissions and sync mode (PHS, PTA, seamless SSO) |
| WSUS presence | Update approval rights and SSL enforcement |

---

## Scope

See `SCOPE.md` for the full build brief and collector catalog.
