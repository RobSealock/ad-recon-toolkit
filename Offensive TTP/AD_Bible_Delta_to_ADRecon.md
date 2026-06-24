# AD Bible → ad-recon-toolkit Coverage Map

How each attack path in `AD_Bible.md` maps to `ad-recon-toolkit` findings.
"Covered" means the toolkit surfaces the **enabling condition** — the misconfiguration
or exposure that makes the attack possible. The toolkit is passive and non-destructive;
it does not execute attacks.

---

## Legend

| Status | Meaning |
|---|---|
| **Covered** | One or more findings directly surface the enabling condition |
| **Partial** | Some signal exists; full coverage requires additional tooling or manual review |
| **Review-required** | Cannot be assessed remotely/automatically; emitted as a `review-required` record |
| **Out of scope** | Intentionally excluded (active exploit, physical access, cloud-only) |

---

## Coverage table

| Attack path (AD_Bible §) | ATT&CK | Finding ID(s) | Status | Notes |
|---|---|---|---|---|
| **§1 — Unauthenticated / external enumeration** | | | | |
| Host & service discovery | T1046 | HOST-025 (WinRM unencrypted) | Partial | Network exposure determined by scope; firewall posture → FW-001–006 |
| SMB null sessions / anonymous RPC | T1135, T1069.002 | ADC-026 (anon LDAP), HOST-006 (SMBv1) | Partial | Null-session registry keys not yet directly checked; RestrictAnonymous surfaced via GPO/BP |
| RID cycling | T1087.002 | ADC-026 | Partial | Same root cause as anonymous LDAP; RID-level enumeration not directly flagged |
| LDAP anonymous bind | T1087.002 | **ADC-026** | **Covered** | Checks `dsHeuristics` position 7 |
| DNS zone transfer | T1590.002 | **DNS-008** | **Covered** | Flags AXFR open to any IP |
| DNS SRV enumeration | T1590.002 | DNS-001–DNS-010 (zone config) | Partial | SRV enumeration is expected; misconfigured zones are flagged |
| Kerberos user enumeration (kerbrute) | T1589.001 | AUD-007 (Kerberos logging) | Partial | Detection only; no pre-auth config change blocks enumeration |
| AS-REP roasting (unauthenticated) | T1558.004 | **ADC-004** | **Covered** | Finds all `DONT_REQ_PREAUTH` accounts |
| **§2 — Authenticated enumeration** | | | | |
| BloodHound / SharpHound collection | T1069.002, T1087.002 | AUD-001 (DS Changes), AUD-002 (DS Access), SharpHound collector | Partial | SharpHound runs as part of toolkit; blue-team detection via audit logging |
| PowerView / LDAP attribute mining | T1087.002 | AUD-009 (audit policy change), AUD-010 (ScriptBlock logging) | Partial | Defensive: ScriptBlock logging (AUD-010) captures PowerView invocations |
| Share discovery / Snaffler | T1135, T1039 | HOST-015 (over-broad share ACL) | Partial | Share enumeration run by toolkit; HOST-015 flags world-writable shares |
| Secrets in AD attributes | T1552.004 | **ADC-017** | **Covered** | Scans description/info/comment for password-pattern strings |
| **§3 — Credential access** | | | | |
| Kerberoasting | T1558.003 | **ADC-005**, **ADC-035** | **Covered** | ADC-005: SPN accounts; ADC-035: RC4 encryption allowed (force multiplier) |
| AS-REP roasting | T1558.004 | **ADC-004** | **Covered** | All `DONT_REQ_PREAUTH` accounts |
| Password spraying | T1110.003 | **ADC-009**, **ADC-032** | **Covered** | ADC-009: default domain password policy; ADC-032: fine-grained PSO gaps |
| LLMNR / NBT-NS poisoning | T1557.001 | **HOST-013**, **GPO-004**, **GPO-005** | **Covered** | HOST-013: per-host; GPO-004/005: domain-wide GPO enforcement |
| NTLM relay (SMB relay) | T1557.001 | **HOST-012**, **HOST-029**, **HOST-028** | **Covered** | HOST-012: SMB server signing; HOST-029: SMB client signing; HOST-028: IPv6/mitm6 surface |
| Responder hash capture | T1557.001 | HOST-013, GPO-004, GPO-005 | **Covered** | Same enabling conditions as LLMNR/NBT-NS poisoning |
| GPP cpassword (MS14-025) | T1552.006 | **GPO-001** | **Covered** | Scans SYSVOL XML for `cpassword` attribute |
| LAPS password read | T1555 | **ADC-020**, **ADC-034** | **Covered** | ADC-020: who can read LAPS attrs; ADC-034: whether LAPS is even deployed |
| gMSA password retrieval | T1555 | **ADC-018** | **Covered** | Flags over-broad `PrincipalsAllowedToRetrieveManagedPassword` |
| Timeroasting | T1558 | — | Partial | Niche; not directly checked. NTP exposure not in current scope |
| DPAPI / on-host secrets | T1555 | HOST-008 (RunAsPPL), HOST-022 (Credential Guard) | Partial | Mitigating controls flagged; DPAPI blob discovery is post-foothold only |
| NTLM usage blind spot | T1557.001 | **AUD-015** | **Covered** | Flags `AuditReceivingNTLMTraffic = 0` — Event 8004 blind |
| **§4 — Domain privilege escalation** | | | | |
| ACL / ACE abuse (GenericAll, WriteDACL) | T1222.001, T1098 | **ADC-007** (DCSync rights), **ADC-019** (AdminSDHolder), **GPO-013** (GPO write rights) | **Covered** | SharpHound collector maps full ACL graph |
| Shadow Credentials | T1556.006 | **ADC-016** | **Covered** | Flags non-empty `msDS-KeyCredentialLink` on unexpected objects |
| Unconstrained delegation | T1558.003 | **ADC-006** | **Covered** | Non-DC computers with `TRUSTED_FOR_DELEGATION` |
| Constrained delegation (S4U2Self) | T1558.003 | **ADC-015** | **Covered** | Protocol-transition delegation flag |
| RBCD | T1098 | **ADC-014**, **ADC-001** | **Covered** | ADC-014: existing RBCD; ADC-001: MachineAccountQuota |
| AD CS ESC1 (enrollee SAN + Client Auth) | T1649 | **ADCS-002**, **ADCS-008** | **Covered** | Locksmith + Certipy + native checks |
| AD CS ESC2 (Any Purpose EKU) | T1649 | **ADCS-005** | **Covered** | |
| AD CS ESC3 (enrollment agent) | T1649 | **ADCS-004** | **Covered** | |
| AD CS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) | T1649 | **ADCS-010** | **Covered** | |
| AD CS ESC8 (HTTP web enrollment relay) | T1649 | **ADCS-001**, **ADCS-011** | **Covered** | HTTP endpoint + EPA enforcement |
| AD CS ESC15 (schema-v1 + enrollee SAN) | T1649 | **ADCS-009** | **Covered** | |
| AD CS DC cert enrollment gap | T1649 | **ADCS-013** | **Covered** | DCs missing userCertificate despite DC Auth template published |
| Weak alt security identity mapping (ESC14) | T1649 | **ADC-024** | **Covered** | Weak `altSecurityIdentities` forms |
| NoPAC (CVE-2021-42278/42287) | T1134.005 | **ADC-001** | Partial | MAQ > 0 is the prerequisite; patch-level check via VulnCheck-Enrich |
| MS14-068 (legacy PAC forgery) | T1134.005 | VulnCheck-Enrich | Partial | Patch level only; modern DCs not vulnerable |
| **§5 — Lateral movement** | | | | |
| Pass-the-Hash | T1550.002 | **ADC-034** (LAPS not deployed), **ADC-037** (Admin not renamed), **HOST-021** (NTLMv1) | Covered | LAPS deployment is the primary control; AUD-015 enables detection |
| Pass-the-Ticket / OverPass-the-Hash | T1550.003 | **ADC-035** (RC4 allowed), HOST-008, HOST-022 | Covered | ADC-035: RC4 ticket forging; RunAsPPL/CredGuard: extraction prevention |
| Token impersonation (SeImpersonate) | T1134.001 | HOST-001 (unexpected roles on DC) | Partial | Service account hardening; process isolation not directly assessed |
| Remote execution (PSExec/WMI/DCOM/WinRM) | T1021, T1569.002 | **HOST-025** (WinRM unencrypted), **HOST-012** (SMB signing), FW-004 | Partial | Network path controls; execution method itself not blocked by toolkit |
| **§6 — Domain dominance & persistence** | | | | |
| DCSync | T1003.006 | **ADC-007** | **Covered** | Non-DC principals with `DS-Replication-Get-Changes-All` |
| Exchange WriteDACL → DCSync | T1222.001 | **ADC-042** | **Covered** | `EXCHANGE WINDOWS PERMISSIONS` WriteDACL on domain root |
| NTDS.dit extraction (VSS / ntdsutil) | T1003.003 | **HOST-032** (backup recency/VSS state), HOST-008 | Partial | Legitimate backup detection; theft of NTDS is post-foothold |
| LSASS dumping | T1003.001 | **HOST-008** (RunAsPPL), **HOST-022** (Credential Guard), **HOST-009** (WDigest) | **Covered** | All three mitigating controls checked |
| WDigest credential caching | T1003.001 | **HOST-009**, **GPO-003** | **Covered** | Per-host and domain-wide GPO enforcement |
| Golden Ticket | T1558.001 | **ADC-003** (krbtgt password age) | **Covered** | Key rotation cadence is the primary preventive control |
| Silver Ticket | T1558.002 | **ADC-040** (AZUREADSSOACC$ static key) | Partial | Service account rotation not directly checked beyond AZUREADSSOACC$ |
| Diamond / Sapphire Ticket | T1558 | ADC-003 | Partial | Same root as Golden Ticket; newer variants harder to detect |
| DSRM logon enablement | T1556 | **HOST-017** | **Covered** | `DsrmAdminLogonBehavior` registry value |
| DCShadow | T1207 | — | Partial | Replication topology anomalies; no direct check in current scope |
| Skeleton Key | T1556.001 | HOST-008 (RunAsPPL prevents LSASS patch) | Partial | Credential Guard blocks it entirely (HOST-022) |
| AdminSDHolder ACL persistence | T1098 | **ADC-019** | **Covered** | Non-default ACEs on `CN=AdminSDHolder` |
| GPO ACL persistence | T1484.001 | **GPO-013** | **Covered** | Non-Tier-0 write rights on DC-linked GPOs |
| Orphaned GPOs | T1484.001 | **GPO-015** | **Covered** | GPOs defined but not linked |
| Schema Admins permanent members | T1098 | **ADC-038** | **Covered** | Schema Admins group should be empty at rest |
| Guest account enabled | T1078.001 | **ADC-036** | **Covered** | |
| Built-in Administrator not renamed | T1078.002 | **ADC-037** | **Covered** | |
| **§7 — Trusts & cross-forest** | | | | |
| Trust enumeration | T1482 | **ADC-010** | **Covered** | SID filtering disabled on external/forest trusts |
| Child → parent (SID history / ExtraSids) | T1134.005 | **ADC-021** | **Covered** | `sIDHistory` populated on accounts |
| Inter-forest trust ticket | T1134.005 | ADC-010 | Partial | Trust key itself not extracted; SID-filtering state is the preventive check |
| PAM trust abuse | T1134.005 | — | Review-required | Shadow-principal mapping requires manual review |
| **§8 — AD-adjacent infrastructure** | | | | |
| AD CS ESC8 relay (coerce + relay to CA) | T1649 | **ADCS-001**, **ADCS-011**, HOST-004, HOST-018 | **Covered** | HTTP endpoint + EPA + coercion surface (spooler/EFS) |
| ADIDNS wildcard / WPAD record | T1557.001 | **DNS-002**, **DNS-003**, **DNS-007** | **Covered** | Wildcard detection, WPAD/ISATAP, zone write ACL |
| ADIDNS non-secure dynamic updates | T1557.001 | **DNS-001** | **Covered** | |
| DNS scavenging not configured | T1557.001 | **DNS-010** | **Covered** | Stale records accumulate → spoofing surface |
| Exchange PrivExchange | T1222.001 | **ADC-042** | **Covered** | WriteDACL path flagged; Exchange role flagged as review-required |
| SCCM/MECM NAA recovery | T1555 | — | Review-required | SCCM presence detected; full NAA assessment out of scope |
| WSUS update injection | T1199 | — | Review-required | WSUS presence detected; SSL/signing assessment out of scope |
| ADFS Golden SAML | T1606.002 | — | Review-required | ADFS presence detected; token-signing cert requires on-console review |
| RODC PRP credential caching | T1552.004 | **ADC-041** | **Covered** | Tier-0 accounts in RODC reveal list |
| Entra Connect sync account | T1078.002 | **ADC-039** | **Covered** | Sync account password age > 365 days |
| AZUREADSSOACC$ static Kerberos key | T1558.002 | **ADC-040** | **Covered** | Static key not rotated → Silver Ticket path to MS Online |
| Print Spooler coercion (PrinterBug) | T1557 | **HOST-004**, **GPO-008** | **Covered** | Spooler running on DC |
| EFS coercion (PetitPotam) | T1557 | **HOST-018** | **Covered** | EFS service running on DC |
| DFS coercion (DFSCoerce) | T1557 | **HOST-019** | **Covered** | DFS Namespace service on DC |
| WebClient/WebDAV relay enabler | T1557 | **HOST-005** | **Covered** | WebClient service running on DC |
| IPv6 / mitm6 surface | T1557 | **HOST-028** | **Covered** | IPv6 not fully disabled on DCs |
| **§9 — CVEs** | | | | |
| ZeroLogon (CVE-2020-1472) | T1190 | **HOST-031** (Netlogon signing) | Partial | Patch state via VulnCheck-Enrich; HOST-031 is the hardening control |
| PrintNightmare (CVE-2021-1675/34527) | T1203 | **HOST-004**, **GPO-008** | **Covered** | Spooler-on-DC is the prerequisite |
| NoPAC (CVE-2021-42278/42287) | T1134.005 | **ADC-001** | Partial | MAQ prerequisite covered; DC patch level via VulnCheck-Enrich |
| PetitPotam (MS-EFSRPC) | T1557 | **HOST-018**, **ADCS-001**, **ADCS-011** | **Covered** | EFS service + unprotected web enrollment = exploit chain |
| PrivExchange / MS14-068 | T1222.001 | **ADC-042**, VulnCheck-Enrich | Partial | WriteDACL path covered; patch level via VulnCheck |
| **Logging & detection baseline** | | | | |
| Process creation logging blind | T1059 | **AUD-003**, **AUD-004** | **Covered** | Event 4688 + command-line capture |
| ScriptBlock logging blind | T1059.001 | **AUD-010** | **Covered** | PowerShell ScriptBlock logging |
| Directory change logging blind | T1484 | **AUD-001**, **AUD-002** | **Covered** | DS Changes (4136) and DS Access (4662) |
| Audit policy change blind | T1562.002 | **AUD-009** | **Covered** | Event 4719 not audited |
| Centralized log collection absent | T1562 | **AUD-014** | **Covered** | WEC subscription not configured on DC |
| NTLM authentication blind | T1557.001 | **AUD-015** | **Covered** | AuditReceivingNTLMTraffic = 0 |
| Cached domain logons on DC | T1003.005 | **HOST-030** | **Covered** | CachedLogonsCount > 0 on DC |
| Netlogon channel not secured | T1557 | **HOST-031** | **Covered** | RequireSignOrSeal + SealSecureChannel |
| SMB client signing not required | T1557.001 | **HOST-029** | **Covered** | LanmanWorkstation RequireSecuritySignature |
| Kerberos RC4 allowed | T1558.003 | **ADC-035** | **Covered** | msDS-SupportedEncryptionTypes includes RC4 |
| DC logon deny rights absent | T1078.002 | **GPO-014** | **Covered** | No SeDenyInteractiveLogonRight in DC OU GPO |
| DC auth certificate not enrolled | T1649 | **ADCS-013** | **Covered** | DC computers missing userCertificate |

---

## Remaining gaps

These conditions are not currently assessed by the toolkit. None were in scope for the implementation sprints to date.

| Gap | Why not covered | Recommended approach |
|---|---|---|
| **RID cycling / null session RestrictAnonymous** | Registry keys `RestrictAnonymous`/`RestrictAnonymousSAM` not currently read | Add to Host-OS or GPO-Settings collector as a single registry read |
| **Timeroasting exposure** | NTP authentication is a niche legacy path; not in current collector scope | Optional: check for computer accounts with `userAccountControl` flags indicating NTP auth; low priority |
| **DCShadow detection** | Replication topology comparison requires multi-DC baseline; no reliable passive single-point check | Handled by Active Directory-aware SIEM (Defender for Identity); out of scope for passive collector |
| **Service account password rotation age** | Kerberoastable accounts are flagged; password age of non-SPN service accounts is not checked | Extend AD-Core to flag `pwdLastSet > 365` days on service accounts (`adminCount=1` or in specific OUs) |
| **Golden gMSA / KDS root key exposure** | Requires reading KDS root key objects; niche attack path | Optional: check read rights on `CN=Master Root Keys,CN=Group Key Distribution Service,...` |
| **PAM trust shadow principals** | Requires bastion forest enumeration; physically separate environment | Review-required record emitted when PAM trust is detected |
| **SCCM NAA credential recovery** | Active retrieval from WMI; out of passive/non-destructive scope | Review-required record emitted when SCCM is detected |
| **ADFS token-signing cert** | Requires ADFS console or certificate store access; not remotely assessable | Review-required record emitted when ADFS is detected |

---

## Finding ID quick reference

| Finding ID | Collector | Attack path enabled/detected |
|---|---|---|
| ADC-001 | AD-Core | MachineAccountQuota — RBCD, NoPAC prerequisite |
| ADC-002 | AD-Core | Domain functional level |
| ADC-003 | AD-Core | krbtgt rotation — Golden Ticket window |
| ADC-004 | AD-Core | AS-REP roasting (DONT_REQ_PREAUTH) |
| ADC-005 | AD-Core | Kerberoasting (SPN accounts) |
| ADC-006 | AD-Core | Unconstrained delegation |
| ADC-007 | AD-Core | DCSync rights (non-DC replication rights) |
| ADC-008 | AD-Core | AdminSDHolder orphans (adminCount=1) |
| ADC-009 | AD-Core | Password policy — spray lockout threshold |
| ADC-010 | AD-Core | SID filtering disabled on trust |
| ADC-011 | AD-Core | Protected Users group empty |
| ADC-012 | AD-Core | AD Recycle Bin not enabled |
| ADC-013 | AD-Core | DES-only Kerberos |
| ADC-014 | AD-Core | RBCD configured on objects |
| ADC-015 | AD-Core | Constrained delegation with protocol transition |
| ADC-016 | AD-Core | Shadow Credentials (msDS-KeyCredentialLink) |
| ADC-017 | AD-Core | Secrets in AD attributes |
| ADC-018 | AD-Core | gMSA over-broad retrieval rights |
| ADC-019 | AD-Core | AdminSDHolder non-default ACEs (persistence) |
| ADC-020 | AD-Core | LAPS read rights (who can read passwords) |
| ADC-021 | AD-Core | sIDHistory populated — cross-domain SID injection |
| ADC-022 | AD-Core | PASSWD_NOTREQD (blank passwords) |
| ADC-023 | AD-Core | Reversible encryption (plaintext-recoverable) |
| ADC-024 | AD-Core | Weak altSecurityIdentities (ESC14) |
| ADC-025 | AD-Core | Pre-Windows 2000 Compatible Access group — Everyone |
| ADC-026 | AD-Core | Anonymous LDAP bind enabled |
| ADC-027 | AD-Core | Privileged accounts not in Protected Users |
| ADC-028 | AD-Core | DONT_EXPIRE_PASSWORD on privileged accounts |
| ADC-029 | AD-Core | Disabled accounts in privileged groups |
| ADC-030 | AD-Core | Tombstone lifetime short |
| ADC-031 | AD-Core | Forest functional level below 2016 |
| ADC-032 | AD-Core | Fine-grained PSO weak policy |
| ADC-033 | AD-Core | Stale DC objects |
| ADC-034 | AD-Core | LAPS not deployed (schema absent or no enrolled computers) |
| ADC-035 | AD-Core | RC4 Kerberos allowed — Kerberoast/Silver Ticket force multiplier |
| ADC-036 | AD-Core | Guest account enabled |
| ADC-037 | AD-Core | Built-in Administrator not renamed |
| ADC-038 | AD-Core | Schema Admins has permanent members |
| ADC-039 | AD-Core | Entra Connect sync account password stale |
| ADC-040 | AD-Core | AZUREADSSOACC$ static Kerberos key |
| ADC-041 | AD-Core | RODC PRP Tier-0 accounts in reveal list |
| ADC-042 | AD-Core | Exchange Windows Permissions WriteDACL on domain root |
| HOST-001 | Host-OS | Unexpected roles on DC |
| HOST-002 | Host-OS | Service running as domain-privileged account |
| HOST-003 | Host-OS | Unquoted service path |
| HOST-004 | Host-OS | Print Spooler on DC — coercion surface |
| HOST-005 | Host-OS | WebClient/WebDAV on DC — NTLM relay surface |
| HOST-006 | Host-OS | SMBv1 enabled |
| HOST-007 | Host-OS | RDP without NLA |
| HOST-008 | Host-OS | LSASS RunAsPPL not enabled |
| HOST-009 | Host-OS | WDigest credential caching |
| HOST-010 | Host-OS | LAPS not deployed on host |
| HOST-011 | Host-OS | LDAP signing not required |
| HOST-012 | Host-OS | SMB server signing not required |
| HOST-013 | Host-OS | LLMNR/NBT-NS enabled |
| HOST-014 | Host-OS | Local Administrator stale password |
| HOST-015 | Host-OS | Over-broad share ACLs |
| HOST-016 | Host-OS | Scheduled task with privileged identity |
| HOST-017 | Host-OS | DSRM admin logon enabled |
| HOST-018 | Host-OS | EFS service on DC — PetitPotam coercion surface |
| HOST-019 | Host-OS | DFS Namespace on DC — DFSCoerce surface |
| HOST-020 | Host-OS | StrongCertificateBindingEnforcement < 2 |
| HOST-021 | Host-OS | LmCompatibilityLevel < 5 — NTLMv1 accepted |
| HOST-022 | Host-OS | Credential Guard not enabled |
| HOST-023 | Host-OS | PowerShell v2 installed — AMSI/logging bypass |
| HOST-024 | Host-OS | LDAP channel binding not required |
| HOST-025 | Host-OS | WinRM unencrypted |
| HOST-026 | Host-OS | Remote Registry on DC |
| HOST-027 | Host-OS | BitLocker not enabled on DC |
| HOST-028 | Host-OS | IPv6 not disabled on DC — mitm6 surface |
| HOST-029 | Host-OS | SMB client signing not required |
| HOST-030 | Host-OS | Cached domain logons on DC |
| HOST-031 | Host-OS | Netlogon secure channel not required |
| HOST-032 | Host-OS | DC backup absent or stale |
| ADCS-001 | CA-Config | HTTP web enrollment — ESC8 relay prerequisite |
| ADCS-002 | CA-Config | Enrollee SAN + Client Auth + broad enrollment — ESC1 |
| ADCS-003 | CA-Config | Over-broad template enrollment rights |
| ADCS-004 | CA-Config | Enrollment agent EKU — ESC3 |
| ADCS-005 | CA-Config | Any Purpose or no EKU — ESC2 |
| ADCS-006 | CA-Config | No CRL Distribution Point |
| ADCS-007 | CA-Config | No manager approval on broad Client Auth template |
| ADCS-008 | CA-Config | Locksmith/Certipy ESC1–ESC16 findings |
| ADCS-009 | CA-Config | Schema-v1 + enrollee SAN — ESC15 (CVE-2024-49019) |
| ADCS-010 | CA-Config | EDITF_ATTRIBUTESUBJECTALTNAME2 — ESC6 |
| ADCS-011 | CA-Config | HTTP enrollment without EPA — ESC8 relay |
| ADCS-012 | CA-Config | Non-default CA in NTAuthCertificates |
| ADCS-013 | CA-Config | DC cert enrollment gap |
| GPO-001 | GPO-Settings | cpassword in SYSVOL — MS14-025 |
| GPO-002 | GPO-Settings | No screensaver lock policy |
| GPO-003 | GPO-Settings | WDigest not disabled via GPO |
| GPO-004 | GPO-Settings | LLMNR not disabled via GPO |
| GPO-005 | GPO-Settings | NBT-NS not disabled via GPO |
| GPO-006 | GPO-Settings | RunAsPPL not enforced via GPO |
| GPO-007 | GPO-Settings | SMBv1 not disabled via GPO |
| GPO-008 | GPO-Settings | Print Spooler not disabled on DCs via GPO |
| GPO-009 | GPO-Settings | Advanced audit policy not configured |
| GPO-010 | GPO-Settings | Group3r sensitive data in GPO settings |
| GPO-011 | GPO-Settings | No AppLocker/WDAC on DC OU |
| GPO-012 | GPO-Settings | No Restricted Groups policy for Domain Admins |
| GPO-013 | GPO-Settings | Non-Tier-0 write rights on DC-linked GPO |
| GPO-014 | GPO-Settings | No deny-logon user rights on DC OU GPO |
| GPO-015 | GPO-Settings | Orphaned GPOs |
| DNS-001 | DNS | Non-secure dynamic updates — ADIDNS spoofing |
| DNS-002 | DNS | Wildcard DNS record |
| DNS-003 | DNS | WPAD / ISATAP record present |
| DNS-004 | DNS | DNS record created in last 24h |
| DNS-005 | DNS | DNS record with no matching computer account |
| DNS-006 | DNS | DnsAdmins group has members |
| DNS-007 | DNS | Non-Tier-0 ADIDNS write rights |
| DNS-008 | DNS | Zone transfer open to any IP |
| DNS-009 | DNS | External DNS forwarders |
| DNS-010 | DNS | DNS scavenging not enabled |
| AUD-001 | Audit-Policy | DS Changes not audited (4136) |
| AUD-002 | Audit-Policy | DS Access not audited (4662) — DCSync blind |
| AUD-003 | Audit-Policy | Process creation not audited (4688) |
| AUD-004 | Audit-Policy | Command-line in 4688 not captured |
| AUD-005 | Audit-Policy | Security group management not audited |
| AUD-006 | Audit-Policy | User account management not audited |
| AUD-007 | Audit-Policy | Kerberos logging insufficient |
| AUD-008 | Audit-Policy | Sensitive privilege use not audited |
| AUD-009 | Audit-Policy | Audit policy change not audited (4719) |
| AUD-010 | Audit-Policy | ScriptBlock logging not enabled |
| AUD-011 | Audit-Policy | Security log size below minimum |
| AUD-012 | Audit-Policy | Sysmon not deployed |
| AUD-013 | Audit-Policy | NTDS Field Engineering logging not active |
| AUD-014 | Audit-Policy | WEC subscription not configured |
| AUD-015 | Audit-Policy | NTLM authentication auditing disabled |
| FW-001–006 | Host-Firewall | Firewall posture per DC |
| DHCP-001–003 | DHCP | DHCP scope misconfigurations |
| BP-001–004 | BestPractice-Baseline | CIS/DISA benchmark deviations |
