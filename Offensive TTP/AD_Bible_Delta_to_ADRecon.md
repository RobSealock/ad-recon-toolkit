# AD_Bible → ad-recon Coverage Delta

How each attack path in `AD_Bible.md` maps to the `ad-recon` toolkit, and the
scope additions required to close the gaps. `ad-recon` is **defensive**: "covered"
means it documents/detects the *enabling condition*, not that it executes the
attack.

Status legend: **Covered** (existing collector) · **Planned** (already in SCOPE,
not yet built) · **Partial** (some signal, needs extension) · **GAP** (net-new,
fold into SCOPE).

Collectors: AD-Core, DNS, DHCP, PingCastle, Locksmith2, SharpHound, PurpleKnight,
VulnCheck-Enrich (built) · Host-OS, GPO-Settings, CA-Config, AD-Core-extensions,
BestPractice-Baseline (planned).

---

## Coverage matrix

| Attack path (AD_Bible §) | Enabling condition `ad-recon` should surface | Status | Collector |
|---|---|---|---|
| External SMB/LDAP/RID enum (§1) | Anonymous SMB/LDAP, `dsHeuristics` anon flag | Planned | AD-Core-ext (dsHeuristics) + Host-OS |
| Kerbrute user enum (§1) | n/a (auth-server behavior) | Partial | Logging-baseline (4768) |
| BloodHound paths (§2) | ACL/group/session/delegation graph | Covered | SharpHound |
| LDAP/PowerView recon (§2) | Object/attr exposure | Covered | AD-Core |
| Share discovery / Snaffler (§2) | Share + NTFS ACLs, SYSVOL anomalies | Planned | Host-OS |
| **Secrets in description/info/comment (§2)** | Cleartext creds in user attributes | **GAP** | AD-Core-ext |
| Kerberoasting (§3) | SPN accounts, RC4, adminCount | Covered | AD-Core |
| AS-REP roasting (§3) | `DONT_REQ_PREAUTH` | Covered | AD-Core |
| Password spraying (§3) | Lockout/password policy | Planned | GPO-Settings (policy) |
| LLMNR/NBT-NS/mDNS/WPAD + relay (§3) | LLMNR/NBT/WPAD on, SMB-signing off | Planned | Host-OS + GPO-Settings |
| GPP cpassword (§3) | cpassword in SYSVOL | Planned | GPO-Settings |
| **LAPS read rights (§3)** | Principals with read on `ms-Mcs-AdmPwd`/`msLAPS-Password` | **Partial→GAP** | AD-Core-ext (DACL) ; Host-OS (presence) |
| **gMSA read rights (§3)** | `PrincipalsAllowedToRetrieveManagedPassword` over-broad | **GAP** | AD-Core-ext |
| **Timeroasting (§3)** | Legacy NTP auth exposure | **GAP (niche)** | AD-Core-ext (optional) |
| DPAPI/LSASS secrets (§3/§6) | RunAsPPL, Credential Guard state | Planned | Host-OS |
| **ACL/ACE abuse (§4)** | GenericAll/Write/WriteDACL/WriteOwner/ForceChangePassword to Tier 0 | Covered (paths) | SharpHound ; **add native AdminSDHolder + DCSync-rights** AD-Core-ext |
| **Shadow Credentials (§4)** | Write to `msDS-KeyCredentialLink`; existing values | **GAP** | AD-Core-ext |
| Unconstrained delegation (§4) | `TRUSTED_FOR_DELEGATION` non-DC | Covered | AD-Core |
| Constrained delegation (§4) | `msDS-AllowedToDelegateTo` (+S4U) | Covered | AD-Core |
| RBCD (§4) | `msDS-AllowedToActOnBehalfOf...`; MAQ>0 | Planned | AD-Core-ext |
| AD CS ESC1–16 (§4/§8) | Vulnerable templates/CA/ACLs | Covered | Locksmith2 |
| ESC6/ESC8 CA flags + web enroll (§4/§8) | `EDITF_ATTRIBUTESUBJECTALTNAME2`, web endpoint | Planned | CA-Config |
| NoPAC / MS14-068 (§4) | MAQ>0 + DC patch level | Partial | AD-Core (MAQ) + VulnCheck/Host-OS hotfix |
| Pass-the-Hash (§5) | Local-admin reuse, shared local accounts | Partial | Host-OS (local admins) ; LAPS presence |
| OverPass/PtT, token abuse (§5) | SeImpersonate holders, RC4 allowed | Planned | Host-OS + AD-Core-ext (enc types) |
| **DCSync (§6)** | `DS-Replication-Get-Changes-All` principals | **GAP** | AD-Core-ext |
| NTDS/LSASS dump (§6) | Backup Operators, RunAsPPL/CredGuard | Planned | AD-Core (priv groups) + Host-OS |
| Golden/Silver ticket (§6) | krbtgt age; service-acct key hygiene | Planned | AD-Core-ext (krbtgt age) |
| DCShadow/Skeleton/DSRM (§6) | DSRM logon behavior; rogue-DC drift | Planned/Partial | AD-Core-ext (DSRM) + diff engine (drift) |
| Golden gMSA (§6) | KDS root key exposure | GAP (niche) | AD-Core-ext (optional) |
| Persistence: AdminSDHolder/GPO ACL (§6) | AdminSDHolder DACL; GPO edit rights | **GAP→Planned** | AD-Core-ext (AdminSDHolder) + GPO-Settings (GPO ACLs) |
| Trust enum / SID filtering (§7) | Trust dir/transitivity/quarantine | Covered | AD-Core |
| Child→forest / SID history (§7) | `sIDHistory` populated; intra-forest trust | Planned | AD-Core-ext (sIDHistory) |
| Inter-forest trust ticket / PAM (§7) | Trust keys, shadow principals | Partial | AD-Core (trusts) ; deeper = post-run |
| **ADIDNS wildcard/WPAD + record ACL (§8)** | Who can add DNS records; wildcard/WPAD present | **Partial→GAP** | DNS-ext |
| SCCM / WSUS / Exchange / ADFS / RODC (§8) | Presence of these roles | **GAP (flag only)** | review-required record (out of scope to assess) |
| Coercion: PetitPotam/PrinterBug/DFSCoerce (§4/§9) | EFSRPC/Spooler/DFS reachable; relay protections | Partial | Host-OS (Spooler/WebClient) ; **add EFSRPC/DFS exposure note** |
| ZeroLogon/PrintNightmare/NoPAC (§9) | DC patch level; Spooler running | Partial | VulnCheck-Enrich + Host-OS (hotfix, Spooler) |
| Weak crypto / reversible / pwd-not-req (§3/§5) | `msDS-SupportedEncryptionTypes` RC4, UAC flags | Planned | AD-Core-ext |

---

## Net-new items to fold into SCOPE (prioritized)

These are the **GAP** rows — not yet in SCOPE Section 6. All are read-only LDAP or
host reads; all fit the existing collector contract.

**P1 — high value, low effort (add to AD-Core extensions, SCOPE §6):**

1. **DCSync rights.** Enumerate principals (non-DC) holding
   `DS-Replication-Get-Changes` / `-Get-Changes-All` / `-Get-Changes-In-Filtered-Set`
   on the domain head. Finding `DCSyncRights`, Tier 0, ATT&CK T1003.006.
2. **Shadow Credentials.** Enumerate objects with a populated
   `msDS-KeyCredentialLink`, and principals with write rights to it. Finding
   `ShadowCredential` / `KeyCredentialWrite`, Tier 0, T1556.
3. **AdminSDHolder DACL.** Snapshot the `CN=AdminSDHolder,CN=System` ACL; flag
   non-default ACEs (SDProp persistence). Diffs across runs reveal backdoors.
4. **Secrets in attributes.** Scan `description`/`info`/`comment` (users and
   computers) for password-like strings. Finding `SecretInAttribute`, T1552.
5. **gMSA retrieval rights.** List gMSA accounts and the principals in
   `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`;
   flag over-broad grants.

**P2 — high value, moderate effort:**

6. **LAPS read-rights enumeration** (DACL on `ms-Mcs-AdmPwd` / `msLAPS-Password`,
   and `msLAPS-EncryptedPassword`): who can read local-admin passwords. Pairs with
   Host-OS LAPS-presence detection. (AD-Core-ext / GPO-Settings.)
7. **ADIDNS extension** (DNS collector): detect wildcard and `wpad`/`isatap`
   records, and read the zone/`MicrosoftDNS` object DACL (who can create records).
   Finding `ADIDNS-RecordWrite` / `ADIDNS-Wildcard`.
8. **Coercion exposure indicators** (Host-OS, document-only): EFSRPC (MS-EFSRPC),
   DFS Namespace, and Spooler/WebClient reachability as relay/coercion surface.
   Emit as exposure records, never triggered.

**P3 — completeness / niche (optional):**

9. **Timeroasting exposure** and **pre-created computer accounts**
   (`UserAccountControl` PASSWD_NOTREQD on computer objects).
10. **Golden gMSA / KDS root key** read-access exposure.

**Already covered by existing SCOPE planned work (no new scope needed):** RBCD,
`sIDHistory`, krbtgt age, DSRM, Protected Users, privileged-group hygiene,
encryption-type/UAC hygiene, GPP cpassword, GPO edit-rights/ACLs,
LLMNR/NBT-NS/WPAD/signing host flags, RunAsPPL/Credential Guard, share/NTFS ACLs,
DC patch level, ADCS ESC1–16, ESC6/8 CA config, trusts/SID-filtering.

**Explicitly out of scope (emit as review-required records, not assessed):**
SCCM/MECM, WSUS, on-prem Exchange, ADFS, RODC internals, and all active exploit
validation (handled post-run via non-destructive MITRE/Atomic validation cards).

---

## Suggested SCOPE edits

- **Section 6 collector table:** add the P1/P2 items as `AD-Core` extensions, one
  `DNS` extension (ADIDNS), and Host-OS coercion-exposure flags.
- **Section 5 catalog:** add "Shadow Credentials", "DCSync rights",
  "AdminSDHolder persistence", "Secrets-in-attributes", "gMSA/LAPS read rights",
  and "ADIDNS record-write" as named documentation targets.
- **Section 9.4 review-required:** add SCCM/WSUS/Exchange/ADFS/RODC *presence
  detection* (flag-only) so the post-run pass knows to assess them.
- **Validation cards (Section 10):** the `finding-attack-atomic.psd1` mapping
  should now also cover ShadowCredential→T1556, DCSyncRights→T1003.006,
  RBCD→T1098, ADIDNS→T1557, gMSA/LAPS read→T1555/T1003 (non-destructive Atomic
  tests only, each with a rollback field).
