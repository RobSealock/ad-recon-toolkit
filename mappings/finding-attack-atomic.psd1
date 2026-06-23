# Finding ID → MITRE ATT&CK technique(s) → Atomic Red Team test reference.
# Used by New-ValidationCards.ps1 to generate non-destructive validation cards.
#
# All Atomic test references must be non-destructive variants only.
# Rollback field is required for every entry ("read-only — no rollback needed" where applicable).

@{

    # ── AD-Core domain findings ────────────────────────────────────────────

    'ADC-001' = @{
        Techniques     = @('T1136.002')
        TechniqueNames = @('Create Account: Domain Account')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read ms-DS-MachineAccountQuota via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4741)
        BlastRadius    = 'LDAP read — no machine joined'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-002' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read msDS-Behavior-Version from domain NC via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP attribute read'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-003' = @{
        Techniques     = @('T1558.001')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Golden Ticket')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read krbtgt pwdLastSet via LDAP to confirm password age (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — no ticket forged'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-004' = @{
        Techniques     = @('T1558.004')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: AS-REP Roasting')
        AtomicTests    = @(
            @{
                Guid        = 'cf8d7d7e-8f1e-4c7a-9e8d-6d3e7a8b1c3e'
                Name        = 'Get-NPUsers (Impacket) or Get-ASREPHash (PowerView) — enumerate and collect AS-REP hashes'
                Destructive = $false
                Rollback    = 'AS-REQ packets to KDC — no account state change, no rollback needed'
            }
        )
        ConfirmationEvents = @(4768)
        BlastRadius    = 'AS-REQ/AS-REP exchange — unauthenticated, targeted at flagged accounts only'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-005' = @{
        Techniques     = @('T1558.003')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Kerberoasting')
        AtomicTests    = @(
            @{
                Guid        = '3f987809-3681-43c8-bcd8-b3ff3a28533a'
                Name        = 'Request TGS for flagged SPN accounts via PowerShell (per-SPN, not bulk)'
                Destructive = $false
                Rollback    = 'TGS-REQ — read-only Kerberos exchange, no rollback needed'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius    = 'TGS-REQ for flagged service accounts — authenticated'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-006' = @{
        Techniques     = @('T1558')
        TechniqueNames = @('Steal or Forge Kerberos Tickets')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate unconstrained delegation computers via LDAP filter (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — no coercion performed'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-007' = @{
        Techniques     = @('T1003.006')
        TechniqueNames = @('OS Credential Dumping: DCSync')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read domain NC DACL for Replicating Directory Changes All right (read-only ACL enumeration)'
                Destructive = $false
                Rollback    = 'ACL read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4662)
        BlastRadius    = 'ACL enumeration — no replication initiated'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-008' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate accounts with adminCount=1 not in current privileged groups via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read only'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-009' = @{
        Techniques     = @('T1110.001')
        TechniqueNames = @('Brute Force: Password Guessing')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read minPwdLength from domain NC via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP attribute read'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-010' = @{
        Techniques     = @('T1134.005')
        TechniqueNames = @('Access Token Manipulation: SID-History Injection')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read trustAttributes for each trust via LDAP — confirm QUARANTINED_DOMAIN bit (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius    = 'LDAP read — no SID injected'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-011' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate Protected Users group membership via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP group read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read only'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-012' = @{
        Techniques     = @('T1485')
        TechniqueNames = @('Data Destruction')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm enabledScopes on Recycle Bin feature container via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — no deletion'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-013' = @{
        Techniques     = @('T1558.003')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Kerberoasting')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate userAccountControl bit USE_DES_KEY_ONLY via LDAP filter (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius    = 'LDAP filter — no ticket requested'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-014' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate msDS-AllowedToActOnBehalfOfOtherIdentity via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — no RBCD configured'
        MinPriv        = 'AnyAuthUser'
    }

    # ── Kerberos attacks ───────────────────────────────────────────────────

    'KERBEROAST' = @{
        Techniques   = @('T1558.003')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Kerberoasting')
        AtomicTests  = @(
            @{
                Guid        = '3f987809-3681-43c8-bcd8-b3ff3a28533a'
                Name        = 'Request a single ticket via PowerShell'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius = 'Read-only LDAP + Kerberos AS_REQ/TGS_REQ only'
        MinPriv     = 'AnyAuthUser'
    }

    'ADC-ASREPROAST' = @{
        Techniques   = @('T1558.004')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: AS-REP Roasting')
        AtomicTests  = @(
            @{
                Guid        = 'cf8d7d7e-8f1e-4c7a-9e8d-6d3e7a8b1c3e'
                Name        = 'Get-NPUsers — enumerate no-preauth accounts'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(4768)
        BlastRadius = 'LDAP query only'
        MinPriv     = 'AnyAuthUser'
    }

    'ADC-UNCONSTRAINED-DELEGATION' = @{
        Techniques   = @('T1558','T1550')
        TechniqueNames = @('Steal or Forge Kerberos Tickets','Use Alternate Authentication Material')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Identify computers with unconstrained delegation via LDAP'
                Destructive = $false
                Rollback    = 'Read-only LDAP query — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'LDAP read only'
        MinPriv     = 'AnyAuthUser'
    }

    'ADC-RBCD' = @{
        Techniques   = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate msDS-AllowedToActOnBehalfOfOtherIdentity via LDAP'
                Destructive = $false
                Rollback    = 'Read-only LDAP query — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'LDAP read only'
        MinPriv     = 'AnyAuthUser'
    }

    'DCSYNC-RIGHTS' = @{
        Techniques   = @('T1003.006')
        TechniqueNames = @('OS Credential Dumping: DCSync')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate accounts with Replicating Directory Changes All rights via LDAP ACL read'
                Destructive = $false
                Rollback    = 'Read-only ACL enumeration — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'Read-only LDAP ACL check'
        MinPriv     = 'AnyAuthUser'
    }

    'ADCS-ESC1' = @{
        Techniques   = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'certipy find -vulnerable — enumerate ESC1 templates (read-only)'
                Destructive = $false
                Rollback    = 'Read-only LDAP and CA enumeration — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'Certipy find — enumeration only, no certificate requested'
        MinPriv     = 'AnyAuthUser'
    }

    'ADCS-ESC8' = @{
        Techniques   = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm HTTP enrollment endpoint reachable (curl HEAD — no authentication)'
                Destructive = $false
                Rollback    = 'Read-only HTTP probe — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'HTTP HEAD request to enrollment endpoint only'
        MinPriv     = 'AnyAuthUser'
    }

    'GPP-CPASSWORD' = @{
        Techniques   = @('T1552.006')
        TechniqueNames = @('Unsecured Credentials: Group Policy Preferences')
        AtomicTests  = @(
            @{
                Guid        = 'e9a4bc37-4f01-4695-93e9-f5e9405abca8'
                Name        = 'Search SYSVOL for cpassword strings (read-only file find)'
                Destructive = $false
                Rollback    = 'Read-only filesystem traversal — no rollback needed'
            }
        )
        ConfirmationEvents = @(5140)
        BlastRadius = 'SYSVOL read — authentication required'
        MinPriv     = 'AnyAuthUser'
    }

    'LLMNR-NBTNS' = @{
        Techniques   = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm LLMNR/NBT-NS registry key state on DCs (read-only)'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'Registry read on DC'
        MinPriv     = 'LocalAdmin'
    }

    'COERCION-PETITPOTAM' = @{
        Techniques   = @('T1187')
        TechniqueNames = @('Forced Authentication')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm EFS RPC endpoint reachable via rpcdump (passive probe)'
                Destructive = $false
                Rollback    = 'rpcdump endpoint enumeration — no coercion performed, no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'RPC endpoint enumeration only — does not trigger authentication'
        MinPriv     = 'AnyAuthUser'
    }

    'SILVER-TICKET' = @{
        Techniques   = @('T1558.002')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Silver Ticket')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate service accounts with SPNs and weak crypto (read-only LDAP)'
                Destructive = $false
                Rollback    = 'LDAP read only — no rollback needed'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius = 'LDAP query for SPN-bearing accounts'
        MinPriv     = 'AnyAuthUser'
    }

    'PRINT-SPOOLER-ON-DC' = @{
        Techniques   = @('T1187','T1068')
        TechniqueNames = @('Forced Authentication','Exploitation for Privilege Escalation')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm Print Spooler service state on DC (sc query spooler — read-only)'
                Destructive = $false
                Rollback    = 'Service state read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'Service query — read-only, no exploitation'
        MinPriv     = 'AnyAuthUser'
    }

    'DNS-ADMINS-DLL' = @{
        Techniques   = @('T1543.003')
        TechniqueNames = @('Create or Modify System Process: Windows Service')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm DnsAdmins group membership via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'LDAP group membership query only'
        MinPriv     = 'AnyAuthUser'
    }

    'LAPS-READ' = @{
        Techniques   = @('T1555','T1552')
        TechniqueNames = @('Credentials from Password Stores','Unsecured Credentials')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm which accounts can read ms-Mcs-AdmPwd via LDAP ACL read (read-only)'
                Destructive = $false
                Rollback    = 'ACL enumeration — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius = 'LDAP ACL check — does not read passwords'
        MinPriv     = 'AnyAuthUser'
    }

    'TIMEROASTING' = @{
        Techniques   = @('T1558')
        TechniqueNames = @('Steal or Forge Kerberos Tickets')
        AtomicTests  = @(
            @{
                Guid        = 'N/A'
                Name        = 'nxc smb timeroast — unauthenticated Kerberos AS-REQ timing probe'
                Destructive = $false
                Rollback    = 'Unauthenticated AS-REQ — no rollback needed'
            }
        )
        ConfirmationEvents = @(4768)
        BlastRadius = 'Unauthenticated AS-REQ packets to DC'
        MinPriv     = 'AnyAuthUser'
    }

    # ── DNS findings ──────────────────────────────────────────────────────────

    'DNS-001' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm zone dynamic update policy via Get-DnsServerZone (read-only)'
                Destructive = $false
                Rollback    = 'Read-only DNS zone query — no rollback needed'
            }
        )
        ConfirmationEvents = @(770)
        BlastRadius    = 'DNS query only'
        MinPriv        = 'DNSAdmin'
    }

    'DNS-002' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm wildcard record via Resolve-DnsName * in zone (read-only)'
                Destructive = $false
                Rollback    = 'DNS query — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'DNS resolution query only'
        MinPriv        = 'AnyAuthUser'
    }

    'DNS-004' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Review AD DNS object whenCreated attributes — confirm each new record is authorised'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @(770,771)
        BlastRadius    = 'LDAP read only'
        MinPriv        = 'AnyAuthUser'
    }

    'DNS-005' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Cross-reference DNS A records against AD computer objects — identify stale/rogue entries (LDAP read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read only'
        MinPriv        = 'AnyAuthUser'
    }

    'DNS-006' = @{
        Techniques     = @('T1543.003')
        TechniqueNames = @('Create or Modify System Process: Windows Service')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate DnsAdmins group membership via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP group query only'
        MinPriv        = 'AnyAuthUser'
    }

    'DNS-007' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read DACL of CN=MicrosoftDNS via ADSI ObjectSecurity — passive DACL snapshot (read-only)'
                Destructive = $false
                Rollback    = 'LDAP nTSecurityDescriptor read — no DNS record created or ACE modified'
            }
        )
        ConfirmationEvents = @(5136,5137)
        BlastRadius    = 'Read-only DACL walk of MicrosoftDNS container and zone objects — no records created'
        MinPriv        = 'AnyAuthUser'
    }

    # ── Firewall findings ──────────────────────────────────────────────────────

    'FW-001' = @{
        Techniques     = @('T1562.004')
        TechniqueNames = @('Impair Defenses: Disable or Modify System Firewall')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-NetFirewallProfile — confirm profile state (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(2003,2004)
        BlastRadius    = 'Registry/WMI read — no change'
        MinPriv        = 'AnyAuthUser'
    }

    'FW-002' = @{
        Techniques     = @('T1562.004')
        TechniqueNames = @('Impair Defenses: Disable or Modify System Firewall')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-NetFirewallProfile DefaultInboundAction — confirm allow-all default (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(2003)
        BlastRadius    = 'Read-only'
        MinPriv        = 'AnyAuthUser'
    }

    'FW-004' = @{
        Techniques     = @('T1562.004')
        TechniqueNames = @('Impair Defenses: Disable or Modify System Firewall')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Test-NetConnection to sensitive port from authorised source — confirm reachability (non-destructive probe)'
                Destructive = $false
                Rollback    = 'TCP SYN probe — no rollback needed'
            }
        )
        ConfirmationEvents = @(5156,5157)
        BlastRadius    = 'Single TCP connection attempt'
        MinPriv        = 'AnyAuthUser'
    }

    'PC-001' = @{
        Techniques   = @()
        TechniqueNames = @()
        AtomicTests  = @()
        ConfirmationEvents = @()
        BlastRadius = 'Review PingCastle report for individual finding details'
        MinPriv     = 'AnyAuthUser'
        Note        = 'PingCastle aggregate score — see raw artifact for per-rule findings'
    }

    # ── Host-OS findings ───────────────────────────────────────────────────────

    'HOST-001' = @{
        Techniques     = @('T1072')
        TechniqueNames = @('Software Deployment Tools')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-WindowsFeature — confirm installed roles on DC (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'WinRM read — no state change'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-002' = @{
        Techniques     = @('T1543.003')
        TechniqueNames = @('Create or Modify System Process: Windows Service')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-CimInstance Win32_Service — enumerate service accounts (read-only)'
                Destructive = $false
                Rollback    = 'WMI read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'WMI read-only'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-003' = @{
        Techniques     = @('T1574.009')
        TechniqueNames = @('Hijack Execution Flow: Path Interception by Unquoted Path')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Review Get-CimInstance Win32_Service PathName for unquoted spaces (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'WMI read-only'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-004' = @{
        Techniques     = @('T1187','T1068')
        TechniqueNames = @('Forced Authentication','Exploitation for Privilege Escalation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-Service Spooler — confirm running state on DC (read-only)'
                Destructive = $false
                Rollback    = 'Service state query — no rollback needed'
            }
        )
        ConfirmationEvents = @(7036)
        BlastRadius    = 'Service query — read-only, no coercion performed'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-005' = @{
        Techniques     = @('T1187')
        TechniqueNames = @('Forced Authentication')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-Service WebClient — confirm running state (read-only)'
                Destructive = $false
                Rollback    = 'Service state query — no rollback needed'
            }
        )
        ConfirmationEvents = @(7036)
        BlastRadius    = 'Service query — read-only'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-006' = @{
        Techniques     = @('T1210')
        TechniqueNames = @('Exploitation of Remote Services')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm SMBv1 registry key (HKLM\...\LanmanServer\Parameters SMB1) — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @(3000)
        BlastRadius    = 'Registry read — no state change'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-007' = @{
        Techniques     = @('T1021.001')
        TechniqueNames = @('Remote Services: Remote Desktop Protocol')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm RDP NLA registry value (UserAuthenticationRequired) — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4624)
        BlastRadius    = 'Registry read — no connection attempted'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-008' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm RunAsPPL registry value — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry read — no state change'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-009' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = '758c36b8-8c38-4c82-8e48-f6c8b5c1d1c4'
                Name        = 'Enable WDigest via registry — USE IN LAB ONLY; confirms plaintext cred exposure'
                Destructive = $false
                Rollback    = 'Set UseLogonCredential=0 and lock workstation to flush cache'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry read — no credential dump performed in validation'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-010' = @{
        Techniques     = @('T1078.003')
        TechniqueNames = @('Valid Accounts: Local Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm LAPS registry keys absent — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry read — no state change'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-011' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm LDAPServerIntegrity registry value on DC — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @(2889)
        BlastRadius    = 'Registry read — no relay performed'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-012' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm RequireSecuritySignature registry value — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4625)
        BlastRadius    = 'Registry read — no relay performed'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-013' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm LLMNR EnableMulticast and NBT-NS TcpipNetbiosOptions registry values — read-only'
                Destructive = $false
                Rollback    = 'Registry/WMI read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry/WMI read — no packets sent'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-014' = @{
        Techniques     = @('T1078.003')
        TechniqueNames = @('Valid Accounts: Local Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-LocalUser Administrator — confirm enabled state and PasswordLastSet (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(4625)
        BlastRadius    = 'Local account query — no login attempted'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-015' = @{
        Techniques     = @('T1039')
        TechniqueNames = @('Data from Network Shared Drive')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-SmbShareAccess — enumerate share ACLs (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(5140)
        BlastRadius    = 'SMB share enumeration — no file access'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-016' = @{
        Techniques     = @('T1053.005')
        TechniqueNames = @('Scheduled Task/Job: Scheduled Task')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-ScheduledTask — enumerate non-Microsoft tasks and their run-as identities (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no rollback needed'
            }
        )
        ConfirmationEvents = @(4698,4702)
        BlastRadius    = 'Task enumeration — no task triggered'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-017' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read DsrmAdminLogonBehavior: Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified; safe value is 0 (absent or explicitly set)'
            }
        )
        ConfirmationEvents = @(4624)
        BlastRadius    = 'Registry read — value 2 enables network DSRM login; confirm value is 0 before incident'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-018' = @{
        Techniques     = @('T1187')
        TechniqueNames = @('Forced Authentication')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check EFS service state: Get-Service EFS — confirm Running status (read-only)'
                Destructive = $false
                Rollback    = 'Service query — no RPC call made; PetitPotam PoC would trigger outbound NTLM — not run'
            }
        )
        ConfirmationEvents = @(4648)
        BlastRadius    = 'Service state query — confirm EFS necessity before disabling on DC'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-019' = @{
        Techniques     = @('T1187')
        TechniqueNames = @('Forced Authentication')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check DFS Namespace service: Get-Service Dfs — confirm Running status (read-only)'
                Destructive = $false
                Rollback    = 'Service query — no DFSCoerce RPC call made; DFSCoerce PoC would trigger outbound auth — not run'
            }
        )
        ConfirmationEvents = @(4648)
        BlastRadius    = 'Service state query — confirm DFS namespace usage before disabling'
        MinPriv        = 'LocalAdmin'
    }

    # ── GPO-Settings findings ──────────────────────────────────────────────────

    'GPO-001' = @{
        Techniques     = @('T1552.006')
        TechniqueNames = @('Unsecured Credentials: Group Policy Preferences')
        AtomicTests    = @(
            @{
                Guid        = 'e9a4bc37-4f01-4695-93e9-f5e9405abca8'
                Name        = 'Search SYSVOL for cpassword strings — Get-ChildItem + Select-String (read-only file scan)'
                Destructive = $false
                Rollback    = 'Read-only filesystem traversal — no rollback needed'
            }
        )
        ConfirmationEvents = @(5140)
        BlastRadius    = 'SYSVOL read — no credential decryption performed'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-002' = @{
        Techniques     = @('T1078')
        TechniqueNames = @('Valid Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-GPOReport — confirm ScreenSaverIsSecure setting absent in all GPOs (read-only)'
                Destructive = $false
                Rollback    = 'Read-only GPO query — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'GPO XML enumeration only'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-003' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm UseLogonCredential not set to 0 in any GPO via Get-GPOReport (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'GPO enumeration — no state change'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-004' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm EnableMulticast not set to 0 in any GPO — Get-GPOReport scan (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'GPO enumeration — no packets sent'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-005' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm NBT-NS TcpipNetbiosOptions via Get-CimInstance Win32_NetworkAdapterConfiguration — per host (read-only)'
                Destructive = $false
                Rollback    = 'WMI read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'WMI read only — no packets sent'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-006' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm RunAsPPL not enforced in any GPO via Get-GPOReport (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'GPO enumeration — no state change'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-007' = @{
        Techniques     = @('T1210')
        TechniqueNames = @('Exploitation of Remote Services')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm SMB1=0 not set in any GPO via Get-GPOReport (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no rollback needed'
            }
        )
        ConfirmationEvents = @(3000)
        BlastRadius    = 'GPO enumeration — no exploitation'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-008' = @{
        Techniques     = @('T1187')
        TechniqueNames = @('Forced Authentication')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm Spooler not set to Disabled in any DC-scoped GPO — Get-GPOReport (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no rollback needed'
            }
        )
        ConfirmationEvents = @(7036)
        BlastRadius    = 'GPO enumeration — no service change'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-009' = @{
        Techniques     = @('T1562.002')
        TechniqueNames = @('Impair Defenses: Disable Windows Event Logging')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm Advanced Audit Policy Configuration absent from all GPOs — Get-GPOReport (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4719)
        BlastRadius    = 'GPO enumeration — no state change'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-010' = @{
        Techniques     = @('T1484.001')
        TechniqueNames = @('Domain Policy Modification: Group Policy Modification')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Group3r analysis — read-only GPO and SYSVOL scan; review artifact for findings'
                Destructive = $false
                Rollback    = 'Read-only GPO/SYSVOL traversal — no rollback needed'
            }
        )
        ConfirmationEvents = @(5136)
        BlastRadius    = 'Read-only GPO analysis via Group3r'
        MinPriv        = 'AnyAuthUser'
    }

    # ── CA-Config / AD CS findings ────────────────────────────────────────────

    'ADCS-001' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm HTTP enrollment URL responds — curl/Invoke-WebRequest HEAD (no auth, no certificate requested)'
                Destructive = $false
                Rollback    = 'HTTP HEAD request only — no certificate issued, no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Single HTTP HEAD request — no relay, no exploitation'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-002' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'certipy find -vulnerable — enumerate ESC1 templates (read-only LDAP and CA enumeration)'
                Destructive = $false
                Rollback    = 'Enumeration only — no certificate requested, no rollback needed'
            }
        )
        ConfirmationEvents = @(4886,4887)
        BlastRadius    = 'LDAP read + CA connection — no certificate issued'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-003' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'certipy find — enumerate templates with broad enrollment rights (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read only — no rollback needed'
            }
        )
        ConfirmationEvents = @(4886)
        BlastRadius    = 'LDAP enumeration — no certificate issued'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-004' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'certipy find — identify Enrollment Agent templates (ESC3) — read-only'
                Destructive = $false
                Rollback    = 'LDAP/CA enumeration — no certificate issued, no rollback needed'
            }
        )
        ConfirmationEvents = @(4886,4887)
        BlastRadius    = 'Read-only enumeration'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-005' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'certipy find — enumerate Any Purpose / no-EKU templates (ESC2) — read-only'
                Destructive = $false
                Rollback    = 'LDAP enumeration — no certificate issued, no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Read-only LDAP enumeration'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-006' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm CRL Distribution Point URLs reachable — curl/Invoke-WebRequest (passive probe)'
                Destructive = $false
                Rollback    = 'HTTP GET to CRL endpoint — read-only, no rollback needed'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'HTTP request to CRL endpoint only'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-007' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Confirm CT_FLAG_PEND_ALL_REQUESTS not set via LDAP msPKI-Enrollment-Flag read (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no rollback needed'
            }
        )
        ConfirmationEvents = @(4886)
        BlastRadius    = 'LDAP read — no certificate requested'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-008' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Invoke-Locksmith -Mode 1 — read-only AD CS vulnerability enumeration (no changes made)'
                Destructive = $false
                Rollback    = 'Read-only LDAP + CA enumeration — no rollback needed'
            }
        )
        ConfirmationEvents = @(4886,4887)
        BlastRadius    = 'Locksmith Mode 1 — enumerate only, no fixes applied'
        MinPriv        = 'AnyAuthUser'
    }

    # ── AD-Core Sprint 1 extensions ──────────────────────────────────────────

    'ADC-015' = @{
        Techniques     = @('T1134.001')
        TechniqueNames = @('Access Token Manipulation: Token Impersonation/Theft')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate msDS-AllowedToDelegateTo via LDAP — read-only constrained delegation audit'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no changes made'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius    = 'Read-only LDAP enumeration'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-016' = @{
        Techniques     = @('T1556')
        TechniqueNames = @('Modify Authentication Process')
        AtomicTests    = @(
            @{
                Guid        = '3a159042-69e6-4398-8c06-5a7b8f8e0c9d'
                Name        = 'Whisker — list shadow credentials for target (read-only enumeration, no addition)'
                Destructive = $false
                Rollback    = 'Whisker /list mode enumerates msDS-KeyCredentialLink — no credentials added'
            }
        )
        ConfirmationEvents = @(5136,4662)
        BlastRadius    = 'LDAP read of msDS-KeyCredentialLink — no credential modification'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-017' = @{
        Techniques     = @('T1552.004')
        TechniqueNames = @('Unsecured Credentials: Private Keys')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'LDAP filter search for description/info/comment containing password-like strings — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute enumeration — no changes to AD'
            }
        )
        ConfirmationEvents = @(4662)
        BlastRadius    = 'LDAP read of user/computer description attributes — no changes'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-018' = @{
        Techniques     = @('T1003')
        TechniqueNames = @('OS Credential Dumping')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate msDS-GroupMSAMembership on gMSA objects via LDAP — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no managed password retrieved'
            }
        )
        ConfirmationEvents = @(4662)
        BlastRadius    = 'LDAP enumeration of gMSA principals — no password material read'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-019' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read AdminSDHolder DACL via ADSI ObjectSecurity — passive ACL snapshot'
                Destructive = $false
                Rollback    = 'LDAP nTSecurityDescriptor read — no ACE added or modified'
            }
        )
        ConfirmationEvents = @(4662,5136)
        BlastRadius    = 'LDAP DACL read of CN=AdminSDHolder — no changes to ACL'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-020' = @{
        Techniques     = @('T1555')
        TechniqueNames = @('Credentials from Password Stores')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate OU and domain DACLs for inheritable ReadProperty on ms-Mcs-AdmPwd — LDAP read'
                Destructive = $false
                Rollback    = 'LDAP DACL walk — no LAPS password read, no changes'
            }
        )
        ConfirmationEvents = @(4662)
        BlastRadius    = 'Read-only DACL enumeration on domain/OU objects — LAPS passwords not read'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-021' = @{
        Techniques     = @('T1134.005')
        TechniqueNames = @('Access Token Manipulation: SID-History Injection')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate accounts with sIDHistory via LDAP filter (sIDHistory=*) — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no SID modification'
            }
        )
        ConfirmationEvents = @(4765,4766)
        BlastRadius    = 'LDAP enumeration — no changes to sIDHistory'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-022' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate PASSWD_NOTREQD accounts via LDAP userAccountControl filter — read-only'
                Destructive = $false
                Rollback    = 'LDAP filter enumeration — no password or UAC change'
            }
        )
        ConfirmationEvents = @(4723,4624)
        BlastRadius    = 'LDAP read — no account modification'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-023' = @{
        Techniques     = @('T1555.003')
        TechniqueNames = @('Credentials from Password Stores: Credentials from Web Browsers')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate ENCRYPTED_TEXT_PASSWORD_ALLOWED accounts via LDAP UAC filter — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no password or UAC modification'
            }
        )
        ConfirmationEvents = @(4738)
        BlastRadius    = 'LDAP enumeration — no credentials extracted'
        MinPriv        = 'AnyAuthUser'
    }

    # ── Audit Policy findings ────────────────────────────────────────────────

    'AUD-001' = @{
        Techniques     = @('T1562.002')
        TechniqueNames = @('Impair Defenses: Disable Windows Event Logging')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Verify 5136 (Directory Service Changes) fires on test OU rename — read: auditpol /get /subcategory:"Directory Service Changes"'
                Destructive = $false
                Rollback    = 'Read-only auditpol query — no policy change'
            }
        )
        ConfirmationEvents = @(5136,5137,5138)
        BlastRadius    = 'Audit policy read — no event log or policy modification'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-002' = @{
        Techniques     = @('T1003.006')
        TechniqueNames = @('OS Credential Dumping: DCSync')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Verify 4662 fires via auditpol /get /subcategory:"Directory Service Access" — read-only'
                Destructive = $false
                Rollback    = 'Read-only auditpol query — no policy change'
            }
        )
        ConfirmationEvents = @(4662)
        BlastRadius    = 'Audit policy read — confirm SACL also required on domain NC head object'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-003' = @{
        Techniques     = @('T1059')
        TechniqueNames = @('Command and Scripting Interpreter')
        AtomicTests    = @(
            @{
                Guid        = '4f5e19a5-4c38-4bc0-9dce-a65c1d25e5fd'
                Name        = 'Audit process creation — read: auditpol /get /subcategory:"Process Creation" (non-destructive query)'
                Destructive = $false
                Rollback    = 'Read-only — no process spawned, no policy modified'
            }
        )
        ConfirmationEvents = @(4688)
        BlastRadius    = 'Audit policy read only — confirm EDR provides compensating control before enabling'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-004' = @{
        Techniques     = @('T1059')
        TechniqueNames = @('Command and Scripting Interpreter')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check ProcessCreationIncludeCmdLine_Enabled registry key: Get-ItemProperty HKLM:\...\Policies\System\Audit'
                Destructive = $false
                Rollback    = 'Registry read — no value modified'
            }
        )
        ConfirmationEvents = @(4688)
        BlastRadius    = 'Registry read — command-line included in 4688 when both subcategory and this key are enabled'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-005' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Verify 4728/4732/4756 fire: auditpol /get /subcategory:"Security Group Management" — read-only'
                Destructive = $false
                Rollback    = 'Audit policy read — no group membership change'
            }
        )
        ConfirmationEvents = @(4728,4732,4756)
        BlastRadius    = 'Read-only audit policy query'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-006' = @{
        Techniques     = @('T1136.001')
        TechniqueNames = @('Create Account: Local Account')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Verify 4720/4738 fire: auditpol /get /subcategory:"User Account Management" — read-only'
                Destructive = $false
                Rollback    = 'Audit policy read — no account created or modified'
            }
        )
        ConfirmationEvents = @(4720,4722,4726,4738)
        BlastRadius    = 'Read-only audit policy query'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-007' = @{
        Techniques     = @('T1558')
        TechniqueNames = @('Steal or Forge Kerberos Tickets')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Verify Kerberos events: auditpol /get /subcategory:"Kerberos Authentication Service","Kerberos Service Ticket Operations" — read-only'
                Destructive = $false
                Rollback    = 'Audit policy read — no Kerberos request made'
            }
        )
        ConfirmationEvents = @(4768,4769,4771)
        BlastRadius    = 'Read-only audit policy query — 4768/4771 required for AS-REP/brute-force detection; 4769 for Kerberoast detection'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-008' = @{
        Techniques     = @('T1134')
        TechniqueNames = @('Access Token Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check: auditpol /get /subcategory:"Sensitive Privilege Use" — read-only query'
                Destructive = $false
                Rollback    = 'Read-only — no privilege exercised'
            }
        )
        ConfirmationEvents = @(4673,4674)
        BlastRadius    = 'Read-only audit policy query'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-009' = @{
        Techniques     = @('T1562.002')
        TechniqueNames = @('Impair Defenses: Disable Windows Event Logging')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check: auditpol /get /subcategory:"Audit Policy Change" — read-only query; 4719 should appear after any auditpol change'
                Destructive = $false
                Rollback    = 'Read-only — no policy modified'
            }
        )
        ConfirmationEvents = @(4719)
        BlastRadius    = 'Read-only audit policy query — 4719 fires on any auditpol /set operation'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-010' = @{
        Techniques     = @('T1059.001')
        TechniqueNames = @('Command and Scripting Interpreter: PowerShell')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check ScriptBlock logging: Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging — read-only'
                Destructive = $false
                Rollback    = 'Registry read — confirms Event 4104 generation in Microsoft-Windows-PowerShell/Operational'
            }
        )
        ConfirmationEvents = @(4103,4104)
        BlastRadius    = 'Registry read — 4104 events contain full script content; ensure log size is adequate before enabling'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-011' = @{
        Techniques     = @('T1562.002')
        TechniqueNames = @('Impair Defenses: Disable Windows Event Logging')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check Security log size: (Get-WinEvent -ListLog Security).MaximumSizeInBytes — read-only'
                Destructive = $false
                Rollback    = 'Read-only — no log configuration modified'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Read-only log metadata query — CIS minimum 196608 KB (192 MB); recommend 524288 KB (512 MB) for high-volume DCs'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-012' = @{
        Techniques     = @('T1562.006')
        TechniqueNames = @('Impair Defenses: Indicator Blocking')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check Sysmon service and config: Get-Service Sysmon64; Get-Item HKLM:\SYSTEM\...\SysmonDrv\Parameters — read-only'
                Destructive = $false
                Rollback    = 'Service and registry read — no Sysmon configuration changed'
            }
        )
        ConfirmationEvents = @(1,2,3,7,8,10,11,12,13,14,15,17,18,22,25,26)
        BlastRadius    = 'Read-only check — confirm config loaded before assuming coverage'
        MinPriv        = 'LocalAdmin'
    }

    'AUD-013' = @{
        Techniques     = @('T1069.002')
        TechniqueNames = @('Permission Groups Discovery: Domain Groups')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check NTDS diagnostics: Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics "15 Field Engineering" — read-only'
                Destructive = $false
                Rollback    = 'Registry read — 1644 events appear in Directory Service log at level 5; tune threshold via "Expensive Search Results Threshold" key'
            }
        )
        ConfirmationEvents = @(1644)
        BlastRadius    = 'Registry read — 1644 logging can be noisy; tune threshold before enabling in production'
        MinPriv        = 'LocalAdmin'
    }

    # ── AD-Core audit-gap sprint (ADC-025 – ADC-033) ───────────────────────────

    'ADC-025' = @{
        Techniques     = @('T1135')
        TechniqueNames = @('Network Share Discovery')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read Pre-Windows 2000 Compatible Access group membership via ADSI — read-only'
                Destructive = $false
                Rollback    = 'LDAP group member read — no membership change. Remove Everyone/Authenticated Users from this group; validate NTLM anonymous access is not required before removal.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — removing broad members may break legacy NT4-compat applications that rely on anonymous enumeration. Test in non-production first.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-026' = @{
        Techniques     = @('T1087.002')
        TechniqueNames = @('Account Discovery: Domain Account')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'ldapsearch / ldp.exe unauthenticated bind — confirm anonymous access to domain objects (read-only probe)'
                Destructive = $false
                Rollback    = 'Unauthenticated LDAP bind — no changes. Remediation: set dsHeuristics position 7 to 0 in CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...'
            }
        )
        ConfirmationEvents = @(2889)
        BlastRadius    = 'Unauthenticated LDAP connection to DC only — no data modification. Disabling anonymous LDAP may break legacy NFS/UNIX clients that rely on anonymous AD lookups.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-027' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Compare DA/EA/Schema Admin members against Protected Users group via LDAP — read-only cross-reference'
                Destructive = $false
                Rollback    = 'LDAP read — no group membership change. Before adding accounts to Protected Users, confirm they do not use NTLM, DES, RC4, CredSSP, or WDigest — membership enforces Kerberos-only auth and may break legacy services.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — adding Tier 0 accounts to Protected Users requires Kerberos-only auth and 4-hour TGT. Test on a non-privileged account first; have a recovery plan if a DA account is locked out.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-028' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate userAccountControl DONT_EXPIRE_PASSWORD (UAC bit 0x10000) on DA/EA members via LDAP — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no UAC or password change. Enable password expiry on privileged accounts; coordinate with JIT/PAM processes to avoid service disruption.'
            }
        )
        ConfirmationEvents = @(4723,4738)
        BlastRadius    = 'LDAP read — no account modification. Enabling password expiry on privileged accounts may expire current credentials; pre-stage new credentials before enabling.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-029' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Filter DA/EA/Schema Admin group members where userAccountControl has ACCOUNTDISABLE bit set — LDAP read-only'
                Destructive = $false
                Rollback    = 'LDAP read — no account state change. Remove disabled accounts from privileged groups; confirm with account owners before removal.'
            }
        )
        ConfirmationEvents = @(4728,4732,4756)
        BlastRadius    = 'LDAP read — no modification. Removing a disabled account from DA also removes residual ACL access; confirm no recovery process depends on re-enabling this specific account.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-030' = @{
        Techniques     = @('T1485')
        TechniqueNames = @('Data Destruction')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read tombstoneLifetime from CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,... via LDAP — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no change. Increasing tombstone lifetime (e.g., to 180) has no immediate operational impact; system defaults to 60 days if attribute is absent.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — setting tombstoneLifetime requires replication to all DCs. Existing tombstones are not retroactively extended.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-031' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read msDS-Behavior-Version from CN=Partitions,CN=Configuration,... (Forest FFL) via LDAP — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no change. Raising FFL to 2016 requires all domains to already be at DFL 2016 and is irreversible.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — no modification. FFL raise is irreversible and requires all DCs across all domains to be running Server 2016 or later.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-032' = @{
        Techniques     = @('T1110.001')
        TechniqueNames = @('Brute Force: Password Guessing')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate PSOs in CN=Password Settings Container,CN=System,DC=... via LDAP — read msDS-MinimumPasswordLength, msDS-LockoutThreshold (read-only)'
                Destructive = $false
                Rollback    = 'LDAP read — no PSO modified. Tightening a PSO that currently grants a weaker policy may lock out service accounts — verify applicability scope (msDS-PSOAppliesTo) before changing.'
            }
        )
        ConfirmationEvents = @(4723,4740)
        BlastRadius    = 'LDAP read — no modification. Changing PSO settings affects all groups/users in msDS-PSOAppliesTo immediately; pilot on a test group first.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-033' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Enumerate DC computer objects (primaryGroupID=516) with lastLogonTimestamp older than 90 days via LDAP — read-only'
                Destructive = $false
                Rollback    = 'LDAP read — no object modification. Confirm DC is truly decommissioned (not just offline) before removing its computer object; consult netlogon.log and replication metadata.'
            }
        )
        ConfirmationEvents = @(4742)
        BlastRadius    = 'LDAP read — no removal performed. Deleting a DC computer object while the DC is still running will cause replication failures; demote the DC properly via dcpromo or ntdsutil first.'
        MinPriv        = 'AnyAuthUser'
    }

    # ── Host-OS audit-gap sprint (HOST-021 – HOST-027) ──────────────────────────

    'HOST-021' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read LmCompatibilityLevel: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Set to 5 (NTLMv2 only). Test with Responder/ntlmrelayx in a lab to confirm NTLMv1 is rejected before enforcing in production.'
            }
        )
        ConfirmationEvents = @(4624)
        BlastRadius    = 'Registry read — setting level 5 (refuse LM/NTLMv1) may break legacy devices that only support NTLMv1. Audit NTLMv1 usage via Event 4624 logon type and package name before enforcing.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-022' = @{
        Techniques     = @('T1003.001')
        TechniqueNames = @('OS Credential Dumping: LSASS Memory')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read DeviceGuard registry: Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name EnableVirtualizationBasedSecurity,LsaCfgFlags — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Enabling Credential Guard requires VBS-capable hardware (IOMMU/SecureBoot/TPM); test on representative hardware before broad deployment. Cannot be enabled on some virtualised DC configurations.'
            }
        )
        ConfirmationEvents = @(3,4)
        BlastRadius    = 'Registry read — enabling Credential Guard changes NTLM and Kerberos credential storage; may break services using MS-CHAPv2 or NTLMv1. Plan rollback via Group Policy before enabling.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-023' = @{
        Techniques     = @('T1059.001')
        TechniqueNames = @('Command and Scripting Interpreter: PowerShell')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'powershell -Version 2 -Command "Write-Output test" — confirm PS v2 is functional (lab only; confirms ScriptBlock logging bypass)'
                Destructive = $false
                Rollback    = 'Process execution — no system state change. Disable: Remove-WindowsFeature PowerShell-V2 (Server) or Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (client). Reboot required.'
            }
        )
        ConfirmationEvents = @(400,403,4103,4104)
        BlastRadius    = 'Single powershell.exe process — confirms ScriptBlock logging (4104) does NOT fire under v2. Remove the feature; v2 is not needed by any supported Windows component.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-024' = @{
        Techniques     = @('T1557')
        TechniqueNames = @('Adversary-in-the-Middle')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read LdapEnforceChannelBinding: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name LdapEnforceChannelBinding -EA SilentlyContinue).LdapEnforceChannelBinding — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Set to 2 on all DCs; confirm with ldp.exe that channel binding is enforced. Value 1 (supported clients only) is an acceptable interim step if older LDAP clients are present.'
            }
        )
        ConfirmationEvents = @(3039,3040,3041)
        BlastRadius    = 'Registry read — enabling channel binding (value=2) may break older LDAP clients (e.g., some Linux/Unix systems using old OpenLDAP). Audit LDAP client versions before enforcing.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-025' = @{
        Techniques     = @('T1557')
        TechniqueNames = @('Adversary-in-the-Middle')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read WinRM policy: (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Name AllowUnencrypted -EA SilentlyContinue).AllowUnencrypted — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no configuration change. Deploy a HTTPS listener with a valid certificate (winrm quickconfig -transport:https) and set AllowUnencrypted=0 via GPO.'
            }
        )
        ConfirmationEvents = @(169,170)
        BlastRadius    = 'Registry read — disabling unencrypted WinRM requires HTTPS configured first; disabling without HTTPS will break all remote PowerShell sessions on that host.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-026' = @{
        Techniques     = @('T1012')
        TechniqueNames = @('Query Registry')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-Service RemoteRegistry — confirm service status and start type (read-only)'
                Destructive = $false
                Rollback    = 'Service query — no state change. Set Remote Registry to Disabled on DCs; confirm no monitoring agent requires it before disabling.'
            }
        )
        ConfirmationEvents = @(7036)
        BlastRadius    = 'Service query — read-only. Disabling Remote Registry may break legacy WMI-based monitoring tools or backup agents that rely on it; audit first via netstat -anb on the DC.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-027' = @{
        Techniques     = @('T1005')
        TechniqueNames = @('Data from Local System')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-BitLockerVolume -MountPoint C: — confirm VolumeStatus and ProtectionStatus (read-only)'
                Destructive = $false
                Rollback    = 'Read-only — no BitLocker change. Enabling BitLocker on a DC OS volume requires TPM or a startup key; store the recovery key in AD DS (Enable-BitLockerKeyProtector -ADAccountOrGroupProtector) and in a PAM system before enabling.'
            }
        )
        ConfirmationEvents = @(24620,24621,24622)
        BlastRadius    = 'Read-only BitLocker status query — enabling BitLocker on a running DC requires a reboot for initial encryption. Ensure recovery key is backed up before enabling.'
        MinPriv        = 'LocalAdmin'
    }

    # ── CA-Config / AD CS audit-gap sprint (ADCS-010 – ADCS-012) ────────────────

    'ADCS-010' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'certutil -config "<CA-Host>\<CA-Name>" -getreg policy\EditFlags — confirm EDITF_ATTRIBUTESUBJECTALTNAME2 bit (0x40000) via read-only certutil query'
                Destructive = $false
                Rollback    = 'certutil registry read on CA — no flag modified. Remediate: certutil -config "<CA>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then net stop/start certsvc. Test certificate enrollment before and after.'
            }
        )
        ConfirmationEvents = @(4886,4887)
        BlastRadius    = 'Read-only CA registry check — removing the flag immediately disables requestor-supplied SANs on all templates; any application relying on this behavior will fail enrollment. Audit current certificate requests before removing.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-011' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Invoke-WebRequest -Method HEAD http://<CA-host>/certsrv/ — confirm HTTP enrollment endpoint reachable without TLS (read-only probe)'
                Destructive = $false
                Rollback    = 'HTTP HEAD request — no authentication, no certificate requested, no relay performed. Require HTTPS and enable EPA (Extended Protection for Authentication) in IIS on the certsrv virtual directory.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Single HTTP HEAD request — no NTLM relay performed in validation. ESC8 exploitation requires coercing an outbound NTLM authentication (PrinterBug/PetitPotam) which is NOT part of this validation.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-012' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read cACertificate from CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,... via LDAP — enumerate trusted CAs (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no certificate added or removed. Removing an unauthorized CA from NTAuthCertificates revokes its ability to issue domain-auth certificates immediately; confirm any active smart card logon sessions will not be disrupted.'
            }
        )
        ConfirmationEvents = @(4768,4769)
        BlastRadius    = 'LDAP read — no modification. Removing a CA from NTAuthCertificates invalidates all certificates issued by that CA for domain logon; ensure users have alternative authentication paths before removing.'
        MinPriv        = 'AnyAuthUser'
    }

    # ── DNS audit-gap sprint (DNS-008 – DNS-009) ─────────────────────────────────

    'DNS-008' = @{
        Techniques     = @('T1590.002')
        TechniqueNames = @('Gather Victim Network Information: DNS')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'dig AXFR @<dns-server> <zone> — confirm zone transfer response from an unauthorised source (read-only passive probe)'
                Destructive = $false
                Rollback    = 'DNS AXFR query — no records modified. Restrict zone transfers to authorised secondary servers via Get-DnsServerZone / Set-DnsServerSecondaryZone -SecureSecondaries TransferToSecureServers -SecondaryServers <IPs>.'
            }
        )
        ConfirmationEvents = @(6001)
        BlastRadius    = 'DNS AXFR request — returns full zone contents if misconfigured; no records are created or modified. Restrict AXFR before the next assessment cycle.'
        MinPriv        = 'AnyAuthUser'
    }

    'DNS-009' = @{
        Techniques     = @('T1590.002')
        TechniqueNames = @('Gather Victim Network Information: DNS')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-DnsServerForwarder — read current forwarder IP list (read-only); confirm public IPs with Resolve-DnsName via each forwarder'
                Destructive = $false
                Rollback    = 'DNS forwarder read — no forwarder added or removed. Replace public forwarders with internal resolvers or remove entirely; use conditional forwarders for specific external domains only.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'DNS query to forwarder — read-only. Removing all forwarders without a recursive fallback may break internet name resolution; configure split-brain DNS or conditional forwarders before removing.'
        MinPriv        = 'DNSAdmin'
    }

    # ── DHCP findings ────────────────────────────────────────────────────────────

    'DHCP-001' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-DhcpServerv4OptionValue -OptionId 252 — read WPAD proxy URL from scope (read-only)'
                Destructive = $false
                Rollback    = 'DHCP option read — no scope modified. Remove option 252 if WPAD is not required; disable WPAD auto-discovery in browsers via GPO regardless.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'DHCP query — read-only. Removing option 252 stops distributing the WPAD URL to new DHCP clients; existing clients retain cached WPAD config until lease renewal. Push a GPO to disable WPAD auto-discovery as a parallel control.'
        MinPriv        = 'AnyAuthUser'
    }

    'DHCP-002' = @{
        Techniques     = @('T1200')
        TechniqueNames = @('Hardware Additions')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-DhcpServerv4OptionValue -OptionId 66,67 — read TFTP server and bootfile from scope (read-only)'
                Destructive = $false
                Rollback    = 'DHCP option read — no scope modified. Review PXE infrastructure; restrict DHCP scope to known network segments and limit PXE boot to authorized MAC addresses or IP ranges.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'DHCP scope option read — read-only. Removing options 66/67 disables PXE boot for all clients on the scope; coordinate with infrastructure team before removing if PXE is in use for OS deployment.'
        MinPriv        = 'AnyAuthUser'
    }

    'DHCP-003' = @{
        Techniques     = @('T1562.002')
        TechniqueNames = @('Impair Defenses: Disable Windows Event Logging')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-DhcpServerAuditLog — read audit log path and enabled state (read-only)'
                Destructive = $false
                Rollback    = 'DHCP audit log read — no configuration change. Enable via Set-DhcpServerAuditLog -Enable $true; logs appear in %SystemRoot%\System32\dhcp\ by default.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Read-only DHCP configuration query — enabling audit logging writes CSV files to the DHCP log directory; ensure adequate disk space. Log rotation is automatic (daily).'
        MinPriv        = 'AnyAuthUser'
    }

    # ── GPO-Settings audit-gap sprint (GPO-011 – GPO-012) ───────────────────────

    'GPO-011' = @{
        Techniques     = @('T1059')
        TechniqueNames = @('Command and Scripting Interpreter')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-GPOReport on all GPOs linked to Domain Controllers OU — search for AppLocker/WDAC XML sections (read-only GPO enumeration)'
                Destructive = $false
                Rollback    = 'GPO XML read — no policy created or linked. Deploy AppLocker in Audit mode first (AuditOnly enforcement) to identify applications before switching to Enforce mode.'
            }
        )
        ConfirmationEvents = @(8003,8004,8006,8007)
        BlastRadius    = 'GPO read — no change. Deploying AppLocker in Enforce mode without adequate testing may block legitimate DC applications (e.g., monitoring agents); deploy in Audit mode first and review Event 8003/8006 for blocked items.'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-012' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-GPOReport — search GPO XML for RestrictedGroups or GroupsXml nodes targeting Domain Admins membership (read-only)'
                Destructive = $false
                Rollback    = 'GPO XML read — no policy created or linked. Create a Restricted Groups policy scoped to the Domain Controllers OU specifying the exact intended members of Domain Admins. Test in a staging OU before linking to production.'
            }
        )
        ConfirmationEvents = @(4728,4729,4732,4733)
        BlastRadius    = 'GPO read — no group membership change. A Restricted Groups policy enforces group membership at every Group Policy refresh (every 90 minutes); any direct DA additions not in the policy will be reverted. Coordinate with all admin processes before enabling.'
        MinPriv        = 'AnyAuthUser'
    }

    # ── Audit-Policy audit-gap sprint (AUD-014) ──────────────────────────────────

    'AUD-014' = @{
        Techniques     = @('T1562.002')
        TechniqueNames = @('Impair Defenses: Disable Windows Event Logging')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read WEF subscription manager: Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no subscription configured. Deploy WEC server; configure source-initiated subscriptions via GPO pointing DCs to the WEC server. Validate forwarding with wecutil enum-subscription on the WEC server.'
            }
        )
        ConfirmationEvents = @(100,101,111)
        BlastRadius    = 'Registry read — no change. Enabling WEF on DCs generates additional network traffic (events forwarded to WEC); size the WEC server log retention appropriately. Use a dedicated WEC server, not a DC.'
        MinPriv        = 'LocalAdmin'
    }

    # ── ESC Coverage Gaps (closed) ──────────────────────────────────────────────

    'HOST-020' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read KDC registry key: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Kdc -Name StrongCertificateBindingEnforcement -EA SilentlyContinue).StrongCertificateBindingEnforcement — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no KDC configuration modified. Value 2 = full enforcement; 1 = audit only; 0 = disabled; absent = pre-patch compatibility mode.'
            }
        )
        ConfirmationEvents = @(39,40,41)
        BlastRadius    = 'Registry read on each DC. Setting to 2 (enforcement) may break certificate-based Kerberos auth for accounts with misconfigured altSecurityIdentities — test in audit mode (1) first.'
        MinPriv        = 'LocalAdmin'
    }

    'ADC-024' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'LDAP query for altSecurityIdentities: (New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://DC=...,DC=...")).FindAll() with filter (altSecurityIdentities=*) — read-only'
                Destructive = $false
                Rollback    = 'LDAP read — no attribute modified. Validate weak mapping forms (X509RFC822, X509IssuerSubject) against expected certificate issuers before removing.'
            }
        )
        ConfirmationEvents = @(4768,4769,4770)
        BlastRadius    = 'LDAP read — converting altSecurityIdentities from weak to strong forms (X509SKI, X509PublicKey) requires re-enrollment or re-binding of existing certificates. Plan a migration window.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADCS-009' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'LDAP read msPKI-Template-Schema-Version on certificate templates: (Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=..." -Properties msPKI-Template-Schema-Version) — read-only'
                Destructive = $false
                Rollback    = 'LDAP read — no template configuration modified. ESC15 (CVE-2024-49019) requires Nov 2024 KB5044280/KB5044284 on issuing CAs; verify patch before relying on schema-upgrade mitigation.'
            }
        )
        ConfirmationEvents = @(4886,4887)
        BlastRadius    = 'Passive LDAP enumeration — read-only. Migrating from schema-v1 to v2+ templates requires re-publishing the template; test with a non-critical template first. Verify Nov 2024 patch is applied on all issuing CAs.'
        MinPriv        = 'AnyAuthUser'
    }

    # ── Sprint 5 new findings ────────────────────────────────────────────────────

    'ADC-034' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Check LAPS schema: [adsi]"LDAP://CN=ms-Mcs-AdmPwd,$SchemaDn" + count computers with ms-Mcs-AdmPwdExpirationTime populated via LDAP — read-only'
                Destructive = $false
                Rollback    = 'LDAP read — no attribute or object modified. Deploy LAPS via schema extension (Update-LapsADSchema) + GPO + CSE. Verify with Get-LapsADPassword before removing manual local admin processes.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — schema extension (one-time write to Configuration NC) is a forest-wide irreversible change; test in a lab forest first. GPO deployment is scoped to OUs and can be reverted.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-035' = @{
        Techniques     = @('T1558.003')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Kerberoasting')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read msDS-SupportedEncryptionTypes on domain root object via LDAP — confirm RC4 bit (0x04) is set or value is 0 (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no value change. Setting msDS-SupportedEncryptionTypes=24 on domain root enforces AES128+AES256 only; test all service accounts for AES Kerberos key presence before enforcing to prevent auth breakage.'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius    = 'LDAP read — enforcing AES-only (value=24) on domain object affects ALL Kerberos ticket issuance; monitor Event 4769 for RC4 requests before and after enforcement. Roll back by setting value to 0 or adding RC4 bit.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-036' = @{
        Techniques     = @('T1078.001')
        TechniqueNames = @('Valid Accounts: Default Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-ADUser Guest — check Enabled attribute (read-only AD query)'
                Destructive = $false
                Rollback    = 'AD object read — no state change. Disable with Disable-ADAccount -Identity Guest; confirm no application relies on Guest access before disabling.'
            }
        )
        ConfirmationEvents = @(4625,4624)
        BlastRadius    = 'AD read — disabling Guest is low risk; confirm no legacy systems (NFS, old printers) rely on unauthenticated Guest access first.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-037' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-ADUser Administrator — read samAccountName and Enabled via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'AD object read — no account change. Rename samAccountName via Rename-ADObject or Set-ADUser -SamAccountName. Create a honeypot account named "Administrator" with alerting on logon success.'
            }
        )
        ConfirmationEvents = @(4625,4624,4776)
        BlastRadius    = 'AD read — renaming the built-in Administrator may break legacy scripts or applications that reference it by name; audit usage before renaming.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-038' = @{
        Techniques     = @('T1098')
        TechniqueNames = @('Account Manipulation')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-ADGroupMember "Schema Admins" — enumerate current members via LDAP (read-only)'
                Destructive = $false
                Rollback    = 'LDAP group member read — no membership change. Remove all permanent members: Remove-ADGroupMember -Identity "Schema Admins" -Members <list>. Confirm the account has no active schema-change operation before removing.'
            }
        )
        ConfirmationEvents = @(4737,4728,4729)
        BlastRadius    = 'LDAP read — Schema Admins removal has no immediate operational impact; schema changes require re-adding temporarily. Document the approved member list and run-book for temporary elevation.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-039' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-ADUser MSOL_* — read pwdLastSet via LDAP; calculate age (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no password change. Rotate via Entra Connect: run Update-MSOLFederatedDomain or use the Entra Connect wizard Account tab to update credentials — it rotates both on-prem and cloud credentials atomically.'
            }
        )
        ConfirmationEvents = @(4723,4738)
        BlastRadius    = 'LDAP read — password rotation requires running the Entra Connect update wizard; a failed rotation can interrupt directory synchronization until corrected.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-040' = @{
        Techniques     = @('T1558.002')
        TechniqueNames = @('Steal or Forge Kerberos Tickets: Silver Ticket')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-ADComputer AZUREADSSOACC$ — verify presence and read pwdLastSet (read-only LDAP query)'
                Destructive = $false
                Rollback    = 'LDAP read — no key change. Rotate via: Update-AzureADSSOForest -OnPremCredentials <cred> -AzureADCredentials <cred>. Rotate every 30 days; document the rotation schedule.'
            }
        )
        ConfirmationEvents = @(4769)
        BlastRadius    = 'LDAP read — key rotation requires running the Seamless SSO refresh script; brief authentication disruption possible during rotation window (<1 minute). Test on a non-production tenant first.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-041' = @{
        Techniques     = @('T1552.004')
        TechniqueNames = @('Unsecured Credentials: Private Keys')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read msDS-RevealOnDemandGroup on RODC computer objects via LDAP — check for Tier 0 group membership (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no PRP change. Remove sensitive groups from msDS-RevealOnDemandGroup using Set-ADObject or ADUC; add them to msDS-NeverRevealGroup instead. Run "repadmin /prp view <RODC> reveal" to audit cached passwords before and after.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'LDAP read — PRP change takes effect immediately on next RODC sync; accounts removed from reveal set will no longer be cached on the RODC. Verify no Tier 0 admin requires RODC-cached credentials for logon before changing.'
        MinPriv        = 'AnyAuthUser'
    }

    'ADC-042' = @{
        Techniques     = @('T1222.001')
        TechniqueNames = @('File and Directory Permissions Modification: Windows File and Directory Permissions Modification')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read domain root object DACL and check for Exchange Windows Permissions WriteDACL ACE via DirectoryServices — read-only'
                Destructive = $false
                Rollback    = 'DACL read — no ACE modified. Remediate using Microsoft Exchange Health Checker DACL remediation script (HealthChecker.ps1) or manually remove the WriteDACL ACE with Set-Acl / ADSIEDIT. Backup the domain DACL (Get-Acl "AD:$domainDN") before modifying.'
            }
        )
        ConfirmationEvents = @(4662,5136)
        BlastRadius    = 'DACL read — removing Exchange WriteDACL ACE may break Exchange recipient management operations if Exchange relies on it; test in a lab Exchange environment before removing from production.'
        MinPriv        = 'AnyAuthUser'
    }

    'HOST-028' = @{
        Techniques     = @('T1557')
        TechniqueNames = @('Adversary-in-the-Middle')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read DisabledComponents: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Name DisabledComponents -EA SilentlyContinue).DisabledComponents — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Disable IPv6: set DisabledComponents=0xFF via GPO or registry if not operationally required. Deploy DHCPv6/RA Guard at the network layer as an alternative. Confirm no services (DirectAccess, IPv6-only resources) depend on IPv6 before disabling.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry read — disabling IPv6 (0xFF) prevents mitm6 but may break DirectAccess, some clustering features, and IPv6-only DNS resolution. Test on one DC before broad deployment; requires reboot to take effect.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-029' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read LanmanWorkstation RequireSecuritySignature: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name RequireSecuritySignature -EA SilentlyContinue).RequireSecuritySignature — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Set RequireSecuritySignature=1 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Digitally sign communications (always). Note: distinct from server-side signing (HOST-012 / LanmanServer).'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry read — enforcing client signing may cause auth failures to old (pre-Win2000) SMB servers; audit SMB client connections before enforcing.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-030' = @{
        Techniques     = @('T1003.005')
        TechniqueNames = @('OS Credential Dumping: Cached Domain Credentials')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read CachedLogonsCount: (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name CachedLogonsCount -EA SilentlyContinue).CachedLogonsCount — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Set to 0 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive Logon: Number of previous logons to cache = 0. DCs do not need cached credentials.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'Registry read — setting CachedLogonsCount=0 means DC local logon fails when domain is unreachable; acceptable for DCs which should always have domain connectivity.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-031' = @{
        Techniques     = @('T1557')
        TechniqueNames = @('Adversary-in-the-Middle')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read Netlogon Parameters: RequireSignOrSeal and SealSecureChannel from HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Set both to 1 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Domain member: Digitally encrypt or sign secure channel data (always)" and "Domain member: Digitally sign secure channel data (when possible)".'
            }
        )
        ConfirmationEvents = @(5840,5841)
        BlastRadius    = 'Registry read — enabling Netlogon secure channel may break legacy NT4 BDC communication; not applicable in modern (2003+ DFL) domains. Apply to all DCs simultaneously or use the "when possible" setting first.'
        MinPriv        = 'LocalAdmin'
    }

    'HOST-032' = @{
        Techniques     = @('T1490')
        TechniqueNames = @('Inhibit System Recovery')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-Service wbengine; Get-WinEvent -LogName Microsoft-Windows-Backup | Where Id -eq 4 — verify most recent backup date (read-only)'
                Destructive = $false
                Rollback    = 'Service query and event log read — no configuration change. Configure Windows Server Backup for system state backup to a UNC path or offline media; verify with wbadmin start systemstatebackup. Test restore in a recovery environment before relying on backup.'
            }
        )
        ConfirmationEvents = @(4,6)
        BlastRadius    = 'Read-only backup verification — enabling Windows Server Backup system-state backup causes VSS snapshot overhead during backup window; plan backup schedule outside business hours for busy DCs.'
        MinPriv        = 'LocalAdmin'
    }

    'GPO-013' = @{
        Techniques     = @('T1484.001')
        TechniqueNames = @('Domain Policy Modification: Group Policy Modification')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read DACL on GPO container objects (CN=<GUID>,CN=Policies,CN=System,...) via DirectoryServices ObjectSecurity — enumerate write ACEs (read-only)'
                Destructive = $false
                Rollback    = 'DACL read — no ACE modified. Remove unauthorized write ACEs via Set-GPPermissions or ADSIEDIT. Back up the GPO (Backup-GPO) before modifying its DACL. Review GPO creation audit (Event 5136) to determine when the ACE was added.'
            }
        )
        ConfirmationEvents = @(5136,4662)
        BlastRadius    = 'DACL read — no modification. Removing a write ACE from a GPO immediately prevents that principal from modifying the GPO; verify the ACE is not intentionally granted before removing.'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-014' = @{
        Techniques     = @('T1078.002')
        TechniqueNames = @('Valid Accounts: Domain Accounts')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-GPOReport on DC-linked GPOs; search XML for UserRightsAssignment SeDenyInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight — read-only'
                Destructive = $false
                Rollback    = 'GPO XML read — no policy change. Create a GPO linked to the Domain Controllers OU that denies interactive and RDS logon for non-Tier-0 accounts. Test by attempting denied-account logon in a lab before deploying.'
            }
        )
        ConfirmationEvents = @(4625)
        BlastRadius    = 'GPO read — adding deny-logon rights to the DC OU GPO immediately prevents the denied accounts from logging onto any DC; verify the deny list does not include accounts required for DC admin operations.'
        MinPriv        = 'AnyAuthUser'
    }

    'GPO-015' = @{
        Techniques     = @('T1484.001')
        TechniqueNames = @('Domain Policy Modification: Group Policy Modification')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read gPLink attribute on all OUs and domain root via LDAP; compare against full GPO GUID list to identify unlinked GPOs — read-only'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no GPO deleted or linked. Review orphaned GPOs with Get-GPOReport; confirm they are no longer needed before deleting with Remove-GPO.'
            }
        )
        ConfirmationEvents = @(5136)
        BlastRadius    = 'LDAP read — deleting orphaned GPOs is irreversible without a backup; run Backup-GPO on each before deleting. A deleted GPO linked elsewhere (if missed by the scan) would cause an error log on clients.'
        MinPriv        = 'AnyAuthUser'
    }

    'AUD-015' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Read AuditReceivingNTLMTraffic: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name AuditReceivingNTLMTraffic -EA SilentlyContinue).AuditReceivingNTLMTraffic — read-only'
                Destructive = $false
                Rollback    = 'Registry read — no value modified. Set to 2 (audit all) via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network Security: Restrict NTLM: Audit NTLM authentication in this domain. Events appear in Microsoft-Windows-NTLM/Operational event log (Event 8004).'
            }
        )
        ConfirmationEvents = @(8004)
        BlastRadius    = 'Registry read — enabling NTLM auditing (value=2) generates Event 8004 for every incoming NTLM authentication on the DC; can be high-volume on busy DCs. Forward logs to SIEM and set adequate log retention before enabling.'
        MinPriv        = 'LocalAdmin'
    }

    'DNS-010' = @{
        Techniques     = @('T1557.001')
        TechniqueNames = @('Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'Get-DnsServerZone -Name <zone> | Select-Object Aging,NoRefreshInterval,RefreshInterval — verify scavenging state (read-only)'
                Destructive = $false
                Rollback    = 'DNS zone property read — no record deleted. Enable scavenging: Set-DnsServerZoneAging -ZoneName <zone> -Aging $true -NoRefreshInterval 7.00:00:00 -RefreshInterval 7.00:00:00; then Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 on the DNS server. Scavenging only removes records whose timestamp has expired past the refresh interval.'
            }
        )
        ConfirmationEvents = @()
        BlastRadius    = 'DNS zone read — enabling scavenging will tombstone and eventually delete DNS records whose owners have not refreshed within the NoRefresh+Refresh window. Test with a short retention zone first; ensure dynamic-update clients actually refresh records before enabling on a production zone.'
        MinPriv        = 'DNSAdmin'
    }

    'ADCS-013' = @{
        Techniques     = @('T1649')
        TechniqueNames = @('Steal or Forge Authentication Certificates')
        AtomicTests    = @(
            @{
                Guid        = 'N/A'
                Name        = 'LDAP filter: (&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(userCertificate=*)) — check if any DC computer objects have userCertificate populated (read-only)'
                Destructive = $false
                Rollback    = 'LDAP attribute read — no certificate enrolled. Configure auto-enrollment GPO: Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client - Auto-Enrollment. Ensure the DC Authentication or Domain Controller template is published and DCs have enroll permission.'
            }
        )
        ConfirmationEvents = @(4886,4887)
        BlastRadius    = 'LDAP read — enabling auto-enrollment causes DCs to request certificates from the CA automatically at next GPO refresh; no manual intervention required. Verify CA capacity and template permissions before enabling.'
        MinPriv        = 'AnyAuthUser'
    }

}
