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

}
