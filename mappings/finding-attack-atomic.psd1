# Finding ID → MITRE ATT&CK technique(s) → Atomic Red Team test reference.
# Used by New-ValidationCards.ps1 to generate non-destructive validation cards.
#
# All Atomic test references must be non-destructive variants only.
# Rollback field is required for every entry ("read-only — no rollback needed" where applicable).

@{

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

}
