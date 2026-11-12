# SIEM Audit Policy for Windows / Active Directory

One PowerShell file, `Deploy-SiemAuditPolicy.ps1`, that sets up Windows security event logging for SIEM monitoring. It can:

- **Deploy** two GPOs to an AD domain (all computers + domain controllers).
- **Apply** the same settings to one standalone or workgroup machine.
- **Verify** that a machine is actually logging what the SIEM needs.

It has no dependencies, needs no extra files, and is ASCII-only, so it survives copy/paste between RDP sessions, jump boxes and ticket systems. It runs on Windows PowerShell 5.1 and PowerShell 7.

---

## Quick start (client domain onboarding)

On a **domain controller**, as a **Domain Admin**, in an **elevated** PowerShell:

1. Get the script onto the DC: copy the file, or paste its contents into Notepad and save it as `Deploy-SiemAuditPolicy.ps1`.
2. Run it:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Deploy-SiemAuditPolicy.ps1
   ```

3. Pick from the menu:

   ```
   1) Deploy GPOs to this Active Directory domain
   2) Preview the domain deployment (no changes, -WhatIf)
   3) Apply settings to THIS computer only (standalone / workgroup)
   4) Verify THIS computer is logging correctly (read-only)
   5) Show all settings (read-only)
   ```

4. Check that it took effect on a DC and a sample member server or workstation:

   ```powershell
   gpupdate /force
   powershell -ExecutionPolicy Bypass -File .\Deploy-SiemAuditPolicy.ps1 -Mode Verify
   ```

Other ways to run it:

- **PowerShell ISE:** paste the whole script into the script pane and press F5. You get the same menu.
- **Non-interactive, for runbooks or RMM:** use `-Mode Domain|Local|Verify|Show`. Add `-WhatIf` for a dry run, `-NoLink` to create the GPOs without linking them, `-GpoPrefix "Contoso SIEM"` to rename them, and `-Server dc01` to target a specific DC (the default is the PDC emulator).
- **From a URL you host:** `& ([scriptblock]::Create((irm https://<your-host>/Deploy-SiemAuditPolicy.ps1))) -Mode Verify`

## What Domain mode does

| GPO | Linked to | Contents |
|---|---|---|
| `SIEM Audit Policy - All Computers` | Domain root | All settings below |
| `SIEM Audit Policy - Domain Controllers` | `OU=Domain Controllers` | The same settings, plus a 4 GB Security log and NTLM-in-domain auditing |

- **Idempotent:** re-running the script rebuilds both GPOs to exactly match the script. To change settings, edit the tables at the top of the script and re-run it. Don't hand-edit the GPOs.
- **Non-disruptive links:** each new link is added at the *lowest* precedence at its level, so existing hardening GPOs keep winning any conflicts. All NTLM settings are audit-only and never block anything.
- **Conflict warning:** at the end, the script lists any other GPO that also defines Advanced Audit Policy, because one of those could override this baseline. Review them, or raise this GPO's link order.
- **Computer settings only:** User settings are disabled on both GPOs. The policy version is stamped in the GPO comment.
- **What it writes:** `audit.csv` (Advanced Audit Policy), `GptTmpl.inf` (Security Options) and `Registry.pol` (everything else) in SYSVOL. It also registers the client-side extensions and bumps the GPO version.

**Rollback:** `Remove-GPO -Name "SIEM Audit Policy - All Computers"` (and the same for the DC GPO). Audit policy settings are not tattooed, so clients revert at the next refresh. Registry-based event log sizes stay as they are, which is harmless.

---

## Settings and rationale

The baseline is Microsoft's Windows Security Baseline and its audit policy recommendations, CIS L1, and the logging guidance from NSA/CISA and the Australian Cyber Security Centre ("Windows Event Logging and Forwarding"). It's tuned for detection value per GB ingested. Subcategories that only fire on certain roles (DC, CA, NPS, file server) produce no events elsewhere, so every computer gets the same audit set.

### Advanced Audit Policy

| Category | Subcategory | Setting | Why (key event IDs) |
|---|---|---|---|
| Account Logon | Credential Validation | S/F | 4774-4777 NTLM auth, password spray |
| | Kerberos Authentication Service | S/F | 4768/4771 TGT requests, AS-REP roasting, spray (DC) |
| | Kerberos Service Ticket Operations | S/F | 4769 Kerberoasting (DC) |
| | Other Account Logon Events | S/F | 4649 |
| Account Management | Application / Computer / Distribution / Security Group / User Account / Other | S/F | 4720-4767, 4741-4743 (RBCD), 4728/4732/4756 (privileged group adds), 4798/4799 (recon) |
| Detailed Tracking | Process Creation | S/F | 4688 **with command line** |
| | DPAPI Activity | S/F | 4692-4695 (DPAPI backup key theft on DCs) |
| | Plug and Play Events | S | 6416 new external device |
| DS Access | Directory Service Access | S/F | 4662 DCSync (replication GUIDs), sensitive object reads (DC) |
| | Directory Service Changes | S/F | 5136-5141 AD object and GPO changes (DC) |
| Logon/Logoff | Logon | S/F | 4624/4625/4648, logon types, lateral movement |
| | Special Logon | S/F | 4672 admin-equivalent logons |
| | Other Logon/Logoff Events | S/F | 4778/4779 RDP reconnect, 4800-4803 lock/unlock |
| | Account Lockout | S/F | 4625 lockouts |
| | Group Membership | S | 4627 groups at logon |
| | Logoff | S | 4634/4647 session duration |
| | Network Policy Server | S/F | 6272-6280 RADIUS/VPN (NPS only) |
| Object Access | Other Object Access Events | S/F | 4698-4702 scheduled task create/modify |
| | File Share | S/F | 5140 ADMIN$/C$/IPC$ access |
| | Detailed File Share | F | 5145 failures only (success is extremely noisy) |
| | Removable Storage | S/F | USB file access |
| | Certification Services | S/F | AD CS abuse, ESC1-ESC8 (CA only) |
| | File System / Registry | S/F | Only objects with a SACL. Enables targeted SACLs and canaries without logging everything |
| Policy Change | Audit Policy Change | S/F | 4719/4907 audit tampering |
| | Authentication Policy Change | S/F | 4706/4707/4713/4716/4739 trusts, Kerberos policy |
| | Authorization Policy Change | S | 4704/4705 user rights changes |
| | MPSSVC Rule-Level Policy Change | S/F | 4946-4950 firewall rule changes |
| | Other Policy Change Events | F | 6144/6145 |
| Privilege Use | Sensitive Privilege Use | S/F | 4673/4674 (see tuning) |
| System | Security System Extension | S/F | **4697 service installed** (PsExec etc.) |
| | Security State Change | S/F | 4608, 4616 system time change |
| | System Integrity | S/F | 4612/4615/5038 |
| | IPsec Driver, Other System Events | S/F | Low volume, Microsoft baseline |

Intentionally **not** enabled (very high volume, low value without a specific use case): Filtering Platform Connection/Packet Drop (5156/5157), Handle Manipulation, Kernel Object, Token Right Adjusted (4703), Process Termination (4689), Detailed File Share success, RPC Events, Non-Sensitive Privilege Use.

### Security Options, registry and event logs

| Setting | Value | Why |
|---|---|---|
| Audit: Force audit policy subcategory settings to override category settings | Enabled | Without this, legacy category audit policy (for example the Default Domain Controllers Policy) can silently override the advanced settings |
| Include command line in process creation events | Enabled | Makes 4688 actually useful |
| PowerShell Script Block Logging (Windows PowerShell + PowerShell 7) | Enabled | 4104: deobfuscated script content |
| PowerShell Module Logging, all modules (`*`) | Enabled | 4103: pipeline execution detail |
| Restrict NTLM: Audit incoming NTLM traffic | All accounts | NTLM visibility (Microsoft-Windows-NTLM/Operational 8001-8004). Audit only |
| Restrict NTLM: Outgoing NTLM traffic | Audit all | Audit only, does not block |
| Restrict NTLM: Audit NTLM authentication in this domain (DC GPO) | Enable all | Shows which servers or apps still use NTLM |
| Security log size | 1 GB (DCs ~4 GB), overwrite as needed | Local buffer if the SIEM agent or forwarder is down. Logging never stops |
| System / Application log size | 128 MB, overwrite | |
| Windows PowerShell log size | 256 MB | |
| Operational channels enabled and sized | PowerShell/Operational 256 MB, TaskScheduler 64 MB, NTLM 64 MB, Defender 64 MB, WMI-Activity 32 MB, DriverFrameworks-UserMode 32 MB | TaskScheduler and DriverFrameworks are off by default |

Channel enable and size settings delivered by GPO take effect after a **reboot**. Local mode applies them immediately with `wevtutil`.

---

## Things the GPO can't do, but you should for full coverage

1. **Sysmon** with a maintained config (for example SwiftOnSecurity or olafhartong/sysmon-modular). It's the biggest detection uplift after this baseline. Deploy it with your RMM or a startup script.
2. **AD CS auditing on the CA:** the audit policy alone isn't enough. On each CA run `certutil -setreg CA\AuditFilter 127` and restart CertSvc.
3. **AD object SACLs for Directory Service Changes/Access:** the default SACLs cover most objects. For DCSync and sensitive-attribute monitoring, check that the domain root SACL audits `Everyone` for replication rights. Microsoft Defender for Identity documents the recommended SACLs.
4. **Collection:** point your SIEM agent or Windows Event Forwarding at the Security, System, PowerShell/Operational, Windows PowerShell, TaskScheduler/Operational, NTLM/Operational, Defender/Operational, WMI-Activity/Operational and Sysmon/Operational channels.
5. **PowerShell 7** writes to the `PowerShellCore/Operational` channel only after you run `RegisterManifest.ps1` from the PowerShell 7 install directory.
6. **DNS Server analytic logging** on DCs, if DNS query visibility is needed. It's high volume.

## Noise tuning (ingest cost)

If ingest volume is a problem, filter these at the collector before reducing auditing at the source:

- **4673/4674 Sensitive Privilege Use:** noisy on workstations (browsers, AV). Filtering by process is better than turning it off.
- **4662 on DCs:** keep only events whose Properties contain the replication GUIDs (`1131f6aa-...`, `1131f6ad-...`, `89e95b76-...`) or that touch sensitive objects.
- **5140 File Share:** high on file servers. Keep `ADMIN$`, `C$` and `IPC$`.
- **4634 Logoff and 4627 Group Membership:** safe to drop if session tracking isn't used.

## Customizing

All settings live in three tables at the top of the script: `$AuditSettings`, `$RegistrySettings` and `$ChannelSettings`. Domain, Local, Verify and Show modes all read from those tables, so one edit changes all four. Bump `$PolicyVersion` when you change anything, so you can see which version a client is running in the GPO comment.

## Testing

```powershell
. .\Deploy-SiemAuditPolicy.ps1          # dot-source: loads functions without running
New-AuditCsvContent                      # inspect generated audit.csv
New-GptTmplContent (Get-DesiredRegistry $true)
.\Deploy-SiemAuditPolicy.ps1 -Mode Show
.\Deploy-SiemAuditPolicy.ps1 -Mode Domain -WhatIf
```
