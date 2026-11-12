# SIEM Audit Policy for Windows / Active Directory

One PowerShell file, `Deploy-SiemAuditPolicy.ps1`, that sets up Windows security event logging for SIEM monitoring. It can:

- **Deploy** audit policy GPOs for workstations, servers and domain controllers, all together or one at a time.
- **Install Sysmon** with the same targeting as the audit GPOs (all, workstations, servers, domain controllers), or on one machine directly. Windows' built-in Sysmon feature is used where the OS has it; the Sysinternals installer is the fallback.
- **Turn on AD and AD CS auditing** that a GPO can't set: DCSync auditing on the domain root and the audit filter on every certificate authority.
- **Install its own prerequisites**: the Group Policy Management tools and the PowerShell 7 event log registration.
- **Apply** the same settings to one standalone or workgroup machine.
- **Verify** that a machine is actually logging what the SIEM needs.

Every step is automated. If a step can't finish (no internet, no permission, a missing tool), the script prints exact manual instructions for that step and moves on. `-Mode Manual` prints all the manual instructions without changing anything.

It's one ASCII-only file with no other files to carry, so it survives copy/paste between RDP sessions, jump boxes and ticket systems. Domain modes need Windows PowerShell 5.1 (`powershell.exe`, the default on every DC). The modes that only touch the local computer also run on PowerShell 7.

---

## Usage

`-Help` prints this summary:

```
SIEM Audit Policy v1.2.0 - run in an elevated PowerShell. No parameters = menu.

  .\Deploy-SiemAuditPolicy.ps1 -Mode <mode> [options]

  Domain (on a DC, as Domain Admin; Windows PowerShell 5.1)    [-Target ...]
    Full          Audit GPOs + Sysmon GPOs + AD/ADCS auditing
    Domain        Audit policy GPOs
    SysmonDomain  Sysmon GPOs (install at restart; built-in Sysmon first)
    AdAudit       DCSync audit on domain root + AD CS audit on every CA
  This computer                                                [-Role ...]
    Local         Apply audit settings (+ remove PowerShell 2.0 engine)
    SysmonLocal   Install Sysmon now (built-in first, installer fallback)
    Verify        Check logging, read-only
    Show          List settings, read-only
    Manual        Print manual steps for everything, no changes

  Options
    -Target All|Workstations|Servers|DomainControllers   (comma-separate several)
    -Role Workstation|Server|DomainController            (default: this computer)
    -SysmonConfigUrl <URL|path>     Sysmon config (default: SwiftOnSecurity)
    -SysmonExisting Keep|Overwrite  Existing Sysmon config (unattended default: Keep)
    -SysmonZip <URL|zip|folder>     Installer fallback source (offline use)
    -AcceptEula   Accept Sysinternals license (installer fallback)
    -WhatIf       Preview only       -Force   Answer yes to prompts
    -NoLink       Create GPOs unlinked       -GpoPrefix <name>   -Server <dc>
```

## Quick start (client domain onboarding)

On a **domain controller**, as a **Domain Admin**:

1. Get the script onto the DC: copy the file, or paste its contents into Notepad and save it as `Deploy-SiemAuditPolicy.ps1`.
2. In an elevated PowerShell, run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Deploy-SiemAuditPolicy.ps1
   ```

3. Pick **1) Full onboarding**. To see what it would do first, pick **5) Preview** instead.

   ```
   SIEM Audit Policy v1.2.0        H) Help   M) Manual steps   Q) Quit
    Domain (on a DC, as Domain Admin) - you pick which computers next:
      1) Full onboarding: audit GPOs + Sysmon GPOs + AD/ADCS auditing
      2) Audit policy GPOs
      3) Sysmon GPOs (built-in Sysmon first, installer fallback)
      4) AD auditing: DCSync audit on domain root + AD CS audit on every CA
      5) Preview full onboarding (no changes)
    This computer:
      6) Apply audit settings + install Sysmon (standalone / workgroup)
      7) Verify this computer (read-only)
      8) Show settings (read-only)
   ```

   Options 1, 2, 3 and 5 then ask which computers the change is for: `1) All  2) Workstations  3) Servers  4) Domain Controllers`. Enter several as `2,3`. AD/ADCS auditing is domain-wide, so Full onboarding includes it only when All or Domain Controllers is chosen. When Sysmon is involved, the script also asks for the config URL, defaulting to SwiftOnSecurity. It also asks whether to overwrite the config of a Sysmon that's already installed.

4. Check that it took effect on a DC, a server and a workstation. Sysmon from the GPO installs at each computer's next restart.

   ```powershell
   gpupdate /force
   powershell -ExecutionPolicy Bypass -File .\Deploy-SiemAuditPolicy.ps1 -Mode Verify
   ```

**Unattended (RMM or runbook):** this is the equivalent of option 1:

```powershell
powershell -ExecutionPolicy Bypass -File .\Deploy-SiemAuditPolicy.ps1 -Mode Full -Target All -AcceptEula -Force `
    -SysmonConfigUrl https://example.com/mssp-sysmon.xml -SysmonExisting Keep
```

`-Force` answers yes to the prompts: installing GPMC if it's missing, restarting CertSvc on each CA, and removing the PowerShell 2.0 engine in Local mode. Without `-Force`, an unattended run skips those actions and prints the manual step instead.

Two decisions are always separate, explicit flags because they affect the client:
- `-AcceptEula` accepts the Sysinternals license, which the installer fallback needs.
- `-SysmonExisting Overwrite` replaces the config of a Sysmon the client already runs. Unattended runs default to `Keep`.

**Standalone server:** `-Mode Local` (audit settings), then `-Mode SysmonLocal`, or menu option 6 for both.

**Other ways to run it:** paste the whole script into PowerShell ISE and press F5 to get the menu, or run it from a URL you host: `& ([scriptblock]::Create((irm https://<your-host>/Deploy-SiemAuditPolicy.ps1))) -Mode Verify`.

## Automated steps and their manual fallbacks

| Step | Automated by | If it can't run, the script prints |
|---|---|---|
| Group Policy Management tools | Asks to run `Install-WindowsFeature GPMC` (server) or the RSAT capability (Windows 10/11). Installs without asking with `-Force` | The install command and the Server Manager / Optional Features path |
| Audit GPOs + WMI filters | Writes the GPOs straight to SYSVOL/AD | GPMC click-path for every setting, plus the WMI filter queries |
| Sysmon (domain) | One GPO per selected target, `<prefix> - Sysmon - <Workstations\|Servers\|Domain Controllers>`, scoped exactly like that role's audit GPO (same WMI filter or the DC OU). Each holds the checked config, the Microsoft-signed installer as a fallback, and a startup script | GPO names and links, file list, the full startup script to paste |
| Sysmon (one host) | Built-in Sysmon feature (`Enable-WindowsOptionalFeature -FeatureName Sysmon`, then `sysmon -i`). If the OS doesn't offer it or enabling fails, the signature-checked Sysinternals installer. The log is sized to 256 MB | Built-in and installer commands, plus the existing-install check |
| Remove PowerShell 2.0 engine | Local mode asks to remove it (or removes it with `-Force`); Verify flags it as WARN | The `dism /disable-feature` command |
| DCSync auditing | Adds Success audit for Everyone on the three replication rights on the domain root (event 4662) | ADUC > Advanced > Auditing click-path |
| AD CS auditing | Finds every enterprise CA in AD, sets `CA\AuditFilter 127`, and restarts CertSvc (asks first, or `-Force`) | `certutil -setreg` + restart commands per CA |
| PowerShell 7 event log | Runs `RegisterManifest.ps1` when PowerShell 7 is installed. Local mode does it directly; the Sysmon startup script does it on every domain computer | The command |
| Local audit settings | `auditpol`, registry, `wevtutil` | Every exact `auditpol` / `reg add` / `wevtutil` command for the role, ready to paste |

### Sysmon

**Config:** pass `-SysmonConfigUrl <url>` (or a file path) to use your own MSSP config. Without it, the menu asks, and unattended runs use SwiftOnSecurity's `sysmon-config`. Every config is checked to be Sysmon XML before it's used.

**Built-in first:** newer Windows builds include Sysmon as an optional feature, which Windows Update keeps current. The script uses it wherever `dism /online /get-featureinfo /featurename:Sysmon` finds it. Elsewhere (Windows 10, Server 2016-2022, older 11 builds), or if enabling it fails, the script falls back to the Sysinternals installer. It refuses any installer binary that doesn't carry a valid Microsoft signature. Only the fallback needs the Sysinternals license (`-AcceptEula`).

**Existing Sysmon:** Microsoft doesn't support running built-in and standalone Sysmon side by side, so the script never stacks a second install.
- **One computer:** if Sysmon is already installed, it asks whether to overwrite its config with yours. `-SysmonExisting Keep|Overwrite` answers for unattended runs; the default is Keep. Either way the installed Sysmon itself isn't touched.
- **Domain:** you're asked once when you deploy, and the answer goes into the GPO. On each computer at restart, the startup script:

| Computer state | What the startup script does |
|---|---|
| No Sysmon | Installs built-in Sysmon if the OS has it, otherwise the installer copy in the GPO |
| Sysmon installed by someone else, Keep chosen | Nothing |
| Sysmon installed by someone else, Overwrite chosen | Applies your config only. The installed Sysmon is never replaced |
| Standalone Sysmon installed by this GPO, OS now offers built-in | Migrates to built-in once. If that fails, it stays on the installer version and stops retrying |
| Standalone Sysmon installed by this GPO, newer installer in the GPO | Upgrades |
| Anything else this GPO installed | Re-applies the config |

To roll out a new config or installer version, re-run `-Mode SysmonDomain` with the same targets.

**Offline environments:** if the DC has no internet access, download the installer and config on another machine, copy them over, and point the script at them: `-SysmonZip C:\temp\Sysmon.zip -SysmonConfigUrl C:\temp\sysmonconfig.xml`. `-SysmonZip` also accepts a folder of extracted `Sysmon*.exe` files.

### PowerShell 5.1 logging

Windows PowerShell 5.1 logging is part of every audit GPO and of Local mode:
- script block logging (4104);
- module logging for all modules (4103);
- a 256 MB `PowerShell/Operational` log;
- a 256 MB classic `Windows PowerShell` log (400/403/600/800 engine and provider events).

PowerShell 7 gets the same settings separately.

The **PowerShell 2.0 engine** (`powershell -version 2`) bypasses all of that logging, so Verify flags it as WARN and Local mode offers to remove it. It isn't removed through the GPOs, because a few legacy apps still need it. Remove it per host after checking. Windows 11 24H2 and Server 2025 no longer ship it.

## What Domain mode does

| GPO | Linked to | Applies to | Role differences |
|---|---|---|---|
| `SIEM Audit Policy - Workstations` | Domain root | WMI filter `ProductType = 1` (client OS) | Sensitive Privilege Use = Failure only; 1 GB Security log |
| `SIEM Audit Policy - Servers` | Domain root | WMI filter `ProductType = 3` (member servers) | Full baseline; 2 GB Security log |
| `SIEM Audit Policy - Domain Controllers` | `OU=Domain Controllers` | Domain controllers | Full baseline; ~4 GB Security log; NTLM-in-domain auditing |

Each workstation and server GPO is linked at the domain root and scoped by a **WMI filter** of the same name, which the script creates or updates. That way each GPO reaches every computer of its type, wherever it sits in the client's OU structure, and the script needs no client-specific OU names. Domain controllers have `ProductType = 2`, so neither filter matches them and the three GPOs never overlap. To scope a GPO to particular OUs instead, deploy it with `-NoLink` and link it by hand; the WMI filter still keeps it on the right OS type.

- **Deploy all or one:** use the menu's "which computers?" prompt, or `-Target`. Deploying one GPO leaves the others untouched.
- **Idempotent:** re-running the script rebuilds the selected GPOs to exactly match the script. To change settings, edit the tables at the top of the script and re-run it. Don't hand-edit the GPOs.
- **Non-disruptive links:** each new link is added at the *lowest* precedence at its level, so existing hardening GPOs keep winning any conflicts. All NTLM settings are audit-only and never block anything.
- **Conflict warning:** at the end, the script lists any other GPO that also defines Advanced Audit Policy, because one of those could override this baseline. Review them, or raise this GPO's link order.
- **Computer settings only:** User settings are disabled on every GPO. The policy version is stamped in the GPO comment.
- **What it writes:** `audit.csv` (Advanced Audit Policy), `GptTmpl.inf` (Security Options) and `Registry.pol` (everything else) in SYSVOL. It also registers the client-side extensions and bumps the GPO version.

**Upgrading from v1.0:** v1.0 created a single `SIEM Audit Policy - All Computers` GPO. After you deploy the Workstations and Servers GPOs, remove it with `Remove-GPO -Name "SIEM Audit Policy - All Computers"`. The script warns you if it still exists, but never deletes it on its own.

**Rollback:** `Remove-GPO -Name "SIEM Audit Policy - Workstations"` (and the same for Servers, Domain Controllers and each `SIEM Audit Policy - Sysmon - <target>`). The WMI filters are shared by the audit and Sysmon GPOs, and can be deleted in GPMC under *WMI Filters*. Removing a Sysmon GPO does not uninstall Sysmon. On each host, run `sysmon -u` for built-in Sysmon or `C:\Windows\Sysmon64.exe -u` for standalone. Audit policy settings are not tattooed, so clients revert at the next refresh. Registry-based event log sizes stay as they are, which is harmless.

---

## Settings and rationale

The baseline is Microsoft's Windows Security Baseline and its audit policy recommendations, CIS L1, and the logging guidance from NSA/CISA and the Australian Cyber Security Centre ("Windows Event Logging and Forwarding"). It's tuned for detection value per GB ingested. Subcategories that only fire on certain roles (DC, CA, NPS, file server) produce no events elsewhere, so every role keeps them. The only per-role differences are the ones in the GPO table above. They're defined with `Override` entries in the script, and `-Mode Show -Role <role>` prints the exact set for a role.

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
| Privilege Use | Sensitive Privilege Use | S/F (workstations: F) | 4673/4674. Success on workstations is mostly browser and AV noise |
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
| PowerShell Script Block Logging (PowerShell 5.1 + PowerShell 7) | Enabled | 4104: deobfuscated script content |
| PowerShell Module Logging, all modules (`*`) | Enabled | 4103: pipeline execution detail |
| Restrict NTLM: Audit incoming NTLM traffic | All accounts | NTLM visibility (Microsoft-Windows-NTLM/Operational 8001-8004). Audit only |
| Restrict NTLM: Outgoing NTLM traffic | Audit all | Audit only, does not block |
| Restrict NTLM: Audit NTLM authentication in this domain (DC GPO) | Enable all | Shows which servers or apps still use NTLM |
| Security log size | Workstations 1 GB, servers 2 GB, DCs ~4 GB; overwrite as needed | Local buffer if the SIEM agent or forwarder is down. Logging never stops |
| System / Application log size | 128 MB, overwrite | |
| Windows PowerShell log size | 256 MB | |
| Operational channels enabled and sized | PowerShell/Operational 256 MB, TaskScheduler 64 MB, NTLM 64 MB, Defender 64 MB, WMI-Activity 32 MB, DriverFrameworks-UserMode 32 MB | TaskScheduler and DriverFrameworks are off by default |

Channel enable and size settings delivered by GPO take effect after a **reboot**. Local mode applies them immediately with `wevtutil`.

---

## Still outside the script

1. **Collection:** point your SIEM agent or Windows Event Forwarding at the Security, System, PowerShell/Operational, PowerShellCore/Operational, Windows PowerShell, TaskScheduler/Operational, NTLM/Operational, Defender/Operational, WMI-Activity/Operational and Sysmon/Operational channels.
2. **Wider AD object SACLs**, if you want 5136 coverage beyond the default SACLs. Microsoft Defender for Identity documents the recommended set. The script only adds the DCSync rules.
3. **DNS Server analytic logging** on DCs, if DNS query visibility is needed. It's high volume.

## Noise tuning (ingest cost)

If ingest volume is a problem, filter these at the collector before reducing auditing at the source:

- **4673/4674 Sensitive Privilege Use:** already failure-only on workstations. If it's still noisy on servers, filter by process at the collector rather than turning it off.
- **4662 on DCs:** keep only events whose Properties contain the replication GUIDs (`1131f6aa-...`, `1131f6ad-...`, `89e95b76-...`) or that touch sensitive objects.
- **5140 File Share:** high on file servers. Keep `ADMIN$`, `C$` and `IPC$`.
- **4634 Logoff and 4627 Group Membership:** safe to drop if session tracking isn't used.

## Customizing

All settings live in three tables at the top of the script: `$AuditSettings`, `$RegistrySettings` and `$ChannelSettings`. Domain, Local, Verify and Show modes all read from those tables, so one edit changes all four. To make a setting different for one role, add `Override = @{ Workstation = <value> }` (or `Server` / `DomainController`) to its row. To limit a registry setting to certain roles, use `Scope = @('DomainController')`. GPO names, links and WMI queries are in `$GpoTargets`. Bump `$PolicyVersion` when you change anything, so you can see which version a client is running in the GPO comment.

## Testing

```powershell
. .\Deploy-SiemAuditPolicy.ps1          # dot-source: loads functions without running
New-AuditCsvContent Workstation          # inspect generated audit.csv for a role
New-GptTmplContent (Get-DesiredRegistry DomainController)
$d = New-SysmonWorkDir; Get-SysmonBinaries $d; Get-SysmonConfigFile $d   # download + verify, no install
New-SysmonStartupCmd                     # the Sysmon GPO startup script
.\Deploy-SiemAuditPolicy.ps1 -Mode Show -Role Server
.\Deploy-SiemAuditPolicy.ps1 -Mode Manual -Role Workstation
.\Deploy-SiemAuditPolicy.ps1 -Mode Full -WhatIf
```
