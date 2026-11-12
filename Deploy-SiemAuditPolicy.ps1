<#
.SYNOPSIS
    SIEM-ready Windows security logging: audit policy GPOs, Sysmon, AD/ADCS auditing,
    plus a read-only verifier. One self-contained file.

.DESCRIPTION
    Run with no parameters for a menu, or with -Help for a one-screen usage summary.
    Every automated step prints exact manual instructions if it cannot complete;
    -Mode Manual prints all manual instructions without changing anything.

.NOTES
    Keep this file ASCII-only so it survives copy/paste and Windows PowerShell 5.1.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('', 'Full', 'Domain', 'SysmonDomain', 'AdAudit', 'Local', 'LocalAll', 'SysmonLocal', 'Verify', 'Show', 'Manual', 'Help')]
    [string]$Mode = '',
    # All|Workstations|Servers|DomainControllers; "Workstations,Servers" also accepted (RMM / -File).
    [string[]]$Target = @('All'),
    [ValidateSet('Auto', 'Workstation', 'Server', 'DomainController')]
    [string]$Role = 'Auto',
    [string]$GpoPrefix = 'SIEM Audit Policy',
    [switch]$NoLink,
    [string]$Server = '',
    [string]$SysmonZip = 'https://download.sysinternals.com/files/Sysmon.zip',
    [Alias('SysmonConfigUrl')]
    [string]$SysmonConfig = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [ValidateSet('', 'Keep', 'Overwrite')]
    [string]$SysmonExisting = '',
    [switch]$AcceptEula,
    [switch]$Force,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# RMM agents (e.g. Kaseya) may start 32-bit PowerShell, where System32 and dism point at
# the 32-bit view. Re-run in 64-bit Windows PowerShell with the same parameters.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $MyInvocation.InvocationName -ne '.') {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if ($PSCommandPath -and (Test-Path $ps64)) {
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($k in @($PSBoundParameters.Keys)) {
            $v = $PSBoundParameters[$k]
            if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $relaunch += "-$k" } }
            elseif ("$(@($v) -join ',')" -ne '') { $relaunch += "-$k"; $relaunch += (@($v) -join ',') }
        }
        Write-Host 'Started in 32-bit PowerShell; re-running in 64-bit PowerShell.'
        & $ps64 @relaunch
        exit $LASTEXITCODE
    }
    Write-Warning 'Running in 32-bit PowerShell on 64-bit Windows; Sysmon steps may fail. Run the script from 64-bit PowerShell.'
}

# RMM script variables (e.g. NinjaOne) arrive as environment variables SIEM_<PARAMETER>,
# e.g. SIEM_MODE=LocalAll, SIEM_ACCEPTEULA=true. A command-line parameter always wins.
$envSet = @{}
foreach ($pair in @(@('Mode', 'MODE'), @('Target', 'TARGET'), @('Role', 'ROLE'), @('GpoPrefix', 'GPOPREFIX'), @('Server', 'SERVER'),
        @('SysmonZip', 'SYSMONZIP'), @('SysmonConfig', 'SYSMONCONFIG'), @('SysmonConfig', 'SYSMONCONFIGURL'), @('SysmonExisting', 'SYSMONEXISTING'))) {
    $ev = [Environment]::GetEnvironmentVariable("SIEM_$($pair[1])")
    if ([string]::IsNullOrWhiteSpace($ev) -or $PSBoundParameters.ContainsKey($pair[0]) -or $envSet.ContainsKey($pair[0])) { continue }
    try { Set-Variable -Name $pair[0] -Value $ev.Trim() } catch { throw "Environment variable SIEM_$($pair[1]) has an invalid value: '$ev'" }
    $envSet[$pair[0]] = $true
}
foreach ($n in @('AcceptEula', 'Force', 'NoLink')) {
    $ev = [Environment]::GetEnvironmentVariable("SIEM_$($n.ToUpper())")
    if (-not $PSBoundParameters.ContainsKey($n) -and "$ev".Trim() -match '^(1|true|yes|y|on)$') { Set-Variable -Name $n -Value ([switch]$true) }
}

# Normalize -Target: accept arrays, "a,b" strings and any letter case.
$ValidTargets = @('All', 'Workstations', 'Servers', 'DomainControllers')
$Target = @($Target | ForEach-Object { "$_" -split '[,;\s]+' } | Where-Object { $_ } | ForEach-Object {
        $t = $_; $hit = @($ValidTargets | Where-Object { $_ -eq $t })
        if ($hit.Count -eq 0) { throw "Invalid -Target '$t'. Use: $($ValidTargets -join ', ')" }
        $hit[0]
    } | Select-Object -Unique)
if ($Target.Count -eq 0) { $Target = @('All') }

$PolicyVersion = '1.3.0'
$script:DryRun = [bool]$WhatIfPreference
if ("$([Environment]::GetEnvironmentVariable('SIEM_WHATIF'))".Trim() -match '^(1|true|yes|y|on)$') { $script:DryRun = $true }
$script:ExitCode = 0               # 0 OK, 1 steps need manual completion / bad invocation, 2 Verify found failures
$script:Interactive = $false       # true when the menu is used (prompts allowed)
$script:Failed = New-Object System.Collections.Generic.List[string]
$script:DomainCtx = $null
$script:SysmonConfigGiven = $PSBoundParameters.ContainsKey('SysmonConfig') -or $envSet.ContainsKey('SysmonConfig')
$script:SysmonConfigSource = $null
$script:SysmonExistingAnswer = $null
$script:AcceptEulaAnswered = $false

# =====================================================================================
#  SETTINGS - single source of truth. Edit here; every mode reads from these tables.
#  Roles: Workstation, Server, DomainController.
#  Value: 1 = Success, 2 = Failure, 3 = Success and Failure
#  Override = @{ <Role> = <value> } changes the value for specific roles only.
#  Subcategories that only fire on certain roles (DC, CA, NPS, file server) are
#  harmless elsewhere, so they stay in every role's set.
# =====================================================================================
$AuditSettings = @(
    # --- Account Logon
    @{ Name = 'Credential Validation';              Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4774-4777 (NTLM auth, password spray)' }
    @{ Name = 'Kerberos Authentication Service';    Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4768, 4771, 4772 (TGT; AS-REP roast, spray) - DC' }
    @{ Name = 'Kerberos Service Ticket Operations'; Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4769, 4770, 4773 (Kerberoasting) - DC' }
    @{ Name = 'Other Account Logon Events';         Guid = '{0CCE9241-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4649 and misc' }
    # --- Account Management
    @{ Name = 'Application Group Management';       Guid = '{0CCE9239-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4783-4792' }
    @{ Name = 'Computer Account Management';        Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4741-4743 (RBCD / machine account abuse)' }
    @{ Name = 'Distribution Group Management';      Guid = '{0CCE9238-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4744-4753, 4759-4763' }
    @{ Name = 'Other Account Management Events';    Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4782, 4793' }
    @{ Name = 'Security Group Management';          Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4727-4737, 4754-4758, 4764, 4799 (privileged group changes)' }
    @{ Name = 'User Account Management';            Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4720-4726, 4738, 4740, 4767, 4781, 4794, 4798' }
    # --- Detailed Tracking
    @{ Name = 'DPAPI Activity';                     Guid = '{0CCE922D-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4692-4695 (DPAPI backup key theft on DCs)' }
    @{ Name = 'Plug and Play Events';               Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Value = 1; Events = '6416 (new external device)' }
    @{ Name = 'Process Creation';                   Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4688 with command line, 4696' }
    # --- DS Access (DC only)
    @{ Name = 'Directory Service Access';           Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4661, 4662 (DCSync detection) - DC' }
    @{ Name = 'Directory Service Changes';          Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '5136-5141 (AD object/GPO changes) - DC' }
    # --- Logon/Logoff
    @{ Name = 'Account Lockout';                    Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4625 (lockout)' }
    @{ Name = 'Group Membership';                   Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Value = 1; Events = '4627' }
    @{ Name = 'Logoff';                             Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Value = 1; Events = '4634, 4647' }
    @{ Name = 'Logon';                              Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4624, 4625, 4648, 4675' }
    @{ Name = 'Network Policy Server';              Guid = '{0CCE9243-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '6272-6280 (NPS/RADIUS only)' }
    @{ Name = 'Other Logon/Logoff Events';          Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4778, 4779 (RDP reconnect), 4800-4803, 5632' }
    @{ Name = 'Special Logon';                      Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4672, 4964 (admin logons)' }
    # --- Object Access
    @{ Name = 'Certification Services';             Guid = '{0CCE9221-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4870-4900 (AD CS abuse; CA only, needs CA AuditFilter)' }
    @{ Name = 'Detailed File Share';                Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Value = 2; Events = '5145 failures only (success is very noisy)' }
    @{ Name = 'File Share';                         Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '5140, 5142-5144 (ADMIN$/C$ lateral movement)' }
    @{ Name = 'File System';                        Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4656, 4663, 4670 (only where SACLs are set)' }
    @{ Name = 'Other Object Access Events';         Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4698-4702 (scheduled tasks), 5148-5149' }
    @{ Name = 'Registry';                           Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4657, 4663 (only where SACLs are set)' }
    @{ Name = 'Removable Storage';                  Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4663 on USB media' }
    # --- Policy Change
    @{ Name = 'Audit Policy Change';                Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4719, 4907, 4912 (audit tampering)' }
    @{ Name = 'Authentication Policy Change';       Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4706, 4707, 4713, 4716, 4739, 4865-4867 (trusts)' }
    @{ Name = 'Authorization Policy Change';        Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Value = 1; Events = '4704, 4705 (user rights changes)' }
    @{ Name = 'MPSSVC Rule-Level Policy Change';    Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4946-4950 (firewall rule changes)' }
    @{ Name = 'Other Policy Change Events';         Guid = '{0CCE9234-69AE-11D9-BED3-505054503030}'; Value = 2; Events = '6144, 6145, 4714 failures' }
    # --- Privilege Use
    @{ Name = 'Sensitive Privilege Use';            Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4673, 4674, 4985 (workstations: failure only - success is browser/AV noise)'; Override = @{ Workstation = 2 } }
    # --- System
    @{ Name = 'IPsec Driver';                       Guid = '{0CCE9213-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4960-4965, 5478-5485' }
    @{ Name = 'Other System Events';                Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '5024-5037, 5058, 5059 (firewall service, key ops)' }
    @{ Name = 'Security State Change';              Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4608, 4616 (time change), 4621' }
    @{ Name = 'Security System Extension';          Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4697 (service installed), 4610, 4611, 4614, 4622' }
    @{ Name = 'System Integrity';                   Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4612, 4615, 4618, 4816, 5038, 5056-5062, 6281' }
)

# Registry-backed settings. Kind:
#   Reg    -> written to Registry.pol (Administrative Templates / extra registry settings)
#   SecOpt -> written to GptTmpl.inf (Security Options). Must be REG_DWORD.
# Scope: All, or an array of roles. Override = @{ <Role> = <value> }. Compare: Equal or Min.
$PsPol   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$Ps7Pol  = 'HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore'
$EvtPol  = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog'
$RegistrySettings = @(
    @{ Kind = 'SecOpt'; Scope = 'All'; Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'Audit: Force audit policy subcategory settings to override category settings' }
    @{ Kind = 'SecOpt'; Scope = 'All'; Key = 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'AuditReceivingNTLMTraffic'; Type = 'DWord'; Value = 2; Compare = 'Equal'
       Purpose = 'Network security: Restrict NTLM: Audit incoming NTLM traffic = all accounts (audit only)' }
    @{ Kind = 'SecOpt'; Scope = 'All'; Key = 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Type = 'DWord'; Value = 1; Compare = 'Min'
       Purpose = 'Network security: Restrict NTLM: Outgoing NTLM traffic = audit all (does not block)' }
    @{ Kind = 'SecOpt'; Scope = @('DomainController'); Key = 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'AuditNTLMInDomain'; Type = 'DWord'; Value = 7; Compare = 'Equal'
       Purpose = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain = enable all (DC)' }

    @{ Kind = 'Reg'; Scope = 'All'; Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'Include command line in process creation events (4688)' }

    @{ Kind = 'Reg'; Scope = 'All'; Key = "$PsPol\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'PowerShell 5.1 script block logging (4104)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$PsPol\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'PowerShell 5.1 module logging (4103)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$PsPol\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Compare = 'Equal'
       Purpose = 'PowerShell 5.1 module logging for all modules' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$Ps7Pol\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'PowerShell 7 script block logging' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$Ps7Pol\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'PowerShell 7 module logging' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$Ps7Pol\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Compare = 'Equal'
       Purpose = 'PowerShell 7 module logging for all modules' }

    # Classic event log sizes (KB) and overwrite-as-needed retention.
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\Security"; Name = 'MaxSize'; Type = 'DWord'; Value = 1048576; Compare = 'Min'
       Override = @{ Server = 2097152; DomainController = 4194240 }
       Purpose = 'Security log max size KB (workstation 1 GB, server 2 GB, DC ~4 GB)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\Security"; Name = 'Retention'; Type = 'String'; Value = '0'; Compare = 'Equal'
       Purpose = 'Security log: overwrite events as needed (never stop logging)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\System"; Name = 'MaxSize'; Type = 'DWord'; Value = 131072; Compare = 'Min'
       Purpose = 'System log max size KB (128 MB)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\System"; Name = 'Retention'; Type = 'String'; Value = '0'; Compare = 'Equal'
       Purpose = 'System log: overwrite as needed' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\Application"; Name = 'MaxSize'; Type = 'DWord'; Value = 131072; Compare = 'Min'
       Purpose = 'Application log max size KB (128 MB)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\Application"; Name = 'Retention'; Type = 'String'; Value = '0'; Compare = 'Equal'
       Purpose = 'Application log: overwrite as needed' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell'; Name = 'MaxSize'; Type = 'DWord'; Value = 268435456; Compare = 'Min'
       Purpose = 'PowerShell 5.1 "Windows PowerShell" log max size bytes (256 MB; 400/403/600/800 events)' }
)

# Operational channels to enable and size (bytes). Written as registry under
# WINEVT\Channels in GPO mode (takes effect after reboot); applied live in Local mode.
$ChannelSettings = @(
    @{ Name = 'Microsoft-Windows-PowerShell/Operational';                MaxBytes = 268435456; Purpose = 'PowerShell 5.1 module and script block events (4103/4104)' }
    @{ Name = 'Microsoft-Windows-TaskScheduler/Operational';             MaxBytes = 67108864;  Purpose = 'Scheduled task registration/execution (106, 140, 141, 200, 201)' }
    @{ Name = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'; MaxBytes = 33554432;  Purpose = 'USB/device connect history (2003, 2100)' }
    @{ Name = 'Microsoft-Windows-NTLM/Operational';                      MaxBytes = 67108864;  Purpose = 'NTLM audit events (8001-8004) from the NTLM audit settings' }
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational';          MaxBytes = 67108864;  Purpose = 'Defender detections and tampering (1116, 1117, 5001, 5007)' }
    @{ Name = 'Microsoft-Windows-WMI-Activity/Operational';              MaxBytes = 33554432;  Purpose = 'WMI persistence/execution (5857-5861)' }
)
$ChannelRoot = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'

# GPOs created in Domain mode. Link 'DomainRoot' or 'DomainControllersOU'.
# Win32_OperatingSystem.ProductType: 1 = workstation, 2 = domain controller, 3 = server.
$GpoTargets = @(
    @{ Target = 'Workstations';      Role = 'Workstation';      Suffix = 'Workstations';       Link = 'DomainRoot'
       Wql = 'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "1"' }
    @{ Target = 'Servers';           Role = 'Server';           Suffix = 'Servers';            Link = 'DomainRoot'
       Wql = 'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "3"' }
    @{ Target = 'DomainControllers'; Role = 'DomainController'; Suffix = 'Domain Controllers'; Link = 'DomainControllersOU'
       Wql = $null }
)

# GPO client-side extension GUID pairs [CSE][Tool]
$CseSecurity = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
$CseAudit    = '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'
$CseRegistry = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}'
$CseScripts  = '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}'

# Sysmon (Microsoft Sysinternals). Binaries must carry a valid Microsoft signature.
$SysmonChannel   = 'Microsoft-Windows-Sysmon/Operational'
$SysmonLogBytes  = 268435456
$SysmonEulaUrl   = 'https://learn.microsoft.com/sysinternals/license-terms'

# AD replication extended rights audited on the domain root (DCSync detection, event 4662).
$ReplicationRights = @(
    @{ Name = 'DS-Replication-Get-Changes';                 Guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }
    @{ Name = 'DS-Replication-Get-Changes-All';             Guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }
    @{ Name = 'DS-Replication-Get-Changes-In-Filtered-Set'; Guid = '89e95b76-444d-4c62-991a-0facbeda640c' }
)
$AdcsAuditFilter = 127   # all 7 AD CS audit categories

# =====================================================================================
#  Helpers
# =====================================================================================
function Write-Step([string]$Text) { Write-Host "[*] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text){ Write-Host "[!] $Text" -ForegroundColor Yellow }

# -WhatIf / menu "preview": print the action instead of doing it.
function Test-ShouldRun([string]$Target, [string]$Action) {
    if ($script:DryRun) { Write-Host "What if: $Action -> $Target" -ForegroundColor DarkGray; return $false }
    return $true
}

# Yes/no prompt. Menu runs ask; scripted runs answer with -Force (otherwise "no").
function Confirm-Step([string]$Question) {
    if ($Force) { return $true }
    if (-not $script:Interactive) { return $false }
    return ((Read-Host "$Question [y/N]") -match '^(y|yes)$')
}

# Runs one automated step. On failure: records it and prints the manual instructions.
function Invoke-Step([string]$Title, [string]$ManualTopic, [scriptblock]$Action) {
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor White
    try {
        & $Action
    } catch {
        Write-Warn2 "Automated step failed: $($_.Exception.Message)"
        Write-Warn2 'Complete it manually:'
        Show-Manual $ManualTopic
        $script:Failed.Add($Title)
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Auto -> role from the OS product type (same test the GPO WMI filters use).
function Resolve-Role([string]$RoleName) {
    if ($RoleName -and $RoleName -ne 'Auto') { return $RoleName }
    switch ([int](Get-CimInstance -ClassName Win32_OperatingSystem).ProductType) {
        1 { return 'Workstation' }
        2 { return 'DomainController' }
        default { return 'Server' }
    }
}

# Value for a setting row on a given role (applies Override if present).
function Get-RoleValue([hashtable]$Setting, [string]$RoleName) {
    if ($Setting.ContainsKey('Override') -and $Setting.Override.ContainsKey($RoleName)) { return $Setting.Override[$RoleName] }
    return $Setting.Value
}

function Get-InclusionText([int]$Value) {
    switch ($Value) { 1 { 'Success' } 2 { 'Failure' } 3 { 'Success and Failure' } default { 'No Auditing' } }
}

# Audit settings resolved for a role.
function Get-DesiredAudit([string]$RoleName) {
    foreach ($a in $AuditSettings) {
        [pscustomobject]@{ Name = $a.Name; Guid = $a.Guid; Value = [int](Get-RoleValue $a $RoleName); Events = $a.Events }
    }
}

# Returns registry settings resolved for a role (channels expanded into registry rows).
function Get-DesiredRegistry([string]$RoleName) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in $RegistrySettings) {
        if ($s.Scope -ne 'All' -and @($s.Scope) -notcontains $RoleName) { continue }
        $v = Get-RoleValue $s $RoleName
        $out.Add([pscustomobject]@{ Kind = $s.Kind; Key = $s.Key; Name = $s.Name; Type = $s.Type; Value = $v; Compare = $s.Compare; Purpose = $s.Purpose; Channel = $null })
    }
    foreach ($c in $ChannelSettings) {
        $k = "$ChannelRoot\$($c.Name)"
        $out.Add([pscustomobject]@{ Kind = 'Reg'; Key = $k; Name = 'Enabled'; Type = 'DWord'; Value = 1; Compare = 'Equal'; Purpose = "Enable channel: $($c.Purpose)"; Channel = $c.Name })
        $out.Add([pscustomobject]@{ Kind = 'Reg'; Key = $k; Name = 'MaxSize'; Type = 'DWord'; Value = $c.MaxBytes; Compare = 'Min'; Purpose = "Channel size bytes: $($c.Name)"; Channel = $c.Name })
    }
    return $out
}

function New-AuditCsvContent([string]$RoleName) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($a in (Get-DesiredAudit $RoleName)) {
        $lines.Add((',System,Audit {0},{1},{2},,{3}' -f $a.Name, $a.Guid.ToLower(), (Get-InclusionText $a.Value), $a.Value))
    }
    return (($lines -join "`r`n") + "`r`n")
}

function New-GptTmplContent([object[]]$Desired) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('[Unicode]'); $lines.Add('Unicode=yes')
    $lines.Add('[Version]'); $lines.Add('signature="$CHICAGO$"'); $lines.Add('Revision=1')
    $lines.Add('[Registry Values]')
    foreach ($d in ($Desired | Where-Object { $_.Kind -eq 'SecOpt' })) {
        $path = 'MACHINE\' + $d.Key.Substring(5) + '\' + $d.Name   # strip "HKLM\"
        $lines.Add(('{0}=4,{1}' -f $path, $d.Value))
    }
    return (($lines -join "`r`n") + "`r`n")
}

# Merges CSE/tool GUID pairs into a gPCMachineExtensionNames string (sorted, deduped).
function Merge-GpoExtensionNames([string]$Existing, [string[]]$Pairs) {
    $map = @{}
    $all = @()
    if ($Existing) { $all += [regex]::Matches($Existing, '\[([^\]]+)\]') | ForEach-Object { $_.Groups[1].Value } }
    if ($Pairs)    { $all += $Pairs }
    foreach ($entry in $all) {
        $guids = @([regex]::Matches($entry, '\{[0-9A-Fa-f\-]+\}') | ForEach-Object { $_.Value.ToUpper() })
        if ($guids.Count -eq 0) { continue }
        $cse = $guids[0]
        if (-not $map.ContainsKey($cse)) { $map[$cse] = New-Object System.Collections.Generic.List[string] }
        for ($i = 1; $i -lt $guids.Count; $i++) { if (-not $map[$cse].Contains($guids[$i])) { $map[$cse].Add($guids[$i]) } }
    }
    $keys = [string[]]@($map.Keys)
    [Array]::Sort($keys, [StringComparer]::OrdinalIgnoreCase)
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in $keys) {
        $tools = [string[]]@($map[$k])
        [Array]::Sort($tools, [StringComparer]::OrdinalIgnoreCase)
        [void]$sb.Append('[').Append($k).Append(($tools -join '')).Append(']')
    }
    return $sb.ToString()
}

function Split-RegPath([string]$Key) {
    # 'HKLM\A\B' -> 'A\B'  (only HKLM is used by this script)
    if ($Key -notmatch '^HKLM\\') { throw "Only HKLM keys are supported: $Key" }
    return $Key.Substring(5)
}

function Get-LocalRegValue([string]$Key, [string]$Name) {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((Split-RegPath $Key))
    if ($null -eq $k) { return $null }
    try { return $k.GetValue($Name, $null) } finally { $k.Close() }
}

# Runs a native exe and captures output + exit code. Local 'Continue' stops Windows
# PowerShell 5.1 from turning stderr text into terminating errors.
function Invoke-NativeRaw([string]$Exe, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $out = @(& $Exe @Arguments 2>&1 | ForEach-Object { "$_" })
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
}

# Same, but throws with the last lines of output when the exit code is not 0.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $r = Invoke-NativeRaw $Exe $Arguments
    if ($r.Code -ne 0) {
        throw ("{0} {1} failed (exit {2}): {3}" -f [IO.Path]::GetFileName($Exe), ($Arguments -join ' '), $r.Code, (($r.Output | Select-Object -Last 3) -join ' '))
    }
}

function Test-ChannelExists([string]$Channel) {
    return ($null -ne (Get-LocalRegValue "$ChannelRoot\$Channel" 'OwningPublisher'))
}

# Effective channel config (Enabled = 1/0, MaxSize = bytes) as the Event Log service sees it.
function Get-ChannelConfig([string]$Channel) {
    $r = Invoke-NativeRaw 'wevtutil.exe' @('gl', $Channel, '/f:xml')
    if ($r.Code -ne 0 -or $r.Output.Count -eq 0) { return $null }
    $x = [xml]($r.Output -join '')
    $en = 0; if ($x.channel.enabled -eq 'true') { $en = 1 }
    return @{ Enabled = $en; MaxSize = [int64]$x.channel.logging.maxSize }
}

# =====================================================================================
#  Help and manual instructions
# =====================================================================================
function Show-Help {
    Write-Host @"

SIEM Audit Policy v$PolicyVersion - run in an elevated PowerShell. No parameters = menu.

  .\Deploy-SiemAuditPolicy.ps1 -Mode <mode> [options]

  Domain (on a DC, as Domain Admin; Windows PowerShell 5.1)    [-Target ...]
    Full          Audit GPOs + Sysmon GPOs + AD/ADCS auditing
    Domain        Audit policy GPOs
    SysmonDomain  Sysmon GPOs (install at restart; built-in Sysmon first)
    AdAudit       DCSync audit on domain root + AD CS audit on every CA
  This computer                                                [-Role ...]
    Local         Apply audit settings (+ remove PowerShell 2.0 engine)
    SysmonLocal   Install Sysmon now (built-in first, installer fallback)
    LocalAll      Local + SysmonLocal (workgroup / RMM)
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

  RMM / unattended: always pass -Mode (+ -AcceptEula -Force). Any option can also be
  set as environment variable SIEM_<OPTION> (SIEM_MODE=Verify, SIEM_FORCE=true).
  Exit code: 0 OK, 1 needs manual completion, 2 Verify found failures.

"@
}

# Startup script placed in each Sysmon GPO. Prefers the Windows built-in Sysmon feature,
# falls back to the Sysinternals binaries next to it, respects OVERWRITE_EXISTING for a
# Sysmon this GPO did not install, then registers the PowerShell 7 event manifest.
function New-SysmonStartupCmd {
    $t = @'
@echo off
rem Managed by Deploy-SiemAuditPolicy.ps1 - installs/updates Sysmon at computer startup.
setlocal EnableExtensions
set "SRC=%~dp0"
set "CFG=%SRC%sysmonconfig.xml"
set "EXE=Sysmon64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "EXE=Sysmon.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" if exist "%SRC%Sysmon64a.exe" set "EXE=Sysmon64a.exe"
set "BUILTIN=%SystemRoot%\System32\Sysmon.exe"
set "MARKDIR=%ProgramData%\SiemSysmon"
set "MARK=%MARKDIR%\managed.txt"
set "WANT="
set /p WANT=<"%SRC%version.txt"
set "OVR=0"
findstr /x /c:"OVERWRITE_EXISTING=1" "%SRC%options.txt" >nul 2>&1 && set "OVR=1"
set "STANDALONE="
for %%F in (Sysmon64.exe Sysmon64a.exe Sysmon.exe) do if not defined STANDALONE if exist "%SystemRoot%\%%F" set "STANDALONE=%SystemRoot%\%%F"
set "HASFEATURE=0"
dism /online /get-featureinfo /featurename:Sysmon >nul 2>&1 && set "HASFEATURE=1"
sc query SysmonDrv >nul 2>&1 && goto installed
sc query Sysmon >nul 2>&1 && goto installed
goto install

:installed
rem Installed by this GPO before -> keep it current. Installed by someone else -> only if allowed.
if exist "%MARK%" goto ours
if "%OVR%"=="1" goto configure
goto ps7

:ours
rem "foreign" = someone else's Sysmon whose config we were allowed to overwrite: config only.
set "HAVE="
set /p HAVE=<"%MARK%"
if /i "%HAVE%"=="foreign" goto configure
if not defined STANDALONE goto configure
rem Ours, standalone: move to built-in when the OS offers it (once), else upgrade if the version changed.
if "%HASFEATURE%"=="1" if not exist "%MARKDIR%\builtin-failed.txt" goto replace
if "%HAVE%"=="%WANT%" goto configure
:replace
"%STANDALONE%" -u force
set "STANDALONE="
goto install

:configure
set "CUR=%BUILTIN%"
if defined STANDALONE set "CUR=%STANDALONE%"
"%CUR%" -c "%CFG%"
if errorlevel 1 goto ps7
if not exist "%MARKDIR%" mkdir "%MARKDIR%"
if not exist "%MARK%" >"%MARK%" echo foreign
goto size

:install
if not "%HASFEATURE%"=="1" goto installer
dism /online /enable-feature /featurename:Sysmon /norestart /quiet >nul 2>&1
if not exist "%BUILTIN%" goto installer
"%BUILTIN%" -accepteula -i "%CFG%"
if errorlevel 1 goto installer
if not exist "%MARKDIR%" mkdir "%MARKDIR%"
if exist "%MARKDIR%\builtin-failed.txt" del "%MARKDIR%\builtin-failed.txt"
goto mark
:installer
"%SRC%%EXE%" -accepteula -i "%CFG%"
if errorlevel 1 goto ps7
if not exist "%MARKDIR%" mkdir "%MARKDIR%"
if "%HASFEATURE%"=="1" >"%MARKDIR%\builtin-failed.txt" echo built-in Sysmon could not be installed; using the installer
:mark
>"%MARK%" echo %WANT%

:size
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:__LOGBYTES__

:ps7
if exist "%ProgramFiles%\PowerShell\7\RegisterManifest.ps1" (
  wevtutil gp PowerShellCore >nul 2>&1 || "%ProgramFiles%\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File "%ProgramFiles%\PowerShell\7\RegisterManifest.ps1"
)
exit /b 0
'@
    return ($t.Replace('__LOGBYTES__', [string]$SysmonLogBytes) -replace "`r?`n", "`r`n")
}

function Show-Manual([string]$Topic) {
    $r = Resolve-Role $Role
    $p = $GpoPrefix
    $out = New-Object System.Collections.Generic.List[string]
    $all = ($Topic -eq 'All')

    if ($all -or $Topic -eq 'Prereqs') {
        $out.Add('--- PREREQUISITES (domain modes) ---')
        $out.Add('  Run on a domain-joined machine (ideally a DC) as Domain Admin, in elevated Windows PowerShell 5.1:')
        $out.Add('    powershell.exe -ExecutionPolicy Bypass -File .\Deploy-SiemAuditPolicy.ps1')
        $out.Add('  Group Policy Management tools:')
        $out.Add('  Server:        Install-WindowsFeature GPMC')
        $out.Add('                 (or Server Manager > Add Roles and Features > Features > Group Policy Management)')
        $out.Add('  Windows 10/11: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0')
        $out.Add('                 (or Settings > Optional features > Add > RSAT: Group Policy Management Tools)')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'Domain') {
        $out.Add('--- AUDIT GPOs (gpmc.msc, as Domain Admin) ---')
        $out.Add("  For each role (Workstation, Server, DomainController) create GPO ""$p - Workstations"" / ""- Servers"" / ""- Domain Controllers"":")
        $out.Add('  1. Right-click GPO > GPO Status > User Configuration Settings Disabled. Then Edit.')
        $out.Add('  2. Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy')
        $out.Add('     Configuration > Audit Policies: set every subcategory listed by  -Mode Show -Role <role>')
        $out.Add('  3. Security Settings > Local Policies > Security Options: set the "SecOpt" rows from that list:')
        $out.Add('     "Audit: Force audit policy subcategory settings..." = Enabled; "Network security: Restrict NTLM: Audit')
        $out.Add('     Incoming NTLM Traffic" = all accounts; "...Outgoing NTLM traffic to remote servers" = Audit all;')
        $out.Add('     DCs only: "...Audit NTLM authentication in this domain" = Enable all.')
        $out.Add('  4. Administrative Templates: System > Audit Process Creation > Include command line = Enabled;')
        $out.Add('     Windows Components > Windows PowerShell > Module Logging (module name *) and Script Block Logging = Enabled;')
        $out.Add('     Windows Components > Event Log Service > Application/Security/System: max size (KB) per -Mode Show,')
        $out.Add('     and "Control Event Log behavior when the log file reaches its maximum size" = Disabled.')
        $out.Add('  5. All other "Reg" rows (event channels, PowerShell 7, Windows PowerShell log): Preferences > Windows')
        $out.Add('     Settings > Registry > New > Registry Item, Action Update, Hive HKEY_LOCAL_MACHINE, path/value from -Mode Show.')
        $out.Add('  6. WMI Filters > New:')
        foreach ($t in $GpoTargets) { if ($t.Wql) { $out.Add("       ""$p - $($t.Suffix)"" :  $($t.Wql)") } }
        $out.Add('     On each of those GPOs: Scope tab > WMI Filtering > select the matching filter.')
        $out.Add('  7. Link Workstations + Servers GPOs to the domain root, the Domain Controllers GPO to OU=Domain Controllers.')
        $out.Add('  8. On a client: gpupdate /force, then run -Mode Verify.')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'Local') {
        $out.Add("--- AUDIT SETTINGS ON THIS COMPUTER (role: $r) - paste into an elevated Command Prompt ---")
        foreach ($a in (Get-DesiredAudit $r)) {
            $s = 'disable'; if ($a.Value -band 1) { $s = 'enable' }
            $f = 'disable'; if ($a.Value -band 2) { $f = 'enable' }
            $out.Add(('auditpol /set /subcategory:"{0}" /success:{1} /failure:{2}' -f $a.Guid, $s, $f))
        }
        foreach ($d in (Get-DesiredRegistry $r)) {
            if ($d.Channel) { continue }
            $t = 'REG_DWORD'; if ($d.Type -eq 'String') { $t = 'REG_SZ' }
            $out.Add(('reg add "{0}" /v "{1}" /t {2} /d "{3}" /f' -f $d.Key, $d.Name, $t, $d.Value))
        }
        foreach ($c in $ChannelSettings) { $out.Add(('wevtutil sl "{0}" /e:true /ms:{1}' -f $c.Name, $c.MaxBytes)) }
        $out.Add('rem Remove the PowerShell 2.0 engine (it bypasses PowerShell 5.1 logging); ignore "unknown feature" errors:')
        $out.Add('dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2Root /norestart')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'SysmonLocal' -or $Topic -eq 'SysmonDomain') {
        $out.Add('--- SYSMON ON ONE COMPUTER (elevated PowerShell) ---')
        $out.Add('  1. Already installed?  Get-Service sysmon*')
        $out.Add('     If yes, either keep it, or apply the MSSP config:  sysmon -c sysmonconfig.xml  (built-in), or')
        $out.Add('     C:\Windows\Sysmon64.exe -c sysmonconfig.xml  (standalone). Then skip to step 4.')
        $out.Add("  2. Download the config as sysmonconfig.xml:  $SysmonConfig")
        $out.Add('  3a. Built-in Sysmon (preferred; newer Windows 11 / Server builds). Check:')
        $out.Add('        dism /online /get-featureinfo /featurename:Sysmon     (error = not available, use 3b)')
        $out.Add('      Install:  Enable-WindowsOptionalFeature -Online -FeatureName Sysmon')
        $out.Add('                sysmon -accepteula -i sysmonconfig.xml')
        $out.Add("  3b. Installer fallback: download $SysmonZip, extract, check")
        $out.Add('      Sysmon64.exe > Properties > Digital Signatures shows Microsoft Corporation, then:')
        $out.Add("        Sysmon64.exe -accepteula -i sysmonconfig.xml   (accepts $SysmonEulaUrl)")
        $out.Add('      (32-bit Windows: Sysmon.exe, ARM64: Sysmon64a.exe)')
        $out.Add("  4. wevtutil sl $SysmonChannel /ms:$SysmonLogBytes")
        $out.Add('  No internet on the host? Download elsewhere, copy over, re-run with -SysmonZip <zip> -SysmonConfigUrl <xml>.')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'SysmonDomain') {
        $out.Add('--- SYSMON ON DOMAIN COMPUTERS (one GPO per target, startup script) ---')
        $out.Add('  1. Download the config and installer as in "Sysmon on one computer" steps 2 and 3b (no install).')
        $out.Add('  2. For each target, gpmc.msc > new GPO, User Configuration Settings Disabled:')
        foreach ($t in $GpoTargets) {
            $where = 'domain root, WMI filter "' + "$p - $($t.Suffix)" + '"'
            if ($t.Link -eq 'DomainControllersOU') { $where = 'OU=Domain Controllers' }
            $out.Add("       ""$p - Sysmon - $($t.Suffix)""  ->  link: $where")
        }
        $out.Add('  3. Edit > Computer Configuration > Policies > Windows Settings > Scripts > Startup > Show Files.')
        $out.Add('     Copy in: Sysmon.exe, Sysmon64.exe, Sysmon64a.exe, sysmonconfig.xml,')
        $out.Add('     version.txt (one line: Sysmon file version, e.g. 15.22),')
        $out.Add('     options.txt (one line: OVERWRITE_EXISTING=1 to replace configs of Sysmon already on hosts, else =0),')
        $out.Add('     and SiemSysmon.cmd with the content below. Add SiemSysmon.cmd as the startup script.')
        $out.Add('  4. Computers install Sysmon at their next restart.')
        $out.Add('  ----- SiemSysmon.cmd -----')
        foreach ($l in ((New-SysmonStartupCmd) -split "`r`n")) { $out.Add("  $l") }
        $out.Add('  --------------------------')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'AdAudit' -or $Topic -eq 'AdSacl') {
        $out.Add('--- DCSYNC AUDITING ON THE DOMAIN ROOT (on a DC) ---')
        $out.Add('  Active Directory Users and Computers > View > Advanced Features. Right-click the domain > Properties >')
        $out.Add('  Security > Advanced > Auditing > Add: Principal Everyone, Type Success, Applies to "This object only",')
        $out.Add('  tick: Replicating Directory Changes, Replicating Directory Changes All,')
        $out.Add('        Replicating Directory Changes In Filtered Set. OK.')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'AdAudit' -or $Topic -eq 'Adcs') {
        $out.Add('--- AD CS AUDITING (on each Certification Authority, elevated) ---')
        $out.Add("  certutil -setreg CA\AuditFilter $AdcsAuditFilter")
        $out.Add('  Restart-Service certsvc')
        $out.Add('  (or certsrv.msc > CA Properties > Auditing: tick all > OK and allow the service restart)')
        $out.Add('  Find the CAs: certutil -dump   (lists every enterprise CA as host\CA name)')
        $out.Add('')
    }
    if ($all -or $Topic -eq 'Verify') {
        $out.Add('--- VERIFY BY HAND ---')
        $out.Add('  auditpol /get /category:*     compare with -Mode Show')
        $out.Add('  gpresult /h gp.html           shows which GPO won each setting')
        $out.Add('  sc query Sysmon64             should be RUNNING')
        $out.Add('')
    }
    $out | ForEach-Object { Write-Host $_ }
}

# =====================================================================================
#  Show
# =====================================================================================
function Invoke-Show([string]$RoleName) {
    Write-Host ''
    Write-Host "SIEM audit policy v$PolicyVersion - settings for role: $RoleName" -ForegroundColor White
    Write-Host '(use -Role Workstation|Server|DomainController to see another role)'
    Write-Host ''
    Write-Host 'Advanced Audit Policy' -ForegroundColor White
    Get-DesiredAudit $RoleName | ForEach-Object { [pscustomobject]@{ Subcategory = $_.Name; Setting = (Get-InclusionText $_.Value); KeyEvents = $_.Events } } |
        Format-Table -AutoSize -Wrap | Out-Host
    Write-Host 'Registry / Security Options / Event Logs' -ForegroundColor White
    Get-DesiredRegistry $RoleName | Select-Object Kind, @{ n = 'Setting'; e = { "$($_.Key)\$($_.Name)" } }, Value, Purpose |
        Format-Table -AutoSize -Wrap | Out-Host
}

# =====================================================================================
#  Local
# =====================================================================================
function Invoke-Local([string]$RoleName) {
    if (-not $script:DryRun -and -not (Test-IsAdmin)) { throw 'Local mode must be run from an elevated (Run as administrator) PowerShell.' }

    $errs = 0
    Write-Step "Applying advanced audit policy for role '$RoleName' (auditpol)"
    foreach ($a in (Get-DesiredAudit $RoleName)) {
        $s = 'disable'; if ($a.Value -band 1) { $s = 'enable' }
        $f = 'disable'; if ($a.Value -band 2) { $f = 'enable' }
        if (Test-ShouldRun $a.Name "auditpol success:$s failure:$f") {
            $r = Invoke-NativeRaw 'auditpol.exe' @('/set', "/subcategory:$($a.Guid)", "/success:$s", "/failure:$f")
            if ($r.Code -ne 0) { Write-Warn2 "auditpol failed for $($a.Name) (exit $($r.Code))"; $errs++ }
        }
    }

    Write-Step 'Writing registry / security option values'
    foreach ($d in (Get-DesiredRegistry $RoleName)) {
        if ($d.Channel) { continue }   # channels handled with wevtutil below
        if (Test-ShouldRun "$($d.Key)\$($d.Name)" "Set $($d.Value)") {
            $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey((Split-RegPath $d.Key))
            try {
                $kind = [Microsoft.Win32.RegistryValueKind]::DWord
                if ($d.Type -eq 'String') { $kind = [Microsoft.Win32.RegistryValueKind]::String }
                $k.SetValue($d.Name, $d.Value, $kind)
            } finally { $k.Close() }
        }
    }

    Write-Step 'Enabling and sizing operational event channels'
    foreach ($c in $ChannelSettings) {
        if (-not (Test-ChannelExists $c.Name)) { Write-Warn2 "Channel not present on this OS, skipped: $($c.Name)"; continue }
        if (Test-ShouldRun $c.Name "wevtutil enable, max size $($c.MaxBytes)") {
            $r = Invoke-NativeRaw 'wevtutil.exe' @('sl', $c.Name, '/e:true', "/ms:$($c.MaxBytes)")
            if ($r.Code -ne 0) { Write-Warn2 "wevtutil failed for $($c.Name) (exit $($r.Code))"; $errs++ }
        }
    }
    if ($errs -gt 0) { throw "$errs local setting(s) could not be applied." }
    Write-Ok 'Local audit settings applied. (A domain GPO will override local settings.)'
}

# PowerShell 7 only writes to PowerShellCore/Operational once its manifest is registered.
function Register-Ps7Manifest {
    $dir = Join-Path $env:ProgramFiles 'PowerShell\7'
    $m = Join-Path $dir 'RegisterManifest.ps1'
    if (-not (Test-Path -LiteralPath $m)) { Write-Ok 'PowerShell 7 not installed - nothing to register.'; return }
    if ((Invoke-NativeRaw 'wevtutil.exe' @('gp', 'PowerShellCore')).Code -eq 0) { Write-Ok 'PowerShell 7 event manifest already registered.'; return }
    if (-not (Test-ShouldRun 'PowerShell 7' 'Register event manifest (PowerShellCore/Operational log)')) { return }
    Invoke-Native (Join-Path $dir 'pwsh.exe') @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $m)
    Write-Ok 'Registered PowerShell 7 event manifest.'
}

# PowerShell 2.0 engine state: Enabled / Removed / Unknown. Windows 11 24H2 and
# Server 2025 no longer ship it at all (reported as Removed).
function Get-PowerShellV2State {
    try {
        $f = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.FeatureName -like 'MicrosoftWindowsPowerShellV2*' })
    } catch { return 'Unknown' }
    if (@($f | Where-Object { [string]$_.State -eq 'Enabled' }).Count -gt 0) { return 'Enabled' }
    return 'Removed'
}

function Disable-PowerShellV2 {
    $state = Get-PowerShellV2State
    if ($state -eq 'Removed') { Write-Ok 'PowerShell 2.0 engine is not installed.'; return }
    if ($state -eq 'Unknown') { throw 'Could not read Windows optional features to check the PowerShell 2.0 engine.' }
    if (-not (Test-ShouldRun 'PowerShell 2.0 engine' 'Remove (it bypasses PowerShell 5.1 logging)')) { return }
    if (-not (Confirm-Step 'The PowerShell 2.0 engine lets attackers bypass PowerShell logging. Remove it?')) {
        Write-Warn2 'PowerShell 2.0 engine left installed (answer y or use -Force to remove it).'
        return
    }
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $r = Invoke-NativeRaw 'dism.exe' @('/online', '/disable-feature', "/featurename:$name", '/norestart', '/quiet')
        if ($r.Code -ne 0 -and $r.Code -ne 3010 -and $r.Code -ne -2146498548) { throw "Removing $name failed (exit $($r.Code))." }
    }
    Write-Ok 'PowerShell 2.0 engine removed.'
}

function Test-IsCaServer { return ($null -ne (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)) }

# =====================================================================================
#  Verify
# =====================================================================================
function Invoke-Verify([string]$RoleName) {
    if (-not (Test-IsAdmin)) { throw 'Verify mode must be run from an elevated (Run as administrator) PowerShell (auditpol needs it).' }
    Write-Step "Verifying this computer against the '$RoleName' baseline"
    $results = New-Object System.Collections.Generic.List[object]

    # auditpol /backup gives locale-independent numeric values keyed by GUID.
    $tmp = Join-Path $env:TEMP ("auditpol-{0}.csv" -f [guid]::NewGuid())
    $null = & auditpol.exe /backup /file:"$tmp"
    if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed (exit $LASTEXITCODE)" }
    try {
        $actual = @{}
        Import-Csv -Path $tmp | Where-Object { $_.'Subcategory GUID' } | ForEach-Object {
            $actual[$_.'Subcategory GUID'.ToUpper()] = [int]$_.'Setting Value'
        }
    } finally { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue }

    foreach ($a in (Get-DesiredAudit $RoleName)) {
        $have = 0
        if ($actual.ContainsKey($a.Guid.ToUpper())) { $have = $actual[$a.Guid.ToUpper()] }
        $status = 'FAIL'; if (($have -band $a.Value) -eq $a.Value) { $status = 'PASS' }
        $results.Add([pscustomobject]@{ Status = $status; Area = 'Audit'; Setting = $a.Name; Expected = (Get-InclusionText $a.Value); Actual = (Get-InclusionText $have) })
    }

    $legacy = Get-LocalRegValue 'HKLM\System\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    foreach ($d in (Get-DesiredRegistry $RoleName)) {
        if ($d.Channel) {
            $cfg = Get-ChannelConfig $d.Channel
            if ($null -eq $cfg) {
                $results.Add([pscustomobject]@{ Status = 'N/A'; Area = 'Channel'; Setting = "$($d.Channel) $($d.Name)"; Expected = $d.Value; Actual = 'channel not on this OS' })
                continue
            }
            $have = $cfg[$d.Name]
        } else {
            $have = Get-LocalRegValue $d.Key $d.Name
        }
        $ok = $false
        if ($null -ne $have) {
            if ($d.Compare -eq 'Min') { $ok = ([int64]$have -ge [int64]$d.Value) } else { $ok = ("$have" -eq "$($d.Value)") }
        }
        $status = 'FAIL'; if ($ok) { $status = 'PASS' }
        $area = 'Registry'; if ($d.Kind -eq 'SecOpt') { $area = 'SecOpt' }; if ($d.Channel) { $area = 'Channel' }
        $label = "$($d.Key.Split('\')[-1])\$($d.Name)"
        if ($d.Purpose -match '^PowerShell') { $label = $d.Purpose }
        if ($d.Channel) { $label = "$($d.Channel) $($d.Name)" }
        $shown = '<not set>'; if ($null -ne $have) { $shown = $have }
        $results.Add([pscustomobject]@{ Status = $status; Area = $area; Setting = $label; Expected = $d.Value; Actual = $shown })
    }

    # Sysmon (built-in or standalone)
    $sm = Get-SysmonState
    $st = 'not installed'
    if ($sm.Service) { $st = "$($sm.Service.Status) ($($sm.Kind) $($sm.Version))" }
    $ok = ($sm.Service -and $sm.Service.Status -eq 'Running')
    $results.Add([pscustomobject]@{ Status = $(if ($ok) { 'PASS' } else { 'FAIL' }); Area = 'Sysmon'; Setting = 'Sysmon service'; Expected = 'Running'; Actual = $st })

    # PowerShell 2.0 engine: "powershell -version 2" bypasses all PowerShell 5.1 logging.
    $v2 = Get-PowerShellV2State
    $v2Status = 'PASS'; if ($v2 -eq 'Enabled') { $v2Status = 'WARN' } elseif ($v2 -eq 'Unknown') { $v2Status = 'N/A' }
    $results.Add([pscustomobject]@{ Status = $v2Status; Area = 'PS5.1'; Setting = 'PowerShell 2.0 engine (logging bypass)'; Expected = 'Removed'; Actual = $v2 })

    # PowerShell 7 manifest (only if PS7 is installed)
    if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')) {
        $reg = ((Invoke-NativeRaw 'wevtutil.exe' @('gp', 'PowerShellCore')).Code -eq 0)
        $results.Add([pscustomobject]@{ Status = $(if ($reg) { 'PASS' } else { 'FAIL' }); Area = 'PS7'; Setting = 'PowerShellCore event manifest'; Expected = 'Registered'; Actual = $(if ($reg) { 'Registered' } else { 'Missing' }) })
    }

    # AD CS audit filter (only on a CA)
    if (Test-IsCaServer) {
        $r = Invoke-NativeRaw 'certutil.exe' @('-getreg', 'CA\AuditFilter')
        $val = '<unknown>'; if (($r.Output -join ' ') -match '\((\d+)\)') { $val = $Matches[1] }
        $results.Add([pscustomobject]@{ Status = $(if ($val -eq [string]$AdcsAuditFilter) { 'PASS' } else { 'FAIL' }); Area = 'ADCS'; Setting = 'CA\AuditFilter'; Expected = $AdcsAuditFilter; Actual = $val })
    }

    # DCSync audit rules on the domain root (only on a DC)
    if ($RoleName -eq 'DomainController') {
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $dn = [string]([ADSI]"LDAP://RootDSE").Properties['defaultNamingContext'].Value
            $miss = @((Get-ReplicationAuditState @{ Dc = $domain.PdcRoleOwner.Name; DN = $dn }).Missing)
            $results.Add([pscustomobject]@{ Status = $(if ($miss.Count -eq 0) { 'PASS' } else { 'FAIL' }); Area = 'AD SACL'; Setting = 'Replication rights audited (DCSync)'; Expected = 3; Actual = (3 - $miss.Count) })
        } catch {
            $results.Add([pscustomobject]@{ Status = 'N/A'; Area = 'AD SACL'; Setting = 'Replication rights audited (DCSync)'; Expected = 3; Actual = "cannot read SACL: $($_.Exception.Message)" })
        }
    }

    $results | Format-Table -AutoSize | Out-Host
    $fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    if ($fail -eq 0) {
        Write-Ok "All checks passed ($pass)."
    } else {
        Write-Warn2 "$fail check(s) FAILED, $pass passed."
        Write-Warn2 'If the GPO was just deployed run: gpupdate /force  (channel settings need a reboot).'
        Write-Warn2 'Use: gpresult /h gp.html  to find a higher-precedence GPO overriding these settings.'
        Write-Warn2 'Fix on this host: -Mode Local / -Mode SysmonLocal.  Step-by-step by hand: -Mode Manual.'
        if ("$legacy" -ne '1') { Write-Warn2 'Legacy audit policy is NOT overridden - advanced audit settings may be ignored.' }
    }
    return $results
}

# =====================================================================================
#  Domain
# =====================================================================================
function ConvertTo-LdapFilterValue([string]$Value) {
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
}

# Creates or updates a WMI filter (msWMI-Som object) and returns its ID, e.g. "{GUID}".
function Set-SiemWmiFilter {
    param([string]$Name, [string]$Wql, [string]$Dc, [string]$DomainDN)

    $somPath = "LDAP://$Dc/CN=SOM,CN=WMIPolicy,CN=System,$DomainDN"
    $ns      = 'root\CIMv2'
    $parm2   = '1;3;{0};{1};WQL;{2};{3};' -f $ns.Length, $Wql.Length, $ns, $Wql
    $now     = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss') + '.000000-000'
    $desc    = "Managed by Deploy-SiemAuditPolicy.ps1 v$PolicyVersion"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry($somPath)))
    $searcher.Filter = "(&(objectClass=msWMI-Som)(msWMI-Name=$(ConvertTo-LdapFilterValue $Name)))"
    $hit = $searcher.FindOne()

    if ($null -ne $hit) {
        $f = $hit.GetDirectoryEntry()
        $id = [string]$f.Properties['msWMI-ID'].Value
        if ([string]$f.Properties['msWMI-Parm2'].Value -ne $parm2) {
            $f.Properties['msWMI-Parm2'].Value      = $parm2
            $f.Properties['msWMI-Parm1'].Value      = $desc
            $f.Properties['msWMI-ChangeDate'].Value = $now
            $f.CommitChanges()
            Write-Ok "Updated WMI filter '$Name'"
        } else {
            Write-Ok "WMI filter '$Name' already up to date"
        }
        return $id
    }

    $id  = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
    $som = New-Object System.DirectoryServices.DirectoryEntry($somPath)
    $f   = $som.Children.Add("CN=$id", 'msWMI-Som')
    $f.Properties['msWMI-Name'].Value             = $Name
    $f.Properties['msWMI-Parm1'].Value            = $desc
    $f.Properties['msWMI-Parm2'].Value            = $parm2
    $f.Properties['msWMI-Author'].Value           = "$env:USERNAME"
    $f.Properties['msWMI-ID'].Value               = $id
    $f.Properties['msWMI-CreationDate'].Value     = $now
    $f.Properties['msWMI-ChangeDate'].Value       = $now
    $f.Properties['showInAdvancedViewOnly'].Value = 'TRUE'
    $f.CommitChanges()
    Write-Ok "Created WMI filter '$Name' ($Wql)"
    return $id
}

# Loads the GroupPolicy module, installing GPMC first if it is missing (asks, or -Force).
function Install-GpmcTools {
    if (Get-Module -ListAvailable -Name GroupPolicy) { return }
    Write-Warn2 'Group Policy Management tools (GroupPolicy module) are not installed.'
    if (-not (Confirm-Step 'Install them now?')) { throw 'GroupPolicy module missing. Answer y, or re-run with -Force to install it automatically.' }
    if (-not (Test-IsAdmin)) { throw 'Installing GPMC needs an elevated PowerShell.' }
    if ((Resolve-Role 'Auto') -eq 'Workstation') {
        Write-Step 'Installing RSAT: Group Policy Management Tools'
        $null = Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
    } else {
        Write-Step 'Installing feature: GPMC'
        Import-Module ServerManager
        $null = Install-WindowsFeature -Name GPMC
    }
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) { throw 'GPMC install finished but the GroupPolicy module is still not available.' }
    Write-Ok 'Installed Group Policy Management tools.'
}

# Domain name, target DC and DNs. Cached for the rest of the run.
function Get-DomainCtx {
    if ($script:DomainCtx) { return $script:DomainCtx }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        throw 'Domain modes need Windows PowerShell 5.1 (powershell.exe). The GroupPolicy module does not fully work in PowerShell 7.'
    }
    Install-GpmcTools
    Import-Module GroupPolicy -ErrorAction Stop
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $dc = $Server; if (-not $dc) { $dc = $domain.PdcRoleOwner.Name }
    $dn = [string]([ADSI]"LDAP://$dc/RootDSE").Properties['defaultNamingContext'].Value
    $script:DomainCtx = @{ Dns = $domain.Name; Dc = $dc; DN = $dn; DcOu = "OU=Domain Controllers,$dn" }
    Write-Step "Domain: $($domain.Name)   Writing to: $dc"
    return $script:DomainCtx
}

function Get-SiemGpo([string]$Name, [string]$Comment, [hashtable]$Ctx) {
    $gpo = $null
    try { $gpo = Get-GPO -Name $Name -Server $Ctx.Dc -ErrorAction Stop } catch { $gpo = $null }
    if ($null -eq $gpo) {
        Write-Step "Creating GPO '$Name'"
        $gpo = New-GPO -Name $Name -Server $Ctx.Dc -Comment $Comment
    } else {
        Write-Step "Updating existing GPO '$Name' ($($gpo.Id))"
        $gpo.Description = $Comment
    }
    $gpo.GpoStatus = 'UserSettingsDisabled'
    return $gpo
}

function Get-GpoPaths($Gpo, [hashtable]$Ctx) {
    $id   = '{' + $Gpo.Id.ToString().ToUpper() + '}'
    $root = "\\$($Ctx.Dc)\SYSVOL\$($Ctx.Dns)\Policies\$id"
    return @{ Root = $root; Machine = (Join-Path $root 'Machine'); DN = "CN=$id,CN=Policies,CN=System,$($Ctx.DN)" }
}

# Registers client-side extensions, sets (or clears) the WMI filter and bumps the
# computer version in AD and GPT.INI so clients pick up the files written to SYSVOL.
function Publish-GpoChange([hashtable]$Paths, [hashtable]$Ctx, [string[]]$Cses, [string]$WmiId) {
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($Ctx.Dc)/$($Paths.DN)")
    if ($WmiId) {
        $de.Properties['gPCWQLFilter'].Value = "[$($Ctx.Dns);$WmiId;0]"
    } elseif ($de.Properties['gPCWQLFilter'].Count -gt 0) {
        $de.Properties['gPCWQLFilter'].Clear()
    }
    $ext = [string]$de.Properties['gPCMachineExtensionNames'].Value
    $de.Properties['gPCMachineExtensionNames'].Value = (Merge-GpoExtensionNames $ext $Cses)
    $ver = [int]$de.Properties['versionNumber'].Value
    $newVer = (($ver -shr 16) -shl 16) -bor ((($ver -band 0xFFFF) + 1) -band 0xFFFF)
    $de.Properties['versionNumber'].Value = $newVer
    $de.CommitChanges()

    $gptIni = Join-Path $Paths.Root 'GPT.INI'
    $ini = ''
    if (Test-Path -LiteralPath $gptIni) { $ini = [IO.File]::ReadAllText($gptIni) }
    if ($ini -match '(?m)^Version=\d+') { $ini = $ini -replace '(?m)^Version=\d+', "Version=$newVer" }
    else { $ini = "[General]`r`nVersion=$newVer`r`n" }
    [IO.File]::WriteAllText($gptIni, $ini, [Text.Encoding]::ASCII)
    return ($newVer -band 0xFFFF)
}

# Link appended = lowest precedence at that level, so existing hardening GPOs keep winning.
function Set-GpoLinkIfMissing($Gpo, [string]$LinkTarget, [hashtable]$Ctx) {
    if ($NoLink) { Write-Warn2 "Not linked (-NoLink). Link it to $LinkTarget when approved."; return }
    $linked = @((Get-GPInheritance -Target $LinkTarget -Server $Ctx.Dc).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id })
    if ($linked.Count -eq 0) {
        $null = New-GPLink -Guid $Gpo.Id -Target $LinkTarget -Server $Ctx.Dc -LinkEnabled Yes
        Write-Ok "Linked to $LinkTarget"
    } else {
        Write-Ok "Already linked to $LinkTarget"
    }
}

function Set-SiemGpo([string]$Name, [string]$RoleName, [string]$Wql, [string]$LinkTarget, [hashtable]$Ctx) {
    $desired = Get-DesiredRegistry $RoleName
    $filterText = 'no WMI filter'; if ($Wql) { $filterText = "WMI filter: $Wql" }
    if (-not (Test-ShouldRun "GPO '$Name' (link: $LinkTarget; $filterText)" "Create/update '$RoleName' baseline: $(@($AuditSettings).Count) audit subcategories, $(@($desired).Count) registry/security settings")) { return }

    $wmiId = $null
    if ($Wql) { $wmiId = Set-SiemWmiFilter -Name $Name -Wql $Wql -Dc $Ctx.Dc -DomainDN $Ctx.DN }

    $gpo   = Get-SiemGpo $Name "SIEM audit logging baseline v$PolicyVersion ($RoleName). Managed by Deploy-SiemAuditPolicy.ps1 - re-run the script instead of editing by hand." $Ctx
    $paths = Get-GpoPaths $gpo $Ctx

    # Registry.pol - reset then write, so the GPO always matches this script exactly.
    $pol = Join-Path $paths.Machine 'Registry.pol'
    if (Test-Path -LiteralPath $pol) { Remove-Item -LiteralPath $pol -Force }
    foreach ($d in ($desired | Where-Object { $_.Kind -eq 'Reg' })) {
        $null = Set-GPRegistryValue -Guid $gpo.Id -Server $Ctx.Dc -Key $d.Key -ValueName $d.Name -Type $d.Type -Value $d.Value
    }

    # Advanced audit policy (audit.csv, ASCII)
    $auditDir = Join-Path $paths.Machine 'Microsoft\Windows NT\Audit'
    $null = New-Item -ItemType Directory -Path $auditDir -Force
    [IO.File]::WriteAllText((Join-Path $auditDir 'audit.csv'), (New-AuditCsvContent $RoleName), [Text.Encoding]::ASCII)

    # Security options (GptTmpl.inf, UTF-16LE)
    $secDir = Join-Path $paths.Machine 'Microsoft\Windows NT\SecEdit'
    $null = New-Item -ItemType Directory -Path $secDir -Force
    [IO.File]::WriteAllText((Join-Path $secDir 'GptTmpl.inf'), (New-GptTmplContent $desired), [Text.Encoding]::Unicode)

    $v = Publish-GpoChange $paths $Ctx @($CseSecurity, $CseAudit, $CseRegistry) $wmiId
    Set-GpoLinkIfMissing $gpo $LinkTarget $Ctx
    Write-Ok "GPO '$Name' is at computer version $v."
}

function Invoke-Domain([string[]]$Targets) {
    $selected = @($GpoTargets | Where-Object { ($Targets -contains 'All') -or ($Targets -contains $_.Target) })
    if ($selected.Count -eq 0) { throw "No valid -Target given: $($Targets -join ', ')" }
    $ctx = Get-DomainCtx
    Write-Step "Deploying: $(($selected | ForEach-Object { $_.Suffix }) -join ', ')"

    foreach ($t in $selected) {
        $link = $ctx.DN; if ($t.Link -eq 'DomainControllersOU') { $link = $ctx.DcOu }
        Set-SiemGpo -Name "$GpoPrefix - $($t.Suffix)" -RoleName $t.Role -Wql $t.Wql -LinkTarget $link -Ctx $ctx
    }

    # v1.0 deployed a single "All Computers" GPO; it now overlaps the Workstations/Servers GPOs.
    $legacyName = "$GpoPrefix - All Computers"
    $legacy = $null
    try { $legacy = Get-GPO -Name $legacyName -Server $ctx.Dc -ErrorAction Stop } catch { $legacy = $null }
    if ($legacy) {
        Write-Warn2 "Found '$legacyName' from v1.0. It overlaps the Workstations/Servers GPOs and should be removed"
        Write-Warn2 "once both are deployed:  Remove-GPO -Name '$legacyName' -Server $($ctx.Dc)"
    }

    # Warn about other GPOs that also define advanced audit policy (they can override ours).
    Write-Step 'Checking for other GPOs that define advanced audit policy'
    $ourNames = @($GpoTargets | ForEach-Object { "$GpoPrefix - $($_.Suffix)" }) + $legacyName
    $others = @()
    foreach ($g in (Get-GPO -All -Server $ctx.Dc)) {
        if ($ourNames -contains $g.DisplayName) { continue }
        $csv = "\\$($ctx.Dc)\SYSVOL\$($ctx.Dns)\Policies\{$($g.Id)}\Machine\Microsoft\Windows NT\Audit\audit.csv"
        if (Test-Path -LiteralPath $csv) { $others += $g.DisplayName }
    }
    if ($others.Count -gt 0) {
        Write-Warn2 'These GPOs also set advanced audit policy and may override or conflict with this baseline:'
        $others | ForEach-Object { Write-Warn2 "    $_" }
        Write-Warn2 'Review them, or raise this GPO''s link order, then run -Mode Verify on a sample of hosts.'
    } else {
        Write-Ok 'No other GPOs define advanced audit policy.'
    }
    if (-not $script:DryRun) {
        Write-Ok 'Clients apply this at the next policy refresh (~90 min) or after: gpupdate /force'
        Write-Ok 'Event channel enable/size settings take effect after a reboot.'
    }
}

# =====================================================================================
#  Sysmon
#  Order of preference: the Windows built-in Sysmon optional feature, then the
#  Sysinternals installer. Built-in and standalone Sysmon cannot coexist.
# =====================================================================================
function Confirm-SysmonEula {
    if ($AcceptEula) { return }
    if ($script:Interactive) {
        Write-Host 'The Sysmon installer is Microsoft Sysinternals software. Using it accepts its license:'
        Write-Host "  $SysmonEulaUrl"
        if ((Read-Host 'Accept the Sysinternals license for this organization? [y/N]') -match '^(y|yes)$') { $script:AcceptEulaAnswered = $true; return }
    }
    if ($script:AcceptEulaAnswered) { return }
    throw 'Sysinternals license not accepted. Answer y, or re-run with -AcceptEula.'
}

# Config source: -SysmonConfig / -SysmonConfigUrl if given; otherwise the menu asks once.
function Resolve-SysmonConfigSource {
    if ($script:SysmonConfigSource) { return $script:SysmonConfigSource }
    $src = $SysmonConfig
    if ($script:Interactive -and -not $script:SysmonConfigGiven) {
        $in = ([string](Read-Host "Sysmon config URL or file path [Enter = $SysmonConfig]")).Trim()
        if ($in) { $src = $in }
    }
    $script:SysmonConfigSource = $src
    return $src
}

# What to do with a Sysmon that is already installed (not by this script):
# -SysmonExisting wins; the menu asks; unattended runs keep the existing config.
function Resolve-SysmonExisting([string]$What) {
    if ($SysmonExisting) { return $SysmonExisting }
    if ($script:SysmonExistingAnswer) { return $script:SysmonExistingAnswer }
    $ans = 'Keep'
    if ($script:Interactive) {
        Write-Host $What
        if ((Read-Host "Overwrite the existing Sysmon configuration with $(Resolve-SysmonConfigSource)? [y/N]") -match '^(y|yes)$') { $ans = 'Overwrite' }
    } else {
        Write-Warn2 "$What Keeping the existing configuration (use -SysmonExisting Overwrite to replace it)."
    }
    $script:SysmonExistingAnswer = $ans
    return $ans
}

function New-SysmonWorkDir {
    $work = Join-Path $env:TEMP ('SiemSysmon-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $work -Force
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    return $work
}

# Downloads or copies the config into $Dir\sysmonconfig.xml and checks it is Sysmon XML.
function Get-SysmonConfigFile([string]$Dir) {
    $src = Resolve-SysmonConfigSource
    $cfg = Join-Path $Dir 'sysmonconfig.xml'
    if ($src -match '^https?://') {
        Write-Step "Downloading Sysmon config $src"
        Invoke-WebRequest -Uri $src -OutFile $cfg -UseBasicParsing
    } elseif (Test-Path -LiteralPath $src -PathType Leaf) {
        Copy-Item -LiteralPath $src -Destination $cfg
    } else {
        throw "Sysmon config not found: $src"
    }
    $x = New-Object System.Xml.XmlDocument
    $x.XmlResolver = $null
    try { $x.Load($cfg) } catch { throw "Sysmon config from $src is not valid XML (check the URL points at the raw .xml file)." }
    if ($x.DocumentElement.Name -ne 'Sysmon') { throw "Sysmon config from $src is not a <Sysmon> XML document." }
    Write-Ok "Sysmon config OK (schema $($x.DocumentElement.GetAttribute('schemaversion')))"
    return $cfg
}

# Downloads (or copies, for offline use) the Sysinternals installer binaries into $Dir and
# verifies a valid Microsoft signature on each. Returns the Sysmon version.
function Get-SysmonBinaries([string]$Dir) {
    $tmp = Join-Path $Dir 'zip'
    $null = New-Item -ItemType Directory -Path $tmp -Force
    if ($SysmonZip -match '^https?://') {
        Write-Step "Downloading Sysmon installer $SysmonZip"
        $zip = Join-Path $tmp 'Sysmon.zip'
        Invoke-WebRequest -Uri $SysmonZip -OutFile $zip -UseBasicParsing
        Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
    } elseif (Test-Path -LiteralPath $SysmonZip -PathType Container) {
        Copy-Item -Path (Join-Path $SysmonZip 'Sysmon*.exe') -Destination $tmp
    } elseif (Test-Path -LiteralPath $SysmonZip -PathType Leaf) {
        Expand-Archive -LiteralPath $SysmonZip -DestinationPath $tmp -Force
    } else {
        throw "Sysmon installer not found: $SysmonZip"
    }
    $exes = @(Get-ChildItem -LiteralPath $tmp -Filter 'Sysmon*.exe' -File)
    if ($exes.Count -eq 0) { throw 'No Sysmon*.exe found in the Sysmon installer package.' }
    foreach ($e in $exes) {
        $sig = Get-AuthenticodeSignature -FilePath $e.FullName
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw "$($e.Name) is not validly signed by Microsoft (status: $($sig.Status)). Refusing to use it."
        }
        Move-Item -LiteralPath $e.FullName -Destination $Dir -Force
    }
    Remove-Item -LiteralPath $tmp -Recurse -Force
    $ref = Join-Path $Dir 'Sysmon64.exe'; if (-not (Test-Path -LiteralPath $ref)) { $ref = (Get-ChildItem -LiteralPath $Dir -Filter 'Sysmon*.exe' | Select-Object -First 1).FullName }
    $ver = ([string](Get-Item -LiteralPath $ref).VersionInfo.FileVersion).Trim()
    Write-Ok "Sysmon installer $ver verified (Microsoft signature)"
    return $ver
}

function Get-SysmonExeName {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { return 'Sysmon64a.exe' }
    if ([Environment]::Is64BitOperatingSystem) { return 'Sysmon64.exe' }
    return 'Sysmon.exe'
}

# Current Sysmon state of this computer.
function Get-SysmonState {
    $svc = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SysmonDrv' }) | Select-Object -First 1
    $drv = Get-Service -Name SysmonDrv -ErrorAction SilentlyContinue
    $standalone = $null
    foreach ($n in @('Sysmon64.exe', 'Sysmon64a.exe', 'Sysmon.exe')) {
        $p = Join-Path $env:SystemRoot $n
        if (-not $standalone -and (Test-Path -LiteralPath $p)) { $standalone = $p }
    }
    $builtin = Join-Path $env:SystemRoot 'System32\Sysmon.exe'
    $feature = ((Invoke-NativeRaw 'dism.exe' @('/online', '/get-featureinfo', '/featurename:Sysmon')).Code -eq 0)
    $installed = [bool]($svc -or $drv)
    $kind = 'none'
    if ($installed) { $kind = 'built-in'; if ($standalone) { $kind = 'standalone' } }
    $exe = $null
    if ($standalone) { $exe = $standalone } elseif (Test-Path -LiteralPath $builtin) { $exe = $builtin }
    $ver = ''; if ($exe) { $ver = ([string](Get-Item -LiteralPath $exe).VersionInfo.FileVersion).Trim() }
    return @{ Installed = $installed; Kind = $kind; Exe = $exe; Version = $ver; Standalone = $standalone
              BuiltinExe = $builtin; FeatureAvailable = $feature; Service = $svc }
}

# Enables the built-in Sysmon feature and installs it with $Config. Returns $true on success.
function Install-SysmonBuiltin([string]$Config) {
    Write-Step 'Enabling the Windows built-in Sysmon feature'
    $r = Invoke-NativeRaw 'dism.exe' @('/online', '/enable-feature', '/featurename:Sysmon', '/norestart', '/quiet')
    if ($r.Code -ne 0 -and $r.Code -ne 3010) { Write-Warn2 "Enabling the Sysmon feature failed (exit $($r.Code))."; return $false }
    $exe = Join-Path $env:SystemRoot 'System32\Sysmon.exe'
    if (-not (Test-Path -LiteralPath $exe)) { Write-Warn2 "Sysmon feature enabled but $exe was not found (a restart may be needed)."; return $false }
    Invoke-Native $exe @('-accepteula', '-i', $Config)
    Write-Ok 'Built-in Sysmon installed.'
    return $true
}

function Invoke-SysmonLocal {
    if (-not (Test-ShouldRun 'this computer' "Install Sysmon (built-in feature first, installer fallback), config $(Resolve-SysmonConfigSource)")) { return }
    if (-not (Test-IsAdmin)) { throw 'Installing Sysmon needs an elevated PowerShell.' }
    $work = New-SysmonWorkDir
    try {
        $cfg = Get-SysmonConfigFile $work
        $st  = Get-SysmonState
        if ($st.Installed) {
            $what = "Sysmon is already installed on this computer ($($st.Kind) $($st.Version))."
            if ((Resolve-SysmonExisting $what) -eq 'Overwrite') {
                if (-not $st.Exe) { throw 'Sysmon is installed but its executable was not found; cannot apply the config.' }
                Invoke-Native $st.Exe @('-c', $cfg)
                Write-Ok 'Existing Sysmon now uses the new configuration.'
            } else {
                Write-Ok 'Existing Sysmon configuration kept.'
            }
            if ($st.Kind -eq 'standalone' -and $st.FeatureAvailable) {
                Write-Warn2 ("This OS has built-in Sysmon. To switch to it: run '{0} -u force', then -Mode SysmonLocal again." -f $st.Standalone)
            }
        } else {
            $done = $false
            if ($st.FeatureAvailable) { $done = Install-SysmonBuiltin $cfg }
            else { Write-Step 'Built-in Sysmon feature not available on this OS - using the Sysinternals installer' }
            if (-not $done) {
                Confirm-SysmonEula
                $ver = Get-SysmonBinaries $work
                Write-Step "Installing Sysmon $ver (Sysinternals installer)"
                Invoke-Native (Join-Path $work (Get-SysmonExeName)) @('-accepteula', '-i', $cfg)
                Write-Ok "Sysmon $ver installed."
            }
        }
        Invoke-Native 'wevtutil.exe' @('sl', $SysmonChannel, "/ms:$SysmonLogBytes")
        Write-Ok "Sysmon log: $SysmonChannel ($([int]($SysmonLogBytes / 1MB)) MB)"
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# One GPO per target ("<prefix> - Sysmon - <Role>"), scoped exactly like the audit GPO
# for that role (same WMI filter / same link). Each holds the config, the installer
# fallback binaries and a startup script that prefers built-in Sysmon.
function Invoke-SysmonDomain([string[]]$Targets) {
    $selected = @($GpoTargets | Where-Object { ($Targets -contains 'All') -or ($Targets -contains $_.Target) })
    if ($selected.Count -eq 0) { throw "No valid -Target given: $($Targets -join ', ')" }
    $ctx = Get-DomainCtx
    $names = @($selected | ForEach-Object { "$GpoPrefix - Sysmon - $($_.Suffix)" })
    if (-not (Test-ShouldRun ($names -join ', ') "Stage Sysmon (built-in first, installer fallback), config $(Resolve-SysmonConfigSource)")) { return }

    Confirm-SysmonEula   # hosts without the built-in feature run the Sysinternals installer
    $existing = Resolve-SysmonExisting 'Some computers may already run Sysmon that this GPO did not install.'
    $work = New-SysmonWorkDir
    try {
        $null = Get-SysmonConfigFile $work
        $ver  = Get-SysmonBinaries $work
        $ovr  = 0; if ($existing -eq 'Overwrite') { $ovr = 1 }

        foreach ($t in $selected) {
            $name  = "$GpoPrefix - Sysmon - $($t.Suffix)"
            $link  = $ctx.DN; if ($t.Link -eq 'DomainControllersOU') { $link = $ctx.DcOu }
            $wmiId = $null
            if ($t.Wql) { $wmiId = Set-SiemWmiFilter -Name "$GpoPrefix - $($t.Suffix)" -Wql $t.Wql -Dc $ctx.Dc -DomainDN $ctx.DN }

            $gpo   = Get-SiemGpo $name "Installs Sysmon ($($t.Role)) at computer startup: built-in feature first, installer fallback. Managed by Deploy-SiemAuditPolicy.ps1 v$PolicyVersion - re-run the script instead of editing by hand." $ctx
            $paths = Get-GpoPaths $gpo $ctx
            $scripts = Join-Path $paths.Machine 'Scripts'
            $startup = Join-Path $scripts 'Startup'
            $null = New-Item -ItemType Directory -Path $startup -Force
            Get-ChildItem -LiteralPath $startup -File | Remove-Item -Force
            Copy-Item -Path (Join-Path $work '*') -Destination $startup
            [IO.File]::WriteAllText((Join-Path $startup 'version.txt'), ($ver + "`r`n"), [Text.Encoding]::ASCII)
            [IO.File]::WriteAllText((Join-Path $startup 'options.txt'), "OVERWRITE_EXISTING=$ovr`r`n", [Text.Encoding]::ASCII)
            [IO.File]::WriteAllText((Join-Path $startup 'SiemSysmon.cmd'), (New-SysmonStartupCmd), [Text.Encoding]::ASCII)
            [IO.File]::WriteAllText((Join-Path $scripts 'scripts.ini'), "[Startup]`r`n0CmdLine=SiemSysmon.cmd`r`n0Parameters=`r`n", [Text.Encoding]::Unicode)

            $v = Publish-GpoChange $paths $ctx @($CseScripts) $wmiId
            Set-GpoLinkIfMissing $gpo $link $ctx
            Write-Ok "'$name' staged (installer fallback $ver, existing Sysmon: $existing, version $v)."
        }
        Write-Ok 'Computers install Sysmon at their next restart. Sooner on one host: -Mode SysmonLocal there.'
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =====================================================================================
#  AD and AD CS auditing
# =====================================================================================
function Get-ReplicationAuditState([hashtable]$Ctx) {
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($Ctx.Dc)/$($Ctx.DN)")
    $de.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
    $sec = $de.ObjectSecurity
    $rules = @($sec.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    $missing = @()
    foreach ($r in $ReplicationRights) {
        $g = [guid]$r.Guid
        $has = @($rules | Where-Object {
            $_.IdentityReference.Value -eq 'S-1-1-0' -and
            ($_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) -and
            ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
            ($_.ObjectType -eq $g -or $_.ObjectType -eq [guid]::Empty) })
        if ($has.Count -eq 0) { $missing += $r }
    }
    return @{ Entry = $de; Security = $sec; Missing = $missing }
}

function Invoke-AdSacl {
    $ctx = Get-DomainCtx
    if (-not (Test-ShouldRun $ctx.DN 'Audit Success for Everyone on the 3 replication rights (DCSync, event 4662)')) { return }
    $state = Get-ReplicationAuditState $ctx
    if ($state.Missing.Count -eq 0) { Write-Ok 'Domain root already audits all replication rights.'; return }
    $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    foreach ($r in $state.Missing) {
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AuditFlags]::Success, [guid]$r.Guid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        $state.Security.AddAuditRule($rule)
        Write-Step "Adding audit rule: $($r.Name)"
    }
    $state.Entry.ObjectSecurity = $state.Security
    $state.Entry.CommitChanges()
    Write-Ok "Added $($state.Missing.Count) audit rule(s) on $($ctx.DN)"
}

function Restart-RemoteService([string]$Computer, [string]$Name) {
    $target = "\\$Computer"
    $null = Invoke-NativeRaw 'sc.exe' @($target, 'stop', $Name)
    for ($i = 0; $i -lt 30; $i++) {
        $q = Invoke-NativeRaw 'sc.exe' @($target, 'query', $Name)
        if (($q.Output -join ' ') -match 'STOPPED') { break }
        Start-Sleep -Seconds 2
    }
    Invoke-Native 'sc.exe' @($target, 'start', $Name)
}

# Sets CA\AuditFilter on one CA. $Config = "host\CA name", or '' for the local CA.
function Set-AdcsAuditFilter([string]$Config, [string]$HostName) {
    $cfgArgs = @(); if ($Config) { $cfgArgs = @('-config', $Config) }
    $label = $Config; if (-not $label) { $label = 'local CA' }
    $cur = Invoke-NativeRaw 'certutil.exe' ($cfgArgs + @('-getreg', 'CA\AuditFilter'))
    if ($cur.Code -eq 0 -and (($cur.Output -join ' ') -match "\($AdcsAuditFilter\)")) { Write-Ok "$label already audits all AD CS categories"; return }
    Invoke-Native 'certutil.exe' ($cfgArgs + @('-setreg', 'CA\AuditFilter', [string]$AdcsAuditFilter))
    Write-Ok "$label AuditFilter set to $AdcsAuditFilter"
    if (Confirm-Step "Restart CertSvc on $HostName now to apply it (issuance pauses a few seconds)?") {
        Restart-RemoteService $HostName 'CertSvc'
        Write-Ok "Restarted CertSvc on $HostName"
    } else {
        Write-Warn2 "Restart CertSvc on $HostName to apply:  Restart-Service certsvc   (or re-run with -Force)"
    }
}

function Invoke-AdcsAudit {
    $ctx = Get-DomainCtx
    $cfgNc = [string]([ADSI]"LDAP://$($ctx.Dc)/RootDSE").Properties['configurationNamingContext'].Value
    $cas = @()
    try {
        $es = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($ctx.Dc)/CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNc")
        foreach ($c in $es.Children) { $cas += @{ Name = [string]$c.Properties['cn'].Value; Host = [string]$c.Properties['dNSHostName'].Value } }
    } catch { $cas = @() }
    if ($cas.Count -eq 0) { Write-Ok 'No enterprise CAs in AD - nothing to do.'; return }

    foreach ($ca in $cas) {
        $config = "$($ca.Host)\$($ca.Name)"
        if (-not (Test-ShouldRun $config "certutil -setreg CA\AuditFilter $AdcsAuditFilter + restart CertSvc")) { continue }
        try {
            Set-AdcsAuditFilter $config $ca.Host
        } catch {
            Write-Warn2 "$config : $($_.Exception.Message)"
            Write-Warn2 "Complete it on $($ca.Host) manually:  certutil -setreg CA\AuditFilter $AdcsAuditFilter ; Restart-Service certsvc"
            $script:Failed.Add("AD CS auditing on $config")
        }
    }
}

# =====================================================================================
#  Main
# =====================================================================================
# Menu: which computers a domain action applies to. Accepts "2,3" for several.
function Read-Targets {
    $in = Read-Host 'Which computers? 1) All  2) Workstations  3) Servers  4) Domain Controllers  [Enter = All, or e.g. 2,3]'
    $map = @{ '1' = 'All'; '2' = 'Workstations'; '3' = 'Servers'; '4' = 'DomainControllers' }
    $sel = @(([string]$in).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $map.ContainsKey($_) } | ForEach-Object { $map[$_] } | Select-Object -Unique)
    if ($sel.Count -eq 0) { $sel = @('All') }
    return ,$sel
}

function Invoke-Main {
    $m = $Mode
    $targets = $Target
    $roleName = $Role
    if ($Help -or $m -eq 'Help') { Show-Help; return }
    if (-not $m) {
        if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
            # RMM / scheduled task: no one can answer the menu, so fail fast instead of hanging.
            Write-Warn2 'No -Mode given and no interactive console. Pass -Mode (or set SIEM_MODE).'
            Show-Help; $script:ExitCode = 1; return
        }
        $script:Interactive = $true
        Write-Host ''
        Write-Host "SIEM Audit Policy v$PolicyVersion        H) Help   M) Manual steps   Q) Quit" -ForegroundColor White
        Write-Host ' Domain (on a DC, as Domain Admin) - you pick which computers next:'
        Write-Host '   1) Full onboarding: audit GPOs + Sysmon GPOs + AD/ADCS auditing'
        Write-Host '   2) Audit policy GPOs'
        Write-Host '   3) Sysmon GPOs (built-in Sysmon first, installer fallback)'
        Write-Host '   4) AD auditing: DCSync audit on domain root + AD CS audit on every CA'
        Write-Host '   5) Preview full onboarding (no changes)'
        Write-Host ' This computer:'
        Write-Host '   6) Apply audit settings + install Sysmon (standalone / workgroup)'
        Write-Host '   7) Verify this computer (read-only)'
        Write-Host '   8) Show settings (read-only)'
        $choice = ([string](Read-Host 'Choose')).Trim().ToUpper()
        switch ($choice) {
            '1' { $m = 'Full' }
            '2' { $m = 'Domain' }
            '3' { $m = 'SysmonDomain' }
            '4' { $m = 'AdAudit' }
            '5' { $m = 'Full'; $script:DryRun = $true }
            '6' { $m = 'LocalAll' }
            '7' { $m = 'Verify' }
            '8' {
                $m = 'Show'
                $r = Read-Host 'Role to show: 1) Workstation  2) Server  3) Domain Controller  [Enter = this computer]'
                switch ($r) { '1' { $roleName = 'Workstation' } '2' { $roleName = 'Server' } '3' { $roleName = 'DomainController' } }
            }
            'H' { Show-Help; return }
            'M' { Show-Manual 'All'; return }
            'Q' { return }
            default { Write-Warn2 'No valid choice; nothing done.'; return }
        }
        if (@('Full', 'Domain', 'SysmonDomain') -contains $m) { $targets = Read-Targets }
    }

    $tText = $targets -join ', '
    $steps = @()
    switch ($m) {
        'Full' {
            $steps += ,@("Audit GPOs ($tText)", 'Domain', { Invoke-Domain $targets })
            $steps += ,@("Sysmon GPOs ($tText)", 'SysmonDomain', { Invoke-SysmonDomain $targets })
            # AD/ADCS auditing is domain-wide; it belongs with the domain controllers.
            if (($targets -contains 'All') -or ($targets -contains 'DomainControllers')) {
                $steps += ,@('DCSync auditing on the domain root', 'AdSacl', { Invoke-AdSacl })
                $steps += ,@('AD CS auditing on every CA', 'Adcs', { Invoke-AdcsAudit })
            }
        }
        'Domain'       { $steps += ,@("Audit GPOs ($tText)", 'Domain', { Invoke-Domain $targets }) }
        'SysmonDomain' { $steps += ,@("Sysmon GPOs ($tText)", 'SysmonDomain', { Invoke-SysmonDomain $targets }) }
        'AdAudit' {
            $steps += ,@('DCSync auditing on the domain root', 'AdSacl', { Invoke-AdSacl })
            $steps += ,@('AD CS auditing on every CA', 'Adcs', { Invoke-AdcsAudit })
        }
    }

    if ($steps.Count -gt 0) {
        # Domain work: check prerequisites once; if they fail, print every remaining step's manual instructions.
        Invoke-Step 'Domain prerequisites (Windows PowerShell 5.1, GPMC, domain access)' 'Prereqs' { $null = Get-DomainCtx }
        if ($script:Failed.Count -gt 0) {
            foreach ($s in $steps) {
                Write-Host ''
                Write-Host "=== $($s[0]) - not run, complete manually ===" -ForegroundColor White
                Show-Manual $s[1]
                $script:Failed.Add($s[0])
            }
        } else {
            foreach ($s in $steps) { Invoke-Step $s[0] $s[1] $s[2] }
        }
    } else {
        $rn = Resolve-Role $roleName
        switch ($m) {
            'Verify' {
                $res = Invoke-Verify $rn
                if (@($res | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { $script:ExitCode = 2 }
            }
            'Show'   { Invoke-Show $rn }
            'Manual' { Show-Manual 'All' }
            'SysmonLocal' { Invoke-Step 'Sysmon on this computer' 'SysmonLocal' { Invoke-SysmonLocal } }
            default {
                # Local / LocalAll
                Invoke-Step "Audit settings on this computer ($rn)" 'Local' { Invoke-Local $rn }
                Invoke-Step 'PowerShell 7 event log' 'Local' { Register-Ps7Manifest }
                Invoke-Step 'Remove PowerShell 2.0 engine (logging bypass)' 'Local' { Disable-PowerShellV2 }
                if (Test-IsCaServer) {
                    Invoke-Step 'AD CS auditing on this CA' 'Adcs' {
                        if (Test-ShouldRun 'local CA' "certutil -setreg CA\AuditFilter $AdcsAuditFilter + restart CertSvc") { Set-AdcsAuditFilter '' $env:COMPUTERNAME }
                    }
                }
                if ($m -eq 'LocalAll') { Invoke-Step 'Sysmon on this computer' 'SysmonLocal' { Invoke-SysmonLocal } }
            }
        }
    }

    if (@('Verify', 'Show', 'Manual') -contains $m) { return }
    Write-Host ''
    if ($script:DryRun) { Write-Ok 'Preview only - nothing was changed.' }
    if ($script:Failed.Count -gt 0) {
        $script:ExitCode = 1
        Write-Warn2 'Needs manual completion (instructions printed above; all of them: -Mode Manual):'
        $script:Failed | ForEach-Object { Write-Warn2 "    $_" }
    } elseif (-not $script:DryRun) {
        Write-Ok 'All steps completed. Check any computer with:  -Mode Verify'
    }
}

# Allow dot-sourcing (". .\Deploy-SiemAuditPolicy.ps1") to load functions without running.
# Exit code for RMM / automation: 0 OK, 1 needs manual completion, 2 Verify found failures.
# (No exit when the text was pasted into a console - that would close the window.)
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main; if ($PSCommandPath) { exit $script:ExitCode } }
