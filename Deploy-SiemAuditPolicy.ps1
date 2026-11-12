<#
.SYNOPSIS
    Deploys SIEM-ready Windows security audit logging as Group Policy (or locally),
    and verifies that a computer is actually logging what the SIEM needs.

.DESCRIPTION
    Single self-contained file. No other files, modules or downloads are required
    beyond what ships with Windows Server (GroupPolicy module / GPMC for Domain mode).

    Modes:
      Domain  - Creates/updates two GPOs and links them:
                  "<Prefix> - All Computers"       -> linked to the domain root
                  "<Prefix> - Domain Controllers"  -> linked to OU=Domain Controllers
                Re-running is safe: the GPOs are rebuilt to exactly the settings below.
                Run on a domain controller (or admin box with GPMC) as a Domain Admin.
      Local   - Applies the same settings directly to THIS computer (workgroup /
                standalone servers, or testing). Run elevated.
      Verify  - Read-only. Checks THIS computer's effective settings and prints PASS/FAIL.
                Run elevated.
      Show    - Read-only. Prints every setting this script manages.

    If -Mode is omitted an interactive menu is shown.

.PARAMETER Mode
    Domain | Local | Verify | Show. Omit for an interactive menu.

.PARAMETER GpoPrefix
    Name prefix for the two GPOs. Default: "SIEM Audit Policy".

.PARAMETER NoLink
    Domain mode: create/update the GPOs but do not link them (for change control).

.PARAMETER Server
    Domain mode: domain controller to write to. Default: the PDC emulator.

.PARAMETER Role
    Local/Verify/Show: Auto (default), Member, or DomainController.

.EXAMPLE
    .\Deploy-SiemAuditPolicy.ps1                     # interactive menu
.EXAMPLE
    .\Deploy-SiemAuditPolicy.ps1 -Mode Domain -WhatIf
.EXAMPLE
    .\Deploy-SiemAuditPolicy.ps1 -Mode Verify

.NOTES
    Keep this file ASCII-only so it survives copy/paste and Windows PowerShell 5.1.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('', 'Domain', 'Local', 'Verify', 'Show')]
    [string]$Mode = '',
    [string]$GpoPrefix = 'SIEM Audit Policy',
    [switch]$NoLink,
    [string]$Server = '',
    [ValidateSet('Auto', 'Member', 'DomainController')]
    [string]$Role = 'Auto'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PolicyVersion = '1.0.0'
$script:DryRun = [bool]$WhatIfPreference

# =====================================================================================
#  SETTINGS - single source of truth. Edit here; every mode reads from these tables.
#  Value: 1 = Success, 2 = Failure, 3 = Success and Failure
#  Subcategories that only fire on certain roles (DC, CA, NPS, file server) are
#  harmless elsewhere, so one audit set is used for every computer.
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
    @{ Name = 'Sensitive Privilege Use';            Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Value = 3; Events = '4673, 4674, 4985 (can be noisy on workstations)' }
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
# Scope: All or DC. DCValue overrides Value on domain controllers. Compare: Equal or Min.
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
    @{ Kind = 'SecOpt'; Scope = 'DC';  Key = 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'AuditNTLMInDomain'; Type = 'DWord'; Value = 7; Compare = 'Equal'
       Purpose = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain = enable all (DC)' }

    @{ Kind = 'Reg'; Scope = 'All'; Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'Include command line in process creation events (4688)' }

    @{ Kind = 'Reg'; Scope = 'All'; Key = "$PsPol\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'Windows PowerShell script block logging (4104)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$PsPol\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'Windows PowerShell module logging (4103)' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$PsPol\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Compare = 'Equal'
       Purpose = 'Module logging for all modules' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$Ps7Pol\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'PowerShell 7 script block logging' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$Ps7Pol\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Compare = 'Equal'
       Purpose = 'PowerShell 7 module logging' }
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$Ps7Pol\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Compare = 'Equal'
       Purpose = 'PowerShell 7 module logging for all modules' }

    # Classic event log sizes (KB) and overwrite-as-needed retention.
    @{ Kind = 'Reg'; Scope = 'All'; Key = "$EvtPol\Security"; Name = 'MaxSize'; Type = 'DWord'; Value = 1048576; DCValue = 4194240; Compare = 'Min'
       Purpose = 'Security log max size KB (1 GB; ~4 GB on DCs)' }
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
       Purpose = 'Windows PowerShell classic log max size bytes (256 MB; 400/800 events)' }
)

# Operational channels to enable and size (bytes). Written as registry under
# WINEVT\Channels in GPO mode (takes effect after reboot); applied live in Local mode.
$ChannelSettings = @(
    @{ Name = 'Microsoft-Windows-PowerShell/Operational';                MaxBytes = 268435456; Purpose = '4103/4104 PowerShell module and script block logging' }
    @{ Name = 'Microsoft-Windows-TaskScheduler/Operational';             MaxBytes = 67108864;  Purpose = 'Scheduled task registration/execution (106, 140, 141, 200, 201)' }
    @{ Name = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'; MaxBytes = 33554432;  Purpose = 'USB/device connect history (2003, 2100)' }
    @{ Name = 'Microsoft-Windows-NTLM/Operational';                      MaxBytes = 67108864;  Purpose = 'NTLM audit events (8001-8004) from the NTLM audit settings' }
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational';          MaxBytes = 67108864;  Purpose = 'Defender detections and tampering (1116, 1117, 5001, 5007)' }
    @{ Name = 'Microsoft-Windows-WMI-Activity/Operational';              MaxBytes = 33554432;  Purpose = 'WMI persistence/execution (5857-5861)' }
)
$ChannelRoot = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'

# GPO client-side extension GUID pairs [CSE][Tool]
$CseSecurity = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
$CseAudit    = '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'
$CseRegistry = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}'

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

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-IsDC([string]$RoleName) {
    if ($RoleName -eq 'DomainController') { return $true }
    if ($RoleName -eq 'Member') { return $false }
    $dr = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    return ($dr -ge 4)
}

function Get-InclusionText([int]$Value) {
    switch ($Value) { 1 { 'Success' } 2 { 'Failure' } 3 { 'Success and Failure' } default { 'No Auditing' } }
}

# Returns registry settings resolved for a role (channels expanded into registry rows).
function Get-DesiredRegistry([bool]$IsDC) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in $RegistrySettings) {
        if ($s.Scope -eq 'DC' -and -not $IsDC) { continue }
        $v = $s.Value
        if ($IsDC -and $s.ContainsKey('DCValue')) { $v = $s.DCValue }
        $out.Add([pscustomobject]@{ Kind = $s.Kind; Key = $s.Key; Name = $s.Name; Type = $s.Type; Value = $v; Compare = $s.Compare; Purpose = $s.Purpose; Channel = $null })
    }
    foreach ($c in $ChannelSettings) {
        $k = "$ChannelRoot\$($c.Name)"
        $out.Add([pscustomobject]@{ Kind = 'Reg'; Key = $k; Name = 'Enabled'; Type = 'DWord'; Value = 1; Compare = 'Equal'; Purpose = "Enable channel: $($c.Purpose)"; Channel = $c.Name })
        $out.Add([pscustomobject]@{ Kind = 'Reg'; Key = $k; Name = 'MaxSize'; Type = 'DWord'; Value = $c.MaxBytes; Compare = 'Min'; Purpose = "Channel size bytes: $($c.Name)"; Channel = $c.Name })
    }
    return $out
}

function New-AuditCsvContent {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($a in $AuditSettings) {
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

function Test-ChannelExists([string]$Channel) {
    return ($null -ne (Get-LocalRegValue "$ChannelRoot\$Channel" 'OwningPublisher'))
}

# Effective channel config (Enabled = 1/0, MaxSize = bytes) as the Event Log service sees it.
function Get-ChannelConfig([string]$Channel) {
    $raw = & wevtutil.exe gl "$Channel" /f:xml 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
    $x = [xml]($raw -join '')
    $en = 0; if ($x.channel.enabled -eq 'true') { $en = 1 }
    return @{ Enabled = $en; MaxSize = [int64]$x.channel.logging.maxSize }
}

# =====================================================================================
#  Show
# =====================================================================================
function Invoke-Show([bool]$IsDC) {
    $roleText = 'member server / workstation'
    if ($IsDC) { $roleText = 'domain controller' }
    Write-Host ''
    Write-Host "SIEM audit policy v$PolicyVersion - settings for a $roleText" -ForegroundColor White
    Write-Host ''
    Write-Host 'Advanced Audit Policy' -ForegroundColor White
    $AuditSettings | ForEach-Object { [pscustomobject]@{ Subcategory = $_.Name; Setting = (Get-InclusionText $_.Value); KeyEvents = $_.Events } } |
        Format-Table -AutoSize -Wrap | Out-Host
    Write-Host 'Registry / Security Options / Event Logs' -ForegroundColor White
    Get-DesiredRegistry $IsDC | Select-Object Kind, @{ n = 'Setting'; e = { "$($_.Key)\$($_.Name)" } }, Value, Purpose |
        Format-Table -AutoSize -Wrap | Out-Host
}

# =====================================================================================
#  Local
# =====================================================================================
function Invoke-Local([bool]$IsDC) {
    if (-not $script:DryRun -and -not (Test-IsAdmin)) { throw 'Local mode must be run from an elevated (Run as administrator) PowerShell.' }

    Write-Step 'Applying advanced audit policy (auditpol)'
    foreach ($a in $AuditSettings) {
        $s = 'disable'; if ($a.Value -band 1) { $s = 'enable' }
        $f = 'disable'; if ($a.Value -band 2) { $f = 'enable' }
        if (Test-ShouldRun $a.Name "auditpol success:$s failure:$f") {
            $null = & auditpol.exe /set /subcategory:"$($a.Guid)" /success:$s /failure:$f
            if ($LASTEXITCODE -ne 0) { Write-Warn2 "auditpol failed for $($a.Name) (exit $LASTEXITCODE)" }
        }
    }

    Write-Step 'Writing registry / security option values'
    foreach ($d in (Get-DesiredRegistry $IsDC)) {
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
            $null = & wevtutil.exe sl "$($c.Name)" /e:true /ms:$($c.MaxBytes)
            if ($LASTEXITCODE -ne 0) { Write-Warn2 "wevtutil failed for $($c.Name) (exit $LASTEXITCODE)" }
        }
    }
    Write-Ok 'Local settings applied. Run -Mode Verify to confirm. (A domain GPO will override local settings.)'
}

# =====================================================================================
#  Verify
# =====================================================================================
function Invoke-Verify([bool]$IsDC) {
    if (-not (Test-IsAdmin)) { throw 'Verify mode must be run from an elevated (Run as administrator) PowerShell (auditpol needs it).' }
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

    foreach ($a in $AuditSettings) {
        $have = 0
        if ($actual.ContainsKey($a.Guid.ToUpper())) { $have = $actual[$a.Guid.ToUpper()] }
        $status = 'FAIL'; if (($have -band $a.Value) -eq $a.Value) { $status = 'PASS' }
        $results.Add([pscustomobject]@{ Status = $status; Area = 'Audit'; Setting = $a.Name; Expected = (Get-InclusionText $a.Value); Actual = (Get-InclusionText $have) })
    }

    $legacy = Get-LocalRegValue 'HKLM\System\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    foreach ($d in (Get-DesiredRegistry $IsDC)) {
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
        if ($d.Channel) { $label = "$($d.Channel) $($d.Name)" }
        $shown = '<not set>'; if ($null -ne $have) { $shown = $have }
        $results.Add([pscustomobject]@{ Status = $status; Area = $area; Setting = $label; Expected = $d.Value; Actual = $shown })
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
        if ("$legacy" -ne '1') { Write-Warn2 'Legacy audit policy is NOT overridden - advanced audit settings may be ignored.' }
    }
    return $results
}

# =====================================================================================
#  Domain
# =====================================================================================
function Set-SiemGpo {
    param([string]$Name, [bool]$IsDC, [string]$LinkTarget, [string]$Dc, [string]$DomainDns, [string]$DomainDN)

    $desired = Get-DesiredRegistry $IsDC
    if (-not (Test-ShouldRun "GPO '$Name' (link: $LinkTarget)" "Create/update with $(@($AuditSettings).Count) audit subcategories and $(@($desired).Count) registry/security settings")) { return $null }

    $gpo = $null
    try { $gpo = Get-GPO -Name $Name -Server $Dc -ErrorAction Stop } catch { $gpo = $null }
    if ($null -eq $gpo) {
        Write-Step "Creating GPO '$Name'"
        $gpo = New-GPO -Name $Name -Server $Dc -Comment "SIEM audit logging baseline v$PolicyVersion. Managed by Deploy-SiemAuditPolicy.ps1 - re-run the script instead of editing by hand."
    } else {
        Write-Step "Updating existing GPO '$Name' ($($gpo.Id))"
        $gpo.Description = "SIEM audit logging baseline v$PolicyVersion. Managed by Deploy-SiemAuditPolicy.ps1 - re-run the script instead of editing by hand."
    }
    $gpo.GpoStatus = 'UserSettingsDisabled'

    $gpoId    = '{' + $gpo.Id.ToString().ToUpper() + '}'
    $gpoRoot  = "\\$Dc\SYSVOL\$DomainDns\Policies\$gpoId"
    $machine  = Join-Path $gpoRoot 'Machine'
    $gpoDN    = "CN=$gpoId,CN=Policies,CN=System,$DomainDN"

    # 1. Registry.pol - reset then write, so the GPO always matches this script exactly.
    $pol = Join-Path $machine 'Registry.pol'
    if (Test-Path -LiteralPath $pol) { Remove-Item -LiteralPath $pol -Force }
    foreach ($d in ($desired | Where-Object { $_.Kind -eq 'Reg' })) {
        $null = Set-GPRegistryValue -Guid $gpo.Id -Server $Dc -Key $d.Key -ValueName $d.Name -Type $d.Type -Value $d.Value
    }

    # 2. Advanced audit policy (audit.csv)
    $auditDir = Join-Path $machine 'Microsoft\Windows NT\Audit'
    $null = New-Item -ItemType Directory -Path $auditDir -Force
    [IO.File]::WriteAllText((Join-Path $auditDir 'audit.csv'), (New-AuditCsvContent), [Text.Encoding]::ASCII)

    # 3. Security options (GptTmpl.inf, UTF-16LE)
    $secDir = Join-Path $machine 'Microsoft\Windows NT\SecEdit'
    $null = New-Item -ItemType Directory -Path $secDir -Force
    [IO.File]::WriteAllText((Join-Path $secDir 'GptTmpl.inf'), (New-GptTmplContent $desired), [Text.Encoding]::Unicode)

    # 4. Register client-side extensions and bump the computer version (AD + GPT.INI).
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Dc/$gpoDN")
    $ext = [string]$de.Properties['gPCMachineExtensionNames'].Value
    $de.Properties['gPCMachineExtensionNames'].Value = (Merge-GpoExtensionNames $ext @($CseSecurity, $CseAudit, $CseRegistry))
    $ver = [int]$de.Properties['versionNumber'].Value
    $newVer = (($ver -shr 16) -shl 16) -bor ((($ver -band 0xFFFF) + 1) -band 0xFFFF)
    $de.Properties['versionNumber'].Value = $newVer
    $de.CommitChanges()

    $gptIni = Join-Path $gpoRoot 'GPT.INI'
    $ini = ''
    if (Test-Path -LiteralPath $gptIni) { $ini = [IO.File]::ReadAllText($gptIni) }
    if ($ini -match '(?m)^Version=\d+') { $ini = $ini -replace '(?m)^Version=\d+', "Version=$newVer" }
    else { $ini = "[General]`r`nVersion=$newVer`r`n" }
    [IO.File]::WriteAllText($gptIni, $ini, [Text.Encoding]::ASCII)

    # 5. Link (appended = lowest precedence at that level, so existing hardening GPOs keep winning)
    if (-not $NoLink) {
        $linked = @((Get-GPInheritance -Target $LinkTarget -Server $Dc).GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id })
        if ($linked.Count -eq 0) {
            $null = New-GPLink -Guid $gpo.Id -Target $LinkTarget -Server $Dc -LinkEnabled Yes
            Write-Ok "Linked to $LinkTarget"
        } else {
            Write-Ok "Already linked to $LinkTarget"
        }
    }
    Write-Ok "GPO '$Name' is at computer version $($newVer -band 0xFFFF)."
    return $gpo
}

function Invoke-Domain {
    try { Import-Module GroupPolicy -ErrorAction Stop }
    catch { throw 'GroupPolicy module not found. Run on a domain controller, or install RSAT Group Policy Management Tools.' }

    $domain    = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DomainDns = $domain.Name
    $Dc        = $Server
    if (-not $Dc) { $Dc = $domain.PdcRoleOwner.Name }
    $DomainDN  = ([ADSI]"LDAP://$Dc/RootDSE").Properties['defaultNamingContext'].Value
    $dcOu      = "OU=Domain Controllers,$DomainDN"

    Write-Step "Domain: $DomainDns   Writing to: $Dc"
    $allName = "$GpoPrefix - All Computers"
    $dcName  = "$GpoPrefix - Domain Controllers"

    $g1 = Set-SiemGpo -Name $allName -IsDC $false -LinkTarget $DomainDN -Dc $Dc -DomainDns $DomainDns -DomainDN $DomainDN
    $g2 = Set-SiemGpo -Name $dcName  -IsDC $true  -LinkTarget $dcOu     -Dc $Dc -DomainDns $DomainDns -DomainDN $DomainDN

    # Warn about other GPOs that also define advanced audit policy (they can override ours).
    Write-Step 'Checking for other GPOs that define advanced audit policy'
    $ours = @()
    foreach ($g in @($g1, $g2)) { if ($g) { $ours += $g.Id } }
    $others = @()
    foreach ($g in (Get-GPO -All -Server $Dc)) {
        if ($ours -contains $g.Id) { continue }
        $csv = "\\$Dc\SYSVOL\$DomainDns\Policies\{$($g.Id)}\Machine\Microsoft\Windows NT\Audit\audit.csv"
        if (Test-Path -LiteralPath $csv) { $others += $g.DisplayName }
    }
    if ($others.Count -gt 0) {
        Write-Warn2 'These GPOs also set advanced audit policy and may override or conflict with this baseline:'
        $others | ForEach-Object { Write-Warn2 "    $_" }
        Write-Warn2 'Review them, or raise this GPO''s link order, then run -Mode Verify on a sample of hosts.'
    } else {
        Write-Ok 'No other GPOs define advanced audit policy.'
    }

    Write-Host ''
    if ($script:DryRun) { Write-Ok 'Preview only - nothing was changed.'; return }
    Write-Ok 'Done. Clients apply this at the next policy refresh (~90 min) or after: gpupdate /force'
    Write-Ok 'Event channel enable/size settings take effect after a reboot.'
    Write-Ok 'Validate any host with:  .\Deploy-SiemAuditPolicy.ps1 -Mode Verify'
}

# =====================================================================================
#  Main
# =====================================================================================
function Invoke-Main {
    $m = $Mode
    if (-not $m) {
        Write-Host ''
        Write-Host "SIEM Audit Policy v$PolicyVersion" -ForegroundColor White
        Write-Host '  1) Deploy GPOs to this Active Directory domain'
        Write-Host '  2) Preview the domain deployment (no changes, -WhatIf)'
        Write-Host '  3) Apply settings to THIS computer only (standalone / workgroup)'
        Write-Host '  4) Verify THIS computer is logging correctly (read-only)'
        Write-Host '  5) Show all settings (read-only)'
        $choice = Read-Host 'Choose 1-5'
        switch ($choice) {
            '1' { $m = 'Domain' }
            '2' { $m = 'Domain'; $script:DryRun = $true }
            '3' { $m = 'Local' }
            '4' { $m = 'Verify' }
            '5' { $m = 'Show' }
            default { Write-Warn2 'No valid choice; nothing done.'; return }
        }
    }

    switch ($m) {
        'Domain' { Invoke-Domain }
        'Local'  { Invoke-Local  (Resolve-IsDC $Role) }
        'Verify' { $null = Invoke-Verify (Resolve-IsDC $Role) }
        'Show'   { Invoke-Show   (Resolve-IsDC $Role) }
    }
}

# Allow dot-sourcing (". .\Deploy-SiemAuditPolicy.ps1") to load functions without running.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
