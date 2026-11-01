#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Grants a local (non-admin) user everything it needs for remote, read-only WMI
    queries, e.g. from Observium via wmic-impacket.  Safe to run repeatedly.

.DESCRIPTION
    The script is idempotent:

      1. Adds the user to the local groups "Distributed COM Users" (S-1-5-32-562)
         and "Performance Monitor Users" (S-1-5-32-558) unless already a member.
      2. Grants "Enable Account" (WBEM_ENABLE, 0x1) and "Remote Enable"
         (WBEM_REMOTE_ACCESS, 0x20) on the WMI namespace, inherited by
         sub-namespaces (CONTAINER_INHERIT_ACE, 0x2).  If an allow ACE for the
         user's SID already exists its mask and flags are extended; no duplicate
         ACE is added.
      3. Enables the built-in firewall rule group "Windows Management
         Instrumentation (WMI)" (@FirewallAPI.dll,-34251), optionally restricting
         the inbound rules to -RemoteAddress.
      4. Lets the user list services remotely (Win32_Service, Observium's
         winservices module): adds "(A;;CCLCRPRC;;;<SID>)" (connect, enumerate,
         query lock status, read control) to the Service Control Manager's
         security descriptor unless an entry for the SID exists.  Without it
         Win32_Service queries fail with WBEM_E_ACCESS_DENIED for non-admins.
         The previous descriptor is printed so it can be restored with
         sc.exe sdset scmanager "<old SDDL>".  Skip with -SkipServiceManager.
      5. Grants the user read access (query config + status, enumerate
         dependents, interrogate, read control) on individual services, so they
         appear in Win32_Service.  The SCM grant in step 4 lets the account
         *enumerate* services, but each service's own security descriptor still
         decides whether the account may read it, and non-admins cannot read
         some by default -- those are silently missing from the result.  By
         default every local service is granted (Observium polls them all unless
         $config['wmi']['service_permit'] restricts the list); pass -Services to
         limit the set, or -SkipServices to skip this entirely.  Every changed
         service's previous SDDL is written to a restore script so the change
         can be undone.

    Requires Windows PowerShell 5.1 (the WMI cmdlets and the [wmiclass] accelerator
    are not available in PowerShell 7).

.PARAMETER User
    Name of the existing local user.  Default: wmi

.PARAMETER Namespace
    WMI namespace to grant access on.  Default: root\cimv2

.PARAMETER RemoteAddress
    Optional.  Restricts the inbound WMI/DCOM firewall rules to this address,
    subnet or list (e.g. 192.0.2.5 or 192.0.2.0/24).  Use 'Any' to remove an
    earlier restriction.  When omitted the rules' address scope is left as is.

.PARAMETER SkipServiceManager
    Do not touch the Service Control Manager's security descriptor (step 4).

.PARAMETER Services
    Names of the services to grant read access on (step 5).  Accepts service
    names (not display names) and wildcards, e.g. -Services MSSQL*,W3SVC.
    Default: every local service.

.PARAMETER SkipServices
    Do not touch individual service security descriptors (step 5).

.PARAMETER RestoreScript
    Where to write the sc.exe commands that undo the step 5 changes.
    Default: a timestamped file under the current directory.

.EXAMPLE
    PS> .\Grant-WmiAccess.ps1
    PS> .\Grant-WmiAccess.ps1 -User wmi -RemoteAddress 192.0.2.5
    PS> .\Grant-WmiAccess.ps1 -Services MSSQL*,W3SVC,Spooler
    PS> .\Grant-WmiAccess.ps1 -SkipServices -Namespace 'root\cimv2' -WhatIf

.NOTES
    Part of wmic-impacket (https://github.com/ravench/wmic-impacket), MIT licence.
    Create the user first, e.g.:
      New-LocalUser -Name wmi -Password (Read-Host -AsSecureString) -PasswordNeverExpires -UserMayNotChangePassword
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$User = 'wmi',

    [ValidateNotNullOrEmpty()]
    [string]$Namespace = 'root\cimv2',

    [string[]]$RemoteAddress,

    [switch]$SkipServiceManager,

    [string[]]$Services,

    [switch]$SkipServices,

    [string]$RestoreScript
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Warning 'This script needs Windows PowerShell 5.1 (powershell.exe); the WMI cmdlets it uses do not exist in PowerShell 7.'
    throw 'Unsupported PowerShell edition. Run: powershell.exe -ExecutionPolicy Bypass -File .\Grant-WmiAccess.ps1'
}

# Constants ([MS-WMI] / wbemcli.h / winnt.h)
$WBEM_ENABLE           = 0x1
$WBEM_REMOTE_ACCESS    = 0x20
$ACCESS_MASK_WANTED    = $WBEM_ENABLE -bor $WBEM_REMOTE_ACCESS   # 0x21
$CONTAINER_INHERIT_ACE = 0x2
$ACCESS_ALLOWED_ACE    = 0
$FirewallGroup         = '@FirewallAPI.dll,-34251'              # "Windows Management Instrumentation (WMI)"
$Groups = @(
    @{ Sid = 'S-1-5-32-562'; Name = 'Distributed COM Users' },
    @{ Sid = 'S-1-5-32-558'; Name = 'Performance Monitor Users' }
)

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop   # Get-LocalUser & co.
Import-Module NetSecurity -ErrorAction Stop                          # *-NetFirewallRule

function Ensure-LocalGroupMember {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string]$GroupSid,
        [Parameter(Mandatory = $true)] [string]$GroupName,
        [Parameter(Mandatory = $true)] [object]$Member     # output of Get-LocalUser
    )
    $isMember = $false
    try {
        # Get-LocalGroupMember can fail on groups containing orphaned SIDs; fall
        # back to "try to add and ignore 'already a member'" below in that case.
        $members = @(Get-LocalGroupMember -SID $GroupSid -ErrorAction Stop)
        $isMember = [bool]($members | Where-Object { $_.SID.Value -eq $Member.SID.Value })
    } catch {
        Write-Verbose "Could not enumerate '$GroupName' ($($_.Exception.Message)); will try to add anyway."
    }
    if ($isMember) {
        Write-Host "[=] $($Member.Name) is already a member of '$GroupName'"
        return
    }
    if ($PSCmdlet.ShouldProcess("'$GroupName'", "Add member $($Member.Name)")) {
        try {
            Add-LocalGroupMember -SID $GroupSid -Member $Member -ErrorAction Stop
            Write-Host "[+] Added $($Member.Name) to '$GroupName'"
        } catch {
            # Microsoft.PowerShell.Commands.MemberExistsException: not an error for us.
            if ($_.Exception.GetType().Name -eq 'MemberExistsException' -or $_.FullyQualifiedErrorId -like 'MemberExists*') {
                Write-Host "[=] $($Member.Name) is already a member of '$GroupName'"
            } else {
                throw
            }
        }
    }
}

function Invoke-WmiSecurityMethod {
    param(
        [Parameter(Mandatory)] [string]$Ns,
        [Parameter(Mandatory)] [string]$Method,
        [object[]]$Arguments
    )
    $params = @{ Namespace = $Ns; Path = '__SystemSecurity=@'; Name = $Method; ErrorAction = 'Stop' }
    if ($Arguments) { $params['ArgumentList'] = $Arguments }
    $result = Invoke-WmiMethod @params
    if ($result.ReturnValue -ne 0) {
        throw "__SystemSecurity.$Method on $Ns failed with 0x$('{0:X8}' -f $result.ReturnValue)"
    }
    return $result
}

# --- 1. local user and groups -----------------------------------------------
try {
    $localUser = Get-LocalUser -Name $User -ErrorAction Stop
} catch {
    throw "Local user '$User' does not exist. Create it first, e.g. New-LocalUser -Name $User -Password (Read-Host -AsSecureString)"
}
$sid = $localUser.SID.Value
Write-Host "[i] User $($localUser.Name) has SID $sid"

foreach ($g in $Groups) {
    Ensure-LocalGroupMember -GroupSid $g.Sid -GroupName $g.Name -Member $localUser
}

# --- 2. namespace security descriptor --------------------------------------
$descriptor = (Invoke-WmiSecurityMethod -Ns $Namespace -Method 'GetSecurityDescriptor').Descriptor
$dacl = @()
if ($null -ne $descriptor.DACL) { $dacl = @($descriptor.DACL) }

$existing = $dacl | Where-Object {
    $_.AceType -eq $ACCESS_ALLOWED_ACE -and $_.Trustee -and $_.Trustee.SIDString -eq $sid
} | Select-Object -First 1

$changed = $false
if ($existing) {
    $newMask  = $existing.AccessMask -bor $ACCESS_MASK_WANTED
    $newFlags = $existing.AceFlags  -bor $CONTAINER_INHERIT_ACE
    if ($newMask -eq $existing.AccessMask -and $newFlags -eq $existing.AceFlags) {
        Write-Host "[=] $Namespace already grants Enable Account + Remote Enable (mask 0x$('{0:X}' -f $existing.AccessMask)) to $sid"
    } else {
        if ($PSCmdlet.ShouldProcess($Namespace, "Extend existing ACE for $sid to mask 0x$('{0:X}' -f $newMask), flags 0x$('{0:X}' -f $newFlags)")) {
            $existing.AccessMask = $newMask
            $existing.AceFlags   = $newFlags
            $changed = $true
            Write-Host "[+] Updated existing ACE for $sid on $Namespace"
        }
    }
} else {
    if ($PSCmdlet.ShouldProcess($Namespace, "Add ACE (Enable Account + Remote Enable, inherit) for $sid")) {
        $trustee = ([wmiclass]'Win32_Trustee').CreateInstance()
        $trustee.SidString = $sid
        $ace = ([wmiclass]'Win32_ACE').CreateInstance()
        $ace.AccessMask = $ACCESS_MASK_WANTED
        $ace.AceFlags   = $CONTAINER_INHERIT_ACE
        $ace.AceType    = $ACCESS_ALLOWED_ACE
        $ace.Trustee    = $trustee
        $dacl += $ace.PSObject.ImmediateBaseObject
        $changed = $true
        Write-Host "[+] Added ACE for $sid on $Namespace"
    }
}

if ($changed) {
    # Re-assign the whole DACL (unwrapped objects), then write it back.
    $descriptor.DACL = @($dacl | ForEach-Object {
        if ($_ -is [System.Management.ManagementBaseObject]) { $_ } else { $_.PSObject.ImmediateBaseObject }
    })
    Invoke-WmiSecurityMethod -Ns $Namespace -Method 'SetSecurityDescriptor' -Arguments @($descriptor.PSObject.ImmediateBaseObject) | Out-Null
    Write-Host "[+] Security descriptor of $Namespace written"
}

# --- 3. firewall -----------------------------------------------------------
$rules = @(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    Write-Warning "Firewall rule group '$FirewallGroup' not found; open TCP 135 and the dynamic RPC range for the WMI service manually."
} else {
    $disabled = @($rules | Where-Object { $_.Enabled -ne 'True' })
    if ($disabled.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess("firewall group '$FirewallGroup'", "Enable $($disabled.Count) rule(s)")) {
            $disabled | Enable-NetFirewallRule
            Write-Host "[+] Enabled $($disabled.Count) WMI firewall rule(s)"
        }
    } else {
        Write-Host "[=] WMI firewall rules already enabled"
    }
    if ($RemoteAddress) {
        $inbound = @($rules | Where-Object { $_.Direction -eq 'Inbound' })
        if ($PSCmdlet.ShouldProcess("$($inbound.Count) inbound WMI rule(s)", "Set RemoteAddress to $($RemoteAddress -join ', ')")) {
            $inbound | Set-NetFirewallRule -RemoteAddress $RemoteAddress
            Write-Host "[+] Inbound WMI rules restricted to $($RemoteAddress -join ', ')"
        }
    }
}

# --- 4. Service Control Manager --------------------------------------------
# Remote service enumeration needs SC_MANAGER_CONNECT (CC),
# SC_MANAGER_ENUMERATE_SERVICE (LC), SC_MANAGER_QUERY_LOCK_STATUS (RP) and
# READ_CONTROL (RC) on the SCM; by default only administrators get them over
# the network.
if (-not $SkipServiceManager) {
    $sdshow = @(& sc.exe sdshow scmanager)
    if ($LASTEXITCODE -ne 0) { throw "sc.exe sdshow scmanager failed: $($sdshow -join ' ')" }
    $sddl = (($sdshow | Where-Object { $_ -match '\S' }) -join '').Trim()
    if (-not $sddl.StartsWith('D:') -and $sddl -notmatch '^(O:[^:]+)?(G:[^:]+)?D:') {
        throw "Unexpected SDDL from 'sc.exe sdshow scmanager': $sddl"
    }
    if ($sddl -match [regex]::Escape(";$sid)")) {
        Write-Host "[=] Service Control Manager already has an entry for $sid"
    } else {
        $scmAce = "(A;;CCLCRPRC;;;$sid)"
        $saclAt = $sddl.IndexOf('S:')
        if ($saclAt -ge 0) { $newSddl = $sddl.Insert($saclAt, $scmAce) } else { $newSddl = $sddl + $scmAce }
        if ($PSCmdlet.ShouldProcess('Service Control Manager', "Add $scmAce")) {
            Write-Host "[i] Previous Service Control Manager descriptor; restore with: sc.exe sdset scmanager `"<SDDL>`""
            Write-Host "    $sddl"
            $sdset = @(& sc.exe sdset scmanager $newSddl)
            if ($LASTEXITCODE -ne 0) { throw "sc.exe sdset scmanager failed: $($sdset -join ' ')" }
            Write-Host "[+] Granted $($localUser.Name) remote service list access (Service Control Manager)"
        }
    }
}

# --- 5. individual services -------------------------------------------------
# WMI enumerates services through the SCM (step 4) but then reads each one;
# a service whose own SD denies the account is left out of Win32_Service.
# Grant read: SERVICE_QUERY_CONFIG (CC), SERVICE_QUERY_STATUS (LC),
# SERVICE_ENUMERATE_DEPENDENTS (SW), SERVICE_INTERROGATE (LO), READ_CONTROL (RC).
if (-not $SkipServices) {
    $svcAceMask = 'CCLCSWLORC'
    $svcAce     = "(A;;$svcAceMask;;;$sid)"

    if ($Services) {
        $targets = @(Get-Service -Name $Services -ErrorAction SilentlyContinue)
    } else {
        $targets = @(Get-Service)
    }
    if ($targets.Count -eq 0) {
        Write-Warning "No matching services found; step 5 skipped."
    } else {
        if (-not $RestoreScript) {
            $RestoreScript = Join-Path (Get-Location) ("Grant-WmiAccess-restore-services-{0:yyyyMMdd-HHmmss}.cmd" -f (Get-Date))
        }
        $restoreLines = @('@echo off', 'rem Restores service security descriptors changed by Grant-WmiAccess.ps1')
        $granted = 0; $already = 0; $failed = 0
        foreach ($svc in $targets) {
            $name = $svc.Name
            try {
                $out = & sc.exe sdshow "$name" 2>&1
                if ($LASTEXITCODE -ne 0) { throw ($out -join ' ') }
                $cur = (($out | Where-Object { $_ -match '\S' }) -join '').Trim()
                if ($cur -notmatch '^(O:[^:]+)?(G:[^:]+)?D:') {
                    throw "unexpected SDDL: $cur"
                }
                if ($cur -match [regex]::Escape(";$sid)")) {
                    $already++
                    continue
                }
                $saclAt = $cur.IndexOf('S:')
                if ($saclAt -ge 0) { $new = $cur.Insert($saclAt, $svcAce) } else { $new = $cur + $svcAce }
                if ($PSCmdlet.ShouldProcess($name, "Add $svcAce")) {
                    $restoreLines += "sc.exe sdset `"$name`" `"$cur`""
                    $res = & sc.exe sdset "$name" "$new" 2>&1
                    if ($LASTEXITCODE -ne 0) { throw ($res -join ' ') }
                    $granted++
                }
            } catch {
                $failed++
                Write-Warning "Service '$name': $($_.Exception.Message)"
            }
        }
        if ($granted -gt 0 -and -not $WhatIfPreference) {
            Set-Content -Path $RestoreScript -Value $restoreLines -Encoding ASCII
            Write-Host "[+] Granted read access on $granted service(s); $already already had it, $failed failed"
            Write-Host "[i] To undo the service changes, run: $RestoreScript"
        } else {
            Write-Host "[=] Services: $already already granted, $granted to change, $failed failed"
        }
    }
}

Write-Host ''
Write-Host "Done. Test from the monitoring host, e.g.:"
Write-Host "  wmic -U '$User%PASSWORD' --namespace='$Namespace' //$env:COMPUTERNAME 'SELECT Caption FROM Win32_OperatingSystem'"
