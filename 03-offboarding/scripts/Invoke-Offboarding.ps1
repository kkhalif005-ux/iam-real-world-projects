<#
.SYNOPSIS
    Emergency offboarding: locks a terminated user out of Entra ID in minutes
    and produces a timestamped timeline as evidence.

.DESCRIPTION
    Order matters. The script cuts off access first and cleans up second:
      1. Snapshot  - records the user's groups, admin roles and app assignments (evidence, rehire)
      2. Disable   - blocks new sign-ins
      3. Revoke    - invalidates refresh tokens and sessions, so open sessions stop working
      4. Password  - resets to a random value, so a cached password is useless
      5. Groups    - removes cloud group memberships (synced AD groups are flagged for AD)
      6. Roles     - removes active and PIM-eligible admin role assignments
      7. Apps      - removes direct enterprise app assignments
      8. Devices   - optionally disables their registered devices
      9. Verify    - re-reads the account to confirm each control took effect

    Every step is written to a timeline with a UTC timestamp. The script also reports
    time-to-contain: minutes from when HR's request came in until sessions were revoked.
    A failed step is logged and the script keeps going, so one error never leaves the user active.

.EXAMPLE
    .\Invoke-Offboarding.ps1 -UserPrincipalName daniel.garcia@yourtenant.onmicrosoft.com -TicketId HR-1042 -Reason 'Involuntary termination' -RequestedAt '2026-11-18 09:00' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$UserPrincipalName,
    [Parameter(Mandatory)] [string]$TicketId,
    [Parameter(Mandatory)] [string]$Reason,
    [datetime]$RequestedAt = (Get-Date),
    [switch]$SkipPasswordReset,
    [switch]$DisableDevices,
    [string]$OutputDir = '.\reports'
)

$ErrorActionPreference = 'Stop'

$scopes = @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Group.Read.All',
            'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Directory.Read.All')
if ($DisableDevices) { $scopes += 'Directory.AccessAsUser.All' }
Connect-MgGraph -Scopes $scopes -NoWelcome

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$safeName = $UserPrincipalName.Split('@')[0]
$timelinePath = Join-Path $OutputDir "offboarding_${safeName}_$stamp.csv"
$reportPath   = Join-Path $OutputDir "offboarding_${safeName}_$stamp.md"
$snapshotPath = Join-Path $OutputDir "offboarding_${safeName}_${stamp}_access_snapshot.json"

$timeline = [System.Collections.Generic.List[object]]::new()
function Add-Step($Step, $Action, $Detail, $Result = 'Success') {
    $entry = [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Step         = $Step
        Action       = $Action
        Detail       = $Detail
        Result       = $Result
    }
    $timeline.Add($entry)
    $entry | Export-Csv -Path $timelinePath -Append -NoTypeInformation
    $color = switch ($Result) { 'Success' { 'Green' } 'Skipped' { 'DarkGray' } 'Manual' { 'Yellow' } default { 'Red' } }
    Write-Host ("[{0}] {1,-2} {2,-22} {3}" -f $entry.TimestampUtc, $Step, $Action, $Detail) -ForegroundColor $color
}
function Invoke-Step($Step, $Action, $Target, [scriptblock]$Do) {
    if (-not $PSCmdlet.ShouldProcess($Target, $Action)) { Add-Step $Step $Action 'Preview only (-WhatIf)' 'Skipped'; return }
    try { $detail = & $Do; Add-Step $Step $Action $detail }
    catch { Add-Step $Step $Action $_.Exception.Message 'Failure' }
}

$requestedUtc = $RequestedAt.ToUniversalTime()
Add-Step 0 'Request received' "Ticket $TicketId - $Reason (HR request at $($requestedUtc.ToString('yyyy-MM-dd HH:mm')) UTC)"

$user = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, UserPrincipalName, AccountEnabled, OnPremisesSyncEnabled
if ($user.OnPremisesSyncEnabled) {
    Add-Step 0 'Hybrid account' 'Synced from AD: also run Disable-ADAccount on-prem, or the next sync can re-enable it' 'Manual'
}

# ---------- 1. Snapshot ----------
$memberOf  = @(Get-MgUserMemberOf -UserId $user.Id -All)
$groups    = @($memberOf | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' })
$roles     = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -All)
$eligible  = @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($user.Id)'" -All -ErrorAction SilentlyContinue)
$appRoles  = @(Get-MgUserAppRoleAssignment -UserId $user.Id -All)
$devices   = @(Get-MgUserRegisteredDevice -UserId $user.Id -All -ErrorAction SilentlyContinue)

[pscustomobject]@{
    CapturedUtc   = (Get-Date).ToUniversalTime().ToString('s')
    User          = $user.UserPrincipalName
    Ticket        = $TicketId
    Groups        = $groups   | ForEach-Object { $_.AdditionalProperties['displayName'] }
    ActiveRoles   = $roles    | ForEach-Object { $_.RoleDefinitionId }
    EligibleRoles = $eligible | ForEach-Object { $_.RoleDefinitionId }
    AppAccess     = $appRoles | ForEach-Object { $_.ResourceDisplayName }
    Devices       = $devices  | ForEach-Object { $_.AdditionalProperties['displayName'] }
} | ConvertTo-Json -Depth 4 | Set-Content $snapshotPath
Add-Step 1 'Access snapshot' ("{0} groups, {1} active roles, {2} eligible roles, {3} apps, {4} devices" -f
    $groups.Count, $roles.Count, $eligible.Count, $appRoles.Count, $devices.Count)

# ---------- 2-4. Cut off access ----------
Invoke-Step 2 'Disable account' $user.UserPrincipalName {
    Update-MgUser -UserId $user.Id -AccountEnabled:$false; 'accountEnabled = false'
}
Invoke-Step 3 'Revoke sessions' $user.UserPrincipalName {
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null; 'Refresh tokens and session cookies invalidated'
}
$revokedAt = (Get-Date).ToUniversalTime()

if ($SkipPasswordReset) { Add-Step 4 'Reset password' 'Skipped by request' 'Skipped' }
else {
    Invoke-Step 4 'Reset password' $user.UserPrincipalName {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%'
        $pw = -join (1..32 | ForEach-Object { $chars[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($chars.Length)] })
        Update-MgUser -UserId $user.Id -PasswordProfile @{ Password = $pw; ForceChangePasswordNextSignIn = $true }
        'Random password set (not recorded)'
    }
}

# ---------- 5-8. Remove access ----------
foreach ($g in $groups) {
    $name = $g.AdditionalProperties['displayName']
    if ($g.AdditionalProperties['groupTypes'] -contains 'DynamicMembership') {
        Add-Step 5 'Group (dynamic)' "$name - drops out automatically once the account is disabled or attributes change" 'Skipped'; continue
    }
    if ($g.AdditionalProperties['onPremisesSyncEnabled']) {
        Add-Step 5 'Group (synced from AD)' "$name - remove in Active Directory" 'Manual'; continue
    }
    Invoke-Step 5 'Remove group' "$($user.UserPrincipalName) from $name" {
        Remove-MgGroupMemberByRef -GroupId $g.Id -DirectoryObjectId $user.Id; $name
    }
}
foreach ($r in $roles) {
    Invoke-Step 6 'Remove admin role' $r.RoleDefinitionId {
        Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $r.Id; "Active role $($r.RoleDefinitionId)"
    }
}
foreach ($e in $eligible) {
    Invoke-Step 6 'Remove PIM eligibility' $e.RoleDefinitionId {
        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter @{
            action           = 'adminRemove'
            principalId      = $user.Id
            roleDefinitionId = $e.RoleDefinitionId
            directoryScopeId = $e.DirectoryScopeId
            justification    = "Offboarding - ticket $TicketId"
        } | Out-Null
        "Eligible role $($e.RoleDefinitionId)"
    }
}
foreach ($a in $appRoles) {
    Invoke-Step 7 'Remove app access' $a.ResourceDisplayName {
        Remove-MgUserAppRoleAssignment -UserId $user.Id -AppRoleAssignmentId $a.Id; $a.ResourceDisplayName
    }
}
if ($DisableDevices) {
    foreach ($d in $devices) {
        $dn = $d.AdditionalProperties['displayName']
        Invoke-Step 8 'Disable device' $dn { Update-MgDevice -DeviceId $d.Id -AccountEnabled:$false; $dn }
    }
} elseif ($devices) {
    Add-Step 8 'Devices' "$($devices.Count) registered device(s) left enabled; use -DisableDevices or wipe through Intune" 'Manual'
}

# ---------- 9. Verify ----------
if (-not $WhatIfPreference) {
    Start-Sleep -Seconds 5
    $check = Get-MgUser -UserId $user.Id -Property AccountEnabled
    $leftGroups = @(Get-MgUserMemberOf -UserId $user.Id -All | Where-Object {
        $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' -and
        $_.AdditionalProperties['groupTypes'] -notcontains 'DynamicMembership' -and
        -not $_.AdditionalProperties['onPremisesSyncEnabled'] })
    $leftApps  = @(Get-MgUserAppRoleAssignment -UserId $user.Id -All)
    $leftRoles = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -All)
    $ok = (-not $check.AccountEnabled) -and $leftGroups.Count -eq 0 -and $leftApps.Count -eq 0 -and $leftRoles.Count -eq 0
    Add-Step 9 'Verify' ("enabled={0}, cloud groups left={1}, apps left={2}, active roles left={3}" -f
        $check.AccountEnabled, $leftGroups.Count, $leftApps.Count, $leftRoles.Count) $(if ($ok) { 'Success' } else { 'Failure' })
}

# ---------- Report ----------
$minutes = [math]::Round(($revokedAt - $requestedUtc).TotalMinutes, 1)
$failures = @($timeline | Where-Object Result -eq 'Failure')
$manual   = @($timeline | Where-Object Result -eq 'Manual')

$md = @"
# Offboarding report: $($user.DisplayName)

| Field | Value |
|-------|-------|
| User | $($user.UserPrincipalName) |
| Ticket | $TicketId |
| Reason | $Reason |
| HR request (UTC) | $($requestedUtc.ToString('yyyy-MM-dd HH:mm:ss')) |
| Sessions revoked (UTC) | $($revokedAt.ToString('yyyy-MM-dd HH:mm:ss')) |
| **Time to contain** | **$minutes minutes** |
| Failed steps | $($failures.Count) |
| Manual follow-ups | $($manual.Count) |

## Timeline

| Time (UTC) | Step | Action | Detail | Result |
|------------|------|--------|--------|--------|
$(($timeline | ForEach-Object { "| $($_.TimestampUtc) | $($_.Step) | $($_.Action) | $($_.Detail -replace '\|','/') | $($_.Result) |" }) -join "`n")

## Still to do outside this script

- Systems that don't use Entra ID sign-in (local app accounts, vendor portals, VPN tokens)
- Mailbox: convert to a shared mailbox or forward to the manager, per policy
- OneDrive: give the manager access before the retention period ends
- Hardware: collect the laptop and badge
- Delete the account only after the retention period
$(($manual | ForEach-Object { "- $($_.Action): $($_.Detail)" }) -join "`n")

Access snapshot taken before removal: ``$(Split-Path $snapshotPath -Leaf)``
"@
$md | Set-Content $reportPath

Write-Host "`nTime to contain: $minutes minutes" -ForegroundColor Cyan
Write-Host "Timeline: $timelinePath`nReport:   $reportPath`nSnapshot: $snapshotPath" -ForegroundColor Cyan
if ($failures) { Write-Host "$($failures.Count) step(s) failed - check the timeline." -ForegroundColor Red }
