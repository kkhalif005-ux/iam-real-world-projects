<#
.SYNOPSIS
    Answers "who has access to this system, and should they still have it?"

.DESCRIPTION
    Pulls every member of one or more groups (the groups that grant access to an app),
    then flags accounts that need a decision:
      - Disabled      : account is disabled but still holds access
      - Stale         : no sign-in for -StaleDays days (accounts newer than that are skipped)
      - RoleMismatch  : the role matrix says their department/title shouldn't have this group
      - Guest         : external account
      - Privileged    : the group grants sensitive access, so a reviewer must certify it explicitly

    Each row gets a recommendation (Revoke, Review or Certify) and empty Decision,
    Justification and Reviewer columns for the reviewer to fill in. Feed the completed
    file to Invoke-ReviewDecisions.ps1.

    Use -SampleDataPath to run the analysis on the sample file with no tenant.

.EXAMPLE
    # Offline demo on sample data
    .\Export-AccessReport.ps1 -SampleDataPath ..\data\sample_group_members.csv -RoleMatrixPath ..\data\role_matrix.csv -AsOfDate 2026-11-18

.EXAMPLE
    # Live report from your tenant
    .\Export-AccessReport.ps1 -GroupName 'GRP-Finance-Users','GRP-Finance-Approvers' -RoleMatrixPath ..\data\role_matrix.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Live')]   [string[]]$GroupName,
    [Parameter(Mandatory, ParameterSetName = 'Sample')] [string]$SampleDataPath,
    [string]$RoleMatrixPath,
    [int]$StaleDays = 90,
    [string]$PrivilegedPattern = 'Admin|Approver|Confidential|Privileged',
    [datetime]$AsOfDate = (Get-Date),
    [string]$OutputPath = ".\reports\access_review_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'

# ---------- 1. Collect members ----------
if ($PSCmdlet.ParameterSetName -eq 'Sample') {
    $members = Import-Csv $SampleDataPath
}
else {
    # signInActivity needs AuditLog.Read.All and an Entra ID P1/P2 license
    Connect-MgGraph -Scopes 'GroupMember.Read.All', 'User.Read.All', 'AuditLog.Read.All' -NoWelcome
    $members = foreach ($name in $GroupName) {
        $group = Get-MgGroup -Filter "displayName eq '$name'"
        if (-not $group) { Write-Warning "Group '$name' not found"; continue }
        $ids = Get-MgGroupMember -GroupId $group.Id -All |
               Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user' } |
               ForEach-Object { $_.Id }
        foreach ($id in $ids) {
            $u = Get-MgUser -UserId $id -Property Id, DisplayName, UserPrincipalName, UserType, AccountEnabled, Department, JobTitle, CreatedDateTime, SignInActivity
            [pscustomobject]@{
                Group             = $name
                UserId            = $u.Id
                DisplayName       = $u.DisplayName
                UserPrincipalName = $u.UserPrincipalName
                UserType          = $u.UserType
                AccountEnabled    = $u.AccountEnabled
                Department        = $u.Department
                JobTitle          = $u.JobTitle
                LastSignIn        = if ($u.SignInActivity.LastSignInDateTime) { $u.SignInActivity.LastSignInDateTime.ToString('s') } else { '' }
                CreatedDateTime   = if ($u.CreatedDateTime) { $u.CreatedDateTime.ToString('s') } else { '' }
            }
        }
    }
}

# ---------- 2. Role matrix (optional) ----------
$roleMap = @{}
$managedGroups = @()
if ($RoleMatrixPath) {
    Import-Csv $RoleMatrixPath | ForEach-Object {
        $groups = @($_.Groups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $roleMap["$($_.Department)|$($_.JobTitle)"] = $groups
        $managedGroups += $groups
    }
    $managedGroups = $managedGroups | Sort-Object -Unique
}

# ---------- 3. Flag and recommend ----------
$report = foreach ($m in $members) {
    $flags = @()
    $enabled = "$($m.AccountEnabled)" -eq 'True'
    $isGuest = $m.UserType -eq 'Guest'

    $days = $null
    if ($m.LastSignIn) { $days = [int]($AsOfDate - [datetime]$m.LastSignIn).TotalDays }
    $ageDays = if ($m.CreatedDateTime) { [int]($AsOfDate - [datetime]$m.CreatedDateTime).TotalDays } else { [int]::MaxValue }

    if (-not $enabled) { $flags += 'Disabled' }
    if ($ageDays -gt $StaleDays -and ($null -eq $days -or $days -gt $StaleDays)) {
        $flags += 'Stale'
    }
    if ($isGuest) { $flags += 'Guest' }
    elseif ($RoleMatrixPath -and $managedGroups -contains $m.Group) {
        $allowed = $roleMap["$($m.Department)|$($m.JobTitle)"]
        if (-not $allowed -or $allowed -notcontains $m.Group) { $flags += 'RoleMismatch' }
    }
    if ($m.Group -match $PrivilegedPattern) { $flags += 'Privileged' }

    $recommendation =
        if ($flags | Where-Object { $_ -in 'Disabled', 'Stale', 'RoleMismatch' }) { 'Revoke' }
        elseif ($flags) { 'Review' }
        else { 'Certify' }

    [pscustomobject]@{
        Group             = $m.Group
        DisplayName       = $m.DisplayName
        UserPrincipalName = $m.UserPrincipalName
        Department        = $m.Department
        JobTitle          = $m.JobTitle
        AccountEnabled    = $enabled
        LastSignIn        = $m.LastSignIn
        DaysSinceSignIn   = if ($null -ne $days) { $days } else { 'Never' }
        Flags             = $flags -join ';'
        Recommendation    = $recommendation
        Decision          = ''
        Justification     = ''
        Reviewer          = ''
        UserId            = $m.UserId
    }
}

New-Item -ItemType Directory -Path (Split-Path $OutputPath) -Force | Out-Null
$report | Sort-Object Group, @{ Expression = { @{ Revoke = 0; Review = 1; Certify = 2 }[$_.Recommendation] } }, DisplayName |
    Export-Csv -Path $OutputPath -NoTypeInformation

# ---------- 4. Summary ----------
Write-Host "`nAccess review as of $($AsOfDate.ToString('yyyy-MM-dd'))  (stale = no sign-in for $StaleDays+ days)`n" -ForegroundColor Cyan
$order = @{ Revoke = 0; Review = 1; Certify = 2 }
$report | Sort-Object Group, @{ Expression = { $order[$_.Recommendation] } }, DisplayName |
    Format-Table Group, DisplayName, JobTitle, DaysSinceSignIn, Flags, Recommendation -AutoSize |
    Out-String -Width 200 | Write-Host
$report | Group-Object Recommendation | ForEach-Object { Write-Host ("{0,-8} {1}" -f $_.Name, $_.Count) }
Write-Host "`nReport: $OutputPath" -ForegroundColor Cyan
Write-Host "Next: fill in Decision (Certify/Revoke), Justification and Reviewer, then run Invoke-ReviewDecisions.ps1." -ForegroundColor Cyan
