<#
.SYNOPSIS
    Applies a completed access review: removes revoked access and records every decision.

.DESCRIPTION
    Reads the CSV from Export-AccessReport.ps1 after a reviewer has filled in
    Decision (Certify or Revoke), Justification and Reviewer.

    The file is validated first. The script stops before touching the tenant if any row:
      - has no decision or an unknown decision
      - has no reviewer
      - is a Revoke, or a Certify of a flagged account, with no justification

    Then each Revoke removes the user from the group, and every decision (Certify and
    Revoke) is written to an audit log as evidence for auditors.

.EXAMPLE
    # Check the completed file without connecting to the tenant
    .\Invoke-ReviewDecisions.ps1 -ReviewPath ..\data\sample_review_completed.csv -ValidateOnly

.EXAMPLE
    # Preview, then apply
    .\Invoke-ReviewDecisions.ps1 -ReviewPath .\reports\access_review_20261118.csv -WhatIf
    .\Invoke-ReviewDecisions.ps1 -ReviewPath .\reports\access_review_20261118.csv
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$ReviewPath,
    [switch]$ValidateOnly,
    [string]$LogPath = ".\logs\review_decisions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'
$rows = @(Import-Csv $ReviewPath)

# ---------- 1. Validate ----------
$problems = foreach ($r in $rows) {
    $who = "$($r.Group) / $($r.UserPrincipalName)"
    if ($r.Decision -notin 'Certify', 'Revoke') { "$who : Decision must be Certify or Revoke (found '$($r.Decision)')" }
    if (-not $r.Reviewer)                      { "$who : Reviewer is empty" }
    $needsReason = $r.Decision -eq 'Revoke' -or ($r.Decision -eq 'Certify' -and $r.Flags)
    if ($needsReason -and -not $r.Justification) { "$who : Justification is required for this decision" }
}
if ($problems) {
    Write-Host "Review file is incomplete. Nothing was changed:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

$overrides = @($rows | Where-Object { $_.Recommendation -eq 'Revoke' -and $_.Decision -eq 'Certify' })
Write-Host ("Review file is valid: {0} certify, {1} revoke." -f
    @($rows | Where-Object Decision -eq 'Certify').Count,
    @($rows | Where-Object Decision -eq 'Revoke').Count) -ForegroundColor Green
if ($overrides) {
    Write-Host "Reviewer kept access the report recommended revoking (check these justifications):" -ForegroundColor Yellow
    $overrides | ForEach-Object { Write-Host "  - $($_.Group) / $($_.UserPrincipalName): $($_.Justification)" -ForegroundColor Yellow }
}
if ($ValidateOnly) { return }

# ---------- 2. Apply ----------
Connect-MgGraph -Scopes 'GroupMember.ReadWrite.All', 'Group.Read.All', 'User.Read.All' -NoWelcome
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null

function Write-AuditLog($Row, $Action, $Result = 'Success', $Detail = '') {
    [pscustomobject]@{
        Timestamp     = (Get-Date).ToString('s')
        Group         = $Row.Group
        User          = $Row.UserPrincipalName
        Decision      = $Row.Decision
        Action        = $Action
        Reviewer      = $Row.Reviewer
        Justification = $Row.Justification
        Result        = $Result
        Detail        = $Detail
    } | Export-Csv -Path $LogPath -Append -NoTypeInformation
}

$groupIds = @{}
foreach ($r in $rows) {
    try {
        if ($r.Decision -eq 'Certify') {
            Write-AuditLog $r 'Certified'
            Write-Host "[Certified] $($r.Group) / $($r.UserPrincipalName)" -ForegroundColor Green
            continue
        }

        if (-not $groupIds.ContainsKey($r.Group)) {
            $g = Get-MgGroup -Filter "displayName eq '$($r.Group)'"
            if (-not $g) { throw "Group '$($r.Group)' not found" }
            $groupIds[$r.Group] = $g.Id
        }
        $userId = if ($r.UserId) { $r.UserId } else { (Get-MgUser -UserId $r.UserPrincipalName).Id }

        if ($PSCmdlet.ShouldProcess("$($r.UserPrincipalName)", "Remove from $($r.Group)")) {
            Remove-MgGroupMemberByRef -GroupId $groupIds[$r.Group] -DirectoryObjectId $userId
            Write-AuditLog $r 'Removed'
            Write-Host "[Removed]   $($r.Group) / $($r.UserPrincipalName)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-AuditLog $r 'Error' 'Failure' $_.Exception.Message
        Write-Host "[Error]     $($r.Group) / $($r.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host "`nDone. Evidence log: $LogPath" -ForegroundColor Cyan
