<#
.SYNOPSIS
    New-hire onboarding: creates the account, provisions app access by role,
    and issues a Temporary Access Pass (TAP) so the user enrolls in MFA at first sign-in.

.DESCRIPTION
    Reads a new-hire CSV (the "HR ticket") and, for each person:
      1. Creates the Entra ID account with a unique UPN, department, title and manager.
      2. Adds the groups the role matrix defines for their department and job title.
         Enterprise apps are assigned to those groups, so group membership = app access.
      3. Creates a Temporary Access Pass that becomes valid at 7:00 on their start date,
         so they can sign in and register MFA before 9:00 without ever knowing a password.

    Users are matched on employeeId, so running the script twice never creates duplicates.
    Every action goes to a CSV audit log. TAP values are shown once on screen and never logged.
    Supports -WhatIf to preview changes.

.EXAMPLE
    .\Invoke-Onboarding.ps1 -NewHiresPath ..\data\new_hires.csv -RoleMatrixPath ..\data\role_matrix.csv -Domain yourtenant.onmicrosoft.com -CreateMissingGroups -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$NewHiresPath,
    [Parameter(Mandatory)] [string]$RoleMatrixPath,
    [Parameter(Mandatory)] [string]$Domain,
    [switch]$CreateMissingGroups,
    [switch]$SkipTemporaryAccessPass,
    [int]$TapLifetimeMinutes = 480,
    [string]$TimeZone = 'Central Standard Time',
    [string]$LogPath = ".\logs\onboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'

# --- Least privilege: only the Graph permissions this script needs ---
$scopes = @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Group.Read.All')
if ($CreateMissingGroups)      { $scopes += 'Group.ReadWrite.All' }
if (-not $SkipTemporaryAccessPass) { $scopes += 'UserAuthenticationMethod.ReadWrite.All' }
Connect-MgGraph -Scopes $scopes -NoWelcome

New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null

function Write-AuditLog {
    param($Action, $EmployeeID, $UPN, $Detail, $Result = 'Success')
    [pscustomobject]@{
        Timestamp  = (Get-Date).ToString('s')
        Action     = $Action
        EmployeeID = $EmployeeID
        UPN        = $UPN
        Detail     = $Detail
        Result     = $Result
    } | Export-Csv -Path $LogPath -Append -NoTypeInformation
    $color = switch ($Result) { 'Success' { 'Green' } 'Warning' { 'Yellow' } default { 'Red' } }
    Write-Host ("[{0}] {1} {2} - {3}" -f $Action, $EmployeeID, $UPN, $Detail) -ForegroundColor $color
}

function New-RandomPassword {
    # Throwaway password the user never sees; they sign in with the TAP instead.
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%'
    -join (1..24 | ForEach-Object { $chars[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($chars.Length)] })
}

function ConvertTo-UpnPart([string]$Text) {
    # "Mary-Kate O'Neil" -> "mary-kateoneil"
    ($Text.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', '' -replace "[^a-zA-Z0-9-]", '').ToLower()
}

function Get-UserByEmployeeId([string]$EmployeeId) {
    Get-MgUser -Filter "employeeId eq '$EmployeeId'" -ConsistencyLevel eventual -CountVariable c `
               -Property Id, DisplayName, UserPrincipalName, EmployeeId
}

function Get-UniqueUpn([string]$First, [string]$Last) {
    $base = "{0}.{1}" -f (ConvertTo-UpnPart $First), (ConvertTo-UpnPart $Last)
    $candidate = "$base@$Domain"
    $n = 2
    while (Get-MgUser -Filter "userPrincipalName eq '$candidate'" -ErrorAction SilentlyContinue) {
        $candidate = "$base$n@$Domain"; $n++
    }
    $candidate
}

function Get-TapStartUtc([string]$StartDate) {
    # TAP becomes valid at 07:00 local time on the start date (or now, if that has passed).
    $tz = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZone)
    $local = [datetime]::ParseExact($StartDate, 'yyyy-MM-dd', $null).AddHours(7)
    $utc = [TimeZoneInfo]::ConvertTimeToUtc([datetime]::SpecifyKind($local, 'Unspecified'), $tz)
    if ($utc -lt (Get-Date).ToUniversalTime()) { $utc = (Get-Date).ToUniversalTime() }
    $utc
}

# --- Role matrix: "Department|JobTitle" -> groups ---
$roleMap = @{}
Import-Csv $RoleMatrixPath | ForEach-Object {
    $roleMap["$($_.Department)|$($_.JobTitle)"] = @($_.Groups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$groupIds = @{}
foreach ($name in ($roleMap.Values | ForEach-Object { $_ } | Sort-Object -Unique)) {
    $g = Get-MgGroup -Filter "displayName eq '$name'"
    if (-not $g -and $CreateMissingGroups -and $PSCmdlet.ShouldProcess($name, 'Create security group')) {
        $g = New-MgGroup -DisplayName $name -Description 'IAM lab - provisioned by role' `
                         -MailEnabled:$false -MailNickname ($name -replace '[^a-zA-Z0-9]', '') -SecurityEnabled
        Write-AuditLog 'GroupCreate' '' '' $name
    }
    if (-not $g) { throw "Group '$name' not found. Re-run with -CreateMissingGroups." }
    $groupIds[$name] = $g.Id
}

$handoff = @()

foreach ($hire in Import-Csv $NewHiresPath) {
    try {
        $roleKey = "$($hire.Department)|$($hire.JobTitle)"
        if (-not $roleMap.ContainsKey($roleKey)) {
            Write-AuditLog 'Skipped' $hire.EmployeeID '' "No role defined for '$roleKey'" 'Warning'
            continue
        }

        # ---------- 1. ACCOUNT ----------
        $user = Get-UserByEmployeeId $hire.EmployeeID
        if ($user) {
            Write-AuditLog 'Exists' $hire.EmployeeID $user.UserPrincipalName 'Account already exists; checking access only' 'Warning'
        }
        else {
            $upn = Get-UniqueUpn $hire.FirstName $hire.LastName
            if (-not $PSCmdlet.ShouldProcess($upn, "Create account ($roleKey)")) { continue }
            $user = New-MgUser -AccountEnabled `
                -DisplayName "$($hire.FirstName) $($hire.LastName)" `
                -GivenName $hire.FirstName -Surname $hire.LastName `
                -MailNickname ($upn.Split('@')[0]) `
                -UserPrincipalName $upn `
                -Department $hire.Department -JobTitle $hire.JobTitle `
                -EmployeeId $hire.EmployeeID `
                -UsageLocation 'US' `
                -PasswordProfile @{ Password = (New-RandomPassword); ForceChangePasswordNextSignIn = $true }
            Write-AuditLog 'AccountCreate' $hire.EmployeeID $upn "$($hire.JobTitle), $($hire.Department), starts $($hire.StartDate)"
        }

        # ---------- 2. APP ACCESS BY ROLE ----------
        $current = @(Get-MgUserMemberOf -UserId $user.Id -All |
                     Where-Object { $groupIds.Values -contains $_.Id } | ForEach-Object { $_.Id })
        foreach ($g in $roleMap[$roleKey]) {
            if ($current -contains $groupIds[$g]) { continue }
            if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Add to $g")) {
                New-MgGroupMember -GroupId $groupIds[$g] -DirectoryObjectId $user.Id
                Write-AuditLog 'GroupAdd' $hire.EmployeeID $user.UserPrincipalName $g
            }
        }

        if ($hire.ManagerEmployeeID) {
            $mgr = Get-UserByEmployeeId $hire.ManagerEmployeeID
            if ($mgr -and $PSCmdlet.ShouldProcess($user.UserPrincipalName, "Set manager $($mgr.UserPrincipalName)")) {
                Set-MgUserManagerByRef -UserId $user.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr.Id)" }
                Write-AuditLog 'ManagerSet' $hire.EmployeeID $user.UserPrincipalName $mgr.UserPrincipalName
            }
        }

        # ---------- 3. MFA ON FIRST SIGN-IN (Temporary Access Pass) ----------
        if (-not $SkipTemporaryAccessPass) {
            $start = Get-TapStartUtc $hire.StartDate
            if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Create Temporary Access Pass valid from $($start.ToString('u'))")) {
                $tap = $null
                foreach ($attempt in 1..5) {
                    # A brand-new account can take a few seconds to replicate.
                    try {
                        $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -BodyParameter @{
                            startDateTime     = $start.ToString('o')
                            lifetimeInMinutes = $TapLifetimeMinutes
                            isUsableOnce      = $false
                        }
                        break
                    } catch {
                        if ($attempt -eq 5) { throw }
                        Start-Sleep -Seconds 10
                    }
                }
                Write-AuditLog 'TapCreate' $hire.EmployeeID $user.UserPrincipalName "Valid from $($start.ToString('u')) for $TapLifetimeMinutes min (value not logged)"
                $handoff += [pscustomobject]@{
                    User      = $user.UserPrincipalName
                    ValidFrom = $start.ToString('u')
                    TAP       = $tap.TemporaryAccessPass
                }
            }
        }
    }
    catch {
        Write-AuditLog 'Error' $hire.EmployeeID '' $_.Exception.Message 'Failure'
    }
}

if ($handoff) {
    Write-Host "`nTemporary Access Passes - give each one to the hiring manager through a secure channel." -ForegroundColor Yellow
    Write-Host "They are shown once and are not saved anywhere." -ForegroundColor Yellow
    $handoff | Format-Table -AutoSize
}
Write-Host "Done. Audit log: $LogPath" -ForegroundColor Cyan
