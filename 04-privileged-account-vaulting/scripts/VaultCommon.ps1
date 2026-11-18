# Shared helpers for the vaulting scripts. Dot-source it: . "$PSScriptRoot\VaultCommon.ps1"

$script:ManagedTag = 'iam-lab-vault'

function New-VaultPassword([int]$Length = 32) {
    # Cryptographically random, with every character class present.
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%^&*-_=+')
    $all  = -join $sets
    $chars = foreach ($s in $sets) { $s[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($s.Length)] }
    $chars += 1..($Length - $sets.Count) | ForEach-Object { $all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)] }
    -join ($chars | Sort-Object { [System.Security.Cryptography.RandomNumberGenerator]::GetInt32([int]::MaxValue) })
}

function Get-SecretNameForAccount([string]$UserPrincipalName) {
    # Key Vault secret names allow letters, digits and dashes only.
    'acct-' + ($UserPrincipalName.ToLower() -replace '[^a-z0-9]', '-')
}

function Set-EntraPassword([string]$UserPrincipalName, [string]$Password) {
    Update-MgUser -UserId $UserPrincipalName -PasswordProfile @{
        Password                      = $Password
        ForceChangePasswordNextSignIn = $false
    }
}

function Write-VaultLog([string]$Path, [string]$Action, [string]$Account, [string]$Detail, [string]$Result = 'Success') {
    New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null
    [pscustomobject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('s')
        Operator  = (Get-AzContext).Account.Id
        Action    = $Action
        Account   = $Account
        Detail    = $Detail
        Result    = $Result
    } | Export-Csv -Path $Path -Append -NoTypeInformation
    $color = if ($Result -eq 'Success') { 'Green' } else { 'Red' }
    Write-Host "[$Action] $Account - $Detail" -ForegroundColor $color
}
