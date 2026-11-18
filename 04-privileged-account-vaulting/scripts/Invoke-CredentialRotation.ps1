<#
.SYNOPSIS
    Rotates vaulted passwords that are older than their rotation interval (24 hours by default).

.DESCRIPTION
    For every secret tagged as managed by this lab:
      1. Skips it if it was rotated within its interval (unless -Force)
      2. Writes the new password to the vault as a new version marked 'pending'
      3. Resets the account's password in Entra ID
      4. Marks the new version 'active'; if the reset failed, disables the pending version
         so the vault never hands out a password that doesn't work

    Run it on a schedule as an Azure Automation runbook with -UseManagedIdentity.
    Run it with -Force -Account after a checkout, so a checked-out password stops working.

.EXAMPLE
    .\Invoke-CredentialRotation.ps1 -VaultName kv-iamlab-khalif -WhatIf
    .\Invoke-CredentialRotation.ps1 -VaultName kv-iamlab-khalif -Account adm-priya.patel@yourtenant.onmicrosoft.com -Force
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$VaultName,
    [string]$Account,
    [switch]$Force,
    [switch]$UseManagedIdentity,
    [string]$LogPath = '.\logs\vault_activity.csv'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\VaultCommon.ps1"

if ($UseManagedIdentity) {
    Connect-AzAccount -Identity | Out-Null
    Connect-MgGraph -Identity -NoWelcome      # needs User-PasswordProfile.ReadWrite.All (application)
} else {
    if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
    Connect-MgGraph -Scopes 'User.ReadWrite.All' -NoWelcome
}

$secrets = Get-AzKeyVaultSecret -VaultName $VaultName |
           Where-Object { $_.Tags -and $_.Tags['managedBy'] -eq $script:ManagedTag }
if ($Account) { $secrets = $secrets | Where-Object { $_.Tags['account'] -eq $Account } }
if (-not $secrets) { Write-Host 'No vaulted accounts matched.' -ForegroundColor Yellow; return }

foreach ($s in $secrets) {
    $upn   = $s.Tags['account']
    $hours = if ($s.Tags['rotationHours']) { [int]$s.Tags['rotationHours'] } else { 24 }
    $age   = ((Get-Date).ToUniversalTime() - $s.Updated.ToUniversalTime()).TotalHours

    if (-not $Force -and $age -lt $hours) {
        Write-Host ("[Current] {0} - rotated {1:N1} h ago (interval {2} h)" -f $upn, $age, $hours) -ForegroundColor DarkGray
        continue
    }
    if (-not $PSCmdlet.ShouldProcess($upn, 'Rotate password')) { continue }

    $tags = @{}; $s.Tags.GetEnumerator() | ForEach-Object { $tags[$_.Key] = $_.Value }
    $tags['status'] = 'pending'
    $tags.Remove('lastCheckoutBy'); $tags.Remove('lastCheckoutUtc'); $tags.Remove('lastCheckoutTicket')

    $password = New-VaultPassword
    $new = Set-AzKeyVaultSecret -VaultName $VaultName -Name $s.Name `
             -SecretValue (ConvertTo-SecureString $password -AsPlainText -Force) -ContentType 'password' -Tag $tags
    try {
        Set-EntraPassword $upn $password
        $tags['status'] = 'active'
        $tags['rotatedUtc'] = (Get-Date).ToUniversalTime().ToString('s')
        Update-AzKeyVaultSecret -VaultName $VaultName -Name $s.Name -Version $new.Version -Tag $tags | Out-Null
        Write-VaultLog $LogPath 'Rotate' $upn ("New version {0} (previous was {1:N1} h old)" -f $new.Version.Substring(0, 8), $age)
    }
    catch {
        Update-AzKeyVaultSecret -VaultName $VaultName -Name $s.Name -Version $new.Version -Enable $false | Out-Null
        Write-VaultLog $LogPath 'Rotate' $upn "Entra reset failed; pending version disabled, previous password still valid: $($_.Exception.Message)" 'Failure'
    }
    finally { Remove-Variable password -ErrorAction SilentlyContinue }
}
