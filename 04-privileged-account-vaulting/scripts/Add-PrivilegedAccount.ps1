<#
.SYNOPSIS
    Onboards a privileged account into the vault.

.DESCRIPTION
    Gives the account a new random password that no person ever sees, stores it in
    Key Vault, and tags it for automatic rotation. From then on, the only way to use
    the account is to check its password out of the vault (Get-VaultedCredential.ps1).

    Lab tip: vault an account that holds no standing admin role and gets its role
    through PIM. Entra ID won't let a script reset the password of an active admin
    without a higher admin role, and standing admin access is the risk you're removing.

.EXAMPLE
    .\Add-PrivilegedAccount.ps1 -VaultName kv-iamlab-khalif -UserPrincipalName adm-priya.patel@yourtenant.onmicrosoft.com -Owner priya.patel@yourtenant.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$VaultName,
    [Parameter(Mandatory)] [string]$UserPrincipalName,
    [Parameter(Mandatory)] [string]$Owner,
    [int]$RotationHours = 24,
    [string]$LogPath = '.\logs\vault_activity.csv'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\VaultCommon.ps1"

if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
Connect-MgGraph -Scopes 'User.ReadWrite.All' -NoWelcome

$secretName = Get-SecretNameForAccount $UserPrincipalName
if (Get-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -ErrorAction SilentlyContinue) {
    throw "$UserPrincipalName is already vaulted as '$secretName'."
}
Get-MgUser -UserId $UserPrincipalName | Out-Null   # fails early if the account doesn't exist

if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Set random password and store it in the vault')) {
    $password = New-VaultPassword
    $tags = @{
        managedBy     = $script:ManagedTag
        account       = $UserPrincipalName
        owner         = $Owner
        rotationHours = "$RotationHours"
        status        = 'active'
    }
    # Store first, then change the real password: if the reset fails, the old password still works.
    $secret = Set-AzKeyVaultSecret -VaultName $VaultName -Name $secretName `
                -SecretValue (ConvertTo-SecureString $password -AsPlainText -Force) `
                -ContentType 'password' -Tag $tags
    try {
        Set-EntraPassword $UserPrincipalName $password
    } catch {
        Update-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -Version $secret.Version -Enable $false | Out-Null
        Write-VaultLog $LogPath 'Onboard' $UserPrincipalName "Password reset failed; vault entry disabled: $($_.Exception.Message)" 'Failure'
        throw
    }
    Remove-Variable password
    Write-VaultLog $LogPath 'Onboard' $UserPrincipalName "Stored as '$secretName', rotates every $RotationHours h"
}
