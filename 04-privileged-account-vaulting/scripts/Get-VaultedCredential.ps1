<#
.SYNOPSIS
    Checks a privileged password out of the vault, with a required justification.

.DESCRIPTION
    - Requires a ticket number and a justification (at least 15 characters)
    - Tags the secret with who checked it out, when and why
    - Key Vault's own audit log separately records the read, with the caller's identity and IP
    - Returns a PSCredential object; the password is never printed to the screen
    - Reminds you to rotate the password when you're done, so the checked-out copy stops working

.EXAMPLE
    $cred = .\Get-VaultedCredential.ps1 -VaultName kv-iamlab-khalif -Account adm-priya.patel@yourtenant.onmicrosoft.com -TicketId CHG-2231 -Justification 'Reset MFA for locked-out VP per ticket'
    # Sign in as the account in a private browser window; copy the password only when you need it:
    $cred.GetNetworkCredential().Password | Set-Clipboard
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$VaultName,
    [Parameter(Mandatory)] [string]$Account,
    [Parameter(Mandatory)] [string]$TicketId,
    [Parameter(Mandatory)] [ValidateLength(15, 500)] [string]$Justification,
    [string]$LogPath = '.\logs\vault_activity.csv'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\VaultCommon.ps1"
if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }

$name = Get-SecretNameForAccount $Account
$secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $name
if (-not $secret -or $secret.Tags['status'] -ne 'active') { throw "No active vaulted credential for $Account." }

$operator = (Get-AzContext).Account.Id
$tags = @{}; $secret.Tags.GetEnumerator() | ForEach-Object { $tags[$_.Key] = $_.Value }
$tags['lastCheckoutBy']     = $operator
$tags['lastCheckoutUtc']    = (Get-Date).ToUniversalTime().ToString('s')
$tags['lastCheckoutTicket'] = $TicketId
Update-AzKeyVaultSecret -VaultName $VaultName -Name $name -Version $secret.Version -Tag $tags | Out-Null

Write-VaultLog $LogPath 'Checkout' $Account "Ticket $TicketId - $Justification"
Write-Host "Checked out. When you're finished, rotate it:" -ForegroundColor Yellow
Write-Host "  .\Invoke-CredentialRotation.ps1 -VaultName $VaultName -Account $Account -Force" -ForegroundColor Yellow

New-Object System.Management.Automation.PSCredential($Account, $secret.SecretValue)
