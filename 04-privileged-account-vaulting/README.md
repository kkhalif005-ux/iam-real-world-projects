# Project 4: Privileged Account Vaulting

## The scenario

An IT admin knows the password to every server. If they leave, get phished or make a mistake, that's a huge risk. Privileged access management (PAM) locks those passwords in a vault, rotates them automatically, and logs every time someone checks one out.

## What this project does

CyberArk and BeyondTrust (the tools named in the original idea) aren't free, so this project builds the same controls with **Azure Key Vault**, Log Analytics and Entra ID PIM.

| Control | How |
|---------|-----|
| Onboard a privileged account into the vault | `Add-PrivilegedAccount.ps1` sets a random password no person sees and stores it in Key Vault |
| Rotate the password every 24 hours | `Invoke-CredentialRotation.ps1` replaces any password older than its interval; run it hourly in Azure Automation |
| Log every checkout | `Get-VaultedCredential.ps1` requires a ticket and a reason; Key Vault's audit log records the caller, time and IP (`queries/vault-checkouts.kql`) |
| Session recording | Needs a paid gateway; see `docs/session-recording.md` for what this lab does instead |

The rotation is ordered so a failure can't lock you out: the new password goes into the vault as "pending", then the real password is changed, then the vault entry is marked "active". If the change fails, the pending entry is disabled and the old password still works.

## Cost

Key Vault and Log Analytics cost cents at lab volume on a pay-as-you-go Azure subscription. The free Azure account credit covers it. Delete the resource group when you're done: `Remove-AzResourceGroup -Name rg-iam-lab`. (Purge protection keeps the deleted vault name reserved for 90 days, so use a new name if you rebuild it.)

## Run it

Use Azure Cloud Shell (PowerShell), which already has the Az and Microsoft Graph modules.

```powershell
cd 04-privileged-account-vaulting/scripts

# 1. Build the vault (vault names are global, so add something unique)
./New-PrivilegedVault.ps1 -ResourceGroupName rg-iam-lab -VaultName kv-iamlab-<yourname>

# 2. Create a lab admin account with no standing role (make it PIM-eligible instead), then vault it
./Add-PrivilegedAccount.ps1 -VaultName kv-iamlab-<yourname> -UserPrincipalName adm-test@yourtenant.onmicrosoft.com -Owner you@yourtenant.onmicrosoft.com

# 3. Check it out with a reason
$cred = ./Get-VaultedCredential.ps1 -VaultName kv-iamlab-<yourname> -Account adm-test@yourtenant.onmicrosoft.com -TicketId CHG-1001 -Justification 'Testing vault checkout for the lab'

# 4. Rotate after use, and preview the scheduled rotation
./Invoke-CredentialRotation.ps1 -VaultName kv-iamlab-<yourname> -Account adm-test@yourtenant.onmicrosoft.com -Force
./Invoke-CredentialRotation.ps1 -VaultName kv-iamlab-<yourname> -WhatIf
```

Then open the Log Analytics workspace and run `queries/vault-checkouts.kql`. Audit events can take 5–15 minutes to appear.

## Schedule rotation every 24 hours (Azure Automation)

1. Create an Automation account in `rg-iam-lab` with a system-assigned managed identity.
2. Give the identity the **Key Vault Secrets Officer** role on the vault.
3. Give it the Microsoft Graph application permission **User-PasswordProfile.ReadWrite.All** (granted with PowerShell; Microsoft documents the steps under "managed identity Graph permissions").
4. Import `VaultCommon.ps1` and `Invoke-CredentialRotation.ps1` as one PowerShell 7.2 runbook, with `-UseManagedIdentity`.
5. Link it to an hourly schedule. Each run rotates only passwords older than 24 hours.

## Why the vaulted account has no standing admin role

Entra ID doesn't let a script reset an active admin's password without an even higher admin role. More importantly, standing admin access is the risk being removed. The vaulted account gets its admin role through PIM: check out the password, then activate the role for a few hours with MFA and a justification.

## Evidence to capture

- The vault with the secret's tags (owner, rotation interval, last checkout)
- The secret's version history after a few rotations
- The KQL results showing a checkout with your identity and IP
- The PIM activation for the vaulted account

## CyberArk / BeyondTrust mapping

| This project | CyberArk |
|--------------|----------|
| Key Vault secret | Account in a safe |
| Add-PrivilegedAccount.ps1 | Account onboarding (manual or through discovery) |
| Invoke-CredentialRotation.ps1 | Central Policy Manager (CPM) rotation policy |
| Get-VaultedCredential.ps1 with a reason | Password checkout with dual control or ticket validation |
| Rotate after checkout | One-time password policy (exclusive access) |
| Key Vault audit log | Vault audit, PTA analytics |
| Session recording (not in lab) | Privileged Session Manager (PSM) |
