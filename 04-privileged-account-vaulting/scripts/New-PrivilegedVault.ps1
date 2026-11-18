<#
.SYNOPSIS
    Builds the vault: an Azure Key Vault with RBAC access and audit logging to Log Analytics.

.DESCRIPTION
    Creates (or reuses):
      - a resource group
      - a Log Analytics workspace that stores the vault's audit log
      - a Key Vault that uses Azure RBAC (no shared access policies) with purge protection
      - a diagnostic setting that sends every secret read and write to the workspace
      - the "Key Vault Secrets Officer" role for you, so you can manage vaulted credentials

    Key Vault plays the role CyberArk or BeyondTrust plays in a company: one locked place
    for privileged passwords, with a record of every checkout.

.EXAMPLE
    .\New-PrivilegedVault.ps1 -ResourceGroupName rg-iam-lab -VaultName kv-iamlab-khalif -Location centralus
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)] [ValidatePattern('^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$')] [string]$VaultName,
    [string]$Location = 'centralus',
    [string]$WorkspaceName = 'law-iam-lab'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
$me = (Get-AzContext).Account.Id

if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Create resource group')) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
        Write-Host "Created resource group $ResourceGroupName" -ForegroundColor Green
    }
}

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $workspace -and $PSCmdlet.ShouldProcess($WorkspaceName, 'Create Log Analytics workspace')) {
    $workspace = New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -Location $Location -Sku PerGB2018
    Write-Host "Created Log Analytics workspace $WorkspaceName" -ForegroundColor Green
}

$vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $vault -and $PSCmdlet.ShouldProcess($VaultName, 'Create Key Vault (RBAC, purge protection)')) {
    $vault = New-AzKeyVault -Name $VaultName -ResourceGroupName $ResourceGroupName -Location $Location -EnablePurgeProtection
    Write-Host "Created Key Vault $VaultName" -ForegroundColor Green
}
if ($vault -and -not $vault.EnableRbacAuthorization) {
    Write-Warning "$VaultName uses access policies, not Azure RBAC. Switch it under Key Vault > Access configuration > Azure role-based access control."
}

if ($vault -and $workspace -and $PSCmdlet.ShouldProcess($VaultName, 'Send audit logs to Log Analytics')) {
    $log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup 'audit'
    New-AzDiagnosticSetting -Name 'vault-audit-to-law' -ResourceId $vault.ResourceId -WorkspaceId $workspace.ResourceId -Log $log | Out-Null
    Write-Host "Audit logging enabled: every secret read and write goes to $WorkspaceName" -ForegroundColor Green
}

if ($vault -and $PSCmdlet.ShouldProcess($me, 'Grant Key Vault Secrets Officer on the vault')) {
    $existing = Get-AzRoleAssignment -SignInName $me -Scope $vault.ResourceId -RoleDefinitionName 'Key Vault Secrets Officer' -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-AzRoleAssignment -SignInName $me -RoleDefinitionName 'Key Vault Secrets Officer' -Scope $vault.ResourceId | Out-Null
        Write-Host "Granted Key Vault Secrets Officer to $me (role assignments can take a few minutes to apply)" -ForegroundColor Green
    }
}

Write-Host "`nVault ready. Next: .\Add-PrivilegedAccount.ps1 -VaultName $VaultName -UserPrincipalName <account>" -ForegroundColor Cyan
