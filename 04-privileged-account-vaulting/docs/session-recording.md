# Session Recording for Privileged Logins

The scenario asks for every privileged login to be recorded. That part doesn't have a free option in this lab, so here is what exists and what this project does instead.

## What companies use

| Tool | How it records |
|------|----------------|
| CyberArk Privileged Session Manager (PSM) | The admin connects through a proxy; CyberArk injects the vaulted password and records video plus keystrokes |
| BeyondTrust Password Safe | Same proxy model, with session playback and search |
| Azure Bastion (Premium SKU) | Records RDP and SSH sessions to Azure VMs into a storage account |

All three use the same idea: the admin never sees the password, and the session runs through a gateway that records it.

## What this lab records instead

| Event | Where it's recorded |
|-------|---------------------|
| Who read a vaulted password, when, from which IP | Key Vault audit log in Log Analytics (`queries/vault-checkouts.kql`) |
| Ticket and reason for each checkout | Tags on the secret version, plus `logs/vault_activity.csv` |
| Each admin role activation, with justification | PIM audit history (Identity governance > PIM > Resource audit) |
| What the admin did while signed in | Entra audit logs and sign-in logs for the vaulted account |

## If you want to try real recording

Azure Bastion Premium can record sessions to a VM in your subscription. It's billed per hour, so create it, test one recorded session, capture screenshots and delete it the same day. Check current pricing before you start.

## How to talk about it

"In the lab I covered vaulting, rotation and checkout auditing with Key Vault and PIM. Session recording needs a gateway like CyberArk PSM or Bastion Premium. I know how it works: the admin connects through the proxy, the vault injects the credential, and the session is recorded. I'd configure it in the company's PAM tool."
