# Emergency Offboarding Runbook

**Trigger:** HR calls or opens a ticket: an employee is being let go, effective now.
**Goal:** No access within 15 minutes of the request, with a timestamped record.

## Before you start

- Confirm the request came from HR through a known channel (call back on a known number if it came by email or chat).
- Get the ticket number, the person's UPN and the exact effective time.
- For a sensitive termination, agree the timing with HR so access is cut while the person is in the meeting.

## Entra ID (cloud identity) — the script does this

```powershell
cd 03-offboarding\scripts
.\Invoke-Offboarding.ps1 -UserPrincipalName <upn> -TicketId <ticket> -Reason '<reason>' -RequestedAt '<time HR called>'
```

| Order | Control | Why this order |
|-------|---------|----------------|
| 1 | Snapshot access | Evidence of what they had; needed if they're rehired or an auditor asks |
| 2 | Disable account | Stops new sign-ins |
| 3 | Revoke sessions | A disabled account can keep using an open session until its token expires; this ends it |
| 4 | Reset password | A cached or saved password stops working everywhere |
| 5–7 | Remove groups, admin roles, app assignments | Cleans up access so re-enabling the account by mistake grants nothing |
| 9 | Verify | Proves each control took effect, instead of assuming it did |

## Active Directory (hybrid accounts)

If the account syncs from on-prem AD, disable it there too. Otherwise the next sync can turn the cloud account back on.

```powershell
Disable-ADAccount -Identity <samAccountName>
Set-ADAccountPassword -Identity <samAccountName> -Reset -NewPassword (Read-Host -AsSecureString 'Random password')
Get-ADPrincipalGroupMembership <samAccountName> | Where-Object Name -ne 'Domain Users' |
    ForEach-Object { Remove-ADGroupMember -Identity $_ -Members <samAccountName> -Confirm:$false }
Move-ADObject -Identity (Get-ADUser <samAccountName>).DistinguishedName -TargetPath 'OU=Disabled Users,DC=corp,DC=local'
```

Then run a delta sync from the Entra Connect server: `Start-ADSyncSyncCycle -PolicyType Delta`.

## Okta (if the company uses Okta)

| Entra ID step | Okta equivalent |
|---------------|-----------------|
| Disable account | Admin console > Directory > People > user > **Deactivate**, or `POST /api/v1/users/{id}/lifecycle/deactivate` |
| Revoke sessions | **Clear user sessions**, or `DELETE /api/v1/users/{id}/sessions?oauthTokens=true` |
| Remove app access | Deactivation unassigns apps and, with provisioning on, deactivates the downstream accounts |

## Outside identity systems

- Apps with local logins (not behind SSO): disable each by hand and list them in the ticket
- VPN tokens, building badge, shared mailbox delegations, company phone
- Mailbox: convert to shared or forward to the manager, per policy
- Hardware return

## Close the ticket

Attach the timeline CSV and the Markdown report, state the time to contain, and list anything still manual.
