# Project 3: Terminated Employee Offboarding

## The scenario

Someone is let go at 9:00 and HR calls IT. The account has to be disabled, every session and app cut off, and the person locked out before they can do damage. Speed matters, and so does proof of when each thing happened.

## What this project does

`Invoke-Offboarding.ps1` runs the whole lockout in one command and writes a timeline:

| Step | Control |
|------|---------|
| 1 | Snapshot of groups, admin roles, app assignments and devices (saved as JSON) |
| 2 | Disable the account |
| 3 | Revoke all sessions and refresh tokens |
| 4 | Reset the password to a random value |
| 5 | Remove cloud group memberships (flags AD-synced groups for removal in AD) |
| 6 | Remove active and PIM-eligible admin roles |
| 7 | Remove direct app assignments |
| 8 | Optionally disable their registered devices |
| 9 | Re-read the account to verify each control |

It then writes a Markdown report with the **time to contain**: minutes from HR's request to sessions revoked.

`docs/offboarding-runbook.md` covers the parts around the script: confirming the request, Active Directory commands for hybrid accounts, the Okta equivalents, and the non-identity steps (mailbox, hardware, badge).

Tools named in the original idea: Active Directory and Okta. This project automates Entra ID and documents the AD and Okta steps.

## Run it

Create a test user first and give them something to remove: add them to two groups, assign an enterprise app, and make them PIM-eligible for a role.

```powershell
cd 03-offboarding\scripts

# Preview
.\Invoke-Offboarding.ps1 -UserPrincipalName test.leaver@yourtenant.onmicrosoft.com -TicketId HR-1042 -Reason 'Involuntary termination' -WhatIf

# Run, recording when HR called
.\Invoke-Offboarding.ps1 -UserPrincipalName test.leaver@yourtenant.onmicrosoft.com -TicketId HR-1042 -Reason 'Involuntary termination' -RequestedAt '2026-11-18 09:00'
```

Output goes to `scripts\reports\`: a timeline CSV, a Markdown report and the access snapshot.

**Prove it worked:** before running, sign in as the test user in a private browser window and leave the session open. After the script runs, refresh: the session should fail within a few minutes, and a new sign-in should show error AADSTS50057 (account disabled).

## Evidence to capture

- The open session failing after the revoke
- The Markdown report with time to contain
- The sign-in log entry with AADSTS50057
- The access snapshot (shows what was removed)

## How this differs from my Joiner-Mover-Leaver project

The JML sync processes leavers in a nightly batch from the HR file. This script is for the urgent case: one person, right now, with a complete removal (admin roles, PIM eligibility, app assignments, devices) and a timeline as evidence.

## Talking points

- "Disabling the account isn't enough on its own. An open session can keep working until its token expires, so I revoke sessions right after."
- "I snapshot access before removing it. If the person is rehired or legal asks what they had, I can answer."
- "The script verifies each control instead of assuming it worked, and it keeps going if one step fails, so an error never leaves the person with access."
- "For hybrid accounts, the cloud disable isn't enough: the next AD sync can re-enable the account."
