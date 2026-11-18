# Project 2: Access Review & Certification

## The scenario

A manager or an auditor asks: "Who has access to this system, and should they still have it?" Finance and healthcare companies have to answer that on a schedule (SOX, HIPAA), and they have to show who decided and why.

## What this project does

| Step | How |
|------|-----|
| Pull an access report | `Export-AccessReport.ps1` lists every member of the groups that grant access to an app, with department, title, account status and last sign-in |
| Flag what needs a decision | Disabled accounts, stale accounts (no sign-in for 90+ days), people whose role no longer matches the access, guests, and anyone holding privileged access |
| Revoke or certify, and record it | The reviewer fills in Decision, Justification and Reviewer. `Invoke-ReviewDecisions.ps1` checks the file is complete, removes revoked access, and logs every decision as audit evidence |

Tools named in the original idea: SailPoint, Saviynt and Entra ID. This project scripts the review on Entra ID and also uses Entra's built-in Access Reviews; the mapping is at the end.

## Try it now, without a tenant

```powershell
cd 02-access-review-certification\scripts
.\Export-AccessReport.ps1 -SampleDataPath ..\data\sample_group_members.csv -RoleMatrixPath ..\data\role_matrix.csv -AsOfDate 2026-11-18
.\Invoke-ReviewDecisions.ps1 -ReviewPath ..\data\sample_review_completed.csv -ValidateOnly
```

The sample is fictional and reuses the people from my Joiner-Mover-Leaver lab. The report produces:

| Person | Group | Flags | Recommendation |
|--------|-------|-------|----------------|
| Marcus Lee | Finance-Approvers | RoleMismatch, Privileged | Revoke (moved to IT) |
| Ava Johnson | Finance-Approvers | Privileged | Review |
| Daniel Garcia | Finance-Users | Disabled, RoleMismatch | Revoke (terminated) |
| Ethan Clark | Finance-Users | Stale (169 days) | Revoke |
| Marcus Lee | Finance-Users | RoleMismatch | Revoke |
| Rosa Alvarez (guest) | Finance-Users | Guest | Review |
| Ava Johnson, Olivia Martinez | Finance-Users | — | Certify |
| Nina Shah | Finance-Users | — (joined 8 days ago, so not stale) | Certify |

In the completed sample, the reviewer keeps Ethan's access because he's on leave. The validation step highlights that override so an auditor can check the reason.

## Run it on your tenant

```powershell
# 1. Report (needs Entra ID P1/P2 for last sign-in data)
.\Export-AccessReport.ps1 -GroupName 'GRP-Finance-Users','GRP-Finance-Approvers' -RoleMatrixPath ..\data\role_matrix.csv

# 2. Open the CSV in reports\, fill in Decision, Justification and Reviewer

# 3. Check, preview, apply
.\Invoke-ReviewDecisions.ps1 -ReviewPath .\reports\<file>.csv -ValidateOnly
.\Invoke-ReviewDecisions.ps1 -ReviewPath .\reports\<file>.csv -WhatIf
.\Invoke-ReviewDecisions.ps1 -ReviewPath .\reports\<file>.csv
```

## The built-in way: Entra ID Access Reviews

Do this as well, since it's what most Microsoft shops use:

1. Identity governance → Access reviews → New access review
2. Review type: Teams + Groups → `GRP-Finance-Approvers`
3. Reviewers: Manager of users; fallback: your admin account
4. Recurrence: quarterly, 14 days
5. Upon completion: auto-apply results, remove access if reviewers don't respond, require a reason
6. Sign in as the manager at `https://myaccess.microsoft.com`, approve one user and deny another, then confirm the denied user was removed

## Evidence to capture

- The flagged report (sample or live)
- The validation output, including the override warning
- The decisions log after applying
- The Entra access review results page

## SailPoint and Saviynt mapping

| This project | SailPoint IdentityIQ / Saviynt |
|--------------|--------------------------------|
| Group membership report | Aggregated entitlements from connected apps |
| Flags (stale, role mismatch, privileged) | Risk scores and policy violations on each entitlement |
| CSV with Decision column | Certification campaign with approve / revoke per line item |
| Validation before applying | Sign-off: the campaign can't close with open items |
| Remove-from-group step | Remediation: revocations sent to the app through provisioning |

## Talking points

- "The report doesn't just list members. It tells the reviewer which ones need attention and why, so a 500-line review becomes a 20-line one."
- "Privileged access never gets auto-certified; someone has to sign off on it every time."
- "Nothing changes until the file is complete, and every decision has a name and a reason attached. That's what an auditor asks for."
