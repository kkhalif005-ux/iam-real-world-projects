# Project 1: New Employee Onboarding Automation

## The scenario

A new hire starts Monday. Before 9:00 their account has to exist, their apps have to be ready, and they have to be able to set up MFA. Large companies do this hundreds of times a month, so it has to be automatic and identical every time.

## What this project does

| Step | How |
|------|-----|
| Create the account in the right place | `Invoke-Onboarding.ps1` creates the user from the new-hire file with a unique UPN, department, title and manager. Matching on employee ID means a second run never makes a duplicate. |
| Provision apps by role | The role matrix maps each department and job title to groups. Each enterprise app is assigned to a group, so joining the group gives the app. No one picks apps by hand. |
| MFA at first sign-in | The script issues a **Temporary Access Pass** that becomes valid at 7:00 on the start date. The new hire signs in with it and registers MFA. They never get a password by email. |

Tools named in the original idea: Okta and Microsoft Entra ID. This project uses Entra ID; the Okta mapping is at the end.

## Files

| File | Purpose |
|------|---------|
| `data/new_hires.csv` | Four fictional hires starting 2026-11-23 (one with an apostrophe and hyphen in her name, to test UPN cleanup) |
| `data/role_matrix.csv` | Department + title → groups |
| `scripts/Invoke-Onboarding.ps1` | The automation |
| `policies/CA-require-mfa-all-users.json` | Conditional Access policy that requires MFA, in report-only mode |

## Set up the tenant (once)

1. **Turn on Temporary Access Pass:** Entra admin center → Protection → Authentication methods → Policies → Temporary Access Pass → Enable for all users. Set the maximum lifetime to at least 8 hours.
2. **Create the app groups and assign apps:** run the script once with `-CreateMissingGroups`. Then for each app (you can use gallery apps such as the Microsoft Entra SAML Toolkit as stand-ins), open Enterprise applications → the app → Users and groups → Add the matching `APP-` group.
3. **Require MFA:** create the Conditional Access policy in the JSON (Protection → Conditional Access → New policy), exclude your break-glass account, and leave it in report-only until you've checked the results.

## Run it

```powershell
cd 01-onboarding-automation\scripts

# Preview
.\Invoke-Onboarding.ps1 -NewHiresPath ..\data\new_hires.csv -RoleMatrixPath ..\data\role_matrix.csv -Domain yourtenant.onmicrosoft.com -CreateMissingGroups -WhatIf

# Apply
.\Invoke-Onboarding.ps1 -NewHiresPath ..\data\new_hires.csv -RoleMatrixPath ..\data\role_matrix.csv -Domain yourtenant.onmicrosoft.com -CreateMissingGroups
```

Expected result: four accounts (Mary-Kate O'Neil becomes `mary-kate.oneil@...`), each in their role's groups, and a table of Temporary Access Passes shown once on screen. The audit log goes to `scripts\logs\`.

**Test the new-hire experience:** in a private browser window, go to `https://myaccount.microsoft.com`, sign in as one of the hires with their TAP, and register Microsoft Authenticator. Then check `https://myapps.microsoft.com`: their role's apps should be there.

## Evidence to capture

- Script output with the accounts and group adds (blur the TAP values)
- A new hire's My Apps page showing only their role's apps
- The MFA registration screen reached with the TAP
- The audit log CSV

## Okta mapping

| This project | Okta |
|--------------|------|
| HR file → Entra ID | HR system (Workday, BambooHR) as a profile source → Okta Universal Directory |
| Role matrix groups | Okta group rules on department and title |
| Group-assigned enterprise apps | App assignments by group, with SCIM provisioning to the app |
| Temporary Access Pass | Okta activation email or a temporary password with an MFA enrollment policy |

## Talking points

- "Access is defined once per role. Changing what Accountants get is a one-line edit, not 50 tickets."
- "The new hire never receives a password. They get a time-limited pass that only works from 7:00 on day one, and the first thing it lets them do is register MFA."
- "The script is idempotent and matches on employee ID, so it's safe to run on a schedule."
