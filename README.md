# Real-World IAM Projects

Five hands-on Identity and Access Management projects, each built around a situation an IAM team handles every week. They run in a Microsoft Entra ID test tenant with PowerShell and Microsoft Graph, and each one maps to the enterprise tool a company would use for the same job.

> **Lab only.** Everything here uses a test tenant and fictional people. Never run these scripts against a production tenant.

## Projects

| # | Project | Scenario | Enterprise tools it maps to |
|---|---------|----------|-----------------------------|
| 1 | [New Employee Onboarding Automation](01-onboarding-automation/) | A new hire starts Monday and needs their account, apps and MFA ready before 9:00 | Okta, Entra ID |
| 2 | [Access Review & Certification](02-access-review-certification/) | "Who has access to this system, and should they still have it?" | SailPoint, Saviynt, Entra ID |
| 3 | [Terminated Employee Offboarding](03-offboarding/) | Someone is let go at 9:00; lock them out in minutes and prove it | Active Directory, Okta |
| 4 | [Privileged Account Vaulting](04-privileged-account-vaulting/) | One admin knows every server password; vault it, rotate it, log every checkout | CyberArk, BeyondTrust |
| 5 | [Suspicious Access Investigation](05-suspicious-access-investigation/) | A 2:00 a.m. sign-in from a new country: the user, or a breach? | Okta, Entra ID, Splunk |

## Status

| Project | Tested here | Run in my tenant |
|---------|-------------|------------------|
| 1. Onboarding | Syntax checked | Not yet |
| 2. Access review | Report and validation tested on sample data | Not yet |
| 3. Offboarding | Syntax checked | Not yet |
| 4. Vaulting | Syntax checked | Not yet |
| 5. Investigation | Full analysis tested on sample data | Not yet |

Projects 2 and 5 include fictional sample data, so you can run the analysis with no tenant at all.

## Skills covered

| Skill | 1 | 2 | 3 | 4 | 5 |
|-------|:-:|:-:|:-:|:-:|:-:|
| User provisioning and de-provisioning | ✅ | | ✅ | | |
| RBAC and least privilege | ✅ | ✅ | | ✅ | |
| MFA and Conditional Access | ✅ | | | | ✅ |
| Access certification and audit evidence | | ✅ | ✅ | ✅ | |
| Privileged access management (PAM, PIM) | | | ✅ | ✅ | |
| Incident response and log analysis (KQL, SPL) | | | | ✅ | ✅ |
| PowerShell and Microsoft Graph | ✅ | ✅ | ✅ | ✅ | ✅ |
| Azure (Key Vault, Log Analytics, Automation) | | | | ✅ | |

## Lab setup

1. **Tenant:** create a free Azure account, which includes a Microsoft Entra ID tenant.
2. **Licenses:** start the free 30-day **Microsoft Entra ID P2** trial (Billing → Licenses → Try/Buy). P2 is needed for sign-in logs through Graph, last sign-in dates, Access Reviews, Conditional Access and PIM.
3. **Break-glass account:** create an emergency admin account excluded from every Conditional Access policy, so you can't lock yourself out.
4. **PowerShell:** use [Azure Cloud Shell](https://shell.azure.com) (PowerShell), which already has the modules, or install them locally:

   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   Install-Module Az -Scope CurrentUser   # project 4 only
   ```

Every script that changes something supports `-WhatIf`, so you can preview first.

## Related project

[Automated Joiner-Mover-Leaver lifecycle in Microsoft Entra ID](https://github.com/kkhalif005-ux/Automated-Joiner-Mover-Leaver-user-lifecycle-in-Microsoft-Entra-ID): an HR-feed-driven sync that handles joiners, movers and leavers in bulk. Projects 1 and 3 here cover the one-person, time-critical versions of the same lifecycle.

## Credit

Project ideas come from a short video by zerodaysloan on TikTok listing five IAM projects with real-world scenarios. The implementations here are my own.

## License

[MIT](LICENSE)
