# Project 5: Suspicious Access Investigation

## The scenario

A user is signing in to internal systems at 2:00 a.m. from a country they've never signed in from. Is it really them, or a breach? You have 30 minutes to find out and act.

## What this project does

`Invoke-SignInInvestigation.ps1` does the first 30 minutes of the work:

| Step | How |
|------|-----|
| Pull the login history | Last 30 days of sign-ins: location, IP, device, app, result |
| Compare to normal | Builds a baseline of the user's usual countries, devices and hours, then checks the last 24 hours for: new country, impossible travel, failures followed by a success, Entra risk rating, new device, off-hours, and legacy protocols that can't do MFA |
| Contain | With `-Contain`, revokes all sessions so the user must sign in again; with `-DisableAccount`, blocks sign-in |
| Document and escalate | Writes an incident report with the verdict, timeline, indicators (IPs), containment actions and what the SOC should check next |

The `queries` folder has the same hunts in KQL (Microsoft Sentinel / Log Analytics) and SPL (Splunk), since Okta, Entra ID and Splunk are the tools named in the original idea.

## Try it now, without a tenant

```powershell
cd 05-suspicious-access-investigation\scripts
.\Invoke-SignInInvestigation.ps1 -SignInsPath ..\data\sample_signins.json -AsOfDate '2026-11-18T09:00:00Z'
```

The sample data is fictional: a month of normal weekday sign-ins from Minneapolis and Saint Paul, then at 2:01 a.m. Central, seven failed attempts from Bucharest on a new Linux device (one over IMAP), followed by two successful sign-ins. The script finds:

| Severity | Finding |
|----------|---------|
| High | Impossible travel: about 8,400 km from Minneapolis in 4.5 hours |
| High | Seven failures, then a success |
| High | New country (Romania) |
| High | Entra ID Protection rated the successful sign-ins medium risk |
| Medium | New device, off-hours, legacy protocol (IMAP) |

Verdict: **Likely compromise: contain now and escalate to the SOC.** Run it with `-AsOfDate '2026-11-18T05:00:00Z'` (before the attack) and the verdict is "No anomaly found", which shows the baseline isn't just flagging everything.

## Run it on your tenant

Sign-in logs through Graph need Entra ID P1 or P2.

```powershell
.\Invoke-SignInInvestigation.ps1 -UserPrincipalName test.user@yourtenant.onmicrosoft.com
.\Invoke-SignInInvestigation.ps1 -UserPrincipalName test.user@yourtenant.onmicrosoft.com -Contain -DisableAccount
```

**Make your own suspicious sign-in:** sign in as a test user over a phone hotspot or a VPN exit in another country, enter the wrong password a few times first, then sign in correctly. Wait 5–10 minutes for the logs, then run the script.

To use the KQL queries, send sign-in logs to a Log Analytics workspace: Entra admin center → Monitoring & health → Diagnostic settings → add `SignInLogs`.

## Evidence to capture

- The script output and the incident report (sample or live)
- The sign-in log entry for the suspicious sign-in
- A KQL query result in Log Analytics
- The revoked session (the test user forced to sign in again)

## Talking points

- "I don't judge a sign-in on its own. I compare it to the user's last 30 days, so a trip abroad looks different from a brute-force from a new device."
- "Impossible travel is distance divided by time. Minneapolis to Bucharest in 4.5 hours is over 1,800 km/h."
- "Containment comes first: revoking sessions kicks the attacker out within minutes. Then I hand the SOC the IPs and ask them to check for persistence, like new MFA methods or inbox forwarding rules."
- "Failures followed by a success over a legacy protocol tells me the password is likely known and MFA is the only thing left. That's why blocking legacy authentication matters."
