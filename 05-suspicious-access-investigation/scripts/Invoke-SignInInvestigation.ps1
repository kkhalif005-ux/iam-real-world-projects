<#
.SYNOPSIS
    Investigates suspicious sign-ins for one user: builds their normal pattern, flags what's
    different, optionally contains the account, and writes an incident report for the SOC.

.DESCRIPTION
    1. Pulls the user's sign-in history (from Entra ID, or from a JSON file for practice)
    2. Builds a baseline from the earlier sign-ins: usual countries, devices and hours
    3. Checks each sign-in in the investigation window for:
         NewCountry       - country never seen in the baseline                 (High)
         ImpossibleTravel - faster than 900 km/h since the previous sign-in   (High)
         FailedThenSuccess- a burst of failures followed by a success         (High)
         RiskyByEntra     - Entra ID Protection rated it medium or high       (High)
         NewDevice        - OS and browser combination never seen before      (Medium)
         OffHours         - between -OffHoursStart and -OffHoursEnd, local    (Medium)
         LegacyAuth       - protocol that can't do MFA (IMAP, POP, SMTP...)   (Medium)
    4. Scores the findings and gives a verdict
    5. With -Contain, revokes the user's sessions (and with -DisableAccount, blocks sign-in)
    6. Writes a Markdown incident report and a CSV of findings

.EXAMPLE
    # Practice run on the sample data, no tenant needed
    .\Invoke-SignInInvestigation.ps1 -SignInsPath ..\data\sample_signins.json -AsOfDate '2026-11-18T09:00:00Z'

.EXAMPLE
    # Live investigation, then contain
    .\Invoke-SignInInvestigation.ps1 -UserPrincipalName jordan.reed@yourtenant.onmicrosoft.com
    .\Invoke-SignInInvestigation.ps1 -UserPrincipalName jordan.reed@yourtenant.onmicrosoft.com -Contain -DisableAccount
#>
[CmdletBinding(DefaultParameterSetName = 'Live', SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ParameterSetName = 'Live')]   [string]$UserPrincipalName,
    [Parameter(Mandatory, ParameterSetName = 'Sample')] [string]$SignInsPath,
    [int]$BaselineDays = 30,
    [int]$InvestigateHours = 24,
    [string]$TimeZone = 'Central Standard Time',
    [int]$OffHoursStart = 0,
    [int]$OffHoursEnd = 5,
    [int]$FailedBurstThreshold = 5,
    [datetime]$AsOfDate = (Get-Date),
    [switch]$Contain,
    [switch]$DisableAccount,
    [string]$OutputDir = '.\reports'
)

$ErrorActionPreference = 'Stop'
$asOf = $AsOfDate.ToUniversalTime()
$tz = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZone)

# ---------- helpers ----------
function ConvertTo-Utc($Value) {
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq 'Unspecified') { return [datetime]::SpecifyKind($Value, 'Utc') }
        return $Value.ToUniversalTime()
    }
    [datetime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}
function Get-DistanceKm($Lat1, $Lon1, $Lat2, $Lon2) {
    $r = 6371; $toRad = [math]::PI / 180
    $dLat = ($Lat2 - $Lat1) * $toRad; $dLon = ($Lon2 - $Lon1) * $toRad
    $a = [math]::Sin($dLat / 2) * [math]::Sin($dLat / 2) +
         [math]::Cos($Lat1 * $toRad) * [math]::Cos($Lat2 * $toRad) * [math]::Sin($dLon / 2) * [math]::Sin($dLon / 2)
    2 * $r * [math]::Asin([math]::Sqrt($a))
}
function Test-OffHours([int]$Hour) {
    if ($OffHoursStart -le $OffHoursEnd) { $Hour -ge $OffHoursStart -and $Hour -lt $OffHoursEnd }
    else { $Hour -ge $OffHoursStart -or $Hour -lt $OffHoursEnd }
}

# ---------- 1. Load sign-ins ----------
if ($PSCmdlet.ParameterSetName -eq 'Sample') {
    $raw = Get-Content $SignInsPath -Raw | ConvertFrom-Json
}
else {
    Connect-MgGraph -Scopes 'AuditLog.Read.All', 'Directory.Read.All' -NoWelcome
    $since = $asOf.AddDays(-$BaselineDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $raw = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $since" -All
}

$signIns = foreach ($s in $raw) {
    $geo = $s.location.geoCoordinates
    [pscustomobject]@{
        TimeUtc   = ConvertTo-Utc $s.createdDateTime
        Upn       = $s.userPrincipalName
        Ip        = $s.ipAddress
        City      = $s.location.city
        Country   = $s.location.countryOrRegion
        Lat       = if ($geo) { [double]$geo.latitude } else { $null }
        Lon       = if ($geo) { [double]$geo.longitude } else { $null }
        Device    = "$($s.deviceDetail.operatingSystem) / $($s.deviceDetail.browser)"
        App       = $s.appDisplayName
        ClientApp = $s.clientAppUsed
        ErrorCode = [int]$s.status.errorCode
        Risk      = "$($s.riskLevelDuringSignIn)"
    }
}
$signIns = @($signIns | Where-Object { $_.TimeUtc -le $asOf } | Sort-Object TimeUtc)
if (-not $signIns) { throw 'No sign-ins found for that user and time range.' }
$upn = if ($UserPrincipalName) { $UserPrincipalName } else { $signIns[0].Upn }

# ---------- 2. Baseline ----------
$windowStart = $asOf.AddHours(-$InvestigateHours)
$baseline = @($signIns | Where-Object { $_.TimeUtc -lt $windowStart -and $_.ErrorCode -eq 0 })
$window   = @($signIns | Where-Object { $_.TimeUtc -ge $windowStart })
$knownCountries = @($baseline.Country | Sort-Object -Unique)
$knownDevices   = @($baseline.Device  | Sort-Object -Unique)
$usualHours = $baseline | ForEach-Object { [TimeZoneInfo]::ConvertTimeFromUtc($_.TimeUtc, $tz).Hour } | Measure-Object -Minimum -Maximum

# ---------- 3. Check the window ----------
$modernClients = 'Browser', 'Mobile Apps and Desktop clients'
$weights = @{ High = 3; Medium = 1 }
$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding($SignIn, $Type, $Severity, $Detail) {
    $findings.Add([pscustomobject]@{
        TimeUtc = $SignIn.TimeUtc.ToString('yyyy-MM-dd HH:mm'); Type = $Type; Severity = $Severity
        Ip = $SignIn.Ip; Location = "$($SignIn.City), $($SignIn.Country)"; Detail = $Detail })
}

$failStreak = 0
$rows = foreach ($s in $window) {
    $flags = @()
    $local = [TimeZoneInfo]::ConvertTimeFromUtc($s.TimeUtc, $tz)
    $ok = $s.ErrorCode -eq 0

    if ($s.Country -and $knownCountries -notcontains $s.Country) {
        Add-Finding $s 'NewCountry' 'High' "$($s.Country) never seen in $BaselineDays days of history"; $flags += 'NewCountry' }
    if ($knownDevices -notcontains $s.Device) {
        Add-Finding $s 'NewDevice' 'Medium' "$($s.Device) never seen before"; $flags += 'NewDevice' }
    if (Test-OffHours $local.Hour) {
        Add-Finding $s 'OffHours' 'Medium' ("{0:HH:mm} local time" -f $local); $flags += 'OffHours' }
    if ($s.ClientApp -and $modernClients -notcontains $s.ClientApp) {
        Add-Finding $s 'LegacyAuth' 'Medium' "$($s.ClientApp) can't do MFA"; $flags += 'LegacyAuth' }
    if ($s.Risk -in 'medium', 'high') {
        Add-Finding $s 'RiskyByEntra' 'High' "Entra ID Protection rated it $($s.Risk)"; $flags += 'RiskyByEntra' }

    # Impossible travel: compare with the previous successful sign-in that has coordinates
    $prev = $signIns | Where-Object { $_.TimeUtc -lt $s.TimeUtc -and $_.ErrorCode -eq 0 -and $null -ne $_.Lat } | Select-Object -Last 1
    if ($prev -and $null -ne $s.Lat) {
        $km = Get-DistanceKm $prev.Lat $prev.Lon $s.Lat $s.Lon
        $hrs = [math]::Max(($s.TimeUtc - $prev.TimeUtc).TotalHours, 0.01)
        if ($km -gt 500 -and ($km / $hrs) -gt 900) {
            if (-not ($findings | Where-Object { $_.Type -eq 'ImpossibleTravel' -and $_.Ip -eq $s.Ip })) {
                Add-Finding $s 'ImpossibleTravel' 'High' ("{0:N0} km from {1} in {2:N1} h ({3:N0} km/h)" -f $km, $prev.City, $hrs, ($km / $hrs))
            }
            $flags += 'ImpossibleTravel'
        }
    }

    if ($ok) {
        if ($failStreak -ge $FailedBurstThreshold) {
            Add-Finding $s 'FailedThenSuccess' 'High' "$failStreak failed attempts, then a successful sign-in"; $flags += 'FailedThenSuccess' }
        $failStreak = 0
    } else { $failStreak++ }

    [pscustomobject]@{
        'Time (UTC)'  = $s.TimeUtc.ToString('yyyy-MM-dd HH:mm')
        'Local'       = $local.ToString('HH:mm')
        'Result'      = if ($ok) { 'Success' } else { "Failed ($($s.ErrorCode))" }
        'Location'    = "$($s.City), $($s.Country)"
        'IP'          = $s.Ip
        'Device'      = $s.Device
        'Client'      = $s.ClientApp
        'Flags'       = ($flags | Sort-Object -Unique) -join ', '
    }
}

# ---------- 4. Verdict (each finding type counts once) ----------
$score = ($findings | Group-Object Type | ForEach-Object { $weights[$_.Group[0].Severity] } | Measure-Object -Sum).Sum
if (-not $score) { $score = 0 }
$verdict = if ($score -ge 6) { 'Likely compromise: contain now and escalate to the SOC' }
           elseif ($score -ge 2) { 'Suspicious: confirm with the user through a known phone number' }
           else { 'No anomaly found' }
$successAbroad = @($window | Where-Object { $_.ErrorCode -eq 0 -and $knownCountries -notcontains $_.Country })

# ---------- 5. Contain ----------
$actions = @()
if ($Contain) {
    if ($PSCmdlet.ParameterSetName -eq 'Sample') {
        $actions += '| - | Containment skipped | Practice data: no tenant connected |'
    } else {
        $user = Get-MgUser -UserId $upn
        if ($PSCmdlet.ShouldProcess($upn, 'Revoke all sessions')) {
            Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
            $actions += "| $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) | Sessions revoked | Refresh tokens invalidated; the user must sign in again |"
        }
        if ($DisableAccount -and $PSCmdlet.ShouldProcess($upn, 'Disable account')) {
            Update-MgUser -UserId $user.Id -AccountEnabled:$false
            $actions += "| $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) | Account disabled | Re-enable only after the user resets their password and MFA |"
        }
    }
}

# ---------- 6. Report ----------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$name = $upn.Split('@')[0]
$reportPath   = Join-Path $OutputDir "incident_${name}_$stamp.md"
$findingsPath = Join-Path $OutputDir "incident_${name}_${stamp}_findings.csv"
$findings | Export-Csv $findingsPath -NoTypeInformation

$iocIps = ($findings | Where-Object Severity -eq 'High' | Select-Object -ExpandProperty Ip -Unique) -join ', '
$table = ($rows | ForEach-Object { "| $($_.'Time (UTC)') | $($_.Local) | $($_.Result) | $($_.Location) | $($_.IP) | $($_.Device) | $($_.Client) | $($_.Flags) |" }) -join "`n"
$findingLines = ($findings | Group-Object Type | ForEach-Object {
    $f = $_.Group[0]; "| $($f.Severity) | $($_.Name) | $($_.Count) | $($f.Detail) |" }) -join "`n"

@"
# Suspicious access investigation: $upn

**Verdict: $verdict** (score $score)

| Field | Value |
|-------|-------|
| Investigated window | $($windowStart.ToString('yyyy-MM-dd HH:mm')) to $($asOf.ToString('yyyy-MM-dd HH:mm')) UTC |
| Baseline | $($baseline.Count) successful sign-ins over the previous $BaselineDays days |
| Usual countries | $($knownCountries -join ', ') |
| Usual devices | $($knownDevices -join '; ') |
| Usual hours ($TimeZone) | $($usualHours.Minimum):00 to $($usualHours.Maximum):59 |
| Successful sign-ins from a new country | $($successAbroad.Count) |

## Findings

| Severity | Type | Count | Example |
|----------|------|-------|---------|
$findingLines

## Sign-ins in the window

| Time (UTC) | Local | Result | Location | IP | Device | Client | Flags |
|------------|-------|--------|----------|----|--------|--------|-------|
$table

## Containment

| Time (UTC) | Action | Detail |
|------------|--------|--------|
$(if ($actions) { $actions -join "`n" } else { '| - | None taken | Re-run with -Contain to revoke sessions |' })

## Escalation to the SOC

- Indicators: IP addresses $iocIps
- Ask the SOC to search for the same IPs across other users and in firewall and email logs
- Check for persistence: new MFA methods, inbox forwarding rules, app consents and OAuth grants
  added during the window
- Before re-enabling: user resets password, re-registers MFA, and the SOC confirms no other accounts are affected

## Next steps

- [ ] Call the user on a known number (not one from the suspicious session)
- [ ] Review the user's audit log for changes made during the window
- [ ] Block the indicator IPs with a Conditional Access named location if the SOC agrees
- [ ] Record root cause and close the ticket
"@ | Set-Content $reportPath

Write-Host "`nSign-ins in the last $InvestigateHours h for $upn" -ForegroundColor Cyan
$rows | Format-Table 'Time (UTC)', Local, Result, Location, Device, Flags -AutoSize | Out-String -Width 220 | Write-Host
$findings | Group-Object Type | ForEach-Object { "{0,-7} {1,-18} x{2}  {3}" -f $_.Group[0].Severity, $_.Name, $_.Count, $_.Group[0].Detail } | Write-Host
$color = if ($score -ge 6) { 'Red' } elseif ($score -ge 2) { 'Yellow' } else { 'Green' }
Write-Host "`nVerdict: $verdict (score $score)" -ForegroundColor $color
Write-Host "Report:   $reportPath`nFindings: $findingsPath" -ForegroundColor Cyan
