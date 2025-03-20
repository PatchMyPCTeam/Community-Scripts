<# 
.SYNOPSIS
Generates a HTML report visualizing application version release across update rings.

.DESCRIPTION
This script creates an interactive HTML visualization of application update deployment
rings for staged rollouts. It calculates and displays a schedule based on specified parameters
and helps you understand your version rollout cadence across different environments.

The update frequency parameter determines how quickly new versions are released, directly 
affecting how long a version remains active on each deployment ring. 

The forecast period determines how far into the future the schedule projects, while ring delays 
specify the waiting period between when Ring 1 receives an update and when subsequent rings 
receive that same version.

The report visualizes version releases, ring update events, and calculates the maximum number 
of concurrent versions your environment will need to support simultaneously, helping you plan 
your deployment strategy and resource allocation.

.NOTES
Author:     Ben Whitmore @PatchMyPC
Created:    March 2025

.PARAMETER UpdateFrequency
The number of days between each new version release.

.PARAMETER ForecastDays
The total number of days to forecast into the future.

.PARAMETER Ring1Delay
The delay in days for Ring 1 (typically 0 for immediate adoption).

.PARAMETER Ring2Delay
The delay in days for Ring 2. Leave empty to disable this ring.

.PARAMETER Ring3Delay
The delay in days for Ring 3. Leave empty to disable this ring.

.PARAMETER Ring4Delay
The delay in days for Ring 4. Leave empty to disable this ring.

.PARAMETER Ring5Delay
The delay in days for Ring 5. Leave empty to disable this ring.

.PARAMETER OutputPath
The file path where the HTML report will be saved.
UpdateRingForecast.html is the default file name saved in the user's temporary directory.

.EXAMPLE
.\Get-UpdateRingForecast.ps1
Generates a report using default settings.

.EXAMPLE
.\Get-UpdateRingForecast.ps1 -UpdateFrequency 7 -ForecastDays 90
Generates a report with weekly updates forecasted for 90 days.

.EXAMPLE
.\Get-UpdateRingForecast.ps1 -Ring1Delay 0 -Ring2Delay 7 -Ring3Delay 14 -Ring4Delay 28 -Ring5Delay ""
Generates a report with 4 active rings using custom delay values.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, 
        Position = 0,
        HelpMessage = "Number of days between version releases")]
    [ValidateRange(1, 365)]
    [int]$UpdateFrequency = 20,
    
    [Parameter(Mandatory = $false,
        Position = 1,
        HelpMessage = "Total number of days to forecast")]
    [ValidateRange(1, 1095)]
    [int]$ForecastDays = 60,
    
    [Parameter(Mandatory = $false,
        Position = 2,
        HelpMessage = "Delay in days for Ring 1")]
    [ValidateRange(0, 365)]
    [int]$Ring1Delay = 0,
    
    [Parameter(Mandatory = $false,
        Position = 3,
        HelpMessage = "Delay in days for Ring 2 (leave empty to disable)")]
    [AllowEmptyString()]
    [string]$Ring2Delay = "7",
    
    [Parameter(Mandatory = $false,
        Position = 4,
        HelpMessage = "Delay in days for Ring 3 (leave empty to disable)")]
    [AllowEmptyString()]
    [string]$Ring3Delay = "14",
    
    [Parameter(Mandatory = $false,
        Position = 5,
        HelpMessage = "Delay in days for Ring 4 (leave empty to disable)")]
    [AllowEmptyString()]
    [string]$Ring4Delay = "21",
    
    [Parameter(Mandatory = $false,
        Position = 6,
        HelpMessage = "Delay in days for Ring 5 (leave empty to disable)")]
    [AllowEmptyString()]
    [string]$Ring5Delay = "28",
    
    [Parameter(Mandatory = $false,
        Position = 7,
        HelpMessage = "Path where HTML report will be saved")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "$env:TEMP\UpdateRingForecast.html"
)

function GenerateSchedule {

    # Initialize rings with more concise PowerShell syntax
    $rings = @(
        @{
            Delay                = $Ring1Delay
            LastVersion          = 0
            FirstVersionAssigned = $false
            Active               = $true
            Name                 = "Ring1"
            DisplayName          = "Ring 1"
            Index                = 0
        }
    )
    
    # Add additional rings dynamically based on parameters
    $ringParams = @($Ring2Delay, $Ring3Delay, $Ring4Delay, $Ring5Delay)
    
    for ($i = 0; $i -lt $ringParams.Count; $i++) {
        $ringNumber = $i + 2
        $delayStr = $ringParams[$i]
        
        $ring = @{
            Name                 = "Ring$ringNumber"
            DisplayName          = "Ring $ringNumber"
            LastVersion          = 0
            FirstVersionAssigned = $false
            Active               = $false
            Index                = $i + 1
        }
        
        if (-not [string]::IsNullOrWhiteSpace($delayStr) -and [int]::TryParse($delayStr, [ref]$null)) {
            $ring.Delay = [int]$delayStr
            $ring.Active = $true
        }
        else {
            $ring.Delay = -1  # Inactive
        }
        
        $rings += $ring
    }
    
    # Filter only active rings
    $activeRings = $rings | Where-Object { $_.Active }
    
    # Generate headers
    $headers = @("Day", "Version Event", "Ring Event")
    $headers += $activeRings | ForEach-Object { "$($_.DisplayName) ($($_.Delay)d)" }
    
    # Generate schedule
    $versionCounter = 1
    $releaseDay = 0
    $rows = @()
    
    for ($day = 0; $day -le $ForecastDays; $day++) {
        $versionReleaseMessage = ""
        $eventMessage = ""
        $ringValues = @{}
        
        # New version release check
        if ($day -eq $releaseDay) {
            $versionReleaseMessage = "Version $versionCounter released"
            $versionCounter++
            $releaseDay += $UpdateFrequency
        }
        
        # Initialize ring values
        foreach ($ring in $activeRings) {
            $ringValues[$ring.Name] = "-"
        }
        
        # Process rings
        foreach ($ring in $activeRings) {
            
            # First version assignment
            if ($day -eq $ring.Delay -and -not $ring.FirstVersionAssigned) {
                $ring.LastVersion = 1
                $ring.FirstVersionAssigned = $true
                $ringValues[$ring.Name] = "V$($ring.LastVersion)"
                $eventMessage += "$($ring.DisplayName) moves to Version $($ring.LastVersion)`n"
            }

            # Subsequent updates
            elseif ($ring.FirstVersionAssigned -and (($day - $ring.Delay) % $UpdateFrequency -eq 0) -and $day -gt $ring.Delay) {
                $ring.LastVersion++
                $ringValues[$ring.Name] = "V$($ring.LastVersion)"
                $eventMessage += "$($ring.DisplayName) moves to Version $($ring.LastVersion)`n"
            }
        }
        
        # Only add row if something happened
        if ($versionReleaseMessage -ne "" -or $eventMessage -ne "") {
            $row = [ordered]@{
                "Day"          = $day
                "VersionEvent" = $versionReleaseMessage
                "RingEvent"    = $eventMessage.Trim()
            }
            
            # Add ring values to row
            foreach ($ring in $activeRings) {
                $row[$ring.Name] = $ringValues[$ring.Name]
            }
            
            $rows += [PSCustomObject]$row
        }
    }
    
    # Get first and last active ring
    $firstRing = $activeRings[0]
    $lastRing = $activeRings[-1]
    
    # Find the latest version for each ring by searching backward through rows
    $firstRingVersion = 0
    $lastRingVersion = 0
    
    # Work backwards through rows to find the latest version for each ring
    for ($i = $rows.Count - 1; $i -ge 0; $i--) {
        $row = $rows[$i]
        
        # Check for first ring version if we haven't found it yet
        if ($firstRingVersion -eq 0) {
            $firstRingValue = $row."$($firstRing.Name)"
            if ($firstRingValue -match 'V(\d+)') {
                $firstRingVersion = [int]$Matches[1]
            }
        }
        
        # Check for last ring version if we haven't found it yet
        if ($lastRingVersion -eq 0) {
            $lastRingValue = $row."$($lastRing.Name)"
            if ($lastRingValue -match 'V(\d+)') {
                $lastRingVersion = [int]$Matches[1]
            }
        }
        
        # If we've found both values, break out of the loop
        if ($firstRingVersion -gt 0 -and $lastRingVersion -gt 0) {
            break
        }
    }
    
    # Calculate max versions
    $maxVersionsInUse = if ($firstRingVersion -gt 0 -and $lastRingVersion -gt 0) {
        $firstRingVersion - $lastRingVersion + 1
    }
    else {
        0
    }
    
    # Build ring delays array for backward compatibility
    $ringDelays = @(0, 0, 0, 0, 0)
    foreach ($ring in $rings) {
        $ringDelays[$ring.Index] = $ring.Delay
    }
    
    # Return the data
    return @{
        "Headers"          = $headers
        "Rows"             = $rows
        "RingDelays"       = $ringDelays
        "ActiveRings"      = $activeRings | ForEach-Object { [int]$_.Name.Substring(4) }
        "MaxVersionsInUse" = $maxVersionsInUse
    }
}

function GenerateHtml {
    param (
        [hashtable]$ScheduleData
    )
    
    # Create HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Rings Schedule</title>
    <style>
    button {
        cursor: pointer;
        background-color: transparent;
        border: none;
        padding: 0px;
        font-family: inherit;
        color: inherit;
     line-height: inherit;
    }
    body {
        font-family: 'Segoe UI', Arial, sans-serif;
        margin: 0;
        padding: 20px;
        background-color: #1e1e1e;
        color: #f0f0f0;
    }
    .header {
        display: flex;
        align-items: center;
        margin-bottom: 30px;
    }
    .css-97v30w > .logoBtn {
        display: flex;
        -webkit-box-align: center;
        align-items: center;
        gap: 10px;
        overflow: hidden;
        color: rgb(27, 188, 155);
        width: 100%;
    }
    .css-97v30w .logo {
        flex-shrink: 0;
    }
    
        h1 {
            color: #1BBC9B;
            font-weight: 500;
            margin: 0;
        }
        .config-container {
            display: flex;
            justify-content: space-between;
            gap: 20px;
            margin-bottom: 20px;
        }
        table {
            border-collapse: separate;
            border-spacing: 0;
            width: 100%;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px 15px;
            text-align: left;
            border: none;
        }
        th {
            background-color: #1BBC9B;
            color: white;
            font-weight: 500;
        }
        .config-container table {
            flex: 1;
        }
        .ring-table td, .versions-table td {
            background-color: #2d2d2d;
            height: 20px;
        }
        .ring-table th, .versions-table th {
            background-color: #1BBC9B;
            height: 20px;
        }
        .versions-table {
            min-width: 300px;
        }
        .version-event {
            font-weight: 600;
            color: #1BBC9B;
        }
        .ring-event {
            white-space: pre-line;
        }
        .ring-column {
            text-align: center;
            font-weight: 600;
        }
        .schedule-table tr:nth-child(odd) td {
            background-color: #2d2d2d;
        }
        .schedule-table tr:nth-child(even) td {
            background-color: #252525;
        }
        .schedule-table tr:hover td {
            background-color: #333333;
        }
        /* Make first cell in each row rounded on the left */
        .schedule-table tr td:first-child,
        .schedule-table tr th:first-child {
            border-top-left-radius: 4px;
            border-bottom-left-radius: 4px;
        }
        /* Make last cell in each row rounded on the right */
        .schedule-table tr td:last-child,
        .schedule-table tr th:last-child {
            border-top-right-radius: 4px;
            border-bottom-right-radius: 4px;
        }
        /* Add space between rows */
        .schedule-table {
            border-spacing: 0 2px;
            background-color: #1e1e1e;
            border: none;
            box-shadow: none;
        }
        .highlight {
            color: #1BBC9B;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
"@

    # Add logo
    $html += @"
<div class='css-97v30w'>
    <button type="button" class="logoBtn"><svg width="38" height="38" viewBox="0 0 38 38" fill="none" xmlns="http://www.w3.org/2000/svg" class="logo"><g clip-path="url(#clip0_1301_19104)"><path d="M1.235 24.852C1.007 24.776 0.836 24.605 0.76 24.377C0.266 22.629 0 20.824 0 19C0 16.758 0.38 14.592 1.14 12.502C1.767 10.754 2.679 9.10099 3.8 7.61899C3.933 7.42899 4.237 7.48599 4.294 7.73299C4.427 8.35999 4.617 9.17699 4.826 10.013C5.871 14.307 6.897 17.974 7.961 20.957C8.303 22.002 8.664 22.971 9.025 23.883C9.424 24.89 9.937 25.897 10.564 26.828C10.811 27.227 11.039 27.569 11.248 27.835C11.305 27.911 11.362 27.968 11.4 28.044L1.235 24.852Z" fill="#0081C6"></path><path d="M18.9999 38C18.2209 38 17.4609 37.943 16.7009 37.867C16.4729 37.848 16.3779 37.563 16.5489 37.392C17.7839 36.233 19.2089 34.941 19.8549 34.352C20.3109 33.991 20.7289 33.649 21.1659 33.326C21.9829 32.68 22.7429 32.072 23.4649 31.483C26.1819 29.241 28.1009 26.619 29.2409 23.674C29.6779 22.515 30.0959 21.223 30.4949 19.855C30.8939 21.736 32.1669 27.664 32.9459 31.483C32.9839 31.711 32.9269 31.939 32.7749 32.11C31.0649 33.896 29.0509 35.34 26.8089 36.347C24.3389 37.43 21.7359 38 18.9999 38Z" fill="#0081C6"></path><path d="M30.9512 18.031C31.5972 15.333 31.9962 12.977 32.1672 11.742L36.7652 13.167C36.9932 13.243 37.1642 13.414 37.2402 13.642C37.7532 15.371 38.0002 17.176 38.0002 18.981C38.0002 21.223 37.6202 23.389 36.8602 25.479C36.2332 27.246 35.3212 28.88 34.2002 30.381C34.0672 30.571 33.7632 30.514 33.7062 30.286L30.9512 18.031Z" fill="#0081C6"></path><path d="M31.1031 10.336L19.6461 4.90199L17.3091 5.79499L23.0091 0.550995C23.0851 0.493995 23.1611 0.455995 23.2561 0.493995C26.2771 1.19699 29.0891 2.622 31.4641 4.65499C33.6301 6.53599 35.3781 8.92999 36.4991 11.552C36.5941 11.761 36.3851 11.989 36.1571 11.932L31.1031 10.336Z" fill="#0081C6"></path><path d="M5.07312 6.536C5.01612 6.308 5.09212 6.061 5.24412 5.89C6.95412 4.104 8.94912 2.679 11.2101 1.653C13.6611 0.57 16.2831 0 19.0001 0C19.7791 0 20.5581 0.057 21.3181 0.152C21.5461 0.19 21.6411 0.475 21.4701 0.627L14.4211 7.087L6.04212 10.887L5.07312 6.536Z" fill="#0081C6"></path><path d="M15.0481 37.468C14.9911 37.525 14.8961 37.563 14.8011 37.544C11.7611 36.86 8.93012 35.397 6.57412 33.383C4.38912 31.483 2.66012 29.108 1.53912 26.467C1.44412 26.258 1.65312 26.03 1.88112 26.087L12.5401 29.431C15.0291 32.167 17.7461 33.649 18.6961 34.105L15.0481 37.468Z" fill="#0081C6"></path><path d="M25.6882 23.237V15.067C25.6882 14.915 25.5742 14.763 25.4792 14.744L25.1562 14.687C25.0992 14.668 25.0422 14.687 24.9852 14.744C24.8902 14.839 24.8142 14.953 24.7192 15.067C24.6432 15.162 24.7002 15.333 24.8332 15.352C24.9092 15.371 24.9852 15.447 24.9852 15.523V22.154C24.9852 22.249 24.9092 22.325 24.8142 22.325L14.1552 22.933C14.0602 22.933 13.9652 22.857 13.9652 22.762V13.908C13.9652 13.794 14.0602 13.718 14.1742 13.737L20.6532 14.706C20.7292 14.725 20.7862 14.687 20.8242 14.611C20.9002 14.478 20.9952 14.345 21.0712 14.193C21.1282 14.079 21.0712 13.946 20.9572 13.927L13.1102 12.597C12.7112 12.521 12.3882 12.901 12.3882 13.167V24.586C12.3882 24.795 12.5782 24.947 12.8252 24.928C12.8252 24.928 15.3902 24.7 18.3542 24.434C18.4682 24.415 18.5632 24.51 18.5442 24.624L18.4872 25.232C18.4872 25.308 18.4112 25.365 18.3352 25.384C17.4802 25.536 16.8722 25.783 16.8532 25.992C16.8532 26.334 18.5252 26.429 20.2922 26.201C21.7552 26.03 22.8002 25.688 22.8002 25.441C22.8002 25.251 22.1732 25.118 21.2422 25.099C21.1472 25.099 21.0712 25.023 21.0712 24.909L21.0902 24.339C21.0902 24.244 21.1662 24.187 21.2422 24.168C23.3512 23.978 25.2702 23.807 25.3272 23.807C25.7072 23.769 25.6882 23.256 25.6882 23.237Z" class="secondary" fill="white"></path><path d="M24.8901 10.165C22.2871 12.35 20.6531 15.675 19.5891 17.974C19.5511 18.069 19.4181 18.088 19.3421 18.012C18.8671 17.518 17.4231 16.036 17.0051 15.523C16.9481 15.447 16.8341 15.447 16.7771 15.523C16.4161 15.979 15.6751 16.872 15.2571 17.366C15.2001 17.423 15.2191 17.537 15.2761 17.575C16.3781 18.392 19.1141 20.805 20.1211 21.755C20.1971 21.831 20.3111 21.793 20.3491 21.698C22.4201 16.948 24.3581 14.269 26.8091 12.331C26.8851 12.274 26.8851 12.179 26.8281 12.122L25.0991 10.184C25.0421 10.127 24.9471 10.108 24.8901 10.165Z" fill="#6DBA44"></path></g><defs><clipPath id="clip0_1301_19104"><rect width="38" height="38" fill="white"></rect></clipPath></defs></svg><svg width="110" height="10" viewBox="0 0 110 10" fill="none" xmlns="http://www.w3.org/2000/svg" class="logo"><g clip-path="url(#clip0_1301_19123)"><path d="M58.2266 0H61.5999L64.4966 6.34333L67.5032 0H70.6566V9.46H68.1999V3.19L65.4132 9.46H63.4332L60.6466 3.19V9.46H58.2266V0Z" fill="#0081C6"></path><path d="M76.2299 6.01333L71.6832 0H74.7999L77.5499 3.77667L80.2999 0H83.1232L78.7966 6.01333V9.46H76.2666V6.01333H76.2299Z" fill="#0081C6"></path><path d="M90.2732 9.46H87.7432V0H93.9032C96.7999 0 97.6799 1.32 97.6799 3.15333V3.26333C97.6799 5.09667 96.7632 6.41667 93.9032 6.41667H90.2732V9.46ZM90.2732 4.36333H93.7199C94.6366 4.36333 95.0766 3.99667 95.0766 3.3V3.22667C95.0766 2.56667 94.6366 2.16333 93.7199 2.16333H90.2732V4.36333Z" fill="#0081C6"></path><path d="M104.317 9.46C100.173 9.46 98.9999 6.78333 98.9999 4.91333V4.54667C98.9999 2.64 100.173 0 104.317 0H104.867C108.68 0 110 1.87 110 3.59333V3.66667H107.36C107.323 3.41 106.993 2.09 104.573 2.09C102.337 2.09 101.64 3.33667 101.64 4.54667V4.69333C101.64 5.83 102.337 7.26 104.573 7.26C106.993 7.26 107.323 5.90333 107.36 5.68333H110V5.72C110 7.66333 108.533 9.46 104.317 9.46Z" fill="#0081C6"></path><path d="M2.53 6.41667V9.46H0V0H6.16C9.05667 0 9.93667 1.28333 9.93667 3.11667V3.22667C9.93667 5.06 9.02 6.34333 6.16 6.34333L2.53 6.41667ZM2.53 4.32667H6.01333C6.93 4.32667 7.37 3.96 7.37 3.3V3.19C7.37 2.53 6.93 2.16333 6.01333 2.16333H2.53V4.32667Z" class="secondary" fill="white"></path><path d="M17.71 7.7H12.7967L12.1 9.46H9.53333L13.6033 0H16.94L21.1933 9.46H18.4433L17.71 7.7ZM15.18 1.87L13.6033 5.68333H16.8667L15.18 1.87Z" class="secondary" fill="white"></path><path d="M23.43 2.16333H19.8733V0H29.37V2.16333H25.9233V9.46H23.3933C23.43 9.46 23.43 2.16333 23.43 2.16333Z" class="secondary" fill="white"></path><path d="M42.57 0H45.1V3.48333H50.2333V0H52.7633V9.46H50.2333V5.64667H45.1367V9.46H42.6067L42.57 0Z" class="secondary" fill="white"></path><path d="M35.31 9.46C31.1667 9.46 29.9933 6.78333 29.9933 4.91333V4.54667C29.9933 2.64 31.1667 0 35.31 0H35.86C39.6733 0 40.9933 1.87 40.9933 3.59333V3.66667H38.3533C38.3167 3.41 37.9867 2.09 35.5667 2.09C33.33 2.09 32.6333 3.33667 32.6333 4.54667V4.69333C32.6333 5.83 33.33 7.26 35.5667 7.26C37.9867 7.26 38.3167 5.90333 38.3533 5.68333H40.9933V5.72C40.9933 7.66333 39.5267 9.46 35.31 9.46Z" class="secondary" fill="white"></path></g><defs><clipPath id="clip0_1301_19123"><rect width="110" height="9.46" fill="white"></rect></clipPath></defs></svg></button>
</div>
"@

    $html += @"
    </div>
        <div>
            <h1>Update Rings Forecaster</h1>
        </div>
    <div class="config-container" style='margin-top: 20px;'>
        <table class="versions-table">
            <tr>
                <th colspan="2">Application Version Management</th>
            </tr>
            <tr>
                <td>Update Frequency:</td>
                <td>${UpdateFrequency} days</td>
            </tr>
            <tr>
                <td>Days to Forecast:</td>
                <td>${ForecastDays}</td>
            </tr>
            <tr>
                <td>Maximum Versions in Use:</td>
                <td class="highlight">$($ScheduleData.MaxVersionsInUse)</td>
            </tr>
            <tr>
                <td>Total Rings:</td>
                <td>$($ScheduleData.ActiveRings.Count)</td>
            </tr>
        </table>
        
        <table class="ring-table">
            <tr>
                <th>Ring</th>
                <th>Delay</th>
            </tr>
"@

    # Add ring delay configuration rows
    foreach ($ring in $ScheduleData.ActiveRings) {
        $delay = $ScheduleData.RingDelays[$ring - 1]
        $html += "<tr><td>Ring $ring</td><td>$delay</td></tr>"
    }

    $html += @"
        </table>
    </div>
    
    <table class="schedule-table">
        <tr>
"@

    # Add table headers
    foreach ($header in $ScheduleData.Headers) {
        $html += "<th>$header</th>"
    }

    $html += "</tr>"

    # Add table rows
    foreach ($row in $ScheduleData.Rows) {
        $html += "<tr>"
        $html += "<td>$($row.Day)</td>"
        $html += "<td class='version-event'>$($row.VersionEvent)</td>"
        $html += "<td class='ring-event'>$($row.RingEvent)</td>"
        
        # Add ring values
        foreach ($ring in $ScheduleData.ActiveRings) {
            $ringKey = "Ring$ring"
            if ($row.PSObject.Properties.Name -contains $ringKey) {
                $html += "<td class='ring-column'>$($row.$ringKey)</td>"
            }
        }
        
        $html += "</tr>"
    }

    $html += @"
    </table>
</body>
</html>
"@

    return $html
}

# Main execution
try {
    # Validate input parameters
    if ([int]::Parse($UpdateFrequency) -le 0) {
        throw "Update frequency must be greater than 0"
    }
    
    # Generate schedule data
    Write-Verbose "Generating schedule with update frequency $UpdateFrequency days and forecast period of $ForecastDays days"
    $scheduleData = GenerateSchedule
    
    # Create HTML report
    Write-Verbose "Creating HTML report"
    $html = GenerateHtml -ScheduleData $scheduleData
    
    # Write to file
    Write-Verbose "Writing HTML report to $OutputPath"
    $html | Out-File -FilePath $OutputPath -Encoding utf8
    
    # Convert relative path to absolute path if needed
    $absolutePath = $OutputPath
    if (-not [System.IO.Path]::IsPathRooted($absolutePath)) {
        $absolutePath = Join-Path -Path (Get-Location) -ChildPath $OutputPath
    }
    
    Write-Host "Output written to $absolutePath" -ForegroundColor Green
    
    # Open the HTML file in the default browser
    Write-Host "Opening the file in your default browser..." -ForegroundColor Cyan
    Start-Process $absolutePath
}
catch {
    Write-Error "Error generating Update Rings report: $_"
    exit 1
}