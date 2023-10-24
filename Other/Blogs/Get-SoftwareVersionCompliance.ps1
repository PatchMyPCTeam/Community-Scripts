## make sure to enter the exact display name shown in Add Remove Programs.
## While you can use wildcards to search for software, the exact display name discovered in appwiz.cpl will be used as the Setting Name for the json compliance check rule
[array]$applicationName = @("Google Chrome","Test App")

# --------------------------------------
# DO NOT EDIT THE LINES BELOW
# --------------------------------------
# Search HKLM for a system-wide app install
[array]$myAppRegEntries = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion
[array]$appInfo = ForEach ($application in $applicationName) {    
    #[array]$myAppRegEntries = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like $application } | Select-Object DisplayName, DisplayVersion
    # Flag to indicate if the application is installed
    $appInstalled = $false
    If ($myAppRegEntries) {
        # Check if the app exists in $myAppRegEntries
        Foreach ($myAppReg in $myAppRegEntries) {
            if ($myAppReg.DisplayName -eq $application) {
                $appInstalled = $true
                [string]$displayName = $myAppReg.DisplayName
                [string]$displayVersion = $myAppReg.DisplayVersion
                break  # No need to check further once found
            }            
        }
    }
    if (-not $appInstalled) {
        # App not installed, set the display name and version accordingly.
        # If not setting this and the app is not installed, the version check would be null, causing the compliance check to error out.
        # this way, if the software is not installed at all, forcing it to be listed as compliant.
        $displayName = $application
        $displayVersion = "0.0.0.0"
    }
    # Create a custom object and add it to the array
    @{
        $displayName = $displayVersion                    
    }
}

# adding loop to convert the $appInfo array into a single custom object named $objectJSONoutput
# doing this because we want a single object with all the apps and versions listed as key-value pairs in the JSON output, instead of an array with separate objects for each app. Intune no likey that.
$objectJSONoutput = @{}
foreach ($app in $appInfo) {
    $objectJSONoutput += $app
}

$hash = $objectJSONoutput
return $hash | ConvertTo-Json -Compress