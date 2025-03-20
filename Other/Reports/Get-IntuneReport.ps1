<#
.Synopsis
Request the most common Intune reports using the Microsoft Graph API.

Created on:   2024-09-01
Updated On:   2024-09-26
Created by:   Ben Whitmore @PatchMyPC
Filename:     Get-IntuneReport.ps1

.Description
This script requests the most common Intune reports using the Microsoft Graph API. It supports both application and delegated authentication flows using the Microsoft Graph SDK. 
If checking the deviceManagement/detectedApps endpoint, we also output to file a list of detected apps and the devices they were found on.
The reports are saved in the specified format csv foprmat be default.
The delegated interactive authentication flow is used by default.

Requirements:

 - The script requires the 'Microsoft.Graph.Authentication' module.
 - If using the application authentication flow with a certificate, the certificate thumbprint, tenant id and client id must be provided.
 - If using the application authentication flow with a client secret, the client secret, tenant id and client if must be provided.
 - By default, the delegated authentication flow is used which leverages the Microsoft Graph Command Line Tools Enterprise application.
 - Permissions required for the principal are DeviceManagementApps.Read.All. DeviceManagementManagedDevices.Read.All is required for the Intune native report 'detectedapps'.


---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.PARAMETER SavePath
The path where the reports will be saved. Default is `$env:TEMP\IntuneReports`.

.PARAMETER FormatChoice
The format of the report. Valid formats are 'csv' and 'json'. Default is 'csv'.

.PARAMETER EndpointVersion
The Microsoft Graph API version to use. Valid endpoints are 'v1.0' and 'beta'. Default is 'beta'.

.PARAMETER TenantId
The Tenant Id if using the Application authentication flow. Not required for Delegated authentication.

.PARAMETER ClientId
The Application (client) Id if using the Application authentication flow. Not required for Delegated authentication.

.PARAMETER CertThumbprint
The certificate thumbprint if using the Application authentication flow with certificate-based authentication. Not required for Delegated authentication.

.PARAMETER ClientSecret
The client secret if using the Application authentication flow with a client secret. Not required for Delegated authentication.

.PARAMETER AuthFlow
The authentication flow to use. Valid authentication flows are 'ApplicationCertificate', 'ApplicationClientSecret', and 'Delegated'. Default is 'Delegated'.

.PARAMETER ReportingEndpointReportName
An array of report names to fetch from the Intune reporting endpoint (e.g., 'AllAppsList', 'AppInstallStatusAggregate'). Default reports include 'AllAppsList', 'AppInstallStatusAggregate', 'AppInvAggregate', and 'AppInvRawData'.

.PARAMETER IntuneReportName
An array of native Intune report names to fetch (e.g., 'deviceManagement/detectedApps').

.EXAMPLE
# Example 1: Run the script using default settings (delegated auth, CSV format)
.\Get-IntuneReport.ps1

.EXAMPLE
# Example 2: Save reports in JSON format to a specific directory
.\Get-IntuneReport.ps1 -SavePath "C:\Reports\Intune" -FormatChoice "json"

.EXAMPLE
# Example 3: Use Application authentication flow with a client secret
.\Get-IntuneReport.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret" -AuthFlow "ApplicationClientSecret"

.EXAMPLE
# Example 4: Use Application authentication with a certificate
.\Get-IntuneReport.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -CertThumbprint "your-cert-thumbprint" -AuthFlow "ApplicationCertificate"

#>

param (
    [string]$SavePath = "$env:TEMP\IntuneReports", # The path where the reports will be saved
    [ValidateSet('csv', 'json')] 
    [string]$FormatChoice = 'csv',
    [ValidateSet('v1.0', 'beta')] 
    [string]$EndpointVersion = 'beta',
    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$ClientSecret = '',

    [ValidateSet('ApplicationCertificate', 'ApplicationClientSecret', 'Delegated')] 
    [string]$AuthFlow = 'Delegated',

    [string[]]$ReportingEndpointReportName = @('AllAppsList','AppInstallStatusAggregate','AppInvAggregate','AppInvRawData'),
    [string[]]$IntuneReportName = @('deviceManagement/detectedApps')
)

# Load necessary assembly for List<>
Add-Type -AssemblyName System.Collections

# Ensure the save path directory exists
if (-not (Test-Path -Path $SavePath -PathType Container)) {
    try {
        Write-Host "Save directory does not exist. Creating directory: $SavePath"
        New-Item -Path $SavePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Successfully created directory: $SavePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create directory: $SavePath. Error: $_"
        throw
    }
}
else {
    Write-Host "Save directory exists: $SavePath" -ForegroundColor Green
}

# Check if the required module is already installed
if (-not (Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable)) {
    Write-Host "Microsoft.Graph.Authentication module not found. Installing..." -ForegroundColor Yellow

    try {
        Install-Module -Name 'Microsoft.Graph.Authentication' -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
        Write-Host "Successfully installed Microsoft.Graph.Authentication module" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Microsoft.Graph.Authentication module. Error: $_"
        break
    }
}
else {
    Write-Host "Microsoft.Graph.Authentication module is already installed" -ForegroundColor Green
}

Write-Host 'Connecting to Microsoft Graph...'

switch ($authFlow) {

    # Connect using the application authentication flow and certificate thumbprint
    'ApplicationCertificate' {
        Write-Host 'Using application authentication flow with certificate.'

        if ([string]::IsNullOrWhiteSpace($certThumbprint) -or [string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($clientId)) { 
            Write-Error "Some authentication information is missing. Please specify the certThumbprint, clientId and tenatnId variables at the top of this script."
            exit
        }

        $stores = @("CurrentUser", "LocalMachine")

        foreach ($store in $stores) {
            $certThumbprintFound = Get-ChildItem -Path "Cert:\$store\My" | Where-Object { $_.Thumbprint -eq $certThumbprint } | Select-Object -ExpandProperty Thumbprint
            
            if ($certThumbprintFound) {
                Write-Host ("Certificate with thumbprint '{0}' found in the '{1}' store." -f $certThumbprint, $store)
                break
            }
        }

        if (-not $certThumbprintFound) {
            Write-Error ("No certificate found. Please ensure you have a certificate with the thumbprint '{0}' in either the Computer or User personal certificate store." -f $certThumbprint)
            exit
        }

        try {
            Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint -NoWelcome -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph. Error: $_"
            exit
        }
    }

    # Connect using the application authentication flow and client secret
    'ApplicationClientSecret' {
        Write-Host 'Using application authentication flow with client secret.'

        if ([string]::IsNullOrWhiteSpace($clientSecret) -or [string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($clientId)) { 
            Write-Error "Some authentication information is missing. Please specify the clientSecret, clientId and tenatnId variables at the top of this script."
            exit
        }

        try {
            $clientSecretSecure = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
            $clientCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecretSecure
            Connect-MgGraph -ClientSecretCredential $clientCredential -TenantId $tenantId
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph. Error: $_"
            exit
        }
    }

    #Connect using the delegated authentication flow
    'Delegated' {
        Write-Host 'Using delegated authentication flow...'
        try {
            Connect-MgGraph -Scopes "DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All" -NoWelcome
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph. Error: $_"
            exit
        }
    }

    # Invalid authentication flow
    default {
        Write-Error "Invalid authentication flow. Please specify a valid authentication flow."
        exit
    }
}

# Initialize a List to hold the custom objects
$reportsToGet = New-Object System.Collections.Generic.List[Object]

# Add reporting endpoint reports to the list
$reportingEndpointReportName | ForEach-Object {
    $reportsToGet.Add([PSCustomObject]@{ Name = $_; Value = 'ReportingEndpoint' })
}

# Add native Intune reports to the list
$intuneReportName | ForEach-Object {
    $reportsToGet.Add([PSCustomObject]@{ Name = $_; Value = 'IntuneNative' })
}

# Format the body and submit the report to the reporting endpoint
Write-Host ("Requesting all reports in the '{0}' format." -f $formatChoice)

foreach ($report in $reportsToGet) {

    # Try the reporting endpoint reports first
    if ($report.value -eq 'ReportingEndpoint') {
  
        $body = @{
            reportName = $report.name
            filter     = ""
            format     = $formatChoice
        } | ConvertTo-Json
    
        $reportEndpoint = "https://graph.microsoft.com/$endpointVersion/deviceManagement/reports/exportJobs"

        try {
            Write-Host ("Requesting the report for {0}..." -f $report.name) -ForegroundColor Cyan
            $response = Invoke-MgGraphRequest -Uri $reportEndpoint -Method Post -Body $body -ContentType "application/json"
        }
        catch {
            Write-Error ("Failed to post the report {0}. Error: {1}" -f $report.name, $_)
            continue
        }

        # Prepare the job Id and polling endpoint
        $jobId = $null
        $jobId = $response.id
        $pollingEndpoint = "https://graph.microsoft.com/$endpointVersion/deviceManagement/reports/exportJobs('$jobId')"
        $reportStatus = ""

        # Poll the endpoint until the report is completed
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $elapsedTimeInSeconds = 0

        while ($reportStatus -ne "completed") {

            # Calculate the elapsed time in seconds
            $elapsedTimeInSeconds = [math]::Floor($timer.Elapsed.TotalSeconds)

            # Display the elapsed time, overwriting the same line
            $timeTaken = [TimeSpan]::FromSeconds($elapsedTimeInSeconds)
            $statusMessage = "Waiting for the report to become available: {0:D2}:{1:D2}:{2:D2}" -f $timeTaken.Hours, $timeTaken.Minutes, $timeTaken.Seconds

            # Overwrite the same line to simulate a dynamic clock
            Write-Host "`r$statusMessage" -NoNewline

            try {
                $jobStatusResponse = Invoke-MgGraphRequest -Uri $pollingEndpoint -Method Get
            }
            catch {
                Write-Error "Failed to get the report status for {0}. Error: {1}" -f $($report.name), $_
                continue
            }

            # Sleep for 1 second before polling again
            Start-Sleep -Seconds 1

            $jobStatusResponse = Invoke-MgGraphRequest -Uri $pollingEndpoint -Method Get
            $reportStatus = $jobStatusResponse.status
        }

        # Once the report is completed, retrieve the download Uri
        $downloadUri = $jobStatusResponse.url
        Write-Host "`nThe report is ready. Downloading it from:"
        Write-Host $downloadUri -ForegroundColor Yellow

        # Stop the timer
        $timer.Stop()
    
        # Define the path for the file to be saved
        $tempPath = [System.IO.Path]::Combine($savePath, "$jobId.zip")
    
        # Download the new file
        try {
            Invoke-WebRequest -Uri $downloadUri -OutFile $tempPath
        }
        catch {
            Write-Error ("Failed to download the report {0}. Error: {1}" -f $report.name, $_)
            continue
        }

        # Extract the zip file to the specified directory
        Expand-Archive -Path $tempPath -DestinationPath $savePath -Force

        # Get the first file from the extracted folder (assuming there is only one file)
        try {
            $extractedFile = Get-ChildItem -Path $savePath | Where-Object { $_.Name -eq "$jobId.$formatChoice" }
        }
        catch {
            Write-Error "Failed to get the extracted file. Error: {0}" -f $_
            continue
        }
        
        Write-Host ("Extracted file path: {0}" -f $extractedFile.FullName) -Foregroundcolor Green

        try {

            # Remove the zip file after extraction
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue

            Write-Host ("Deleted zip file: {0}" -f $tempPath)
        }
        catch {
            Write-Error "Failed to delete the zip file. Error: {0}" -f $_
        }
    }

    # Intune native report logic
    if ($report.value -eq 'IntuneNative') {

        Write-Host ("Requesting the report for {0}..." -f $report.name) -ForegroundColor Cyan
        $reportEndpoint = "https://graph.microsoft.com/$endpointVersion/$($report.name)"
        $intuneReport = Invoke-MgGraphRequest -Uri $reportEndpoint -Method Get
        $intuneReportFile = $intuneReport.value

        if ($intuneReport) {
            Write-Host ("Retrieved the report {0}" -f $report.name)

            # Account for how PowerShell 5 handles the response
            if ($PSVersionTable.PSVersion.Major -like "5*") {
                $intuneReportFile = $intuneReport.Value | ForEach-Object {
                    New-Object -TypeName PSObject -Property $_
                }
            }

            $reportName = ($report.name).replace('/', '_')

            # If the report is deviceManagement/detectedApps, do additional processing
            if ($report.name -eq 'deviceManagement/detectedApps') {
                $detectedApps = $intuneReportFile

                if ($detectedApps.Count -eq 0) {
                    Write-Host "No detected apps found."
                }
                else {
                    Write-Host "Successfully retrieved detected apps."
                    Write-Host "Matching detected apps with managed devices..." -ForegroundColor Cyan

                    # Total number of apps to process
                    $totalApps = $detectedApps.Count
                    $counter = 0

                    # Initialize lists for detected apps and managed devices
                    $detectedAppsList = @()
                    $allManagedDevices = @()

                    # Loop through each detected app
                    foreach ($app in $detectedApps) {
                        $appId = $app.id
                        $appName = $app.displayName
                        $appVersion = $app.version
                        $appPublisher = $app.publisher

                        # Create a custom object for each detected app
                        $detectedAppObject = [PSCustomObject]@{
                            AppId        = $appId
                            AppName      = $appName
                            AppVersion   = $appVersion
                            AppPublisher = $appPublisher
                        }
                        $detectedAppsList += $detectedAppObject

                        # Show progress as a percentage
                        $percentComplete = ($counter / $totalApps) * 100
                        $statusMessage = "Processing $counter of $totalApps - App ID: $appId"
                        Write-Progress -Activity "Processing Detected Apps" -Status $statusMessage -PercentComplete $percentComplete

                        # Define the endpoint for fetching managed devices for the current app
                        $managedDevicesEndpoint = "https://graph.microsoft.com/$endpointVersion/deviceManagement/detectedApps('$appId')/managedDevices"

                        try {

                            # Request managed devices for this app
                            $managedDevicesResponse = Invoke-MgGraphRequest -Uri $managedDevicesEndpoint -Method Get
                            $managedDevices = $managedDevicesResponse.value

                            if ($managedDevices) {

                                # Add relevant information to each managed device for traceability
                                foreach ($device in $managedDevices) {
                                    $customDeviceObject = [PSCustomObject]@{
                                        DeviceName   = $device.deviceName
                                        AppName      = $appName
                                        AppId        = $appId
                                        AppVersion   = $appVersion
                                        AppPublisher = $appPublisher
                                    }

                                    # Append to the combined managed device list
                                    $allManagedDevices += $customDeviceObject
                                }
                            }
                            else {

                                # If no managed devices found, add a placeholder entry for the app
                                $customDeviceObject = [PSCustomObject]@{
                                    DeviceName   = "No Devices Found"
                                    AppName      = $appName
                                    AppId        = $appId
                                    AppVersion   = $appVersion
                                    AppPublisher = $appPublisher
                                }

                                # Append the placeholder to the managed device list
                                $allManagedDevices += $customDeviceObject
                            }
                        }
                        catch {
                            Write-Error "Failed to retrieve managed devices for app ID {0}. Error: {1}" -f $appId, $_
                        }

                        # Increment the counter for the next app
                        $counter++
                    }

                    # Clear the progress bar when done
                    Write-Progress -Activity "Processing Detected Apps" -Status "Completed" -Completed

                    # Output both detected apps and managed devices based on the FormatChoice parameter
                    $outputPaths = @{
                        DetectedAppsPath   = "$savePath\detectedApps.$formatChoice"
                        ManagedDevicesPath = "$savePath\managedDevices_detectedApps.$formatChoice"
                    }

                    switch ($formatChoice) {
                        'json' {
                            $detectedAppsList | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPaths.DetectedAppsPath
                            $allManagedDevices | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPaths.ManagedDevicesPath
                        }
                        'csv' {
                            $detectedAppsList | Export-Csv -Path $outputPaths.DetectedAppsPath -NoTypeInformation
                            $allManagedDevices | Export-Csv -Path $outputPaths.ManagedDevicesPath -NoTypeInformation
                        }
                    }

                    Write-Host ("Exported detected apps to {0}" -f $outputPaths.DetectedAppsPath) -ForegroundColor Green
                    Write-Host ("Exported managed devices to {0}" -f $outputPaths.ManagedDevicesPath) -ForegroundColor Green
                }
            }
            else {
                # Process the other Intune reports as usual
                switch ($formatChoice) {
                    'json' {
                        $intuneReportFile | ConvertTo-Json -Depth 10 | Out-File -FilePath "$savePath\$reportName.json"
                        Write-Host ("Exported the report {0} to {1}" -f $reportName, "$savePath\$reportName.$formatChoice") -ForegroundColor Green
                    }
                    'csv' {
                        $intuneReportFile | Export-Csv -Path "$savePath\$reportName.csv" -NoTypeInformation
                        Write-Host ("Exported the report {0} to {1}" -f $reportName, "$savePath\$reportName.$formatChoice") -ForegroundColor Green
                    }
                }
            }
        }
        else {
            Write-Error ("Failed to retrieve the report {0}" -f $report.name)
        }
    }
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null