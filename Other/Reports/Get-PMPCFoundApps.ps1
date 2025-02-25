<#
.SYNOPSIS
This script downloads application inventory data from Microsoft Graph, matches it against a list of supported products from Patch My PC, and outputs the results in specified formats (CSV or JSON).

Created on:   2024-10-04
Updated On:   2024-10-06
Created by:   Ben Whitmore @PatchMyPC
Filename:     Get-PMPCFoundApps.ps1

.DESCRIPTION

The script performs the following tasks:
1. Defines parameters for saving paths, authentication, and format choices.
2. Downloads and parses the Patch My PC Supported Products XML.
3. Connects to Microsoft Graph and requests application inventory reports and/or a managed device count.
4. Matches applications against supported products based on specified inclusion and exclusion patterns.
5. Outputs matched and unmatched application results to specified file formats.
6. Calculates the ROI based on matched applications and device counts.

Requires the following modules:
- Microsoft.Graph.Authentication

Requires the following permissions:
- DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is.
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose.
Please note that the script may need to be modified or adapted to fit your specific environment or requirements.
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system.
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script.
You assume all risks and responsibilities associated with its usage.
---------------------------------------------------------------------------------

.PARAMETER SavePath
The directory path where report files will be saved. Default is set to the TEMP directory.

.PARAMETER FormatChoice
The format for output files, either 'csv' or 'json'. Default is 'csv'.

.PARAMETER EndpointVersion
The version of the Microsoft Graph API to use, either 'v1.0' or 'beta'. Default is 'beta'.

.PARAMETER GraphScopes
The Microsoft Graph scopes required for the script to run when using the delegated authentication flow. Default is "DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All".

.PARAMETER TenantId
The Tenant ID for the Azure AD tenant.

.PARAMETER ClientId
The Client ID for the Azure AD application.

.PARAMETER CertThumbprint
The thumbprint of the certificate used for authentication.

.PARAMETER ClientSecret
The client secret for the Azure AD application.

.PARAMETER AuthFlow
The authentication flow to use, either 'ApplicationCertificate', 'ApplicationClientSecret', or 'Delegated'. Default is 'Delegated'.

.PARAMETER ReportingEndpointReportName
The name of the report to request from Microsoft Graph. Accepts 'AppInvRawData' or 'AppInvAggregate'. Default is 'AppInvAggregate'.

.PARAMETER AppInvRawData_Filter
The filter to apply when requesting the AppInvRawData report. Default is "Platform eq 'Windows'".

.PARAMETER AppInvRawData_SelectedProperties
An array of selected properties to include in the AppInvRawData report. Defaults to:
- ApplicationKey
- ApplicationName
- ApplicationVersion
- DeviceName
- OSVersion
- Platform
- EmailAddress

.PARAMETER AppInvAggregate_SelectedProperties
An array of selected properties to include in the AppInvAggregate report. Defaults to:
- ApplicationKey
- ApplicationName
- ApplicationPublisher
- ApplicationVersion
- DeviceCount
- Platform

.PARAMETER AppNameExclusions
An array of application name patterns to exclude from the matching process. Default includes common Microsoft applications.

.PARAMETER XmlUrl
The URL for the Patch My PC Supported Products XML file. Default is set to the official URL.

.PARAMETER UseExistingAppReportData
A switch to indicate whether to reuse existing application inventory data generated today. Default is $false.

.PARAMETER ROI_AverageAppsPerYear
The average number of updates per application per year, used in ROI calculation. Default is 8.

.PARAMETER ROI_AverageHoursPerApp
The average number of hours spent per application for packaging, testing, etc. Default is 4 hours.

.PARAMETER ROI_AverageCostPerHour
The average cost per hour of time spent on packaging or testing applications. Default is 100 USD.

.PARAMETER ROI_Currency
The currency used for the ROI calculation. Default is "USD".

.PARAMETER ROI_SKU1
The name of the first Patch My PC SKU used in ROI calculation. Default is "Enterprise Premium".

.PARAMETER ROI_SKU2
The name of the second Patch My PC SKU used in ROI calculation. Default is "Enterprise Plus".

.PARAMETER ROI_Quote1
The initial quote amount for the first SKU. Default is 3500.

.PARAMETER ROI_Quote1_Device
The quote per device for the first SKU. Default is 5.

.PARAMETER ROI_Quote2
The initial quote amount for the second SKU. Default is 2500.

.PARAMETER ROI_Quote2_Device
The quote per device for the second SKU. Default is 3.5.

.PARAMETER IgnorePrefixes
An array of prefixes to ignore when cleaning application names. Default is an empty array.

.PARAMETER DisplayNameHasNoSpaces
A boolean value to indicate whether the display name of the application has no spaces. Default is $false.

.EXAMPLE
.\Get-PMPCFoundApps.ps1

This command runs the script using the current user's TEMP directory for saving output $env:TEMP\IntuneReports, requesting the results in CSV format and using the delegated authentication flow.

.EXAMPLE
.\Get-PMPCFoundApps.ps1 -SavePath "C:\Reports" -FormatChoice "json" -TenantId "your-tenant-id" -ClientId "your-client-id" -CertThumbprint "your-cert-thumbprint" -AuthFlow "ApplicationCertificate"

This command runs the script, saving the output as a JSON file in "C:\Reports" using the specified tenant ID, client ID, and certificate thumbprint for authentication.

#>
[CmdletBinding()]
param (
    [string]$SavePath = "$env:TEMP\IntuneReports",
    [ValidateSet('csv', 'json')] 
    [string]$FormatChoice = 'csv',
    [ValidateSet('v1.0', 'beta')] 
    [string]$EndpointVersion = 'beta',
    [string]$GraphScopes = "DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All",
    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$ClientSecret = '',
    [ValidateSet('ApplicationCertificate', 'ApplicationClientSecret', 'Delegated')] 
    [string]$AuthFlow = 'Delegated',
    [ValidateSet('AppInvRawData', 'AppInvAggregate')]
    [string]$ReportingEndpointReportName = 'AppInvAggregate',
    [string]$AppInvRawData_Filter = "Platform eq 'Windows'", # MS Document suggests filters are not supported for AppInvRawData but it works!
    [string[]]$AppInvRawData_SelectedProperties = @(
        "ApplicationKey",
        "ApplicationName",
        "ApplicationVersion",
        "DeviceName",
        "OSVersion",
        "Platform",
        "EmailAddress"
    ),
    [string[]]$AppInvAggregate_SelectedProperties = @(
        "ApplicationKey",
        "ApplicationName",
        "ApplicationPublisher",
        "ApplicationVersion",
        "DeviceCount",
        "Platform"
    ),
    [string[]]$AppNameExclusions = @(
        "Microsoft.*", 
        "MicrosoftWindows.*", 
        "Clipchamp.*", 
        "Microsoft Intune Management Extension",
        "Patch My PC Publishing Service", 
        "Microsoft Configuration Manager Console"
    ),
    [ValidatePattern('^https://.*')]
    [string]$XmlUrl = "https://api.patchmypc.com/downloads/xml/supportedproducts.xml",
    [switch]$UseExistingAppReportData = $false,
    [ValidateRange(1, 300)]
    [int]$ROI_AverageAppsPerYear = 8,
    [ValidateRange(1, 24)]
    [int]$ROI_AverageHoursPerApp = 4,
    [ValidateRange(1, 1000)]
    [int]$ROI_AverageCostPerHour = 100,
    [ValidateSet('USD', 'EUR', 'GBP')]
    [string]$ROI_Currency = "USD",
    [ValidateNotNullOrEmpty()]
    [string]$ROI_SKU1 = "Enterprise Premium",
    [ValidateNotNullOrEmpty()]
    [string]$ROI_SKU2 = "Enterprise Plus",
    [ValidateRange(0, 100000)]
    [int]$ROI_Quote1 = 3500,
    [ValidateRange(0.01, 100)]
    [double]$ROI_Quote1_Device = 5,
    [ValidateRange(0, 100000)]
    [int]$ROI_Quote2 = 2500,
    [ValidateRange(0.01, 100)]
    [double]$ROI_Quote2_Device = 3.5,
    [string[]]$IgnorePrefixes = @(),
    [switch]$DisplayNameHasNoSpaces = $false
)


$VerbosePreference = "SilentlyContinue"

function Get-CleanAppName {
    param(
        [string]$AppName,
        [string[]]$Prefixes
    )
    
    if (-not $Prefixes) {
        return $AppName
    }

    foreach ($prefix in $Prefixes) {

        if ($AppName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $cleanName = $AppName.Substring($prefix.Length)
            break
        }
        else {
            $cleanName = $AppName
        }
    }

    return $cleanName
}

# Function to download and parse XML
Function Get-Xml {
    [CmdletBinding()]
    Param(
        [String]$Url
    )

    try {
        Write-Host ("Downloading Patch My PC SupportedProducts XML from '{0}'" -f $Url) -ForegroundColor Cyan
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
        $xmlContent = [xml]$response.Content
        Write-Host "SupportedProducts XML downloaded and parsed successfully." -ForegroundColor Green
        return $xmlContent
    }
    catch {
        Write-Error ("Failed to download or parse the Patch My PC SupportedProducts XML. Error: {0}" -f $_)
        break
    }
}

# Function to request the report and handle progress display
Function Request-Report {
    param (
        [string]$reportEndpoint,
        [string]$reportName,
        [string]$formatChoice,
        [string]$filter,
        [string[]]$selectedProperties
    )

    $body = @{
        reportName       = $reportName
        localizationType = "ReplaceLocalizableValues"
        filter           = $filter
        format           = $formatChoice
        select           = $selectedProperties
    } | ConvertTo-Json -Depth 3

    try {
        Write-Host ("Requesting the report for {0}..." -f $reportName) -ForegroundColor Cyan
        $response = Invoke-MgGraphRequest -Uri $reportEndpoint -Method Post -Body $body -ContentType "application/json"
    }
    catch {
        Write-Error ("Failed to post the report {0}. Error: {1}" -f $reportName, $_)
        exit
    }

    $jobId = $response.id
    $pollingEndpoint = "https://graph.microsoft.com/$($EndpointVersion)/deviceManagement/reports/exportJobs('$($jobId)')"
    $reportStatus = ""
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    while ($reportStatus -ne "completed") {
        try {
            $jobStatusResponse = Invoke-MgGraphRequest -Uri $pollingEndpoint -Method Get
            $reportStatus = $jobStatusResponse.status

            # Display the elapsed time, overwriting the same line
            $timeTaken = [TimeSpan]::FromSeconds($timer.Elapsed.TotalSeconds)
            Write-Host -NoNewline ("`rWaiting for the reporting endpoint to reply with a completed status: {0:D2}:{1:D2}:{2:D2}" -f $timeTaken.Hours, $timeTaken.Minutes, $timeTaken.Seconds)

            Start-Sleep -Seconds 1
        }
        catch {
            Write-Error ("Failed to get the report status. Error: {0}" -f $_)
            exit
        }
    }

    # Clear the progress line after completion
    Write-Host ("`rReport generation completed in {0:N2} minutes." -f $timer.Elapsed.TotalMinutes)

    $timer.Stop()

    return $jobStatusResponse.url
}

function Get-IntuneDeviceCount {

    try {

        # Define the API endpoint for managed devices with filter for Windows devices
        $filter = "operatingSystem eq 'Windows'"
        $uri = "https://graph.microsoft.com/$($EndpointVersion)/deviceManagement/managedDevices?`$filter=$filter&`$count=true"

        # Make the request using Invoke-MgGraphRequest
        Write-Host "Retrieving the number of Windows devices enrolled in Intune as this report does not contain device information..." -ForegroundColor Cyan
        $response = Invoke-MgGraphRequest -Method Get -Uri $uri

        # Extract the count from the response
        $windowsDeviceCount = $response.'@odata.count'

        # Output the count
        Write-Host "Number of Intune enrolled Windows devices: $windowsDeviceCount" -ForegroundColor Green

        return $windowsDeviceCount

    }
    catch {
        return $null
    }
}

# Function to clean up files
Function Remove-ZipFile {
    param (
        [string]$ZipFilePath
    )

    # Clean up by deleting the zip file after extraction
    try {
        Remove-Item -Path $ZipFilePath -Force -ErrorAction Stop
        Write-Host ("Deleted zip file: {0}" -f $ZipFilePath) -ForegroundColor Green
    }
    catch {
        Write-Error ("Failed to delete the zip file. Error: {0}" -f $_.Exception.Message)
    }
}

# Function to match applications with supported products and count incidents per product
Function Find-Applications {
    param (
        [array]$ApplicationData,
        [hashtable]$supportedProductsHash
    )

    $detailedMatchedApplications = @()  
    $unmatchedApps = @()  

    # Total number of applications for progress tracking
    $totalApps = $ApplicationData.Count
    $currentAppIndex = 0

    foreach ($app in $ApplicationData) {

        # Increment the current app index
        $currentAppIndex++
    
        $appName = $app.ApplicationName
        
        # Are we testing for display name with spaces removed?
        if ($IgnorePrefixes) {
            $cleanAppName = Get-CleanAppName -AppName $appName -Prefixes $IgnorePrefixes
        }
        else {
            $cleanAppName = $appName
        }

        $appVersion = $app.ApplicationVersion
        $isMatched = $false
    
        foreach ($pattern in $supportedProductsHash.Keys) {
            foreach ($product in $supportedProductsHash[$pattern]) {

                # If $DisplayNameHasNoSpaces is set, add an additional pattern check onspaces removed from pattern
                $sqlSearchIncludePattern = if ($DisplayNameHasNoSpaces -and $product.SQLSearchIncludePattern) { 
                    @($product.SQLSearchIncludePattern, $product.SQLSearchIncludePattern.Replace(" ", ""))
                }
                else { 
                    @($product.SQLSearchIncludePattern) 
                }
                $sqlSearchExcludePattern = if ($DisplayNameHasNoSpaces -and $product.SQLSearchExcludePattern) { 
                    @($product.SQLSearchExcludePattern, $product.SQLSearchExcludePattern.Replace(" ", ""))
                }
                else { 
                    @($product.SQLSearchExcludePattern) 
                }
                $excludePattern = if ($DisplayNameHasNoSpaces -and $product.ExcludePattern) { 
                    @($product.ExcludePattern, $product.ExcludePattern.Replace(" ", ""))
                }
                else { 
                    @($product.ExcludePattern) 
                }
                $sqlSearchVersionIncludePattern = $product.SQLSearchVersionIncludePattern

                # Check if include pattern is null or empty
                if ([string]::IsNullOrWhiteSpace($sqlSearchIncludePattern)) {
                    continue
                }

                foreach ($pattern in $sqlSearchIncludePattern) {

                    $likeIncludePattern = $pattern -replace '\*', '*' -replace '\%', '*'

                    if ($cleanAppName -like $likeIncludePattern) {
                        # Check exclusion patterns
                        $sqlSearchExcludeMatch = -not [string]::IsNullOrWhiteSpace($sqlSearchExcludePattern) -and ($appName -like ($sqlSearchExcludePattern -replace '\*', '*' -replace '\%', '*'))
                        $excludeMatch = -not [string]::IsNullOrWhiteSpace($excludePattern) -and ($appName -like ($excludePattern -replace '\*', '*' -replace '\%', '*'))

                        # If the application name matches and is not excluded
                        if (-not ($sqlSearchExcludeMatch -or $excludeMatch)) {

                            # Track individual matches for CSV/JSON
                            $matchedOnNamePattern = $likeIncludePattern
                            $matchedOnVersionPattern = $null

                            # Check SQLSearchVersionInclude only if it exists and after confirming name match
                            if (-not [string]::IsNullOrWhiteSpace($sqlSearchVersionIncludePattern)) {

                                # Replace wildcards in the version pattern
                                $likeVersionPattern = $sqlSearchVersionIncludePattern -replace '\*', '*' -replace '\%', '*'
                                
                                # Perform version comparison
                                if ($appVersion -like $likeVersionPattern) {
                                    $matchedOnVersionPattern = $sqlSearchVersionIncludePattern
                                }
                            }

                            $matchedAppDetail = [pscustomobject]@{
                                DeviceName           = if ($app.PSObject.Properties['DeviceName']) { $app.DeviceName } else { $null }
                                MatchedAppInvName    = $appName
                                MatchedAppInvVersion = $appVersion
                                MatchedPMPCProduct   = $product.Name
                                MatchedPMPCProductId = $product.Id
                                MatchedOnName        = $matchedOnNamePattern
                                MatchedOnVersion     = $matchedOnVersionPattern
                            }

                            $detailedMatchedApplications += $matchedAppDetail
                            $isMatched = $true
                            break
                        }
                    }
                
                if ($cleanAppName -like $likeIncludePattern) {

                    # Check exclusion patterns
                    $sqlSearchExcludeMatch = -not [string]::IsNullOrWhiteSpace($sqlSearchExcludePattern) -and ($appName -like ($sqlSearchExcludePattern -replace '\*', '*' -replace '\%', '*'))
                    $excludeMatch = -not [string]::IsNullOrWhiteSpace($excludePattern) -and ($appName -like ($excludePattern -replace '\*', '*' -replace '\%', '*'))

                    # If the application name matches and is not excluded
                    if (-not ($sqlSearchExcludeMatch -or $excludeMatch)) {

                        # Track individual matches for CSV/JSON
                        $matchedOnNamePattern = $sqlSearchIncludePattern
                        $matchedOnVersionPattern = $null

                        # Check SQLSearchVersionInclude only if it exists and after confirming name match
                        if (-not [string]::IsNullOrWhiteSpace($sqlSearchVersionIncludePattern)) {

                            # Replace wildcards in the version pattern
                            $likeVersionPattern = $sqlSearchVersionIncludePattern -replace '\*', '*' -replace '\%', '*'
                            
                            # Perform version comparison
                            if ($appVersion -like $likeVersionPattern) {
                                $matchedOnVersionPattern = $sqlSearchVersionIncludePattern
                            }
                        }

                        $matchedAppDetail = [pscustomobject]@{
                            DeviceName           = if ($app.PSObject.Properties['DeviceName']) { $app.DeviceName } else { $null }
                            MatchedAppInvName    = $appName
                            MatchedAppInvVersion = $appVersion
                            MatchedPMPCProduct   = $product.Name
                            MatchedPMPCProductId = $product.Id
                            MatchedOnName        = $matchedOnNamePattern
                            MatchedOnVersion     = $matchedOnVersionPattern
                        }

                        $detailedMatchedApplications += $matchedAppDetail
                        $isMatched = $true
                    }
                }
            }
            }
        }

        # If no match is found, add the app to unmatched list
        if (-not $isMatched) {
            $unmatchedAppDetail = [pscustomobject]@{
                DeviceName             = if ($app.PSObject.Properties['DeviceName']) { $app.DeviceName } else { $null }
                UnmatchedAppInvName    = $appName
                UnmatchedAppInvVersion = $appVersion
            }
            $unmatchedApps += $unmatchedAppDetail
        }

        # Calculate and display progress
        $progressPercent = [math]::Round(($currentAppIndex / $totalApps) * 100)
        Write-Host -NoNewLine ("Progress: {0}% (Processing app {1} of {2})" -f $progressPercent, $currentAppIndex, $totalApps) "`r" -ForegroundColor Yellow
        [Console]::Out.Flush()
    }
    
    Write-Host ("`r`nProcessing complete. Found {0} matched applications in {1}." -f $detailedMatchedApplications.Count, $ReportingEndpointReportName) -ForegroundColor Green
    
    return $detailedMatchedApplications, $unmatchedApps
}

# Function to calculate ROI based on matched applications
Function Measure-ROI {
    param (
        [int]$TotalMatchedApps,
        [int]$ROI_AverageAppsPerYear,
        [int]$ROI_AverageHoursPerApp,
        [int]$ROI_AverageCostPerHour,
        [string]$ROI_Currency,
        [string]$ROI_SKU1,
        [string]$ROI_SKU2,
        [int]$ROI_Quote1,
        [double]$ROI_Quote1_Device,
        [int]$ROI_Quote2,
        [double]$ROI_Quote2_Device,
        [int]$DeviceCount
    )

    # Initialize values
    $AnnualHoursSaving = $TotalMatchedApps * $ROI_AverageAppsPerYear * $ROI_AverageHoursPerApp
    $AnnualCostSaving = $AnnualHoursSaving * $ROI_AverageCostPerHour

    # Create an array to hold results
    $result = @()

    # Calculate the device quote based on the number of devices
    if ($DeviceCount -ne 0) {
        $deviceQuote1 = $DeviceCount * $ROI_Quote1_Device
        $deviceQuote2 = $DeviceCount * $ROI_Quote2_Device
   
        # Does the device quote exceed the current ROI_Quotes?
        if ($deviceQuote1 -gt $ROI_Quote1) {
            $ROI_FinalQuote1 = $deviceQuote1
        }
        else {
            $ROI_FinalQuote1 = $ROI_Quote1
        }

        if ($deviceQuote2 -gt $ROI_Quote2) {
            $ROI_FinalQuote2 = $deviceQuote2
        }
        else {
            $ROI_FinalQuote2 = $ROI_Quote2
        }

    }
    else {
        $ROI_FinalQuote1 = $ROI_Quote1
        $ROI_FinalQuote2 = $ROI_Quote2
    }

    # Calculate the cost saving if the quote is based on the number of devices
    $AnnualCostSaving1 = $AnnualCostSaving - $ROI_FinalQuote1
    $AnnualCostSaving2 = $AnnualCostSaving - $ROI_FinalQuote2

    # Create first row for ROI Quote 1
    $row1 = [PSCustomObject]@{
        Annual_Cost_Saving = "{0:N0} {1}" -f $AnnualCostSaving1, $ROI_Currency
        Annual_Time_Saving = "{0:N0} Hours" -f $AnnualHoursSaving
        Pricing_SKU        = $ROI_SKU1
        Price_per_Device   = "{0:N2} {1}" -f $ROI_Quote1_Device, $ROI_Currency
        Est_Quote          = if ($DeviceCount -eq 0) { 'N/A' } 
        else { "{0:N0} {1}" -f $ROI_FinalQuote1, $ROI_Currency }
    }

    # Add the first row to the result
    $result += $row1

    # Create second row for ROI Quote 2
    $row2 = [PSCustomObject]@{
        Annual_Cost_Saving = "{0:N0} {1}" -f $AnnualCostSaving2, $ROI_Currency
        Annual_Time_Saving = "{0:N0} Hours" -f $AnnualHoursSaving
        Pricing_SKU        = $ROI_SKU2
        Price_per_Device   = "{0:N2} {1}" -f $ROI_Quote2_Device, $ROI_Currency
        Est_Quote          = if ($DeviceCount -eq 0) { 'N/A' } 
        else { "{0:N0} {1}" -f $ROI_FinalQuote2, $ROI_Currency }
    }

    # Add the second row to the result
    $result += $row2

    return $result
}

# Initialize the filter variable based on the ReportingEndpointReportName
switch ($ReportingEndpointReportName) {
    'AppInvRawData' {
        $filter = $AppInvRawData_Filter
        $selectedProperties = $AppInvRawData_SelectedProperties
    }
    'AppInvAggregate' {
        $filter = $null
        $selectedProperties = $AppInvAggregate_SelectedProperties
    }
}

# Test if the SavePath exists and create it if it doesn't
if (-not (Test-Path -Path $SavePath)) {
    try {
        # Attempt to create the directory
        New-Item -ItemType Directory -Path $SavePath -ErrorAction Stop
        Write-Host ("Reports directory '{0}' created successfully." -f $SavePath) -ForegroundColor Green
    }
    catch {
        Write-Error ("Failed to create directory '{0}'. Error: {1}" -f $SavePath, $_)
        break
    }
}
else {
    Write-Host ("Directory '{0}' already exists." -f $SavePath) -ForegroundColor Yellow
}

# Step 1: Check for existing inventory data generated today based on ReportingEndpointReportName
Write-Host "Checking for existing inventory data file generated today..." -ForegroundColor Cyan

# Determine the search pattern based on the ReportingEndpointReportName
$searchPattern = "${ReportingEndpointReportName}_*.$FormatChoice"
$existingDataFile = Get-ChildItem -Path $SavePath -Filter $searchPattern | Sort-Object LastWriteTime -Descending | Select-Object -First 1

$reuseExistingData = $false

if ($UseExistingAppReportData -and $existingDataFile) {
    $fileCreationDate = (Get-Item $existingDataFile.FullName).CreationTime
    $currentDate = Get-Date

    if ($fileCreationDate.Date -eq $currentDate.Date) {
        $reuseExistingData = $true
        Write-Host ("Using existing {0} inventory data as specified by UseExistingAppInvData parameter." -f $ReportingEndpointReportName) -ForegroundColor Green
    }
    else {
        Write-Host ("Existing {0} inventory data is not from today. Will download fresh data." -f $ReportingEndpointReportName) -ForegroundColor Yellow
    }
}
elseif ($existingDataFile) {
    $fileCreationDate = (Get-Item $existingDataFile.FullName).CreationTime
    $currentDate = Get-Date

    if ($fileCreationDate.Date -eq $currentDate.Date) {
        $reuseChoice = Read-Host ("The {0} inventory data file '{1}' was generated today. Do you want to reuse this data? (y/n)" -f $ReportingEndpointReportName, $existingDataFile.Name)
        $reuseExistingData = ($reuseChoice -eq 'y')
    }
}

if ($reuseExistingData) {
    Write-Host ("Reusing existing inventory data from '{0}'." -f $existingDataFile.FullName) -ForegroundColor Green
    switch ($FormatChoice) {
        'csv' {
            $appReportData = Import-Csv -Path $existingDataFile.FullName
        }
        'json' {
            $appReportData = (Get-Content -Path $existingDataFile.FullName | ConvertFrom-Json).values
        }
    } 
}

# Do we need to connect to Graph to get any data?
if (-not $reuseExistingData -or ($reuseExistingData -and $ReportingEndpointReportName -eq 'AppInvAggregate')) {

    # Prepare the report request and endpoint and connect to Graph
    Write-Host "Connecting to Graph..." -ForegroundColor Cyan
    
    $moduleName = 'Microsoft.Graph.Authentication'
    $module = Get-Module -ListAvailable -Name $moduleName

    if (-not $module) {
        # Install the module if it is not installed
        Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction SilentlyContinue
        Write-Host "Module '$moduleName' installed."
    }
    else {
        Write-Host "Module '$moduleName' is already installed. Skipping installation."
    }

    Write-Host 'Connecting to Microsoft Graph...'
    
    switch ($authFlow) {
    
        # Connect using the application authentication flow and certificate thumbprint
        'ApplicationCertificate' {
            Write-Host 'Using application authentication flow with certificate.'

            if ([string]::IsNullOrWhiteSpace($certThumbprint) -or [string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($clientId)) { 
                Write-Error ("Some authentication information is missing. Please specify the certThumbprint, clientId and tenantId variables at the top of this script.") 
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
                Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint -ErrorAction Stop
            }
            catch {
                Write-Error ("Failed to connect to Microsoft Graph. Error: {0}" -f $_)
                exit
            }
        }

        # Connect using the application authentication flow and client secret
        'ApplicationClientSecret' {
            Write-Host 'Using application authentication flow with client secret.'

            if ([string]::IsNullOrWhiteSpace($clientSecret) -or [string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($clientId)) { 
                Write-Error ("Some authentication information is missing. Please specify the clientSecret, clientId and tenantId variables at the top of this script.") 
                exit
            }

            try {
                $clientSecretSecure = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
                $clientCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecretSecure
                Connect-MgGraph -ClientSecretCredential $clientCredential -TenantId $tenantId
            }
            catch {
                Write-Error ("Failed to connect to Microsoft Graph. Error: {0}" -f $_)
                exit
            }
        }

        # Connect using the delegated authentication flow
        'Delegated' {
            Write-Host 'Using delegated authentication flow...'
            try {
                Connect-MgGraph -Scopes $GraphScopes -ErrorAction Stop
            }
            catch {
                Write-Error ("Failed to connect to Microsoft Graph. Error: {0}" -f $_)
                exit
            }
        }

        # Invalid authentication flow
        default {
            Write-Error "Invalid authentication flow. Please specify a valid authentication flow."
            exit
        }
    }
    if (-not $reuseExistingData) {

        $reportEndpoint = "https://graph.microsoft.com/$($EndpointVersion)/deviceManagement/reports/exportJobs"
        $downloadUri = Request-Report -reportEndpoint $reportEndpoint -reportName $ReportingEndpointReportName -formatChoice $FormatChoice -filter $filter -selectedProperties $selectedProperties

        # Define the path for the zip file to be saved
        Write-Host "Downloading the report zip file..." -ForegroundColor Cyan
        $tempPath = [System.IO.Path]::Combine($SavePath, "$([guid]::NewGuid()).zip")

        try {
            Invoke-WebRequest -Uri $downloadUri -OutFile $tempPath
        }
        catch {
            Write-Error ("Failed to download the report {0}. Error: {1}" -f $ReportingEndpointReportName, $_)
            exit
        }

        # Extract the zip file contents
        Write-Host "Extracting the zip file..." -ForegroundColor Cyan
        try {
            Expand-Archive -Path $tempPath -DestinationPath $SavePath -Force
        }
        catch {
            Write-Error ("Failed to extract the zip file {0}. Error: {1}" -f $tempPath, $_)
            exit
        }
    }
}

# Import the correct file (CSV or JSON) based on the $FormatChoice
Write-Host "Importing data from the extracted report..." -ForegroundColor Cyan
if (-not $reuseExistingData) {

    # Get the newest extracted CSV or JSON file
    $newestFile = Get-ChildItem -Path $SavePath -Filter "*.$FormatChoice" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($null -eq $newestFile) {
        Write-Error ("No {0} file found in the extracted files." -f $FormatChoice)
        exit
    }

    Write-Host ("Importing {0} data from: {1}" -f $FormatChoice, $newestFile.FullName) -ForegroundColor Cyan

    switch ($FormatChoice) {
        'csv' {
            try {
                $appReportData = Import-Csv -Path $newestFile.FullName
                Start-Sleep -Seconds 3
                Write-Host ("Imported {0} applications from CSV" -f $appReportData.Count) -ForegroundColor Yellow
            }
            catch {
                Write-Error ("Failed to import the CSV file. Error: {0}" -f $_)
                exit
            }
        }
        'json' {
            try {
                $appReportData = Get-Content -Path $newestFile.FullName | ConvertFrom-Json
                Start-Sleep -Seconds 3
                Write-Host ("Imported {0} applications from JSON" -f $appReportData.Count) -ForegroundColor Yellow
            }
            catch {
                Write-Error ("Failed to import the JSON file. Error: {0}" -f $_)
                exit
            }
        }
    }

    # Call the Remove-ZipFile function to handle deletion of the zip file
    Remove-ZipFile -ZipFilePath $tempPath
}
else {

    # Reuse the existing app inventory data logic remains the same
    switch ($FormatChoice) {
        'csv' {
            try {
                Write-Host "Importing existing CSV file into variable..." -ForegroundColor Cyan
                $appReportData = Import-Csv -Path $existingDataFile.FullName
            }
            catch {
                Write-Error ("Failed to import the CSV file. Error: {0}" -f $_)
                exit
            }
        }
        'json' {
            try {
                Write-Host "Importing existing JSON file into variable..." -ForegroundColor Cyan
                $appReportData = (Get-Content -Path $existingDataFile.FullName | ConvertFrom-Json).values
            }
            catch {
                Write-Error ("Failed to import the JSON file. Error: {0}" -f $_)
                exit
            }
        }
    } 
}

# Get the Intune device count if the report is AppInvAggregate
if ($ReportingEndpointReportName -eq 'AppInvAggregate') {

    # Call the function to get the Intune Windows device count
    $deviceCount = Get-IntuneDeviceCount
}

# Step 2: Get XML content (download)
Write-Host "Getting Patch My PC SupportedProducts XML..." -ForegroundColor Cyan
$xmlContent = Get-Xml -Url $XmlUrl

if (-not $xmlContent) { 
    Write-Error "Failed to get XML content."
    exit 
}

# Step 3: Preprocess supported products and store them in a hashtable for fast lookup
Write-Host "Preprocessing supported products from XML into hashtable..." -ForegroundColor Cyan
$supportedProductsHash = @{}

foreach ($vendor in $xmlContent.SupportedProducts.Vendor) {
    foreach ($product in $vendor.Product) {

        # Check if the ProductSplit node exists
        if ($product.ProductSplit) {
            continue
        }

        # Create a custom object for each product
        $productObject = [PSCustomObject]@{
            Name                           = $product.Name
            Id                             = $product.Id
            
            # Store include patterns
            SQLSearchIncludePattern        = if ($product.SQLSearchInclude) { 
                $product.SQLSearchInclude.Replace('%', '*').Replace('_', '?') 
            }
            else { 
                $null 
            }
            
            # Store exclude patterns
            SQLSearchExcludePattern        = if ($product.SQLSearchExclude) { 
                $product.SQLSearchExclude.Replace('%', '*').Replace('_', '?')
            }
            else { 
                $null 
            }

            # Store version include pattern for later checks
            SQLSearchVersionIncludePattern = if ($product.SQLSearchVersionInclude) { 
                $product.SQLSearchVersionInclude.Replace('%', '*').Replace('_', '?') 
                
            }
            else { 
                $null 
            }

            # Store exclude node pattern for later checks
            ExcludePattern                 = if ($product.Exclude) { 
                $product.Exclude.Replace('%', '*').Replace('_', '?')
            }
            else { 
                $null 
            }
        }

        # Use the SQLSearchInclude as the key for quick lookups
        if ($product.SQLSearchInclude -and -not [string]::IsNullOrWhiteSpace($product.SQLSearchInclude)) {
            $includePattern = $product.SQLSearchInclude.Trim()
            if (-not $supportedProductsHash.ContainsKey($includePattern)) {
                $supportedProductsHash[$includePattern] = @()
            }
            $supportedProductsHash[$includePattern] += $productObject
        }
        else {
            # Write-Host ("    Skipping product '{0}' due to empty SQLSearchInclude." -f $product.Name) -ForegroundColor Yellow
        }
    }
}

# Output the number of supported products
$supportedProductCount = $supportedProductsHash.Values.Name | Measure-Object | Select-Object -ExpandProperty Count
Write-Host ("Extracted {0} supported products from XML" -f $supportedProductCount) -ForegroundColor Cyan

# Step 4: Matching applications with progress tracking outside the function
$totalApps = $appReportData.Count
Write-Host ("Checking {0} applications against supported products..." -f $totalApps)

# Set App Index to 0 outside of Function for progress tracking
$currentAppIndex = 0

# Sanitise the raw data and remove apps to ignore
Write-Host "Filtering apps and excluding the following patterns from the collected results:" -ForegroundColor Cyan
$AppNameExclusions | ForEach-Object { Write-Host " - $_" -ForegroundColor Cyan }

# Apply the filter to exclude matching app names
$appReportData = $appReportData | Where-Object {
    # Check if the ApplicationName matches any of the exclusion patterns
    $excludeMatch = $false
    foreach ($pattern in $AppNameExclusions) {
        if ($_.ApplicationName -like $pattern) {
            $excludeMatch = $true
            break  # Exit the loop if a match is found
        }
    }
    -not $excludeMatch  # Only include apps that do not match any exclusion patterns
}

# Get the total number of apps after filtering
$totalAppsToMatch = $appReportData.Count
Write-Host "Total applications to test after filtering: $totalAppsToMatch" -ForegroundColor Green

# Call the Find-Applications function and capture the results for all apps in one go
$result = Find-Applications -ApplicationData $appReportData -supportedProductsHash $supportedProductsHash -totalApps $totalAppsToMatch

# Store the results returned by the function
$matchedApps = $result[0]
$unmatchedApps = $result[1]

# Create a unique list of unmatched app names
$uniqueUnmatchedAppNames = $unmatchedApps | Select-Object -ExpandProperty UnmatchedAppInvName -Unique

# Convert the unique unmatched app names into custom objects for export
$uniqueUnmatchedAppNameObjects = $uniqueUnmatchedAppNames | ForEach-Object { [PSCustomObject]@{UnmatchedAppInvName = $_ } }

# After processing all applications
$totalSkippedStoreApps = $totalApps - $totalAppsToMatch  # Calculate total skipped applications

# Display the totals
Write-Host ("Total skipped applications (Store Apps & Non-Windows Apps): {0}" -f $totalSkippedStoreApps) -ForegroundColor Yellow

# Group matched applications by MatchedPMPCProduct to calculate Total Instances
$instanceCount = $matchedApps | Group-Object MatchedPMPCProduct | ForEach-Object {
    [pscustomobject]@{
        MatchedPMPCProduct    = $_.Name
        TotalInstances        = $_.Count
        MatchedPMPCProductId  = $_.Group[0].MatchedPMPCProductId
        MatchedAppInvNames    = ($_.Group | Select-Object -ExpandProperty MatchedAppInvName | Sort-Object -Unique) -join ", "
        MatchedAppInvVersions = ($_.Group | Select-Object -ExpandProperty MatchedAppInvVersion | Sort-Object -Unique) -join ", "
        MatchedOnName         = ($_.Group | Select-Object -ExpandProperty MatchedOnName | Sort-Object -Unique) -join ", "
        TotalVersionCount     = ($_.Group | Select-Object -ExpandProperty MatchedAppInvVersion | Sort-Object -Unique).Count
        MatchedOnVersion      = ($_.Group | Select-Object -ExpandProperty MatchedOnVersion | Sort-Object -Unique) -join ", "
    }
}

# Display the table with the required columns in the desired order
if ($instanceCount.Count -gt 0) {
    Write-Host ("Found {0} apps in {1} that matched PMPC products" -f $instanceCount.Count, $ReportingEndpointReportName) -ForegroundColor Green
    $instanceCount | Format-Table -Property MatchedPMPCProduct, 
    @{Name = 'TotalInstances'; Expression = { [string]$_.TotalInstances }; Width = 15 }, 
    @{Name = 'MatchedOnName'; Expression = { $_.MatchedOnName }; Width = 25 },
    @{Name = 'MatchedOnVersion'; Expression = { $_.MatchedOnVersion }; Width = 25 },
    @{Name = 'MatchedAppInvNames'; Expression = { 
            if ($_.MatchedAppInvNames.Length -gt 55) { 
                $_.MatchedAppInvNames.Substring(0, 52) + '...' 
            }
            else { 
                $_.MatchedAppInvNames 
            } 
        }; Width = 50 
    },
    @{Name = 'TotalVersions'; Expression = { [string]$_.TotalVersionCount }; Width = 15 }, 
    @{Name = 'MatchedAppInvVersions'; Expression = { $_.MatchedAppInvVersions }; Width = 25 } -AutoSize
}

# Step 5: Calculate ROI
# Check if DeviceName data is available
if ($matchedApps | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceName) }) {

    # Calculate the total number of unique devices
    $uniqueDevices = $matchedApps | Select-Object -ExpandProperty DeviceName -Unique
    $deviceCount = $uniqueDevices.Count
}
else {

    # Check if the device count is available, typically this should be available for AppInvAggregate when we called Get-InTuneDeviceCount
    if (-not $deviceCount) { $deviceCount = 0 }
}

# Display the ROI calculation
$roiResults = Measure-ROI -TotalMatchedApps $instanceCount.Count `
    -ROI_AverageAppsPerYear $ROI_AverageAppsPerYear `
    -ROI_AverageHoursPerApp $ROI_AverageHoursPerApp `
    -ROI_AverageCostPerHour $ROI_AverageCostPerHour `
    -ROI_Currency $ROI_Currency `
    -ROI_SKU1 $ROI_SKU1 `
    -ROI_SKU2 $ROI_SKU2 `
    -ROI_Quote1 $ROI_Quote1 `
    -ROI_Quote1_Device $ROI_Quote1_Device `
    -ROI_Quote2 $ROI_Quote2 `
    -ROI_Quote2_Device $ROI_Quote2_Device `
    -DeviceCount $deviceCount

Write-Host "ROI Calculation:" -ForegroundColor Green
if ($instanceCount.Count -gt 0) {
    Write-Host ("We found {0} apps in the {1} report that PMPC can patch!" -f $instanceCount.Count, $ReportingEndpointReportName) -ForegroundColor Green

    Write-Host "Calculation is based on the following assumptions:" -ForegroundColor Yellow
    Write-Host ("  - Average number of updates per application per year: {0}" -f $ROI_AverageAppsPerYear) -ForegroundColor Yellow
    Write-Host ("  - Average number of hours to research, package and test each application: {0}" -f $ROI_AverageHoursPerApp) -ForegroundColor Yellow
    Write-Host ("  - Average human cost per hour to package a single application: {0} {1}" -f $ROI_AverageCostPerHour, $ROI_Currency) -ForegroundColor Yellow

    if ($deviceCount -ne 0) {
        Write-Host ("  - Number of devices in your environment: {0}" -f $deviceCount) -ForegroundColor Yellow
    }
    else {
        Write-Host ("  - Number of devices in your environment: {0}" -f $deviceCount) -ForegroundColor Yellow
        Write-Host "    * No device data was found in the report to calculate cost based on your device count." -ForegroundColor Yellow
    }

    # Output the results as a table
    $roiResults | Format-Table -AutoSize
    if ($deviceCount -ne 0) {
        Write-Host 'Please note: Estimated quotes do not reflect the multiple discounts we offer for partners, non-profits and multi-year purchases.' -ForegroundColor Yellow
    }
    Write-Host "You can request an accurate quote from our team at https://patchmypc.com/request-quote" -ForegroundColor Green
    Write-Host "Feature comaprisons for our different SKU's can be found at https://patchmypc.com/request-quote#feature-comparison" -ForegroundColor Green
}
else {
    Write-Host "No PMPC matched applications found in the report - this very rarely happens!" -ForegroundColor Yellow
}

# Step 6: Save the matched and unmatched applications
$matchedOutputFile = Join-Path -Path $SavePath -ChildPath ("MatchedApps.$FormatChoice")
$unmatchedOutputRawFile = Join-Path -Path $SavePath -ChildPath ("UnmatchedApps.$FormatChoice")
$unmatchedOutputFile = Join-Path -Path $SavePath -ChildPath ("UnSupportedApps.$FormatChoice")
$supportedAppsOutputFile = Join-Path -Path $SavePath -ChildPath ("SupportedApps.$FormatChoice")

# Check if DeviceName exists in the report data
$hasDeviceName = $appReportData | Get-Member -Name DeviceName -ErrorAction SilentlyContinue

switch ($FormatChoice) {
    'csv' {
        Write-Host ("`nSaving matched results to CSV: {0}" -f $matchedOutputFile) -ForegroundColor Cyan
        
        # Conditional selection of columns based on DeviceName existence
        if ($hasDeviceName) {
            $matchedApps | Select-Object DeviceName, MatchedAppInvName, MatchedAppInvVersion, MatchedPMPCProduct, MatchedPMPCProductId | Export-Csv -Path $matchedOutputFile -NoTypeInformation
        }
        else {
            $matchedApps | Select-Object MatchedAppInvName, MatchedAppInvVersion, MatchedPMPCProduct, MatchedPMPCProductId | Export-Csv -Path $matchedOutputFile -NoTypeInformation
        }
        
        Write-Host ("Saving unmatched results to CSV: {0}" -f $unmatchedOutputRawFile) -ForegroundColor Cyan
        if ($hasDeviceName) {
            $unmatchedApps | Select-Object DeviceName, UnmatchedAppInvName, UnmatchedAppInvVersion | Export-Csv -Path $unmatchedOutputRawFile -NoTypeInformation
        }
        else {
            $unmatchedApps | Select-Object UnmatchedAppInvName, UnmatchedAppInvVersion | Export-Csv -Path $unmatchedOutputRawFile -NoTypeInformation
        }
        
        Write-Host ("Saving unsupported app results to CSV: {0}" -f $unmatchedOutputFile) -ForegroundColor Cyan
        
        # Group by UnmatchedAppName and count instances for TotalInstances
        $uniqueUnmatchedAppNameObjects = $unmatchedApps | Group-Object -Property UnmatchedAppInvName | ForEach-Object {
            [PSCustomObject]@{
                UnmatchedAppInvName    = $_.Name
                UnmatchedAppInvVersion = ($_.Group | Select-Object -ExpandProperty UnmatchedAppInvVersion | Sort-Object -Unique) -join ", "
                TotalInstances         = $_.Count
            }
        }

        $uniqueUnmatchedAppNameObjects | Export-Csv -Path $unmatchedOutputFile -NoTypeInformation

        # Create supported apps data and export to CSV
        $supportedAppsData = $instanceCount | ForEach-Object {
            [PSCustomObject]@{
                MatchedAppInvName     = $_.MatchedAppInvNames
                MatchedAppInvVersions = $_.MatchedAppInvVersions
                TotalInstances        = $_.TotalInstances
                MatchedPMPCProduct    = $_.MatchedPMPCProduct
                MatchedPMPCProductId  = $_.MatchedPMPCProductId
            }
        }

        Write-Host ("Saving supported apps results to CSV: {0}" -f $supportedAppsOutputFile) -ForegroundColor Cyan
        $supportedAppsData | Export-Csv -Path $supportedAppsOutputFile -NoTypeInformation
    }
    'json' {
        Write-Host ("`nSaving matched results to JSON: {0}" -f $matchedOutputFile) -ForegroundColor Cyan
        if ($hasDeviceName) {
            $matchedApps | Select-Object DeviceName, MatchedAppInvName, MatchedAppInvVersion, MatchedPMPCProduct, MatchedPMPCProductId | ConvertTo-Json | Out-File -FilePath $matchedOutputFile
        }
        else {
            $matchedApps | Select-Object MatchedAppInvName, MatchedAppInvVersion, MatchedPMPCProduct, MatchedPMPCProductId | ConvertTo-Json | Out-File -FilePath $matchedOutputFile
        }

        Write-Host ("Saving unmatched results to JSON: {0}" -f $unmatchedOutputRawFile) -ForegroundColor Cyan
        if ($hasDeviceName) {
            $unmatchedApps | Select-Object DeviceName, UnmatchedAppInvName, UnmatchedAppInvVersion | ConvertTo-Json | Out-File -FilePath $unmatchedOutputRawFile
        }
        else {
            $unmatchedApps | Select-Object UnmatchedAppInvName, UnmatchedAppInvVersion | ConvertTo-Json | Out-File -FilePath $unmatchedOutputRawFile
        }

        Write-Host ("Saving unsupported app results to JSON: {0}" -f $unmatchedOutputFile) -ForegroundColor Cyan
        
        # Group by UnmatchedAppName and count instances for TotalInstances
        $uniqueUnmatchedAppNameObjects = $unmatchedApps | Group-Object -Property UnmatchedAppInvName | ForEach-Object {
            [PSCustomObject]@{
                UnmatchedAppInvName    = $_.Name
                UnmatchedAppInvVersion = ($_.Group | Select-Object -ExpandProperty UnmatchedAppInvVersion | Sort-Object -Unique) -join ", "
                TotalInstances         = $_.Count
            }
        }

        $uniqueUnmatchedAppNameObjects | ConvertTo-Json | Out-File -FilePath $unmatchedOutputFile

        # Create supported apps data and export to JSON
        $supportedAppsData = $instanceCount | ForEach-Object {
            [PSCustomObject]@{
                MatchedAppInvName    = $_.MatchedPMPCProduct
                MatchedAppInvVersion = ($_.MatchedAppVersions -join ", ")
                TotalInstances       = $_.TotalInstances
                MatchedPMPCProduct   = $_.MatchedPMPCProduct
                MatchedPMPCProductId = $_.MatchedPMPCProductId
            }
        }

        Write-Host ("Saving supported apps results to JSON: {0}" -f $supportedAppsOutputFile) -ForegroundColor Cyan
        $supportedAppsData | ConvertTo-Json | Out-File -FilePath $supportedAppsOutputFile
    }
}

# Disconnect from Graph
if (Get-MgContext) {

    $disconnectChoice = Read-Host "Do you want to disconnect from Microsoft Graph? (y/n)"

    if ($disconnectChoice -eq 'y') {
        Disconnect-MgGraph
       
    }
    else {
        Write-Host "You chose not to disconnect from Microsoft Graph. You can use the Disconnect-MgGraph cmdlet to delete your session manually." -ForegroundColor Yellow
    }
}