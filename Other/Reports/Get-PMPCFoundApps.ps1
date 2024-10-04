<#
.SYNOPSIS
This script downloads application inventory data from Microsoft Graph, matches it against a list of supported products from Patch My PC, and outputs the results in specified formats (CSV or JSON).

Created on:   2024-10-04
Created by:   Ben Whitmore @PatchMyPC
Filename:     Get-PMPCFoundApps.ps1

.DESCRIPTION

The script performs the following tasks:
1. Defines parameters for saving paths, authentication, and format choices.
2. Downloads and parses the Patch My PC Supported Products XML.
3. Connects to Microsoft Graph and requests application inventory reports.
4. Matches applications against supported products based on specified inclusion and exclusion patterns.
5. Outputs matched and unmatched application results to specified file formats.
6. Calculates the ROI based on matched applications and device counts.

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
The directory path where report files will be saved. Default is set to the TEMP directory.

.PARAMETER FormatChoice
The format for output files, either 'csv' or 'json'. Default is 'csv'.

.PARAMETER EndpointVersion
The version of the Microsoft Graph API to use, either 'v1.0' or 'beta'. Default is 'beta'.

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
The name of the report to request from Microsoft Graph. Default is 'AppInvRawData'.

.PARAMETER XmlUrl
The URL for the Patch My PC Supported Products XML file. Default is set to the official URL.

.PARAMETER UseExistingAppInvData
A switch to indicate whether to reuse existing application inventory data generated today. Default is $false.

.PARAMETER ROI_AverageAppsPerYear
The average number of updates per application per year, used in ROI calculation. Default is 8.

.PARAMETER ROI_AverageHoursPerApp
The average number of hours spent per application for packaging, testing, etc. Default is 4 hours.

.PARAMETER ROI_AverageCostPerHour
The average cost per hour of time spent on packaging or testing applications. Default is 30 USD.

.PARAMETER ROI_Currency
The currency used for the ROI calculation. Default is "USD".

.PARAMETER ROI_SKU1
The name of the first Patch My PC SKU used in ROI calculation. Default is "Enterprise Premium".

.PARAMETER ROI_SKU2
The name of the second Patch My PC SKU used in ROI calculation. Default is "Enterprise Plus".

.PARAMETER ROI_Quote1
The initial quote amount for the first SKU. Default is 3499.

.PARAMETER ROI_Quote1_Device
The quote per device for the first SKU. Default is 5.

.PARAMETER ROI_Quote2
The initial quote amount for the second SKU. Default is 2499.

.PARAMETER ROI_Quote2_Device
The quote per device for the second SKU. Default is 3.5.

.EXAMPLE
.\Get-PMPCFoundApps.ps1 -SavePath "C:\Reports" -FormatChoice "csv" -TenantId "your-tenant-id" -ClientId "your-client-id" -CertThumbprint "your-cert-thumbprint" -AuthFlow "ApplicationCertificate"

This command runs the script, saving the output as a CSV file in "C:\Reports" using the specified tenant ID, client ID, and certificate thumbprint for authentication.

.EXAMPLE
.\Get-PMPCFoundApps.ps1

This command runs the script using the current user's TEMP directory for saving output $env:TEMP\IntuneReports, requesting the results in csv format and using the delegated authentication flow.

#>
[CmdletBinding()]
param (
    [string]$SavePath = "$env:TEMP\IntuneReports",
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
    [ValidateSet('AppInvRawData', 'AppInvAggregate')]
    [string]$ReportingEndpointReportName = 'AppInvRawData',
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
    [int]$ROI_Quote1 = 3499,
    [ValidateRange(0.01, 100)]
    [double]$ROI_Quote1_Device = 5,
    [ValidateRange(0, 100000)]
    [int]$ROI_Quote2 = 2499,
    [ValidateRange(0.01, 100)]
    [double]$ROI_Quote2_Device = 3.5
)

$VerbosePreference = "SilentlyContinue"

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
        [string]$formatChoice
    )

    $body = @{
        reportName = $reportName
        filter     = ""
        format     = $formatChoice
    } | ConvertTo-Json

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

# Function to clean up files
Function Remove-ZipFile {
    param (
        [string]$ZipFilePath
    )

    # Clean up by deleting the zip file after extraction
    try {
        Remove-Item -Path $ZipFilePath -Force
        Write-Host ("Deleted zip file: {0}" -f $ZipFilePath) -ForegroundColor Green
    }
    catch {
        Write-Error ("Failed to delete the zip file. Error: {0}" -f $_)
    }
}

# Function to match applications with supported products and count incidents per product
Function Find-Applications {
    param (
        [array]$ApplicationData, # Changed parameter name for generality
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
        $deviceName = if ($app.PSObject.Properties['DeviceName']) { $app.DeviceName } else { $null }
        $isMatched = $false

        foreach ($pattern in $supportedProductsHash.Keys) {
            foreach ($product in $supportedProductsHash[$pattern]) {
                $sqlSearchIncludePattern = $product.SQLSearchIncludePattern
                $sqlSearchExcludePattern = $product.SQLSearchExcludePattern

                if ([string]::IsNullOrWhiteSpace($sqlSearchIncludePattern)) {
                    continue
                }

                # Test the app name against the SQLSearchInclude and SQLSearchExclude patterns
                $likeIncludePattern = $sqlSearchIncludePattern -replace '\*', '*' -replace '\%', '*'
                $sqlSearchIncludeMatch = $appName -like $likeIncludePattern

                if (-not [string]::IsNullOrWhiteSpace($sqlSearchExcludePattern)) {
                    $likeExcludePattern = $sqlSearchExcludePattern -replace '\*', '*' -replace '\%', '*'
                    $sqlSearchExcludeMatch = $appName -like $likeExcludePattern
                    if ($sqlSearchExcludeMatch) {
                        continue
                    }
                }

                if ($sqlSearchIncludeMatch) {

                    # Track all individual matches for CSV/JSON, keeping MatchedAppName
                    $matchedAppDetail = [pscustomobject]@{
                        DeviceName           = $deviceName
                        MatchedAppInvName    = $appName
                        MatchedPMPCProduct   = $product.Name
                        MatchedPMPCProductId = $product.Id
                    }
                    
                    $detailedMatchedApplications += $matchedAppDetail
                    $isMatched = $true
                }
            }
        }

        # If no match is found, add the app to unmatched list
        if (-not $isMatched) {
            $unmatchedAppDetail = [pscustomobject]@{
                DeviceName       = $deviceName
                UnmatchedAppName = $appName
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

# Test if the SavePath exists and create it if it doesn't
if (-not (Test-Path -Path $SavePath)) {
    try {
        # Attempt to create the directory
        New-Item -ItemType Directory -Path $SavePath -ErrorAction Stop
        Write-Host ("Directory '{0}' created successfully." -f $SavePath) -ForegroundColor Green
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
else {
    # Prepare the report request and endpoint and connect to Graph
    Write-Host "Requesting report and connecting to Graph..." -ForegroundColor Cyan
    
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
                Connect-MgGraph -Scopes "DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All"
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

    $reportEndpoint = "https://graph.microsoft.com/$($EndpointVersion)/deviceManagement/reports/exportJobs"
    $downloadUri = Request-Report -reportEndpoint $reportEndpoint -reportName $ReportingEndpointReportName -formatChoice $FormatChoice

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
            $appReportData = Import-Csv -Path $newestFile.FullName
            Write-Host ("Imported {0} applications from CSV" -f $appReportData.Count) -ForegroundColor Yellow
        }
        'json' {
            $appReportData = Get-Content -Path $newestFile.FullName | ConvertFrom-Json
            Write-Host ("Imported {0} applications from JSON" -f $appReportData.Count) -ForegroundColor Yellow
        }
    }

    # Call the Remove-ZipFile function to handle deletion of the zip file
    Remove-ZipFile -ZipFilePath $tempPath
}
else {

    # Reuse the existing app inventory data logic remains the same
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
            Name                    = $product.Name
            Id                      = $product.Id
            SQLSearchIncludePattern = if ($product.SQLSearchInclude) { 
                $product.SQLSearchInclude.Replace('%', '*').Replace('_', '?') 
            }
            else { 
                $null 
            }
            SQLSearchExcludePattern = if ($product.SQLSearchExclude) { 
                $product.SQLSearchExclude.Replace('%', '*').Replace('_', '?')
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
            Write-Host ("    Skipping product '{0}' due to empty SQLSearchInclude." -f $product.Name) -ForegroundColor Yellow
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
Write-Host "Filtering Windows apps and excluding Store apps from AppInvRawData..." -ForegroundColor Cyan
$appReportData = $appReportData | Where-Object { -not ($_.ApplicationName -like "Microsoft.*") -and -not ($_.ApplicationName -like "MicrosoftWindows.*") -and $_.Platform -eq 'Windows' }
$totalAppsToMatch = $appReportData.Count
Write-Host ("Total applications to test is: {0} out of a total of a total of {1}" -f $totalAppsToMatch, $totalApps) -ForegroundColor Cyan

# Call the Find-Applications function and capture the results for all apps in one go
$result = Find-Applications -ApplicationData $appReportData -supportedProductsHash $supportedProductsHash -totalApps $totalAppsToMatch

# Store the results returned by the function
$matchedApps = $result[0]
$unmatchedApps = $result[1]

# Create a unique list of unmatched app names
$uniqueUnmatchedAppNames = $unmatchedApps | Select-Object -ExpandProperty UnmatchedAppName -Unique

# Convert the unique unmatched app names into custom objects for export
$uniqueUnmatchedAppNameObjects = $uniqueUnmatchedAppNames | ForEach-Object { [PSCustomObject]@{UnmatchedAppName = $_ } }

# After processing all applications
$totalSkippedStoreApps = $totalApps - $totalAppsToMatch  # Calculate total skipped applications

# Display the totals
Write-Host ("Total skipped applications (Store Apps & Non-Windows Apps): {0}" -f $totalSkippedStoreApps) -ForegroundColor Yellow

# Group matched applications by MatchedPMPCProduct to calculate Total Instances
$instanceCount = $matchedApps | Group-Object MatchedPMPCProduct | ForEach-Object {
    [pscustomobject]@{
        MatchedPMPCProduct   = $_.Name
        TotalInstances       = $_.Count
        MatchedPMPCProductId = $_.Group[0].MatchedPMPCProductId
        MatchedAppNames      = ($_.Group | Select-Object -ExpandProperty MatchedAppInvName | Sort-Object -Unique) -join ", "
    }
}

# Display the table with the required columns in the desired order
if ($instanceCount.Count -gt 0) {
    Write-Host ("Found {0} apps in {1} that matched PMPC products" -f $instanceCount.Count, $ReportingEndpointReportName) -ForegroundColor Green
    $instanceCount | Format-Table -Property MatchedPMPCProduct, TotalInstances, MatchedPMPCProductId, MatchedAppNames -AutoSize
}

# Step 5: Calculate ROI

# Check if DeviceName data is available
if ($matchedApps.DeviceName) {

    # Calculate the total number of unique devices
    $uniqueDevices = $matchedApps | Select-Object -ExpandProperty DeviceName -Unique
    $deviceCount = $uniqueDevices.Count
}
else {
    $deviceCount = 0
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

    if ($deviceCount -gt 0) {
        Write-Host ("  - Number of devices in your environment: {0}" -f $deviceCount) -ForegroundColor Yellow
    }
    else {
        Write-Host ("  - Number of devices in your environment: {0}" -f $deviceCount) -ForegroundColor Yellow
        Write-Host "  - * No device data was found in the report to calculate cost based on your device count." -ForegroundColor Yellow
    }

    # Output the results as a table
    $roiResults | Format-Table -AutoSize
    if ($deviceCount -gt 0) {
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
            $matchedApps | Select-Object DeviceName, MatchedAppInvName, MatchedPMPCProduct, MatchedPMPCProductId | Export-Csv -Path $matchedOutputFile -NoTypeInformation
        }
        else {
            $matchedApps | Select-Object MatchedAppInvName, MatchedPMPCProduct, MatchedPMPCProductId | Export-Csv -Path $matchedOutputFile -NoTypeInformation
        }
        
        Write-Host ("Saving unmatched results to CSV: {0}" -f $unmatchedOutputRawFile) -ForegroundColor Cyan
        if ($hasDeviceName) {
            $unmatchedApps | Select-Object DeviceName, UnmatchedAppName | Export-Csv -Path $unmatchedOutputRawFile -NoTypeInformation
        }
        else {
            $unmatchedApps | Select-Object UnmatchedAppName | Export-Csv -Path $unmatchedOutputRawFile -NoTypeInformation
        }
        
        Write-Host ("Saving unsupported app results to CSV: {0}" -f $unmatchedOutputFile) -ForegroundColor Cyan
        
        # Group by UnmatchedAppName and count instances for TotalInstances
        $uniqueUnmatchedAppNameObjects = $unmatchedApps | Group-Object -Property UnmatchedAppName | ForEach-Object {
            [PSCustomObject]@{
                UnmatchedAppName = $_.Name
                TotalInstances   = $_.Count
            }
        }

        $uniqueUnmatchedAppNameObjects | Export-Csv -Path $unmatchedOutputFile -NoTypeInformation

        # Create supported apps data and export to CSV
        $supportedAppsData = $instanceCount | ForEach-Object {
            [PSCustomObject]@{
                MatchedAppInvName    = $_.MatchedPMPCProduct
                TotalInstances       = $_.TotalInstances
                MatchedPMPCProduct   = $_.MatchedPMPCProduct
                MatchedPMPCProductId = $_.MatchedPMPCProductId
            }
        }

        Write-Host ("Saving supported apps results to CSV: {0}" -f $supportedAppsOutputFile) -ForegroundColor Cyan
        $supportedAppsData | Export-Csv -Path $supportedAppsOutputFile -NoTypeInformation
    }
    'json' {
        Write-Host ("`nSaving matched results to JSON: {0}" -f $matchedOutputFile) -ForegroundColor Cyan
        if ($hasDeviceName) {
            $matchedApps | Select-Object DeviceName, MatchedAppInvName, MatchedPMPCProduct, MatchedPMPCProductId | ConvertTo-Json | Out-File -FilePath $matchedOutputFile
        }
        else {
            $matchedApps | Select-Object MatchedAppInvName, MatchedPMPCProduct, MatchedPMPCProductId | ConvertTo-Json | Out-File -FilePath $matchedOutputFile
        }

        Write-Host ("Saving unmatched results to JSON: {0}" -f $unmatchedOutputRawFile) -ForegroundColor Cyan
        if ($hasDeviceName) {
            $unmatchedApps | Select-Object DeviceName, UnmatchedAppName | ConvertTo-Json | Out-File -FilePath $unmatchedOutputRawFile
        }
        else {
            $unmatchedApps | Select-Object UnmatchedAppName | ConvertTo-Json | Out-File -FilePath $unmatchedOutputRawFile
        }

        Write-Host ("Saving unsupported app results to JSON: {0}" -f $unmatchedOutputFile) -ForegroundColor Cyan
        
        # Group by UnmatchedAppName and count instances for TotalInstances
        $uniqueUnmatchedAppNameObjects = $unmatchedApps | Group-Object -Property UnmatchedAppName | ForEach-Object {
            [PSCustomObject]@{
                UnmatchedAppName = $_.Name
                TotalInstances   = $_.Count  # Changed to TotalInstances
            }
        }

        $uniqueUnmatchedAppNameObjects | ConvertTo-Json | Out-File -FilePath $unmatchedOutputFile

        # Create supported apps data and export to JSON
        $supportedAppsData = $instanceCount | ForEach-Object {
            [PSCustomObject]@{
                MatchedAppInvName    = $_.MatchedPMPCProduct
                TotalInstances       = $_.TotalInstances
                MatchedPMPCProduct   = $_.MatchedPMPCProduct
                MatchedPMPCProductId = $_.MatchedPMPCProductId
            }
        }

        Write-Host ("Saving supported apps results to JSON: {0}" -f $supportedAppsOutputFile) -ForegroundColor Cyan
        $supportedAppsData | ConvertTo-Json | Out-File -FilePath $supportedAppsOutputFile
    }
}