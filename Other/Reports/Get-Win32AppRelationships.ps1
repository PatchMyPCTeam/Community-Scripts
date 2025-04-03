<# 
.SYNOPSIS
Generates a comprehensive HTML report of Win32 application relationships in Microsoft Intune.

.DESCRIPTION
This script creates an interactive HTML visualization of Win32 application relationships
in Microsoft Intune, including dependencies, supersedence chains, and parent/child relationships.
It connects to Microsoft Graph API to retrieve app data and builds a relationship tree
that can be navigated, filtered, and explored through an interactive HTML interface.

The script offers multiple modes of operation: analyze all applications at once,
focus on a specific application by name, or select an application interactively
through a GridView. It recursively traverses relationships to the specified maximum depth,
helping administrators understand complex application dependencies and relationships.

The generated HTML report provides a visual representation of these relationships with
filtering capabilities and navigation between related applications.

.NOTES
Author:     Ben Whitmore @PatchMyPC
Created:    March 2025

.PARAMETER AppName
The display name of a specific application to analyze. Supports wildcards (e.g., "Microsoft*"). 
If specified, only matching application(s) and their relationships will be processed.

.PARAMETER AllApps
Switch parameter to process all applications in the Intune environment.
This provides the most comprehensive view but may take longer to generate.

.PARAMETER MaxDepth
The maximum recursive depth to traverse when building the relationship tree.
Default is 10 levels deep, which balances thoroughness with performance.

.PARAMETER OutputPath
The file path where the HTML report will be saved.
Win32AppRelationships.html is the default file name saved in the user's temporary directory.

.EXAMPLE
.\Get-Win32AppRelationships.ps1
Launches an interactive GridView to select a single application for analysis.

.EXAMPLE
.\Get-Win32AppRelationships.ps1 -AppName "Microsoft*"
Analyzes relationships for all applications with names starting with "Microsoft".

.EXAMPLE
.\Get-Win32AppRelationships.ps1 -AllApps -MaxDepth 5
Analyzes all applications with a maximum relationship depth of 5 levels.

.EXAMPLE
.\Get-Win32AppRelationships.ps1 -AllApps -OutputPath "C:\Reports\AppRelationships.html"
Analyzes all applications and saves the report to a custom location.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$AppName = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$AllApps,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxDepth = 10,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({
            if ([string]::IsNullOrEmpty($_) -or (Test-Path (Split-Path $_ -Parent) -PathType Container)) {
                $true
            }
            else {
                throw "Path '$_' is not valid or the directory does not exist"
            }
        })]
    [string]$OutputPath = "$env:TEMP\Win32AppRelationships.html"
)

$VerbosePreference = "Continue"

# Initialize variables at the script level
$script:relationshipTree = @{}
$script:processedApps = @{}
$script:graphCache = @{}
$script:selectedApp = $null
$script:htmlComponents = @{}

# Cached Graph API request function
function Invoke-CachedGraphRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",
        
        [Parameter(Mandatory = $false)]
        [string]$Body
    )
    
    # Return cached response if available for GET requests
    if ($Method -eq "GET" -and $script:graphCache.ContainsKey($Uri)) {
        Write-Verbose "Returning cached response for URI: $Uri"
        return $script:graphCache[$Uri]
    }
    
    # Ensure token is valid
    if (-not (Ensure-ValidGraphToken)) {
        throw "Unable to obtain a valid Graph token"
    }
    
    try {
        $params = @{
            Uri    = $Uri
            Method = $Method
        }
        
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = "application/json"
        }
        
        $response = Invoke-MgGraphRequest @params
        
        # Cache GET responses
        if ($Method -eq "GET") {
            $script:graphCache[$Uri] = $response
        }
        
        return $response
    }
    catch {
        Write-Error "Graph API request failed for URI: $Uri. Error: $_"
        throw $_
    }
}

# Graph API app retrieval
function Get-GraphApps {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Filter = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Select = "id,displayName,publisher",
        
        [Parameter(Mandatory = $false)]
        [int]$Top = 999,
        
        [Parameter(Mandatory = $false)]
        [string]$AppId = ""
    )
    
    # If AppId is provided, get a specific app
    if (-not [string]::IsNullOrEmpty($AppId)) {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppId`?`$select=$Select"
        
        try {
            $response = Invoke-CachedGraphRequest -Uri $uri
            return $response
        }
        catch {
            Write-Warning "Failed to retrieve app with ID $AppId`: $_"
            return $null
        }
    }
    
    # Otherwise, get all apps matching the filter
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$select=$Select&`$top=$Top"
    
    if (-not [string]::IsNullOrEmpty($Filter)) {

        # Don't escape the filter if it's already been escaped
        if ($Filter.Contains("%")) {
            $uri += "&`$filter=$Filter"
        }
        else {
            $escapedFilter = [uri]::EscapeDataString($Filter)
            $uri += "&`$filter=$escapedFilter"
        }
    }
    
    try {
        $response = Invoke-CachedGraphRequest -Uri $uri
        return $response.value
    }
    catch {
        Write-Warning "Failed to retrieve apps: $_"
        return @()
    }
}

# Function to get app relationships
function Get-AppRelationships {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'Single', Mandatory = $true)]
        [string]$AppId,
        
        [Parameter(ParameterSetName = 'Batch', Mandatory = $true)]
        [array]$Apps,
        
        [Parameter(ParameterSetName = 'Batch', Mandatory = $false)]
        [int]$BatchSize = 20
    )
    
    # For single app relationship retrieval
    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppId/relationships"
        
        try {
            $response = Invoke-CachedGraphRequest -Uri $uri
            return $response.value
        }
        catch {
            Write-Warning "Failed to retrieve relationships for app $AppId`: $_"
            return @()
        }
    }

    # For batch retrieval
    else {
        $results = @{}
        $totalApps = $Apps.Count
        $processedCount = 0
        
        # Process apps in batches
        for ($i = 0; $i -lt $totalApps; $i += $BatchSize) {
            $batchApps = $Apps | Select-Object -Skip $i -First $BatchSize
            
            # Prepare batch request
            $batchRequests = @()
            $requestMap = @{}
            $requestId = 0
            
            foreach ($app in $batchApps) {

                # Skip apps with missing/invalid ID
                if ([string]::IsNullOrEmpty($app.id)) {
                    Write-Warning "Skipping app with missing ID"
                    continue
                }
                
                $requestId++
                $requestIdStr = $requestId.ToString()
                $requestMap[$requestIdStr] = $app.id
                $batchRequests += @{
                    id     = $requestIdStr
                    method = "GET"
                    url    = "/deviceAppManagement/mobileApps/$($app.id)/relationships"
                }
                $processedCount++
            }
            
            if ($batchRequests.Count -eq 0) {
                Write-Verbose "No valid requests in this batch, skipping"
                continue
            }
            
            $batchRequestBody = @{
                requests = $batchRequests
            } | ConvertTo-Json -Depth 10
            
            # Send batch request
            Write-Progress -Activity "Retrieving app relationships" -Status "Processing batch $([Math]::Ceiling($i / $BatchSize) + 1) of $([Math]::Ceiling($totalApps / $BatchSize))" -PercentComplete (($processedCount / $totalApps) * 100)
            
            try {
                $batchResponse = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/`$batch" -Body $batchRequestBody -ContentType "application/json"
                
                if ($null -eq $batchResponse -or $null -eq $batchResponse.responses) {
                    Write-Warning "Received invalid batch response"
                    continue
                }
                
                # Process responses
                foreach ($response in $batchResponse.responses) {
                    $appId = $requestMap[$response.id]
                    if ($response.status -eq 200) {
                        $results[$appId] = $response.body.value
                    }
                    else {
                        Write-Warning "Failed to get relationships for app $appId. Status: $($response.status)"
                    }
                }
            }
            catch {
                Write-Error "Error in batch request: $_"
            }
        }
        
        Write-Progress -Activity "Retrieving app relationships" -Completed
        return $results
    }
}

# Connect to Microsoft Graph
function Ensure-ValidGraphToken {
    [CmdletBinding()]
    param()
    
    $graphContext = Get-MgContext
    $tokenExpirationBuffer = 5 # minutes
    
    if (-not $graphContext) {
        try {
            Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -NoWelcome
            return $true
        }
        catch {
            Write-Error "Error connecting to Microsoft Graph: $_"
            return $false
        }
    }
    else {

        # Check if token is about to expire
        if ($graphContext.ExpiresOn -and $graphContext.ExpiresOn -lt (Get-Date).AddMinutes($tokenExpirationBuffer)) {
            try {
                Write-Verbose "Token expires soon. Refreshing..."
                Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -NoWelcome
                return $true
            }
            catch {
                Write-Error "Error refreshing Microsoft Graph token: $_"
                return $false
            }
        }
        return $true
    }
}

# Process all apps
function Process-AllApps {
    [CmdletBinding()]
    param()
    
    if (-not (Ensure-ValidGraphToken)) {
        return $false
    }
    
    try {

        # Get all apps first
        $apps = Get-GraphApps
        
        if ($apps.Count -eq 0) {
            Write-Warning "No apps found"
            return $false
        }
        
        # Setup progress bar
        Write-Progress -Activity "Processing applications" -Status "Retrieving app relationships in batches" -PercentComplete 0
        
        # Get relationships for all apps in batches
        try {
            $relationshipsResults = Get-AppRelationships -Apps $apps
        }
        catch {
            Write-Error "Error retrieving app relationships: $_"
            return $false
        }
        
        # Process each app and add to relationship tree
        $totalApps = $apps.Count
        $currentApp = 0
        $errors = 0
        
        foreach ($app in $apps) {
            $currentApp++
            try {

                # Ensure we have valid data
                if ($null -eq $app.id -or [string]::IsNullOrEmpty($app.displayName)) {
                    Write-Warning "Skipping app with invalid data: $($app.id)"
                    continue
                }
                
                Write-Progress -Activity "Processing applications" -Status "Processing $($app.displayName) ($currentApp of $totalApps)" -PercentComplete (($currentApp / $totalApps) * 100)
                
                # Add app to tree with its relationships
                $relationships = if ($relationshipsResults.ContainsKey($app.id)) { $relationshipsResults[$app.id] } else { @() }
                Add-AppRelationshipToTree -AppId $app.id -AppName $app.displayName -Relationships $relationships
            }
            catch {
                Write-Warning "Error processing app $($app.displayName): $_"
                $errors++
            }
        }
        
        Write-Progress -Activity "Processing applications" -Completed
        
        if ($errors -gt 0) {
            Write-Warning "Completed with $errors errors."
        }
        
        return $errors -lt $totalApps # Return true if at least some apps were processed successfully
    }
    catch {
        Write-Error "Error processing all apps: $_"
        return $false
    }
}

# Function to add app relationships to the tree
function Add-AppRelationshipToTree {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppId,
        
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $false)]
        [array]$Relationships = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$RelationshipTree = $script:relationshipTree
    )
    
    # Initialize the app in the relationship tree if it doesn't exist
    if (-not $RelationshipTree.ContainsKey($AppId)) {
        $RelationshipTree[$AppId] = @{
            AppId         = $AppId
            AppName       = $AppName
            Dependencies  = @()
            DependentApps = @()
            SupersededBy  = @()
            Supersedes    = @()
        }
    }
    
    if ($Relationships.Count -eq 0) {
        return
    }
    
    # Helper function to add related app if not exists
    $addRelatedApp = {
        param ($collection, $app)
        if (-not ($collection | Where-Object Id -eq $app.Id)) {
            $collection += $app
        }
        return $collection
    }
    
    foreach ($relationship in $Relationships) {
        $relatedApp = @{
            Id          = $relationship.targetId
            DisplayName = $relationship.targetDisplayName
            Version     = $relationship.targetDisplayVersion
            Publisher   = $relationship.targetPublisherDisplayName
        }
        
        switch ($relationship."@odata.type") {
            "#microsoft.graph.mobileAppDependency" {
                if ($relationship.targetType -eq "child") {

                    # This app depends on the target
                    $RelationshipTree[$AppId].Dependencies = & $addRelatedApp $RelationshipTree[$AppId].Dependencies $relatedApp
                }
                elseif ($relationship.targetType -eq "parent") {

                    # Target depends on this app
                    $RelationshipTree[$AppId].DependentApps = & $addRelatedApp $RelationshipTree[$AppId].DependentApps $relatedApp
                }
            }
            "#microsoft.graph.mobileAppSupersedence" {
                if ($relationship.targetType -eq "parent") {

                    # This app is superseded by the target
                    $RelationshipTree[$AppId].SupersededBy = & $addRelatedApp $RelationshipTree[$AppId].SupersededBy $relatedApp
                }
                elseif ($relationship.targetType -eq "child") {

                    # This app supersedes the target
                    $RelationshipTree[$AppId].Supersedes = & $addRelatedApp $RelationshipTree[$AppId].Supersedes $relatedApp
                }
            }
        }
    }
}

# Function to process app by name
function Process-AppByName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    if (-not (Ensure-ValidGraphToken)) {
        return $false
    }
    
    try {

        # Retrieve all apps once to avoid multiple API calls
        Write-Verbose "Retrieving all apps for name matching"
        $apps = Get-GraphApps
        
        if ($apps.Count -eq 0) {
            Write-Warning "No apps found"
            return $false
        }
        
        # Helper function for finding matches
        function Find-MatchingApps {
            param (
                [Parameter(Mandatory = $true)]
                [array]$Apps,
                
                [Parameter(Mandatory = $true)]
                [string]$SearchPattern,
                
                [Parameter(Mandatory = $false)]
                [switch]$ExactMatch
            )
            
            if ($ExactMatch) {
                return $Apps | Where-Object { $_.displayName -eq $SearchPattern }
            }
            else {
                return $Apps | Where-Object { $_.displayName -like $SearchPattern }
            }
        }
        
        # Handle wildcard search
        if ($Name -match '[*?]') {
            Write-Verbose "Wildcard detected in app name pattern: $Name"
            $matchedApps = Find-MatchingApps -Apps $apps -SearchPattern $Name
            
            if ($matchedApps.Count -eq 0) {
                Write-Warning "No apps found matching pattern: $Name"
                return $false
            }
            
            Write-Verbose "Found $($matchedApps.Count) apps matching pattern: $Name"
            
            # Process each matched app
            foreach ($app in $matchedApps) {
                Write-Verbose "Processing matched app: $($app.displayName)"
                Process-AppRelationships -AppId $app.id -AppName $app.displayName -VisitedApps @{}
            }
            
            return $true
        }
        
        # Try exact match first
        Write-Verbose "Searching for exact match: '$Name'"
        $exactMatches = Find-MatchingApps -Apps $apps -SearchPattern $Name -ExactMatch
        
        if ($exactMatches.Count -gt 0) {
            Write-Verbose "Found exact match for: '$Name'"
            foreach ($app in $exactMatches) {
                Write-Verbose "Processing app: $($app.displayName)"
                Process-AppRelationships -AppId $app.id -AppName $app.displayName -VisitedApps @{}
            }
            return $true
        }
        
        # Then try contains match
        Write-Verbose "No exact match found, searching for apps containing: '$Name'"
        $containsMatches = Find-MatchingApps -Apps $apps -SearchPattern "*$Name*"
        
        # If no contains matches, try with base name part (before version number)
        if ($containsMatches.Count -eq 0) {
            $nameParts = $Name -split '\s+\d'
            if ($nameParts.Count -gt 0) {
                $appNamePart = $nameParts[0].Trim()
                Write-Verbose "Trying with base app name: '$appNamePart'"
                $containsMatches = Find-MatchingApps -Apps $apps -SearchPattern "*$appNamePart*"
            }
        }
        
        if ($containsMatches.Count -eq 0) {
            Write-Warning "No apps found containing: '$Name'"
            return $false
        }
        
        # If only one match, process it
        if ($containsMatches.Count -eq 1) {
            $app = $containsMatches[0]
            Write-Verbose "Processing app: $($app.displayName)"
            Process-AppRelationships -AppId $app.id -AppName $app.displayName -VisitedApps @{}
            return $true
        }
        
        # Interactive selection for multiple matches
        Handle-MultipleAppMatches -MatchedApps $containsMatches -SearchName $Name
    }
    catch {
        Write-Error "Error processing app by name: $_"
        return $false
    }
}

# Function for handling multiple app matches
function Handle-MultipleAppMatches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$MatchedApps,
        
        [Parameter(Mandatory = $true)]
        [string]$SearchName
    )
    
    Write-Host "Multiple apps found matching '$SearchName'. Please select the correct app:" -ForegroundColor Yellow
    $maxToShow = [Math]::Min($MatchedApps.Count, 15)
    
    for ($i = 0; $i -lt $maxToShow; $i++) {
        Write-Host "[$($i+1)] $($MatchedApps[$i].displayName)" -ForegroundColor Cyan
    }
    
    if ($MatchedApps.Count -gt 15) {
        Write-Host "[More than 15 matches found. Showing first 15 only.]" -ForegroundColor Yellow
    }
    
    $selection = Read-Host "Enter the number of the app to process (or 'A' for all)"
    
    if ($selection -eq 'A' -or $selection -eq 'a') {
        foreach ($app in $MatchedApps) {
            Write-Verbose "Processing app: $($app.displayName)"
            Process-AppRelationships -AppId $app.id -AppName $app.displayName -VisitedApps @{}
        }
        return $true
    }
    elseif ([int]::TryParse($selection, [ref]$null) -and [int]$selection -ge 1 -and [int]$selection -le $MatchedApps.Count) {
        $app = $MatchedApps[[int]$selection - 1]
        Write-Verbose "Processing selected app: $($app.displayName)"
        Process-AppRelationships -AppId $app.id -AppName $app.displayName -VisitedApps @{}
        return $true
    }
    else {
        Write-Warning "Invalid selection. No apps processed."
        return $false
    }
}

# Function to process app selection
function Process-AppSelection {
    [CmdletBinding()]
    param()
    
    if (-not (Ensure-ValidGraphToken)) {
        return $false
    }
    
    try {
        $apps = Get-GraphApps
        
        if ($apps.Count -eq 0) {
            Write-Warning "No apps found"
            return $false
        }
        
        # Transform data for Out-GridView
        $appsForSelection = @()
        foreach ($app in $apps) {
            $appsForSelection += [PSCustomObject]@{
                Id          = $app.id
                DisplayName = $app.displayName
                Publisher   = if ($app.publisher) { $app.publisher } else { "Unknown" }
            }
        }
        
        $script:selectedApp = $appsForSelection | Out-GridView -Title "Select an app to view complete relationship tree" -OutputMode Single
        
        if ($null -eq $script:selectedApp) {
            Write-Warning "No app selected"
            return $false
        }
        
        Write-Verbose "Processing selected app: $($script:selectedApp.DisplayName)"
        
        # Process the app and its relationships recursively
        Process-AppRelationships -AppId $script:selectedApp.Id -AppName $script:selectedApp.DisplayName -VisitedApps @{}
        return $true
    }
    catch {
        Write-Error "Error processing app selection: $_"
        return $false
    }
}

# Function for relationship processing
function Process-AppRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppId,
        
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $false)]
        [int]$CurrentDepth = 0,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$VisitedApps = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$BatchResults = $null,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = $script:MaxDepth,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$ProcessedApps = $script:processedApps,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$RelationshipTree = $script:relationshipTree
    )
    
    # Skip if already processed at same or lower depth
    if ($VisitedApps.ContainsKey($AppId) -and $VisitedApps[$AppId] -le $CurrentDepth) {
        return
    }
    
    # Skip if max depth reached
    if ($CurrentDepth -gt $MaxDepth) {
        return
    }
    
    $VisitedApps[$AppId] = $CurrentDepth
    $ProcessedApps[$AppId] = $true
    
    # Get relationships - either from batch results or individually
    $relationships = $null
    if ($BatchResults -and $BatchResults.ContainsKey($AppId)) {
        $relationships = $BatchResults[$AppId]
    }
    else {
        $relationships = Get-AppRelationships -AppId $AppId
    }
    
    # Add app and relationships to the tree
    Add-AppRelationshipToTree -AppId $AppId -AppName $AppName -Relationships $relationships -RelationshipTree $RelationshipTree
    
    # Process related apps recursively
    if ($relationships) {
        foreach ($relationship in $relationships) {
            $relatedAppId = $relationship.targetId
            $relatedAppName = $relationship.targetDisplayName
            
            # Recursively process this related app
            Process-AppRelationships -AppId $relatedAppId -AppName $relatedAppName -CurrentDepth ($CurrentDepth + 1) `
                -VisitedApps $VisitedApps -BatchResults $BatchResults -MaxDepth $MaxDepth -ProcessedApps $ProcessedApps -RelationshipTree $RelationshipTree
        }
    }
}

# Function to create a visual tree representation with added filter option
function Format-RelationshipTree {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Tree,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string]$AppNameRequested = "",
        
        [Parameter(Mandatory = $false)]
        [bool]$AllAppsRequested = $false,
        
        [Parameter(Mandatory = $false)]
        [string]$SelectedAppName = ""
    )

    $totalAppsWithRelationships = @($Tree.Values | Where-Object { 
            $_.Dependencies.Count -gt 0 -or 
            $_.DependentApps.Count -gt 0 -or 
            $_.SupersededBy.Count -gt 0 -or 
            $_.Supersedes.Count -gt 0 
        }).Count

    # Determine the source of the apps in the report
    $appSource = "Unknown"
    if ($AllAppsRequested) {
        $appSource = "All Applications"
    }
    elseif (-not [string]::IsNullOrEmpty($AppNameRequested)) {
        $appSource = "Application Pattern: '$AppNameRequested'"
    }
    elseif (-not [string]::IsNullOrEmpty($SelectedAppName)) {
        $appSource = "Selected Application: '$SelectedAppName'"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
   <head>
      <meta charset="UTF-8" />
      <title>Win32 App Relationships</title>
      <style>
         :root {
         --font-family: "Poppins", sans-serif;
         --primary-color: #1BBC9B;
         --bg-dark: rgb(21, 21, 33);
         --bg-card: rgb(30, 30, 45);
         --bg-input: rgb(42, 42, 60);
         --text-light: #f0f0f0;
         --text-dark: #ffffff;
         --border-color: #444;
         --border-radius: 8px;
         --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
         --spacing-sm: 5px;
         --spacing-md: 10px;
         --spacing-lg: 15px;
         --spacing-xl: 30px;
         }
         body {
         font-family: var(--font-family);
         color: var(--text-light);
         background-color: var(--bg-dark);
         margin: 0;
         padding: var(--spacing-xl);
         font-size: 14px;
         }
         button {
         cursor: pointer;
         border: none;
         background-color: transparent;
         font-family: inherit;
         color: inherit;
         }
         .logoBtn {
         display: flex;
         align-items: center;
         justify-content: flex-start;
         gap: 8px; 
         background: none;
         border: none;
         padding: 0;
         cursor: pointer;
         }
         .clear-button {
         background-color: var(--primary-color);
         color: var(--text-dark);
         padding: 10px 16px;
         border-radius: var(--border-radius);
         transition: background-color 0.2s ease;
         }
         .clear-button:hover {
         background-color: #139b7f;
         }
         h1, h2 {
         color: var(--text-dark);
         }
         .highlight {
         color: var(--primary-color);
         font-weight: bold;
         }
         .card, .summary, .controls, .app-card {
         background-color: var(--bg-card);
         border-radius: var(--border-radius);
         box-shadow: var(--box-shadow);
         overflow: hidden;
         border: 1px solid var(--border-color);
         }
         .summary {
         padding: var(--spacing-lg);
         color: var(--text-light);
         }
         .controls {
         padding: var(--spacing-lg);
         color: var(--text-light);
         }
         .app-header {
         background-color: var(--bg-input);
         padding: var(--spacing-md) var(--spacing-lg);
         color: var(--text-dark);
         font-weight: bold;
         border-bottom: none;
         display: flex;
         align-items: center;
         gap: 8px; 
         }
         .app-content {
         padding: var(--spacing-lg);
         height: 100%;
         }
         .section-title {
         margin-top: var(--spacing-md);
         font-weight: bold;
         color: var(--primary-color);
         }
         .item {
         padding: var(--spacing-sm) var(--spacing-md);
         background-color: var(--bg-card:);
         border-radius: 4px;
         margin-top: var(--spacing-sm);
         }
         .app-link {
         color: #4da6ff;
         cursor: pointer;
         text-decoration: none;
         transition: color 0.2s ease;
         }
         .app-link:hover {
         color: #80c1ff;
         }
         .grid-container {
         display: grid;
         gap: var(--spacing-xl);
         }
         .grid-cols-1 { grid-template-columns: repeat(1, 1fr); }
         .grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
         .grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
         .grid-cols-4 { grid-template-columns: repeat(4, 1fr); }
         input.filter-box {
         all: unset;
         padding: 8px 16px;
         color: var(--text-light);
         background-color: var(--bg-input);
         border-radius: var(--border-radius);
         border: 1px solid var(--border-color);
         cursor: text;
         width: 250px;
         }
         input.filter-box:focus {
         border-color: var(--primary-color);
         background-color: var(--bg-card:);
         }
         select#gridSize {
         appearance: none;
         padding: 8px 30px 8px 12px;
         color: var(--text-light);
         background-color: var(--bg-input);
         border-radius: var(--border-radius);
         border: 1px solid var(--border-color);
         cursor: pointer;
         width: 80px;
         box-sizing: border-box;
         }
         select#gridSize:focus {
         border-color: var(--primary-color);
         background-color: var(--bg-card:);
         }
         .filter-count {
         color: var(--text-light);
         }
         .navigation-controls {
         position: fixed;
         bottom: var(--spacing-xl);
         right: var(--spacing-xl);
         background-color: var(--bg-card);
         border-radius: 50%;
         padding: var(--spacing-md);
         box-shadow: var(--box-shadow);
         display: flex;
         flex-direction: column;
         gap: var(--spacing-md);
         }
         .nav-button {
         background-color: var(--primary-color);
         color: var(--text-dark);
         width: 40px;
         height: 40px;
         border-radius: 50%;
         display: flex;
         align-items: center;
         justify-content: center;
         transition: background-color 0.2s ease;
         }
         .nav-button:hover {
         background-color: #139b7f;
         }
         .custom-select-wrapper {
         position: relative;
         display: inline-block;
         }
         .custom-select-wrapper select {
         appearance: none;
         cursor: pointer;
         width: 100%;
         padding: 8px 30px 8px 12px;
         box-sizing: border-box; 
         }
         .dropdown-icon {
         position: absolute;
         right: 5px;
         top: 50%;
         transform: translateY(-50%);
         height: 16px;
         width: 16px;
         pointer-events: none;
         fill: currentColor;
         }
      </style>
"@

    # Add JavaScript for grid layout, app navigation and filtering 
    $html += @"
<script>
   document.addEventListener('DOMContentLoaded', () => {
       // Cache DOM elements to avoid repeated queries
       const gridSizeSelect = document.getElementById('gridSize');
       const dropdownIcon = document.querySelector('.dropdown-icon');
       const appGrid = document.getElementById('appGrid');
       const filterInput = document.getElementById('appFilter');
       const filterCount = document.getElementById('filterCount');
       const noRelationshipsMessage = document.getElementById('noRelationshipsMessage');
       const appCards = {};
       const relatedApps = {};
       
       document.querySelectorAll('.app-card').forEach(card => {
           const appId = card.getAttribute('data-app-id');
           
           if (appId) {
               appCards[appId] = card;
               card.id = 'app-' + appId;
               
               // Build relationship map
               relatedApps[appId] = {
                   name: card.querySelector('.app-header').textContent.trim(),
                   relationships: []
               };
               
               // Collect all related app IDs
               card.querySelectorAll('.app-link').forEach(link => {
                   const relatedAppId = link.getAttribute('data-app-id');
                   if (relatedAppId && !relatedApps[appId].relationships.includes(relatedAppId)) {
                       relatedApps[appId].relationships.push(relatedAppId);
                   }
               });
           }
       });
       
       const hasRelationships = Object.keys(appCards).length > 0;
       if (!hasRelationships) {
           noRelationshipsMessage.style.display = 'block';
       }
   
       // Setup app link navigation
       document.querySelectorAll('.app-link').forEach(link => {
           link.addEventListener('click', () => {
               const targetAppId = link.getAttribute('data-app-id');
               navigateToApp(targetAppId);
           });
       });
   
       // Update grid column layout
       function updateGridColumns() {
           const cols = gridSizeSelect.value;
           appGrid.className = 'grid-container grid-cols-' + cols;
       }
   
       // Dropdown icon handling - consolidated transitions
       function handleDropdownIcon(isOpen) {
           dropdownIcon.style.transform = isOpen ? 
               'translateY(-50%) rotate(180deg)' : 
               'translateY(-50%) rotate(0deg)';
       }
   
       gridSizeSelect.addEventListener('focus', () => handleDropdownIcon(true));
       gridSizeSelect.addEventListener('blur', () => handleDropdownIcon(false));
       gridSizeSelect.addEventListener('change', () => {
           updateGridColumns();
           handleDropdownIcon(false);
           gridSizeSelect.blur();
       });
   
       // Filter apps based on input text
       function filterApps() {
           const filterText = filterInput.value.toLowerCase();
           let visibleApps = 0;
           
           // Use sets for better performance with large data
           const visibleAppIds = new Set();
           const expandedAppIds = new Set();
   
           // First pass: identify direct matches
           if (filterText.trim() === '') {

               // Show all apps if filter is empty
               Object.keys(appCards).forEach(appId => {
                   appCards[appId].style.display = '';
                   visibleApps++;
                   visibleAppIds.add(appId);
               });
           } else {
               Object.keys(relatedApps).forEach(appId => {
                   const appName = relatedApps[appId].name.toLowerCase();
                   if (appName.includes(filterText)) {
                       visibleAppIds.add(appId);
                   }
               });
   
               // Second pass: expand to include related apps
               visibleAppIds.forEach(appId => {
                   expandedAppIds.add(appId);
                   relatedApps[appId].relationships.forEach(relatedId => {
                       expandedAppIds.add(relatedId);
                   });
               });
   
               // Apply visibility
               Object.keys(appCards).forEach(appId => {
                   if (expandedAppIds.has(appId)) {
                       appCards[appId].style.display = '';
                       visibleApps++;
                   } else {
                       appCards[appId].style.display = 'none';
                   }
               });
           }
   
           // Update filter count
           const totalApps = Object.keys(appCards).length;
           filterCount.textContent = visibleApps + ' out of ' + totalApps + ' apps shown';
       }
   
       filterInput.addEventListener('input', filterApps);
   
       // Clear filter button
       document.getElementById('clearFilter').addEventListener('click', () => {
           filterInput.value = '';
           filterApps();
           filterInput.focus();
       });
   
       // Navigation function - consolidated style transitions
       window.navigateToApp = function(appId) {
           const targetCard = document.getElementById('app-' + appId);
   
           if (targetCard) {

               // If the card is hidden due to filtering, show it
               if (targetCard.style.display === 'none') {

                   // Set the filter to match this app
                   filterInput.value = relatedApps[appId].name;

                   // Apply the filter
                   filterApps();
               }
   
               targetCard.scrollIntoView({
                   behavior: 'smooth',
                   block: 'start'
               });
   
               // Apply highlight effect
               applyHighlightEffect(targetCard);
           }
       };
       
       // Extracted highlight effect to separate function
       function applyHighlightEffect(card) {

           // Apply transitions once
           card.style.transition = 'background-color 0.5s';
           const appContent = card.querySelector('.app-content');
           appContent.style.transition = 'background-color 0.5s';
           appContent.style.backgroundColor = '#3a5d56';
           
           // Get all items and apply transition once
           const items = card.querySelectorAll('.item');
           items.forEach(item => {
               item.style.transition = 'background-color 0.5s';
               item.style.backgroundColor = 'transparent';
           });
   
           // Reset after animation
           setTimeout(() => {
               appContent.style.backgroundColor = 'rgb(30, 30, 45)';
               
               // Restore item colors
               items.forEach((item, index) => {
                   item.style.backgroundColor = index % 2 === 1 ? 'rgb(30, 30, 45)' : 'rgb(30, 30, 45)';
               });
               
               // Cleanup transitions after another delay
               setTimeout(() => {
                   card.style.transition = '';
                   appContent.style.transition = '';
                   items.forEach(item => {
                       item.style.transition = '';
                   });
               }, 1000);
           }, 1000);
       }
   
       // Back to top functionality
       document.getElementById('backToTop').addEventListener('click', () => {
           window.scrollTo({
               top: 0,
               behavior: 'smooth'
           });
       });
   
       // Initialize
       updateGridColumns();
       filterApps(); // Initialize filter count
   
       // Handle hash navigation if present
       if (window.location.hash) {
           const appId = window.location.hash.substring(5);
           setTimeout(() => navigateToApp(appId), 300);
       }
   });
</script>
"@

    # Add HTML Logo
    $html += @"
<!--Logo Start-->
<div class='css-97v30w'>
<button type="button" class="logoBtn">
   <svg width="48" height="48" viewBox="0 0 38 38" fill="none"
      xmlns="http://www.w3.org/2000/svg" class="logo">
      <g clip-path="url(#clip0_1301_19104)">
         <path d="M1.235 24.852C1.007 24.776 0.836 24.605 0.76 24.377C0.266 22.629 0 20.824 0 19C0 16.758 0.38 14.592 1.14 12.502C1.767 10.754 2.679 9.10099 3.8 7.61899C3.933 7.42899 4.237 7.48599 4.294 7.73299C4.427 8.35999 4.617 9.17699 4.826 10.013C5.871 14.307 6.897 17.974 7.961 20.957C8.303 22.002 8.664 22.971 9.025 23.883C9.424 24.89 9.937 25.897 10.564 26.828C10.811 27.227 11.039 27.569 11.248 27.835C11.305 27.911 11.362 27.968 11.4 28.044L1.235 24.852Z"
            fill="#0081C6"></path>
         <path d="M18.9999 38C18.2209 38 17.4609 37.943 16.7009 37.867C16.4729 37.848 16.3779 37.563 16.5489 37.392C17.7839 36.233 19.2089 34.941 19.8549 34.352C20.3109 33.991 20.7289 33.649 21.1659 33.326C21.9829 32.68 22.7429 32.072 23.4649 31.483C26.1819 29.241 28.1009 26.619 29.2409 23.674C29.6779 22.515 30.0959 21.223 30.4949 19.855C30.8939 21.736 32.1669 27.664 32.9459 31.483C32.9839 31.711 32.9269 31.939 32.7749 32.11C31.0649 33.896 29.0509 35.34 26.8089 36.347C24.3389 37.43 21.7359 38 18.9999 38Z"
            fill="#0081C6"></path>
         <path d="M30.9512 18.031C31.5972 15.333 31.9962 12.977 32.1672 11.742L36.7652 13.167C36.9932 13.243 37.1642 13.414 37.2402 13.642C37.7532 15.371 38.0002 17.176 38.0002 18.981C38.0002 21.223 37.6202 23.389 36.8602 25.479C36.2332 27.246 35.3212 28.88 34.2002 30.381C34.0672 30.571 33.7632 30.514 33.7062 30.286L30.9512 18.031Z"
            fill="#0081C6"></path>
         <path d="M31.1031 10.336L19.6461 4.90199L17.3091 5.79499L23.0091 0.550995C23.0851 0.493995 23.1611 0.455995 23.2561 0.493995C26.2771 1.19699 29.0891 2.622 31.4641 4.65499C33.6301 6.53599 35.3781 8.92999 36.4991 11.552C36.5941 11.761 36.3851 11.989 36.1571 11.932L31.1031 10.336Z"
            fill="#0081C6"></path>
         <path d="M5.07312 6.536C5.01612 6.308 5.09212 6.061 5.24412 5.89C6.95412 4.104 8.94912 2.679 11.2101 1.653C13.6611 0.57 16.2831 0 19.0001 0C19.7791 0 20.5581 0.057 21.3181 0.152C21.5461 0.19 21.6411 0.475 21.4701 0.627L14.4211 7.087L6.04212 10.887L5.07312 6.536Z"
            fill="#0081C6"></path>
         <path d="M15.0481 37.468C14.9911 37.525 14.8961 37.563 14.8011 37.544C11.7611 36.86 8.93012 35.397 6.57412 33.383C4.38912 31.483 2.66012 29.108 1.53912 26.467C1.44412 26.258 1.65312 26.03 1.88112 26.087L12.5401 29.431C15.0291 32.167 17.7461 33.649 18.6961 34.105L15.0481 37.468Z"
            fill="#0081C6"></path>
         <path d="M25.6882 23.237V15.067C25.6882 14.915 25.5742 14.763 25.4792 14.744L25.1562 14.687C25.0992 14.668 25.0422 14.687 24.9852 14.744C24.8902 14.839 24.8142 14.953 24.7192 15.067C24.6432 15.162 24.7002 15.333 24.8332 15.352C24.9092 15.371 24.9852 15.447 24.9852 15.523V22.154C24.9852 22.249 24.9092 22.325 24.8142 22.325L14.1552 22.933C14.0602 22.933 13.9652 22.857 13.9652 22.762V13.908C13.9652 13.794 14.0602 13.718 14.1742 13.737L20.6532 14.706C20.7292 14.725 20.7862 14.687 20.8242 14.611C20.9002 14.478 20.9952 14.345 21.0712 14.193C21.1282 14.079 21.0712 13.946 20.9572 13.927L13.1102 12.597C12.7112 12.521 12.3882 12.901 12.3882 13.167V24.586C12.3882 24.795 12.5782 24.947 12.8252 24.928C12.8252 24.928 15.3902 24.7 18.3542 24.434C18.4682 24.415 18.5632 24.51 18.5442 24.624L18.4872 25.232C18.4872 25.308 18.4112 25.365 18.3352 25.384C17.4802 25.536 16.8722 25.783 16.8532 25.992C16.8532 26.334 18.5252 26.429 20.2922 26.201C21.7552 26.03 22.8002 25.688 22.8002 25.441C22.8002 25.251 22.1732 25.118 21.2422 25.099C21.1472 25.099 21.0712 25.023 21.0712 24.909L21.0902 24.339C21.0902 24.244 21.1662 24.187 21.2422 24.168C23.3512 23.978 25.2702 23.807 25.3272 23.807C25.7072 23.769 25.6882 23.256 25.6882 23.237Z"
            class="secondary" fill="white"></path>
         <path d="M24.8901 10.165C22.2871 12.35 20.6531 15.675 19.5891 17.974C19.5511 18.069 19.4181 18.088 19.3421 18.012C18.8671 17.518 17.4231 16.036 17.0051 15.523C16.9481 15.447 16.8341 15.447 16.7771 15.523C16.4161 15.979 15.6751 16.872 15.2571 17.366C15.2001 17.423 15.2191 17.537 15.2761 17.575C16.3781 18.392 19.1141 20.805 20.1211 21.755C20.1971 21.831 20.3111 21.793 20.3491 21.698C22.4201 16.948 24.3581 14.269 26.8091 12.331C26.8851 12.274 26.8851 12.179 26.8281 12.122L25.0991 10.184C25.0421 10.127 24.9471 10.108 24.8901 10.165Z"
            fill="#6DBA44"></path>
      </g>
      <defs>
         <clipPath id="clip0_1301_19104">
            <rect width="58" height="58" fill="white"></rect>
         </clipPath>
      </defs>
   </svg>
   <svg width="130" height="20" viewBox="0 0 110 10" fill="none" xmlns="http://www.w3.org/2000/svg"
      class="logo">
      <g clip-path="url(#clip0_1301_19123)">
         <path d="M58.2266 0H61.5999L64.4966 6.34333L67.5032 0H70.6566V9.46H68.1999V3.19L65.4132 9.46H63.4332L60.6466 3.19V9.46H58.2266V0Z"
            fill="#0081C6"></path>
         <path d="M76.2299 6.01333L71.6832 0H74.7999L77.5499 3.77667L80.2999 0H83.1232L78.7966 6.01333V9.46H76.2666V6.01333H76.2299Z"
            fill="#0081C6"></path>
         <path d="M90.2732 9.46H87.7432V0H93.9032C96.7999 0 97.6799 1.32 97.6799 3.15333V3.26333C97.6799 5.09667 96.7632 6.41667 93.9032 6.41667H90.2732V9.46ZM90.2732 4.36333H93.7199C94.6366 4.36333 95.0766 3.99667 95.0766 3.3V3.22667C95.0766 2.56667 94.6366 2.16333 93.7199 2.16333H90.2732V4.36333Z"
            fill="#0081C6"></path>
         <path d="M104.317 9.46C100.173 9.46 98.9999 6.78333 98.9999 4.91333V4.54667C98.9999 2.64 100.173 0 104.317 0H104.867C108.68 0 110 1.87 110 3.59333V3.66667H107.36C107.323 3.41 106.993 2.09 104.573 2.09C102.337 2.09 101.64 3.33667 101.64 4.54667V4.69333C101.64 5.83 102.337 7.26 104.573 7.26C106.993 7.26 107.323 5.90333 107.36 5.68333H110V5.72C110 7.66333 108.533 9.46 104.317 9.46Z"
            fill="#0081C6"></path>
         <path d="M2.53 6.41667V9.46H0V0H6.16C9.05667 0 9.93667 1.28333 9.93667 3.11667V3.22667C9.93667 5.06 9.02 6.34333 6.16 6.34333L2.53 6.41667ZM2.53 4.32667H6.01333C6.93 4.32667 7.37 3.96 7.37 3.3V3.19C7.37 2.53 6.93 2.16333 6.01333 2.16333H2.53V4.32667Z"
            class="secondary" fill="white"></path>
         <path d="M17.71 7.7H12.7967L12.1 9.46H9.53333L13.6033 0H16.94L21.1933 9.46H18.4433L17.71 7.7ZM15.18 1.87L13.6033 5.68333H16.8667L15.18 1.87Z"
            class="secondary" fill="white"></path>
         <path d="M23.43 2.16333H19.8733V0H29.37V2.16333H25.9233V9.46H23.3933C23.43 9.46 23.43 2.16333 23.43 2.16333Z"
            class="secondary" fill="white"></path>
         <path d="M42.57 0H45.1V3.48333H50.2333V0H52.7633V9.46H50.2333V5.64667H45.1367V9.46H42.6067L42.57 0Z"
            class="secondary" fill="white"></path>
         <path d="M35.31 9.46C31.1667 9.46 29.9933 6.78333 29.9933 4.91333V4.54667C29.9933 2.64 31.1667 0 35.31 0H35.86C39.6733 0 40.9933 1.87 40.9933 3.59333V3.66667H38.3533C38.3167 3.41 37.9867 2.09 35.5667 2.09C33.33 2.09 32.6333 3.33667 32.6333 4.54667V4.69333C32.6333 5.83 33.33 7.26 35.5667 7.26C37.9867 7.26 38.3167 5.90333 38.3533 5.68333H40.9933V5.72C40.9933 7.66333 39.5267 9.46 35.31 9.46Z"
            class="secondary" fill="white"></path>
      </g>
      <defs>
         <clipPath id="clip0_1301_19123">
            <rect width="110" height="9.46" fill="white"></rect>
         </clipPath>
      </defs>
   </svg>
</button>
"@

    # Add the rest of the HTML content
    $html += @"
</div>
</head>
<body>
   <svg xmlns="http://www.w3.org/2000/svg" style="display: none;">
      <symbol id="grid-icon" viewBox="0 0 20 20">
         <path d="M5.83333 0H3.33333C2.44928 0 1.60143 0.35119 0.976311 0.976311C0.35119 1.60143 0 2.44928 0 3.33333L0 5.83333C0 6.71739 0.35119 7.56524 0.976311 8.19036C1.60143 8.81548 2.44928 9.16667 3.33333 9.16667H5.83333C6.71739 9.16667 7.56524 8.81548 8.19036 8.19036C8.81548 7.56524 9.16667 6.71739 9.16667 5.83333V3.33333C9.16667 2.44928 8.81548 1.60143 8.19036 0.976311C7.56524 0.35119 6.71739 0 5.83333 0V0ZM7.5 5.83333C7.5 6.27536 7.32441 6.69928 7.01184 7.01184C6.69928 7.32441 6.27536 7.5 5.83333 7.5H3.33333C2.89131 7.5 2.46738 7.32441 2.15482 7.01184C1.84226 6.69928 1.66667 6.27536 1.66667 5.83333V3.33333C1.66667 2.89131 1.84226 2.46738 2.15482 2.15482C2.46738 1.84226 2.89131 1.66667 3.33333 1.66667H5.83333C6.27536 1.66667 6.69928 1.84226 7.01184 2.15482C7.32441 2.46738 7.5 2.89131 7.5 3.33333V5.83333Z" fill="currentColor"></path>
         <path d="M16.6665 0H14.1665C13.2825 0 12.4346 0.35119 11.8095 0.976311C11.1844 1.60143 10.8332 2.44928 10.8332 3.33334V5.83334C10.8332 6.71739 11.1844 7.56524 11.8095 8.19036C12.4346 8.81548 13.2825 9.16667 14.1665 9.16667H16.6665C17.5506 9.16667 18.3984 8.81548 19.0235 8.19036C19.6487 7.56524 19.9998 6.71739 19.9998 5.83334V3.33334C19.9998 2.44928 19.6487 1.60143 19.0235 0.976311C18.3984 0.35119 17.5506 0 16.6665 0V0ZM18.3332 5.83334C18.3332 6.27537 18.1576 6.69929 17.845 7.01185C17.5325 7.32441 17.1085 7.50001 16.6665 7.50001H14.1665C13.7245 7.50001 13.3006 7.32441 12.988 7.01185C12.6754 6.69929 12.4999 6.27537 12.4999 5.83334V3.33334C12.4999 2.89131 12.6754 2.46738 12.988 2.15482C13.3006 1.84226 13.7245 1.66667 14.1665 1.66667H16.6665C17.1085 1.66667 17.5325 1.84226 17.845 2.15482C18.1576 2.46738 18.3332 2.89131 18.3332 3.33334V5.83334Z" fill="currentColor"></path>
         <path d="M5.83333 10.8333H3.33333C2.44928 10.8333 1.60143 11.1845 0.976311 11.8096C0.35119 12.4347 0 13.2826 0 14.1667L0 16.6667C0 17.5507 0.35119 18.3986 0.976311 19.0237C1.60143 19.6488 2.44928 20 3.33333 20H5.83333C6.71739 20 7.56524 19.6488 8.19036 19.0237C8.81548 18.3986 9.16667 17.5507 9.16667 16.6667V14.1667C9.16667 13.2826 8.81548 12.4347 8.19036 11.8096C7.56524 11.1845 6.71739 10.8333 5.83333 10.8333ZM7.5 16.6667C7.5 17.1087 7.32441 17.5326 7.01184 17.8452C6.69928 18.1577 6.27536 18.3333 5.83333 18.3333H3.33333C2.89131 18.3333 2.46738 18.1577 2.15482 17.8452C1.84226 17.5326 1.66667 17.1087 1.66667 16.6667V14.1667C1.66667 13.7246 1.84226 13.3007 2.15482 12.9881C2.46738 12.6756 2.89131 12.5 3.33333 12.5H5.83333C6.27536 12.5 6.69928 12.6756 7.01184 12.9881C7.32441 13.3007 7.5 13.7246 7.5 14.1667V16.6667Z" fill="currentColor"></path>
         <path d="M16.6665 10.8333H14.1665C13.2825 10.8333 12.4346 11.1845 11.8095 11.8096C11.1844 12.4347 10.8332 13.2826 10.8332 14.1667V16.6667C10.8332 17.5507 11.1844 18.3986 11.8095 19.0237C12.4346 19.6488 13.2825 20 14.1665 20H16.6665C17.5506 20 18.3984 19.6488 19.0235 19.0237C19.6487 18.3986 19.9998 17.5507 19.9998 16.6667V14.1667C19.9998 13.2826 19.6487 12.4347 19.0235 11.8096C18.3984 11.1845 17.5506 10.8333 16.6665 10.8333ZM18.3332 16.6667C18.3332 17.1087 18.1576 17.5326 17.845 17.8452C17.5325 18.1577 17.1085 18.3333 16.6665 18.3333H14.1665C13.7245 18.3333 13.3006 18.1577 12.988 17.8452C12.6754 17.5326 12.4999 17.1087 12.4999 16.6667V14.1667C12.4999 13.7246 12.6754 13.3007 12.988 12.9881C13.3006 12.6756 13.7245 12.5 14.1665 12.5H16.6665C17.1085 12.5 17.5325 12.6756 17.845 12.9881C18.1576 13.3007 18.3332 13.7246 18.3332 14.1667V16.6667Z" fill="currentColor"></path>
      </symbol>
   </svg>
   <br>
   <div class="summary card" style="width: 1200px; justify-content: space-between; display: flex; gap: 40px; padding: 20px;">
      <div>
        <h2>Win32 App Relationship Summary</h2>
        <p><span class="highlight">Query Type:</span> $appSource</p>
        <p><span class="highlight">Total apps with relationships:</span> $totalAppsWithRelationships</p>
        <p><span class="highlight">Maximum Depth Analyzed:</span> $MaxDepth</p>
        <p><span class="highlight">Report generated on:</span> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
      <div class="controls-container" style="width: 500px;">
         <div class="controls card" style="padding:15px;">
            <div style="margin-bottom: 15px;">
               <div style="margin-bottom: 8px;"><span class="highlight">Grid Layout:</span></div>
               <div class="custom-select-wrapper">
                  <select id="gridSize">
                     <option value="1">1</option>
                     <option value="2">2</option>
                     <option value="3" selected>3</option>
                     <option value="4">4</option>
                  </select>
                  <svg class="dropdown-icon" viewBox="0 0 20 20" aria-hidden="true" focusable="false">
                     <path d="M4.516 7.548c0.436-0.446 1.043-0.481 1.576 0l3.908 3.747 3.908-3.747c0.533-0.481 1.141-0.446 1.574 0 0.436 0.445 0.408 1.197 0 1.615-0.406 0.418-4.695 4.502-4.695 4.502-0.217 0.223-0.502 0.335-0.787 0.335s-0.57-0.112-0.789-0.335c0 0-4.287-4.084-4.695-4.502s-0.436-1.17 0-1.615z"></path>
                  </svg>
               </div>
            </div>
            <div>
               <div style="margin-bottom: 8px;"><span class="highlight">Filter apps:</span></div>
               <div class="filter-input-group">
                  <input type="text" id="appFilter" class="filter-box" placeholder="Enter app name...">
                  <button id="clearFilter" class="clear-button">Clear</button>
               </div>
               <br>
               <span id="filterCount" class="filter-count"></span>
            </div>
         </div>
      </div>
   </div>
   <br>
   <div id="appGrid" class="grid-container grid-cols-3">
   <!-- No relationships message - will be shown/hidden via JavaScript -->
   <div id="noRelationshipsMessage" class="card summary" style="grid-column: 1 / -1; display: none; text-align: center; width: 1200px; padding: 20px;">
      <h2 style="color: var(--primary-color); margin-bottom: 20px;">No Relationships Found</h2>
      <p style="font-size: 16px;">No application relationships were found for your query.</p>
      <p style="font-size: 16px;">This application does not have any dependencies, dependent apps, superseded apps, or supersedence relationships. Re-Run the script and consider using the -AllApps switch to check for relationships in all Win32 apps or dont use any parameter to select another application from the out-grid view.</p>
   </div>
"@

    foreach ($app in $Tree.Values | Where-Object {
            $_.Dependencies.Count -gt 0 -or
            $_.DependentApps.Count -gt 0 -or
            $_.SupersededBy.Count -gt 0 -or
            $_.Supersedes.Count -gt 0
        }) {

        $html += @"
<div class="app-card" id="app-$($app.AppId)" data-app-id="$($app.AppId)">
<div class="app-header">
   <span>
      <svg width="20" height="20" class="gl_icon_sm">
         <use href="#grid-icon" />
      </svg>
   </span>
   $($app.AppName)
</div>
<div class="app-content">
"@

        if ($app.SupersededBy.Count -gt 0) {
            $html += "<div class='section-title'>⬅️ Superseded By:</div>"
            foreach ($item in $app.SupersededBy) {
                $html += "<div class='item'><a class='app-link' data-app-id='$($item.Id)'>$($item.DisplayName) $(if($item.Version){"v$($item.Version)"})</a></div>"
            }
        }

        if ($app.Supersedes.Count -gt 0) {
            $html += "<div class='section-title'>➡️ Supersedes:</div>"
            foreach ($item in $app.Supersedes) {
                $html += "<div class='item'><a class='app-link' data-app-id='$($item.Id)'>$($item.DisplayName) $(if($item.Version){"v$($item.Version)"})</a></div>"
            }
        }

        if ($app.Dependencies.Count -gt 0) {
            $html += "<div class='section-title'>⤵️ Depends on:</div>"
            foreach ($item in $app.Dependencies) {
                $html += "<div class='item'><a class='app-link' data-app-id='$($item.Id)'>$($item.DisplayName) $(if($item.Version){"v$($item.Version)"})</a></div>"
            }
        }

        if ($app.DependentApps.Count -gt 0) {
            $html += "<div class='section-title'>⤴️ Dependency for:</div>"
            foreach ($item in $app.DependentApps) {
                $html += "<div class='item'><a class='app-link' data-app-id='$($item.Id)'>$($item.DisplayName) $(if($item.Version){"v$($item.Version)"})</a></div>"
            }
        }

        $html += "</div></div>"  # close app-content and app-card
    }

    # Add navigation controls
    $html += @"
<div class="navigation-controls">
   <button id="backToTop" class="nav-button" title="Back to Top">↑</button>
</div>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Relationship tree report saved to: $OutputPath" -ForegroundColor Green
        Invoke-Item $OutputPath
    }
    catch {
        Write-Error "Error saving report: $_"
    }
}

# Connect to Microsoft Graph
if (-not (Ensure-ValidGraphToken)) {
    Write-Error "Failed to connect to Microsoft Graph. Exiting."
    exit 1
}

# Process apps based on input parameters
$success = $false
$selectedAppName = ""

if ($AllApps) {
    $success = Process-AllApps
}
elseif (-not [string]::IsNullOrEmpty($AppName)) {
    $success = Process-AppByName -Name $AppName
}
else {
    $selectedApp = $null
    $success = Process-AppSelection
    if ($success -and $selectedApp) {
        $selectedAppName = $selectedApp.DisplayName
    }
}

if (-not $success) {
    Write-Error "Failed to process app relationships. Exiting."
    exit 1
}

# Generate the visual report
Format-RelationshipTree -Tree $script:relationshipTree -OutputPath $OutputPath -AppNameRequested $AppName -AllAppsRequested $AllApps -SelectedAppName $selectedAppName