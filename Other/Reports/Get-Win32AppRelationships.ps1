[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$AppName = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$AllApps,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxDepth = 10,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "$env:TEMP\Win32AppRelationships.html"
)

$VerbosePreference = "Continue"


$relationshipTree = @{}
$processedAppPaths = @{}
$queriedAppRelationships = @{}

function Get-AppRelationships {
    param (
        [string]$AppId,
        [string]$AppName,
        [int]$ParentDepth = 0,
        [int]$ChildDepth = 0,
        [string]$RelationshipPath = ""
    )

    $uniquePathKey = "$AppId|$RelationshipPath"

    # Avoid repeated recursion down the same path
    if ($processedAppPaths.ContainsKey($uniquePathKey)) {
        return
    }
    $processedAppPaths[$uniquePathKey] = $true

    if (-not $relationshipTree.ContainsKey($AppId)) {
        $relationshipTree[$AppId] = @{
            AppId                = $AppId
            AppName              = $AppName
            Dependencies         = @()
            DependentApps        = @()
            SupersededBy         = @()
            Supersedes           = @()
            ParentDepth          = $ParentDepth
            ChildDepth           = $ChildDepth
            RelationshipPaths    = @($RelationshipPath)
        }
    }
    else {
        # Update depths if higher
        $relationshipTree[$AppId].ParentDepth = [Math]::Max($ParentDepth, $relationshipTree[$AppId].ParentDepth)
        $relationshipTree[$AppId].ChildDepth  = [Math]::Max($ChildDepth, $relationshipTree[$AppId].ChildDepth)
        if (-not $relationshipTree[$AppId].RelationshipPaths.Contains($RelationshipPath)) {
            $relationshipTree[$AppId].RelationshipPaths += $RelationshipPath
        }
    }

    # Avoid repeated Graph requests for the same app
    if ($queriedAppRelationships.ContainsKey($AppId)) {
        return
    }
    $queriedAppRelationships[$AppId] = $true

    # Get relationships from Graph (only once per AppId)
    $relationshipsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppId/relationships"
    $relationshipsResponse = Invoke-MgGraphRequest -Uri $relationshipsUri -Method GET

    foreach ($relationship in $relationshipsResponse.value) {
        $relatedApp = @{
            Id          = $relationship.targetId
            DisplayName = $relationship.targetDisplayName
            Version     = $relationship.targetDisplayVersion
            Publisher   = $relationship.targetPublisherDisplayName
        }

        switch ($relationship."@odata.type") {
            "#microsoft.graph.mobileAppDependency" {
                if ($relationship.targetType -eq "child") {
                    if (-not ($relationshipTree[$AppId].Dependencies | Where-Object Id -eq $relatedApp.Id)) {
                        $relationshipTree[$AppId].Dependencies += $relatedApp
                    }
                    Get-AppRelationships `
                        -AppId $relatedApp.Id `
                        -AppName $relatedApp.DisplayName `
                        -ParentDepth $ParentDepth `
                        -ChildDepth ($ChildDepth + 1) `
                        -RelationshipPath ("$RelationshipPath -> $AppName")
                }
                elseif ($relationship.targetType -eq "parent") {
                    if (-not ($relationshipTree[$AppId].DependentApps | Where-Object Id -eq $relatedApp.Id)) {
                        $relationshipTree[$AppId].DependentApps += $relatedApp
                    }
                    Get-AppRelationships `
                        -AppId $relatedApp.Id `
                        -AppName $relatedApp.DisplayName `
                        -ParentDepth ($ParentDepth + 1) `
                        -ChildDepth $ChildDepth `
                        -RelationshipPath ("$RelationshipPath -> $AppName")
                }
            }

            "#microsoft.graph.mobileAppSupersedence" {
                if ($relationship.targetType -eq "parent") {
                    if (-not ($relationshipTree[$AppId].SupersededBy | Where-Object Id -eq $relatedApp.Id)) {
                        $relationshipTree[$AppId].SupersededBy += $relatedApp
                    }
                    Get-AppRelationships `
                        -AppId $relatedApp.Id `
                        -AppName $relatedApp.DisplayName `
                        -ParentDepth ($ParentDepth + 1) `
                        -ChildDepth $ChildDepth `
                        -RelationshipPath ("$RelationshipPath -> $AppName")
                }
                elseif ($relationship.targetType -eq "child") {
                    if (-not ($relationshipTree[$AppId].Supersedes | Where-Object Id -eq $relatedApp.Id)) {
                        $relationshipTree[$AppId].Supersedes += $relatedApp
                    }
                    Get-AppRelationships `
                        -AppId $relatedApp.Id `
                        -AppName $relatedApp.DisplayName `
                        -ParentDepth $ParentDepth `
                        -ChildDepth ($ChildDepth + 1) `
                        -RelationshipPath ("$RelationshipPath -> $AppName")
                }
            }
        }
    }
}

# Ensure Graph Connection
try {
    Write-Verbose "Checking Microsoft Graph connection..."
    $graphContext = Get-MgContext
    if (-not $graphContext) {
        Write-Verbose "Not connected to Microsoft Graph. Attempting to connect..."
        try {
            Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -NoWelcome
            Write-Verbose "Successfully connected to Microsoft Graph."
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $_"
            return
        }
    }
    else {
        Write-Verbose "Already connected to Microsoft Graph."
    }
}
catch {
    Write-Error "Error checking Microsoft Graph connection: $_"
    return
}

# Get all apps or specified app
if ($AllApps) {
    try {
        Write-Verbose "Retrieving all apps from Microsoft Graph..."
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$select=id,displayName,publisher"
        $appsResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($appsResponse.value.Count -eq 0) {
            Write-Error "No apps found in the tenant."
            return
        }
        
        foreach ($app in $appsResponse.value) {
            Write-Verbose "Processing app: $($app.displayName)"
            Get-AppRelationships -AppId $app.id -AppName $app.displayName
        }
    }
    catch {
        Write-Error "Error retrieving all apps: $_"
        return
    }
}
elseif (-not [string]::IsNullOrEmpty($AppName)) {
    try {
        Write-Verbose "Searching for app by name: '$AppName'"
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$AppName'&`$select=id,displayName,publisher,displayVersion"
        $appResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($appResponse.value.Count -eq 0) {
            Write-Error "No app found with name: $AppName"
            return
        }
        
        $app = $appResponse.value[0]
        Write-Verbose "Found app: $($app.displayName)"
        Get-AppRelationships -AppId $app.id -AppName $app.displayName
    }
    catch {
        Write-Error "Error finding app by name: $_"
        return
    }
}
else {
    try {
        Write-Verbose "Retrieving list of apps from Microsoft Graph for selection..."
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$select=id,displayName,publisher"
        $appsResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($appsResponse.value.Count -eq 0) {
            Write-Error "No apps found in the tenant."
            return
        }
        
        $appsForSelection = $appsResponse.value | ForEach-Object {
            [PSCustomObject]@{
                Id          = $_.id
                DisplayName = $_.displayName
                Publisher   = $_.publisher
            }
        }
        
        Write-Verbose "Displaying app selection grid view..."
        $selectedApp = $appsForSelection | Out-GridView -Title "Select an app to view complete relationship tree" -OutputMode Single
        
        if ($null -eq $selectedApp) {
            Write-Warning "No app selected. Operation cancelled."
            return
        }
        
        Write-Verbose "Selected app: $($selectedApp.DisplayName)"
        Get-AppRelationships -AppId $selectedApp.Id -AppName $selectedApp.DisplayName
    }
    catch {
        Write-Error "Error retrieving apps for selection: $_"
        return
    }
}

# Display the relationship tree
Write-Verbose "Generating relationship tree report..."

# Create a visual tree representation
function Format-RelationshipTree {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Tree,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )

    $totalAppsWithRelationships = @($Tree.Values | Where-Object { 
            $_.Dependencies.Count -gt 0 -or 
            $_.DependentApps.Count -gt 0 -or 
            $_.SupersededBy.Count -gt 0 -or 
            $_.Supersedes.Count -gt 0 
        }).Count

    $html =
    @"
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Intune App Relationship Tree</title>
    <style>
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

        .css-97v30w>.logoBtn {
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

        button {
            cursor: pointer;
            background-color: transparent;
            border: none;
            padding: 0px;
            font-family: inherit;
            color: inherit;
            line-height: inherit;
        }

        h1,
        h2 {
            color: #1BBC9B;
            font-weight: 500;
        }

        .summary {
            background-color: #252525;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        .highlight {
            color: #1BBC9B;
            font-weight: bold;
        }

        .app-card {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        .section-title {
            margin-top: 10px;
            font-weight: bold;
            color: #1BBC9B;
        }

        .item {
            padding: 5px 10px;
            margin: 5px 0;
            border-radius: 4px;
        }

        .item:nth-child(even) {
            background-color: #333333;
        }

        .item:nth-child(odd) {
            background-color: #2d2d2d;
        }

        .path,
        .depth {
            font-size: 0.9em;
            color: #bbb;
            margin-top: 5px;
        }

        .icon {
            vertical-align: middle;
            width: 20px;
            height: 20px;
            margin-right: 5px;
        }

        .sort-options {
        background-color: #252525;
        padding: 10px;
        border-radius: 8px;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        .sort-options label {
        cursor: pointer;
        margin-right: 15px;
        color: #1BBC9B;
        }
    
        .indent-level-0 { margin-left: 0px; }
        .indent-level-1 { margin-left: 25px; }
        .indent-level-2 { margin-left: 50px; }
        .indent-level-3 { margin-left: 75px; }
        .indent-level-4 { margin-left: 100px; }
    </style>
"@

    # Add logo
    $html += 
    @"
    <div class='css-97v30w'>
        <button type="button" class="logoBtn"><svg width="38" height="38" viewBox="0 0 38 38" fill="none"
                xmlns="http://www.w3.org/2000/svg" class="logo">
                <g clip-path="url(#clip0_1301_19104)">
                    <path
                        d="M1.235 24.852C1.007 24.776 0.836 24.605 0.76 24.377C0.266 22.629 0 20.824 0 19C0 16.758 0.38 14.592 1.14 12.502C1.767 10.754 2.679 9.10099 3.8 7.61899C3.933 7.42899 4.237 7.48599 4.294 7.73299C4.427 8.35999 4.617 9.17699 4.826 10.013C5.871 14.307 6.897 17.974 7.961 20.957C8.303 22.002 8.664 22.971 9.025 23.883C9.424 24.89 9.937 25.897 10.564 26.828C10.811 27.227 11.039 27.569 11.248 27.835C11.305 27.911 11.362 27.968 11.4 28.044L1.235 24.852Z"
                        fill="#0081C6"></path>
                    <path
                        d="M18.9999 38C18.2209 38 17.4609 37.943 16.7009 37.867C16.4729 37.848 16.3779 37.563 16.5489 37.392C17.7839 36.233 19.2089 34.941 19.8549 34.352C20.3109 33.991 20.7289 33.649 21.1659 33.326C21.9829 32.68 22.7429 32.072 23.4649 31.483C26.1819 29.241 28.1009 26.619 29.2409 23.674C29.6779 22.515 30.0959 21.223 30.4949 19.855C30.8939 21.736 32.1669 27.664 32.9459 31.483C32.9839 31.711 32.9269 31.939 32.7749 32.11C31.0649 33.896 29.0509 35.34 26.8089 36.347C24.3389 37.43 21.7359 38 18.9999 38Z"
                        fill="#0081C6"></path>
                    <path
                        d="M30.9512 18.031C31.5972 15.333 31.9962 12.977 32.1672 11.742L36.7652 13.167C36.9932 13.243 37.1642 13.414 37.2402 13.642C37.7532 15.371 38.0002 17.176 38.0002 18.981C38.0002 21.223 37.6202 23.389 36.8602 25.479C36.2332 27.246 35.3212 28.88 34.2002 30.381C34.0672 30.571 33.7632 30.514 33.7062 30.286L30.9512 18.031Z"
                        fill="#0081C6"></path>
                    <path
                        d="M31.1031 10.336L19.6461 4.90199L17.3091 5.79499L23.0091 0.550995C23.0851 0.493995 23.1611 0.455995 23.2561 0.493995C26.2771 1.19699 29.0891 2.622 31.4641 4.65499C33.6301 6.53599 35.3781 8.92999 36.4991 11.552C36.5941 11.761 36.3851 11.989 36.1571 11.932L31.1031 10.336Z"
                        fill="#0081C6"></path>
                    <path
                        d="M5.07312 6.536C5.01612 6.308 5.09212 6.061 5.24412 5.89C6.95412 4.104 8.94912 2.679 11.2101 1.653C13.6611 0.57 16.2831 0 19.0001 0C19.7791 0 20.5581 0.057 21.3181 0.152C21.5461 0.19 21.6411 0.475 21.4701 0.627L14.4211 7.087L6.04212 10.887L5.07312 6.536Z"
                        fill="#0081C6"></path>
                    <path
                        d="M15.0481 37.468C14.9911 37.525 14.8961 37.563 14.8011 37.544C11.7611 36.86 8.93012 35.397 6.57412 33.383C4.38912 31.483 2.66012 29.108 1.53912 26.467C1.44412 26.258 1.65312 26.03 1.88112 26.087L12.5401 29.431C15.0291 32.167 17.7461 33.649 18.6961 34.105L15.0481 37.468Z"
                        fill="#0081C6"></path>
                    <path
                        d="M25.6882 23.237V15.067C25.6882 14.915 25.5742 14.763 25.4792 14.744L25.1562 14.687C25.0992 14.668 25.0422 14.687 24.9852 14.744C24.8902 14.839 24.8142 14.953 24.7192 15.067C24.6432 15.162 24.7002 15.333 24.8332 15.352C24.9092 15.371 24.9852 15.447 24.9852 15.523V22.154C24.9852 22.249 24.9092 22.325 24.8142 22.325L14.1552 22.933C14.0602 22.933 13.9652 22.857 13.9652 22.762V13.908C13.9652 13.794 14.0602 13.718 14.1742 13.737L20.6532 14.706C20.7292 14.725 20.7862 14.687 20.8242 14.611C20.9002 14.478 20.9952 14.345 21.0712 14.193C21.1282 14.079 21.0712 13.946 20.9572 13.927L13.1102 12.597C12.7112 12.521 12.3882 12.901 12.3882 13.167V24.586C12.3882 24.795 12.5782 24.947 12.8252 24.928C12.8252 24.928 15.3902 24.7 18.3542 24.434C18.4682 24.415 18.5632 24.51 18.5442 24.624L18.4872 25.232C18.4872 25.308 18.4112 25.365 18.3352 25.384C17.4802 25.536 16.8722 25.783 16.8532 25.992C16.8532 26.334 18.5252 26.429 20.2922 26.201C21.7552 26.03 22.8002 25.688 22.8002 25.441C22.8002 25.251 22.1732 25.118 21.2422 25.099C21.1472 25.099 21.0712 25.023 21.0712 24.909L21.0902 24.339C21.0902 24.244 21.1662 24.187 21.2422 24.168C23.3512 23.978 25.2702 23.807 25.3272 23.807C25.7072 23.769 25.6882 23.256 25.6882 23.237Z"
                        class="secondary" fill="white"></path>
                    <path
                        d="M24.8901 10.165C22.2871 12.35 20.6531 15.675 19.5891 17.974C19.5511 18.069 19.4181 18.088 19.3421 18.012C18.8671 17.518 17.4231 16.036 17.0051 15.523C16.9481 15.447 16.8341 15.447 16.7771 15.523C16.4161 15.979 15.6751 16.872 15.2571 17.366C15.2001 17.423 15.2191 17.537 15.2761 17.575C16.3781 18.392 19.1141 20.805 20.1211 21.755C20.1971 21.831 20.3111 21.793 20.3491 21.698C22.4201 16.948 24.3581 14.269 26.8091 12.331C26.8851 12.274 26.8851 12.179 26.8281 12.122L25.0991 10.184C25.0421 10.127 24.9471 10.108 24.8901 10.165Z"
                        fill="#6DBA44"></path>
                </g>
                <defs>
                    <clipPath id="clip0_1301_19104">
                        <rect width="38" height="38" fill="white"></rect>
                    </clipPath>
                </defs>
            </svg><svg width="110" height="10" viewBox="0 0 110 10" fill="none" xmlns="http://www.w3.org/2000/svg"
                class="logo">
                <g clip-path="url(#clip0_1301_19123)">
                    <path
                        d="M58.2266 0H61.5999L64.4966 6.34333L67.5032 0H70.6566V9.46H68.1999V3.19L65.4132 9.46H63.4332L60.6466 3.19V9.46H58.2266V0Z"
                        fill="#0081C6"></path>
                    <path
                        d="M76.2299 6.01333L71.6832 0H74.7999L77.5499 3.77667L80.2999 0H83.1232L78.7966 6.01333V9.46H76.2666V6.01333H76.2299Z"
                        fill="#0081C6"></path>
                    <path
                        d="M90.2732 9.46H87.7432V0H93.9032C96.7999 0 97.6799 1.32 97.6799 3.15333V3.26333C97.6799 5.09667 96.7632 6.41667 93.9032 6.41667H90.2732V9.46ZM90.2732 4.36333H93.7199C94.6366 4.36333 95.0766 3.99667 95.0766 3.3V3.22667C95.0766 2.56667 94.6366 2.16333 93.7199 2.16333H90.2732V4.36333Z"
                        fill="#0081C6"></path>
                    <path
                        d="M104.317 9.46C100.173 9.46 98.9999 6.78333 98.9999 4.91333V4.54667C98.9999 2.64 100.173 0 104.317 0H104.867C108.68 0 110 1.87 110 3.59333V3.66667H107.36C107.323 3.41 106.993 2.09 104.573 2.09C102.337 2.09 101.64 3.33667 101.64 4.54667V4.69333C101.64 5.83 102.337 7.26 104.573 7.26C106.993 7.26 107.323 5.90333 107.36 5.68333H110V5.72C110 7.66333 108.533 9.46 104.317 9.46Z"
                        fill="#0081C6"></path>
                    <path
                        d="M2.53 6.41667V9.46H0V0H6.16C9.05667 0 9.93667 1.28333 9.93667 3.11667V3.22667C9.93667 5.06 9.02 6.34333 6.16 6.34333L2.53 6.41667ZM2.53 4.32667H6.01333C6.93 4.32667 7.37 3.96 7.37 3.3V3.19C7.37 2.53 6.93 2.16333 6.01333 2.16333H2.53V4.32667Z"
                        class="secondary" fill="white"></path>
                    <path
                        d="M17.71 7.7H12.7967L12.1 9.46H9.53333L13.6033 0H16.94L21.1933 9.46H18.4433L17.71 7.7ZM15.18 1.87L13.6033 5.68333H16.8667L15.18 1.87Z"
                        class="secondary" fill="white"></path>
                    <path
                        d="M23.43 2.16333H19.8733V0H29.37V2.16333H25.9233V9.46H23.3933C23.43 9.46 23.43 2.16333 23.43 2.16333Z"
                        class="secondary" fill="white"></path>
                    <path d="M42.57 0H45.1V3.48333H50.2333V0H52.7633V9.46H50.2333V5.64667H45.1367V9.46H42.6067L42.57 0Z"
                        class="secondary" fill="white"></path>
                    <path
                        d="M35.31 9.46C31.1667 9.46 29.9933 6.78333 29.9933 4.91333V4.54667C29.9933 2.64 31.1667 0 35.31 0H35.86C39.6733 0 40.9933 1.87 40.9933 3.59333V3.66667H38.3533C38.3167 3.41 37.9867 2.09 35.5667 2.09C33.33 2.09 32.6333 3.33667 32.6333 4.54667V4.69333C32.6333 5.83 33.33 7.26 35.5667 7.26C37.9867 7.26 38.3167 5.90333 38.3533 5.68333H40.9933V5.72C40.9933 7.66333 39.5267 9.46 35.31 9.46Z"
                        class="secondary" fill="white"></path>
                </g>
                <defs>
                    <clipPath id="clip0_1301_19123">
                        <rect width="110" height="9.46" fill="white"></rect>
                    </clipPath>
                </defs>
            </svg></button>
    </div>
</head>
<script>
document.addEventListener('DOMContentLoaded', () => {
    const sortRadios = document.querySelectorAll('input[name="sortOption"]');
    const appCards = document.querySelectorAll('.app-card');
    const appContainer = appCards[0].parentNode;

    function sortAndIndentCards() {
        const sortBy = document.querySelector('input[name="sortOption"]:checked').value;

        const cardsArray = Array.from(appCards);
        cardsArray.sort((a, b) => {
            const selector = sortBy === 'parent' ? '.parent-depth' : '.child-depth';
            const depthA = parseInt(a.querySelector(selector).textContent.replace(/\D/g, ''));
            const depthB = parseInt(b.querySelector(selector).textContent.replace(/\D/g, ''));
            return depthA - depthB;
        });

        cardsArray.forEach(card => {
            const selector = sortBy === 'parent' ? '.parent-depth' : '.child-depth';
            const depthValue = parseInt(card.querySelector(selector).textContent.replace(/\D/g, ''));
            const indentValue = depthValue * 25;
            card.style.marginLeft = `${indentValue}px`;
            appContainer.appendChild(card);
        });
    }

    sortRadios.forEach(radio => {
        radio.addEventListener('change', sortAndIndentCards);
    });

    sortAndIndentCards();
});
</script>
<body>
    <h1>Intune App Relationship Tree</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total apps with relationships: <span class="highlight">$totalAppsWithRelationships</span></p>
        <p>Report generated on: <span class="highlight">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span></p>
    </div>
"@

    $html += 
    @"
<div class="sort-options">
    <label><input type="radio" name="sortOption" value="parent" checked> Sort by Parent Depth</label>
    <label><input type="radio" name="sortOption" value="child"> Sort by Child Depth</label>
</div>
"@

    foreach ($app in $Tree.Values | Where-Object {
            $_.Dependencies.Count -gt 0 -or
            $_.DependentApps.Count -gt 0 -or
            $_.SupersededBy.Count -gt 0 -or
            $_.Supersedes.Count -gt 0 }) {

        $html += 
        @"
    <div class="app-card">
        <h2>📦 $($app.AppName)</h2>
        <div class="depth parent-depth">🟡 <strong>Parent Depth:</strong> $($app.ParentDepth)</div>
        <div class="depth child-depth">🔵 <strong>Child Depth:</strong> $($app.ChildDepth)</div>
        <div class="path">🔗 <strong>Paths:</strong> $(($app.RelationshipPaths -join '<br>'))</div>
"@

        if ($app.SupersededBy.Count -gt 0) {
            $html += "<div class='section-title'>⬅️ Superseded By:</div>"
            foreach ($item in $app.SupersededBy) {
                $html += "<div class='item'>🟢 $($item.DisplayName) $(if($item.Version){"v$($item.Version)"})
            $(if($item.Publisher){"by $($item.Publisher)"})</div>"
            }
        }

        if ($app.Supersedes.Count -gt 0) {
            $html += "<div class='section-title'>➡️ Supersedes:</div>"
            foreach ($item in $app.Supersedes) {
                $html += "<div class='item'>🟡 $($item.DisplayName) $(if($item.Version){"v$($item.Version)"})
            $(if($item.Publisher){"by $($item.Publisher)"})</div>"
            }
        }

        if ($app.Dependencies.Count -gt 0) {
            $html += "<div class='section-title'>🔗 Depends on:</div>"
            foreach ($item in $app.Dependencies) {
                $html += "<div class='item'>🔵 $($item.DisplayName) $(if($item.Version){"v$($item.Version)"}) $(if($item.Publisher){"by $($item.Publisher)"})</div>"
            }
        }
        
        if ($app.DependentApps.Count -gt 0) {
            $html += "<div class='section-title'>🔗 Dependency for:</div>"
            foreach ($item in $app.DependentApps) {
                $html += "<div class='item'>🟣 $($item.DisplayName) $(if($item.Version){"v$($item.Version)"}) $(if($item.Publisher){"by $($item.Publisher)"})</div>"
            }
        }        

        $html += "</div>"
    }

    $html += 
    @"
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Relationship tree report saved to: $OutputPath" -ForegroundColor Green
    Invoke-Item $OutputPath
}

# Generate the visual report
Format-RelationshipTree -Tree $relationshipTree -OutputPath $OutputPath

# Return the raw data as well
return $relationshipTree
