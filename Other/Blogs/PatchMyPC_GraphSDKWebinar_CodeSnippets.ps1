########################################################################################################
########################################################################################################
##   ______   ______   ______   ______    __  __        __    __    __  __        ______   ______     ##
##  /\  == \ /\  __ \ /\__  _\ /\  ___\  /\ \_\ \      /\ "-./  \  /\ \_\ \      /\  == \ /\  ___\    ##
##  \ \  _-/ \ \  __ \\/_/\ \/ \ \ \____ \ \  __ \     \ \ \-./\ \ \ \____ \     \ \  _-/ \ \ \____   ##
##   \ \_\    \ \_\ \_\  \ \_\  \ \_____\ \ \_\ \_\     \ \_\ \ \_\ \/\_____\     \ \_\    \ \_____\  ##
##    \/_/     \/_/\/_/    \/_/  \/_____/  \/_/\/_/      \/_/  \/_/  \/_____/      \/_/     \/_____/  ##
##                                                                                                    ##
########################################################################################################
################################  Microsoft Graph SDK and Graph API  ###################################
########################################################################################################

$kvName = 'kv-xxxxxx-xxxxx' #Enter Key Vault Name
$keyVaultURI = "https://$kvName.vault.azure.net/secrets/xxxxxxxxx/xxxxxxxxxxxxxxx?api-version=7.2"
$userObjectId = 'xxxxxxxxxxxx' #Entra ID Object ID of me@contoso.com
$clientId = 'xxxxxxxxxxxxxxxxxxx' #Entra Application (client) ID
$private:clientSecret = 'xxxXXXxxxXXXXxxxxxx' #Enter the client secret for the application
$tenantId = 'xxxxxxxxxxxxxxxxxxx' #Entra Directory (tenant) ID
$certFolder = 'C:\temp\certs' #Enter the folder path to store the certificate
$subjectName = 'PMPCWebinar-SDKCert' #Enter the subject name of the certificate

#region using_an_api
https://developer.microsoft.com/en-us/graph/graph-explorer 

#endregion
#region installing_the_sdk

<##
Graph SDK is large and modular
Over 6.5k commands. Only install the modules you need for your script
Required Modules (Still 835 commands *shock*)
##>

Install-Module (  `
                'Microsoft.Graph.Authentication', `
                'Microsoft.Graph.Users' `
)

#endregion
#region connect_mggraph_interactive

<##
By default, device InteractiveBrowserCredential is used (delegated)
If we don't specify an application (CliendId), we are connected via delegated access using Microsoft Graph SDK Enterprise Application (Microsoft Command Line Tools)
https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/5f4f7de6-ab64-4791-85c6-33f56a57f2e9/appId/14d82eec-204b-4c2f-b7e8-296a70dab67e
##>

Connect-MgGraph -Scopes ('User.Read', 'openid', 'profile', 'offline_access') # The default scopes applied if none specified

# View scopes and auth type using Get-MgContext
Get-MgContext

# Simple Test
Get-MgUser -UserId 'me@contoso.com'

#endregion
#region get_data_invalid_scope

# Lets try getting another user using those basic scopes
Get-MgUser -UserId 'myfriend@contoso.com'

# Simple 403 failures can indicate incorrect scopes. Check the Enterprise app permission or connect with the correct scope and grant permission interactively
# New delegated permissions defined by the scopes require user consent but the permissions are cumulative, previously granted permissions are not revoked
Disconnect-MgGraph
Connect-MgGraph -Scopes 'User.Read.All'
Get-MgUser -UserId 'myfriend@contoso.com'

#endregion
#region remove_scopes

# Revoke consent for a single user using Remove-MgServicePrincipalAppRoleAssignment or from My Apps in the Azure Portal
Install-Module (  `
                'Microsoft.Graph.Identity.SignIns', `
                'Microsoft.Graph.Applications', `
                'Microsoft.Graph.Authentication' `
)

Connect-MgGraph -Scopes ('Application.ReadWrite.All', 'Directory.ReadWrite.All')

#$applicationObjectId = '562d586e-414f-4e2d-a285-ef5009000d5c' # Graph Explorer
#$applicationObjectId = 'd4e32e09-f285-44c7-8ede-ad47ae3790bc' # PMPC Webinar
$applicationObjectId = '5f4f7de6-ab64-4791-85c6-33f56a57f2e9' # Microsoft Graph Command Line Tools

$sp = Get-MgServicePrincipal -ServicePrincipalId $applicationObjectId
$spOAuth2PermissionsGrants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id -All
$spOAuth2PermissionsGrants | Where-Object { $_.PrincipalId -eq $userObjectId } | ForEach-Object {
        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
}
$spApplicationPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
$spApplicationPermissions | Where-Object { $_.PrincipalId -eq $userObjectId } | ForEach-Object {
        Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.PrincipalId -AppRoleAssignmentId $_.Id
}

#endregion
#region connect_mggraph_devicecode

# By default, devicecode will use the same enteprise application, Microsoft Graph Command Line Tools (delegated)
# Useful in scenarios where there is no input device like IoT devices, TVs, etc
Disconnect-MgGraph
Connect-MgGraph -UseDeviceCode

# Prove we have authentiucated with DeviceCode flow
(Get-MgContext).TokenCredentialType

# Simple Test
Get-MgUser -UserId 'me@contoso.com'

#endregion
#region connect_mggraph_application_delegated

# Useful to use your own application registration for more control usiong Conditional Access and to avoid using the Microsoft Graph Command Line Tools Enterprise Application
# Define the application details

# App Registration requires the following RedirectUri's configured for delegated flow on your own app registration
# https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands?view=graph-powershell-1.0
# http://localhost

# Lets reconnect using a delegated permission
Disconnect-MgGraph
Connect-MgGraph -ClientId $clientId -TenantId $tenantId

#endregion
#region connect_mggraph_application_client_secret

# Define the application details
$clientSecretSecure = ConvertTo-SecureString -String $private:clientSecret -AsPlainText -Force

# Create a ClientCredential object
$clientCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecretSecure

# Lets reconnect using a delegated permission
Disconnect-MgGraph | Out-Null
Connect-MgGraph -ClientSecretCredential $clientCredential -TenantId $tenantId

# Default permissions as granted for the application permission
Get-MgContext

# Simple Test
# Will this work - will we be authorized?
Get-MgUser -UserId 'me@contoso.com'

#endregion
#region connect_mggraph_application_certificate

# Define the certificate details
$certStore = 'CurrentUser'
$validityPeriod = 12

$newCert = @{
        Subject           = "CN=$($subjectName)"
        CertStoreLocation = "Cert:\$($certStore)\My"
        KeyExportPolicy   = 'Exportable'    # Exportable not great security practice tbh, use NonExportable?
        KeySpec           = 'Signature'
        NotAfter          = (Get-Date).AddMonths($($validityPeriod))
}
$cert = New-SelfSignedCertificate @newCert

# Export public key only. Navigate to 'C:\temp\certs' to show .cer generated
# Upload the .cer to the app registration. Open link on line 3 of this script
$certExport = @{
        Cert     = $cert
        FilePath = "$($certFolder)\$($subjectName).cer"
}
Export-Certificate @certExport

$certPassword = Read-Host -Prompt 'Enter password for your certificate: ' -AsSecureString
$pfxExport = @{
        Cert         = "Cert:\$($certStore)\My\$($cert.Thumbprint)"
        FilePath     = "$($certFolder)\$($subjectName).pfx"
        ChainOption  = 'EndEntityCertOnly'
        NoProperties = $null
        Password     = $certPassword
}

Export-PfxCertificate @pfxExport

# Add the certificate to the App
# Lets reconnect using a certificate credential. We have options!
Disconnect-MgGraph | Out-Null
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -Certificate $cert
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $cert.Thumbprint
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateSubject $cert.Subject

# Default permissions as granted for the application permission
Get-MgContext

#endregion
#region automation_account_certificate

# Multiple ways to authenticate from an automation account. We can use credentials from a key vault, resources in the automation account or even the managed identity of the automation account
# We can use the certificate we uploaded to the automation account to authenticate to Graph

# Import the Microsoft Graph SDK Modules
# Modules > Add Module > Browse from Gallery > Microsoft.Graph.Authentication, Microsoft.Graph.Users (Choose the correct runtime that matches your runbook)
# rb-graphtest

$cert = Get-AutomationCertificate -Name 'PMPCWebinar-SDKCert'
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -Certificate $cert
Get-MgContext
Get-MgUser -UserId 'myfriend@contoso.com'
# Edit and view in test pane

#endregion
#region automation_account_kv

# Use certificate from a Key Vault to connect to Graph

Connect-AzAccount -Identity

$secret = Get-AzKeyVaultSecret -VaultName $kvName -Name 'PMPCWebinar-SDKCert' -AsPlainText
$secret64 = [Convert]::FromBase64String($secret)

$x509Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
$x509Cert.Import($secret64, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

Connect-MgGraph -ClientId $clientId -TenantId $tenantId -Certificate $x509Cert
Get-MgContext
Get-MgUser -UserId 'myfriend@contoso.com'

#endregion
#region useful_modules

Install-Module 'Microsoft.Graph.Devices.CorporateManagement'

# Add an application permission manually on our client to authorize us playing with Win32 apps 'DeviceManagementApps.ReadWrite.All'

#endregion
#region basic_device_app_management

Disconnect-MgGraph | Out-Null
$clientSecretSecure = ConvertTo-SecureString -String $private:clientSecret -AsPlainText -Force
$clientCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecretSecure
Connect-MgGraph -ClientSecretCredential $clientCredential -TenantId $tenantId
(Get-MgContext).Scopes

# Lets get some Win32 app information. We can use Filter, Sort and Where-Object

Get-MgDeviceAppManagementMobileApp | Measure-Object | Select-Object -ExpandProperty Count
Get-MgDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32LobApp'))" | Measure-Object | Select-Object -ExpandProperty Count
Get-MgDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32LobApp'))" -Sort "DisplayName" | Select-Object -First 10
Get-MgDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32LobApp'))" | Where-Object { $_.DisplayName -like '*Microsoft*' } | Select-Object DisplayName, CreatedDateTime
Get-MgDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32LobApp'))" | Where-Object { $_.DisplayName -like '*Microsoft*' } | Out-GridView -Title 'Microsoft Win32 Apps' -OutputMode Multiple | ForEach-Object { $_ }

#endregion
#region patch_app_management

# Lets update the DisplayName of the Win32 app called CMTrace
# Using the cmlets Get-MgDeviceAppManagementMobileApp and Update-MgDeviceAppManagementMobileApp
$app = Get-MgDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32LobApp'))" | Where-Object { $_.DisplayName -eq 'CMTrace' }
$app.DisplayName = 'PatchMyPC Webinar App t.a.f.k.a.CMTrace'
$jsonPayload = @{'@odata.type' = "#microsoft.graph.win32LobApp"; DisplayName = $app.DisplayName } | ConvertTo-Json -Depth 5
Update-MgDeviceAppManagementMobileApp -MobileAppId $app.Id -BodyParameter $jsonPayload

# Something a little more advanced where we would need to loop through some different PowerShell objects returned
$app = Get-MgDeviceAppManagementMobileApp -MobileAppId $app.Id
$returnCode = 0
$returnCodeAction = 'hardReboot'
$returnCodes = $app.AdditionalProperties.returnCodes

# Iterate through each hashtable of return codes
foreach ($item in $returnCodes) {
        if ($item.returnCode -eq $returnCode) {
                # Update the type of the return code
                $item.type = $returnCodeAction
        }
}

# Prepare the json payload with the proper structure
$jsonPayload = @{
        '@odata.type' = "#microsoft.graph.win32LobApp"
        'returnCodes' = $returnCodes
} | ConvertTo-Json -Depth 10

# Update the mobile app with the new return codes
Update-MgDeviceAppManagementMobileApp -MobileAppId $app.Id -BodyParameter $jsonPayload

#endregion
#region invoke_mggraphrequest

# If the Mg commands are a little intersting to navigate, we can use Invoke-MgGraphRequest to make direct calls to the Graph API
Disconnect-MgGraph | Out-Null
Connect-MgGraph -ClientId $clientId -TenantId $tenantId
Invoke-MgGraphRequest -Method 'GET' -Uri 'https://graph.microsoft.com/v1.0/me'

# Lets list those apps again using Invoke-MgGraphRequest
Disconnect-MgGraph | Out-Null
$clientSecretSecure = ConvertTo-SecureString -String $private:clientSecret -AsPlainText -Force
$clientCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecretSecure
Connect-MgGraph -ClientSecretCredential $clientCredential -TenantId $tenantId
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp'))&`$orderby=displayName"
$irmApp = Invoke-MgGraphRequest -Method 'GET' -Uri $uri
$irmApp.value | Measure-Object | Select-Object -ExpandProperty Count

# Does it contain the same number of apps as the Mg cmdlet we tried earlier?
Get-MgDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32LobApp'))" | Measure-Object | Select-Object -ExpandProperty Count

# The Mg cmdlet also returns ('microsoft.graph.win32CatalogApp') but the native REST method did not
$uri2 = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp') and not(isof('microsoft.graph.win32CatalogApp')))&`$orderby=displayName"
$irmApp2 = Invoke-MgGraphRequest -Method 'GET' -Uri $uri2
$irmApp2.value | Measure-Object | Select-Object -ExpandProperty Count

# Another Example of grabbing all Win32apps that begin “7-Zip” and were created after 1st August 2022
$uri3 = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp') and createdDateTime ge 2022-08-01) and startswith(displayName,'7-Zip') &`$orderby=displayName"
$irmApp3 = Invoke-MgGraphRequest -Method 'GET' -Uri $uri3

$irmApp3.value | ForEach-Object {
        [PSCustomObject]@{
            DisplayName     = $_['displayName']
            CreatedDateTime = $_['createdDateTime']
        }
    } | Select-Object displayName, createdDateTime
    

# Get a Win32 app icon
$uri4 = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(displayName eq '4K Video Downloader 4.31.0.91')"
$payload = Invoke-MgGraphRequest -Method 'GET' -Uri $uri4
$uri5 = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($payload.value.id)"
$payload = Invoke-MgGraphRequest -Method 'GET' -Uri $uri5
$image = "$($env:temp)\$($payload.displayName).png"
[byte[]]$Bytes = [convert]::FromBase64String(($payload.largeIcon.value))
[System.IO.File]::WriteAllBytes($image, $Bytes)
Start-Process $image

# Pagination can still be leveraged using Invoke-MgGraphRequest. We only have a few apps so all results are returned in one page
$uri6 = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/?`$filter=(isof('microsoft.graph.win32LobApp'))"
$payload = Invoke-MgGraphRequest -Method 'GET' -Uri $uri6
$payload.value.Count

# Count the results by seeing how many pages are returned by iterating over the odata.nextLink property when choosing to show only a few results per page
$resultsPerPage = 10
$totalResults = 0
$pageCount = 0
$uri7 = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/?`$filter=(isof('microsoft.graph.win32LobApp'))&`$top=$resultsPerPage"
Invoke-MgGraphRequest -Method Get -Uri $uri7 # Observe the @odata.nextLink property

# Lets loop through the pages and count the results and pages
do {
        # Fetch the data from Microsoft Graph
        $response = Invoke-MgGraphRequest -Method Get -Uri $uri7
        $currentPageCount = $response.value.Count
        $totalResults += $currentPageCount
        $pageCount++

        if (-not [string]::IsNullOrWhiteSpace($response.'@odata.nextLink')) {
                $uri7 = $response.'@odata.nextLink'
                Write-Host $response.'@odata.nextLink' -ForegroundColor Cyan
        }
        else {
                $uri7 = $null
        }
} while (-not [string]::IsNullOrWhiteSpace($uri7))

Write-Output "Total number of results: $totalResults"
Write-Output "Results per page: $resultsPerPage"
Write-Output "Total number of pages: $pageCount"

#endregion
#region managed_identity_test

#Grab a token using the Azure Instance Metadata service endpoint
$splat = @{
        Uri     = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://vault.azure.net'
        Headers = @{Metadata = 'true' }
    }
    $response = Invoke-WebRequest @splat
    $content = $response.Content | ConvertFrom-Json
    $accessToken = $content.access_token

    $headers = @{ Authorization = "Bearer $accessToken" }
    $secret = Invoke-MgGraphRequest -Method Get -Headers $headers -Uri $keyVaultURI 
    Write-Host $secret.value -ForegroundColor Cyan -BackgroundColor yellow

#endregion
#region irm
#You can still get tokens without using MSAL.PS. If you dont like the SDK, go native

$uri8 = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

$authN = @{
    client_id     = $clientId
    client_secret = $private:clientSecret
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
}
Invoke-RestMethod -Method Post -Uri $uri8 -ContentType "application/x-www-form-urlencoded" -Body $authN

#endregion