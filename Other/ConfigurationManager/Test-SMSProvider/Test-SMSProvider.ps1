<#
.SYNOPSIS
This script connects to a specified site server and retrieves the first 10 applications.

.DESCRIPTION
The script uses WMI to connect to the SMS provider on the specified site server and retrieves the first 10 applications.
Make sure to run this script with an account that has sufficient permissions to connect to the SMS provider and read applications from the SMS_Application class.

.NOTES
FileName:    Test-SMSProvider.ps1
Author:      Ben Whitmore @ PatchMyPC

.PARAMETER SiteServer
The FQDN of the site server to connect to

.PARAMETER SiteCode
The site code for the Configuration Manager site

.PARAMETER AppSampleSize
The number of applications to retrieve from the SMS_Application class. The default value is 10

.EXAMPLE
.\Test-SMSProvider.ps1 -SiteServer 'bb-cm1.byteben.com' -SiteCode 'bb1' -AppSampleSize 20
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SiteServer,

    [Parameter(Mandatory = $true)]
    [string]$SiteCode,

    [Parameter(Mandatory = $false)]
    [string]$AppSampleSize = 10
)

# Create a new COM object for WMI scripting
$swbemLocator = New-Object -ComObject wbemscripting.swbemlocator

# Set the authentication level for WMI connections
$swbemLocator.Security_.AuthenticationLevel = 6

try {

    # Connect to the SMS provider on the specified site server
    $service = $swbemLocator.ConnectServer("$SiteServer", "root\sms\site_$SiteCode", $null, $null)
    Write-Host ("Connected to the SMS provider on '{0}'" -f $SiteServer) -ForegroundColor Cyan

}
catch {
    Write-Host ("Failed to connect to the SMS provider on '{0}'" -f $SiteServer) -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    break
}

try {

    # Execute a WMI query to get the first x applications according to the sample size specified
    $apps = $service.ExecQuery("Select * From SMS_Application") | Select-Object -First $AppSampleSize

    # Determine if the sample size is 1 or more to format the output
    $AppOrApps = if ($AppSampleSize -eq 1) { 'app' } else { 'apps' }
    Write-Host ("Querying the SMS_Application class on '{0}' for the first '{1} {2}'" -f $SiteServer, $AppSampleSize, $apporApps ) -ForegroundColor Cyan

    # Loop through each application
    foreach ($app in $apps) { 

        # Get the localized display name of the application
        $app.properties_ | where-object { $_.Name -eq 'LocalizedDisplayName' } | Select-Object -ExpandProperty Value
    }
}
catch {
    Write-Host ("Failed to execute WMI query to retrieve applications from the SMS_Application class on siteserver '{0}'" -f $SiteServer) -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
} 

# Release the COM object to free up resources
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($service) | Out-Null