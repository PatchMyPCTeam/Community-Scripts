

Connect-MGGraph
$allapps = Get-MgDeviceAppManagementMobileApp -All # | Out-GridView
$body = @{
    "@odata.type"             = "#microsoft.graph.win32LobApp"
    "allowAvailableUninstall" = $true
}
$app = ($allapps[20]).Id
foreach ($app in $allapps) {
    $appid = $app.id
    $graphApiVersion = "beta"
    $DMS_resource = "deviceAppManagement/mobileApps/$appid"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$DMS_resource"
    Write-Host "Enabling Uninstall for: " $app.DisplayName
    #Update-MgBetaDeviceAppManagementMobileApp -MobileAppId $app.Id -AdditionalProperties ($body)
    Invoke-MgGraphRequest -Uri $uri -Method Patch -ContentType "application/json" -Body ($body | ConvertTo-Json) -Verbose
}