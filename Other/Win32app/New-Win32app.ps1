
#Requires -Modules Microsoft.Graph.Authentication, Az.Storage

<#
.Synopsis
Creates a test Win32 app in Intune using the Graph SDK PowerShell module.

Created on:   21/04/2026
Created by:   Ben Whitmore@PatchMyPC
Filename:     New-Win32app.ps1

.Description
- Creates a test Win32 app in Intune using the Graph SDK PowerShell module. Downloads the Win32 Content Prep Tool, builds a small .intunewin from a test payload, then uploads and commits to Intune via Graph SDK.
- Requires Microsoft.Graph.Authentication, Az.Storage PowerShell modules. 
- Logs to console and CMTrace-compatible, log file in TEMP folder. Designed for testing and validation of Win32 app deployment in Intune.
- Client app used for authentication must have DeviceManagementApps.ReadWrite.All Graph API permission.

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.Notes
- This script is intended for testing and validation purposes only. The created app is a generic test
- You must provide your Entra ID App Registration details for $tenantId, $clientId, and $clientSecret below before running this script.
#>

param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$tenantId,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$clientId,
    [Parameter(Mandatory)]
    [string]$clientSecret,
    [string]$appName = "!Test App",
    [string]$appVersion = "1.0.0",
    [string]$appPublisher = "Generic",
    [string]$appDescription = "Generic test application used for Intune Win32 app creation validation."
)

#region LOG
$logDateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logPath = Join-Path $env:TEMP ("New-Win32app-{0}.log" -f $logDateTime)
 
function Write-CMTraceLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
 
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
 
        [Parameter(Mandatory = $false)]
        [string]$Component = "New-Win32app"
    )
 
    $timeStamp = Get-Date -Format "HH:mm:ss.fff"
    $dateStamp = Get-Date -Format "MM-dd-yyyy"
    $logEntry = '<![LOG[{0}]LOG]!><time="{1}+000" date="{2}" component="{3}" context="" type="{4}" thread="" file="">' -f $Message, $timeStamp, $dateStamp, $Component, $Severity
 
    Add-Content -Path $logPath -Value $logEntry -Encoding UTF8
}
 
function Write-LogAndHost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
 
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
 
        [Parameter(Mandatory = $false)]
        [string]$Component = "New-Win32app",
 
        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor = "White"
    )
 
    switch ($Severity) {
        2 { $ForegroundColor = "Yellow" }
        3 { $ForegroundColor = "Red" }
    }
 
    Write-Host $Message -ForegroundColor $ForegroundColor
    Write-CMTraceLog -Message $Message -Severity $Severity -Component $Component
}
 
function Get-GraphErrorDetail {
    <#
    .Description
    Extracts the full error detail from a failed Invoke-MgGraphRequest call.
    $_.Exception.Message only returns the HTTP status line. The actual Graph error
    code, message and request ID are in $_.ErrorDetails.Message as JSON.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
 
    $detail = [ordered]@{
        ExceptionMessage = $ErrorRecord.Exception.Message
        GraphErrorCode   = $null
        GraphMessage     = $null
        RequestId        = $null
        RawErrorBody     = $null
    }
 
    if ($ErrorRecord.ErrorDetails.Message) {
        $detail.RawErrorBody = $ErrorRecord.ErrorDetails.Message
 
        try {
            $parsed = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
 
            if ($parsed.error) {
                $detail.GraphErrorCode = $parsed.error.code
                $detail.GraphMessage = $parsed.error.message
                $detail.RequestId = $parsed.error.innerError.'request-id'
            }
        }
        catch {
            # JSON parse failed - RawErrorBody already captured above
        }
    }
 
    return $detail
}
 
#endregion
 
Write-LogAndHost -Message ("Log started: {0}" -f $logPath) -ForegroundColor Cyan
 
#region MODULES
foreach ($module in @('Microsoft.Graph.Authentication', 'Az.Storage')) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-LogAndHost -Message ("Module '{0}' not found. Installing..." -f $module) -Severity 2
        Install-Module $module -Force -Scope CurrentUser
    }
    Import-Module $module -Force
    Write-LogAndHost -Message ("Module '{0}' loaded" -f $module) -ForegroundColor Cyan
}
 
#endregion
 
#region WORKING FOLDERS
$workingFolder = Join-Path $env:TEMP "PatchMyPC_TestApp"
$contentFolder = Join-Path $workingFolder "Content"
$outputFolder = Join-Path $workingFolder "Output"
$toolFolder = Join-Path $workingFolder "ContentPrepTool"
 
foreach ($folder in @($workingFolder, $contentFolder, $outputFolder, $toolFolder)) {
    if (Test-Path $folder) {
        Remove-Item $folder -Recurse -Force
    }
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}
 
Write-LogAndHost -Message ("Working folder: '{0}'" -f $workingFolder) -ForegroundColor Cyan
 
#endregion
 
# Tracks which step we are in so the catch block can report exactly where it failed
$currentStep = "Initialise"
 
try {
 
    #region 1. DOWNLOAD WIN32 CONTENT PREP TOOL
    $currentStep = "Download Win32 Content Prep Tool"
    $toolPath = Join-Path $toolFolder "IntuneWinAppUtil.exe"
 
    Write-LogAndHost -Message ("Downloading Win32 Content Prep Tool from '{0}'" -f $contentPrepToolUrl) -ForegroundColor Cyan
 
    Invoke-WebRequest -Uri $contentPrepToolUrl -OutFile $toolPath -UseBasicParsing
 
    if (-not (Test-Path $toolPath)) {
        throw ("Win32 Content Prep Tool download failed. File not found at '{0}'" -f $toolPath)
    }
 
    Write-LogAndHost -Message ("Win32 Content Prep Tool downloaded to '{0}'" -f $toolPath) -ForegroundColor Green
 
    #endregion
 
    #region 2. CREATE TEST APP PAYLOAD
    $currentStep = "Create test app payload"
 
    $readmePath = Join-Path $contentFolder "readme.txt"
    $readmeContent = @"
Patch My PC Test App v{0}
Publisher  : {1}
Created    : {2}
Description: {3}
 
This is a generic test application used to validate Win32 app deployment in Intune.
It does not install any software. The install script writes a registry key that acts
as the detection method. The uninstall script removes it.
"@ -f $appVersion, $appPublisher, (Get-Date -Format "yyyy-MM-dd"), $appDescription
 
    [System.IO.File]::WriteAllText($readmePath, $readmeContent, [System.Text.Encoding]::UTF8)
    Write-LogAndHost -Message ("Created readme.txt at '{0}'" -f $readmePath) -ForegroundColor Cyan
 
    $installCmdPath = Join-Path $contentFolder "install.cmd"
    $installCmd = "@echo off`r`nreg add ""HKLM\SOFTWARE\PatchMyPC\TestApp"" /v ""Version"" /t REG_SZ /d ""{0}"" /f`r`nreg add ""HKLM\SOFTWARE\PatchMyPC\TestApp"" /v ""Publisher"" /t REG_SZ /d ""{1}"" /f`r`nreg add ""HKLM\SOFTWARE\PatchMyPC\TestApp"" /v ""InstalledDate"" /t REG_SZ /d ""%DATE%"" /f`r`nexit 0" -f $appVersion, $appPublisher
 
    [System.IO.File]::WriteAllText($installCmdPath, $installCmd, [System.Text.Encoding]::ASCII)
    Write-LogAndHost -Message ("Created install.cmd at '{0}'" -f $installCmdPath) -ForegroundColor Cyan
 
    $uninstallCmdPath = Join-Path $contentFolder "uninstall.cmd"
    $uninstallCmd = "@echo off`r`nreg delete ""HKLM\SOFTWARE\PatchMyPC\TestApp"" /f`r`nexit 0"
 
    [System.IO.File]::WriteAllText($uninstallCmdPath, $uninstallCmd, [System.Text.Encoding]::ASCII)
    Write-LogAndHost -Message ("Created uninstall.cmd at '{0}'" -f $uninstallCmdPath) -ForegroundColor Cyan
 
    #endregion
 
    #region 3. BUILD .intunewin
    $currentStep = "Build .intunewin"
 
    Write-LogAndHost -Message "Building .intunewin file..." -ForegroundColor Cyan
 
    $arguments = @('-s', ('"{0}"' -f $installCmdPath), '-c', ('"{0}"' -f $contentFolder), '-o', ('"{0}"' -f $outputFolder), '-q')
 
    Write-LogAndHost -Message ("Running: '{0} {1}'" -f $toolPath, ($arguments -join ' ')) -ForegroundColor Cyan
 
    $process = Start-Process -FilePath $toolPath -ArgumentList $arguments -Wait -PassThru
 
    if ($process.ExitCode -ne 0) {
        throw ("IntuneWinAppUtil.exe exited with code {0}" -f $process.ExitCode)
    }
 
    $intuneWinFile = Get-ChildItem $outputFolder -Filter "*.intunewin" | Select-Object -First 1
 
    if (-not $intuneWinFile) {
        throw ("No .intunewin file found in '{0}' after running the content prep tool" -f $outputFolder)
    }
 
    $intuneWinPath = $intuneWinFile.FullName
    Write-LogAndHost -Message ("Built .intunewin: '{0}'" -f $intuneWinPath) -ForegroundColor Green
 
    #endregion
 
    #region 4. EXTRACT .intunewin METADATA
    $currentStep = "Extract .intunewin metadata"
 
    Write-LogAndHost -Message "Extracting .intunewin metadata..." -ForegroundColor Cyan
 
    Add-Type -AssemblyName System.IO.Compression.FileSystem
 
    $extractPath = Join-Path $workingFolder "Extract"
 
    if (Test-Path $extractPath) {
        Remove-Item $extractPath -Recurse -Force
    }
 
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($intuneWinPath, $extractPath)
 
    $metaXml = [xml](Get-Content (Join-Path $extractPath "IntuneWinPackage\Metadata\Detection.xml"))
    $encryptedFilePath = Get-ChildItem (Join-Path $extractPath "IntuneWinPackage\Contents") | Select-Object -First 1 -ExpandProperty FullName
    $sizeEncrypted = (Get-Item $encryptedFilePath).Length
    $sizeUnencrypted = [int64]$metaXml.ApplicationInfo.UnencryptedContentSize
 
    Write-LogAndHost -Message ("Metadata extracted. Encrypted: {0} bytes, Unencrypted: {1} bytes" -f $sizeEncrypted, $sizeUnencrypted) -ForegroundColor Green
 
    $encryptionInfo = @{
        encryptionKey        = $metaXml.ApplicationInfo.EncryptionInfo.EncryptionKey
        macKey               = $metaXml.ApplicationInfo.EncryptionInfo.MacKey
        initializationVector = $metaXml.ApplicationInfo.EncryptionInfo.InitializationVector
        mac                  = $metaXml.ApplicationInfo.EncryptionInfo.Mac
        profileIdentifier    = "ProfileVersion1"
        fileDigest           = $metaXml.ApplicationInfo.EncryptionInfo.FileDigest
        fileDigestAlgorithm  = $metaXml.ApplicationInfo.EncryptionInfo.FileDigestAlgorithm
    }
 
    Write-LogAndHost -Message ("Encryption info parsed. Algorithm: '{0}'" -f $encryptionInfo.fileDigestAlgorithm) -ForegroundColor Cyan
 
    #endregion
 
    #region 5. CONNECT TO GRAPH
    $currentStep = "Connect to Microsoft Graph"
    if ([string]::IsNullOrWhiteSpace($clientSecret)) {
        throw "clientSecret is empty. Provide a valid client secret."
    }
    # Disconnect any existing cached session
    Write-LogAndHost -Message "Disconnecting any existing Graph session..." -ForegroundColor Cyan
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
 
    Write-LogAndHost -Message "Connecting to Microsoft Graph..." -ForegroundColor Cyan
 
    $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)
 
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential -NoWelcome
    Write-LogAndHost -Message "Connected to Microsoft Graph" -ForegroundColor Green
 
    #endregion
 
    #region 6. CREATE APP RECORD
    $currentStep = "Create app record"
 
    Write-LogAndHost -Message ("Creating app record for '{0}'..." -f $appName) -ForegroundColor Cyan
 
    $detectionScript = 'if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\PatchMyPC\TestApp" -Name "Version" -ErrorAction SilentlyContinue).Version -eq "{0}") {{ Write-Output "Detected" }}' -f $appVersion
 
    $appBody = [ordered]@{
        "@odata.type"                   = "#microsoft.graph.win32LobApp"
        displayName                     = $appName
        description                     = $appDescription
        publisher                       = $appPublisher
        displayVersion                  = $appVersion
        informationUrl                  = "https://learn.microsoft.com/en-us/graph/api/intune-apps-win32lobapp-create"
        notes                           = "Generic test app - safe to delete"
        fileName                        = $intuneWinFile.Name
        setupFilePath                   = "install.cmd"
        installCommandLine              = "install.cmd"
        uninstallCommandLine            = "uninstall.cmd"
        minimumSupportedWindowsRelease  = "1607"
        allowedArchitectures            = "x64,arm64"
        minimumFreeDiskSpaceInMB        = 1
        installExperience               = @{
            "@odata.type"         = "#microsoft.graph.win32LobAppInstallExperience"
            runAsAccount          = "system"
            maxRunTimeInMinutes   = 15
            deviceRestartBehavior = "suppress"
        }
        returnCodes                     = @(
            @{ returnCode = 0; type = "success" }
            @{ returnCode = 1707; type = "success" }
            @{ returnCode = 3010; type = "softReboot" }
            @{ returnCode = 1641; type = "hardReboot" }
            @{ returnCode = 1618; type = "retry" }
        )
        rules                           = @(
            @{
                "@odata.type"         = "#microsoft.graph.win32LobAppPowerShellScriptRule"
                ruleType              = "detection"
                enforceSignatureCheck = $false
                runAs32Bit            = $false
                scriptContent         = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($detectionScript))
            }
        )
        minimumSupportedOperatingSystem = @{ v10_1607 = $true }
    } | ConvertTo-Json -Depth 10 -Compress
 
    $app = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Body $appBody -ContentType "application/json"
    $appId = $app.id
 
    Write-LogAndHost -Message ("App record created. App ID: '{0}'" -f $appId) -ForegroundColor Green
 
    #endregion
 
    #region 7. CREATE CONTENT VERSION
    $currentStep = "Create content version"
 
    Write-LogAndHost -Message ("Creating content version for app '{0}'..." -f $appId) -ForegroundColor Cyan
 
    $contentVersion = Invoke-MgGraphRequest -Method POST -Uri ("https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions" -f $appId) -Body "{}" -ContentType "application/json"
    $contentVersionId = $contentVersion.id
 
    Write-LogAndHost -Message ("Content version created. Version ID: '{0}'" -f $contentVersionId) -ForegroundColor Green
 
    #endregion
 
    #region 8. CREATE FILE ENTRY
    $currentStep = "Create file entry"
 
    Write-LogAndHost -Message "Creating file entry..." -ForegroundColor Cyan
 
    $fileBody = [ordered]@{
        "@odata.type" = "#microsoft.graph.mobileAppContentFile"
        name          = $metaXml.ApplicationInfo.FileName
        size          = $sizeUnencrypted
        sizeEncrypted = $sizeEncrypted
        isDependency  = $false
        manifest      = $null
    } | ConvertTo-Json -Compress
 
    $fileEntry = Invoke-MgGraphRequest -Method POST -Uri ("https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/files" -f $appId, $contentVersionId) -Body $fileBody -ContentType "application/json"
    $fileId = $fileEntry.id
    $fileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/files/{2}" -f $appId, $contentVersionId, $fileId
 
    Write-LogAndHost -Message ("File entry created. File ID: '{0}'" -f $fileId) -ForegroundColor Green
 
    #endregion
 
    #region 9. POLL FOR SAS URI
    $currentStep = "Poll for SAS URI"
 
    Write-LogAndHost -Message "Polling for SAS URI..." -ForegroundColor Cyan
 
    $attempt = 0
 
    do {
        Start-Sleep -Seconds 3
        $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $fileUri
        $attempt++
        Write-LogAndHost -Message ("SAS URI poll attempt {0}/{1}. State: '{2}'" -f $attempt, $maxRetries, $fileStatus.uploadState) -ForegroundColor Cyan
    } until ($fileStatus.uploadState -eq 'azureStorageUriRequestSuccess' -or $attempt -ge $maxRetries)
 
    if ($fileStatus.uploadState -ne 'azureStorageUriRequestSuccess') {
        throw ("Failed to get SAS URI after {0} attempts. Final state: '{1}'" -f $maxRetries, $fileStatus.uploadState)
    }
 
    $sasUri = [System.Uri]::new($fileStatus.azureStorageUri)
    Write-LogAndHost -Message "SAS URI obtained successfully" -ForegroundColor Green
 
    #endregion
 
    #region 10. UPLOAD VIA CloudBlockBlob
    $currentStep = "Upload to Azure Blob Storage"
 
    $container = $sasUri.AbsolutePath.Split('/')[1]
    $blobPath = $sasUri.AbsolutePath.Substring($container.Length + 2)
    $blockSize = 4 * 1024 * 1024
    $totalBlocks = [Math]::Ceiling($sizeEncrypted / $blockSize)
 
    Write-LogAndHost -Message ("Starting upload. Container: '{0}', Blob: '{1}', Blocks: {2}" -f $container, $blobPath, $totalBlocks) -ForegroundColor Cyan
 
    $fileStream = [System.IO.File]::OpenRead($encryptedFilePath)
    $buffer = New-Object Byte[] $blockSize
    $blockIds = New-Object 'System.Collections.Generic.List[System.String]'
    $blobClient = [Microsoft.Azure.Storage.Blob.CloudBlockBlob]::new($sasUri)
 
    try {
        $i = 0
        while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $encodedBlockId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Guid]::NewGuid().ToString()))
            $blockIds.Add($encodedBlockId)
 
            $memStream = New-Object System.IO.MemoryStream
            $memStream.Write($buffer, 0, $bytesRead)
            $memStream.Position = 0
 
            $blobClient.PutBlock($encodedBlockId, $memStream, $null)
            $memStream.Dispose()
 
            $i++
            Write-LogAndHost -Message ("Uploaded block {0} of {1}" -f $i, $totalBlocks) -ForegroundColor Cyan
        }
 
        $blobClient.PutBlockList($blockIds)
        Write-LogAndHost -Message "All blocks committed to Azure Storage successfully" -ForegroundColor Green
    }
    finally {
        $fileStream.Dispose()
    }
 
    #endregion
 
    #region 11. VERIFY UPLOAD STATE BEFORE COMMIT
    $currentStep = "Verify upload state"
 
    Write-LogAndHost -Message "Verifying upload state before committing..." -ForegroundColor Cyan
 
    $attempt = 0
 
    do {
        Start-Sleep -Seconds 3
        $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $fileUri
        $attempt++
        Write-LogAndHost -Message ("Upload state verification attempt {0}/{1}. State: '{2}'" -f $attempt, $maxRetries, $fileStatus.uploadState) -ForegroundColor Cyan
    } until ($fileStatus.uploadState -eq 'azureStorageUriRequestSuccess' -or $attempt -ge $maxRetries)
 
    if ($fileStatus.uploadState -ne 'azureStorageUriRequestSuccess') {
        throw ("Upload state check failed before commit after {0} attempts. Final state: '{1}'" -f $maxRetries, $fileStatus.uploadState)
    }
 
    Write-LogAndHost -Message ("Upload state confirmed '{0}'. Safe to commit" -f $fileStatus.uploadState) -ForegroundColor Green
 
    #endregion
 
    #region 12. COMMIT THE FILE
    $currentStep = "Commit file"
 
    Write-LogAndHost -Message "Committing file content to Intune..." -ForegroundColor Cyan
 
    $commitBody = @{ fileEncryptionInfo = $encryptionInfo } | ConvertTo-Json -Depth 5 -Compress
 
    Invoke-MgGraphRequest -Method POST -Uri ("{0}/commit" -f $fileUri) -Body $commitBody -ContentType "application/json"
    Write-LogAndHost -Message "Commit request sent successfully" -ForegroundColor Green
 
    #endregion
 
    #region 13. POLL FOR commitFileSuccess
    $currentStep = "Poll for commit completion"
 
    Write-LogAndHost -Message "Polling for commit completion..." -ForegroundColor Cyan
 
    $attempt = 0
    $success = $false
 
    do {
        Start-Sleep -Seconds 5
        $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $fileUri
        $attempt++
 
        if ($fileStatus.uploadState -eq 'commitFileSuccess') {
            $success = $true
            Write-LogAndHost -Message ("Commit successful. State: '{0}'" -f $fileStatus.uploadState) -ForegroundColor Green
        }
        elseif ($fileStatus.uploadState -eq 'commitFileFailed') {
            throw ("Commit failed after {0} attempts. State: '{1}'" -f $attempt, $fileStatus.uploadState)
        }
        else {
            Write-LogAndHost -Message ("Commit poll attempt {0}/{1}. State: '{2}'" -f $attempt, $maxRetries, $fileStatus.uploadState) -Severity 2
        }
    } until ($success -or $attempt -ge $maxRetries)
 
    if (-not $success) {
        throw ("Commit did not complete within {0} attempts. Final state: '{1}'" -f $maxRetries, $fileStatus.uploadState)
    }
 
    #endregion
 
    #region 14. PATCH APP WITH COMMITTED CONTENT VERSION
    $currentStep = "Patch app with committed content version"
 
    Write-LogAndHost -Message ("Updating app '{0}' with committed content version '{1}'..." -f $appId, $contentVersionId) -ForegroundColor Cyan
 
    $patchBody = @{
        "@odata.type"           = "#microsoft.graph.win32LobApp"
        committedContentVersion = $contentVersionId
    } | ConvertTo-Json -Compress
 
    Invoke-MgGraphRequest -Method PATCH -Uri ("https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}" -f $appId) -Body $patchBody -ContentType "application/json"
 
    Write-LogAndHost -Message "Win32 app creation complete" -ForegroundColor Green
    Write-LogAndHost -Message ("App Name : {0}" -f $appName) -ForegroundColor Green
    Write-LogAndHost -Message ("App ID   : {0}" -f $appId) -ForegroundColor Green
    Write-LogAndHost -Message ("Version  : {0}" -f $appVersion) -ForegroundColor Green
    Write-LogAndHost -Message ("Log file : {0}" -f $logPath) -ForegroundColor Green
    Write-LogAndHost -Message ("Intune Admin Center Link : https://intune.microsoft.com/#view/Microsoft_Intune_Apps/SettingsMenu/~/0/appId/{0}" -f $appId) -ForegroundColor Green
 
    #endregion
}
catch {

    Write-LogAndHost -Message ("Script failed at step: '{0}'" -f $currentStep) -Severity 3
    $graphError = Get-GraphErrorDetail -ErrorRecord $_

    Write-LogAndHost -Message ("Exception     : {0}" -f $graphError.ExceptionMessage) -Severity 3
 
    if ($graphError.GraphErrorCode) {
        Write-LogAndHost -Message ("Graph code    : {0}" -f $graphError.GraphErrorCode) -Severity 3
    }
 
    if ($graphError.GraphMessage) {
        Write-LogAndHost -Message ("Graph message : {0}" -f $graphError.GraphMessage) -Severity 3
    }
 
    if ($graphError.RequestId) {
        Write-LogAndHost -Message ("Request ID    : {0}" -f $graphError.RequestId) -Severity 3
    }
 
    if ($graphError.RawErrorBody -and -not $graphError.GraphErrorCode) {
        Write-LogAndHost -Message ("Raw error body: {0}" -f $graphError.RawErrorBody) -Severity 3
    }
 
    Write-LogAndHost -Message ("Log file      : {0}" -f $logPath) -Severity 3
 
    throw
}
finally {
    if (Test-Path $workingFolder) {
        Remove-Item $workingFolder -Recurse -Force
        Write-LogAndHost -Message ("Working folder '{0}' removed" -f $workingFolder) -ForegroundColor Cyan
    }
}