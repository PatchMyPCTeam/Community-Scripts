<#
.Synopsis
Created on:   07/09/2025
Updated on:   12/09/2025
Created by:   Ben Whitmore@PatchMyPC
Filename:     Invoke-M365AppsHelper.ps1

The script dynamically parses Office configuration XML files, downloads the required setup files, and creates deployment-ready packages.

.Description
This script automates the process of creating Microsoft 365 Office deployment packages by:
- Dynamically parsing Office configuration XML files without hardcoded property dependencies
- Downloading Office setup files and creating organized deployment packages
- Supporting flexible output formats including optional zip packaging with supporting PreScript 
- Validating parsed Office versions against Microsoft's REST API

VERSION VALIDATION:
When the parsed XML contains an Office version, the script performs version validation by querying Microsoft's Office REST API. This validation is essential because:
- Office versions are used for application detection rules in deployment systems (ConfigMgr, Intune, etc.)
- Invalid versions cause deployment failures
- Version availability varies by channel and changes frequently
- Proper validation prevents downloading non-existent Office builds

If no version is specified in the XML configuration, the script automatically retrieves and uses the latest available version for the specified channel.

The script implements an intelligent retry mechanism because Microsoft's Office version API:
- May return partial results on first attempt due to load balancing
- Can experience temporary network issues or rate limiting
- Sometimes provides incomplete channel data that requires re-querying
- Benefits from multiple attempts to ensure complete version information

.NOTES
PowerShell 5.1 or later is required to run this script.
Requires internet connectivity for downloading Office setup files and version validation.
Version validation can be bypassed with -SkipAPICheck if version is pre-specified.

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

This solution is distributed under the GNU GENERAL PUBLIC LICENSE 

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.PARAMETER ConfigXML
Path to the Office configuration XML file. If not specified, the script will auto-detect a single XML file in the script directory.
The XML should be generated or validated using https://config.office.com to ensure compatibility.

.PARAMETER SetupUrl
URL to download the Office setup executable. Defaults to the official Microsoft Office CDN URL.
Custom URLs can be specified for enterprise scenarios with local mirrors.

.PARAMETER OfficeVersionUrl
URL to query the latest Office version information. Defaults to the official Microsoft REST API endpoint.
This endpoint provides comprehensive version data for all Office channels and is critical for validation.

.PARAMETER OfficeIconUrl
URL to download the Office icon.
This icon will be included in the output package as Microsoft.png for use when creating custom applications.

.PARAMETER DownloadPath
Path where temporary files and Office installation files will be downloaded. Defaults to ".\Staging" in the current directory.
Ensure sufficient disk space (typically 3-6 GB depending on configuration).

.PARAMETER OutputPath
Path where the final deployment package will be created. Defaults to ".\Output" in the current directory.
Output packages include setup files, configuration, and optional compressed archives.
Ensure sufficient disk space (typically 3-6 GB depending on configuration).

.PARAMETER LogName
Path for the main script log file. Defaults to ".\Invoke-M365AppsHelper.log".

.PARAMETER NoZip
Switch parameter to skip creating a zip file of the deployment package. When specified, only the folder structure is created.

.PARAMETER OnlineMode
Switch parameter to create a package without downloading Office files.
This mode is useful for:
- Pre-validating configurations before bulk downloads
- Updating XML files with latest version information
- Creating lightweight packages

.PARAMETER SkipAPICheck
Switch parameter to skip the Office version API validation. Only works if a version is already specified in the XML configuration.
Use this when performing rapid testing with a pre-validated Office channel and version.
Warning: Skipping validation may result in download failures if the version is invalid.

.PARAMETER ApiRetryDelaySeconds
Delay in seconds between API retry attempts. Defaults to 3 seconds.
Increase this value if experiencing rate limiting or network latency issues.
Range: 1-30 seconds.

.PARAMETER ApiMaxExtendedAttempts
Maximum number of retry attempts for the Office version API call. Defaults to 10 attempts.
The script uses intelligent retry logic to ensure complete version data retrieval.
Range: 1-20 attempts.

.PARAMETER OutputConfigName
Specifies the name of the configuration XML file in the Output folder. Defaults to "Configuration.xml". This ensures a consistent name for deployment and avoids issues with spaces or special characters.

.EXAMPLE
.\Invoke-M365AppsHelper.ps1

Basic usage with auto-detection:
- Automatically finds XML file in script directory
- Downloads and packages Office using detected configuration
- Validates version against Microsoft API
- Creates compressed deployment package in .\Output
- Suitable for standard deployment scenarios

.EXAMPLE
.\Invoke-M365AppsHelper.ps1 -NoZip

Uncompressed package with custom settings:
- Creates deployment package without zip compression
- Useful for direct folder deployment or further processing

.EXAMPLE
.\Invoke-M365AppsHelper.ps1 -OnlineMode

Online validation mode:
- Validates XML configuration against latest Office versions
- Updates configuration with current version information
- Creates lightweight package without downloading Office files
- Perfect for configuration testing and validation workflows

.EXAMPLE
.\Invoke-M365AppsHelper.ps1 -ConfigXML "C:\Configs\Enterprise-Office365.xml" -OutputPath "C:\Deployments\Office" -LogName "C:\Logs\Office-Deploy.log"

Enterprise deployment with custom paths:
- Uses specific XML configuration file
- Custom output directory for deployment packages
- Centralized logging location
- Ideal for automated deployment pipelines and enterprise environments

.EXAMPLE
.\Invoke-M365AppsHelper.ps1 -ConfigXML "C:\Configs\Visio-Project.xml" -OutputPath "\\FileServer\Deployments$\Office" -LogName "\\LogServer\Logs$\Office-$(Get-Date -Format 'yyyyMMdd').log"

Network deployment with centralized storage:
- Uses configuration for Visio and Project applications
- Network share output location for distributed access
- Date-stamped logs on centralized log server
- Ideal for large-scale enterprise deployments
#>

param(
    [string]$ConfigXML,
    [ValidatePattern('^https?://.+')]
    [string]$SetupUrl = "https://officecdn.microsoft.com/pr/wsus/setup.exe",
    [ValidatePattern('^https?://.+')]
    [string]$OfficeVersionUrl = "https://clients.config.office.net/releases/v1.0/OfficeReleases",
    [ValidatePattern('^https?://.+')]
    [string]$OfficeIconUrl = "https://patchmypc.com/scupcatalog/downloads/icons/Microsoft.png",
    [ValidateScript({ Test-Path $_ -PathType Container -ErrorAction SilentlyContinue -or -not (Test-Path $_) })]
    [string]$DownloadPath = ".\Staging",
    [ValidateScript({ Test-Path $_ -PathType Container -ErrorAction SilentlyContinue -or -not (Test-Path $_) })]
    [string]$OutputPath = ".\Output",
    [ValidatePattern('\.log$')]
    [string]$LogName = ".\Invoke-M365AppsHelper.log",
    [string]$OutputConfigName = "Configuration.xml",
    [switch]$NoZip,
    [switch]$OnlineMode,
    [switch]$SkipAPICheck,
    [ValidateRange(1, 30)]
    [int]$ApiRetryDelaySeconds = 3,
    [ValidateRange(1, 20)]
    [int]$ApiMaxExtendedAttempts = 10
)

#region Logging

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
        [Parameter(Mandatory = $false)]
        [string]$Component = $MyInvocation.MyCommand.Name,
        [Parameter(Mandatory = $false)]
        [string]$LogFile = $script:LogPath
    )

    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $LogFile = (Resolve-Path $logDir -ErrorAction SilentlyContinue)?.Path ?? (New-Item -ItemType Directory -Path $logDir -Force).FullName
    $LogFile = Join-Path $LogFile (Split-Path $script:LogPath -Leaf)

    $time = Get-Date -Format "HH:mm:ss.ffffff"
    $date = Get-Date -Format "MM-dd-yyyy"
    $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    $logEntry = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$Component`" context=`"$context`" type=`"$Severity`" thread=`"$PID`" file=`"`">"
    
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Warning ("Failed to write to log file {0}: {1}" -f $LogFile, $_.Exception.Message)
    }
}

function Write-LogHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
        [Parameter(Mandatory = $false)]
        [string]$Component = $MyInvocation.MyCommand.Name,
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$ForegroundColor = 'White'
    )
    
    Write-Log -Message $Message -Severity $Severity -Component $Component
    Write-Host $Message -ForegroundColor $ForegroundColor
}

#endregion

if ($OnlineMode -and $NoZip) {

    $script:LogPath = $LogName
    $logID = "ParameterValidation"
    
    Write-LogHost "Error: OnlineMode and NoZip parameters cannot be used together." -ForegroundColor Red -Severity 3 -Component $logID
    Write-LogHost "Note: OnlineMode checks the Office version validity using the OfficeVersionUrl endpoint, it does not download Office files." -ForegroundColor Yellow -Severity 2 -Component $logID
    exit 1
}

if ($OnlineMode -and $SkipAPICheck) {

    $script:LogPath = $LogName
    $logID = "ParameterValidation"
    
    Write-LogHost "Error: OnlineMode and SkipAPICheck parameters cannot be used together." -ForegroundColor Red -Severity 3 -Component $logID
    Write-LogHost "Note: OnlineMode requires API access to validate/retrieve Office versions, but SkipAPICheck bypasses all API calls." -ForegroundColor Yellow -Severity 2 -Component $logID
    exit 1
}

#region Configuration Management

function Get-LocaleDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocaleCodes,
        [string]$LogID = $MyInvocation.MyCommand.Name
    )
    
    # Compressed locale hashtable
    $localeHashtable = @{
        "ar-SA" = "Arabic"; "bg-BG" = "Bulgarian"; "zh-CN" = "Chinese (China)"; "zh-TW" = "Chinese (Taiwan)"; "hr-HR" = "Croatian"; "cs-CZ" = "Czech"
        "da-DK" = "Danish"; "nl-NL" = "Dutch"; "en-US" = "English"; "en-GB" = "English (United Kingdom)"; "et-EE" = "Estonian"; "fi-FI" = "Finnish"
        "fr-FR" = "French"; "fr-CA" = "French (Canada)"; "de-DE" = "German"; "el-GR" = "Greek"; "he-IL" = "Hebrew"; "hi-IN" = "Hindi"
        "hu-HU" = "Hungarian"; "id-ID" = "Indonesian"; "it-IT" = "Italian"; "ja-JP" = "Japanese"; "kk-KZ" = "Kazakh"; "ko-KR" = "Korean"
        "lv-LV" = "Latvian"; "lt-LT" = "Lithuanian"; "ms-MY" = "Malay"; "nb-NO" = "Norwegian Bokmål"; "pl-PL" = "Polish"; "pt-BR" = "Portuguese (Brazil)"
        "pt-PT" = "Portuguese (Portugal)"; "ro-RO" = "Romanian"; "ru-RU" = "Russian"; "sr-Latn-RS" = "Serbian (Latin)"; "sk-SK" = "Slovak"; "sl-SI" = "Slovenian"
        "es-ES" = "Spanish"; "es-MX" = "Spanish (Mexico)"; "sv-SE" = "Swedish"; "th-TH" = "Thai"; "tr-TR" = "Turkish"; "uk-UA" = "Ukrainian"
        "vi-VN" = "Vietnamese"; "af-ZA" = "Afrikaans"; "sq-AL" = "Albanian"; "hy-AM" = "Armenian"; "as-IN" = "Assamese"; "az-Latn-AZ" = "Azerbaijani (Latin)"
        "eu-ES" = "Basque"; "bn-BD" = "Bangla (Bangladesh)"; "bn-IN" = "Bangla (India)"; "bs-Latn-BA" = "Bosnian (Latin)"; "ca-ES" = "Catalan"; "gl-ES" = "Galician"
        "ka-GE" = "Georgian"; "gu-IN" = "Gujarati"; "is-IS" = "Icelandic"; "ga-IE" = "Irish"; "kn-IN" = "Kannada"; "sw-KE" = "Swahili"
        "kok-IN" = "Konkani"; "ky-KG" = "Kyrgyz"; "lb-LU" = "Luxembourgish"; "mk-MK" = "Macedonian"; "ml-IN" = "Malayalam"; "mt-MT" = "Maltese"
        "mi-NZ" = "Maori"; "mr-IN" = "Marathi"; "ne-NP" = "Nepali"; "nn-NO" = "Norwegian Nynorsk"; "or-IN" = "Odia"; "fa-IR" = "Persian"
        "pa-IN" = "Punjabi"; "gd-GB" = "Scottish Gaelic"; "sr-Cyrl-RS" = "Serbian (Cyrillic)"; "sr-Cyrl-BA" = "Serbian (Cyrillic)"; "si-LK" = "Sinhala"; "ta-IN" = "Tamil"
        "tt-RU" = "Tatar"; "te-IN" = "Telugu"; "ur-PK" = "Urdu"; "uz-Latn-UZ" = "Uzbek"; "ca-ES-VALENCIA" = "Catalan (Valencian)"; "cy-GB" = "Welsh"
        "ha-Latn-NG" = "Hausa"; "ig-NG" = "Igbo"; "xh-ZA" = "Xhosa"; "zu-ZA" = "Zulu"; "rw-RW" = "Kinyarwanda"; "ps-AF" = "Pashto"
        "rm-CH" = "Romansh"; "nso-ZA" = "Sesotho sa Leboa"; "tn-ZA" = "Tswana"; "wo-SN" = "Wolof"; "yo-NG" = "Yoruba"
    }
    
    try {
        $codes = $LocaleCodes -split ',' | ForEach-Object { $_.Trim() }
    
        $displayNames = @()
        foreach ($code in $codes) {
            if ($localeHashtable.ContainsKey($code)) {
                $displayNames += $localeHashtable[$code]
            }
            else {
                $displayNames += "$code (Unknown)"
                Write-Log ("Code {0} not found in locale hashtable" -f $code) -Severity 2 -Component $LogID
            }
        }

        if ($displayNames.Count -eq 1) {
            Write-Log ("Single locale code {0} resolved: {1}" -f $LocaleCodes, $displayNames[0]) -Component $LogID
            return $displayNames[0]
            
        }
        else {
            Write-Log ("Multiple locale codes {0} resolved: {1}" -f $LocaleCodes, ($displayNames -join ', ')) -Component $LogID
            return $displayNames
        }
    }
    catch {
        Write-LogHost "Error parsing locale codes. Will return original input: {0}" -f $_ -ForegroundColor Red -Severity 3 -Component $LogID
        return $LocaleCodes
    }
}

function Resolve-ConfigXml {
    param(
        [AllowEmptyString()]
        [string]$Path,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )

    if ($Path) { 
        if (Test-Path -Path $Path) { 
            Write-Log ("Using provided configuration XML: {0}" -f $Path) -Component $LogID
            return (Resolve-Path -Path $Path).Path 
        }
        else { 
            Write-Log ("The provided configuration XML file was not found at: {0}" -f $Path) -Severity 3 -Component $LogID
            throw ("The provided configuration XML file was not found at: {0}" -f $Path)
        } 
    }

    $xmlFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.xml"

    if ($xmlFiles.Count -eq 0) { 
        Write-Log ("No XML files found in script directory: {0}" -f $PSScriptRoot) -Severity 3 -Component $LogID
        throw ("No XML files found in script directory: {0}" -f $PSScriptRoot)
    }
    if ($xmlFiles.Count -gt 1) {
        Write-Log ("Multiple XML files found in {0}. Specify -ConfigXML" -f $PSScriptRoot) -Severity 3 -Component $LogID
        throw ("Multiple XML files found in {0}. Specify -ConfigXML" -f $PSScriptRoot)
    }

    Write-Log ("Using configuration XML found: {0}" -f $xmlFiles[0].FullName) -Component $LogID    
    return $xmlFiles[0].FullName
}

function Get-OfficeConfigInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$XmlData,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )

    Write-Log ("Parsing Office configuration XML dynamically") -Component $LogID

    $languages = [System.Collections.Generic.HashSet[string]]::new()
    $excludedApps = [System.Collections.Generic.HashSet[string]]::new()
    $products = [System.Collections.Generic.List[object]]::new()
    $configurationAttributes = [ordered]@{}

    if ($XmlData.Configuration.Attributes) {
        foreach ($attr in $XmlData.Configuration.Attributes) {
            $configurationAttributes[$attr.Name] = $attr.Value
        }
    }

    $addNode = $XmlData.Configuration.Add
    $addAttributes = [ordered]@{}
    if ($addNode -and $addNode.Attributes) {
        foreach ($attr in $addNode.Attributes) {
            $addAttributes[$attr.Name] = $attr.Value
        }
    }

    $configChannel = $addAttributes['Channel']
    $configVersion = $addAttributes['Version']
    
    Write-Log ("XML Configuration - Channel: {0}, Version: {1}, Add Attributes: {2}" -f $configChannel, $configVersion, ($addAttributes.Keys -join ', ')) -Component $LogID

    foreach ($product in @($addNode.Product)) {
        $productLanguages = [System.Collections.Generic.List[string]]::new()
        $productExclusions = [System.Collections.Generic.List[string]]::new()
        $productAttributes = [ordered]@{}

        if ($product.Attributes) {
            foreach ($attr in $product.Attributes) {
                $productAttributes[$attr.Name] = $attr.Value
            }
        }

        foreach ($language in @($product.Language)) {
            if ($language.ID) {
                $null = $languages.Add($language.ID)
                $productLanguages.Add($language.ID)
            }
        }
        
        foreach ($exclusion in @($product.ExcludeApp)) {
            if ($exclusion.ID) {
                $null = $excludedApps.Add($exclusion.ID)
                $productExclusions.Add($exclusion.ID)
            }
        }

        $productObj = [PSCustomObject]@{
            Languages    = $productLanguages.ToArray()
            ExcludedApps = $productExclusions.ToArray()
        }
        
        foreach ($attr in $productAttributes.GetEnumerator()) {
            $productObj | Add-Member -NotePropertyName $attr.Key -NotePropertyValue $attr.Value
        }
        
        $products.Add($productObj)
    }

    $propertyElements = [ordered]@{
    }
    foreach ($property in @($XmlData.Configuration.Property)) {
        if ($property.Name) { 
            $propertyElements[$property.Name] = $property.Value 
        }
    }
    
    $otherElements = [ordered]@{
    }
    foreach ($element in $XmlData.Configuration.ChildNodes) {
        if ($element.NodeType -eq 'Element' -and $element.LocalName -notin @('Add', 'Property')) {
            if ($element.Attributes.Count -gt 0) {
                foreach ($attr in $element.Attributes) {
                    $key = "{0}_{1}" -f $element.LocalName, $attr.Name
                    $otherElements[$key] = $attr.Value
                }
            }
        }
    }

    $configResult = [PSCustomObject]@{
        Channel      = $configChannel
        Version      = $configVersion
        Products     = $products
        Languages    = @($languages)
        ExcludedApps = @($excludedApps)
    }
    
    foreach ($attr in $configurationAttributes.GetEnumerator()) {
        $configResult | Add-Member -NotePropertyName $attr.Key -NotePropertyValue $attr.Value
    }
    
    foreach ($attr in $addAttributes.GetEnumerator()) {
        if ($attr.Key -notin @('Channel', 'Version')) {
            $configResult | Add-Member -NotePropertyName $attr.Key -NotePropertyValue $attr.Value
        }
    }
    
    foreach ($prop in $propertyElements.GetEnumerator()) {
        $configResult | Add-Member -NotePropertyName $prop.Key -NotePropertyValue $prop.Value
    }
    
    foreach ($elem in $otherElements.GetEnumerator()) {
        $configResult | Add-Member -NotePropertyName $elem.Key -NotePropertyValue $elem.Value
    }
    
    Write-Log ("Parsed {0} products, {1} languages, {2} excluded apps, {3} total properties" -f $products.Count, $languages.Count, $excludedApps.Count, ($configurationAttributes.Count + $addAttributes.Count + $propertyElements.Count + $otherElements.Count)) -Component $LogID
    return $configResult
}

#endregion

#region File Operations

function Invoke-FileDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^https?://.+')]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    Invoke-WebRequest -Uri $Uri -OutFile $Destination -ErrorAction Stop
    if (-not (Test-Path $Destination)) { 
        Write-LogHost ("Failed to download {0}" -f $Uri) -ForegroundColor Red -Severity 3 -Component $LogID
        throw ("Failed to download {0} at line {1}: {2}" -f $Uri, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }
    Write-Log ("Downloaded file to {0}" -f $Destination) -Component $LogID
    $Destination
}

function Format-Size {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [long]::MaxValue)]
        [long]$Bytes,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        if ($Bytes -lt 1KB) { 
            return ("{0:n0} B" -f $Bytes) 
        }
        if ($Bytes -lt 1MB) { 
            return ("{0:n2} KB" -f ($Bytes / 1KB)) 
        }
        if ($Bytes -lt 1GB) { 
            return ("{0:n2} MB" -f ($Bytes / 1MB)) 
        }
        return ("{0:n2} GB" -f ($Bytes / 1GB))
    }
    catch {
        Write-Log ("Error formatting size for {0} bytes: {1}" -f $Bytes, $_.Exception.Message) -Severity 3 -Component $LogID
        return "Unknown"
    }
}

function Start-OfficeDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$SetupPath,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$WorkingDir,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ConfigPath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )

    Set-Location -Path $WorkingDir
    try {
        Write-Log "Starting Office download using setup.exe" -Component $LogID
        Write-Log ("Current working directory changed to: {0}" -f $WorkingDir) -Component $LogID
        Write-Log ("Script log path remains: {0}" -f $script:LogPath) -Component $LogID
        $process = Start-Process -FilePath $SetupPath -ArgumentList ('/download "{0}"' -f $ConfigPath) -WorkingDirectory $WorkingDir -WindowStyle Hidden -PassThru
        $watchPath = Join-Path $WorkingDir 'Office'
        if (-not (Test-Path $watchPath)) { New-Item -ItemType Directory -Path $watchPath -Force | Out-Null }

        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $maxBytes = 0L

        while (-not $process.HasExited) {
            $files = Get-ChildItem -Path $watchPath -File -Recurse -Force -ErrorAction SilentlyContinue
            $total = 0L
            foreach ($file in $files) {
                $total += $file.Length
                if ($file.Length -gt 0 -and $seen.Add($file.FullName)) {
                    $relativePath = $file.FullName.Replace($WorkingDir, '.')
                    Write-LogHost ("Downloaded: {0}" -f $relativePath) -ForegroundColor Yellow -Component $LogID
                }
            }
            if ($total -gt $maxBytes) { 
                $maxBytes = $total 
            }
            
            $status = 'Files: {0} | Size: {1}' -f ($files.Count), (Format-Size $maxBytes)
            Write-Progress -Id 1000 -Activity 'Downloading Office' -Status $status -PercentComplete 0
            Start-Sleep -Seconds 1
        }

        Write-Progress -Id 1000 -Activity 'Downloading Office' -Completed
        Start-Sleep -Milliseconds 100
        if ($process.ExitCode -ne 0) { 
            Write-LogHost ("Office download failed with exit code {0}" -f $process.ExitCode) -ForegroundColor Red -Severity 3 -Component $LogID
            
            switch ($process.ExitCode) {
                400 {
                    Write-LogHost ("EXIT CODE 400: Invalid Office configuration detected") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("This usually means:") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("  - The version specified is invalid for the selected channel") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("  - The channel name is incorrect or unsupported") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("  - Product ID is invalid or incompatible") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost " " -Component $LogID
                    Write-LogHost ("SOLUTION: Review your XML configuration at https://config.office.com") -ForegroundColor Cyan -Component $LogID
                    Write-LogHost ("  1. Go to https://config.office.com to validate your configuration") -ForegroundColor Cyan -Component $LogID
                    Write-LogHost ("  2. Ensure the Channel and Version combination is valid") -ForegroundColor Cyan -Component $LogID
                    Write-LogHost ("  3. Try running this script WITHOUT -SkipAPICheck to validate versions") -ForegroundColor Cyan -Component $LogID
                }
                17301 {
                    Write-LogHost ("EXIT CODE 17301: Network or download location issue") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("Check your internet connection and firewall settings") -ForegroundColor Yellow -Severity 2 -Component $LogID
                }
                17004 {
                    Write-LogHost ("EXIT CODE 17004: File access or permissions issue") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("Try running as administrator or check file permissions") -ForegroundColor Yellow -Severity 2 -Component $LogID
                }
                default {
                    Write-LogHost ("Unexpected exit code. Common causes:") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("  - Invalid XML configuration") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("  - Network connectivity issues") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("  - Insufficient permissions") -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost " " -Component $LogID
                    Write-LogHost ("Validate your XML at: https://config.office.com") -ForegroundColor Cyan -Component $LogID
                }
            }
            
            throw ("Office download failed with exit code {0}" -f $process.ExitCode)
        }
        if ($maxBytes -eq 0) {
            Write-LogHost ("Office download completed but no files were downloaded. Check your configuration XML or network connectivity") -ForegroundColor Red -Severity 3 -Component $LogID
            throw ("Office download completed but no files were downloaded")
        }
        return Format-Size $maxBytes
    }
    catch {
        Write-LogHost ("Office download failed: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        Write-LogHost ("Error occurred at line {0} in {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.ScriptName) -ForegroundColor Red -Severity 3 -Component $LogID
        throw $_
    }
    finally { Set-Location -Path $PSScriptRoot }
}

function Get-OfficeBuildFromCabs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$Root,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )

    Write-Log ("Extracting Office build number from CAB files in {0}" -f $Root) -Component $LogID
    $cabFiles = Get-ChildItem -Path (Join-Path $Root "Office\Data") -Filter "*.cab" -Recurse -ErrorAction SilentlyContinue
    if (-not $cabFiles) { 
        return $null 
    }
    $buildRegex = [regex]'(\d+\.\d+\.\d+\.\d+)'
    foreach ($cabFile in $cabFiles) { 
        if ($buildRegex.IsMatch($cabFile.Name)) { 
            return $buildRegex.Match($cabFile.Name).Groups[1].Value 
        } 
    }
    $null
}

function Get-ValidOfficeVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Channel,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^https?://.+')]
        [string]$VersionUrl,
        [string]$CurrentVersion,
        [string]$StagingDir = ".\Staging",
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        Write-Log ("Validating Office version for channel {0}" -f $Channel) -Component $LogID
        
        if ($script:OfficeApiData) {
            Write-Log ("Using cached Office API data") -Component $LogID
            $apiData = $script:OfficeApiData
        }
        else {
            Write-Log ("Fetching fresh Office API data") -Component $LogID
            $apiData = Get-OfficeApiData -VersionUrl $VersionUrl -StagingDir $StagingDir -RetryDelaySeconds $script:ApiRetryDelaySeconds -MaxExtendedAttempts $script:ApiMaxExtendedAttempts
        }

        $versionInfo = Get-ChannelVersionInfo -Channel $Channel -OfficeApiData $apiData -CurrentVersion $CurrentVersion -LogID $LogID
        
        if (-not $versionInfo) {
            Write-LogHost ("Could not retrieve version information for channel {0}" -f $Channel) -ForegroundColor Red -Severity 3 -Component $LogID
            return $null
        }
        
        if (-not [string]::IsNullOrWhiteSpace($CurrentVersion)) {
            if ($versionInfo.CurrentVersionValid) {
                Write-LogHost ("Current XML version {0} is valid for channel {1}" -f $CurrentVersion, $Channel) -ForegroundColor Green -Component $LogID
                return $CurrentVersion
            }
            else {

                Write-LogHost ("The version '{0}' specified in your XML is NOT valid for channel '{1}'" -f $CurrentVersion, $Channel) -ForegroundColor Red -Severity 3 -Component $LogID
                Write-LogHost ("You can select a valid version below but your XML configuration might be out-dated. Re-validate it at https://config.office.com") -ForegroundColor Yellow -Component $LogID
                Write-Host ""
                Write-LogHost ("Available valid versions for channel '{0}':-" -f $Channel) -ForegroundColor Green -Component $LogID
                
                $availableVersions = $versionInfo.AllVersions | Sort-Object -Descending
                for ($i = 0; $i -lt $availableVersions.Count; $i++) {
                    $versionText = $availableVersions[$i]
                    if ($availableVersions[$i] -eq $versionInfo.LatestVersion) {
                        $versionText += " (Latest)"
                    }
                    Write-Host ("  {0} - {1}" -f ($i + 1), $versionText) -ForegroundColor Cyan
                }

                $abandonOption = $availableVersions.Count + 1
                Write-Host ("  {0} - Abandon script execution" -f $abandonOption) -ForegroundColor Red
                Write-Host ""
                
                do {
                    $response = Read-Host "Select a version number to use, or $abandonOption to abandon"
                    
                    if ([int]::TryParse($response, [ref]$null)) {
                        $responseInt = [int]$response

                        if ($responseInt -eq $abandonOption) {
                            Write-LogHost ("User chose to abandon script execution due to invalid version {0}" -f $CurrentVersion) -ForegroundColor Yellow -Severity 2 -Component $LogID
                            Write-LogHost ("SCRIPT ABANDONED BY USER") -ForegroundColor Red -Severity 3 -Component $LogID
                            exit 1
                        }
                        elseif ($responseInt -ge 1 -and $responseInt -le $availableVersions.Count) {
                            $selectedVersion = $availableVersions[$responseInt - 1]
                            $validChoice = $true
                        }
                        else {
                            Write-Host ("Invalid choice. Please enter a number between 1 and {0}." -f $abandonOption) -ForegroundColor Red
                            $validChoice = $false
                        }
                    }
                    else {
                        Write-Host ("Invalid choice. Please enter a number between 1 and {0}." -f $abandonOption) -ForegroundColor Red
                        $validChoice = $false
                    }
                } while (-not $validChoice)
                
                Write-LogHost ("User selected version: {0}" -f $selectedVersion) -ForegroundColor Green -Component $LogID
                return $selectedVersion 
            }
        }
        else {
            Write-LogHost ("No version specified in provided XML, we will use latest version: {0}" -f $versionInfo.LatestVersion) -ForegroundColor Yellow -Component $LogID
            return $versionInfo.LatestVersion
        }
    }
    catch {
        Write-LogHost ("Failed to validate Office version: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $null
    }
}

function Get-OfficeApiData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^https?://.+')]
        [string]$VersionUrl,
        [string]$StagingDir = ".\Staging",
        [int]$RetryDelaySeconds = 3,
        [int]$MaxExtendedAttempts = 10,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        Write-LogHost "Querying Office version information..." -Component $LogID
        Write-Progress -Id 1001 -Activity "Downloading Office API Data" -Status "Connecting to Microsoft Office endpoint..." -PercentComplete 0
        Write-LogHost ("API URL: {0}" -f $VersionUrl) -ForegroundColor White -Component $LogID
        Write-Log ("Starting API retry mechanism: up to {0} attempts" -f $MaxExtendedAttempts) -Component $LogID
        
        $bestResponse = $null
        $bestResponseSize = 0
        
        for ($attempt = 1; $attempt -le $MaxExtendedAttempts; $attempt++) {
            try {
                $progressPercent = [Math]::Round(($attempt / $MaxExtendedAttempts) * 100)
                Write-Progress -Id 1001 -Activity "Downloading Office API Data" -Status "API attempt $attempt of $MaxExtendedAttempts..." -PercentComplete $progressPercent
                
                Write-Log ("Making API call (attempt {0} of {1})" -f $attempt, $MaxExtendedAttempts) -Component $LogID
                $webResponse = Invoke-WebRequest -Uri $VersionUrl -UseBasicParsing
                $response = $webResponse.Content | ConvertFrom-Json
                
                Write-Log ("API Response Status: {0}, Content Length: {1} characters (attempt {2})" -f $webResponse.StatusCode, $webResponse.Content.Length, $attempt) -Component $LogID
                
                $totalChannels = $response.Count
                if ($totalChannels -gt $bestResponseSize) {
                    $bestResponse = $response
                    $bestResponseSize = $totalChannels
                    Write-Log ("New best response found: {0} channels (attempt {1})" -f $totalChannels, $attempt) -Component $LogID
                }

                if ($totalChannels -ge 5) {
                    Write-Log ("Good response found with {0} channels (attempt {1})" -f $totalChannels, $attempt) -Component $LogID
                    break
                }
                
                if ($attempt -lt $MaxExtendedAttempts) {
                    Write-Log ("Waiting {0} seconds before next attempt..." -f $RetryDelaySeconds) -Component $LogID
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
            }
            catch {
                Write-Log ("API attempt {0} failed: {1}" -f $attempt, $_.Exception.Message) -Severity 2 -Component $LogID
                if ($attempt -eq $MaxExtendedAttempts) {
                    throw $_
                }
                
                if ($attempt -lt $MaxExtendedAttempts) {
                    Write-Log ("Waiting {0} seconds before retry..." -f $RetryDelaySeconds) -Component $LogID
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
            }
        }
        
        Write-Progress -Id 1001 -Activity "Downloading Office API Data" -Completed
        Write-Host "API data downloaded successfully" -ForegroundColor Green
        
        if (-not $bestResponse) {
            throw "Failed to get any valid response after $MaxExtendedAttempts attempts"
        }
        
        try {
            if (-not (Test-Path $StagingDir)) {
                New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
                Write-Log ("Created staging directory for JSON response: {0}" -f $StagingDir) -Component $LogID
            }
            $jsonFileName = "OfficeVersions_Latest.json"
            $jsonFilePath = Join-Path $StagingDir $jsonFileName
            $bestResponse | ConvertTo-Json -Depth 20 | Out-File -FilePath $jsonFilePath -Encoding UTF8 -Force
            Write-LogHost ("Saved Office version JSON to: {0}" -f $jsonFilePath) -ForegroundColor Green -Component $LogID
        }
        catch {
            Write-Log ("Failed to save JSON response to staging: {0}" -f $_.Exception.Message) -Severity 2 -Component $LogID
        }
        
        Write-Log ("API call completed successfully with {0} channels" -f $bestResponse.Count) -Component $LogID
        return $bestResponse
    }
    catch {
        Write-LogHost ("Failed to retrieve Office API data: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        throw $_
    }
}

function Test-OfficeChannelValid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Channel,
        [Parameter(Mandatory = $false)]
        [object[]]$OfficeApiData,
        [string]$StagingDir = ".\Staging",
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    $validChannels = @()
    
    
    if ($OfficeApiData) {
        Write-Log ("Using provided API data with {0} channels" -f $OfficeApiData.Count) -Component $LogID
        $apiData = $OfficeApiData
    }
    else {
        
        $jsonPath = Join-Path $StagingDir "OfficeVersions_Latest.json"
        if (Test-Path $jsonPath) {
            try {
                Write-Log ("Reading channel data from JSON: {0}" -f $jsonPath) -Component $LogID
                $jsonContent = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
                $apiData = $jsonContent
                Write-Log ("Loaded {0} channels from JSON file" -f $apiData.Count) -Component $LogID
            }
            catch {
                Write-Log ("Failed to read JSON file: {0}" -f $_.Exception.Message) -Severity 2 -Component $LogID
                $apiData = $null
            }
        }
        else {
            Write-Log ("JSON file not found at {0}" -f $jsonPath) -Severity 2 -Component $LogID
            $apiData = $null
        }
    }
    
    if ($apiData) {
        
        foreach ($channelData in $apiData) {
            if ($channelData.channelId) {
                $validChannels += $channelData.channelId
                
                if ($channelData.alternateNames -and $channelData.alternateNames.Count -gt 0) {
                    $validChannels += $channelData.alternateNames
                }
            }
        }

        $validChannels = $validChannels | Select-Object -Unique | Sort-Object
        Write-Log ("Extracted {0} valid channels from API data: {1}" -f $validChannels.Count, ($validChannels -join ', ')) -Component $LogID
    }
    
    $isValid = $Channel -in $validChannels
    Write-Log ("Channel '{0}' validation result: {1}" -f $Channel, $isValid) -Component $LogID
    
    return [PSCustomObject]@{
        IsValid       = $isValid
        ValidChannels = $validChannels
        TestedChannel = $Channel
    }
}

function Get-ChannelVersionInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Channel,
        [Parameter(Mandatory = $true)]
        [object[]]$OfficeApiData,
        [string]$CurrentVersion,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        Write-Log ("Processing version information for channel '{0}'" -f $Channel) -Component $LogID
        
        $targetChannelData = $OfficeApiData | Where-Object { $_.channelId -eq $Channel }
        
        if (-not $targetChannelData) {
            Write-LogHost ("Channel '{0}' not found in API data" -f $Channel) -ForegroundColor Red -Severity 3 -Component $LogID
            return $null
        }
        
        $allVersionsForChannel = @()
        if ($targetChannelData.officeVersions -and $targetChannelData.officeVersions.Count -gt 0) {
            foreach ($update in $targetChannelData.officeVersions) {
                if ($update.legacyVersion) {
                    $allVersionsForChannel += $update.legacyVersion
                }
            }
        }
        $uniqueVersions = $allVersionsForChannel | Select-Object -Unique | Sort-Object -Descending
        
        $channelInfo = [PSCustomObject]@{
            Channel             = $targetChannelData.channelId
            DisplayName         = $targetChannelData.channel
            LatestVersion       = $targetChannelData.latestVersion
            AllVersions         = $uniqueVersions
            CurrentVersionValid = $false
            CurrentVersion      = $CurrentVersion
            TotalVersionsCount  = $uniqueVersions.Count
        }
        
        if (-not [string]::IsNullOrWhiteSpace($CurrentVersion)) {
            $channelInfo.CurrentVersionValid = $CurrentVersion -in $uniqueVersions
            
            if ($channelInfo.CurrentVersionValid) {
                Write-LogHost ("Version '{0}' is valid for channel '{1}'" -f $CurrentVersion, $Channel) -ForegroundColor Green -Component $LogID
            }
            else {
                Write-LogHost ("Version '{0}' is NOT valid for channel '{1}'" -f $CurrentVersion, $Channel) -ForegroundColor Yellow -Severity 2 -Component $LogID
            }
        }
        
        Write-Log ("Channel '{0}': Latest={1}, TotalVersions={2}" -f $Channel, $channelInfo.LatestVersion, $channelInfo.TotalVersionsCount) -Component $LogID
        return $channelInfo
    }
    catch {
        Write-LogHost ("Failed to process channel version info: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $null
    }
}

function Update-XmlVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$XmlPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$Version,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        Write-Log ("Updating XML at {0} with version {1}" -f $XmlPath, $Version) -Component $LogID
        
        [xml]$xmlData = Get-Content -Path $XmlPath -Raw
        $addNode = $xmlData.Configuration.Add
        
        if ($addNode.HasAttribute('Version')) {
            $oldVersion = $addNode.Version
            $addNode.SetAttribute('Version', $Version)
            Write-Log ("Updated version from {0} to {1}" -f $oldVersion, $Version) -Component $LogID
        }
        else {
            $addNode.SetAttribute('Version', $Version)
            Write-Log ("Added version attribute: {0}" -f $Version) -Component $LogID
        }
        
        $xmlData.Save($XmlPath)
        Write-LogHost ("XML updated with version: {0}" -f $Version) -ForegroundColor Green -Component $LogID
        return $true
    }
    catch {
        Write-LogHost ("Failed to update XML: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $false
    }
}

#endregion

#region Zip Creation

function New-ZipFromDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [ValidateSet("Optimal", "Fastest", "NoCompression", "SmallestSize")]
        [string]$CompressionLevel = "Fastest",
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    Write-LogHost ("Creating Zip file: {0}" -f $ZipPath) -Component $LogID
    
    try {
        $zipDir = [System.IO.Path]::GetDirectoryName($ZipPath)
        if (-not [System.IO.Directory]::Exists($zipDir)) {
            Write-LogHost ("Creating directory for Zip: {0}" -f $zipDir) -ForegroundColor Yellow -Severity 2 -Component $LogID
            [System.IO.Directory]::CreateDirectory($zipDir) | Out-Null
        }
        
        if ([System.IO.File]::Exists($ZipPath)) {
            Write-LogHost ("Removing existing Zip file: {0}" -f $ZipPath) -ForegroundColor Yellow -Severity 2 -Component $LogID
            [System.IO.File]::Delete($ZipPath)
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Write-LogHost ("Running Zip compression to reduce the number of additional files in the package. Compression Level: {0}" -f $CompressionLevel) -Component $LogID
        [System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $ZipPath, [System.IO.Compression.CompressionLevel]::$CompressionLevel, $false)
        
        if ([System.IO.File]::Exists($ZipPath)) {
            return $ZipPath
        }
        else {
            Write-LogHost ("Zip file was not created at expected location: {0}" -f $ZipPath) -ForegroundColor Red -Severity 3 -Component $LogID
            throw ("Zip file was not created at expected location: {0} at line {1}: {2}" -f $ZipPath, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
        }
    }
    catch {
        Write-LogHost ("Failed to create Zip: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        throw ("Failed to create Zip at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }
}

function Get-ZipContents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$SourcePath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        $contents = @()
        
        if (-not (Test-Path $ZipPath)) {
            Write-LogHost ("Zip file not found: {0}" -f $ZipPath) -ForegroundColor Red -Severity 3 -Component $LogID
            throw ("Zip file not found at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
        }
        
        Write-LogHost ("Reading contents of Zip file: {0}" -f $ZipPath) -Component $LogID
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        
        try {
            $entries = $zip.Entries | Sort-Object FullName
            
            foreach ($entry in $entries) {
                if (-not $entry.FullName.EndsWith('/')) {
                    $contents += ("    {0}" -f $entry.FullName)
                }
            }
            
            if ($contents.Count -eq 0) {
                $contents += ("    Zip appears to be empty")
            }
        }
        finally {
            $zip.Dispose()
        }
        
        return $contents
    }
    catch {
        Write-LogHost ("Error reading Zip contents: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        throw ("Error reading Zip contents at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }
}

#endregion

#region PreScript Generation

function New-PreScriptContent {
    return @'
<#
.SYNOPSIS
    Automatically detects and extracts any zip file in the current directory for application deployment.

.DESCRIPTION
    This script automatically detects and extracts any zip file in the current directory.
    Optionally accepts a specific zip filename to extract only that file when multiple zips exist.

.PARAMETER Name
    Optional. Name of a specific zip file to extract. If not provided, auto-detects any zip file in the directory.

.PARAMETER LogPath
    Path to the directory where the log file will be created. Defaults to temp directory.

.PARAMETER LogName
    Name of the log file. Defaults to timestamped "ZipExtractor-PreScript_yymmdd-hhmm.log".

.NOTES
    Generic zip extraction utility for any zip file
#>

[CmdletBinding()]
param(
    [string]$Name,
    [string]$LogPath = $env:TEMP,
    [string]$LogName = ("ZipExtractor-PreScript_{0}.log" -f (Get-Date -Format "yyMMdd-HHmm"))
)

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
        [Parameter(Mandatory = $false)]
        [string]$Component = "PreScript"
    )

    # Construct full log file path
    $fullLogPath = Join-Path $LogPath $LogName

    # Create log directory if it doesn't exist, fallback to temp if creation fails
    if (-not (Test-Path $LogPath)) {
        try {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        }
        catch {
            Write-Warning ("Failed to create log directory {0}: {1}. Using temp directory instead." -f $LogPath, $_.Exception.Message)
            $LogPath = $env:TEMP
            $fullLogPath = Join-Path $LogPath $LogName
        }
    }

    # Format log entry in CMTrace format
    $time = Get-Date -Format "HH:mm:ss.ffffff"
    $date = Get-Date -Format "MM-dd-yyyy"
    $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    $logEntry = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$Component`" context=`"$context`" type=`"$Severity`" thread=`"$PID`" file=`"`">"
    
    try {
        Add-Content -Path $fullLogPath -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Warning ("Failed to write to log file {0}: {1}" -f $fullLogPath, $_.Exception.Message)
    }
}

function Expand-ZipFile {
    param(
        [string]$ZipPath,
        [string]$DestinationPath
    )
    
    try {
        Write-Log ("Extracting {0} to {1}" -f $ZipPath, $DestinationPath)
        
        # Use .NET System.IO.Compression for maximum compatibility (PowerShell 5.1+ with .NET 4.5+)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)
        Write-Log ("Zip extraction completed using .NET compression")
        
        return $true
    }
    catch {
        Write-Log ("Failed to extract Zip file: {0}" -f $_.Exception.Message) -Severity 3
        return $false
    }
}

# Main execution
try {
    $currentDir = Get-Location
    
    Write-Log ("Starting zip file extraction")
    Write-Log ("Current directory: {0}" -f $currentDir)
    Write-Log ("PowerShell version: {0}" -f $PSVersionTable.PSVersion)
    
    if ($Name) {
        # Use explicitly specified zip file
        $zipFile = Join-Path $currentDir $Name
        Write-Log ("Using explicitly specified zip file: {0}" -f $Name)
        
        if (-not (Test-Path $zipFile)) {
            Write-Log ("Specified zip file not found: {0}" -f $Name) -Severity 3
            throw ("Specified zip file not found: {0}" -f $Name)
        }
        
        $ZipFileName = $Name
    }
    else {
        # Auto-detect zip file in current directory
        Write-Log ("Auto-detecting zip files in directory")
        $zipFiles = Get-ChildItem -Path $currentDir -Filter "*.zip" -File
        
        if ($zipFiles.Count -eq 0) {
            Write-Log ("No zip files found in current directory: {0}" -f $currentDir) -Severity 3
            throw ("No zip files found in current directory: {0}" -f $currentDir)
        }
        
        if ($zipFiles.Count -gt 1) {
            Write-Log ("Multiple zip files found. Using first one: {0}" -f $zipFiles[0].Name) -Severity 2
            foreach ($zip in $zipFiles) {
                Write-Log ("Available zip file: {0}" -f $zip.Name)
            }
        }
        
        $zipFile = $zipFiles[0].FullName
        $ZipFileName = $zipFiles[0].Name
        Write-Log ("Auto-selected zip file: {0}" -f $ZipFileName)
    }
    
    $zipInfo = Get-Item $zipFile
    Write-Log ("Found {0} ({1:N2} MB)" -f $ZipFileName, ($zipInfo.Length / 1MB))
    
    # Extract Zip contents
    $extractResult = Expand-ZipFile -ZipPath $zipFile -DestinationPath $currentDir
    
    if ($extractResult) {
        Write-Log ("Application source files extracted successfully")
        
        # Count extracted files
        $extractedFiles = Get-ChildItem -Path $currentDir -File -Recurse | Where-Object { $_.Name -ne $ZipFileName }
        Write-Log ("Extracted {0} files from {1}" -f $extractedFiles.Count, $ZipFileName)
        Write-Log ("Ready for application installation")
    }
    else {
        Write-Log ("Zip extraction failed") -Severity 3
        throw ("Zip extraction failed")
    }
}
catch {
    Write-Log ("PreScript execution failed: {0}" -f $_.Exception.Message) -Severity 3
    exit 1
}

Write-Log ("PreScript execution completed successfully")
'@
}

function New-PreScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$OutputPath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        $preScriptPath = Join-Path $OutputPath "PreScript.ps1"
        $preScriptContent = New-PreScriptContent
        $preScriptContent | Out-File -FilePath $preScriptPath -Encoding UTF8 -Force
        Write-LogHost "Generated PreScript.ps1 for Zip extraction" -ForegroundColor Green -Component $LogID
        
        return $preScriptPath
    }
    catch {
        throw ("Failed to create PreScript.ps1 at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }
}
#endregion

#region Instructions File Generation

function New-PatchMyPCInstructions {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CustomApp,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        $instructionsPath = Join-Path $OutputPath "PatchMyPC_CustomApp_Details.txt"
        $hasOfficeZip = Test-Path -Path "$OutputPath\Office.zip"
        $hasOfficeFolder = Test-Path -Path "$OutputPath\Office"
        $fileSection = switch ($true) {
            $hasOfficeFolder { "Add Primary Install File: setup.exe`nAdd Folders: Office`nAdd Files: Configuration.xml" }
            $hasOfficeZip { "Add Primary Install File: setup.exe`nAdd Files: Office.zip, Configuration.xml" }
            default { "Add Primary Install File: setup.exe`nAdd Files: Configuration.xml" }
        }
        $notesSection = "Notes: $($CustomApp.Notes)`n"

        $deployHeader = @"
################################################
### Deploy a Custom App in Patch My PC Cloud ###
################################################
"@

        $docLink = "For more information on how to deploy any app, including a Custom app, from Patch My PC Cloud, please see:- https://docs.patchmypc.com/patch-my-pc-cloud/cloud-deployments/deploy-an-app-using-cloud"

        $baseSteps = @"
1. Sign in to the Patch My PC Cloud at https://portal.patchmypc.com
2. Find the Custom App, select it and click "Deploy"
"@

        $conflictingProcessNote = @"

NOTE: If you also want to leverage the "Conflicting processes" feature, add the processes listed in the JSON in this output folder. The entry in the JSON looks similar to the list below:-

$($CustomApp.ConflictingProcesses)
"@

        if ($hasOfficeZip) {
            $deploySection = @"
$deployHeader

When you are ready to deploy the app, you will need to add a Pre-install script to un-compress the Office source files into the ccmcache/IMECache folder during installation. The Pre-install script can only be added during deployment, not during the initial creation of the custom app. $docLink

$baseSteps
3. Click "Import" and browse to the .ps1 in this output folder named "PreScript.ps1"

=== Configurations ===
Scripts > Pre-Install > Add > Import > PreScript.ps1

4. Click "Save"
5. Complete the rest of the deployment as desired
$conflictingProcessNote
"@
        }
        else {
            $deploySection = @"
$deployHeader

$docLink

$baseSteps
3. Complete the rest of the deployment as desired
$conflictingProcessNote
"@
        }

        $instructions = @"
################################################
### Create a Custom App in Patch My PC Cloud ###
################################################

The files created in this output folder and the information below can be used to create a Custom App for Microsoft 365 Apps. For more information on how to create a custom app, please see:- https://docs.patchmypc.com/patch-my-pc-cloud/custom-apps/create-a-custom-app

1. Sign in to the Patch My PC Cloud at https://portal.patchmypc.com
2. Click "Add App"
3. Use the following values:-

=== File ===
$fileSection

=== General Information ===
App Icon: $($CustomApp.AppIcon)
App Name: $($CustomApp.AppName)
Vendor: $($CustomApp.Vendor)
Description: $($CustomApp.Description)
$notesSection
=== Configuration ===
Install Context: $($CustomApp.InstallContext)
Architecture: $($CustomApp.Architecture)-bit
Version: $($CustomApp.Version)
Language: $($CustomApp.Language)
Apps & Features Name: $($CustomApp.AppsAndFeaturesName)
Conflicting Processes: $($CustomApp.ConflictingProcesses)
Silent Install Parameters: $($CustomApp.SilentInstallParameters)

=== Detection Rules ===
Patch My PC Default (Recommended)

$deploySection
"@
        $instructions | Out-File -FilePath $instructionsPath -Encoding UTF8
        Write-LogHost ("Custom app instructions exported to: {0}" -f $instructionsPath) -ForegroundColor Green -Component $LogID
        return $instructionsPath
    }
    catch {
        Write-LogHost ("Failed to create instructions file: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $null
    }
}

#endregion

#region Patch My PC Cloud Functions

function Get-OfficeAppName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Product,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    $appName = switch -Wildcard ($Product) {
        "O365ProPlusRetail" { "Microsoft 365 Apps for Enterprise" }
        "O365ProPlusEEANoTeamsRetail" { "Microsoft 365 Apps for Enterprise (No Teams)" }
        "O365BusinessRetail" { "Microsoft 365 Apps for Business" }
        "O365BusinessEEANoTeamsRetail" { "Microsoft 365 Apps for Business (No Teams)" }
        "*2024*" { "Office 2024 Perpetual Enterprise" }
        "*2021*" { "Office 2021 Perpetual Enterprise" }
        "*2019*" { "Office 2019 Perpetual Enterprise" }
    }
    
    Write-Log ("Mapped Product ID '{0}' to app name '{1}'" -f $Product, $appName) -Component $LogID
    return $appName
}

function Get-OfficeDescription {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductID,
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    $baseDescription = "Office provides always-up-to-date versions of Word, Excel, PowerPoint, Outlook, OneNote"
    $teamsInfo = if ($ProductID -match "NoTeams" -or $AppName -match "No Teams") {
        ""
    }
    else {
        ", Teams"
    }
    $fullDescription = "$baseDescription$teamsInfo, and more. It delivers the familiar Office experience across PCs, Macs, tablets, and mobile devices with seamless access to files in OneDrive and SharePoint."
    Write-Log ("Generated description for Product ID '{0}': {1}" -f $ProductID, $fullDescription) -Component $LogID
    return $fullDescription
}

function Get-OfficeDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        [Parameter(Mandatory = $false)]
        [string]$Language,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    $baseName = $AppName -replace '\s*\(No Teams\)', ''
    $displayName = if ($Language -eq "MatchOS" -or [string]::IsNullOrEmpty($Language)) {
        "$baseName - %"
    }
    else {
        "$baseName - $Language"
    }
    
    Write-Log ("Generated Apps & Features display name: '{0}' for app '{1}' and language '{2}'" -f $displayName, $AppName, $Language) -Component $LogID
    return $displayName
}

function Get-OfficeIcon {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^https?://.+')]
        [string]$IconUrl,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    $iconPath = Join-Path $OutputPath "Microsoft.png"
    
    try {
        Write-Log ("Downloading Office icon from: {0}" -f $IconUrl) -Component $LogID
        Invoke-FileDownload -Uri $IconUrl -Destination $iconPath | Out-Null
        Write-LogHost ("Office icon downloaded to: {0}" -f $iconPath) -ForegroundColor Green -Component $LogID
        return $iconPath
    }
    catch {
        Write-LogHost ("Failed to download Office icon: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogID
        return $null
    }
}

function New-PatchMyPCCustomApp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [string]$XmlFileName,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^https?://.+')]
        [string]$IconUrl,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {

        Write-Log ("Creating Patch My PC custom app object") -Component $LogID
        $xmlPath = Join-Path $OutputPath $XmlFileName
        if (-not (Test-Path $xmlPath)) {
            throw "XML file not found at: $xmlPath"
        }
        
        [xml]$xmlData = Get-Content -Path $xmlPath -Raw
        $addNode = $xmlData.Configuration.Add
        $productNodes = @($addNode.Product)
        $productIds = $productNodes | ForEach-Object { $_.ID }
        $versions = $addNode.Version
        $channel = $addNode.Channel
        $architecture = $addNode.OfficeClientEdition

        if ($productIds -is [array]) {
            $mainAppName = Get-OfficeAppName -Product $productIds[0] -LogID $LogID
        }
        else {
            $mainAppName = Get-OfficeAppName -Product $productIds -LogID $LogID
        }
        
        $addonNames = @()
        if ($productIds.Count -gt 1) {
            $addonNames = $productIds[1..($productIds.Count - 1)]
        }
        
        $appNameStr = $mainAppName
        if ($addonNames.Count -gt 0) {
            $appNameStr += " + " + ($addonNames -join " + ")
        }
        
        $languages = $productNodes | ForEach-Object { @($_.Language) | ForEach-Object { $_.ID } }
        $languages = $languages | Where-Object { $_ } | Select-Object -Unique
        
        if (-not $languages) { 
            $languages = @("MatchOS")
        }
        
        if ($languages -is [array]) {
            $mainLang = $languages[0]
        }
        else {
            $mainLang = $languages
        }

        if ($mainLang -eq "MatchOS") {
            $mainLangDisplayName = $mainLang
        }
        else {
            $mainLangDisplayName = Get-LocaleDisplayName -LocaleCodes $mainLang -LogID $LogID
        }
        
        $notesLanguage = $null
        if ($languages.Count -gt 1) {
            $langList = $languages -join ", "
            $notesLanguage = Get-LocaleDisplayName -LocaleCodes $langList -LogID $LogID
            $notesLanguage = $notesLanguage -join ", "
        }

        $displayNameStr = Get-OfficeDisplayName -AppName $mainAppName -Language $mainLang -LogID $LogID
        Get-OfficeIcon -OutputPath $OutputPath -IconUrl $IconUrl -LogID $LogID | Out-Null

        $customApp = [PSCustomObject]@{
            AppName                 = $appNameStr
            AppIcon                 = "Microsoft.png"
            Vendor                  = "Microsoft"
            Description             = "Office provides always-up-to-date versions of Word, Excel, PowerPoint, Outlook, OneNote, and more. It delivers the familiar Office experience across PCs, Macs, tablets, and mobile devices with seamless access to files in OneDrive and SharePoint."
            Notes                   = "Product ID: $($productIds -join ', '). Office Channel: $channel"
            InstallContext          = "System"
            Architecture            = $architecture
            Version                 = $versions
            Language                = $mainLangDisplayName
            AppsAndFeaturesName     = $displayNameStr
            ConflictingProcesses    = "winword.exe,excel.exe,powerpnt.exe,msaccess.exe,mspub.exe,outlook.exe,onenote.exe"
            SilentInstallParameters = if ($XmlFileName -match '\s') { "/configure `"$XmlFileName`"" } else { "/configure $XmlFileName" }
            XmlFileName             = $XmlFileName
        }

        if ($notesLanguage) {
            $customApp.Notes += ". Additional Languages: {0}" -f $notesLanguage
        }
        if ($mainLangDisplayName -eq "MatchOS" ) {
            $customApp.Notes += ". Detection Information: As the language is set to 'MatchOS', we cannot use an exact Display Name for detection. The Apps & Features name contain a '%' wildcard to match any language."
        }

        Write-Log ("Created custom app object for Product ID(s): {0}, Version: {1}, Architecture: {2}" -f ($productIds -join ", "), $versions, $architecture) -Component $LogID
        return $customApp
    }
    catch {
        Write-LogHost ("Failed to create Patch My PC custom app object: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $null
    }
}

function Show-PatchMyPCCustomAppInfo {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CustomApp,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    Write-Host "`n========== Patch My PC Custom App Information ==========" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "=== General Tab ===" -ForegroundColor Green
    Write-Host ("App Name: {0}" -f $CustomApp.AppName)
    Write-Host ("App Icon: {0}" -f $CustomApp.AppIcon)
    Write-Host ("Vendor: {0}" -f $CustomApp.Vendor)
    Write-Host ("Description: {0}" -f $CustomApp.Description)
    Write-Host ("Notes: {0}" -f $CustomApp.Notes)
    Write-Host ""
    Write-Host "=== Configuration Tab ===" -ForegroundColor Green
    Write-Host ("Install Context: {0}" -f $CustomApp.InstallContext)
    Write-Host ("Architecture: {0}-bit" -f $CustomApp.Architecture)
    Write-Host ("Version: {0}" -f $CustomApp.Version)
    Write-Host ("Language: {0}" -f $CustomApp.Language)
    Write-Host ("Apps & Features Name: {0}" -f $CustomApp.AppsAndFeaturesName)
    Write-Host ("Conflicting Processes: {0}" -f $CustomApp.ConflictingProcesses)
    Write-Host ("Silent Install Parameters: /configure {0}" -f $CustomApp.XmlFileName)
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Export-PatchMyPCCustomAppInfo {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CustomApp,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {

        $jsonPath = Join-Path $OutputPath "PatchMyPC_CustomApp_Info.json"
        $CustomApp | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-LogHost ("Custom app JSON exported to: {0}" -f $jsonPath) -ForegroundColor Green -Component $LogID
        New-PatchMyPCInstructions -CustomApp $CustomApp -OutputPath $OutputPath -LogID $LogID
    }
    catch {
        Write-LogHost ("Failed to export custom app information: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $null
    }
}

#endregion

#region Helper Functions

function ConvertTo-CompressedString {
    param(
        $Object, 
        $MaxDepth = 5, 
        $CurrentDepth = 0
    )
    
    if ($CurrentDepth -ge $MaxDepth) { 
        return "..." 
    }

    if ($null -eq $Object) { 
        return "null" 
    }
    if ($Object -is [string]) { 
        return $Object 
    }
    if ($Object -is [array] -or $Object -is [System.Collections.IEnumerable] -and $Object -isnot [string] -and $Object -isnot [hashtable] -and $Object.GetType().Name -ne 'OrderedDictionary') { 
        $items = @()
        foreach ($item in $Object) { 
            $items += ConvertTo-CompressedString $item $MaxDepth ($CurrentDepth + 1) 
        }
        return "[{0}]" -f ($items -join ',')
    }
    if ($Object -is [hashtable] -or $Object.GetType().Name -eq 'OrderedDictionary' -or $Object -is [System.Collections.Specialized.OrderedDictionary]) {
        $items = $Object.GetEnumerator() | ForEach-Object { 
            "{0}={1}" -f $_.Key, (ConvertTo-CompressedString $_.Value $MaxDepth ($CurrentDepth + 1))
        }
        return "{{{0}}}" -f ($items -join ';')
    }
    if ($Object -is [PSCustomObject]) {
        $items = $Object.PSObject.Properties | ForEach-Object { 
            "{0}={1}" -f $_.Name, (ConvertTo-CompressedString $_.Value $MaxDepth ($CurrentDepth + 1))
        }
        return "{{{0}}}" -f ($items -join ';')
    }
    return $Object.ToString()
}

#endregion

#region Main Execution

function Invoke-Main {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$ConfigXml, 
        [Parameter(Mandatory = $true)]
        [string]$StagingDir,
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('\.log$')]
        [string]$LogFile,
        [switch]$NoZip,
        [switch]$OnlineMode,
        [switch]$SkipAPICheck,
        [int]$ApiRetryDelaySeconds = 3,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )

    # Set script-level log path variable - ensure it's absolute path
    $script:LogPath = if ([System.IO.Path]::IsPathRooted($LogFile)) { 
        $LogFile 
    }
    else { 
        Join-Path $PSScriptRoot (Split-Path $LogFile -Leaf) 
    }
    
    # Store retry parameters in script scope for use in Get-OfficeVersionInfo
    $script:ApiRetryDelaySeconds = $ApiRetryDelaySeconds
    $script:ApiMaxExtendedAttempts = $ApiMaxExtendedAttempts
    
    if ($SkipAPICheck) {
        Write-Host ("SkipAPICheck enabled - API validation will be bypassed if version exists in XML") -ForegroundColor Yellow
    }

    # Clean staging directory at script start to ensure clean slate
    if (Test-Path $StagingDir) {
        Write-LogHost ("Cleaning existing staging folder: {0}" -f $StagingDir) -Component $LogID
        try {

            # Remove all contents first, then the folder itself
            $oldProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Remove-Item -Path $StagingDir -Recurse -Force -ErrorAction Stop | Out-Null
            $ProgressPreference = $oldProgressPreference
            Write-LogHost ("Staging folder cleaned successfully") -ForegroundColor Green -Component $LogID
        }
        catch {
            $errorMsg = ("Failed to clean staging folder {0}: {1}" -f $StagingDir, $_.Exception.Message)
            Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogID
            throw $errorMsg
        }
    }

    # Log script start
    Write-Log ("Starting Invoke-M365AppsHelper script") -Component $LogID
    Write-Log ("Parameters: ConfigXml='{0}', StagingDir='{1}', OutputDir='{2}', LogFile='{3}', NoZip={4}, OnlineMode={5}, SkipAPICheck={6}" -f $ConfigXml, $StagingDir, $OutputDir, $LogFile, $NoZip, $OnlineMode, $SkipAPICheck) -Component $LogID

    # Set TLS version to TLS 1.2 for secure downloads
    try {
        Write-LogHost ("Setting the TLS version to 1.2 for secure downloads") -Component $LogID
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    }
    catch {
        throw ("Unable to set TLS version to 1.2 for downloads at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }

    # Get Office API data early for channel validation (unless we're skipping API checks)
    if (-not $SkipAPICheck) {
        try {
            Write-LogHost ("Downloading Office channel information for validation...") -Component $LogID
            $script:OfficeApiData = Get-OfficeApiData -VersionUrl $OfficeVersionUrl -StagingDir $StagingDir -RetryDelaySeconds $ApiRetryDelaySeconds -MaxExtendedAttempts $ApiMaxExtendedAttempts
            Write-Log ("Office API data cached for channel validation") -Component $LogID
        }
        catch {
            Write-Log ("Failed to download Office API data early: {0}" -f $_.Exception.Message) -Severity 2 -Component $LogID
            Write-LogHost ("Will skip early channel validation and validate during version check") -ForegroundColor Yellow -Severity 2 -Component $LogID
            $script:OfficeApiData = $null
        }
    }

    # Always resolve and parse the config FIRST, before any staging logic
    $resolvedConfig = Resolve-ConfigXml -Path $ConfigXml
    $xmlFileName = [System.IO.Path]::GetFileName($resolvedConfig)
    Write-Log ("Importing XML configuration from: {0}" -f $resolvedConfig) -Component $LogID
    
    # Validate XML structure before processing
    try {
        $xmlData = [xml](Get-Content -Path $resolvedConfig -Raw)
        
        # Basic XML structure validation
        if (-not $xmlData.Configuration) {
            throw "XML does not contain a Configuration element"
        }
        if (-not $xmlData.Configuration.Add) {
            throw "XML does not contain an Add element under Configuration"
        }
        if (-not $xmlData.Configuration.Add.Channel) {
            throw "XML does not specify a Channel in the Add element"
        }
        
        # Validate channel value
        $channelValidation = Test-OfficeChannelValid -Channel $xmlData.Configuration.Add.Channel -StagingDir $StagingDir
        if (-not $channelValidation.IsValid) {
            Write-LogHost ("Invalid channel '{0}' specified in XML" -f $xmlData.Configuration.Add.Channel) -ForegroundColor Red -Severity 3 -Component $logID
            Write-LogHost ("Valid channels are: {0}" -f ($channelValidation.ValidChannels -join ', ')) -ForegroundColor Red -Severity 2 -Component $logID
            Write-LogHost ("Please validate your XML configuration at: https://config.office.com") -ForegroundColor Red -Component $logID
            throw ("Invalid channel specified in XML: {0}" -f $xmlData.Configuration.Add.Channel)
        }
        
        Write-Log ("XML structure validation passed") -Component $LogID
    }
    catch {
        Write-LogHost ("XML configuration validation failed: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        Write-LogHost ("Please check your XML configuration at: https://config.office.com") -ForegroundColor Red -Component $LogID
        throw ("Invalid XML configuration: {0}" -f $_.Exception.Message)
    }
    
    $configInfo = Get-OfficeConfigInfo -XmlData $xmlData
    
    # Display existing XML configuration content before version testing
    Write-LogHost ("Current XML Configuration:") -ForegroundColor Green -Component $LogID
    
    # Dynamically display all properties from the configuration object
    foreach ($property in $configInfo.PSObject.Properties) {
        $displayValue = if ($null -eq $property.Value) { 
            'Not specified' 
        }
        elseif ($property.Value -is [hashtable] -or $property.Value.GetType().Name -eq 'OrderedDictionary' -or $property.Value -is [System.Collections.Specialized.OrderedDictionary]) {
            
            # Handle hash table properties
            if ($property.Value.Count -eq 0) {
                'None'
            }
            else {
                ($property.Value.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join '; '
            }
        }
        elseif ($property.Value -is [array] -or ($property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string])) {
            if ($property.Value.Count -eq 0) {
                'None'
            }
            elseif ($property.Value[0] -is [PSCustomObject]) {
                
                # Handle array of PSCustomObjects
                $items = @()
                foreach ($item in $property.Value) {
                    if ($item.ID) {
                        $items += $item.ID
                    }
                    else {
                        $items += $item.ToString()
                    }
                }
                $items -join ', '
            }
            else {

                # Handle simple arrays
                $property.Value -join ', '
            }
        }
        elseif ([string]::IsNullOrWhiteSpace($property.Value)) {
            'Not specified'
        }
        else {

            # Handle simple values
            $property.Value.ToString()
        }
        
        Write-Host ("{0}: {1}" -f $property.Name, $displayValue) -ForegroundColor Cyan
    }
    
    # Log the compressed XML configuration data for debugging
    $compressedXmlConfig = ($configInfo | ConvertTo-Json -Depth 10 -Compress)
    Write-Log ("XML Configuration (compressed): {0}" -f $compressedXmlConfig) -Component $LogID

    # Abort if the Display Level is not set to None
    $configInfo = Get-OfficeConfigInfo -XmlData $xmlData

    # Validate that Display Level is set to None for silent installation
    if ($configInfo.Display_Level -ne "None") {
        Write-LogHost ("Warning: Office installation is not configured for silent deployment") -ForegroundColor Red -Severity 3 -Component $LogID
        Write-LogHost ("Current Display Level: {0}" -f ($configInfo.Display_Level ?? "Not specified")) -ForegroundColor Yellow -Severity 2 -Component $LogID
        Write-Host ("  1. Go to https://config.office.com") -ForegroundColor Yellow
        Write-Host ("  2. Load your existing configuration") -ForegroundColor Yellow
        Write-Host ("  3. Under 'Installation preferences', toggle OFF 'Show installation to user'") -ForegroundColor Yellow
        Write-Host ("  4. This will set Display Level='None' for automated deployment") -ForegroundColor Yellow
        Write-Host ("  5. Export and use the updated XML configuration") -ForegroundColor Yellow
    
        throw "Office XML configuration error: Display Level must be set to 'None' for silent installation"
    }

    Write-LogHost ("Display Level validation passed: Silent installation configured") -ForegroundColor Green -Component $LogID

    # Your existing display code continues here...
    Write-LogHost ("Current XML Configuration:") -ForegroundColor Green -Component $LogID
    
    # Handle version management - check if XML has version, get latest online if needed
    Write-Log ("Version management: SkipAPICheck={0}, XML Version='{1}'" -f $SkipAPICheck, $configInfo.Version) -Component $LogID
    
    if ([string]::IsNullOrWhiteSpace($configInfo.Version)) {

        # No version in XML
        Write-Log ("No version found in XML configuration") -Component $LogID
        
        if ($SkipAPICheck) {

            # Cannot skip API check without a version in XML
            Write-LogHost ("SkipAPICheck requires a version to be specified in the XML configuration") -ForegroundColor Red -Severity 3 -Component $LogID
            Write-LogHost ("The XML configuration has no Version attribute in the Add node, but a version is required when skipping API validation") -ForegroundColor Red -Severity 3 -Component $LogID
            Write-LogHost ("Either remove the SkipAPICheck parameter or add a Version attribute to your XML configuration") -ForegroundColor Yellow -Severity 2 -Component $LogID
            throw "SkipAPICheck failed: No version specified in XML configuration"
        }
        
        # Get valid version to use
        $validVersion = Get-ValidOfficeVersion -Channel $configInfo.Channel -VersionUrl $OfficeVersionUrl -CurrentVersion ""
        
        if ($validVersion) {
            
            # Store the version to use in staging/output copies later
            $script:VersionToUse = $validVersion
            Write-LogHost ("Will use version: {0}" -f $validVersion) -ForegroundColor Green -Component $LogID
        }
        else {
            Write-LogHost ("Failed to get valid version information") -ForegroundColor Red -Severity 3 -Component $LogID
            if ($OnlineMode) {
                Write-LogHost ("OnlineMode requires version information but cannot connect to Office version URL." -f $configInfo.Channel) -ForegroundColor Red -Severity 3 -Component $LogID
                Write-LogHost ("Either specify a version in the XML file or ensure internet connectivity to retrieve the latest version." -f $configInfo.Channel) -ForegroundColor Red -Severity 3 -Component $LogID
                throw "OnlineMode failed: No version in XML and cannot retrieve latest version online"
            }
            else {
                Write-LogHost ("Offline mode will continue. The version will be determined from downloaded Office files" -f $configInfo.Channel) -ForegroundColor Yellow -Severity 2 -Component $LogID
            }
        }
    }
    else {

        # Version exists in XML
        Write-Log ("Version found in XML: {0}" -f $configInfo.Version) -Component $LogID
        Write-LogHost ("The Office version found in the supplied XML is: {0}. The channel specified is: {1}." -f $configInfo.Version, $configInfo.Channel) -ForegroundColor Green -Component $LogID
        
        if ($SkipAPICheck) {

            # Skip API validation and use the version from XML
            Write-LogHost ("SkipAPICheck specified - using XML version without validation: {0}" -f $configInfo.Version) -ForegroundColor Yellow -Component $LogID
            $script:VersionToUse = $configInfo.Version
        }
        else {

            # Validate the current version and get version to use
            Write-Log ("Proceeding with API validation for version: {0}" -f $configInfo.Version) -Component $LogID
            $validVersion = Get-ValidOfficeVersion -Channel $configInfo.Channel -VersionUrl $OfficeVersionUrl -CurrentVersion $configInfo.Version
            
            if ($validVersion) {

                # Store the version to use in staging/output copies
                $script:VersionToUse = $validVersion
                if ($validVersion -ne $configInfo.Version) {
                    Write-LogHost ("Will use different version: {0} (Original: {1})" -f $validVersion, $configInfo.Version) -ForegroundColor Yellow -Component $LogID
                }
            }
            else {
                Write-LogHost ("Version validation failed - could not connect to Office version URL") -ForegroundColor Red -Severity 3 -Component $LogID
                
                if ($OnlineMode) {
                    Write-LogHost ("OnlineMode: Cannot validate version {0} but will continue with existing XML version" -f $configInfo.Version) -ForegroundColor Yellow -Severity 2 -Component $LogID
                    Write-LogHost ("WARNING: Version {0} may not be available or valid for deployment" -f $configInfo.Version) -ForegroundColor Yellow -Severity 2 -Component $LogID
                    $script:VersionToUse = $configInfo.Version
                }
                else {
                    Write-LogHost ("Offline mode will continue. The version will be validated during Office file download." -f $configInfo.Channel) -ForegroundColor Yellow -Severity 2 -Component $LogID
                    $script:VersionToUse = $configInfo.Version
                }
            }
        }
    }
    
    # If in OnlineMode, create output package with setup.exe and XML, then exit
    if ($OnlineMode) {
        Write-LogHost ("OnlineMode: Version check completed. Creating staging files before output package.") -ForegroundColor Green -Component $LogID
        
        # Use the staging directory for OnlineMode files (consistent with OfflineMode)
        New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
        $stagingDirectory = (Resolve-Path $StagingDir).Path
        $stagingSetupPath = Join-Path $stagingDirectory "setup.exe"
        $stagingConfigPath = Join-Path $stagingDirectory $xmlFileName

        # Download setup.exe to staging folder
        Write-LogHost ("Downloading setup.exe to staging folder...") -Component $LogID
        Invoke-FileDownload -Uri $SetupUrl -Destination $stagingSetupPath | Out-Null

        # Copy configuration XML to staging folder (preserve original name)
        Copy-Item -Path $resolvedConfig -Destination $stagingConfigPath -Force
        Write-LogHost ("Copied configuration XML to staging directory") -ForegroundColor Green -Component $LogID

        # Update the staging XML with the validated/selected version if needed
        if ($script:VersionToUse -and (Test-Path $stagingConfigPath)) {
            $null = Update-XmlVersion -XmlPath $stagingConfigPath -Version $script:VersionToUse
        }

        # Create output directory structure for OnlineMode
        $buildVersionSuffix = if ($script:VersionToUse) {
            "_build-{0}" -f $script:VersionToUse.Replace('.', '')
        }
        else {
            "_buildUnknown"
        }
        
        $baseFolderName = "OnlineMode{0}" -f $buildVersionSuffix
        
        # Handle name clashes with incremental numbering
        $sessionFolderName = $baseFolderName
        $counter = 1
        $outputRootDir = if ($OutputDir) { 
            (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path ?? (New-Item -ItemType Directory -Path $OutputDir -Force).FullName
        }
        else { 
            Join-Path $PSScriptRoot "Output" 
        }
        
        while (Test-Path (Join-Path $outputRootDir $sessionFolderName)) {
            $sessionFolderName = "{0}_{1}" -f $baseFolderName, $counter
            $counter++
        }
        
        $outputRootDir = if ($OutputDir) { 
            (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path ?? (New-Item -ItemType Directory -Path $OutputDir -Force).FullName
        }
        else { 
            Join-Path $PSScriptRoot "Output" 
        }
        if (-not (Test-Path $outputRootDir)) {
            New-Item -ItemType Directory -Path $outputRootDir -Force | Out-Null
        }
        $sessionPath = Join-Path $outputRootDir $sessionFolderName
        
        # Create the final output folder
        New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
        Write-LogHost ("Created OnlineMode output folder: {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
        
        # Copy setup.exe and XML from staging to output folder
        $outputSetupPath = Join-Path $sessionPath "setup.exe"
        $outputConfigPath = Join-Path $sessionPath $OutputConfigName
        Copy-Item -Path $stagingSetupPath -Destination $outputSetupPath -Force
        Copy-Item -Path $stagingConfigPath -Destination $outputConfigPath -Force
        Write-LogHost ("Copied setup.exe and $OutputConfigName from staging to output folder") -ForegroundColor Green -Component $LogId
        
        # Log the actual package contents
        $actualFileNames = $actualFiles | ForEach-Object { $_.Name }
        $packageContentsCompressed = $actualFileNames -join ';'
        Write-Log ("OnlineMode Package Contents (actual): {0}" -f $packageContentsCompressed) -Component $LogId
        
        Write-LogHost ("OnlineMode package ready at: {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
        
        # Actually scan the output folder to see what files are there
        $actualFiles = Get-ChildItem -Path $sessionPath -File | Sort-Object Name
        Write-Host "OnlineMode package contains:" -ForegroundColor Green
        
        foreach ($file in $actualFiles) {
            $description = switch ($file.Name) {
                "setup.exe" { "setup.exe" }
                "Configuration.xml" { "Configuration.xml (with validated/updated version)" }
                "Microsoft.png" { "Microsoft.png (app icon to use for Patch My PC custom app)" }
                "PatchMyPC_CustomApp_Info.json" { "PatchMyPC_CustomApp_Info.json (custom app metadata)" }
                "PatchMyPC_CustomApp_Details.txt" { "PatchMyPC_CustomApp_Details.txt (usage instructions)" }
                default { $file.Name }
            }
            Write-Host ("  {0}" -f $description) -ForegroundColor Cyan
        }

        # Generate Patch My PC Cloud custom app information for OnlineMode
        Write-Host ""
        Write-LogHost ("Generating Patch My PC custom app information...") -ForegroundColor Yellow -Component $LogID
        $customApp = New-PatchMyPCCustomApp -OutputPath $sessionPath -XmlFileName $OutputConfigName -IconUrl $OfficeIconUrl -LogID $LogID

        if ($customApp) {

            # Export custom app information
            Export-PatchMyPCCustomAppInfo -CustomApp $customApp -OutputPath $sessionPath -LogID $LogID
            
            # Display custom app information to console
            Show-PatchMyPCCustomAppInfo -CustomApp $customApp -LogID $LogID
        }

        # Script completion summary
        Write-LogHost ("Script completed successfully - M365 Office deployment package created at {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId

        return
    }

    # Create compressed object structure for log
    $objectStructure = "ConfigInfo={0}" -f (ConvertTo-CompressedString $configInfo)
    Write-Log ("Parsed XML object structure: {0}" -f $objectStructure) -Component $LogID

    # Use the staging directory directly for downloads
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
    $downloadDirectory = (Resolve-Path $StagingDir).Path
    $setupPath = Join-Path $downloadDirectory "setup.exe"
    $configCopy = Join-Path $downloadDirectory $xmlFileName

    Write-LogHost ("Downloading setup.exe to {0}" -f $setupPath) -Component $LogID
    Invoke-FileDownload -Uri $SetupUrl -Destination $setupPath | Out-Null

    Copy-Item -Path $resolvedConfig -Destination $configCopy -Force
    Write-LogHost ("Copied configuration XML to staging directory") -ForegroundColor Green -Component $LogID

    # Update the staging XML with the validated/selected version BEFORE download
    if ($script:VersionToUse -and (Test-Path $configCopy)) {
        $updateResult = Update-XmlVersion -XmlPath $configCopy -Version $script:VersionToUse
        if ($updateResult) {

            # Success message already shown by Update-XmlVersion function
        }
        else {
            Write-LogHost ("Failed to update staging XML with validated version") -ForegroundColor Red -Severity 3 -Component $LogID
            throw "Failed to update staging XML configuration before download"
        }
    }
    
    # Display the XML contents that will be used for download and verify the update worked
    try {
        $configForDownload = [xml](Get-Content -Path $configCopy -Raw)
        $channelInXml = $configForDownload.Configuration.Add.Channel
        $versionInXml = $configForDownload.Configuration.Add.Version
        Write-LogHost ("XML being used for download - Channel: {0}, Version: {1}" -f $channelInXml, $versionInXml) -ForegroundColor Green -Component $LogID
        
        # Verify the version was actually updated if we expected it to be
        if ($script:VersionToUse -and $versionInXml -ne $script:VersionToUse) {
            Write-LogHost ("WARNING: XML version verification failed - expected {0} but got {1}" -f $script:VersionToUse, $versionInXml) -ForegroundColor Red -Severity 3 -Component $LogID
            Write-LogHost ("This may indicate an XML update failure or file access issue") -ForegroundColor Yellow -Severity 2 -Component $LogID
            throw "XML version verification failed after update"
        }
    }
    catch {
        Write-Log ("Failed to read staging XML for validation: {0}" -f $_.Exception.Message) -Severity 2 -Component $LogID
    }
    
    Write-LogHost ("Downloading Office files...") -Component $LogID
    $downloadSize = Start-OfficeDownload -SetupPath $setupPath -WorkingDir $downloadDirectory -ConfigPath $configCopy
    Write-LogHost ("Office files downloaded successfully. {0} payload." -f $downloadSize) -ForegroundColor Green -Component $LogID

    $buildNumber = Get-OfficeBuildFromCabs -Root $downloadDirectory
    if ($buildNumber) { 
        Write-LogHost ("Office build number obtained from cab: {0}" -f $buildNumber) -ForegroundColor Green -Component $LogID
    } 
    else { 
        Write-LogHost ("Exact build not found") -ForegroundColor Yellow -Severity 2 -Component $LogID
    }

    # Create the properly named folder with build version and determine mode suffix based on compression
    $modeSuffix = if ($NoZip) { 
        "OfflineMode" 
    }
    else { 
        "OfflineModeCompressed"
    }

    # Get build version for folder name
    $buildVersionSuffix = if ($buildNumber) { 
        "_build-{0}" -f $buildNumber.Replace('.', '') 
    }
    elseif ($script:VersionToUse) {
        "_build-{0}" -f $script:VersionToUse.Replace('.', '')
    }
    else {
        "_buildUnknown"
    }
    
    # Base folder name without timestamp
    $baseFolderName = "{0}{1}" -f $modeSuffix, $buildVersionSuffix
    
    # Handle name clashes with incremental numbering
    $sessionFolderName = $baseFolderName
    $counter = 1
    $outputRootDir = if ($OutputDir) { 
        (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path ?? (New-Item -ItemType Directory -Path $OutputDir -Force).FullName
    }
    else { 
        Join-Path $PSScriptRoot "Output" 
    }
    
    while (Test-Path (Join-Path $outputRootDir $sessionFolderName)) {
        $sessionFolderName = "{0}_{1}" -f $baseFolderName, $counter
        $counter++
    }
    
    # Create the final output folder regardless of Zip option
    $outputRootDir = if ($OutputDir) { 
        (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path ?? (New-Item -ItemType Directory -Path $OutputDir -Force).FullName
    }
    else { 
        Join-Path $PSScriptRoot "Output" 
    }
    if (-not (Test-Path $outputRootDir)) {
        New-Item -ItemType Directory -Path $outputRootDir -Force | Out-Null
    }
    $sessionPath = Join-Path $outputRootDir $sessionFolderName
    
    # Create the final output folder
    New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
    Write-LogHost ("Created output folder: {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
    
    # Always copy setup.exe and configuration XML to output folder
    $outputSetupPath = Join-Path $sessionPath "setup.exe"
    $outputConfigPath = Join-Path $sessionPath $xmlFileName
    Copy-Item -Path $setupPath -Destination $outputSetupPath -Force
    Copy-Item -Path $configCopy -Destination $outputConfigPath -Force
    
    Write-LogHost ("Copied setup.exe and $xmlFileName to output folder") -ForegroundColor Green -Component $LogId

    # Zip creation logic
    if (-not $NoZip) {
        Write-LogHost ("Starting Zip creation process") -Component $LogId
        try {

            # Create Zip file directly in the output folder - include only the Office folder
            $zipPath = Join-Path $sessionPath "Office.zip"
            $sourceOfficeDir = Join-Path $downloadDirectory "Office"
            
            if (Test-Path $zipPath) {
                $oldProgressPreference = $ProgressPreference
                $ProgressPreference = 'SilentlyContinue'
                Remove-Item -Path $zipPath -Force | Out-Null
                $ProgressPreference = $oldProgressPreference
            }
            
            if (-not (Test-Path $sourceOfficeDir)) {
                $errorMsg = ("Office folder not found at {0}" -f $sourceOfficeDir)
                Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogId
                throw $errorMsg
            }
            
            # Check Office folder contents before zipping
            $officeFiles = Get-ChildItem -Path $sourceOfficeDir -Recurse -File -ErrorAction SilentlyContinue
            Write-LogHost ("Office folder contains {0} files before zipping" -f $officeFiles.Count) -ForegroundColor Green -Component $LogId
            
            if ($officeFiles.Count -eq 0) {
                Write-LogHost ("ERROR: Office folder is empty - cannot create zip from empty directory" -f $sourceOfficeDir) -ForegroundColor Red -Severity 3 -Component $LogId
                Write-LogHost ("Office folder path: {0}" -f $sourceOfficeDir) -ForegroundColor Yellow -Severity 2 -Component $LogId
                
                # List what's actually in the download directory
                $downloadContents = Get-ChildItem -Path $downloadDirectory -Recurse -ErrorAction SilentlyContinue
                Write-LogHost ("Download directory contents ({0} items):" -f $downloadContents.Count) -ForegroundColor Yellow -Component $LogId
                foreach ($item in $downloadContents | Select-Object -First 10) {
                    Write-LogHost ("  {0} - {1}" -f $item.Name, $item.GetType().Name) -ForegroundColor Cyan -Component $LogId
                }
                
                throw "Office folder is empty - zip creation aborted"
            }
            
            # Create a temporary directory to stage just the Office folder for zipping
            $tempZipStaging = Join-Path $downloadDirectory "TempZipStaging"
            if (Test-Path $tempZipStaging) {            
                $oldProgressPreference = $ProgressPreference
                $ProgressPreference = 'SilentlyContinue'
                Remove-Item -Path $tempZipStaging -Recurse -Force | Out-Null
                $ProgressPreference = $oldProgressPreference
            }
            New-Item -ItemType Directory -Path $tempZipStaging -Force | Out-Null
            
            # Copy only the Office folder to the temp staging area
            $tempOfficeDir = Join-Path $tempZipStaging "Office"
            Copy-Item -Path $sourceOfficeDir -Destination $tempOfficeDir -Recurse -Force
            
            # Zip from the temp staging directory so Office folder structure is preserved
            $createdZip = New-ZipFromDirectory -SourcePath $tempZipStaging -ZipPath $zipPath
            
            # Show what's inside the Zip file BEFORE deleting temp staging
            $zipContents = Get-ZipContents -ZipPath $zipPath -SourcePath $sessionPath
            $zipContentsCompressed = ($zipContents | ForEach-Object { $_.Trim() }) -join ';'
            Write-Log ("Zip Contents: {0}" -f $zipContentsCompressed) -Component $LogId
            
            # Clean up temp staging directory
            $oldProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Remove-Item -Path $tempZipStaging -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            $ProgressPreference = $oldProgressPreference
        
            # Did we actually create the Zip file?
            if (Test-Path -Path $createdZip) {
                $zipInfo = Get-Item -Path $createdZip
                $zipSize = Format-Size -Bytes $zipInfo.Length
                Write-LogHost ("Created Zip file: {0} ({1})" -f (Split-Path $createdZip -Leaf), $zipSize) -ForegroundColor Green -Component $LogId
                
                # Generate PreScript.ps1 for Zip extraction
                New-PreScript -OutputPath $sessionPath
                
            }
            else {
                $errorMsg = ("Zip file was not created after creation")
                Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogId
                throw $errorMsg
            }

            Write-LogHost ("Output package ready at: {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
            
            # Actually scan the output folder to see what files are there
            $actualFiles = Get-ChildItem -Path $sessionPath -File | Sort-Object Name
            Write-Host "OfflineMode compressed package contains:" -ForegroundColor Green
            foreach ($file in $actualFiles) {
                $description = switch ($file.Name) {
                    "Office.zip" { "Office.zip (Office installation files)" }
                    "setup.exe" { "setup.exe" }
                    "Configuration.xml" { "Configuration.xml" }
                    "PreScript.ps1" { "PreScript.ps1 (zip extraction utility)" }
                    "Microsoft.png" { "Microsoft.png (app icon for Patch My PC custom app)" }
                    "PatchMyPC_CustomApp_Info.json" { "PatchMyPC_CustomApp_Info.json (custom app metadata)" }
                    "PatchMyPC_CustomApp_Details.txt" { "PatchMyPC_CustomApp_Details.txt (usage instructions)" }
                    default { $file.Name }
                }
                Write-Host ("  {0}" -f $description) -ForegroundColor Cyan
            }
            
            # Show what's inside the Zip file
            $zipContents = Get-ZipContents -ZipPath $zipPath -SourcePath $sessionPath
            $zipContentsCompressed = ($zipContents | ForEach-Object { $_.Trim() }) -join ';'
            Write-Log ("Zip Contents: {0}" -f $zipContentsCompressed) -Component $LogId
            
            # Display contents to console with formatting
            Write-Host "Zip Contents:" -ForegroundColor Green
            foreach ($file in $zipContents) {
                Write-Host $file -ForegroundColor Cyan
            }
            
            # Generate Patch My PC Cloud custom app information
            Write-Host ""
            Write-LogHost ("Generating Patch My PC custom app information...") -Component $LogId
            $customApp = New-PatchMyPCCustomApp -OutputPath $sessionPath -XmlFileName $xmlFileName -IconUrl $OfficeIconUrl -LogID $LogID
    
            if ($customApp) {

                # Export custom app information
                Export-PatchMyPCCustomAppInfo -CustomApp $customApp -OutputPath $sessionPath -LogID $LogID

                # Log the compressed custom app info
                $compressedCustomApp = $customApp | ConvertTo-Json -Depth 3 -Compress
                Write-Log ("Patch My PC Custom App Info: {0}" -f $compressedCustomApp) -Component $LogId
            }
            else {
                Write-LogHost ("Failed to generate Patch My PC custom app information") -ForegroundColor Yellow -Severity 2 -Component $LogId
            }
        
            # Display Patch My PC custom app information right before completion
            if ($customApp) {
                Show-PatchMyPCCustomAppInfo -CustomApp $customApp -LogID $LogId
            }
            
            # Script completion summary
            Write-LogHost ("Script completed successfully - M365 Office deployment package created with zip compression at {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
        }
        catch {
            $errorMsg = ("Zip creation failed: {0}" -f $_.Exception.Message)
            Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogId
            throw $errorMsg
        }
    }
    else {

        # Copy Office folder directly to output (no Zip compression)
        Write-LogHost ("Copying Office files to output folder (no Zip compression)...") -Component $LogId
        $sourceOfficeDir = Join-Path $downloadDirectory "Office"
        $outputOfficeDir = Join-Path $sessionPath "Office"
        
        if (Test-Path $sourceOfficeDir) {
            Copy-Item -Path $sourceOfficeDir -Destination $outputOfficeDir -Recurse -Force
            Write-LogHost ("Office files copied to: {0}" -f $outputOfficeDir) -ForegroundColor Green -Component $LogId
        }
        
        Write-LogHost ("Package ready at: {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
        
        # Actually scan the output folder to see what files and folders are there
        $actualFiles = Get-ChildItem -Path $sessionPath -File | Sort-Object Name
        
        # Combine files and folders for logging
        $allItems = @()
        $allItems += ($actualFiles | ForEach-Object { $_.Name })
        $packageContentsCompressed = $allItems -join ';'
        Write-Log ("OfflineMode Uncompressed Package Contents (actual): {0}" -f $packageContentsCompressed) -Component $LogId
        
        # Display actual package contents to console with formatting
        Write-Host "OfflineMode uncompressed package contains:" -ForegroundColor Green
        foreach ($file in $actualFiles) {
            $description = switch ($file.Name) {
                "setup.exe" { "setup.exe" }
                "Configuration.xml" { "Configuration.xml" }
                "Microsoft.png" { "Microsoft.png (app icon for Patch My PC custom app)" }
                "PatchMyPC_CustomApp_Info.json" { "PatchMyPC_CustomApp_Info.json (custom app metadata)" }
                "PatchMyPC_CustomApp_Details.txt" { "PatchMyPC_CustomApp_Details.txt (usage instructions)" }
                default { $file.Name }
            }
            Write-Host ("{0}" -f $description) -ForegroundColor Cyan
        }
        
        # Show the actual Office folder structure
        if (Test-Path $outputOfficeDir) {
            $officeContents = Get-ChildItem -Path $outputOfficeDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 15
            $officeFilesList = @()

            foreach ($file in $officeContents) {
                $relativePath = $file.FullName.Replace($sessionPath, '').TrimStart('\')
                $officeFilesList += "    $relativePath"
            }
            $officeContentsCompressed = ($officeFilesList | ForEach-Object { $_.Trim() }) -join ';'
            Write-Log ("Office Folder Contents: {0}" -f $officeContentsCompressed) -Component $LogId
            
            # Display contents to console with formatting
            foreach ($file in $officeContents) {
                $relativePath = $file.FullName.Replace($sessionPath, '').TrimStart('\')
                Write-Host "    $relativePath" -ForegroundColor Cyan
            }
        }
        else {
            Write-LogHost ("Office folder not found in {0}" -f $outputOfficeDir) -ForegroundColor Cyan -Severity 2 -Component $LogId
        }

        # Generate Patch My PC Cloud custom app information
        Write-Host ""
        Write-LogHost ("Generating Patch My PC custom app information...") -Component $LogId
        $customApp = New-PatchMyPCCustomApp -OutputPath $sessionPath -XmlFileName $xmlFileName -IconUrl $OfficeIconUrl -LogID $LogId
    
        if ($customApp) {

            # Export custom app information
            Export-PatchMyPCCustomAppInfo -CustomApp $customApp -OutputPath $sessionPath -LogID $LogId

            # Log the compressed custom app info
            $compressedCustomApp = $customApp | ConvertTo-Json -Depth 3 -Compress
            Write-Log ("Patch My PC Custom App Info: {0}" -f $compressedCustomApp) -Component $LogId
        }
        else {
            Write-LogHost ("Failed to generate Patch My PC custom app information") -ForegroundColor Yellow -Severity 2 -Component $LogId
        }
        
        # Display Patch My PC custom app information right before completion
        if ($customApp) {
            Show-PatchMyPCCustomAppInfo -CustomApp $customApp -LogID $LogId
        }
        
        # Script completion summary
        Write-LogHost ("Script completed successfully - M365 Office deployment package created without zip compression at {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId

    }
}

#endregion

#region Script Execution

try { 
    Invoke-Main -ConfigXml $ConfigXML -StagingDir $DownloadPath -OutputDir $OutputPath -LogFile $LogName -NoZip:$NoZip -OnlineMode:$OnlineMode -SkipAPICheck:$SkipAPICheck -ApiRetryDelaySeconds $ApiRetryDelaySeconds
}
catch { 
    $logID = "ScriptExecution"
    Write-Host ""

    Write-LogHost "SCRIPT FAILED" -ForegroundColor Red -Component $logID
    Write-LogHost ("M365 Office deployment package creation failed. {0}" -f $_.Exception.Message) -ForegroundColor Red -Component $logID
    
    # So, what went wrong :(
    if ($_.InvocationInfo.ScriptLineNumber) {
        Write-LogHost ("Error at line {0} in {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.ScriptName) -ForegroundColor Red -Component $logID
    }
    if ($_.ScriptStackTrace) {
        Write-Log ("Stack trace: {0}" -f $_.ScriptStackTrace) -Severity 3 -Component $logID
    }
    
    # Specific guidance for exit code 400
    if ($_.Exception.Message -match "exit code 400") {
        Write-LogHost "EXIT CODE 400 indicates an invalid Office configuration." -ForegroundColor Yellow -Severity 2 -Component $logID
        Write-LogHost "This typically means:" -ForegroundColor Yellow -Severity 2 -Component $logID
        Write-LogHost "  - The version specified in XML is invalid for the selected channel" -ForegroundColor Yellow -Severity 2 -Component $logID
        Write-LogHost "  - The channel name is incorrect" -ForegroundColor Yellow -Severity 2 -Component $logID
        Write-LogHost "  - Network connectivity issues" -ForegroundColor Yellow -Severity 2 -Component $logID
        Write-LogHost "Try running with version validation enabled (remove -SkipAPICheck if used)" -ForegroundColor Cyan -Component $logID
    }
    
    exit 1
}

#endregion