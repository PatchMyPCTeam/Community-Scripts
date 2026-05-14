<#
.Synopsis
Created on:   07/09/2025
Updated on:   14/05/2026
Created by:   Ben Whitmore@PatchMyPC
Filename:     Invoke-M365AppsHelper.ps1
Version:      1.0.2

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
PowerShell 7 or later is required to run this script.
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

.PARAMETER BasePath
Root path for all script operations (Packages, Downloads, Logs subdirectories).
If not specified the script will choose a sensible per-user default depending on the platform:
- Windows: "%APPDATA%\M365AppsHelper" (preferred when %APPDATA% is available)
- macOS: "~/Documents/M365AppsHelper" (visible per-user folder; used when no BasePath is supplied)

The script will create the required subfolders under this path (Packages, Downloads, Logs). If the path is not writable or cannot be created the script will error. You can override the default by supplying `-BasePath` with any writable path. All output, temporary files, and logs will be organized under this base directory.

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
Switch to create a package without downloading Office data files. When enabled, the package contains only setup.exe and configuration files (~200MB). When disabled, the full Office data files are downloaded and included (~3-4GB). 
Unchecked mode requires the Office files to be downloaded during execution, significantly increasing package time and storage requirements.
Checked mode requires version validation via the Office version API. OnlineMode requires API access to validate or retrieve Office versions from the configured OfficeVersionUrl. OnlineMode cannot be used together with -NoZip or -SkipAPICheck (these combinations will be rejected by the script).

.PARAMETER SkipAPICheck
Switch parameter to skip the Office version API validation. Only works if a version is already specified in the XML configuration.
Use this when performing rapid testing with a pre-validated Office channel and version.
Warning: Skipping validation may result in download failures if the version is invalid.
Note: -SkipAPICheck cannot be used with -OnlineMode. If -SkipAPICheck is supplied but the XML does not contain a Version element, the script will fail.

.PARAMETER Win32ContentPrepToolUrl
URL to download the Microsoft Win32 Content Prep Tool (IntuneWinAppUtil.exe). Used when creating an Intune Win32 package.

.PARAMETER CreateIntuneWin
Switch to create a .intunewin package for Win32 app deployment using the Microsoft Win32 Content Prep Tool. Cannot be used with the NoZip parameter. Can be used with OnlineMode to generate Intune-ready packages without downloading full Office content.

Important: Creating a .intunewin requires the Microsoft Win32 Content Prep Tool (IntuneWinAppUtil.exe), which is a Windows executable. This operation must be performed on a Windows host (Windows Server/Windows 10/11). When running on non-Windows hosts (macOS/Linux) the script will disable CreateIntuneWin and log a warning; it cannot create .intunewin files on macOS/Linux. CreateIntuneWin is also mutually exclusive with -PMPCCustomApp and with -NoZip. If not explicitly supplied on a Windows host and -PMPCCustomApp is not used, the script may enable CreateIntuneWin by default.

.PARAMETER ApiRetryDelaySeconds
Delay in seconds between API retry attempts. Defaults to 3 seconds.
Increase this value if experiencing rate limiting or network latency issues.
Range: 1-30 seconds.

.PARAMETER ApiMaxExtendedAttempts
Maximum number of retry attempts for the Office version API call. Defaults to 10 attempts.
The script uses intelligent retry logic to ensure complete version data retrieval.
Range: 1-20 attempts.

.EXAMPLE
This command generates a Microsoft 365 Apps deployment package in Online Mode using the specified configuration XML.
The package will include setup.exe and configuration files but will not download the full Office content, resulting in a smaller package size (~200MB). 
The script will validate the Office version specified in the XML against Microsoft's REST API to ensure it is valid before creating the package.

.\Invoke-M365AppsHelper.ps1 -ConfigXML "C:\Configs\Enterprise-Office365.xml" -OnlineMode

.EXAMPLE
This command generates a Microsoft 365 Apps deployment package in Offline Mode using the specified configuration XML.
The package will include setup.exe, configuration files and will download and compress the full Office content, resulting in a larger package size (~4GB). 
The script will validate the Office version specified in the XML against Microsoft's REST API to ensure it is valid before creating the package.
A pre-script will be generated to handle the extraction of Office files from the compressed archive during deployment.

.\Invoke-M365AppsHelper.ps1 -ConfigXML "C:\Configs\Enterprise-Office365.xml"
#>

param(
    [string]$ConfigXML,
    [string]$BasePath,
    [ValidatePattern('^https?://.+')]
    [string]$SetupUrl = "https://officecdn.microsoft.com/pr/wsus/setup.exe",
    [ValidatePattern('^https?://.+')]
    [string]$OfficeVersionUrl = "https://clients.config.office.net/releases/v1.0/OfficeReleases",
    [ValidatePattern('^https?://.+')]
    [string]$OfficeIconUrl = "https://www.svgrepo.com/show/452062/microsoft.svg",
    [ValidatePattern('(?i)\.log$')]
    [string]$LogName = "Invoke-M365AppsHelper.log",
    [ValidatePattern('^https?://.+')]
    [string]$Win32ContentPrepToolUrl = "https://raw.githubusercontent.com/microsoft/Microsoft-Win32-Content-Prep-Tool/master/IntuneWinAppUtil.exe",
    [switch]$CreateIntuneWin,
    [switch]$NoZip,
    [switch]$OnlineMode,
    [switch]$SkipAPICheck,
    [switch]$PMPCCustomApp = $true,
    [ValidateRange(1, 30)]
    [int]$ApiRetryDelaySeconds = 3,
    [ValidateRange(1, 20)]
    [int]$ApiMaxExtendedAttempts = 10
)

# Initialize BasePath
if (-not $BasePath -or [string]::IsNullOrWhiteSpace($BasePath)) {
    if ($env:APPDATA -and -not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        $BasePath = Join-Path $env:APPDATA 'M365AppsHelper'
    }
    else {
        # macOS: use ~/Documents
        $BasePath = Join-Path (Join-Path $HOME 'Documents') 'M365AppsHelper'
    }
}

# Initialize folders
$OutputPath = Join-Path $BasePath 'Packages'
$DownloadPath = Join-Path $BasePath 'Downloads'
$LogFolder = Join-Path $BasePath 'Logs'

foreach ($path in @($BasePath, $OutputPath, $DownloadPath, $LogFolder)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error ("Failed to create required path {0}: {1}" -f $path, $_.Exception.Message)
            exit 1
        }
    }
}

# Default config names
$defaultConfigNames = @("install", "uninstall")
$script:DefaultInstallConfigName = "{0}.xml" -f $defaultConfigNames[0]
$script:DefaultUninstallConfigName = "{0}.xml" -f $defaultConfigNames[1]

# Default install config name
$OutputConfigName = $script:DefaultInstallConfigName

if ([string]::IsNullOrWhiteSpace($LogName)) {
    $LogName = 'Invoke-M365AppsHelper.log'
}
$LogName = Join-Path $LogFolder (Split-Path $LogName -Leaf)
$resolvedLog = Resolve-Path $LogName -ErrorAction SilentlyContinue
if ($resolvedLog) {
    $LogName = $resolvedLog.Path
}
else {
    $LogName = Join-Path $LogFolder (Split-Path $LogName -Leaf)
}
$script:LogPath = $LogName
$script:DownloadPath = $DownloadPath


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

    $resolvedLogDir = Resolve-Path $logDir -ErrorAction SilentlyContinue
    if ($resolvedLogDir) {
        $LogFile = $resolvedLogDir.Path
    }
    else {
        $LogFile = (New-Item -ItemType Directory -Path $logDir -Force).FullName
    }
    $LogFile = Join-Path $LogFile (Split-Path $script:LogPath -Leaf)

    $time = Get-Date -Format "HH:mm:ss.ffffff"
    $date = Get-Date -Format "MM-dd-yyyy"

    try {
        $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        try { $context = [System.Environment]::UserName } catch { $context = $env:USER -or $env:USERNAME -or 'Unknown' }
    }

    $logEntry = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$Component`" context=`"$context`" type=`"$Severity`" thread=`"$PID`" file=```">"
    
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
    
    $autoHighlightPattern = '(?i)\b(Channel|Version|Product|Language|OfficeClientEdition|ExcludedApps|Display_Level|Display_AcceptEULA|Apps\s*&\s*Features|Silent\s*Install\s*Parameters)\b'
    if ($ForegroundColor -eq 'White' -and ($Message -match $autoHighlightPattern)) {
        $ForegroundColor = 'Cyan'
    }

    Write-Host $Message -ForegroundColor $ForegroundColor
}

if ($CreateIntuneWin -and $PMPCCustomApp) {

    $script:LogPath = $LogName
    $logID = "ParameterValidation"
    
    Write-LogHost "Error: CreateIntuneWin and PMPCCustomApp parameters cannot be used together." -ForegroundColor Red -Severity 3 -Component $logID
    Write-LogHost "Note: CreateIntuneWin is for Intune Win32 deployments, while PMPCCustomApp is for Patch My PC Cloud. These are mutually exclusive deployment methods." -ForegroundColor Yellow -Severity 2 -Component $logID
    exit 1
}

if ($OnlineMode -and $SkipAPICheck) {

    $script:LogPath = $LogName
    $logID = "ParameterValidation"
    
    Write-LogHost "Error: OnlineMode and SkipAPICheck parameters cannot be used together." -ForegroundColor Red -Severity 3 -Component $logID
    Write-LogHost "Note: OnlineMode requires API access to validate/retrieve Office versions, but SkipAPICheck bypasses all API calls." -ForegroundColor Yellow -Severity 2 -Component $logID
    exit 1
}


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
        "lv-LV" = "Latvian"; "lt-LT" = "Lithuanian"; "ms-MY" = "Malay"; "nb-NO" = "Norwegian BokmÃ¥l"; "pl-PL" = "Polish"; "pt-BR" = "Portuguese (Brazil)"
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

    # Convert collections to arrays
    $configResult = [PSCustomObject]@{
        Channel      = $configChannel
        Version      = $configVersion
        Products     = $products.ToArray()
        Languages    = @($languages | ForEach-Object { $_ })
        ExcludedApps = @($excludedApps | ForEach-Object { $_ })
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

    # Build full log path
    $fullLogPath = Join-Path $LogPath $LogName

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

    # Compose CMTrace log entry
    $time = Get-Date -Format "HH:mm:ss.ffffff"
    $date = Get-Date -Format "MM-dd-yyyy"
    # Get user context (cross-platform)
    try {
        $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        try { $context = [System.Environment]::UserName } catch { $context = $env:USER -or $env:USERNAME -or 'Unknown' }
    }

    $logEntry = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$Component`" context=`"$context`" type=`"$Severity`" thread=`"$PID`" file=```">"
    
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

# Main execution entry
try {
    $currentDir = Get-Location
    
    Write-Log ("Starting zip file extraction")
    Write-Log ("Current directory: {0}" -f $currentDir)
    Write-Log ("PowerShell version: {0}" -f $PSVersionTable.PSVersion)
    
    if ($Name) {
# Use specified zip if provided
        $zipFile = Join-Path $currentDir $Name
        Write-Log ("Using explicitly specified zip file: {0}" -f $Name)
        
        if (-not (Test-Path $zipFile)) {
            Write-Log ("Specified zip file not found: {0}" -f $Name) -Severity 3
            throw ("Specified zip file not found: {0}" -f $Name)
        }
        
        $ZipFileName = $Name
    }
    else {
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
    
    # Extract zip contents
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


function New-DetectionScriptContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,
        [Parameter(Mandatory = $true)]
        [string]$Version
    )
    
    return @"
<#
.SYNOPSIS
    Detects Microsoft Office installation based on registry entries.

.DESCRIPTION
    This script searches the Windows registry for Office installations matching
    the specified DisplayName and verifies the installed version meets minimum requirements.
    Returns exit code 0 if detected, 1 if not detected.

.NOTES
    Detection Method: Registry-based
    DisplayName: $DisplayName
    Minimum Version: $Version
#>

`$displayName = "$DisplayName"
`$minVersion = [version]"$Version"

# Registry paths to check for installed apps
`$registryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

try {
    `$found = `$false
    
    foreach (`$path in `$registryPaths) {
        `$items = Get-ItemProperty -Path `$path -ErrorAction SilentlyContinue | Where-Object { `$_.DisplayName }
        
        foreach (`$item in `$items) {
            # Match DisplayName (supports % wildcard)
            `$nameMatch = if (`$displayName -match '%') {
                `$pattern = '^' + [regex]::Escape(`$displayName).Replace('%', '.*') + '$'
                `$item.DisplayName -match `$pattern
            }
            else {
                `$item.DisplayName -eq `$displayName
            }
            
            if (`$nameMatch) {
                # Parse version
                `$installedVersionStr = `$item.DisplayVersion
                if (`$installedVersionStr) {
                    try {
                        `$installedVersion = [version]`$installedVersionStr
                        
                        # Compare installed vs required version
                        if (`$installedVersion -ge `$minVersion) {
                            Write-Output "Detected: `$(`$item.DisplayName) version `$installedVersionStr (>= `$minVersion)"
                            `$found = `$true
                            break
                        }
                    }
                    catch {
                        # Skip on parse failure
                        continue
                    }
                }
            }
        }
        
        if (`$found) { break }
    }
    
    if (`$found) {
        Write-Output "Detected: Office installation meets requirements"
        exit 0
    }
    else {
    # Silent exit when not detected (Intune requirement)
        exit 1
    }
}
catch {
    Write-Output "Error during detection: `$(`$_.Exception.Message)"
    exit 1
}
"@
}

function New-DetectionScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        $detectionScriptPath = Join-Path $OutputPath "Detect-OfficeInstallation.ps1"
        $detectionScriptContent = New-DetectionScriptContent -DisplayName $DisplayName -Version $Version
        $detectionScriptContent | Out-File -FilePath $detectionScriptPath -Encoding UTF8 -Force
        Write-LogHost "Generated Detect-OfficeInstallation.ps1 for Win32 app detection" -ForegroundColor Green -Component $LogID
        
        return $detectionScriptPath
    }
    catch {
        throw ("Failed to create detection script at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    }
}


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
            $hasOfficeFolder { "Add Primary Install File: setup.exe`nAdd Folders: Office`nAdd Files: $($CustomApp.XmlFileName), $($CustomApp.XmlUninstallFileName)" }
            $hasOfficeZip { "Add Primary Install File: setup.exe`nAdd Files: Office.zip, $($CustomApp.XmlFileName), $($CustomApp.XmlUninstallFileName)" }
            default { "Add Primary Install File: setup.exe`nAdd Files: $($CustomApp.XmlFileName), $($CustomApp.XmlUninstallFileName)" }
        }
        $notesSection = "Internal Notes: $($CustomApp.Notes)`n"

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
Uninstall Command (Use Custom): & ".\setup.exe" /configure ".\uninstall.xml"
Intune Notes: $($CustomApp.Notes)
Information URL: https://www.microsoft.com/en-gb/microsoft-365/products-apps-services
Privacy URL: https://learn.microsoft.com/en-us/microsoft-365-apps/privacy/overview-privacy-controls

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

function New-Win32AppInstructions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [string]$IntunewinFileName,
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$AppDetails,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        $instructionsPath = Join-Path $OutputPath "Win32App_Details.txt"
        
        # Build details section from AppDetails if provided
        $detailsSection = ""
        if ($AppDetails) {
            $detailsSection = @"

================================================================================
DEPLOYMENT DETAILS:
================================================================================

Name:                   $($AppDetails.AppName)
Description:            $($AppDetails.Description)
Publisher:              $($AppDetails.Vendor)
App Version:            $($AppDetails.Version)
Information URL: https://www.microsoft.com/en-gb/microsoft-365/products-apps-services
Privacy URL: https://learn.microsoft.com/en-us/microsoft-365-apps/privacy/overview-privacy-controls
Notes:                  $($AppDetails.Notes)
Install Command:        setup.exe /configure $($AppDetails.XmlFileName)
Uninstall Command:      setup.exe /configure $($AppDetails.XmlUninstallFileName)

"@
        }
        
        $instructions = @"
================================================================================
                    WIN32 APP DEPLOYMENT INSTRUCTIONS
================================================================================

OVERVIEW:
This package contains an Intune Win32 app (.intunewin file) that can be deployed
to your organization using Microsoft Intune or other mobile device management (MDM)
solutions.

================================================================================
PACKAGE CONTENTS:
================================================================================

-Microsoft Office Win32 app package for Intune deployment   - $IntunewinFileName
- Office installation executable                            - setup.exe                             
- Office deployment configuration file                      - $($AppDetails.XmlFileName)            
- Office uninstallation configuration file                  - $($AppDetails.XmlUninstallFileName)   
- Application icon for display in Intune/Company Portal     - Microsoft.png
- Detection script for Office version verification          - Detect-OfficeInstallation.ps1                         
$detailsSection
================================================================================
HOW TO USE THIS WIN32 APP PACKAGE:
================================================================================

1. UPLOAD TO INTUNE:
    a) Sign in to the Microsoft Intune admin center
    b) Navigate to: Apps > Windows apps > + Create
    c) Select "Windows app (Win32)" from the app type list
    d) Click "Select" to proceed
    e) Upload the .intunewin file by clicking "Select app package file"
    f) Browse to and select: $IntunewinFileName

2. CONFIGURE APP PROPERTIES:
    a) Fill in the required app information (Use information from above e.g. Name, Description, Publisher, etc.)
    b) Upload the application icon: Microsoft.png
    c) Click "Next" to proceed
    d) Set the install and uninstall commands as follows:
      - Install command: setup.exe /configure $($AppDetails.XmlFileName)
      - Uninstall command: setup.exe /configure $($AppDetails.XmlUninstallFileName)
    e) Set "Allow available uninstall" to "Yes" (Optional)
    f) Set the install behavior to "System" and architecture to "$($AppDetails.Architecture)-bit"
    g) Complete any additional app configuration as needed

3. CONFIGURE DETECTION RULES:
    a) Click "Next" to proceed to the Requirements section, configure as needed
    b) Click "Next" to proceed to the Detection rules section
    c) Select "Use a custom detection script" from the Rules format dropdown
    d) Click "Select" to upload the detection script
    e) Browse to and select: Detect-OfficeInstallation.ps1
    f) Set "Run script as 32-bit process on 64-bit clients" to "No"
    g) Set "Enforce script signature check" to "No" unless you have signed the script after it was generated
    h) Click "OK" to save the detection rule
    i) Click "Next" to proceed

   NOTE: The detection script searches HKLM registry for Office installations
   matching DisplayName "$($AppDetails.AppsAndFeaturesName)" with version >= $($AppDetails.Version).
   The script supports wildcard matching (%) in the DisplayName.

4. ASSIGN THE APP:
   a) Assign the app to the desired user or device groups for installation

================================================================================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================
"@
        # Manual packaging note for non-Windows hosts (cannot run Intune packer)
        try {
            $isWin = $false
            if (Test-Path Variable:IsWindows) { $isWin = $IsWindows }
            else { $isWin = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows) }
        }
        catch {
            $isWin = ($env:OS -and $env:OS -match 'Windows')
        }

        $manualNote = ""
        if (-not $isWin) {
            $manualNote = @"


================================================================================
NOTE FOR NON-WINDOWS HOSTS (macOS/Linux)
================================================================================

This run could not create the Intune Win32 package (.intunewin) because the
Intune Win32 Content Prep Tool (IntuneWinAppUtil.exe) is a Windows executable.
To create the .intunewin manually, copy the following files from this output
folder to a Windows machine and run the Win32 Content Prep Tool there:

 - Office installation files folder: 'Office' (contains the Office payload files)
 - setup.exe
 - Install XML: $($AppDetails.XmlFileName)
 - Uninstall XML: $($AppDetails.XmlUninstallFileName)

Steps to create the .intunewin on a Windows machine:
 1) Download the Microsoft Win32 Content Prep Tool (IntuneWinAppUtil.exe).
    Official documentation: https://learn.microsoft.com/mem/intune/apps/apps-win32-app-management
 2) Place IntuneWinAppUtil.exe on the Windows machine.
 3) Open an elevated command prompt and run:

    IntuneWinAppUtil.exe -c "<path-to-source-folder>" -s "setup.exe" -o "<path-to-output-folder>"

    Example:
    IntuneWinAppUtil.exe -c "C:\path\to\output\sessionfolder" -s "setup.exe" -o "C:\path\to\output\sessionfolder\intunepkg"

================================================================================
"@
        }

        $finalInstructions = $instructions + $manualNote
        $finalInstructions | Out-File -FilePath $instructionsPath -Encoding UTF8
        Write-LogHost ("Win32 app instructions exported to: {0}" -f $instructionsPath) -ForegroundColor Green -Component $LogID
        return $instructionsPath
    }
    catch {
        Write-LogHost ("Failed to create Win32 app instructions file: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 3 -Component $LogID
        return $null
    }
}



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
        "ProjectPro*2024*" { "Microsoft Project Professional 2024" }
        "ProjectPro*2021*" { "Microsoft Project Professional 2021" }
        "ProjectPro*2019*" { "Microsoft Project Professional 2019" }
        "ProjectPro*" { "Microsoft Project Professional" }
        "ProjectStd*2024*" { "Microsoft Project Standard 2024" }
        "ProjectStd*2021*" { "Microsoft Project Standard 2021" }
        "ProjectStd*2019*" { "Microsoft Project Standard 2019" }
        "ProjectStd*" { "Microsoft Project Standard" }
        "VisioPro*2024*" { "Microsoft Visio Professional 2024" }
        "VisioPro*2021*" { "Microsoft Visio Professional 2021" }
        "VisioPro*2019*" { "Microsoft Visio Professional 2019" }
        "VisioPro*" { "Microsoft Visio Professional" }
        "VisioStd*2024*" { "Microsoft Visio Standard 2024" }
        "VisioStd*2021*" { "Microsoft Visio Standard 2021" }
        "VisioStd*2019*" { "Microsoft Visio Standard 2019" }
        "VisioStd*" { "Microsoft Visio Standard" }
        "*2024*" { "Office 2024 Perpetual Enterprise" }
        "*2021*" { "Office 2021 Perpetual Enterprise" }
        "*2019*" { "Office 2019 Perpetual Enterprise" }
        default { $Product }
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
    
    $downloadFolder = if ($script:DownloadPath) { $script:DownloadPath } else { Join-Path $env:APPDATA 'M365AppsHelper\Downloads' }
    if (-not (Test-Path -LiteralPath $downloadFolder -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $downloadFolder -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-LogHost ("Failed to ensure icon cache folder {0}: {1}" -f $downloadFolder, $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogID
            return $null
        }
    }

    $cachedIconPath = Join-Path $downloadFolder "Microsoft.png"
    if (-not (Test-Path -LiteralPath $cachedIconPath)) {
        try {
            Write-Log ("Downloading Office icon from: {0}" -f $IconUrl) -Component $LogID
            Invoke-FileDownload -Uri $IconUrl -Destination $cachedIconPath | Out-Null
            Write-LogHost ("Office icon cached at: {0}" -f $cachedIconPath) -ForegroundColor Green -Component $LogID
        }
        catch {
            Write-LogHost ("Failed to download Office icon: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogID
            return $null
        }
    }

    $iconPath = Join-Path $OutputPath "Microsoft.png"
    try {
        Copy-Item -LiteralPath $cachedIconPath -Destination $iconPath -Force
        return $iconPath
    }
    catch {
        Write-LogHost ("Failed to copy Office icon into package: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogID
        return $null
    }
}

function New-OfficeUninstallXml {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$SourceXmlPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )
    
    try {
        Write-Log ("Creating Office uninstall XML from source: {0}" -f $SourceXmlPath) -Component $LogID
        
        # Load source XML
        [xml]$sourceXml = Get-Content -Path $SourceXmlPath -Raw

        $addNode = $sourceXml.Configuration.Add
        if (-not $addNode) {
            Write-LogHost ("Uninstall XML generation skipped: source XML contains no Add node") -ForegroundColor Yellow -Severity 2 -Component $LogID
            return $null
        }

        $productNodes = @($addNode.Product) | Where-Object { $_ }
        if (-not $productNodes -or $productNodes.Count -eq 0) {
            Write-LogHost ("Uninstall XML generation skipped: no products found in source XML") -ForegroundColor Yellow -Severity 2 -Component $LogID
            return $null
        }

        # Build a fresh XML document to avoid string-casting issues
        $doc = New-Object System.Xml.XmlDocument
        $xmlDecl = $doc.CreateXmlDeclaration("1.0", "UTF-8", $null)
        $doc.AppendChild($xmlDecl) | Out-Null

        $root = $doc.CreateElement("Configuration")
        $doc.AppendChild($root) | Out-Null

        # Create Remove node populated from source products/languages
        $removeNode = $doc.CreateElement("Remove")

        foreach ($product in $productNodes) {
            $productElement = $doc.CreateElement("Product")
            if ($product.ID) {
                $productElement.SetAttribute("ID", $product.ID)
            }

            $languages = @($product.Language) | Where-Object { $_ }
            foreach ($lang in $languages) {
                if ($lang.ID -and $lang.ID -ne "MatchPreviousMSI") {
                    $langElement = $doc.CreateElement("Language")
                    $langElement.SetAttribute("ID", $lang.ID)
                    $productElement.AppendChild($langElement) | Out-Null
                }
            }

            $removeNode.AppendChild($productElement) | Out-Null
        }

        $root.AppendChild($removeNode) | Out-Null

        # Add silent display settings (match sample UX/EULA)
        $displayNode = $doc.CreateElement("Display")
        $displayNode.SetAttribute("Level", "None")
        $displayNode.SetAttribute("AcceptEULA", "TRUE")
        $root.AppendChild($displayNode) | Out-Null
        
        # Save uninstall XML
        $uninstallFileName = if ($script:DefaultUninstallConfigName) { $script:DefaultUninstallConfigName } else { "Uninstall.xml" }
        $uninstallXmlPath = Join-Path $OutputPath $uninstallFileName
        $doc.Save($uninstallXmlPath)
        
        Write-Log ("Created Office uninstall XML at: {0}" -f $uninstallXmlPath) -Component $LogID
        return $uninstallFileName
    }
    catch {
        Write-LogHost ("Failed to create Office uninstall XML: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogID
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

        Write-Log ("Creating app details object from configuration") -Component $LogID
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
        # Always append language to app name for OnlineMode or single language
        if ($mainLangDisplayName) {
            $appNameStr += " - $mainLangDisplayName"
        }
        
        $languages = $productNodes | ForEach-Object { @($_.Language) | ForEach-Object { $_.ID } }
        $languages = $languages | Where-Object { $_ -and $_ -notin @("MatchPreviousMSI") } | Select-Object -Unique
        
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
            # Exclude the main language from additional languages
            $additionalLangs = $languages | Where-Object { $_ -ne $mainLang }
            if ($additionalLangs) {
                $notesLanguage = Get-LocaleDisplayName -LocaleCodes ($additionalLangs -join ",") -LogID $LogID
                $notesLanguage = $notesLanguage -join ", "
            }
        }

        $displayNameStr = Get-OfficeDisplayName -AppName $mainAppName -Language $mainLang -LogID $LogID
        Get-OfficeIcon -OutputPath $OutputPath -IconUrl $IconUrl -LogID $LogID | Out-Null

        # Generate uninstall XML
        $uninstallXmlFileName = New-OfficeUninstallXml -SourceXmlPath $xmlPath -OutputPath $OutputPath -LogID $LogID

        $customApp = [PSCustomObject]@{
            # Always append language to AppName for Win32App output
            AppName                 = "$appNameStr - $mainLang"
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
            XmlUninstallFileName    = $uninstallXmlFileName
        }

        if ($notesLanguage) {
            $customApp.Notes += ". Language: $mainLangDisplayName"
            if ($notesLanguage) {
                $customApp.Notes += ". Additional Languages: {0}" -f $notesLanguage
            }
        }
        elseif ($mainLangDisplayName) {
            $customApp.Notes += ". Language: $mainLangDisplayName"
        }
        if ($mainLangDisplayName -eq "MatchOS" ) {
            $customApp.Notes += ". Detection Information: As the language is set to 'MatchOS', we cannot use an exact Display Name for detection. The Apps & Features name contain a '%' wildcard to match any language."
        }

        Write-Log ("Created app details object for Product ID(s): {0}, Version: {1}, Architecture: {2}" -f ($productIds -join ", "), $versions, $architecture) -Component $LogID
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
    Write-Host "Uninstall Command: Custom: & "".\setup.exe"" /configure "".\$($CustomApp.XmlUninstallFileName)"""
    Write-Host "Information URL: https://www.microsoft.com/en-gb/microsoft-365/products-apps-services"
    Write-Host "Privacy URL: https://learn.microsoft.com/en-us/microsoft-365-apps/privacy/overview-privacy-controls"
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



function New-IntuneWinPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ (Test-Path $_ -PathType Container -ErrorAction SilentlyContinue) -or (-not (Test-Path $_)) })]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^https?://.+')]
        [string]$ToolUrl,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$StagingPath,
        [string]$LogID = $($MyInvocation.MyCommand).Name
    )

    $setupPath = Join-Path $SourcePath $SetupFileName
    if (-not (Test-Path $setupPath)) {
        throw ("Setup file '{0}' not found in source path '{1}'" -f $SetupFileName, $SourcePath)
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Download the Intune Win32 Content Prep Tool directly to staging folder
    $contentPrepToolPath = Join-Path $StagingPath "IntuneWinAppUtil.exe"

    if (-not (Test-Path $contentPrepToolPath)) {
        Write-LogHost ("Downloading Intune Content Prep Tool from {0}" -f $ToolUrl) -Component $LogID
        Invoke-FileDownload -Uri $ToolUrl -Destination $contentPrepToolPath -LogID $LogID | Out-Null

        if (-not (Test-Path $contentPrepToolPath)) {
            $errorMsg = "IntuneWinAppUtil.exe was not found after download"
            Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogID
            throw $errorMsg
        }
    }

    $arguments = "-c `"$SourcePath`" -s `"$SetupFileName`" -o `"$OutputPath`" -qq"
    Write-LogHost ("Win32 Content Prep Tool parameters: Tool={0} | Arguments={1}" -f $contentPrepToolPath, $arguments) -Component $LogID
    Write-LogHost ("Running Intune Content Prep Tool to create .intunewin..." ) -Component $LogID
    $process = Start-Process -FilePath $contentPrepToolPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        throw ("Intune Content Prep Tool failed with exit code {0}" -f $process.ExitCode)
    }

    $intunePackage = Get-ChildItem -Path $OutputPath -Filter "*.intunewin" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $intunePackage) {
        throw "No .intunewin package was created"
    }

    Write-LogHost ("Created Intune Win32 package: {0}" -f $intunePackage.FullName) -ForegroundColor Green -Component $LogID
    return $intunePackage.FullName
}



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
        [ValidatePattern('^https?://.+')]
        [string]$Win32ContentPrepToolUrl,
        [switch]$CreateIntuneWin,
        [switch]$NoZip,
        [switch]$OnlineMode,
        [switch]$SkipAPICheck,
        [switch]$PMPCCustomApp,
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

    # Clean specific staging artifacts but keep cached assets (e.g., Microsoft.png)
    if (-not (Test-Path $StagingDir)) {
        try { New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction Stop | Out-Null }
        catch {
            $errorMsg = ("Failed to create staging folder {0}: {1}" -f $StagingDir, $_.Exception.Message)
            Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogID
            throw $errorMsg
        }
    }
    else {
        Write-LogHost ("Cleaning staging artifacts in: {0}" -f $StagingDir) -Component $LogID
        $oldProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            $targets = @(
                (Join-Path $StagingDir 'OfficeVersions_Latest.json')
                (Join-Path $StagingDir 'setup.exe')
            )
            foreach ($target in $targets) {
                if (Test-Path -LiteralPath $target) {
                    Remove-Item -LiteralPath $target -Force -ErrorAction Stop
                }
            }
            Write-LogHost ("Removed old Office version metadata and setup executable; preserved cached assets.") -ForegroundColor Green -Component $LogID
        }
        catch {
            $errorMsg = ("Failed to clean staging artifacts in {0}: {1}" -f $StagingDir, $_.Exception.Message)
            Write-LogHost $errorMsg -ForegroundColor Red -Severity 3 -Component $LogID
            throw $errorMsg
        }
        finally {
            $ProgressPreference = $oldProgressPreference
        }
    }

    # Log script start
    Write-Log ("Starting Invoke-M365AppsHelper script") -Component $LogID
    Write-Log ("Parameters: ConfigXml='{0}', StagingDir='{1}', OutputDir='{2}', LogFile='{3}', NoZip={4}, OnlineMode={5}, SkipAPICheck={6}, CreateIntuneWin={7}" -f $ConfigXml, $StagingDir, $OutputDir, $LogFile, $NoZip, $OnlineMode, $SkipAPICheck, $CreateIntuneWin) -Component $LogID
    Write-LogHost ("CreateIntuneWin requested: {0}" -f $CreateIntuneWin) -Component $LogID

    # If running on non-Windows hosts, CreateIntuneWin cannot run (IntuneWinAppUtil.exe is Windows-only)
    try {
        $isWin = $false
        if (Test-Path Variable:IsWindows) { $isWin = $IsWindows }
        else { $isWin = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows) }
    }
    catch {
        $isWin = ($env:OS -and $env:OS -match 'Windows')
    }

    if ($CreateIntuneWin -and -not $isWin) {
        Write-LogHost "CreateIntuneWin requested but the current host is not Windows; skipping CreateIntuneWin (not supported on macOS/Linux)." -ForegroundColor Yellow -Component $LogID -Severity 2
        Write-Log "CreateIntuneWin skipped on non-Windows host" -Component $LogID -Severity 2
        $CreateIntuneWin = $false
    }

    try {
        $isMac = $false
        if (Test-Path Variable:IsMacOS) { $isMac = $IsMacOS }
        else { $isMac = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX) }
    }
    catch {
        $isMac = ($env:OSTYPE -and $env:OSTYPE -match 'darwin') -or ($env:OS -and $env:OS -match 'Darwin')
    }

    if ($isMac -and $CreateIntuneWin) {
        Write-LogHost "Host detected as macOS; CreateIntuneWin is not supported and will be disabled." -ForegroundColor Yellow -Component $LogID
        Write-Log "CreateIntuneWin disabled on macOS" -Component $LogID -Severity 2
        $CreateIntuneWin = $false
    }

    # Default behavior: enable Intune Win32 packaging unless a Patch My PC custom app is selected
    if ($PMPCCustomApp) {
        if ($CreateIntuneWin) {
            Write-LogHost ("PMPCCustomApp selected - disabling CreateIntuneWin to avoid conflicting flows") -ForegroundColor Yellow -Component $LogID
            $CreateIntuneWin = $false
        }
    }
    else {
        if (-not $CreateIntuneWin) {
            if ($isWin) {
                Write-LogHost ("PMPCCustomApp not selected - enabling CreateIntuneWin by default") -ForegroundColor Yellow -Component $LogID
                $CreateIntuneWin = $true
            }
            else {
                Write-LogHost ("PMPCCustomApp not selected but host is not Windows; CreateIntuneWin will remain disabled") -ForegroundColor Yellow -Component $LogID
            }
        }
    }
    Write-LogHost ("CreateIntuneWin effective: {0}" -f $CreateIntuneWin) -Component $LogID

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
    
    # Dynamically display all properties from the configuration object (robust against non-indexable enumerables)
    try {
        foreach ($property in $configInfo.PSObject.Properties) {
            $displayValue = if ($null -eq $property.Value) { 
                'Not specified' 
            }
            elseif ($property.Value -is [hashtable] -or $property.Value.GetType().Name -eq 'OrderedDictionary' -or $property.Value -is [System.Collections.Specialized.OrderedDictionary]) {
                if ($property.Value.Count -eq 0) { 'None' }
                else { ($property.Value.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join '; ' }
            }
            elseif ($property.Value -is [array] -or ($property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string])) {
                $enumItems = @()
                foreach ($item in $property.Value) { $enumItems += $item }
                if ($enumItems.Count -eq 0) { 'None' }
                elseif ($enumItems[0] -is [PSCustomObject]) {
                    $items = @()
                    foreach ($item in $enumItems) {
                        if ($item.ID) { $items += $item.ID }
                        else { $items += $item.ToString() }
                    }
                    $items -join ', '
                }
                else { $enumItems -join ', ' }
            }
            elseif ([string]::IsNullOrWhiteSpace($property.Value)) {
                'Not specified'
            }
            else { $property.Value.ToString() }
            Write-LogHost ("{0}: {1}" -f $property.Name, $displayValue) -ForegroundColor Cyan -Component $LogID
        }
    }
    catch {
        Write-LogHost ("Failed to display XML configuration properties: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogID
    }
    
    # Log the compressed XML configuration data for debugging
    $compressedXmlConfig = ($configInfo | ConvertTo-Json -Depth 10 -Compress)
    Write-Log ("XML Configuration (compressed): {0}" -f $compressedXmlConfig) -Component $LogID

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
        if ($OutputDir) {
            $resolvedOut = Resolve-Path $OutputDir -ErrorAction SilentlyContinue
            $outputRootDir = if ($resolvedOut) { $resolvedOut.Path } else { (New-Item -ItemType Directory -Path $OutputDir -Force).FullName }
        }
        else { 
            $outputRootDir = Join-Path $PSScriptRoot "Output" 
        }
        
        while (Test-Path (Join-Path $outputRootDir $sessionFolderName)) {
            $sessionFolderName = "{0}_{1}" -f $baseFolderName, $counter
            $counter++
        }
        
        if ($OutputDir) {
            $resolvedOut = Resolve-Path $OutputDir -ErrorAction SilentlyContinue
            $outputRootDir = if ($resolvedOut) { $resolvedOut.Path } else { (New-Item -ItemType Directory -Path $OutputDir -Force).FullName }
        }
        else { 
            $outputRootDir = Join-Path $PSScriptRoot "Output" 
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

        # Generate uninstall XML in the same output folder
        $null = New-OfficeUninstallXml -SourceXmlPath $outputConfigPath -OutputPath $sessionPath -LogID $LogID
        
        # Actually scan the output folder to see what files are there
        $actualFiles = Get-ChildItem -Path $sessionPath -File | Sort-Object Name

        # Log the actual package contents
        $actualFileNames = $actualFiles | ForEach-Object { $_.Name }
        $packageContentsCompressed = $actualFileNames -join ';'
        Write-Log ("OnlineMode Package Contents (actual): {0}" -f $packageContentsCompressed) -Component $LogId
        
        Write-LogHost ("OnlineMode package ready at: {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId
        
        Write-Host "OnlineMode package contains:" -ForegroundColor Green
        
        foreach ($file in $actualFiles) {
            $description = switch ($file.Name) {
                "setup.exe" { "setup.exe" }
                $OutputConfigName { "$OutputConfigName (with validated/updated version)" }
                $script:DefaultUninstallConfigName { "$script:DefaultUninstallConfigName (Office uninstall configuration)" }
                "Microsoft.png" { "Microsoft.png (app icon to use for Patch My PC custom app)" }
                "PatchMyPC_CustomApp_Info.json" { "PatchMyPC_CustomApp_Info.json (custom app metadata)" }
                "PatchMyPC_CustomApp_Details.txt" { "PatchMyPC_CustomApp_Details.txt (usage instructions)" }
                "Win32App_Details.txt" { "Win32App_Details.txt (deployment instructions)" }
                default { $file.Name }
            }
            Write-Host ("  {0}" -f $description) -ForegroundColor Cyan
        }

        # Generate deployment information based on PMPCCustomApp flag
        Write-Host ""
        # Always create the custom app object for details
        Write-LogHost ("Creating application details from configuration...") -ForegroundColor Yellow -Component $LogID
        $customApp = New-PatchMyPCCustomApp -OutputPath $sessionPath -XmlFileName $OutputConfigName -IconUrl $OfficeIconUrl -LogID $LogID

        if ($customApp) {
            if ($PMPCCustomApp) {
                # Generate Patch My PC custom app information (json and txt files)
                Write-LogHost ("Exporting Patch My PC custom app information...") -ForegroundColor Yellow -Component $LogID
                Export-PatchMyPCCustomAppInfo -CustomApp $customApp -OutputPath $sessionPath -LogID $LogID

                # Display custom app information to console only if not creating Intune Win32 package
                if (-not $CreateIntuneWin) {
                    Show-PatchMyPCCustomAppInfo -CustomApp $customApp -LogID $LogID
                }
            }
            else {
                # Generate generic Win32 app deployment instructions with app details
                Write-LogHost ("Generating Win32 app deployment instructions...") -ForegroundColor Yellow -Component $LogID
                $intunewinFile = if ($CreateIntuneWin) { "setup.intunewin" } else { "[intunewin file]" }
                
                # Generate detection script
                New-DetectionScript -OutputPath $sessionPath -DisplayName $customApp.AppsAndFeaturesName -Version $customApp.Version -LogID $LogID
                
                New-Win32AppInstructions -OutputPath $sessionPath -IntunewinFileName $intunewinFile -AppDetails $customApp -LogID $LogID
            }
        }

        if ($CreateIntuneWin) {
            try {
                $intunePackagePath = New-IntuneWinPackage -SourcePath $sessionPath -SetupFileName "setup.exe" -OutputPath $sessionPath -ToolUrl $Win32ContentPrepToolUrl -StagingPath $stagingDirectory -LogID $LogId
                Write-Log ("Intune Win32 package created at {0}" -f $intunePackagePath) -Component $LogId
            }
            catch {
                Write-LogHost ("Failed to create Intune Win32 package: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogId
            }
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
    # Only use NoZip if PMPCCustomApp is also passed
    if ($PMPCCustomApp) {
        # Compress by default unless NoZip is passed
        $modeSuffix = if ($NoZip) { "OfflineMode" } else { "OfflineModeCompressed" }
    }
    else {
        # Never do zip compression if not PMPCCustomApp
        $modeSuffix = "OfflineMode"
        $NoZip = $true
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
    if ($OutputDir) {
        $resolvedOut = Resolve-Path $OutputDir -ErrorAction SilentlyContinue
        $outputRootDir = if ($resolvedOut) { $resolvedOut.Path } else { (New-Item -ItemType Directory -Path $OutputDir -Force).FullName }
    }
    else { 
        $outputRootDir = Join-Path $PSScriptRoot "Output" 
    }
    
    while (Test-Path (Join-Path $outputRootDir $sessionFolderName)) {
        $sessionFolderName = "{0}_{1}" -f $baseFolderName, $counter
        $counter++
    }
    
    # Create the final output folder regardless of Zip option
    if ($OutputDir) {
        $resolvedOut = Resolve-Path $OutputDir -ErrorAction SilentlyContinue
        $outputRootDir = if ($resolvedOut) { $resolvedOut.Path } else { (New-Item -ItemType Directory -Path $OutputDir -Force).FullName }
    }
    else { 
        $outputRootDir = Join-Path $PSScriptRoot "Output" 
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
    $outputConfigPath = Join-Path $sessionPath $OutputConfigName
    Copy-Item -Path $setupPath -Destination $outputSetupPath -Force
    Copy-Item -Path $configCopy -Destination $outputConfigPath -Force

    Write-LogHost ("Copied setup.exe and {0} to output folder" -f $OutputConfigName) -ForegroundColor Green -Component $LogId

    # Generate uninstall XML in the output folder
    $null = New-OfficeUninstallXml -SourceXmlPath $outputConfigPath -OutputPath $sessionPath -LogID $LogID

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
                    $OutputConfigName { "$OutputConfigName" }
                    $script:DefaultUninstallConfigName { "$script:DefaultUninstallConfigName (Office uninstall configuration)" }
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
            
            # Generate deployment information based on PMPCCustomApp flag
            Write-Host ""
            # Always create the custom app object for details
            Write-LogHost ("Creating application details from configuration...") -Component $LogId
            $customApp = New-PatchMyPCCustomApp -OutputPath $sessionPath -XmlFileName $OutputConfigName -IconUrl $OfficeIconUrl -LogID $LogId
        
            if ($customApp) {
                if ($PMPCCustomApp) {
                    # Generate Patch My PC custom app information (json and txt files)
                    Write-LogHost ("Exporting Patch My PC custom app information...\") -Component $LogId
                    Export-PatchMyPCCustomAppInfo -CustomApp $customApp -OutputPath $sessionPath -LogID $LogId

                    # Log the compressed custom app info
                    $compressedCustomApp = $customApp | ConvertTo-Json -Depth 3 -Compress
                    Write-Log ("Patch My PC Custom App Info: {0}" -f $compressedCustomApp) -Component $LogId
                    
                    # Display Patch My PC custom app information to console only if not creating Intune Win32 package
                    if (-not $CreateIntuneWin) {
                        Show-PatchMyPCCustomAppInfo -CustomApp $customApp -LogID $LogId
                    }
                }
                else {
                    # Generate generic Win32 app deployment instructions with app details
                    Write-LogHost ("Generating Win32 app deployment instructions...") -Component $LogId
                    $intunewinFile = if ($CreateIntuneWin) { "Microsoft365Apps.intunewin" } else { "[intunewin file]" }
                    
                    # Generate detection script
                    New-DetectionScript -OutputPath $sessionPath -DisplayName $customApp.AppsAndFeaturesName -Version $customApp.Version -LogID $LogId
                    
                    New-Win32AppInstructions -OutputPath $sessionPath -IntunewinFileName $intunewinFile -AppDetails $customApp -LogID $LogId
                }
            }

            if ($CreateIntuneWin) {
                try {
                    $intunePackagePath = New-IntuneWinPackage -SourcePath $sessionPath -SetupFileName "setup.exe" -OutputPath $sessionPath -ToolUrl $Win32ContentPrepToolUrl -StagingPath $downloadDirectory -LogID $LogId
                    Write-Log ("Intune Win32 package created at {0}" -f $intunePackagePath) -Component $LogId
                }
                catch {
                    Write-LogHost ("Failed to create Intune Win32 package: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogId
                }
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
                $OutputConfigName { "$OutputConfigName" }
                $script:DefaultUninstallConfigName { "$script:DefaultUninstallConfigName (Office uninstall configuration)" }
                "Microsoft.png" { "Microsoft.png (app icon for Patch My PC custom app)" }
                "PatchMyPC_CustomApp_Info.json" { "PatchMyPC_CustomApp_Info.json (custom app metadata)" }
                "PatchMyPC_CustomApp_Details.txt" { "PatchMyPC_CustomApp_Details.txt (usage instructions)" }
                default { $file.Name }
            }
            Write-Host ("  {0}" -f $description) -ForegroundColor Cyan
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

        # Cleanup Office data files from downloads folder after packaging
        $sourceOfficeDir = Join-Path $downloadDirectory "Office"
        if (Test-Path $sourceOfficeDir) {
            try {
                Remove-Item -Path $sourceOfficeDir -Recurse -Force -ErrorAction Stop
                Write-LogHost ("Cleaned up Office data files from downloads folder: {0}" -f $sourceOfficeDir) -ForegroundColor Yellow -Component $LogId
            }
            catch {
                Write-LogHost ("Failed to clean up Office data files from downloads folder: {0}" -f $_.Exception.Message) -ForegroundColor Red -Severity 2 -Component $LogId
            }
        }

        # Generate deployment information based on PMPCCustomApp flag
        Write-Host ""
        if ($PMPCCustomApp) {
            # Generate Patch My PC custom app information
            Write-LogHost ("Generating Patch My PC custom app information...") -Component $LogId
            $customApp = New-PatchMyPCCustomApp -OutputPath $sessionPath -XmlFileName $OutputConfigName -IconUrl $OfficeIconUrl -LogID $LogId
        
            if ($customApp) {
                # Export custom app information (json and txt files)
                Export-PatchMyPCCustomAppInfo -CustomApp $customApp -OutputPath $sessionPath -LogID $LogId

                # Log the compressed custom app info
                $compressedCustomApp = $customApp | ConvertTo-Json -Depth 3 -Compress
                Write-Log ("Patch My PC Custom App Info: {0}" -f $compressedCustomApp) -Component $LogId
                
                # Display Patch My PC custom app information to console only if not creating Intune Win32 package
                if (-not $CreateIntuneWin) {
                    Show-PatchMyPCCustomAppInfo -CustomApp $customApp -LogID $LogId
                }
            }
        }
        else {
            # Generate generic Win32 app deployment instructions
            Write-LogHost ("Generating Win32 app deployment instructions...") -Component $LogId
            $intunewinFile = if ($CreateIntuneWin) { "Microsoft365Apps.intunewin" } else { "[intunewin file]" }
            New-Win32AppInstructions -OutputPath $sessionPath -IntunewinFileName $intunewinFile -LogID $LogId
        }

        if ($CreateIntuneWin) {
            try {
                $intunePackagePath = New-IntuneWinPackage -SourcePath $sessionPath -SetupFileName "setup.exe" -OutputPath $sessionPath -ToolUrl $Win32ContentPrepToolUrl -StagingPath $downloadDirectory -LogID $LogId
                Write-Log ("Intune Win32 package created at {0}" -f $intunePackagePath) -Component $LogId
            }
            catch {
                Write-LogHost ("Failed to create Intune Win32 package: {0}" -f $_.Exception.Message) -ForegroundColor Yellow -Severity 2 -Component $LogId
            }
        }
        
        # Script completion summary
        Write-LogHost ("Script completed successfully - M365 Office deployment package created without zip compression at {0}" -f $sessionPath) -ForegroundColor Green -Component $LogId

    }
}



try { 
    Invoke-Main -ConfigXml $ConfigXML -StagingDir $DownloadPath -OutputDir $OutputPath -LogFile $LogName -Win32ContentPrepToolUrl $Win32ContentPrepToolUrl -CreateIntuneWin:$CreateIntuneWin -NoZip:$NoZip -OnlineMode:$OnlineMode -SkipAPICheck:$SkipAPICheck -PMPCCustomApp:$PMPCCustomApp -ApiRetryDelaySeconds $ApiRetryDelaySeconds
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


