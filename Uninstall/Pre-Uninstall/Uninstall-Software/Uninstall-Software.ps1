<#
.SYNOPSIS
    Uninstall software based on the DisplayName of said software in the registry
.DESCRIPTION
    This script is useful if you need to uninstall software before installing or updating other software. 

    Typically best used as a pre-script in most situations.

    One example use case of this script with Patch My PC's Publisher is if you have previously re-packaged software installed
    on your devices and you need to uninstall the repackaged software, and install using the vendor's native install media 
    (provided by the Patch My PC catalogue).

    The script searches the registry for installed software, matching the supplied DisplayName value in the -DisplayName parameter
    with that of the DisplayName in the registry. If one match is found, it uninstalls the software using the QuietUninstallString or UninstallString.
    
    You can supply additional arguments to the uninstaller using the -AdditionalArguments, -AdditionalMSIArguments, or -AdditionalEXEArguments parameters.

    You cannot use -AdditionalArguments with -AdditionalMSIArguments or -AdditionalEXEArguments.

    If a product code is not in the UninstallString, QuietUninstallString or UninstallString are used. QuietUninstallString is preferred if it exists.

    If more than one matches of the DisplayName occurs, uninstall is not possible unless you use the -UninstallAll switch.

    If QuietUninstallString and UninstallString is not present or null, uninstall is not possible.

    A log file is created in the temp directory with the name "Uninstall-Software-<DisplayName>.log" which contains the verbose output of the script.

    An .msi log file is created in the temp directory with the name "<DisplayName>_<DisplayVersion>.msi.log" which contains the verbose output of the msiexec.exe process.
.PARAMETER DisplayName
    The name of the software you wish to uninstall as it appears in the registry as its DisplayName value. * wildcard supported.
.PARAMETER Architecture
    Choose which registry key path to search in while looking for installed software. Acceptable values are:

    - "x86" will search in SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall on a 64-bit system.
    - "x64" will search in SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall.
    - "Both" will search in both key paths.
.PARAMETER HivesToSearch
    Choose which registry hive to search in while looking for installed software. Acceptable values are:

    - "HKLM" will search in hive HKEY_LOCAL_MACHINE which is typically where system-wide installed software is registered.
    - "HKCU" will search in hive HKEY_CURRENT_USER which is typically where user-based installed software is registered.
.PARAMETER WindowsInstaller
    Specify a value between 1 and 0 to use as an additional criteria when trying to find installed software.

    If WindowsInstaller registry value has a data of 1, it generally means software was installed from MSI.

    Omitting the parameter entirely or specify a value of 0 generally means software was installed from EXE

    This is useful to be more specific about software titles you want to uninstall.

    Specifying a value of 0 will look for software where WindowsInstaller is equal to 0, or not present at all.
.PARAMETER SystemComponent
    Specify a value between 1 and 0 to use as an additional criteria when trying to find installed software.

    Specifying a value of 0 will look for software where SystemComponent is equal to 0, or not present at all.
.PARAMETER VersionLessThan
    Specify a version number to use as an additional criteria when trying to find installed software.

    This parameter can be used in conjuction with -VersionEqualTo and -VersionGreaterThan.
.PARAMETER VersionEqualTo
    Specify a version number to use as an additional criteria when trying to find installed software.

    This parameter can be used in conjuction with -VersionLessThan and -VersionGreaterThan.
.PARAMETER VersionGreaterThan
    Specify a version number to use as an additional criteria when trying to find installed software.

    This parameter can be used in conjuction with -VersionLessThan and -VersionEqualTo.
.PARAMETER AdditionalArguments
    A string which includes the additional parameters you would like passed to the uninstaller.

    Cannot be used with -AdditionalMSIArguments or -AdditionalEXEArguments.
.PARAMETER AdditionalMSIArguments
    A string which includes the additional parameters you would like passed to the MSI uninstaller. 
    
    This is useful if you use this, and (or not at all) -AdditionalEXEArguments, in conjuction with -UninstallAll to apply different parameters for MSI based uninstalls.

    Cannot be used with -AdditionalArguments.
.PARAMETER AdditionalEXEArguments
    A string which includes the additional parameters you would like passed to the EXE uninstaller.

    This is useful if you use this, and (or not at all) -AdditionalMSIArguments, in conjuction with -UninstallAll to apply different parameters for EXE based uninstalls.

    Cannot be used with -AdditionalArguments.
.PARAMETER UninstallAll
    This switch will uninstall all software matching the search criteria of -DisplayName, -WindowsInstaller, and -SystemComponent.

    -DisplayName allows wildcards, and if there are multiple matches based on the wild card, this switch will uninstall matching software.

    Without this parameter, the script will do nothing if there are multiple matches found.
.PARAMETER ProcessName
    Wait for this process to finish after the uninstallation has started.
    
    If the process is already running before the uninstallation has even started, the script will quit with an error.

    This is useful for some software which spawn a seperate process to do the uninstallation, and the main process exits before the uninstallation is finished.

    The .exe extension is not required, and the process name is case-insensitive.
.EXAMPLE
    PS C:\> Uninstall-Software.ps1 -DisplayName "Greenshot"
    
    Uninstalls Greenshot if "Greenshot" is detected as the DisplayName in a key under either of the registry key paths:

    - SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
    - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall 
.EXAMPLE
    PS C:\> Uninstall-Software.ps1 -DisplayName "Mozilla*"

    Uninstalls any products where DisplayName starts with "Mozilla"
.EXAMPLE
    PS C:\> Uninstall-Software.ps1 -DisplayName "*SomeSoftware*" -AdditionalMSIArguments "/quiet /norestart" -AdditionalEXEArguments "/S" -UninstallAll

    Uninstalls all software where DisplayName contains "SomeSoftware". 
    
    For any software found in the registry matching the search criteria and are MSI-based (WindowsInstaller = 1), "/quiet /norestart" will be supplied to the uninstaller.
    
    For any software found in the registry matching the search criteria and  are EXE-based (WindowsInstaller = 0 or non-existent), "/S" will be supplied to the uninstaller.
.EXAMPLE
    PS C:\> Uninstall-Software.ps1 -DisplayName "KiCad*" -ProcessName "Un_A"

    Uninstalls KiCad and waits for the process "Un_A" to finish after the uninstallation has started.
.EXAMPLE
    PS C:\> Uninstall-Software.ps1 -DisplayName "SomeSoftware" -VersionGreaterThan 1.0.0

    Uninstalls SomeSoftware if the version is greater than 1.0.0
#>
[CmdletBinding(DefaultParameterSetName = 'AdditionalArguments')]
param (
    [Parameter(Mandatory)]
    [String]$DisplayName,

    [Parameter()]
    [ValidateSet('Both', 'x86', 'x64')]
    [String]$Architecture = 'Both',

    [Parameter()]
    [ValidateSet('HKLM', 'HKCU')]
    [String[]]$HivesToSearch = 'HKLM',

    [Parameter()]
    [Boolean]$WindowsInstaller,

    [Parameter()]
    [Boolean]$SystemComponent,

    [Parameter()]
    [String]$VersionLessThan,

    [Parameter()]
    [String]$VersionEqualTo,

    [Parameter()]
    [String]$VersionGreaterThan,

    [Parameter(ParameterSetName = 'AdditionalArguments')]
    [String]$AdditionalArguments,

    [Parameter(ParameterSetName = 'AdditionalEXEorMSIArguments')]
    [String]$AdditionalMSIArguments,
    
    [Parameter(ParameterSetName = 'AdditionalEXEorMSIArguments')]
    [String]$AdditionalEXEArguments,

    [Parameter()]
    [Switch]$UninstallAll,

    [Parameter()]
    [String]$ProcessName
)

function Get-InstalledSoftware {
    param(
        [Parameter(Mandatory)]
        [String]$DisplayName,

        [Parameter()]
        [ValidateSet('Both', 'x86', 'x64')]
        [String]$Architecture = 'Both',

        [Parameter()]
        [ValidateSet('HKLM', 'HKCU')]
        [String[]]$HivesToSearch = 'HKLM',

        [Parameter()]
        [Boolean]$WindowsInstaller,
    
        [Parameter()]
        [Boolean]$SystemComponent,
    
        [Parameter()]
        [String]$VersionLessThan,
    
        [Parameter()]
        [String]$VersionEqualTo,
    
        [Parameter()]
        [String]$VersionGreaterThan
    )

    $PathsToSearch = if ([IntPtr]::Size -eq 4) {
        # IntPtr will be 4 on a 32 bit system, where there is only one place to look
        'Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        switch -regex ($Architecture) {
            'Both|x86' {
                # If we are searching for a 32 bit application then we will only search under Wow6432Node
                'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            }
            'Both|x64' {
                # If we are searching for a 64 bit application then we will only search the 64-bit registry
                'Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            }
        }
    }

    $FullPaths = foreach ($PathFragment in $PathsToSearch) {
        switch ($HivesToSearch) {
            'HKLM' {
                [string]::Format('registry::HKEY_LOCAL_MACHINE\{0}', $PathFragment)

            }
            'HKCU' {
                # There is no Wow6432Node Uninstall key for HKEY_CURRENT_USER
                [string]::Format('registry::HKEY_CURRENT_USER\{0}', $PathFragment.Replace('\Wow6432Node',''))
            }
        }
    }
    # Remove duplicate created when -Architecture Both|x86 -HivesToSearch HKCU,HKLM is used
    $FullPaths = $FullPaths | Select-Object -Unique

    Write-Verbose "Will search the following registry paths based on [Architecture = $Architecture] [HivesToSearch = $HivesToSearch]"
    foreach ($RegPath in $FullPaths) {
        Write-Verbose $RegPath
    }

    $PropertyNames = 'DisplayName', 'DisplayVersion', 'PSChildName', 'Publisher', 'InstallDate', 'QuietUninstallString', 'UninstallString', 'WindowsInstaller', 'SystemComponent'

    $AllFoundObjects = Get-ItemProperty -Path $FullPaths -Name $propertyNames -ErrorAction SilentlyContinue

    foreach ($Result in $AllFoundObjects) {
        try {
            if ($Result.DisplayName -notlike $DisplayName) {
                Write-Verbose ('Skipping {0} as name does not match {1}' -f $Result.DisplayName, $DisplayName)
                continue
            }
            # Casting to [bool] will return $false if the property is 0 or not present
            if ($PSBoundParameters.ContainsKey('WindowsInstaller') -and [bool]$Result.WindowsInstaller -ne $WindowsInstaller) {
                Write-Verbose ('Skipping {0} as WindowsInstaller value {1} does not match {2}' -f [bool]$Result.DisplayName, $Result.WindowsInstaller, $WindowsInstaller)
                continue
            }
            if ($PSBoundParameters.ContainsKey('SystemComponent') -and [bool]$Result.SystemComponent -ne $SystemComponent) {
                Write-Verbose ('Skipping {0} as SystemComponent value {1} does not match {2}' -f [bool]$Result.DisplayName, $Result.SystemComponent, $SystemComponent)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionEqualTo') -and (ConvertTo-Version $Result.DisplayVersion) -ne (ConvertTo-Version $VersionEqualTo)) {
                Write-Verbose ('Skipping {0} as version {1} is not equal to {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionEqualTo)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionLessThan') -and (ConvertTo-Version $Result.DisplayVersion) -ge (ConvertTo-Version $VersionLessThan)) {
                Write-Verbose ('Skipping {0} as version {1} is not less than {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionLessThan)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionGreaterThan') -and (ConvertTo-Version $Result.DisplayVersion) -le (ConvertTo-Version $VersionGreaterThan)) {
                Write-Verbose ('Skipping {0} as version {1} is not greater than {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionGreaterThan)
                continue
            }
            # If we get here, then all criteria have been met
            Write-Verbose ('Found matching application {0} {1}' -f $Result.DisplayName, $Result.DisplayVersion)
            $Result | Select-Object -Property $PropertyNames
        }
        catch {
            # ConvertTo-Version will throw an error if it can't convert the version string to a [version] object
            Write-Warning "Error processing $($Result.DisplayName): $_"
            continue
        }

    }
}

function ConvertTo-Version {
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$VersionString
    )

    #Delete any backslashes
    $FormattedVersion = $VersionString.Replace('\','')

    #Replace build or _build with a .
    $FormattedVersion = $FormattedVersion -replace '(_|\s)build', '.'

    #Replace any underscore, dash. plus, or open bracket surrounded by digits with a .
    $FormattedVersion = $FormattedVersion -replace '(?<=\d)(_|-|\+|\()(?=\d)', '.'

    # If Version ends in a trailing ., delete it
    $FormattedVersion = $FormattedVersion -replace '\.$', ''

    # Delete anything that isn't a decimal or a dot
    $FormattedVersion = $FormattedVersion -replace '[^\d.]', ''

    # Delete any random instances of a-z followed by digits, such as b1, ac3, beta5
    $FormattedVersion = $FormattedVersion -replace '[a-z]+\d+', ''

    # Trim any version numbers with 5 or more parts down to 4
    $FormattedVersion = $FormattedVersion -replace '^((\d+\.){3}\d+).*', '$1'

    # Add a .0 to any single integers
    $FormattedVersion = $FormattedVersion -replace '^(\d+)$','$1.0'

    # Pad the version number out to contain 4 parts before casting to [version]
    $PeriodCount = $FormattedVersion.ToCharArray().Where{$_ -eq '.'}.Count
    switch($PeriodCount) {
        1 { $PaddedVersion = $FormattedVersion + '.0.0' }    # One period, so it's a two-part version number
        2 { $PaddedVersion = $FormattedVersion + '.0' }      # Two periods, so it's a three-part version number
        default { $PaddedVersion = $FormattedVersion }
    }

    try {
        [System.Version]::Parse($PaddedVersion)
    }
    catch {
        throw "'$VersionString' was formatted to '$FormattedVersion' which failed to be cast as [System.Version]: $_"
    }

}

function Split-UninstallString {
    param(
        [Parameter(Mandatory)]
        [String]$UninstallString
    )

    if ($UninstallString.StartsWith('"')) {
        [Int]$EndOfFilePath = [String]::Join('', $UninstallString[1..$UninstallString.Length]).IndexOf('"')
        [String]$FilePath   = [String]::Join('', $UninstallString[0..$EndOfFilePath]).Trim(' ','"')

        [Int]$StartOfArguments = $EndOfFilePath + 2
        [String]$Arguments     = [String]::Join('', $UninstallString[$StartOfArguments..$UninstallString.Length]).Trim()
    }
    else {
        for($i = 0; $i -lt $UninstallString.Length - 3; $i++) {
            if ($UninstallString.Substring($i, 4) -eq '.exe') {
                # If the character after .exe is null or whitespace, then with reasoanbly high confidence we have found the end of the file path
                if ([String]::IsNullOrWhiteSpace($UninstallString[$i + 4])) {
                    $EndOfFilePath = $i + 4
                    break
                }
            }
        }

        $FilePath  = [String]::Join('', $UninstallString[0..$EndOfFilePath]).Trim(' ','"')
        $Arguments = [String]::Join('', $UninstallString[$EndOfFilePath..$UninstallString.Length]).Trim()
    }

    return $FilePath, $Arguments
}

function Uninstall-Software {
    # Specifically written to take an input object made by Get-InstalledSoftware in this same script file
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$Software,

        [Parameter()]
        [String]$AdditionalArguments,

        [Parameter()]
        [String]$AdditionalMSIArguments,

        [Parameter()]
        [String]$AdditionalEXEArguments,

        [Parameter()]
        [String]$UninstallProcessName
    )

    Write-Verbose ('Found "{0}":' -f $Software.DisplayName)
    Write-Verbose ($Software | ConvertTo-Json)

    if ([String]::IsNullOrWhiteSpace($Software.UninstallString) -And [String]::IsNullOrWhiteSpace($Software.QuietUninstallString)) {
        Write-Verbose ('Can not uninstall software as UninstallString and QuietUninstallString are both empty for "{0}"' -f $Software.DisplayName)
    }
    else {
        $ProductCode = [Regex]::Match($Software.UninstallString, "^msiexec.+(\{.+\})", 'IgnoreCase').Groups[1].Value
        if ($ProductCode) { 
            Write-Verbose ('Found product code, will uninstall using "{0}"' -f $ProductCode)

            $MsiLog = '{0}\{1}_{2}.msi.log' -f 
                $env:temp, 
                [String]::Join('', $Software.DisplayName.Replace(' ','_').Split([System.IO.Path]::GetInvalidFileNameChars())), 
                [String]::Join('', $Software.DisplayVersion.Split([System.IO.Path]::GetInvalidFileNameChars()))

            $StartProcessSplat = @{
                FilePath     = 'msiexec.exe'
                ArgumentList = '/x', $ProductCode, '/qn', 'REBOOT=ReallySuppress', ('/l*v {0}' -f $MsiLog)
                Wait         = $true
                PassThru     = $true
                ErrorAction  = $ErrorActionPreference
            }

            if (-not [String]::IsNullOrWhiteSpace($AdditionalArguments)) {
                Write-Verbose ('Adding additional arguments "{0}" to uninstall string' -f $AdditionalArguments)
                $StartProcessSplat['ArgumentList'] = $StartProcessSplat['ArgumentList'] += $AdditionalArguments
            }
            elseif (-not [String]::IsNullOrWhiteSpace($AdditionalMSIArguments)) {
                Write-Verbose ('Adding additional MSI arguments "{0}" to uninstall string' -f $AdditionalMSIArguments)
                $StartProcessSplat['ArgumentList'] = $StartProcessSplat['ArgumentList'] += $AdditionalMSIArguments
            }

            $Message = 'Trying uninstall with "msiexec.exe {0}"' -f [String]$StartProcessSplat['ArgumentList']
        } 
        else { 
            Write-Verbose ('Could not parse product code from "{0}"' -f $Software.UninstallString)

            if (-not [String]::IsNullOrWhiteSpace($Software.QuietUninstallString)) {
                $UninstallString = $Software.QuietUninstallString
                Write-Verbose ('Found QuietUninstallString "{0}"' -f $Software.QuietUninstallString)
            }
            else {
                $UninstallString = $Software.UninstallString
                Write-Verbose ('Found UninstallString "{0}"' -f $Software.UninstallString)
            }

            $FilePath, $Arguments = Split-UninstallString $UninstallString

            $StartProcessSplat = @{
                FilePath     = $FilePath
                Wait         = $true
                PassThru     = $true
                ErrorAction  = $ErrorActionPreference
            }

            if (-not [String]::IsNullOrWhiteSpace($AdditionalArguments)) {
                Write-Verbose ('Adding additional arguments "{0}" to UninstallString' -f $AdditionalArguments)
                $Arguments = "{0} {1}" -f $Arguments, $AdditionalArguments
            }
            elseif (-not [String]::IsNullOrWhiteSpace($AdditionalEXEArguments)) {
                Write-Verbose ('Adding additional EXE arguments "{0}" to UninstallString' -f $AdditionalEXEArguments)
                $Arguments = "{0} {1}" -f $Arguments, $AdditionalEXEArguments
            }

            if (-not [String]::IsNullOrWhiteSpace($Arguments)) {
                $StartProcessSplat['ArgumentList'] = $Arguments.Trim()
                $Message = 'Trying uninstall with "{0} {1}"' -f $FilePath, $StartProcessSplat['ArgumentList']
            }
            else {
                $Message = 'Trying uninstall with "{0}"' -f $FilePath
            }
        }

        Write-Verbose $Message

        $Process = Start-Process @StartProcessSplat
        $Duration = $Process.ExitTime - $Process.StartTime
        Write-Verbose ('Exit code "{0}", duration "{1}"' -f $Process.ExitCode, $Duration)

        if ($PSBoundParameters.ContainsKey('UninstallProcessName')) {
            Start-Sleep -Seconds 5
            try {
                Write-Verbose ('Waiting for process "{0}" to finish' -f $UninstallProcessName)
                Wait-Process -Name $UninstallProcessName -Timeout 1800 -ErrorAction 'Stop'
            }
            catch {
                if ($_.FullyQualifiedErrorId -match 'NoProcessFoundForGivenName') {
                    Write-Verbose 'Process not found, continuing'
                }
                else {
                    throw
                }
            }

        }

        return $Process.ExitCode
    }
}

$log = '{0}\Uninstall-Software-{1}.log' -f $env:temp, $DisplayName.Replace(' ','_').Replace('*','')
$null = Start-Transcript -Path $log -Append -NoClobber -Force

$VerbosePreference = 'Continue'

$UninstallSoftwareSplat = @{
    AdditionalArguments    = $AdditionalArguments
    AdditionalMSIArguments = $AdditionalMSIArguments
    AdditionalEXEArguments = $AdditionalEXEArguments
    ErrorAction            = $ErrorActionPreference
}

if ($PSBoundParameters.ContainsKey('ProcessName')) {
    $Processes = Get-Process

    if ($Processes.Name -contains $ProcessName) {
        $Message = "Process '{0}' is already running before the uninstallation has even started, quitting" -f $ProcessName
        $Exception = [System.InvalidOperationException]::new($Message)
        $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
            $Exception, 
            'ProcessAlreadyRunning', 
            [System.Management.Automation.ErrorCategory]::InvalidOperation, 
            $ProcessName
        )
        Write-Error $ErrorRecord
        $null = Stop-Transcript
        $PSCmdlet.ThrowTerminatingError($ErrorRecord)
    }

    $UninstallSoftwareSplat['UninstallProcessName'] = $ProcessName -replace '\.exe$'
}

$GetInstalledSoftwareSplat = @{
    DisplayName     = $DisplayName
    Architecture    = $Architecture
    HivesToSearch   = $HivesToSearch
}
if ($PSBoundParameters.ContainsKey('WindowsInstaller')) { $GetInstalledSoftwareSplat['WindowsInstaller'] = $WindowsInstaller }
if ($PSBoundParameters.ContainsKey('SystemComponent')) { $GetInstalledSoftwareSplat['SystemComponent'] = $SystemComponent }
if ($PSBoundParameters.ContainsKey('VersionLessThan')) { $GetInstalledSoftwareSplat['VersionLessThan'] = $VersionLessThan }
if ($PSBoundParameters.ContainsKey('VersionEqualTo')) { $GetInstalledSoftwareSplat['VersionEqualTo'] = $VersionEqualTo }
if ($PSBoundParameters.ContainsKey('VersionGreaterThan')) { $GetInstalledSoftwareSplat['VersionGreaterThan'] = $VersionGreaterThan }

[array]$InstalledSoftware = Get-InstalledSoftware @GetInstalledSoftwareSplat

if ($InstalledSoftware.Count -eq 0) {
    Write-Verbose ('Software "{0}" not installed or version does not match criteria' -f $DisplayName)
}
elseif ($InstalledSoftware.Count -gt 1) {
    if ($UninstallAll.IsPresent) {
        foreach ($Software in $InstalledSoftware) {
            Uninstall-Software -Software $Software @UninstallSoftwareSplat
       }
    }
    else {
        Write-Verbose ('Found more than one instance of software "{0}". Quitting because not sure which UninstallString to execute. Consider using -UninstallAll switch if necessary.' -f $DisplayName)
    }
}
else {
    Uninstall-Software -Software $InstalledSoftware[0] @UninstallSoftwareSplat
}

$null = Stop-Transcript