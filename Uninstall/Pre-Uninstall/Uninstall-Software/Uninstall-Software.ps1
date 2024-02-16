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
    [ValidateSet(1, 0)]
    [Int]$WindowsInstaller,

    [Parameter()]
    [ValidateSet(1, 0)]
    [Int]$SystemComponent,

    [Parameter()]
    [Version]$VersionLessThan,

    [Parameter()]
    [Version]$VersionEqualTo,

    [Parameter()]
    [Version]$VersionGreaterThan,

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
        [ValidateSet('Both', 'x86', 'x64')]
        [String]$Architecture,

        [Parameter(Mandatory)]
        [ValidateSet('HKLM', 'HKCU')]
        [String[]]$HivesToSearch
    )
    $PathsToSearch = switch -regex ($Architecture) {
        'Both|x86' {
            # IntPtr will be 4 on a 32 bit system, so this add Wow6432Node if script running on 64 bit system
            if (-not ([IntPtr]::Size -eq 4)) {
                'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            }
            # If not running on a 64 bit system then we will search for 32 bit apps in the normal software node, non-Wow6432
            else {
                'Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            }
        }
        'Both|x64' {
            # If we are searching for a 64 bit application then we will only search the normal software node, non-Wow6432
            if (-not ([IntPtr]::Size -eq 4)) {
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
                [string]::Format('registry::HKEY_CURRENT_USER\{0}', $PathFragment)
            }
        }
    }

    Write-Verbose "Will search the following registry paths based on [Architecture = $Architecture] [HivesToSearch = $HivesToSearch]"
    foreach ($RegPath in $FullPaths) {
        Write-Verbose $RegPath
    }

    $propertyNames = 'DisplayName', 'DisplayVersion', 'PSChildName', 'Publisher', 'InstallDate', 'QuietUninstallString', 'UninstallString', 'WindowsInstaller', 'SystemComponent'

    $AllFoundObjects = Get-ItemProperty -Path $FullPaths -Name $propertyNames -ErrorAction SilentlyContinue

    foreach ($Result in $AllFoundObjects) {
        if (-not [string]::IsNullOrEmpty($Result.DisplayName)) {
            $Result | Select-Object -Property $propertyNames
        }
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
                if ($_.Exception.Message -match 'Cannot find a process with the name') {
                    Write-Verbose $_.Exception.Message.Replace('Verify the process name and call the cmdlet again.')
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

[array]$InstalledSoftware = Get-InstalledSoftware -Architecture $Architecture -HivesToSearch $HivesToSearch | Where-Object { 
    $Software = $_

    $_WindowsInstaller = if ($PSBoundParameters.ContainsKey('WindowsInstaller')) {
        switch ($WindowsInstaller) {
            1 {
                [int]$WindowsInstaller -eq [int]$Software.WindowsInstaller
            }
            0 {
                [int]$WindowsInstaller -eq [int]$Software.WindowsInstaller -Or [String]::IsNullOrWhiteSpace($Software.WindowsInstaller)
            }
        }
    }
    else {
        $true
    }

    $_SystemComponent = if ($PSBoundParameters.ContainsKey('SystemComponent')) {
        switch ($SystemComponent) {
            1 {
                [int]$SystemComponent -eq [int]$Software.SystemComponent
            }
            0 {
                [int]$SystemComponent -eq [int]$Software.SystemComponent -Or [String]::IsNullOrWhiteSpace($Software.SystemComponent)
            }
        }
    }
    else {
        $true
    }

    if ($_.DisplayName -like $DisplayName -And $_WindowsInstaller -And $_SystemComponent) {
        if ($PSBoundParameters.Keys -match 'Version(?:LessThan|EqualTo|GreaterThan)') {
            try {
                Write-Verbose ('Parsing DisplayVersion {0} for software "{1}"' -f $Software.DisplayVersion, $Software.DisplayName)
                [Version]$DisplayVersion = $Software.DisplayVersion.Replace('-','.').Replace('_','.')
            }
            catch {
                Write-Verbose ('Could not parse version {0} for software "{1}"' -f $Software.DisplayVersion, $Software.DisplayName)
                return $false
            }

            $Result = foreach ($Match in [Regex]::Matches($PSBoundParameters.Keys, 'Version(?:LessThan|EqualTo|GreaterThan)')) {
                $Operator = $Match.Value
                [Version]$VersionToCompare = $PSBoundParameters[$Operator]

                $OperatorHt = @{
                    'VersionLessThan'    = '-lt'
                    'VersionEqualTo'     = '-eq'
                    'VersionGreaterThan' = '-gt'
                }

                $r = switch ($Operator) {
                    'VersionLessThan' {
                        [Version]$DisplayVersion -lt [Version]$VersionToCompare
                    }
                    'VersionEqualTo' {
                        [Version]$DisplayVersion -eq [Version]$VersionToCompare
                    }
                    'VersionGreaterThan' {
                        [Version]$DisplayVersion -gt [Version]$VersionToCompare
                    }
                }

                Write-Verbose ('Comparing {0} {1} {2}: {3}' -f $DisplayVersion, $OperatorHt[$Operator], $VersionToCompare, $r)

                $r
            }

            if ($Result -notcontains $false) { 
                Write-Verbose ('Software "{0}" has version {1} which is {2} {3}' -f 
                    $Software.DisplayName, 
                    $Software.DisplayVersion, 
                    $Operator.Replace('Version','').Replace('Than',' than').Replace('EqualTo','equal to').ToLower(), 
                    $VersionToCompare)
                return $true 
            }
            else {
                Write-Verbose ('Software "{0}" has version {1} which is not {2} {3}' -f 
                    $Software.DisplayName, 
                    $Software.DisplayVersion, 
                    $Operator.Replace('Version','').Replace('Than',' than').Replace('EqualTo','equal to').ToLower(), 
                    $VersionToCompare)
                return $false
            }
        }
        else {
            return $true
        }
    }
    else {
        return $false
    }
}

if ($InstalledSoftware.Count -eq 0) {
    if ($PSBoundParameters.Keys -match '^Version(?:LessThan|EqualTo|GreaterThan)$') {
        Write-Verbose ('Software "{0}" not installed or version does not match criteria' -f $DisplayName)
    }
    else {
        Write-Verbose ('Software "{0}" not installed' -f $DisplayName)
    }
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
