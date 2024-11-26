<#
.SYNOPSIS
    Uninstall all, or specific versions of Python.
.DESCRIPTION
    This script is useful if you need to uninstall older version of Python before installing or updating newer versions. 

    Typically best used as a pre-script in most situations.

    A log file is created in the temp directory with the name "Uninstall-Python.log" which contains the verbose output of the script.

    An .msi log file is created in the temp directory with the name "<DisplayName>_<DisplayVersion>.msi.log" which contains the verbose output of the msiexec.exe process.
.PARAMETER Architecture
    Choose which registry key path to search in while looking for installed software. Acceptable values are:

    - "x86" will search in SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall on a 64-bit system.
    - "x64" will search in SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall.
    - "Both" will search in both key paths.
.PARAMETER VersionLessThan
    Specify a version number to use as an additional criteria when trying to find installed software. Only the first 2 parts of the version used for comparison.

.PARAMETER VersionLessThanOrEqualTo
    Specify a version number to use as an additional criteria when trying to find installed software. Only the first 2 parts of the version used for comparison.

.PARAMETER VersionEqualTo
    Specify a version number to use as an additional criteria when trying to find installed software. Only the first 2 parts of the version used for comparison.

.PARAMETER VersionNotEqualTo
    Specify a version number to use as an additional criteria when trying to find installed software. Only the first 2 parts of the version used for comparison.

.PARAMETER VersionGreaterThan
    Specify a version number to use as an additional criteria when trying to find installed software. Only the first 2 parts of the version used for comparison.

.PARAMETER VersionGreaterThanOrEqualTo
    Specify a version number to use as an additional criteria when trying to find installed software. Only the first 2 parts of the version used for comparison.

.PARAMETER Force
    This switch will instruct the script to force uninstallation of per-user instances via MsiZap.

.EXAMPLE
    Uninstall-Python.ps1 -VersionLessThan '3.13'
    
    Uninstalls all versions of Python lower than 3.13.
.EXAMPLE
    Uninstall-Python.ps1 -Architecture 'x86''

    Uninstalls all 32-bit versions of Python.
.EXAMPLE
    Uninstall-Python.ps1 -VersionGreaterThanOrEqualTo '3.0' -VersionLessThanOrEqualTo '3.12' -Force

    Uninstalls all versions of Python between v3.0.x and 3.12.x, force removing per-user installations via MsiZap.exe.
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet('Both', 'x86', 'x64')]
    [String]$Architecture = 'Both',

    [Parameter()]
    [String]$VersionLessThan,

    [Parameter()]
    [String]$VersionLessThanOrEqualTo,

    [Parameter()]
    [String]$VersionEqualTo,

    [Parameter()]
    [String]$VersionNotEqualTo,
    
    [Parameter()]
    [String]$VersionGreaterThan,

    [Parameter()]
    [String]$VersionGreaterThanOrEqualTo,

    [Parameter()]
    [Switch]$Force
)

#region function definitions
function Get-InstalledSoftware {
    param(
        [Parameter(Mandatory)]
        [String]$DisplayName,

        [Parameter()]
        [String]$Publisher,

        [Parameter()]
        [ValidateSet('Both', 'x86', 'x64')]
        [String]$Architecture = 'Both',

        [Parameter()]
        [ValidateSet('HKLM', 'HKCU', 'HKU')]
        [String[]]$HivesToSearch = 'HKLM',

        [Parameter()]
        [ValidateSet(1, 0)]
        [Int]$WindowsInstaller,
    
        [Parameter()]
        [ValidateSet(1, 0)]
        [Int]$SystemComponent,
    
        [Parameter()]
        [String]$VersionGreaterThan,
    
        [Parameter()]
        [String]$VersionGreaterThanOrEqualTo,
    
        [Parameter()]
        [String]$VersionLessThan,
    
        [Parameter()]
        [String]$VersionLessThanOrEqualTo,
    
        [Parameter()]
        [String]$VersionEqualTo,

        [Parameter()]
        [String]$VersionNotEqualTo,

        [Parameter()]
        [ValidateSet(1, 2, 3, 4)]
        [int16]$FieldCount = 4
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
                [string]::Format('registry::HKEY_CURRENT_USER\{0}', $PathFragment.Replace('\Wow6432Node', ''))
            }
            'HKU' {
                Get-ChildItem -Path 'registry::HKEY_USERS' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Where-Object { $_ -match '^HKEY_USERS\\S(-\d+)+$' } | ForEach-Object {
                    [string]::Format("registry::$_\{0}", $PathFragment.Replace('\Wow6432Node', ''))
                }
            }
        }
    }
    $FullPaths = $FullPaths | Select-Object -Unique

    # Write-Verbose "Will search the following registry paths based on [Architecture = $Architecture] [HivesToSearch = $HivesToSearch]"
    # foreach ($RegPath in $FullPaths) {
    #    Write-Verbose $RegPath
    # }

    $PropertyNames = 'DisplayName', 'DisplayVersion', 'PSPath', 'PSChildName', 'Publisher', 'InstallDate', 'InstallSource', 'QuietUninstallString', 'UninstallString', 'WindowsInstaller', 'SystemComponent'

    $AllFoundObjects = Get-ItemProperty -Path $FullPaths -Name $propertyNames -ErrorAction SilentlyContinue

    foreach ($Result in $AllFoundObjects) {
        try {
            if ($Result.DisplayName -notmatch $DisplayName) {
                #Write-Verbose ('Skipping {0} as name does not match {1}' -f $Result.DisplayName, $DisplayName)
                continue
            }
            if (!$Result.DisplayVersion) {
                #Write-Verbose ('Skipping {0} as DisplayVersion is missing' -f $Result.DisplayName)
                continue
            }
            if ($PSBoundParameters.ContainsKey('Publisher') -and $Result.Publisher -notmatch $Publisher) {
                #Write-Verbose ('Skipping {0} as publisher does not match {1}' -f $Result.Publisher, $Publisher)
                continue
            }
            # Casting to [bool] will return $false if the registry property is 0 or not present, and can also cast integers 0/1 to $false/$true.
            # Function accepts integers however, as supplying 1 for an expected bool works within powershell, but not on a powershell.exe command line.
            if ($PSBoundParameters.ContainsKey('WindowsInstaller') -and [bool]$Result.WindowsInstaller -ne [bool]$WindowsInstaller) {
                #Write-Verbose ('Skipping {0} as WindowsInstaller value {1} does not match {2}' -f $Result.DisplayName, $Result.WindowsInstaller, $WindowsInstaller)
                continue
            }
            if ($PSBoundParameters.ContainsKey('SystemComponent') -and [bool]$Result.SystemComponent -ne [bool]$SystemComponent) {
                #Write-Verbose ('Skipping {0} as SystemComponent value {1} does not match {2}' -f $Result.DisplayName, $Result.SystemComponent, $SystemComponent)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionEqualTo') -and (ConvertTo-Version $Result.DisplayVersion -FieldCount $FieldCount) -ne (ConvertTo-Version $VersionEqualTo -FieldCount $FieldCount)) {
                #Write-Verbose ('Skipping {0} as version {1} is not equal to {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionEqualTo)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionNotEqualTo') -and (ConvertTo-Version $Result.DisplayVersion -FieldCount $FieldCount) -eq (ConvertTo-Version $VersionNotEqualTo -FieldCount $FieldCount)) {
                #Write-Verbose ('Skipping {0} as version {1} is not equal to {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionEqualTo)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionGreaterThan') -and (ConvertTo-Version $Result.DisplayVersion -FieldCount $FieldCount) -le (ConvertTo-Version $VersionGreaterThan -FieldCount $FieldCount)) {
                #Write-Verbose ('Skipping {0} as version {1} is not greater than {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionGreaterThan)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionGreaterThanOrEqualTo') -and (ConvertTo-Version $Result.DisplayVersion -FieldCount $FieldCount) -lt (ConvertTo-Version $VersionGreaterThanOrEqualTo -FieldCount $FieldCount)) {
                #Write-Verbose ('Skipping {0} as version {1} is not greater than or equal to {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionGreaterThan)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionLessThan') -and (ConvertTo-Version $Result.DisplayVersion -FieldCount $FieldCount) -ge (ConvertTo-Version $VersionLessThan -FieldCount $FieldCount)) {
                #Write-Verbose ('Skipping {0} as version {1} is not less than {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionLessThan)
                continue
            }
            if ($PSBoundParameters.ContainsKey('VersionLessThanOrEqualTo') -and (ConvertTo-Version $Result.DisplayVersion -FieldCount $FieldCount) -gt (ConvertTo-Version $VersionLessThanOrEqualTo -FieldCount $FieldCount)) {
                #Write-Verbose ('Skipping {0} as version {1} is not less than {2}' -f $Result.DisplayName, $Result.DisplayVersion, $VersionLessThan)
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
        [String]$VersionString,

        [Parameter()]
        [ValidateSet(1, 2, 3, 4)]
        [int16]$FieldCount
    )

    #Delete any backslashes
    $FormattedVersion = $VersionString.Replace('\', '')

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
    $FormattedVersion = $FormattedVersion -replace '^(\d+)$', '$1.0'

    # Pad the version number out to contain 4 parts before casting to [version]
    $PeriodCount = $FormattedVersion.ToCharArray().Where{ $_ -eq '.' }.Count
    switch ($PeriodCount) {
        1 { $FormattedVersion = $FormattedVersion + '.0.0' }    # One period, so it's a two-part version number
        2 { $FormattedVersion = $FormattedVersion + '.0' }      # Two periods, so it's a three-part version number
        default { $FormattedVersion = $FormattedVersion }
    }

    if ($FieldCount) {
        $FormattedVersion = ($FormattedVersion.Split('.') | Select-Object -First $FieldCount) -join '.'
    }

    try {
        [System.Version]::Parse($FormattedVersion)
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
        [String]$FilePath = [String]::Join('', $UninstallString[0..$EndOfFilePath]).Trim(' ', '"')

        [Int]$StartOfArguments = $EndOfFilePath + 2
        [String]$Arguments = [String]::Join('', $UninstallString[$StartOfArguments..$UninstallString.Length]).Trim()
    }
    else {
        for ($i = 0; $i -lt $UninstallString.Length - 3; $i++) {
            if ($UninstallString.Substring($i, 4) -eq '.exe') {
                # If the character after .exe is null or whitespace, then with reasoanbly high confidence we have found the end of the file path
                if ([String]::IsNullOrWhiteSpace($UninstallString[$i + 4])) {
                    $EndOfFilePath = $i + 4
                    break
                }
            }
        }

        $FilePath = [String]::Join('', $UninstallString[0..$EndOfFilePath]).Trim(' ', '"')
        $Arguments = [String]::Join('', $UninstallString[$EndOfFilePath..$UninstallString.Length]).Trim()
    }

    return $FilePath, $Arguments
}

function Get-ProductState {
    param(
        [Parameter(Mandatory)]
        [String]$ProductCode
    )

    # TODO: Query the registry, instead of WindowsInstaller COM object, to determine if the product is installed for the current user, so we can log the username who has the software installed

    $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
    $ProductState = $WindowsInstaller.ProductState($ProductCode)
    [Runtime.Interopservices.Marshal]::ReleaseComObject($WindowsInstaller) | Out-Null

    return $ProductState
}

function Get-MsiInstallationContext {
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                if (-not ($_ -match '^\{?[A-F0-9]{8}-(?:[A-F0-9]{4}-){3}[A-F0-9]{12}\}?$')) {
                    throw "Invalid ProductCode format. Please provide a valid GUID."
                }
                return $true
            })]
        [String]$ProductCode
    )

    $CompressedGuid = -join (($ProductCode | Select-String -Pattern '^\{?(.{8})-(.{4})-(.{4})-(.{2})(.{2})-(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})\}?$' -AllMatches).Matches.Groups[1..11].Value | ForEach-Object { $CharArray = $_.ToCharArray(); [System.Array]::Reverse($CharArray); -join $CharArray })

    [Boolean]$AllUsers = Test-Path -Path "HKLM:\SOFTWARE\Classes\Installer\Products\$CompressedGuid"
    [Boolean]$CurrentUser = Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Installer\Products\$CompressedGuid"

    $SIDs = Get-ChildItem -Path 'Registry::HKEY_USERS\' -ErrorAction Ignore | Where-Object PSChildName -match '^S.+\d$' | Select-Object -ExpandProperty PSChildName
    $Users = foreach ($SID in $SIDs) {
        if (Test-Path -Path "Registry::HKEY_USERS\$SID\SOFTWARE\Microsoft\Installer\Products\$CompressedGuid") {
            try {
                (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
            }
            catch {
                $SID
            }
        }
    }

    [PSCustomObject]@{
        AllUsers    = $AllUsers
        CurrentUser = $CurrentUser
        Users       = $Users
    }
}

function Uninstall-Software {
    # Specifically written to take an input object made by Get-InstalledSoftware in this same script file
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$Software,

        [Parameter()]
        [String]$EnforcedArguments,

        [Parameter()]
        [String]$AdditionalArguments,

        [Parameter()]
        [String]$AdditionalMSIArguments,

        [Parameter()]
        [String]$AdditionalEXEArguments,

        [Parameter()]
        [String]$UninstallProcessName,

        [Parameter()]
        [Switch]$Force
    )

    Write-Verbose ('Uninstalling "{0}":' -f $Software.DisplayName)
    #Write-Verbose ($Software | ConvertTo-Json)

    if ([String]::IsNullOrWhiteSpace($Software.UninstallString) -And [String]::IsNullOrWhiteSpace($Software.QuietUninstallString)) {
        Write-Verbose ('Can not uninstall software as UninstallString and QuietUninstallString are both empty for "{0}"' -f $Software.DisplayName)
    }
    else {
        $ProductCode = [Regex]::Match($Software.UninstallString, "^msiexec.+(\{.+\})", 'IgnoreCase').Groups[1].Value

        if ($ProductCode) { 

            $ProductState = Get-ProductState -ProductCode $ProductCode

            if ($ProductState -eq 5) {
                Write-Verbose ('Product code "{0}" is installed.' -f $ProductCode)
            }
            elseif ($ProductState -eq 1) {
                Write-Verbose ('Product code "{0}" is advertised.' -f $ProductCode)
            }
            else {
                if ($ProductState -eq 2) {
                    Write-Verbose ('Product code "{0}" is installed for another user.' -f $ProductCode)
                }
                else {
                    Write-Verbose ('Product code "{0}" is not installed.' -f $ProductCode)
                }

                if ($Force.IsPresent) {
                    Write-Verbose 'Uninstall will be attempted anyway as -Force was specfied.'
                }
                else {
                    Write-Verbose 'Will not attempt to uninstall.'
                    return
                }
            }

            $MsiLog = '{0}\{1}_{2}.msi.log' -f 
            $env:temp, 
            [String]::Join('', $Software.DisplayName.Replace(' ', '_').Split([System.IO.Path]::GetInvalidFileNameChars())), 
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
            #Write-Verbose ('Could not parse product code from "{0}"' -f $Software.UninstallString)

            if (-not [String]::IsNullOrWhiteSpace($Software.QuietUninstallString)) {
                $UninstallString = $Software.QuietUninstallString
                #Write-Verbose ('Found QuietUninstallString "{0}"' -f $Software.QuietUninstallString)
            }
            else {
                $UninstallString = $Software.UninstallString
                #Write-Verbose ('Found UninstallString "{0}"' -f $Software.UninstallString)
            }

            $FilePath, $Arguments = Split-UninstallString $UninstallString

            $StartProcessSplat = @{
                FilePath    = $FilePath
                Wait        = $true
                PassThru    = $true
                ErrorAction = $ErrorActionPreference
            }

            if (-not [String]::IsNullOrWhiteSpace($AdditionalArguments)) {
                Write-Verbose ('Adding additional arguments "{0}" to UninstallString' -f $AdditionalArguments)
                $Arguments = "{0} {1}" -f $Arguments, $AdditionalArguments
            }
            elseif (-not [String]::IsNullOrWhiteSpace($AdditionalEXEArguments)) {
                Write-Verbose ('Adding additional EXE arguments "{0}" to UninstallString' -f $AdditionalEXEArguments)
                $Arguments = "{0} {1}" -f $Arguments, $AdditionalEXEArguments
            }
            elseif (-not [String]::IsNullOrWhiteSpace($EnforcedArguments)) {
                Write-Verbose ('Using enforced arguments "{0}" instead of those in UninstallString' -f $EnforcedArguments)
                $Arguments = $EnforcedArguments
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

        if ($Process.ExitCode -eq 1605 -and $Force.IsPresent) {
            Write-Verbose 'Exit code 1605 detected (product not installed) will be ignored since -Force was specified.'
            return 0
        }
        else {
            return $Process.ExitCode
        }
    
    }
}

function Remove-Paths {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]]$Path
    )

    process {
        foreach ($eachPath in $Path) {
            if (Test-Path $eachPath) {
                Write-Verbose "Removing $eachPath"
                try {
                    Remove-Item -Path $eachPath -Recurse -Force
                }
                catch {
                    Write-Warning "Failed to remove $eachPath`: $_"
                }
            }
            else {
                Write-Verbose "Path $eachPath does not exist"
            }
        }
    }
}

function Mount-RegistryHive {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [PSObject[]]$UserProfiles = (Get-UserProfiles)
    )

    Process {
        ForEach ($UserProfile in $UserProfiles) {
            [String]$UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"
            [String]$UserRegistryHiveFile = Join-Path -Path $UserProfile.ProfilePath -ChildPath 'NTUSER.DAT'

            #  Load the User profile registry hive if it is not already loaded because the User is logged in
            If (-not (Test-Path -LiteralPath $UserRegistryPath)) {
                #  Load the User registry hive if the registry hive file exists
                If (Test-Path -LiteralPath $UserRegistryHiveFile -PathType 'Leaf') {
                    Write-Verbose -Message "Loading the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]."
                    [String]$HiveLoadResult = & "$env:SystemRoot\System32\reg.exe" load "`"HKEY_USERS\$($UserProfile.SID)`"" "`"$UserRegistryHiveFile`""

                    If ($global:LastExitCode -ne 0) {
                        Throw "Failed to load the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Failure message [$HiveLoadResult]. Continue..."
                    }
                    $UserProfile
                }
                Else {
                    Throw "Failed to find the registry hive file [$UserRegistryHiveFile] for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Continue..."
                }
            }
            Else {
                Write-Verbose -Message "The user [$($UserProfile.NTAccount)] registry hive is already loaded in path [HKEY_USERS\$($UserProfile.SID)]."
            }
        }
    }
}

function Dismount-RegistryHive {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [PSObject[]]$UserProfiles = (Get-UserProfiles)
    )

    Process {
        ForEach ($UserProfile in $UserProfiles) {
            Try {
                [String]$UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"
                Write-Verbose -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]."
                [String]$HiveLoadResult = & "$env:SystemRoot\System32\reg.exe" unload "`"HKEY_USERS\$($UserProfile.SID)`"" 2>$null

                If ($global:LastExitCode -ne 0) {
                    #Write-Verbose -Message "REG.exe failed to unload the registry hive and exited with exit code [$($global:LastExitCode)]. Performing manual garbage collection to ensure successful unloading of registry hive."
                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()
                    Start-Sleep -Seconds 5

                    #Write-Verbose -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]."
                    [String]$HiveLoadResult = & "$env:SystemRoot\System32\reg.exe" unload "`"HKEY_USERS\$($UserProfile.SID)`""
                    If ($global:LastExitCode -ne 0) {
                        Throw "REG.exe failed with exit code [$($global:LastExitCode)] and result [$HiveLoadResult]."
                    }
                }
            }
            Catch {
                Write-Verbose -Message "Failed to unload the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. `r`n$_"
            }
        }
    }
}

function ConvertTo-NTAccountOrSID {
    <#
.SYNOPSIS

Convert between NT Account names and their security identifiers (SIDs).

.DESCRIPTION

Specify either the NT Account name or the SID and get the other. Can also convert well known sid types.

.PARAMETER AccountName

The Windows NT Account name specified in <domain>\<username> format.
Use fully qualified account names (e.g., <domain>\<username>) instead of isolated names (e.g, <username>) because they are unambiguous and provide better performance.

.PARAMETER SID

The Windows NT Account SID.

.PARAMETER WellKnownSIDName

Specify the Well Known SID name translate to the actual SID (e.g., LocalServiceSid).

To get all well known SIDs available on system: [Enum]::GetNames([Security.Principal.WellKnownSidType])

.PARAMETER WellKnownToNTAccount

Convert the Well Known SID to an NTAccount name

.INPUTS

System.String

Accepts a string containing the NT Account name or SID.

.OUTPUTS

System.String

Returns the NT Account name or SID.

.EXAMPLE

ConvertTo-NTAccountOrSID -AccountName 'CONTOSO\User1'

Converts a Windows NT Account name to the corresponding SID

.EXAMPLE

ConvertTo-NTAccountOrSID -SID 'S-1-5-21-1220945662-2111687655-725345543-14012660'

Converts a Windows NT Account SID to the corresponding NT Account Name

.EXAMPLE

ConvertTo-NTAccountOrSID -WellKnownSIDName 'NetworkServiceSid'

Converts a Well Known SID name to a SID

.NOTES

This is an internal script function and should typically not be called directly.

The conversion can return an empty result if the user account does not exist anymore or if translation fails.

http://blogs.technet.com/b/askds/archive/2011/07/28/troubleshooting-sid-translation-failures-from-the-obvious-to-the-not-so-obvious.aspx

.LINK

https://psappdeploytoolkit.com

.LINK

http://msdn.microsoft.com/en-us/library/system.security.principal.wellknownsidtype(v=vs.110).aspx

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'NTAccountToSID', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$AccountName,
        [Parameter(Mandatory = $true, ParameterSetName = 'SIDToNTAccount', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SID,
        [Parameter(Mandatory = $true, ParameterSetName = 'WellKnownName', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$WellKnownSIDName,
        [Parameter(Mandatory = $false, ParameterSetName = 'WellKnownName')]
        [ValidateNotNullOrEmpty()]
        [Switch]$WellKnownToNTAccount
    )

    Process {
        Try {
            Switch ($PSCmdlet.ParameterSetName) {
                'SIDToNTAccount' {
                    [String]$msg = "the SID [$SID] to an NT Account name"

                    Try {
                        $NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($SID)
                        $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
                        Write-Output -InputObject ($NTAccount)
                    }
                    Catch {
                        Write-Verbose -Message "Unable to convert $msg. It may not be a valid account anymore or there is some other problem. `r`n$_"
                    }
                }
                'NTAccountToSID' {
                    [String]$msg = "the NT Account [$AccountName] to a SID"

                    Try {
                        $NTAccount = New-Object -TypeName 'System.Security.Principal.NTAccount' -ArgumentList ($AccountName)
                        $NTAccountSID = $NTAccount.Translate([Security.Principal.SecurityIdentifier])
                        Write-Output -InputObject ($NTAccountSID)
                    }
                    Catch {
                        Write-Verbose -Message "Unable to convert $msg. It may not be a valid account anymore or there is some other problem. `r`n$_"
                    }
                }
                'WellKnownName' {
                    If ($WellKnownToNTAccount) {
                        [String]$ConversionType = 'NTAccount'
                    }
                    Else {
                        [String]$ConversionType = 'SID'
                    }
                    [String]$msg = "the Well Known SID Name [$WellKnownSIDName] to a $ConversionType"

                    #  Get the SID for the root domain
                    Try {
                        $MachineRootDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'Stop').Domain.ToLower()
                        $ADDomainObj = New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList ("LDAP://$MachineRootDomain")
                        $DomainSidInBinary = $ADDomainObj.ObjectSid
                        $DomainSid = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($DomainSidInBinary[0], 0)
                    }
                    Catch {
                        Write-Verbose -Message 'Unable to get Domain SID from Active Directory. Setting Domain SID to $null.'
                        $DomainSid = $null
                    }

                    #  Get the SID for the well known SID name
                    $WellKnownSidType = [Security.Principal.WellKnownSidType]::$WellKnownSIDName
                    $NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($WellKnownSidType, $DomainSid)

                    If ($WellKnownToNTAccount) {
                        $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
                        Write-Output -InputObject ($NTAccount)
                    }
                    Else {
                        Write-Output -InputObject ($NTAccountSID)
                    }
                }
            }
        }
        Catch {
            Write-Verbose -Message "Failed to convert $msg. It may not be a valid account anymore or there is some other problem. `r`n$_"
        }
    }
}

function Get-UserProfiles {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]$ExcludeSID
    )

    Process {
        Try {
            ## Get the User Profile Path, User Account Sid, and the User Account Name for all users that log onto the machine
            [String]$UserProfileListRegKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
            [PSObject[]]$UserProfiles = Get-ChildItem -LiteralPath $UserProfileListRegKey -ErrorAction 'Stop' |
            ForEach-Object {
                Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'Stop' | Where-Object { ($_.ProfileImagePath) } |
                Select-Object @{ Label = 'NTAccount'; Expression = { $(ConvertTo-NTAccountOrSID -SID $_.PSChildName).Value } }, @{ Label = 'SID'; Expression = { $_.PSChildName } }, @{ Label = 'ProfilePath'; Expression = { $_.ProfileImagePath } }
            } |
            Where-Object { $_.NTAccount } # This removes the "defaultuser0" account, which is a Windows 10 bug
            If ($ExcludeSID) {
                [PSObject[]]$UserProfiles = $UserProfiles | Where-Object { $_.SID -notin $ExcludeSID }
            }

            Write-Output -InputObject ($UserProfiles)
        }
        Catch {
            Write-Verbose -Message "Failed to create a custom object representing all user profiles on the machine. `r`n$_"
        }
    }
}

function Get-MsiZap {
    $base64 = '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aABlAGQAIABjAG8AbQBwAG8AbgBlAG4AdABzACAAcQB1AGEAbABpAGYAaQBlAHIAAAAAAHAAdQBiAGwAaQBzAGgAZQBkACAAYwBvAG0AcABvAG4AZQBuAHQAAABDAG8AbQBwAG8AbgBlAG4AdABzAAAAAABBAEwATABQAFIATwBEAFUAQwBUAFMAAABSdGxOdFN0YXR1c1RvRG9zRXJyb3IAAABOdERlbGV0ZUtleQBuAHQAZABsAGwALgBkAGwAbAAAAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAHMAdABvAHAAIABNAHMAaQAgAHMAZQByAHYAaQBjAGUAOgAgAEUAcgByAG8AcgAgACUAZAAKAAAATQBzAGkAUwBlAHIAdgBlAHIAAABPAHUAdAAgAG8AZgAgAG0AZQBtAG8AcgB5AAoAAAAAAENoZWNrVG9rZW5NZW1iZXJzaGlwAAAAAGEAZAB2AGEAcABpADMAMgAuAGQAbABsAAAAAAAgACAAIABTAGUAdABTAGUAYwB1AHIAaQB0AHkASQBuAGYAbwAgAEUAcgByAG8AcgAgACUAdQAKAAAAAAAgACAAIABBAGwAbABvAGMAYQB0AGUAQQBuAGQASQBuAGkAdABpAGEAbABpAHoAZQBTAGkAZAAgAEUAcgByAG8AcgAgACUAdQAKAAAAAAAAACAAIAAgAEUAcgByAG8AcgAgACUAZAAgAG8AcABlAG4AaQBuAGcAIABzAHUAYgBrAGUAeQA6ACAAJwAlAHMAJwAKAAAAIAAgACAAUwBlAHQARQBuAHQAcgBpAGUAcwBJAG4AQQBjAGwAIABFAHIAcgBvAHIAIAAlAHUACgAAAAAAIAAgACAARwBlAHQAUwBlAGMAdQByAGkAdAB5AEkAbgBmAG8AIABFAHIAcgBvAHIAIAAlAHUACgAAAAAAIAAgACAAJQBzACAAXAAlAHMACgAAAAAAUgBlAG0AbwB2AGUAZAAgAAAAAABSAGUAbQBvAHYAZQBkACAAQQBDAEwAcwAgAGYAcgBvAG0AAAAAAAAAIAAgACAAQwBvAHUAbABkACAAbgBvAHQAIABkAGUAbABlAHQAZQAgAHMAdQBiAGsAZQB5ADoAIAAlAHMACgAgACAAIAAgACAAIAAlAHMAAAAgACAAIABFAHIAcgBvAHIAIAAlAGQAIABhAHQAdABlAG0AcAB0AGkAbgBnACAAdABvACAAZABlAGwAZQB0AGUAIABzAHUAYgBrAGUAeQA6ACAAJwAlAHMAJwAKAAAAAAAgACAAIABVAG4AYQBiAGwAZQAgAHQAbwAgAGEAZABkACAAYQBkAG0AaQBuACAAZgB1AGwAbAAgAGMAbwBuAHQAcgBvAGwAIAB0AG8AIAByAGUAZwAgAGsAZQB5ACAAJwAlAHMAJwAuACAARQByAHIAbwByADoAIAAlAGQACgAAACAAIAAgAEEAQwBMAHMAIABjAGgAYQBuAGcAZQBkACAAdABvACAAYQBkAG0AaQBuACAAbwB3AG4AZQByAHMAaABpAHAAIABhAG4AZAAgAGYAdQBsAGwAIABjAG8AbgB0AHIAbwBsACAAZgBvAHIAIABrAGUAeQAgACcAJQBzACcACgAAAAAAAAAgACAAIABFAHIAcgBvAHIAIAAlAGQAIABzAGUAdAB0AGkAbgBnACAAQgBVAEkATABUAEkATgBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwAgAGEAcwAgAG8AdwBuAGUAcgAgAG8AZgAgAGsAZQB5ACAAJwAlAHMAJwAKAAAAAABTAGUAVABhAGsAZQBPAHcAbgBlAHIAcwBoAGkAcABQAHIAaQB2AGkAbABlAGcAZQAAAAAAIAAgACAARgBhAGkAbABlAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQAgAGEAbABsACAAcwB1AGIAawBlAHkAcwAuACAARQByAHIAbwByADoAIAAlAGQACgAAAAAAIAAgACAARQByAHIAbwByACAAJQBkACAAYQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAG8AcABlAG4AIABcACUAcwAKAAAAIAAgACAAQwBvAHUAbABkACAAbgBvAHQAIABvAHAAZQBuACAASABLAEwATQBcACUAcwAuACAARQByAHIAbwByADoAIAAlAGQACgAAAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABVAG4AaQBuAHMAdABhAGwAbAAAAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABwAHIAbwBkAHUAYwB0ACAAJQBzACAAZABhAHQAYQAgAGkAbgAgAHQAaABlACAASABLAEwATQBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAFUAbgBpAG4AcwB0AGEAbABsACAAawBlAHkALgAgAC4AIAAuAAoAAAB7AEEATABMACAAUABSAE8ARABVAEMAVABTAH0AAAAAACAAIAAgAEMAbwB1AGwAZAAgAG4AbwB0ACAAbwBwAGUAbgAgACUAcwBcACUAcwAuACAARQByAHIAbwByADoAIAAlAGQACgAAACAAIAAgACUAcwBcACUAcwAgAGsAZQB5ACAAaQBzACAAbgBvAHQAIABwAHIAZQBzAGUAbgB0AC4ACgAAAAAAAAAgACAAIABVAG4AYQBiAGwAZQAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlACAAYQBsAGwAIABwAHIAbwBkAHUAYwB0ACAAYwBsAGkAZQBuAHQAIABpAG4AZgBvAC4AIABFAHIAcgBvAHIAOgAgACUAZAAKAAAAAAAgACAAIABFAHIAcgBvAHIAIABkAGUAbABlAHQAaQBuAGcAIABjAGwAaQBlAG4AdAAgAG8AZgAgAGMAbwBtAHAAbwBuAGUAbgB0ACAAJQBzAC4AIABFAHIAcgBvAHIAOgAgACUAZAAKAAAAAAAAAAAAIAAgACAAUgBlAG0AbwB2AGUAZAAgAEEAQwBMAHMAIABmAG8AcgAgAGMAbwBtAHAAbwBuAGUAbgB0ACAAJQBzAAoAAAAAAAAAIAAgACAAUgBlAG0AbwB2AGUAZAAgAGMAbABpAGUAbgB0ACAAbwBmACAAYwBvAG0AcABvAG4AZQBuAHQAIAAlAHMACgAAAAAAIAAgACAARgBhAGkAbABlAGQAIAB0AG8AIABhAGQAZAAgAGEAZABtAGkAbgAgAGYAdQBsAGwAIABjAG8AbgB0AHIAbwBsACAAdABvACAAawBlAHkAIAAnACUAcwAnAC4AIABFAHIAcgBvAHIAOgAgACUAZAAKAAAAIAAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABwAHIAbwBkAHUAYwB0ACAAJQBzACAAYwBsAGkAZQBuAHQAIABpAG4AZgBvACAAZABhAHQAYQAuACAALgAgAC4ACgAAACAAIAAgAFIAZQBtAG8AdgBlAGQAIAAlAHMAXAAlAHMAXAAlAHMACgAAAAAASABLAEMAVQAAAAAASABLAEwATQAAAAAAIAAgACAAUgBlAG0AbwB2AGUAZAAgACUAcwAgAHYAYQBsAHUAZQAgACUAcwAKAAAAIAAgACAAUgBlAG0AbwB2AGUAZAAgAHAAcgBvAGQAdQBjAHQAJwBzACAAJQBzACAAdgBhAGwAdQBlACAAJQBzACAAZgBvAHIAIAAlAHMAIAAlAHMACgAAACAAIABTAGUAYQByAGMAaABpAG4AZwAgACUAcwBcACUAcwAgAGYAbwByACAAJQBzACAAZABhAHQAYQAgAGYAbwByACAAdABoAGUAIABwAHIAbwBkAHUAYwB0ACAAJQBzAC4AIAAuACAALgAKAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAFIAbwBsAGwAYgBhAGMAawAAAAAAAAAAAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB0AGgAZQAgAFcAaQBuAGQAbwB3AHMAIABJAG4AcwB0AGEAbABsAGUAcgAgAFIAbwBsAGwAYgBhAGMAawAgAGsAZQB5AC4AIAAuACAALgAKAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAEkAbgBQAHIAbwBnAHIAZQBzAHMAAAAAAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB0AGgAZQAgAFcAaQBuAGQAbwB3AHMAIABJAG4AcwB0AGEAbABsAGUAcgAgAEkAbgBQAHIAbwBnAHIAZQBzAHMAIABrAGUAeQAuACAALgAgAC4ACgAAAAAAAAAAAAoAKgAgAEEAbgB5ACAAcAB1AGIAbABpAHMAaABlAGQAIABpAGMAbwBuAHMAIAB3AGkAbABsACAAYgBlACAAcgBlAG0AbwB2AGUAZAAuAAoACgAqACAAVABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAGsAZQB5AHMAIAB3AGkAbABsACAAYgBlACAAZABlAGwAZQB0AGUAZAA6AAoAIAAgAEgASwBDAFUAXABTAG8AZgB0AHcAYQByAGUAXABDAGwAYQBzAHMAZQBzAFwASQBuAHMAdABhAGwAbABlAHIACgAgACAASABLAEMAVQBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwASQBuAHMAdABhAGwAbABlAHIACgAgACAASABLAEwATQBcAFMAbwBmAHQAdwBhAHIAZQBcAEMAbABhAHMAcwBlAHMAXABJAG4AcwB0AGEAbABsAGUAcgAKACAAIABIAEsATABNAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIACgAgAE8AbgAgAE4AVAA6AAoAIAAgAEgASwBMAE0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAFUAcwBlAHIARABhAHQAYQBcADwAVQBzAGUAcgAgAEkARAA+AAoAIAAgAEgASwBMAE0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABVAG4AaQBuAHMAdABhAGwAbABcAHsAUAByAG8AZAB1AGMAdABDAG8AZABlAH0AIAAtACAAbwBuAGwAeQAgAGkAZgAgAHQAaABlAHIAZQAgAGEAcgBlACAAbgBvACAAbQBvAHIAZQAgAGkAbgBzAHQAYQBsAGwAYQB0AGkAbwBuAHMAIABvAGYAIAB7AFAAcgBvAGQAdQBjAHQAQwBvAGQAZQB9AAoAIABPAG4AIABXAGkAbgA5AHgAOgAKACAAIABIAEsATABNAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABVAHMAZQByAEQAYQB0AGEAXABDAG8AbQBtAG8AbgBVAHMAZQByAAoAIAAgAEgASwBMAE0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABVAG4AaQBuAHMAdABhAGwAbABcAHsAUAByAG8AZAB1AGMAdABDAG8AZABlAH0ACgAKACoAIABTAGgAYQByAGUAZAAgAEQATABMACAAcgBlAGYAYwBvAHUAbgB0AHMAIABmAG8AcgAgAGYAaQBsAGUAcwAgAHIAZQBmAGMAbwB1AG4AdABlAGQAIABiAHkAIAB0AGgAZQAgAFcAaQBuAGQAbwB3AHMAIABJAG4AcwB0AGEAbABsAGUAcgAgAHcAaQBsAGwAIABiAGUAIABhAGQAagB1AHMAdABlAGQALgAKAAoAKgAgAFQAaABlACAAZgBvAGwAbABvAHcAaQBuAGcAIABmAG8AbABkAGUAcgBzACAAdwBpAGwAbAAgAGIAZQAgAGQAZQBsAGUAdABlAGQAOgAKACAAIAAlACUAVQBTAEUAUgBQAFIATwBGAEkATABFACUAJQBcAE0AUwBJAAoAIAAgAHsAQQBwAHAARABhAHQAYQB9AFwATQBpAGMAcgBvAHMAbwBmAHQAXABJAG4AcwB0AGEAbABsAGUAcgAKACAAIAAlACUAVwBJAE4ARABJAFIAJQAlAFwATQBTAEkACgAgACAAJQAlAFcASQBOAEQASQBSACUAJQBcAEkAbgBzAHQAYQBsAGwAZQByAAoAIAAgAFgAOgBcAGMAbwBuAGYAaQBnAC4AbQBzAGkAIAAoAGYAbwByACAAZQBhAGMAaAAgAGwAbwBjAGEAbAAgAGQAcgBpAHYAZQApAAoACgBOAG8AdABlAHMALwBXAGEAcgBuAGkAbgBnAHMAOgAgAE0AcwBpAFoAYQBwACAAYgBsAGkAcwBzAGYAdQBsAGwAeQAgAGkAZwBuAG8AcgBlAHMAIABBAEMATAAnAHMAIABpAGYAIAB5AG8AdQAnAHIAZQAgAGEAbgAgAEEAZABtAGkAbgAuAAoAAABDAG8AcAB5AHIAaQBnAGgAdAAgACgAQwApACAATQBpAGMAcgBvAHMAbwBmAHQAIABDAG8AcgBwAG8AcgBhAHQAaQBvAG4ALgAgACAAQQBsAGwAIAByAGkAZwBoAHQAcwAgAHIAZQBzAGUAcgB2AGUAZAAuAAoATQBTAEkAWgBBAFAAIAAtACAAWgBhAHAAcwAgACgAYQBsAG0AbwBzAHQAKQAgAGEAbABsACAAdAByAGEAYwBlAHMAIABvAGYAIABXAGkAbgBkAG8AdwBzACAASQBuAHMAdABhAGwAbABlAHIAIABkAGEAdABhACAAZgByAG8AbQAgAHkAbwB1AHIAIABtAGEAYwBoAGkAbgBlAC4ACgAKAFUAcwBhAGcAZQA6ACAAbQBzAGkAegBhAHAAIABUAFsAVwBBACEAXQAgAHsAcAByAG8AZAB1AGMAdAAgAGMAbwBkAGUAfQAKACAAIAAgACAAIAAgACAAbQBzAGkAegBhAHAAIABUAFsAVwBBACEAXQAgAHsAbQBzAGkAIABwAGEAYwBrAGEAZwBlAH0ACgAgACAAIAAgACAAIAAgAG0AcwBpAHoAYQBwACAAKgBbAFcAQQAhAF0AIABBAEwATABQAFIATwBEAFUAQwBUAFMACgAgACAAIAAgACAAIAAgAG0AcwBpAHoAYQBwACAAUABXAFMAQQA/ACEACgAKACAAIAAgACAAIAAgACAAKgAgAD0AIAByAGUAbQBvAHYAZQAgAGEAbABsACAAVwBpAG4AZABvAHcAcwAgAEkAbgBzAHQAYQBsAGwAZQByACAAZgBvAGwAZABlAHIAcwAgAGEAbgBkACAAcgBlAGcAawBlAHkAcwA7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgAGEAZABqAHUAcwB0ACAAcwBoAGEAcgBlAGQAIABEAEwATAAgAGMAbwB1AG4AdABzADsAIABzAHQAbwBwACAAVwBpAG4AZABvAHcAcwAgAEkAbgBzAHQAYQBsAGwAZQByACAAcwBlAHIAdgBpAGMAZQAKACAAIAAgACAAIAAgACAAVAAgAD0AIAByAGUAbQBvAHYAZQAgAGEAbABsACAAaQBuAGYAbwAgAGYAbwByACAAZwBpAHYAZQBuACAAcAByAG8AZAB1AGMAdAAgAGMAbwBkAGUACgAgACAAIAAgACAAIAAgAFAAIAA9ACAAcgBlAG0AbwB2AGUAIABJAG4ALQBQAHIAbwBnAHIAZQBzAHMAIABrAGUAeQAKACAAIAAgACAAIAAgACAAUwAgAD0AIAByAGUAbQBvAHYAZQAgAFIAbwBsAGwAYgBhAGMAawAgAEkAbgBmAG8AcgBtAGEAdABpAG8AbgAKACAAIAAgACAAIAAgACAAQQAgAD0AIABmAG8AcgAgAGEAbgB5ACAAcwBwAGUAYwBpAGYAaQBlAGQAIAByAGUAbQBvAHYAYQBsACwAIABqAHUAcwB0ACAAYwBoAGEAbgBnAGUAIABBAEMATABzACAAdABvACAAQQBkAG0AaQBuACAARgB1AGwAbAAgAEMAbwBuAHQAcgBvAGwACgAgACAAIAAgACAAIAAgAFcAIAA9ACAAZgBvAHIAIABhAGwAbAAgAHUAcwBlAHIAcwAgACgAYgB5ACAAZABlAGYAYQB1AGwAdAAsACAAbwBuAGwAeQAgAGYAbwByACAAdABoAGUAIABjAHUAcgByAGUAbgB0ACAAdQBzAGUAcgApAAoAIAAgACAAIAAgACAAIABNACAAPQAgAHIAZQBtAG8AdgBlACAAYQAgAG0AYQBuAGEAZwBlAGQAIABwAGEAdABjAGgAIAByAGUAZwBpAHMAdAByAGEAdABpAG8AbgAgAGkAbgBmAG8ACgAgACAAIAAgACAAIAAgAEcAIAA9ACAAcgBlAG0AbwB2AGUAIABvAHIAcABoAGEAbgBlAGQAIABjAGEAYwBoAGUAZAAgAFcAaQBuAGQAbwB3AHMAIABJAG4AcwB0AGEAbABsAGUAcgAgAGQAYQB0AGEAIABmAGkAbABlAHMAIAAoAGYAbwByACAAYQBsAGwAIAB1AHMAZQByAHMAKQAKACAAIAAgACAAIAAgACAAPwAgAD0AIAB2AGUAcgBiAG8AcwBlACAAaABlAGwAcAAKACAAIAAgACAAIAAgACAAIQAgAD0AIABmAG8AcgBjAGUAIAAnAHkAZQBzACcAIAByAGUAcwBwAG8AbgBzAGUAIAB0AG8AIABhAG4AeQAgAHAAcgBvAG0AcAB0AAoACgBDAEEAVQBUAEkATwBOADoAIABQAHIAbwBkAHUAYwB0AHMAIABpAG4AcwB0AGEAbABsAGUAZAAgAGIAeQAgAHQAaABlACAAVwBpAG4AZABvAHcAcwAgAEkAbgBzAHQAYQBsAGwAZQByACAAbQBhAHkAIABmAGEAaQBsACAAdABvAAoAIAAgACAAIAAgACAAIAAgACAAZgB1AG4AYwB0AGkAbwBuACAAYQBmAHQAZQByACAAdQBzAGkAbgBnACAAbQBzAGkAegBhAHAACgAKAE4ATwBUAEUAOgAgAE0AcwBpAFoAYQBwACAAcgBlAHEAdQBpAHIAZQBzACAAYQBkAG0AaQBuACAAcAByAGkAdgBpAGwAZQBnAGUAcwAgAHQAbwAgAHIAdQBuACAAYwBvAHIAcgBlAGMAdABsAHkALgAgAFQAaABlACAAVwAgAG8AcAB0AGkAbwBuACAAcgBlAHEAdQBpAHIAZQBzACAAdABoAGEAdAAgAHQAaABlACAAcAByAG8AZgBpAGwAZQBzACAAZgBvAHIAIABhAGwAbAAgAG8AZgAgAHQAaABlACAAdQBzAGUAcgBzACAAYgBlACAAbABvAGEAZABlAGQALgAKAAAAQwBvAG0AbQBvAG4AVQBzAGUAcgAAAAAAAAAAAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgBzAHQAYQBsAGwAZQByAFwATQBhAG4AYQBnAGUAZAAAAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAVQBzAGUAcgBEAGEAdABhAAAAAAAAAAAATQBzAGkAWgBhAHAAIAB3AGEAcgBuAGkAbgBnADoAIABSAGUAZwBRAHUAZQByAHkAVgBhAGwAdQBlAEUAeAAgAGYAYQBpAGwAZQBkACAAcgBlAHQAdQByAG4AaQBuAGcAIAAlAGQAIAB3AGgAaQBsAGUAIAByAGUAdAByAGkAZQB2AGkAbgBnACAAJwAlAHMAJwAgAGYAbwBsAGQAZQByAC4AIAAgAEcAZQB0AEwAYQBzAHQARQByAHIAbwByACAAcgBlAHQAdQByAG4AcwAgACUAZAAuAAoAAAAAAEMAbwBtAG0AbwBuACAARgBpAGwAZQBzAAAAAABDAG8AbQBtAG8AbgBGAGkAbABlAHMARABpAHIAAAAAAEMAbwBtAG0AbwBuACAARgBpAGwAZQBzACAAKAB4ADgANgApAAAAAABDAG8AbQBtAG8AbgBGAGkAbABlAHMARABpAHIAIAAoAHgAOAA2ACkAAAAAAFAAcgBvAGcAcgBhAG0AIABGAGkAbABlAHMAAABQAHIAbwBnAHIAYQBtAEYAaQBsAGUAcwBEAGkAcgAAAFAAcgBvAGcAcgBhAG0AIABGAGkAbABlAHMAIAAoAHgAOAA2ACkAAABQAHIAbwBnAHIAYQBtAEYAaQBsAGUAcwBEAGkAcgAgACgAeAA4ADYAKQAAAAAAAABNAHMAaQBaAGEAcAAgAHcAYQByAG4AaQBuAGcAOgAgAFIAZQBnAE8AcABlAG4ASwBlAHkARQB4ACAAZgBhAGkAbABlAGQAIAByAGUAdAB1AHIAbgBpAG4AZwAgACUAZAAgAHcAaABpAGwAZQAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABzAHAAZQBjAGkAYQBsACAAZgBvAGwAZABlAHIAcwAuACAAIABHAGUAdABMAGEAcwB0AEUAcgByAG8AcgAgAHIAZQB0AHUAcgBuAHMAIAAlAGQALgAKAAAAAAAAAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgAAAAAAAABNAHMAaQBaAGEAcAAgAHcAYQByAG4AaQBuAGcAOgAgACcAJQBzACcAIABpAHMAIABhACAAcwB0AHIAYQBuAGcAZQAgADYANAAtAGIAaQB0ACAAcwB5AHMAdABlAG0AIABkAGkAcgBlAGMAdABvAHIAeQAuACAAVwBlACcAbABsACAAbgBvAHQAIABhAHQAdABlAG0AcAB0ACAAdABvACAAZgBpAGcAdQByAGUAIABvAHUAdAAgAGkAdABzACAAMwAyAC0AYgBpAHQAIABjAG8AdQBuAHQAZQByAHAAYQByAHQALgAKAAAAXABzAHkAcwB3AG8AdwA2ADQAAAAAAAAATQBzAGkAWgBhAHAAIAB3AGEAcgBuAGkAbgBnADoAIABHAGUAdABTAHkAcwB0AGUAbQBEAGkAcgBlAGMAdABvAHIAeQAgAGMAYQBsAGwAIABmAGEAaQBsAGUAZAAuACAARwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAByAGUAdAB1AHIAbgBlAGQAIAAlAGQALgAKAAAAAABNAHMAaQBaAGEAcAAgAHcAYQByAG4AaQBuAGcAOgAgAEYAYQBpAGwAZQBkACAAdABvACAAYQBsAGwAbwBjAGEAdABlACAAZQBuAG8AdQBnAGgAIABtAGUAbQBvAHIAeQAgAHQAbwAgAGwAbwBhAGQAIABzAHAAZQBjAGkAYQBsACAAZgBvAGwAZABlAHIAcwAuAAoAAAAAAE0AcwBpAFoAYQBwACAAdwBhAHIAbgBpAG4AZwA6ACAAZABpAGQAIABuAG8AdAAgAHMAdwBhAHAAIABzAHAAZQBjAGkAYQBsACAAZgBvAGwAZABlAHIAIABkAHUAZQAgAHQAbwAgAGkAbgB2AGEAbABpAGQAIABpAG4AZABlAHgALgAKAAAAAABNAHMAaQBaAGEAcAAgAHcAYQByAG4AaQBuAGcAOgAgAGQAaQBkACAAbgBvAHQAIABzAHcAYQBwACAAJwAlAHMAJwAgAGYAbwBsAGQAZQByACAAYgBlAGMAYQB1AHMAZQAgAG8AZgAgAHUAbgBpAG4AaQB0AGkAYQBsAGkAegBlAGQAIAByAGUAcABsAGEAYwBlAG0AZQBuAHQALgAKAAAATQBzAGkAWgBhAHAAIAB3AGEAcgBuAGkAbgBnADoAIABkAGkAZAAgAG4AbwB0ACAAcwB3AGEAcAAgAHMAcABlAGMAaQBhAGwAIABmAG8AbABkAGUAcgAgAGQAdQBlACAAdABvACAAbQBpAHMAbQBhAHQAYwBoAGkAbgBnACAAdAB5AHAAZQBzAC4ACgAAAAAALQAlAGwAdQAAAAAAAAAAADAAeAAlADAAMgBoAHgAJQAwADIAaAB4ACUAMAAyAGgAeAAlADAAMgBoAHgAJQAwADIAaAB4ACUAMAAyAGgAeAAAAAAAJQBsAHUAAABTAC0AJQB1AC0AAAAgACAAIABGAGEAaQBsAGUAZAAgAHQAbwAgAHQAYQBrAGUAIABvAHcAbgBlAHIAcwBoAGkAcAAgAG8AZgAgACUAcwA6ACAAJQBzACAAJQBkAAoAAAAAAAAAIAAgACAARgBhAGkAbABlAGQAIAB0AG8AIABzAGUAdAAgAGYAaQBsAGUAIABhAHQAdAByAGkAYgB1AHQAZQBzACAAZgBvAHIAIAAlAHMAOgAgACUAcwAgACUAZAAKAAAAIAAgACAARgBhAGkAbABlAGQAIAB0AG8AIABhAGMAYwBlAHMAcwAgACUAcwA6ACAAJQBzAC4AIABMAGEAcwB0AEUAcgByAG8AcgAgACUAZAAKAAAAZgBpAGwAZQAAAAAAZgBvAGwAZABlAHIAAAAAACAAIAAgAFIAZQBtAG8AdgBlAGQAIABmAGkAbABlADoAIAAlAHMACgAAAAAAIAAgACAAUgBlAG0AbwB2AGUAZAAgAEEAQwBMACAAbwBuACAAZgBpAGwAZQA6ACAAJQBzAAoAAAAgACAAIABGAGEAaQBsAGUAZAAgAHQAbwAgAHIAZQBtAG8AdgBlACAAZgBpAGwAZQA6ACAAJQBzAAoAAAAgACAAIABGAGEAaQBsAGUAZAAgAHQAbwAgAHIAZQBtAG8AdgBlACAAQQBDAEwAIABvAG4AIABmAGkAbABlADoAIAAlAHMACgAAAAAAAAAAACAAIAAgAEMAbwB1AGwAZAAgAG4AbwB0ACAAZABlAGwAZQB0AGUAIABmAGkAbABlADoAIAAlAHMACgAgACAAIAAgACAAIAAlAHMACgAAAAAAIAAgACAARQByAHIAbwByACAAJQBkACAAYQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAGQAZQBsAGUAdABlACAAZgBpAGwAZQA6ACAAJwAlAHMAJwAKAAAAAAAgACAAIABSAGUAbQBvAHYAZQBkACAAZgBvAGwAZABlAHIAOgAgACUAcwAKAAAAAAAgACAAIABSAGUAbQBvAHYAZQBkACAAQQBDAEwAIABvAG4AIABmAG8AbABkAGUAcgA6ACAAJQBzAAoAAAAgACAAIABGAGEAaQBsAGUAZAAgAHQAbwAgAHIAZQBtAG8AdgBlACAAZgBvAGwAZABlAHIAOgAgACUAcwAKAAAAIAAgACAARgBhAGkAbABlAGQAIAB0AG8AIAByAGUAbQBvAHYAZQAgAEEAQwBMACAAbwBuACAAZgBvAGwAZABlAHIAOgAgACUAcwAKAAAAAAAgACAAIABDAG8AdQBsAGQAIABuAG8AdAAgAGQAZQBsAGUAdABlACAAZgBvAGwAZABlAHIAOgAgACUAcwAKACAAIAAgACAAIAAgACUAcwAKAAAAAAAAAAAAIAAgACAARQByAHIAbwByACAAJQBkACAAYQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAGQAZQBsAGUAdABlACAAZgBvAGwAZABlAHIAOgAgACcAJQBzACcACgAAAAAAIAAgACAARQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAZgBpAGwAZQBzACAAaQBuACAAZgBvAGwAZABlAHIAIAAlAHMACgAAAAAAXAAAAC4ALgAAAAAALgAAAFwAKgAuACoAAAAAACUAcwBcAEkAbgBzAHQAYQBsAGwAZQByAFwAUAByAG8AZAB1AGMAdABzAFwAJQBzAAAAAAAlAHMAXABQAHIAbwBkAHUAYwB0AHMAXAAlAHMAAAAAACUAcwBcAEkAbgBzAHQAYQBsAGwAUAByAG8AcABlAHIAdABpAGUAcwAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABVAHMAZQByAEQAYQB0AGEAXAAlAHMAXABQAHIAbwBkAHUAYwB0AHMAAAAAAAAAAABTAGUAYQByAGMAaABpAG4AZwAgAGYAbwByACAAaQBuAHMAdABhAGwAbAAgAHAAcgBvAHAAZQByAHQAeQAgAGQAYQB0AGEAIABmAG8AcgAgAHAAcgBvAGQAdQBjAHQAIAAlAHMALgAgAC4AIAAuAAoAAAAAAAAAAAAgACAAIABFAHIAcgBvAHIAIABvAHAAZQBuAGkAbgBnACAAawBlAHkAIABmAG8AcgAgAGMAbwBtAHAAbwBuAGUAbgB0ACAAJQBzAC4AIABFAHIAcgBvAHIAIAAlAGQALgAKAAAAAAAAACAAIAAgAEUAcgByAG8AcgAgAGUAbgB1AG0AZQByAGEAdABpAG4AZwAgAGMAbABpAGUAbgB0AHMAIABvAGYAIABjAG8AbQBwAG8AbgBlAG4AdAAgACUAcwAuACAARQByAHIAbwByADoAIAAlAGQALgAKAAAAAAAAACAAIAAgAEUAcgByAG8AcgAgAHEAdQBlAHIAeQBpAG4AZwAgAHMAaABhAHIAZQBkACAARABMAEwAIABrAGUAeQAgAGYAbwByACAAYwBsAGkAZQBuAHQAIAAlAHMALAAgAGsAZQB5AGYAaQBsAGUAIAAlAHMACgAAACAAIAAgAEYAYQBpAGwAZQBkACAAdABvACAAcgBlAGQAdQBjAGUAIABzAGgAYQByAGUAZAAgAEQATABMACAAYwBvAHUAbgB0ACAAZgBvAHIAOgAgACUAcwAuACAARwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAByAGUAdAB1AHIAbgBlAGQAIAAlAGQALgAKAAAAAAAAAAAAIAAgACAAUgBlAGQAdQBjAGUAZAAgAHMAaABhAHIAZQBkACAARABMAEwAIABjAG8AdQBuAHQAIAB0AG8AIAAlAGQAIABmAG8AcgA6ACAAJQBzAAoAAAAAACAAIAAgAEYAYQBpAGwAZQBkACAAdABvACAAcgBlAG0AbwB2AGUAIABzAGgAYQByAGUAZAAgAEQATABMACAAZQBuAHQAcgB5ADoAIAAlAHMALgAgAEcAZQB0AEwAYQBzAHQARQByAHIAbwByACAAcgBlAHQAdQByAG4AZQBkACAAJQBkAC4ACgAAAAAAAAAAACAAIAAgAFIAZQBtAG8AdgBlAGQAIABzAGgAYQByAGUAZAAgAEQATABMACAAZQBuAHQAcgB5ADoAIAAlAHMACgAAAAAASABLAEwATQAzADIAAAAAAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABTAGgAYQByAGUAZABEAEwATABzAAAAAAAAAAAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAHMAaABhAHIAZQBkACAARABMAEwAIABjAG8AdQBuAHQAcwAgAGYAbwByACAAYwBvAG0AcABvAG4AZQBuAHQAcwAgAHQAaQBlAGQAIAB0AG8AIAB0AGgAZQAgAHAAcgBvAGQAdQBjAHQAIAAlAHMALgAgAC4AIAAuAAoAAAAlAGMAOgBcACUAcwAAAAAAYwBvAG4AZgBpAGcALgBtAHMAaQAAAAAAJQBjADoAXAAAAAAAAAAAACAAIABTAGUAYQByAGMAaABpAG4AZwAgAGYAbwByACAAcgBvAGwAbABiAGEAYwBrACAAZgBvAGwAZABlAHIAcwAuACAALgAgAC4ACgAAAAAAXABJAG4AcwB0AGEAbABsAGUAcgAAAAAAIAAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABmAGkAbABlAHMAIABhAG4AZAAgAGYAbwBsAGQAZQByAHMAIABpAG4AIAB0AGgAZQAgACUAJQBXAEkATgBEAEkAUgAlACUAXABJAG4AcwB0AGEAbABsAGUAcgAgAGYAbwBsAGQAZQByAAoAAABNAGkAYwByAG8AcwBvAGYAdABcAEkAbgBzAHQAYQBsAGwAZQByAAAAXABNAHMAaQAAAAAAVQBTAEUAUgBQAFIATwBGAEkATABFAAAAIAAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABmAGkAbABlAHMAIABhAG4AZAAgAGYAbwBsAGQAZQByAHMAIABpAG4AIAB0AGgAZQAgAHUAcwBlAHIAJwBzACAAcAByAG8AZgBpAGwAZQAuACAALgAgAC4ACgAAAAAAAABTAGUAYQByAGMAaABpAG4AZwAgAGYAbwByACAASQBuAHMAdABhAGwAbABlAHIAIABmAGkAbABlAHMAIABhAG4AZAAgAGYAbwBsAGQAZQByAHMAIABhAHMAcwBvAGMAaQBhAHQAZQBkACAAdwBpAHQAaAAgAHQAaABlACAAcAByAG8AZAB1AGMAdAAgACUAcwAuACAALgAgAC4ACgAAAAAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAG8AYgB0AGEAaQBuACAAdQBzAGUAcgAnAHMAIABTAEkARAAgAGYAYQBpAGwAZQBkACAAdwBpAHQAaAAgAGUAcgByAG8AcgAgACUAZAAKAAAAAABVAG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIAB0AGgAZQAgAEgASwBFAFkAXwBVAFMARQBSAFMAIABoAGkAdgBlACAAZgBvAHIAIAB1AHMAZQByACAAJQBzAC4AIABUAGgAZQAgAGgAaQB2AGUAIABtAGEAeQAgAG4AbwB0ACAAYgBlACAAbABvAGEAZABlAGQAIABhAHQAIAB0AGgAaQBzACAAdABpAG0AZQAuACAAKABMAGEAcwB0AEUAcgByAG8AcgAgAD0AIAAlAGQAKQAKAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAEkAbgBzAHQAYQBsAGwAZQByAAAAAABTAG8AZgB0AHcAYQByAGUAXABDAGwAYQBzAHMAZQBzAFwASQBuAHMAdABhAGwAbABlAHIAAAAAAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgAAAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABhAGwAbAAgAFcAaQBuAGQAbwB3AHMAIABJAG4AcwB0AGEAbABsAGUAcgAgAHIAZQBnAGkAcwB0AHIAeQAgAGQAYQB0AGEALgAgAC4AIAAuAAoAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAFUAcwBlAHIARABhAHQAYQBcACUAcwBcAFAAcgBvAGQAdQBjAHQAcwBcACUAcwBcAEkAbgBzAHQAYQBsAGwAUAByAG8AcABlAHIAdABpAGUAcwAAAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAEwAbwBjAGEAbABQAGEAYwBrAGEAZwBlAHMAAAAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABMAG8AYwBhAGwAUABhAGMAawBhAGcAZQBzAFwAJQBzAAAAAABMAG8AYwBhAGwAUABhAGMAawBhAGcAZQAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVQBuAGkAbgBzAHQAYQBsAGwAXAAlAHMAAAAAAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB0AGgAZQAgAHAAcgBvAGQAdQBjAHQAIAAlAHMAIABjAGEAYwBoAGUAZAAgAHAAYQBjAGsAYQBnAGUALgAgAC4AIAAuAAoAAAAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABVAHMAZQByAEQAYQB0AGEAXAAlAHMAXABQAGEAdABjAGgAZQBzAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABQAGEAdABjAGgAZQBzAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABVAHMAZQByAEQAYQB0AGEAXAAlAHMAXABQAGEAdABjAGgAZQBzAFwAJQBzAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAFAAYQB0AGMAaABlAHMAXAAlAHMAAAAAACUAcwBcACUAcwAAACUAcwBcACUAcwBcAFAAYQB0AGMAaABlAHMAAAAgACAAIABSAGUAbQBvAHYAZQBkACAAdQBwAGcAcgBhAGQAZQAgAGMAbwBkAGUAIAAnACUAcwAnACAAYQB0ACAAJQBzAFwAJQBzAAoAAAAAACAAIAAgAEMAbwB1AGwAZAAgAG4AbwB0ACAAbwBwAGUAbgAgACUAcwBcACUAcwAAACAAIABTAGUAYQByAGMAaABpAG4AZwAgAGYAbwByACAAcAByAG8AZAB1AGMAdAAgACUAcwAgAHUAcABnAHIAYQBkAGUAIABjAG8AZABlAHMAIABpAG4AIAAlAHMALgAuAC4ACgAAAAAAVQBuAGEAYgBsAGUAIAB0AG8AIABvAGIAdABhAGkAbgAgAHQAaABlACAAYwB1AHIAcgBlAG4AdAAgAHUAcwBlAHIAJwBzACAAUwBJAEQAIAAoAEwAYQBzAHQARQByAHIAbwByACAAPQAgACUAZAApAAAAAAAAAAAAUwBvAGYAdAB3AGEAcgBlAFwAQwBsAGEAcwBzAGUAcwBcAEkAbgBzAHQAYQBsAGwAZQByAFwAUABhAHQAYwBoAGUAcwAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABNAGEAbgBhAGcAZQBkAFwAJQBzAFwASQBuAHMAdABhAGwAbABlAHIAXABQAGEAdABjAGgAZQBzAAAAAAAAAAAAJQBzAFwASQBuAHMAdABhAGwAbABlAHIAXAAkAFAAYQB0AGMAaABDAGEAYwBoAGUAJABcAFUAbgBNAGEAbgBhAGcAZQBkAFwAJQBzAFwAJQBzAAAAAAAAACUAcwBcAEkAbgBzAHQAYQBsAGwAZQByAFwAJABQAGEAdABjAGgAQwBhAGMAaABlACQAXABNAGEAbgBhAGcAZQBkAFwAJQBzAAAAAAAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABVAHMAZQByAEQAYQB0AGEAXAAlAHMAXABDAG8AbQBwAG8AbgBlAG4AdABzAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG4AcwB0AGEAbABsAGUAcgBcAFUAcwBlAHIARABhAHQAYQBcACUAcwBcAFAAcgBvAGQAdQBjAHQAcwBcACUAcwAAAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAQwBvAG0AcABvAG4AZQBuAHQAcwAAAAAAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABQAHIAbwBkAHUAYwB0AHMAXAAlAHMAAAAlAHMAXABNAGEAbgBhAGcAZQBkAFwAJQBzAFwASQBuAHMAdABhAGwAbABlAHIAXABGAGUAYQB0AHUAcgBlAHMAXAAlAHMAAAAlAHMAXABNAGEAbgBhAGcAZQBkAFwAJQBzAFwASQBuAHMAdABhAGwAbABlAHIAXABQAHIAbwBkAHUAYwB0AHMAXAAlAHMAAAAlAHMAXABNAGEAbgBhAGcAZQBkAFwAJQBzAFwASQBuAHMAdABhAGwAbABlAHIAXAAlAHMAAAAAACAAIAAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIABIAEsATABNAFwAJQBzAAoAAAAAAAAAJQBzAFwATQBhAG4AYQBnAGUAZABcACUAcwBcAEkAbgBzAHQAYQBsAGwAZQByAFwAUABhAHQAYwBoAGUAcwAAACUAcwBcAE0AYQBuAGEAZwBlAGQAXAAlAHMAXABJAG4AcwB0AGEAbABsAGUAcgBcAFAAcgBvAGQAdQBjAHQAcwAAAAAAAAAAACUAcwBcAE0AYQBuAGEAZwBlAGQAXAAlAHMAXABJAG4AcwB0AGEAbABsAGUAcgBcAFAAcgBvAGQAdQBjAHQAcwBcACUAcwBcAFAAYQB0AGMAaABlAHMAAAAlAHMAXABNAGEAbgBhAGcAZQBkAFwAJQBzAFwASQBuAHMAdABhAGwAbABlAHIAXABVAHAAZwByAGEAZABlAEMAbwBkAGUAcwAAAAAAAAAAAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABwAHIAbwBkAHUAYwB0ACAAJQBzACAAaQBuACAAcABlAHIALQB1AHMAZQByACAAbQBhAG4AYQBnAGUAZAAgAGwAbwBjAGEAdABpAG8AbgAuACAALgAgAC4ACgAAACAAIABTAGUAYQByAGMAaABpAG4AZwAgACUAcwBcACUAcwAgAGYAbwByACAAcAByAG8AZAB1AGMAdAAgAGYAZQBhAHQAdQByAGUAIABkAGEAdABhAC4AIAAuACAALgAKAAAAAAAlAHMAXABGAGUAYQB0AHUAcgBlAHMAXAAlAHMAAAAAAAAAAAAgACAAUwBlAGEAcgBjAGgAaQBuAGcAIAAlAHMAXAAlAHMAIABmAG8AcgAgAHAAcgBvAGQAdQBjAHQAIABkAGEAdABhAC4AIAAuACAALgAKAAAAAABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdAAAAAAAIAAgACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgACUAcwBcACUAcwAKAAAAJQBzAFwAUABhAHQAYwBoAGUAcwAAAAAAJQBzAFwAUAByAG8AZAB1AGMAdABzAAAAAAAAACAAIABTAGUAYQByAGMAaABpAG4AZwAgAGYAbwByACAAcABhAHQAYwBoAGUAcwAgAGYAbwByACAAcAByAG8AZAB1AGMAdAAgACUAcwAgAGkAbgAgACUAcwAKAAAAJQBzAFwAUAByAG8AZAB1AGMAdABzAFwAJQBzAFwAUABhAHQAYwBoAGUAcwAAAAAAJQBzAFwAVQBwAGcAcgBhAGQAZQBDAG8AZABlAHMAAABcAFUAcABnAHIAYQBkAGUAQwBvAGQAZQBzAAAAXABVAHMAZQByAEQAYQB0AGEAAAAAAAAAUwBlAGEAcgBjAGgAaQBuAGcAIAAlAHMAIABsAG8AYwBhAHQAaQBvAG4AIABmAG8AcgAgAHAAcgBvAGQAdQBjAHQAIAAlAHMAIABkAGEAdABhAC4AIAAuACAALgAKAAAAUwBrAGkAcABwAGkAbgBnACAAcwBlAGEAcgBjAGgAIABvAGYAIAAlAHMAIABsAG8AYwBhAHQAaQBvAG4AIABmAG8AcgAgAHAAcgBvAGQAdQBjAHQAIAAlAHMAIABkAGEAdABhACAAcwBpAG4AYwBlACAAdABoAGUAIAByAGUAZwBpAHMAdAByAHkAIABoAGkAdgBlACAAaQBzACAAbgBvAHQAIABhAHYAYQBpAGwAYQBiAGwAZQAuAAoAAABnAGwAbwBiAGEAbAAgAGMAbwBuAGYAaQBnAAAAcABlAHIALQB1AHMAZQByAAAAAABvAGwAZAAgAHAAZQByAC0AdQBzAGUAcgAAAAAAcABlAHIALQBtAGEAYwBoAGkAbgBlAAAAbwBsAGQAIABnAGwAbwBiAGEAbAAgAGMAbwBuAGYAaQBnAAAAcABlAHIALQBtAGEAYwBoAGkAbgBlACAAZwBsAG8AYgBhAGwAIABjAG8AbgBmAGkAZwAAAHUAcwBlAHIAJwBzACAAZwBsAG8AYgBhAGwAIABjAG8AbgBmAGkAZwAAAAAAAAAAAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAVQBzAGUAcgBEAGEAdABhAFwAJQBzAAAAVQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAdABoAGUAIABIAEsARQBZAF8AVQBTAEUAUgBTACAAaABpAHYAZQAgAGYAbwByACAAdQBzAGUAcgAgACUAcwAuACAASABLAEMAVQAgAGQAYQB0AGEAIABmAG8AcgAgAHQAaABpAHMAIAB1AHMAZQByACAAdwBpAGwAbAAgAG4AbwB0ACAAYgBlACAAbQBvAGQAaQBmAGkAZQBkAC4AIAAgAFQAaABlACAAaABpAHYAZQAgAG0AYQB5ACAAbgBvAHQAIABiAGUAIABsAG8AYQBkAGUAZAAgAGEAdAAgAHQAaABpAHMAIAB0AGkAbQBlAC4AIAAoAEwAYQBzAHQARQByAHIAbwByACAAPQAgACUAZAApAAoAAAAAAAAATQBzAGkAWgBhAHAAIABpAG4AZgBvADoAIABmAGEAaQBsAGUAZAAgAHQAbwAgAGcAZQB0ACAAcABvAGkAbgB0AGUAcgAgAHQAbwAgAEkAcwBXAG8AdwA2ADQAUAByAG8AYwBlAHMAcwAuACAARwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAByAGUAdAB1AHIAbgBlAGQAIAAlAGQACgAAAElzV293NjRQcm9jZXNzAABNAHMAaQBaAGEAcAAgAHcAYQByAG4AaQBuAGcAOgAgAGYAYQBpAGwAZQBkACAAdABvACAAbABvAGEAZAAgAEsAZQByAG4AZQBsADMAMgAuAGQAbABsACwAIABzAG8AIAB3AGUAIABjAGEAbgBuAG8AdAAgAGEAYwBjAGUAcwBzACAASQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzACAAQQBQAEkALgAgAEcAZQB0AEwAYQBzAHQARQByAHIAbwByACAAcgBlAHQAdQByAG4AZQBkACAAJQBkAAoAAAAAAGsAZQByAG4AZQBsADMAMgAuAGQAbABsAAAAAAAAAAAAIAAgACAAQwBvAHUAbABkACAAbgBvAHQAIABmAGkAbgBkACAAYQBuAHkAIABtAG8AcgBlACAAJwAlAHMAJwAgAGYAaQBsAGUAcwAuACAARwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAByAGUAdAB1AHIAbgBzADoAIAAlAGQALgAKAAAAAAAAACAAIAAgAEMAbwB1AGwAZAAgAG4AbwB0ACAAZgBpAG4AZAAgAGEAbgB5ACAAJwAlAHMAJwAgAGYAaQBsAGUAcwAuACAARwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAByAGUAdAB1AHIAbgBzADoAIAAlAGQALgAKAAAAAAAqAAAAIAAgACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgAEgASwBMAE0AXAAuAC4ALgBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAUABhAHQAYwBoAGUAcwAgAGsAZQB5AC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAgACAAIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABQAGEAdABjAGgAZQBzACAAdQBuAGQAZQByACAASABLAEwATQBcAC4ALgAuAFwASQBuAHMAdABhAGwAbABlAHIAXABQAGEAdABjAGgAZQBzACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAAAAAIAAgACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgACUAcwAgAHMAdQBiAGsAZQB5ACAAbwBmACAASABLAEwATQBcAC4ALgAuAFwASQBuAHMAdABhAGwAbABlAHIAXABQAGEAdABjAGgAZQBzACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAAAAAAAAgACAAIABFAHIAcgBvAHIAIABvAHAAZQBuAGkAbgBnACAASABLAEwATQBcAC4ALgAuAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHMAdABhAGwAbABlAHIAXABMAG8AYwBhAGwAUABhAGMAawBhAGcAZQBzACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAAAAAAAAgACAAIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABQAHIAbwBkAHUAYwB0AHMAIABrAGUAeQAgAHUAbgBkAGUAcgAgAEgASwBMAE0AXAAuAC4ALgBcAEkAbgBzAHQAYQBsAGwAZQByAFwATABvAGMAYQBsAFAAYQBjAGsAYQBnAGUAcwAgAGsAZQB5AC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAAAAAAIAAgACAARQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAJQBzACAAcwB1AGIAawBlAHkAIABvAGYAIABIAEsATABNAFwALgAuAC4AXABJAG4AcwB0AGEAbABsAGUAcgBcAEwAbwBjAGEAbABQAGEAYwBrAGEAZwBlAHMAIABrAGUAeQAuACAARQByAHIAbwByADoAIAAlAGQALgAKAAAAIAAgACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgACUAcwAgAHMAdQBiAGsAZQB5ACAAbwBmACAASABLAEwATQBcAC4ALgAuAFwASQBuAHMAdABhAGwAbABlAHIAXABMAG8AYwBhAGwAUABhAGMAawBhAGcAZQBzACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAACAAIAAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIABIAEsATABNAFwALgAuAC4AXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABVAG4AaQBuAHMAdABhAGwAbAAgAGsAZQB5AC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAgACAAIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABQAHIAbwBkAHUAYwB0AHMAIABrAGUAeQAgAHUAbgBkAGUAcgAgAEgASwBMAE0AXAAuAC4ALgBcAFUAbgBpAG4AcwB0AGEAbABsACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAACAAIAAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIAAlAHMAIABzAHUAYgBrAGUAeQAgAG8AZgAgAEgASwBMAE0AXAAuAC4ALgBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAFUAbgBpAG4AcwB0AGEAbABsACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAAAAAAAAAACAAIAAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIABIAEsATABNAFwALgAuAC4AXABJAG4AcwB0AGEAbABsAGUAcgBcAFUAcwBlAHIARABhAHQAYQAgAGsAZQB5AC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAAAAAAIAAgACAARQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAdQBzAGUAcgAgAEkARABzAC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAAACAAIAAgAEUAcgByAG8AcgAgAGUAbgB1AG0AZQByAGEAdABpAG4AZwAgAFAAYQB0AGMAaABlAHMAIABrAGUAeQAgAGYAbwByACAAJQBzACAAdQBzAGUAcgAuACAARQByAHIAbwByADoAIAAlAGQALgAKAAAAAAAAACAAIAAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIAAlAHMAIABzAHUAYgBrAGUAeQAgAG8AZgAgAEgASwBMAE0AXAAuAC4ALgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAVQBzAGUAcgBEAGEAdABhAFwAJQBzAFwAUABhAHQAYwBoAGUAcwAgAGsAZQB5AC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAAAAAAIAAgACAARQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAJQBzACAAawBlAHkAIABmAG8AcgAgACUAcwAgAHUAcwBlAHIALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAAAAAJQBzAFwAVAByAGEAbgBzAGYAbwByAG0AcwAAAE0AYQBuAGEAZwBlAGQATABvAGMAYQBsAFAAYQBjAGsAYQBnAGUAAABXAGkAbgBkAG8AdwBzAEkAbgBzAHQAYQBsAGwAZQByAAAAAAAAAAAAIAAgACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgAEgASwBMAE0AXAAuAC4ALgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAVQBzAGUAcgBEAGEAdABhAFwAJQBzAFwAUABhAHQAYwBoAGUAcwAgAGsAZQB5AC4AIABFAHIAcgBvAHIAOgAgACUAZAAuAAoAAAAAAAAAAAAgACAAIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABQAHIAbwBkAHUAYwB0AHMAIABrAGUAeQAgAGYAbwByACAAJQBzACAAdQBzAGUAcgAuACAARQByAHIAbwByADoAIAAlAGQALgAKAAAAAAAgACAAIABFAHIAcgBvAHIAIABvAHAAZQBuAGkAbgBnACAAJQBzACAAcwB1AGIAawBlAHkAIABvAGYAIABQAHIAbwBkAHUAYwB0AHMAIABrAGUAeQAgAGYAbwByACAAJQBzACAAdQBzAGUAcgAuACAARQByAHIAbwByADoAIAAlAGQALgAKAAAAIAAgACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgAEgASwBMAE0AXAAuAC4ALgBcAEkAbgBzAHQAYQBsAGwAZQByAFwAVQBzAGUAcgBEAGEAdABhAFwAJQBzAFwAUAByAG8AZAB1AGMAdABzACAAawBlAHkALgAgAEUAcgByAG8AcgA6ACAAJQBkAC4ACgAAAEkAbgBzAHQAYQBsAGwAZQByAAAAIAAgACAARQByAHIAbwByACAAcgBlAHQAcgBpAGUAdgBpAG4AZwAgAFcAaQBuAGQAbwB3AHMAIABkAGkAcgBlAGMAdABvAHIAeQAuACAARwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAByAGUAdAB1AHIAbgBlAGQAOgAgACUAZAAuAAoAAAAAAC4AbQBzAHAAAAAAAC4AbQBzAHQAAAAAAC4AbQBzAGkAAAAAAAAAAABSAGUAbQBvAHYAaQBuAGcAIABvAHIAcABoAGEAbgBlAGQAIABjAGEAYwBoAGUAZAAgAGYAaQBsAGUAcwAuAAoAAAAAAEYAbwBsAGQAZQByAHMAIABjAGwAZQBhAHIAZQBkAC4ACgAAAEYAbwBsAGQAZQByACAAQQBDAEwAcwAgAGMAbABlAGEAcgBlAGQALgAKAAAARgBvAGwAZABlAHIAcwAgAGMAbABlAGEAcgBlAGQALgANAAoAAAAAAFIAZQBnAGkAcwB0AHIAeQAgAGQAYQB0AGEAIABjAGwAZQBhAHIAZQBkAC4ACgAAAFIAZQBnAGkAcwB0AHIAeQAgAEEAQwBMAHMAIABjAGwAZQBhAHIAZQBkAC4ACgAAAFIAZQBnAGkAcwB0AHIAeQAgAGQAYQB0AGEAIABjAGwAZQBhAHIAZQBkAC4ADQAKAAAAAABNAHMAaQBaAGEAcABJAG4AZgBvADoAIABQAGUAcgBmAG8AcgBtAGkAbgBnACAAbwBwAGUAcgBhAHQAaQBvAG4AcwAgAGYAbwByACAAdQBzAGUAcgAgACUAcwAKAAAAAABOAG8AIABwAHIAbwBkAHUAYwB0AC8AcABhAHQAYwBoACAAZABhAHQAYQAgAHcAYQBzACAAZgBvAHUAbgBkAC4ACgAAAEYAQQBJAEwARQBEACAAdABvACAAYwBsAGUAYQByACAAYQBsAGwAIABkAGEAdABhAC4ACgAAAAAAAAAAAAoACgAqACoAKgAqACoAIABaAGEAcABwAGkAbgBnACAAZABhAHQAYQAgAGYAbwByACAAdQBzAGUAcgAgACUAcwAgAGYAbwByACAAcAByAG8AZAB1AGMAdAAgACUAcwAgACoAKgAqACoAKgAKAAAAAAAKAAoAKgAqACoAKgAqACAAQQBkAGoAdQBzAHQAaQBuAGcAIABBAEMATABzACAAbwBuACAAZABhAHQAYQAgAGYAbwByACAAdQBzAGUAcgAgACUAcwAgAGYAbwByACAAcAByAG8AZAB1AGMAdAAgACUAcwAgACoAKgAqACoAKgAKAAAAAABBAGIAbwByAHQAZQBkAC4ACgAAAEQAbwAgAHkAbwB1ACAAdwBhAG4AdAAgAHQAbwAgAGQAZQBsAGUAdABlACAAYQBsAGwAIABXAGkAbgBkAG8AdwBzACAAaQBuAHMAdABhAGwAbABlAHIAIABjAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAAZABhAHQAYQA/ACAASQBmACAAeQBvAHUAIABkAG8ALAAgAHMAbwBtAGUAIABwAHIAbwBnAHIAYQBtAHMAIABtAGkAZwBoAHQAIABuAG8AdAAgAHIAdQBuAC4AIAAoAFkALwBOACkAPwAAAAAAUwBFAEwARQBDAFQAIABgAFYAYQBsAHUAZQBgACAARgBSAE8ATQAgAGAAUAByAG8AcABlAHIAdAB5AGAAIABXAEgARQBSAEUAIABgAFAAcgBvAHAAZQByAHQAeQBgAD0AJwBQAHIAbwBkAHUAYwB0AEMAbwBkAGUAJwAAAE0AUwBJAEQAQgBPAFAARQBOAF8AUgBFAEEARABPAE4ATABZAAAAAAAAAAAAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAHAAcgBpAHYAaQBsAGUAZwBlAHMAIABhAHIAZQAgAHIAZQBxAHUAaQByAGUAZAAgAHQAbwAgAHIAdQBuACAATQBzAGkAWgBhAHAALgAKAAAAAAAAAE8AcAB0AGkAbwBuACAAJwBSACcAIABpAHMAIABuAG8AIABsAG8AbgBnAGUAcgAgAHMAdQBwAHAAbwByAHQAZQBkAC4AIABBAGMAdABpAG8AbgAgAGMAYQBuACAAYgBlACAAYQBjAGMAbwBtAHAAbABpAHMAaABlAGQAIAB3AGkAdABoACAAcgBlAG0AbwB2AGUAIABhAGwAbAAuAAoAAABPAHAAdABpAG8AbgAgACcAVQAnACAAaQBzACAAbgBvACAAbABvAG4AZwBlAHIAIABzAHUAcABwAG8AcgB0AGUAZAAuACAAQQBjAHQAaQBvAG4AIABjAGEAbgAgAGIAZQAgAGEAYwBjAG8AbQBwAGwAaQBzAGgAZQBkACAAdwBpAHQAaAAgAHIAZQBtAG8AdgBlACAAYQBsAGwALgAKAAAATwBwAHQAaQBvAG4AIAAnAFYAJwAgAGkAcwAgAG4AbwAgAGwAbwBuAGcAZQByACAAcwB1AHAAcABvAHIAdABlAGQALgAgAEEAYwB0AGkAbwBuACAAYwBhAG4AIABiAGUAIABhAGMAYwBvAG0AcABsAGkAcwBoAGUAZAAgAHcAaQB0AGgA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tRD8//+NjQj8///oLPH//zhdEFCNhRT8//91JWgfAAIAU1BW6E3x//+L8IPEFDvzD4SUAQAAg/4FD4V6AQAA6zpoGQACAFNQVugo8f//i/CDxBQ78w+FBAIAAFNTU1P/tfj7////tQj8////FVwQAAGL8DvzD4XkAQAAaFwYAAHoNfb//4TAWQ+EKwEAAI2FFPz//1D/tRD8///oX/j//4vwO/NZWXRGjYUU/P//UFZo2BcAAei7XwAAg8QMOF0QD4TzAAAAjY0I/P//6Inw//+NjRD8///ofvD//42NBPz//+hz8P//MsDpBwIAAIu1EPz//42NBPz//+g98P//UGgAAAYAU42FFPz//1BW6GPw//+L8IPEFDvzdXz/tQT8///ocvn//4vwO/NZjYUU/P//dQ9QaFAXAAHoNl8AAFlZ6xhWUGjgHAAB6CZfAACDxAw4XRAPhWv///9TjY0E/P//6LHv//84XRB1TYu1EPz//42NCPz//+i/7///UGgfAAIAU42FFPz//1BW6OXv//+DxBSL8OshjYUU/P//UFZoEBUAAejLXgAAg8QMU42NBPz//+hf7///O/MPhZ4AAAA4XRAPhYcAAAD/tfj7////tQj8////FVgQAAGL8DvzdX04XRB1alNTU1ONhfT7//9QjYXw+///UFP/tQj8///HhfT7//8BAAAA/xVUEAABPQMBAAB1Ho2FFPz//1D/tRD8///ohO///4XAWVl1Bv+NAPz//42FFPz//1BomBwAAegvXgAAWVnGBRyIAQEB6y+NhRT8//9QaFAcAAHr4oP+AnQcVo2FFPz//1Bo4BsAAej/XQAAg8QMxoUP/P//AVNTU1ONhfz7//9QjYUU/P//UP+1APz///+1EPz//8eF/Pv///QBAAD/1zvDD4RH/f//PQMBAAB0ElBoaBsAAeixXQAAWVnp+/3//42NCPz//+iE7v//jY0Q/P//6Hnu//+NjQT8///obu7//zidD/z//w+UwF+LTfxeW+jAWAAAycPMzMzMzIv/VYvsgey0AAAAoUhwAQGJRfyLRRBTiYVs////i0UUVot1DFeLfQiJhVz///+LRRgz241NmIm9TP///4mFeP///4ldmOjr7f//UGgbAAIAU/+1bP///1foEu7//4PEFDvDdAeD+AJ0NOs0U1NTU1NTjUWMUI2FZP///1BTU1P/dZiJnWT///+JXYz/FWQQAAE7w3UKOZ1k////dRGzAY1NmOis7f//isPp8wMAAIuFXP///zvDdQW4wBoAAVCLhXj/////cAT/tWz///9WaIgeAAHollwAAP9FjItFjAPAUIhdq+gAXQAAg8QYO8OJRZR1BMZFqwGLRYyJhWD///+JXZwz9omddP///+koAwAAU1NTU42FYP///1D/dZT/tXT/////dZj/FVAQAAE7w4mFUP///w+FIAMAAIt9mI1NpIldpOjs7P//UGgbAAIAU/91lFfoFu3//4PEFIXAD4XfAgAAU1ONRYhQjYV8////UFNTU1NTU1P/daT/FWQQAAGFwA+FugIAAP+FfP///4uFfP///wPAUOhMXAAA/0WIiUWci4V8////iYVw////i0WIA8BQ6C9cAACL8ItFiFlZA8CJRZCNRZBQVo2FaP///1BTjYVw////UP91nIldhFPppwEAAIO9aP///weIXaOJXYAPhWMBAAA78w+EWwEAADhdq4m1WP///w+FAwEAAGY5Hg+E+gAAAP9FgFNTU41FrFBW6HDFAACFwA+F3gAAAI1FrFD/tVz/////FZgQAAGFwFYPhbYAAAD/TYDGRaMBi/7/FYwQAAG5////fyvIi0WQjQRIVolFkP8VjBAAAWY5XEYCVnUP/xWMEAABjXRGAmaJH+sy/xWMEAABjURGAusYZokPR0dAQDPJZosIZjvLde9miQ9HR0BAZosIZjvLdeBmi8FmiQf/dZD/tVj///9qB1P/dZz/daT/FWAQAAGFwHU6/3WUi4V4/////3AE/3Wc/3AIaDAeAAHofVoAAIPEFMYFHIgBAQHpEP////8VjBAAAY10RgLpAf///8ZFqwE4XaOLtVj///90PjldgHU5/3Wc/3Wk/xVYEAABhcB0B/9FhMZFqwH/dZyLhXj/////cAhoAB4AAegeWgAAg8QMxgUciAEBAesD/0WEi4V8////iYVw////i0WIA8CJRZCNRZBQVo2FaP///1BTjYVw////UP91nP91hP91pP8VVBAAATvDD4RI/v//vwMBAAA7xw+FmAAAAFNTU1ONhVT///9QU1NTU1NT/3Wk/xVkEAABO8d0ejmdVP///3VQU41NpOg36v///3WU/3WY6MHq//+FwFlZdWKBvUz///8CAACAuPQdAAF0BbjoHQAB/3WU/7Vs////UGi8HQAB6FlZAACDxBDGBRyIAQEB6wb/hXT///+LRYyNTaSJhWD////oG+r//zhdqw+Ez/z//+sljU2k6Ajq///rG41NpMZFqwHo+un//+sFvwMBAAA5vVD///90BMZFqwE5XZx0Cf91nOhgWQAAWTvzdAdW6FVZAABZOV2UdAn/dZToR1kAAFmNTZjouOn//zhdqw+UwItN/F9eW+gNVAAAycPMzMzMzIv/VYvsU2h4HwAB6KtYAAD/dQgy22j4HgABaAIAAIDo0/L//4PEEIXAdQL+wzPAhNsPlMBbXcPMzMzMzIv/VYvsU2hoIAAB6G9YAAD/dQgy22joHwABaAIAAIDol/L//4PEEIXAdQL+wzPAhNsPlMBbXcPMzMzMzIv/VYvsaFgoAAHoNFgAAIB9CABZdAto4CAAAegjWAAAWV3DzMzMzMyL/1WL7IHsIAIAAKFIcAEBUzPbOB0QiAEBVolF/FcPhVUCAACNjfj9//+Jnfj9///orej//1C/GQACAFdTaHgxAAG+AgAAgFboz+j//4PEFDvDdBWD+AJ0EI2N+P3//+ic6P//6SECAAA5nfj9//+Jnej9//90IVNTU1NTU1ONhej9//9QU1NT/7X4/f///xVkEAABhcB1wY2N9P3//4md9P3//+g56P//UFdTaAAxAAFW6GXo//+DxBQ7w3QFg/gCdVQ5nfT9//+JneD9//90IVNTU1NTU1ONheD9//9QU1NT/7X0/f///xVkEAABhcB1JYuF6P3//4uN4P3//410AQKLxsHgAlDoiVcAADvDWaMYiAEBdRCNjfT9///o3uf//+ky////aFwSAAHom1cAAFmLDRiIAQGJATPJQTvxi8F+DosVGIgBAYkcgkA7xnzyOZ3o/f//izVQEAABvwABAACJjfD9//+Jvez9//90XlNTU1ONhez9//9QjYX8/f//UFPrPY2F/P3//1DoO1cAAIsVGIgBAVmLjfD9//9TU4kEilNTjYXs/f//UEGNhfz9//+JjfD9//9QSYm97P3//1H/tfj9////1oXAdLc5neD9//8PhIcAAABTU1NTjYXs/f//UI2F/P3//1BT/7X0/f//iZ3k/f///9aFwHVii4Xw/f//weACiYXw/f//jYX8/f//UOiyVgAAi5Xw/f///4Xk/f//g4Xw/f//BFmLDRiI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U1ONhdz7//9QjYX0/f//UP+12Pv///+15Pv//4m13Pv///8VUBAAAYXAD4RF////jY3k+///6GXY//9QV1NoADEAAWgCAACA6I3Y//+DxBSFwA+F4wAAAFNTU1ONheD7//9QjYX0/f//UImd2Pv//1PpnQAAAFPobfn//1lQjYX0/f//UP8VyBAAAYXAdGb/tdD7//+NhfT9//9QaGg+AAGNhez7//9WUOh18v//i4Xk+///g8QUjY3c+///iZ3c+///iYXU+///6NLX//9QV1ONhez7//9Q/7XU+///6PfX//+DxBSFwI2N3Pv//3Q/6MnX////hdj7//9TU1NTjYXg+///UI2F9P3//1D/tdj7////teT7//+JteD7////FVAQAAGFwA+ESf///+sMxoXr+///AeiD1///jY3k+///6HjX//+LTfyKhev7//9fXlvozUEAAMnDzMzMzMyL/1WL7IHsgAYAAKFIcAEBU1ZXi30MM9s7+4lF/Im9gPn//4vHdQW4wBoAAVBogD8AAehERgAAjYWI+f//UImdjPn//+hC+P//UGjoPgABvgQBAACNhZz7//9WUOhk8f//g8QcOZ2I+f//dUSNjYz5///oy9b//1BoPwAPAFONhZz7//9QaAIAAIDo7db//4PEFDvDdDuD+AJ0J1CNhZz7//9QaDgZAAHozkUAAIPEDI2NjPn//+il1v//isPpMQEAAFf/dQjom+L//1lZitjr32oTM8A5nYD5//9miV2sWY19rvOribWE+f//Zqt0EY1FrFD/tYD5///oj9z//1lZiz1QEAABU1NTU42FhPn//1CNhaT9//9QiJ2T+f//iZ2I+f//U+mlAAAAZjldrHQVjUWsUI2FpP3//1D/FZgQAAGFwHVmjYWk/f//UGi8PgABjYWU+f//VlDoZ/D///91CI2FlPn//1D/tYz5///oRN///4PEHIXAD4Qy////jYWk/f//UOgQ/P//hMBZdRz/tYD5////dQjoyeH///bYGsBZ/sAIhZP5//9Z/4WI+f//U1NTU42FhPn//1CNhaT9//9Q/7WI+f//ibWE+f///7WM+f///9eFwA+ES////42NjPn//+h21f//OJ2T+f//D5TAi038X15b6Mg/AADJw8zMzMzMi/9Vi+yB7PwGAAChSHABAVNWi3UIiUX8i0UMVzP/O8eJ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//+EwFlZD4RHAQAAjYVo9f//UI2FlPn//1CNhVz1//9QU42FbPX//1CNhXj1//9Q/7Vw9f///7V09f//x4Vs9f//CgEAAMeFaPX//wgCAAD/FVQQAAGFwHSTjY109f//6CvK//9QV1NoGEoAAVboV8r//4PEFIXAdR3/dQyNRaxQ/7V09f//6HnT//+DxAyFwA+EvAAAAI1FrFCNhXD1//9Q6DLr//9ZUGhYSQABjYWk/f//aAQBAABQ6FTk//+DxBQ5nXD1//8PhYUAAACNjXT1///ot8n//1BXU42FpP3//1BW6OHJ//+DxBSFwHVhjYVw9f//UI2FnPv//1CNhWD1//9QU2gsSwAB/7V09f//vgYCAACJtXD1////FVwQAAGFwHUtg71g9f//AXUk/3UMjYWc+///UIm1cPX//2aJnaL9///oLOz//4TAWVl0ArMBjY109f//6FDJ//+LTfxfXorDW+ipMwAAycPMzMzMzIv/VYvsgex4DgAAoUhwAQFTM9tWiUX8i0UIi3UMU4mFyPH//4tFEFNTiYWw8f//i0UUU4mFlPH//4tFGImFiPH//42FqPH//1BTU1NTU1NWiJ3j8f//iZ248f//iZ208f//iZ3U8f//iZ288f//iZ3Q8f//iZ2o8f///xVkEAABhcAPhUIGAACLhajx//87w3UHswHpMQYAAGnA7AMAAFdQ6Cw4AACLPVQQAAFZU1OJhczx//+NhaDx//9QU42F2PH//1CNhQT4//9QU1aJnejx///Hhdjx///0AQAAiZ3c8f///9c7w3V6i4XM8f//iYXk8f//g72g8f//B3QwjYUE+P//UP+15PH//+idOAAAi4Xk8f///4Xc8f//gYXk8f//7AMAAFlZiZjoAwAA/4Xo8f//U1ONhaDx//9QU42F2PH//1CNhQT4//9Q/7Xo8f//x4XY8f//9AEAAFb/1zvDdJI9AwEAAA+FSQUAAIuF3PH//4mFpPH//42F0PH//1Do4ej//zmd0PH//1mJhZDx//8PhR4FAAA7ww+EFgUAAI2NuPH//+hyx///UGgZAAIAU/+1lPH///+1yPH//+iUx///g8QUhcAPhegEAABTU1NTjYXY8f//UI2FBPj//1BT/7W48f//iZ3o8f//x4XY8f//9AEAAP8VUBAAAb4EAQAA6ZMBAACNhQT4//9Q/7WI8f///xWYEAABhcAPhEQBAACNhQT4//9Q/7WU8f//jYXs8f//aExOAAFWUOhf4f//g8QUjY208f//6M7G//9QaBkAAgBTjYXs8f//UP+1yPH//+jvxv//g8QUO8MPheoAAABTU42FjPH//1BTjYWs8f//UI2F9PP//1CJndDx//9T6akAAACDvYzx//8HdHw5ndzx//+JncDx//92bouFzPH//4mF5PH//4uF5PH//zmY6AMAAHUXjYX08///UP+15PH///8VmBAAAYXAdCD/hcDx//+LhcDx//+BheTx///sAwAAO4Xc8f//cr3rHYuFwPH//4uNzPH//2nA7AMAAMeECOgDAAABAAAA/4XQ8f//U1ONhYzx//9QU42FrPH//1CNhfTz//9Q/7XQ8f///7W08f//ibWs8f///9c7ww+EQf///z0DAQAA6wOD+AIPhVADAAD/hejx//9TU1NTjYXY8f//UI2FBPj//1D/tejx///Hhdjx///0AQAA/7W48f///xVQEAABO8MPhGX+//89AwEAAA+FCQMAALqBAAAAM8BmiZ30/f//i8qNvfb9///zq2arM8A5naTx//9miZ3s+///i8qNve77///zq2aribWY8f//iZ2c8f//iZ3c8f//D4ZxAQAAi4XM8f//iYXk8f//i4Xk8f//OZjoAwAAD4UxAQAAUP+1sPH//42F9P3//2hATgABVlDob9///1ONhfT9//9Q/7XI8f//6E7O//+DxCCFwA+EZwIAAImd6PH//zmd6PH///+15PH//42F9P3//3URaMBNAAFWUOgr3///g8QQ6xX/tZDx//9oKE0AAVZQ6BTf//+DxBSNjbzx///og8T//1BoGQACAFONhfT9//9QvwIAAIBX/xUEEAABO8N0C4P4Ag+F9QEAAOtWjYWY8f//UI2F7Pv//1CNhZzx//9QU2gsSwAB/7W88f//x4WY8f//CAIAAP8VXBAAAYXAdSGDvZzx//8BdRhmOZ3s+///dA+Nhez7//9TUOjt5v//WVlTjY288f//6NTD//9TjYX0/f//UFfoX83//4PEDP+F6PH//4O96PH//wIPjAz/////hdzx//+Lhdzx//+BheTx///sAwAAO4Wk8f//D4Kb/v//jY3U8f//6KfD//9QvxkAAgBXU/+1sPH///+1yPH//+jIw///g8QUhcAPhRwBAABTU1NTU1NTjYXE8f//UFNTU/+11PH///8VZBAAAYXAD4X3AAAAOZ3E8f//dSFTjY3U8f//6CbD//9T/7Ww8f///7XI8f//6K3M//+DxAyJnejx//85nejx//+Nhfz1//91EWiwTAABVlDomN3//4PEDOsV/7WQ8f//aCBMAAFWUOiB3f//g8QQjY3U8f//6PDC//9QV1ONhfz1//9QaAIAAIDoFsP//4PEFIXAdVRTU1NTU1NTjYXE8f//UFNTU/+11PH//4mdxPH///8VZBAAAYXAdS05ncTx//91JVONjdTx///odsL//1ONhfz1//9QaAIAAIDo/cv//4PEDIXAdBr/hejx//+Dvejx//8CD4w/////xoXj8f//Af+1zPH//+gAMgAAip3j8f//WV+Njbzx///oZ8L//42N1PH//+hcwv//jY208f//6FHC//+Njbjx///oRsL//4tN/F6Kw1vooCwAAMnDzMzMzMyL/1WL7IHsCAgAAKFIcAEBU1aLdRBXi30MV4lF/ItFCFZo6E4AAYmFHPj//4m9CPj//4m1APj//+gRMQAAM9uDxAw783QXZjkedBJW6Bzo//+EwFl0B7AB6c0CAACNjST4//+JnST4///op8H//1BoGQACAFNX/7Uc+P//6M7B//+DxBQ7w3Qzg/gCD4SKAgAAgb0c+P//AgAAgLj0HQABdAW46B0AAVdQaLhOAAHomzAAAIPEDOliAgAAU1NTU42FFPj//1CNhSz4//++9AEAAFCJtRT4//+JnRj4//+JnQT4//9T6aABAACLvST4//+NjSj4//+JnSj4///oFMH//1BoGwACAFONhSz4//9QV+g6wf//g8QUO8OJhSD4//8PhYABAABTU1NTjYUM+P//UI2FFPz//1CJnRD4//9T6zX/tQD4//+NhRT8//9Q/xWYEAABhcB0OP+FEPj//1NTU1ONhQz4//9QjYUU/P//UP+1EPj///+1KPj//4m1DPj///8VVBAAAYv4O/t0s+tfjYUU/P//UP+1KPj///8VWBAAAYv4O/sPhfkAAACBvRz4//8CAACAuPQdAAF0BbjoHQAB/7UI+P//UI2FFPz//1BoaE4AAehzLwAAg8QQx4UE+P//AQAAAMYFHIgBAQGB/wMBAAB0CDv7D4WnAAAAU1NTU42F/Pf//1BTU1NTU1P/tSj4////FWQQAAGFwA+FggAAADmd/Pf//3UnU42NKPj//+i5v///jYUs+P//UP+1JPj//+g8wP//WVnGBRyIAQEBOZ0E+P//jY0o+P//dVL/hRj4//+JtRT4///owb///1NTU1ONhRT4//9QjYUs+P//UP+1GPj///+1JPj///8VUBAAATvDiYUg+P//D4RG/v//6xKNjSj4///ogr///+tq6Hu///+BvSD4//8DAQAAdAg5nSD4//91UVNTU1NTU1ONhfj3//9QU1NT/7Uk+P///xVkEAABhcB1MDmd+Pf//3UmU42NJPj//+jwvv///7UI+P///7Uc+P//6HS///9ZWcYFHIgBAQGzAY2NJPj//+gLv///isOLTfxfXlvoZCkAAMnDzMzMzMyL/1WL7IHsZAIAAKFIcAEBU1aNTayJRfyLRQxRM/ZQibWg/f//Mtvo+MT//42FoP3//1Do6t///4PEDDm1oP3//w+FzQAAADvGD4TFAAAAV1BoEFAAAY2FpP3//2gEAQAAUIm1oP3//+jv2P//g8QQjY2g/f//6F6+//9QaBkAAgBWizUEEAABjYWk/f//UL8CAACAV//WhcB1Hf91EI1FrFD/taD9///oocf//4PEDIvY99sa2/7Dg6Wc/f//AI2NnP3//+gPvv//UGgZAAIAagBoyE8AAVf/1oXAX3Ud/3UQjUWsUP+1nP3//+hdx///g8QMi9j32xrb/sONjZz9///o8L3//42NoP3//+jlvf//6xT/taD9//9oUE8AAejuLAAAWVmzAYtN/DPAhNteD5TAW+gkKAAAycPMzMzMzIv/VYvsgez4DQAAoUhwAQFTVot1DFf/dRCJRfxWibUU8///6G7x//9W/3UQPAEPlYUr8///6B3m//+DxBCEwHUHxoUr8///AY2FDPP//zP2UIm1DPP//+iG3v//ObUM8///i/hZib0g8///D4UDCgAAO/4PhPsJAACAPRCIAQEAibUM8///xoUf8///AXU4jY0M8///6P+8//9QaBkAAgBWV2gDAACA/xUEEAABO8Z0FlBXaAhbAAHoFSwAAIPEDMaFH/P//wD/tSDz//++iFoAAVa7BAEAAI2FLPP//1NQ6DfX//9mg6U89///ADPAuYEAAACNvT73///zq2hcEgABVmarjYU89///U1DoC9f//42FLPP//4mFCPL//42FPPf//4mFHPL//4uFDPP//74CAACAu3ASAAGJhVzy//+JhXDy//+6REgAAYPEIDPAuXwSAAGJhYDy//+JhYTy//+IhYjy//+JhYzy//+NvZDy//+JtQzy///GhRDy//8AiZ0U8v//x4UY8v//WFoAAYm1IPL//8aFJPL//wCJnSjy///HhSzy//8kWgABx4Uw8v//gEgAAYm1NPL//8aFOPL//wCJnTzy///HhUDy//8AWgABiZVE8v//ibVI8v//xoVM8v//AImdUPL//8eFVPL//+hZAAGJlVjy///GhWDy//8BiY1k8v//x4Vo8v//zFkAAceFbPL//whIAAHGhXTy//8BiY148v//x4V88v//uFkAAauNhSzz//+JhZTy//+JtZjy///GhZzy//8AiZ2g8v//x4Wk8v//WFoAAceFqPL//4BIAAGJtazy///GhbDy//8AiZ208v//x4W48v//nFkAAYmVvPL//4m1wPL//8aFxPL//wCJncjy///Hhczy///oWQABuAEAAICJhdTy//+Jhejy//8zwDgFEIgBAYmF+PL//4mF/PL//4iFAPP//4mFBPP//429CPP//4mV0PL//8aF2PL//wGJjdzy///HheDy///MWQABx4Xk8v//CEgAAcaF7PL//wGJjfDy///HhfTy//+4WQABq42FlPL//3UGjYUI8v//iYUk8///jUWsUP+1FPP//+ijwP//i4Uk8///iwCFwFlZvwQBAAAPhHcDAACLhSTz//+KQAiEwHRHgL0f8///AHUh/7UU8///i4Uk8////3AQaOBYAAHoSykAAIPEDOkqAwAAhMB0GWhcEgAB/7Ug8////xWYEAABhcAPhA0DAAD/tRTz//+LhSTz////cBBogFgAAegNKQAAg8QMgH0QAA+FKQIAAIuFJPP//2hoWAAB/zDobSsAAIXAWVl0MIuNJPP//4sJK8HR+EBQUY2FpP3//1D/FdwQAAFoTFgAAY2FpP3//1D/FaQQAAHrHYuFJPP///8wjYWk/f//aCxYAAFXUOjo0///g8QQi4Uk8///i0AEjU2sUY2NpP3//1FQ6DP3//+DxAyEwHUHxoUr8///AY1FrFCLhSTz////MI2FpP3//2j8VwABV1Don9P//42FpP3//1CNRaxQaKBXAAHoQCgAAIOlEPP//wCDxCCNjRDz///o8rj//1BoGQACAGoAjYWk/f//UIuFJPP///9wBP8VBBAAAYXAdWOLhSTz////MI2FTPv//2iEVwABV1DoOdP//4uFJPP///8wjYWk/f//aGxXAAFXUOgf0///jUWsUI2FTPv//1CNhaT9//9Q/7UQ8///i4Uk8////3AE6Fjv//+DxDSEwHU46y+D+AJ0MYuFJPP//zlwBLj0HQABdAW46B0AAY2NpP3//1FQaDxXAAHoeicAAIPEDMaFK/P//wGLhSTz//85cAR1EmgUVwAB/zDo2CkAAIXAWVl1cceFGPP//wRwAQGLhRjz////MIuFJPP///8wjYWk/f//aEBOAAFXUOhx0v///7UY8///jYWk/f///7UU8///UIuFJPP///9wDP9wBOiVyf//g8QohMB1B8aFK/P//wGDhRjz//8Mgb0Y8///HHABAX6ZjY0Q8///6Ly3//+NRaxQi4Uk8////zCNhaT9//9onD4AAVdQ6APS//+LhSTz//+LQAyNjaT9//9RUGjAVgAB6J4mAAD/dRCLhSTz//+LQASNjaT9//9RUOjBwP//g8QshcB1B8aFK/P//wGNRaxQi4Uk8////zCNhaT9//9onFYAAVdQ6KPR//+NhaT9//9Qi4Uk8////3AMaDhWAAHoPyYAAP91EI2FpP3//1CLhSTz////cAToY8D//4PELIXAdQfGhSvz//8Bg4Uk8///FIuFJPP//4M4AA+Fifz//4uFFPP//4XAdQW4wBoAAVBowFUAAejpJQAAgH0QAFlZD4WWAQAA/7Ug8///jYWk/f//aIBIAAFocFUAAVdQ6ArR//+NRaxQjYWk/f//UFboYfT//4PEIITAdQfGhSvz//8BjUWsUP+1IPP//42FpP3//2iASAABaBhVAAFXUOjK0P//jYWk/f//UI1FrFBooFcAAehrJQAAg6UQ8///AIPEJI2NEPP//+gdtv//UGgZAAIAagCNhaT9//9QVv8VBBAAAYXAdWH/tSDz//+NhUz7//9ogEgAAWjQVAABV1DoadD///+1IPP//42FpP3//2iASAABaJBUAAFXUOhM0P//jUWsUI2FTPv//1CNhaT9//9Q/7UQ8///VuiN7P//g8Q8hMB1IesYg/gCdBqNhaT9//9QaFhUAAHoxSQAAFlZxoUr8///AceFGPP//wRwAQGLhRjz////MI2FpP3///+1IPP//2iASAABaCBUAAFXUOjXz////7UY8///jYWk/f///7UU8///UFNW6AXH//+DxCyEwHUHxoUr8///AYOFGPP//wyBvRjz//8ccAEBfqCNjRDz///oLLX//41FrFD/tSDz//+NhaT9//9ogEgAAWjYUwABV1DocM///42FpP3//1C79B0AAVNowFYAAegPJAAA/3UQjYWk/f//UFboO77//4PEMIXAdQfGhSvz//8BjUWsUP+1IPP//42FpP3//2iASAABaJBTAAFXUOgaz///jYWk/f//UFNoOFYAAei+IwAAi10QU42FpP3//1BW6Om9//+DxDCFwHUHxoUr8///AY1FrFBoEFMAAY2FpP3//1dQ6NPO//9TjYWk/f//UFbot73//4PEHIXAdQfGhSvz//8BhNt1IDhdFHUbjUWsUGiQUgAB6ODe//+EwFlZdQfGhSvz//8BjUWsUP+1IPP//42FpP3//2j4UQABV1Dod87//1ONhaT9//9QVuhbvf//g8QghcB1B8aFK/P//wH/tSDz//+NhaT9//9oYFEAAVdQ6EPO//+DxBCE23UiOF0UdR2NRaxQjYWk/f//UOhn3v//hMBZWXUHxoUr8///AVONRaxQjYWk/f//UOh0wf//g8QMhMB1B8aFK/P//wFTjUWsUGiQUgAB6FfB//+DxAyEwHUHxoUr8///AYTbuIABAAB0A4PACP91FP+1FPP//1DoEOP//4PEDITAdQfGhSvz//8BjY0M8///6EWz///rIf+1DPP//2hQTwAB6E4iAACLXRBZWcaFK/P//wG/BAEAAI2FVP3//1D/tRTz///oPbn//1lZV42FNPX//1D/FdQQAAGFwA+EiAAAAI2FVP3//1CNhTT1//9QaBBRAAGNhUT5//9XUOg9zf//g8QUhcB8Go2FRPn//1NQ6JXW//+FwFlZdQfGhSvz//8BjYVU/f//UP+1IPP//42FNPX//1BouFAAAY2FRPn//1dQ6PbM//+DxBiFwHwajYVE+f//U1DoTtb//4XAWVl1B8aFK/P//wGLTfwzwDiFK/P//19eD5TAW+jAHAAAycPMzMzMzIv/VYvsgewoAwAAoUhwAQGJRfyNhdz8//9Qx4Xc/P//FAEAAP8V4BAAAYO97Pz//wF1B8YFEIgBAQGDvez8//8Ci4Xg/P//oxSIAQHGBRGIAQEAD4XKAAAAg/gFdxMPhb8AAACDveT8//8BD4KyAAAAV2jQXQAB/xV4EAABi/iF/3Uv/xVwEAABUGjwXAABjYXw/f//aAUBAABQ6BjM//+DxBCNhfD9//9Q/xWcEAAB63BWaOBcAAFX/xV0EAABi/CF9nU2/xVwEAABUGhAXAABjYXw/f//aAUBAABQ6NbL//+DxBCNhfD9//9Q/xWcEAABV/8VbBAAAesmg6XY/P//AI2F2Pz//1D/FYAQAAFQ/9aDvdj8//8AD5XAohGIAQFeX4tN/OiOGwAAycPMzMzMzIv/VYvsuPgXAADoXCIAAKFIcAEBUzPbOB0higEBiUX8dBAzwDgdIIoBAQ+UwOnEFAAAaABrAAHGBSGKAQEB6PkfAACNhRTo//+JhQjo//9Zx4UM6P//CgAAAImdxOj//zPAi40I6P//iRyBQDuFDOj//3zujYWA6P//iYV06P//x4V46P//CgAAAImd3Oj//zPAi4106P//iRyBQDuFeOj//3zujYVM6P//iYVA6P//x4VE6P//CgAAAImd2Oj//zPAi41A6P//iRyBQDuFROj//3zuVldqCseFsOj///BqAAHHhbTo///kagABx4W46P//2GoAATP2X1ONhdjo//9QjYVA6P//UP+0tbDo//+JvUjo///oN8///4PEEITAdFJGg/4DctIzwGaJnXDx//+5gQAAAI29cvH///OrZqu+BAEAAFaNhXDx//9Q/xXUEAABhcB1Z/8VcBAAAVBoUGoAAejVHgAAxgUgigEBAemGAAAAOb1E6P//xgUgigEBAX4M/7VA6P//6BofAABZOb146P//fgz/tXTo///oBh8AAFk5vQzo//9+DP+1COj//+jyHgAAWTLA6TcTAACNhXDx//9Q6FQeAABmg7xFbvH//1xZdBONhXDx//9oTD4AAVDoeR8AAFlZjYVw8f//aDxqAAFQ6GYfAABZWY2NAOn//4mdAOn//+j3rv//UGgZAAIAU2h4MQABaAIAAIDoG6///4s9UBAAAYPEFDvDD4VIBwAAU1NTU42F6Oj//1CNhYj3//9QiZ3s6P//U+m6BgAAjYWI9///UGiEVwABjYVg7f//VlDoHMn//4uFAOn//4PEEI2N4Oj//4md4Oj//4mF8Oj//+h5rv//UGgZAAIAU42FYO3//1D/tfDo///omq7//4PEFDvDdBeD+AJ0ElCNhYj3//9QaKhpAAHp8QAAAFNTU1ONhdTo//9QjYVY6///UImd8Oj//1PpqQAAAI2FWOv//1BovD4AAY2FePP//1ZQ6I7I//+LheDo//+DxBCNjfjo//+Jnfjo//+JhQTp///o663//1BoGQACAFONhXjz//9Q/7UE6f//6Ayu//+DxBQ7ww+E/QAAAFCNhYj3//9QjYV48///UGggaQAB6OccAACDxBDGBSCKAQEBjY346P//6Let////hfDo//9TU1NTjYXU6P//UI2FWOv//1D/tfDo////teDo//+JtdTo////1zvDD4RB////PQMBAAB0HFCNhYj3//9QaKhoAAHohRwAAIPEDMYFIIoBAQGNhYj3//9QaGxXAAGNhWDt//9WUOisx///i4UA6f//g8QQjY3M6P//iZ3M6P//iYXw6P//6Amt//9QaBkAAgBTjYVg7f//UP+18Oj//+gqrf//g8QUO8MPhEQDAACD+AIPhLAEAABQjYWI9///UGgQaAAB6Y8EAACNhdDo//9QjYU86P//UI2F9Oj//1BTaOhnAAH/tfjo///HhdDo//8EAAAA/xVcEAABhcAPhe3+//+DvfTo//8EdQ2DvTzo//8BD4XX/v//M8BmiZ1o7///uYEAAACNvWrv///zq2aruCxLAAGJhbDo///HhbTo///AZwABiZ246P//jb2w6P//jY3Q6P//UY2NaO///1GNjfTo//9RU1D/tfjo///HhdDo//8IAgAA/xVcEAABhcB1CYO99Oj//wF0CYPHBIsHO8N1vWY5nWjv//90QmoKWImFSOj//4mFfOj//42F2Oj//1CNhUDo//9QjYXc6P//UI2FdOj//1CNhWjv//9Q6JDL//+DxBSEwA+E4QMAADgdEIgBAQ+F8QEAAGY5nXDx//8PhOQBAACNhVjr//9QaKRnAAGNhXjz//9WUOgFxv//i73g6P//g8QQjY386P//iZ386P//6Gir//9QaBkAAgBTjYV48///UFfojqv//4PEFDvDdCKD+AIPhIIBAABQjYWI9///UI2FePP//1BoIGkAAelaAQAAjYVw8f//UI2FpP3//1DopxsAAI2FpP3//1DoJhoAAIPEDGaDvEWi/f//XHQTjYWk/f//aEw+AAFQ6EkbAABZWY2FpP3//2pcUOgAGwAAWVmL+I2F0Oj//1CNhWjv//9QjYX06P//UFONhbzo//9QjYVQ6f//R1BHiZ0E6f//U+mXAAAA/4UE6f//ZjmdaO///3RYg7306P//AXVPjYVo7///UFfoERsAAGoKWImFSOj//4mFfOj//42F2Oj//1CNhUDo//9QjYXc6P//UI2FdOj//1CNhaT9//9Q6BzK//+DxByEwA+EigIAAP+FBOn//42F0Oj//1CNhWjv//9QjYX06P//UFONhbzo//9QjYVQ6f//UP+1BOn///+1/Oj//4m1vOj//8eF0Oj//wgCAAD/FVQQAAE7ww+ERf///z0DAQAAdCNQjYWI9///UI2FePP//1BoOGcAAegFGQAAg8QQxgUgigEBAY2N/Oj//+jVqf//jY346P//6Mqp//+LPVAQAAHpCPz//1NTU1ONheTo//9QjYWA9f//UImd8Oj//1PpHgEAAIuFzOj//42NBOn//4mdBOn//4mFrOj//+hmqf//UGgZAAIAU42FgPX//1D/tazo///oh6n//4PEFDvDdChQjYWI9///UI2FgPX//1BoiGYAAehmGAAAg8QQxgUgigEBAemQAAAAjYXI6P//UI2FYO3//1CNhfTo//9QU2gsSwAB/7UE6f//x4XI6P//CAIAAGaJnWDt////FVwQAAGFwHVUg7306P//AXVLZjmdYO3//3RCagpYiYVI6P//iYV86P//jYXY6P//UI2FQOj//1CNhdzo//9QjYV06P//UI2FYO3//1Doasj//4PEFITAD4TsAAAAjY0E6f//6KGo////hfDo//9TU1NTjYXk6P//UI2FgPX//1D/tfDo////tczo//+JteTo////1zvDD4TM/v//PQMBAAB0HFCNhYj3//9QaBBmAAHobxcAAMYFIIoBAQGDxAyNjczo///oP6j//42N4Oj//+g0qP///4Xs6P//U1NTU42F6Oj//1CNhYj3//9Q/7Xs6P///7UA6f//ibXo6P///9c7ww+EMPn//z0DAQAAdGxQaLhlAAHrVsYFIIoBAQGNjfjo///o36f//42N4Oj//+mRBgAAjY386P//xgUgigEBAejCp///69aNjQTp///GBSCKAQEB6K6n//+Njczo///rwoP4AnQUUGg4ZQAB6LEWAABZWcYFIIoBAQGNjQDp///oZKf//1BoGQACAFNoiBkAAWgCAACA6Iin//+DxBQ7ww+FAAIAAFNTU1ONhejo//9QjYWA9f//UImd5Oj//1PpggAAAIuFAOn//42N+Oj//4md+Oj//4mFyOj//+gIp///UGgZAAIAU42FgPX//1D/tcjo///oKaf//4PEFDvDdHFQjYWA9f//UGiQZAAB6A8WAACDxAzGBSCKAQEBjY346P//6N+m////heTo//9TU1NTjYXo6P//UI2FgPX//1D/teTo////tQDp//+Jtejo////1zvDD4Ro////PQMBAAAPhFgBAABQaPhjAAHpPwEAAI2F7Oj//1CNhazo//9QjYX06P//UFNo6GcAAf+1+Oj//8eF7Oj//wQAAAD/FVwQAAGFwA+Fcv///4O99Oj//wR1DYO9rOj//wEPhVz///8zwGaJnaT9//+5gQAAAI29pv3///OrZqu4LEsAAYmFsOj//8eFtOj//8BnAAGJnbjo//+NvbDo//+Njezo//9RjY2k/f//UY2N9Oj//1FTUP+1+Oj//8eF7Oj//wgCAAD/FVwQAAGFwHUJg7306P//AXQJg8cEiwc7w3W9ZjmdpP3//3UIjY346P//60hqCliJhUjo//+JhXzo//+Nhdjo//9QjYVA6P//UI2F3Oj//1CNhXTo//9QjYWk/f//UOg1xf//g8QUhMCNjfjo//8PhCcEAADobKX//4s9UBAAAemC/v//g/gCdBRQaHBjAAHobBQAAFlZxgUgigEBAY2NAOn//+gfpf//UGgZAAIAU2gYSgABaAIAAIDoQ6X//4PEFDvDD4UdAgAAU1NTU42F8Oj//1CNhXjz//9QiZ3U6P//U+nPAQAAi4UA6f//jY386P//iZ386P//iYXI6P//6MOk//9QaBkAAgBTjYV48///UP+1yOj//+jkpP//g8QUO8N0LFCNhXjz//9QaNBiAAHoyhMAAIPEDI2N/Oj//8YFIIoBAQHomqT//+lIAQAAM8C6gQAAAGaJnaT9//+Lyo29pv3///OrZqszwGaJnYD1//+Lyo29gvX///OrZquNhezo//9QjYWk/f//UI2F9Oj//1BTjYXo6P//UI2FgPX//1BT/7X86P//iZ3k6P//x4Xs6P//CAIAAIm16Oj///8VVBAAATvDD4WWAAAAagpf/4Xk6P//jYXY6P//UI2FQOj//1CNhdzo//9QjYV06P//UI2FpP3//1CJvUjo//+JvXzo///ojcP//4PEFITAD4TFAAAAjYXs6P//UI2FpP3//1CNhfTo//9QU42F6Oj//1CNhYD1//9Q/7Xk6P//ibXo6P///7X86P//x4Xs6P//CAIAAP8VVBAAATvDD4Rt////PQMBAAB0HFCNhXjz//9QaChiAAHogxIAAIPEDMYFIIoBAQGNjfzo///oU6P//4s9UBAAAf+F1Oj//1NTU1ONhfDo//9QjYV48///UP+11Oj///+1AOn//4m18Oj////XO8MPhBv+//89AwEAAHQsUGhwYQAB6xaNjfzo///ptQEAAIP4AnQUUGjIYAAB6AoSAABZWcYFIIoBAQGNjQDp///ovaL//1BoGQACAFNosEwAAWgCAACA6OGi//+DxBQ7ww+FgQEAAIs1UBAAAWoTWTPAU2aJXayNfa7zq1NTZqtTjYXs6P//UI1FrFCJnejo//9T6RABAACLvQDp//+NjQTp//+JnQTp///oVKL//1BoGQACAFONRaxQV+h9ov//g8QUO8N0HlCNRaxQaDBgAAHoZhEAAIPEDMYFIIoBAQHpnQAAADPAZomdpP3//7mBAAAAjb2m/f//86tmq42FyOj//1CNhaT9//9QjYX06P//UFNoLEsAAf+1BOn//8eFyOj//wgCAAD/FVwQAAGFwHVQg7306P//AXVHZjmdpP3//3Q+agpYiYVI6P//iYV86P//jYXY6P//UI2FQOj//1CNhdzo//9QjYV06P//UI2FpP3//1DoWcH//4PEFITAdE+NjQTp///olKH///+F6Oj//1NTU1ONhezo//9QjUWsUP+16Oj///+1AOn//8eF7Oj//ygAAAD/1jvDD4TW/v//PQMBAAB0OFBokF8AAesijY0E6f//xgUgigEBAeg+of//6UIEAACD+AJ0FFBo+F4AAehEEAAAWVnGBSCKAQEBZjmdcPH//76ERQABD4SMAAAAagpfagGNhcTo//9QjYUI6P//UI2FcPH//1CJvRDo///oGcD//4PEEITAD4QdAwAAjYVw8f//UI2FkPn//1DoPBEAAI2FkPn//2pcUOjCEAAAg8QQO8N0NFZQ6CARAABqAY2FxOj//1CNhQjo//9QjYWQ+f//UIm9EOj//+i9v///g8QYhMAPhMECAABoCQIA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6waLjbT7//9qAl4BteD7//+DveT7//8AD4yPCQAAaiBfZjvfchVmg/t4dw8Pt8MPvoAYegABg+AP6wIzwA++hME4egABagfB+ARZO8GJhbT7//8Ph0IJAAD/JIVkFgEBM8CDjfD7////iYWw+///iYW4+///iYXY+///iYXc+///iYX4+///iYXU+///6QkJAAAPt8Mrx3RHg+gDdDaD6Ah0JSvGdBWD6AMPhesIAACDjfj7//8I6d8IAACDjfj7//8E6dMIAACDjfj7//8B6ccIAACAjfj7//+A6bsIAAAJtfj7///psAgAAGaD+yp1MIOF9Pv//wSLhfT7//+LQPyFwImF2Pv//w+NjAgAAION+Pv//wT3ndj7///peggAAIuF2Pv//w+3y40EgI1EQdCJhdj7///pXwgAAIOl8Pv//wDpUwgAAGaD+yp1KoOF9Pv//wSLhfT7//+LQPyFwImF8Pv//w+NLwgAAION8Pv////pIwgAAIuF8Pv//w+3y40EgI1EQdCJhfD7///pCAgAAA+3w4P4SXQ2g/hodCaD+Gx0FYP4dw+F7QcAAICN+fv//wjp4QcAAION+Pv//xDp1QcAAAm9+Pv//+nKBwAAi4Xg+///ZosAZj02AHUgi43g+///ZoN5AjR1E4OF4Pv//wSAjfn7//+A6ZsHAABmPTMAdSCLjeD7//9mg3kCMnUTg4Xg+///BICl+fv//3/pdQcAAGY9ZAAPhGsHAABmPWkAD4RhBwAAZj1vAA+EVwcAAGY9dQAPhE0HAABmPXgAD4RDBwAAZj1YAA+EOQcAAIOltPv//wCLhcz7//9TjbXk+///x4XU+///AQAAAOhx/P//6RAHAAAPt8OD+GcPj0cDAACD+GUPjdIAAACD+FgPj2sBAAAPhLYDAACD6EMPhOkAAAArxg+EpgAAACvGD4SeAAAAg+gMD4VRBQAAZveF+Pv//zAIdQYJvfj7//+LvfD7//+D//91Bb////9/g4X0+///BPaF+Pv//yCLhfT7//+LQPyJhez7//8PhAsDAACFwHULofh3AQGJhez7//+Dpej7//8Ahf+Ltez7//8PjukEAACAPgAPhOAEAADoKikAAA+2DvZESAGAdAFGRv+F6Pv//zm96Pv//3zY6bwEAADHhbD7//8BAAAAA9+Djfj7//9Ag73w+///AI29/Pv//4m97Pv//w+NVQEAAMeF8Pv//wYAAADppQEAAGb3hfj7//8wCHUGCb34+///g4X0+///BIuF9Pv//w+3QPwz9kb2hfj7//8gibXU+///iYWs+///D4SDAAAA/zUYeAEBiIXI+///jYXI+///UI2F/Pv//1DGhcn7//8A6DkoAACDxAyFwH1dibW4+///61WD6Fp0Z4PoCXSUSA+F/QMAAION+Pv//0DHhej7//8KAAAAi534+///vgCAAACF3g+EvAIAAIuN9Pv//4sBi1EEg8EIiY30+///6dECAABmiYX8+///jYX8+///iYXs+///ibXo+///6aIDAACDhfT7//8Ei4X0+///i0D8hcB0OYtIBIXJdDL2hfn7//8ID78AiY3s+///dBSZK8LR+MeF1Pv//wEAAADpWwMAAIOl1Pv//wDpTwMAAKH4dwEBiYXs+///jVABighAhMl1+enwAAAAdRJmg/tndVfHhfD7//8BAAAA60u4AAIAADmF8Pv//34GiYXw+///vqMAAAA5tfD7//9+K4uN8Pv//4HBXQEAAOh6FwAAhcCJhcT7//90ComF7Pv//4v46waJtfD7//+LhfT7//+LCP+1sPv//4PACP+18Pv//4mF9Pv//4tA/ImFoPv//w++w1CNhZz7//9XUImNnPv///8VAHgBAYu1+Pv//4PEFIHmgAAAAHQRg73w+///AHUIV/8VDHgBAVlmg/tndQyF9nUIV/8VBHgBAVmAPy11DoCN+fv//wFHib3s+///i8eNUAGKCECEyXX5K8LpPgIAAIPoaQ+EPv7//4PoBQ+E2QAAAEgPhK8AAABIdGGD6AMPhN/8//8rxg+EIf7//4PoAw+FDgIAAMeFwPv//ycAAADrS4XAdQuh/HcBAYmF7Pv//4uF7Pv//8eF1Pv//wEAAADrCU9mgzgAdAYDxoX/dfMrhez7///R+OnBAQAAx4Xw+///CAAAAImNwPv///aF+Pv//4DHhej7//8QAAAAD4S0/f//i4XA+///g8BRZseF0Pv//zAAZomF0vv//4m13Pv//+mQ/f//9oX4+///gMeF6Pv//wgAAAAPhHn9//+Ajfn7//8C6W39//+DhfT7//8E9oX4+///IIuF9Pv//4tA/HQMZouN5Pv//2aJCOsIi43k+///iQjHhbj7//8BAAAA6XsCAACDhfT7//8E9sMgi4X0+///dBL2w0B0Bw+/QPyZ6xAPt0D86/f2w0CLQPx17zPS9sNAdBiF0n8UfASFwHMO99iD0gD32oCN+fv//wGFtfj7//+L2Iv6dQIz/4O98Pv//wB9DMeF8Pv//wEAAADrGoOl+Pv///e4AAIAADmF8Pv//34GiYXw+///i8MLx3UHg6Xc+///AI21+/3//4uF8Pv///+N8Pv//4XAfwaLwwvHdC2Lhej7//+ZUlBXU+i3JAAAg8Ewg/k5iZ2o+///i9iL+n4GA43A+///iA5O672Nhfv9//8rxkb2hfn7//8CiYXo+///ibXs+///dCGLzoA5MHUEhcB1Fv+N7Pv//4uN7Pv//8YBMECJhej7//+Dvbj7//8AD4VRAQAAi4X4+///qEB0NvbEAXQLZseF0Pv//y0A6xyoAXQLZseF0Pv//ysA6w2oAnQTZseF0Pv//yAAx4Xc+///AQAAAIud2Pv//4u16Pv//yveK53c+///9oX4+///DHUX/7XM+///jYXk+///U2og6If2//+DxAz/tdz7//+Lvcz7//+NheT7//+NjdD7///ok/b///aF+Pv//whZdBv2hfj7//8EdRJXU2owjYXk+///6EX2//+DxAyDvdT7//8AdV+F9n5bi73s+///ibW8+////zUYeAEB/428+///jYWs+///V1DoJyMAAIPEDIXAiYWo+///fjz/taz7//+Lhcz7//+NteT7///ovPX//wO9qPv//4O9vPv//wBZf7PrE4uN7Pv//1aNheT7///o9PX//1n2hfj7//8EdBf/tcz7//+NheT7//9TaiDoqvX//4PEDIO9xPv//wB0E/+1xPv//+g/4v//g6XE+///AFmLheD7//9mixhmhdsPhVX2//9fXotN/IuF5Pv//1voetr//8nDDQ8BAQQNAQE2DQEBjw0BAeANAQHsDQEBNw4BAS4PAQHMzMzMzIv/VYvsUbj//wAAZjlFDHRQZoF9DAABVot1CHMYagH/dQxW6GYlAACDxAyFwHUGZotFDOsr/3YEjUX8agFQagGNRQxQaAABAAD/dhTo4CIAAIPEHIXAZotFDHQEZotF/F7Jw8zMzMzMi/9Vi+xWi3UIi0Y8VzP/OwW4lAEBdGM7x3Rfi0YsOTh1WItGNDvHdBw5OHUYOwUIlgEBdBBQ6Erh////djzo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VIld3Ild1Ild2DldCHUIoeiUAQGJRQg5XSB1CKH4lAEBiUUg/3UI6EgYAABZOUUgdAiD+P90A4lFIFNTU1P/dRT/dRBT/3Ug/xWwEQABiUXgO8N1BzPA6VUBAACJXfyDwAOD4Pzo/rz//4ll6IvEiUXkg038/+sYM8BAw4tl6OjlFgAAM9uJXeSDTfz/M/9HOV3kdRKLTeDoVO7//4lF5DvDdLGJfdRTU/914P915P91FP91EFP/dSD/FbARAAGFwA+EygAAAFNT/3Xg/3Xk/3UM/3UI/xWsEQABi/CJddA78w+EqQAAAIl9/IPAA4Pg/OhyvP//iWXoi/yJfcyDTfz/6xczwEDDi2Xo6FkWAAAz2zP/g038/4t10Dv7dRSLzujL7f//i/g7+3Rox0XYAQAAAFZX/3Xg/3Xk/3UM/3UI/xWsEQABhcB0SfZFDQR0H4l13DldHHQ7OXUcfQOLdRxWV/91GOhd7P//g8QM6yQ5XRx1BFNT6wb/dRz/dRhWV2oB/3Ug/xUwEQABiUXc6wOLfcw5Xdh0B1fof7z//1k5XdR0Cf915OhxvP//WYtF3I1lwOhKzf//w8zMzMzMi/9Vi+xRZoF9DP//dDlmgX0MAAFzEA+3RQyLDSh4AQFmiwRB6yiLRQj/cBT/cASNRfxQagGNRQxQagHorhgAAIPEGIXAdQQzwOsDi0X8D7dNEA+3wCPBycPMzMzMzIv/VYvsVot1CIX2D4SBAQAA/3YE6Oi7////dgjo4Lv///92DOjYu////3YQ6NC7////dhToyLv///92GOjAu////zboubv///92IOixu////3Yk6Km7////dijoobv///92LOiZu////3Yw6JG7////djToibv///92HOiBu////3Y46Hm7////djzocbv//4PEQP92QOhmu////3ZE6F67////dkjoVrv///92TOhOu////3ZQ6Ea7////dlToPrv///92WOg2u////3Zc6C67////dmDoJrv///92ZOgeu////3Zo6Ba7////dmzoDrv///92cOgGu////3Z06P66////dnjo9rr///92fOjuuv//g8RA/7aAAAAA6OC6////toQAAADo1br///+2iAAAAOjKuv///7aMAAAA6L+6////tpAAAADotLr///+2lAAAAOipuv///7aYAAAA6J66////tpwA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VQJMb2FkTGlicmFyeVcAAFcDU2xlZXAAQgFHZXRDdXJyZW50UHJvY2VzcwBFAUdldEN1cnJlbnRUaHJlYWQAADQAQ2xvc2VIYW5kbGUAzgNsc3RybGVuVwAAXAJMb2NhbEZyZWUA9ABGb3JtYXRNZXNzYWdlVwAAxQNsc3RyY21waVcAjgJPdXRwdXREZWJ1Z1N0cmluZ1cAAMIBR2V0U3lzdGVtRGlyZWN0b3J5VwC/A2xzdHJjYXRXAADIA2xzdHJjcHlXAAAaA1NldEZpbGVBdHRyaWJ1dGVzVwAAVgBDcmVhdGVGaWxlVwCEAERlbGV0ZUZpbGVXAGEBR2V0RmlsZUF0dHJpYnV0ZXNXAADFAlJlbW92ZURpcmVjdG9yeVcAAM4ARmluZENsb3NlAN0ARmluZE5leHRGaWxlVwDCA2xzdHJjbXBXAADVAEZpbmRGaXJzdEZpbGVXAABUAUdldERyaXZlVHlwZVcA9AFHZXRXaW5kb3dzRGlyZWN0b3J5VwAAWQFHZXRFbnZpcm9ubWVudFZhcmlhYmxlVwDLA2xzdHJjcHluVwDqAUdldFZlcnNpb25FeFcAowJRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgDfAUdldFRpY2tDb3VudAAARgFHZXRDdXJyZW50VGhyZWFkSWQAAEMBR2V0Q3VycmVudFByb2Nlc3NJZADKAUdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAF8DVGVybWluYXRlUHJvY2VzcwAAbwNVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAEsDU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyABYCSGVhcEZyZWUAAOkBR2V0VmVyc2lvbkV4QQAQAkhlYXBBbGxvYwCjAUdldFByb2Nlc3NIZWFwAAC5AEV4aXRQcm9jZXNzAH8BR2V0TW9kdWxlSGFuZGxlQQAApQNXcml0ZUZpbGUAuQFHZXRTdGRIYW5kbGUAAH0BR2V0TW9kdWxlRmlsZU5hbWVBAAB+AUdldE1vZHVsZUZpbGVOYW1lVwAA9gBGcmVlRW52aXJvbm1lbnRTdHJpbmdzQQB1Ak11bHRpQnl0ZVRvV2lkZUNoYXIAVQFHZXRFbnZpcm9ubWVudFN0cmluZ3MA9wBGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwBXAUdldEVudmlyb25tZW50U3RyaW5nc1cAABABR2V0Q29tbWFuZExpbmVBABEBR2V0Q29tbWFuZExpbmVXACUDU2V0SGFuZGxlQ291bnQAAGYBR2V0RmlsZVR5cGUAtwFHZXRTdGFydHVwSW5mb0EAgQBEZWxldGVDcml0aWNhbFNlY3Rpb24AZANUbHNBbGxvYwAAKQNTZXRMYXN0RXJyb3IAAGUDVGxzRnJlZQBnA1Rsc1NldFZhbHVlAGYDVGxzR2V0VmFsdWUAFAJIZWFwRGVzdHJveQASAkhlYXBDcmVhdGUAAIQDVmlydHVhbEZyZWUAmABFbnRlckNyaXRpY2FsU2VjdGlvbgAAUQJMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAggNWaXJ0dWFsQWxsb2MAABoCSGVhcFJlQWxsb2MAUgJMb2FkTGlicmFyeUEAACMCSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbgD9AEdldEFDUAAAkwFHZXRPRU1DUAAABAFHZXRDUEluZm8A1wJSdGxVbndpbmQAKQJJbnRlcmxvY2tlZEV4Y2hhbmdlAIkDVmlydHVhbFF1ZXJ5AAAcA1NldEZpbGVQb2ludGVyAABEAkxDTWFwU3RyaW5nQQAAlQNXaWRlQ2hhclRvTXVsdGlCeXRlAEUCTENNYXBTdHJpbmdXAAB0AUdldExvY2FsZUluZm9BAAC6AUdldFN0cmluZ1R5cGVBAAC9AUdldFN0cmluZ1R5cGVXAAA4A1NldFN0ZEhhbmRsZQAAhwNWaXJ0dWFsUHJvdGVjdAAAxQFHZXRTeXN0ZW1JbmZvAO4ARmx1c2hGaWxlQnVmZmVycwAAtQJSZWFkRmlsZQAAS0VSTkVMMzIuZGxsAAC9AFNIR2V0UGF0aEZyb21JRExpc3RXAADDAFNIR2V0U3BlY2lhbEZvbGRlckxvY2F0aW9uAAC3AFNIR2V0TWFsbG9jAFNIRUxMMzIuZGxsAG1zaS5kbGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwTAAFkEwABPBMAAfwSAAHkEgAByBIAAcgSAAGoEgABiBIAAYgSAAH/////QwBvAG0AbQBvAG4AVQBzAGUAcgAAAAAAv0T//0C7AADR+gABAQAAAAAAAAAAAAAAAAAAAAIAAACodgABCAAAAHx2AAEJAAAAUHYAAQoAAAC4dQABEAAAAIh1AAERAAAAWHUAARIAAAA0dQABEwAAAAh1AAEYAAAA0HQAARkAAACodAABGgAAAHB0AAEbAAAAOHQAARwAAAAQdAABHgAAAPBzAAF4AAAA4HMAAXkAAADQcwABegAAAMBzAAH8AAAAvHMAAf8AAACscwABBQAAwAsAAAAAAAAAHQAAwAQAAAAAAAAAlgAAwAQAAAAAAAAAjQAAwAgAAAAAAAAAjgAAwAgAAAAAAAAAjwAAwAgAAAAAAAAAkAAAwAgAAAAAAAAAkQAAwAgAAAAAAAAAkgAAwAgAAAAAAAAAkwAAwAgAAAAAAAAAAwAAAAcAAAB4AAAACgAAAP////+ACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8QAAAAAAAAAEMAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAD0eAEBAAAAAAAAAAAAAAAAAIIAATh4AQEAAAAAuHEBAQAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGCYAQEAAAAAYJgBAQEBAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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cABwAGUAcgAAAAAAPAAOAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAzAC4AMQAuADQAMAAwADAALgAzADkANQA5AAAALgAHAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABtAHMAaQB6AGEAcAAAAAAAgAAuAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcAaAB0AAAAqQAgAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAC4AIABBAGwAbAAgAHIAaQBnAGgAdABzACAAcgBlAHMAZQByAHYAZQBkAC4AAACmAD8AAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAxAAAATQBpAGMAcgBvAHMAbwBmAHQArgAgAGkAcwAgAGEAIAByAGUAZwBpAHMAdABlAHIAZQBkACAAdAByAGEAZABlAG0AYQByAGsAIABvAGYAIABNAGkAYwByAG8AcwBvAGYAdAAgAEMAbwByAHAAbwByAGEAdABpAG8AbgAuAAAAAACiAD0AAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAyAAAAVwBpAG4AZABvAHcAcwCuACAAaQBzACAAYQAgAHIAZQBnAGkAcwB0AGUAcgBlAGQAIAB0AHIAYQBkAGUAbQBhAHIAawAgAG8AZgAgAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAC4AAAAAAD4ACwABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABtAHMAaQB6AGEAcAAuAGUAeABlAAAAAABYABwAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAAFcAaQBuAGQAbwB3AHMAIABJAG4AcwB0AGEAbABsAGUAcgAgAC0AIABVAG4AaQBjAG8AZABlAAAAQAAOAAEAUAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAMwAuADEALgA0ADAAMAAwAC4AMwA5ADUAOQAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEAbgBzAGwAYQB0AGkAbwBuAAAAAAAAALAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='

    $msiZapSha256 = '1363416B411D5DFC4992862E4C7840A721AA0122DD1C4D0EB3A8501F794B736B'
    $msiZapPath = "$PSScriptRoot\msizap.exe"
    if ((Test-Path -LiteralPath $msiZapPath -PathType Leaf) -and (Get-FileHash -LiteralPath $msiZapPath -Algorithm SHA256).Hash -eq $msiZapSha256) {
        Write-Verbose "Found msizap.exe at $msiZapPath"
        return $msiZapPath
    }
    else {
        $msiZapPath = "$env:TEMP\msizap.exe" 
        Write-Verbose "Unpacking $msiZapPath..."
        try {
            $bytes = [System.Convert]::FromBase64String($base64)
            [System.IO.File]::WriteAllBytes($msiZapPath, $bytes)
            
            if ((Get-FileHash -LiteralPath $msiZapPath -Algorithm SHA256).Hash -eq $msiZapSha256) {
                Write-Verbose "Successfully unpacked msizap.exe to $msiZapPath"
                return $msiZapPath
            }
            else {
                Write-Error "Failed to verify the hash of the unpacked msizap.exe"
            }
        }
        catch {
            Write-Error "Failed to unpack $msiZapPath`: $_"
        }
    }
}

function Test-EmptyFolder {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path -PathType Container) {
        $items = Get-ChildItem -LiteralPath $Path -Force
        if ($items) {
            return $false
        }
        else {
            return $true
        }
    }
    else {
        return $true
    }
}

function Remove-FolderIfEmpty {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path
    )

    if (Test-EmptyFolder -Path $Path) {
        Write-Verbose "Removing empty folder $Path..."
        Remove-Item -LiteralPath $Path -Force
    }
}
#endregion

$VerbosePreference = 'Continue'
$log = "$env:Temp\Uninstall-Python.log"
$null = Start-Transcript -Path $log -Append -NoClobber -Force

# Find/extract MsiZap if -Force specified
if ($Force) {
    $msiZapPath = Get-MsiZap
}

$UserProfiles = Get-UserProfiles -ExcludeSID 'S-1-5-19', 'S-1-5-20'
$MountedUserProfiles = Mount-RegistryHive -UserProfiles $UserProfiles

$GetInstalledSoftwareSplat = @{
    Architecture = $Architecture
    Publisher    = 'Python Software Foundation'
    FieldCount   = 2
}
foreach ($prop in 'VersionLessThan', 'VersionLessThanOrEqualTo', 'VersionEqualTo', 'VersionNotEqualTo', 'VersionGreaterThan', 'VersionGreaterThanOrEqualTo') {
    if ($PSBoundParameters.ContainsKey($prop)) {
        $GetInstalledSoftwareSplat[$prop] = $PSBoundParameters[$prop]
    }
}

Write-Verbose 'Searching for Python bootstrap entries for all users...'

if ($Architecture -eq 'x64') {
    $BootStrapNameMatch = 'Python \d+(?:\.\d+)+ \(64-bit\)'
}
elseif ($Architecture -eq 'x86') {
    $BootStrapNameMatch = 'Python \d+(?:\.\d+)+ \(32-bit\)'
}
else {
    $BootStrapNameMatch = 'Python \d+(?:\.\d+)+ \(\d{2}-bit\)'
}

$PythonBootstraps = Get-InstalledSoftware -DisplayName $BootStrapNameMatch -HivesToSearch 'HKU' @GetInstalledSoftwareSplat

foreach ($PythonBootstrap in $PythonBootstraps) {
    Uninstall-Software -Software $PythonBootstrap
    if ($Force) {
        if (Test-Path $PythonBootstrap.PSPath) {
            Write-Verbose "Force deleting bootstrap uninstall key $($PythonBootstrap.PSPath)..."
            Remove-Item -LiteralPath $PythonBootstrap.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        $uninstallExe = Split-UninstallString -UninstallString $PythonBootstrap.QuietUninstallString | Select-Object -First 1
        if ((Test-Path $uninstallExe) -and $uninstallExe -match '^C:\\.+Package Cache') {
            $parentFolder = Split-Path $uninstallExe -Parent
            Write-Verbose "Force deleting bootstrap package cache $parentFolder..."
            Remove-Item -LiteralPath $uninstallExe -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath "$parentFolder\state.rsm") { Remove-Item -LiteralPath "$parentFolder\state.rsm" -Force -ErrorAction SilentlyContinue }
            Remove-FolderIfEmpty $parentFolder
        }
    }
}

Write-Verbose 'Searching for Python MSI entries...'

$PythonMSIs = Get-InstalledSoftware -DisplayName '^Python.+\d{2}-bit' -HivesToSearch 'HKLM' -WindowsInstaller 1 @GetInstalledSoftwareSplat | Sort-Object { if ($_.DisplayName -match 'Core') { 1 } elseif ($_.DisplayName -match 'Executables') { 2 } else { 0 } }

foreach ($PythonMSI in $PythonMSIs) {
    Uninstall-Software -Software $PythonMSI
    if ($Force -and $msiZapPath) {
        if (Test-Path $PythonMSI.PSPath) {
            Write-Verbose "Forcing MsiZap on $($PythonMSI.DisplayName) $($PythonMSI.PSChildName)..."
            $null = &$msiZapPath TW! $PythonMSI.PSChildName
            if ($LASTEXITCODE -eq 0) {
                if (Test-Path $PythonMSI.PSPath) {
                    Write-Verbose "Force deleting MSI uninstall key $($PythonMSI.PSPath)..."
                    Remove-Item -LiteralPath $PythonMSI.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                if ((Test-Path $PythonMSI.InstallSource) -and $PythonMSI.InstallSource -match '^C:\\.+Package Cache') {
                    Write-Verbose "Force deleting MSI package cache $($PythonMSI.InstallSource)..."
                    if (Test-Path -Path "$($PythonMSI.InstallSource)\*.msi") { Remove-Item -Path "$($PythonMSI.InstallSource)\*.msi" -Force -ErrorAction SilentlyContinue }
                    Remove-FolderIfEmpty $PythonMSI.InstallSource
                }
            }
            else {
                Write-Warning "MsiZap failed with exit code $LASTEXITCODE."
            }
        }
    }
}

if ($Force) {
    $Everything = @($PythonBootstraps) + @($PythonMSIs) | Sort-Object { $_.DisplayName -replace '^.+\((\d{2}-bit)\).*$', '$1' }, DisplayVersion -Unique
    foreach ($Thing in $Everything) {
        $DisplayVersion = [version]$Thing.DisplayVersion
        $MajorVersion = $DisplayVersion.Major
        $MinorVersion = $DisplayVersion.Minor
        $Arch = if ($Thing.DisplayName -match '64-bit') { 'x64' } else { 'x86' }
        $Bitness = if ($Arch -eq 'x64') { '64-bit' } else { '32-bit' }
        $Suffix = if ($Arch -eq 'x64') { '' } else { '-32' }
        $Is64BitOS = (Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false).OSArchitecture -eq '64-bit'
        if (!$Is64BitOS -or ($Arch -eq 'x64' -and $Is64BitOS)) {
            $ProgramFiles = $env:ProgramFiles
            $HKLMSoftware = 'Registry::HKEY_LOCAL_MACHINE\Software'
        }
        else {
            $ProgramFiles = ${env:ProgramFiles(x86)}
            $HKLMSoftware = 'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node'
        }

        Write-Verbose "Cleaning up Python $MajorVersion.$MinorVersion $Bitness..."
        Write-Verbose " - $HKLMSoftware\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix..."
        Write-Verbose " - $ProgramFiles\Python$MajorVersion$MinorVersion$Suffix..."
        Write-Verbose " - $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion..."
        foreach ($UserProfile in $UserProfiles) {
            Write-Verbose " - HKEY_USERS\$($UserProfile.SID)\Software\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix..."
            Write-Verbose " - $($UserProfile.ProfilePath)\AppData\Local\Programs\Python\Python$MajorVersion$MinorVersion$Suffix..."
            Write-Verbose " - $($UserProfile.ProfilePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion..."
        }

        # Remove per-system elements
        if (Test-Path -LiteralPath "$HKLMSoftware\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix") {
            Write-Verbose "Force removing registry key $HKLMSoftware\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix..."
            Remove-Item -LiteralPath "$HKLMSoftware\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix" -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath "$ProgramFiles\Python$MajorVersion$MinorVersion$Suffix") {
            Write-Verbose "Force removing folder $ProgramFiles\Python$MajorVersion$MinorVersion$Suffix..."
            Remove-Item -LiteralPath "$ProgramFiles\Python$MajorVersion$MinorVersion$Suffix" -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion") {
            if (Test-Path -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion\*$Bitness*.lnk") {
                Write-Verbose "Force removing $Bitness shortcuts in $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion..."
                Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion\*$Bitness*.lnk" -Force -ErrorAction SilentlyContinue
            }
            Remove-FolderIfEmpty "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion"
        }

        # Remove per-user elements
        foreach ($UserProfile in $UserProfiles) {
            if (Test-Path -LiteralPath "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix") {
                Write-Verbose "Force removing registry key HKEY_USERS\$($UserProfile.SID)\Software\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix..."
                Remove-Item -LiteralPath "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Python\PythonCore\$MajorVersion.$MinorVersion$Suffix" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath "$($UserProfile.ProfilePath)\AppData\Local\Programs\Python\Python$MajorVersion$MinorVersion$Suffix") {
                Write-Verbose "Force removing folder $($UserProfile.ProfilePath)\AppData\Local\Programs\Python\Python$MajorVersion$MinorVersion$Suffix..."
                Remove-Item -LiteralPath "$($UserProfile.ProfilePath)\AppData\Local\Programs\Python\Python$MajorVersion$MinorVersion$Suffix" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath "$($UserProfile.ProfilePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion") {
                if (Test-Path -Path "$($UserProfile.ProfilePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion\*$Bitness*.lnk") {
                    Write-Verbose "Force removing $Bitness shortcuts in $($UserProfile.ProfilePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion..."
                    Remove-Item -Path "$($UserProfile.ProfilePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion\*$Bitness*.lnk" -Force -ErrorAction SilentlyContinue
                }
                Remove-FolderIfEmpty "$($UserProfile.ProfilePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $MajorVersion.$MinorVersion"
            }
        }
    }
}

Write-Verbose 'Checking for all Python MSI entries...'
$AllPythonMSIs = Get-InstalledSoftware -DisplayName '^Python.+\d{2}-bit' -Publisher 'Python Software Foundation' -HivesToSearch 'HKLM' -WindowsInstaller 1
Write-Verbose 'Searching for Python launcher...'
$PythonLauncher = Get-InstalledSoftware -DisplayName 'Python Launcher' -WindowsInstaller 1

if ($PythonLauncher) {
    if ($AllPythonMSIs) {
        Write-Verbose 'Python Launcher is installed, but other Python products are still present. Skipping uninstallation.'
    }
    else {
        Write-Verbose 'Uninstalling Python Launcher since no other Python products detected...'
        Uninstall-Software -Software $PythonLauncher
        if ($Force -and $msiZapPath) {
            if (Test-Path $PythonLauncher.PSPath) {
                Write-Verbose "Forcing MsiZap on $($PythonLauncher.DisplayName) $($PythonLauncher.PSChildName)..."
                $null = &$msiZapPath TW! $PythonLauncher.PSChildName
                if ($LASTEXITCODE -eq 0) {
                    if (Test-Path $PythonLauncher.PSPath) {
                        Write-Verbose "Force deleting MSI uninstall key $($PythonLauncher.PSPath)..."
                        Remove-Item -LiteralPath $PythonLauncher.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    if ((Test-Path $PythonLauncher.InstallSource) -and $PythonLauncher.InstallSource -match '^C:\\.+Package Cache') {
                        Write-Verbose "Force deleting MSI package cache $($PythonLauncher.InstallSource)..."
                        if (Test-Path -Path "$($PythonLauncher.InstallSource)\*.msi") { Remove-Item -Path "$($PythonLauncher.InstallSource)\*.msi" -Force -ErrorAction SilentlyContinue }
                        Remove-FolderIfEmpty $PythonLauncher.InstallSource
                    }
                }
                else {
                    Write-Warning "MsiZap failed with exit code $LASTEXITCODE."
                }
            }

            # Remove per-system files and registry
            if (!$Is64BitOS) {
                $HKLMSoftware = 'Registry::HKEY_LOCAL_MACHINE\Software'
            }
            else {
                $HKLMSoftware = 'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node'
            }
            $Paths = @(
                "C:\Windows\pyshellext.amd64.dll"
                "C:\Windows\py.exe"
                "C:\Windows\pyw.exe"
                "$HKLMSoftware\Python\PyLauncher"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.py"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.pyc"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.pyd"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.pyo"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.pyw"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.pyz"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\.pyzw"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\Python.ArchiveFile"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\Python.CompiledFile"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\Python.Extension"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\Python.File"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\Python.NoConArchiveFile"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\Python.NoConFile"
                "Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{BEA218D2-6950-497B-9434-61683EC065FE}"
            )
            foreach ($Path in $Paths) {
                if (Test-Path -LiteralPath $Path) {
                    Write-Verbose "Force deleting $Path..."
                    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Remove per-user files and registry
            foreach ($UserProfile in $UserProfiles) {
                $Paths = @(
                    $PythonLauncher.InstallSource
                    "$($UserProfile.ProfilePath)\AppData\Local\Programs\Python\Launcher"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Python\PyLauncher"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.py"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.pyc"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.pyd"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.pyo"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.pyw"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.pyz"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\.pyzw"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\Python.ArchiveFile"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\Python.CompiledFile"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\Python.Extension"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\Python.File"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\Python.NoConArchiveFile"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\Python.NoConFile"
                    "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\CLSID\{BEA218D2-6950-497B-9434-61683EC065FE}"
                )
                foreach ($Path in $Paths) {
                    if (Test-Path -LiteralPath $Path) {
                        Write-Verbose "Force deleting $Path..."
                        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}
else {
    Write-Verbose 'Python Launcher is not installed.'
}

Write-Verbose 'Checking to see if all desired Python products were removed...'
if ((Get-InstalledSoftware -DisplayName $BootStrapNameMatch -HivesToSearch 'HKU' @GetInstalledSoftwareSplat) -or (Get-InstalledSoftware -DisplayName '^Python.+\d{2}-bit' -HivesToSearch 'HKLM' -WindowsInstaller 1 @GetInstalledSoftwareSplat)) {
    if ($Force) {
        Write-Verbose 'Unable to remove all desired Python products.'
    }
    else {
        Write-Verbose 'Unable to remove all desired Python products, consider re-running with -Force.'
    }
}
else {
    Write-Verbose 'All desired Python products have been removed.'
}

if ($MountedUserProfiles) {
    Dismount-RegistryHive -UserProfiles $MountedUserProfiles
}

if ($Force -and $msiZapPath -eq "$env:TEMP\msizap.exe") {
    Remove-Item -LiteralPath $msiZapPath -Force
}

$null = Stop-Transcript