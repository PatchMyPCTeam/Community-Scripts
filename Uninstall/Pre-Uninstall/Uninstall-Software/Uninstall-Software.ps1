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
    with that of the DisplayName in the registry. If one match is found, it uninstalls the software using the UninstallString. 

    If a product code is not in the UninstallString, the whole value in QuietUninstallString is used, or just UninstallString if QuietUninstallString doesn't exist.

    If more than one matches of the DisplayName occurs, uninstall is not possible.

    If QuietUninstallString and UninstallString is not present or null, uninstall is not possible.
.PARAMETER DisplayName
    The name of the software you wish to uninstall as it appears in the registry as its DisplayName value. * wildcard supported.
.PARAMETER Architecture
    Choose which registry key path to search in while looking for installed software. Acceptable values are:
        - "x86" will search in SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall on a 64-bit system.
        - "x64" will search in SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall.
        - "Both" will search in both key paths.
.PARAMETER HivesToSearch
    Choose which registry hive to search in while looking for installed software. Acceptabel values aref;
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

    [Parameter(ParameterSetName = 'AdditionalArguments')]
    [String]$AdditionalArguments,

    [Parameter(ParameterSetName = 'AdditionalEXEorMSIArguments')]
    [String]$AdditionalMSIArguments,
    
    [Parameter(ParameterSetName = 'AdditionalEXEorMSIArguments')]
    [String]$AdditionalEXEArguments,

    [Parameter()]
    [Switch]$UninstallAll
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
        [String]$AdditionalEXEArguments
    )

    Write-Verbose ("Found '{0}':" -f $Software.DisplayName)
    Write-Verbose ($Software | ConvertTo-Json)

    if ([String]::IsNullOrWhiteSpace($Software.UninstallString) -And [String]::IsNullOrWhiteSpace($Software.QuietUninstallString)) {
        Write-Verbose ("Can not uninstall software as UninstallString and QuietUninstallString are both empty for '{0}'" -f $Software.DisplayName)
    }
    else {
        $ProductCode = [Regex]::Match($Software.UninstallString, "^msiexec.+(\{.+\})", 'IgnoreCase').Groups[1].Value
        if ($ProductCode) { 
            Write-Verbose ("Found product code, will uninstall using '{0}'" -f $ProductCode)

            $StartProcessSplat = @{
                FilePath     = "msiexec.exe"
                ArgumentList = "/x", $ProductCode, "/qn", "REBOOT=ReallySuppress"
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

            Write-Verbose ("Trying uninstall with 'msiexec.exe {0}'" -f [String]$StartProcessSplat['ArgumentList'])
            $proc = Start-Process @StartProcessSplat
            return $proc.ExitCode
        } 
        else { 
            Write-Verbose ("Could not parse product code from '{0}'" -f $Software.UninstallString)
            if (-not [String]::IsNullOrWhiteSpace($Software.QuietUninstallString)) {
                $UninstallString = $Software.QuietUninstallString
                Write-Verbose ("Found QuietUninstallString '{0}'" -f $Software.QuietUninstallString)
            }
            else {
                $UninstallString = $Software.UninstallString
                Write-Verbose ("Found UninstallString '{0}'" -f $Software.UninstallString)
            }

            if (-not [String]::IsNullOrWhiteSpace($AdditionalArguments)) {
                Write-Verbose ("Adding additional arguments '{0}' to UninstallString" -f $AdditionalArguments)
                $UninstallString = "{0} {1}" -f $UninstallString, $AdditionalArguments
            }
            elseif (-not [String]::IsNullOrWhiteSpace($AdditionalEXEArguments)) {
                Write-Verbose ("Adding additional EXE arguments '{0}' to UninstallString" -f $AdditionalEXEArguments)
                $UninstallString = "{0} {1}" -f $UninstallString, $AdditionalEXEArguments
            }

            Write-Verbose ("Trying uninstall with '{0}'" -f $UninstallString)
            Invoke-Expression "& $UninstallString" -ErrorAction $ErrorActionPreference
        }
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

[array]$InstalledSoftware = Get-InstalledSoftware -Architecture $Architecture -HivesToSearch $HivesToSearch | 
    Where-Object { 
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

        $_.DisplayName -like $DisplayName -And $_WindowsInstaller -And $_SystemComponent        
    }

if ($InstalledSoftware.count -eq 0) {
    Write-Verbose ("Software '{0}' not installed" -f $DisplayName)
}
elseif ($InstalledSoftware.count -gt 1) {
    if ($UninstallAll.IsPresent) {
        foreach ($Software in $InstalledSoftware) {
            Uninstall-Software -Software $Software @UninstallSoftwareSplat
       }
    }
    else {
        Write-Verbose ("Found more than one instance of software '{0}', skipping because not sure which UninstallString to execute" -f $DisplayName)
    }
}
else {
    Uninstall-Software -Software $InstalledSoftware[0] @UninstallSoftwareSplat
}

$null = Stop-Transcript