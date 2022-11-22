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
    The name of the software you wish to uninstall as it exactly appears in the registry as its DisplayName value.
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
.PARAMETER AdditionalArguments
    A string which includes the additional parameters you would like passed to the uninstaller.
.EXAMPLE
    PS C:\> Uninstall-Software.ps1 -DisplayName "Greenshot"
    
    Uninstalls Greenshot if "Greenshot" is detected as the DisplayName in a key under either of the registry key paths:
        - SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall 
#>
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
    [String]$AdditionalArguments
)
function Get-InstalledSoftware {
    param(
        [Parameter()]
        [ValidateSet('Both', 'x86', 'x64')]
        [string]$Architecture,

        [Parameter()]
        [ValidateSet('HKLM', 'HKCU')]
        [string[]]$HivesToSearch
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

    $propertyNames = 'DisplayName', 'DisplayVersion', 'PSChildName', 'Publisher', 'InstallDate', 'QuietUninstallString', 'UninstallString', 'WindowsInstaller'

    $AllFoundObjects = Get-ItemProperty -Path $FullPaths -Name $propertyNames -ErrorAction SilentlyContinue

    foreach ($Result in $AllFoundObjects) {
        if (-not [string]::IsNullOrEmpty($Result.DisplayName)) {
            $Result | Select-Object -Property $propertyNames
        }
    }
}

$log = '{0}\Uninstall-Software-{1}.log' -f $env:temp, $DisplayName.Replace(' ','_')
$null = Start-Transcript -Path $log -Append -NoClobber -Force

$VerbosePreference = 'Continue'

[array]$InstalledSoftware = Get-InstalledSoftware -Architecture $Architecture -HivesToSearch $HivesToSearch | 
    Where-Object { 
        $_.DisplayName -eq $DisplayName -And $(if ($PSBoundParameters.ContainsKey('WindowsInstaller')) {
            $WindowsInstaller -eq $_.WindowsInstaller
        }
        else {
            $true
        })
    }

if ($InstalledSoftware.count -eq 0) {
    Write-Verbose ("Software '{0}' not installed" -f $DisplayName)
}
elseif ($InstalledSoftware.count -gt 1) {
    Write-Verbose ("Found more than one instance of software '{0}', skipping because not sure which UninstallString to execute" -f $DisplayName)
}
else {
    Write-Verbose ("Found '{0}':" -f $DisplayName)
    Write-Verbose ($InstalledSoftware | ConvertTo-Json)

    if ([String]::IsNullOrWhiteSpace($InstalledSoftware.UninstallString) -And [String]::IsNullOrWhiteSpace($InstalledSoftware.QuietUninstallString)) {
        Write-Verbose ("Can not uninstall software as UninstallString and QuietUninstallString are both empty for '{0}'" -f $InstalledSoftware.DisplayName)
    }
    else {
        $ProductCode = [Regex]::Match($InstalledSoftware.UninstallString, "(\{.+\})").Groups[0].Value
        if ($ProductCode) { 
            Write-Verbose ("Found product code, will uninstall using '{0}'" -f $ProductCode)

            $StartProcessSplat = @{
                FilePath = "msiexec.exe"
                ArgumentList = "/x", $ProductCode, "/qn", "REBOOT=ReallySuppress"
                Wait = $true
                PassThru = $true
                ErrorAction = 'Stop'
            }

            if ($PSBoundParameters.ContainsKey('AdditionalArguments')) {
                Write-Verbose ('Adding additional arguments "{0}" to uninstall string' -f $AdditionalArguments)
                $StartProcessSplat['ArgumentList'] = $StartProcessSplat['ArgumentList'] += $AdditionalArguments
            }

            Write-Verbose ("Trying uninstall with 'msiexec.exe {0}'" -f [String]$StartProcessSplat['ArgumentList'])
            $proc = Start-Process @StartProcessSplat
            return $proc.ExitCode
        } 
        else { 
            Write-Verbose ("Could not parse product code from '{0}'" -f $InstalledSoftware.UninstallString)
            if (-not [String]::IsNullOrWhiteSpace($InstalledSoftware.QuietUninstallString)) {
                if ($PSBoundParameters.ContainsKey('AdditionalArguments')) {
                    Write-Verbose ('Adding additional arguments "{0}" to QuietUninstallString' -f $AdditionalArguments)
                    $InstalledSoftware.QuietUninstallString = '{0} {1}' -f $InstalledSoftware.QuietUninstallString, $AdditionalArguments
                }

                Write-Verbose ("Trying QuietUninstallString '{0}'" -f $InstalledSoftware.QuietUninstallString)
                Invoke-Expression "& $($InstalledSoftware.QuietUninstallString)" -ErrorAction "Stop"
            }
            else {
                Write-Verbose ("Trying UninstallString '{0}'" -f $InstalledSoftware.UninstallString)

                if ($PSBoundParameters.ContainsKey("AdditionalArguments")) {
                    Write-Verbose ("Adding additional arguments '{0}' to UninstallString" -f $AdditionalArguments)
                    $InstalledSoftware.UninstallString = "{0} {1}" -f $InstalledSoftware.UninstallString, $AdditionalArguments
                }

                Write-Verbose ("Trying UninstallString '{0}'" -f $InstalledSoftware.UninstallString)
                Invoke-Expression "& $($InstalledSoftware.UninstallString)" -ErrorAction "Stop"
            }
        }
    }
}

$null = Stop-Transcript