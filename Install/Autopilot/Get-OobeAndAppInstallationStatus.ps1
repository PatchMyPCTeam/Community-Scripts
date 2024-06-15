<#
.Synopsis
Check if the device is in oobe and search for installed software by DisplayName and return 'Applicable' if software is not found and device is in oobe.

Created on:   2024-06-15
Created by:   Ben Whitmore @PatchMyPC
Filename:     Get-OobeAndAppInstallationStatus.ps1

.Description
This script can be used as a requirement rule on a Win32 app to ensure the Win32 app is only applicable if software list in $appNameList is not installed and the device is still in oobe.
This script searches through specified registry paths to find installed software that matches a given DisplayName and determines whether OOBE (Windows Welcome) has been completed by loading the Kernel32 class from the Api namespace.
If a match is not found for any software defined in $appnameList and the device is still in oobe, 'Applicable' is written to the output stream to indicate the Win32 app is applicable because the requirement is met.
By default, both apps and OOBE are checked. The conditionalTest parameter can be used to test only 'onlyOOBE', 'onlyApps', or 'both'.

References/credit:
https://learn.microsoft.com/en-us/windows/win32/api/oobenotification/nf-oobenotification-oobecomplete
https://github.com/PatchMyPCTeam/Community-Scripts/tree/main/Uninstall/Pre-Uninstall/Uninstall-Software
https://oofhours.com/2023/09/15/detecting-when-you-are-in-oobe/

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------
#>

# Define the application names to search for. If any of these apps are installed, the script will return not return 'Applicable'. 
# We use -like $app* in code to match the string to the start of the DisplayName
[array]$appNameList = @('Cisco Secure Client', 'Cisco AnyConnect')

# Call the function with the prefered conditionalTest parameter. valid options are ('onlyOOBE', 'onlyApps', 'both')
Test-Requirements -conditionalTest 'both'

# Set the error action preference to stop the script if an error occurs
$ErrorActionPreference = 'Stop'

# Define the conditions to test for. Default is to test for both OOBE and installed software
function Test-Requirements {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('onlyOOBE', 'onlyApps', 'both')]
        [string]$conditionalTest
    )

    # Function to detect if the device is still going through OOBE
    function Get-IsOobeComplete {
        $cSharpDef = @"
    using System;
    using System.Runtime.InteropServices;
    
    namespace Api
    {
        public class Kernel32
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool OOBEComplete(ref bool isOOBEComplete);
        }
    }
"@
        
        # Add the C# type definition to the session
        if (-not ([System.Management.Automation.PSTypeName]'Api.Kernel32').Type) {
            Add-Type -TypeDefinition $cSharpDef -Language CSharp
        }
    
        # Using the method
        $oobeComplete = 0
        $result = [Api.Kernel32]::OOBEComplete([ref] $oobeComplete)
    
        if ($result) {
            return [bool]$result
        }
        else {
            exit 1
        }
    }

    # Function to generate full registry paths based on architecture and hives to search
    function Get-PathsToSearch {
        param(
            [Parameter(Mandatory = $false)]
            [ValidateSet('Both', 'x86', 'x64')]
            [String]$Architecture = 'Both',
            [Parameter(Mandatory = $false)]
            [ValidateSet('HKLM', 'HKCU')]
            [String[]]$HivesToSearch = ('HKLM', 'HKCU')
        )
    
        # Decide paths to search based on architecture parameter
        $pathsToSearch = switch -regex ($Architecture) {
            'Both|x86' { if (-not ([IntPtr]::Size -eq 4)) { 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } else { 'Software\Microsoft\Windows\CurrentVersion\Uninstall\*' } }
            'Both|x64' { if (-not ([IntPtr]::Size -eq 4)) { 'Software\Microsoft\Windows\CurrentVersion\Uninstall\*' } }
        }

        # Generate full registry paths
        $fullPaths = foreach ($pathFragment in $pathsToSearch) {
            foreach ($hive in $HivesToSearch) {
                [string]::Format('registry::{0}\{1}', $hive, $pathFragment)
            }
        }

        # Return the full paths
        return $fullPaths
    }

    function Get-InstalledSoftware {
        param (
            [Parameter(Mandatory = $true)]
            [array]$appName
        )

        # Variable to detect if any matching software is found
        [bool]$detected = $false

        # Search through all generated registry paths
        foreach ($path in Get-PathsToSearch) {

            # Retrieve all subkeys from the path
            $subkeys = Get-ChildItem $path

            # Check each subkey for matching DisplayName
            foreach ($subkey in $subkeys) {

                # Retrieve the DisplayName from the subkey
                $displayName = (Get-ItemProperty -Path $subkey.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName

                foreach ($app in $appName) {
                    if ($displayName -like "$app*") {

                        # Gather additional information when a match is found
                        $displayVersion = (Get-ItemProperty -Path $subkey.PSPath -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
                        $publisher = (Get-ItemProperty -Path $subkey.PSPath -Name Publisher -ErrorAction SilentlyContinue).Publisher
                        $installDate = (Get-ItemProperty -Path $subkey.PSPath -Name InstallDate -ErrorAction SilentlyContinue).InstallDate

                        # Create a custom object to hold software information
                        $application = [PSCustomObject]@{
                            DisplayName    = $displayName
                            DisplayVersion = $displayVersion
                            Publisher      = $publisher
                            InstallDate    = $installDate
                        }

                        $detected = $true
                        # Only un-comment the line below to write-host during testing to see if the $appname match is working as expected
                        # Write-Host $application
                    }
                }
            }
        }

        # Return the result
        if ($detected -eq $true) {
            return $true
        }
        else {
            return $false
        }
    }

    # Output an output stream if no software match was found from $appNameList and oobe is not complete
    # Switch statement to test for conditions
    switch ($conditionalTest) {
        'onlyOOBE' {
            if ((Get-IsOobeComplete) -eq $false) {
                Write-Host 'Applicable'
            }
        }
        'onlyApps' {
            if ((Get-InstalledSoftware -appName $appNameList) -eq $false) {
                Write-Host 'Applicable'
            }
        }
        default {
            if ((Get-InstalledSoftware -appName $appNameList) -eq $false -and (Get-IsOobeComplete) -eq $false) {
                Write-Host 'Applicable'
            }
        }
    }
}