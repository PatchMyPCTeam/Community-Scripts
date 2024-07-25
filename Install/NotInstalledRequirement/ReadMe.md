# Get-NotInstalledRequirement

## Synopsis

Searches for installed software by DisplayName and returns 'Applicable' if not found.  

Created on:   2024-06-17  
Created by:   Ben Whitmore @PatchMyPC  
Filename:     Get-NotInstalledRequirement.ps1  

## Description

This script can be used as a requirement rule on a Win32 app to ensure the Win32 app is only applicable if software listed in the $appNameList is not installed  
This script searches through specified registry paths to find installed software that matches a given DisplayName.  
If a match is found on $appnameList, no output is displayed and the requirment rule is not satisfied which prevents the installation of the Win32 app.  
If no match is found, 'Applicable' is written to the output stream to indicate the software is not installed and the Win32 app is applicable because the requirement is met.  

References/credit:  
https://github.com/PatchMyPCTeam/Community-Scripts/tree/main/Uninstall/Pre-Uninstall/Uninstall-Software  
Author/Maintainer: [@Codaamok](https://github.com/codaamok)  

## Usage

You will need to modify the array variable at the top of the script to specify the app(s) you want to check for. If the apps are found, the script will return nothing, and the requirement will not be met. If the apps are not found, the script will return 'Applicable' and the requirement will be met.  

### Example 1

```powershell
[array]$appNameList = @('Cisco Secure Client', 'Cisco AnyConnect')
````

### Example 2

```powershell
[array]$appNameList = @('Google Chrome')
````

## Further Testing
You can uncomment line 105 to see the results of the search using the $appNameList array. Dont forget to comment it out again before using the script in Intune.  

```powershell
105 # Write-Host $application
````
