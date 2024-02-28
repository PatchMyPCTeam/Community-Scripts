<#
.SYNOPSIS
    Grab Installation Information from the registry to determine properties for Patch My PC Custom Apps
.DESCRIPTION
    This script is useful if you need to grab application information when creating EXE-based apps in Patch My PC Custom Apps. 

    One To use this script, install the targeted app on an endpoint, run the script, then select the newly installed software from the list and click "OK".
    The script will output the following information (note that these are all best-guesses and may need to be adjusted):
        AppName - suggested name for the application
        Architecture - Application Architecture (32 or 64-bit)
        AppsAndFeaturesName - The "Apps & Features" name with wildcards included for proper detection
        Version - Application version number
        InstallContext - Application Install Context (System or User)
        PotentialConflictingProcesses - List of the exe's in the installtion target directory

.EXAMPLE
    PS C:\> PatchMyPC-CustomAppsHelper.ps1
    
    Displays a list of installed software and will provide relevant info for Patch My PC Custom Apps
#>

$Apps = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\, HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\, HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ -ErrorAction SilentlyContinue | Get-ItemProperty | Select-Object DisplayName, DisplayVersion, Version, WindowsInstaller, SystemComponent, UninstallString, QuietUninstallString, Publisher, URLInfoAbout, InstallLocation, InstallSource, PSPath) | Where-Object { -not([System.String]::IsNullOrEmpty($_.DisplayName)) }
$SelectedApp = $Apps | Sort-Object WindowsInstaller, DisplayName, SystemComponent | Out-GridView -Title "Select Application" -OutputMode Single | Select-Object -First 1

if ($SelectedApp) {
	$SelectedApp.DisplayName -match '(?:(\d+)\.)?(?:(\d+)\.)?(?:(\d+)\.\d+)' | Out-Null
	if ($Matches) {
		$version = $Matches[0]
		$DisplayNameNew = ($SelectedApp.DisplayName).Replace($version, '%')
	}
	else {
		$DisplayNameNew = $SelectedApp.DisplayName
	}

	if ($SelectedApp.PSPath -like "*WOW6432Node*") {
		$Architecture = "32-bit"
	}
	elseif (($SelectedApp.PSPath -notlike "*WOW6432Node*") -and ([IntPtr]::Size -eq 4)) {
		$Architecture = "32-bit"
	}
	else {
		$Architecture = "64-bit"
	}

	if ($SelectedApp.PSPath -like "*HKEY_LOCAL_MACHINE*") {
		$InstallContext = "System"
	}
	else {
		$InstallContext = "User"
	}

	$ConflictingProcesses = (Get-ChildItem $SelectedApp.InstallLocation -Include "*.exe" -Recurse).Name

	$DetectionInfo = [PSCustomObject]@{
		AppName                       = $($DisplayNameNew.Replace('%', '').Replace('  ', ' ').trim())
		Publisher                     = $SelectedApp.Publisher
		Architecture                  = $Architecture
		AppsAndFeaturesName           = $DisplayNameNew
		Version                       = $SelectedApp.DisplayVersion
		InstallContext                = $InstallContext
		PotentialConflictingProcesses = $($ConflictingProcesses -join ",")
	}
	$DetectionInfo
} else {
	Write-Output "No App Selected. Exiting."
}

# Uncomment the below line to output the results to a file
#$DetectionInfo | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$($DisplayNameNew.Replace('%','').Replace('  ',' ').trim()).txt" -Encoding oem -Force