<#
.SYNOPSIS
    Uninstall installshield based software
    Original Credit to SilentInstallHQ using PSAppDeployToolkit
    https://silentinstallhq.com/3dconnexion-3dxware-silent-uninstall-powershell/?utm_content=cmp-true

.DESCRIPTION
    Some older apps install using an InstallShield installer and do not have the correct uninstall information in the ARP registry key to pivot off to do an unattended uninstallation of the application.
    This script can be used to build a response file to uninstall the app using the setup.exe and setup.ilg files that are created when the app is installed.

.NOTES
    FileName:    PatchMyPC-Remove-InstallShieldApp.ps1
    Author:      Ben Whitmore @ PatchMyPC

    ################# DISCLAIMER #################
    Patch My PC provides scripts, macro, and other code examples for illustration only, without warranty 
    either expressed or implied, including but not limited to the implied warranties of merchantability 
    and/or fitness for a particular purpose. This script is provided 'AS IS' and Patch My PC does not 
    guarantee that the following script, macro, or code can or should be used in any situation or that 
    operation of the code will be error-free.
    
.PARAMETER App
    Specify the app remove (this name is used to search the DisplayName property in the ARP registry keys)

.PARAMETER Vendor
    Specify the app vendor (this name will be used to build the ISS response file)

.PARAMETER AppVersions
    Specify the app versions to look for in the ARP registry keys. This is passed as as string rather than an object so we can use it with the PMP pre/post script feature. The comma-seperated values are converted back into an array in the script

.PARAMETER Lang
    Specify the app language (this name will be used to build the ISS response file)

.PARAMETER TimeToWait
    Time to wait for installshield to uninstall the app after start-process is called

.EXAMPLE
    .\PatchMyPC-Remove-InstallShieldApp.ps1 -App '3Dconnexion 3DxWare 10' -Vendor '3Dconnexion' -AppVersions 10.4.10, 10.6.3, 10.6.4 -Lang '0009' -TimeToWait 60

.EXAMPLE 
 When used with PMP pre Script feature, comment out the quotes around the parameters
 -----------------------------------------------------------------------------------
    .\PatchMyPC-Remove-InstallShieldApp.ps1 -App \"3Dconnexion 3DxWare 10\" -Vendor \"3Dconnexion\" -AppVersions \"10.4.10, 10.6.3, 10.6.4\"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$app,
    [string]$vendor,
    [string]$appVersions,
    [string]$lang = '0009',
    [int]$timeToWait = 60
)

Begin {
    
    $appVersionsArray = $appVersions -split ', ' | ForEach-Object { $_.Trim() } # trim space and convert string to an array
    $log = '{0}\Uninstall-Software-{1}.log' -f $env:temp, $app
    $logDetail = '{0}\Uninstall-Software-{1}-detail.log' -f $env:temp, $app

    Write-Host "Starting $($MyInvocation.MyCommand.Name)"
    Write-Host "Using $($PSVersionTable.PSVersion)"
    Write-Host "Looking for app $app"
    Write-Host "Looking for app version to be one of $($appVersions)"
    Write-Host "Logging to $($log)"

    $null = Start-Transcript -Path $log -Append -NoClobber -Force

    try {
        Write-Host "Checking to see if $app is installed"
        $appInfo = Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Where-Object { $_.DisplayName -match $app } | Select-Object -Property DisplayName, DisplayVersion, ProductGuid, LogFile
        
        if ([string]::IsNullOrWhiteSpace($appInfo)) {
            Write-Warning -Message "Cannot to find '$app' in the registry. Unable to uninstall"
            $null = Stop-Transcript
            Exit 0
        }
        else {
            [string]$appInfo.ProductGuid
            [version]$appInfo.DisplayVersion
            [string]$appInfo.LogFile 
            Write-Host "Found $($appInfo.DisplayName) $($appInfo.DisplayVersion) installed"
        }
    }
    catch {
        Write-Warning -Message "Error trying while trying to find $app. Error: $($_.Exception.Message)"
    }
}

Process {

    if ($appVersionsArray -contains $appInfo.DisplayVersion) {
        $uninstallPath = $($appInfo.LogFile).Replace('setup.ilg', 'setup.exe') 
        $uninstallIss = "$($env:temp)\uninstall.iss"
        Write-Host "Creating $($uninstallIss)"  
        New-Item -Path $uninstallIss -Force | Out-Null
        Set-Content -Path "$uninstallIss" -Value "[InstallShield Silent]"
        Add-Content -Path "$uninstallIss" -Value "Version=v7.00"
        Add-Content -Path "$uninstallIss" -Value "File=Response File"
        Add-Content -Path "$uninstallIss" -Value "[File Transfer]"
        Add-Content -Path "$uninstallIss" -Value "OverwrittenReadOnly=NoToAll"
        Add-Content -Path "$uninstallIss" -Value "[$($appInfo.ProductGuid)-DlgOrder]"
        Add-Content -Path "$uninstallIss" -Value "Dlg0=$($appInfo.ProductGuid)-SdWelcomeMaint-0"
        Add-Content -Path "$uninstallIss" -Value "Count=3"
        Add-Content -Path "$uninstallIss" -Value "Dlg1=$($appInfo.ProductGuid)-MessageBox-0"
        Add-Content -Path "$uninstallIss" -Value "Dlg2=$($appInfo.ProductGuid)-SdFinishReboot-0"
        Add-Content -Path "$uninstallIss" -Value "[$($appInfo.ProductGuid)-SdWelcomeMaint-0]"
        Add-Content -Path "$uninstallIss" -Value "Result=303"
        Add-Content -Path "$uninstallIss" -Value "[$($appInfo.ProductGuid)-MessageBox-0]"
        Add-Content -Path "$uninstallIss" -Value "Result=6"
        Add-Content -Path "$uninstallIss" -Value "[Application]"
        Add-Content -Path "$uninstallIss" -Value "Name=$($app)"
        Add-Content -Path "$uninstallIss" -Value "Version=$($appInfo.DisplayVersion)"
        Add-Content -Path "$uninstallIss" -Value "Company=$($vendor)"
        Add-Content -Path "$uninstallIss" -Value "Lang=$($lang)"
        Add-Content -Path "$uninstallIss" -Value "[$($appInfo.ProductGuid)-SdFinishReboot-0]"
        Add-Content -Path "$uninstallIss" -Value "Result=1"
        Add-Content -Path "$uninstallIss" -Value "BootOption=0"

        Start-Sleep -Seconds 5
        Write-Host "Calling Start-Process to uninstall $($appInfo.DisplayName) $($appInfo.DisplayVersion) using $($uninstallPath) with parameters in $($uninstallIss) and detailed logging in $($logDetail)"
        Start-Process -FilePath $uninstallPath -ArgumentList "-removeall -s -f1""$($uninstallIss)"" -f2""$($logDetail)"" -Wait -NoNewWindow -PassThru"
        Write-Host "Waiting $($timeToWait) seconds for $($appInfo.DisplayName) $($appInfo.DisplayVersion) to uninstall"
        Start-Sleep -Seconds $timeToWait

        Write-Host "Checking to see if $($appInfo.DisplayName) $($appInfo.DisplayVersion) was uninstalled"
        $appInfoTest = Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Where-Object { $_.DisplayName -match $app } | Select-Object -Property DisplayName, DisplayVersion, ProductGuid, LogFile
        if ([string]::IsNullOrWhiteSpace($appInfoTest)) {
            Write-Host "Successfully uninstalled $app version $($appInfo.DisplayVersion)"
            $null = Stop-Transcript
            Exit 0
        }
        else {
            Write-Warning -Message "Unable to uninstall $app"
            $null = Stop-Transcript
            Exit 1
        }
    }
    else {
        Write-Warning -Message "Unable to find the required version of $app. Should be one of $($appVersions) but instead we found $($appInfo.DisplayVersion)"
        $null = Stop-Transcript
        Exit 0
    }
}

End {
    $null = Stop-Transcript
}