<#
    .SYNOPSIS
        Download and copy the MSI from the FortiClientVPN Online Installer
    .DESCRIPTION
        This function is used to download the FortiClientVPN Online Installer, Run it and then copy out the MSI required by the Patch My PC Publisher
    .PARAMETER LocalContentRepo
        Specify the path to your Patch My PC Local Content Repository
    .EXAMPLE
        C:\PS>  Get-FortiClientVPNOnlineInstaller -LocalContentRepo "C:\LocalContentRepository" -DownloadDir "$HOME\Downloads\FortiClientVPNOnlineInstaller_7.0.exe"
        Downloads the Online installer to your Downloads folder and exports the MSI to your Local Content Repo
    .NOTES
        ################# DISCLAIMER #################
        Patch My PC provides scripts, macro, and other code examples for illustration only, without warranty 
        either expressed or implied, including but not limited to the implied warranties of merchantability 
        and/or fitness for a particular purpose. This script is provided 'AS IS' and Patch My PC does not 
        guarantee that the following script, macro, or code can or should be used in any situation or that 
        operation of the code will be error-free.
#>
param (
    [Parameter(Mandatory = $true, Position=0)]
    [IO.Fileinfo]$LocalContentRepo
)
$Source = "https://links.fortinet.com/forticlient/win/vpnagent"
Invoke-RestMethod -Uri $Source -OutFile ".\FortiClientVPNOnlineInstaller_7.0.exe"
Start-Process ".\FortiClientVPNOnlineInstaller_7.0.exe" -WindowStyle Minimized

$started = $false
$exists = $false
Do {  
    $status = Get-Process "FortiClientVPN" -ErrorAction SilentlyContinue
    If (!$status) {
        Write-Host "waiting for FortiClientVPN.msi to start"
        Start-Sleep -Seconds 1
    }
    else {
        $started = $true
    }
} Until ($started)
Do {
    $FortiClientVPNMSI = Get-ChildItem -Path "C:\ProgramData\Applications\Cache" -Recurse -Filter "FortiClientVPN.msi" -ErrorAction SilentlyContinue
    If (!$FortiClientVPNMSI)
    {
        Start-Sleep -Seconds 1
    }
    else {
        $exists = $true
    }
} Until ($exists)
Copy-Item $FortiClientVPNMSI.FullName -Destination "$LocalContentRepo"
Stop-Process -Name $status.ProcessName -Force
Remove-Item -Path ".\FortiClientVPNOnlineInstaller_7.0.exe" -Force
