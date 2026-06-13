$appName = $packageXml.Package.ProductName
If($runningProcesses){
    $noDuplicatesRunningProcesses = $runningProcesses | Sort-Object FileName -Unique
    Foreach($processToStart in $noDuplicatesRunningProcesses){        
        Write-Host "$($processToStart.Description) was running when the installation started. Relaunching it and informing the user about installation complete."
        [string]$processToStartPath = $processToStart.FileName 
        Start-ADTProcessAsUser -FilePath $processToStartPath -NoWait
    }
    Show-ADTInstallationPrompt -Title 'Installation complete' -Message "$appName was successfully installed on your device" -ButtonMiddleText 'OK' -Force

}else{
    Write-Host "$appName was not running when the installation started."
}