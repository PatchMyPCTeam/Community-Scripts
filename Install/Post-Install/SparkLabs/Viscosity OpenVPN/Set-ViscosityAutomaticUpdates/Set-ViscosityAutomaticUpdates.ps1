<#
.Synopsis
   Disable or Enable automatic updates for Viscosity
.DESCRIPTION
   This script can be used to enable or disable the Automatic updates for the app Viscosity.
   The installer of this app does not support this option, unfortunately.
   The setting enabling/disabling the automatic updates is stored in the Settings.xml located in %AppData%\Viscosity.
   The Setting.xml is created automatically when the application is launched for the first time. The app is launched automatically even during a /VERYSILENT install.
   2 keys will have to exist under /plist/dict in order to enable/disable the automatic updates:
   <key>AutoUpdate</key>
   <string>NO</string>--> to disable automatic updates OR <string>YES</string> --> to enable automatic updates.   
   This script will add the entries if they don't exist already. If they do, it will update the the corresponding string to enable/disable the update.
   Given that the XML file resides in the user %appdata% folder, it will make the change for each user profile where the profile path will be like "C:\Users" if the settings.xml file exists.
   A log file will be exported in %windir\temp.
.NOTES
    Author: Barbat Liviu
    Big thanks to Cody Mathis and Adam Cook for their help.
.EXAMPLE
   Set-ViscosityAutomaticUpdates.ps1 -UpdatesEnabled "Yes"
.EXAMPLE
   Set-ViscosityAutomaticUpdates.ps1 -UpdatesEnabled "No"
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('Yes', 'No')]
    [String]$UpdatesEnabled
)

$LogName = "SetViscosityAutomaticUpdates.log"
Function Write-CMLogEntry {
    <#
    .DESCRIPTION
        Write CMTrace friendly log files with options for log rotation
    .EXAMPLE
        $Bias = Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias
        $FileName = "myscript_" + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + ".log"
        Write-CMLogEntry -Value "Writing text to log file" -Severity 1 -Component "Some component name" -FileName $FileName -Folder "C:\Windows\temp" -Bias $Bias -Enable -MaxLogFileSize 1MB -MaxNumOfRotatedLogs 3
    .NOTES
        Authors:    Cody Mathis / Adam Cook
        Contact:    @CodyMathis123 / @codaamok
    #>
    param (
        [parameter(Mandatory = $true, HelpMessage = 'Value added to the log file.')]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        [parameter(Mandatory = $false, HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('1', '2', '3')]
        [string]$Severity = 1,
        [parameter(Mandatory = $false, HelpMessage = "Stage that the log entry is occuring in, log refers to as 'component'.")]
        [ValidateNotNullOrEmpty()]
        [string]$Component = "ViscosityXMLUpdater",
        [parameter(Mandatory = $false, HelpMessage = 'Name of the log file that the entry will written to.')]
        [ValidateNotNullOrEmpty()]
        [string]$FileName = $LogName,
        [parameter(Mandatory = $false, HelpMessage = 'Path to the folder where the log will be stored.')]
        [ValidateNotNullOrEmpty()]
        [string]$Folder = "C:\Windows\Temp",
        [parameter(Mandatory = $false, HelpMessage = 'Set timezone Bias to ensure timestamps are accurate.')]
        [ValidateNotNullOrEmpty()]
        [int32]$Bias,
        [parameter(Mandatory = $false, HelpMessage = 'Maximum size of log file before it rolls over. Set to 0 to disable log rotation.')]
        [ValidateNotNullOrEmpty()]
        [int32]$MaxLogFileSize = 5MB,
        [parameter(Mandatory = $false, HelpMessage = 'Maximum number of rotated log files to keep. Set to 0 for unlimited rotated log files.')]
        [ValidateNotNullOrEmpty()]
        [int32]$MaxNumOfRotatedLogs = 0,
        [parameter(Mandatory = $false, HelpMessage = 'A switch that enables the use of this function.')]
        [ValidateNotNullOrEmpty()]
        [switch]$Enable =$true
    )
    If ($Enable) {
        # Determine log file location
        $LogFilePath = Join-Path -Path $Folder -ChildPath $FileName

        If ((([System.IO.FileInfo]$LogFilePath).Exists) -And ($MaxLogFileSize -ne 0)) {

            # Get log size in bytes
            $LogFileSize = [System.IO.FileInfo]$LogFilePath | Select-Object -ExpandProperty Length

            If ($LogFileSize -ge $MaxLogFileSize) {

                # Get log file name without extension
                $LogFileNameWithoutExt = $FileName -replace ([System.IO.Path]::GetExtension($FileName))

                # Get already rolled over logs
                $AllLogs = Get-ChildItem -Path $Folder -Name "$($LogFileNameWithoutExt)_*" -File

                # Sort them numerically (so the oldest is first in the list)
                $AllLogs = $AllLogs | Sort-Object -Descending { $_ -replace '_\d+\.lo_$' }, { [Int]($_ -replace '^.+\d_|\.lo_$') } -ErrorAction Ignore
            
                ForEach ($Log in $AllLogs) {
                    # Get log number
                    $LogFileNumber = [int32][Regex]::Matches($Log, "_([0-9]+)\.lo_$").Groups[1].Value
                    switch (($LogFileNumber -eq $MaxNumOfRotatedLogs) -And ($MaxNumOfRotatedLogs -ne 0)) {
                        $true {
                            # Delete log if it breaches $MaxNumOfRotatedLogs parameter value
                            [System.IO.File]::Delete("$($Folder)\$($Log)")
                        }
                        $false {
                            # Rename log to +1
                            $NewFileName = $Log -replace "_([0-9]+)\.lo_$","_$($LogFileNumber+1).lo_"
                            [System.IO.File]::Copy("$($Folder)\$($Log)", "$($Folder)\$($NewFileName)", $true)
                        }
                    }
                }

                # Copy main log to _1.lo_
                [System.IO.File]::Copy($LogFilePath, "$($Folder)\$($LogFileNameWithoutExt)_1.lo_", $true)

                # Blank the main log
                $StreamWriter = [System.IO.StreamWriter]::new($LogFilePath, $false)
                $StreamWriter.Close()
            }
        }

        # Construct time stamp for log entry
        switch -regex ($Bias) {
            '-' {
                $Time = [string]::Concat($(Get-Date -Format 'HH:mm:ss.fff'), $Bias)
            }
            Default {
                $Time = [string]::Concat($(Get-Date -Format 'HH:mm:ss.fff'), '+', $Bias)
            }
        }
        # Construct date for log entry
        $Date = (Get-Date -Format 'MM-dd-yyyy')
    
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    
        # Construct final log entry
        $LogText = [string]::Format('<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="">', $Value, $Time, $Date, $Component, $Context, $Severity, $PID)
    
        # Add value to log file
        try {
            $StreamWriter = [System.IO.StreamWriter]::new($LogFilePath, 'Append')
            $StreamWriter.WriteLine($LogText)
            $StreamWriter.Close()
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $FileName file. Error message: $($_.Exception.Message)"
        }
    }
}

If($UpdatesEnabled -eq "No"){
    [string]$autoUpdateValueToBeSet = "NO"
}else{
    [string]$autoUpdateValueToBeSet = "YES"
}

Write-CMLogEntry -Value "Starting Script... AutoUpdateValue should be set to $autoUpdateValueToBeSet"
Write-CMLogEntry -Value "Given that the Settings.xml file resides in the user %appdata% folder, getting user profiles"
[array]$allUserProfiles = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | % {Get-ItemProperty $_.pspath}).profileImagePath
Foreach ($userprofile in $allUserProfiles){
    #Write-host "I am $userprofile" -BackgroundColor Yellow
    Write-CMLogEntry -Value "Found $userprofile..."
    If($userprofile -like "C:\Users\*"){
        Write-CMLogEntry "Checking Settings.xml to see if the AutoUpdate key exists..."
        $viscositySettingsXML = "$userprofile\AppData\Roaming\Viscosity\settings.xml"
        If(Test-Path "$userprofile\AppData\Roaming\Viscosity\settings.xml"){
            [array]$settings = Get-Content $viscositySettingsXML
            [string]$exists = $settings -match '<key>AutoUpdate<\/key>'
            If($exists){
                Write-CMLogEntry -Value "Found AutoUpdate"
                Write-CMLogEntry -Value "Getting Value of AutoUpdate String from Viscosity settings.xml"
                $IndexOfAutoUpdate = $settings.IndexOf($exists)
                $autoUpdateValue = $settings[$IndexOfAutoUpdate+1]
                Write-CMLogEntry -Value "It's value is $autoUpdateValue"
                If($autoUpdateValue -match $autoUpdateValueToBeSet){
                    Write-CMLogEntry -Value "The value in the settings.xml is already set to $autoUpdateValueToBeSet for this user profile."
                }else{
                    Write-CMLogEntry -Value "The value in the settings.xml is not set to $autoUpdateValueToBeSet. setting it" -Severity 3  
                    $Settings[$IndexOfAutoUpdate+1] = '<string>{0}</string>' -f $autoUpdateValueToBeSet
                    $Settings | Set-Content $viscositySettingsXML
                    Write-CMLogEntry -Value "Value set!"
                }
            }else{
                Write-CMLogEntry -Value "Didn't find AutoUpdate key in the XML file. Adding it." 
                [Reflection.Assembly]::LoadWithPartialName("System.Xml.Linq") | Out-Null
                [System.Xml.Linq.XDocument]$existingXML = [System.Xml.Linq.XDocument]::Load($viscositySettingsXML)
                [System.Xml.Linq.XElement]$mySelectedNode = $existingXML.Descendants().Where({$_.Name.LocalName -eq "dict"},1)[0]
                [System.Xml.Linq.XName]$element1 = "key"
                [System.Xml.Linq.XName]$element2 = "string"
                [System.Xml.Linq.XElement]$newObjectElement1 = New-Object -TypeName System.Xml.Linq.XElement $element1, "AutoUpdate"
                [System.Xml.Linq.XElement]$newObjectElement2 = New-Object -TypeName System.Xml.Linq.XElement $element2, $autoUpdateValueToBeSet
                $mySelectedNode.Add($newObjectElement1)
                $mySelectedNode.Add($newObjectElement2)
                $existingXML.Save($viscositySettingsXML)
                Write-CMLogEntry -Value "Entries added!"
            }
        }else{
            Write-CMLogEntry -Value "$viscositySettingsXML doesn't exist for this profile" -Severity 3
        }
    }else{
        Write-CMLogEntry -Value "No reason to update the Settings.xml for this user profile" -Severity 2
    }
}
Write-CMLogEntry -Value "Checks complete! Exiting..."