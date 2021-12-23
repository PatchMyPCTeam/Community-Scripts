<#
.SYNOPSIS
    Deploy additional language packs to Firefox install directory
.DESCRIPTION
    This post install script will create the necessary directory for Firefox language packs, copy the packs to that folder and rename them to the correct format  
#>

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
        [string]$Component,
        [parameter(Mandatory = $true, HelpMessage = 'Name of the log file that the entry will written to.')]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [parameter(Mandatory = $true, HelpMessage = 'Path to the folder where the log will be stored.')]
        [ValidateNotNullOrEmpty()]
        [string]$Folder,
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
        [switch]$Enable
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
$LogName = "FirefoxLanguagePacks_" + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + ".log"

<#
    Check OS architecture and adjust paths accordingly
#>
Write-CMLogEntry -Value "Starting deployment of Firefox language packs" -Severity 1 -Component "Script Starting" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
Write-CMLogEntry -Value "Determining OS Architecture" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
if ([System.Environment]::Is32BitOperatingSystem -eq "True"){
    Write-CMLogEntry -Value "OS Architecture is 32bit" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
    $architecture = $Env:Programfiles
}elseif ([System.Environment]::Is64BitOperatingSystem -eq "True"){
    Write-CMLogEntry -Value "OS Architecture is 64bit, Checking for install directory" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
    $installdirectory64 = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -like "*firefox*" }) -ne $null

    if(-not $installdirectory64){
        Write-CMLogEntry -Value "64bit install directory not found, checking 32bit install directory" -Severity 2 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
        $installdirectory32 = (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -like "*firefox*" }) -ne $null
    
        If(-Not $installdirectory32){
            Write-CMLogEntry -Value "Firefox install path cannot be found. Likely not installed" -Severity 3 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
        }else{
            Write-CMLogEntry -Value "Firefox install path is 32bit" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
            $architecture = ${Env:ProgramFiles(x86)}
        }
    } else {
        Write-CMLogEntry -Value "Firefox install path is 64bit" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
        $architecture = $Env:Programfiles
    }
}
    
<#
    Check if distribution and distribution/extensions exist under Firefox install directory
    If not, Create folders
#>
Write-CMLogEntry -Value "Checking if Firefox policy folder exists" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
$folder = $architecture + '\Mozilla Firefox\distribution\extensions\'
if (-not(Test-Path -Path $folder -PathType Container)) {
    try {
        Write-CMLogEntry -Value "Folder does not exist, Creating $folder" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
        $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    }
    catch {
        Write-CMLogEntry -Value "Folder creation failed" -Severity 3 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
        throw $_
    }
}

<#
    Copy language packs to extensions folder
    Rename language packs to meet required naming convention
#>
Write-CMLogEntry -Value "Copying language packs to $folder" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
Get-ChildItem -Filter '.\*.xpi' | Copy-Item -Destination $folder
Write-CMLogEntry -Value "Renaming language packs to correct naming convention" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
Get-ChildItem -Path $folder | Rename-Item -NewName {"langpack-" + (($_.name).TrimEnd(".xpi")) + "@firefox.mozilla.org.xpi"}


<#
    Get system locale
    Check to see if policies.json exists
        If it doesn't, Create it and populate it with the relavant policy information
        If it does exist, Amend it to include the relevant policy information
#>
Write-CMLogEntry -Value "Getting system locale" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
$systemlocale = (Get-WinSystemLocale).name
Write-CMLogEntry -Value "System locale is $systemlocale" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
Write-CMLogEntry -Value "Creating JSON to be written to policies.json" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
$json = @"
{
  "policies": {
   "RequestedLocales": "$systemlocale"
  }
}
"@
$policiesfile = $architecture + '\Mozilla Firefox\distribution\policies.json'
Write-CMLogEntry -Value "Checking if $policiesfile exists" -Severity 3 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
if (-not(Test-Path -Path $policiesfile -PathType Leaf)) {
    Write-CMLogEntry -Value "Policy file does not exist, Creating $policiesfile" -Severity 2 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
    New-Item -ItemType File -Path $policiesfile -Force
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($policiesfile, $json, $Utf8NoBomEncoding)
} else {
    Write-CMLogEntry -Value "Policy file exists, Updating $policiesfile with locale policy" -Severity 1 -Component "OS Architecture" -FileName $LogName -Folder "C:\Windows\Temp" -Bias $Bias -Enable
    $policyjson = Get-Content $policiesfile | ConvertFrom-Json -Depth 10
    $policyjson.policies | Add-Member -NotePropertyName RequestedLocales -NotePropertyValue "$systemlocale" -Force
    $policyjson = $policyjson | ConvertTo-Json -Depth 10
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($policiesfile, $policyjson, $Utf8NoBomEncoding)
}