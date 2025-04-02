# Script to install Cisco AnyConnect modules as a post-install script after the Security Mobility Client module installs
# It also copies the configuration.xml and preferences.xml files to the newConfigFiles folder if found
#
# Patch My PC
# Version 1.4
#  - Pre-create missing destination folders before copying config files
#
# Version 1.3
#  - Add support for Cisco AnyConnect Secure Mobility Client 5.0 and later
# 
# Version 1.
#  - Search and copy preferences.xml if found
# 
# Version 1.1
#  - Ensure Dart installs first if found
#  - Add additional exit code
#  - Search and copy Configuration.xml if found
#
# Version 1.0
#  - Initial Release

[cmdletbinding()]
param()

#region Define functions
Function Start-TSxLog
#Set global variable for the write-TSxInstallLog function in this session or script.
{
    [CmdletBinding()]
    param (
    #[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
    [string]$FilePath
   )
    try
        {
            if(!(Split-Path $FilePath -Parent | Test-Path))
            {
                New-Item (Split-Path $FilePath -Parent) -Type Directory | Out-Null
            }
            #Confirm the provided destination for logging exists if it doesn't then create it.
            if (!(Test-Path $FilePath))
                {
                    ## Create the log file destination if it doesn't exist.
                    New-Item $FilePath -Type File | Out-Null
                }
                ## Set the global variable to be used as the FilePath for all subsequent write-TSxInstallLog
                ## calls in this session
                $global:ScriptLogFilePath = $FilePath
        }
    catch
    {
        #In event of an error write an exception
        Write-Error $_.Exception.Message
    }
}

Function Write-TSxLog
#Write the log file if the global variable is set
{
    param (
    [Parameter(Mandatory = $true)]
    [string]$Message,
    [Parameter()]
    [ValidateSet(1, 2, 3)]
    [string]$LogLevel=1,
    [Parameter(Mandatory = $false)]
    [bool]$writetoscreen = $true   
   )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    Add-Content -Value $Line -Path $ScriptLogFilePath
    if($writetoscreen){
        switch ($LogLevel)
        {
            '1'{
                Write-Verbose -Message $Message
                }
            '2'{
                Write-Warning -Message $Message
                }
            '3'{
                Write-Error -Message $Message
                }
            Default {
            }
        }
    }
    if($writetolistbox -eq $true){
        $result1.Items.Add("$Message")
    }
}

function set-TSxDefaultLogPath {
    #Function to set the default log path if something is put in the field then it is sent somewhere else. 
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $false)]
        [bool]$defaultLogLocation = $true,
        [parameter(Mandatory = $false)]
        [string]$LogLocation
    )
    if($defaultLogLocation){
        $LogPath = Split-Path $script:MyInvocation.MyCommand.Path
        $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"     
        Start-TSxLog -FilePath $($LogPath + "\" + $LogFile)
    }
    else {
        $LogPath = $LogLocation
        $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"     
        Start-TSxLog -FilePath $($LogPath + "\" + $LogFile)
    }
}
#endregion

set-TSxDefaultLogPath -defaultLogLocation:$false -LogLocation $ENV:TEMP
Write-TSxLog -Message "Starting Cisco AnyConnect modules post-install script"

$SuccessReturnCodes = 0, 1610, 3010, 1614

try {
    $Files = Get-ChildItem -Filter "*.msi" -ErrorAction "Stop"
}
catch {
    Write-TSxLog -Message "Failed to get all .msi files in current working directory"
    Write-TSxLog -Message $_.Exception.Message
    throw
}

if ($Files.Count -eq 0) {
    Write-TSxLog -Message "No .msi files found in current working directory '$($pwd.Path)', quitting"
    return
}
else {
    Write-TSxLog -Message "Found $($Files.Count) .msi files in current working directory: $([String]::Join(', ', $Files.Name))"
}

# DART > Secure Mobility Client > the remaining modules
$Files = $Files | Sort-Object { $_.Name -notmatch 'dart-predeploy' }

$AllReturnCodes = foreach ($File in $Files) {
    if ($File.Name -notmatch "core-vpn-predeploy") { 
        Write-TSxLog -Message "Installing '$($File.Name)'"
        try {
            $rc = Start-Process -FilePath $File.FullName -ArgumentList "REBOOT=ReallySuppress","/qn" -Wait -PassThru -ErrorAction "Stop"
            $rc.ExitCode
            if ($SuccessReturnCodes -contains $rc.ExitCode) {
                Write-TSxLog -Message "Success, exit code was '$($rc.ExitCode)'"
            }
            else {
                Write-TSxLog -Message "Failed, exit code was '$($rc.ExitCode)'"
            }
        }
        catch {
            Write-TSxLog -Message "Failed, exit code was '$($rc.ExitCode)' and exception message is '$($_.Exception.Message)'"
        }
    }
    else {
        $Version = [Regex]::Match($File.Name, '\d+(?:.\d+){2}').Groups[0].Value -as [System.Version]
        Write-TSxLog -Message "Skipping '$($File.Name)'"
    }
}

# Filter out success error codes and exit with the first matched failed error code
$Regex = '^({0})$' -f [String]::Join('|', $SuccessReturnCodes)
$FailedReturnCodes = @($AllReturnCodes) -notmatch $Regex | Select-Object -Unique

# Filter out non-zero exit codes and exit with the first match if there were no failed return codes
$NonZeroReturnCodes = @($AllReturnCodes -notmatch '^0$') | Select-Object -Unique

if ($FailedReturnCodes.Count -gt 0) {
    $ExitCode = $FailedReturnCodes[0]
}
elseif ($NonZeroReturnCodes.Count -gt 0) {
    $ExitCode = $NonZeroReturnCodes[0]
}
else {
    $ExitCode = 0
}

if ($Version -ge [Version]'5.0') {
    $newConfigFiles = '{0}\Cisco\Cisco Secure Client\Network Access Manager\newConfigFiles' -f $env:ProgramData
    $UmbrellaOrgInfo = '{0}\Cisco\Cisco Secure Client\Umbrella' -f $env:ProgramData
    $VPNProfile = '{0}\Cisco\Cisco Secure Client\VPN\Profile' -f $env:ProgramData
}
else {
    $newConfigFiles = '{0}\Cisco\Cisco AnyConnect Secure Mobility Client\Network Access Manager\newConfigFiles' -f $env:ProgramData
}

if ((Test-Path "configuration.xml" -ErrorAction SilentlyContinue) -and ($FailedReturnCodes.Count -eq 0)) {
    Write-TSxLog "Installation was successful and configuration.xml file was found, copying file to $($newConfigFiles)"
    try {
        if (!(Test-Path $newConfigFiles -ErrorAction SilentlyContinue)) { New-Item $newConfigFiles -ItemType Directory -Force }
        Copy-Item "configuration.xml" $newConfigFiles -Force -ErrorAction 'Stop'
        Write-TSxLog "Successfully copied configuration.xml"
    } 
    catch {
        Write-TSxLog "Failed to copy configuration.xml"
        Write-TSxLog -Message $_.Exception.Message
    }
} else {
    Write-TSxLog "Skipping configuration.xml because it was not found or the installation was not successful"
}

if ((Test-Path "preferences.xml" -ErrorAction SilentlyContinue) -and ($FailedReturnCodes.Count -eq 0)) {
    Write-TSxLog "Installation was successful and preferences.xml file was found, copying file to $($newConfigFiles)"
    try {
        if (!(Test-Path $newConfigFiles -ErrorAction SilentlyContinue)) { New-Item $newConfigFiles -ItemType Directory -Force }
        Copy-Item "preferences.xml" $newConfigFiles -Force -ErrorAction 'Stop'
        Write-TSxLog "Successfully copied preferences.xml"
    }
    catch {
        Write-TSxLog "Failed to copy preferences.xml"
        Write-TSxLog -Message $_.Exception.Message
    }
} else {
    Write-TSxLog "Skipping preferences.xml because it was not found or the installation was not successful"
}

if ((Test-Path "OrgInfo.json" -ErrorAction SilentlyContinue) -and ($FailedReturnCodes.Count -eq 0)) {
    Write-TSxLog "Installation was successful and OrgInfo.json file was found, copying file to $($UmbrellaOrgInfo)"
    try {
        if (!(Test-Path $UmbrellaOrgInfo -ErrorAction SilentlyContinue)) { New-Item $UmbrellaOrgInfo -ItemType Directory -Force }
        Copy-Item "OrgInfo.json" $UmbrellaOrgInfo -Force -ErrorAction 'Stop'
        Write-TSxLog "Successfully copied OrgInfo.json"
    }
    catch {
        Write-TSxLog "Failed to copy OrgInfo.json"
        Write-TSxLog -Message $_.Exception.Message
    }
} else {
    Write-TSxLog "Skipping OrgInfo.json because it was not found or the installation was not successful"
}

if ((Test-Path "VPNDisable_ServiceProfile.xml" -ErrorAction SilentlyContinue) -and ($FailedReturnCodes.Count -eq 0)) {
    Write-TSxLog "Installation was successful and VPNDisable_ServiceProfile.xml file was found, copying file to $($newConfigFiles)"
    try {
        if (!(Test-Path $VPNProfile -ErrorAction SilentlyContinue)) { New-Item $VPNProfile -ItemType Directory -Force }
        Copy-Item "VPNDisable_ServiceProfile.xml" $VPNProfile -Force -ErrorAction 'Stop'
        Write-TSxLog "Successfully copied VPNDisable_ServiceProfile.xml"
    }
    catch {
        Write-TSxLog "Failed to copy VPNDisable_ServiceProfile.xml"
        Write-TSxLog -Message $_.Exception.Message
    }
} else {
    Write-TSxLog "Skipping VPNDisable_ServiceProfile.xml because it was not found or the installation was not successful"
}

Write-TSxLog -Message "Finished Cisco AnyConnect modules post-install script with exit code $($ExitCode)"

return $ExitCode
