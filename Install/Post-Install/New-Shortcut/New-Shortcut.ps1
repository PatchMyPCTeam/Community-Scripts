<#
.SYNOPSIS
    Creates shortcuts on the user's system.

.DESCRIPTION
    This script allows for creating shortcuts with various customization options. It accepts parameters for the shortcut's name, target, working directory, icon path, icon index, and window style. It also supports creating shortcuts in the Start Menu or on the Desktop for either the current user or all users.

.PARAMETER Path
    The path where the shortcut should be created. This parameter is mandatory when creating a shortcut in a custom location. If Desktop or StartMenu switches are used, the path is appended to the base path, e.g. use it to provide the subfolder name in the Start Menu.

.PARAMETER Name
    The name of the shortcut. This parameter is mandatory.

.PARAMETER Target
    The target path of the shortcut. This parameter is mandatory.

.PARAMETER Arguments
    The arguments to pass to the target application.

.PARAMETER WorkingDirectory
    The working directory for the shortcut.

.PARAMETER IconPath
    The path to the icon file for the shortcut.

.PARAMETER IconIndex
    The index of the icon within the icon file. Will default to 0.

.PARAMETER WindowStyle
    The window style for the shortcut. Possible values are 'Normal', 'Maximized', 'Minimized', and 'Hidden'. Will default to 'Normal'.

.PARAMETER StartMenu
    Indicates that the shortcut should be created in the Start Menu. The path provided will be appended to the base Start Menu path.

.PARAMETER Desktop
    Indicates that the shortcut should be created on the Desktop. This is mutually exclusive with -StartMenu.

.PARAMETER User
    Indicates that the shortcut should be created under the user StartMenu or Desktop rather than allusers StartMenu or public Desktop.

.PARAMETER ExpandEnvironmentVariables
    Expand environment variables in the shortcut Target, Arguments, WorkingDirectory, and IconPath.

.PARAMETER As32on64
    Expand %ProgramFiles% and %CommonProgramFiles% as if they were 32-bit on 64-bit systems. Use this in conjunction with -ExpandEnvironmentVariables when %ProgramFiles% should be interpreted as C:\Program Files (x86) on a 64-bit OS.

.PARAMETER Shortcuts
    An array of hashtable entries for creating multiple shortcuts. Each hashtable should include the parameters as keys.

.EXAMPLE
    .\New-Shortcut.ps1 -Name "Example" -Target "C:\Path\To\Target.exe" -Desktop

    This creates a shortcut named "Example" on the current user's desktop targeting "C:\Path\To\Target.exe".

.EXAMPLE
    .\New-Shortcut.ps1 -Shortcuts @(@{Name="Example1"; Target="C:\Path\To\Target.exe"; Desktop=$true;},@{Name="Example2"; Target="C:\Path\To\Target.exe"; StartMenu=$true; Path="SubFolder"})

    This creates two shortcuts, one named "Example1" on the desktop and another named "Example2" in the Start Menu folder named "SubFolder".

.EXAMPLE
    .\New-Shortcut.ps1 -Path 'MyApp' -Name 'MyApp' -Target "%ProgramFiles%\MyApp\MyApp.exe" -Arguments '/Something' -IconPath "%ProgramFiles%\MyApp\MyApp.exe" -StartMenu -ExpandEnvironmentVariables

    This creates a shortcut named "MyApp" in a Start Menu folder named "MyApp", pointing to the target executable in Program Files, with specified arguments and icon.

.EXAMPLE
    .\New-Shortcut.ps1 -Path 'MyApp' -Name 'MyApp' -Target "%ProgramFiles%\MyApp\MyApp.exe" -Arguments '/Something' -IconPath "%ProgramFiles%\MyApp\MyApp.exe" -StartMenu -ExpandEnvironmentVariables -As32on64

    This creates a shortcut named "MyApp" in a Start Menu folder named "MyApp", pointing to the target executable in Program Files on a 32-bit OS / Program Files (x86) on a 64-bit OS.

.INPUTS
    You can pipe an array of hashtable entries to New-Shortcut.ps1.

.OUTPUTS
    None. This script does not produce any output.

.NOTES
    Version:        1.0
    Author:         Dan Gough
    Creation Date:  2023-04-01
    Purpose/Change: Script for creating shortcuts, designed to be used as a post-install script for Patch My PC customers.

#>

[CmdletBinding(DefaultParameterSetName = 'Path')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [string]$Path,

    [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $true, ParameterSetName = 'StartMenu')]
    [string]$Name,

    [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $true, ParameterSetName = 'StartMenu')]
    [string]$Target,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [string]$Arguments,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [string]$WorkingDirectory,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [string]$IconPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [int]$IconIndex = 0,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [ValidateSet('Normal', 'Maximized', 'Minimized', 'Hidden')]
    [string]$WindowStyle = 'Normal',

    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [switch]$StartMenu,

    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [switch]$Desktop,

    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [switch]$User,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [switch]$ExpandEnvironmentVariables,

    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Desktop')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StartMenu')]
    [switch]$As32on64,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'Hashtable')]
    [System.Collections.Hashtable[]]$Shortcuts
)

begin {
    # Load Windows Script Host Object Model for creating shortcuts
    $WshShell = New-Object -ComObject WScript.Shell

    # Determine base paths for Start Menu and Desktop
    $UserStartMenu = [System.Environment]::GetFolderPath('Programs')
    $allUsersStartMenu = [System.Environment]::GetFolderPath('CommonPrograms')
    $UserDesktop = [System.Environment]::GetFolderPath('Desktop')
    $PublicDesktop = [System.Environment]::GetFolderPath('CommonDesktopDirectory')

    # Map friendly names to window style codes
    $WindowStyleMap = @{
        'Normal'    = 1
        'Maximized' = 3
        'Minimized' = 7
        'Hidden'    = 0
    }

    function Expand-EnvironmentVariables {
        param(
            [Parameter(Mandatory)]
            [string]$String,
            [switch]$As32on64
        )

        if ($As32on64 -and [Environment]::Is64BitOperatingSystem) {
            # Minimal remap for the variables that differ
            $String = $String.Replace('%ProgramFiles%', '%ProgramFiles(x86)%').Replace('%CommonProgramFiles%', '%CommonProgramFiles(x86)%')
        }

        [Environment]::ExpandEnvironmentVariables($String)
    }

}

process {
    if (!$Shortcuts) {
        $Shortcuts = @(
            @{
                Name                       = $Name
                Path                       = $Path
                Target                     = $Target
                Arguments                  = $Arguments
                WorkingDirectory           = $WorkingDirectory
                IconPath                   = $IconPath
                IconIndex                  = $IconIndex
                WindowStyle                = $WindowStyle
                Desktop                    = $Desktop
                StartMenu                  = $StartMenu
                User                       = $User
                ExpandEnvironmentVariables = $ExpandEnvironmentVariables
                As32on64                   = $As32on64
            }
        )
    }

    foreach ($Shortcut in $Shortcuts) {

        # Determine the path based on parameters
        if ($Shortcut.Desktop) {
            if ($Shortcut.User) {
                $FolderPath = Join-Path $UserDesktop $Shortcut.Path
            }
            else {
                $FolderPath = Join-Path $PublicDesktop $Shortcut.Path
            }
        }
        elseif ($Shortcut.StartMenu) {
            if ($Shortcut.User) {
                $FolderPath = Join-Path $UserStartMenu $Shortcut.Path
            }
            else {
                $FolderPath = Join-Path $allUsersStartMenu $Shortcut.Path
            }
        }
        else {
            $FolderPath = $Shortcut.Path
        }
        Write-Verbose "Determined folder path: $FolderPath"

        # Create folder path if it does not exist
        if (-not (Test-Path -LiteralPath $FolderPath -PathType Container)) {
            Write-Verbose "Creating folder: $FolderPath"
            New-Item -ItemType Directory -Path $FolderPath -Force -ErrorAction Stop
        }

        # Delete shortcut if it exists
        $ShortcutPath = Join-Path $FolderPath "$($Shortcut.name).lnk"
        if (Test-Path -LiteralPath $ShortcutPath) {
            Write-Verbose "Deleting existing shortcut: $ShortcutPath"
            Remove-Item -Path $ShortcutPath -Force
        }

        # Set default window style if not valid
        if ($Shortcut.WindowStyle -notin $WindowStyleMap.Keys) {
            $Shortcut.WindowStyle = 'Normal'
        }

        $WshShortcut = $WshShell.CreateShortcut($ShortcutPath)
        $WshShortcut.TargetPath = if ($Shortcut.ExpandEnvironmentVariables) {
            Expand-EnvironmentVariables -String $Shortcut.Target -As32on64:$Shortcut.As32on64
        }
        else {
            $Shortcut.Target
        }
        if ($Shortcut.Arguments) {
            $WshShortcut.Arguments = if ($Shortcut.ExpandEnvironmentVariables) {
                Expand-EnvironmentVariables -String $Shortcut.Arguments -As32on64:$Shortcut.As32on64
            }
            else {
                $Shortcut.Arguments
            }
        }
        if ($Shortcut.WorkingDirectory) {
            $WshShortcut.WorkingDirectory = if ($Shortcut.ExpandEnvironmentVariables) {
                Expand-EnvironmentVariables -String $Shortcut.WorkingDirectory -As32on64:$Shortcut.As32on64
            }
            else {
                $Shortcut.WorkingDirectory
            }
        }
        if ($Shortcut.IconPath) {
            $WshShortcut.IconLocation = if ($Shortcut.ExpandEnvironmentVariables) {
                "$(Expand-EnvironmentVariables -String $Shortcut.IconPath -As32on64:$Shortcut.As32on64), $($Shortcut.IconIndex)"
            }
            else {
                "$($Shortcut.IconPath), $($Shortcut.IconIndex)"
            }
        }
        $WshShortcut.WindowStyle = $WindowStyleMap[$Shortcut.WindowStyle]
        Write-Verbose "Creating shortcut: $ShortcutPath"
        $WshShortcut.Save()
    }
}

end {
    # Cleanup COM object
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
    Remove-Variable WshShell
}