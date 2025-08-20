# New-Shortcut.ps1

## Description
`New-Shortcut.ps1` is a PowerShell script designed to facilitate the creation of shortcuts on a user's system. It offers a range of customization options, including the shortcut's name, target, working directory, icon path, icon index, and window style. The script supports creating shortcuts in the Start Menu or on the Desktop for either the current user or all users.

## Parameters

- **Path**: Specifies the path where the shortcut should be created. Mandatory for custom locations. For Desktop or StartMenu shortcuts, this parameter defines the subfolder name.
- **Name**: The name of the shortcut. This is a mandatory parameter.
- **Target**: The target path of the shortcut. This is a mandatory parameter.
- **Arguments**: The arguments to pass to the target application.
- **WorkingDirectory**: The working directory for the shortcut.
- **IconPath**: The path to the icon file for the shortcut.
- **IconIndex**: The index of the icon within the icon file. Will default to 0.
- **WindowStyle**: The window style for the shortcut. Possible values are 'Normal', 'Maximized', 'Minimized', and 'Hidden'.
- **StartMenu**: Indicates that the shortcut should be created in the Start Menu.
- **Desktop**: Indicates that the shortcut should be created on the Desktop. This is mutually exclusive with -StartMenu.
- **User**: Specifies that the shortcut should be created under the user's StartMenu or Desktop rather than for all users.
- **ExpandEnvironmentVariables**: Expand environment variables in the shortcut Target, Arguments, WorkingDirectory, and IconPath.
- **As32on64**: Expand %ProgramFiles% and %CommonProgramFiles% as if they were 32-bit on 64-bit systems. Use this in conjunction with -ExpandEnvironmentVariables when %ProgramFiles% should be interpreted as C:\Program Files (x86) on a 64-bit OS.
- **Shortcuts**: An array of hashtable entries for creating multiple shortcuts. Each hashtable should include the parameters as keys.

## Examples

### Example 1: Creating a Single Shortcut on the Desktop
```powershell
.\New-Shortcut.ps1 -Name "Example" -Target "C:\Path\To\Target.exe" -Desktop
```

### Example 2: Creating Multiple Shortcuts
```powershell
.\New-Shortcut.ps1 -Shortcuts @(@{Name="Example1"; Target="C:\Path\To\Target.exe"; Desktop=$true;}, @{Name="Example2"; Target="C:\Path\To\Target.exe"; StartMenu=$true; Path="SubFolder"})
```

### Example 3: Creating a Shortcut in Program Files
```powershell
.\New-Shortcut.ps1 -Path 'MyApp' -Name 'MyApp' -Target "%ProgramFiles%\MyApp\MyApp.exe" -Arguments '/Something' -IconPath "%ProgramFiles%\MyApp\MyApp.exe" -StartMenu -ExpandEnvironmentVariables
```

### Example 4: Creating a Shortcut in Program Files on a 32-bit OS and Program Files (x86) on a 64-bit OS
```powershell
.\New-Shortcut.ps1 -Path 'MyApp' -Name 'MyApp' -Target "%ProgramFiles%\MyApp\MyApp.exe" -Arguments '/Something' -IconPath "%ProgramFiles%\MyApp\MyApp.exe" -StartMenu -ExpandEnvironmentVariables -As32on64
```