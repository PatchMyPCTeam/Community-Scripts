# New-Shortcut.ps1

## Description
`New-Shortcut.ps1` is a PowerShell script designed to facilitate the creation of shortcuts on a user's system. It offers a range of customization options, including the shortcut's name, target, working directory, icon path, icon index, and window style. The script supports creating shortcuts in the Start Menu or on the Desktop for either the current user or all users.

## Parameters

- **Path**: Specifies the path where the shortcut should be created. Mandatory for custom locations. For Desktop or StartMenu shortcuts, this parameter defines the subfolder name.
- **Name**: The name of the shortcut. This is a mandatory parameter.
- **Target**: The target path of the shortcut. This is a mandatory parameter.
- **WorkingDirectory**: The working directory for the shortcut.
- **IconPath**: The path to the icon file for the shortcut.
- **IconIndex**: The index of the icon within the icon file. Will default to 0.
- **WindowStyle**: The window style for the shortcut. Possible values are 'Normal', 'Maximized', 'Minimized', and 'Hidden'.
- **StartMenu**: Indicates that the shortcut should be created in the Start Menu.
- **Desktop**: Indicates that the shortcut should be created on the Desktop. This is mutually exclusive with -StartMenu.
- **User**: Specifies that the shortcut should be created under the user's StartMenu or Desktop rather than for all users.
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