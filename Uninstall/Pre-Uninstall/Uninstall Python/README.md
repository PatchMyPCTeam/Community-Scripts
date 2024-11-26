# Uninstall-Python.ps1

## Synopsis
Uninstall all, or specific versions of Python.

## Description
This script is useful if you need to uninstall older versions of Python before installing or updating newer versions.

Typically best used as a pre-script in most situations.

A log file is created in the temp directory with the name `Uninstall-Python.log` which contains the verbose output of the script.

An MSI log file is created in the temp directory with the name `<DisplayName>_<DisplayVersion>.msi.log` which contains the verbose output of the `msiexec.exe` process.

## Parameters

### `-Architecture`
Choose which registry key path to search in while looking for installed software. Acceptable values are:
- `x86` will search in `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` on a 64-bit system.
- `x64` will search in `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`.
- `Both` will search in both key paths.

### `-VersionLessThan`
Specify a version number to use as an additional criterion when trying to find installed software. Only the first 2 parts of the version are used for comparison.

### `-VersionLessThanOrEqualTo`
Specify a version number to use as an additional criterion when trying to find installed software. Only the first 2 parts of the version are used for comparison.

### `-VersionEqualTo`
Specify a version number to use as an additional criterion when trying to find installed software. Only the first 2 parts of the version are used for comparison.

### `-VersionNotEqualTo`
Specify a version number to use as an additional criterion when trying to find installed software. Only the first 2 parts of the version are used for comparison.

### `-VersionGreaterThan`
Specify a version number to use as an additional criterion when trying to find installed software. Only the first 2 parts of the version are used for comparison.

### `-VersionGreaterThanOrEqualTo`
Specify a version number to use as an additional criterion when trying to find installed software. Only the first 2 parts of the version are used for comparison.

### `-Force`
This switch will instruct the script to force uninstallation of per-user instances via `MsiZap.exe`.

## Examples

### Example 1
```powershell
Uninstall-Python.ps1 -VersionLessThan '3.13'
```
Uninstalls all versions of Python lower than 3.13.

### Example 2
```powershell
Uninstall-Python.ps1 -Architecture 'x86'
```
Uninstalls all 32-bit versions of Python.

### Example 3
```powershell
Uninstall-Python.ps1 -VersionGreaterThanOrEqualTo '3.0' -VersionLessThanOrEqualTo '3.12' -Force
```
Uninstalls all versions of Python between v3.0.x and 3.12.x, force removing per-user installations via MsiZap.exe.