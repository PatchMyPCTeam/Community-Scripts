# Uninstall-Software.ps1

## SYNOPSIS
Uninstall software based on the DisplayName of said software in the registry

## SYNTAX

```
Uninstall-Software [-DisplayName] <String> [[-Architecture] <String>] [[-HivesToSearch] <String[]>]
 [[-WindowsInstaller] <Int32>] [[-SystemComponent] <Int32>] [[-AdditionalArguments] <String>] [-UninstallAll]
 [<CommonParameters>]
```

## DESCRIPTION
This script is useful if you need to uninstall software before installing or updating other software. 

Typically best used as a pre-script in most situations.

One example use case of this script with Patch My PC's Publisher is if you have previously re-packaged software installed
on your devices and you need to uninstall the repackaged software, and install using the vendor's native install media 
(provided by the Patch My PC catalogue).

The script searches the registry for installed software, matching the supplied DisplayName value in the -DisplayName parameter
with that of the DisplayName in the registry.
If one match is found, it uninstalls the software using the UninstallString. 

If a product code is not in the UninstallString, the whole value in QuietUninstallString is used, or just UninstallString if QuietUninstallString doesn't exist.

If more than one matches of the DisplayName occurs, uninstall is not possible.

If QuietUninstallString and UninstallString is not present or null, uninstall is not possible.

## EXAMPLES

### EXAMPLE 1
```
Uninstall-Software.ps1 -DisplayName "Greenshot"
```

Uninstalls Greenshot if "Greenshot" is detected as the DisplayName in a key under either of the registry key paths:
    - SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
    - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

### EXAMPLE 2
```
Uninstall-Software.ps1 -DisplayName "Mozilla*"
```

Uninstalls any products where DisplayName starts with "Mozilla"

## PARAMETERS

### -DisplayName
The name of the software you wish to uninstall as it appears in the registry as its DisplayName value.
* wildcard supported.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Architecture
Choose which registry key path to search in while looking for installed software.
Acceptable values are:
    - "x86" will search in SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall on a 64-bit system.
    - "x64" will search in SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall.
    - "Both" will search in both key paths.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: Both
Accept pipeline input: False
Accept wildcard characters: False
```

### -HivesToSearch
Choose which registry hive to search in while looking for installed software.
Acceptabel values aref;
    - "HKLM" will search in hive HKEY_LOCAL_MACHINE which is typically where system-wide installed software is registered.
    - "HKCU" will search in hive HKEY_CURRENT_USER which is typically where user-based installed software is registered.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: HKLM
Accept pipeline input: False
Accept wildcard characters: False
```

### -WindowsInstaller
Specify a value between 1 and 0 to use as an additional criteria when trying to find installed software.

If WindowsInstaller registry value has a data of 1, it generally means software was installed from MSI.

Omitting the parameter entirely or specify a value of 0 generally means software was installed from EXE

This is useful to be more specific about software titles you want to uninstall.

Specifying a value of 0 will look for software where WindowsInstaller is equal to 0, or not present at all.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -SystemComponent
Specify a value between 1 and 0 to use as an additional criteria when trying to find installed software.

Specifying a value of 0 will look for software where SystemComponent is equal to 0, or not present at all.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdditionalArguments
A string which includes the additional parameters you would like passed to the uninstaller.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UninstallAll
This switch will uninstall all software matching the search criteria of -DisplayName, -WindowsInstaller, and -SystemComponent.

-DisplayName allows wildcards, and if there are multiple matches based on the wild card, this switch will uninstall matching software.

Without this parameter, the script will do nothing if there are multiple matches found.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
