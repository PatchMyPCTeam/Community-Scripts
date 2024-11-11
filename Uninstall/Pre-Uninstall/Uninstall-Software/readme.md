# Uninstall-Software.ps1

## SYNOPSIS
Uninstall software based on the DisplayName of said software in the registry

## SYNTAX

### AdditionalArguments (Default)
```
Uninstall-Software.ps1 -DisplayName <String> [-Architecture <String>] [-HivesToSearch <String[]>]
 [-WindowsInstaller <Int32>] [-SystemComponent <Int32>] [-VersionLessThan <Version>]
 [-VersionEqualTo <Version>] [-VersionGreaterThan <Version>] [-AdditionalArguments <String>] [-UninstallAll]
 [-ProcessName <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### EnforcedArguments
```
Uninstall-Software.ps1 -DisplayName <String> [-Architecture <String>] [-HivesToSearch <String[]>]
 [-WindowsInstaller <Int32>] [-SystemComponent <Int32>] [-VersionLessThan <Version>]
 [-VersionEqualTo <Version>] [-VersionGreaterThan <Version>] [-EnforcedArguments <String>] [-UninstallAll]
 [-ProcessName <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### AdditionalEXEorMSIArguments
```
Uninstall-Software.ps1 -DisplayName <String> [-Architecture <String>] [-HivesToSearch <String[]>]
 [-WindowsInstaller <Int32>] [-SystemComponent <Int32>] [-VersionLessThan <Version>]
 [-VersionEqualTo <Version>] [-VersionGreaterThan <Version>] [-AdditionalMSIArguments <String>]
 [-AdditionalEXEArguments <String>] [-UninstallAll] [-ProcessName <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
This script is useful if you need to uninstall software before installing or updating other software. 

Typically best used as a pre-script in most situations.

One example use case of this script with Patch My PC's Publisher is if you have previously re-packaged software installed
on your devices and you need to uninstall the repackaged software, and install using the vendor's native install media 
(provided by the Patch My PC catalogue).

The script searches the registry for installed software, matching the supplied DisplayName value in the -DisplayName parameter
with that of the DisplayName in the registry.
If one match is found, it uninstalls the software using the QuietUninstallString or UninstallString.

You can supply additional arguments to the uninstaller using the -AdditionalArguments, -AdditionalMSIArguments, or -AdditionalEXEArguments parameters.

You cannot use -AdditionalArguments with -AdditionalMSIArguments or -AdditionalEXEArguments.

If a product code is not in the UninstallString, QuietUninstallString or UninstallString are used.
QuietUninstallString is preferred if it exists.

If more than one matches of the DisplayName occurs, uninstall is not possible unless you use the -UninstallAll switch.

If QuietUninstallString and UninstallString is not present or null, uninstall is not possible.

A log file is created in the temp directory with the name "Uninstall-Software-\<DisplayName\>.log" which contains the verbose output of the script.

An .msi log file is created in the temp directory with the name "\<DisplayName\>_\<DisplayVersion\>.msi.log" which contains the verbose output of the msiexec.exe process.

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

### EXAMPLE 3
```
Uninstall-Software.ps1 -DisplayName "*SomeSoftware*" -AdditionalMSIArguments "/quiet /norestart" -AdditionalEXEArguments "/S" -UninstallAll
```

Uninstalls all software where DisplayName contains "SomeSoftware". 

For any software found in the registry matching the search criteria and are MSI-based (WindowsInstaller = 1), "/quiet /norestart" will be supplied to the uninstaller.

For any software found in the registry matching the search criteria and  are EXE-based (WindowsInstaller = 0 or non-existent), "/S" will be supplied to the uninstaller.

### EXAMPLE 4
```
Uninstall-Software.ps1 -DisplayName "KiCad*" -ProcessName "Un_A"
```

Uninstalls KiCad and waits for the process "Un_A" to finish after the uninstallation has started.

### EXAMPLE 5
```
Uninstall-Software.ps1 -DisplayName "SomeSoftware" -VersionGreaterThan 1.0.0
```

Uninstalls SomeSoftware if the version is greater than 1.0.0

### EXAMPLE 6
```
Uninstall-Software.ps1 -DisplayName "AnyDesk" -EnforcedArguments "--remove --silent"
```

Uninstalls AnyDesk with the enforced arguments "--remove --silent", instead of using the default parameters in the UninstallString.

### EXAMPLE 7
```
Uninstall-Software.ps1 -DisplayName "VLC Media Player*" -WindowsInstaller "Both" -AdditionalEXEArguments "/S" -UninstallAll
```

Uninstalls all instances of VLC Media Player, whether it was installed from an MSI or an EXE, and supplies "/S" to the uninstaller if it was installed with an EXE.

## PARAMETERS

### -DisplayName
The name of the software you wish to uninstall as it appears in the registry as its DisplayName value.
* wildcard supported.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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
Position: Named
Default value: Both
Accept pipeline input: False
Accept wildcard characters: False
```

### -HivesToSearch
Choose which registry hive to search in while looking for installed software.
Acceptable values are:

- "HKLM" will search in hive HKEY_LOCAL_MACHINE which is typically where system-wide installed software is registered.
- "HKCU" will search in hive HKEY_CURRENT_USER which is typically where user-based installed software is registered.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: HKLM
Accept pipeline input: False
Accept wildcard characters: False
```

### -WindowsInstaller
Acceptable string values are: "0", "1" and "Both" - these are used as an additional criteria when trying to find installed software.

If the WindowsInstaller registry value has a data of 1, it generally means software was installed from MSI. 

If the registry value is 0 (not common), or not present at all (more common), it generally means software was installed from an EXE.

Specifying a value of 0 will look for software where WindowsInstaller is equal to 0, or not present at all. 

Alternatively, if you specify "Both", the script will look for software where WindowsInstaller is either not present, 0, or 1.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
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
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -VersionLessThan
Specify a version number to use as an additional criteria when trying to find installed software.

This parameter can be used in conjuction with -VersionEqualTo and -VersionGreaterThan.

```yaml
Type: Version
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VersionEqualTo
Specify a version number to use as an additional criteria when trying to find installed software.

This parameter can be used in conjuction with -VersionLessThan and -VersionGreaterThan.

```yaml
Type: Version
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VersionGreaterThan
Specify a version number to use as an additional criteria when trying to find installed software.

This parameter can be used in conjuction with -VersionLessThan and -VersionEqualTo.

```yaml
Type: Version
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnforcedArguments
A string which includes the arguments you would like passed to the uninstaller.

Cannot be used with -AdditionalArguments, -AdditionalMSIArguments, or -AdditionalEXEArguments.

This will not be used for .msi based software uninstalls.

```yaml
Type: String
Parameter Sets: EnforcedArguments
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdditionalArguments
A string which includes the additional parameters you would like passed to the uninstaller.

Cannot be used with -AdditionalMSIArguments or -AdditionalEXEArguments.

```yaml
Type: String
Parameter Sets: AdditionalArguments
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdditionalMSIArguments
A string which includes the additional parameters you would like passed to the MSI uninstaller. 

This is useful if you use this, and (or not at all) -AdditionalEXEArguments, in conjuction with -UninstallAll to apply different parameters for MSI based uninstalls.

Cannot be used with -AdditionalArguments.

```yaml
Type: String
Parameter Sets: AdditionalEXEorMSIArguments
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdditionalEXEArguments
A string which includes the additional parameters you would like passed to the EXE uninstaller.

This is useful if you use this, and (or not at all) -AdditionalMSIArguments, in conjuction with -UninstallAll to apply different parameters for EXE based uninstalls.

Cannot be used with -AdditionalArguments.

```yaml
Type: String
Parameter Sets: AdditionalEXEorMSIArguments
Aliases:

Required: False
Position: Named
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

### -ProcessName
Wait for this process to finish after the uninstallation has started.

If the process is already running before the uninstallation has even started, the script will quit with an error.

This is useful for some software which spawn a seperate process to do the uninstallation, and the main process exits before the uninstallation is finished.

The .exe extension is not required, and the process name is case-insensitive.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemovePath
Supply a list of files and folders to be removed after the uninstallations have been processed.

Use with -Force if all items are to be removed even if there is no software found to be uninstalled or if errors are encountered during uninstallation.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
