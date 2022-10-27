# Set-ViscosityAutomaticUpdates.ps1

## SYNOPSIS
Disable or Enable automatic updates for Viscosity

## SYNTAX

```
Set-ViscosityAutomaticUpdates.ps1 [-UpdatesEnabled] <String>
```

## DESCRIPTION
This script can be used to enable or disable the Automatic updates for the app Viscosity from SparkLabs.
The installer of this app does not support this option, unfortunately.

The setting enabling/disabling the automatic updates is stored in the Settings.xml located in %AppData%\Viscosity.

The Setting.xml is created automatically when the application is launched for the first time. The app is launched automatically even during a /VERYSILENT install.
2 keys will have to exist under /plist/dict in order to enable/disable the automatic updates:
<key>AutoUpdate</key>
<string>NO</string>--> to disable automatic updates OR <string>YES</string> --> to enable automatic updates.   

This script will add the entries if they don't exist already. If they do, it will update the the corresponding string to enable/disable the update.
Given that the XML file resides in the user %appdata% folder, it will make the change for each user profile where the profile path will be like "C:\Users" if the settings.xml file exists.

A log file will be exported in %windir\temp.

## EXAMPLES

### EXAMPLE 1
```
Set-ViscosityAutomaticUpdates.ps1 -UpdatesEnabled "No"
```

Goes through each User Profile, and if the path is like C:\Users it will check if the Settings.xml exists in %AppData%\Viscosity. If it does, it will
    - check to see if the AutoUpdate Key and corresponding string exists. If it exists, it will check the value
        --> If the value is YES, it will change it to NO
        --> if it's already set to NO, it will leave it as it is.
    - If the AutoUpdate Key doesn't exist, it will create it, and set its corresponding string to NO.

## PARAMETERS

### -UpdatesEnabled
"Yes" if you want AutoUpdates enabled.
"No" if you want AutoUpdates disabled.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
