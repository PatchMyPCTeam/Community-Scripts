# Get-OobeAndAppInstallationStatus

## Synopsis
This PowerShell script checks if the device is in OOBE (Out Of Box Experience) and searches for installed software by DisplayName. It returns 'Applicable' if the specified software is not found and the device is still in OOBE.

## Description
Use this script as a requirement rule on a Win32 app to ensure the app is only applicable if the software listed in `$appNameList` is not installed and the device is still in OOBE. The script searches through specified registry paths to find installed software that matches a given DisplayName. It also determines whether OOBE (Windows Welcome) has been completed by loading the Kernel32 class from the Api namespace. If no software from `$appNameList` is installed and OOBE is not complete, 'Applicable' is written to the output stream.

## Usage
To use this script, define the application names in `$appNameList` you wish to check for. If any of these apps are installed, the script will not return 'Applicable'.  
  
You can call the function with the preferred `conditionalTest` parameter (`'onlyOOBE'`, `'onlyApps'`, or `'both'`).  

# Define applications to check
The array is defined within the script body because we cannot pass parameters to a requirement rule script.  
```powershell
$appNameList = @('Cisco Secure Client', 'Cisco AnyConnect')
```

```yaml
Type: Array
Parameter Sets: (All)
Required: False
Position: 0
Default value: ('Cisco Secure Client', 'Cisco AnyConnect')
Accept pipeline input: False
Accept wildcard characters: False
```

# Define conditions to test
The script will test for apps and oobe by default but can be customized with the `conditionalTest` parameter which is set to `'both'` by default and hardcoded in the script.  
```yaml
Type: String
Parameter Sets: (All)
Required: False
Position: 0
Default value: both
Accept pipeline input: False
Accept wildcard characters: False
```

# Execute the script
Assign the script as an additional requirement rule to the Win32 app if you only want the WIn32 app to be applicable if the device is in OOBE and the specified software is not installed.  
  
You can uncomment line 150 to test the script to see what applications are installed. Remeber to comment it out again before using the script as a requirement rule.