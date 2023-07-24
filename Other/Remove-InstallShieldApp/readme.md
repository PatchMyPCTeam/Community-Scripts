# PatchMyPC-Remove-InstallShieldApp.ps1

## SYNOPSIS
Uninstall installshield based software
Original Credit to SilentInstallHQ using PSAppDeployToolkit
https://silentinstallhq.com/3dconnexion-3dxware-silent-uninstall-powershell/?utm_content=cmp-true

## DESCRIPTION
Some older apps installed using an InstallSHield installer do not have the correct uninstall information in the ARP registry key to pivot off to do an uninstall of the application.
This script can be used to build a response file to uninstall the app using the setup.exe and setup.ilg files that are created when the app is installed.

## EXAMPLES

### EXAMPLE 1
```
.\PatchMyPC-Remove-InstallShieldApp.ps1 -App '3Dconnexion 3DxWare 10' -Vendor '3Dconnexion' -AppVersions 10.4.10, 10.6.3, 10.6.4 -Lang '0009' -TimeToWait 60
```

### EXAMPLE 2
```
.\PatchMyPC-Remove-InstallShieldApp.ps1 -App \"3Dconnexion 3DxWare 10\" -Vendor \"3Dconnexion\" -AppVersions \"10.4.10, 10.6.3, 10.6.4\"
```
 When used with PMP pre Script feature, comment out the quotes around the parameters
 -----------------------------------------------------------------------------------


## PARAMETERS

### -App
Specify the app remove (this name is used to search the DisplayName property in the ARP registry keys)

```yaml
Type: String
Required: False
Default value: None
Accept pipeline input: False
Accept wildcard characters: False 
```

### -Vendor
Specify the app vendor (this name will be used to build the ISS response file)

```yaml
Type: String
Required: False
Default value: None
Accept pipeline input: False
Accept wildcard characters: False 
```

### -AppVersions
Specify the app versions to look for in the ARP registry keys. This is passed as as string rather than an object so we can use it with the PMP pre/post script feature. The comma-seperated values are converted back into an array in the script

```yaml
Type: String
Required: False
Default value: None
Accept pipeline input: False
Accept wildcard characters: False 
```

### -Lang
Specify the app language (this name will be used to build the ISS response file)

```yaml
Type: String
Required: False
Default value: None
Accept pipeline input: False
Accept wildcard characters: False 
```

### -TimeToWait
Time to wait for installshield to uninstall the app after start-process is called

```yaml
Type: Integer
Required: False
Default value: None
Accept pipeline input: False
Accept wildcard characters: False 
```