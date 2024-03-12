# Get-FortiClientVPNOnlineInstaller.ps1

## SYNOPSIS
Download and copy the MSI from the FortiClientVPN Online Installer

## SYNTAX

```
Get-FortiClientVPNOnlineInstaller [-LocalContentRepo] <String>
```

## DESCRIPTION
This function is used to download the FortiClientVPN Online Installer, Run it and then copy out the MSI required by the Patch My PC Publisher

## EXAMPLES

### EXAMPLE 1
```
Get-FortiClientVPNOnlineInstaller -LocalContentRepo "C:\LocalContentRepository" -DownloadDir "$HOME\Downloads\FortiClientVPNOnlineInstaller"
```
Downloads the Online installer to your Downloads folder and exports the MSI to your Local Content Repo


## PARAMETERS

### -LocalContentRepo
The path to your Local Content Repository

```yaml
Type: String
Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False 
```
