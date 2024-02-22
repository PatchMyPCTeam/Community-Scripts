# PatchMyPC-CustomAppsHelper.ps1

## SYNOPSIS
Grab Installation Information from the registry to determine properties for Patch My PC Custom Apps

## DESCRIPTION
This script is useful if you need to grab application information when creating EXE-based apps in Patch My PC Custom Apps. 

One To use this script, install the targeted app on an endpoint, run the script, then select the newly installed software from the list and click "OK".
The script will output the following information (note that these are all best-guesses and may need to be adjusted):
- AppName - suggested name for the application
- Architecture - Application Architecture (32 or 64-bit)
- AppsAndFeaturesName - The "Apps & Features" name with wildcards included for proper detection
- Version - Application version number
- InstallContext - Application Install Context (System or User)
- PotentialConflictingProcesses - List of the exe's in the installtion target directory

## EXAMPLES

### EXAMPLE 1
    PS C:\> PatchMyPC-CustomAppsHelper.ps1
    
    Displays a list of installed software and will provide relevant info for Patch My PC Custom Apps

