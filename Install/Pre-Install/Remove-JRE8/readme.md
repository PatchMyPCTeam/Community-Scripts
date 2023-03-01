# Script to Remove Java Runtime Environment 8 prior to installing the latest update

# Description
This PowerShell script's intention is to remove all versions of Java Runtime Environment 8 prior to installing the latest update.

# EXAMPLE
.\PatchMyPC-Remove-JRE8.ps1
This will remove ALL versions of JRE8 x86 and x64 present on the device

.\PatchMyPC-Remove-JRE8.ps1 -VersionToExclude "361"
This will remove all versions of JRE8 except 8u361 x86 and x64

.\PatchMyPC-Remove-JRE8.ps1 -VersionToExclude "361 (64-bit)"
This will remove all versions of JRE8 except 8u361 x64