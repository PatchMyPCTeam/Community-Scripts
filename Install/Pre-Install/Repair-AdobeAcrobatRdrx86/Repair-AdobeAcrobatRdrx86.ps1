<#
.SYNOPSIS
    This script is intended to recache the MSI sources, if deemed missing, for Adobe Acrobat x86 installations. Optionally, if repair is not possible, it can run AdobeAcroCleaner_DC2015.exe to allow for a clean reinstallation.
.DESCRIPTION
    Sometimes, updates for Adobe Acrobat x86 fail due to MSI missing sources. The issue is so widely known, even by Adobe themselves, it's why they made AdobeAcroCleaner_DC2015.exe.

    This script will attempt to repair the MSI sources for Adobe Acrobat x86. If the repair is not possible, it can optionally remove the installation to allow for a clean reinstallation by using the -RemoveIfRepairFails switch.

    AdobeAcroCleaner_DC2015.exe is expected to be in the same directory as this script when using the -RemoveIfRepairFails switch. If not found, the removal step will be skipped.

    The script determines if the MSI source sources are missing by using the following logic:
        1. Check if the LocalPackage registry value exists and points to a valid file.
            HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{CompressedGUID}\InstallProperties\LocalPackage
        2. If not, check each network path listed in the Net registry key for the presence of the MSI PackageName.
            HKLM:\SOFTWARE\Classes\Installer\Products\{CompressedGUID}\SourceList\Net
    If neither are found, the script assumes the MSI sources are missing and attempts a repair.
.PARAMETER RemoveIfRepairFails
    If specified, the script will invoke AdobeAcroCleaner_DC2015.exe to remove the Adobe Acrobat installation if the repair attempt fails.
.EXAMPLE
    .\Repair-AdobeAcrobatRdrx86.ps1 -RemoveIfRepairFails
    Attempts to repair the Adobe Acrobat x86 installation. If the repair fails, it will remove the installation.
#>
[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$RemoveIfRepairFails
)

#region Functions
function Convert-CompressedGuidToProductCode {
    param(
        [Parameter(Mandatory)]
        [string]$CompressedGuid
    )

    function Reverse-String ([array]$a) { 
        # Returns the given array in reverse order as string
        [String]::Join('', $a[-1..-($a.Count)]) 
    }
    function Reverse-Bytes ([String]$a) { 
        # Reverses each pair of hex digits in the given string
        [String]::Join('', ($a -split '(..)' -ne '' -replace '(\w)(\w)','$2$1')) 
    }

    # Undo MSI GUID byte-swapping
    $data1 = Reverse-String $CompressedGuid[0..7]
    $data2 = Reverse-String $CompressedGuid[8..11]
    $data3 = Reverse-String $CompressedGuid[12..15]
    $data4 = Reverse-Bytes ($CompressedGuid[16..19] -join '')
    $data5 = Reverse-Bytes ($CompressedGuid[20..31] -join '')

    return '{0}-{1}-{2}-{3}-{4}' -f $data1, $data2, $data3, $data4, $data5
}

function Invoke-AcroCleaner {
    param(
        [Parameter()]
        [String]$InstallLocation
    )
    $AcroCleanerPath = Join-Path $PSScriptRoot 'AdobeAcroCleaner_DC2015.exe'
    if (Test-Path $AcroCleanerPath) {
        $StartProcessSplat = @{
            FilePath     = $AcroCleanerPath
            ArgumentList = @('/silent','/product=1')
            PassThru     = $true
            Wait         = $true
        }

        if ($InstallLocation) {
            $StartProcessSplat['ArgumentList'] += "/installLocation=`"$InstallLocation`""
        }

        Start-Process @StartProcessSplat
    }
}
#endregion

$log = '{0}\Repair-AdobeAcrobatRdrx86.log' -f $env:temp
$null = Start-Transcript -Path $log -Append -NoClobber -Force
$VerbosePreference = 'Continue'

$Adobe = [ordered]@{
    Found = $false
}

Write-Verbose "Searching for Adobe Acrobat Reader installation..."
$Products = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
foreach ($Product in $Products) {
    $InstallProperties = Get-ItemProperty -Path "$($Product.PSPath)\InstallProperties"
    if ('Adobe Acrobat Reader','Adobe Acrobat Reader DC' -contains $InstallProperties.DisplayName) {
        $Adobe['InstallProperties'] = $InstallProperties | Select-Object -Property * -ExcludeProperty 'PSProvider'
        $Adobe['CompressedGuid'] = $InstallProperties.PSParentPath.Split('\')[-1]
        $Adobe['UncompressedGuid'] = Convert-CompressedGuidToProductCode -CompressedGuid $Adobe['CompressedGuid']
        Write-Verbose 'Found Adobe Acrobat Reader x86'
        break
    }
}

if ($Adobe) {
    $Products = Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products'
    Write-Verbose "Searching for MSI source information..."
    foreach ($Product in $Products) {
        if ($Product.PSChildName -eq $Adobe['CompressedGuid']) {
            $Adobe['Found']       = $true
            $Adobe['PackageName'] = Get-ItemProperty -Path "$($Product.PSPath)\SourceList" | Select-Object -ExpandProperty PackageName
            $Adobe['NetPaths']    = Get-ItemProperty -Path "$($Product.PSPath)\SourceList\Net" | 
                                    Select-Object -Property * -ExcludeProperty 'PS*' | ForEach-Object {
                                        $_.PSObject.Properties.Value
                                    }
            Write-Verbose 'Found MSI source information'
            break
        }
    }
}

$Adobe | ConvertTo-Json -Depth 2 | Write-Verbose

if (-not $Adobe['Found']) {
    Write-Verbose "Adobe Acrobat Reader installation not found"
}
else {
    Write-Verbose "Checking for missing MSI sources..."

    $1612IsPredicted = $true

    if (Test-Path $Adobe['InstallProperties'].LocalPackage) {
        Write-Verbose "Found LocalPackage at $($Adobe['InstallProperties'].LocalPackage)"
        $1612IsPredicted = $false
    }
    else {
        Write-Verbose "LocalPackage not found, checking network paths..."
        foreach ($NetPath in $Adobe['NetPaths']) {
            $FullPath = Join-Path -Path $NetPath -ChildPath $Adobe['PackageName']
            if (Test-Path $FullPath) {
                Write-Verbose "Found network package at $FullPath"
                $1612IsPredicted = $false
                break
            }
        }
    }

    if ($1612IsPredicted) {
        Write-Verbose "MSI sources appear to be missing, attempting repair..."

        $MsiPath = Join-Path $Adobe['InstallProperties'].InstallLocation 'Setup Files' | 
                        Join-Path -ChildPath ('{' + $Adobe['UncompressedGuid'] + '}') |
                        Join-Path -ChildPath $Adobe['PackageName']

        Write-Verbose "Attempting repair with MSI at $MsiPath"
        if (Test-Path $MsiPath) {
            $r = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/fvomus', "`"$MsiPath`"", '/qn' -Wait -PassThru
            Write-Verbose "MSI repair process exited with code $($r.ExitCode)"

            Write-Verbose "Retrieving post-repair installation properties..."
            $Adobe['PostRepairInstallProperties'] = Get-ItemProperty -Path $Adobe['InstallProperties'].PSPath
            
            if (-not (Test-Path $Adobe['PostRepairInstallProperties'].LocalPackage)) {
                Write-Verbose "Repair failed, MSI sources are still missing."
                if ($RemoveIfRepairFails.IsPresent) {
                    Write-Verbose "RemoveIfRepairFails flag is set, invoking AcroCleaner to remove installation."
                    $r = Invoke-AcroCleaner -InstallLocation $Adobe['InstallProperties'].InstallLocation
                    Write-Verbose "AcroCleaner process exited with code $($r.ExitCode)"
                }
            }
            else {
                Write-Verbose "Repair successful, MSI sources are now present."
            }
        }
        else {
            Write-Verbose "MSI path $MsiPath not found, cannot repair."
        }
    }
    else {
        Write-Verbose "MSI sources are present, no repair needed."
    }
}

Write-Verbose "Script completed"
Stop-Transcript
