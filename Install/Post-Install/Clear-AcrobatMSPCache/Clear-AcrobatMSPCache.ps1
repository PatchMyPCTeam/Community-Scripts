#Requires -Version 3.0

<#
.SYNOPSIS
    Removes superseded/obsoleted cached Adobe Acrobat MSP files from C:\Windows\Installer.

    Created on:   2026-10-16
    Created by:   Dan Gough @PatchMyPC
    Filename:     Clear-AcrobatMSPCache.ps1
    Version:      1.0

.DESCRIPTION
    When Adobe Acrobat installs updates (either via the EXE or MSP), superseded MSP files remain in
    C:\Windows\Installer, taking up valuable disk space. These patches are over 600MB each, resulting
    in several GBs of wasted space.

    For each installed Adobe Acrobat / Reader product code:
    - Enumerates all registered MSP patches (applied, superseded and obsoleted) via the WindowsInstaller.Installer COM object
    - Keeps the cached MSP of the currently applied patch
    - Deletes the cached MSP of superseded/obsoleted patches, unless that file is still the
      cached package of a patch applied to any product on the machine
    Use -WhatIf to preview what would be deleted.

.EXAMPLE
    .\Clear-AcrobatMSPCache.ps1 -WhatIf
.EXAMPLE
    .\Clear-AcrobatMSPCache.ps1 -Verbose

.NOTES
    Version history:
    1.0 - 2026-10-16 - Initial release

    ---------------------------------------------------------------------------------
    LEGAL DISCLAIMER

    The PowerShell script provided is shared with the community as-is
    The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
    Please note that the script may need to be modified or adapted to fit your specific environment or requirements
    It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
    The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
    You assume all risks and responsibilities associated with its usage
    ---------------------------------------------------------------------------------
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Patch states are unreliable mid-transaction, e.g. while an Acrobat update is installing
try {
    [System.Threading.Mutex]::OpenExisting('Global\_MSIExecute').Dispose()
    $msiBusy = $true
}
catch [System.Threading.WaitHandleCannotBeOpenedException] {
    $msiBusy = $false
}
catch {
    # Access denied still means the mutex exists
    $msiBusy = $true
}
if ($msiBusy) {
    Write-Host 'A Windows Installer operation is in progress. Try again once it has finished.' -ForegroundColor Yellow
    return
}

$installerFolder = Join-Path $env:SystemRoot 'Installer'

$products = [ordered]@{
    '{AC76BA86-7AD7-FFFF-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 MUI'
    '{AC76BA86-7AD7-1033-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 en-US'
    '{AC76BA86-7AD7-1026-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 bg-BG'
    '{AC76BA86-7AD7-1027-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 ca-ES'
    '{AC76BA86-7AD7-1028-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 zh-TW'
    '{AC76BA86-7AD7-1029-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 cs-CZ'
    '{AC76BA86-7AD7-1030-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 da-DK'
    '{AC76BA86-7AD7-1031-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 de-DE'
    '{AC76BA86-7AD7-1034-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 es-ES'
    '{AC76BA86-7AD7-1035-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 fi-FI'
    '{AC76BA86-7AD7-1036-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 fr-FR'
    '{AC76BA86-7AD7-1038-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 hu-HU'
    '{AC76BA86-7AD7-1040-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 it-IT'
    '{AC76BA86-7AD7-1041-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 ja-JP'
    '{AC76BA86-7AD7-1042-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 ko-KR'
    '{AC76BA86-7AD7-1043-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 nl-NL'
    '{AC76BA86-7AD7-1044-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 nb-NO'
    '{AC76BA86-7AD7-1045-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 pl-PL'
    '{AC76BA86-7AD7-1046-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 pt-BR'
    '{AC76BA86-7AD7-1048-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 ro-RO'
    '{AC76BA86-7AD7-1049-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 ru-RU'
    '{AC76BA86-7AD7-1050-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 hr-HR'
    '{AC76BA86-7AD7-1051-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 sk-SK'
    '{AC76BA86-7AD7-1053-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 sv-SE'
    '{AC76BA86-7AD7-1055-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 tr-TR'
    '{AC76BA86-7AD7-1058-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 uk-UA'
    '{AC76BA86-7AD7-1060-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 sl-SI'
    '{AC76BA86-7AD7-1061-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 et-EE'
    '{AC76BA86-7AD7-1062-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 lv-LV'
    '{AC76BA86-7AD7-1063-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 lt-LT'
    '{AC76BA86-7AD7-1069-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 eu-ES'
    '{AC76BA86-7AD7-2052-7B44-AC0F074E4100}' = 'Adobe Acrobat Reader x86 zh-CN'
    '{AC76BA86-1033-FF00-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 MUI'
    '{AC76BA86-1033-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 en-US'
    '{AC76BA86-1028-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 zh-TW'
    '{AC76BA86-1029-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 cs-CZ'
    '{AC76BA86-1030-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 da-DK'
    '{AC76BA86-1031-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 de-DE'
    '{AC76BA86-1034-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 es-ES'
    '{AC76BA86-1035-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 fi-FI'
    '{AC76BA86-1036-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 fr-FR'
    '{AC76BA86-1038-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 hu-HU'
    '{AC76BA86-1040-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 it-IT'
    '{AC76BA86-1041-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 ja-JP'
    '{AC76BA86-1042-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 ko-KR'
    '{AC76BA86-1043-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 nl-NL'
    '{AC76BA86-1044-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 nb-NO'
    '{AC76BA86-1045-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 pl-PL'
    '{AC76BA86-1046-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 pt-BR'
    '{AC76BA86-1049-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 ru-RU'
    '{AC76BA86-1051-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 sk-SK'
    '{AC76BA86-1053-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 sv-SE'
    '{AC76BA86-1055-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 tr-TR'
    '{AC76BA86-1058-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 uk-UA'
    '{AC76BA86-1060-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 sl-SI'
    '{AC76BA86-2052-1033-7760-BC15014EA700}' = 'Adobe Acrobat Reader x64 zh-CN'
    '{AC76BA86-1033-FFFF-7760-0C0F074E4100}' = 'Adobe Acrobat Pro x86 MUI'
    '{AC76BA86-1033-FFFF-7760-BC15014EA700}' = 'Adobe Acrobat Pro x64 MUI'
    '{AC76BA86-1033-FFFF-7760-0E1401753200}' = 'Adobe Acrobat 2020 Classic x86 MUI'
    '{AC76BA86-7AD7-FFFF-7B44-AE1401753200}' = 'Adobe Acrobat Reader 2020 Classic x86 MUI'
    '{AC76BA86-1033-FFFF-7760-BE180175AB00}' = 'Adobe Acrobat 2024 x64 MUI'
}

$MSIINSTALLCONTEXT_MACHINE = 4
$MSIINSTALLCONTEXT_ALL = 7
$MSIPATCHSTATE_APPLIED = 1
$MSIPATCHSTATE_ALL = 15
$INSTALLSTATE_DEFAULT = 5

function Get-ComProperty {
    param(
        [System.__ComObject]$Object,
        [string]$Name,
        [object[]]$Arguments
    )
    $Object.GetType().InvokeMember($Name, [System.Reflection.BindingFlags]::GetProperty, $null, $Object, $Arguments)
}

function Get-PatchProperty {
    param(
        [System.__ComObject]$Patch,
        [string]$Name
    )
    try {
        Get-ComProperty -Object $Patch -Name 'PatchProperty' -Arguments @($Name)
    }
    catch {
        $null
    }
}

$stateNames = @{
    1 = 'Applied'
    2 = 'Superseded'
    4 = 'Obsoleted'
    8 = 'Registered'
}

[long]$bytesRemoved = 0
$failures = 0

$installer = New-Object -ComObject WindowsInstaller.Installer

try {
    # Cached MSPs still applied to any product on the machine must never be deleted
    # Enumerating other users' contexts needs admin; non-admin runs can't delete anyway
    # PatchesEx rejects $null; '' means all products / machine SID
    $appliedPatches = if ($isAdmin) {
        Get-ComProperty -Object $installer -Name 'PatchesEx' -Arguments @('', 's-1-1-0', $MSIINSTALLCONTEXT_ALL, $MSIPATCHSTATE_APPLIED)
    }
    else {
        Get-ComProperty -Object $installer -Name 'PatchesEx' -Arguments @('', '', $MSIINSTALLCONTEXT_MACHINE, $MSIPATCHSTATE_APPLIED)
    }
    $appliedPackages = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($patch in $appliedPatches) {
        $localPackage = Get-PatchProperty -Patch $patch -Name 'LocalPackage'
        if ($localPackage) {
            $null = $appliedPackages.Add($localPackage)
        }
    }

    foreach ($product in $products.GetEnumerator()) {
        $productCode = $product.Key
        $productName = $product.Value
        Write-Verbose "Checking: $productName $productCode"

        $state = Get-ComProperty -Object $installer -Name 'ProductState' -Arguments @($productCode)
        if ($state -ne $INSTALLSTATE_DEFAULT) {
            Write-Verbose "Product not installed (state=$state), skipping."
            continue
        }

        $productVersion = Get-ComProperty -Object $installer -Name 'ProductInfo' -Arguments @($productCode, 'VersionString')
        Write-Host "$productName $productVersion $productCode" -ForegroundColor Magenta

        $patches = Get-ComProperty -Object $installer -Name 'PatchesEx' -Arguments @($productCode, '', $MSIINSTALLCONTEXT_MACHINE, $MSIPATCHSTATE_ALL)
        $patchDetails = @(foreach ($patch in $patches) {
                $patchState = Get-ComProperty -Object $patch -Name 'State'
                $rawInstallDate = Get-PatchProperty -Patch $patch -Name 'InstallDate'
                $parsedDate = [datetime]::MinValue
                $installDate = if ([datetime]::TryParseExact($rawInstallDate, 'yyyyMMdd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) { $parsedDate } else { $rawInstallDate }
                [pscustomobject]@{
                    PatchCode    = Get-ComProperty -Object $patch -Name 'PatchCode'
                    DisplayName  = Get-PatchProperty -Patch $patch -Name 'DisplayName'
                    InstallDate  = $installDate
                    State        = $patchState
                    StateName    = if ($stateNames.ContainsKey([int]$patchState)) { $stateNames[[int]$patchState] } else { "Unknown ($patchState)" }
                    LocalPackage = Get-PatchProperty -Patch $patch -Name 'LocalPackage'
                }
            })

        if (-not $patchDetails) {
            Write-Host "No registered patches."
            continue
        }

        foreach ($patch in $patchDetails | Sort-Object InstallDate, DisplayName) {
            $label = if ($patch.DisplayName) { $patch.DisplayName } else { $patch.PatchCode }
            $dateText = if ($patch.InstallDate -is [datetime]) { $patch.InstallDate.ToString('yyyy-MM-dd') } elseif ($patch.InstallDate) { $patch.InstallDate } else { 'unknown date' }
            Write-Host "`n[$($patch.StateName)] $label" -ForegroundColor Cyan
            Write-Host "Installed: $dateText"
            Write-Host "LocalPackage: $($patch.LocalPackage)"

            if ($patch.State -notin 2, 4) {
                Write-Host "Keeping." -ForegroundColor Green
                continue
            }

            if (-not $patch.LocalPackage) {
                Write-Host "Could not determine LocalPackage for $($patch.PatchCode), skipping." -ForegroundColor Yellow
                continue
            }

            if ([System.IO.Path]::GetDirectoryName($patch.LocalPackage) -ne $installerFolder -or [System.IO.Path]::GetExtension($patch.LocalPackage) -ne '.msp') {
                Write-Host "LocalPackage is not an MSP in $installerFolder, skipping." -ForegroundColor Yellow
                continue
            }

            if ($appliedPackages.Contains($patch.LocalPackage)) {
                Write-Host "Still applied to another product, keeping." -ForegroundColor Yellow
                continue
            }

            if (-not (Test-Path -LiteralPath $patch.LocalPackage)) {
                Write-Host "Cached MSP already removed."
                continue
            }

            $size = (Get-Item -LiteralPath $patch.LocalPackage -Force).Length

            if (-not $isAdmin -and -not $WhatIfPreference) {
                Write-Host "Administrator rights are required to delete this file." -ForegroundColor Yellow
            }
            elseif ($PSCmdlet.ShouldProcess($patch.LocalPackage, "Delete $($patch.StateName.ToLower()) cached MSP ($([math]::Round($size / 1MB, 1)) MB)")) {
                # Freshly superseded MSPs can be briefly locked, e.g. by AV scanning after the update
                $maxAttempts = 6
                for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                    try {
                        Remove-Item -LiteralPath $patch.LocalPackage -Force -ErrorAction Stop
                        $bytesRemoved += $size
                        Write-Host "Deleted." -ForegroundColor Green
                        break
                    }
                    catch {
                        if ($attempt -lt $maxAttempts) {
                            Write-Host "Delete attempt $attempt failed, retrying in 5s: $($_.Exception.Message)" -ForegroundColor Yellow
                            Start-Sleep -Seconds 5
                        }
                        else {
                            $failures++
                            Write-Host "Failed to delete after $maxAttempts attempts: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }
}
finally {
    $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
}

Write-Host "`nTotal space reclaimed: $([math]::Round($bytesRemoved / 1MB, 1)) MB" -ForegroundColor Green

if ($failures) {
    Write-Host "$failures cached MSP(s) could not be deleted." -ForegroundColor Red
    exit 1
}
