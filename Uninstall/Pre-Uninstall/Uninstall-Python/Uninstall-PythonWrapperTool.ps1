<# 
.SYNOPSIS
    Extracts Uninstall-Python.ps1 from Uninstall-Python.zip and runs it as a pre-install process.
.DESCRIPTION
    Designed for Patch My PC pre-scripts. Extracts the large uninstall script from the ZIP archive
    and executes it before continuing with the main installation.
#>

$ErrorActionPreference = 'Stop'

Write-Output "Starting Uninstall-Python pre-install process..."

# Paths - Uninstall-Python.zip script must be included in the package. 
$ZipFile        = Join-Path $PSScriptRoot 'Uninstall-Python.zip'
$Destination    = $PSScriptRoot
$UninstallScript = Join-Path $Destination 'Uninstall-Python.ps1'

# Validate ZIP
if (-not (Test-Path $ZipFile)) {
    Write-Error "ZIP file not found: $ZipFile"
    exit 1
}

try {
    Write-Output "Extracting $ZipFile..."
    Expand-Archive -Path $ZipFile -DestinationPath $Destination -Force
    Write-Output "Extraction completed successfully."
}
catch {
    Write-Error "Failed to extract ZIP: $($_.Exception.Message)"
    exit 1
}

# Validate extracted script
if (-not (Test-Path $UninstallScript)) {
    Write-Error "Uninstall-Python.ps1 not found after extraction."
    exit 1
}

try {
    Write-Output "Executing $UninstallScript with documented arguments..."

    # IMPORTANT:
    # -VersionLessThan 3.13  => targets Python 3.12 and older
    # -Force                 => ensures user-based installs are removed
    #
    # These flags must match exactly what is listed in the Uninstall Python README.
    $Arguments = "-ExecutionPolicy Bypass -File `"$UninstallScript`" -VersionLessThan 3.13 -Force"

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $Arguments -Wait -PassThru

    Write-Output "Uninstall-Python.ps1 completed with exit code $($process.ExitCode)"

    if ($process.ExitCode -ne 0) {
        Write-Error "Uninstall-Python.ps1 failed with exit code $($process.ExitCode)"
        exit $process.ExitCode
    }

    Write-Output "Python uninstall completed successfully. Proceeding with main installation..."
    exit 0
}
catch {
    Write-Error "Error executing Uninstall-Python.ps1: $_"
    exit 1
}
