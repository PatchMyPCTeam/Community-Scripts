<#
.Synopsis
Detects and extracts zip file(s) from the script directory for application deployment.
Created on:   27/04/2026
Created by:   Ben Whitmore@PatchMyPC
Filename:     Extract-Zip.ps1

.Description
- Automatically detects and extracts all zip files found in the script's own directory.
- Optionally accepts a specific zip filename via the -Name parameter to target a single archive when multiple zips are present.
- Supports overwriting existing files during extraction.
- Logs to a CMTrace-compatible log file in the TEMP folder by default.

---------------------------------------------------------------------------------
LEGAL DISCLAIMER
The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.Parameter Name
Optional. Name of a specific zip file to extract. If not provided, all zip files in the script directory are extracted.

.Parameter LogPath
Path to the directory where the log file will be created. Defaults to $env:TEMP.

.Parameter LogName
Name of the log file. Defaults to a timestamped "ZipExtractor-PreScript_yyMMdd-HHmm.log".
#>

[CmdletBinding()]
param(
    [string]$Name,
    [string]$LogPath = $env:TEMP,
    [string]$LogName = ("ZipExtractor-PreScript_{0}.log" -f (Get-Date -Format "yyMMdd-HHmm"))
)

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
        [Parameter(Mandatory = $false)]
        [string]$Component = "PreScript"
    )

    $fullLogPath = Join-Path $LogPath $LogName

    if (-not (Test-Path $LogPath)) {
        try {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        }
        catch {
            Write-Warning ("Failed to create log directory {0}: {1}. Using temp directory instead." -f $LogPath, $_.Exception.Message)
            $LogPath = $env:TEMP
            $fullLogPath = Join-Path $LogPath $LogName
        }
    }

    $time = Get-Date -Format "HH:mm:ss.ffffff"
    $date = Get-Date -Format "MM-dd-yyyy"

    try {
        $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        if ($env:USERNAME) { $context = $env:USERNAME }
        elseif ($env:USER)  { $context = $env:USER }
        else                 { $context = 'Unknown' }
    }

    $logEntry = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$Component`" context=`"$context`" type=`"$Severity`" thread=`"$PID`" file=```">"

    try {
        Add-Content -Path $fullLogPath -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Warning ("Failed to write to log file {0}: {1}" -f $fullLogPath, $_.Exception.Message)
    }
}

function Expand-ZipFile {
    param(
        [string]$ZipPath,
        [string]$DestinationPath
    )

    try {
        Write-Log ("Extracting {0} to {1}" -f $ZipPath, $DestinationPath)

        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force

        Write-Log ("Zip extraction completed successfully")
        return $true
    }
    catch {
        Write-Log ("Failed to extract zip file: {0}" -f $_.Exception.Message) -Severity 3
        return $false
    }
}

# Main execution
try {
    $currentDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

    Write-Log ("Starting zip file extraction")
    Write-Log ("Script directory: {0}" -f $currentDir)
    Write-Log ("PowerShell version: {0}" -f $PSVersionTable.PSVersion)

    # Build the list of zips to process
    if ($Name) {
        $zipPath = Join-Path $currentDir $Name
        Write-Log ("Using explicitly specified zip file: {0}" -f $Name)

        if (-not (Test-Path $zipPath)) {
            Write-Log ("Specified zip file not found: {0}" -f $Name) -Severity 3
            throw ("Specified zip file not found: {0}" -f $Name)
        }

        $zipFiles = @(Get-Item $zipPath)
    }
    else {
        Write-Log ("Auto-detecting zip files in directory")
        $zipFiles = @(Get-ChildItem -Path $currentDir -Filter "*.zip" -File)

        if ($zipFiles.Count -eq 0) {
            Write-Log ("No zip files found in: {0}" -f $currentDir) -Severity 3
            throw ("No zip files found in: {0}" -f $currentDir)
        }

        Write-Log ("Found {0} zip file(s) to extract" -f $zipFiles.Count)
        foreach ($zip in $zipFiles) {
            Write-Log ("Queued: {0} ({1:N2} MB)" -f $zip.Name, ($zip.Length / 1MB))
        }
    }

    # Loop over ALL zips
    $successCount = 0
    $failCount    = 0

    foreach ($zipFile in $zipFiles) {
        Write-Log ("Processing: {0} ({1:N2} MB)" -f $zipFile.Name, ($zipFile.Length / 1MB))

        # Snapshot existing files before extraction so the count only reflects new files
        $beforeFiles = @(Get-ChildItem -Path $currentDir -File -Recurse |
                            Where-Object { $_.FullName -ne $zipFile.FullName })

        $result = Expand-ZipFile -ZipPath $zipFile.FullName -DestinationPath $currentDir

        if ($result) {
            $afterFiles    = @(Get-ChildItem -Path $currentDir -File -Recurse |
                                   Where-Object { $_.FullName -ne $zipFile.FullName })
            $extractedCount = $afterFiles.Count - $beforeFiles.Count

            Write-Log ("Extracted {0} new file(s) from {1}" -f $extractedCount, $zipFile.Name)
            $successCount++
        }
        else {
            Write-Log ("Extraction failed for: {0}" -f $zipFile.Name) -Severity 3
            $failCount++
        }
    }

    Write-Log ("Extraction complete. Success: {0}, Failed: {1}" -f $successCount, $failCount)

    if ($failCount -gt 0) {
        throw ("{0} zip file(s) failed to extract. Check log for details." -f $failCount)
    }
}
catch {
    Write-Log ("PreScript execution failed: {0}" -f $_.Exception.Message) -Severity 3
    exit 1
}