[xml]$packageXml = Get-Content -LiteralPath "$PSScriptRoot\package.xml" -Raw

if ($packageXml.Package.CommandLine -match '/KillProcessList=([^ÿ/]+)') {
    # Clean encoding artifacts, quotes, and split by pipe
    $rawProcessNames = $matches[1] -replace 'Ã¿.*$' -replace '".*$'
    
    $processArray = $rawProcessNames -split '\|' | ForEach-Object { 
        $_.Trim() -replace '\.exe$' -replace '"'
    } | Where-Object { $_ -ne '' -and $_ -notmatch '^\s*$' }
    
    if ($processArray.Count -gt 0) {
        $runningProcesses = Get-ADTRunningProcesses -ProcessObjects $processArray
        Write-Host "Detected following running processes: $processArray"
    }
}