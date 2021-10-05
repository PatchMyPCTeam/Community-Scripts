
<#
.SYNOPSIS
    Deploy additional language packs to Firefox install directory
.DESCRIPTION
    This post install script will create the necessary directory for Firefox language packs, copy the packs to that folder and rename them to the correct format  
#>

#check os architecture and adjust paths accordingly
if ([System.Environment]::Is64BitOperatingSystem -ne "True"){
    $architecture = ${Env:ProgramFiles(x86)}
} else {
    $architecture = $Env:Programfiles
}

<#
check if distribution and distribution/extensions exist under Firefox install directory (C:\Program Files\Mozilla Firefox)
#>
$folder = $architecture + '\Mozilla Firefox\distribution\extensions\'
if (-not(Test-Path -Path $folder -PathType Container)) {
    try {
        $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    }
    catch {
        throw $_
    }
}

<#
    Copy language packs to extensions folder
    Rename language packs
#>
Copy-Item -Filter '*.xpi' -Destination $folder
Get-ChildItem -Path $folder | Rename-Item -NewName {"langpack-" + (($_.name).TrimEnd(".xpi")) + "@firefox.mozilla.org.xpi"}


<#
    Create the required policies.json file or amend the existing one
#>
$systemlocale = (Get-WinSystemLocale).name
$json = @"
{
  "policies": {
   "RequestedLocales": "$systemlocale"
  }
}
"@
$policiesfile = $architecture + '\Mozilla Firefox\distribution\policies.json'

if (-not(Test-Path -Path $policiesfile -PathType Leaf)) {
    New-Item -ItemType File -Path $policiesfile -Force
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($policiesfile, $json, $Utf8NoBomEncoding)
} else {
    $policyjson = Get-Content $policiesfile | ConvertFrom-Json -Depth 10
    $policyjson.policies | Add-Member -NotePropertyName RequestedLocales -NotePropertyValue "$systemlocale" -Force
    $policyjson = $policyjson | ConvertTo-Json -Depth 10
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($policiesfile, $policyjson, $Utf8NoBomEncoding)
}