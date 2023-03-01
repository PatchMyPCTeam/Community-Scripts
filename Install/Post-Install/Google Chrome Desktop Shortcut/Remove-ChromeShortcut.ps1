#region Remove Desktop shortcut
## Remove existing Desktop shortcut
Remove-File -Path "$($env:PUBLIC)\desktop\Google Chrome.lnk"
## Prevent creation of the Desktop shortcut
$InstallLocation = Split-Path ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\ChromeHTML\shell\open\command" -Name "(Default)")."(Default)").Split("--")[0].Trim('"',' ') -Parent
$PrefFile = "$($InstallLocation)\master_preferences"
if (Test-Path -Path "$PrefFile" -PathType Leaf) {
    try {
	    $json = Get-Content $PrefFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
	    If ($json) {
    	    If ($json.distribution -ne $null) {
        	    $json.distribution | Add-Member -Name "do_not_create_desktop_shortcut" -Value $true -MemberType NoteProperty -Force -ErrorAction Stop
    	    }
    	    Else {
        	    $json | Add-Member -Name "distribution" -Value @{"do_not_create_desktop_shortcut"=$true} -MemberType NoteProperty -Force -ErrorAction Stop
    	    }
    	    $json | ConvertTo-Json -Depth 100  -ErrorAction Stop | Out-File -FilePath $PrefFile -Encoding ASCII -ErrorAction Stop
	    }
    }
    catch {
		
	}
}
#endregion
