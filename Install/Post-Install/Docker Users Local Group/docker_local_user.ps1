$localGroup = "docker-users"
$localGroupMembers = Get-LocalGroupMember -Name $localGroup | Select-Object -ExpandProperty Name

$loggedOnUsers = get-wmiobject win32_process -Filter "name='explorer.exe'" |
    ForEach-Object { "$($_.GetOwner().Domain)\$($_.GetOwner().User)" } | Select-Object -Unique

foreach ($user in $loggedOnUsers) {
    if ($user -notin $localGroupMembers){
        Write-Host "Adding $user to group"
        Add-LocalGroupMember -Group $localGroup -Member $user
    }
    else {
        Write-Host "$user already in group"
    }
}