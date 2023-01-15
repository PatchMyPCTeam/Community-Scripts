$local_group = "docker-users"
$local_group_members = Get-LocalGroupMember -name $local_group

# Getting current session user
$currentUser = get-wmiobject win32_process -Filter "name='explorer.exe'" |
    ForEach-Object { $_.GetOwner() } | Select-Object -Unique -Expand User

# If user is not in 'docker-users' add current user
if (!($local_group_members -contains $currentUser)){
    Add-LocalGroupMember -Group $local_group -Member $currentUser
}
else {
    write-host "$user already in group"
    Exit
}