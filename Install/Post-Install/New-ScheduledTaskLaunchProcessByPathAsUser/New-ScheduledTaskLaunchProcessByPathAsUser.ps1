<#
.SYNOPSIS
    Launch an process in the user's context using a one-time scheduled task
.DESCRIPTION
    This script is useful if you need to launch a process in the user's context.

    Typically best used as a post-script in most situations.

    One example use case of this script with Patch My PC's Publisher is to launch a process in the logged in user's 
    security context if the security context used to install or update the software is something else e.g. NT AUTHORITY\SYSTEM.
.PARAMETER FilePath
    Specify the path to the binary to launch in the user's context from the scheduled task
.PARAMETER Arguments
    The arguments to pass to the binary
.PARAMETER Seconds
    The next of seconds to start the scheduled task after running the script
.PARAMETER ScheduledTaskName
    The name of the scheduled task
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String]$FilePath,

    [Parameter()]
    [String[]]$Arguments,

    [Parameter()]
    [Int32]$Seconds = 10,

    [Parameter()]
    [String]$ScheduledTaskName = "Patch My PC - Start {0}" -f (Split-Path $FilePath -Leaf)
)

$FilePath = $ExecutionContext.InvokeCommand.ExpandString($FilePath)

$newScheduledTaskActionSplat = @{
    Execute = $FilePath
}

if ($PSBoundParameters.ContainsKey("Arguments")) {
    $newScheduledTaskActionSplat["Argument"] = [String]::Join(' ', $Arguments)
}

$newScheduledTaskSplat = @{
    Action      = New-ScheduledTaskAction @newScheduledTaskActionSplat
    Description = 'Start the following process for the currently logged on user {0} seconds after task creation: {1}' -f $Seconds, $FilePath
    Settings    = New-ScheduledTaskSettingsSet -Compatibility Vista -AllowStartIfOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Trigger     = New-ScheduledTaskTrigger -At ($Start = (Get-Date).AddSeconds($Seconds)) -Once
    Principal   = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
}

$ScheduledTask = New-ScheduledTask @newScheduledTaskSplat
$ScheduledTask.Settings.DeleteExpiredTaskAfter = "PT0S"
$ScheduledTask.Triggers[0].StartBoundary = $Start.ToString("yyyy-MM-dd'T'HH:mm:ss")
$ScheduledTask.Triggers[0].EndBoundary = $Start.AddMinutes($Seconds * 2).ToString('s')

Register-ScheduledTask -InputObject $ScheduledTask -TaskName $ScheduledTaskName -Force
