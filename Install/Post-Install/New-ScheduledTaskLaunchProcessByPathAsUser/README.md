---
external help file:
Module Name:
online version:
schema: 2.0.0
---

# New-ScheduledTaskLaunchProcessByPathAsUser

## SYNOPSIS
Launch an process in the user's context using a one-time scheduled task

## SYNTAX

```
New-ScheduledTaskLaunchProcessByPathAsUser [-FilePath] <String> [[-Arguments] <String[]>] [[-Seconds] <Int32>]
 [[-ScheduledTaskName] <String>] [<CommonParameters>]
```

## DESCRIPTION
This script is useful if you need to launch a process in the user's context.

Typically best used as a post-script in most situations.

One example use case of this script with Patch My PC's Publisher is to launch a process in the logged in user's 
security context if the security context used to install or update the software is something else e.g.
NT AUTHORITY\SYSTEM.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -FilePath
Specify the path to the binary to launch in the user's context from the scheduled task

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Arguments
The arguments to pass to the binary

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Seconds
The next of seconds to start the scheduled task after running the script

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: 10
Accept pipeline input: False
Accept wildcard characters: False
```

### -ScheduledTaskName
The name of the scheduled task

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: "Patch My PC - Start {0}" -f (Split-Path $FilePath -Leaf)
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
