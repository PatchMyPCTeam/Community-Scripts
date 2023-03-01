<#
.SYNOPSIS
    Script to Remove Java Runtime Environment 8 prior to installing the latest update
    Patch My PC
.DESCRIPTION
    This PowerShell script's intention is to remove all versions of Java Runtime Environment 8 prior to installing the latest update.
.EXAMPLE
    .\PatchMyPC-Remove-JRE8.ps1
    This will remove ALL versions of JRE8 x86 and x64 present on the device

    .\PatchMyPC-Remove-JRE8.ps1 -VersionToExclude "361"
    This will remove all versions of JRE8 except 8u361 x86 and x64

    .\PatchMyPC-Remove-JRE8.ps1 -VersionToExclude "361 (64-bit)"
    This will remove all versions of JRE8 except 8u361 x64
#>

[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VersionToExclude = ""
)
begin {
    #Set variables#
    $AppToUninstall = "Java 8*"
    $PublisherToUninstall = "Oracle*"
    #Set log  path desired if you want to change simply change the loglocation parameter to a folder path the log will alwyays be the name of the script.
    Function Get-InstSoftware {
        if ([IntPtr]::Size -eq 4) {
            $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        }
        else {
            $regpath = @(
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
        }
        Get-ItemProperty $regpath | .{ process { if ($_.DisplayName -and $_.UninstallString) { $_ } } } | Select-Object DisplayName, UninstallString, PSChildName, Publisher, InstallDate | Sort DisplayName
    }
    
    Function Start-TSxLog
    { #Set global variable for the write-TSxInstallLog function in this session or script.
        [CmdletBinding()]
        param (
            #[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
            [string]$FilePath
        )
        try {
            if (!(Split-Path $FilePath -Parent | Test-Path)) {
                New-Item (Split-Path $FilePath -Parent) -Type Directory | Out-Null
            }
            #Confirm the provided destination for logging exists if it doesn't then create it.
            if (!(Test-Path $FilePath)) {
                ## Create the log file destination if it doesn't exist.
                New-Item $FilePath -Type File | Out-Null
            }
            ## Set the global variable to be used as the FilePath for all subsequent write-TSxInstallLog
            ## calls in this session
            $global:ScriptLogFilePath = $FilePath
        }
        catch {
            #In event of an error write an exception
            Write-Error $_.Exception.Message
        }
    }

    Function Write-TSxLog
    { #Write the log file if the global variable is set
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [Parameter()]
            [ValidateSet(1, 2, 3)]
            [string]$LogLevel = 1,
            [Parameter(Mandatory = $false)]
            [bool]$writetoscreen = $true   
        )
        $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
        $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
        $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
        $Line = $Line -f $LineFormat
        Add-Content -Value $Line -Path $ScriptLogFilePath
        if ($writetoscreen) {
            switch ($LogLevel) {
                '1' {
                    Write-Verbose -Message $Message
                }
                '2' {
                    Write-Warning -Message $Message
                }
                '3' {
                    Write-Error -Message $Message
                }
                Default {
                }
            }
        }
        if ($writetolistbox -eq $true) {
            $result1.Items.Add("$Message")
        }
    }

    function set-TSxDefaultLogPath {
        #Function to set the default log path if something is put in the field then it is sent somewhere else. 
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory = $false)]
            [bool]$defaultLogLocation = $true,
            [parameter(Mandatory = $false)]
            [string]$LogLocation
        )
        if ($defaultLogLocation) {
            $LogPath = Split-Path $script:MyInvocation.MyCommand.Path
            $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"     
            Start-TSxLog -FilePath $($LogPath + "\" + $LogFile)
        }
        else {
            $LogPath = $LogLocation
            $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"     
            Start-TSxLog -FilePath $($LogPath + "\" + $LogFile)
        }
    }

}
process {
    set-TSxDefaultLogPath -defaultLogLocation:$true
    $Software = Get-InstSoftware | Where-Object { ($_.DisplayName -like $AppToUninstall) -and ($_.DisplayName -notlike "*$VersionToExclude*") -and ($_.Publisher -like $PublisherToUninstall) }
    Write-TSxLog -Message "Starting log for JRE removal for Patch My PC"
    If ($Software -eq $null) { Exit 0 }
    Else {    
        foreach ($Install in $Software) {
            Write-TSxLog -Message "Now removing $($Install.DisplayName) using command $($Install.PSChildName)"
            Write-TSxLog -Message "Now building the MSI arguments for start process"
            $MSIArguments = @(
                '/x'
                $Install.PSChildName
                '/qn'    
                '/L*v "C:\Windows\Temp\PatchMyPC-' + $($Install.DisplayName) + '.log"'
                'REBOOT=REALLYSUPPRESS'
            )
            Write-TSxLog -Message "Now submitting the following arguments to start-process using MSIExec.exe $($MSIArguments)"
            try {
                $Results = Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow -ErrorAction Stop -PassThru
                Write-TSxLog -Message "The application was uninstalled with Exit Code: $($Results.ExitCode)"
            }
            catch {
                Write-TSxLog -Message "An error occured trying to remove a version of the software it terminated with the error $($_.Exception.Message)" -LogLevel 3
                Write-TSxLog -Message "The Exit code was $($Results.ExitCode)"
            }
            Write-TSxLog -Message "The application has been succesfully removed"
        }
    }
}

# SIG # Begin signature block
# MIIovAYJKoZIhvcNAQcCoIIorTCCKKkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxTf+qJac1ea1I
# DVPzWJ32Xr9xTPwNwnzmeFC1yoaabKCCIb8wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwDCCBKigAwIBAgIQ
# DE1pckuU+jwqSj0pB4A9WjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIyMDkyMTAw
# MDAwMFoXDTMzMTEyMTIzNTk1OVowRjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERp
# Z2lDZXJ0MSQwIgYDVQQDExtEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMiAtIDIwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDP7KUmOsap8mu7jcENmtuh6BSF
# dDMaJqzQHFUeHjZtvJJVDGH0nQl3PRWWCC9rZKT9BoMW15GSOBwxApb7crGXOlWv
# M+xhiummKNuQY1y9iVPgOi2Mh0KuJqTku3h4uXoW4VbGwLpkU7sqFudQSLuIaQyI
# xvG+4C99O7HKU41Agx7ny3JJKB5MgB6FVueF7fJhvKo6B332q27lZt3iXPUv7Y3U
# TZWEaOOAy2p50dIQkUYp6z4m8rSMzUy5Zsi7qlA4DeWMlF0ZWr/1e0BubxaompyV
# R4aFeT4MXmaMGgokvpyq0py2909ueMQoP6McD1AGN7oI2TWmtR7aeFgdOej4TJEQ
# ln5N4d3CraV++C0bH+wrRhijGfY59/XBT3EuiQMRoku7mL/6T+R7Nu8GRORV/zbq
# 5Xwx5/PCUsTmFntafqUlc9vAapkhLWPlWfVNL5AfJ7fSqxTlOGaHUQhr+1NDOdBk
# +lbP4PQK5hRtZHi7mP2Uw3Mh8y/CLiDXgazT8QfU4b3ZXUtuMZQpi+ZBpGWUwFjl
# 5S4pkKa3YWT62SBsGFFguqaBDwklU/G/O+mrBw5qBzliGcnWhX8T2Y15z2LF7OF7
# ucxnEweawXjtxojIsG4yeccLWYONxu71LHx7jstkifGxxLjnU15fVdJ9GSlZA076
# XepFcxyEftfO4tQ6dwIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1Ud
# EwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZn
# gQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCP
# nshvMB0GA1UdDgQWBBRiit7QYfyPMRTtlwvNPSqUFN9SnDBaBgNVHR8EUzBRME+g
# TaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRS
# U0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCB
# gDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUF
# BzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUA
# A4ICAQBVqioa80bzeFc3MPx140/WhSPx/PmVOZsl5vdyipjDd9Rk/BX7NsJJUSx4
# iGNVCUY5APxp1MqbKfujP8DJAJsTHbCYidx48s18hc1Tna9i4mFmoxQqRYdKmEIr
# UPwbtZ4IMAn65C3XCYl5+QnmiM59G7hqopvBU2AJ6KO4ndetHxy47JhB8PYOgPvk
# /9+dEKfrALpfSo8aOlK06r8JSRU1NlmaD1TSsht/fl4JrXZUinRtytIFZyt26/+Y
# siaVOBmIRBTlClmia+ciPkQh0j8cwJvtfEiy2JIMkU88ZpSvXQJT657inuTTH4YB
# ZJwAwuladHUNPeF5iL8cAZfJGSOA1zZaX5YWsWMMxkZAO85dNdRZPkOaGK7DycvD
# +5sTX2q1x+DzBcNZ3ydiK95ByVO5/zQQZ/YmMph7/lxClIGUgp2sCovGSxVK05iQ
# RWAzgOAj3vgDpPZFR+XOuANCR+hBNnF3rf2i6Jd0Ti7aHh2MWsgemtXC8MYiqE+b
# vdgcmlHEL5r2X6cnl7qWLoVXwGDneFZ/au/ClZpLEQLIgpzJGgV8unG1TnqZbPTo
# ntRamMifv427GFxD9dAq6OJi7ngE273R+1sKqHB+8JeEeOMIA11HLGOoJTiXAdI/
# Otrl5fbmm9x+LMz/F0xNAKLY1gEOuIvu5uByVYksJxlh9ncBjDCCCAAwggXooAMC
# AQICEA9Lp9vIoK2Todmfupg/Pk0wDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTAe
# Fw0yMjA5MTUwMDAwMDBaFw0yNTA5MTAyMzU5NTlaMIHRMRMwEQYLKwYBBAGCNzwC
# AQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCENvbG9yYWRvMR0wGwYDVQQPDBRQcml2
# YXRlIE9yZ2FuaXphdGlvbjEUMBIGA1UEBRMLMjAxMzE2MzgzMjcxCzAJBgNVBAYT
# AlVTMREwDwYDVQQIEwhDb2xvcmFkbzEUMBIGA1UEBxMLQ2FzdGxlIFJvY2sxGTAX
# BgNVBAoTEFBhdGNoIE15IFBDLCBMTEMxGTAXBgNVBAMTEFBhdGNoIE15IFBDLCBM
# TEMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDyn6DYy4BKs5cC/2mS
# 0pXQpEU32UNY72+mTIWWKMVHTac1BBjaW3UwfTTYPa0HWQrzwxWMYc9NGzrcBXc8
# 6zt1fuBsUjyuwQSpAgEseTnva1RvbtL5lNrwrJ0TjLXMyvFAYhEQ/v1vhWDdgIEM
# HWGlLGjzE/0DZX1boThIxUFwWKAjDDv3DV1EC2ZCMBeBmnGhjIfU1Erm/CvcvDjM
# +QEMo5n08VKwS1M4tFiUtXg6EwHiewSK70+/o3voBLWHvTqSM9oEyZmFMpCFLCMe
# wPDrU8qeo+7XTA2ocMltQ171JxUB1FYl4rL2o0orghnj7XrdZXPsMiYsxheiLzAY
# 8P8S5P9/GQEbOOIjRTVchL4Gui+KVjj6eFJfVZha6lk6fD7eLKaQO8hP9To7GANF
# 5NMd5uh4lIglI8IWPHkYQQqeZnvtUkfCx8IbEtk0jvK2JGhY3LZ0aY6cIajdoWf6
# u1iCIZmUaB8R9ET0KzyTx5HQXrOzjO0la2U7bOyIURF0eD13ngkQ1ojSCG+qU5iY
# lBp68e4MtGsopVDnxD28NCNj0nJAV376scb5yRq/gWVmISFAuv3B1IasHxVTe7av
# J2IgBkiyxYSU9byVhmQVVTW6QwvY6AG7vUrw+PGrdk6zn+oh6c/8oYAvoj4Y4qCU
# TDiStiptFNIwtHarSYSTZn2XlwIDAQABo4ICOTCCAjUwHwYDVR0jBBgwFoAUaDfg
# 67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYEFL08i+NsZzrUZStu8U9uSIfGjEz3
# MDIGA1UdEQQrMCmgJwYIKwYBBQUHCAOgGzAZDBdVUy1DT0xPUkFETy0yMDEzMTYz
# ODMyNzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwgbUGA1Ud
# HwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BR
# oE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENv
# ZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD0GA1UdIAQ2MDQwMgYF
# Z4EMAQMwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BT
# MIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIx
# Q0ExLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBXT6IfohG7
# JJYdOBmpeg04Ckp8P+Zjv5OKFzDyoZj/3mIE3739ocEnsHvVtiCtv1R9B7rVDJOt
# N3FbXMitaaYg5EdDE7IQ+wVVh3gFyUJgIy0FK/N7y4eFoTzmdvkfhsVk97NU7Pyx
# QBeamB6Xefj4Wy7Ugf6cedJNKLl/w3P5GLSmDe/1Qb3tNYJFfqWwbFUTb479k3wD
# EwQ6J4CQ9yeSfn8uz1WVRhby6Y2UbUIx3mourzOy8LofaP3bT00Fe2m3j/IZjsYU
# PakTF2EnqBZE8PPnf/f8D6EMwbsMTdYDUgkRhKH+DWpq3J1B7TgnK1FmygBN63qg
# LWTxxaolQQsFAlAA2dNJg7cGe6hDlKe9Zf9StY96zS1xkpJDjbh2yGmQNz7AqrNJ
# bSBOv+TnfEHyUStsJFLuL2rpoECiVyg4p6jE14uHk7I6tQ+vqrKer53PjtscN+ss
# 7PAlMqJQ9eH0UQ29kDbx5Vs7hvyYLEbJvh2O2KfLyKlXO9zxaK+vhXtgTJ0wjW1Z
# BFeV4t3XpJE2AFf7EMXfF5TgSvoh6Px7eIIMs6oWIzX3V6w+F4dMwbCXziHHjmWN
# vpm95j4OaLb1EUiUvBKSB1pUQWpc8yycMHWOMs/aVNOS9udMBGPolMqMCUeQQ576
# JArSmtO3WKXcMb2BNZeSM+jQQhK+EjG70TGCBlMwggZPAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MQIQD0un28igrZOh2Z+6mD8+TTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBcc1V7DGhq
# idlthN4+hW5s5L3d9VOxPixKU71YyAPIbjANBgkqhkiG9w0BAQEFAASCAgAr1+nf
# rUh8zPyjj76VAmxZreELsp62lQSER7okdnfTcbTE8ehoQ9rg6R0fGR0T+LigeeMn
# W+mzMwMZtm4VAlC4nefJ2JYsvlT2nK+WjnfThmGrPZgp3rrnEDK8SS8BtxKRy+dZ
# M165CKiG58fMljo8CBucVC8usVc7jrXDSGAHxEneBB+7OofuYlgduJIaMzNqWwcS
# rum0WovI9+KBjQiIDEwRK970XkGZe/Fp+dOn5wET4UdODdJ8brZ4StRQWArS52fW
# ljWg63mNXuDVS4JSS845Pws6jyBKhKKWcLxQnmjieXsbw2DBBYtd+MwY/ztM1UAs
# jodZWeWr4+LAbBZYzQtAtYyZM7h7a+IwWmyaQupKD9EODld5WtiW3Dj7acO6kwOL
# gknFIsMHG48TAu4UrNa/v9R457OrT7iHcfZRW7LoFSafElNhcTNHshIkQEBeJ7RD
# Wl+97DoQ2diQvAcsQJF74CW21B/rL0y8Hi1PlwIwjjAyEoNbhyz7wcF4KLix+lH+
# 3fuOAMcz2hF7lpqDziznK8X22G1WkMIvQiuSdsN4T8lmQJxMi/GNRFwVl1qLP2cA
# rxRkBdPYIqtxUrAgOeO7kK7ueCgE2Wp5ndOXXjtI4V+WFYiI03V4WcKaVasAOlmh
# FiNSdlLc61Of8qzBVeXTTiIw2OMcAvOdclRE66GCAyAwggMcBgkqhkiG9w0BCQYx
# ggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1
# NiBUaW1lU3RhbXBpbmcgQ0ECEAxNaXJLlPo8Kko9KQeAPVowDQYJYIZIAWUDBAIB
# BQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0y
# MzAzMDExOTMyNTNaMC8GCSqGSIb3DQEJBDEiBCCgBtZYRjTMhMoDwLz12TghdkaR
# HdcbUY20bvcNPxHVuDANBgkqhkiG9w0BAQEFAASCAgC9iREAREuQhg8XoqdVL9Ap
# cRHvOQ05gnsMRxC5NW6nNYCfItTq1SgwtkDT3zfSVhM9Zn9ukuMZxs7h6TAlPRKk
# G8YXO2R+8+lL2Czojj7S9MKHuwWrJwYoysOJ15xJtSgjaGCG2Ii7RSv+VL/J6hKL
# XjXQLb5a3NgNoKpBemBwrsy07UuoWxLOVKMCk1YDtvs89U6zOGbceATNi5jiLgM1
# VZbEsNVC5nGA95GsvxX/r5zTIOCZhasd3YEnL9IkUx7ZwdmqQM+ca1FvKNGxXyuc
# EBvyMNIx1xaMfdWZXXilVG5utT225O+GXpZvKD69ydZlr4d/yiO24NTWBTgFgpss
# NyXeNYFz+sBWYluIc6SkxO4S5nulan1fkus7rSpLDDq1vlW2YZlQKNNViE9tb7DH
# eUAi4eEo+zpp+CENk8uOibts6imnTRJqtlffr2Z+GwNIoRzNgIcU3O7d1tuDRyl1
# v7yoVXRcwlKIPfrpj18woHqYNI+fAMPiFpwjU6YBsVc6Xhno1oT++Asj5m1aXAM5
# meT/c+TQsj2EPghSBozDBFlnXDyfgf5C5ZkH5As95WspLleU2ptdE1tRrlQJwz0E
# keZZobSsvgFB9ttx8rdqRY2BpDBCjlA9fC0xN63yBI3yfcP6fuVxlPdSY2nRtlGx
# 7gZCN3dPZ96/RJreynQCxQ==
# SIG # End signature block
