<#
.SYNOPSIS
    Imports the PSAppDeployToolkit code-signing certificate public key into the local machine Trusted Publishers store.
    This certificate is used to sign the PSAppDeployToolkit module.

.NOTES
    FileName:    Import-PSADTTrustedPublisherCertificate.ps1
    Author:      Ben Whitmore
    Date:        15th May 2026
    
.DESCRIPTION
    This script imports the PSAppDeployToolkit code-signing certificate public key into the local machine Trusted Publishers store. 
    The certificate is store in base64 format in the script and is converted to a certificate object before being added to the store.

    NOTE: This script requires elevated permissions to install the certificate into the Local Machine store.

    # The following code was used to import the certificate as a Base64-encoded string
    $certPath = '.\PSAppDeployToolkit.cer'
    $bytes = [System.IO.File]::ReadAllBytes($certPath)
    $base64 = [System.Convert]::ToBase64String($bytes)
#>

# Base64-encoded certificate content
$base64Cert = @"
MIIHSTCCBTGgAwIBAgIQCvlbtr6iDIUOmMb7jqwI+TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MDkwNTAwMDAwMFoX
DTI3MDkwNzIzNTk1OVowgdExEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMI
Q29sb3JhZG8xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRQwEgYDVQQFEwsyMDEzMTYz
ODMyNzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRQwEgYDVQQHEwtDYXN0bGUgUm9j
azEZMBcGA1UEChMQUGF0Y2ggTXkgUEMsIExMQzEZMBcGA1UEAxMQUGF0Y2ggTXkgUEMsIExMQzCC
AaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALsncZKNh65erADSVI33cqSj+tKgR+RJIX2k
UAJ5/nt74NnlXG4hFiI5azGM7ytrIDjAW8Bnm6gFEZBZlAig3RsXMSnrl3Wlzx1jysHNlo2AhWo6
1+h6H4osDczgnS+lRODw0IT0Ue0iHTTRUq8eQuGQzdU+jh/snV+xEBfPjQVDR0WxFXZfofR+QHsc
et2n2vM7t4Pxl5bslym2/iR7YDSWlIBbhTkU8cNUzuqh/kuh66aX/UHABZruMRrZHNhUoYL9DYFj
DRg2aia/6PbKidrXWmRw8q+h/D72PHoKFLIRe3HIBGLRBHQfUkUfJlUIpNcOaBk4w1ox4/vI4E6c
5XrUcsKbZP5vD3oVQTfJ7aqEnbyy3LkFc5rjy8zf4rioebGXlr6jzjQKXBJ2XDjaV3m8olD5xHj6
+a2QFO4TIzMNmT50JTHGxr7YD9qou5tn95lxWMVo5SgsWgKWB3qkhXlgvMzOzmC9h5WfhriuFxvI
ylROrFklvVpP3ZtLyW2rLwIDAQABo4ICAjCCAf4wHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsI
iGX0TkIwHQYDVR0OBBYEFORglN0hKniG4YWPXslNC3EyO+V/MD0GA1UdIAQ2MDQwMgYFZ4EMAQMw
KTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQEAwIH
gDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5k
aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIx
Q0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9j
YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNI
QTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggIBAKgNLm/4pTIHSLzI
gXlgaIjMXuTiG5TmxiO5XpnD9lhKmhAEltdf8FcCVOt2cIbZEGjVOK143+n6suaTlM6UF4GI0mju
A/wDjCSh5cqcbJRamf3WKXLntsRNx+5ZjuCj3/FcV7hSFKoy3rVPpJIe6P0OdkWm1QLjqzxSpzm4
sctRyMdP+Rfkbj/cYapg23zO5ec1AHLjggpGO27riJxLIqfQWV1IlW/CuWz0fUZOw6GreBUJje9s
Y2pHBGTjFP74NGYFWvJ8ZAV7VbI8W7K/mzg59HHXRytUB1opfz5qQDZMTex/LXQgGfG08yL77ncU
i57e7LG20A5AMjcNG7Qx/jCr/5flXGMkB+dWecU/Q7xwphHe++G6GZD9hn0xb5+/4CEhI03TrlBr
LXa4EsINcyT6oCu81sSuPMQu2sKWt4MDrPaZ8oqhxt68fOP0h1IgC9pZJY7A93qZkcbFnmYWTWPd
8RKUB3vSwb6P7eFUY2c6lM/qXxDD6nl/4OfpqW+GqemZjSbgGCRZlNCyJAi0DfZil4tSJfVlOon5
972LrRjEi/wXXlj/u3zOzGS4jvtQSLAXUpleqWVUty0QQMt8CJW1i+vZr8iwjyEO8+HbX7s8At+h
PZNr4c3og0PpNXRSQ0ncUw3rbHJNBbg9aL4YrtnGi+AXRbAlrFzyzMr7ujpW
"@

try {

    # Convert the Base64 string to byte array
    $certBytes = [System.Convert]::FromBase64String($base64Cert)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

    # Open the Trusted Publisher store with ReadWrite permissions
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher", "LocalMachine")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    try {

        # Check if the certificate already exists in the store
        $certExists = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

        if ($certExists) {
            Write-Output "PSAppDeployToolkit certificate already exists in the Local Machine Trusted Publisher store"
        }
        else {
            # Add the certificate to the store
            $store.Add($cert)
            Write-Output "PSAppDeployToolkit certificate successfully imported into the Local Machine Trusted Publisher store"
        }
    }
    catch {

        throw "An error occurred importing the certificate: $_"
    }
    finally {

        # Close the store
        $store.Close()
    }
}
catch {
    throw "An error setting up the certificate or opening the store: $_"
}
finally {

    # Clear the Base64 certificate content
    $base64Cert = $null
    $certBytes = $null
    $cert = $null
    $store = $null
}