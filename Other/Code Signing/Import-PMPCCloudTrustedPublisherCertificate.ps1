<#
.SYNOPSIS
    Imports the Patch My PC code-signing certificate public key into the local machine Trusted Publishers store.
    This certificate is used to sign detection and remediation scripts for Patch My PC applications published using Patch My PC Cloud.

.NOTES
    FileName:    Import-PMPCCloudTrustedPublisherCertificate.ps1
    Author:      Ben Whitmore
    Date:        25th June 2024
    Updated:     20th June 2025

.DESCRIPTION
    This script imports the Patch My PC code-signing certificate public key into the local machine Trusted Publishers store. 
    The certificate is store in base64 format in the script and is converted to a certificate object before being added to the store.

    NOTE: This script requires elevated permissions to install the certificate into the Local Machine store.

    # The following code was used to import the certificate as a Base64-encoded string
    $certPath = 'C:\Temp\PmpcScripts\certs\Patch My PC LLC.cer'
    $bytes = [System.IO.File]::ReadAllBytes($certPath)
    $base64 = [System.Convert]::ToBase64String($bytes)
#>

# Base64-encoded certificate content
$base64Cert = @"
MIIHSTCCBTGgAwIBAgIQCCFR6ulgpnd5CTnQhq7j0TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MDYwNTAwMDAwMFoX
DTI3MDYwNDIzNTk1OVowgdExEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMI
Q29sb3JhZG8xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRQwEgYDVQQFEwsyMDEzMTYz
ODMyNzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRQwEgYDVQQHEwtDYXN0bGUgUm9j
azEZMBcGA1UEChMQUGF0Y2ggTXkgUEMsIExMQzEZMBcGA1UEAxMQUGF0Y2ggTXkgUEMsIExMQzCC
AaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAI4L1foPMR+0UKjzSsQZzLOdoKNJXO9EVFR1
j+iVYzQA7wrEe9pwfgns3Bs9NDf9VcIGAcPdApOB46weoZWNE1P8pPhL2V42dh96c/eHUadCCXrv
6gPMguKKh0CiaHATdQjAG+GmPwAETrW0gwWRvhQbbLoLYiBnW6z72a0rZ2NUv1s9aXd5sq42PMIi
flL/hqWEoXD9clvDERPfAStHbxZwEXJ3EpsI9Y9N7O5hd+PGnskLUTQfs5dt03HWhgCDI0mlXdi0
2LI2Zem4r5iRzt5NGY0b3sp5E10lC5v8KWgf5VfmjNdV875ILJ6sfEyfvIFwiVn/Q9/UWVklzwVR
HPXK9NUO5YXWG792OhKK0KXlLXN1VzrppbAWUZMICEa8a8h6JM9/8071dlcwST2cY20plbXpS9tV
xK/6E/YCN9Fopz2+F3dNeeW7okXd2q8Ez90uOKZuj4fZkozrmM+/hGzOVRFFV23XinJDvMI7/I52
At48tLE1CLoL4zalnJUQWwIDAQABo4ICAjCCAf4wHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsI
iGX0TkIwHQYDVR0OBBYEFICQ/SZIAGMkmdGRtx9TQIMONAEmMD0GA1UdIAQ2MDQwMgYFZ4EMAQMw
KTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQEAwIH
gDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5k
aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIx
Q0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9j
YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNI
QTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggIBALlBqZymgkuENodf
7tC1viaTZFFzAeuR9DO9u36GeFy4iZ3tKJ4IKznvVGRNYb2F5UTFHTDE0rgJPF+w0w8dnT6R2MB2
aXzvyV4MBmezgPIhbx/y1h+M72wLkydNSLt0PJkw8R0BE4M794lZnh8Vmh3/bpfjIq8NYXYx/fNi
Iwiud8+kLcLsJ53qO2W0nytZh22HccJSXKOaxQxMdBSieV+ff150Q0AKvse87/ZscY3QnTKgPHqh
DFGgeVQpCOXayaWWbluVYo5eeVsN+k36QkXDaGctpvEd4pbelMIN3DonD1NrL3Cp1YT5eMs7D9LU
p+5SoOkVBj9+b6j5fNHVH+Fwx1F+ATejXO3BB+mt8WkFRQgREwp01UVD2gPtcj8KnY1IIgYGAogB
7UraIXXTxJxhUXeSZNW1HpWaa/K7skUUlsYv/4PJTgAB5yvG5ZDJBi9M58MFAzmlH4qdrJRbxMuK
9AxAqJKjGwm7B4AZeivSDnhC0UQ0g29tfOLzGXx0AfrdcAnn1U8bCzHg5Qc+Xy1Y6Ybx6MYLvFAL
S3Q++Rc05INimwTgM8F0PW9Ch7g88zXwad3p0CJrXdfU/b3SdLEcf2e62qM+//+15aVIuClYeam8
oC58q+Rfefn5eG3hKpyHzmQdzlSpVbR/9eRRO2kXESPuAL7Xo0sZW8IVSRtM
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
            Write-Output "Patch My PC Cloud certificate already exists in the Local Machine Trusted Publisher store"
        }
        else {
            # Add the certificate to the store
            $store.Add($cert)
            Write-Output "Patch My PC Cloud certificate successfully imported into the Local Machine Trusted Publisher store"
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