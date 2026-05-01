<#
.SYNOPSIS
    Proactive Remediation (Health Script) to test if the Patch My PC code-signing certificate is installed in the Local Machine Trusted Publisher store.
    This certificate is used to sign required and recommended pre/post scripts for certain applications in the Patch My PC catalog.

.NOTES
    FileName:    PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1
    Author:      Ben Whitmore
    Date:        20th June 2025
    
.DESCRIPTION
    This script checks if the Patch My PC code-signing certificate is installed in the Local Machine Trusted Publisher store. 
    The certificate is store in base64 format in the script and is converted to a certificate object before being added to the store.

    # The following code was used to import the certificate as a Base64-encoded string
    $certPath = 'C:\Temp\PmpcScripts\certs\Patch My PC LLC.cer'
    $bytes = [System.IO.File]::ReadAllBytes($certPath)
    $base64 = [System.Convert]::ToBase64String($bytes)
#>

# Base64-encoded certificate content
$base64Cert = @"
MIIHyTCCBbGgAwIBAgIQDMNw87U7UZ48Hv1za61jojANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTIzMDQwNzAwMDAwMFoX
DTI2MDQzMDIzNTk1OVowgdExEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMI
Q29sb3JhZG8xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRQwEgYDVQQFEwsyMDEzMTYz
ODMyNzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRQwEgYDVQQHEwtDYXN0bGUgUm9j
azEZMBcGA1UEChMQUGF0Y2ggTXkgUEMsIExMQzEZMBcGA1UEAxMQUGF0Y2ggTXkgUEMsIExMQzCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKaQcs40YzBFv5HXQFPd04rKJ4uBdwvAZLKu
ULy+icZOpgs/Sy329Ng5ikhB5o1IdvE2cOT20sjs3qgb4e+rqs7taTCe6RNLsDINsmcTlp4yxOfV
80EZ08ld3o36GEgH0Vy1vrJXLTRKNULzV7gIzF/e3tO1Fab4IxKZNcBSXiv8ORqcgT9O7/RZoqyG
87iU6Q/dKfC4WzvU396XJ3FMZrI+s4CgV8p6pVNjijBjH7pmzoXynFtA0j6NH6tg4DmQvm+kfWXt
WbDpPYhdFz1gccJt1DjTrJetpIwBzDAS8NGA75HQhBmQ3gcnNDJLgylB3HyWOeXS+vxXR0Pi/W41
9cfn8zCFH0u2O4QFaZsT2HoIE/t9EhdAKdHoKwvVoCgwvlx3jjwFq5MnoB2oJiNmTGQyhiRvCaw6
JACKUa43eJvlRKylEy4INDTOX5BeivJoTqCw0cCAd6ZuRh6gRl8shIVfN78qunQqJZQkDimtQY5S
n33w+ee5/lFSxOxBg6iu7vCGPZ6QxJd6oVdRa8t87vJ4QVlsMQQRa400S7kqIX1HOnbR3hxgvcks
8kBRMYtZ8g3Fz/WTCW5sWbExVpn6HC6DsRhosF/DBGYmIqQJz6odkCFCr7QcmpGjoZs4jRDegSC5
utEusBYmvCfVxtud3R43WEdCRfHuD1OFDm5HoonnAgMBAAGjggICMIIB/jAfBgNVHSMEGDAWgBRo
N+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQU3wgET0b7maQo7OF3wwGWm83hl+0wDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNI
QTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRU
cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA9BgNVHSAENjA0MDI
GBWeBDAEDMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYB
BQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEF
BQcwAoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNp
Z25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
AgEADaIfBgYBzz7rZspAw5OGKL7nt4eo6SMcS91NAex1HWxak4hX7yqQB25Oa66WaVBtd14rZxpt
oGQ88FDezI1qyUs4bwi4NaW9WBY8QDnGGhgyZ3aT3ZEBEvMWy6MFpzlyvjPBcWE5OGuoRMhP42TS
MhvFlZGCPZy02PLUdGcTynL55YhdTcGJnX0Z2OgSaHUQTmXhgRX+fajIilPnmmv8Av4Clr6Xa9So
NHltA04JRiCu4ejDGFqA94F696jSJ+AUYHys6bnPc0E8JB9YnFCAurPRG8YBJAofUtxnGIHGE0Ei
QTZeXf0nKmVBIXkE3hT4mZx7pH7wrlCr0FV4qnq6j0uaj4oKqFbkdyzb5u+XQe9pPojshnjVzhIR
K53wsGaFP4gSURxWvcThIOyoaKrVDZOdLQZXEz8Anks3Vs5XscjyzFR7pv/3Reik7FaZRTvd5rDW
6foDJOiCwX5p+UnldHGHW83rDvtks1rwgKwuuxvCG3Bkjirl94EImpiugGaRQ7S2Lydxpqzv7Hng
4YQbIIvVMNC7mNrVZPNWdF4/a9yjDt2nJrnRcDK1zvHBXSrAYIycQ6hhhlHS9Y4MRhz35t1du/Y0
IXDB7HBYSvcsrpxtBzXLTd2NCNCtdkwYIl7WTQeoCbZWvo4PbzJBOnPjs1tN4upe9XomxtZkNAwI
OfM=
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
            Write-Output "Certificate Installed"
            exit 0
        } else {
            exit 1
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