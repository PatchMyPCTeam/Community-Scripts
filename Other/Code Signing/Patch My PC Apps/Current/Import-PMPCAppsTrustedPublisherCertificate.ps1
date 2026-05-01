<#
.SYNOPSIS
    Imports the Patch My PC code-signing certificate public key into the local machine Trusted Publishers store.
    This certificate is used to sign required and recommended pre/post scripts for certain applications in the Patch My PC catalog.

.NOTES
    FileName:    Import-PMPCAppsTrustedPublisherCertificate.ps1
    Author:      Ben Whitmore
    Date:        1st May 2026
    
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
MIIHyTCCBbGgAwIBAgIQCUGFLDEub3esx3RE1rIuRjANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTI2MDMxMTAwMDAwMFoX
DTI3MDQzMDIzNTk1OVowgdExEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMI
Q29sb3JhZG8xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRQwEgYDVQQFEwsyMDEzMTYz
ODMyNzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRQwEgYDVQQHEwtDYXN0bGUgUm9j
azEZMBcGA1UEChMQUGF0Y2ggTXkgUEMsIExMQzEZMBcGA1UEAxMQUGF0Y2ggTXkgUEMsIExMQzCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKYWuaFOfSJ2iMnt3nVgLc4mOcOO1Z3+7WIa
0qv7/rVcMNDS6+u3nLN3T75wfiEgVG8jleToh7oZa5H8MiI1mEweeZVTHUv/1eRQen8oDB3CR5i1
OfoPKFypvGKV3jZCZJhoKhPPm2nP32JmpxqtBDxzzmP/o4y3fXaKLFkP84FwaiSmSWWeTK9CedeJ
vj6Fe0Ku3KiZFNTznsl+Q9kpR0cqTxYSU+L0+0geOhag1CRMgVR6o424AOBVxOFrtxAqAemFwqGp
lP4YcgI3IeIvt5wGs0aCjH1ml3ZduXzjla9etvIjCnFvBXryewtOXE0Dt9pcQN1Iy7i6rA0sTyFw
RR8RO8BnQDXGqcWsREU91dDTF+Uq5lVIsNqTmZgqlvoKZxGUKsGPxJePs0zVA8RPExuxaSeeYXGF
yP+YGQMhN0FekEmdIoHbEvDMLx5lOqVhDuAOqghwQAm/891IMhVFsIH1PzOIuYhgEAyMpjW08zIw
j6Qbj6kKFp2wPrji0qXPNRfIe/C9sc67PCu/CrxSwysbbvBADq5bidmuBpiZVstNKKRiFNVzNXu3
FO4ePw7pbYTzstUvpM+e0umRcLVPJEneOoFcMr4yPO9pCpw6APARM1NGQsE4yzLcHIKEIp9bpl7i
t2bOoErk4+KiEnctPsqnZbMmr0ZfjwLrK0D1bAYPAgMBAAGjggICMIIB/jAfBgNVHSMEGDAWgBRo
N+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUSwvURs71qBAFSCCp+wDYicgjpVAwPQYDVR0g
BDYwNDAyBgVngQwBAzApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw
DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+G
TWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNB
NDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGln
aUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDCBlAYIKwYB
BQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEF
BQcwAoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNp
Z25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
AgEAH5lNvUFVkHQWIby+gePVfooOQdPaJp7IG3NyU5gamREO5swPO2gSH+RKVhjhoez6Lsg4AvQk
tpYFo3F/j4E5TlNT/pMGwGqs3DeT+R5JZeGQobxMbqBs6TcWW8LVVqKj0zAvqQ4IhyeUhfD4MiCp
7jEVt7dRhvp3wtBmqkcIH3zJPufM6CJop8TwHiV2oyv9k8wVnVFXWTdUbyWoilkXZnaFe97mBxEy
f++iEL81Bi41Oyc7OK4UcD7Dh3QECF1E+6QUxG81ykpha1+/AVb0rPxiUl9cpWzs/TfgZjTwxY/z
0ZI0vyM/Ut01xrFPVXBqjaR8OxOAzjgGjcTykbSd7UoJP2MEeaL9SKRlrNeSieD29+DsuZaqhfkF
5JGWyaDhqWShmos9uwG5PEYf+4FOX6iZquQD4cVlhzOBVomrcYH+e97vPmgmRMp+hGZX66eDNswv
jazFvUZclDIDe3rDwHDhvvrXzyprFmIrhnSZkCQzle3sjVSCVHojUQV3G+BliKhUEf/h4KjGLCAB
3eenuyTY4c04ttjkst6mL9us+hnhmJbTJy4k/H3XMVJvJJgxtDWsd/XqUPYM/0N1r+g3rJ53zbmB
htqvTQ/NwOOqU9nOz4IiZiobTnmd9kPPCKn4G7T0BpPMexg168qQ1vbUjTBN1Zlq5F1VgdSPepuU
CXA=
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
            Write-Output "Patch My PC Apps certificate already exists in the Local Machine Trusted Publisher store"
        }
        else {
            # Add the certificate to the store
            $store.Add($cert)
            Write-Output "Patch My PC Apps certificate successfully imported into the Local Machine Trusted Publisher store"
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