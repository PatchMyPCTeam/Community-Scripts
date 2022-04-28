# When set to $true, the script will import the certificate into the appropriate stores if needed
# When set to $false, the script simply validates that the certificate is present in the needed stores, and returns a boolean
$Remediate = $true

# See function help for instructions on getting the Thumbprint
$CodeSigningCertificateThumbprint = '6f474206bcbb391bb82ba9e5dc0302def37aebbe'

# See function help for instructions on getting the the Encoded Cert String
$EncodedCertString = 'MIIFNzCCBB+gAwIBAgIQBTCLdqwuFbKXIPtDlfZfODANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS4wLAYDVQQDEyVEaWdpQ2VydCBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQS0xMB4XDTE5MDMxOTAwMDAwMFoXDTIyMDMyMzEyMDAwMFowgYIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEXMBUGA1UEBxMOUmVkd29vZCBTaG9yZXMxGzAZBgNVBAoTEk9yYWNsZSBDb3Jwb3JhdGlvbjETMBEGA1UECxMKVmlydHVhbGJveDEbMBkGA1UEAxMST3JhY2xlIENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtqeTgikxn1Dwcv2BY6K+LyCOciwaMraBGXkYVbhdOSkyySP5EUm798iHgU1cj/yKS1e2c0YOJnVZlTeAzyGZp9TiVO4HPNO2Q0cNwsNI8uLRChzfD0BqKvmhZyNC/shn8btp4HJ2VeaUiHzl+B7419nUXcL1gqW1Kpo1Jow98BHx59+TR90/47cR5C+6SDbjEcY2qVWmqN1QQmQtmKxFtuPRx6KQ0SRDwpDZUcqdaLgFAwQxOrMCYDePRglf57KJhJlL4KevHOw3HutKIm/XlikyWSgDdZEzt4Yzy4GZeYyD2AYG7Pk4jSe5f4/TT5V54pz7EhrVPp1WhPwPTS/tGwIDAQABo4IBuTCCAbUwHwYDVR0jBBgwFoAUe2jOKarAF75JeuHlP9an90WPNTIwHQYDVR0OBBYEFFgKRlPhddNuWHAgJkHhRvQy83XOMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzBtBgNVHR8EZjBkMDCgLqAshipodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vYXNzdXJlZC1jcy1nMS5jcmwwMKAuoCyGKmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9hc3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCBggYIKwYBBQUHAQEEdjB0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTAYIKwYBBQUHMAKGQGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENvZGVTaWduaW5nQ0EtMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQUFAAOCAQEAPOD9kFcXdfjc5nfZeM2NJ3CSfXnxPlfQAT5Vq5CKJpyYS19MmzNMx9ejcCuhNs0xtAQ5CEx8IbhWBwFBaVQOMMKbcDxYH862qqwicxUHGE33PlrxDlonrggO6TmqL8t8ihbukfVAFeWIOwJn1Ng9YTVJLRhFeifqP2vzn66SA/6I2wGHP0m3kJi/nnrE/S9Qzu7dv+2xFeZoIeeFZ1skOxmYQi0xuzC+M5iSziFD3tr5BJa9Rvl1Uc28SVtqRS53qDSv6fn1LRhFns4WUZadZtb76Gij61pEPzzvppViVwqbGAC66BhscTdm4ZYFCZazK9fn7/xxnBhZeEkgkWpypQ=='

function Register-CodeSigningCertificate {
    <#
        .SYNOPSIS
            Import a certificate into the Trusted Publishers and Trusted Root cert store
        .DESCRIPTION
            This function is used to validate or import a certificate into both the Trusted Publishers 
            and the Trusted Root certificate store. This is useful when you need to manage a Code Signing
            certificate. The function accepts a 'EncodedCertString' which will be a base64 encoded value
            which equates the the actual certificate file. This is used to allow for the script to be used
            without provided additional files. 

            The main use case is for use in a Configuration Item within Configuration Manager.
        .PARAMETER Remediate
            A boolean that determines if the certificate will be imported if not found.
        .PARAMETER CodeSigningCertificateThumbprint
            The thumbprint of the certificate which will be useed to find the certificate in the
            two certificate stores. The 'Thumbprint' of a certificate can be retrieved from the details
            tab of the properties of a certificate.
        .PARAMETER EncodedCertString
            A string that is a base64 represntation of the certificate file. This can be retrieved with the
            below code snippet where ExportedCert.cer is your Code Signing certificate file, and is located.
            in the directory where the command is being ran from.

            Set-Clipboard -Value ([System.Convert]::ToBase64String((Get-Content -Path .\ExportedCert.cer -Encoding Byte)))

            Note: You don't need to have the Private Key marked as exportable to do this.
        .EXAMPLE
            C:\PS>
            Example of how to use this cmdlet
        .EXAMPLE
            C:\PS>
            Another example of how to use this cmdlet
        .NOTES
            FileName:    Register-CodeSigningCertificate.ps1
            Author:      Cody Mathis
            Contact:     @CodyMathis123
            Created:     2020-05-11
            Updated:     2020-05-11
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [bool]$Remediate,
        [Parameter(Mandatory = $true)]
        [string]$CodeSigningCertificateThumbprint,
        [Parameter(Mandatory = $true)]
        [string]$EncodedCertString
    )
    # A hashtable of the targeted certificate stores, and the result of searching them
    $CertStoreSearchResult = @{
        TrustedPublisher = $false
        Root             = $false
    }

    foreach ($CertStoreName in @("TrustedPublisher")) {
        $CertStore = [System.Security.Cryptography.X509Certificates.X509Store]::new($CertStoreName, "LocalMachine")
        $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        switch ($CertStore.Certificates.Thumbprint) {
            $CodeSigningCertificateThumbprint {
                $CertStoreSearchResult[$CertStoreName] = $true
            }
        }
        $CertStore.Close()
    }

    foreach ($Result in $CertStoreSearchResult.GetEnumerator()) {
        switch ($Result.Value) {
            $false {
                switch ($Remediate) {
                    $true {
                        $CertStore = [System.Security.Cryptography.X509Certificates.X509Store]::new($Result.Key, "LocalMachine")
                        $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                
                        $CertificateByteArray = [System.Convert]::FromBase64String($EncodedCertString)
                        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $Certificate.Import($CertificateByteArray)
                    
                        $CertStore.Add($Certificate)
                        $CertStore.Close()
                    }
                    $false {
                        return $false
                    }
                }   
            }
        }
    }

    return $true
}

Register-CodeSigningCertificate -Remediate $Remediate -CodeSigningCertificateThumbprint $CodeSigningCertificateThumbprint -EncodedCertString $EncodedCertString