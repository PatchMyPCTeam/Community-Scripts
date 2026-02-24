<#
.SYNOPSIS
    Imports the PSAppDeployToolkit code-signing certificate public key into the local machine Trusted Publishers store.
    This certificate is used to sign the PSAppDeployToolkit module.

.NOTES
    FileName:    Import-PSADTTrustedPublisherCertificate.ps1
    Author:      Dan Gough
    Date:        13th February 2026
    
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
$base64Cert = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlIU1RDQ0JUR2dBd0lCQWdJUUN2bGJ0cjZpRElVT21NYjdqcXdJK1RBTkJna3Foa2lHOXcwQkFRc0ZBREJwDQpNUXN3Q1FZRFZRUUdFd0pWVXpFWE1CVUdBMVVFQ2hNT1JHbG5hVU5sY25Rc0lFbHVZeTR4UVRBL0JnTlZCQU1UDQpPRVJwWjJsRFpYSjBJRlJ5ZFhOMFpXUWdSelFnUTI5a1pTQlRhV2R1YVc1bklGSlRRVFF3T1RZZ1UwaEJNemcwDQpJREl3TWpFZ1EwRXhNQjRYRFRJME1Ea3dOVEF3TURBd01Gb1hEVEkzTURrd056SXpOVGsxT1Zvd2dkRXhFekFSDQpCZ3NyQmdFRUFZSTNQQUlCQXhNQ1ZWTXhHVEFYQmdzckJnRUVBWUkzUEFJQkFoTUlRMjlzYjNKaFpHOHhIVEFiDQpCZ05WQkE4TUZGQnlhWFpoZEdVZ1QzSm5ZVzVwZW1GMGFXOXVNUlF3RWdZRFZRUUZFd3N5TURFek1UWXpPRE15DQpOekVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnVENFTnZiRzl5WVdSdk1SUXdFZ1lEVlFRSEV3dERZWE4wDQpiR1VnVW05amF6RVpNQmNHQTFVRUNoTVFVR0YwWTJnZ1RYa2dVRU1zSUV4TVF6RVpNQmNHQTFVRUF4TVFVR0YwDQpZMmdnVFhrZ1VFTXNJRXhNUXpDQ0FhSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnR1BBRENDQVlvQ2dnR0JBTHNuDQpjWktOaDY1ZXJBRFNWSTMzY3FTait0S2dSK1JKSVgya1VBSjUvbnQ3NE5ubFhHNGhGaUk1YXpHTTd5dHJJRGpBDQpXOEJubTZnRkVaQlpsQWlnM1JzWE1TbnJsM1dsengxanlzSE5sbzJBaFdvNjEraDZING9zRGN6Z25TK2xST0R3DQowSVQwVWUwaUhUVFJVcThlUXVHUXpkVStqaC9zblYreEVCZlBqUVZEUjBXeEZYWmZvZlIrUUhzY2V0Mm4ydk03DQp0NFB4bDVic2x5bTIvaVI3WURTV2xJQmJoVGtVOGNOVXp1cWgva3VoNjZhWC9VSEFCWnJ1TVJyWkhOaFVvWUw5DQpEWUZqRFJnMmFpYS82UGJLaWRyWFdtUnc4cStoL0Q3MlBIb0tGTElSZTNISUJHTFJCSFFmVWtVZkpsVUlwTmNPDQphQms0dzFveDQvdkk0RTZjNVhyVWNzS2JaUDV2RDNvVlFUZko3YXFFbmJ5eTNMa0ZjNXJqeTh6ZjRyaW9lYkdYDQpscjZqempRS1hCSjJYRGphVjNtOG9sRDV4SGo2K2EyUUZPNFRJek1ObVQ1MEpUSEd4cjdZRDlxb3U1dG45NWx4DQpXTVZvNVNnc1dnS1dCM3FraFhsZ3ZNek96bUM5aDVXZmhyaXVGeHZJeWxST3JGa2x2VnBQM1p0THlXMnJMd0lEDQpBUUFCbzRJQ0FqQ0NBZjR3SHdZRFZSMGpCQmd3Rm9BVWFEZmc2N1k3K0Y4Umh2ditZWHNJaUdYMFRrSXdIUVlEDQpWUjBPQkJZRUZPUmdsTjBoS25pRzRZV1BYc2xOQzNFeU8rVi9NRDBHQTFVZElBUTJNRFF3TWdZRlo0RU1BUU13DQpLVEFuQmdnckJnRUZCUWNDQVJZYmFIUjBjRG92TDNkM2R5NWthV2RwWTJWeWRDNWpiMjB2UTFCVE1BNEdBMVVkDQpEd0VCL3dRRUF3SUhnREFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQXpDQnRRWURWUjBmQklHdE1JR3FNRk9nDQpVYUJQaGsxb2RIUndPaTh2WTNKc015NWthV2RwWTJWeWRDNWpiMjB2UkdsbmFVTmxjblJVY25WemRHVmtSelJEDQpiMlJsVTJsbmJtbHVaMUpUUVRRd09UWlRTRUV6T0RReU1ESXhRMEV4TG1OeWJEQlRvRkdnVDRaTmFIUjBjRG92DQpMMk55YkRRdVpHbG5hV05sY25RdVkyOXRMMFJwWjJsRFpYSjBWSEoxYzNSbFpFYzBRMjlrWlZOcFoyNXBibWRTDQpVMEUwTURrMlUwaEJNemcwTWpBeU1VTkJNUzVqY213d2daUUdDQ3NHQVFVRkJ3RUJCSUdITUlHRU1DUUdDQ3NHDQpBUVVGQnpBQmhoaG9kSFJ3T2k4dmIyTnpjQzVrYVdkcFkyVnlkQzVqYjIwd1hBWUlLd1lCQlFVSE1BS0dVR2gwDQpkSEE2THk5allXTmxjblJ6TG1ScFoybGpaWEowTG1OdmJTOUVhV2RwUTJWeWRGUnlkWE4wWldSSE5FTnZaR1ZUDQphV2R1YVc1blVsTkJOREE1TmxOSVFUTTROREl3TWpGRFFURXVZM0owTUFrR0ExVWRFd1FDTUFBd0RRWUpLb1pJDQpodmNOQVFFTEJRQURnZ0lCQUtnTkxtLzRwVElIU0x6SWdYbGdhSWpNWHVUaUc1VG14aU81WHBuRDlsaEttaEFFDQpsdGRmOEZjQ1ZPdDJjSWJaRUdqVk9LMTQzK242c3VhVGxNNlVGNEdJMG1qdUEvd0RqQ1NoNWNxY2JKUmFtZjNXDQpLWExudHNSTngrNVpqdUNqMy9GY1Y3aFNGS295M3JWUHBKSWU2UDBPZGtXbTFRTGpxenhTcHptNHNjdFJ5TWRQDQorUmZrYmovY1lhcGcyM3pPNWVjMUFITGpnZ3BHTzI3cmlKeExJcWZRV1YxSWxXL0N1V3owZlVaT3c2R3JlQlVKDQpqZTlzWTJwSEJHVGpGUDc0TkdZRld2SjhaQVY3VmJJOFc3Sy9temc1OUhIWFJ5dFVCMW9wZno1cVFEWk1UZXgvDQpMWFFnR2ZHMDh5TDc3bmNVaTU3ZTdMRzIwQTVBTWpjTkc3UXgvakNyLzVmbFhHTWtCK2RXZWNVL1E3eHdwaEhlDQorK0c2R1pEOWhuMHhiNSsvNENFaEkwM1RybEJyTFhhNEVzSU5jeVQ2b0N1ODFzU3VQTVF1MnNLV3Q0TURyUGFaDQo4b3FoeHQ2OGZPUDBoMUlnQzlwWkpZN0E5M3Faa2NiRm5tWVdUV1BkOFJLVUIzdlN3YjZQN2VGVVkyYzZsTS9xDQpYeERENm5sLzRPZnBxVytHcWVtWmpTYmdHQ1JabE5DeUpBaTBEZlppbDR0U0pmVmxPb241OTcyTHJSakVpL3dYDQpYbGovdTN6T3pHUzRqdnRRU0xBWFVwbGVxV1ZVdHkwUVFNdDhDSlcxaSt2WnI4aXdqeUVPOCtIYlg3czhBdCtoDQpQWk5yNGMzb2cwUHBOWFJTUTBuY1V3M3JiSEpOQmJnOWFMNFlydG5HaStBWFJiQWxyRnp5ek1yN3VqcFcNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg=='

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
