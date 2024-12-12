<#
.SYNOPSIS
    Script to digitally sign a file, apply a timestamp using a trusted timestamp server, and extract metadata from the timestamp certificate.

.DESCRIPTION
    This script performs the following tasks:
    - Digitally sign a specified file by generating a self-signed code-signing certificate (certificate is saved as a pfx).
    - Applies a trusted timestamp to the signed file using a timestamp server (e.g. DigiCert TSA).
    - Extracts and saves the certificates used by the timestamp server for validation.
    - Extracts and displays the CRL (Certificate Revocation List) distribution points from the timestamp server's certificates.
    - Ensures the integrity and authenticity of signed files for future verification.
    - Extracts additional metadata from the timestamp response, including certificate details, hash algorithm, policy OID, and serial number.

.NOTES
    Author: Ben Whitmore
    Created: 2024-12-07
    Filename: Test-TimeStamping.ps1
---------------------------------------------------------------------------------
REQUIREMENTS

    BOUNCY CASTLE LIBRARY
    - The BouncyCastle library is required for ASN.1 parsing and timestamp-related cryptographic operations.
      Download the BouncyCastle.Cryptography NuGet package from: https://www.nuget.org/packages/BouncyCastle.Cryptography
    - Place the BouncyCastle DLL file (e.g., BouncyCastle.Crypto.dll) in the same directory as the script or specify its path.

    SIGNTOOL
    - **signtool.exe** is a part of the Windows SDK and is required for signing and timestamping files.
      You can download the **Windows SDK** from:
      https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/
      
      After installing the SDK, you can locate **signtool.exe** in the following directory:
      `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x86\signtool.exe`
      or
      `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe`
      
      Ensure you have **signtool.exe** accessible in your script directory, or specify the full path to it in the `$SignTool` parameter.

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.PARAMETER Path
    The directory where the files will be located and where temporary files (e.g., signed files, timestamp requests, etc.) will be saved. Default is 'C:\temp\timestamp'.

.PARAMETER TimestampServer
    The URL of the timestamp server to use for timestamping the signed file. Default is 'http://timestamp.digicert.com'.

.PARAMETER TimestampCertsFolder
    The folder where the certificates retrieved from the timestamp server will be saved. Default is 'timestamp_certs'.

.PARAMETER OriginalFileName
    The name of the original file that will be signed. Default is 'testfile'.

.PARAMETER SignedFileName
    The suffix added to the original file name for the signed file. Default is '_signed'.

.PARAMETER FileExtension
    The file extension to use for the original and signed file. Default is '.ps1'.

.PARAMETER DummyScriptContent
    The content to be written into the original file. Default is "Write-Host 'Hello, World!'".

.PARAMETER TempPfx
    The name of the temporary PFX file to use for signing. Default is 'temp_cert.pfx'.

.PARAMETER PfxPassword
    The password for the PFX file. Default is '1234'.

.PARAMETER Store
    The certificate store to use for creating and deleting certificates. Can be "CurrentUser" or "LocalMachine". Default is 'CurrentUser'.

.PARAMETER SignTool
    The path to the signtool.exe executable used for signing. Default is 'signtool.exe'.

.PARAMETER Subject
    The subject for the self-signed certificate used for signing. Default is 'CN=TimeStamp Code Signing Test'.

.EXAMPLE
Test-TimeStamping.ps1 -Path "C:\temp\timestamp" -TimestampServer "http://timestamp.digicert.com" -OriginalFileName "myScript" -PfxPassword "mypassword"

This example signs and timestamps a file located in "C:\temp\timestamp" using the DigiCert Timestamp Server and saves the signed file with the name "myScript_signed.ps1".
It generates a self-signed certificate, signs the file, requests a timestamp, and saves relevant certificates and CRLs to the specified directory.

.EXAMPLE
Test-TimeStamping.ps1 -Store "LocalMachine" -OriginalFileName "example" -SignTool "C:\tools\signtool.exe" -Subject "CN=Example Signing"

This example signs the file "example.ps1" located in the current directory with a certificate from the LocalMachine store and uses a specified SignTool location. The file is signed and timestamped, with details logged for review.
#>

[CmdletBinding()]
param (
    [string]$Path = 'C:\temp\timestamptest',
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [string]$TimestampCertsFolder = 'timestamp_certs',
    [string]$OriginalFileName = 'testfile',
    [string]$SignedFileName = '_signed',
    [ValidateSet('.ps1', '.cab')]
    [string]$FileExtension = '.cab',
    [string]$DummyScriptContent = "Write-Host 'Hello, World!'",
    [string]$TempPfx = 'temp_cert.pfx',
    [string]$PfxPassword = '1234',
    [string]$Store = 'CurrentUser',
    [string]$SignTool = 'signtool.exe',
    [string]$Subject = 'CN=TimeStamp Code Signing Test',
    [string]$windowsExplorerPath = "C:\Windows\explorer.exe"
)

# Set verbose preference to enable detailed logging
$VerbosePreference = "Continue"

# Variables
[SecureString]$pfxSecurePassword = (ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText)
[string]$timestampCertsPath = Join-Path -Path $path -ChildPath $TimestampCertsFolder
[string]$originalFilePath = Join-Path -Path $path -ChildPath "$OriginalFileName$FileExtension"
[string]$signedFilePath = Join-Path -Path $path -ChildPath "$OriginalFileName$SignedFileName$FileExtension"
[string]$tempPfxPath = Join-Path -Path $path -ChildPath $TempPfx
[string]$signToolPath = Join-Path -Path $path -ChildPath $SignTool
[string]$tempCertStore = "Cert:\$($Store)\My"

# Check if BouncyCastle.Crypto.dll exists
$bouncyCastleDllPath = Join-Path -Path $path -ChildPath "BouncyCastle.Crypto.dll"
if (-not (Test-Path $bouncyCastleDllPath)) {
    Write-Error "Error: BouncyCastle.Crypto.dll not found at $bouncyCastleDllPath. Please ensure the BouncyCastle library is available."
    exit 1
}
else {
    Write-Verbose "BouncyCastle.Crypto.dll found at $bouncyCastleDllPath"
    Add-Type -Path $bouncyCastleDllPath
}

# Ensure necessary directories exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory | Out-Null
    Write-Verbose "Created directory: $path"
}

if (-not (Test-Path $timestampCertsPath)) {
    New-Item -Path $timestampCertsPath -ItemType Directory | Out-Null
    Write-Verbose "Created directory for timestamp certificates: $timestampCertsPath"
}
else {

    # Clear existing certificates in the folder
    Get-ChildItem -Path $timestampCertsPath -File | Remove-Item -Force
    Write-Verbose "Cleared existing certificates in: $timestampCertsPath"
}

# Create the files with dummy content
foreach ($file in  @("$OriginalFileName", "$OriginalFileName$SignedFileName")) {
    Write-Verbose "Processing file base name: $file"
    $matchingFiles = Get-ChildItem -Path $path -Filter "$file.*" -ErrorAction SilentlyContinue

    if ($matchingFiles) {

        # Remove all matching files
        $matchingFiles | ForEach-Object {
            Write-Verbose "Removing existing file: $($_.FullName)"
            Remove-Item -Path $_.FullName -Force
            Write-Verbose "Removed existing file: $($_.FullName)"
        }
    }
    else {
        Write-Verbose "No files found with base name: $file"
    }

    switch ($FileExtension) {
        '.ps1' {

            # Create a basic script file with dummy content
            try {
                New-Item -Path (Join-Path -Path $path -ChildPath "$file$FileExtension") -ItemType File | Out-Null
                Set-Content -Path (Join-Path -Path $path -ChildPath "$file$FileExtension") -Value $DummyScriptContent
                Write-Verbose "Created script file $file with content: $DummyScriptContent"
            }
            catch {
                Write-Error "Failed to create script file: $_"
                exit 1
            }
        }
        '.cab' {

            try {
                Copy-Item -Path $windowsExplorerPath -Destination (Join-Path -Path $Path -ChildPath "$file.exe") -Force
                Write-Verbose "Copied $windowsExplorerPath to $$path\$file.exe"
            }
            catch {
                Write-Error "Failed to copy $windowsExplorerPath $_"
                exit 1
            }
            
            # Add the file to the CAB using makecab
            try {
                
                # Execute makecab to create the CAB file
                Write-Verbose "Running makecab to include $destinationExplorerPath in the CAB file."
                $sourceFile = "$path\$file.exe"
                $destinationFile = "$path\$file$FileExtension"
                & makecab $sourceFile $destinationFile | Out-Null
            
                # Verify the CAB file was created
                if (-not (Test-Path $destinationFile)) {
                    Write-Error "CAB file was not created. Verify your makecab configuration."
                    exit 1
                }
                Write-Verbose "CAB file created at $destinationFile."
            }
            catch {
                Write-Error "Failed to create the CAB file: $_"
                exit 1
            }
            
            # Clean up temporary files if needed
            try {
                Remove-Item -Path $sourceFile -Force
                Write-Verbose "Cleaned up temporary file: $sourceFile."
            }
            catch {
                Write-Error "Failed to clean up temporary file: $_"
            }
        }
        default {
            Write-Error "Unsupported file extension: $FileExtension"
            exit 1
        }
    }
}

# Generate a code-signing certificate
try {
    # Generate a self-signed certificate for code signing
    $certToCreate = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" `
        -Subject "CN=Test Code Signing Certificate, O=Test Organization, C=US" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeySpec Signature `
        -NotAfter (Get-Date).AddYears(1) `
        -KeyExportPolicy Exportable `
        -Type CodeSigning `
        -FriendlyName "Test Code Signing Certificate"

    # Export the self-signed certificate to a .pfx file
    Export-PfxCertificate -Cert "$tempCertStore\$($certToCreate.Thumbprint)" -FilePath $tempPfxPath -Password $pfxSecurePassword | Out-Null
    Write-Verbose "Self-signed certificate generated and saved to: $tempPfxPath"
}
catch {
    Write-Error "Failed to generate and add the self-signed certificate: $_"
    exit 1
}

# Sign the file using signtool with SHA256
try {

    # Prepare the signtool command with /fd SHA256 for file digest algorithm
    $signToolCmd = "$signToolPath sign /f `"$($tempPfxPath)`" /p `$pfxPassword /t `$TimestampServer /fd SHA256 /v `"$signedFilePath`""
    Write-Verbose "Executing: $signToolCmd"

    # Run the command and capture output
    $signToolOutput = Invoke-Expression $signToolCmd 2>&1

    # Validate output
    if (-not $signToolOutput) {
        throw "SignTool did not return any output. Ensure the command is valid."
    }

    # Filter the output for specific patterns
    $filteredOutput = $signToolOutput | Select-String -Pattern "Issued to:|Expires:|Successfully signed:"
    if ($filteredOutput) {
        $filteredOutput | ForEach-Object { Write-Verbose ($_.Line.TrimStart()) }
    }
    else {
        Write-Verbose "No relevant output found in SignTool execution."
    }

    # Extract error count using regex
    $errorCount = 0
    foreach ($line in $signToolOutput) {
        if ($line -match "Number of errors: (\d+)") {
            $errorCount = [int]$matches[1]
            break
        }
    }

    if ($errorCount -gt 0) {
        throw "SignTool encountered $errorCount errors: $signToolOutput"
    }
    else {
        Write-Verbose "No errors found."
        Write-Verbose "File signed and timestamped successfully."
    }
}
catch {
    Write-Error "An error occurred: $_"
    if ($signToolOutput) {
        Write-Error "SignTool Output: $signToolOutput"
    }
    else {
        Write-Error "No output was captured from SignTool."
    }
    exit 1
}

# Request timestamp from timestamp server using BouncyCastle (for certificates and CRL extraction)
try {

    # Load the signed file content
    $signedContent = [System.IO.File]::ReadAllBytes($signedFilePath)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $fileHash = $sha256.ComputeHash($signedContent)

    # Prepare timestamp request (using BouncyCastle for timestamp interaction)
    $tsq = [Org.BouncyCastle.Tsp.TimeStampRequestGenerator]::new()
    $tsq.SetCertReq($true)
    $tsRequest = $tsq.Generate("2.16.840.1.101.3.4.2.1", $fileHash)  # SHA-256 OID

    # Send timestamp request
    $timestampRequestFilePath = Join-Path -Path $path -ChildPath "timestamp_request.tsq"
    [System.IO.File]::WriteAllBytes($timestampRequestFilePath, $tsRequest.GetEncoded())
    Write-Verbose "Timestamp request saved."

    $responseBytes = Invoke-WebRequest -Uri $TimestampServer -Method Post -Body $tsRequest.GetEncoded() -ContentType "application/timestamp-query"
    $timestampResponseFilePath = Join-Path -Path $path -ChildPath "timestamp_response.tsr"
    [System.IO.File]::WriteAllBytes($timestampResponseFilePath, $responseBytes.Content)
    Write-Verbose "Timestamp response saved."
    
    # Validate timestamp response
    try {
        
        $tsResponse = [Org.BouncyCastle.Tsp.TimeStampResponse]::new($responseBytes.Content)
        $tsResponse.Validate($tsRequest)

        # Test the TimeStampResponse.Status value
        try {
            $status = $tsResponse.Status
            switch ($status) {
                0 {
                    Write-Verbose "Status: 0 - Granted. The request was successfully processed."
                }
                1 {
                    Write-Warning "Status: 1 - Granted with modifications. The request was granted, but with modifications."
                }
                2 {
                    Write-Error "Status: 2 - Rejection. The request was rejected."
                    throw "The timestamp request was rejected by the server."
                }
                3 {
                    Write-Warning "Status: 3 - Waiting. The request is being held for further processing."
                }
                4 {
                    Write-Warning "Status: 4 - Revocation Warning. A certificate revocation is imminent."
                }
                5 {
                    Write-Warning "Status: 5 - Revocation Notification. A certificate has been revoked."
                }
                default {
                    Write-Error "Unknown Status: $status. The status code is not recognized."
                    throw "Unexpected status code received from the timestamp server."
                }
            }
        }
        catch {
            Write-Error "An error occurred while testing the response validity: $_"
            exit 1
        }

    }
    catch {
        Write-Error "Failed to parse or validate timestamp response: $_"
        exit 1
    }

    # Extract the timestamp token from the response
    $timeStampToken = $tsResponse.TimeStampToken

    # Check if the timestamp token is present
    if ($timeStampToken -eq $null) {
        Write-Error "Timestamp token is missing in the response."
    }
    else {
        Write-Verbose "Timestamp token retrieved successfully."
        Write-Verbose "Timestamp Generation Time: $($timeStampToken.TimeStampInfo.GenTime)"
        Write-Verbose "Timestamp Token Serial Number: $($timeStampToken.TimeStampInfo.SerialNumber)"
    }

    # Extract and save certificates used by the timestamp server
    try {
        $certStore = $timeStampToken.GetCertificates()
        $certCollection = $certStore.GetMatches($null)

        Write-Verbose "Saving timestamp certificates to $timestampCertsPath"

        $certIndex = 0
        foreach ($cert in $certCollection) {
            # Generate a unique filename for each certificate
            $certFilePath = Join-Path -Path $timestampCertsPath -ChildPath "timestamp_cert_$certIndex.cer"
        
            # Save the certificate to a file
            $certData = $cert.GetEncoded()
            [System.IO.File]::WriteAllBytes($certFilePath, $certData)
        
            Write-Verbose "Saved timestamp certificate to: $certFilePath"

            $certIndex++
        }

        if ($certIndex -eq 0) {
            Write-Verbose "No certificates were found in the timestamp response."
        }
        else {
            Write-Verbose "Total certificates saved: $certIndex"
        }
    }
    catch {
        Write-Error "Failed to save timestamp certificates: $_"
        exit 1
    }
}
catch {
    Write-Error "Failed to request timestamp and extract CRL distribution points: $_"
    exit 1
}

# Create a PSCustomObject for the signing and timestamp certificate information
$signingDetails = [PSCustomObject]@{
    FilePath            = $signedFilePath
    FileCertSubject     = $certToCreate.Subject
    FileCertIssuer      = $certToCreate.Issuer
    FileCertValidTo     = $certToCreate.NotAfter
    FileTimestampServer = $TimestampServer
}

# Now, extract the timestamp information directly from the signed file
try {

    # Use Get-AuthenticodeSignature to retrieve the signature and timestamp details
    $signature = Get-AuthenticodeSignature -FilePath $signedFilePath

    # Extract timestamp details from the signature
    $timestampInfo = $signature.TimeStamperCertificate

    if ($timestampInfo) {
        Write-Verbose "Timestamp information found in the signature."

        # Add timestamp details to the PSCustomObject
        $signingDetails | Add-Member -MemberType NoteProperty -Name "FileTimestampSubject" -Value $timestampInfo.Subject
        $signingDetails | Add-Member -MemberType NoteProperty -Name "FileTimestampIssuer" -Value $timestampInfo.Issuer
        $signingDetails | Add-Member -MemberType NoteProperty -Name "FileTimestampThumbprint" -Value $timestampInfo.Thumbprint
        $signingDetails | Add-Member -MemberType NoteProperty -Name "FileTimestampValidTo" -Value $timestampInfo.NotAfter
    }
    else {
        Write-Verbose "No timestamp information found in the signature."
        $signingDetails | Add-Member -MemberType NoteProperty -Name "FileTimestamp" -Value "No timestamp information found."
    }
}
catch {
    Write-Error "Failed to extract timestamp information from the signed file: $_"
}

# Add base properties to the object
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampRequestFilePath" -Value $timestampRequestFilePath
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampResponseFilePath" -Value $timestampResponseFilePath
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampServer" -Value $TimestampServer
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampToken" -Value $timeStampToken.GetEncoded()
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampTokenSignerID" -Value $timeStampToken.SignerID.Issuer
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampTokenGenTime" -Value $timeStampToken.TimeStampInfo.GenTime
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampTokenTimeStampHashAlg" -Value $timeStampToken.TimeStampInfo.HashAlgorithm.Algorithm.id
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampTokenPolicy" -Value $timeStampToken.TimeStampInfo.Policy
$signingDetails | Add-Member -MemberType NoteProperty -Name "TimestampTokenSerialNumber" -Value $timeStampToken.TimeStampInfo.SerialNumber.ToString()

# Initialize variables
$allCrlUrls = @()
$certCounter = 0

# Process each certificate in the certCollection
foreach ($cert in $certCollection) {
    $issuerPropertyName = "TimeStampChain$certCounter" + "Issuer"
    $subjectPropertyName = "TimeStampChain$certCounter" + "Subject"

    # Add certificate issuer and subject to the object dynamically
    $signingDetails | Add-Member -MemberType NoteProperty -Name $issuerPropertyName -Value $cert.Issuer
    $signingDetails | Add-Member -MemberType NoteProperty -Name $subjectPropertyName -Value $cert.Subject

    # Extract CRL URLs for the current certificate
    $crlUrlsForCert = @()
    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.GetEncoded())

    foreach ($extension in $x509.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.31') {
            # Extract CRL Distribution Points
            $rawData = $extension.RawData
            $sequence = [Org.BouncyCastle.Asn1.Asn1InputStream]::new($rawData).ReadObject()
            $distributionPoints = [Org.BouncyCastle.Asn1.X509.CrlDistPoint]::GetInstance($sequence)

            foreach ($point in $distributionPoints.GetDistributionPoints()) {
                $generalNames = $point.DistributionPointName.Name
                if ($generalNames -is [Org.BouncyCastle.Asn1.X509.GeneralNames]) {
                    foreach ($name in $generalNames.GetNames()) {
                        if ($name.TagNo -eq 6) {
                            $url = $name.Name.ToString()
                            if ($url -like "http*") {
                                $crlUrlsForCert += $url
                                $allCrlUrls += $url  # Add to the global CRL URL array
                            }
                        }
                    }
                }
            }
        }
    }

    # Add CRL URLs for this certificate to the object dynamically
    $crlUrlsPropertyName = "TimeStampChain$certCounter" + "CrlUrls"
    $signingDetails | Add-Member -MemberType NoteProperty -Name $crlUrlsPropertyName -Value ($crlUrlsForCert -join ', ')

    # Increment the counter for the next certificate
    $certCounter++
}

# Remove the self-signed certificate from the certificate store after exporting
try {
    $tempCertStorePersonal = "$tempCertStore\Personal"
    $certutilFlag = if ($Store -eq "CurrentUser") { "-user" }

    # Prepare the certutil command
    $thumbprint = ($certToCreate.Thumbprint).ToUpper()
    $certutilCmd = "certutil $certutilFlag -delstore My $thumbprint"

    Write-Verbose "Executing: $certutilCmd"
    $certutilOutput = & cmd.exe /c $certutilCmd 2>&1
    Write-Verbose "CertUtil Output: $certutilOutput"
}
catch {
    Write-Error "Failed to remove the certificate: $_"
}

# Display the results from both the signing and timestamping request
$signingDetails | Format-List

# Write all collected CRLs at the end
if ($allCrlUrls.Count -gt 0) {
    Write-Verbose "Collected CRL URL for Firewall exception(s):"
    $allCrlUrls | ForEach-Object { Write-Verbose " - $_" }
}
else {
    Write-Verbose "No CRL URLs were found in the certificate chain."
}

Write-Host ("`nNOTE: The timestamp server information provided above reflects the request details and response from '{0}'" -f $timeStampServer)
Write-Host ("The file '{0}' was signed using the same server, but the timestamp information above came from a seperate request to the same server." -f $SignedFilePath)