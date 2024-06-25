# Patch My PC Trusted Publisher Certificate Import Script

This PowerShell script imports a Base64-encoded certificate into the Local Machine Trusted Publisher store. It checks if the certificate already exists in the store before attempting to add it.
The certificate is required in the Trusted Publisher certificate store if you are enforcing an AllSigned PowerShell execution policy.

## Script Overview

The script performs the following steps:

1. Converts a Base64-encoded certificate string to a byte array.
2. Creates an X509Certificate2 object from the byte array.
3. Opens the Trusted Publisher store on the Local Machine with ReadWrite permissions.
4. Checks if the certificate already exists in the store.
5. If the certificate does not exist, it adds the certificate to the store.
6. Handles any errors that occur during the process and provides appropriate output messages.

## Usage

1. Save the script to a `.ps1` file, for example, `Import-PMPTrustedPublisherCertificate.ps1`.
2. Run the script using PowerShell. This script can be deployed as a platform script or a proactive remediation in Intune.

### Running the Script

```powershell
.\Import-Certificate.ps1
```
