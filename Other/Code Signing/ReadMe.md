# Patch My PC Trusted Publisher Certificate Import Scripts

## Overview

These PowerShell scripts import Patch My PC code-signing certificates into the Local Machine Trusted Publishers certificate store.

The certificates may be required when enforcing an `AllSigned` PowerShell execution policy, enabling script signature checking for Intune Win32 apps, or using application control technologies such as Windows Defender Application Control (WDAC), AppLocker, or similar controls.

Patch My PC uses separate code-signing certificates for different signed components, including:

- Intune detection and requirement scripts
- Patch My PC helper scripts used by certain catalog applications
- The PSAppDeployToolkit module

## Repository structure

The code-signing certificate scripts are organized by signed component and certificate generation.

```text
Code Signing/
├─ Patch My PC Apps/
│  ├─ Current/
│  │  ├─ Import-PMPCAppsTrustedPublisherCertificate.ps1
│  │  ├─ PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1
│  │  └─ PatchMyPCAppsTrustedPublisherCertificate.cer
│  └─ Archived/
│     └─ 2023-2026/
│        ├─ Import-PMPCAppsTrustedPublisherCertificate.ps1
│        ├─ PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1
│        └─ PatchMyPCAppsTrustedPublisherCertificate.cer
├─ Patch My PC Cloud/
│  └─ Current/
│     ├─ Import-PMPCCloudTrustedPublisherCertificate.ps1
│     ├─ PMPCCloudTrustedPublisherCertificate_HealthScript_Detection.ps1
│     └─ PatchMyPCCloudTrustedPublisherCertificate.cer
├─ PSADT/
│  └─ Current/
│     ├─ Import-PSADTTrustedPublisherCertificate.ps1
│     ├─ PSADTTrustedPublisherCertificate_HealthScript_Detection.ps1
│     └─ PSADTTrustedPublisherCertificate.cer
└─ ReadMe.md
```

Use the files in the relevant `Current` folder for newly signed Patch My PC content.

Use the files in the `Archived` folders only when devices need to continue trusting content signed with a previous Patch My PC certificate.

## Current and archived certificates

Use the scripts and certificate files from the relevant `Current` folder for newly signed Patch My PC content.

Archived certificates are retained because customers may still have previously deployed applications, scripts, or modules that were signed with an earlier Patch My PC certificate.

If you are implementing `AllSigned`, WDAC, AppLocker, or similar controls after applications have already been deployed, some existing deployed content may have been signed with a previous Patch My PC certificate. In that instance, you may also need to deploy the relevant archived certificate from the corresponding `Archived` folder.

Previously signed scripts are timestamped, so they are not expected to fail simply because the signing certificate expires. Archived certificates are provided for environments that still need to trust the signer used for previously signed content.

## Available files

Each certificate folder may include:

- An import script
- A proactive remediation detection script
- A `.cer` file containing the public code-signing certificate
- A README file with certificate-specific details, where applicable

## Certificate use cases

### Intune detection and requirement scripts

**Folder:** `Patch My PC Cloud/Current`  
**Import script:** `Import-PMPCCloudTrustedPublisherCertificate.ps1`  
**Detection script:** `PMPCCloudTrustedPublisherCertificate_HealthScript_Detection.ps1`  
**Certificate file:** `PatchMyPCCloudTrustedPublisherCertificate.cer`

Installs the certificate used to sign Intune detection and requirement scripts for Win32 applications published through Patch My PC Cloud.

This certificate allows Intune detection and requirement scripts to run in environments enforcing an `AllSigned` PowerShell execution policy or other controls that require the signer to be trusted.

### Patch My PC helper scripts

**Folder:** `Patch My PC Apps/Current`  
**Import script:** `Import-PMPCAppsTrustedPublisherCertificate.ps1`  
**Detection script:** `PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1`  
**Certificate file:** `PatchMyPCAppsTrustedPublisherCertificate.cer`

Installs the certificate used to sign required and recommended pre/post helper scripts for certain applications in the Patch My PC catalog.

These helper scripts perform tasks such as stopping processes, uninstalling older software versions, or configuring application behavior during deployment.

### PSAppDeployToolkit module

**Folder:** `PSADT/Current`  
**Import script:** `Import-PSADTTrustedPublisherCertificate.ps1`  
**Detection script:** `PSADTTrustedPublisherCertificate_HealthScript_Detection.ps1`  
**Certificate file:** `PSADTTrustedPublisherCertificate.cer`

Installs the certificate used to sign the PSAppDeployToolkit module included with deployments that use Modern branding or PSADT-based functionality.

This certificate allows the PSAppDeployToolkit module to be imported successfully in environments that require signed PowerShell content to come from a trusted publisher.

## How the import scripts work

The import scripts perform the following steps:

1. Convert the Base64-encoded certificate string to a byte array.
2. Create an `X509Certificate2` object from the byte array.
3. Open the Local Machine Trusted Publishers certificate store with read/write permissions.
4. Check whether the certificate already exists in the store.
5. If the certificate does not exist, add it to the store.
6. Handle any errors and provide output messages.

## How the detection scripts work

The detection scripts are intended for use with Intune remediation scripts.

The detection scripts perform the following steps:

1. Convert the Base64-encoded certificate string to a byte array.
2. Create an `X509Certificate2` object from the byte array.
3. Open the Local Machine Trusted Publishers certificate store.
4. Check whether the certificate already exists in the store.
5. If the certificate does not exist, exit with code `1` to indicate remediation is required.
6. If the certificate exists, write output and exit with code `0` to indicate remediation is not required.

## Deployment methods

### Method 1: Intune platform script or manual execution

You can deploy the import scripts as Intune platform scripts or run them manually with PowerShell.

Example:

```powershell
.\Import-PMPCCloudTrustedPublisherCertificate.ps1
.\Import-PMPCAppsTrustedPublisherCertificate.ps1
.\Import-PSADTTrustedPublisherCertificate.ps1
```

When using Intune platform scripts, select the import script that matches the certificate you want to deploy.

### Method 2: Intune remediation script

Use the detection script and matching import script for the certificate you want to deploy.

#### Intune detection and requirement scripts

- **Detection script:** `PMPCCloudTrustedPublisherCertificate_HealthScript_Detection.ps1`
- **Remediation script:** `Import-PMPCCloudTrustedPublisherCertificate.ps1`

#### Patch My PC helper scripts

- **Detection script:** `PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1`
- **Remediation script:** `Import-PMPCAppsTrustedPublisherCertificate.ps1`

#### PSAppDeployToolkit module

- **Detection script:** `PSADTTrustedPublisherCertificate_HealthScript_Detection.ps1`
- **Remediation script:** `Import-PSADTTrustedPublisherCertificate.ps1`

## Requirements

- Administrative privileges to modify the Local Machine certificate store.
- Windows PowerShell 5.1 or later.
- A PowerShell execution policy or application control configuration that allows the import or remediation script itself to run.

## Notes

- Use the `Current` folders for newly signed Patch My PC content.
- Use the `Archived` folders only when devices need to continue trusting content signed with a previous Patch My PC certificate.
- The `.cer` files are provided as an alternative way to obtain the public certificate.
- The import scripts add the selected certificate to the Local Machine Trusted Publishers certificate store.
- The detection scripts are intended for use with Intune remediation scripts.
