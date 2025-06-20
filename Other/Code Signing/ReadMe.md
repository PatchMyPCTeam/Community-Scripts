# Patch My PC Trusted Publisher Certificate Import Scripts

## Overview

These PowerShell scripts import Base64-encoded certificates into the Local Machine Trusted Publisher store. The certificates are required in the Trusted Publisher certificate store if you are enforcing an AllSigned PowerShell execution policy. These scripts are designed to work with Patch My PC Cloud and Patch My PC catalog applications, ensuring that detection, requirement, and pre/post deployment scripts can run without issues in environments with strict PowerShell execution policies.

## Available Scripts

There are two scripts available:

> ⚠️**IMPORTANT**  
> If you're using Patch My PC Cloud and have an `AllSigned` PowerShell execution policy in place, you may need to deploy **both certificates**. One is required for **detection/requirement scripts**, and the other for **pre/post deployment scripts** used with some applications in the Patch My PC catalog.
  
- **`Import-PMPCCloudTrustedPublisherCertificate.ps1`**  
  Installs the certificate used to sign **Intune detection and requirement scripts** for Win32 applications published through Patch My PC Cloud.  
  This certificate ensures that app detection and requirement logic can run in environments enforcing an `AllSigned` PowerShell execution policy.

- **`Import-PMPCAppsTrustedPublisherCertificate.ps1`**  
  Installs the certificate used to sign **required and recommended pre/post scripts** for certain applications in the Patch My PC catalog.  
  These scripts perform tasks like stopping processes, uninstalling older versions, or configuring app behavior during deployment.
  This certificate ensures that PMPC defined pre/post scripts can run in environments enforcing an `AllSigned` PowerShell execution policy.

## How the Scripts Work

Both scripts perform the following steps:

1. Convert a Base64-encoded certificate string to a byte array
2. Create an X509Certificate2 object from the byte array
3. Open the Trusted Publisher store on the Local Machine with ReadWrite permissions
4. Check if the certificate already exists in the store
5. If the certificate does not exist, add the certificate to the store
6. Handle any errors that occur during the process and provide appropriate output messages

## Deployment Methods

### Method 1: Intune Platform Script or Manual Execution

You can deploy these scripts as Intune platform scripts or run them manually via PowerShell.

#### Usage
1. Save the desired script to a `.ps1` file
2. Deploy as a platform script in Intune, or run manually using PowerShell:

```powershell
.\Import-PMPCCloudTrustedPublisherCertificate.ps1
.\Import-PMPCAppsTrustedPublisherCertificate.ps1
```

### Method 2: Proactive Remediation

#### For the Patch My PC Cloud Certificate
- **Detection Script**: `PMPCCloudTrustedPublisherCertificate_HealthScript_Detection.ps1`
- **Remediation Script**: `Import-PMPCCloudTrustedPublisherCertificate.ps1`

#### For the Patch My PC Apps Certificate
- **Detection Script**: `PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1`
- **Remediation Script**: `Import-PMPCAppsTrustedPublisherCertificate.ps1`

#### Script Overview

The detection scripts (`PMPCCloudTrustedPublisherCertificate_HealthScript_Detection.ps1` and `PMPCAppsTrustedPublisherCertificate_HealthScript_Detection.ps1`) perform the following steps:

1. Converts a Base64-encoded certificate string to a byte array
2. Creates an X509Certificate2 object from the byte array
3. Opens the Trusted Publisher store on the Local Machine with ReadWrite permissions
4. Checks if the certificate already exists in the store
5. If the certificate does not exist, it exits the script with exit code 1 (indicating remediation is required)
6. If the certificate is already installed, it exits the script with a STD output stream and exit code 0 (indicating remediation is not required)

The remediation scripts (`Import-PMPCCloudTrustedPublisherCertificate.ps1` and `Import-PMPCAppsTrustedPublisherCertificate.ps1`) perform the following steps:

1. Converts a Base64-encoded certificate string to a byte array
2. Creates an X509Certificate2 object from the byte array
3. Opens the Trusted Publisher store on the Local Machine with ReadWrite permissions
4. Checks if the certificate already exists in the store
5. If the certificate does not exist, it adds the certificate to the store
6. Handles any errors that occur during the process and provides appropriate output messages

## Requirements

- PowerShell execution policy that allows script execution
- Administrative privileges to modify the Local Machine certificate store
- Windows PowerShell 5.1 or later