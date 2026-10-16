# Clear-AcrobatMSPCache

## Synopsis

Removes superseded/obsoleted cached Adobe Acrobat MSP files from `C:\Windows\Installer`.

Created on:   2026-10-16  
Created by:   Dan Gough @PatchMyPC  
Filename:     Clear-AcrobatMSPCache.ps1  
Version:      1.0  

## Description

When Adobe Acrobat installs updates (either via the EXE or MSP), superseded MSP files remain in `C:\Windows\Installer`, taking up valuable disk space. These patches are over 600MB each now, resulting in several GBs of wasted space.

This script looks up which patches are installed for all known Adobe Acrobat product codes and removes any cached patches that have been superseded, keeping only those that are installed (i.e. the latest).

## How it works

1. Checks whether a Windows Installer operation is in progress (the `Global\_MSIExecute` mutex). If so, the script exits without making changes, as patch states are unreliable mid-transaction.
2. Builds a list of every cached MSP that is currently **applied** to any product on the machine. These files are never deleted, even if they are also registered as superseded against an Acrobat product.
3. For each known Adobe Acrobat / Reader product code that is installed, enumerates all registered patches via the `WindowsInstaller.Installer` COM object and reports each one with its state, install date and cached package path.
4. Patches in the **Applied** or **Registered** state are kept.
5. Patches in the **Superseded** or **Obsoleted** state have their cached MSP deleted, provided that:
   - The cached package path is known
   - The file is an `.msp` located directly in `C:\Windows\Installer`
   - The file is not the cached package of a patch still applied to any product
6. Deletions are retried up to 6 times, 5 seconds apart, as a freshly superseded MSP can be briefly locked (e.g. by antivirus scanning after the update).
7. Reports the total disk space reclaimed.

Only the cached MSP files are removed. The patch registration in Windows Installer is left intact, so the installed product and its current patch level are unaffected.

## Supported products

The script contains a list of known product codes, covering:

- Adobe Acrobat Reader x86 (MUI and language-specific builds)
- Adobe Acrobat Reader x64 (MUI and language-specific builds)
- Adobe Acrobat Pro x86 / x64 MUI
- Adobe Acrobat 2020 Classic x86 MUI
- Adobe Acrobat Reader 2020 Classic x86 MUI
- Adobe Acrobat 2024 x64 MUI

Additional product codes can be added to the `$products` table in the script if required.

## Using with other products

While this approach could be used for apps other than Adobe Acrobat, take care before extending it to other products or making the script generic to handle all MSP patches:

- Some patches are designed to be uninstallable, allowing a rollback to a previous version. Removing their superseded cached MSPs can break that rollback. Acrobat patches are not removable.
- Some patches rely on previous patches being cached for uninstall or repair operations. Acrobat patches are always cumulative and the base MSI is rarely updated, so only the latest patch is needed.

## Requirements

- Windows PowerShell 3.0 or later
- Administrator rights (or SYSTEM) to delete files from `C:\Windows\Installer`. When run without administrator rights, the script will still report what it finds but will not delete anything.

## Usage

### Patch My PC post-install script

Add `Clear-AcrobatMSPCache.ps1` as a post-install script for your Adobe Acrobat / Reader updates (and/or base installs) in Patch My PC. Each time a new Acrobat patch is applied, the previously cached patch becomes superseded and will be removed by the script.

### Standalone

Preview what would be deleted without making any changes:

```powershell
.\Clear-AcrobatMSPCache.ps1 -WhatIf
```

Remove superseded cached MSPs, with additional detail on which product codes are checked:

```powershell
.\Clear-AcrobatMSPCache.ps1 -Verbose
```

## Parameters

- **WhatIf**: Shows which cached MSP files would be deleted, and their size, without deleting them.
- **Confirm**: Prompts for confirmation before each deletion.
- **Verbose**: Outputs each product code checked, including those that are not installed.

## Exit codes

| Exit code | Meaning |
|-----------|---------|
| 0 | Completed successfully, or exited early because a Windows Installer operation was in progress |
| 1 | One or more superseded cached MSPs could not be deleted |
