# Extract-Zip.ps1

## Overview

A pre-script for use with [Patch My PC](https://patchmypc.com/) deployments that automatically extracts one or more zip archives from the script's own directory into the current working directory at runtime.

The primary use case is working around PMPC's per-deployment file count limitation. Instead of deploying many individual files, bundle them into a zip alongside this pre-script. The pre-script extracts the contents before the main installer runs, so the installer sees a fully populated directory.

---

## Why Use This?

Patch My PC Cloud deployments and app migration scenarios have a limit on the number of files that can be included in a single deployment package (1000). When your application payload exceeds that limit, zip the extra files and let this script handle extraction at deploy time.

---

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-Name` | No | *(auto-detect)* | Name of a specific zip to extract. If omitted, all `.zip` files in the script directory are extracted. |
| `-LogPath` | No | `$env:TEMP` | Directory where the log file is written. Created automatically if it doesn't exist. |
| `-LogName` | No | `ZipExtractor-PreScript_yyMMdd-HHmm.log` | Log file name. Timestamped by default to avoid collisions across runs. |

---

## Behaviour

1. Resolves the working directory from `$PSScriptRoot` (the folder the script lives in). Falls back to `Get-Location` if invoked interactively from a console.
2. If `-Name` is provided, targets that specific zip. If not, all `.zip` files in the directory are queued.
3. Each zip is extracted in turn using `Expand-Archive -Force`, which safely overwrites any existing files.
4. A before/after file snapshot is taken per zip so the log reports only newly extracted files, not pre-existing ones.
5. Exits with code `1` if any extraction fails, which surfaces as a pre-script failure.

---

## Logging

Logs are written in **CMTrace format** and can be opened directly in CMTrace or the [CMTrace log viewer built into Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/support/cmtrace).

**Default log location:** `$env:TEMP\ZipExtractor-PreScript_yyMMdd-HHmm.log`

---

## PMPC Setup

**Patch My PC Cloud**
1. Upload your `.zip` archive(s) using the **Extra Files** feature in the PMPC Cloud Publisher.
2. Set `Extract-Zip.ps1` as the **Pre-Install Script**.
3. No parameters are needed in typical use, the script auto-detects all zips in its directory.
4. To target a specific zip only, pass the `-Name` parameter in the script arguments field.
 
```
-Name "MyPayload.zip"
```

**Patch My PC Publisher**
1. Upload your `.zip` archive(s) using the **Additional Files** section under the **custom pre/post scripts** feature.
2. Set `Extract-Zip.ps1` as the **Pre-Install Script**.
3. No parameters are needed in typical use, the script auto-detects all zips in its directory.
4. To target a specific zip only, pass the `-Name` parameter in the publisher script argument field. Quotes must be escaped with a backslash:
 
```
-Name \"MyPayload.zip\"
```