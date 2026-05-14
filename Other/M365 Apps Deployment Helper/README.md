
# Microsoft 365 Apps Deployment Helper

PowerShell tool to automate packaging Microsoft 365 Apps for deployment using an Office configuration XML.

## Features
- Parses Office configuration XML (from [config.office.com](https://config.office.com))
- Validates Office version/channel (via Microsoft API)
- Downloads required setup files
- Generates output for Patch My PC Cloud Custom Apps

## Usage

### Online Mode (Recommended)
Creates a lightweight package (~200 MB) with:
- setup.exe
- install.xml & uninstall.xml
- Office content streamed from Microsoft CDN during install

**Example:**
```
./Invoke-M365AppsHelper.ps1 -ConfigXML "C:\Configs\Enterprise-Office365.xml" -OnlineMode
```

### Offline Mode
Downloads full Office data files (~3–4 GB), compresses to Office.zip, and generates PreScript.ps1 required for extraction during deployment.

**Example:**
```
./Invoke-M365AppsHelper.ps1 -ConfigXML "C:\Configs\Enterprise-Office365.xml"
```

Use only if devices cannot access the Office CDN or require fully offline deployment (files will be present in IMECache).

## Version Validation
- XML with Version: validated against Microsoft API
- No Version: latest available version is used

## Output Location
- Windows: `%APPDATA%\M365AppsHelper\Packages`
- macOS: `~/Documents/M365AppsHelper/Packages`
- Override: `-BasePath "C:\CustomPath"`

## Requirements
- PowerShell 7+
- Internet connectivity
- XML from [config.office.com](https://config.office.com)

## Notes
- This tool creates deployment packages, not ongoing Office updates
- Manage Office updates via [config.office.com](https://config.office.com)