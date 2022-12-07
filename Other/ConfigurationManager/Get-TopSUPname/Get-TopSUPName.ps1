Function Set-CMDrive {
    <#
    .SYNOPSIS
    Import ConfigMgr module, create ConfigrMgr PS drive and set location to it.
    .DESCRIPTION
    Set current working directory to site code for access to ConfigMgr cmdlets. Some validation is in place to verify the site code marrys up to be of $Server.
    Called by main body.
    #>
    Param(
        [string]$SiteCode,
        [string]$Server,
        [string]$Path
    )

    # Import the ConfigurationManager.psd1 module 
    if (-not(Get-Module ConfigurationManager)) {
        try {
            Import-Module ("{0}\..\ConfigurationManager.psd1" -f $ENV:SMS_ADMIN_UI_PATH)
        }
        catch {
            $Message = "Failed to import Configuration Manager module"
            throw $Message
        }
    }

    try {
        # Connect to the site's drive if it is not already present
        if (-not (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $Server -ErrorAction Stop | Out-Null
        }
        # Set the current location to be the site code.
        Set-Location ("{0}:\" -f $SiteCode) -ErrorAction Stop

        # Verify given sitecode
        if ((Get-CMSite -SiteCode $SiteCode | Select-Object -ExpandProperty SiteCode) -ne $SiteCode) { throw }

    } 
    catch {
        if (-not(Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
            Set-Location $Path
            Remove-PSDrive -Name $SiteCode -Force
        }
        $Message = "Failed to create New-PSDrive with site code `"{0}`" and server `"{1}`"" -f $SiteCode, $Server
        throw $Message
    }

}

##################################### Edit to specify your site code ################################################
[string]$mySiteCode = ''
#####################################################################################################################

Set-CMDrive -SiteCode $mySiteCode
((Get-CMSoftwareUpdatePointComponent).Props | Where-Object PropertyName -eq "DefaultWSUS").Value2