BeforeAll {
    $64HKLMMockedARPData = @(
        [PSCustomObject]@{
            DisplayName = '7-Zip 22.01 (x64 edition)'
            DisplayVersion = '21.01.00.0'
            PSChildName = '{23170F69-40C1-2702-2201-000001000000}'
            Publisher = 'Igor Pavlov'
            InstallDate = '20220729'
            QuietUninstallString = ''
            UninstallString = 'MsiExec.exe /I{23170F69-40C1-2702-2201-000001000000}'
            WindowsInstaller = 1
            SystemComponent = ''
        },
        [PSCustomObject]@{
            DisplayName = '7-Zip 22.01 (x64)'
            DisplayVersion = '21.01'
            PSChildName = '7-Zip'
            Publisher = 'Igor Pavlov'
            InstallDate = '20220729'
            QuietUninstallString = '"C:\Program Files\7-Zip\Uninstall.exe" /S'
            UninstallString = '"C:\Program Files\7-Zip\Uninstall.exe"'
            WindowsInstaller = ''
            SystemComponent = ''
        },
        [PSCustomObject]@{
            DisplayName = 'Zscaler'
            DisplayVersion = '4.0.0.80'
            PSChildName = 'Zscaler'
            Publisher = 'Zscaler Inc.'
            InstallDate = '20220729'
            QuietUninstallString = ''
            UninstallString = '"C:\Program Files\Zscaler\ZSAInstaller\uninstall.exe"'
            WindowsInstaller = ''
            SystemComponent = ''
        },
        [PSCustomObject]@{
            DisplayName = 'Zscaler'
            DisplayVersion = '0.0.12179'
            PSChildName = '{FF4D5F84-0CFF-4865-8395-51445340F429}'
            Publisher = 'Zscaler Inc.'
            InstallDate = '20220729'
            QuietUninstallString = ''
            UninstallString = 'MsiExec.exe /X{FF4D5F84-0CFF-4865-8395-51445340F429}'
            WindowsInstaller = 1
            SystemComponent = 1
        }
    )

    Mock Start-Process {}
    Mock Invoke-Expression {}

    function Get-InstalledSoftware {
        # Function defined / used within the script
        # Need to define it before we can mock it with Pester
    }
    Mock Get-InstalledSoftware {
        param($Architecture, $HivesToSearch)
        $64HKLMMockedARPData
    } -ParameterFilter { $Architecture -eq 'x64' -and $HivesToSearch -eq 'HKLM' }
}

Describe 'Uninstall-Software.ps1' {
    it 'will call msiexec.exe for an MSI product' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'msiexec.exe' -and 
            $ProductCode -eq '{23170F69-40C1-2702-2201-000001000000}' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -SystemComponent 0 | Should -InvokeVerifiable
    }

    it 'will call QuietUninstallString for an EXE product' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'C:\Program Files\7-Zip\Uninstall.exe' -and 
            $ArgumentList -eq '/S' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -SystemComponent 0 | Should -InvokeVerifiable
    }

    it 'will not uninstall any software because it could not find any' {
        .\Uninstall-Software.ps1 -DisplayName 'idonotexist' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -SystemComponent 1 | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'will not uninstall any software because multiple are found and -UninstallAll is not used' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'will uninstall both MSI and EXE 7-Zip because the -UninstallAll is used' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -UninstallAll | Should -Invoke -CommandName 'Start-Process' -Times 2
    }

    it 'will only uninstall the non-visible component in ARP' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'msiexec.exe' -and 
            $ProductCode -eq '{FF4D5F84-0CFF-4865-8395-51445340F429}' 
        }
        .\Uninstall-Software.ps1 -DisplayName 'Zscaler' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -SystemComponent 1 | Should -InvokeVerifiable
    }

    it 'will only uninstall the visible component in ARP' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'C:\Program Files\Zscaler\ZSAInstaller\uninstall.exe' -and 
            $ArgumentList -eq '/S' 
        }
        .\Uninstall-Software.ps1 -DisplayName 'Zscaler' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -SystemComponent 0 -AdditionalArguments '/S' | Should -InvokeVerifiable
    }

    it 'will uninstall both MSI and EXE 7-Zip because the -UninstallAll with -AdditionalArguments is used' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'msiexec.exe' -and 
            $ProductCode -eq '{23170F69-40C1-2702-2201-000001000000}' -and 
            $ArgumentList -contains '/FakeParameter' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -UninstallAll -AdditionalArguments '/FakeParameter' | Should -InvokeVerifiable

        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'C:\Program Files\7-Zip\Uninstall.exe' -and 
            $ArgumentList -eq '/S /FakeParameter' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -UninstallAll -AdditionalArguments '/FakeParameter' | Should -InvokeVerifiable
    }

    it 'will uninstall both MSI and EXE 7-Zip because the -UninstallAll with -AdditionalMSIArguments and -AdditionalEXEArguments is used' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'msiexec.exe' -and 
            $ProductCode -eq '{23170F69-40C1-2702-2201-000001000000}' -and 
            $ArgumentList -contains 'MSIRMSHUTDOWN=0' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -UninstallAll -AdditionalEXEArguments '/FakeParameter' -AdditionalMSIArguments 'MSIRMSHUTDOWN=0' | Should -InvokeVerifiable

        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'C:\Program Files\7-Zip\Uninstall.exe' -and
            $ArgumentList -eq '/S /FakeParameter'
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -UninstallAll -AdditionalEXEArguments '/FakeParameter' -AdditionalMSIArguments 'MSIRMSHUTDOWN=0' | Should -InvokeVerifiable
    }

    it 'will verify parameter set validation for -AdditionalArguments, -AdditionalEXEArguments, and -AdditionalMSIArguments' {
        { .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -AdditionalArguments '/FakeParameter' -AdditionalEXEArguments '/FakeParameter' -AdditionalMSIArguments 'MSIRMSHUTDOWN=0' } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
    }
}