BeforeAll {
    Push-Location $PSScriptRoot

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

    Mock Get-ItemProperty -ParameterFilter { $Path -eq 'registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
        $64HKLMMockedARPData
    }

    function Get-ProductState {}
    Mock Get-ProductState {
        5
    }
}

Describe 'Uninstall-Software.ps1' {
    BeforeAll {
        # Use Import-Module on a .ps1 as a bit of 'tricky' to avoid the mandatory paramter but still load the internal functions
        # The script still run but find / do nothing
        Import-Module '.\Uninstall-Software.ps1' -Force
    }

    it 'call msiexec.exe for an MSI product' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'msiexec.exe' -and 
            $ProductCode -eq '{23170F69-40C1-2702-2201-000001000000}' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -SystemComponent 0 | Should -InvokeVerifiable
    }

    it 'call QuietUninstallString for an EXE product' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'C:\Program Files\7-Zip\Uninstall.exe' -and 
            $ArgumentList -eq '/S' 
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -SystemComponent 0 | Should -InvokeVerifiable
    }

    it 'not uninstall any software because it could not find any' {
        .\Uninstall-Software.ps1 -DisplayName 'idonotexist' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -SystemComponent 1 | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'not uninstall any software because multiple are found and -UninstallAll is not used' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'uninstall both MSI and EXE 7-Zip because the -UninstallAll is used' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -UninstallAll | Should -Invoke -CommandName 'Start-Process' -Times 2
    }

    it 'only uninstall the non-visible component in ARP' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'msiexec.exe' -and 
            $ProductCode -eq '{FF4D5F84-0CFF-4865-8395-51445340F429}' 
        }
        .\Uninstall-Software.ps1 -DisplayName 'Zscaler' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -SystemComponent 1 | Should -InvokeVerifiable
    }

    it 'only uninstall the visible component in ARP' {
        Mock Start-Process {} -Verifiable -ParameterFilter { 
            $FilePath -eq 'C:\Program Files\Zscaler\ZSAInstaller\uninstall.exe' -and 
            $ArgumentList -eq '/S' 
        }
        .\Uninstall-Software.ps1 -DisplayName 'Zscaler' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -SystemComponent 0 -AdditionalArguments '/S' | Should -InvokeVerifiable
    }

    it 'uninstall both MSI and EXE 7-Zip because the -UninstallAll with -AdditionalArguments is used' {
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

    it 'uninstall both MSI and EXE 7-Zip because the -UninstallAll with -AdditionalMSIArguments and -AdditionalEXEArguments is used' {
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

    it 'verify parameter set validation for -AdditionalArguments, -AdditionalEXEArguments, and -AdditionalMSIArguments' {
        { .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -AdditionalArguments '/FakeParameter' -AdditionalEXEArguments '/FakeParameter' -AdditionalMSIArguments 'MSIRMSHUTDOWN=0' } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
    }

    it 'validate Split-UninstallString correctly parses UninstallString: <UninstallString>' -TestCases @(
        @{ UninstallString = '"C:\Program Files\7-Zip\Uninstall.exe" /S /abc /whatever';         Expected = @('C:\Program Files\7-Zip\Uninstall.exe', '/S /abc /whatever') },
        @{ UninstallString = 'C:\Program Files\7-Zip\Uninstall.exe /S';                          Expected = @('C:\Program Files\7-Zip\Uninstall.exe', '/S') },
        @{ UninstallString = 'C:\Program Files\7-Zip.exe.exe\Uninstall.exe /S /abc /whatever';   Expected = @('C:\Program Files\7-Zip.exe.exe\Uninstall.exe', '/S /abc /whatever') },
        @{ UninstallString = '"C:\Program Files\7-Zip.exe.exe\Uninstall.exe" /S /abc /whatever'; Expected = @('C:\Program Files\7-Zip.exe.exe\Uninstall.exe', '/S /abc /whatever') },
        @{ UninstallString = 'C:\Program Files\7-Zip.exe\Uninstall.exe.exe /S /abc /whatever';   Expected = @('C:\Program Files\7-Zip.exe\Uninstall.exe.exe', '/S /abc /whatever') },
        @{ UninstallString = '"C:\Program Files\7-Zip.exe\Uninstall.exe.exe" /S /abc /whatever'; Expected = @('C:\Program Files\7-Zip.exe\Uninstall.exe.exe', '/S /abc /whatever') },
        @{ UninstallString = 'C:\Program Files\7-Zip\Uninstall.exe.exe /S /abc /whatever';       Expected = @('C:\Program Files\7-Zip\Uninstall.exe.exe', '/S /abc /whatever') },
        @{ UninstallString = '"C:\Program Files\7-Zip\Uninstall.exe.exe" /S /abc /whatever';     Expected = @('C:\Program Files\7-Zip\Uninstall.exe.exe', '/S /abc /whatever') },
        @{ UninstallString = 'C:\Program Files\7-Zip\Uninstall.exe';                             Expected = @('C:\Program Files\7-Zip\Uninstall.exe') },
        @{ UninstallString = '"C:\Program Files\7-Zip\Uninstall.exe"';                           Expected = @('C:\Program Files\7-Zip\Uninstall.exe') },
        @{ UninstallString = 'C:\Program Files\7-Zip\Uninstall.exe.exe';                         Expected = @('C:\Program Files\7-Zip\Uninstall.exe.exe') },
        @{ UninstallString = '"C:\Program Files\7-Zip\Uninstall.exe.exe"';                       Expected = @('C:\Program Files\7-Zip\Uninstall.exe.exe') },
        @{ UninstallString = 'C:\Program Files\7-Zip.exe\Uninstall.exe';                         Expected = @('C:\Program Files\7-Zip.exe\Uninstall.exe') },
        @{ UninstallString = '"C:\Program Files\7-Zip.exe\Uninstall.exe"';                       Expected = @('C:\Program Files\7-Zip.exe\Uninstall.exe') }
    ) {
        $Result = Split-UninstallString -UninstallString $UninstallString
        $Result[0] | Should -Be $Expected[0]

        if ([String]::IsNullOrWhitespace($Expected[1])) { 
            $Result[1] | Should -BeNullOrEmpty
        }
        else {
            $Result[1] | Should -Be $Expected[1]
        }
    }

    it 'throw if notepad.exe is already running and specified as -ProcessName' {
        Mock Get-Process { 
            [PSCustomObject]@{ Name = 'notepad' }
        }

        { .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -ProcessName 'notepad' } | Should -Throw -ExceptionType ([System.InvalidOperationException]) -ExpectedMessage "Process 'notepad' is already running before the uninstallation has even started, quitting"
    }

    it 'should call Wait-Process if notepad.exe is running and specified as -ProcessName' {
        Mock Get-Process {}
        Mock Wait-Process {} -Verifiable -ParameterFilter {
            $Name -eq 'notepad'
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -ProcessName 'notepad' | Should -Invoke -CommandName 'Wait-Process' -Times 1
    }

    it '<Action> software because it is <Operator> than <Version>' -TestCases @(
        @{ Action = 'not uninstall'; Operator = 'greater than'; Version = '22.01' },
        @{ Action = 'not uninstall'; Operator = 'less than';    Version = '21.01' },
        @{ Action = 'not uninstall'; Operator = 'equal to';     Version = '1.0'   },
        @{ Action = 'uninstall';     Operator = 'greater than'; Version = '20.01' },
        @{ Action = 'uninstall';     Operator = 'less than';    Version = '22.01' },
        @{ Action = 'uninstall';     Operator = 'equal to';     Version = '21.01' }
    ) {
        $Splat = @{
            DisplayName      = '7-Zip*'
            Architecture     = 'x64'
            HivesToSearch    = 'HKLM'
            WindowsInstaller = 0
        }

        switch ($Operator) {
            'greater than' { $Splat['VersionGreaterThan'] = $Version }
            'less than'    { $Splat['VersionLessThan']    = $Version }
            'equal to'     { $Splat['VersionEqualTo']     = $Version }
        }

        $Times = if ($Action -eq 'uninstall') { 1 } else { 0 }

        .\Uninstall-Software.ps1 @Splat | Should -Invoke -CommandName 'Start-Process' -Times $Times
    }

    it 'not uninstall any software because it is not greater than 22.01 and less than 20.01' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -VersionGreaterThan '22.01' -VersionLessThan '20.01' | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'not uninstall any software because it is not greater than 22.01 and less than 21.01 and equal to 21.0' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -VersionGreaterThan '22.01' -VersionLessThan '21.01' -VersionEqualTo '21.0' | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'uninstall software because it is greater than 20.00 and less than 22.00' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -VersionGreaterThan '20.0' -VersionLessThan '22.0' | Should -Invoke -CommandName 'Start-Process' -Times 1
    }

    it 'uninstall software because it is greater than 20.00 and less than 22.00 and equal to 21.01' {
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 0 -VersionGreaterThan '20.0' -VersionLessThan '22.0' -VersionEqualTo '21.01' | Should -Invoke -CommandName 'Start-Process' -Times 1
    }

    it 'uninstall if MSI product state is "installed"' {
        Mock Get-ProductState {
            5
        }
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 | Should -Invoke -CommandName 'Start-Process' -Times 1
    }

    it 'not uninstall if MSI product state is "absent"' {
        Mock Get-ProductState {
            -1
        }
        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 | Should -Invoke -CommandName 'Start-Process' -Times 0
    }

    it 'verify 1605 is ignored when -Force is used and MSI product state is installed for another user' {
        Mock Get-ProductState {
            2
        }

        Mock Start-Process {
            [PSCustomObject]@{
                ExitCode = 1605
            }
        }

        .\Uninstall-Software.ps1 -DisplayName '7-Zip*' -Architecture 'x64' -HivesToSearch 'HKLM' -WindowsInstaller 1 -Force | Should -Be 0
    }
}

AfterAll {
    Pop-Location
}