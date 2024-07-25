Describe 'New-Shortcut.ps1 Integration Test' {
    BeforeAll {
        $VerbosePreference = 'Continue'
        $guid = [guid]::NewGuid().Guid
        $defaultTarget = 'cmd.exe'
        $userStartMenu = [System.Environment]::GetFolderPath('Programs')
        $allUsersStartMenu = [System.Environment]::GetFolderPath('CommonPrograms')
        $userDesktop = [System.Environment]::GetFolderPath('Desktop')
        $publicDesktop = [System.Environment]::GetFolderPath('CommonDesktopDirectory')
    }

    AfterAll {
    }

    It 'Creates a shortcut on the user desktop' {
        . .\New-Shortcut.ps1 -Name $guid -Target $defaultTarget -Desktop -User
        "$userDesktop\$guid.lnk" | Should -Exist
        Remove-Item -Path "userDesktop\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }

    It 'Creates a shortcut on the public desktop' {
        . .\New-Shortcut.ps1 -Name $guid -Target $defaultTarget -Desktop
        "$publicDesktop\$guid.lnk" | Should -Exist
        Remove-Item -Path "$publicDesktop\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }

    It 'Creates a shortcut in the user Start Menu' {
        . .\New-Shortcut.ps1 -Name $guid -Target $defaultTarget -StartMenu -User
        "$userStartMenu\$guid.lnk" | Should -Exist
        Remove-Item -Path "$userStartMenu\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }

    It 'Creates a shortcut in a subfolder of the user Start Menu' {
        . .\New-Shortcut.ps1 -Name $guid -Target $defaultTarget -StartMenu -User -Path $guid
        "$userStartMenu\$guid\$guid.lnk" | Should -Exist
        Remove-Item -Path "$userStartMenu\$guid" -Force -Recurse -ErrorAction SilentlyContinue
    }

    It 'Creates a shortcut in the all users Start Menu' {
        . .\New-Shortcut.ps1 -Name $guid -Target $defaultTarget -StartMenu
        "$allUsersStartMenu\$guid.lnk" | Should -Exist
        Remove-Item -Path "$allUsersStartMenu\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }

    It 'Creates a shortcut in a custom location' {
        . .\New-Shortcut.ps1 -Path $TestDrive -Name $guid -Target $defaultTarget
        "$TestDrive\$guid.lnk" | Should -Exist
        Remove-Item -Path "$TestDrive\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }

    It 'Creates a shortcut via a hashtable' {
        $shortcut = @{
            Name = $guid
            Target = $defaultTarget
            Desktop = $true
            User = $true
        }
        . .\New-Shortcut.ps1 -Shortcuts $shortcut
        "$userDesktop\$guid.lnk" | Should -Exist
        Remove-Item -Path "$userDesktop\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }

    It 'Creates multiple shortcuts via an array of hashtables' {
        $shortcuts = @(
            @{
                Name = $guid
                Target = $defaultTarget
                Desktop = $true
                User = $true
            },
            @{
                Name = $guid
                Target = $defaultTarget
                StartMenu = $true
                User = $true
            }
        )
        . .\New-Shortcut.ps1 -Shortcuts $shortcuts
        "$userDesktop\$guid.lnk" | Should -Exist
        "$userStartMenu\$guid.lnk" | Should -Exist
        Remove-Item -Path "$userDesktop\$guid.lnk" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$userStartMenu\$guid.lnk" -Force -ErrorAction SilentlyContinue
    }
}