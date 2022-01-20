#by default this will download and install the latest x64 vc_redist from the microsoft link (until they inexcplicably change it without any notification) 
#for a different vc redist you can change thr URL paramater to the one for you purpose 
# x86 is https://aka.ms/vs/17/release/vc_redist.x86.exe
# arm64 is https://aka.ms/vs/17/release/vc_redist.arm64.exe
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Mandatory = $False)] $url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
)

begin {

    if (!(get-item c:\temp)) { new-item -path c:\ -name temp -itemtype directory }
    if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64 -Name installed).installed -eq 1) { exit 0 }
    Start-Transcript C:\ProgramData\PatchMyPC\VCREDIST.log

    $content = Invoke-WebRequest -Uri $url
    $exe = $content.Headers."content-disposition".Split('; ')[2].split('=')[1]
    Invoke-WebRequest -Uri $url -OutFile "c:\temp\$exe"
    try {
        Start-Process -FilePath "C:\Temp\$exe" -ArgumentList "/install /quiet /norestart"
        Stop-Transcript
        exit 0
    }
    catch {
        write-host "error installing redistributable"
        Stop-Transcript
        exit 1
    }
}