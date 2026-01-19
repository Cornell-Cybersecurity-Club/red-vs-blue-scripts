# Objective: downloads scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

# *-WindowsFeature - Roles and Features on Windows Server 2012 R2 and above
# *-WindowsCapability - Features under Settings > "Optional Features"
# *-WindowsOptionalFeature - Featuers under Control Panel > "Turn Windows features on or off" (apparently this is compatible with Windows Server)

param (
    [Parameter(Mandatory=$true)]
    [string]$Path = $(throw "-Path is required."),
    [Parameter(Mandatory=$false)]
    [bool]$ansibleInstall = $false,
    [Parameter(Mandatory=$false)]
    [bool]$dev
)

# somehow this block verifies if the path is legit
$ErrorActionPreference = "Stop"
[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid path" -ForegroundColor white
        break
    }
    $true
})]
$InputPath = $Path
Set-Location -Path $InputPath | Out-Null

function Get-DownloadURL {
    param (
        [String]$repo,
        [String]$file
    )
    if($repo -eq "Windows-Scripts"){
        $branch = "master"
    } else {
        $branch = "main"
    }

    if($dev) {
        return "http://192.168.1.2/ccdc/$($repo)/raw/branch/$($branch)/$($file)"
    }
    else {
        return "https://raw.githubusercontent.com/CCDC-RIT/$($repo)/$($branch)/$($file)"
    }
    
}


# Creating all the directories
$ErrorActionPreference = "Continue"
New-Item -Path $InputPath -Name "scripts" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "installers" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "tools" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "zipped" -ItemType "directory" | Out-Null
$ScriptPath = Join-Path -Path $InputPath -ChildPath "scripts"
$SetupPath = Join-Path -Path $InputPath -ChildPath "installers"
$ToolsPath = Join-Path -Path $InputPath -ChildPath "tools"
$ZippedPath = Join-Path -Path $InputPath -ChildPath "zipped"

New-Item -Path $ScriptPath -Name "conf" -ItemType "directory" | Out-Null
New-Item -Path $ScriptPath -Name "results" -ItemType "directory" | Out-Null
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"
$ResultsPath = Join-Path -Path $ScriptPath -ChildPath "results"

New-Item -Path $ResultsPath -Name "artifacts" -ItemType "directory" | Out-Null
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory" | Out-Null
New-item -Path $ToolsPath -Name "yara" -ItemType "directory" | Out-Null
New-item -Path $ToolsPath -Name "antipwny" -ItemType "directory" | Out-Null
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"
$yaraPath = Join-Path -Path $ToolsPath -ChildPath "yara"
$antipwnyPath = Join-Path -Path $ToolsPath -ChildPath "antipwny"

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Directories created" -ForegroundColor white

# yo i hope this works
if ((Get-CimInstance -Class Win32_OperatingSystem).Caption -match "Windows Server") {
    Install-WindowsFeature -Name Bitlocker | Out-Null

    # Check the Windows Server version and install the appropriate Windows Defender features
    if (([version](Get-CimInstance -Class Win32_OperatingSystem).Version) -ge [version]"10.0") {
        # Windows Server 2016 or newer
        Install-WindowsFeature -Name Windows-Defender | Out-Null
        Install-WindowsFeature -Name Windows-Defender-GUI -ErrorAction SilentlyContinue | Out-Null
    } elseif (([version](Get-CimInstance -Class Win32_OperatingSystem).Version) -ge [version]"6.3") {
        # Windows Server 2012 R2
        Install-WindowsFeature -Name Windows-Defender | Out-Null
    }

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Bitlocker and Windows Defender installed" -ForegroundColor white
}

# Custom tooling downloads
$ProgressPreference = 'SilentlyContinue'
# Audit script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "audit.ps1"), (Join-Path -Path $ScriptPath -ChildPath "audit.ps1"))
# Audit policy file
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "auditpol.csv"), (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
# Backups script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "backup.ps1"), (Join-Path -Path $ScriptPath -ChildPath "backup.ps1"))
# Command runbook
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "command_runbook.txt"), (Join-Path -Path $ScriptPath -ChildPath "command_runbook.txt"))
# Defender exploit guard settings
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "defender-exploit-guard-settings.xml"), (Join-Path -Path $ConfPath -ChildPath "def-eg-settings.xml"))  
# Firewall script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "firewall.ps1"), (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
# Inventory script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "inventory.ps1"), (Join-Path -Path $ScriptPath -ChildPath "inventory.ps1"))
# Logging script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "logging.ps1"), (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
# Secure baseline script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "secure.ps1"), (Join-Path -Path $ScriptPath -ChildPath "secure.ps1"))
# Powershell Profile
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "profile.ps1"), (Join-Path -Path $ScriptPath -ChildPath "profile.ps1"))
# Cert Template
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts/certs" -file "cert.txt"), (Join-Path -Path $ScriptPath -ChildPath "cert.txt"))
# Windows Contain script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "windows-contain.py"), (Join-Path -Path $ScriptPath -ChildPath "windows-contain.py"))
# Dynamic inventory script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "windows-recon.py"), (Join-Path -Path $ScriptPath -ChildPath "windows-recon.py"))
# Recon requirements and OpenSSL fix
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "recon-requirements.txt"), (Join-Path -Path $ScriptPath -ChildPath "recon-requirements.txt"))
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "fix_openssl.py"), (Join-Path -Path $ScriptPath -ChildPath "fix_openssl.py"))
# Yara response script
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Logging-Scripts" -file "yara.bat"), (Join-Path -Path $ScriptPath -ChildPath "yara.bat"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] System scripts and config files downloaded" -ForegroundColor white

# Service tooling 
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') { # DC detection
    # RSAT tooling (AD management tools + DNS management)
    Install-WindowsFeature -Name RSAT-AD-Tools,RSAT-DNS-Server,GPMC
    # Domain, Domain Controller, member/client, and Defender GPOs 
    (New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "gpos/%7BEE3B9E95-9783-474A-86A5-907E93E64F57%7D.zip"), (Join-Path -Path $ConfPath -ChildPath "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip"))
    (New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "gpos/%7B40E1EAFA-8121-4FFA-B6FE-BC348636AB83%7D.zip"), (Join-Path -Path $ConfPath -ChildPath "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip"))
    (New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "gpos/%7B6136C3E1-B316-4C46-9B8B-8C1FC373F73C%7D.zip"), (Join-Path -Path $ConfPath -ChildPath "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip"))
    (New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "gpos/%7BBEAA6460-782B-4351-B17D-4DC8076633C9%7D.zip"), (Join-Path -Path $ConfPath -ChildPath "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip"))
    
    # Reset-KrbtgtKeyInteractive script
    (New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1", (Join-Path -Path $ScriptPath -ChildPath "Reset-KrbtgtKeyInteractive.ps1"))
    # Pingcastle
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip", (Join-Path -Path $InputPath -ChildPath "pc.zip"))
    # Adalanche
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe", (Join-Path -Path $ToolsPath -ChildPath "adalanche.exe"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools downloaded" -ForegroundColor white
    # Pingcastle, GPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pc.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "pc") 
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip") -DestinationPath $ConfPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools extracted" -ForegroundColor white
} else { # Member server/client tools
    # Local policy file
    (New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "Windows-Scripts" -file "gpos/localpolicy.PolicyRules"), (Join-Path -Path $ConfPath -ChildPath "localpolicy.PolicyRules"))
    # LGPO tool
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $InputPath -ChildPath "lg.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO and local policy file downloaded" -ForegroundColor white
    # LGPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "lg.zip") -DestinationPath $ToolsPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO extracted" -ForegroundColor white
}

if (Get-Service -Name CertSvc 2>$null) { # ADCS tools
    # Add package manager and repository for PowerShell
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted | Out-Null
    # install dependency for locksmith (AD PowerShell module) and ADCS management tools
    Install-WindowsFeature -Name RSAT-AD-PowerShell,RSAT-ADCS-Mgmt | Out-Null
    # install locksmith
    Install-Module -Name Locksmith -Scope CurrentUser | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Locksmith downloaded and installed" -ForegroundColor white
}

# Server Core Tooling
if ((Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion") -and (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty "InstallationType") -eq "Server Core") {
    # Explorer++
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip", (Join-Path -Path $InputPath -ChildPath "epp.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "epp.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "epp")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Explorer++ downloaded and extracted" -ForegroundColor white
    # Server Core App Compatibility FOD
    Add-WindowsCapability -Online -Name ServerCore.AppCompatibility~~~~0.0.1.0 | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Additional MS tools installed" -ForegroundColor white
    # NetworkMiner
    (New-Object System.Net.WebClient).DownloadFile("https://netresec.com/?download=NetworkMiner", (Join-Path -Path $InputPath -ChildPath "nm.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "nm.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "nm")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] NetworkMiner downloaded and extracted" -ForegroundColor white
}

# Third-party tooling for every system
# Get-InjectedThread and Stop-Thread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Stop-Thread.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Get-InjectedThread and Stop-Thread downloaded" -ForegroundColor white
# Remove Powershell Profiles Tool
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/haxr/PowerShell-Scripts/refs/heads/master/Remove-LocalProfiles.ps1", (Join-Path -Path $ScriptPath -ChildPath "Remove-LocalProfiles.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Remove-LocalProfiles script downloaded" -ForegroundColor white
# PrivEsc checker script
(New-Object System.Net.WebClient).DownloadFile("https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1", (Join-Path -Path $ScriptPath -ChildPath "PrivescCheck.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] PrivescChecker script downloaded" -ForegroundColor white
# chainsaw + dependency library
$redistpath = Join-Path -Path $SetupPath -ChildPath "vc_redist.64.exe"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip", (Join-Path -Path $InputPath -ChildPath "cs.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", $redistpath)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chainsaw and C++ redist downloaded" -ForegroundColor white
## silently installing dependency library
& $redistpath /install /passive /norestart
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] C++ redist installed" -ForegroundColor white
# hollows hunter
(New-Object System.Net.WebClient).DownloadFile("https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip", (Join-Path -Path $InputPath -ChildPath "hh64.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter downloaded" -ForegroundColor white
# ADFS Rapid Restore Tool
(New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/6/8/a/68af3cd3-1337-4389-967c-a6751182f286/ADFSRapidRecreationTool.msi", (Join-Path -Path $InputPath -ChildPath "ADFSRapidRecreationTool.msi"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ADFS Rapid Recreation Tool downloaded" -ForegroundColor white
# Wazuh agent
# (New-Object System.Net.WebClient).DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi", (Join-Path -Path $SetupPath -ChildPath "wazuhagent.msi"))
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh agent installer downloaded" -ForegroundColor white
# Basic Sysmon conf file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", (Join-Path -Path $ConfPath -ChildPath "sysmon.xml"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Sysmon config downloaded" -ForegroundColor white
# Windows Firewall Control + .NET 4.8
$net48path = Join-Path -Path $SetupPath -ChildPath "net_installer.exe"
(New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", (Join-Path -Path $SetupPath -ChildPath "wfcsetup.exe"))
(New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?LinkId=2088631", $net48path)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Windows Firewall Control and .NET 4.8 installers downloaded" -ForegroundColor white
## silently installing .NET 4.8 library
& $net48path /passive /norestart
# Wireshark
# (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
(New-Object System.Net.WebClient).DownloadFile("https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe", (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe"))
if(!($ansibleInstall)){
    & (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wireshark downloaded and installed" -ForegroundColor white
} else {
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wireshark downloaded" -ForegroundColor white
}

# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $InputPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $InputPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $InputPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $InputPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $InputPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $InputPath -ChildPath "tv.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Streams.zip", (Join-Path -Path $InputPath -ChildPath "stm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", (Join-Path -Path $InputPath -ChildPath "sm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AccessChk.zip", (Join-Path -Path $InputPath -ChildPath "ac.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Strings.zip", (Join-Path -Path $InputPath -ChildPath "str.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/PsExec.zip", (Join-Path -Path $InputPath -ChildPath "psexec.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools downloaded" -ForegroundColor white
# yara
(New-Object System.Net.WebClient).DownloadFile("https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip", (Join-Path -Path $InputPath -ChildPath "yara.zip"))
## yara rules
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "YaraRules" -file "Windows.zip"), (Join-Path -Path $InputPath -ChildPath "Windows.zip"))
(New-Object System.Net.WebClient).DownloadFile((Get-DownloadURL -repo "YaraRules" -file "Multi.zip"), (Join-Path -Path $InputPath -ChildPath "Multi.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip", (Join-Path -Path $InputPath -ChildPath "yarahq.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] YARA and YARA rules downloaded" -ForegroundColor white

# Notepad++
$npppath = Join-Path -Path $SetupPath -ChildPath "notepadpp_installer.exe"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe", $npppath)
& $npppath /S
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Notepad++ downloaded and installed" -ForegroundColor white

# VSCode
# (New-Object System.Net.WebClient).DownloadFile("https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user", (Join-Path -Path $SetupPath -ChildPath "vscodesetup.exe"))
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] VSCode installer downloaded" -ForegroundColor white

# googoo chrome
$chromepath = Join-Path -Path $SetupPath -ChildPath "chromeinstall.exe"
(New-Object System.Net.WebClient).DownloadFile("http://dl.google.com/chrome/install/375.126/chrome_installer.exe", $chromepath)
& $chromepath /silent /install
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Google Chrome downloaded and installed" -ForegroundColor white

# Everything
(New-Object System.Net.WebClient).DownloadFile("https://www.voidtools.com/Everything-1.4.1.1024.x64.zip", (Join-Path -Path $InputPath -ChildPath "everything.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://www.voidtools.com/ES-1.1.0.27.x64.zip", (Join-Path -Path $InputPath -ChildPath "es.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Everything downloaded" -ForegroundColor white

# BCU
(New-Object System.Net.WebClient).DownloadFile("https://github.com/Klocman/Bulk-Crap-Uninstaller/releases/download/v5.7/BCUninstaller_5.7_portable.zip", (Join-Path -Path $InputPath -ChildPath "bcu.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] BCU downloaded" -ForegroundColor white

# Antipwny (Meterpreter Detection)
(New-Object System.Net.WebClient).DownloadFile("https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe", (Join-Path -Path $antipwnyPath -ChildPath "AntiPwny.exe"))
(New-Object System.Net.WebClient).DownloadFile("https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll", (Join-Path -Path $antipwnyPath -ChildPath "ObjectListView.dll"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Antipwny downloaded" -ForegroundColor white

# Password Manager Client
(New-Object System.Net.WebClient).DownloadFile("https://github.com/CCDC-RIT/Password-Manager/raw/refs/heads/main/client/windows.exe", (Join-Path -Path $ToolsPath -ChildPath "CCDC-Password-Manager.exe"))

# Datadog IP Addresses
(New-Object System.Net.WebClient).DownloadFile("https://ip-ranges.us5.datadoghq.com/", (Join-Path -Path $ScriptPath -ChildPath "datadog_ips.txt"))

# Tabula
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/stabvest-public/refs/heads/main/tabula/tabula.py", (Join-Path -Path $ScriptPath -ChildPath "tabula.py"))

# Extraction
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "stm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "stm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ac.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ac")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "str.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "str")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "psexec.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ps")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "everything.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "everything")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "es.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "everything-cli")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Everything extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "bcu.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "bcu")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] BCU extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "hh64.zip") -DestinationPath $ToolsPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter extracted" -ForegroundColor white
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "cs.zip") -DestinationPath $ToolsPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chainsaw extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "yara.zip") -DestinationPath $yaraPath
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "Windows.zip") -DestinationPath $yaraPath
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "Multi.zip") -DestinationPath $yaraPath
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "yarahq.zip") -DestinationPath $yaraPath
Move-Item -Path (Join-Path -Path $yaraPath -ChildPath "packages\full\yara-rules-full.yar") -Destination (Join-Path -Path $yaraPath -ChildPath "Multi\YaraHQRules.yara")
Remove-Item -Path (Join-Path -Path $yaraPath -ChildPath "packages") -Recurse

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] YARA and YARA rules extracted" -ForegroundColor white

foreach($file in (Get-childItem -Path $InputPath)){
    if($file.name -match ".zip"){
        Move-item -path (Join-Path -path $InputPath -ChildPath $file.name) -Destination $zippedPath
    }
}
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Cleaned up zipped Files" -ForegroundColor white

# Rename important executables to obfuscate for IFEO detection evasion
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ac\accesschk.exe") -NewName "accesschk_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ac\accesschk64.exe") -NewName "accesschk64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ac\accesschk64a.exe") -NewName "accesschk64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ar\Autoruns.exe") -NewName "Autoruns_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ar\Autoruns64.exe") -NewName "Autoruns64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ar\Autoruns64a.exe") -NewName "Autoruns64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ar\Autorunsc.exe") -NewName "Autorunsc_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ar\Autorunsc64.exe") -NewName "Autorunsc64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ar\Autorunsc64a.exe") -NewName "Autorunsc64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "dll\Listdlls.exe") -NewName "Listdlls_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "dll\Listdlls64.exe") -NewName "Listdlls64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "pe\procexp.exe") -NewName "procexp_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "pe\procexp64.exe") -NewName "procexp64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "pe\procexp64a.exe") -NewName "procexp64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "pm\procmon.exe") -NewName "procmon_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "pm\procmon64.exe") -NewName "procmon64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "pm\procmon64a.exe") -NewName "procmon64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ps\PsExec.exe") -NewName "PsExec_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ps\PsExec64.exe") -NewName "PsExec64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "ps\PsExec64a.exe") -NewName "PsExec64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "sc\sigcheck.exe") -NewName "sigcheck_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "sc\sigcheck64.exe") -NewName "sigcheck64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "sc\sigcheck64a.exe") -NewName "sigcheck64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "sm\Sysmon.exe") -NewName "Sysmon_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "sm\Sysmon64.exe") -NewName "Sysmon64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "sm\Sysmon64a.exe") -NewName "Sysmon64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "stm\streams.exe") -NewName "streams_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "stm\streams64.exe") -NewName "streams64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "stm\streams64a.exe") -NewName "streams64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "str\strings.exe") -NewName "strings_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "str\strings64.exe") -NewName "strings64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "str\strings64a.exe") -NewName "strings64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "tv\tcpvcon.exe") -NewName "tcpvcon_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "tv\tcpvcon64.exe") -NewName "tcpvcon64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "tv\tcpvcon64a.exe") -NewName "tcpvcon64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "tv\tcpview.exe") -NewName "tcpview_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "tv\tcpview64.exe") -NewName "tcpview64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $SysPath -ChildPath "tv\tcpview64a.exe") -NewName "tcpview64a_ccdc.exe"
Rename-Item -Path (Join-Path -Path $yaraPath -ChildPath "yara64.exe") -NewName "yara64_ccdc.exe"
Rename-Item -Path (Join-Path -Path $yaraPath -ChildPath "yarac64.exe") -NewName "yarac64_ccdc.exe"
Rename-Item -Path (Join-Path -Path "C:\Program Files\Wireshark" -ChildPath "wireshark.exe") -NewName "wireshark_ccdc.exe"

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Executables renamed for IFEO evasion" -ForegroundColor white

