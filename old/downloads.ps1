# TODO: create reference page of links, replace links in 5 min plan w/shortened versions

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

$ErrorActionPreference = "Stop"

[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        throw "Invalid Path"
    }
    $true
})]
$UserPath = Read-Host -Prompt "Input absolute path to download files"
Set-Location -Path $UserPath

$ErrorActionPreference = "Continue"
New-Item -Path $UserPath -Name "scripts" -ItemType "directory"
New-Item -Path $UserPath -Name "setup" -ItemType "directory"
New-Item -Path $UserPath -Name "tools" -ItemType "directory"
$ScriptPath = Join-Path -Path $UserPath -ChildPath "scripts"
$SetupPath = Join-Path -Path $UserPath -ChildPath "setup"
$ToolsPath = Join-Path -Path $UserPath -ChildPath "tools"

# Certain tools are specific to types of systems
$ad = Read-Host "Is this a Domain Controller (Y or N)? "
if (($ad -eq "N") -or ($ad -eq "n")) {
    Write-Host "Downloading local user management script..."
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/blum.bat", (Join-Path -Path $ScriptPath -ChildPath "blum.bat"))
} 
$core = Read-Host "Is this server a Core Server (Y or N)? "
if (($core -eq "Y") -or ($core -eq "y")) {
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip", (Join-Path -Path $UserPath -ChildPath "epp.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "epp.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "epp")
}

# Scripts and config files 
New-Item -Path $ScriptPath -Name "conf" -ItemType "directory"
New-Item -Path $ScriptPath -Name "results" -ItemType "directory"
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"

(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.bat", (Join-Path -Path $ScriptPath -ChildPath "audit.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.bat", (Join-Path -Path $ScriptPath -ChildPath "firewall.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.bat", (Join-Path -Path $ScriptPath -ChildPath "inventory.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.bat", (Join-Path -Path $ScriptPath -ChildPath "logging.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/netstat.bat", (Join-Path -Path $ScriptPath -ChildPath "netstat.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.bat", (Join-Path -Path $ScriptPath -ChildPath "secure.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/folderintegrity.bat", (Join-Path -Path $ScriptPath -ChildPath "folderintegrity.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/goldentickets.bat", (Join-Path -Path $ScriptPath -ChildPath "goldentickets.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/log_generator.bat", (Join-Path -Path $ScriptPath -ChildPath "log_generator.bat"))
# Get-InjectedThread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
# Security policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secpol.inf", (Join-Path -Path $ConfPath -ChildPath "secpol.inf"))
# Audit policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv", (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
# Basic Sysmon config file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", (Join-Path -Path $ConfPath -ChildPath "sysmon.xml"))
# TODO: wazuh config file

# Installers programs for various tools
# Windows Firewall Control
(New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", (Join-Path -Path $SetupPath -ChildPath "wfcsetup.exe"))
# Wireshark
# (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
(New-Object System.Net.WebClient).DownloadFile("https://1.na.dl.wireshark.org/win64/Wireshark-win64-latest.exe", (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe"))
# Wazuh agent
(New-Object System.Net.WebClient).DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.10-1.msi", (Join-Path -Path $SetupPath -ChildPath "wazuhagent.msi"))

# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $UserPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $UserPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $UserPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $UserPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $UserPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", (Join-Path -Path $UserPath -ChildPath "sm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $UserPath -ChildPath "tv.zip"))

# Unzipping stuff
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory"
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "sm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sm")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
