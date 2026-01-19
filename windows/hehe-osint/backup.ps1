param(
    [Parameter(Mandatory=$false)]
    [Array]$extraDirs,
    [Parameter(Mandatory=$false)]
    [string]$adfsPasswd
)

[string]$path = ($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("scripts\backup.ps1"))

if (!(Test-Path -Path (Join-Path $path "backup"))) {
    New-Item -Path $path -Name "backup" -ItemType "directory" | Out-Null
}
[string]$backupGrandparentPath = (Join-Path $path "backup")
[string]$hostname = (Get-CimInstance -Class Win32_ComputerSystem).Name
[string]$backupParentPath = (Join-Path $backupGrandparentPath $hostname)
if (!(Test-Path $backupParentPath)) {
    New-Item -Path $backupParentPath -Name $hostname -ItemType "directory" | Out-Null
}
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
[string]$backupPath = (Join-Path $backupParentPath $dateTime)

if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    New-Item -Path $backupPath -Name "sysvol" -ItemType "directory" | Out-Null
    robocopy "C:\Windows\SYSVOL" (Join-Path $backupPath "sysvol") /MIR /COPYALL /B /R:0 /XD "DfsrPrivate" "staging" "staging areas" "ContentSet*" | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SYSVOL folder backed up" -ForegroundColor white

    dnscmd /exportsettings | Out-Null
    New-Item -Path $backupPath -Name "dns_backup" -ItemType "directory" | Out-Null
    xcopy /E /I C:\Windows\System32\dns (Join-Path -Path $backupPath -childPath "dns_backup") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DNS folder backed up" -ForegroundColor white
}

if (Get-Service -Name W3SVC 2>$null) {
    xcopy /E /I C:\inetpub (Join-Path -Path $backupPath -childPath "iis_backup") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] IIS folder backed up" -ForegroundColor white
}

if (Get-Service -Name CertSvc 2>$null) {
    New-Item -Path $backupPath -Name "ca_backup" -ItemType "directory" | Out-Null
    New-Item -Path (Join-Path -Path $backupPath -childPath "ca_backup") -Name "ca_templates" -ItemType "directory" | Out-Null
    certutil -backupDB (Join-Path -Path $backupPath -childPath "ca_backup") | Out-Null
    Get-CATemplate | Foreach-Object { $_.Name } | Out-File -FilePath (Join-Path -Path $backupPath -childPath "ca_backup\ca_templates\CATemplates.txt") -Encoding String -Force
    Get-Content -Path (Join-Path -Path $backupPath -ChildPath "ca_backup\ca_templates\CATemplates.txt") | ForEach-Object {certutil -v -template $_ > (Join-Path -Path $backupPath -ChildPath "ca_backup\ca_templates\$_.txt")}
    reg export HKLM\System\CurrentControlSet\Services\CertSvc\Configuration (Join-Path -Path $backupPath -childPath "ca_backup\regkey.reg") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] CA certs, templates, and settings backed up" -ForegroundColor white
}

if (Get-Service -Name adfssrv 2>$null) {
    $adfsBackupPath = Join-Path -Path $backupPath -childPath "adfs_backup"
    Import-Module 'C:\Program Files (x86)\ADFS Rapid Recreation Tool\ADFSRapidRecreationTool.dll' 
    Backup-ADFS -StorageType "FileSystem" -StoragePath $adfsBackupPath -EncryptionPassword $adfsPasswd -BackupDKM
    Remove-Module ADFSRapidRecreationTool
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ADFS backup completed" -ForegroundColor white
}

if (Get-Service -Name WinRM 2>$null) {
    New-Item -Path $backupPath -Name "winrm" -ItemType "directory" | Out-Null
    $winrmConfigBackupPath = Join-Path -Path $backupPath -childPath "winrm\winrm_config_backup.txt"
    winrm get winrm/config > $winrmConfigBackupPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WinRM configuration backed up" -ForegroundColor white
}

# Creates profiles backup folder
New-Item -Path $backupPath -Name "profiles" -ItemType "directory" | Out-Null
$profileBackupPath = Join-Path -Path $backupPath -childPath "profiles"

# Copy's backup script, Suppresses errors in case they don't exist
Copy-Item "$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" $profileBackupPath -ErrorAction SilentlyContinue
Copy-Item "$HOME\Documents\WindowsPowerShell\profile.ps1" $profileBackupPath -ErrorAction SilentlyContinue
Copy-Item "C:/Windows/System32/WindowsPowerShell/v1.0/profile.ps1" $profileBackupPath -ErrorAction SilentlyContinue
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Copied powershell profiles" -ForegroundColor white

# Creates the path directory
New-Item -Path $backupPath -Name "user_files" -ItemType "directory" | Out-Null
$userBackupPath = Join-Path -Path $backupPath -childPath "user_files"

# Finds the paths
$userPaths = Get-ChildItem -Path C:\Users\ -Include _.txt,_.pdf,*.xlsx,*.xls,*.doc,*.docx,*.ini,*.pdf,*.yaml,*.yml,*.log,*.ps1,*.vbs,*.exe,*.tmp,*.db, *.py -File -Recurse -ErrorAction SilentlyContinue

# Copies the items
foreach ($path in $userPaths){
    Copy-Item $path $userBackupPath
}


# Notes for xcopy
# /H - Include Hidden Files
# /I - Creates the Destination Directory if it doesn't exist (Kind of)
# /K - Retains read-only perms on read-only files
# /S - Copy Subdirectories
# /X - Copy File Audit settings and file ACLs

# Wazuh agent backup 
xcopy "C:\Program Files (x86)\ossec-agent\client.keys" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\ossec.conf" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\internal_options.conf" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\*.pem" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\ossec.log" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\logs\*"  $backupPath\logs\ /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\rids\*"  $backupPath\rids\ /H /I /K /S /X | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh agent files backed up" -ForegroundColor white

# Back up Extra Directories
foreach ($dir in $extraDirs){
    # xcopy doesn't work with a triling '\'
    if ($dir[$dir.Length - 1] -eq "\"){
        $dir = $dir.substring(0, $dir.Length - 1)
    }
    # Get the Last directory, because that is going to be the name of the directory within the backup
    $dirs = $dir -split "\\"
    $lastDir = $dirs[$dirs.Length - 1]
    
    # Copy over the directory
    xcopy $dir (Join-Path -Path $backupPath -ChildPath $lastDir) /H /I /K /S /X | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] $($lastDir) folder backed up" -ForegroundColor white
}


