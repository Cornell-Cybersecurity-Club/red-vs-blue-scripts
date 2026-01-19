# Only proceed if PSReadLine exists
Import-Module PSReadLine -ErrorAction SilentlyContinue
if (Get-Module -ListAvailable -Name PSReadLine) {

    $backupMarker = "$env:USERPROFILE\Documents\WindowsPowerShell\.history_migrated"
    $oldHistory   = (Get-PSReadLineOption).HistorySavePath
    $backupDir    = "$env:USERPROFILE\Documents\WindowsPowerShell\HistoryBackups"

    # Run only once
    if (-not (Test-Path $backupMarker)) {

        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

        $timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupFile = Join-Path $backupDir "OldProfileHistory-$timestamp.txt"

        if (Test-Path $oldHistory) {
            Copy-Item $oldHistory $backupFile -Force
        }

        # Create marker so this never runs again
        New-Item -ItemType File -Path $backupMarker -Force | Out-Null
    }
}


# Simple profile
Set-PsReadLineOption -EditMode Windows

# Any other settings that are needed to secure the current powershell session on boot

# Little message upon profile load
#Write-Host "CCDC PROFILE LOADED" -ForegroundColor Magenta -BackgroundColor White

# Only load PSReadLine if available
Import-Module PSReadLine -ErrorAction SilentlyContinue
if (Get-Module -ListAvailable -Name PSReadLine) {

    Set-PSReadLineOption -HistorySavePath "$env:USERPROFILE\Documents\WindowsPowerShell\NewProfileHistory.txt" -HistoryNoDuplicates:$false -MaximumHistoryCount 5000 -HistorySaveStyle SaveIncrementally

}
