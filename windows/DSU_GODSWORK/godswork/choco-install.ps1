Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# Handle broken/partial installs where C:\ProgramData\chocolatey exists but choco.exe does not.
$chocoRoot = 'C:\ProgramData\chocolatey'
$chocoExe  = Join-Path $chocoRoot 'bin\choco.exe'

if (Test-Path $chocoExe) {
	Write-Host '[INFO] Existing Chocolatey installation detected at' $chocoExe
	return
}

if ((Test-Path $chocoRoot) -and -not (Test-Path $chocoExe)) {
	Write-Warning "Detected Chocolatey folder at '$chocoRoot' but no choco.exe. Removing broken install..."
	try {
		Remove-Item -Recurse -Force $chocoRoot -ErrorAction Stop
		Write-Host '[INFO] Removed previous broken Chocolatey folder.'
	} catch {
		Write-Warning "Failed to remove '$chocoRoot'. Error: $($_.Exception.Message)"
	}
}

iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))