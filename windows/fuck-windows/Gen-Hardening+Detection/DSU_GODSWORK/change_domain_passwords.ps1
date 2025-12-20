# Domain Password Change Script
# Reads username,password pairs from a file and updates AD passwords
# Then deletes the password file and reports unlisted users

param(
    [Parameter(Mandatory=$false)]
    [string]$PasswordFile = "passwords.txt"
)

$ErrorActionPreference = "Stop"

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "Error: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Check if running on a domain controller or domain-joined machine
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "Error: Active Directory module not available. This script must run on a domain controller or with RSAT installed." -ForegroundColor Red
    exit 1
}

# Check if password file exists
if (-not (Test-Path $PasswordFile)) {
    Write-Host "Error: Password file '$PasswordFile' not found." -ForegroundColor Red
    exit 1
}

Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Domain Password Change Script" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Password File: $PasswordFile`n" -ForegroundColor Yellow

# Confirm before proceeding
$confirmation = Read-Host "This will change domain user passwords. Continue? (yes/no)"
if ($confirmation -ne "yes") {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Get all domain users (excluding built-in accounts and computers)
Write-Host "`n[*] Retrieving all domain users..." -ForegroundColor Green
$allDomainUsers = Get-ADUser -Filter * -Properties SamAccountName | 
    Where-Object { $_.Enabled -eq $true -and $_.SamAccountName -notlike "*$" } | 
    Select-Object -ExpandProperty SamAccountName

Write-Host "[+] Found $($allDomainUsers.Count) enabled domain users." -ForegroundColor Green

# Read password file
Write-Host "`n[*] Reading password file..." -ForegroundColor Green
$passwordEntries = @{}
$lineNumber = 0

try {
    Get-Content $PasswordFile | ForEach-Object {
        $lineNumber++
        $line = $_.Trim()
        
        # Skip empty lines and comments
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
            return
        }
        
        # Parse username,password format
        $parts = $line -split ',', 2
        if ($parts.Count -ne 2) {
            Write-Host "[!] Warning: Line $lineNumber has invalid format. Expected 'username,password'. Skipping." -ForegroundColor Yellow
            return
        }
        
        $username = $parts[0].Trim()
        $password = $parts[1].Trim()
        
        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
            Write-Host "[!] Warning: Line $lineNumber has empty username or password. Skipping." -ForegroundColor Yellow
            return
        }
        
        $passwordEntries[$username] = $password
    }
} catch {
    Write-Host "Error reading password file: $_" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Loaded $($passwordEntries.Count) password entries from file." -ForegroundColor Green

# Change passwords for users in the file
Write-Host "`n[*] Changing domain user passwords..." -ForegroundColor Green
$successCount = 0
$failCount = 0
$usersChanged = @()

foreach ($username in $passwordEntries.Keys) {
    try {
        # Check if user exists
        $user = Get-ADUser -Identity $username -ErrorAction SilentlyContinue
        
        if ($null -eq $user) {
            Write-Host "[-] User '$username' not found in domain. Skipping." -ForegroundColor Red
            $failCount++
            continue
        }
        
        # Convert password to secure string
        $securePassword = ConvertTo-SecureString $passwordEntries[$username] -AsPlainText -Force
        
        # Change the password
        Set-ADAccountPassword -Identity $username -NewPassword $securePassword -Reset
        
        # Force password change at next logon (optional - comment out if not desired)
        # Set-ADUser -Identity $username -ChangePasswordAtLogon $false
        
        Write-Host "[+] Successfully changed password for: $username" -ForegroundColor Green
        $successCount++
        $usersChanged += $username
        
    } catch {
        Write-Host "[-] Failed to change password for '$username': $_" -ForegroundColor Red
        $failCount++
    }
}

# Report unlisted domain users
Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Users Not Listed in Password File" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

$unlistedUsers = $allDomainUsers | Where-Object { $_ -notin $usersChanged }

if ($unlistedUsers.Count -gt 0) {
    Write-Host "[!] WARNING: The following $($unlistedUsers.Count) domain users were NOT listed in the password file:`n" -ForegroundColor Yellow
    foreach ($user in $unlistedUsers) {
        Write-Host "    - $user" -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] All domain users were listed in the password file." -ForegroundColor Green
}

# Summary
Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Passwords changed successfully: $successCount" -ForegroundColor Green
Write-Host "Failed password changes: $failCount" -ForegroundColor Red
Write-Host "Domain users not in file: $($unlistedUsers.Count)" -ForegroundColor Yellow

# Delete the password file
Write-Host "`n[*] Deleting password file for security..." -ForegroundColor Green
try {
    Remove-Item $PasswordFile -Force
    Write-Host "[+] Password file deleted successfully." -ForegroundColor Green
} catch {
    Write-Host "[-] Warning: Could not delete password file: $_" -ForegroundColor Red
    Write-Host "    Please manually delete: $PasswordFile" -ForegroundColor Red
}

Write-Host "`n[+] Operation completed.`n" -ForegroundColor Green
