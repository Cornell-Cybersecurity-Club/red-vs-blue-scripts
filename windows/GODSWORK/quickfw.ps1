# Quick Firewall Block Script
# Rapidly block IPs, subnets, or ranges

param(
    [Parameter(Mandatory=$false)]
    [string[]]$IPs,
    
    [Parameter(Mandatory=$false)]
    [switch]$DomainWide,
    
    [Parameter(Mandatory=$false)]
    [switch]$AllowInstead,
    
    [Parameter(Mandatory=$false)]
    [string]$RuleName = "QuickBlock"
)

$ErrorActionPreference = "Continue"

function Show-Usage {
    Write-Host "`nQuick Firewall Rule Creator" -ForegroundColor Cyan
    Write-Host "============================`n" -ForegroundColor Cyan
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\quickfw.ps1 10.213.37.72" -ForegroundColor Green
    Write-Host "  .\quickfw.ps1 192.168.50.3,10.213.37.72" -ForegroundColor Green
    Write-Host "  .\quickfw.ps1 10.0.0.0/8 -DomainWide" -ForegroundColor Green
    Write-Host "  .\quickfw.ps1 192.168.1.100 -AllowInstead" -ForegroundColor Green
    Write-Host "`nParameters:" -ForegroundColor Yellow
    Write-Host "  -IPs          : Comma-separated IPs, subnets, or ranges" -ForegroundColor White
    Write-Host "  -DomainWide   : Apply to entire domain via GPO" -ForegroundColor White
    Write-Host "  -AllowInstead : Create ALLOW rules instead of BLOCK" -ForegroundColor White
    Write-Host "  -RuleName     : Custom rule name prefix`n" -ForegroundColor White
}

# If no parameters, show interactive mode
if (-not $IPs) {
    Write-Host "`n==================================" -ForegroundColor Cyan
    Write-Host "  Quick Firewall Rule Creator" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    
    $input = Read-Host "`nEnter IPs to block (comma-separated, or press Enter for help)"
    
    if ([string]::IsNullOrWhiteSpace($input)) {
        Show-Usage
        exit 0
    }
    
    $IPs = $input -split ',' | ForEach-Object { $_.Trim() }
    
    $domainChoice = Read-Host "Apply domain-wide via GPO? (y/n)"
    $DomainWide = ($domainChoice -eq 'y')
    
    $actionChoice = Read-Host "Action: (b)lock or (a)llow?"
    $AllowInstead = ($actionChoice -eq 'a')
}

# Determine action
$action = if ($AllowInstead) { "Allow" } else { "Block" }
$actionVerb = if ($AllowInstead) { "Allowing" } else { "Blocking" }

# Determine policy store
$policyStore = if ($DomainWide) {
    try {
        $domain = (Get-ADDomain).DNSRoot
        "$domain\Default Domain Policy"
    } catch {
        Write-Host "[!] Warning: Could not get domain. Applying locally." -ForegroundColor Yellow
        $null
    }
} else {
    $null
}

$successCount = 0
$failCount = 0

Write-Host "`n[$actionVerb Rules]" -ForegroundColor Cyan
if ($DomainWide -and $policyStore) {
    Write-Host "[*] Policy Store: $policyStore (Domain-wide)`n" -ForegroundColor Yellow
} else {
    Write-Host "[*] Policy Store: Local Machine`n" -ForegroundColor Yellow
}

foreach ($ip in $IPs) {
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }
    
    $ruleNameOut = "${RuleName}_${ip}_Out".Replace("/", "_").Replace(".", "_")
    $ruleNameIn = "${RuleName}_${ip}_In".Replace("/", "_").Replace(".", "_")
    
    try {
        # Outbound rule
        $params = @{
            DisplayName = $ruleNameOut
            Direction = "Outbound"
            RemoteAddress = $ip
            Action = $action
            ErrorAction = "Stop"
        }
        if ($policyStore) { $params['PolicyStore'] = $policyStore }
        
        New-NetFirewallRule @params | Out-Null
        
        # Inbound rule
        $params['DisplayName'] = $ruleNameIn
        $params['Direction'] = "Inbound"
        
        New-NetFirewallRule @params | Out-Null
        
        Write-Host "[+] $action rules created for: $ip" -ForegroundColor Green
        $successCount++
        
    } catch {
        Write-Host "[-] Failed to create rule for $ip : $_" -ForegroundColor Red
        $failCount++
    }
}

Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Successfully created: $successCount rules" -ForegroundColor Green
Write-Host "Failed: $failCount rules" -ForegroundColor Red

if ($DomainWide -and $policyStore) {
    Write-Host "`n[*] Forcing GPO update on domain machines..." -ForegroundColor Yellow
    Write-Host "    Run 'gpupdate /force' on clients to apply immediately.`n" -ForegroundColor Yellow
}
