# Requires -RunAsAdministrator

$script:allowedProcesses = @{}
Get-Process | ForEach-Object { $script:allowedProcesses[$_.Name] = $true }

$popupTimeout = 15  
$buttonYes = 6     
$buttonNo = 7      

$action = {
    $processName = $event.SourceEventArgs.NewEvent.ProcessName
    $processId = $event.SourceEventArgs.NewEvent.ProcessId
    
    # Get full process details including command line
    $processDetails = Get-WmiObject Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
    $commandLine = if ($processDetails) { $processDetails.CommandLine } else { "N/A" }
    $executablePath = if ($processDetails) { $processDetails.ExecutablePath } else { "N/A" }

    if (-not $allowedProcesses.ContainsKey($processName)) {
        $popupMessage = @"
ALARM! NEW PROCESS HAS STARTED!
Name: $processName
PID: $processId
Path: $executablePath
Command Line: $commandLine

Allow this process?
"@
        $wshell = New-Object -ComObject WScript.Shell
        $response = $wshell.Popup(
            $popupMessage,
            $popupTimeout,
            "Security Control - $processName",
            0x34 -bor 0x1000
        )

        switch ($response) {
            $buttonYes {
                $script:allowedProcesses[$processName] = $true
                Write-Host "[ALLOWED] $processName (PID: $processId)"
                Write-Host "  Path: $executablePath"
                Write-Host "  Args: $commandLine"
            }
            default {
                Write-Host "[TERMINATING] $processName (PID: $processId)"
                Write-Host "  Path: $executablePath"
                Write-Host "  Args: $commandLine"
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

$query = "SELECT * FROM Win32_ProcessStartTrace"
$eventParams = @{
    Query          = $query
    Action         = $action
    SourceIdentifier = "ProcessMonitor"
    ErrorAction    = "Stop"
}
Register-CimIndicationEvent @eventParams | Out-Null

Write-Host "Process Monitor Active (Ctrl+C to exit)..."
Write-Host "Allowed processes: $($script:allowedProcesses.Count)"
try {
    while ($true) { Start-Sleep -Seconds 1 }
}
finally {
    Unregister-Event -SourceIdentifier "ProcessMonitor"
    Get-EventSubscriber | Where-Object SourceIdentifier -eq "ProcessMonitor" | Unregister-Event
}