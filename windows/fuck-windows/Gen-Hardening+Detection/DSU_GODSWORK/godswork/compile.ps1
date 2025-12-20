# Quick compilation script for portable Windows executables
# Static linking ensures compatibility across Windows systems

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  DSU GODSWORK Compilation Script" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if g++ is available
try {
    $gppVersion = g++ --version 2>&1 | Select-String "g\+\+"
    Write-Host "[*] Compiler found: $gppVersion`n" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] g++ not found in PATH" -ForegroundColor Red
    Write-Host "Please install MinGW-w64 or add it to your PATH" -ForegroundColor Yellow
    Write-Host "Download: https://github.com/msys2/msys2-installer/releases`n" -ForegroundColor Yellow
    exit 1
}

# Compile 1.exe (Process-based firewall)
Write-Host "[*] Compiling 1.exe (Process Firewall)..." -ForegroundColor Yellow
$compile1Args = @(
    "-o", "1.exe",
    "1.cpp",
    "-lpsapi",
    "-static-libgcc",
    "-static-libstdc++",
    "-static",
    "-D_WIN32_WINNT=0x0603",
    "-std=c++17",
    "-O2",
    "-s"
)

try {
    $proc = Start-Process -FilePath "g++" -ArgumentList $compile1Args -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Compilation failed with exit code $($proc.ExitCode)"
    }
    Write-Host "[SUCCESS] 1.exe compiled successfully`n" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] 1.exe compilation failed: $_`n" -ForegroundColor Red
    exit 1
}

# Compile UseThismain.exe (Subnet-wide hardening)
Write-Host "[*] Compiling UseThismain.exe (Subnet Hardening)..." -ForegroundColor Yellow
$compileMainArgs = @(
    "-o", "UseThismain.exe",
    "main.cpp",
    "-lbcrypt",
    "-lws2_32",
    "-lnetapi32",
    "-lactiveds",
    "-ladsiid",
    "-lole32",
    "-loleaut32",
    "-liphlpapi",
    "-lmpr",
    "-municode",
    "-static-libgcc",
    "-static-libstdc++",
    "-static",
    "-D_WIN32_WINNT=0x0603",
    "-std=c++17",
    "-O2",
    "-s"
)

try {
    $proc = Start-Process -FilePath "g++" -ArgumentList $compileMainArgs -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Compilation failed with exit code $($proc.ExitCode)"
    }
    Write-Host "[SUCCESS] UseThismain.exe compiled successfully`n" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] UseThismain.exe compilation failed: $_`n" -ForegroundColor Red
    exit 1
}

# Show file sizes
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Compilation Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$files = @("1.exe", "UseThismain.exe")
foreach ($file in $files) {
    if (Test-Path $file) {
        $size = (Get-Item $file).Length
        $sizeKB = [math]::Round($size / 1KB, 2)
        $sizeMB = [math]::Round($size / 1MB, 2)
        Write-Host "$file - $size bytes ($sizeKB KB / $sizeMB MB)" -ForegroundColor Green
    }
}

Write-Host "`n[*] Executables are statically linked for portability" -ForegroundColor Yellow
Write-Host "[*] Safe to copy to Windows Server 2022 or any Windows system`n" -ForegroundColor Yellow
