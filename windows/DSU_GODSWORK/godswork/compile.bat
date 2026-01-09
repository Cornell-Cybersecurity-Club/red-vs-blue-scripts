@echo off
REM Quick compilation script for portable Windows executables
REM Static linking ensures compatibility across Windows systems

echo.
echo ========================================
echo   DSU GODSWORK Compilation Script
echo ========================================
echo.

REM Check if g++ is available
where g++ >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] g++ not found in PATH
    echo Please install MinGW-w64 or add it to your PATH
    echo Download: https://github.com/msys2/msys2-installer/releases
    exit /b 1
)

echo [*] Compiler found: 
g++ --version | findstr "g++"
echo.

REM Compile 1.exe (Process-based firewall)
echo [*] Compiling 1.exe (Process Firewall)...
g++ -o 1.exe 1.cpp ^
    -lpsapi ^
    -static-libgcc ^
    -static-libstdc++ ^
    -static ^
    -D_WIN32_WINNT=0x0603 ^
    -std=c++17 ^
    -O2 ^
    -s

if %ERRORLEVEL% NEQ 0 (
    echo [FAILED] 1.exe compilation failed
    exit /b 1
)
echo [SUCCESS] 1.exe compiled successfully
echo.

REM Compile main.exe (Subnet-wide hardening)
echo [*] Compiling UseThismain.exe (Subnet Hardening)...
g++ -o UseThismain16.exe main.cpp ^
    -lbcrypt ^
    -lws2_32 ^
    -lnetapi32 ^
    -lactiveds ^
    -ladsiid ^
    -lole32 ^
    -loleaut32 ^
    -liphlpapi ^
    -lmpr ^
    -municode ^
    -static-libgcc ^
    -static-libstdc++ ^
    -static ^
    -D_WIN32_WINNT=0x0603 ^
    -std=c++17 ^
    -O2 ^
    -s

if %ERRORLEVEL% NEQ 0 (
    echo [FAILED] UseThismain.exe compilation failed
    exit /b 1
)
echo [SUCCESS] UseThismain.exe compiled successfully
echo.

REM Show file sizes
echo ========================================
echo   Compilation Complete
echo ========================================
echo.
dir /b 1.exe UseThismain.exe 2>nul
echo.
for %%F in (1.exe UseThismain.exe) do (
    if exist %%F (
        for %%S in (%%F) do echo %%F - %%~zS bytes
    )
)
echo.
echo [*] Executables are statically linked for portability
echo [*] Safe to copy to Windows Server 16 or any Windows system
echo.
pause
