@echo off

if "%~1"=="" (
    echo Usage: .\BLUM.bat [csv list of users]
    exit /b
) 

:: Main menu 
:x
cls
:: Aesthetics are important
echo [33m----------- Bulk Local User Management -----------[0m
echo:
echo [96mNOTE: This tool is intended to be used to mass-manage [1mlocal users[0m[96m on systems. Please run this script in an elevated prompt.[0m
echo:

echo [4mOptions:[0m
echo  [36m1.[0m Change passwords for all users in file
echo  [36m2.[0m Enable/Disable all users in file
echo  [36m3.[0m Exit
echo:

set /p choice="Choose an option: "
if %choice%==1 (
    goto 1
) else if %choice%==2 (
    goto 2
) else if %choice%==3 (
    goto 3
) else (
    echo:
    echo [31mInvalid choice, please try again.[0m
    timeout /t 3
    goto x
)

:: Changing passwords for all users
:1
cls
:: Using powershell to mask inputs for entering password twice
echo [91mWARNING: The password input forms take in signals (CTRL+C, CTRL+D, etc.) as standard input. If you need to kill the program for some reason, just mismatch the passwords and hit Ctrl+C when the timeout shows up.[0m
echo: 
set "psCommand=powershell -Command "$pword = read-host 'Enter password' -AsSecureString ; ^
    $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pword); ^
        [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)""
for /f "usebackq delims=" %%p in (`%psCommand%`) do set pass1=%%p

set "psCommand=powershell -Command "$pword = read-host 'Enter password again to confirm' -AsSecureString ; ^
    $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pword); ^
        [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)""
for /f "usebackq delims=" %%p in (`%psCommand%`) do set pass2=%%p

:: Comparing for password confirmation
setlocal EnableDelayedExpansion
if !pass1!==!pass2! ( 
    echo [92mPasswords match![0m 
    echo:
    echo [96mStand by, changing passwords...[0m
    echo:

    :: Attempting to change passwords
    for /F "skip=1 tokens=2 delims=," %%G in ('type "%~1%"') do (
        net user %%G !pass1!
    )

    echo:
    echo [96mPasswords have attempted to be changed.[0m
    timeout /t 5
) else (
    :: Password mismatch
    echo [31mPasswords don't match, please try again.[0m
    timeout /t 5
    goto 1
)
goto x

:: Enabling/Disabling users
:2
cls
echo [4mOptions:[0m
echo  [36m1.[0m Disable all users in file
echo  [36m2.[0m Enable all users in file
echo  [36m3.[0m Return to main menu
echo:

set /p answer="Choose an option: "
if %answer%==1 (
    goto one
) else if %answer%==2 (
    goto two
) else if %answer%==3 (
    goto three
) else (
    echo [31mInvalid choice, please try again.[0m
    timeout /t 3
    goto 2
)

:: Disabling users
:one
cls
echo [93mAttempting to disable users...[0m
echo:

:: Attempting to disable users
for /F "skip=1 tokens=2 delims=," %%G in ('type "%~1%"') do (
    net user %%G /active:no
)

echo:
echo [96mSpecified users have attempted to be disabled.[0m
timeout /t 5
goto x

:: Enabling users
:two
cls
echo [93mAttempting to enable users...[0m

:: Attempting to enable users
for /F "skip=1 tokens=2 delims=," %%G in ('type "%~1%"') do (
    net user %%G /active:yes
)

echo:
echo [96mSpecified users have attempted to be enabled.[0m
timeout /t 5
goto x

:: Exiting to main menu
:three
goto x

:: Exiting the program
:3
cls
echo [33mBye![0m
exit /b
