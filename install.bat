@echo off
setlocal enabledelayedexpansion
title Nino Language Installer
echo ========================================================
echo         Nino High-Assurance Language Installer
echo ========================================================
echo.

set "INSTALL_DIR=%USERPROFILE%\.nino"
set "BIN_DIR=%INSTALL_DIR%\bin"

echo [*] Target installation directory: %INSTALL_DIR%
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo [*] Installing Nino compiler binary...
if not exist "%~dp0ninoc.exe" (
    echo [!] Error: ninoc.exe not found next to install.bat.
    exit /b 1
)

copy /Y "%~dp0ninoc.exe" "%BIN_DIR%\ninoc.exe" >nul
if errorlevel 1 (
    echo [!] Failed to copy ninoc.exe.
    exit /b 1
)
copy /Y "%~dp0ninoc.exe" "%BIN_DIR%\nino.exe" >nul

if exist "%~dp0bin\z3.exe" copy /Y "%~dp0bin\z3.exe" "%BIN_DIR%\z3.exe" >nul
if exist "%~dp0bin\libz3.dll" copy /Y "%~dp0bin\libz3.dll" "%BIN_DIR%\libz3.dll" >nul
if exist "%~dp0tools\z3.exe" copy /Y "%~dp0tools\z3.exe" "%BIN_DIR%\z3.exe" >nul
if exist "%~dp0tools\libz3.dll" copy /Y "%~dp0tools\libz3.dll" "%BIN_DIR%\libz3.dll" >nul

if exist "%~dp0std" (
    echo [*] Installing Standard Library...
    xcopy /E /I /Y "%~dp0std" "%INSTALL_DIR%\std" >nul
)
if exist "%~dp0runtime" (
    echo [*] Installing Runtime Headers...
    xcopy /E /I /Y "%~dp0runtime" "%INSTALL_DIR%\runtime" >nul
)

echo [*] Registering Nino to User PATH...
for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USER_PATH=%%B"

echo !USER_PATH! | find /I "%BIN_DIR%" >nul
if errorlevel 1 (
    if defined USER_PATH (
        setx PATH "!USER_PATH!;%BIN_DIR%" >nul
    ) else (
        setx PATH "%BIN_DIR%" >nul
    )
    echo [*] Added %BIN_DIR% to PATH.
) else (
    echo [*] %BIN_DIR% is already in PATH.
)

echo.
echo ========================================================
echo   [OK] Nino Language v1.2.1 installed successfully!
echo   Open a new terminal and type: ninoc version
echo ========================================================
echo.
