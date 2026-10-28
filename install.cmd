@echo off
rem Your Wallet: build from source and install for the current Windows user (scripts\install.ps1).
rem Double-click this file. Options: install.cmd [-DryRun] [-NoBuild] [-NoShortcut] [-NoNativeHost] [-InstallDir <folder>]
rem No administrator rights needed. Wallet data in %LOCALAPPDATA%\YourWallet is never touched.
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install.ps1" %*
set "YW_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %YW_EXIT%
