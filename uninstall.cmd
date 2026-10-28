@echo off
rem Your Wallet: remove the installed program for the current Windows user (scripts\uninstall.ps1).
rem Double-click this file. Options: uninstall.cmd [-DryRun] [-InstallDir <folder>] [-NoShortcut] [-NoNativeHost] [-RemoveWalletData]
rem Wallet data in %LOCALAPPDATA%\YourWallet is kept unless -RemoveWalletData and the typed confirmation phrase are given.
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\uninstall.ps1" %*
set "YW_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %YW_EXIT%
