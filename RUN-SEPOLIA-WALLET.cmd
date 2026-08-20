@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run-sepolia-wallet.ps1"
set "LAUNCHER_RESULT=%ERRORLEVEL%"
exit /b %LAUNCHER_RESULT%
