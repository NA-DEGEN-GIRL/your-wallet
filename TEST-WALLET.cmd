@echo off
setlocal
cd /d "%~dp0"

echo.
echo ============================================================
echo  Your Wallet - safe development test
echo ============================================================
echo  This tests the production foundation and Sepolia demo.
echo  It does not create a key, send a transaction, or use funds.
echo.

echo [1/2] Running code and security tests...
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\check.ps1" check
if errorlevel 1 goto failed

echo.
echo [2/2] Running release-policy tests...
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\release\check.ps1" all
if errorlevel 1 goto failed

echo.
echo ============================================================
echo  PASS - all development and release-policy tests passed.
echo  Sepolia demo is runnable. Mainnet remains disabled.
echo ============================================================
set "RESULT=0"
goto finished

:failed
echo.
echo ============================================================
echo  FAIL - at least one test failed. Do not use this with funds.
echo ============================================================
set "RESULT=1"

:finished
if /I not "%~1"=="--no-pause" pause
exit /b %RESULT%
