@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

where cargo >nul 2>&1
if errorlevel 1 (
  echo.
  echo  Rust/Cargo를 찾지 못했습니다.
  echo  https://rustup.rs 에서 Rust를 한 번 설치한 뒤 다시 실행해 주세요.
  echo.
  pause
  exit /b 1
)

echo.
echo  Your Wallet - Sepolia 테스트넷 전용
echo  [1/2] 잠금된 의존성으로 릴리스 앱을 빌드합니다.
echo  처음에는 몇 분 걸릴 수 있습니다. 창을 닫지 말고 기다려 주세요.
echo.

cargo build --release --locked --manifest-path "demo\sepolia-wallet\Cargo.toml"
if errorlevel 1 (
  echo.
  echo  빌드에 실패했습니다. 위 오류 내용을 확인해 주세요.
  echo.
  pause
  exit /b 1
)

if not exist "demo\sepolia-wallet\target\release\sepolia-wallet-demo.exe" (
  echo.
  echo  빌드는 끝났지만 실행 파일을 찾지 못했습니다.
  echo.
  pause
  exit /b 1
)

echo.
echo  [2/2] Sepolia 테스트 지갑을 엽니다.
start "" "demo\sepolia-wallet\target\release\sepolia-wallet-demo.exe"
if errorlevel 1 (
  echo.
  echo  앱을 열지 못했습니다. 이 창의 오류를 확인해 주세요.
  echo.
  pause
  exit /b 1
)
exit /b 0
