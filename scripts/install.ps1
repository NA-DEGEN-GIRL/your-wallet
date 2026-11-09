# scripts/install.ps1 - Your Wallet을 소스에서 빌드해 현재 사용자에게 설치한다 (spec.md D1, spec/01 §9.2).
# 저장소 루트의 install.cmd를 더블클릭하면 이 스크립트가 실행된다. 미리 빌드한 실행 파일은 배포하지 않는다(D1).
# Windows PowerShell 5.1과 PowerShell 7에서 동작한다. 관리자 권한이 필요 없다(현재 사용자 범위만 바꾼다).
#
# 사용 (저장소 루트에서):
#   install.cmd [-InstallDir <폴더>] [-FixPermissions] [-AllowUnsafeToolchainPath] [-AllowAncestorCargoConfig] [-AllowUnsafeSourcePath] [-NoShortcut] [-NoNativeHost] [-NoBuild] [-DryRun]
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install.ps1 [같은 옵션]
#
#   -InstallDir    설치 폴더. 기본 %LOCALAPPDATA%\Programs\YourWallet
#   -FixPermissions  이미 있는 설치 폴더를 다른 사용자가 바꿀 수 있으면(아래 권한 규칙) 그 폴더가 현재 사용자 소유일
#                  때만 권한을 고친다. 없으면 그런 폴더에는 설치하지 않는다.
#   -AllowUnsafeToolchainPath  빌드에 쓸 cargo·rustup·rustc(또는 그 폴더)를 다른 사용자가 바꿀 수 있어도(아래 도구 규칙)
#                  설명을 출력한 뒤 그대로 빌드한다. 없으면 그런 도구로는 빌드하지 않는다(종료 7).
#   -AllowAncestorCargoConfig  저장소 바깥 상위 폴더의 .cargo\config.toml·.cargo\config(아래 cargo 설정 규칙)가 있어도
#                  목록을 출력한 뒤 그대로 빌드한다. 없으면 그런 폴더에서는 빌드하지 않는다(종료 7).
#   -AllowUnsafeSourcePath  설치할 파일이 나오는 저장소 폴더·extension\·빌드 폴더(target\release)를 다른 사용자가 바꿀 수
#                  있어도(아래 소스 폴더 규칙), 또는 소스·빌드·설치 폴더에 낮은 무결성 레이블이 있어도(아래 레이블 규칙) 목록을
#                  출력한 뒤 그대로 설치한다. 없으면 그런 소스로는 설치하지 않는다(종료 1; 레이블은 대화형이면 '계속' 입력으로 계속).
#   -NoShortcut   시작 메뉴 바로가기를 만들지 않는다.
#   -NoNativeHost  HKCU에 Chrome native messaging host를 등록하지 않는다(manifest 파일은 설치 폴더에 쓴다).
#   -NoBuild       빌드하지 않고 이미 있는 target\release\yw-app.exe·yw-host.exe를 쓴다(빌드 도구 확인도 건너뛴다).
#   -DryRun        확인과 할 일 출력만 하고 아무것도 바꾸지 않는다(빌드·winget도 실행하지 않는다).
#
# 빌드 도구: rustup·cargo·rustc는 PATH에서 찾지 않고 %CARGO_HOME%\bin(CARGO_HOME이 드라이브 문자로 시작하는 절대 경로일
# 때) 또는 %USERPROFILE%\.cargo\bin의 전체 경로로 실행한다. 그 폴더나 파일(심볼릭 링크면 대상 파일과 그 폴더까지)의
# 소유자가 현재 사용자·SYSTEM·Administrators·TrustedInstaller가 아니거나, 그 밖의 SID에 쓰기·추가·삭제·하위 삭제·권한
# 변경·소유권 가져오기(GENERIC_WRITE·GENERIC_ALL 포함)를 주는 허용 ACE가 있으면 설명을 출력하고 종료 7
# (-AllowUnsafeToolchainPath면 계속). 다른 PATH 항목은 보지 않는다. git(커밋 표시용)은 Program Files 아래이거나 현재
# 사용자 소유 폴더이고 같은 권한 검사를 통과할 때만 쓰고, 아니면 커밋 표시를 건너뛴다. 빌드는 cargo +1.95.0이고
# Cargo.toml [profile.release]와 같은 값을 명령줄 --config로 다시 주며, 컴파일러·빌드 설정을 바꾸는 환경 변수를 빌드
# 동안만 지운다(Invoke-Build). cargo·rustc가 1.95.0이 아니면 종료 7. 빌드 폴더는 명령줄 --target-dir로 준다(아래 빌드 폴더).
#
# cargo 설정 규칙(Confirm-CargoConfigs): cargo는 저장소 루트와 그 모든 상위 폴더(D:\#Programming, D:\ 등)의
# .cargo\config.toml·.cargo\config, 그리고 CARGO_HOME의 config.toml·config를 빌드에 적용한다. 저장소 자신의 .cargo는
# 소스의 일부다. CARGO_HOME(위 도구 규칙과 같은 폴더: %CARGO_HOME% 또는 %USERPROFILE%\.cargo)은 사용자 자신의 설정이라
# 빌드 동작을 바꾸는 키(build.rustc*·build.rustflags·build.target, target.*.linker·target.*.rustflags, profile.release.*,
# [patch]·[source]·paths)가 있을 때 그 키를 출력해 경고만 한다. 그 밖의 상위 폴더에 그런 파일이 하나라도 있으면(드라이브 루트처럼
# 다른 사용자가 만들 수 있는 곳일 수 있다) 목록을 출력하고 종료 7(-AllowAncestorCargoConfig면 계속). 빌드는 또
# --config로 build.rustc-wrapper·build.rustc-workspace-wrapper를 빈 값으로, target.x86_64-pc-windows-msvc.linker를 기본
# link.exe로 고정한다.
#
# 순서: (1) 확장 파일·ID 확인 -> (2) 빌드 도구 확인(rustup·cargo, Visual Studio C++ 빌드 도구). 없으면 winget 명령을
# 보여 주고 Y라고 답할 때만 실행 -> (3) cargo +1.95.0 build --release --locked -p yw-app -p yw-host -> (4) 설치 폴더 확인(이전
# 설치가 있으면 업그레이드). 바꿀 파일을 실행 중인 yw-app·yw-host가 쓰고 있으면 닫아 달라고 묻는다(강제 종료하지 않는다)
# -> (5) yw-app.exe·yw-host.exe·uninstall.ps1·extension\(런타임 파일만) 복사. 내용이 같은 파일은 건너뛰고 이전 설치에만
# 있던 파일은 지운다 -> (6) native host manifest 쓰기·검증 -> (7) HKCU 등록 -> (8) 시작 메뉴 바로가기 -> 설치 기록, 안내.
# 지갑 데이터 %LOCALAPPDATA%\YourWallet\ 은 읽지도 바꾸지도 않는다. 같은 소스로 다시 실행해도 결과가 같다(멱등).
#
# 설치 폴더 권한: yw-host.exe·yw-app.exe·확장 파일·native host manifest를 다른 로컬 사용자가 바꾸면 지갑이 그 사용자의
# 코드를 실행한다. 그래서 새 설치 폴더는 현재 사용자·SYSTEM·Administrators만 모든 권한을 갖고 상속을 끊은 DACL로
# 만든다(C:\ 바로 아래처럼 Authenticated Users가 수정 권한을 물려주는 곳에서도 안전). 이미 있는 폴더(새 설치·업그레이드)는
# 소유자가 그 셋 중 하나가 아니거나, 그 밖의 SID(Users·Authenticated Users·Everyone 등)에 쓰기·수정·삭제·권한 변경·
# 소유권 가져오기를 주는 허용 ACE가 폴더나 그 안 항목에 있으면 설치하지 않는다(CREATOR OWNER의 상속 전용 ACE만 예외).
# -FixPermissions는 폴더가 현재 사용자 소유일 때만 위 DACL로 고친다.
#
# 소스 폴더 권한(Confirm-SourcePathsTrusted, 2026-11-01 검토 L7): 설치 폴더가 안전해도 복사해 오는 파일을 다른 사용자가
# 미리 바꿔 둘 수 있으면 그 사용자의 코드가 사설 폴더에 설치된다. 그래서 저장소 루트·scripts\·uninstall.ps1·extension\과
# 그 안의 런타임 파일·폴더, 그리고 빌드 뒤(또는 -NoBuild) 빌드 폴더(target 또는 CARGO_TARGET_DIR)·release\·yw-app.exe·
# yw-host.exe에 설치 폴더와 같은 권한 규칙(Get-AclProblem)을 적용한다. 예외: S-1-4-*(non-unique authority)과
# AppContainer(S-1-15-2-*·S-1-15-3-*) SID의 ACE는 무시한다 — 로그온 세션에 주어지는 SID가 아니고(샌드박스가 현재 사용자의
# 제한 토큰에 넣는 제한 SID·AppContainer SID), 그런 토큰은 사용자 SID 권한이 함께 있어야만 접근한다. 위반이면 목록을
# 출력하고 종료 1(-AllowUnsafeSourcePath면 경고 후 계속).
#
# 빌드 폴더(2026-11-08): CARGO_TARGET_DIR(상대 경로면 저장소 기준), 없으면 저장소의 target. cargo에 --target-dir로 그 폴더를
# 그대로 넘긴다 — 명령줄이 .cargo\config.toml·CARGO_HOME 설정의 build.target-dir과 CARGO_BUILD_TARGET_DIR보다 우선하므로,
# 설치 프로그램이 복사해 오는 release\ 폴더가 언제나 이번 빌드의 결과다(다른 곳에 빌드되고 옛 exe가 설치되는 일이 없다).
# 대상 지정(2026-11-10): CARGO_BUILD_TARGET은 빌드 동안 지우고, 설정 파일의 build.target(결과를 <빌드 폴더>\<대상>\release로
# 보낸다)은 아래 cargo 설정 규칙대로 경고한다. 그리고 빌드 직전에 release\의 yw-app.exe·yw-host.exe를 지운다: 변경 없는 빌드도
# cargo가 deps\에서 다시 링크해 되살리고, 결과가 다른 폴더로 간 빌드는 옛 exe를 설치하지 않고 종료 8로 멈춘다.
# cargo는 빌드 폴더의 빌드 스크립트·proc-macro를 실행하므로 빌드 폴더의 권한(소스 폴더 규칙)과 레이블(아래)은 cargo를 실행하기
# **전에** 본다: 빌드 폴더와 release\·release\build\·release\deps\(있는 것), 빌드 폴더가 아직 없으면 그것을 만들 가장 가까운
# 상위 폴더(다른 사용자나 낮은 무결성 프로세스가 먼저 만들 수 있으면 안 된다). 빌드 뒤에도 release\·yw-app.exe·yw-host.exe를
# 다시 본다.
#
# 무결성 레이블(2026-11-08, Confirm-IntegrityLabels): 소스(저장소 루트, Cargo.toml·Cargo.lock·rust-toolchain.toml, .cargo\·
# crates\·scripts\·extension\ 아래 모든 항목), 빌드 폴더(위), 설치 폴더(있으면 그 안 모든 항목, 없으면 만들 상위 폴더)의
# 무결성 레이블을 GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)로 읽는다(Get-Acl은 레이블을 돌려주지 않고 -Audit는 관리자
# 권한이 필요하다). 레이블 ACE가 Medium보다 낮거나(Low·Untrusted) 쓰기 금지(NW) 정책이 없으면 — 다른 도구가 저장소에 붙이는
# 일이 있다 — 브라우저 샌드박스 같은 낮은 무결성 프로세스도 현재 사용자 권한으로 그 파일을 바꿀 수 있고, 그 코드가 빌드·설치되어
# 지갑으로 실행된다. 그러면 목록과 이유, 되돌리는 명령(icacls "<폴더>" /setintegritylevel (OI)(CI)M)을 출력하고, 대화형이면
# '계속'을 정확히 입력할 때만 계속한다(그 밖의 입력은 종료 3; 소스와 빌드 폴더는 한 번, 설치 폴더는 따로 묻는다). 비대화형이면
# 종료 1(-AllowUnsafeSourcePath면 경고 후 계속). 설치 프로그램은 레이블을 바꾸지 않는다.
#
# 설치 기록(yw-install.json)에는 설치한 파일마다 SHA-256(hashes)을 남기고, 다음 실행에서 설치 폴더의 파일과 비교해 설치 뒤에
# 바뀐 파일을 경고한다(이번 설치가 소스의 파일로 다시 쓴다). 이전 버전의 기록(hashes 없음)은 비교하지 않는다.
#
# 상위 폴더 권한(Get-InstallAncestorProblems): 설치 폴더의 상위 폴더를 다른 사용자가 지우거나 이름을 바꾼 뒤 같은 경로에
# 자기 폴더를 만들 수 있으면, HKCU 등록이 가리키는 경로의 yw-host.exe를 그 사용자가 정한다. 그래서 -InstallDir이면
# 드라이브 루트까지, 기본 경로면 사용자 프로필(%USERPROFILE%)부터 아래의 이미 있는 상위 폴더마다 다음을 본다. "신뢰하지
# 않는 SID" = 현재 사용자·SYSTEM·Administrators·TrustedInstaller가 아닌 SID(CREATOR OWNER·CREATOR GROUP·OWNER RIGHTS와
# AppContainer SID S-1-15-2-*·S-1-15-3-*는 뺀다: 앞의 둘은 유효 ACE로는 아무에게도 권한을 주지 않고, OWNER RIGHTS는
# 아래에서 확인한 소유자에게만, AppContainer SID는 사용자 SID 권한과 함께 있어야만 접근을 준다). 그 폴더 자체에
# 적용되는 허용 ACE(상속받은 것 포함, 상속 전용 제외; 거부 ACE는 무시)가 신뢰하지 않는 SID들에 주는 권한을 모두 합쳐
#   (가) 링크(재분석 지점)이거나, 소유자가 신뢰하지 않는 SID이거나, DACL이 없거나, 합친 권한에 FILE_DELETE_CHILD·
#        WRITE_DAC·WRITE_OWNER·GENERIC_ALL이 있으면 거부.
#   (나) 합친 권한에 DELETE가 있고, 그 부모 폴더(드라이브 루트가 아닐 때)의 합친 권한에 파일 추가·폴더 추가·
#        GENERIC_WRITE가 있으면 거부(이 폴더를 옮기고 같은 이름으로 새로 만들 수 있다). 부모에 그 권한이 없으면 DELETE만으로는
#        옮기거나 지울 수만 있고 바꿔치기할 수 없다(설치 실패일 뿐이다).
#   읽기 권한, 그리고 파일·폴더 추가만(C:\의 Authenticated Users "폴더 만들기"처럼)은 이미 있는 하위 폴더를 바꿀 수 없으므로
#   거부하지 않는다. 없는 중간 폴더는 설치 폴더와 같은 DACL로 하나씩 만들고 소유자·DACL을 다시 확인한다(다른 사용자가
#   먼저 같은 이름을 만들었으면 소유자가 달라 거부된다). 시스템 폴더의 권한은 바꾸지 않는다. 위반은 종료 1.
#
# 종료 코드:
#   0  성공(-DryRun 포함)
#   1  환경·인자 오류(저장소 밖의 사본을 실행, LOCALAPPDATA 없음, 64비트 Windows 아님, 쓸 수 없는 설치 경로,
#      설치 기록이 없는 비어 있지 않은 폴더, 다른 사용자가 바꿀 수 있는 설치 폴더나 상위 폴더, 다른 사용자가 바꿀 수
#      있는 소스·빌드 폴더, 비대화형 실행에서 낮은 무결성 레이블(둘 다 -AllowUnsafeSourcePath 없음) 등)
#   2  소스·빌드 결과 오류(확장 파일 없음·형식 오류, 확장 ID 불일치, rust-toolchain.toml이 1.95.0이 아님,
#      -NoBuild인데 yw-app.exe·yw-host.exe 없음)
#   3  취소(사용자가 취소함 — 낮은 무결성 레이블 질문에 '계속' 아닌 입력 포함 — 또는 실행 중인 yw-app·yw-host를 닫아 달라고
#      물을 수 없는 비대화형 실행)
#   4  파일 복사·삭제·설치 기록 실패
#   5  native host manifest 검증 또는 HKCU 등록 실패
#   6  시작 메뉴 바로가기 생성 실패
#   7  빌드 도구(Rust·C++ 빌드 도구) 없음: 설치하지 않기로 했거나, 비대화형이라 물을 수 없거나, 설치 뒤에도 찾지 못함.
#      다른 사용자가 바꿀 수 있는 위치의 Rust 도구(-AllowUnsafeToolchainPath 없음), cargo·rustc가 1.95.0이 아님,
#      Rust 기본 대상이 x86_64-pc-windows-msvc가 아님, 저장소 바깥 상위 폴더의 cargo 설정 파일(-AllowAncestorCargoConfig 없음)
#   8  빌드 실패
#   9  예상하지 못한 오류(스크립트 결함; 출력된 줄 번호와 함께 알려 주세요)
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = '',
    [switch]$FixPermissions,
    [switch]$AllowUnsafeToolchainPath,
    [switch]$AllowAncestorCargoConfig,
    [switch]$AllowUnsafeSourcePath,
    [switch]$NoShortcut,
    [switch]$NoNativeHost,
    [switch]$NoBuild,
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExtensionId = 'nnpjlobjgbanccjddghlpaafpohfkeph'   # extension/extension-id.txt (spec.md D22, spec/05 §2.3)
$HostName = 'com.your_wallet.native'
$HostDescription = 'Your Wallet native messaging host'
$RegistryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$MarkerName = 'yw-install.json'
$ShortcutName = 'Your Wallet.lnk'
$RustToolchain = '1.95.0'   # cargo·rustc의 +툴체인. rust-toolchain.toml channel과 같아야 한다(빌드 전에 확인).
$BuildArgs = @('build', '--release', '--locked', '-p', 'yw-app', '-p', 'yw-host')
# Cargo.toml [profile.release]와 정확히 같은 값을 명령줄 --config로 다시 준다(명령줄이 환경 변수와 상위 폴더·CARGO_HOME의
# .cargo\config.toml보다 우선한다). 문자열은 TOML 리터럴('...')로 쓴다: Windows PowerShell 5.1은 네이티브 인자 안의
# 큰따옴표를 escape하지 않아 "fat"이 cargo에 fat으로 간다. 같은지는 scripts/install.test.mjs가 확인한다.
$ReleaseProfileOverrides = @('codegen-units=1', "lto='fat'", 'overflow-checks=true', "panic='abort'", "strip='symbols'", 'debug=false')
# 같은 방식으로 컴파일러 래퍼를 끄고(빈 문자열 = 래퍼 없음) 링커를 rustc의 MSVC 기본값(link.exe)으로 고정한다. 상위
# 폴더·CARGO_HOME의 설정이나 환경 변수가 정한 값보다 우선한다.
$BuildConfigOverrides = @("build.rustc-wrapper=''", "build.rustc-workspace-wrapper=''", "target.x86_64-pc-windows-msvc.linker='link.exe'")
# 빌드(cargo·rustc 실행) 동안만 지우는 환경 변수: 정확한 이름과 접두사(대소문자 무시). RUSTFLAGS 계열은 아래 목록.
# CARGO_BUILD_TARGET은 결과를 <빌드 폴더>\<대상>\release로 보내 설치가 읽는 release\를 비껴간다(머리말의 빌드 폴더).
$ClearedBuildVariableNames = @('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET')
$ClearedBuildVariablePrefixes = @('CARGO_PROFILE_RELEASE_', 'CARGO_BUILD_RUSTC', 'CC', 'CFLAGS', 'CXX', 'CXXFLAGS')
# 사용자가 Y라고 답할 때만 실행하는 winget 명령(인자 문자열 그대로 winget에 넘긴다).
$RustupWingetArgs = 'install --id Rustlang.Rustup -e'
$BuildToolsWingetArgs = 'install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
$MsvcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
$RustflagsVariables = @('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')
# 설치 폴더 권한(위 머리말): 모든 권한을 갖는 SID와, 다른 SID에 주면 안 되는 권한 비트.
$SidSystem = 'S-1-5-18'
$SidAdministrators = 'S-1-5-32-544'
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$SidCreatorOwner = 'S-1-3-0'
# WriteData/AddFile 0x2, AppendData/AddSubdirectory 0x4, WriteExtendedAttributes 0x10, DeleteChild 0x40,
# WriteAttributes 0x100, DELETE 0x10000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000, GENERIC_ALL 0x10000000,
# GENERIC_WRITE 0x40000000.
$UnsafeRightsMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
# 상위 폴더 규칙(머리말): (가) DeleteChild·WRITE_DAC·WRITE_OWNER·GENERIC_ALL, (나) DELETE + 부모의 파일·폴더 추가·GENERIC_WRITE.
$AncestorTakeoverMask = 0x40 -bor 0x40000 -bor 0x80000 -bor 0x10000000
$AncestorDeleteMask = 0x10000
$AncestorCreateEntryMask = 0x2 -bor 0x4 -bor 0x40000000

# ---------------------------------------------------------------- 출력·공통

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "== $Message" -ForegroundColor Cyan
}

function Write-Plan([string]$Message) {
    Write-Host "  [DryRun] $Message" -ForegroundColor DarkYellow
}

function Write-Warn([string]$Message) {
    Write-Host "  주의: $Message" -ForegroundColor Yellow
}

function Stop-Install([int]$Code, [string]$Message) {
    Write-Host ''
    Write-Host "설치 실패(종료 코드 $Code): $Message" -ForegroundColor Red
    exit $Code
}

function Test-Interactive {
    if (-not [Environment]::UserInteractive) { return $false }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { return $false }
    foreach ($arg in [Environment]::GetCommandLineArgs()) {
        if ($arg -match '^-(?i:noni)') { return $false }
    }
    return $true
}

function Get-InnerException($ErrorRecordOrException) {
    $ex = $ErrorRecordOrException
    if ($ex -is [System.Management.Automation.ErrorRecord]) { $ex = $ex.Exception }
    while ($null -ne $ex.InnerException -and $ex -is [System.Management.Automation.RuntimeException]) { $ex = $ex.InnerException }
    return $ex
}

# 출력이 파일·파이프로 갈 때 한글이 콘솔 코드 페이지로 깨지지 않게 UTF-8로 쓴다(콘솔 창에서는 바꾸지 않는다).
function Set-RedirectedOutputUtf8 {
    try {
        if ([Console]::IsOutputRedirected) { [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false) }
    } catch { }
}

# 네이티브 명령: stderr 진행 출력이 PowerShell 오류로 바뀌지 않게 Continue로 실행하고 종료 코드를 돌려준다.
# stdout은 화면으로 보낸다(cargo·rustup의 진행 출력은 stderr로 바로 나간다).
function Invoke-NativeCommand([string]$Exe, [string[]]$ArgList) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @ArgList | Out-Host
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}

# 네이티브 명령의 stdout 줄을 돌려준다. 명령이 없거나 실패하면 $null. $Exe는 전체 경로다(PATH에서 찾지 않는다).
# -ShowStderr: stderr(예: rustup의 툴체인 내려받기 진행)를 숨기지 않고 화면에 보인다.
function Get-NativeOutput([string]$Exe, [string[]]$ArgList, [switch]$ShowStderr) {
    if ([string]::IsNullOrEmpty($Exe) -or -not [IO.Path]::IsPathRooted($Exe) -or -not (Test-Path -LiteralPath $Exe -PathType Leaf)) { return $null }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($ShowStderr) { $lines = @(& $Exe @ArgList) } else { $lines = @(& $Exe @ArgList 2>$null) }
        if ($LASTEXITCODE -ne 0) { return $null }
        return , [string[]]$lines
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $previous
    }
}

# ---------------------------------------------------------------- 경로

function ConvertTo-FullPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    return $full
}

# $Child가 $Parent와 같거나 그 아래이면 true (대소문자 무시).
function Test-PathInside([string]$Child, [string]$Parent) {
    $c = $Child.TrimEnd('\')
    $p = $Parent.TrimEnd('\')
    return $c.Equals($p, [StringComparison]::OrdinalIgnoreCase) -or $c.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase)
}

# 설치 폴더 안 상대 경로('/' 구분)가 안전한지: 절대 경로·'..'·드라이브·예약 문자 금지.
function Test-RelativePackagePath([string]$Rel) {
    if ([string]::IsNullOrEmpty($Rel) -or $Rel.Length -gt 200) { return $false }
    if ($Rel -match '[\x00-\x1f\x7f\\:*?"<>|]') { return $false }
    if ($Rel.StartsWith('/')) { return $false }
    foreach ($segment in $Rel.Split('/')) {
        if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..' -or $segment.EndsWith(' ') -or $segment.EndsWith('.')) { return $false }
    }
    return $true
}

function Join-RelativePath([string]$Base, [string]$Rel) {
    $full = [IO.Path]::GetFullPath((Join-Path $Base ($Rel.Replace('/', '\'))))
    if (-not $full.StartsWith($Base.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "path escapes base: $Rel"
    }
    return $full
}

function Get-Sha256Hex([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { $bytes = $sha.ComputeHash($stream) } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

# 다른 프로세스가 실행·사용 중이라 덮어쓰거나 지울 수 없는 파일이면 true.
function Test-FileLocked([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Dispose()
        return $false
    } catch {
        $inner = Get-InnerException $_
        return ($inner -is [IO.IOException]) -and -not ($inner -is [IO.FileNotFoundException]) -and -not ($inner -is [IO.DirectoryNotFoundException])
    }
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Read-Utf8Strict([string]$Path) {
    return [IO.File]::ReadAllText($Path, (New-Object Text.UTF8Encoding($false, $true)))
}

# ---------------------------------------------------------------- 설치 폴더 권한

function Get-CurrentUserSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

# 보안 설명자(SDDL)가 설치 폴더·파일(그리고 빌드 도구 파일·폴더)로 안전하면 $null, 아니면 이유 문장. 소유자는 현재
# 사용자·SYSTEM·Administrators·TrustedInstaller여야 하고(소유자는 언제든 DACL을 바꿀 수 있다), 그 밖의 SID에 쓰기 계열 권한($UnsafeRightsMask)을
# 주는 허용 ACE가 없어야 한다. 상속 전용 ACE도 앞으로 만들 파일에 적용되므로 본다(CREATOR OWNER의 상속 전용
# ACE만 예외: 만든 사람 자신의 ACE가 된다). 거부 ACE는 권한을 줄이기만 하므로 무시한다.
function Get-TrustedSids([string]$UserSid) {
    return @($UserSid, $SidSystem, $SidAdministrators, $SidTrustedInstaller)
}

function Get-AclProblem([string]$Sddl, [string]$UserSid) {
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    $trusted = Get-TrustedSids $UserSid
    if ($null -eq $sd.Owner -or $trusted -notcontains $sd.Owner.Value) {
        return "소유자가 현재 사용자·SYSTEM·Administrators가 아닙니다($(if ($null -eq $sd.Owner) { '없음' } else { $sd.Owner.Value }))"
    }
    if ($null -eq $sd.DiscretionaryAcl) { return 'DACL이 없어 모든 사용자가 모든 권한을 가집니다' }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.QualifiedAce]) { return '알 수 없는 형식의 ACE가 있습니다' }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        $sid = $ace.SecurityIdentifier.Value
        if ($trusted -contains $sid) { continue }
        $inheritOnly = ([int]$ace.AceFlags -band 0x08) -ne 0   # INHERIT_ONLY_ACE
        if ($sid -eq $SidCreatorOwner -and $inheritOnly) { continue }
        if (($ace.AccessMask -band $UnsafeRightsMask) -ne 0) {
            return "다른 사용자($sid)에게 쓰기·수정·삭제·권한 변경 권한이 있습니다(0x$('{0:x}' -f $ace.AccessMask))"
        }
    }
    return $null
}

# 설치 폴더용 DACL: 현재 사용자·SYSTEM·Administrators 모든 권한(하위 폴더·파일에 상속), 부모에서 상속 끊음.
function New-InstallDirSecurity([string]$UserSid) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in $UserSid, $SidSystem, $SidAdministrators) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    return $security
}

# DACL만 쓴다(소유자·SACL은 그대로). Set-Acl은 새 보안 객체에도 SACL까지 쓰려다 관리자가 아니면 SeSecurityPrivilege
# 오류가 나므로, 바뀐 부분(DACL)만 쓰는 .NET SetAccessControl을 쓴다: Windows PowerShell 5.1(.NET Framework)은
# DirectoryInfo/FileInfo의 메서드, PowerShell 7(.NET)은 FileSystemAclExtensions.
function Set-PathSecurity([string]$Path, $Security) {
    $item = Get-Item -LiteralPath $Path -Force
    $extensions = 'System.IO.FileSystemAclExtensions' -as [type]
    if ($null -eq $extensions) {
        $item.SetAccessControl($Security)
    } elseif ($item.PSIsContainer) {
        $extensions::SetAccessControl([IO.DirectoryInfo]$item, [Security.AccessControl.DirectorySecurity]$Security)
    } else {
        $extensions::SetAccessControl([IO.FileInfo]$item, [Security.AccessControl.FileSecurity]$Security)
    }
}

# 폴더와 그 안 모든 항목(재분석 지점은 따라가지 않는다)의 권한 문제. 문제가 없으면 빈 배열.
function Get-InstallDirProblems([string]$Dir, [string]$UserSid) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $problem = Get-AclProblem (Get-Acl -LiteralPath $Dir).Sddl $UserSid
    if ($null -ne $problem) { $problems.Add("$Dir : $problem") }
    foreach ($item in @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -ErrorAction Stop)) {
        $problem = Get-AclProblem (Get-Acl -LiteralPath $item.FullName).Sddl $UserSid
        if ($null -ne $problem) { $problems.Add("$($item.FullName) : $problem") }
    }
    return , $problems.ToArray()
}

# 소스 폴더 규칙(머리말): Get-AclProblem과 같되, 로그온 세션에 주어지지 않는 SID(S-1-4-*, AppContainer S-1-15-2-*·
# S-1-15-3-*)의 ACE는 빼고 본다.
$SourceIgnoredSidPattern = '^S-1-(4|15-2|15-3)-'

function Get-SourceAclProblem([string]$Sddl, [string]$UserSid) {
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -ne $sd.DiscretionaryAcl) {
        for ($index = $sd.DiscretionaryAcl.Count - 1; $index -ge 0; $index--) {
            $ace = $sd.DiscretionaryAcl[$index]
            if ($ace -is [Security.AccessControl.QualifiedAce] -and $ace.SecurityIdentifier.Value -match $SourceIgnoredSidPattern) {
                $sd.DiscretionaryAcl.RemoveAce($index)
            }
        }
    }
    return Get-AclProblem ($sd.GetSddlForm([Security.AccessControl.AccessControlSections]::All)) $UserSid
}

# $Paths 중 있는 것마다 Get-SourceAclProblem. 문제 문장 목록(없으면 빈 배열).
function Get-SourcePathProblems([string[]]$Paths, [string]$UserSid) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($path in $Paths) {
        if ([string]::IsNullOrEmpty($path) -or $seen.ContainsKey($path.ToLowerInvariant())) { continue }
        $seen[$path.ToLowerInvariant()] = $true
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $problem = Get-SourceAclProblem (Get-Acl -LiteralPath $path).Sddl $UserSid
        if ($null -ne $problem) { $problems.Add("$path : $problem") }
    }
    return , $problems.ToArray()
}

# 소스·빌드 폴더 확인: 문제가 있으면 목록을 출력하고 종료 1(-AllowUnsafeSourcePath면 경고 후 계속).
function Confirm-SourcePathsTrusted([string[]]$Paths, [string]$UserSid, [bool]$Allow) {
    $problems = Get-SourcePathProblems $Paths $UserSid
    if ($problems.Count -eq 0) { return }
    Write-Host '  설치할 파일이 나오는 소스·빌드 폴더를 다른 사용자가 바꿀 수 있습니다:' -ForegroundColor Yellow
    foreach ($problem in $problems) { Write-Host "    - $problem" }
    if ($Allow) {
        Write-Warn '-AllowUnsafeSourcePath: 그대로 설치합니다. 그 사용자가 실행 파일이나 확장 파일을 바꿔 두었다면 그대로 설치됩니다.'
        return
    }
    Stop-Install 1 '이 소스로는 설치하지 않습니다. 다른 사용자가 저장소나 빌드 폴더의 파일을 바꿔 두면 그 코드가 지갑으로 설치됩니다. 저장소를 사용자 프로필 아래(예: %USERPROFILE%\src)에 다시 받아 설치하거나, 폴더 권한을 확인한 뒤 -AllowUnsafeSourcePath로 실행하세요.'
}

# ---------------------------------------------------------------- 무결성 레이블(머리말의 레이블 규칙)

# 레이블은 SACL의 ML ACE라 Get-Acl이 돌려주지 않고 Get-Acl -Audit는 SeSecurityPrivilege(관리자)가 필요하다. READ_CONTROL만 쓰는
# GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)로 읽는다(메모리에서만 만드는 P/Invoke: Add-Type처럼 %TEMP%에 쓰거나
# 컴파일러를 실행하지 않는다; scripts/check.ps1과 같은 방식).
$script:NativeLabel = $null
function Get-NativeLabel {
    if ($null -ne $script:NativeLabel) { return $script:NativeLabel }
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object Reflection.AssemblyName('YwInstallNative')), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $type = $assembly.DefineDynamicModule('YwInstallNative').DefineType('YwInstallNative.Advapi', 'Public, Class')
    $out = [IntPtr].MakeByRefType()
    foreach ($m in @(
        @('advapi32.dll', 'GetNamedSecurityInfoW', [int], @([string], [int], [int], $out, $out, $out, $out, $out)),
        @('advapi32.dll', 'ConvertSecurityDescriptorToStringSecurityDescriptorW', [bool], @([IntPtr], [int], [int], $out, [IntPtr])),
        @('kernel32.dll', 'LocalFree', [IntPtr], @([IntPtr])))) {
        $method = $type.DefinePInvokeMethod($m[1], $m[0], [Reflection.MethodAttributes]'Public, Static, PinvokeImpl',
            [Reflection.CallingConventions]::Standard, $m[2], [type[]]$m[3],
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    $script:NativeLabel = $type.CreateType()
    return $script:NativeLabel
}

# $Path의 레이블 SDDL(예 'S:AI(ML;OICI;NW;;;LW)'; 레이블이 없으면 빈 문자열). 읽지 못하면 예외.
function Read-IntegrityLabel([string]$Path) {
    $native = Get-NativeLabel
    $owner = [IntPtr]::Zero; $group = [IntPtr]::Zero; $dacl = [IntPtr]::Zero; $sacl = [IntPtr]::Zero; $sd = [IntPtr]::Zero
    $status = $native::GetNamedSecurityInfoW($Path, 1, 0x10, [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$sd)   # SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION
    if ($status -ne 0) { throw "GetNamedSecurityInfoW 오류 $status" }
    try {
        $text = [IntPtr]::Zero
        if (-not $native::ConvertSecurityDescriptorToStringSecurityDescriptorW($sd, 1, 0x10, [ref]$text, [IntPtr]::Zero)) { throw 'ConvertSecurityDescriptorToStringSecurityDescriptorW 실패' }
        try { return [Runtime.InteropServices.Marshal]::PtrToStringUni($text) } finally { [void]$native::LocalFree($text) }
    } finally { [void]$native::LocalFree($sd) }
}

# 레이블 SDDL이 낮은 무결성 프로세스의 쓰기를 허용하면 이유 문장, 아니면 $null. 레이블이 없으면 Windows는 Medium + 쓰기 금지(NW)로
# 본다. 레이블 ACE마다(상속 전용 포함: 앞으로 그 안에 만들 항목에 붙는다) 수준이 Medium(S-1-16-8192)보다 낮거나(Low LW,
# Untrusted S-1-16-0) 정책에 NW가 없으면 문제다.
function Get-IntegrityLabelProblem([string]$Sddl) {
    if ([string]::IsNullOrEmpty($Sddl)) { return $null }
    foreach ($ace in [regex]::Matches($Sddl, '\(ML;([^;]*);([^;]*);[^;]*;[^;]*;([^)]+)\)')) {
        $flags = $ace.Groups[1].Value
        $rights = $ace.Groups[2].Value
        $sid = $ace.Groups[3].Value
        $level = switch -Regex ($sid) { '^LW$' { 0x1000 } '^ME$' { 0x2000 } '^MP$' { 0x2100 } '^HI$' { 0x3000 } '^SI$' { 0x4000 } '^S-1-16-(\d+)$' { [int64]$Matches[1] } default { -1 } }
        if ($rights -match '^0[xX]([0-9A-Fa-f]+)$') {
            $noWriteUp = ([Convert]::ToInt64($Matches[1], 16) -band 1) -ne 0
        } else {
            $noWriteUp = @([regex]::Matches($rights, '..') | ForEach-Object { $_.Value }) -contains 'NW'
        }
        $scope = ''
        if (@([regex]::Matches($flags, '..') | ForEach-Object { $_.Value }) -contains 'IO') { $scope = ' (상속 전용: 앞으로 그 안에 만드는 항목에 붙음)' }
        if ($level -lt 0x2000) {
            $name = switch ($sid) { 'LW' { 'Low' } 'S-1-16-0' { 'Untrusted' } default { $sid } }
            return "무결성 레이블 $name(Medium보다 낮음)$scope"
        }
        if (-not $noWriteUp) { return "무결성 레이블 $sid 에 쓰기 금지(NW) 정책이 없음$scope" }
    }
    return $null
}

# $Paths(있는 것만)와 $Trees 폴더 안의 모든 항목(재분석 지점은 따라가지 않는다)의 레이블 문제. "경로 : 이유" 목록.
function Get-IntegrityLabelProblems([string[]]$Paths, [string[]]$Trees) {
    $all = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in @($Paths) + @($Trees)) { if (-not [string]::IsNullOrEmpty($path)) { $all.Add($path) } }
    foreach ($tree in @($Trees)) {
        if ([string]::IsNullOrEmpty($tree) -or -not (Test-Path -LiteralPath $tree -PathType Container)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $tree -Recurse -Force -ErrorAction Stop)) { $all.Add($item.FullName) }
    }
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($path in $all) {
        if ($seen.ContainsKey($path.ToLowerInvariant())) { continue }
        $seen[$path.ToLowerInvariant()] = $true
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $problem = Get-IntegrityLabelProblem (Read-IntegrityLabel $path)
        } catch {
            $problem = "무결성 레이블을 읽지 못했습니다($((Get-InnerException $_).Message))"
        }
        if ($null -ne $problem) { $problems.Add("$path : $problem") }
    }
    return , $problems.ToArray()
}

# 레이블 확인: 문제가 있으면 목록·이유와 되돌리는 명령($Root 기준)을 출력한다(레이블은 바꾸지 않는다). $Allow
# (-AllowUnsafeSourcePath)면 경고 후 계속, 대화형이면 '계속'을 정확히 입력해야 계속(그 밖의 입력은 종료 3), 비대화형이면 종료 1.
# 같은 $Key로 이미 '계속'을 받았으면 다시 묻지 않는다(소스와 빌드 폴더는 'build', 설치 폴더는 'install').
$script:LabelAccepted = @{}
function Confirm-IntegrityLabels([string]$What, [string]$Key, [string]$Root, [string[]]$Paths, [string[]]$Trees, [bool]$Allow) {
    $problems = Get-IntegrityLabelProblems $Paths $Trees
    if ($problems.Count -eq 0) { return }
    Write-Host "  $What 에 낮은 무결성 레이블이 있습니다:" -ForegroundColor Yellow
    foreach ($problem in @($problems | Select-Object -First 10)) { Write-Host "    - $problem" }
    if ($problems.Count -gt 10) { Write-Host "    - 그 밖에 $($problems.Count - 10)개" }
    Write-Host '  이 레이블은 보통 다른 도구(샌드박스·에디터 확장 등)가 붙인 것입니다. 레이블이 있으면 브라우저 샌드박스 같은 낮은 무결성'
    Write-Host '  프로세스도 현재 사용자 권한으로 이 파일을 바꿀 수 있고, 바뀐 코드가 빌드·설치되어 지갑(yw-app·yw-host)으로 실행됩니다.'
    Write-Host '  설치 프로그램은 레이블을 바꾸지 않습니다. 직접 붙인 것이 아니면 다음 명령으로 보통 수준(Medium)으로 되돌린 뒤 다시'
    Write-Host '  실행하세요(하위 항목에 따로 붙은 레이블이 남으면 끝에 /T를 붙입니다):'
    Write-Host "    icacls `"$Root`" /setintegritylevel (OI)(CI)M"
    if ($script:LabelAccepted.ContainsKey($Key)) {
        Write-Warn '위에서 이미 계속하기로 했습니다.'
        return
    }
    if ($Allow) {
        Write-Warn '-AllowUnsafeSourcePath: 레이블을 그대로 두고 계속합니다. 낮은 무결성 프로세스가 파일을 바꿔 두었다면 그대로 빌드·설치됩니다.'
        return
    }
    if (-not (Test-Interactive)) {
        Stop-Install 1 "낮은 무결성 레이블이 있는 $What 로는 설치하지 않습니다(비대화형이라 물을 수 없습니다). 위 명령으로 레이블을 되돌린 뒤 다시 실행하거나, 위험을 이해했으면 -AllowUnsafeSourcePath로 실행하세요."
    }
    $answer = "$(Read-Host "  그래도 계속하려면 '계속'을 입력하세요(그 밖의 입력 = 설치 취소)")".Trim()
    if ($answer -cne '계속') { Stop-Install 3 '설치를 취소했습니다. 레이블을 되돌린 뒤 다시 실행하세요.' }
    $script:LabelAccepted[$Key] = $true
    Write-Warn '레이블을 그대로 두고 계속합니다.'
}

# 가장 가까운 있는 상위 폴더(없으면 $null).
function Get-ExistingAncestor([string]$Path) {
    $parent = [IO.Path]::GetDirectoryName($Path)
    while (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) { $parent = [IO.Path]::GetDirectoryName($parent) }
    return $parent
}

# cargo 실행 전에 볼 빌드 폴더 경로(머리말의 빌드 폴더): 빌드 폴더와 release\·release\build\·release\deps\ 중 있는 것,
# 빌드 폴더가 아직 없으면 그것을 만들 가장 가까운 상위 폴더.
function Get-BuildDirPaths([string]$TargetDir) {
    if (-not (Test-Path -LiteralPath $TargetDir)) { return , [string[]]@(Get-ExistingAncestor $TargetDir | Where-Object { $_ }) }
    $release = Join-Path $TargetDir 'release'
    return , [string[]]@($TargetDir, $release, (Join-Path $release 'build'), (Join-Path $release 'deps') | Where-Object { Test-Path -LiteralPath $_ })
}

# 이미 있는 폴더를 고친다(-FixPermissions, 현재 사용자 소유일 때만 호출): 폴더에 설치 DACL, 안의 항목은 명시 ACE를
# 지우고 상속만 받게 한다.
function Set-InstallDirPermissions([string]$Dir, [string]$UserSid) {
    Set-PathSecurity $Dir (New-InstallDirSecurity $UserSid)
    foreach ($item in @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -ErrorAction Stop)) {
        if ($item.PSIsContainer) {
            $security = New-Object Security.AccessControl.DirectorySecurity
        } else {
            $security = New-Object Security.AccessControl.FileSecurity
        }
        $security.SetAccessRuleProtection($false, $false)
        Set-PathSecurity $item.FullName $security
    }
}

# $Dir의 상위 폴더 중 없는 것(위에서 아래 순서).
function Get-MissingParents([string]$Dir) {
    $missing = New-Object 'System.Collections.Generic.List[string]'
    $parent = [IO.Path]::GetDirectoryName($Dir)
    while (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) {
        $missing.Insert(0, $parent)
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return , $missing.ToArray()
}

# 폴더 하나를 처음부터 설치 DACL로 만든다(부모의 느슨한 ACL을 물려받는 순간이 없게). 만든 뒤 링크가 아님·소유자·
# DACL을 다시 확인한다(그 사이 다른 사용자가 같은 이름을 만들었으면 CreateDirectory는 그 폴더를 돌려주므로 소유자가
# 달라 여기서 거부된다).
function New-PrivateDirectory([string]$Dir, [string]$UserSid) {
    if (Test-Path -LiteralPath $Dir) { throw "만들려던 폴더가 이미 있습니다(다른 프로그램이 같은 이름을 만들었을 수 있습니다): $Dir" }
    $security = New-InstallDirSecurity $UserSid
    $created = $false
    try {
        [void][IO.Directory]::CreateDirectory($Dir, $security)   # .NET Framework (Windows PowerShell 5.1)
        $created = $true
    } catch [System.Management.Automation.MethodException] {
        $created = $false
    }
    if (-not $created) {
        $extensions = 'System.IO.FileSystemAclExtensions' -as [type]   # .NET 6+ (PowerShell 7)
        if ($null -ne $extensions) {
            [void]$extensions::CreateDirectory($security, $Dir)
        } else {
            [void][IO.Directory]::CreateDirectory($Dir)
        }
    }
    $item = Get-Item -LiteralPath $Dir -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "새로 만든 폴더가 링크입니다: $Dir" }
    Set-PathSecurity $Dir $security
    $acl = Get-Acl -LiteralPath $Dir
    $problem = Get-AclProblem $acl.Sddl $UserSid
    if ($null -ne $problem -or -not $acl.AreAccessRulesProtected) {
        throw "새 폴더의 권한을 확인하지 못했습니다: $Dir ($problem)"
    }
}

# 새 설치 폴더와 없는 상위 폴더를 모두 설치 DACL로 하나씩 만들고(New-PrivateDirectory), 설치 폴더가 비어 있음을 확인한다.
function New-InstallDir([string]$Dir, [string]$UserSid) {
    foreach ($parent in (Get-MissingParents $Dir)) { New-PrivateDirectory $parent $UserSid }
    New-PrivateDirectory $Dir $UserSid
    if (@(Get-ChildItem -LiteralPath $Dir -Force).Count -gt 0) {
        throw "새로 만든 설치 폴더가 비어 있지 않습니다(다른 프로그램이 같은 폴더를 만들었을 수 있습니다): $Dir"
    }
}

# 이미 있는 설치 폴더(비어 있거나 설치 기록이 있는 폴더)의 권한을 확인한다. 문제가 있으면 -FixPermissions이고 현재
# 사용자 소유일 때만 고치고, 아니면 종료 1.
function Confirm-InstallDirPermissions([string]$Dir, [string]$UserSid) {
    $problems = Get-InstallDirProblems $Dir $UserSid
    if ($problems.Count -eq 0) {
        Write-Host '  설치 폴더 권한: 다른 사용자는 바꿀 수 없습니다.'
        return
    }
    Write-Host '  설치 폴더를 다른 사용자가 바꿀 수 있습니다(그 사용자가 yw-host.exe 등을 바꿔치기할 수 있음):' -ForegroundColor Yellow
    foreach ($problem in @($problems | Select-Object -First 10)) { Write-Host "    - $problem" }
    $owner = (Get-Acl -LiteralPath $Dir).GetOwner([Security.Principal.SecurityIdentifier]).Value
    $ownedByUser = $owner -eq $UserSid
    $elsewhere = "사용자 프로필 아래의 새 폴더(예: -InstallDir `"$env:USERPROFILE\Apps\YourWallet`")를 지정하세요"
    if (-not $FixPermissions) {
        if ($ownedByUser) {
            Stop-Install 1 "이 폴더에는 설치하지 않습니다: $Dir. -FixPermissions를 붙여 다시 실행하면 권한을 현재 사용자·SYSTEM·Administrators만으로 고칩니다. 또는 $elsewhere."
        }
        Stop-Install 1 "이 폴더에는 설치하지 않습니다: $Dir (소유자 $owner, 현재 사용자 소유가 아니라 고칠 수 없습니다). $elsewhere."
    }
    if (-not $ownedByUser) {
        Stop-Install 1 "-FixPermissions는 현재 사용자 소유 폴더만 고칩니다(소유자 $owner): $Dir. $elsewhere."
    }
    if ($DryRun) {
        Write-Plan "권한 고치기: $Dir (현재 사용자·SYSTEM·Administrators만, 상속 끊음; 안의 항목은 상속만)"
        return
    }
    try {
        Set-InstallDirPermissions $Dir $UserSid
    } catch {
        Stop-Install 4 "설치 폴더 권한을 고치지 못했습니다: $Dir ($((Get-InnerException $_).Message))"
    }
    $problems = Get-InstallDirProblems $Dir $UserSid
    if ($problems.Count -gt 0) { Stop-Install 1 "권한을 고친 뒤에도 문제가 남았습니다: $($problems[0]). $elsewhere." }
    Write-Host '  설치 폴더 권한을 고쳤습니다(현재 사용자·SYSTEM·Administrators만).'
}

# 상위 폴더의 보안 설명자(SDDL): 소유자·DACL 문제(없으면 $null)와, 신뢰하지 않는 SID(머리말)에 이 폴더 자체에서
# 주는 권한의 합(유효 허용 ACE만: 상속 전용 ACE는 이 폴더에 적용되지 않고, 이미 있는 하위 폴더는 따로 검사한다).
function Get-AncestorAccess([string]$Sddl, [string]$UserSid) {
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    $trusted = Get-TrustedSids $UserSid
    $problem = $null
    if ($null -eq $sd.Owner -or $trusted -notcontains $sd.Owner.Value) {
        $problem = "소유자가 현재 사용자·SYSTEM·Administrators·TrustedInstaller가 아닙니다($(if ($null -eq $sd.Owner) { '없음' } else { $sd.Owner.Value }))"
    }
    if ($null -eq $sd.DiscretionaryAcl) {
        return [pscustomobject]@{ Problem = 'DACL이 없어 모든 사용자가 모든 권한을 가집니다'; Rights = -1 }
    }
    $rights = 0
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.QualifiedAce]) { $problem = '알 수 없는 형식의 ACE가 있습니다'; continue }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        if (([int]$ace.AceFlags -band 0x08) -ne 0) { continue }   # INHERIT_ONLY_ACE
        $sid = $ace.SecurityIdentifier.Value
        if ($trusted -contains $sid) { continue }
        if ($sid -eq 'S-1-3-0' -or $sid -eq 'S-1-3-1' -or $sid -eq 'S-1-3-4') { continue }   # CREATOR OWNER·CREATOR GROUP·OWNER RIGHTS
        if ($sid.StartsWith('S-1-15-2-') -or $sid.StartsWith('S-1-15-3-')) { continue }       # AppContainer 패키지·capability
        $rights = $rights -bor $ace.AccessMask
    }
    return [pscustomobject]@{ Problem = $problem; Rights = $rights }
}

function Read-AncestorAccess([string]$Dir, [string]$UserSid) {
    try {
        return Get-AncestorAccess (Get-Acl -LiteralPath $Dir).Sddl $UserSid
    } catch {
        return [pscustomobject]@{ Problem = "권한을 읽을 수 없습니다($((Get-InnerException $_).Message))"; Rights = -1 }
    }
}

# 설치 폴더 $Target의 이미 있는 상위 폴더(드라이브 루트부터; $CheckFrom이 있으면 그 폴더와 그 아래만)가 머리말의
# 규칙 (가)·(나)를 어기는 이유 목록. 없는 폴더를 만나면 멈춘다(그 아래는 설치 프로그램이 New-InstallDir로 만든다).
# 설치 폴더 자체는 Get-InstallDirProblems가 본다.
function Get-InstallAncestorProblems([string]$Target, [string]$UserSid, [string]$CheckFrom) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $chain = New-Object 'System.Collections.Generic.List[string]'
    $parent = [IO.Path]::GetDirectoryName($Target)
    while (-not [string]::IsNullOrEmpty($parent)) {
        $chain.Insert(0, $parent)
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    foreach ($dir in $chain) {
        if (-not [string]::IsNullOrEmpty($CheckFrom) -and -not (Test-PathInside $dir $CheckFrom)) { continue }
        $item = Get-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) { break }
        if (-not $item.PSIsContainer) { $problems.Add("$dir : 폴더가 아니라 파일입니다"); break }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $problems.Add("$dir : 링크(정션·심볼릭 링크)입니다. 링크가 아닌 실제 폴더 경로를 지정하세요")
            break
        }
        $access = Read-AncestorAccess $dir $UserSid
        if ($null -ne $access.Problem) { $problems.Add("$dir : $($access.Problem)"); continue }
        if (($access.Rights -band $AncestorTakeoverMask) -ne 0) {
            $problems.Add("$dir : 다른 사용자에게 하위 항목 삭제·권한 변경·소유권 가져오기 권한이 있습니다(0x$('{0:x}' -f $access.Rights))")
            continue
        }
        $dirParent = [IO.Path]::GetDirectoryName($dir)
        if (($access.Rights -band $AncestorDeleteMask) -ne 0 -and -not [string]::IsNullOrEmpty($dirParent)) {
            $parentAccess = Read-AncestorAccess $dirParent $UserSid
            if ($null -ne $parentAccess.Problem -or ($parentAccess.Rights -band $AncestorCreateEntryMask) -ne 0) {
                $problems.Add("$dir : 다른 사용자가 이 폴더를 옮기거나 지우고, 상위 폴더($dirParent)에 같은 이름의 폴더를 새로 만들 수 있습니다")
            }
        }
    }
    return , $problems.ToArray()
}

# ---------------------------------------------------------------- 소스 트리

# 루트 Cargo.toml [workspace.package] version.
function Get-WorkspaceVersion([string]$Root) {
    $text = Read-Utf8Strict (Join-Path $Root 'Cargo.toml')
    $section = [regex]::Match($text, '(?ms)^\[workspace\.package\][ \t]*\r?$(.*?)(?=^\[|\z)')
    if ($section.Success) {
        $match = [regex]::Match($section.Groups[1].Value, '(?m)^[ \t]*version[ \t]*=[ \t]*"(\d+\.\d+\.\d+)"')
        if ($match.Success) { return $match.Groups[1].Value }
    }
    return '0.0.0'
}

# rust-toolchain.toml channel (예: 1.95.0). 없으면 $null.
function Get-ToolchainChannel([string]$Root) {
    $path = Join-Path $Root 'rust-toolchain.toml'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $match = [regex]::Match((Read-Utf8Strict $path), '(?m)^[ \t]*channel[ \t]*=[ \t]*"([0-9A-Za-z.-]+)"')
    if ($match.Success) { return $match.Groups[1].Value }
    return $null
}

# Git으로 받은 저장소면 HEAD 커밋(12자), GitHub "Download ZIP" 등 .git이 없거나 믿을 수 있는 git이 없으면 $null.
function Get-SourceCommit([string]$Root, [string]$UserSid) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root '.git'))) { return $null }
    $git = Find-TrustedGit $UserSid
    if ($null -eq $git) {
        Write-Host '  참고: Program Files 아래나 다른 사용자가 바꿀 수 없는 내 폴더에서 git을 찾지 못해 커밋 표시를 건너뜁니다.'
        return $null
    }
    $lines = Get-NativeOutput $git @('-C', $Root, 'rev-parse', '--short=12', 'HEAD')
    if ($null -eq $lines -or $lines.Count -lt 1) { return $null }
    $commit = $lines[0].Trim()
    if ($commit -cnotmatch '^[0-9a-f]{7,40}$') { return $null }
    return $commit
}

function Format-Source([string]$Version, $Commit) {
    if ([string]::IsNullOrEmpty($Commit)) { return "버전 $Version" }
    return "버전 $Version, 커밋 $Commit"
}

# 설치할 확장 런타임 파일: scripts/audit-extension.mjs auditExtensionRoot().packagedFiles와 같은 목록, 같은 순서
# (manifest.json, popup/*, src/*.js, icons/*.png). tests/·native-host/·test-dapp/·package.json은 넣지 않는다.
# 두 목록이 같은지는 scripts/install.test.mjs가, 파일 내용은 scripts/check.ps1의 audit-ext 단계가 확인한다.
function Get-ExtensionRuntimeFiles([string]$ExtensionRoot) {
    $reparse = [IO.FileAttributes]::ReparsePoint
    $files = New-Object 'System.Collections.Generic.List[string]'
    $manifest = Get-Item -LiteralPath (Join-Path $ExtensionRoot 'manifest.json') -Force -ErrorAction SilentlyContinue
    if ($null -eq $manifest -or $manifest.PSIsContainer -or ($manifest.Attributes -band $reparse)) { throw 'extension\manifest.json이 없거나 일반 파일이 아닙니다.' }
    $files.Add('manifest.json')
    foreach ($dir in 'popup', 'src', 'icons') {
        $item = Get-Item -LiteralPath (Join-Path $ExtensionRoot $dir) -Force -ErrorAction SilentlyContinue
        if ($null -eq $item -or -not $item.PSIsContainer -or ($item.Attributes -band $reparse)) { throw "extension\$dir 폴더가 없거나 일반 폴더가 아닙니다." }
        $names = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in @(Get-ChildItem -LiteralPath $item.FullName -Force)) {
            if ($entry.PSIsContainer -or ($entry.Attributes -band $reparse)) { throw "extension\$dir 안에 쓸 수 없는 항목이 있습니다: $($entry.Name)" }
            if ($dir -eq 'src' -and $entry.Name -cnotmatch '^[A-Za-z0-9._-]+\.js$') { throw "extension\src 안에 .js가 아닌 파일이 있습니다: $($entry.Name)" }
            if ($dir -eq 'icons' -and $entry.Name -cnotmatch '^[A-Za-z0-9._-]+\.png$') { throw "extension\icons 안에 .png가 아닌 파일이 있습니다: $($entry.Name)" }
            $names.Add("$dir/$($entry.Name)")
        }
        if ($names.Count -eq 0) { throw "extension\$dir 폴더가 비어 있습니다." }
        $sorted = $names.ToArray()
        [Array]::Sort($sorted, [StringComparer]::Ordinal)
        $files.AddRange($sorted)
    }
    foreach ($rel in $files) {
        if (-not (Test-RelativePackagePath $rel)) { throw "확장 파일 경로를 쓸 수 없습니다: $rel" }
    }
    return , $files.ToArray()
}

# ---------------------------------------------------------------- 검증 (validate-manifest.mjs와 같은 규칙)

# 확장 ID = SHA-256(base64 디코딩한 manifest key) 앞 16바이트의 hex를 0-f -> a-p로 바꾼 32자 (spec/05 §2.3).
function Get-ExtensionIdFromKey([string]$Base64Key) {
    $der = [Convert]::FromBase64String($Base64Key)
    if ($der.Length -lt 64 -or [Convert]::ToBase64String($der) -cne $Base64Key) { throw 'invalid key' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($der) } finally { $sha.Dispose() }
    $sb = New-Object Text.StringBuilder
    for ($i = 0; $i -lt 16; $i++) {
        [void]$sb.Append([char](0x61 + ($hash[$i] -shr 4)))
        [void]$sb.Append([char](0x61 + ($hash[$i] -band 0xf)))
    }
    return $sb.ToString()
}

# extension/native-host/validate-manifest.mjs validAbsoluteWindowsExePath와 같다.
function Test-AbsoluteWindowsExePath([string]$Value) {
    if ($Value.Length -gt 32767 -or $Value -cnotmatch '^[A-Za-z]:\\') { return $false }
    $components = $Value.Substring(3).Split([char]'\')
    foreach ($component in $components) {
        if ($component.Length -eq 0 -or $component -eq '.' -or $component -eq '..' -or $component.EndsWith(' ') -or $component.EndsWith('.')) { return $false }
        if ($component -match '[<>:"/\\|?*\x00-\x1f]') { return $false }
    }
    return $components[$components.Length - 1].ToLowerInvariant() -ceq 'yw-host.exe'
}

# extension/native-host/validate-manifest.mjs validateNativeManifest와 같다(+ ID 일치).
function Test-NativeManifestValue($Value, [string]$ExpectedId) {
    if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $names = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    $expected = @('name', 'description', 'path', 'type', 'allowed_origins')
    if ($names.Count -ne $expected.Count) { return $false }
    foreach ($name in $names) { if ($expected -cnotcontains $name) { return $false } }
    $origins = $Value.allowed_origins
    if (-not ($Value.name -is [string]) -or $Value.name -cne $HostName) { return $false }
    if (-not ($Value.description -is [string]) -or $Value.description.Length -eq 0 -or $Value.description.Length -gt 128) { return $false }
    if (-not ($Value.type -is [string]) -or $Value.type -cne 'stdio') { return $false }
    if (-not ($Value.path -is [string])) { return $false }
    if ($Value.path -cmatch '__[A-Z0-9_]+__' -or $Value.path -match '[%&^!]') { return $false }
    if (-not (Test-AbsoluteWindowsExePath $Value.path)) { return $false }
    if (-not ($origins -is [array]) -or $origins.Count -ne 1 -or -not ($origins[0] -is [string])) { return $false }
    if ($origins[0] -cmatch '__[A-Z0-9_]+__') { return $false }
    $match = [regex]::Match($origins[0], '^chrome-extension://([a-p]{32})/\z')
    if (-not $match.Success) { return $false }
    return $match.Groups[1].Value -ceq $ExpectedId
}

# 파일 단위 검증: UTF-8(BOM 없음, 잘못된 바이트 거부) -> JSON -> Test-NativeManifestValue.
function Test-NativeManifestFile([string]$Path, [string]$ExpectedId) {
    try { $bytes = [IO.File]::ReadAllBytes($Path) } catch { return $false }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return $false }
    try {
        $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes)
        $value = ConvertFrom-Json -InputObject $text
    } catch { return $false }
    return Test-NativeManifestValue $value $ExpectedId
}

function New-NativeManifestJson([string]$HostExe) {
    $manifest = [ordered]@{
        name            = $HostName
        description     = $HostDescription
        path            = $HostExe
        type            = 'stdio'
        allowed_origins = @("chrome-extension://$ExtensionId/")
    }
    return (ConvertTo-Json -InputObject $manifest -Depth 3)
}

# ---------------------------------------------------------------- 설치 기록 (yw-install.json)

# 이전 배포 zip 설치의 기록(commit 없음)도 읽는다.
function Read-InstallMarker([string]$Dir) {
    $path = Join-Path $Dir $MarkerName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $value = ConvertFrom-Json -InputObject (Read-Utf8Strict $path)
        if ($value.product -cne 'YourWallet' -or -not ($value.version -is [string])) { throw 'product' }
        $files = @($value.files)
        foreach ($file in $files) {
            if (-not ($file -is [string]) -or -not (Test-RelativePackagePath $file)) { throw 'files' }
        }
        $commit = $null
        $commitProperty = $value.PSObject.Properties['commit']
        if ($null -ne $commitProperty -and $commitProperty.Value -is [string]) { $commit = $commitProperty.Value }
        # 파일별 SHA-256(2026-11-01부터). 없으면(이전 기록) 비교하지 않는다.
        $hashes = $null
        $hashesProperty = $value.PSObject.Properties['hashes']
        if ($null -ne $hashesProperty -and $null -ne $hashesProperty.Value) {
            $hashes = @{}
            foreach ($entry in $hashesProperty.Value.PSObject.Properties) {
                if (-not (Test-RelativePackagePath $entry.Name) -or -not ($entry.Value -is [string]) -or $entry.Value -cnotmatch '^[0-9a-f]{64}$') { throw 'hashes' }
                $hashes[$entry.Name] = $entry.Value
            }
        }
        return [pscustomobject]@{ Version = $value.version; Commit = $commit; Files = [string[]]$files; Hashes = $hashes }
    } catch {
        Stop-Install 1 "설치 기록 파일이 손상되었습니다: $path. 이 폴더에는 설치하지 않습니다. -InstallDir로 다른 빈 폴더를 지정하세요."
    }
}

function Write-InstallMarker([string]$Dir, [string]$Version, $Commit, [string]$State, [string[]]$Files, $Hashes = $null) {
    $sorted = [string[]]@($Files)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $marker = [ordered]@{
        product = 'YourWallet'
        version = $Version
        commit  = $Commit
        state   = $State
        files   = $sorted
    }
    if ($null -ne $Hashes) {
        $ordered = [ordered]@{}
        foreach ($file in $sorted) { if ($Hashes.ContainsKey($file)) { $ordered[$file] = $Hashes[$file] } }
        $marker['hashes'] = $ordered
    }
    $path = Join-Path $Dir $MarkerName
    $json = (ConvertTo-Json -InputObject $marker -Depth 3) + "`n"
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and ([IO.File]::ReadAllText($path) -ceq $json)) { return }
    Write-Utf8NoBom $path $json
}

# ---------------------------------------------------------------- 실행 중인 프로그램

# 프로세스를 하나씩 파이프라인으로 내보낸다(호출하는 쪽은 @()로 감싼다).
function Get-WalletProcesses {
    foreach ($process in @(Get-Process -Name 'yw-app', 'yw-host' -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $process.Path } catch { $path = $null }
        [pscustomobject]@{ Name = $process.ProcessName; Id = $process.Id; Path = $path; Process = $process }
    }
}

# 덮어쓰거나 지울 파일 중 사용 중인 것이 없어질 때까지 사용자에게 닫아 달라고 묻는다. 강제 종료는 하지 않는다.
# 반환: $true = 진행, $false = 취소(또는 물을 수 없음).
function Wait-FilesReleased([string[]]$Paths) {
    while ($true) {
        $locked = @($Paths | Where-Object { Test-FileLocked $_ })
        if ($locked.Count -eq 0) { return $true }
        $holders = @(Get-WalletProcesses | Where-Object { $null -ne $_.Path -and ($locked -contains $_.Path) })
        Write-Host ''
        Write-Host '  다음 파일을 실행 중인 프로그램이 쓰고 있어 바꿀 수 없습니다:' -ForegroundColor Yellow
        foreach ($path in $locked) { Write-Host "    - $path" }
        foreach ($holder in $holders) { Write-Host "    실행 중: $($holder.Name) (PID $($holder.Id))" }
        Write-Host '  - yw-app: 지갑 앱 창을 닫아 주세요(창을 닫으면 잠근 뒤 정상 종료합니다). 창이 보이지 않으면'
        Write-Host '    시작 메뉴의 Your Wallet을 실행하면 숨어 있던 창이 앞으로 나옵니다.'
        Write-Host '  - yw-host: Chrome이 확장 연결용으로 실행한 프로세스입니다. Chrome 창을 모두 닫으면 끝납니다.'
        Write-Host '  이 스크립트는 프로그램을 강제로 종료하지 않습니다.'
        if ($DryRun) {
            Write-Plan '실제 설치 때는 위 프로그램을 닫아 달라고 묻고 기다립니다.'
            return $true
        }
        if (-not (Test-Interactive)) {
            Write-Host '  비대화형 실행이라 물어볼 수 없습니다.' -ForegroundColor Yellow
            return $false
        }
        $answer = "$(Read-Host '  닫은 뒤 Enter = 다시 확인 / C = 지갑 앱에 정상 종료 요청(창 닫기와 같음) / Q = 설치 취소')".Trim()
        if ($answer -match '^[qQ]$') { return $false }
        if ($answer -match '^[cC]$') {
            $apps = @($holders | Where-Object { $_.Name -eq 'yw-app' })
            if ($apps.Count -eq 0) { Write-Host '  종료를 요청할 yw-app이 없습니다(yw-host는 Chrome을 닫으면 끝납니다).' }
            foreach ($app in $apps) {
                if ($app.Process.CloseMainWindow()) {
                    Write-Host "  yw-app (PID $($app.Id))에 종료를 요청했습니다. 최대 15초 기다립니다..."
                    [void]$app.Process.WaitForExit(15000)
                } else {
                    Write-Host '  yw-app 창이 숨겨져 있어 요청을 보낼 수 없습니다. 시작 메뉴에서 Your Wallet을 실행해 창을 연 뒤 닫아 주세요.'
                }
            }
        }
    }
}

# ---------------------------------------------------------------- 빌드 도구

# rustup 프록시(rustup·cargo·rustc)가 있는 폴더: CARGO_HOME이 드라이브 문자로 시작하는 절대 경로면 %CARGO_HOME%\bin,
# 아니면 %USERPROFILE%\.cargo\bin. PATH는 보지 않는다(PATH 앞쪽의 다른 사용자가 쓸 수 있는 폴더에 cargo.exe를 두는
# 바꿔치기를 막는다). 둘 다 없으면 $null.
function Get-CargoBinDir {
    $cargoHome = Get-CargoHomeDir
    if ($null -eq $cargoHome) { return $null }
    return Join-Path $cargoHome 'bin'
}

# CARGO_HOME 폴더: CARGO_HOME이 드라이브 문자로 시작하는 절대 경로면 그 폴더, 아니면 %USERPROFILE%\.cargo. 둘 다 없으면 $null.
function Get-CargoHomeDir {
    $cargoHome = $env:CARGO_HOME
    if (-not [string]::IsNullOrEmpty($cargoHome) -and $cargoHome -match '^[A-Za-z]:\\') {
        return ConvertTo-FullPath $cargoHome
    }
    $userProfile = $env:USERPROFILE
    if (-not [string]::IsNullOrEmpty($userProfile) -and $userProfile -match '^[A-Za-z]:\\') {
        return Join-Path (ConvertTo-FullPath $userProfile) '.cargo'
    }
    return $null
}

# 빌드에 쓸 도구의 전체 경로(없으면 $null).
function Get-RustTools {
    $bin = Get-CargoBinDir
    $paths = @{}
    foreach ($name in 'rustup', 'cargo', 'rustc') {
        $paths[$name] = $null
        if ($null -ne $bin) {
            $path = Join-Path $bin "$name.exe"
            if (Test-Path -LiteralPath $path -PathType Leaf) { $paths[$name] = $path }
        }
    }
    return [pscustomobject]@{ Bin = $bin; Rustup = $paths['rustup']; Cargo = $paths['cargo']; Rustc = $paths['rustc'] }
}

function Test-RustToolsPresent($Tools) {
    return $null -ne $Tools -and $null -ne $Tools.Rustup -and $null -ne $Tools.Cargo -and $null -ne $Tools.Rustc
}

# 실행할 도구 파일이 안전하면 $null, 아니면 이유 문장. 파일과 그 폴더, 그리고 심볼릭 링크면(rustup은 cargo.exe 등을
# rustup.exe로의 링크로 만들 수 있다) 링크 대상 파일과 그 폴더를 Get-AclProblem으로 본다. 다른 PATH 항목은 보지 않는다.
function Get-ToolPathProblem([string]$File, [string]$UserSid) {
    $paths = New-Object 'System.Collections.Generic.List[string]'
    $current = $File
    for ($hop = 0; $true; $hop++) {
        if ($hop -ge 8) { return "$File : 링크가 너무 많이 이어집니다" }
        foreach ($path in [IO.Path]::GetDirectoryName($current), $current) {
            if (-not $paths.Contains($path)) { $paths.Add($path) }
        }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { break }
        $target = @($item.Target | Where-Object { -not [string]::IsNullOrEmpty($_) }) | Select-Object -First 1
        if ($null -eq $target) { return "$current : 링크 대상을 알 수 없습니다" }
        if (-not [IO.Path]::IsPathRooted($target)) { $target = Join-Path ([IO.Path]::GetDirectoryName($current)) $target }
        $current = [IO.Path]::GetFullPath($target)
        if (-not (Test-Path -LiteralPath $current -PathType Leaf)) { return "$File : 링크 대상이 없습니다($current)" }
    }
    foreach ($path in $paths) {
        $problem = Get-AclProblem (Get-Acl -LiteralPath $path).Sddl $UserSid
        if ($null -ne $problem) { return "$path : $problem" }
    }
    return $null
}

# 커밋 표시에 쓸 git: Program Files(x86 포함) 아래이거나 현재 사용자 소유 폴더에 있고 Get-ToolPathProblem을 통과하는
# 첫 후보. 후보는 Program Files의 Git\cmd\git.exe와 PATH의 git(위치는 위 조건으로 다시 확인한다). 없으면 $null.
function Find-TrustedGit([string]$UserSid) {
    $roots = @(@($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { -not [string]::IsNullOrEmpty($_) })
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in $roots) { $candidates.Add((Join-Path $root 'Git\cmd\git.exe')) }
    foreach ($command in @(Get-Command git -CommandType Application -All -ErrorAction SilentlyContinue)) { $candidates.Add($command.Source) }
    foreach ($candidate in $candidates) {
        if ($candidate -cnotmatch '^[A-Za-z]:\\' -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            $folder = [IO.Path]::GetDirectoryName((ConvertTo-FullPath $candidate))
            $inProgramFiles = @($roots | Where-Object { Test-PathInside $folder $_ }).Count -gt 0
            if (-not $inProgramFiles -and (Get-Acl -LiteralPath $folder).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $UserSid) { continue }
            if ($null -eq (Get-ToolPathProblem $candidate $UserSid)) { return $candidate }
        } catch {
            continue
        }
    }
    return $null
}

# 도구 파일·폴더를 다른 사용자가 바꿀 수 있으면 설명을 출력하고 종료 7(-AllowUnsafeToolchainPath면 경고 후 계속).
function Confirm-RustToolsTrusted($Tools, [string]$UserSid) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $Tools.Rustup, $Tools.Cargo, $Tools.Rustc) {
        try {
            $problem = Get-ToolPathProblem $file $UserSid
        } catch {
            $problem = "$file : 권한을 확인할 수 없습니다($((Get-InnerException $_).Message))"
        }
        if ($null -ne $problem -and -not $problems.Contains($problem)) { $problems.Add($problem) }
    }
    if ($problems.Count -eq 0) {
        Write-Host '  Rust 도구 위치 권한: 다른 사용자는 바꿀 수 없습니다.'
        return
    }
    Write-Host ''
    Write-Host '  빌드에 쓸 Rust 도구(rustup·cargo·rustc)나 그 폴더를 다른 사용자가 바꿀 수 있습니다:' -ForegroundColor Yellow
    foreach ($problem in $problems) { Write-Host "    - $problem" }
    Write-Host '  그 사용자가 이 파일을 바꿔치기하면 빌드하는 yw-app.exe·yw-host.exe에 자기 코드를 넣을 수 있고, 지갑이 그 코드를'
    Write-Host '  실행합니다. 이 설치 프로그램은 그 폴더의 권한을 바꾸지 않습니다. CARGO_HOME이 여러 사용자가 쓰는 폴더를 가리키면,'
    Write-Host '  CARGO_HOME 없이 rustup을 내 사용자 프로필(%USERPROFILE%\.cargo)에 설치해 쓰는 방법이 있습니다.'
    if ($AllowUnsafeToolchainPath) {
        Write-Warn '-AllowUnsafeToolchainPath: 위 위험을 감수하고 이 도구로 계속합니다.'
        return
    }
    Stop-Install 7 '다른 사용자가 바꿀 수 있는 위치의 Rust 도구로는 빌드하지 않습니다. 위 설명을 읽고 위험을 감수한다면 -AllowUnsafeToolchainPath를 붙여 다시 실행하세요.'
}

# Visual Studio(Build Tools 포함)의 MSVC x64 C++ 도구가 있으면 설치 경로, 없으면 $null.
function Find-MsvcBuildTools {
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrEmpty($programFilesX86)) { return $null }
    $vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { return $null }
    $lines = Get-NativeOutput $vswhere @('-products', '*', '-requires', $MsvcComponent, '-property', 'installationPath', '-nologo')
    if ($null -eq $lines) { return $null }
    foreach ($line in $lines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { return $line.Trim() }
    }
    return $null
}

# Windows SDK(kernel32.lib x64)가 있으면 true. 판단할 수 없으면 true(경고만 하는 확인이다).
function Test-WindowsSdk {
    $roots = @()
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots') {
        try {
            $value = (Get-ItemProperty -LiteralPath $key -Name 'KitsRoot10' -ErrorAction Stop).KitsRoot10
            if (-not [string]::IsNullOrEmpty($value)) { $roots += $value }
        } catch { }
    }
    if ($roots.Count -eq 0) { return $false }
    foreach ($root in $roots) {
        $lib = Join-Path $root 'Lib'
        if (-not (Test-Path -LiteralPath $lib -PathType Container)) { continue }
        foreach ($version in @(Get-ChildItem -LiteralPath $lib -Directory -ErrorAction SilentlyContinue)) {
            if (Test-Path -LiteralPath (Join-Path $version.FullName 'um\x64\kernel32.lib') -PathType Leaf) { return $true }
        }
    }
    return $false
}

function Get-Prerequisites {
    return [pscustomobject]@{
        Tools = Get-RustTools
        Msvc  = Find-MsvcBuildTools
    }
}

function Write-Prerequisites($State) {
    if (Test-RustToolsPresent $State.Tools) {
        Write-Host "  Rust (rustup, cargo)        : 있음 ($($State.Tools.Bin))"
    } else {
        Write-Host "  Rust (rustup, cargo)        : 없음 ($($State.Tools.Bin) 에 rustup.exe·cargo.exe·rustc.exe가 모두 있어야 합니다)" -ForegroundColor Yellow
        $elsewhere = @(Get-Command cargo -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
        if ($elsewhere.Count -gt 0) {
            Write-Host "    PATH의 cargo($($elsewhere[0]))는 쓰지 않습니다. 설치 프로그램은 CARGO_HOME\bin 또는 %USERPROFILE%\.cargo\bin의 rustup만 씁니다."
        }
    }
    if ($null -ne $State.Msvc) {
        Write-Host "  C++ 빌드 도구 (MSVC x64)    : 있음 ($($State.Msvc))"
    } else {
        Write-Host '  C++ 빌드 도구 (MSVC x64)    : 없음' -ForegroundColor Yellow
    }
}

# 필요한 winget 인자 문자열 목록. 둘 다 있으면 빈 배열.
function Get-MissingInstalls($State) {
    $missing = @()
    if (-not (Test-RustToolsPresent $State.Tools)) {
        $missing += [pscustomobject]@{ Name = 'Rust 툴체인 관리자 rustup (cargo 포함, Rust 1.95.0은 빌드할 때 자동으로 받음)'; Args = $RustupWingetArgs }
    }
    if ($null -eq $State.Msvc) {
        $missing += [pscustomobject]@{ Name = 'Visual Studio 2022 Build Tools의 "C++를 사용한 데스크톱 개발"(MSVC 컴파일러·링커, Windows SDK)'; Args = $BuildToolsWingetArgs }
    }
    return , $missing
}

function Write-MissingHelp($Missing) {
    Write-Host ''
    Write-Host '  빌드에 필요한 도구가 없습니다:' -ForegroundColor Yellow
    foreach ($item in $Missing) { Write-Host "    - $($item.Name)" }
    Write-Host '  다음 명령으로 설치할 수 있습니다(winget = Windows 앱 설치 관리자):'
    foreach ($item in $Missing) { Write-Host "    winget $($item.Args)" }
    if (@($Missing | Where-Object { $_.Args -eq $BuildToolsWingetArgs }).Count -gt 0) {
        Write-Host '  Visual Studio(또는 Build Tools)가 이미 있는데 C++ 도구만 없다면 winget 대신 Visual Studio Installer에서'
        Write-Host '  "수정" -> "C++를 사용한 데스크톱 개발"을 선택해 추가하세요.'
    }
}

# 빌드 도구를 확인하고, 없으면 winget 설치를 제안한다(Y일 때만 실행). Rust 도구 위치 권한도 확인한다
# (Confirm-RustToolsTrusted). 준비되면 반환하고, 아니면 종료 7.
function Confirm-Prerequisites([string]$UserSid) {
    $state = Get-Prerequisites
    Write-Prerequisites $state
    $missing = Get-MissingInstalls $state
    if ($missing.Count -eq 0) {
        if (-not (Test-WindowsSdk)) {
            Write-Warn 'Windows SDK(kernel32.lib)를 찾지 못했습니다. 빌드가 링크 단계에서 실패하면 Visual Studio Installer에서 "수정" -> "Windows 11 SDK"를 추가하세요.'
        }
        Confirm-RustToolsTrusted $state.Tools $UserSid
        return $state
    }
    Write-MissingHelp $missing
    if ($DryRun) {
        Write-Plan '실제 설치 때는 위 명령을 지금 실행할지 묻습니다(Y일 때만 실행). 이번에는 묻지 않습니다.'
        if (Test-RustToolsPresent $state.Tools) { Confirm-RustToolsTrusted $state.Tools $UserSid }
        return $state
    }
    if (-not (Test-Interactive)) {
        Stop-Install 7 '비대화형 실행이라 설치 여부를 물을 수 없습니다. 위 명령으로 도구를 설치한 뒤 다시 실행하세요.'
    }
    $winget = Get-Command winget -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $winget) {
        Write-Host '  winget(앱 설치 관리자)을 찾을 수 없습니다. Microsoft Store에서 "앱 설치 관리자"를 설치하거나,'
        Write-Host '  https://rustup.rs 와 https://visualstudio.microsoft.com/visual-cpp-build-tools/ 에서 직접 설치하세요.'
        Stop-Install 7 '빌드 도구가 없습니다.'
    }
    Write-Host ''
    Write-Host '  Build Tools 설치는 수 GB를 내려받고 10분 이상 걸릴 수 있으며, 관리자 권한 확인 창이 뜨면 "예"를 눌러야 합니다.'
    $answer = "$(Read-Host '  위 winget 명령을 지금 실행할까요? (Y = 실행 / N = 그만두기)')".Trim()
    if ($answer -notmatch '^[yY]$') {
        Stop-Install 7 '빌드 도구를 설치하지 않았습니다. 위 명령으로 직접 설치한 뒤 install.cmd를 다시 실행하세요.'
    }
    foreach ($item in $missing) {
        Write-Host ''
        Write-Host "  > winget $($item.Args)" -ForegroundColor Cyan
        # 이 창의 콘솔을 그대로 쓴다(winget의 동의 질문·진행 표시). winget 프로세스 자체가 끝날 때까지 기다린다.
        $process = Start-Process -FilePath $winget.Source -ArgumentList $item.Args -NoNewWindow -PassThru
        $null = $process.Handle   # 종료 코드를 읽을 수 있게 핸들을 잡아 둔다
        $process.WaitForExit()
        Write-Host "  winget 종료 코드: $($process.ExitCode)"
    }
    $state = Get-Prerequisites
    Write-Host ''
    Write-Prerequisites $state
    $missing = Get-MissingInstalls $state
    if ($missing.Count -gt 0) {
        Write-MissingHelp $missing
        Stop-Install 7 '설치 뒤에도 빌드 도구를 찾지 못했습니다. 설치 창이 끝났는지 확인하고, 새 창에서 install.cmd를 다시 실행하세요(필요하면 PC 재시작).'
    }
    Confirm-RustToolsTrusted $state.Tools $UserSid
    return $state
}

# 빌드 동안 지우는 환경 변수인지(대소문자 무시): RUSTFLAGS 계열 4개, RUSTC·RUSTC_WRAPPER·RUSTC_WORKSPACE_WRAPPER·
# CARGO_BUILD_TARGET, CARGO_PROFILE_RELEASE_*·CARGO_BUILD_RUSTC*·CC*·CFLAGS*·CXX*·CXXFLAGS*.
function Test-ClearedBuildVariable([string]$Name) {
    foreach ($exact in @($ClearedBuildVariableNames) + @($RustflagsVariables)) {
        if ($Name.Equals($exact, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($prefix in $ClearedBuildVariablePrefixes) {
        if ($Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# 이 프로세스 환경에서 위 변수를 지우고, 되돌릴 이름·값을 돌려준다(Restore-BuildEnvironment). 자식 프로세스(cargo·
# rustc·빌드 스크립트·cc)는 지운 환경을 물려받는다. 시스템·사용자 환경 변수 설정은 바꾸지 않는다.
function Clear-BuildEnvironment {
    $saved = [ordered]@{}
    $names = @([Environment]::GetEnvironmentVariables('Process').Keys | ForEach-Object { [string]$_ } | Where-Object { Test-ClearedBuildVariable $_ } | Sort-Object)
    foreach ($name in $names) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        # [NullString]::Value: PowerShell 7은 $null을 ""로 넘기고, .NET(Core)는 ""이면 지우지 않고 빈 값으로 둔다.
        [Environment]::SetEnvironmentVariable($name, [NullString]::Value, 'Process')
    }
    return $saved
}

function Restore-BuildEnvironment($Saved) {
    foreach ($name in @($Saved.Keys)) { [Environment]::SetEnvironmentVariable($name, $Saved[$name], 'Process') }
}

# cargo 인자: +툴체인, Cargo.toml [profile.release]를 다시 주는 --config, build 인자, --target-dir $TargetDir(설치 프로그램이
# 결과를 읽는 바로 그 폴더; 설정 파일의 build.target-dir·CARGO_BUILD_TARGET_DIR보다 우선한다). 배열로 넘겨 PowerShell 5.1·7이
# 같은 명령줄을 만든다(--config 값에 공백·큰따옴표가 없다; 공백이 있는 폴더 경로는 PowerShell이 따옴표로 감싼다).
function Get-CargoBuildArguments([string]$TargetDir) {
    $list = New-Object 'System.Collections.Generic.List[string]'
    $list.Add("+$RustToolchain")
    foreach ($setting in $ReleaseProfileOverrides) {
        $list.Add('--config')
        $list.Add("profile.release.$setting")
    }
    foreach ($setting in $BuildConfigOverrides) {
        $list.Add('--config')
        $list.Add($setting)
    }
    $list.AddRange([string[]]$BuildArgs)
    $list.Add('--target-dir')
    $list.Add($TargetDir)
    return , $list.ToArray()
}

# ---------------------------------------------------------------- cargo 설정 파일(머리말의 cargo 설정 규칙)

# TOML 키 한 조각(맨 키, "기본 문자열", '리터럴 문자열')과 점으로 이은 키 경로.
$TomlKeyPart = '(?:"(?:[^"\\]|\\.)*"|''[^'']*''|[A-Za-z0-9_-]+)'
$TomlKeyPath = "$TomlKeyPart(?:\s*\.\s*$TomlKeyPart)*"

function Split-TomlKeyPath([string]$Path) {
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($match in [regex]::Matches($Path, $TomlKeyPart)) {
        $value = $match.Value
        if ($value.StartsWith('"') -or $value.StartsWith("'")) { $value = $value.Substring(1, $value.Length - 2) }
        $parts.Add($value)
    }
    return , $parts.ToArray()
}

# 줄에서 문자열 밖의 # 주석을 뗀다.
function Remove-TomlComment([string]$Line) {
    $quote = [char]0
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $ch = $Line[$i]
        if ($quote -ne [char]0) {
            if ($ch -eq '\' -and $quote -eq '"') { $i++; continue }
            if ($ch -eq $quote) { $quote = [char]0 }
        } elseif ($ch -eq '"' -or $ch -eq "'") {
            $quote = $ch
        } elseif ($ch -eq '#') {
            return $Line.Substring(0, $i)
        }
    }
    return $Line
}

# 빌드 동작을 바꾸는 cargo 설정 키인지(키 조각 배열, 대소문자 구분): build.rustc*(rustc·rustc-wrapper·
# rustc-workspace-wrapper)·build.rustflags·build.target(결과가 <빌드 폴더>\<대상>\release로 간다; build.target-dir은
# 명령줄 --target-dir이 이긴다), target.<대상>.linker·target.<대상>.rustflags, profile.release.*, patch.*·
# source.*(의존성 소스 바꾸기), paths(경로 재정의).
function Test-RiskyCargoKey([string[]]$Parts) {
    if ($Parts.Count -lt 1) { return $false }
    $first = $Parts[0]
    if ($first -ceq 'build') { return $Parts.Count -ge 2 -and ($Parts[1].StartsWith('rustc', [StringComparison]::Ordinal) -or $Parts[1] -ceq 'rustflags' -or $Parts[1] -ceq 'target') }
    if ($first -ceq 'target') { return $Parts.Count -ge 3 -and ($Parts[2] -ceq 'linker' -or $Parts[2] -ceq 'rustflags') }
    if ($first -ceq 'profile') { return $Parts.Count -ge 2 -and $Parts[1] -ceq 'release' }
    return $first -ceq 'patch' -or $first -ceq 'source' -or $first -ceq 'paths'
}

# cargo 설정 파일 내용에서 위 키를 찾아 점으로 이은 이름으로 돌려준다(중복 없이, 나온 순서). 완전한 TOML 해석기는
# 아니다: 표 머리 [a.b]·[[a.b]], 점 키 a.b = ..., 한 줄 인라인 표 a = { b = ... }를 본다(경고용이라 여러 줄 문자열 안의
# "키 = 값" 모양 줄도 키로 셀 수 있다).
function Get-CargoConfigRiskyKeys([string]$Text) {
    $keys = New-Object 'System.Collections.Generic.List[string]'
    $table = [string[]]@()
    $add = {
        param([string[]]$Parts)
        $name = $Parts -join '.'
        if ((Test-RiskyCargoKey $Parts) -and -not $keys.Contains($name)) { $keys.Add($name) }
    }
    foreach ($raw in ($Text -split "\r?\n")) {
        $line = (Remove-TomlComment $raw).Trim()
        if ($line.Length -eq 0) { continue }
        $header = [regex]::Match($line, "^\[\[?\s*($TomlKeyPath)\s*\]\]?$")
        if ($header.Success) {
            $table = Split-TomlKeyPath $header.Groups[1].Value
            continue
        }
        $pair = [regex]::Match($line, "^($TomlKeyPath)\s*=\s*(.*)$")
        if (-not $pair.Success) { continue }
        $own = Split-TomlKeyPath $pair.Groups[1].Value   # 배열 그대로(@()로 감싸면 한 겹 더 싸인다)
        $base = [string[]]($table + $own)
        & $add $base
        $value = $pair.Groups[2].Value
        if ($value.StartsWith('{')) {
            foreach ($inner in [regex]::Matches($value, "[{,]\s*($TomlKeyPath)\s*=")) {
                $innerParts = Split-TomlKeyPath $inner.Groups[1].Value
                & $add ([string[]]($base + $innerParts))
            }
        }
    }
    return , $keys.ToArray()
}

# 저장소 루트의 상위 폴더(부모부터 드라이브 루트까지)마다 .cargo\config.toml·.cargo\config가 있으면 그 경로. 저장소
# 자신의 .cargo는 보지 않고, $CargoHome과 같은 .cargo 폴더(사용자 프로필 아래 저장소의 %USERPROFILE%\.cargo 등)는
# 사용자 설정이라 뺀다(Confirm-CargoConfigs가 키만 경고).
function Get-AncestorCargoConfigs([string]$Root, [string]$CargoHome) {
    $found = New-Object 'System.Collections.Generic.List[string]'
    $homeDir = $null
    if (-not [string]::IsNullOrEmpty($CargoHome)) { $homeDir = ConvertTo-FullPath $CargoHome }
    $dir = [IO.Path]::GetDirectoryName((ConvertTo-FullPath $Root))
    while (-not [string]::IsNullOrEmpty($dir)) {
        $dotCargo = [IO.Path]::Combine($dir, '.cargo')
        if ($null -eq $homeDir -or -not $dotCargo.Equals($homeDir, [StringComparison]::OrdinalIgnoreCase)) {
            foreach ($name in 'config.toml', 'config') {
                $file = [IO.Path]::Combine($dotCargo, $name)
                if (Test-Path -LiteralPath $file) { $found.Add($file) }
            }
        }
        $dir = [IO.Path]::GetDirectoryName($dir)
    }
    return , $found.ToArray()
}

# 빌드 전에: 상위 폴더의 cargo 설정 파일이 있으면 목록을 출력하고 종료 7($Allow면 경고 후 계속), CARGO_HOME의 설정
# 파일(config.toml·config)이 빌드를 바꾸는 키를 정하면 그 키를 경고한다.
function Confirm-CargoConfigs([string]$Root, [string]$CargoHome, [bool]$Allow) {
    $ancestors = Get-AncestorCargoConfigs $Root $CargoHome   # 배열 그대로(@()로 감싸면 한 겹 더 싸인다)
    if ($ancestors.Count -gt 0) {
        Write-Host '  저장소 바깥의 상위 폴더에 cargo 설정 파일이 있습니다. cargo는 이 파일을 빌드에 그대로 적용합니다(컴파일러·링커·의존성 소스를 바꿀 수 있습니다):' -ForegroundColor Yellow
        foreach ($file in $ancestors) { Write-Host "    - $file" }
        if (-not $Allow) {
            Stop-Install 7 "상위 폴더의 cargo 설정 파일($($ancestors.Count)개) 때문에 빌드하지 않습니다. 직접 만든 파일이 아니면 내용을 확인한 뒤 지우거나, 저장소를 그런 파일이 없는 폴더(예: 사용자 프로필 아래)로 옮겨 다시 실행하세요. 직접 둔 설정이면 -AllowAncestorCargoConfig로 계속할 수 있습니다."
        }
        Write-Warn '-AllowAncestorCargoConfig: 위 cargo 설정 파일을 적용한 채로 빌드합니다.'
    }
    if ([string]::IsNullOrEmpty($CargoHome)) { return }
    foreach ($name in 'config.toml', 'config') {
        $file = [IO.Path]::Combine($CargoHome, $name)
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
        try {
            $text = [IO.File]::ReadAllText($file)
        } catch {
            Write-Warn "CARGO_HOME의 cargo 설정 파일을 읽을 수 없습니다: $file"
            continue
        }
        $keys = Get-CargoConfigRiskyKeys $text
        if ($keys.Count -gt 0) {
            Write-Warn "CARGO_HOME의 cargo 설정 파일 $file 이 빌드를 바꾸는 키를 정합니다: $($keys -join ', '). 설치 빌드는 컴파일러 래퍼·링커·release 프로필 일부를 명령줄로 다시 정하지만 나머지는 그대로 적용됩니다. 직접 넣은 설정인지 확인하세요."
            if ($keys -contains 'build.target') {
                Write-Warn "build.target이 있으면 cargo가 결과를 빌드 폴더\<대상>\release에 만들어 설치가 읽는 release\에 새 exe가 없으므로 설치하지 않고 멈춥니다(종료 8). 설치하려면 그 줄을 지우거나 주석으로 막으세요."
            }
        }
    }
}

# 빌드 직전에 $TargetDir\release의 yw-app.exe·yw-host.exe를 지운다(머리말의 빌드 폴더). 변경 없는 빌드도 cargo가 deps\에서
# 다시 링크해 되살리므로 결과는 같고, 설정 파일의 build.target처럼 결과를 다른 폴더로 보내는 빌드는 옛 exe를 남기지 않는다
# (빌드 뒤 결과 파일이 없어 종료 8 — 옛 코드를 새 버전으로 기록해 설치하는 일이 없다). 지울 수 없으면(그 exe를 실행 중) 종료 8.
function Remove-StaleBuildOutputs([string]$TargetDir) {
    foreach ($name in 'yw-app.exe', 'yw-host.exe') {
        $file = [IO.Path]::Combine($TargetDir, 'release', $name)
        if (-not [IO.File]::Exists($file)) { continue }
        try {
            [IO.File]::Delete($file)
        } catch {
            Stop-Install 8 "이전 빌드 결과를 지울 수 없습니다: $file ($((Get-InnerException $_).Message)). 이 파일을 실행 중이면(개발 중 직접 실행한 yw-app, Chrome이 실행한 yw-host) 닫은 뒤 다시 실행하세요."
        }
    }
}

# Rust $RustToolchain(+툴체인)으로 릴리스 빌드한다. $Tools = Get-RustTools(전체 경로), $TargetDir = 빌드 폴더(전체 경로,
# --target-dir). 컴파일러·빌드 설정을 바꾸는 환경 변수는 이 함수 동안만 지우고 끝나면 되돌린다. 툴체인 버전·대상이 다르면
# 종료 7, 이전 결과를 지울 수 없거나 빌드가 실패하면 종료 8.
function Invoke-Build([string]$Root, $Tools, [string]$TargetDir) {
    $saved = Clear-BuildEnvironment
    foreach ($name in @($saved.Keys)) {
        if ($RustflagsVariables -contains $name) {
            Write-Warn "환경 변수 $name 이 .cargo\config.toml의 빌드 설정을 덮어쓰므로 이 빌드에서는 지웁니다(시스템 설정은 그대로)."
        }
    }
    $others = @($saved.Keys | Where-Object { $RustflagsVariables -notcontains $_ })
    if ($others.Count -gt 0) {
        Write-Warn "컴파일러·빌드 설정을 바꾸는 환경 변수를 이 빌드 동안만 지웁니다(시스템 설정은 그대로): $($others -join ', ')"
    }
    Push-Location -LiteralPath $Root
    try {
        $selector = "+$RustToolchain"
        $versionPattern = [regex]::Escape($RustToolchain) + '(\s|$)'
        # 툴체인이 없으면 받는다(rustup이 +툴체인을 자동으로 받지 않는 설정이어도).
        Write-Host "  Rust $RustToolchain 확인(처음이면 rustup이 내려받습니다)"
        $cargoVersion = Get-NativeOutput $Tools.Cargo @($selector, '--version') -ShowStderr
        if ($null -eq $cargoVersion) {
            Write-Host "  rustup toolchain install $RustToolchain --profile minimal"
            [void](Invoke-NativeCommand $Tools.Rustup @('toolchain', 'install', $RustToolchain, '--profile', 'minimal'))
            $cargoVersion = Get-NativeOutput $Tools.Cargo @($selector, '--version') -ShowStderr
        }
        if ($null -eq $cargoVersion -or $cargoVersion.Count -lt 1) { Stop-Install 8 "cargo를 실행할 수 없습니다: $($Tools.Cargo) $selector --version. 새 창에서 install.cmd를 다시 실행하세요." }
        Write-Host "  $($cargoVersion[0])"
        if ($cargoVersion[0] -cnotmatch ('^cargo ' + $versionPattern)) {
            Stop-Install 7 "cargo $selector 가 Rust $RustToolchain 이 아닙니다($($cargoVersion[0])). rustup toolchain install $RustToolchain 으로 정식 툴체인을 설치한 뒤 다시 실행하세요(같은 이름의 rustup toolchain link가 있으면 지우세요)."
        }
        $rustc = Get-NativeOutput $Tools.Rustc @($selector, '-vV')
        if ($null -eq $rustc -or $rustc.Count -lt 1) { Stop-Install 7 "rustc를 실행할 수 없습니다: $($Tools.Rustc) $selector -vV" }
        $release = @($rustc | Where-Object { $_ -cmatch '^release: ' } | Select-Object -First 1)
        if ($rustc[0] -cnotmatch ('^rustc ' + $versionPattern) -or $release.Count -ne 1 -or $release[0].Trim() -cne "release: $RustToolchain") {
            Stop-Install 7 "rustc $selector 가 Rust $RustToolchain 이 아닙니다($($rustc[0])). rustup toolchain install $RustToolchain 으로 정식 툴체인을 설치한 뒤 다시 실행하세요."
        }
        Write-Host "  $($rustc[0])"
        $hostLine = @($rustc | Where-Object { $_ -cmatch '^host: ' } | Select-Object -First 1)
        if ($hostLine.Count -ne 1 -or $hostLine[0].Trim() -cne 'host: x86_64-pc-windows-msvc') {
            Stop-Install 7 "Rust 기본 대상이 x86_64-pc-windows-msvc가 아닙니다($(if ($hostLine.Count -eq 1) { $hostLine[0] } else { 'host 없음' })). rustup set default-host x86_64-pc-windows-msvc 실행 후 다시 실행하세요."
        }
        Remove-StaleBuildOutputs $TargetDir
        $argList = Get-CargoBuildArguments $TargetDir
        Write-Host "  $($Tools.Cargo) $($argList -join ' ')"
        Write-Host '  처음 빌드는 crates.io에서 의존성을 내려받고(Cargo.lock 체크섬으로 고정) 몇 분 걸립니다.'
        $code = Invoke-NativeCommand $Tools.Cargo $argList
        if ($code -ne 0) {
            Write-Host ''
            Write-Host '  빌드가 실패했습니다. 흔한 원인:' -ForegroundColor Yellow
            Write-Host '  - "link.exe not found", "kernel32.lib" 같은 오류: Visual Studio Build Tools의 "C++를 사용한 데스크톱 개발"과 Windows SDK가 필요합니다.'
            Write-Host '  - 내려받기 오류: 처음 빌드는 인터넷 연결이 필요합니다.'
            Write-Host "  - `"Access is denied`"(액세스 거부): $TargetDir\release의 yw-app.exe를 실행 중이면 닫으세요."
            Stop-Install 8 "cargo build 실패(종료 코드 $code). 위 cargo 출력의 첫 error 줄을 확인하세요."
        }
    } finally {
        Pop-Location
        Restore-BuildEnvironment $saved
    }
}

# ---------------------------------------------------------------- 설치

function Invoke-Install {
    trap {
        Write-Host ''
        Write-Host "설치 실패(종료 코드 9): 예상하지 못한 오류: $((Get-InnerException $_).Message)" -ForegroundColor Red
        Write-Host "  위치: 줄 $($_.InvocationInfo.ScriptLineNumber)"
        exit 9
    }
    Set-RedirectedOutputUtf8
    if ($env:OS -ne 'Windows_NT') { Stop-Install 1 'Windows에서만 설치할 수 있습니다.' }
    if (-not [Environment]::Is64BitOperatingSystem) { Stop-Install 1 '64비트 Windows가 필요합니다(x86_64-pc-windows-msvc 빌드).' }
    $build = [Environment]::OSVersion.Version.Build
    if ($build -lt 22621) { Write-Warn "Windows 빌드 $build. 이 지갑은 Windows 11 22H2(22621) 이상을 대상으로 시험했습니다." }
    if ([string]::IsNullOrEmpty($PSScriptRoot)) { Stop-Install 1 '스크립트 파일로 실행하세요: 저장소 루트의 install.cmd' }

    # 소스 트리: 이 스크립트가 있는 저장소(scripts\..).
    $root = ConvertTo-FullPath (Join-Path $PSScriptRoot '..')
    foreach ($required in 'Cargo.toml', 'Cargo.lock', 'extension\manifest.json', 'scripts\uninstall.ps1') {
        if (-not (Test-Path -LiteralPath (Join-Path $root $required) -PathType Leaf)) {
            Stop-Install 1 "저장소 파일이 없습니다: $required. 저장소 전체(Git 또는 GitHub Download ZIP)의 install.cmd를 실행하세요."
        }
    }
    $userSid = Get-CurrentUserSid
    $extensionRoot = Join-Path $root 'extension'
    $version = Get-WorkspaceVersion $root
    $channel = Get-ToolchainChannel $root
    $commit = Get-SourceCommit $root $userSid
    $cargoTarget = Join-Path $root 'target'
    if (-not [string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) {
        $cargoTarget = $env:CARGO_TARGET_DIR
        if (-not [IO.Path]::IsPathRooted($cargoTarget)) { $cargoTarget = Join-Path $root $cargoTarget }
    }
    # cargo에는 --target-dir로 이 폴더를 그대로 준다(머리말의 빌드 폴더): 빌드 결과와 설치가 읽는 폴더가 언제나 같다.
    $cargoTarget = ConvertTo-FullPath $cargoTarget
    $releaseDir = Join-Path $cargoTarget 'release'

    $localAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($localAppData) -or -not [IO.Path]::IsPathRooted($localAppData)) {
        Stop-Install 1 'LOCALAPPDATA 환경 변수가 없거나 절대 경로가 아닙니다.'
    }
    $dataDir = ConvertTo-FullPath (Join-Path $localAppData 'YourWallet')
    $defaultDir = [string]::IsNullOrWhiteSpace($InstallDir)
    if ($defaultDir) {
        $script:InstallDir = Join-Path $localAppData 'Programs\YourWallet'
    }
    $target = ConvertTo-FullPath $InstallDir

    # 설치 경로 규칙: cmd.exe 메타문자 금지(Chrome이 cmd.exe로 host를 실행할 수 있다, spec/05 §9.1·§11-5),
    # 드라이브 문자로 시작하는 로컬 경로, 지갑 데이터 폴더·저장소·빌드 폴더와 분리.
    if ($target -match '["%&^|<>!]' -or $target -match '[\x00-\x1f\x7f]') {
        Stop-Install 1 "설치 경로에 쓸 수 없는 문자(`" % & ^ | < > !)가 있습니다: $target. 사용자 프로필 아래의 단순한 경로(예: -InstallDir `"$env:USERPROFILE\Apps\YourWallet`")를 지정하세요. 프로필 경로 자체에 이 문자가 있으면 그 문자가 없는 경로에 설치 프로그램이 새로 만들 폴더를 지정하세요(새 폴더는 현재 사용자·SYSTEM·Administrators만 바꿀 수 있게 만듭니다)."
    }
    if ($target -cnotmatch '^[A-Za-z]:\\.+') { Stop-Install 1 "설치 경로는 드라이브 문자로 시작하는 폴더여야 합니다(드라이브 루트·네트워크 경로 불가): $target" }
    if ((Test-PathInside $target $dataDir) -or (Test-PathInside $dataDir $target)) {
        Stop-Install 1 "설치 폴더는 지갑 데이터 폴더($dataDir)와 겹칠 수 없습니다: $target"
    }
    if ((Test-PathInside $target $root) -or (Test-PathInside $root $target)) {
        Stop-Install 1 "설치 폴더는 저장소 폴더($root)와 겹칠 수 없습니다: $target"
    }
    if ((Test-PathInside $target $releaseDir) -or (Test-PathInside $releaseDir $target)) {
        Stop-Install 1 "설치 폴더는 빌드 폴더($releaseDir)와 겹칠 수 없습니다: $target"
    }
    $appExe = Join-Path $target 'yw-app.exe'
    $hostExe = Join-Path $target 'yw-host.exe'
    $manifestPath = Join-Path $target "$HostName.json"
    $manifestJson = New-NativeManifestJson $hostExe
    if (-not (Test-NativeManifestValue (ConvertFrom-Json -InputObject $manifestJson) $ExtensionId)) {
        Stop-Install 1 "이 설치 경로로는 Chrome native host manifest를 만들 수 없습니다(경로 규칙 위반): $target"
    }
    # 상위 폴더 권한(머리말의 규칙). -InstallDir이면 드라이브 루트까지, 기본 경로는 사용자 프로필부터 아래만 본다
    # (기본 경로가 프로필 아래가 아니면 보지 않는다). 빌드 전에 확인해 오래 빌드한 뒤 거부되는 일이 없게 한다.
    $checkFrom = $null
    $checkAncestors = $true
    if ($defaultDir) {
        $checkAncestors = $false
        if (-not [string]::IsNullOrEmpty($env:USERPROFILE) -and $env:USERPROFILE -match '^[A-Za-z]:\\') {
            $profileDir = ConvertTo-FullPath $env:USERPROFILE
            if (Test-PathInside $target $profileDir) {
                $checkFrom = $profileDir
                $checkAncestors = $true
            }
        }
    }
    if ($checkAncestors) {
        $ancestorProblems = Get-InstallAncestorProblems $target $userSid $checkFrom
        if ($ancestorProblems.Count -gt 0) {
            Write-Host '  설치 폴더의 상위 폴더를 다른 사용자가 바꿀 수 있습니다:' -ForegroundColor Yellow
            foreach ($problem in $ancestorProblems) { Write-Host "    - $problem" }
            Stop-Install 1 "이 경로에는 설치하지 않습니다: $target. 다른 사용자가 상위 폴더를 옮기고 같은 경로에 자기 폴더를 만들면 Chrome이 그 폴더의 yw-host.exe를 실행하게 됩니다(설치 프로그램은 상위 폴더의 권한을 바꾸지 않습니다). 사용자 프로필 아래의 경로(예: -InstallDir `"$env:USERPROFILE\Apps\YourWallet`")를 지정하세요."
        }
    }

    Write-Host "Your Wallet 설치 (소스에서 빌드)" -ForegroundColor Green
    Write-Host "  소스        : $root ($(Format-Source $version $commit))"
    Write-Host "  설치 폴더   : $target"
    Write-Host "  지갑 데이터 : $dataDir (설치·업그레이드는 이 폴더를 건드리지 않습니다)"
    if ($DryRun) { Write-Host '  -DryRun: 확인과 할 일 출력만 하고 아무것도 바꾸지 않습니다.' -ForegroundColor DarkYellow }

    # 1. 확장 파일과 ID
    Write-Step '1/8 확장 파일 확인'
    try {
        $extensionFiles = Get-ExtensionRuntimeFiles $extensionRoot
    } catch {
        Stop-Install 2 "확장 폴더를 설치할 수 없습니다: $((Get-InnerException $_).Message)"
    }
    try {
        $extManifest = ConvertFrom-Json -InputObject (Read-Utf8Strict (Join-Path $extensionRoot 'manifest.json'))
        $sourceExtensionId = Get-ExtensionIdFromKey ([string]$extManifest.key)
    } catch {
        Stop-Install 2 'extension\manifest.json에서 확장 ID를 계산할 수 없습니다.'
    }
    if ($sourceExtensionId -cne $ExtensionId) {
        Stop-Install 2 "확장 ID가 다릅니다(manifest $sourceExtensionId, 기대 $ExtensionId). 이 소스로 설치하지 마세요."
    }
    Write-Host "  런타임 파일 $($extensionFiles.Count)개, 확장 ID $ExtensionId 확인."
    # 소스 폴더 권한(머리말의 규칙): 저장소 루트, scripts\, extension\과 그 안의 런타임 파일·폴더.
    $sourcePaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $root, (Join-Path $root 'scripts'), (Join-Path $root 'scripts\uninstall.ps1'), $extensionRoot) { $sourcePaths.Add($path) }
    foreach ($rel in $extensionFiles) {
        $file = Join-RelativePath $extensionRoot $rel
        $sourcePaths.Add([IO.Path]::GetDirectoryName($file))
        $sourcePaths.Add($file)
    }
    Confirm-SourcePathsTrusted $sourcePaths.ToArray() $userSid $AllowUnsafeSourcePath.IsPresent
    # 무결성 레이블(머리말의 레이블 규칙): 빌드 입력과 설치할 파일 전체.
    $labelPaths = @($root, (Join-Path $root 'Cargo.toml'), (Join-Path $root 'Cargo.lock'), (Join-Path $root 'rust-toolchain.toml'))
    $labelTrees = @((Join-Path $root '.cargo'), (Join-Path $root 'crates'), (Join-Path $root 'scripts'), $extensionRoot)
    Confirm-IntegrityLabels '저장소(소스)' 'build' $root $labelPaths $labelTrees $AllowUnsafeSourcePath.IsPresent

    # 2. 빌드 도구
    Write-Step '2/8 빌드 도구 확인'
    $tools = $null
    if ($NoBuild) {
        Write-Host '  건너뜀(-NoBuild).'
    } else {
        if ($channel -cne $RustToolchain) {
            Stop-Install 2 "rust-toolchain.toml의 Rust($channel)가 설치 프로그램이 빌드에 쓰는 Rust $RustToolchain 와 다릅니다. 두 곳(rust-toolchain.toml, scripts\install.ps1 `$RustToolchain)을 함께 바꿔야 합니다."
        }
        $tools = (Confirm-Prerequisites $userSid).Tools
        if ($DryRun -and (Test-RustToolsPresent $tools)) {
            $toolchains = Get-NativeOutput $tools.Rustup @('toolchain', 'list')
            if ($null -ne $toolchains -and @($toolchains | Where-Object { $_ -match ('^' + [regex]::Escape($RustToolchain) + '-') }).Count -eq 0) {
                Write-Plan "rustup이 Rust $RustToolchain 을 처음 한 번 내려받습니다."
            }
        }
    }

    # 3. 빌드
    Write-Step '3/8 빌드'
    $sourceApp = Join-Path $releaseDir 'yw-app.exe'
    $sourceHost = Join-Path $releaseDir 'yw-host.exe'
    if ($NoBuild) {
        foreach ($exe in $sourceApp, $sourceHost) {
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
                Stop-Install 2 "빌드 결과가 없습니다: $exe. -NoBuild 없이 실행하세요."
            }
        }
        Write-Host "  건너뜀(-NoBuild). $releaseDir 의 yw-app.exe·yw-host.exe를 씁니다."
    } else {
        # 빌드 폴더의 권한과 레이블은 cargo가 그 안의 빌드 스크립트·proc-macro를 실행하기 전에 본다(머리말의 빌드 폴더).
        $buildPaths = Get-BuildDirPaths $cargoTarget
        Confirm-SourcePathsTrusted $buildPaths $userSid $AllowUnsafeSourcePath.IsPresent
        $buildLabelRoot = $cargoTarget
        if (-not (Test-Path -LiteralPath $cargoTarget) -and $buildPaths.Count -gt 0) { $buildLabelRoot = $buildPaths[0] }
        Confirm-IntegrityLabels '빌드 폴더' 'build' $buildLabelRoot $buildPaths @() $AllowUnsafeSourcePath.IsPresent
        Confirm-CargoConfigs $root (Get-CargoHomeDir) $AllowAncestorCargoConfig.IsPresent
        if ($DryRun) {
            $cargoExe = 'cargo'
            if ($null -ne $tools -and $null -ne $tools.Cargo) { $cargoExe = $tools.Cargo }
            Write-Plan "실행: $cargoExe $((Get-CargoBuildArguments $cargoTarget) -join ' ')  (저장소 루트, 결과 $releaseDir)"
            Write-Plan "빌드 동안만 지울 환경 변수: $((@($ClearedBuildVariableNames) + @($RustflagsVariables)) -join ', '), 이름이 $($ClearedBuildVariablePrefixes -join '·')로 시작하는 것"
            Write-Plan "cargo 실행 직전에 지울 이전 결과: $releaseDir 의 yw-app.exe·yw-host.exe(변경 없는 빌드는 cargo가 다시 링크한다)"
        } else {
            Invoke-Build $root $tools $cargoTarget
            foreach ($exe in $sourceApp, $sourceHost) {
                if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
                    Stop-Install 8 "빌드가 끝났지만 결과 파일이 없습니다: $exe. cargo 설정(CARGO_HOME의 config.toml 등)의 build.target이 결과를 $cargoTarget\<대상>\release로 보냈을 수 있습니다(위 경고 참고). 그 줄을 지우거나 주석으로 막은 뒤 다시 실행하세요."
                }
            }
            Write-Host '  빌드 완료.'
        }
    }
    # 빌드 폴더 권한·레이블(머리말의 소스 폴더 규칙·레이블 규칙): 복사해 올 실행 파일과 그 폴더.
    $builtPaths = @($cargoTarget, $releaseDir, $sourceApp, $sourceHost)
    Confirm-SourcePathsTrusted $builtPaths $userSid $AllowUnsafeSourcePath.IsPresent
    Confirm-IntegrityLabels '빌드 폴더' 'build' $cargoTarget $builtPaths @() $AllowUnsafeSourcePath.IsPresent

    # 4. 설치 폴더 상태와 계획
    Write-Step '4/8 설치 폴더 확인'
    $sources = New-Object 'System.Collections.Generic.List[object]'
    $sources.Add([pscustomobject]@{ Path = 'yw-app.exe'; Source = $sourceApp })
    $sources.Add([pscustomobject]@{ Path = 'yw-host.exe'; Source = $sourceHost })
    $sources.Add([pscustomobject]@{ Path = 'uninstall.ps1'; Source = (Join-Path $root 'scripts\uninstall.ps1') })
    foreach ($rel in $extensionFiles) {
        $sources.Add([pscustomobject]@{ Path = "extension/$rel"; Source = (Join-RelativePath $extensionRoot $rel) })
    }
    $newFiles = [string[]]@($sources | ForEach-Object { $_.Path })
    $oldFiles = @()
    $marker = $null
    $userSid = Get-CurrentUserSid
    if (Test-Path -LiteralPath $target -PathType Leaf) { Stop-Install 1 "설치 경로가 폴더가 아니라 파일입니다: $target" }
    if (Test-Path -LiteralPath $target -PathType Container) {
        $marker = Read-InstallMarker $target
        if ($null -eq $marker) {
            if (@(Get-ChildItem -LiteralPath $target -Force).Count -gt 0) {
                Stop-Install 1 "설치 기록($MarkerName)이 없는 비어 있지 않은 폴더에는 설치하지 않습니다: $target. 빈 폴더를 -InstallDir로 지정하세요."
            }
            Write-Host '  새로 설치합니다(빈 폴더).'
        } else {
            $oldFiles = @($marker.Files)
            if ($null -ne $commit -and $marker.Commit -ceq $commit -and $marker.Version -ceq $version) {
                Write-Host "  기존 설치를 찾았습니다(같은 소스: $(Format-Source $version $commit)). 바뀐 파일만 고칩니다."
            } else {
                Write-Host "  기존 설치를 찾았습니다($(Format-Source $marker.Version $marker.Commit)). 업그레이드합니다 -> $(Format-Source $version $commit)"
            }
            $cmp = 0
            try { $cmp = ([version]$version).CompareTo([version]$marker.Version) } catch { $cmp = 0 }
            if ($cmp -lt 0) { Write-Warn "설치된 버전($($marker.Version))보다 낮은 버전($version)으로 바꿉니다." }
            # 설치 뒤에 바뀐 파일(설치 기록의 SHA-256과 비교, 2026-11-01 검토 L7).
            if ($null -ne $marker.Hashes) {
                $changed = New-Object 'System.Collections.Generic.List[string]'
                foreach ($rel in @($marker.Hashes.Keys | Sort-Object)) {
                    $path = Join-RelativePath $target $rel
                    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $changed.Add("$rel (없음)"); continue }
                    if ((Get-Sha256Hex $path) -ne $marker.Hashes[$rel]) { $changed.Add($rel) }
                }
                if ($changed.Count -gt 0) {
                    Write-Warn "설치한 뒤 바뀐 파일이 있습니다(다른 프로그램이나 사용자가 바꿨을 수 있습니다): $($changed -join ', '). 이번 설치가 소스의 파일로 다시 씁니다. 직접 바꾼 것이 아니면 이 PC에서 다른 프로그램이 지갑 파일을 건드리는지 확인하세요."
                }
            }
        }
        # 비어 있거나 이전 설치인 폴더: 다른 사용자가 바꿀 수 있으면 설치하지 않는다(-FixPermissions로 고침).
        Confirm-InstallDirPermissions $target $userSid
        Confirm-IntegrityLabels '설치 폴더' 'install' $target @() @($target) $AllowUnsafeSourcePath.IsPresent
    } else {
        Write-Host '  새로 설치합니다(현재 사용자·SYSTEM·Administrators만 바꿀 수 있는 폴더로 만듭니다).'
        # 새 폴더는 만들 상위 폴더의 레이블을 물려받는다.
        $installParent = Get-ExistingAncestor $target
        Confirm-IntegrityLabels '설치 폴더를 만들 상위 폴더' 'install' $installParent @($installParent) @() $AllowUnsafeSourcePath.IsPresent
    }

    $toCopy = New-Object 'System.Collections.Generic.List[object]'
    $unchanged = 0
    foreach ($entry in $sources) {
        $destination = Join-RelativePath $target $entry.Path
        $hash = $null
        if (Test-Path -LiteralPath $entry.Source -PathType Leaf) {
            $hash = Get-Sha256Hex $entry.Source
        } elseif (-not $DryRun) {
            Stop-Install 2 "설치할 파일이 없습니다: $($entry.Source)"
        }
        if ($null -ne $hash -and (Test-Path -LiteralPath $destination -PathType Leaf) -and ((Get-Sha256Hex $destination) -eq $hash)) {
            $unchanged++
            continue
        }
        $toCopy.Add([pscustomobject]@{ Path = $entry.Path; Source = $entry.Source; Destination = $destination; Hash = $hash })
    }
    $newSet = @{}
    foreach ($file in $newFiles) { $newSet[$file.ToLowerInvariant()] = $true }
    $toRemove = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $oldFiles) {
        if ($newSet.ContainsKey($file.ToLowerInvariant())) { continue }
        $path = Join-RelativePath $target $file
        if (Test-Path -LiteralPath $path -PathType Leaf) { $toRemove.Add($path) }
    }
    Write-Host "  복사할 파일 $($toCopy.Count)개, 그대로인 파일 $($unchanged)개, 지울 이전 설치 파일 $($toRemove.Count)개"

    $touched = [string[]](@($toCopy | ForEach-Object { $_.Destination }) + @($toRemove))
    if (-not (Wait-FilesReleased $touched)) {
        Stop-Install 3 '설치를 취소했습니다. 설치 폴더는 바뀌지 않았습니다. yw-app과 Chrome을 닫은 뒤 다시 실행하세요.'
    }
    foreach ($process in @(Get-WalletProcesses | Where-Object { $_.Name -eq 'yw-app' })) {
        if ($null -eq $process.Path -or -not $process.Path.Equals($appExe, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warn "다른 위치의 yw-app이 실행 중입니다(PID $($process.Id), $($process.Path)). 한 번에 하나만 실행되므로, 설치한 앱을 쓰려면 그 앱을 먼저 닫으세요."
        }
    }

    # 5. 파일 복사
    Write-Step '5/8 파일 복사'
    if ($DryRun) {
        if (-not (Test-Path -LiteralPath $target -PathType Container)) {
            foreach ($dir in ([string[]](Get-MissingParents $target) + $target)) { Write-Plan "폴더 만들기: $dir (현재 사용자·SYSTEM·Administrators만, 상속 끊음)" }
        }
        foreach ($item in $toCopy) {
            if ($null -eq $item.Hash) { Write-Plan "복사(빌드 후): $($item.Path)" } else { Write-Plan "복사: $($item.Path)" }
        }
        foreach ($path in $toRemove) { Write-Plan "삭제(이전 설치 파일): $path" }
        Write-Plan "설치 기록 쓰기: $(Join-Path $target $MarkerName)"
    } else {
        try {
            if (-not (Test-Path -LiteralPath $target -PathType Container)) { New-InstallDir $target $userSid }
            # 중간에 실패해도 다음 실행과 uninstall.ps1이 남은 파일을 알 수 있게 이전·새 목록을 합쳐 먼저 기록한다.
            if ($toCopy.Count -gt 0 -or $toRemove.Count -gt 0) {
                Write-InstallMarker $target $version $commit 'installing' ([string[]](@($oldFiles) + @($newFiles) | Sort-Object -Unique))
            }
            foreach ($item in $toCopy) {
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($item.Destination))
                [IO.File]::Copy($item.Source, $item.Destination, $true)
                if ((Get-Sha256Hex $item.Destination) -ne $item.Hash) { throw "복사한 파일의 해시가 다릅니다: $($item.Path)" }
            }
            foreach ($path in $toRemove) {
                [IO.File]::Delete($path)
                $dir = [IO.Path]::GetDirectoryName($path)
                while ((Test-PathInside $dir $target) -and -not $dir.Equals($target, [StringComparison]::OrdinalIgnoreCase) -and
                       (Test-Path -LiteralPath $dir -PathType Container) -and @(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) {
                    [IO.Directory]::Delete($dir)
                    $dir = [IO.Path]::GetDirectoryName($dir)
                }
            }
        } catch {
            Stop-Install 4 "파일 복사·삭제 실패: $((Get-InnerException $_).Message). yw-app과 Chrome을 닫은 뒤 다시 실행하세요."
        }
        Write-Host "  복사 $($toCopy.Count)개, 삭제 $($toRemove.Count)개 완료."
    }

    # 6. native host manifest
    Write-Step '6/8 Chrome native host manifest'
    $existingJson = $null
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) { $existingJson = [IO.File]::ReadAllText($manifestPath) }
    if ($DryRun) {
        if ($existingJson -ceq $manifestJson) { Write-Plan "그대로: $manifestPath" } else { Write-Plan "쓰기: $manifestPath (path = $hostExe)" }
    } else {
        try {
            if ($existingJson -cne $manifestJson) { Write-Utf8NoBom $manifestPath $manifestJson }
        } catch {
            Stop-Install 5 "manifest를 쓸 수 없습니다: $manifestPath ($((Get-InnerException $_).Message))"
        }
        if (-not (Test-NativeManifestFile $manifestPath $ExtensionId)) { Stop-Install 5 "manifest 검증 실패: $manifestPath" }
        Write-Host "  $manifestPath (검증 통과)"
    }

    # 7. HKCU 등록
    Write-Step '7/8 Chrome native host 등록 (HKCU)'
    $current = $null
    if (Test-Path -LiteralPath $RegistryKey) { $current = (Get-Item -LiteralPath $RegistryKey).GetValue('') }
    if ($NoNativeHost) {
        Write-Host '  건너뜀(-NoNativeHost). 확장이 앱에 연결하려면 등록이 필요합니다.'
        if ($null -ne $current) { Write-Host "  현재 등록: $current" }
    } elseif ($null -ne $current -and ([string]$current).Equals($manifestPath, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "  이미 등록되어 있습니다: $RegistryKey"
    } else {
        if ($null -ne $current) { Write-Host "  기존 등록을 이 설치로 바꿉니다(이전 값: $current)." }
        if ($DryRun) {
            Write-Plan "레지스트리 쓰기: $RegistryKey (기본값) = $manifestPath"
        } else {
            try {
                New-Item -Path $RegistryKey -Value $manifestPath -Force | Out-Null
                $registered = (Get-Item -LiteralPath $RegistryKey).GetValue('')
            } catch {
                Stop-Install 5 "레지스트리 등록 실패: $RegistryKey ($((Get-InnerException $_).Message))"
            }
            if ($registered -ne $manifestPath) { Stop-Install 5 "레지스트리 확인 실패: $RegistryKey" }
            Write-Host "  등록: $RegistryKey = $manifestPath"
        }
    }

    # 8. 시작 메뉴 바로가기
    Write-Step '8/8 시작 메뉴 바로가기'
    if ($NoShortcut) {
        Write-Host '  건너뜀(-NoShortcut).'
    } else {
        $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
        if ([string]::IsNullOrEmpty($programs)) { Stop-Install 6 '시작 메뉴 폴더를 찾을 수 없습니다.' }
        $shortcutPath = Join-Path $programs $ShortcutName
        if ($DryRun) {
            Write-Plan "바로가기 만들기: $shortcutPath -> $appExe"
        } else {
            $shell = $null
            try {
                $shell = New-Object -ComObject WScript.Shell
                $shortcut = $shell.CreateShortcut($shortcutPath)
                $shortcut.TargetPath = $appExe
                $shortcut.Arguments = ''
                $shortcut.WorkingDirectory = $target
                $shortcut.Description = 'Your Wallet'
                $shortcut.IconLocation = "$appExe,0"
                $shortcut.Save()
            } catch {
                Stop-Install 6 "바로가기를 만들 수 없습니다: $shortcutPath ($((Get-InnerException $_).Message))"
            } finally {
                if ($null -ne $shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
            }
            Write-Host "  $shortcutPath"
        }
    }

    if (-not $DryRun) {
        try {
            $installedHashes = @{}
            foreach ($file in $newFiles) { $installedHashes[$file] = Get-Sha256Hex (Join-RelativePath $target $file) }
            Write-InstallMarker $target $version $commit 'installed' $newFiles $installedHashes
        } catch {
            Stop-Install 4 "설치 기록을 쓸 수 없습니다: $((Get-InnerException $_).Message)"
        }
    }

    # 안내
    $extensionDir = Join-Path $target 'extension'
    $upgrade = $null -ne $marker
    $copied = $false
    if (-not $DryRun -and (Test-Interactive)) {
        try { Set-Clipboard -Value $extensionDir; $copied = $true } catch { $copied = $false }
    }
    Write-Host ''
    if ($DryRun) {
        Write-Host 'DryRun 완료: 바뀐 것은 없습니다. 실제로 설치하려면 -DryRun 없이 다시 실행하세요.' -ForegroundColor Green
    } elseif ($upgrade) {
        Write-Host "업그레이드 완료: Your Wallet ($(Format-Source $version $commit)) -> $target" -ForegroundColor Green
    } else {
        Write-Host "설치 완료: Your Wallet ($(Format-Source $version $commit)) -> $target" -ForegroundColor Green
    }
    Write-Host ''
    Write-Host '[Chrome 확장 - 처음 한 번]'
    Write-Host "  Chrome → chrome://extensions → 개발자 모드 → 압축해제된 확장 프로그램 로드 → $extensionDir"
    if ($copied) { Write-Host '  (이 경로를 클립보드에 복사했습니다. 폴더 선택 창 주소창에 Ctrl+V)' }
    Write-Host "  카드에 표시된 ID가 $ExtensionId 인지 확인합니다. 다르면 쓰지 말고 그 카드를 삭제하세요."
    if ($upgrade) {
        Write-Host ''
        Write-Host '[업그레이드] chrome://extensions 의 Your Wallet 확장 카드에서 새로고침을 누르고, 열려 있던 dApp 탭도 새로고침합니다.' -ForegroundColor Yellow
    }
    Write-Host ''
    $runHint = '시작 메뉴 → Your Wallet'
    if ($NoShortcut) { $runHint = $appExe }
    Write-Host "[실행] $runHint. 처음이면 지갑 만들기(24단어 종이 백업) → 설정 → 네트워크(RPC). 자세한 안내: docs\install.ko.md"
    Write-Host '[업데이트] 저장소 폴더에서 git pull 후 install.cmd를 다시 실행합니다(ZIP으로 받았다면 새 ZIP의 install.cmd).'
    Write-Host '[제거] 저장소의 uninstall.cmd. 지갑 데이터는 지우지 않습니다.'
    Write-Host "지갑 데이터와 로그: $dataDir\v3"
    exit 0
}

# 점 소싱(. .\install.ps1)하면 함수만 정의한다(scripts/install.test.mjs의 검증 함수 시험용).
if ($MyInvocation.InvocationName -ne '.') { Invoke-Install }
