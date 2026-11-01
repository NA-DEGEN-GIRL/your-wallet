# scripts/check.ps1 — 저장소 게이트. 사용: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 [-Step <name>] [-Offline]
[CmdletBinding()]
param(
    [ValidateSet("all", "fmt", "deps", "clippy", "test", "fuzz", "build", "ext-test", "script-test", "privacy", "audit-ext", "icons")]
    [string]$Step = "all",
    [switch]$Offline
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $Root

function Fail([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("check: FAIL $Code $Message")
    exit $Code
}
function Invoke-Step([string]$Name, [int]$Code, [string]$Exe, [string[]]$ArgList) {
    if ($Step -ne "all" -and $Step -ne $Name) { return }
    Write-Host "check: $Name"
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { Fail $Code "$Name (exit $LASTEXITCODE)" }
}
function Get-Tests([string]$Dir, [int]$Code) {
    $files = @(Get-ChildItem -LiteralPath $Dir -Filter "*.test.mjs" -File | Sort-Object Name | ForEach-Object { $_.FullName })
    if ($files.Count -eq 0) { Fail $Code "no tests in $Dir" }
    return $files
}

# 설치(scripts/install.ps1 Invoke-Build)와 같은 빌드 조건: 컴파일러·빌드 설정을 바꾸는 환경 변수를 이 게이트 프로세스에서만
# 지우고(시스템·사용자 설정은 그대로), cargo에 --config로 컴파일러 래퍼를 끄고 링커를 기본 link.exe로 고정한다. 그래야 게이트
# 통과가 설치 빌드와 같은 조건을 뜻한다. 이름·접두사·--config 값은 install.ps1과 같아야 한다(scripts/install.test.mjs가 확인;
# 게이트는 dev·test 프로필도 빌드하므로 CARGO_PROFILE_RELEASE_ 대신 CARGO_PROFILE_ 전체를 지운다). RUSTFLAGS 계열은 지우지
# 않고 거부한다(아래, 종료 11).
$ClearedBuildVariableNames = @('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')
$ClearedBuildVariablePrefixes = @('CARGO_PROFILE_', 'CARGO_BUILD_RUSTC', 'CC', 'CFLAGS', 'CXX', 'CXXFLAGS')
$BuildConfigOverrides = @("build.rustc-wrapper=''", "build.rustc-workspace-wrapper=''", "target.x86_64-pc-windows-msvc.linker='link.exe'")
$clearedNames = @([Environment]::GetEnvironmentVariables('Process').Keys | ForEach-Object { [string]$_ } | Where-Object {
    $name = $_
    @($ClearedBuildVariableNames | Where-Object { $name.Equals($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 -or
    @($ClearedBuildVariablePrefixes | Where-Object { $name.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
} | Sort-Object)
foreach ($name in $clearedNames) { [Environment]::SetEnvironmentVariable($name, [NullString]::Value, 'Process') }
if ($clearedNames.Count -gt 0) { Write-Host "check: cleared for this run: $($clearedNames -join ', ')" }
$config = @(foreach ($setting in $BuildConfigOverrides) { '--config'; $setting })
# clippy는 cargo-clippy가 RUSTC_WORKSPACE_WRAPPER(clippy-driver)로 돌므로 그 키는 덮어쓰지 않는다.
$clippyConfig = @(foreach ($setting in $BuildConfigOverrides | Where-Object { $_ -notlike 'build.rustc-workspace-wrapper=*' }) { '--config'; $setting })

$cargoVersion = & cargo --version 2>$null
if ($LASTEXITCODE -ne 0 -or "$cargoVersion" -notmatch '^cargo 1\.95\.0 ') { Fail 10 "cargo 1.95.0 required (rust-toolchain.toml)" }
$nodeVersion = & node --version 2>$null
if ($LASTEXITCODE -ne 0 -or "$nodeVersion" -notmatch '^v(\d+)\.' -or [int]$Matches[1] -lt 22) { Fail 10 "Node.js 22+ required" }
foreach ($name in "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS") {
    if ([Environment]::GetEnvironmentVariable($name)) { Fail 11 "$name must be unset (.cargo/config.toml owns rustflags)" }
}
$net = @("--locked"); if ($Offline) { $net += "--offline" }
$deps = @("scripts/check-core-deps.mjs"); if ($Offline) { $deps += "--offline" }

Invoke-Step "fmt" 20 "cargo" @("fmt", "--all", "--", "--check")
Invoke-Step "deps" 21 "node" $deps
Invoke-Step "clippy" 22 "cargo" (@("clippy", "--workspace", "--all-targets") + $net + $clippyConfig + @("--", "-D", "warnings"))
Invoke-Step "test" 23 "cargo" (@("test", "--workspace") + $net + $config)
$env:YW_FUZZ_RUNS = "20000"                                           # fuzz-lite 스모크([09] §2.4): 무시된 fuzz_lite_*를 2만 회씩
Invoke-Step "fuzz" 29 "cargo" (@("test", "--workspace") + $net + $config + @("--", "--ignored", "fuzz_lite"))
$env:YW_FUZZ_RUNS = $null                                             # 직접 --ignored로 돌리면 1,000,000회
Invoke-Step "build" 24 "cargo" (@("build", "--workspace") + $net + $config)   # target\debug\yw-host.exe ([09] §2.2, [05] H1)
$env:YW_CHECK = "1"                                                   # 확장 프로세스 테스트가 skip 대신 실패([09])
if ($Step -in "all", "ext-test") { Invoke-Step "ext-test" 25 "node" (@("--test") + (Get-Tests "extension/tests" 25)) }
if ($Step -in "all", "script-test") { Invoke-Step "script-test" 26 "node" (@("--test") + (Get-Tests "scripts" 26)) }
Invoke-Step "privacy" 27 "node" @("scripts/privacy-scan.mjs")
Invoke-Step "audit-ext" 28 "node" @("scripts/audit-extension.mjs", "check", "--extension-root", "extension")
Invoke-Step "icons" 30 "node" @("scripts/make-icons.mjs", "--check")   # 커밋된 아이콘 = 생성기 출력([04] §1.7, [05] §2.2)
Write-Host "check: OK"
exit 0
