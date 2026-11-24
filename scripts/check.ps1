# scripts/check.ps1 — 저장소 게이트. 사용: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 [-Step <name>] [-Offline] [-RequireAndroid]
[CmdletBinding()]
param(
    [ValidateSet("all", "fmt", "deps", "clippy", "test", "fuzz", "winui", "s4fz", "build", "ext-test", "script-test", "privacy", "audit-ext", "icons", "android")]
    [string]$Step = "all",
    [switch]$Offline,
    [switch]$RequireAndroid
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
# 않고 거부한다(아래, 종료 11). CARGO_BUILD_TARGET은 결과를 <빌드 폴더>\<대상>\debug로 보내 확장 테스트가 찾는 yw-host.exe를
# 비껴가게 한다.
$ClearedBuildVariableNames = @('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET')
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

# 빌드 폴더([09] §2.2): 결과가 호스트 ACL 특성에 좌우되지 않게 한다. 빌드 폴더(CARGO_TARGET_DIR, 없으면 target\)나 그것을 담은
# 저장소 루트에 Medium보다 낮은 무결성 레이블(Low·Untrusted; 일부 샌드박스 도구가 저장소에 붙인다)이 있으면 그 아래 만든 exe가
# 레이블을 물려받아 Low 무결성으로 돌고(yw-win·yw-host 무결성 검사, H1, %TEMP% 쓰기가 실패한다), 빌드 폴더가 재분석 지점이면
# 다른 곳에 쓴다. 그때는 이 실행에서만 저장소 밖 사설 폴더 %LOCALAPPDATA%\YourWallet-dev\target(현재 사용자·SYSTEM·
# Administrators만, 상속 끊음, 레이블 없음)을 CARGO_TARGET_DIR로 쓰고 한 줄 출력한다. 저장소의 ACL은 바꾸지 않는다.
# 레이블은 Get-Acl이 돌려주지 않으므로 GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)로 읽는다(메모리에서만 만드는
# P/Invoke: Add-Type처럼 %TEMP%에 쓰지 않는다).
$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$TrustedSids = @($UserSid, 'S-1-5-18', 'S-1-5-32-544')
$script:NativeSecurity = $null
function Get-NativeSecurity {
    if ($null -ne $script:NativeSecurity) { return $script:NativeSecurity }
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object Reflection.AssemblyName('YwCheckNative')), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $type = $assembly.DefineDynamicModule('YwCheckNative').DefineType('YwCheckNative.Advapi', 'Public, Class')
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
    $script:NativeSecurity = $type.CreateType()
    return $script:NativeSecurity
}
# $Path의 무결성 레이블이 Medium보다 낮으면 이유 문장, 아니면 $null(레이블 없음 = Medium).
function Get-LowLabel([string]$Path) {
    $native = Get-NativeSecurity
    $owner = [IntPtr]::Zero; $group = [IntPtr]::Zero; $dacl = [IntPtr]::Zero; $sacl = [IntPtr]::Zero; $sd = [IntPtr]::Zero
    $status = $native::GetNamedSecurityInfoW($Path, 1, 0x10, [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$sd)   # SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION
    if ($status -ne 0) { return "integrity label unreadable (error $status)" }
    try {
        $text = [IntPtr]::Zero
        if (-not $native::ConvertSecurityDescriptorToStringSecurityDescriptorW($sd, 1, 0x10, [ref]$text, [IntPtr]::Zero)) { return "integrity label unreadable" }
        try { $sddl = [Runtime.InteropServices.Marshal]::PtrToStringUni($text) } finally { [void]$native::LocalFree($text) }
    } finally { [void]$native::LocalFree($sd) }
    foreach ($ace in [regex]::Matches($sddl, '\(ML;[^;]*;[^;]*;[^;]*;[^;]*;([^)]+)\)')) {
        $sid = $ace.Groups[1].Value
        $level = switch -Regex ($sid) { '^LW$' { 0x1000 } '^(ME|MP|HI|SI)$' { 0x2000 } '^S-1-16-(\d+)$' { [int]$Matches[1] } default { 0 } }
        if ($level -lt 0x2000) { return "integrity label $sid (below Medium)" }
    }
    return $null
}
# 빌드 폴더로 쓸 수 없으면 이유, 아니면 $null. 아직 없는 폴더는 가장 가까운 있는 상위 폴더의 레이블을 본다(물려받으므로).
function Get-BuildDirProblem([string]$Dir) {
    $paths = @()
    if (Test-Path -LiteralPath $Dir) {
        $item = Get-Item -LiteralPath $Dir -Force
        if (-not $item.PSIsContainer) { return "not a folder" }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return "reparse point (link)" }
        $paths += $Dir
    } else {
        $parent = [IO.Path]::GetDirectoryName($Dir)
        while (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) { $parent = [IO.Path]::GetDirectoryName($parent) }
        if (-not [string]::IsNullOrEmpty($parent)) { $paths += $parent }
    }
    $rootPrefix = $Root.TrimEnd('\') + '\'
    if ($Dir.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { $paths += $Root }
    foreach ($path in $paths) {
        $problem = Get-LowLabel $path
        if ($null -ne $problem) { return "$problem on $path" }
    }
    return $null
}
# 사설 폴더 확인: 링크가 아니고, 소유자·허용 ACE가 현재 사용자·SYSTEM·Administrators뿐이고, 낮은 레이블이 없다. $Protected면
# 상속도 끊겨 있어야 한다. 문제가 없으면 $null.
function Get-PrivateDirProblem([string]$Dir, [bool]$Protected) {
    $item = Get-Item -LiteralPath $Dir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return "not a plain folder" }
    $acl = Get-Acl -LiteralPath $Dir
    if ($Protected -and -not $acl.AreAccessRulesProtected) { return "inherits permissions from its parent" }
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($acl.Sddl)
    if ($null -eq $sd.Owner -or $TrustedSids -notcontains $sd.Owner.Value) { return "owner is not the current user, SYSTEM or Administrators" }
    if ($null -eq $sd.DiscretionaryAcl) { return "no DACL" }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.QualifiedAce]) { return "unknown ACE" }
        if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and $TrustedSids -notcontains $ace.SecurityIdentifier.Value) {
            return "access granted to $($ace.SecurityIdentifier.Value)"
        }
    }
    return Get-LowLabel $Dir
}
function New-PrivateDir([string]$Dir) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $TrustedSids) {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),
            [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    $extensions = 'System.IO.FileSystemAclExtensions' -as [type]   # PowerShell 7(.NET); 5.1(.NET Framework)은 CreateDirectory(path, security)
    if ($null -ne $extensions) { [void]$extensions::CreateDirectory($security, $Dir) } else { [void][IO.Directory]::CreateDirectory($Dir, $security) }
}
$TargetDir = if ([string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) { Join-Path $Root "target" } else { [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $env:CARGO_TARGET_DIR)) }
$problem = Get-BuildDirProblem $TargetDir
if ($null -ne $problem) {
    if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) { Fail 12 "build folder $TargetDir unsuitable ($problem) and LOCALAPPDATA is not set" }
    $privateBase = Join-Path $env:LOCALAPPDATA "YourWallet-dev"
    $privateTarget = Join-Path $privateBase "target"
    try {
        if (-not (Test-Path -LiteralPath $privateBase)) { New-PrivateDir $privateBase }
        $privateProblem = Get-PrivateDirProblem $privateBase $true
        if ($null -eq $privateProblem -and (Test-Path -LiteralPath $privateTarget)) { $privateProblem = Get-PrivateDirProblem $privateTarget $false }
    } catch {
        $privateProblem = $_.Exception.Message
    }
    if ($null -ne $privateProblem) { Fail 12 "build folder $TargetDir unsuitable ($problem); private folder $privateBase unusable ($privateProblem): remove it and run again" }
    Write-Host "check: build folder $TargetDir unsuitable ($problem); using CARGO_TARGET_DIR=$privateTarget"
    $env:CARGO_TARGET_DIR = $privateTarget
}

Invoke-Step "fmt" 20 "cargo" @("fmt", "--all", "--", "--check")
Invoke-Step "deps" 21 "node" $deps
Invoke-Step "clippy" 22 "cargo" (@("clippy", "--workspace", "--all-targets") + $net + $clippyConfig + @("--", "-D", "warnings"))
Invoke-Step "test" 23 "cargo" (@("test", "--workspace") + $net + $config)
$env:YW_FUZZ_RUNS = "20000"                                           # fuzz-lite 스모크([09] §2.4): 무시된 fuzz_lite_*를 2만 회씩
Invoke-Step "fuzz" 29 "cargo" (@("test", "--workspace") + $net + $config + @("--", "--ignored", "fuzz_lite"))
$env:YW_FUZZ_RUNS = $null                                             # 직접 --ignored로 돌리면 1,000,000회
# 창 UI 하네스 winui(2026-11-18 [15] §11.4 S4 A3, [09] §2.2): 숨은 승인 창을 만드는 #[ignore] 시험을 직렬로 돌린다. 창은 보이지
# 않고 전경을 가져가지 않는다(자체 시험이 확인). 테스트 스레드에 비공개 데스크톱을 붙이는 길은 yw-win에 데스크톱 API가 없고(더하면
# A3 밖의 yw-win unsafe 변경) 주인이 대안(O-3)을 골라 쓰지 않는다. 2026-11-20(S4 B7, 주인이 맡긴 결정): 이 단계는 상설이다. 실제 Win32
# 재진입(s4_flow/reentry.txt의 drop 항목)과 창 흔적(input.txt, flow.txt의 l1_* fx 항목·포커스·Tab·패널 클릭, lifecycle.txt의
# windows=N)은 비평 A-7·A-8의 고정이고 창 없이 돌리면 만들 수 없다. 창 없는 절반(셸 없이 같은 시나리오, s4_flow/headless.txt와 그
# 교차 확인)은 test 단계에서 돈다. 그 전에는 이름이 s4fl이었고 B7에서 없앨 예정이었다. 필터가 아무 시험도 고르지 않으면
# libtest는 0으로 끝나므로(2026-11-18 A3 검토), 먼저 --list로 필터마다 #[ignore] 시험 수를 세어 최소 수보다 적으면 31로 멈춘다.
# 최소 수는 그 시험을 더하는 커밋(S4 A4·A5·A6)이 올리고 이름을 바꾸는 커밋이 함께 고친다.
# 2026-11-20(S4 B7 검토): 최소 수는 실제 수다 — flow_tests 80은 창 있는 시험 79(단계 A의 66에 F1 검토·F2·B5 검토·B6이 더한
# 13)와 창 없는 print_headless 하나. 그 전에는 단계 A 끝의 66이라 창 있는 시험 14개가 빠져도 31이 나지 않았다. 시험을 더하거나
# 빼는 커밋이 이 수를 함께 고친다.
# 2026-11-22(S4 W14ab 검토): input_tests 9 → 10 — RepaintAi 실행 팔을 실제(숨긴) 창에서 보는 the_ai_repaint_reaches_only_its_window를 더했다.
$WinuiMinimum = [ordered]@{ "app_approval::flow_support" = 3; "app_approval::flow_tests" = 80; "app_approval::input_tests" = 10 }
$winuiArgs = @("test", "-p", "yw-app", "--lib") + $net + $config + @("--", "--ignored")
if ($Step -in "all", "winui") {
    Write-Host "check: winui (list)"
    $winuiListed = @(& cargo @($winuiArgs + @("--list") + @($WinuiMinimum.Keys)))
    if ($LASTEXITCODE -ne 0) { Fail 31 "winui list (exit $LASTEXITCODE)" }
    foreach ($filter in $WinuiMinimum.Keys) {
        $found = @($winuiListed | Where-Object { "$_".StartsWith("${filter}::") -and "$_".EndsWith(": test") }).Count
        if ($found -lt $WinuiMinimum[$filter]) { Fail 31 "winui: $found ignored tests under $filter, at least $($WinuiMinimum[$filter]) expected" }
    }
}
Invoke-Step "winui" 31 "cargo" ($winuiArgs + @("--test-threads=1") + @($WinuiMinimum.Keys))
# S4 고정 시험이 컴파일되어 도는지(2026-11-19 [15] §11.4 S4 F-A 검토, [09] §2.1): test 단계의 frozen_tests_keep_their_names_and_bodies는
# 소스 글만 읽으므로, 파일·모듈 cfg, 빠진 mod·#[path] 줄, [[test]] test = false, 컴파일되지 않는 파일에 남긴 사본이면 고정 시험이 돌지 않아도
# 초록이다. 그래서 test 단계와 같은 인자의 --list와 --list --ignored로 고정 이름(frozen-tests.txt와 frozen-helpers.txt의 test 줄)마다
# 컴파일된 수·무시된 수를 세어 YW_S4_COMPILED로 넘기고, #[ignore]된 frozen_tests_are_compiled가 소스의 같은 이름 #[test] 수와 맞춰 본다
# (소스보다 적게 컴파일되거나, 소스에서 무시되지 않은 것보다 적게 돌면 32). 그 시험이 목록에 정확히 하나 없으면 32. S4 동안 둔다.
$S4fzTest = "app::tests::s4_frozen::frozen_tests_are_compiled"
if ($Step -in "all", "s4fz") {
    Write-Host "check: s4fz"
    $frozenDir = Join-Path $Root "crates/yw-app/src/app/tests/s4_flow"
    $leaves = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $frozenDir "frozen-tests.txt"))) { $parts = $line.Split(' '); if ($parts.Count -eq 4) { [void]$leaves.Add($parts[1]) } }
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $frozenDir "frozen-helpers.txt"))) { $parts = $line.Split(' '); if ($parts.Count -eq 5 -and $parts[1] -eq "test") { [void]$leaves.Add($parts[2]) } }
    if ($leaves.Count -eq 0) { Fail 32 "s4fz: no frozen test names" }
    $s4fzList = @("test", "--workspace") + $net + $config + @("--", "--list")
    $s4fzCounts = @{}
    foreach ($ignoredOnly in $false, $true) {
        $listed = @(& cargo @($s4fzList + @(if ($ignoredOnly) { "--ignored" })))
        if ($LASTEXITCODE -ne 0) { Fail 32 "s4fz list (exit $LASTEXITCODE)" }
        $counts = [System.Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
        foreach ($leaf in $leaves) { $counts[$leaf] = 0 }
        foreach ($entry in $listed) {
            $text = "$entry"
            if (-not $text.EndsWith(": test")) { continue }
            $leaf = ($text.Substring(0, $text.Length - 6) -split "::")[-1]
            if ($counts.ContainsKey($leaf)) { $counts[$leaf] += 1 }
        }
        $s4fzCounts[$ignoredOnly] = $counts
    }
    $env:YW_S4_COMPILED = (@(foreach ($leaf in $leaves) { "$leaf=$($s4fzCounts[$false][$leaf])/$($s4fzCounts[$true][$leaf])" }) -join ";")
    $s4fzArgs = @("test", "-p", "yw-app", "--lib") + $net + $config + @("--", "--ignored", "--exact", $S4fzTest)
    $s4fzFound = @(& cargo @($s4fzArgs + @("--list")) | Where-Object { "$_" -eq "${S4fzTest}: test" })
    if ($LASTEXITCODE -ne 0 -or $s4fzFound.Count -ne 1) { Fail 32 "s4fz: $S4fzTest not listed exactly once" }
    & cargo @s4fzArgs
    if ($LASTEXITCODE -ne 0) { Fail 32 "s4fz (exit $LASTEXITCODE)" }
    $env:YW_S4_COMPILED = $null
}
Invoke-Step "build" 24 "cargo" (@("build", "--workspace") + $net + $config)   # <빌드 폴더>\debug\yw-host.exe ([09] §2.2, [05] H1)
$env:YW_CHECK = "1"                                                   # 확장 프로세스 테스트가 skip 대신 실패([09])
if ($Step -in "all", "ext-test") { Invoke-Step "ext-test" 25 "node" (@("--test") + (Get-Tests "extension/tests" 25)) }
if ($Step -in "all", "script-test") { Invoke-Step "script-test" 26 "node" (@("--test") + (Get-Tests "scripts" 26)) }
Invoke-Step "privacy" 27 "node" @("scripts/privacy-scan.mjs")
Invoke-Step "audit-ext" 28 "node" @("scripts/audit-extension.mjs", "check", "--extension-root", "extension")
Invoke-Step "icons" 30 "node" @("scripts/make-icons.mjs", "--check")   # 커밋된 아이콘 = 생성기 출력([04] §1.7, [05] §2.2)
# Android([15] §13, [09] §2.2; 2026-11-24 A2-3, 종료 33 — 31은 winui다, §18 42 N1): scripts/build-android.ps1 -Check가 aarch64
# clippy(-D warnings), check-core-deps.mjs의 두 Android 표, 릴리스 libyw.so와 그 검사, 새 Gradle 홈의 엄격 검증 assembleDebug·assembleRelease(-Offline이면 오프라인; release는 2026-11-25 A2-3 검토부터),
# JVM 단위 시험, 런타임 닫힘 대조(check-android-deps.mjs), APK·매니페스트 검사를 돈다. 도구가 없으면 "android: skipped (<이유>)"로
# 넘어가되(rustup 타깃과 NDK가 있으면 clippy와 Android 표는 건너뛰지 않는다), -RequireAndroid 또는 YW_CHECK_ANDROID=1이면 건너뛰기도
# 실패다. yw-android·yw-engine·android/를 바꾸는 커밋 전 게이트는 -RequireAndroid로 돈다(AGENTS.md §2).
$androidArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $Root "scripts\build-android.ps1"), "-Check")
if ($Offline) { $androidArgs += "-Offline" }
if ($RequireAndroid -or $env:YW_CHECK_ANDROID -eq "1") { $androidArgs += "-Require" }
Invoke-Step "android" 33 "powershell" $androidArgs
Write-Host "check: OK"
exit 0
