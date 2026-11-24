# scripts/build-android.ps1 — Android 빌드([15] §13; 2026-11-24 A2-3).
# 사용: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-android.ps1 [-Variant release|debug]
#        [-Abi arm64-v8a|x86_64|all] [-SignKey <키스토어.p12> -SignPassFile <암호 파일>] [-Offline] [-ToolRoot <폴더>]
#      게이트: ... -File scripts/build-android.ps1 -Check [-Require] [-Offline]  (scripts/check.ps1의 android 단계, 종료 33)
# 순서([15] §13): 1 도구 판 확인(android/toolchain.sha256, §4.4) → 2 cargo로 libyw.so(--release, 경로 지우기) → 3 .so 검사
# (LOAD 정렬 0x4000, 내보낸 기호 다섯, 빌드 PC 경로 문자열 없음) → 4 Gradle(--no-daemon, 검증 메타데이터 강제)이 서명 전 APK →
# 5 zipalign -P 16 -f, -c -P 16, APK·매니페스트 검사 → 6 -SignKey가 있으면 apksigner(정렬 뒤에만).
# -Check: aarch64 clippy(-D warnings)와 check-core-deps.mjs의 두 Android 표는 rustup 타깃과 NDK가 있으면 건너뛰지 않는다. 그 뒤
# (JDK·SDK·Gradle이 있고, -Offline이면 Gradle 캐시가 있을 때) 위 2–5를 debug APK로 돌고, Gradle은 새로 만든 Gradle 홈(검증된 캐시
# modules-2만 복사)에서 엄격 오프라인으로 돌며(§4.3), JVM 단위 시험(jvmTest, §18 42 N15)과 런타임 닫힘 대조(check-android-deps.mjs,
# §4.2)를 더한다. 없는 것이 있으면 "android: skipped (<이유>)"를 출력하고 0으로 끝난다. -Require면 건너뛰기가 실패(1)다.
# 이 스크립트는 경로 리터럴을 두지 않는다: 도구 폴더는 -ToolRoot, 없으면 YW_ANDROID_TOOLS, 없으면 %LOCALAPPDATA%\build-cache\droid
# (지갑을 드러내지 않는 이름, §4.4 N5). 찾을 빌드 PC 경로 문자열도 실행할 때 환경에서 만든다(§13 3).
[CmdletBinding()]
param(
    [ValidateSet("release", "debug")]
    [string]$Variant = "release",
    [ValidateSet("arm64-v8a", "x86_64", "all")]
    [string]$Abi = "arm64-v8a",
    [string]$SignKey = "",
    [string]$SignPassFile = "",
    [string]$ToolRoot = "",
    [switch]$Offline,
    [switch]$Check,
    [switch]$Require
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$AndroidDir = Join-Path $RepoRoot "android"

function Stop-Build([string]$Message) {
    [Console]::Error.WriteLine("android: FAIL $Message")
    exit 1
}
function Skip-Build([string]$Reason) {
    if ($Require) { Stop-Build "required but skipped ($Reason)" }
    Write-Host "android: skipped ($Reason)"
    exit 0
}
function Invoke-Native([string]$What, [string]$Exe, [string[]]$ArgList) {
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { Stop-Build "$What (exit $LASTEXITCODE)" }
}

# --- 0. 환경 -----------------------------------------------------------------------------------------------------
# RUSTFLAGS 계열은 .cargo/config.toml의 [target.*-linux-android] rustflags(serial cfg)를 통째로 대신하므로 거부한다(§13 2).
foreach ($name in "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
    "CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS", "CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS") {
    if ([Environment]::GetEnvironmentVariable($name)) { Stop-Build "$name must be unset (.cargo/config.toml owns rustflags)" }
}
foreach ($name in "RUSTC", "RUSTC_WRAPPER", "CARGO_BUILD_TARGET") { [Environment]::SetEnvironmentVariable($name, [NullString]::Value, "Process") }
if ($Check) { $Variant = "debug" }
$Tools = if ($ToolRoot) { $ToolRoot } elseif ($env:YW_ANDROID_TOOLS) { $env:YW_ANDROID_TOOLS } elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "build-cache\droid" } else { "" }
if (-not $Tools) { Skip-Build "no tool folder (LOCALAPPDATA is not set)" }
$Tools = [IO.Path]::GetFullPath($Tools)

# toolchain.sha256의 "version <도구> <판> [<수정판>]" 줄(§4.4).
$Versions = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $AndroidDir "toolchain.sha256"))) {
    $parts = $line.Trim() -split '\s+'
    if ($parts.Count -ge 3 -and $parts[0] -eq "version") { $Versions[$parts[1]] = @($parts | Select-Object -Skip 2) }
}
foreach ($tool in "jdk", "ndk", "gradle", "build-tools", "platform", "platform-tools") {
    if (-not $Versions.ContainsKey($tool)) { Stop-Build "android/toolchain.sha256 has no version line for $tool" }
}
function Get-Property([string]$File, [string]$Key) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return $null }
    foreach ($line in [IO.File]::ReadAllLines($File)) {
        $at = $line.IndexOf("=")
        if ($at -gt 0 -and $line.Substring(0, $at).Trim() -eq $Key) { return $line.Substring($at + 1).Trim().Trim('"') }
    }
    return $null
}

$Ndk = Join-Path $Tools "ndk-r30\android-ndk-r30"
$NdkBin = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$JavaHome = Join-Path $Tools ("jdk17\jdk-" + $Versions["jdk"][0])
$GradleDist = Join-Path $Tools ("gradle\gradle-" + $Versions["gradle"][0])
$Sdk = Join-Path $Tools "sdk"
$BuildTools = Join-Path $Sdk ("build-tools\" + $Versions["build-tools"][0])
$GradleHome = Join-Path $Tools "gradle-home"
$TargetDir = Join-Path $Tools "target"
$CargoTmp = Join-Path $Tools "tmp"
# §13 2 (P0-2): CARGO_TARGET_DIR와 cargo·NDK의 TMP에는 '#'을 두지 않는다(값싼 방어; r30의 .cmd 래퍼는 '#'에 걸리지 않았다).
foreach ($dir in $TargetDir, $CargoTmp) { if ($dir.Contains("#")) { Stop-Build "tool folder path contains '#'" } }

$Triples = switch ($Abi) {
    "arm64-v8a" { @("aarch64-linux-android") }
    "x86_64" { @("x86_64-linux-android") }
    default { @("aarch64-linux-android", "x86_64-linux-android") }
}
$AbiOf = @{ "aarch64-linux-android" = "arm64-v8a"; "x86_64-linux-android" = "x86_64" }

# --- 1. Rust 쪽 도구: rustup 타깃과 NDK ---------------------------------------------------------------------------
Push-Location -LiteralPath $RepoRoot
$sysroot = "$(& rustc --print sysroot 2>$null)".Trim()
Pop-Location
if ($LASTEXITCODE -ne 0 -or -not $sysroot) { Skip-Build "rustc not found" }
foreach ($triple in @(if ($Check) { "aarch64-linux-android" } else { $Triples })) {
    if (-not (Test-Path -LiteralPath (Join-Path $sysroot "lib\rustlib\$triple\lib"))) { Skip-Build "rustup target $triple not installed" }
}
if (-not (Test-Path -LiteralPath (Join-Path $Ndk "source.properties"))) { Skip-Build "NDK not found under the tool folder" }
$ndkRevision = Get-Property (Join-Path $Ndk "source.properties") "Pkg.Revision"
if ($ndkRevision -ne $Versions["ndk"][0]) { Stop-Build "NDK $ndkRevision installed, android/toolchain.sha256 records $($Versions["ndk"][0])" }

$CargoNet = @("--locked")
if ($Offline) { $CargoNet += "--offline" }
$CargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } elseif ($env:USERPROFILE) { Join-Path $env:USERPROFILE ".cargo" } else { "" }
$RustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } elseif ($env:USERPROFILE) { Join-Path $env:USERPROFILE ".rustup" } else { "" }

# NDK clang.exe에 타깃을 직접 준다(§13 2, P0-2 F2-1: .cmd 래퍼와 같은 바이트, cmd.exe 인자 해석 없음).
function Set-TargetEnv([string]$Triple) {
    $lower = $Triple.Replace("-", "_")
    $upper = $lower.ToUpperInvariant()
    foreach ($prefix in "CC_", "CXX_", "AR_", "CFLAGS_", "CXXFLAGS_") {
        foreach ($name in "$prefix$lower", "$prefix$Triple") { [Environment]::SetEnvironmentVariable($name, [NullString]::Value, "Process") }
    }
    [Environment]::SetEnvironmentVariable("CC_$lower", (Join-Path $NdkBin "clang.exe"), "Process")
    [Environment]::SetEnvironmentVariable("CFLAGS_$lower", "--target=${Triple}29", "Process")
    [Environment]::SetEnvironmentVariable("AR_$lower", (Join-Path $NdkBin "llvm-ar.exe"), "Process")
    [Environment]::SetEnvironmentVariable("CARGO_TARGET_${upper}_LINKER", (Join-Path $NdkBin "clang.exe"), "Process")
    $env:ANDROID_NDK_HOME = $Ndk
    $env:ANDROID_NDK_ROOT = $Ndk
}
# --config "target.<타깃>.rustflags=[...]": 링크 타깃과 경로 지우기(§13 2). 설정 파일의 같은 배열(serial cfg)과 합쳐진다.
# 값은 TOML 작은따옴표 리터럴이라 '\'와 '#'이 그대로 가고, 안쪽 큰따옴표가 없어 Windows PowerShell 5.1에서도 그대로 넘어간다.
function Get-TargetConfig([string]$Triple, [bool]$Remap) {
    $flags = @("-Clink-arg=--target=${Triple}29")
    if ($Remap) {
        foreach ($pair in @(@($RepoRoot, "yw"), @($CargoHome, "cargo"), @($RustupHome, "rustup"))) {
            if (-not $pair[0]) { Stop-Build "cannot build the path remap (CARGO_HOME, RUSTUP_HOME or USERPROFILE missing)" }
            if ($pair[0].Contains("'")) { Stop-Build "a build path contains a single quote" }
            $flags += "--remap-path-prefix=$($pair[0])=$($pair[1])"
        }
    }
    $items = ($flags | ForEach-Object { "'$_'" }) -join ","
    return @("--config", "target.$Triple.rustflags=[$items]", "--config", "build.rustc-wrapper=''")
}
$env:CARGO_TARGET_DIR = $TargetDir
[void](New-Item -ItemType Directory -Force -Path $CargoTmp)

if ($Check) {
    Write-Host "android: clippy aarch64-linux-android"
    Set-TargetEnv "aarch64-linux-android"
    $savedTmp = $env:TMP; $savedTemp = $env:TEMP
    $env:TMP = $CargoTmp; $env:TEMP = $CargoTmp
    # 빌드와 같은 rustflags(경로 지우기 포함): 다르면 cargo가 둘을 오갈 때마다 의존을 다시 컴파일한다.
    $clippy = @("clippy", "--target", "aarch64-linux-android", "-p", "yw-android", "--all-targets") + $CargoNet +
        (Get-TargetConfig "aarch64-linux-android" $true) + @("--", "-D", "warnings")
    Push-Location -LiteralPath $RepoRoot
    & cargo @clippy
    $clippyExit = $LASTEXITCODE
    Pop-Location
    $env:TMP = $savedTmp; $env:TEMP = $savedTemp
    if ($clippyExit -ne 0) { Stop-Build "clippy aarch64-linux-android (exit $clippyExit)" }
    foreach ($triple in "aarch64-linux-android", "x86_64-linux-android") {
        Write-Host "android: deps $triple"
        $depsArgs = @((Join-Path $RepoRoot "scripts\check-core-deps.mjs"), "--target", $triple)
        if ($Offline) { $depsArgs += "--offline" }
        Push-Location -LiteralPath $RepoRoot
        & node @depsArgs
        $depsExit = $LASTEXITCODE
        Pop-Location
        if ($depsExit -ne 0) { Stop-Build "check-core-deps $triple (exit $depsExit)" }
    }
}

# --- 2. Java 쪽 도구: JDK·SDK·Gradle(§4.4) -------------------------------------------------------------------------
$missing = @()
if (-not (Test-Path -LiteralPath (Join-Path $JavaHome "release"))) { $missing += "JDK" }
if (-not (Test-Path -LiteralPath (Join-Path $GradleDist "bin\gradle.bat"))) { $missing += "Gradle" }
if (-not (Test-Path -LiteralPath (Join-Path $BuildTools "source.properties"))) { $missing += "SDK build-tools" }
if ($missing.Count -gt 0) {
    if ($Check) { Skip-Build "Gradle part: $($missing -join ', ') not found under the tool folder" }
    Stop-Build "$($missing -join ', ') not found under the tool folder"
}
if ($Offline -and -not (Test-Path -LiteralPath (Join-Path $GradleHome "caches\modules-2\files-2.1"))) {
    if ($Check) { Skip-Build "Gradle part: -Offline and no Gradle cache" }
    Stop-Build "-Offline and no Gradle cache"
}
$jdkVersion = Get-Property (Join-Path $JavaHome "release") "JAVA_RUNTIME_VERSION"
$jdkVendor = Get-Property (Join-Path $JavaHome "release") "IMPLEMENTOR"
if ($jdkVersion -ne $Versions["jdk"][0] -or $jdkVendor -ne "Eclipse Adoptium") { Stop-Build "JDK $jdkVendor $jdkVersion installed, android/toolchain.sha256 records Temurin $($Versions["jdk"][0])" }
if (-not (Test-Path -LiteralPath (Join-Path $GradleDist ("lib\gradle-api-metadata-" + $Versions["gradle"][0] + ".jar")))) { Stop-Build "Gradle is not $($Versions["gradle"][0])" }
$checks = @(
    @("build-tools", (Join-Path $BuildTools "source.properties"), $Versions["build-tools"][0]),
    @("platform", (Join-Path $Sdk ("platforms\" + $Versions["platform"][0] + "\source.properties")), $Versions["platform"][1]),
    @("platform-tools", (Join-Path $Sdk "platform-tools\source.properties"), $Versions["platform-tools"][0]))
foreach ($entry in $checks) {
    $found = Get-Property $entry[1] "Pkg.Revision"
    if ($found -ne $entry[2]) { Stop-Build "$($entry[0]) $found installed, android/toolchain.sha256 records $($entry[2])" }
}

# --- 3. libyw.so ---------------------------------------------------------------------------------------------------
$JniDir = Join-Path $AndroidDir "app\build\rustJniLibs"
if (Test-Path -LiteralPath $JniDir) { Remove-Item -LiteralPath $JniDir -Recurse -Force }
# 찾을 빌드 PC 경로 문자열(§13 3): 실행할 때 환경에서 만들고, 대소문자를 가리지 않으며 '\'와 '/' 둘 다 본다.
$needles = New-Object System.Collections.Generic.List[string]
foreach ($value in @($env:USERPROFILE, $env:LOCALAPPDATA, $CargoHome, $RustupHome, $RepoRoot, $Ndk, $Tools, $TargetDir, $CargoTmp, $env:TMP, $env:TEMP)) {
    if ($value -and $value.Length -ge 4) { $needles.Add($value.TrimEnd('\')); $needles.Add($value.TrimEnd('\').Replace('\', '/')) }
}
if ($env:USERNAME -and $env:USERNAME.Length -ge 2) { foreach ($sep in '\', '/') { $needles.Add("Users$sep$($env:USERNAME)$sep") } }
$ExpectedExports = @("JNI_OnLoad", "rustsecp256k1_v0_11_context_create", "rustsecp256k1_v0_11_context_destroy",
    "rustsecp256k1_v0_11_default_error_callback_fn", "rustsecp256k1_v0_11_default_illegal_callback_fn")

$BuiltAbis = @()
foreach ($triple in $Triples) {
    Write-Host "android: cargo build --release $triple"
    Set-TargetEnv $triple
    $savedTmp = $env:TMP; $savedTemp = $env:TEMP
    $env:TMP = $CargoTmp; $env:TEMP = $CargoTmp
    $build = @("build", "--release", "--target", $triple, "-p", "yw-android") + $CargoNet + (Get-TargetConfig $triple $true)
    Push-Location -LiteralPath $RepoRoot
    $cOutput = @(& cargo @build 2>&1 | ForEach-Object { $text = "$_"; Write-Host $text; $text })
    $buildExit = $LASTEXITCODE
    Pop-Location
    $env:TMP = $savedTmp; $env:TEMP = $savedTemp
    if ($buildExit -ne 0) { Stop-Build "cargo build $triple (exit $buildExit)" }
    # C 진단은 cc-rs의 cargo:warning 줄만 본다(P0-2 F2-2).
    $cWarnings = @($cOutput | Where-Object { $_ -match '^warning: secp256k1-sys@' })
    if ($cWarnings.Count -gt 0) { Stop-Build "C diagnostics from secp256k1-sys ($($cWarnings.Count))" }
    $so = Join-Path $TargetDir "$triple\release\libyw.so"
    if (-not (Test-Path -LiteralPath $so)) { Stop-Build "libyw.so not built for $triple" }

    # .so 검사(§13 3): LOAD 정렬, 내보낸 기호, 경로 문자열.
    $loads = @(& (Join-Path $NdkBin "llvm-readelf.exe") -Wl $so | Where-Object { "$_" -match '^\s+LOAD\s' })
    if ($loads.Count -eq 0) { Stop-Build "no LOAD segment in libyw.so ($triple)" }
    foreach ($load in $loads) { if ((("$load".Trim()) -split '\s+')[-1] -ne "0x4000") { Stop-Build "LOAD segment not 16 KB aligned ($triple): $("$load".Trim())" } }
    $exported = @(& (Join-Path $NdkBin "llvm-readelf.exe") --dyn-syms -W $so | ForEach-Object {
        $cols = ("$_".Trim()) -split '\s+'
        if ($cols.Count -ge 8 -and $cols[4] -eq "GLOBAL" -and $cols[6] -ne "UND" -and $cols[0] -match '^\d+:$') { ($cols[7] -split '@')[0] }
    } | Sort-Object -Unique)
    if (($exported -join ",") -ne (($ExpectedExports | Sort-Object) -join ",")) { Stop-Build "exported symbols of libyw.so ($triple): $($exported -join ', ')" }
    $hits = 0
    foreach ($text in @(& (Join-Path $NdkBin "llvm-strings.exe") -n 4 $so)) {
        foreach ($needle in $needles) { if ("$text".IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits += 1; break } }
    }
    if ($hits -gt 0) { Stop-Build "libyw.so ($triple) holds $hits build-PC path strings" }
    $abiDir = Join-Path $JniDir $AbiOf[$triple]
    [void](New-Item -ItemType Directory -Force -Path $abiDir)
    Copy-Item -LiteralPath $so -Destination (Join-Path $abiDir "libyw.so")
    $BuiltAbis += $AbiOf[$triple]
    Write-Host "android: libyw.so $triple $((Get-Item -LiteralPath $so).Length) bytes, LOAD 0x4000, 5 exports, 0 path strings"
}

# --- 4. Gradle -----------------------------------------------------------------------------------------------------
$env:JAVA_HOME = $JavaHome
$env:ANDROID_HOME = $Sdk
$env:ANDROID_SDK_ROOT = $null
$env:ANDROID_USER_HOME = Join-Path $Tools "android-home"
$env:GRADLE_OPTS = $null
$env:JAVA_TOOL_OPTIONS = $null
$env:Path = (Join-Path $JavaHome "bin") + ";" + $env:Path
# Java·Gradle의 임시 폴더는 표준 임시 폴더(§4.4, P0-6 F6-3).
if ($env:LOCALAPPDATA) { $env:TMP = Join-Path $env:LOCALAPPDATA "Temp"; $env:TEMP = $env:TMP }
$env:GRADLE_USER_HOME = $GradleHome
if ($Check) {
    # §4.3: 검증된 캐시(modules-2)만 새 홈에 복사해 엄격 검증이 모든 해석을 다시 보게 한다(P0-7: 원래 홈에서만 통과한 경우를 잡는다).
    $checkHome = Join-Path $Tools "gradle-check-home"
    if (Test-Path -LiteralPath $checkHome) { Remove-Item -LiteralPath $checkHome -Recurse -Force }
    [void](New-Item -ItemType Directory -Force -Path (Join-Path $checkHome "caches"))
    Copy-Item -LiteralPath (Join-Path $GradleHome "caches\modules-2") -Destination (Join-Path $checkHome "caches\modules-2") -Recurse
    $env:GRADLE_USER_HOME = $checkHome
}
$taskVariant = $Variant.Substring(0, 1).ToUpperInvariant() + $Variant.Substring(1)
# clean은 쓰지 않는다: build/rustJniLibs(위 3)를 지운다. Gradle의 증분 빌드가 APK를 새로 만든다.
$gradleArgs = @("--no-daemon", "--dependency-verification", "strict", "--project-dir", $AndroidDir, ":app:assemble$taskVariant")
if ($Check) { $gradleArgs += ":app:jvmTest" }
if ($Offline) { $gradleArgs = @("--offline") + $gradleArgs }
$depsReport = Join-Path $AndroidDir "app\build\yw-runtime-deps.txt"
Write-Host "android: gradle $($gradleArgs -join ' ')"
Invoke-Native "gradle" (Join-Path $GradleDist "bin\gradle.bat") $gradleArgs
$reportArgs = @("--no-daemon", "--quiet", "--dependency-verification", "strict", "--project-dir", $AndroidDir, ":app:dependencies", "--configuration", "releaseRuntimeClasspath")
if ($Offline) { $reportArgs = @("--offline") + $reportArgs }
$report = @(& (Join-Path $GradleDist "bin\gradle.bat") @reportArgs)
if ($LASTEXITCODE -ne 0) { Stop-Build "gradle dependencies (exit $LASTEXITCODE)" }
[IO.File]::WriteAllLines($depsReport, [string[]]$report)
Invoke-Native "check-android-deps runtime" "node" @((Join-Path $RepoRoot "scripts\check-android-deps.mjs"), "runtime", $depsReport, (Join-Path $AndroidDir "runtime-deps.txt"))

# --- 5. 정렬과 검사 ------------------------------------------------------------------------------------------------
$unsigned = Join-Path $AndroidDir "app\build\outputs\apk\$Variant\app-$Variant-unsigned.apk"
if (-not (Test-Path -LiteralPath $unsigned)) { Stop-Build "Gradle made no app-$Variant-unsigned.apk" }
$outDir = Join-Path $AndroidDir "app\build\outputs\yw"
[void](New-Item -ItemType Directory -Force -Path $outDir)
$aligned = Join-Path $outDir "yw-$Variant-aligned.apk"
$zipalign = Join-Path $BuildTools "zipalign.exe"
Invoke-Native "zipalign" $zipalign @("-P", "16", "-f", "4", $unsigned, $aligned)
Invoke-Native "zipalign check" $zipalign @("-c", "-P", "16", "4", $aligned)
Invoke-Native "check-android-deps apk" "node" @((Join-Path $RepoRoot "scripts\check-android-deps.mjs"), "apk", $aligned, ($BuiltAbis -join ","))
$tree = Join-Path $AndroidDir "app\build\yw-manifest-tree.txt"
$dump = @(& (Join-Path $BuildTools "aapt2.exe") dump xmltree --file AndroidManifest.xml $aligned)
if ($LASTEXITCODE -ne 0) { Stop-Build "aapt2 dump xmltree (exit $LASTEXITCODE)" }
[IO.File]::WriteAllLines($tree, [string[]]$dump)
Invoke-Native "check-android-deps manifest" "node" @((Join-Path $RepoRoot "scripts\check-android-deps.mjs"), "manifest", $tree, $Variant)

# --- 6. 서명(정렬 뒤에만, §13 6, §14.2) ----------------------------------------------------------------------------
$result = $aligned
if ($SignKey) {
    if (-not $SignPassFile) { Stop-Build "-SignKey needs -SignPassFile" }
    $signed = Join-Path $outDir "yw-$Variant.apk"
    $apksigner = Join-Path $BuildTools "apksigner.bat"
    # PKCS12는 --ks-pass 하나만 준다(P0-8 F8-1). 암호는 파일로만 넘기고 출력하지 않는다.
    Invoke-Native "apksigner sign" $apksigner @("sign", "--v1-signing-enabled", "false", "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true", "--ks", $SignKey, "--ks-pass", "file:$SignPassFile", "--out", $signed, $aligned)
    Invoke-Native "apksigner verify" $apksigner @("verify", "--min-sdk-version", "29", $signed)
    Invoke-Native "zipalign check (signed)" $zipalign @("-c", "-P", "16", "4", $signed)
    $result = $signed
}
# Get-FileHash가 없는 셸(다른 PowerShell이 물려준 PSModulePath)에서도 되게 .NET으로 잰다.
$sha = [Security.Cryptography.SHA256]::Create()
try { $stream = [IO.File]::OpenRead($result); try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant() } finally { $stream.Dispose() } } finally { $sha.Dispose() }
Write-Host "android: OK $Variant $($BuiltAbis -join ',') $((Get-Item -LiteralPath $result).Length) bytes sha256 $hash"
Write-Host "android: apk $result"
exit 0
