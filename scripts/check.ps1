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
Invoke-Step "build" 24 "cargo" (@("build", "--workspace") + $net + $config)   # <빌드 폴더>\debug\yw-host.exe ([09] §2.2, [05] H1)
$env:YW_CHECK = "1"                                                   # 확장 프로세스 테스트가 skip 대신 실패([09])
if ($Step -in "all", "ext-test") { Invoke-Step "ext-test" 25 "node" (@("--test") + (Get-Tests "extension/tests" 25)) }
if ($Step -in "all", "script-test") { Invoke-Step "script-test" 26 "node" (@("--test") + (Get-Tests "scripts" 26)) }
Invoke-Step "privacy" 27 "node" @("scripts/privacy-scan.mjs")
Invoke-Step "audit-ext" 28 "node" @("scripts/audit-extension.mjs", "check", "--extension-root", "extension")
Invoke-Step "icons" 30 "node" @("scripts/make-icons.mjs", "--check")   # 커밋된 아이콘 = 생성기 출력([04] §1.7, [05] §2.2)
Write-Host "check: OK"
exit 0
