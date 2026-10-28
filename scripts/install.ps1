# scripts/install.ps1 - Your Wallet을 소스에서 빌드해 현재 사용자에게 설치한다 (spec.md D1, spec/01 §9.2).
# 저장소 루트의 install.cmd를 더블클릭하면 이 스크립트가 실행된다. 미리 빌드한 실행 파일은 배포하지 않는다(D1).
# Windows PowerShell 5.1과 PowerShell 7에서 동작한다. 관리자 권한이 필요 없다(현재 사용자 범위만 바꾼다).
#
# 사용 (저장소 루트에서):
#   install.cmd [-InstallDir <폴더>] [-NoShortcut] [-NoNativeHost] [-NoBuild] [-DryRun]
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install.ps1 [같은 옵션]
#
#   -InstallDir    설치 폴더. 기본 %LOCALAPPDATA%\Programs\YourWallet
#   -NoShortcut    시작 메뉴 바로가기를 만들지 않는다.
#   -NoNativeHost  HKCU에 Chrome native messaging host를 등록하지 않는다(manifest 파일은 설치 폴더에 쓴다).
#   -NoBuild       빌드하지 않고 이미 있는 target\release\yw-app.exe·yw-host.exe를 쓴다(빌드 도구 확인도 건너뛴다).
#   -DryRun        확인과 할 일 출력만 하고 아무것도 바꾸지 않는다(빌드·winget도 실행하지 않는다).
#
# 순서: (1) 확장 파일·ID 확인 -> (2) 빌드 도구 확인(rustup·cargo, Visual Studio C++ 빌드 도구). 없으면 winget 명령을
# 보여 주고 Y라고 답할 때만 실행 -> (3) cargo build --release --locked -p yw-app -p yw-host -> (4) 설치 폴더 확인(이전
# 설치가 있으면 업그레이드). 바꿀 파일을 실행 중인 yw-app·yw-host가 쓰고 있으면 닫아 달라고 묻는다(강제 종료하지 않는다)
# -> (5) yw-app.exe·yw-host.exe·uninstall.ps1·extension\(런타임 파일만) 복사. 내용이 같은 파일은 건너뛰고 이전 설치에만
# 있던 파일은 지운다 -> (6) native host manifest 쓰기·검증 -> (7) HKCU 등록 -> (8) 시작 메뉴 바로가기 -> 설치 기록, 안내.
# 지갑 데이터 %LOCALAPPDATA%\YourWallet\ 은 읽지도 바꾸지도 않는다. 같은 소스로 다시 실행해도 결과가 같다(멱등).
#
# 종료 코드:
#   0  성공(-DryRun 포함)
#   1  환경·인자 오류(저장소 밖의 사본을 실행, LOCALAPPDATA 없음, 64비트 Windows 아님, 쓸 수 없는 설치 경로,
#      설치 기록이 없는 비어 있지 않은 폴더 등)
#   2  소스·빌드 결과 오류(확장 파일 없음·형식 오류, 확장 ID 불일치, -NoBuild인데 yw-app.exe·yw-host.exe 없음)
#   3  취소(사용자가 취소함, 또는 실행 중인 yw-app·yw-host를 닫아 달라고 물을 수 없는 비대화형 실행)
#   4  파일 복사·삭제·설치 기록 실패
#   5  native host manifest 검증 또는 HKCU 등록 실패
#   6  시작 메뉴 바로가기 생성 실패
#   7  빌드 도구(Rust·C++ 빌드 도구) 없음: 설치하지 않기로 했거나, 비대화형이라 물을 수 없거나, 설치 뒤에도 찾지 못함
#   8  빌드 실패
#   9  예상하지 못한 오류(스크립트 결함; 출력된 줄 번호와 함께 알려 주세요)
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = '',
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
$BuildArgs = @('build', '--release', '--locked', '-p', 'yw-app', '-p', 'yw-host')
# 사용자가 Y라고 답할 때만 실행하는 winget 명령(인자 문자열 그대로 winget에 넘긴다).
$RustupWingetArgs = 'install --id Rustlang.Rustup -e'
$BuildToolsWingetArgs = 'install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
$MsvcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
$RustflagsVariables = @('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')

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

# 네이티브 명령의 stdout 줄을 돌려준다. 명령이 없거나 실패하면 $null.
# -ShowStderr: stderr(예: rustup의 툴체인 내려받기 진행)를 숨기지 않고 화면에 보인다.
function Get-NativeOutput([string]$Exe, [string[]]$ArgList, [switch]$ShowStderr) {
    if ($null -eq (Get-Command $Exe -CommandType Application -ErrorAction SilentlyContinue)) { return $null }
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

# Git으로 받은 저장소면 HEAD 커밋(12자), GitHub "Download ZIP" 등 .git이 없으면 $null.
function Get-SourceCommit([string]$Root) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root '.git'))) { return $null }
    if ($null -eq (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { return $null }
    $lines = Get-NativeOutput 'git' @('-C', $Root, 'rev-parse', '--short=12', 'HEAD')
    if ($null -eq $lines -or $lines.Count -lt 1) { return $null }
    $commit = $lines[0].Trim()
    if ($commit -cnotmatch '^[0-9a-f]{7,40}$') { return $null }
    return $commit
}

function Format-Source([string]$Version, $Commit) {
    if ([string]::IsNullOrEmpty($Commit)) { return "버전 $Version" }
    return "버전 $Version, 커밋 $Commit"
}

# 설치할 확장 런타임 파일: scripts/audit-extension.mjs auditExtensionRoot().packagedFiles와 같은 목록
# (manifest.json, popup/*, src/*.js)과 icons/(있으면). tests/·native-host/·test-dapp/·package.json은 넣지 않는다.
# 두 목록이 같은지는 scripts/install.test.mjs가, 파일 내용은 scripts/check.ps1의 audit-ext 단계가 확인한다.
function Get-ExtensionRuntimeFiles([string]$ExtensionRoot) {
    $reparse = [IO.FileAttributes]::ReparsePoint
    $files = New-Object 'System.Collections.Generic.List[string]'
    $manifest = Get-Item -LiteralPath (Join-Path $ExtensionRoot 'manifest.json') -Force -ErrorAction SilentlyContinue
    if ($null -eq $manifest -or $manifest.PSIsContainer -or ($manifest.Attributes -band $reparse)) { throw 'extension\manifest.json이 없거나 일반 파일이 아닙니다.' }
    $files.Add('manifest.json')
    foreach ($dir in 'popup', 'src') {
        $item = Get-Item -LiteralPath (Join-Path $ExtensionRoot $dir) -Force -ErrorAction SilentlyContinue
        if ($null -eq $item -or -not $item.PSIsContainer -or ($item.Attributes -band $reparse)) { throw "extension\$dir 폴더가 없거나 일반 폴더가 아닙니다." }
        $names = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in @(Get-ChildItem -LiteralPath $item.FullName -Force)) {
            if ($entry.PSIsContainer -or ($entry.Attributes -band $reparse)) { throw "extension\$dir 안에 쓸 수 없는 항목이 있습니다: $($entry.Name)" }
            if ($dir -eq 'src' -and $entry.Name -cnotmatch '^[A-Za-z0-9._-]+\.js$') { throw "extension\src 안에 .js가 아닌 파일이 있습니다: $($entry.Name)" }
            $names.Add("$dir/$($entry.Name)")
        }
        if ($names.Count -eq 0) { throw "extension\$dir 폴더가 비어 있습니다." }
        $sorted = $names.ToArray()
        [Array]::Sort($sorted, [StringComparer]::Ordinal)
        $files.AddRange($sorted)
    }
    $icons = Join-Path $ExtensionRoot 'icons'
    if (Test-Path -LiteralPath $icons -PathType Container) {
        $iconFiles = New-Object 'System.Collections.Generic.List[string]'
        $iconsFull = (Get-Item -LiteralPath $icons -Force).FullName.TrimEnd('\')
        foreach ($file in @(Get-ChildItem -LiteralPath $iconsFull -Recurse -File -Force)) {
            $relative = $file.FullName.Substring($iconsFull.Length + 1).Replace('\', '/')
            if ($relative -match '(^|/)\.') { continue }   # 점 파일 제외
            $iconFiles.Add("icons/$relative")
        }
        $sorted = $iconFiles.ToArray()
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
        return [pscustomobject]@{ Version = $value.version; Commit = $commit; Files = [string[]]$files }
    } catch {
        Stop-Install 1 "설치 기록 파일이 손상되었습니다: $path. 이 폴더에는 설치하지 않습니다. -InstallDir로 다른 빈 폴더를 지정하세요."
    }
}

function Write-InstallMarker([string]$Dir, [string]$Version, $Commit, [string]$State, [string[]]$Files) {
    $sorted = [string[]]@($Files)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $marker = [ordered]@{
        product = 'YourWallet'
        version = $Version
        commit  = $Commit
        state   = $State
        files   = $sorted
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

# rustup 기본 위치(%CARGO_HOME%\bin 또는 %USERPROFILE%\.cargo\bin)를 이 프로세스의 PATH 앞에 더한다.
# rustup을 방금 설치했거나 PATH가 아직 갱신되지 않은 창에서도 찾기 위해서다. 시스템·사용자 PATH는 바꾸지 않는다.
function Add-CargoBinToPath {
    if ($null -ne (Get-Command rustup -CommandType Application -ErrorAction SilentlyContinue)) { return }
    $candidates = @()
    if (-not [string]::IsNullOrEmpty($env:CARGO_HOME)) { $candidates += (Join-Path $env:CARGO_HOME 'bin') }
    if (-not [string]::IsNullOrEmpty($env:USERPROFILE)) { $candidates += (Join-Path $env:USERPROFILE '.cargo\bin') }
    foreach ($bin in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $bin 'rustup.exe') -PathType Leaf) {
            $env:PATH = "$bin;$env:PATH"
            Write-Host "  $bin 을 이 창의 PATH에 더했습니다."
            return
        }
    }
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
    Add-CargoBinToPath
    $rustup = Get-Command rustup -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $cargo = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    return [pscustomobject]@{
        Rustup = $rustup
        Cargo  = $cargo
        Msvc   = Find-MsvcBuildTools
    }
}

function Write-Prerequisites($State) {
    if ($null -ne $State.Rustup -and $null -ne $State.Cargo) {
        Write-Host "  Rust (rustup, cargo)        : 있음 ($($State.Cargo.Source))"
    } else {
        Write-Host '  Rust (rustup, cargo)        : 없음' -ForegroundColor Yellow
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
    if ($null -eq $State.Rustup -or $null -eq $State.Cargo) {
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

# 빌드 도구를 확인하고, 없으면 winget 설치를 제안한다(Y일 때만 실행). 준비되면 반환하고, 아니면 종료 7.
function Confirm-Prerequisites {
    $state = Get-Prerequisites
    Write-Prerequisites $state
    $missing = Get-MissingInstalls $state
    if ($missing.Count -eq 0) {
        if (-not (Test-WindowsSdk)) {
            Write-Warn 'Windows SDK(kernel32.lib)를 찾지 못했습니다. 빌드가 링크 단계에서 실패하면 Visual Studio Installer에서 "수정" -> "Windows 11 SDK"를 추가하세요.'
        }
        return $state
    }
    Write-MissingHelp $missing
    if ($DryRun) {
        Write-Plan '실제 설치 때는 위 명령을 지금 실행할지 묻습니다(Y일 때만 실행). 이번에는 묻지 않습니다.'
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
    return $state
}

# rust-toolchain.toml의 툴체인으로 릴리스 빌드한다. 실패하면 종료 8.
function Invoke-Build([string]$Root, [string]$Channel) {
    foreach ($name in $RustflagsVariables) {
        if ([Environment]::GetEnvironmentVariable($name)) {
            Write-Warn "환경 변수 $name 이 .cargo\config.toml의 빌드 설정을 덮어쓰므로 이 빌드에서는 지웁니다(시스템 설정은 그대로)."
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
    Push-Location -LiteralPath $Root
    try {
        # rustup이 rust-toolchain.toml의 툴체인을 처음 한 번 내려받는다(자동 설치를 끈 rustup이면 직접 설치한다).
        Write-Host "  Rust $Channel 확인(처음이면 rustup이 내려받습니다)"
        $cargoVersion = Get-NativeOutput 'cargo' @('--version') -ShowStderr
        if ($null -eq $cargoVersion -and -not [string]::IsNullOrEmpty($Channel)) {
            Write-Host "  rustup toolchain install $Channel --profile minimal"
            [void](Invoke-NativeCommand 'rustup' @('toolchain', 'install', $Channel, '--profile', 'minimal'))
            $cargoVersion = Get-NativeOutput 'cargo' @('--version') -ShowStderr
        }
        if ($null -eq $cargoVersion -or $cargoVersion.Count -lt 1) { Stop-Install 8 'cargo를 실행할 수 없습니다. 새 창에서 install.cmd를 다시 실행하세요.' }
        Write-Host "  $($cargoVersion[0])"
        if (-not [string]::IsNullOrEmpty($Channel) -and $cargoVersion[0] -notmatch ('^cargo ' + [regex]::Escape($Channel) + ' ')) {
            Write-Warn "rust-toolchain.toml의 Rust $Channel 이 아닌 cargo가 선택되었습니다(RUSTUP_TOOLCHAIN 환경 변수나 rustup override 확인)."
        }
        $rustc = Get-NativeOutput 'rustc' @('-vV')
        if ($null -ne $rustc) {
            $hostLine = @($rustc | Where-Object { $_ -match '^host: ' } | Select-Object -First 1)
            if ($hostLine.Count -eq 1 -and $hostLine[0] -notmatch 'x86_64-pc-windows-msvc') {
                Stop-Install 7 "Rust 기본 대상이 x86_64-pc-windows-msvc가 아닙니다($($hostLine[0])). rustup set default-host x86_64-pc-windows-msvc 실행 후 다시 실행하세요."
            }
        }
        Write-Host "  cargo $($BuildArgs -join ' ')"
        Write-Host '  처음 빌드는 crates.io에서 의존성을 내려받고(Cargo.lock 체크섬으로 고정) 몇 분 걸립니다.'
        $code = Invoke-NativeCommand 'cargo' $BuildArgs
        if ($code -ne 0) {
            Write-Host ''
            Write-Host '  빌드가 실패했습니다. 흔한 원인:' -ForegroundColor Yellow
            Write-Host '  - "link.exe not found", "kernel32.lib" 같은 오류: Visual Studio Build Tools의 "C++를 사용한 데스크톱 개발"과 Windows SDK가 필요합니다.'
            Write-Host '  - 내려받기 오류: 처음 빌드는 인터넷 연결이 필요합니다.'
            Write-Host '  - "Access is denied"(액세스 거부): target\release의 yw-app.exe를 실행 중이면 닫으세요.'
            Stop-Install 8 "cargo build 실패(종료 코드 $code). 위 cargo 출력의 첫 error 줄을 확인하세요."
        }
    } finally {
        Pop-Location
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
    $extensionRoot = Join-Path $root 'extension'
    $version = Get-WorkspaceVersion $root
    $channel = Get-ToolchainChannel $root
    $commit = Get-SourceCommit $root
    $cargoTarget = Join-Path $root 'target'
    if (-not [string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) {
        $cargoTarget = $env:CARGO_TARGET_DIR
        if (-not [IO.Path]::IsPathRooted($cargoTarget)) { $cargoTarget = Join-Path $root $cargoTarget }
    }
    $releaseDir = Join-Path (ConvertTo-FullPath $cargoTarget) 'release'

    $localAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($localAppData) -or -not [IO.Path]::IsPathRooted($localAppData)) {
        Stop-Install 1 'LOCALAPPDATA 환경 변수가 없거나 절대 경로가 아닙니다.'
    }
    $dataDir = ConvertTo-FullPath (Join-Path $localAppData 'YourWallet')
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $script:InstallDir = Join-Path $localAppData 'Programs\YourWallet'
    }
    $target = ConvertTo-FullPath $InstallDir

    # 설치 경로 규칙: cmd.exe 메타문자 금지(Chrome이 cmd.exe로 host를 실행할 수 있다, spec/05 §9.1·§11-5),
    # 드라이브 문자로 시작하는 로컬 경로, 지갑 데이터 폴더·저장소·빌드 폴더와 분리.
    if ($target -match '["%&^|<>!]' -or $target -match '[\x00-\x1f\x7f]') {
        Stop-Install 1 "설치 경로에 쓸 수 없는 문자(`" % & ^ | < > !)가 있습니다: $target. -InstallDir C:\YourWallet 처럼 단순한 경로를 지정하세요."
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

    # 2. 빌드 도구
    Write-Step '2/8 빌드 도구 확인'
    if ($NoBuild) {
        Write-Host '  건너뜀(-NoBuild).'
    } else {
        [void](Confirm-Prerequisites)
        if ($DryRun -and -not [string]::IsNullOrEmpty($channel)) {
            $toolchains = Get-NativeOutput 'rustup' @('toolchain', 'list')
            if ($null -ne $toolchains -and @($toolchains | Where-Object { $_ -match ('^' + [regex]::Escape($channel) + '-') }).Count -eq 0) {
                Write-Plan "rustup이 rust-toolchain.toml의 Rust $channel 을 처음 한 번 내려받습니다."
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
    } elseif ($DryRun) {
        Write-Plan "실행: cargo $($BuildArgs -join ' ')  (저장소 루트, 결과 $releaseDir)"
    } else {
        Invoke-Build $root $channel
        foreach ($exe in $sourceApp, $sourceHost) {
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Stop-Install 8 "빌드가 끝났지만 결과 파일이 없습니다: $exe" }
        }
        Write-Host '  빌드 완료.'
    }

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
        }
    } else {
        Write-Host '  새로 설치합니다.'
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
        if (-not (Test-Path -LiteralPath $target -PathType Container)) { Write-Plan "폴더 만들기: $target" }
        foreach ($item in $toCopy) {
            if ($null -eq $item.Hash) { Write-Plan "복사(빌드 후): $($item.Path)" } else { Write-Plan "복사: $($item.Path)" }
        }
        foreach ($path in $toRemove) { Write-Plan "삭제(이전 설치 파일): $path" }
        Write-Plan "설치 기록 쓰기: $(Join-Path $target $MarkerName)"
    } else {
        try {
            [void][IO.Directory]::CreateDirectory($target)
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
        try { Write-InstallMarker $target $version $commit 'installed' $newFiles } catch {
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
