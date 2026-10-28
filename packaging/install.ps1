# packaging/install.ps1 - Your Wallet 설치 (spec.md D1, spec/01 §9.3). 배포 zip에 들어가는 스크립트다.
# Windows PowerShell 5.1과 PowerShell 7에서 동작한다. 관리자 권한이 필요 없다(현재 사용자 범위만 바꾼다).
#
# 사용 (zip을 푼 폴더에서):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 [-InstallDir <폴더>] [-NoShortcut] [-NoNativeHost] [-DryRun]
#
#   -InstallDir    설치 폴더. 기본 %LOCALAPPDATA%\Programs\YourWallet
#   -NoShortcut    시작 메뉴 바로가기를 만들지 않는다.
#   -NoNativeHost  HKCU에 Chrome native messaging host를 등록하지 않는다(manifest 파일은 설치 폴더에 쓴다).
#   -DryRun        파일 확인과 할 일 출력만 하고 아무것도 바꾸지 않는다.
#
# 순서: (1) SHA256SUMS로 압축을 푼 파일을 모두 확인 -> (2) 바꿀 파일을 실행 중인 yw-app·yw-host가 쓰고 있으면
# 닫아 달라고 묻는다(강제 종료하지 않는다) -> (3) 설치 폴더에 복사(내용이 같은 파일은 건너뛰고, 이전 버전에만 있던
# 파일은 지운다) -> (4) yw-host.exe 옆에 native host manifest를 쓰고 검증 -> (5) HKCU 등록 -> (6) 시작 메뉴 바로가기
# -> (7) 확장 로드 안내. 지갑 데이터 %LOCALAPPDATA%\YourWallet\ 은 읽지도 바꾸지도 않는다.
# 같은 패키지로 다시 실행해도 결과가 같다(멱등).
#
# 종료 코드:
#   0  성공(-DryRun 포함)
#   1  환경·인자 오류(LOCALAPPDATA 없음, 64비트 Windows 아님, 쓸 수 없는 설치 경로, 다른 파일이 있는 폴더 등)
#   2  패키지 무결성 오류(SHA256SUMS 없음·형식 오류, 파일 누락·해시 불일치, 확장 ID 불일치, 버전 정보 없음)
#   3  취소(사용자가 취소함, 또는 실행 중인 yw-app·yw-host를 닫아 달라고 물을 수 없는 비대화형 실행)
#   4  파일 복사·삭제 실패
#   5  native host manifest 검증 또는 HKCU 등록 실패
#   6  시작 메뉴 바로가기 생성 실패
#   9  예상하지 못한 오류(스크립트 결함; 출력된 줄 번호와 함께 알려 주세요)
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = '',
    [switch]$NoShortcut,
    [switch]$NoNativeHost,
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PackageVersion = '@YW_VERSION@'                    # scripts/package.ps1이 패키지 버전으로 바꾼다.
$ExtensionId = 'nnpjlobjgbanccjddghlpaafpohfkeph'   # extension/extension-id.txt (spec.md D22, spec/05 §2.3)
$HostName = 'com.your_wallet.native'
$HostDescription = 'Your Wallet native messaging host'
$RegistryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$MarkerName = 'yw-install.json'
$ShortcutName = 'Your Wallet.lnk'
$RequiredFiles = @('yw-app.exe', 'yw-host.exe', 'extension/manifest.json', 'install.ps1', 'uninstall.ps1')

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

# 패키지 안 상대 경로('/' 구분)가 안전한지: 절대 경로·'..'·드라이브·예약 문자 금지.
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

# ---------------------------------------------------------------- 검증 (scripts/register-native-host.ps1, validate-manifest.mjs와 같은 규칙)

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

# ---------------------------------------------------------------- 패키지

function Read-Sha256Sums([string]$PackageDir) {
    $sumsPath = Join-Path $PackageDir 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
        Stop-Install 2 "SHA256SUMS 파일이 없습니다: $sumsPath. zip 전체를 다시 풀어 주세요."
    }
    $bytes = [IO.File]::ReadAllBytes($sumsPath)
    $start = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    try {
        $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes, $start, $bytes.Length - $start)
    } catch {
        Stop-Install 2 'SHA256SUMS가 UTF-8 텍스트가 아닙니다.'
    }
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    $lineNumber = 0
    foreach ($rawLine in ($text -split "`n")) {
        $lineNumber++
        $line = $rawLine.TrimEnd("`r")
        if ($line.Length -eq 0) { continue }
        $match = [regex]::Match($line, '^([0-9A-Fa-f]{64}) [ *](.+)\z')
        if (-not $match.Success) { Stop-Install 2 "SHA256SUMS $lineNumber 번째 줄의 형식이 올바르지 않습니다." }
        $rel = $match.Groups[2].Value
        $reserved = @('SHA256SUMS', $MarkerName, "$HostName.json")
        if (-not (Test-RelativePackagePath $rel) -or ($reserved -contains $rel)) {
            Stop-Install 2 "SHA256SUMS $lineNumber 번째 줄의 경로를 쓸 수 없습니다: $rel"
        }
        $key = $rel.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { Stop-Install 2 "SHA256SUMS에 같은 파일이 두 번 있습니다: $rel" }
        $seen[$key] = $true
        $entries.Add([pscustomobject]@{ Path = $rel; Hash = $match.Groups[1].Value.ToLowerInvariant() })
    }
    foreach ($required in $RequiredFiles) {
        if (-not $seen.ContainsKey($required.ToLowerInvariant())) { Stop-Install 2 "SHA256SUMS에 필수 파일이 없습니다: $required" }
    }
    return , $entries.ToArray()
}

function Test-PackageFiles([string]$PackageDir, $Entries) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $Entries) {
        $full = Join-RelativePath $PackageDir $entry.Path
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            $problems.Add("없음: $($entry.Path)")
            continue
        }
        if ((Get-Sha256Hex $full) -ne $entry.Hash) { $problems.Add("해시 불일치: $($entry.Path)") }
    }
    if ($problems.Count -gt 0) {
        foreach ($problem in $problems) { Write-Host "  $problem" -ForegroundColor Red }
        Stop-Install 2 "압축을 푼 파일 $($problems.Count)개가 SHA256SUMS와 다릅니다. 아무것도 바꾸지 않았습니다. zip을 다시 내려받아 SHA-256을 확인하고 새 폴더에 풀어 주세요."
    }
    # 목록에 없는 파일은 설치하지 않는다(경고만).
    $listed = @{}
    foreach ($entry in $Entries) { $listed[$entry.Path.ToLowerInvariant()] = $true }
    $extra = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in @(Get-ChildItem -LiteralPath $PackageDir -Recurse -File -Force)) {
        $rel = $file.FullName.Substring($PackageDir.TrimEnd('\').Length + 1).Replace('\', '/')
        if ($rel -ne 'SHA256SUMS' -and -not $listed.ContainsKey($rel.ToLowerInvariant())) { $extra.Add($rel) }
    }
    if ($extra.Count -gt 0) {
        Write-Warn "SHA256SUMS에 없는 파일 $($extra.Count)개는 설치하지 않습니다: $((@($extra) | Select-Object -First 5) -join ', ')"
    }
}

# ---------------------------------------------------------------- 설치 기록 (yw-install.json)

function Read-InstallMarker([string]$Dir) {
    $path = Join-Path $Dir $MarkerName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $value = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path, (New-Object Text.UTF8Encoding($false, $true))))
        if ($value.product -cne 'YourWallet' -or -not ($value.version -is [string])) { throw 'product' }
        $files = @($value.files)
        foreach ($file in $files) {
            if (-not ($file -is [string]) -or -not (Test-RelativePackagePath $file)) { throw 'files' }
        }
        return [pscustomobject]@{ Version = $value.version; Files = [string[]]$files }
    } catch {
        Stop-Install 1 "설치 기록 파일이 손상되었습니다: $path. 이 폴더에는 설치하지 않습니다. -InstallDir로 다른 빈 폴더를 지정하세요."
    }
}

function Write-InstallMarker([string]$Dir, [string]$Version, [string]$State, [string[]]$Files) {
    $sorted = [string[]]@($Files)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $marker = [ordered]@{
        product = 'YourWallet'
        version = $Version
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

# ---------------------------------------------------------------- 설치

function Invoke-Install {
    trap {
        Write-Host ''
        Write-Host "설치 실패(종료 코드 9): 예상하지 못한 오류: $((Get-InnerException $_).Message)" -ForegroundColor Red
        Write-Host "  위치: 줄 $($_.InvocationInfo.ScriptLineNumber)"
        exit 9
    }
    if ($env:OS -ne 'Windows_NT') { Stop-Install 1 'Windows에서만 설치할 수 있습니다.' }
    if (-not [Environment]::Is64BitOperatingSystem) { Stop-Install 1 '64비트 Windows가 필요합니다(win-x64 빌드).' }
    $build = [Environment]::OSVersion.Version.Build
    if ($build -lt 22621) { Write-Warn "Windows 빌드 $build. 이 지갑은 Windows 11 22H2(22621) 이상을 대상으로 시험했습니다." }
    if ($PackageVersion -cnotmatch '^\d+\.\d+\.\d+$') {
        Stop-Install 2 '패키지 버전 정보가 없습니다. scripts\package.ps1로 만든 zip 안의 install.ps1을 실행하세요.'
    }
    if ([string]::IsNullOrEmpty($PSScriptRoot)) { Stop-Install 1 '스크립트 파일로 실행하세요: powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1' }
    $packageDir = ConvertTo-FullPath $PSScriptRoot

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
    # 드라이브 문자로 시작하는 로컬 경로, 지갑 데이터 폴더·압축을 푼 폴더와 분리.
    if ($target -match '["%&^|<>!]' -or $target -match '[\x00-\x1f\x7f]') {
        Stop-Install 1 "설치 경로에 쓸 수 없는 문자(`" % & ^ | < > !)가 있습니다: $target. -InstallDir C:\YourWallet 처럼 단순한 경로를 지정하세요."
    }
    if ($target -cnotmatch '^[A-Za-z]:\\.+') { Stop-Install 1 "설치 경로는 드라이브 문자로 시작하는 폴더여야 합니다(드라이브 루트·네트워크 경로 불가): $target" }
    if ((Test-PathInside $target $dataDir) -or (Test-PathInside $dataDir $target)) {
        Stop-Install 1 "설치 폴더는 지갑 데이터 폴더($dataDir)와 겹칠 수 없습니다: $target"
    }
    if ((Test-PathInside $target $packageDir) -or (Test-PathInside $packageDir $target)) {
        Stop-Install 1 "설치 폴더는 zip을 푼 폴더($packageDir)와 겹칠 수 없습니다: $target"
    }
    $appExe = Join-Path $target 'yw-app.exe'
    $hostExe = Join-Path $target 'yw-host.exe'
    $manifestPath = Join-Path $target "$HostName.json"
    $manifestJson = New-NativeManifestJson $hostExe
    if (-not (Test-NativeManifestValue (ConvertFrom-Json -InputObject $manifestJson) $ExtensionId)) {
        Stop-Install 1 "이 설치 경로로는 Chrome native host manifest를 만들 수 없습니다(경로 규칙 위반): $target"
    }

    Write-Host "Your Wallet $PackageVersion 설치" -ForegroundColor Green
    Write-Host "  패키지 폴더 : $packageDir"
    Write-Host "  설치 폴더   : $target"
    Write-Host "  지갑 데이터 : $dataDir (설치·업그레이드는 이 폴더를 건드리지 않습니다)"
    if ($DryRun) { Write-Host '  -DryRun: 확인과 할 일 출력만 하고 아무것도 바꾸지 않습니다.' -ForegroundColor DarkYellow }

    # 1. 무결성
    Write-Step '1/6 패키지 파일 확인 (SHA256SUMS)'
    $entries = Read-Sha256Sums $packageDir
    Test-PackageFiles $packageDir $entries
    try {
        $extManifest = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $packageDir 'extension\manifest.json'), (New-Object Text.UTF8Encoding($false, $true))))
        $packageExtensionId = Get-ExtensionIdFromKey ([string]$extManifest.key)
    } catch {
        Stop-Install 2 'extension\manifest.json에서 확장 ID를 계산할 수 없습니다.'
    }
    if ($packageExtensionId -cne $ExtensionId) {
        Stop-Install 2 "확장 ID가 다릅니다(패키지 $packageExtensionId, 기대 $ExtensionId). 이 패키지를 쓰지 마세요."
    }
    Write-Host "  파일 $($entries.Count)개 모두 일치. 확장 ID $ExtensionId 확인."

    # 2. 설치 폴더 상태
    Write-Step '2/6 설치 폴더 확인'
    $installEntries = @($entries | Where-Object { $_.Path -ne 'install.ps1' })
    $newFiles = [string[]]@($installEntries | ForEach-Object { $_.Path })
    $oldFiles = @()
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
            $cmp = 0
            try { $cmp = ([version]$PackageVersion).CompareTo([version]$marker.Version) } catch { $cmp = 1 }
            if ($cmp -gt 0) { Write-Host "  업그레이드: $($marker.Version) -> $PackageVersion" }
            elseif ($cmp -eq 0) { Write-Host "  같은 버전 다시 설치: $PackageVersion (바뀐 파일만 고칩니다)" }
            else { Write-Warn "설치된 버전($($marker.Version))보다 낮은 버전($PackageVersion)으로 바꿉니다." }
        }
    } else {
        Write-Host '  새로 설치합니다.'
    }

    $toCopy = New-Object 'System.Collections.Generic.List[object]'
    $unchanged = 0
    foreach ($entry in $installEntries) {
        $source = Join-RelativePath $packageDir $entry.Path
        $destination = Join-RelativePath $target $entry.Path
        if ((Test-Path -LiteralPath $destination -PathType Leaf) -and ((Get-Sha256Hex $destination) -eq $entry.Hash)) {
            $unchanged++
            continue
        }
        $toCopy.Add([pscustomobject]@{ Path = $entry.Path; Source = $source; Destination = $destination; Hash = $entry.Hash })
    }
    $newSet = @{}
    foreach ($file in $newFiles) { $newSet[$file.ToLowerInvariant()] = $true }
    $toRemove = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $oldFiles) {
        if ($newSet.ContainsKey($file.ToLowerInvariant())) { continue }
        $path = Join-RelativePath $target $file
        if (Test-Path -LiteralPath $path -PathType Leaf) { $toRemove.Add($path) }
    }
    Write-Host "  복사할 파일 $($toCopy.Count)개, 그대로인 파일 $($unchanged)개, 지울 이전 버전 파일 $($toRemove.Count)개"

    $touched = [string[]](@($toCopy | ForEach-Object { $_.Destination }) + @($toRemove))
    if (-not (Wait-FilesReleased $touched)) {
        Stop-Install 3 '설치를 취소했습니다. 바뀐 것은 없습니다. yw-app과 Chrome을 닫은 뒤 다시 실행하세요.'
    }
    foreach ($process in @(Get-WalletProcesses | Where-Object { $_.Name -eq 'yw-app' })) {
        if ($null -eq $process.Path -or -not $process.Path.Equals($appExe, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warn "다른 위치의 yw-app이 실행 중입니다(PID $($process.Id), $($process.Path)). 한 번에 하나만 실행되므로, 설치한 앱을 쓰려면 그 앱을 먼저 닫으세요."
        }
    }

    # 3. 파일 복사
    Write-Step '3/6 파일 복사'
    if ($DryRun) {
        if (-not (Test-Path -LiteralPath $target -PathType Container)) { Write-Plan "폴더 만들기: $target" }
        foreach ($item in $toCopy) { Write-Plan "복사: $($item.Path)" }
        foreach ($path in $toRemove) { Write-Plan "삭제(이전 버전 파일): $path" }
        Write-Plan "설치 기록 쓰기: $(Join-Path $target $MarkerName)"
    } else {
        try {
            [void][IO.Directory]::CreateDirectory($target)
            # 중간에 실패해도 다음 실행과 uninstall.ps1이 남은 파일을 알 수 있게 이전·새 목록을 합쳐 먼저 기록한다.
            if ($toCopy.Count -gt 0 -or $toRemove.Count -gt 0) {
                Write-InstallMarker $target $PackageVersion 'installing' ([string[]](@($oldFiles) + @($newFiles) | Sort-Object -Unique))
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

    # 4. native host manifest
    Write-Step '4/6 Chrome native host manifest'
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

    # 5. HKCU 등록
    Write-Step '5/6 Chrome native host 등록 (HKCU)'
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

    # 6. 시작 메뉴 바로가기
    Write-Step '6/6 시작 메뉴 바로가기'
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
        try { Write-InstallMarker $target $PackageVersion 'installed' $newFiles } catch {
            Stop-Install 4 "설치 기록을 쓸 수 없습니다: $((Get-InnerException $_).Message)"
        }
    }

    # 7. 안내
    $extensionDir = Join-Path $target 'extension'
    Write-Host ''
    if ($DryRun) {
        Write-Host "DryRun 완료: 바뀐 것은 없습니다. 실제로 설치하려면 -DryRun 없이 다시 실행하세요." -ForegroundColor Green
    } else {
        Write-Host "설치 완료: Your Wallet $PackageVersion" -ForegroundColor Green
    }
    Write-Host ''
    Write-Host '[Chrome 확장 로드 - 처음 한 번]'
    Write-Host '  1. Chrome 주소창에 chrome://extensions 를 입력합니다.'
    Write-Host '  2. 오른쪽 위 "개발자 모드"를 켭니다.'
    Write-Host '  3. "압축해제된 확장 프로그램을 로드합니다"를 누르고 다음 폴더를 선택합니다:'
    Write-Host "       $extensionDir"
    Write-Host "  4. 카드에 표시된 ID가 $ExtensionId 인지 확인합니다. 다르면 쓰지 말고 그 확장을 삭제하세요."
    Write-Host '  업그레이드했다면: Your Wallet 카드의 새로고침 버튼을 누르고, 열려 있던 dApp 탭도 새로고침합니다.'
    Write-Host '  Chrome을 켤 때 "개발자 모드 확장 프로그램" 경고가 뜰 수 있습니다(정상).'
    Write-Host ''
    Write-Host '[실행]'
    Write-Host '  시작 메뉴 -> Your Wallet. 서명하지 않은 프로그램이라 "Windows의 PC 보호" 창이 뜨면 "추가 정보" -> "실행".'
    Write-Host '  처음 실행하면: 지갑 만들기(24단어 종이 백업) -> 설정 -> 네트워크(RPC)에서 "QuickNode 멀티체인" 엔드포인트 이름·토큰 저장 -> "네트워크 URL 생성".'
    Write-Host "  지갑 데이터와 로그: $dataDir\v3 (제거 스크립트도 기본으로는 지우지 않습니다)"
    Write-Host "  제거: powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $target 'uninstall.ps1')`""
    exit 0
}

# 점 소싱(. .\install.ps1)하면 함수만 정의한다(검증 함수 시험용).
if ($MyInvocation.InvocationName -ne '.') { Invoke-Install }
