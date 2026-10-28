# scripts/package.ps1 - 배포 zip을 만든다 (spec.md D1, spec/01 §9.2).
# Windows PowerShell 5.1과 PowerShell 7에서 동작한다. 네트워크를 쓰지 않는다(cargo --offline --locked).
# 사용: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1 [-SkipCheck] [-IncludeTestDapp]
#   -SkipCheck        scripts\check.ps1 -Offline 게이트를 건너뛴다(개발 중 반복용. 배포할 zip은 게이트를 통과해야 한다).
#   -IncludeTestDapp  extension\test-dapp\ 을 zip의 extension\test-dapp\ 에 넣는다(기본: 넣지 않음).
# 결과: dist\YourWallet-<버전>\ (스테이징), dist\YourWallet-<버전>-win-x64.zip, dist\YourWallet-<버전>-win-x64.zip.sha256
# 버전은 루트 Cargo.toml [workspace.package] version. 종료 코드: 0 성공, 1 실패(첫 오류에서 멈춘다, "package: FAIL ...").
[CmdletBinding()]
param(
    [switch]$SkipCheck,
    [switch]$IncludeTestDapp
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path.TrimEnd('\')
$Dist = Join-Path $Root 'dist'
$ExtensionRoot = Join-Path $Root 'extension'
$ReadmeName = 'README-설치.txt'

function Fail([string]$Message) {
    [Console]::Error.WriteLine("package: FAIL $Message")
    exit 1
}
trap {
    [Console]::Error.WriteLine("package: FAIL $($_.Exception.Message)")
    exit 1
}

# 네이티브 명령: stderr 진행 출력이 PowerShell 오류로 바뀌지 않게 Continue로 실행하고 종료 코드를 돌려준다.
function Invoke-Native([string]$Exe, [string[]]$ArgList) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @ArgList | Out-Host
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}

# 네이티브 명령의 stdout 줄을 돌려준다. 실패하면 중단.
function Get-NativeOutput([string]$What, [string]$Exe, [string[]]$ArgList) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& $Exe @ArgList)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { Fail "$What (exit $code)" }
    return , [string[]]$lines
}

function Get-Sha256Hex([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try { $bytes = $sha.ComputeHash($stream) } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Copy-ToStage([string]$Source, [string]$Rel) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { Fail "missing source file: $Source" }
    $destination = Join-Path $script:Stage ($Rel.Replace('/', '\'))
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
    [IO.File]::Copy($Source, $destination, $false)
}

function Copy-TreeToStage([string]$SourceDir, [string]$RelDir) {
    foreach ($file in @(Get-ChildItem -LiteralPath $SourceDir -Recurse -File)) {
        $relative = $file.FullName.Substring($SourceDir.TrimEnd('\').Length + 1).Replace('\', '/')
        if ($relative -match '(^|/)\.') { continue }   # 점 파일 제외
        Copy-ToStage $file.FullName "$RelDir/$relative"
    }
}

function Sort-Ordinal([string[]]$Items) {
    $sorted = [string[]]@($Items)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    return , $sorted
}

# ---------------------------------------------------------------- 1. 버전·도구

$cargoToml = [IO.File]::ReadAllText((Join-Path $Root 'Cargo.toml'))
$section = [regex]::Match($cargoToml, '(?ms)^\[workspace\.package\][ \t]*\r?$(.*?)(?=^\[|\z)')
if (-not $section.Success) { Fail 'Cargo.toml has no [workspace.package] section' }
$versionMatch = [regex]::Match($section.Groups[1].Value, '(?m)^[ \t]*version[ \t]*=[ \t]*"([^"]+)"')
if (-not $versionMatch.Success) { Fail 'Cargo.toml [workspace.package] has no version' }
$Version = $versionMatch.Groups[1].Value
if ($Version -cnotmatch '^\d+\.\d+\.\d+$') { Fail "unsupported workspace version: $Version" }
$PackageName = "YourWallet-$Version"
$ZipName = "$PackageName-win-x64.zip"
Write-Host "package: version $Version"

$cargoVersion = Get-NativeOutput 'cargo --version' 'cargo' @('--version')
if ("$cargoVersion" -notmatch '^cargo 1\.95\.0 ') { Fail "cargo 1.95.0 required (rust-toolchain.toml), got: $cargoVersion" }
$nodeVersion = Get-NativeOutput 'node --version' 'node' @('--version')
if ("$nodeVersion" -notmatch '^v(\d+)\.' -or [int]$Matches[1] -lt 22) { Fail 'Node.js 22+ required' }
foreach ($name in 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS') {
    if ([Environment]::GetEnvironmentVariable($name)) { Fail "$name must be unset (same rule as check.ps1)" }
}
$commit = (Get-NativeOutput 'git rev-parse HEAD' 'git' @('-C', $Root, 'rev-parse', 'HEAD'))[0].Trim()
$dirtyLines = Get-NativeOutput 'git status' 'git' @('-C', $Root, 'status', '--porcelain')
$dirty = $dirtyLines.Count -gt 0
if ($dirty) { Write-Warning "working tree has uncommitted changes; the package is not exactly commit $commit" }
if ($env:SOURCE_DATE_EPOCH) {
    $epoch = [long]$env:SOURCE_DATE_EPOCH
} else {
    $epoch = [long]((Get-NativeOutput 'git log' 'git' @('-C', $Root, 'log', '-1', '--format=%ct', 'HEAD'))[0].Trim())
}
$entryTime = [DateTimeOffset]::FromUnixTimeSeconds($epoch)

# ---------------------------------------------------------------- 2. 게이트

if ($SkipCheck) {
    Write-Warning 'package: -SkipCheck: scripts\check.ps1 was not run. Do not publish this zip.'
} else {
    Write-Host 'package: scripts\check.ps1 -Offline'
    $psExe = (Get-Process -Id $PID).Path
    $code = Invoke-Native $psExe @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root 'scripts\check.ps1'), '-Offline')
    if ($code -ne 0) { Fail "scripts\check.ps1 -Offline failed (exit $code)" }
}

# ---------------------------------------------------------------- 3. 확장 ID와 런타임 파일 목록

$code = Invoke-Native 'node' @((Join-Path $Root 'scripts\extension-key.mjs'), 'check')
if ($code -ne 0) { Fail 'node scripts/extension-key.mjs check failed' }
$extensionId = ([IO.File]::ReadAllText((Join-Path $ExtensionRoot 'extension-id.txt'))).Trim()
if ($extensionId -cnotmatch '^[a-p]{32}$') { Fail 'extension/extension-id.txt is not a 32-character a-p ID' }
$installSource = Join-Path $Root 'packaging\install.ps1'
$uninstallSource = Join-Path $Root 'packaging\uninstall.ps1'
$installText = [IO.File]::ReadAllText($installSource)
if (-not $installText.Contains("`$ExtensionId = '$extensionId'")) { Fail "packaging/install.ps1 `$ExtensionId does not match extension/extension-id.txt ($extensionId)" }
if (([regex]::Matches($installText, [regex]::Escape("'@YW_VERSION@'"))).Count -ne 1) { Fail "packaging/install.ps1 must contain exactly one '@YW_VERSION@'" }
foreach ($scriptPath in $installSource, $uninstallSource) {
    $head = [IO.File]::ReadAllBytes($scriptPath)
    if ($head.Length -lt 3 -or $head[0] -ne 0xEF -or $head[1] -ne 0xBB -or $head[2] -ne 0xBF) { Fail "$scriptPath must be UTF-8 with BOM (Windows PowerShell 5.1 reads Korean text correctly only with a BOM)" }
}

# audit-extension.mjs의 auditExtensionRoot().packagedFiles가 확장 런타임 파일의 정본이다(manifest.json, popup/*, src/*.js).
$listScript = @'
import { pathToFileURL } from 'node:url';
// argv[1] must not be the audit script itself, or its CLI guard would run on import.
const [extensionRoot, auditScript] = process.argv.slice(1);
const { auditExtensionRoot } = await import(pathToFileURL(auditScript).href);
const { packagedFiles, extensionId } = await auditExtensionRoot(extensionRoot);
process.stdout.write(['id ' + extensionId, ...packagedFiles.map((file) => 'file ' + file)].join('\n') + '\n');
'@
$listing = Get-NativeOutput 'extension audit (packaged file list)' 'node' @('--input-type=module', '-e', $listScript, $ExtensionRoot, (Join-Path $Root 'scripts\audit-extension.mjs'))
$extensionFiles = @()
foreach ($line in $listing) {
    if ($line -cmatch '^id ([a-p]{32})$') {
        if ($Matches[1] -cne $extensionId) { Fail "manifest key ID $($Matches[1]) != extension-id.txt $extensionId" }
    } elseif ($line -cmatch '^file ([A-Za-z0-9._/-]+)$') {
        $extensionFiles += $Matches[1]
    } elseif ($line.Trim().Length -gt 0) {
        Fail "unexpected audit output: $line"
    }
}
if ($extensionFiles -notcontains 'manifest.json') { Fail 'packaged extension file list has no manifest.json' }
Write-Host "package: extension $extensionId, $($extensionFiles.Count) runtime files"

# ---------------------------------------------------------------- 4. 릴리스 빌드

Write-Host 'package: cargo build --release --locked --offline -p yw-app -p yw-host'
$code = Invoke-Native 'cargo' @('build', '--release', '--locked', '--offline', '-p', 'yw-app', '-p', 'yw-host')
if ($code -ne 0) { Fail "cargo build failed (exit $code)" }
$releaseDir = Join-Path $Root 'target\release'

# ---------------------------------------------------------------- 5. 스테이징

$script:Stage = Join-Path $Dist $PackageName
$zipPath = Join-Path $Dist $ZipName
$shaPath = "$zipPath.sha256"
if (-not $script:Stage.StartsWith($Dist + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "stage path outside dist: $($script:Stage)" }
[void][IO.Directory]::CreateDirectory($Dist)
if (Test-Path -LiteralPath $script:Stage) { Remove-Item -LiteralPath $script:Stage -Recurse -Force }
foreach ($old in $zipPath, $shaPath) { if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force } }
[void][IO.Directory]::CreateDirectory($script:Stage)

Copy-ToStage (Join-Path $releaseDir 'yw-app.exe') 'yw-app.exe'
Copy-ToStage (Join-Path $releaseDir 'yw-host.exe') 'yw-host.exe'
foreach ($rel in $extensionFiles) { Copy-ToStage (Join-Path $ExtensionRoot ($rel.Replace('/', '\'))) "extension/$rel" }
$icons = Join-Path $ExtensionRoot 'icons'
if (Test-Path -LiteralPath $icons -PathType Container) { Copy-TreeToStage $icons 'extension/icons' }
if ($IncludeTestDapp) { Copy-TreeToStage (Join-Path $ExtensionRoot 'test-dapp') 'extension/test-dapp' }

# install.ps1: 버전 자리표시자만 바꾼다(BOM·줄바꿈 유지).
$stagedInstall = $installText.Replace("'@YW_VERSION@'", "'$Version'")
[IO.File]::WriteAllText((Join-Path $script:Stage 'install.ps1'), $stagedInstall, (New-Object Text.UTF8Encoding($true)))
Copy-ToStage $uninstallSource 'uninstall.ps1'
foreach ($license in 'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING') {
    $licensePath = Join-Path $Root $license
    if (Test-Path -LiteralPath $licensePath -PathType Leaf) { Copy-ToStage $licensePath $license }
}

$sourceLabel = $commit
if ($dirty) { $sourceLabel = "$commit (+ 커밋되지 않은 변경)" }
$readme = @'
Your Wallet @VERSION@ (Windows 11 x64)

관리자 권한 없이 현재 사용자에게만 설치합니다. 지갑 데이터(%LOCALAPPDATA%\YourWallet)는
설치·업그레이드·제거 때 건드리지 않습니다. 복구 단어 24개가 유일한 백업입니다.

1. 확인(권장): 배포자가 따로 알려준 zip SHA-256과 비교합니다.
     Get-FileHash .\YourWallet-@VERSION@-win-x64.zip
   install.ps1은 설치 전에 SHA256SUMS로 압축을 푼 모든 파일을 확인합니다.

2. 설치: 이 폴더에서 PowerShell을 열고 실행합니다.
     powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
   먼저 할 일만 보려면 끝에 -DryRun 을 붙입니다.
   설치 위치: %LOCALAPPDATA%\Programs\YourWallet

3. Chrome 확장: chrome://extensions -> 개발자 모드 켜기 -> "압축해제된 확장 프로그램을 로드합니다"
   -> %LOCALAPPDATA%\Programs\YourWallet\extension 선택
   -> ID가 @EXTENSION_ID@ 인지 확인합니다.

4. 실행: 시작 메뉴 -> Your Wallet. "Windows의 PC 보호" 창이 뜨면 "추가 정보" -> "실행".
   (코드 서명을 하지 않은 프로그램입니다.)

5. 제거(지갑 데이터는 남김):
     powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\YourWallet\uninstall.ps1"

자세한 안내: 소스 저장소의 docs/install.ko.md
소스 커밋: @COMMIT@
'@
$readme = $readme.Replace('@VERSION@', $Version).Replace('@EXTENSION_ID@', $extensionId).Replace('@COMMIT@', $sourceLabel)
$readme = ($readme -replace "`r?`n", "`r`n")
[IO.File]::WriteAllText((Join-Path $script:Stage $ReadmeName), $readme, (New-Object Text.UTF8Encoding($true)))

# 스테이징한 확장 폴더를 다시 감사한다(런타임 파일만으로 완결되는지).
$auditArgs = @((Join-Path $Root 'scripts\audit-extension.mjs'), 'check', '--extension-root', (Join-Path $script:Stage 'extension'))
$code = Invoke-Native 'node' $auditArgs
if ($code -ne 0) { Fail 'staged extension failed the static audit' }

# ---------------------------------------------------------------- 6. SHA256SUMS

$files = @()
foreach ($file in @(Get-ChildItem -LiteralPath $script:Stage -Recurse -File -Force)) {
    $files += $file.FullName.Substring($script:Stage.Length + 1).Replace('\', '/')
}
$files = Sort-Ordinal $files
$sumsBuilder = New-Object Text.StringBuilder
foreach ($rel in $files) {
    [void]$sumsBuilder.Append((Get-Sha256Hex (Join-Path $script:Stage ($rel.Replace('/', '\'))))).Append('  ').Append($rel).Append("`n")
}
[IO.File]::WriteAllText((Join-Path $script:Stage 'SHA256SUMS'), $sumsBuilder.ToString(), (New-Object Text.UTF8Encoding($false)))
$zipFiles = Sort-Ordinal (@($files) + @('SHA256SUMS'))

# ---------------------------------------------------------------- 7. zip (서수 정렬, 고정 시각, UTF-8 이름, 최상위 폴더 하나)

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipStream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
try {
    # Encoding.UTF8 자체를 넘겨야 .NET Framework가 UTF-8 이름 플래그(bit 11)를 켠다(README-설치.txt).
    $archive = New-Object IO.Compression.ZipArchive($zipStream, [IO.Compression.ZipArchiveMode]::Create, $true, [Text.Encoding]::UTF8)
    try {
        foreach ($rel in $zipFiles) {
            $entry = $archive.CreateEntry("$PackageName/$rel", [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $entryTime
            $entryStream = $entry.Open()
            try {
                $source = [IO.File]::OpenRead((Join-Path $script:Stage ($rel.Replace('/', '\'))))
                try { $source.CopyTo($entryStream) } finally { $source.Dispose() }
            } finally { $entryStream.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $zipStream.Dispose() }

# ---------------------------------------------------------------- 8. zip 다시 읽어 확인

$expectedHashes = @{}
foreach ($line in ([IO.File]::ReadAllText((Join-Path $script:Stage 'SHA256SUMS')) -split "`n")) {
    if ($line.Length -gt 0) { $expectedHashes[$line.Substring(66)] = $line.Substring(0, 64) }
}
$reader = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $names = @($reader.Entries | ForEach-Object { $_.FullName })
    $expectedNames = @($zipFiles | ForEach-Object { "$PackageName/$_" })
    if (($names -join "`n") -cne ($expectedNames -join "`n")) { Fail 'zip entry list differs from the staged files' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($entry in $reader.Entries) {
            $rel = $entry.FullName.Substring($PackageName.Length + 1)
            if ($rel -ceq 'SHA256SUMS') { continue }
            $stream = $entry.Open()
            try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant() } finally { $stream.Dispose() }
            if ($hash -cne $expectedHashes[$rel]) { Fail "zip entry hash mismatch: $rel" }
        }
    } finally { $sha.Dispose() }
} finally { $reader.Dispose() }

$zipHash = Get-Sha256Hex $zipPath
[IO.File]::WriteAllText($shaPath, "$zipHash  $ZipName`n", (New-Object Text.UTF8Encoding($false)))
$zipSize = (Get-Item -LiteralPath $zipPath).Length

Write-Host ''
Write-Host "package: OK $zipPath"
Write-Host "package: files  $($zipFiles.Count) (SHA256SUMS included)"
Write-Host "package: size   $zipSize bytes"
Write-Host "package: sha256 $zipHash"
if ($SkipCheck) { Write-Warning 'package: built with -SkipCheck' }
exit 0
