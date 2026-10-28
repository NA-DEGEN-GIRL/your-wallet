# scripts/uninstall.ps1 - Your Wallet 제거 (spec.md D1, spec/01 §9.3). 저장소 루트의 uninstall.cmd가 이 스크립트를
# 실행한다. scripts/install.ps1이 설치 폴더에도 사본을 둔다(저장소를 지운 뒤에도 제거할 수 있게).
# Windows PowerShell 5.1과 PowerShell 7에서 동작한다. 관리자 권한이 필요 없다.
#
# 사용:
#   uninstall.cmd [-InstallDir <폴더>] [-NoShortcut] [-NoNativeHost] [-RemoveWalletData] [-DryRun]
#   powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\YourWallet\uninstall.ps1" [같은 옵션]
#
#   -InstallDir        설치 폴더. 기본: 이 스크립트가 설치 폴더 안의 사본이면(옆에 yw-install.json) 그 폴더,
#                      아니면 %LOCALAPPDATA%\Programs\YourWallet
#   -NoShortcut        시작 메뉴 바로가기를 건드리지 않는다.
#   -NoNativeHost      HKCU native host 등록을 건드리지 않는다.
#   -RemoveWalletData  지갑 데이터 %LOCALAPPDATA%\YourWallet\ 도 지운다. 확인 문구를 정확히 입력해야 하며
#                      비대화형 실행에서는 거부한다.
#   -DryRun            지울 것만 출력하고 아무것도 바꾸지 않는다.
#
# 지우는 것: 시작 메뉴 'Your Wallet' 바로가기(이 설치의 yw-app.exe를 가리킬 때만), HKCU
#   Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native(이 설치의 manifest를 가리킬 때만), 설치 폴더에서
#   install.ps1이 설치 기록(yw-install.json)에 적은 파일과 manifest. 목록에 없는 파일은 남긴다.
# 지우지 않는 것: 지갑 데이터 %LOCALAPPDATA%\YourWallet\ (vault·설정·RPC 주소·로그) - -RemoveWalletData와 확인 문구가
#   있을 때만 지운다. Chrome에 로드한 확장 카드는 chrome://extensions에서 직접 삭제한다.
#
# 종료 코드:
#   0  성공(-DryRun 포함, 이미 제거된 경우 포함)
#   1  환경·인자 오류(LOCALAPPDATA 없음, 설치 기록이 없거나 손상된 폴더 - 이 경우 프로그램 파일은 지우지 않는다)
#   3  취소(사용자 취소, 확인 문구 불일치, 실행 중인 프로그램을 닫아 달라고 물을 수 없는 비대화형 실행)
#   4  일부 항목(파일·레지스트리·바로가기·지갑 데이터)을 지우지 못함
#   9  예상하지 못한 오류(스크립트 결함; 출력된 줄 번호와 함께 알려 주세요)
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = '',
    [switch]$NoShortcut,
    [switch]$NoNativeHost,
    [switch]$RemoveWalletData,
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = 'com.your_wallet.native'
$RegistryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$MarkerName = 'yw-install.json'
$ShortcutName = 'Your Wallet.lnk'
$ConfirmPhrase = 'DELETE MY WALLET'

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

function Stop-Uninstall([int]$Code, [string]$Message) {
    Write-Host ''
    Write-Host "제거 중단(종료 코드 $Code): $Message" -ForegroundColor Red
    Write-RecoveryReminder
    exit $Code
}

function Write-RecoveryReminder {
    Write-Host ''
    Write-Host '[중요] 지갑의 유일한 백업은 종이에 적은 24개 복구 단어(BIP39 passphrase를 썼다면 그 passphrase 포함)입니다.' -ForegroundColor Yellow
    Write-Host '       vault 비밀번호만으로는 복구할 수 없고, vault 파일을 잃으면 복구 단어로만 지갑을 되살릴 수 있습니다. 지우기 전에 종이 백업을 확인하세요.' -ForegroundColor Yellow
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

function ConvertTo-FullPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    return $full
}

function Test-PathInside([string]$Child, [string]$Parent) {
    $c = $Child.TrimEnd('\')
    $p = $Parent.TrimEnd('\')
    return $c.Equals($p, [StringComparison]::OrdinalIgnoreCase) -or $c.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-RelativePackagePath([string]$Rel) {
    if ([string]::IsNullOrEmpty($Rel) -or $Rel.Length -gt 200) { return $false }
    if ($Rel -match '[\x00-\x1f\x7f\\:*?"<>|]') { return $false }
    if ($Rel.StartsWith('/')) { return $false }
    foreach ($segment in $Rel.Split('/')) {
        if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..' -or $segment.EndsWith(' ') -or $segment.EndsWith('.')) { return $false }
    }
    return $true
}

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

# 프로세스를 하나씩 파이프라인으로 내보낸다(호출하는 쪽은 @()로 감싼다).
function Get-WalletProcesses {
    foreach ($process in @(Get-Process -Name 'yw-app', 'yw-host' -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $process.Path } catch { $path = $null }
        [pscustomobject]@{ Name = $process.ProcessName; Id = $process.Id; Path = $path; Process = $process }
    }
}

# 반환: 설치 기록의 파일 목록, 폴더가 없으면 빈 배열, 기록이 없거나 손상되면 $null.
function Read-InstallMarkerFiles([string]$Dir) {
    $path = Join-Path $Dir $MarkerName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $value = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path, (New-Object Text.UTF8Encoding($false, $true))))
        if ($value.product -cne 'YourWallet') { return $null }
        $files = @($value.files)
        foreach ($file in $files) {
            if (-not ($file -is [string]) -or -not (Test-RelativePackagePath $file)) { return $null }
        }
        return , ([string[]]$files)
    } catch {
        return $null
    }
}

# 사용 중인 파일이나 실행 중인 지갑 앱이 없어질 때까지 닫아 달라고 묻는다. 강제 종료하지 않는다.
# $AnyWalletApp: 위치와 상관없이 yw-app이 실행 중이면 막는다(지갑 데이터 삭제 때).
function Wait-WalletClosed([string[]]$Paths, [bool]$AnyWalletApp) {
    while ($true) {
        $locked = @($Paths | Where-Object { Test-FileLocked $_ })
        $apps = @()
        if ($AnyWalletApp) { $apps = @(Get-WalletProcesses | Where-Object { $_.Name -eq 'yw-app' }) }
        if ($locked.Count -eq 0 -and $apps.Count -eq 0) { return $true }
        Write-Host ''
        Write-Host '  실행 중인 프로그램 때문에 지울 수 없습니다:' -ForegroundColor Yellow
        foreach ($path in $locked) { Write-Host "    - 사용 중: $path" }
        foreach ($app in $apps) { Write-Host "    - 실행 중: yw-app (PID $($app.Id)) $($app.Path)" }
        Write-Host '  - yw-app: 지갑 앱 창을 닫아 주세요(창을 닫으면 잠근 뒤 정상 종료합니다). 창이 보이지 않으면'
        Write-Host '    시작 메뉴의 Your Wallet을 실행하면 숨어 있던 창이 앞으로 나옵니다.'
        Write-Host '  - yw-host: Chrome이 확장 연결용으로 실행한 프로세스입니다. Chrome 창을 모두 닫으면 끝납니다.'
        Write-Host '  이 스크립트는 프로그램을 강제로 종료하지 않습니다.'
        if ($DryRun) {
            Write-Plan '실제 제거 때는 위 프로그램을 닫아 달라고 묻고 기다립니다.'
            return $true
        }
        if (-not (Test-Interactive)) {
            Write-Host '  비대화형 실행이라 물어볼 수 없습니다.' -ForegroundColor Yellow
            return $false
        }
        $answer = "$(Read-Host '  닫은 뒤 Enter = 다시 확인 / C = 지갑 앱에 정상 종료 요청(창 닫기와 같음) / Q = 취소')".Trim()
        if ($answer -match '^[qQ]$') { return $false }
        if ($answer -match '^[cC]$') {
            $targets = @(Get-WalletProcesses | Where-Object { $_.Name -eq 'yw-app' -and ($AnyWalletApp -or ($null -ne $_.Path -and $locked -contains $_.Path)) })
            if ($targets.Count -eq 0) { Write-Host '  종료를 요청할 yw-app이 없습니다(yw-host는 Chrome을 닫으면 끝납니다).' }
            foreach ($app in $targets) {
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

function Invoke-Uninstall {
    trap {
        Write-Host ''
        Write-Host "제거 중단(종료 코드 9): 예상하지 못한 오류: $((Get-InnerException $_).Message)" -ForegroundColor Red
        Write-Host "  위치: 줄 $($_.InvocationInfo.ScriptLineNumber)"
        Write-RecoveryReminder
        exit 9
    }
    Set-RedirectedOutputUtf8
    $failures = New-Object 'System.Collections.Generic.List[string]'
    $localAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($localAppData) -or -not [IO.Path]::IsPathRooted($localAppData)) {
        Stop-Uninstall 1 'LOCALAPPDATA 환경 변수가 없거나 절대 경로가 아닙니다.'
    }
    $dataDir = ConvertTo-FullPath (Join-Path $localAppData 'YourWallet')
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        # 설치 폴더에 복사된 이 스크립트를 실행했으면 그 폴더(-InstallDir로 설치한 경우 포함), 아니면 기본 위치.
        if (-not [string]::IsNullOrEmpty($PSScriptRoot) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot $MarkerName) -PathType Leaf)) {
            $script:InstallDir = $PSScriptRoot
        } else {
            $script:InstallDir = Join-Path $localAppData 'Programs\YourWallet'
        }
    }
    $target = ConvertTo-FullPath $InstallDir
    if ($target -cnotmatch '^[A-Za-z]:\\.+') { Stop-Uninstall 1 "설치 폴더 경로가 올바르지 않습니다: $target" }
    if ((Test-PathInside $target $dataDir) -or (Test-PathInside $dataDir $target)) {
        Stop-Uninstall 1 "설치 폴더가 지갑 데이터 폴더($dataDir)와 겹칩니다: $target"
    }
    # 이 스크립트가 설치 폴더 안에 있어도 폴더를 지울 수 있게 현재 폴더를 옮긴다.
    $neutral = [IO.Path]::GetTempPath()
    Set-Location -LiteralPath $neutral
    [Environment]::CurrentDirectory = $neutral

    $appExe = Join-Path $target 'yw-app.exe'
    $hostExe = Join-Path $target 'yw-host.exe'
    $manifestPath = Join-Path $target "$HostName.json"
    $markerPath = Join-Path $target $MarkerName

    Write-Host 'Your Wallet 제거' -ForegroundColor Green
    Write-Host "  설치 폴더   : $target"
    if ($RemoveWalletData) {
        Write-Host "  지갑 데이터 : $dataDir (-RemoveWalletData: 확인 문구를 입력하면 지웁니다)" -ForegroundColor Yellow
    } else {
        Write-Host "  지갑 데이터 : $dataDir (지우지 않습니다)"
    }
    if ($DryRun) { Write-Host '  -DryRun: 지울 것만 출력하고 아무것도 바꾸지 않습니다.' -ForegroundColor DarkYellow }

    # 프로그램 파일 목록
    $programFiles = @()
    $programFilesKnown = $true
    if (Test-Path -LiteralPath $target -PathType Container) {
        $markerFiles = Read-InstallMarkerFiles $target
        if ($null -eq $markerFiles) {
            if (@(Get-ChildItem -LiteralPath $target -Force).Count -gt 0) {
                $programFilesKnown = $false
                Write-Warn "설치 기록($MarkerName)이 없거나 손상되어 이 폴더의 파일은 지우지 않습니다: $target"
            }
        } else {
            foreach ($rel in $markerFiles) {
                $full = [IO.Path]::GetFullPath((Join-Path $target ($rel.Replace('/', '\'))))
                if (-not (Test-PathInside $full $target)) { continue }
                if (Test-Path -LiteralPath $full -PathType Leaf) { $programFiles += $full }
            }
            if (Test-Path -LiteralPath $manifestPath -PathType Leaf) { $programFiles += $manifestPath }
            $programFiles += $markerPath
        }
    } else {
        Write-Host "  설치 폴더가 없습니다(이미 제거됨). 바로가기·등록만 확인합니다."
    }

    # 지갑 데이터 삭제 확인은 무엇이든 지우기 전에 받는다.
    $removeData = $false
    if ($RemoveWalletData) {
        Write-Step '지갑 데이터 삭제 확인'
        if (-not (Test-Path -LiteralPath $dataDir -PathType Container)) {
            Write-Host "  지갑 데이터 폴더가 없습니다: $dataDir"
        } else {
            $vault = Join-Path $dataDir 'v3\vault.ywv'
            if (Test-Path -LiteralPath $vault -PathType Leaf) { Write-Host "  vault 파일이 있습니다: $vault" -ForegroundColor Yellow }
            Write-Host "  다음 폴더 전체를 영구 삭제합니다: $dataDir" -ForegroundColor Yellow
            Write-Host '  (vault, 계정·주소록·연결된 사이트, 진행 중 거래 저널, 설정, RPC 주소, 로그)' -ForegroundColor Yellow
            Write-RecoveryReminder
            if ($DryRun) {
                Write-Plan "실제 실행 때는 '$ConfirmPhrase' 입력을 받은 뒤에만 지웁니다."
                $removeData = $true
            } else {
                if (-not (Test-Interactive)) { Stop-Uninstall 3 '지갑 데이터 삭제는 직접 연 PowerShell 창에서 확인 문구를 입력해야 합니다. 아무것도 지우지 않았습니다.' }
                $typed = "$(Read-Host "  정말 지우려면 $ConfirmPhrase 를 정확히 입력하세요(그 밖의 입력은 취소)")"
                if ($typed -cne $ConfirmPhrase) { Stop-Uninstall 3 '확인 문구가 일치하지 않아 취소했습니다. 아무것도 지우지 않았습니다.' }
                $removeData = $true
            }
        }
    }

    $mustRelease = [string[]]@($programFiles | Where-Object { $_ -ieq $appExe -or $_ -ieq $hostExe })
    if (-not (Wait-WalletClosed $mustRelease $removeData)) {
        Stop-Uninstall 3 '제거를 취소했습니다. 바뀐 것은 없습니다. yw-app과 Chrome을 닫은 뒤 다시 실행하세요.'
    }

    # 1. 시작 메뉴 바로가기
    Write-Step '1/4 시작 메뉴 바로가기'
    if ($NoShortcut) {
        Write-Host '  건너뜀(-NoShortcut).'
    } else {
        $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
        $shortcutPath = $null
        if (-not [string]::IsNullOrEmpty($programs)) { $shortcutPath = Join-Path $programs $ShortcutName }
        if ($null -eq $shortcutPath -or -not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
            Write-Host '  바로가기가 없습니다.'
        } else {
            $shell = $null
            $shortcutTarget = $null
            try {
                $shell = New-Object -ComObject WScript.Shell
                $shortcutTarget = $shell.CreateShortcut($shortcutPath).TargetPath
            } catch {
                $shortcutTarget = $null
            } finally {
                if ($null -ne $shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
            }
            if ($null -eq $shortcutTarget -or -not ([string]$shortcutTarget).Equals($appExe, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Host "  바로가기가 다른 위치를 가리켜 남겨 둡니다: $shortcutPath -> $shortcutTarget"
            } elseif ($DryRun) {
                Write-Plan "삭제: $shortcutPath"
            } else {
                try {
                    [IO.File]::Delete($shortcutPath)
                    Write-Host "  삭제: $shortcutPath"
                } catch {
                    $failures.Add("바로가기 $shortcutPath")
                }
            }
        }
    }

    # 2. HKCU native host 등록
    Write-Step '2/4 Chrome native host 등록 (HKCU)'
    if ($NoNativeHost) {
        Write-Host '  건너뜀(-NoNativeHost).'
    } elseif (-not (Test-Path -LiteralPath $RegistryKey)) {
        Write-Host '  등록이 없습니다.'
    } else {
        $current = [string](Get-Item -LiteralPath $RegistryKey).GetValue('')
        if (-not $current.Equals($manifestPath, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "  다른 설치를 가리키는 등록이라 남겨 둡니다: $current"
        } elseif ($DryRun) {
            Write-Plan "레지스트리 키 삭제: $RegistryKey"
        } else {
            try {
                Remove-Item -LiteralPath $RegistryKey -Recurse -Force
                Write-Host "  삭제: $RegistryKey"
            } catch {
                $failures.Add("레지스트리 $RegistryKey")
            }
        }
    }

    # 3. 프로그램 파일
    Write-Step '3/4 프로그램 파일'
    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
        Write-Host '  설치 폴더가 없습니다.'
    } elseif (-not $programFilesKnown) {
        Write-Host "  설치 기록이 없어 건너뜁니다. 필요하면 폴더를 직접 확인한 뒤 지우세요: $target"
    } elseif ($DryRun) {
        foreach ($file in $programFiles) { Write-Plan "삭제: $file" }
        Write-Plan "빈 폴더 삭제: $target"
    } else {
        $deleted = 0
        foreach ($file in $programFiles) {
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
            try { [IO.File]::Delete($file); $deleted++ } catch { $failures.Add($file) }
        }
        # 빈 하위 폴더를 깊은 것부터 지운다. 설치 기록에 없던 파일이 있는 폴더는 남는다.
        $dirs = @(Get-ChildItem -LiteralPath $target -Recurse -Directory -Force | Sort-Object { $_.FullName.Length } -Descending)
        foreach ($dir in $dirs) {
            if (@(Get-ChildItem -LiteralPath $dir.FullName -Force).Count -eq 0) {
                try { [IO.Directory]::Delete($dir.FullName) } catch { }
            }
        }
        $left = @(Get-ChildItem -LiteralPath $target -Recurse -Force)
        if ($left.Count -eq 0) {
            try {
                [IO.Directory]::Delete($target)
                Write-Host "  삭제: $target"
            } catch {
                Write-Warn "빈 설치 폴더를 지우지 못했습니다(다른 창이 이 폴더를 열고 있을 수 있음): $target"
            }
        } else {
            Write-Warn "설치 기록에 없던 항목 $($left.Count)개가 남아 폴더를 지우지 않았습니다: $target"
        }
        Write-Host "  프로그램 파일 $($deleted)개 삭제."
    }

    # 4. 지갑 데이터
    Write-Step '4/4 지갑 데이터'
    if (-not $removeData) {
        Write-Host "  지우지 않았습니다: $dataDir"
        Write-Host '  다시 설치(저장소의 install.cmd)하면 같은 데이터를 그대로 씁니다. 완전히 지우려면 -RemoveWalletData를 쓰세요.'
    } elseif ($DryRun) {
        Write-Plan "폴더 전체 삭제: $dataDir"
    } else {
        try {
            Remove-Item -LiteralPath $dataDir -Recurse -Force
            Write-Host "  삭제: $dataDir"
        } catch {
            $failures.Add("지갑 데이터 $dataDir")
        }
    }

    Write-Host ''
    Write-Host '[Chrome] chrome://extensions 에서 Your Wallet 카드를 "삭제"하세요(압축해제 로드한 확장은 스크립트가 지울 수 없습니다).'
    Write-RecoveryReminder
    Write-Host ''
    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Host "  지우지 못함: $failure" -ForegroundColor Red }
        Write-Host "제거 일부 실패(종료 코드 4). yw-app과 Chrome을 닫은 뒤 다시 실행하세요." -ForegroundColor Red
        exit 4
    }
    if (-not $programFilesKnown) {
        Write-Host '바로가기·등록은 처리했지만 설치 기록이 없어 프로그램 파일은 지우지 않았습니다(종료 코드 1).' -ForegroundColor Yellow
        exit 1
    }
    if ($DryRun) {
        Write-Host 'DryRun 완료: 바뀐 것은 없습니다.' -ForegroundColor Green
    } else {
        Write-Host '제거 완료.' -ForegroundColor Green
    }
    Write-Host "지갑 데이터 폴더: $dataDir"
    exit 0
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Uninstall }
