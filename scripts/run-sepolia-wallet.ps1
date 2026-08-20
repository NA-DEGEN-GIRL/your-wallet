[CmdletBinding()]
param(
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:ExitCargoMissing = 10
$script:ExitArtifactMissing = 11
$script:ExitLaunchFailed = 12
$script:ExitBuildInvocationFailed = 13

function Initialize-LauncherEncoding {
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [Console]::InputEncoding = $utf8NoBom
    [Console]::OutputEncoding = $utf8NoBom
    $script:OutputEncoding = $utf8NoBom
}

function Invoke-ExactCargoBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CargoPath,
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    & $CargoPath build --release --locked --manifest-path $ManifestPath | Out-Host
    $nativeExitCode = $LASTEXITCODE
    return [int]$nativeExitCode
}

function Invoke-SepoliaLauncherCore {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ResolveCargo,
        [Parameter(Mandatory = $true)]
        [scriptblock]$RunBuild,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ArtifactExists,
        [Parameter(Mandatory = $true)]
        [scriptblock]$StartWallet,
        [Parameter(Mandatory = $true)]
        [scriptblock]$WriteLine
    )

    $manifestPath = Join-Path $RepoRoot "demo\sepolia-wallet\Cargo.toml"
    $executablePath = Join-Path $RepoRoot "demo\sepolia-wallet\target\release\sepolia-wallet-demo.exe"

    & $WriteLine ""
    & $WriteLine " Your Wallet - Sepolia 테스트넷 전용"
    & $WriteLine " [1/2] 잠금된 의존성으로 릴리스 앱을 빌드합니다."
    & $WriteLine " 처음에는 몇 분 걸릴 수 있습니다. 창을 닫지 말고 기다려 주세요."
    & $WriteLine ""

    try {
        $cargoPath = & $ResolveCargo
    }
    catch {
        $cargoPath = $null
    }
    if ([string]::IsNullOrWhiteSpace([string]$cargoPath)) {
        & $WriteLine " Rust/Cargo를 찾지 못했습니다."
        & $WriteLine " https://rustup.rs 에서 Rust를 한 번 설치한 뒤 다시 실행해 주세요."
        return $script:ExitCargoMissing
    }

    try {
        $buildExitCode = & $RunBuild ([string]$cargoPath) $manifestPath
    }
    catch {
        & $WriteLine " 빌드 명령을 시작하지 못했습니다. Rust/Cargo 설치를 확인해 주세요."
        return $script:ExitBuildInvocationFailed
    }
    if ($buildExitCode -isnot [int]) {
        & $WriteLine " 빌드 명령의 종료 상태를 확인하지 못했습니다."
        return $script:ExitBuildInvocationFailed
    }
    if ($buildExitCode -ne 0) {
        & $WriteLine ""
        & $WriteLine " 빌드에 실패했습니다. 위 오류 내용을 확인해 주세요."
        return [int]$buildExitCode
    }

    $artifactPresent = $false
    try {
        $artifactPresent = [bool](& $ArtifactExists $executablePath)
    }
    catch {
        $artifactPresent = $false
    }
    if (-not $artifactPresent) {
        & $WriteLine ""
        & $WriteLine " 빌드는 끝났지만 실행 파일을 찾지 못했습니다."
        return $script:ExitArtifactMissing
    }

    & $WriteLine ""
    & $WriteLine " [2/2] Sepolia 테스트 지갑을 엽니다."
    try {
        & $StartWallet $executablePath
    }
    catch {
        & $WriteLine ""
        & $WriteLine " 앱을 열지 못했습니다. 이 창의 오류를 확인해 주세요."
        return $script:ExitLaunchFailed
    }
    return 0
}

function Invoke-SepoliaLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [bool]$SkipPause,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ResolveCargo,
        [Parameter(Mandatory = $true)]
        [scriptblock]$RunBuild,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ArtifactExists,
        [Parameter(Mandatory = $true)]
        [scriptblock]$StartWallet,
        [Parameter(Mandatory = $true)]
        [scriptblock]$WriteLine,
        [Parameter(Mandatory = $true)]
        [scriptblock]$PauseOnFailure
    )

    $exitCode = Invoke-SepoliaLauncherCore `
        -RepoRoot $RepoRoot `
        -ResolveCargo $ResolveCargo `
        -RunBuild $RunBuild `
        -ArtifactExists $ArtifactExists `
        -StartWallet $StartWallet `
        -WriteLine $WriteLine
    if ($exitCode -ne 0 -and -not $SkipPause) {
        & $PauseOnFailure
    }
    return [int]$exitCode
}

function Invoke-DefaultSepoliaLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$SkipPause
    )

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $resolveCargo = {
        $command = Get-Command -Name "cargo" -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -eq $command) {
            return $null
        }
        return [string]$command.Source
    }
    $runBuild = {
        param($CargoPath, $ManifestPath)
        return Invoke-ExactCargoBuild -CargoPath $CargoPath -ManifestPath $ManifestPath
    }
    $artifactExists = {
        param($ExecutablePath)
        return Test-Path -LiteralPath $ExecutablePath -PathType Leaf
    }
    $startWallet = {
        param($ExecutablePath)
        $workingDirectory = Split-Path -Parent $ExecutablePath
        Start-Process -FilePath $ExecutablePath -WorkingDirectory $workingDirectory -ErrorAction Stop |
            Out-Null
    }
    $writeLine = {
        param($Text)
        [Console]::WriteLine([string]$Text)
    }
    $pauseOnFailure = {
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
            [Console]::WriteLine("")
            [Console]::WriteLine(" 이 창을 닫으려면 아무 키나 누르세요.")
            [void][Console]::ReadKey($true)
        }
    }

    return Invoke-SepoliaLauncher `
        -RepoRoot $repoRoot `
        -SkipPause $SkipPause `
        -ResolveCargo $resolveCargo `
        -RunBuild $runBuild `
        -ArtifactExists $artifactExists `
        -StartWallet $startWallet `
        -WriteLine $writeLine `
        -PauseOnFailure $pauseOnFailure
}

if ($MyInvocation.InvocationName -ne ".") {
    Initialize-LauncherEncoding
    $launcherExitCode = Invoke-DefaultSepoliaLauncher -SkipPause $NoPause.IsPresent
    exit $launcherExitCode
}
