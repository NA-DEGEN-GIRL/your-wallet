[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Contract {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "launcher contract failed: $Message"
    }
}

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Assert-Contract -Condition ($Actual -eq $Expected) -Message $Message
}

function Assert-ExactCrlf {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)]
        [int]$StartIndex,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    for ($index = $StartIndex; $index -lt $Bytes.Length; $index += 1) {
        if ($Bytes[$index] -eq 10) {
            Assert-Contract -Condition ($index -gt $StartIndex -and $Bytes[$index - 1] -eq 13) `
                -Message "$Label contains a bare LF"
        }
        if ($Bytes[$index] -eq 13) {
            Assert-Contract -Condition ($index + 1 -lt $Bytes.Length -and $Bytes[$index + 1] -eq 10) `
                -Message "$Label contains a bare CR"
        }
    }
}

function New-InjectedScenario {
    param(
        [AllowNull()]
        [string]$CargoPath,
        [int]$BuildExitCode,
        [bool]$ArtifactPresent,
        [bool]$LaunchThrows,
        [bool]$SkipPause,
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $state = [pscustomobject]@{
        CargoPath = $CargoPath
        BuildExitCode = $BuildExitCode
        ArtifactPresent = $ArtifactPresent
        LaunchThrows = $LaunchThrows
        ResolveCalls = 0
        BuildCalls = 0
        ArtifactCalls = 0
        LaunchCalls = 0
        PauseCalls = 0
        BuildCargoPath = $null
        ManifestPath = $null
        ArtifactPath = $null
        LaunchPath = $null
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $resolveCargo = {
        $state.ResolveCalls += 1
        return $state.CargoPath
    }.GetNewClosure()
    $runBuild = {
        param($ResolvedCargoPath, $ResolvedManifestPath)
        $state.BuildCalls += 1
        $state.BuildCargoPath = [string]$ResolvedCargoPath
        $state.ManifestPath = [string]$ResolvedManifestPath
        return [int]$state.BuildExitCode
    }.GetNewClosure()
    $artifactExists = {
        param($ResolvedArtifactPath)
        $state.ArtifactCalls += 1
        $state.ArtifactPath = [string]$ResolvedArtifactPath
        return [bool]$state.ArtifactPresent
    }.GetNewClosure()
    $startWallet = {
        param($ResolvedLaunchPath)
        $state.LaunchCalls += 1
        $state.LaunchPath = [string]$ResolvedLaunchPath
        if ($state.LaunchThrows) {
            throw "injected launch failure"
        }
    }.GetNewClosure()
    $writeLine = {
        param($Text)
        [void]$state.Messages.Add([string]$Text)
    }.GetNewClosure()
    $pauseOnFailure = {
        $state.PauseCalls += 1
    }.GetNewClosure()

    $exitCode = Invoke-SepoliaLauncher `
        -RepoRoot $RepoRoot `
        -SkipPause $SkipPause `
        -ResolveCargo $resolveCargo `
        -RunBuild $runBuild `
        -ArtifactExists $artifactExists `
        -StartWallet $startWallet `
        -WriteLine $writeLine `
        -PauseOnFailure $pauseOnFailure
    return [pscustomobject]@{
        ExitCode = $exitCode
        State = $state
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wrapperPath = Join-Path $repoRoot "RUN-SEPOLIA-WALLET.cmd"
$launcherPath = Join-Path $PSScriptRoot "run-sepolia-wallet.ps1"
$contractPath = $PSCommandPath
$ascii = [System.Text.Encoding]::ASCII
$strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)

$wrapperBytes = [System.IO.File]::ReadAllBytes($wrapperPath)
Assert-Contract -Condition ($wrapperBytes.Length -gt 0) -Message "wrapper is empty"
Assert-Contract -Condition (-not ($wrapperBytes | Where-Object { $_ -gt 127 })) `
    -Message "wrapper is not 7-bit ASCII"
Assert-ExactCrlf -Bytes $wrapperBytes -StartIndex 0 -Label "wrapper"
$wrapperText = $ascii.GetString($wrapperBytes)
$expectedWrapper = @(
    "@echo off",
    "setlocal",
    '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run-sepolia-wallet.ps1"',
    'set "LAUNCHER_RESULT=%ERRORLEVEL%"',
    'exit /b %LAUNCHER_RESULT%',
    ""
) -join "`r`n"
Assert-Equal -Actual $wrapperText -Expected $expectedWrapper -Message "wrapper is not the exact thin trampoline"
Assert-Contract -Condition (-not $wrapperText.Contains("chcp")) -Message "wrapper changes code page"
Assert-Contract -Condition (-not $wrapperText.Contains("cargo")) -Message "wrapper contains build logic"
Assert-Contract -Condition (-not $wrapperText.Contains("start ")) -Message "wrapper contains launch logic"
foreach ($argumentExpansion in @("%1", "%2", "%*")) {
    Assert-Contract -Condition (-not $wrapperText.Contains($argumentExpansion)) `
        -Message "wrapper expands caller-controlled arguments"
}

foreach ($scriptPath in @($launcherPath, $contractPath)) {
    $scriptBytes = [System.IO.File]::ReadAllBytes($scriptPath)
    Assert-Contract -Condition ($scriptBytes.Length -gt 3) -Message "PowerShell script is empty"
    Assert-Contract -Condition (
        $scriptBytes[0] -eq 0xEF -and $scriptBytes[1] -eq 0xBB -and $scriptBytes[2] -eq 0xBF
    ) -Message "PowerShell script lacks the UTF-8 BOM"
    Assert-ExactCrlf -Bytes $scriptBytes -StartIndex 3 -Label "PowerShell script"
    [void]$strictUtf8.GetString($scriptBytes, 3, $scriptBytes.Length - 3)
}

$launcherBytes = [System.IO.File]::ReadAllBytes($launcherPath)
$launcherText = $strictUtf8.GetString($launcherBytes, 3, $launcherBytes.Length - 3)
foreach ($sentinel in @(
    "Your Wallet - Sepolia 테스트넷 전용",
    "Rust/Cargo를 찾지 못했습니다.",
    "빌드에 실패했습니다. 위 오류 내용을 확인해 주세요.",
    "빌드는 끝났지만 실행 파일을 찾지 못했습니다.",
    "앱을 열지 못했습니다. 이 창의 오류를 확인해 주세요."
)) {
    Assert-Contract -Condition $launcherText.Contains($sentinel) -Message "Korean launcher sentinel is missing"
}
Assert-Contract -Condition (-not $launcherText.Contains([char]0xFFFD)) -Message "launcher contains replacement text"
Assert-Contract -Condition $launcherText.Contains(
    "& `$CargoPath build --release --locked --manifest-path `$ManifestPath"
) -Message "cargo arguments changed"
Assert-Contract -Condition $launcherText.Contains(
    "Start-Process -FilePath `$ExecutablePath -WorkingDirectory `$workingDirectory -ErrorAction Stop"
) -Message "exact Start-Process contract changed"
Assert-Contract -Condition (-not $launcherText.Contains("Invoke-Expression")) -Message "launcher uses shell evaluation"
Assert-Contract -Condition (-not $launcherText.Contains("chcp")) -Message "PowerShell launcher changes cmd code page"

. $launcherPath

$missingCargo = New-InjectedScenario -CargoPath $null -BuildExitCode 0 -ArtifactPresent $false `
    -LaunchThrows $false -SkipPause $true -RepoRoot $repoRoot
Assert-Equal $missingCargo.ExitCode 10 -Message "missing Cargo exit code changed"
Assert-Equal $missingCargo.State.ResolveCalls 1 -Message "Cargo resolution count changed"
Assert-Equal $missingCargo.State.BuildCalls 0 -Message "missing Cargo reached build"
Assert-Equal $missingCargo.State.LaunchCalls 0 -Message "missing Cargo reached launch"
Assert-Equal $missingCargo.State.PauseCalls 0 -Message "NoPause attempted input"
Assert-Contract -Condition $missingCargo.State.Messages.Contains(" Rust/Cargo를 찾지 못했습니다.") `
    -Message "missing Cargo Korean message changed"

$buildFailure = New-InjectedScenario -CargoPath "C:\fixture\cargo.exe" -BuildExitCode 37 `
    -ArtifactPresent $false -LaunchThrows $false -SkipPause $false -RepoRoot $repoRoot
Assert-Equal $buildFailure.ExitCode 37 -Message "native build exit code was not preserved"
Assert-Equal $buildFailure.State.BuildCalls 1 -Message "build failure call count changed"
Assert-Equal $buildFailure.State.ArtifactCalls 0 -Message "build failure queried artifact"
Assert-Equal $buildFailure.State.LaunchCalls 0 -Message "build failure reached launch"
Assert-Equal $buildFailure.State.PauseCalls 1 -Message "interactive failure did not request one pause"

$artifactMissing = New-InjectedScenario -CargoPath "C:\fixture\cargo.exe" -BuildExitCode 0 `
    -ArtifactPresent $false -LaunchThrows $false -SkipPause $true -RepoRoot $repoRoot
Assert-Equal $artifactMissing.ExitCode 11 -Message "missing artifact exit code changed"
Assert-Equal $artifactMissing.State.ArtifactCalls 1 -Message "artifact check count changed"
Assert-Equal $artifactMissing.State.LaunchCalls 0 -Message "missing artifact reached launch"

$launchFailure = New-InjectedScenario -CargoPath "C:\fixture\cargo.exe" -BuildExitCode 0 `
    -ArtifactPresent $true -LaunchThrows $true -SkipPause $true -RepoRoot $repoRoot
Assert-Equal $launchFailure.ExitCode 12 -Message "launch failure exit code changed"
Assert-Equal $launchFailure.State.LaunchCalls 1 -Message "launch failure call count changed"

$success = New-InjectedScenario -CargoPath "C:\fixture\cargo.exe" -BuildExitCode 0 `
    -ArtifactPresent $true -LaunchThrows $false -SkipPause $false -RepoRoot $repoRoot
$expectedManifest = Join-Path $repoRoot "demo\sepolia-wallet\Cargo.toml"
$expectedExecutable = Join-Path $repoRoot "demo\sepolia-wallet\target\release\sepolia-wallet-demo.exe"
Assert-Equal $success.ExitCode 0 -Message "success exit code changed"
Assert-Equal $success.State.BuildCalls 1 -Message "success build count changed"
Assert-Equal $success.State.LaunchCalls 1 -Message "success launch count changed"
Assert-Equal $success.State.PauseCalls 0 -Message "success requested pause"
Assert-Equal $success.State.ManifestPath $expectedManifest -Message "manifest path changed"
Assert-Equal $success.State.ArtifactPath $expectedExecutable -Message "artifact path changed"
Assert-Equal $success.State.LaunchPath $expectedExecutable -Message "launch path changed"

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempBase ("your-wallet launcher contract # (" + [guid]::NewGuid().ToString("N") + ")")
$tempRootFull = [System.IO.Path]::GetFullPath($tempRoot)
Assert-Contract -Condition $tempRootFull.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) `
    -Message "temporary launcher path escaped the temp directory"
$capturePath = Join-Path $tempRootFull "launcher-output.bin"
$savedPath = $env:PATH
try {
    [void](New-Item -ItemType Directory -Path (Join-Path $tempRootFull "scripts") -Force)
    Copy-Item -LiteralPath $wrapperPath -Destination (Join-Path $tempRootFull "RUN-SEPOLIA-WALLET.cmd")
    Copy-Item -LiteralPath $launcherPath -Destination (Join-Path $tempRootFull "scripts\run-sepolia-wallet.ps1")
    $env:PATH = Join-Path $env:SystemRoot "System32"
    $copiedWrapper = Join-Path $tempRootFull "RUN-SEPOLIA-WALLET.cmd"
    $commandLine = "chcp 437 >nul & call `"$copiedWrapper`" < nul > `"$capturePath`" 2>&1"
    & $env:ComSpec /d /s /c $commandLine
    $wrapperExitCode = $LASTEXITCODE
    Assert-Equal $wrapperExitCode 10 -Message "cmd wrapper did not propagate PowerShell exit code"
    $capturedBytes = [System.IO.File]::ReadAllBytes($capturePath)
    $capturedText = $strictUtf8.GetString($capturedBytes)
    Assert-Contract -Condition $capturedText.Contains("Rust/Cargo를 찾지 못했습니다.") `
        -Message "cmd-to-PowerShell Korean output was not exact UTF-8"
    Assert-Contract -Condition (-not $capturedText.Contains([char]0xFFFD)) `
        -Message "cmd-to-PowerShell output contained replacement text"
    foreach ($forbiddenFragment in @(
        "not recognized",
        "내부 또는 외부 명령",
        "배치 파일이 아닙니다",
        "지정된 경로를 찾을 수 없습니다."
    )) {
        Assert-Contract -Condition (-not $capturedText.Contains($forbiddenFragment)) `
            -Message "cmd parsed launcher text as a command"
    }

}
finally {
    $env:PATH = $savedPath
    if (Test-Path -LiteralPath $tempRootFull) {
        Remove-Item -LiteralPath $tempRootFull -Recurse -Force
    }
}

[Console]::WriteLine("LAUNCHER_CONTRACT_PASS")
