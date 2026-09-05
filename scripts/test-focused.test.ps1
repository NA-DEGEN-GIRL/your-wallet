[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
. (Join-Path $PSScriptRoot 'test-focused.ps1')

function Assert-Focused {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Focused runner contract failed: $Message" }
}

function New-FocusedScenario {
    param([string]$Artifact)
    $state = [pscustomobject]@{
        Calls = New-Object 'System.Collections.Generic.List[object]'
        Listed = @('module::first: test', 'module::second: test')
        BuildLines = @((@{
            reason = 'compiler-artifact'
            target = @{ name = 'key-agent'; kind = @('bin') }
            executable = $Artifact
        } | ConvertTo-Json -Depth 4 -Compress))
        Summary = @('test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s')
        FailAt = 0
        ThrowAt = 0
        ObservedExecutable = $null
    }
    $run = {
        param($arguments)
        [void]$state.Calls.Add(@($arguments))
        $number = $state.Calls.Count
        if ($number -eq $state.ThrowAt) { throw 'Injected child start failure.' }
        if ($number -eq $state.FailAt) {
            return [pscustomobject]@{ ExitCode = 101; Lines = @('test module::first ... FAILED') }
        }
        if ($number -eq 1) { $lines = $state.Listed }
        elseif ($number -eq 2) { $lines = $state.BuildLines }
        else {
            $state.ObservedExecutable = [Environment]::GetEnvironmentVariable('YW_TEST_KEY_AGENT_EXECUTABLE', 'Process')
            $lines = $state.Summary
        }
        return [pscustomobject]@{ ExitCode = 0; Lines = $lines }
    }.GetNewClosure()
    return [pscustomobject]@{ State = $state; Run = $run }
}

function Invoke-Scenario {
    param($Scenario, [bool]$ShouldFail, [int]$Expected = 2)
    $failed = $false
    try {
        Invoke-FocusedTests -SelectedPackage 'platform-windows' -SelectedFilter 'module::' `
            -ExpectedTests $Expected -RunCargo $Scenario.Run 6>$null
    }
    catch { $failed = $true }
    Assert-Focused ($failed -eq $ShouldFail) 'expected success/failure classification'
}

function Invoke-FullBuilderScenario {
    param([string[]]$Lines, [bool]$ShouldFail, [string]$ExpectedArtifact, [int]$ExitCode = 0)

    # Exercise the real full-gate builder without running the full gate or Cargo.
    $parseTokens = $null
    $parseErrors = $null
    $checkAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'check.ps1'), [ref]$parseTokens, [ref]$parseErrors
    )
    $builder = $checkAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Build-KeyAgentTestExecutable'
    }, $true)
    Assert-Focused ($parseErrors.Count -eq 0 -and $null -ne $builder) 'full builder AST'
    # An AST-created scriptblock has no file-backed PSScriptRoot. Restore only
    # that fixed import path; the builder and shared parser otherwise run intact.
    $fullBuilderParserPath = Join-Path $PSScriptRoot 'test-focused.ps1'
    $builderSource = $builder.Extent.Text.Replace(
        '[IO.Path]::Combine($PSScriptRoot, "test-focused.ps1")', '$fullBuilderParserPath'
    )
    . ([scriptblock]::Create($builderSource))
    $child = [pscustomobject]@{ Calls = 0; Arguments = @(); Lines = $Lines; ExitCode = $ExitCode }
    function cargo {
        $child.Calls += 1
        $child.Arguments = @($args)
        $global:LASTEXITCODE = $child.ExitCode
        return $child.Lines
    }
    $failed = $false
    try {
        $actual = @(Build-KeyAgentTestExecutable)
    }
    catch { $failed = $true }
    Assert-Focused ($failed -eq $ShouldFail) 'full builder success/failure classification'
    Assert-Focused ($child.Calls -eq 1) 'one full builder Cargo invocation'
    Assert-Focused (($child.Arguments -join ' ') -ceq 'build --locked -p key-agent --bin key-agent --message-format=json-render-diagnostics') 'full builder artifact profile'
    if (-not $ShouldFail) {
        Assert-Focused ($actual.Count -eq 1 -and $actual[0] -ceq $ExpectedArtifact) 'full builder exact artifact and silent import'
    }
}

$savedExecutable = [Environment]::GetEnvironmentVariable('YW_TEST_KEY_AGENT_EXECUTABLE', 'Process')
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('yw-focused-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fixtureRoot
$fixtureArtifact = Join-Path $fixtureRoot 'key-agent.exe'
$null = New-Item -ItemType File -Path $fixtureArtifact
try {
    # Absent and present ambient values are restored; exact Cargo artifact is used.
    foreach ($previous in @($null, 'fixture-previous-executable')) {
        [Environment]::SetEnvironmentVariable('YW_TEST_KEY_AGENT_EXECUTABLE', $previous, 'Process')
        $case = New-FocusedScenario $fixtureArtifact
        Invoke-Scenario $case $false
        Assert-Focused ($case.State.ObservedExecutable -ceq $fixtureArtifact) 'artifact injection'
        Assert-Focused ([Environment]::GetEnvironmentVariable('YW_TEST_KEY_AGENT_EXECUTABLE', 'Process') -ceq $previous) 'success restoration'
        Assert-Focused (($case.State.Calls[0] -join ' ') -ceq 'test --locked -p platform-windows --lib module:: -- --list --format terse') 'discovery profile'
        Assert-Focused (($case.State.Calls[1] -join ' ') -ceq 'build --locked -p key-agent --bin key-agent --message-format=json-render-diagnostics') 'artifact profile'
        Assert-Focused (($case.State.Calls[2] -join ' ') -ceq 'test --locked -p platform-windows --lib module:: -- --format pretty') 'execution profile'
    }

    foreach ($inventory in @(@(), @('module::first: test'), @('module::first: test', 'module::first: test'))) {
        $case = New-FocusedScenario $fixtureArtifact
        $case.State.Listed = $inventory
        Invoke-Scenario $case $true
        Assert-Focused ($case.State.Calls.Count -eq 1) 'inventory rejection precedes build/run'
    }
    $case = New-FocusedScenario $fixtureArtifact
    $case.State.Listed = @()
    Invoke-Scenario $case $true 0

    foreach ($summary in @(
        'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s',
        'test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s',
        'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s',
        'not a libtest summary'
    )) {
        $case = New-FocusedScenario $fixtureArtifact
        $case.State.Summary = @($summary)
        Invoke-Scenario $case $true
        Assert-Focused ($env:YW_TEST_KEY_AGENT_EXECUTABLE -ceq 'fixture-previous-executable') 'summary failure restoration'
    }
    $case = New-FocusedScenario $fixtureArtifact
    $case.State.Summary += $case.State.Summary
    Invoke-Scenario $case $true

    foreach ($stage in @(1, 2, 3)) {
        foreach ($failureKind in @('FailAt', 'ThrowAt')) {
            $case = New-FocusedScenario $fixtureArtifact
            $case.State.$failureKind = $stage
            Invoke-Scenario $case $true
            Assert-Focused ($case.State.Calls.Count -eq $stage) 'failure stops subsequent stages'
            Assert-Focused ($env:YW_TEST_KEY_AGENT_EXECUTABLE -ceq 'fixture-previous-executable') 'child failure restoration'
        }
    }

    foreach ($artifactLines in @(@(), @('{}'), @('malformed JSON'))) {
        $case = New-FocusedScenario $fixtureArtifact
        $case.State.BuildLines = $artifactLines
        Invoke-Scenario $case $true
        Assert-Focused ($case.State.Calls.Count -eq 2) 'missing artifact stops test execution'
    }
    $case = New-FocusedScenario $fixtureArtifact
    $case.State.BuildLines += $case.State.BuildLines
    Invoke-Scenario $case $true
    foreach ($badPath in @('key-agent.exe', (Join-Path $fixtureRoot 'missing-key-agent.exe'), (Join-Path $fixtureRoot 'KEY-AGENT.EXE'))) {
        $case = New-FocusedScenario $badPath
        Invoke-Scenario $case $true
    }

    $case = New-FocusedScenario $fixtureArtifact
    Invoke-FullBuilderScenario -Lines $case.State.BuildLines -ShouldFail $false -ExpectedArtifact $fixtureArtifact
    Invoke-FullBuilderScenario -Lines $case.State.BuildLines -ShouldFail $true -ExitCode 101
    Invoke-FullBuilderScenario -Lines ($case.State.BuildLines + $case.State.BuildLines) -ShouldFail $true
    foreach ($artifactLines in @(@(), @('{}'), @('malformed JSON'))) {
        Invoke-FullBuilderScenario -Lines $artifactLines -ShouldFail $true
    }
    foreach ($badPath in @('key-agent.exe', (Join-Path $fixtureRoot 'missing-key-agent.exe'), (Join-Path $fixtureRoot 'KEY-AGENT.EXE'))) {
        $case = New-FocusedScenario $badPath
        Invoke-FullBuilderScenario -Lines $case.State.BuildLines -ShouldFail $true
    }

    # Windows rooted paths are not necessarily absolute. Both forms below
    # resolve to an existing fixture, so rejection cannot rely on file absence.
    Push-Location -LiteralPath $fixtureRoot
    try {
        foreach ($badPath in @(
            ($fixtureArtifact.Substring(0, 2) + 'key-agent.exe'),
            $fixtureArtifact.Substring(2)
        )) {
            Assert-Focused ([IO.Path]::IsPathRooted($badPath) -and (Test-Path -LiteralPath $badPath -PathType Leaf)) 'existing drive-relative/root-relative fixture'
            $case = New-FocusedScenario $badPath
            Invoke-Scenario $case $true
            Invoke-FullBuilderScenario -Lines $case.State.BuildLines -ShouldFail $true
        }
    }
    finally { Pop-Location }

    $case = New-FocusedScenario $fixtureArtifact
    Invoke-FocusedTests -SelectedPackage 'platform-windows' -SelectedFilter 'module::first' `
        -SelectedFeatures @('first-feature', 'second_feature') -ExactMatch $true `
        -ExpectedTests 2 -RunCargo $case.Run 6>$null
    Assert-Focused (($case.State.Calls[0] -join ' ') -ceq 'test --locked -p platform-windows --lib --features first-feature,second_feature module::first -- --exact --list --format terse') 'feature and exact profile'
    Assert-Focused (($case.State.Calls[2] -join ' ') -ceq 'test --locked -p platform-windows --lib --features first-feature,second_feature module::first -- --exact --format pretty') 'same run selection'

    foreach ($bad in @(
        @{ SelectedPackage = '--workspace'; SelectedFilter = 'module::' },
        @{ SelectedPackage = 'platform-windows'; SelectedFilter = '' },
        @{ SelectedPackage = 'platform-windows'; SelectedFilter = '--ignored' },
        @{ SelectedPackage = 'platform-windows'; SelectedFilter = 'module::'; SelectedFeatures = @('--all-features') },
        @{ SelectedPackage = 'platform-windows'; SelectedFilter = 'module::'; ExpectedTests = -1 }
    )) {
        $case = New-FocusedScenario $fixtureArtifact
        $rejected = $false
        try { Invoke-FocusedTests @bad -RunCargo $case.Run 6>$null }
        catch { $rejected = $true }
        Assert-Focused ($rejected -and $case.State.Calls.Count -eq 0) 'invalid options rejected before child execution'
    }
}
finally {
    [Environment]::SetEnvironmentVariable('YW_TEST_KEY_AGENT_EXECUTABLE', $savedExecutable, 'Process')
    Remove-Item -LiteralPath $fixtureArtifact -Force
    Remove-Item -LiteralPath $fixtureRoot
}
Write-Output 'FOCUSED_TEST_CONTRACT_PASS'
}
catch {
    Write-Output 'FOCUSED_TEST_CONTRACT_FAIL'
    exit 1
}
