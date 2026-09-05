[CmdletBinding()]
param(
    [string]$Package,
    [string]$Filter,
    [string[]]$Features = @(),
    [switch]$Exact,
    [int]$ExpectedCount = 0
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-FocusedCargo {
    param([string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = @(& cargo @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ ExitCode = $code; Lines = $lines }
}

function Assert-FocusedCargoSuccess {
    param($Result, [string]$Stage)

    if ($Result.ExitCode -ne 0) {
        # Do not echo arbitrary compiler/test output: it can contain local paths
        # or test inputs. Identifiers below are deliberately restricted.
        foreach ($line in $Result.Lines) {
            if ($line -cmatch '^test (?<name>[A-Za-z_][A-Za-z0-9_:]*) \.\.\. FAILED$') {
                Write-Host ("failed-test: " + $Matches.name)
            }
        }
        throw "$Stage failed (exit $($Result.ExitCode)); no successful test result was recorded."
    }
}

function Get-FocusedKeyAgentArtifact {
    param([string[]]$Lines)

    $paths = @()
    foreach ($line in $Lines) {
        try { $message = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { continue }
        if ($null -eq $message -or
            $null -eq $message.PSObject.Properties['reason'] -or
            $message.reason -cne 'compiler-artifact') { continue }
        if ($null -eq $message.PSObject.Properties['target'] -or
            $null -eq $message.PSObject.Properties['executable'] -or
            $null -eq $message.target -or
            $null -eq $message.target.PSObject.Properties['name'] -or
            $null -eq $message.target.PSObject.Properties['kind']) { continue }
        if ($message.target.name -ceq 'key-agent' -and
            @($message.target.kind) -ccontains 'bin' -and
            $message.executable -is [string] -and
            -not [string]::IsNullOrWhiteSpace($message.executable)) {
            $paths += $message.executable
        }
    }
    if ($paths.Count -ne 1) {
        throw 'Build must report exactly one Key Agent executable artifact.'
    }
    $candidate = $paths[0]
    # IsPathRooted alone accepts C:file.exe and \file.exe on Windows. Require
    # a complete drive root or UNC server/share root before resolving the path.
    $candidateRoot = [IO.Path]::GetPathRoot($candidate)
    if (-not [IO.Path]::IsPathRooted($candidate) -or
        ($candidateRoot -cnotmatch '^[A-Za-z]:[\\/]$' -and
            $candidateRoot -cnotmatch '^[\\]{2}[^\\/]+[\\][^\\/]+[\\]?$') -or
        [IO.Path]::GetFileName($candidate) -cne 'key-agent.exe' -or
        -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'Cargo reported an invalid Key Agent executable artifact.'
    }
    return (Resolve-Path -LiteralPath $candidate).Path
}

function Invoke-FocusedTests {
    param(
        [string]$SelectedPackage,
        [string]$SelectedFilter,
        [string[]]$SelectedFeatures = @(),
        [bool]$ExactMatch = $false,
        [int]$ExpectedTests = 0,
        [scriptblock]$RunCargo = { param($arguments) Invoke-FocusedCargo -Arguments $arguments }
    )

    if ($SelectedPackage -cnotmatch '^[a-z][a-z0-9-]*$' -or
        $SelectedFilter -cnotmatch '^[A-Za-z_][A-Za-z0-9_:]*$' -or
        $ExpectedTests -lt 0) {
        throw 'Provide a package, a Rust test/module filter, and a nonnegative expected count.'
    }
    foreach ($feature in $SelectedFeatures) {
        if ($feature -cnotmatch '^[a-z][a-z0-9_-]*$') {
            throw 'Each feature must be one Cargo feature name.'
        }
    }
    $cargoArguments = @('test', '--locked', '-p', $SelectedPackage, '--lib')
    if ($SelectedFeatures.Count -gt 0) {
        $cargoArguments += @('--features', ($SelectedFeatures -join ','))
    }
    $cargoArguments += @($SelectedFilter, '--')
    if ($ExactMatch) { $cargoArguments += '--exact' }

    $watch = [Diagnostics.Stopwatch]::StartNew()
    Write-Host 'focused-test: discover'
    $listed = & $RunCargo ($cargoArguments + @('--list', '--format', 'terse'))
    Assert-FocusedCargoSuccess -Result $listed -Stage 'Test discovery'
    $names = @($listed.Lines | Where-Object { $_ -cmatch '^[A-Za-z_][A-Za-z0-9_:]*: test$' })
    if ($names.Count -eq 0 -or @($names | Select-Object -Unique).Count -ne $names.Count) {
        throw 'The filter must select at least one uniquely named library test.'
    }
    if ($ExpectedTests -gt 0 -and $names.Count -ne $ExpectedTests) {
        throw "Test inventory mismatch: expected $ExpectedTests, selected $($names.Count)."
    }

    Write-Host 'focused-test: build-helper'
    $built = & $RunCargo (@('build', '--locked', '-p', 'key-agent', '--bin', 'key-agent', '--message-format=json-render-diagnostics'))
    Assert-FocusedCargoSuccess -Result $built -Stage 'Key Agent test artifact build'
    $artifact = Get-FocusedKeyAgentArtifact -Lines $built.Lines
    $previousExecutable = [Environment]::GetEnvironmentVariable('YW_TEST_KEY_AGENT_EXECUTABLE', 'Process')
    try {
        $env:YW_TEST_KEY_AGENT_EXECUTABLE = $artifact
        Write-Host "focused-test: run ($($names.Count) selected)"
        $tested = & $RunCargo ($cargoArguments + @('--format', 'pretty'))
        Assert-FocusedCargoSuccess -Result $tested -Stage 'Focused test run'
        $summaries = @($tested.Lines | Where-Object {
            $_ -cmatch '^test result: ok\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored;'
        })
        if ($summaries.Count -ne 1 -or
            $summaries[0] -cnotmatch '^test result: ok\. (?<passed>[0-9]+) passed; 0 failed; 0 ignored;') {
            throw 'Expected one successful library test summary with no ignored tests.'
        }
        if ([int]$Matches.passed -ne $names.Count) {
            throw 'The executed passing test count does not match discovery.'
        }
        Write-Host ("focused-test: PASS ({0} tests, {1:N1}s; full repository gate still required)" -f $names.Count, $watch.Elapsed.TotalSeconds)
    }
    finally {
        if ($null -eq $previousExecutable) {
            Remove-Item Env:YW_TEST_KEY_AGENT_EXECUTABLE -ErrorAction SilentlyContinue
        }
        else { $env:YW_TEST_KEY_AGENT_EXECUTABLE = $previousExecutable }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    Push-Location -LiteralPath $repo
    try {
        Invoke-FocusedTests -SelectedPackage $Package -SelectedFilter $Filter `
            -SelectedFeatures $Features -ExactMatch $Exact.IsPresent -ExpectedTests $ExpectedCount
    }
    catch {
        # PowerShell's default exception renderer includes absolute script paths.
        # Keep CLI failure output data-free as well as child-process output.
        Write-Host 'focused-test: FAIL (last reported stage did not complete)'
        exit 1
    }
    finally { Pop-Location }
}
