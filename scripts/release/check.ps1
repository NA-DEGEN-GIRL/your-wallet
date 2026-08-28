[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("help", "static", "test", "all")]
    [string]$Target,
    [Parameter(Mandatory = $true)]
    [string]$NodeExecutable
)

$PSModuleAutoLoadingPreference = "None"
$ErrorActionPreference = "Stop"
$script:ReleasePowerShellEntryScriptPath = $PSCommandPath
. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))

if (-not [System.IO.Path]::IsPathRooted($NodeExecutable)) {
    throw "Release check requires an absolute Node executable path"
}
$NodeExecutable = [System.IO.Path]::GetFullPath($NodeExecutable)
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $RepoRoot

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string]$Executable, [Parameter(Mandatory = $true)][string[]]$CommandArguments)
    $result = Invoke-ReleaseCommand `
        -Executable $Executable `
        -CommandArguments $CommandArguments `
        -WorkingDirectory $RepoRoot
    if (-not [System.String]::IsNullOrEmpty($result.Stderr)) {
        throw "Release check command emitted stderr"
    }
    if (-not [System.String]::IsNullOrEmpty($result.Stdout)) {
        Write-Output $result.Stdout
    }
}

function Invoke-StaticChecks {
    foreach ($source in Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.mjs" -File) {
        Invoke-Checked -Executable $NodeExecutable -CommandArguments @("--check", $source.FullName)
    }
    foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.ps1" -File) {
        $null = [scriptblock]::Create((Get-Content -LiteralPath $script.FullName -Raw))
    }
    Invoke-Checked -Executable $NodeExecutable -CommandArguments @("scripts/release/audit-extension.mjs", "check", "--extension-root", "extension")
}

function Invoke-Tests {
    $approvedTestSha256 = [ordered]@{
        "audit-extension.test.mjs" = "ad38466ba18481611a6e55575231b313c12644464d643580edc9aaede73a6906"
        "generate-inventories.test.mjs" = "cf6a80cd902dc3a35fc88a8cb5c65fe84790254bc1e9693a0404a311223f7dbc"
        "release-manifest.test.mjs" = "72fedde11de2e28a2a351697f0a2e733c6297adcbd161c6d167913c875902c9b"
        "release-verifier-integration.test.mjs" = "3b92f785e9bd81dc7f1a4173c2fb506f2d7ac74b32552e5b2955a332d0d0b2c7"
        "review-evidence-set.test.mjs" = "b556b49d3c349c6519edddf5817e16972540ed55f613cb208a738c4e3ed6f470"
    }
    $tests = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.test.mjs" -File | Sort-Object -Property Name | ForEach-Object { $_.FullName })
    if ($tests.Count -ne $approvedTestSha256.Count) {
        throw "Release-policy test inventory is not approved"
    }
    $approvedTestNames = @($approvedTestSha256.Keys)
    for ($index = 0; $index -lt $approvedTestNames.Count; $index += 1) {
        $testName = [System.IO.Path]::GetFileName($tests[$index])
        if (
            -not [System.String]::Equals(
                $testName,
                [string]$approvedTestNames[$index],
                [System.StringComparison]::Ordinal
            )
        ) {
            throw "Release-policy test inventory is not approved"
        }
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha256.ComputeHash([System.IO.File]::ReadAllBytes($tests[$index]))
        }
        finally {
            $sha256.Dispose()
        }
        $actualSha256 = ([System.BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
        if (
            -not [System.String]::Equals(
                $actualSha256,
                [string]$approvedTestSha256[$testName],
                [System.StringComparison]::Ordinal
            )
        ) {
            throw "Release-policy test source is not approved"
        }
    }
    $stderrRejected = $false
    try {
        $null = Invoke-Checked `
            -Executable $NodeExecutable `
            -CommandArguments @(
                "-e",
                'process.stdout.write("EXACT_STDOUT");process.stderr.write("REJECTED_STDERR")'
            )
    }
    catch {
        $stderrRejected = $true
    }
    if (-not $stderrRejected) {
        throw "Release check accepted child stderr"
    }
    Invoke-Checked -Executable $NodeExecutable -CommandArguments (@("--test") + $tests)
    $systemPowerShell = [System.IO.Path]::Combine(
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System),
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe"
    )
    if (-not [System.IO.File]::Exists($systemPowerShell)) {
        throw "System Windows PowerShell is unavailable"
    }
    $expectedPowerShellTestSuccess = @{
        "common.test.ps1" = "POWERSHELL_RELEASE_HELPERS_PASS"
        "verifier-toolset.test.ps1" = "POWERSHELL_VERIFIER_TOOLSET_PASS"
    }
    foreach ($testScriptName in @("common.test.ps1", "verifier-toolset.test.ps1")) {
        $testOutput = @(
            Invoke-Checked -Executable $systemPowerShell -CommandArguments @(
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                (Join-Path $PSScriptRoot $testScriptName)
            )
        )
        $expectedSuccess = $expectedPowerShellTestSuccess[$testScriptName]
        if (
            $testOutput.Count -ne 1 -or
            -not [System.String]::Equals(
                [string]$testOutput[0],
                $expectedSuccess,
                [System.StringComparison]::Ordinal
            )
        ) {
            throw "Release PowerShell behavior test did not emit its exact success sentinel"
        }
        Write-Output $testOutput[0]
    }
}

switch ($Target) {
    "help" {
        @"
Usage: <system-powershell> -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/check.ps1 <target> -NodeExecutable <absolute-node.exe>

Targets:
  static  Parse release scripts and run the extension static audit.
  test    Run deterministic release-policy unit tests.
  all     Run static and test checks. Never builds, signs, installs, or publishes.
"@
    }
    "static" { Invoke-StaticChecks }
    "test" { Invoke-Tests }
    "all" {
        Invoke-StaticChecks
        Invoke-Tests
    }
}
