[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "static", "test", "all")]
    [string]$Target = "help"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $RepoRoot

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string]$Executable, [Parameter(Mandatory = $true)][string[]]$CommandArguments)
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Executable @CommandArguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exitCode -ne 0) {
        throw "Release check failed with exit code ${exitCode}: $Executable"
    }
}

function Invoke-StaticChecks {
    foreach ($source in Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.mjs" -File) {
        Invoke-Checked -Executable "node" -CommandArguments @("--check", $source.FullName)
    }
    foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.ps1" -File) {
        $null = [scriptblock]::Create((Get-Content -LiteralPath $script.FullName -Raw))
    }
    Invoke-Checked -Executable "node" -CommandArguments @("scripts/release/audit-extension.mjs", "check", "--extension-root", "extension")
}

function Invoke-Tests {
    $tests = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.test.mjs" -File | Sort-Object -Property Name | ForEach-Object { $_.FullName })
    if ($tests.Count -eq 0) {
        throw "No release-policy tests were found"
    }
    Invoke-Checked -Executable "node" -CommandArguments (@("--test") + $tests)
    Invoke-Checked -Executable "powershell" -CommandArguments @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "common.test.ps1"))
}

switch ($Target) {
    "help" {
        @"
Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release/check.ps1 <target>

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
