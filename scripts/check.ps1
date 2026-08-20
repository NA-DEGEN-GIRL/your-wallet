[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "setup", "fmt", "fmt-apply", "lint", "typecheck", "test", "privacy", "architecture", "check")]
    [string]$Target = "help"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $RepoRoot

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$CommandArguments
    )

    $previousErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Executable @CommandArguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $Executable"
    }
}

function Invoke-Setup {
    foreach ($tool in @("cargo", "rustc", "node", "npm", "git")) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "Required tool is missing: $tool"
        }
    }
    Invoke-Checked -Executable "cargo" -CommandArguments @("metadata", "--locked", "--no-deps", "--format-version", "1")
}

function Invoke-FormatCheck {
    Invoke-Checked -Executable "cargo" -CommandArguments @("fmt", "--all", "--", "--check")
    Invoke-Checked -Executable "cargo" -CommandArguments @("fmt", "--manifest-path", "demo/sepolia-wallet/Cargo.toml", "--", "--check")
}

function Invoke-FormatApply {
    Invoke-Checked -Executable "cargo" -CommandArguments @("fmt", "--all")
    Invoke-Checked -Executable "cargo" -CommandArguments @("fmt", "--manifest-path", "demo/sepolia-wallet/Cargo.toml")
}

function Invoke-Lint {
    Invoke-Checked -Executable "cargo" -CommandArguments @("clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")
    Invoke-Checked -Executable "cargo" -CommandArguments @("clippy", "--manifest-path", "demo/sepolia-wallet/Cargo.toml", "--locked", "--all-targets", "--", "-D", "warnings")
}

function Invoke-Typecheck {
    Invoke-Checked -Executable "cargo" -CommandArguments @("check", "--locked", "--workspace", "--all-targets", "--all-features")
    Invoke-Checked -Executable "cargo" -CommandArguments @("check", "--manifest-path", "demo/sepolia-wallet/Cargo.toml", "--locked", "--all-targets")
}

function Invoke-Tests {
    Invoke-Checked -Executable "cargo" -CommandArguments @("test", "--locked", "--workspace", "--all-targets", "--all-features")
    Invoke-Checked -Executable "cargo" -CommandArguments @("test", "--locked", "--workspace", "--doc", "--all-features")
    Invoke-Checked -Executable "cargo" -CommandArguments @("test", "--manifest-path", "demo/sepolia-wallet/Cargo.toml", "--locked")
    Invoke-Checked -Executable "npm" -CommandArguments @("--prefix", "extension", "test")
    foreach ($source in Get-ChildItem -LiteralPath "extension/src" -Filter "*.js") {
        Invoke-Checked -Executable "node" -CommandArguments @("--check", $source.FullName)
    }
}

function Invoke-Privacy {
    Invoke-Checked -Executable "node" -CommandArguments @("scripts/privacy-scan.mjs")
}

function Invoke-Architecture {
    Invoke-Checked -Executable "node" -CommandArguments @("scripts/architecture-scan.mjs")
}

function Show-Help {
    @"
Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 <target>

Targets:
  help       Show this help.
  setup      Verify required tools and locked workspace metadata.
  fmt        Check Rust formatting without modifying files.
  fmt-apply  Apply Rust formatting (the only mutating gate target).
  lint       Run Clippy with warnings denied.
  typecheck  Type-check every target and feature.
  test       Run all Rust and extension tests.
  privacy    Scan tracked source artifacts for forbidden secret fixtures.
  architecture
             Enforce trust-boundary and extension-permission invariants.
  check      Run fmt, lint, typecheck, test, privacy, and architecture checks.
"@
}

switch ($Target) {
    "help" { Show-Help }
    "setup" { Invoke-Setup }
    "fmt" { Invoke-FormatCheck }
    "fmt-apply" { Invoke-FormatApply }
    "lint" { Invoke-Lint }
    "typecheck" { Invoke-Typecheck }
    "test" { Invoke-Tests }
    "privacy" { Invoke-Privacy }
    "architecture" { Invoke-Architecture }
    "check" {
        Invoke-FormatCheck
        Invoke-Lint
        Invoke-Typecheck
        Invoke-Tests
        Invoke-Privacy
        Invoke-Architecture
    }
}
