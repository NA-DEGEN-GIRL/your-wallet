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

    $timer = [Diagnostics.Stopwatch]::StartNew()
    Write-Host "check: $Executable started"
    $previousErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # Windows PowerShell wraps native stderr in ErrorRecord objects when
        # captured. Emit their text without implying that successful tools failed.
        & $Executable @CommandArguments 2>&1 | ForEach-Object { [string]$_ }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $Executable"
    }
    Write-Host ("check: {0} passed ({1:N1}s)" -f $Executable, $timer.Elapsed.TotalSeconds)
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

function Build-KeyAgentTestExecutable {
    $previousErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $messages = & cargo build --locked -p key-agent --bin key-agent --message-format=json-render-diagnostics
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: cargo"
    }

    # Share the exact-one, absolute-path artifact parser with focused tests.
    # Dot-sourcing defines the helpers without invoking the focused CLI.
    . ([IO.Path]::Combine($PSScriptRoot, "test-focused.ps1"))
    return Get-FocusedKeyAgentArtifact -Lines @($messages)
}

function Invoke-WindowsEvidenceReadinessChecks {
    foreach ($scriptPath in @(
        "scripts/windows-evidence/preflight.ps1",
        "scripts/windows-evidence/run-current-user.ps1"
    )) {
        $null = [scriptblock]::Create(
            (Get-Content -LiteralPath $scriptPath -Raw -ErrorAction Stop)
        )
    }

    foreach ($sourcePath in @(
        "scripts/windows-evidence/evidence-contract.mjs",
        "scripts/windows-evidence/compare-build-inventories.mjs"
    )) {
        Invoke-Checked -Executable "node" -CommandArguments @("--check", $sourcePath)
    }

    Invoke-Checked -Executable "node" -CommandArguments @(
        "--test",
        "scripts/windows-evidence/evidence-contract.test.mjs",
        "scripts/windows-evidence/compare-build-inventories.test.mjs"
    )
}

function Invoke-Tests {
    Invoke-WindowsEvidenceReadinessChecks
    Invoke-Checked -Executable "node" -CommandArguments @("--test", "scripts/architecture-diagnostic.test.mjs")
    Invoke-Checked -Executable "powershell" -CommandArguments @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/test-focused.test.ps1")
    Invoke-Checked -Executable "powershell" -CommandArguments @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/launcher-contract.test.ps1")
    $keyAgentExecutable = Build-KeyAgentTestExecutable
    $previousKeyAgentExecutable = [Environment]::GetEnvironmentVariable(
        "YW_TEST_KEY_AGENT_EXECUTABLE",
        [EnvironmentVariableTarget]::Process
    )
    try {
        $env:YW_TEST_KEY_AGENT_EXECUTABLE = $keyAgentExecutable
        Invoke-Checked -Executable "cargo" -CommandArguments @("test", "--locked", "--workspace", "--all-targets", "--all-features")
        Invoke-Checked -Executable "cargo" -CommandArguments @("test", "--locked", "--workspace", "--doc", "--all-features")
        Invoke-Checked -Executable "cargo" -CommandArguments @("test", "--manifest-path", "demo/sepolia-wallet/Cargo.toml", "--locked")
        Invoke-Checked -Executable "npm" -CommandArguments @("--prefix", "extension", "test")
        foreach ($source in Get-ChildItem -LiteralPath "extension/src" -Filter "*.js") {
            Invoke-Checked -Executable "node" -CommandArguments @("--check", $source.FullName)
        }
    }
    finally {
        if ($null -eq $previousKeyAgentExecutable) {
            Remove-Item Env:YW_TEST_KEY_AGENT_EXECUTABLE -ErrorAction SilentlyContinue
        }
        else {
            $env:YW_TEST_KEY_AGENT_EXECUTABLE = $previousKeyAgentExecutable
        }
    }
}

function Invoke-Privacy {
    Invoke-Checked -Executable "node" -CommandArguments @("--test", "scripts/privacy-scan.test.mjs")
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
  test       Run readiness-contract, Rust, and extension tests.
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
