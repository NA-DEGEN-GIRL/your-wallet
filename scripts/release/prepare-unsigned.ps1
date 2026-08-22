[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$PSModuleAutoLoadingPreference = "None"
$ErrorActionPreference = "Stop"
$script:ReleasePowerShellEntryScriptPath = $PSCommandPath
. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$OutputFull = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputFull) {
    throw "OutputDirectory must not already exist"
}
if ($env:OS -ne "Windows_NT") {
    throw "Private Mainnet Canary release preparation requires Windows"
}
foreach ($tool in @("cargo", "git", "node", "rustc")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required release tool is unavailable: $tool"
    }
}
foreach ($ambient in @("CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "RUSTFLAGS")) {
    if (Test-Path "Env:${ambient}") {
        throw "Release preparation refuses ambient ${ambient}; the build environment must be explicit"
    }
}

Assert-CleanGitRepository -RepositoryRoot $RepoRoot
$commit = (Invoke-ReleaseCommand -Executable "git" -CommandArguments @("rev-parse", "--verify", "HEAD^{commit}") -WorkingDirectory $RepoRoot).Stdout.Trim()
if ($commit -notmatch "^(?:[0-9a-f]{40}|[0-9a-f]{64})$") {
    throw "Git commit identifier has an unexpected format"
}
$sourceDateEpoch = (Invoke-ReleaseCommand -Executable "git" -CommandArguments @("show", "-s", "--format=%ct", $commit) -WorkingDirectory $RepoRoot).Stdout.Trim()
if ($sourceDateEpoch -notmatch "^[1-9][0-9]*$") {
    throw "Git commit timestamp has an unexpected format"
}

$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$workRoot = Join-Path $temporaryBase ("your-wallet-release-" + [System.Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $workRoot)
$safeCleanupRoot = Assert-SafeTemporaryRoot -LiteralPath $workRoot

$priorIncremental = [System.Environment]::GetEnvironmentVariable("CARGO_INCREMENTAL", "Process")
$priorSourceDate = [System.Environment]::GetEnvironmentVariable("SOURCE_DATE_EPOCH", "Process")
$priorRustFlags = [System.Environment]::GetEnvironmentVariable("RUSTFLAGS", "Process")

try {
    $staging = Join-Path $workRoot "prepared"
    $evidence = Join-Path $staging "evidence"
    $unsignedOutput = Join-Path $staging "unsigned-payload"
    [void](New-Item -ItemType Directory -Path $evidence)
    [void](New-Item -ItemType Directory -Path $unsignedOutput)

    $sourceArchive = Join-Path $workRoot "source.zip"
    [void](Invoke-ReleaseCommand -Executable "git" -CommandArguments @("archive", "--format=zip", "--output", $sourceArchive, $commit) -WorkingDirectory $RepoRoot)
    Copy-Item -LiteralPath $sourceArchive -Destination (Join-Path $evidence "source.zip")

    $firstSource = Join-Path $workRoot "clean-a"
    $secondSource = Join-Path $workRoot "clean-b"
    [void](New-Item -ItemType Directory -Path $firstSource)
    [void](New-Item -ItemType Directory -Path $secondSource)
    Expand-ReleaseZipArchive -LiteralPath $sourceArchive -DestinationPath $firstSource
    Expand-ReleaseZipArchive -LiteralPath $sourceArchive -DestinationPath $secondSource

    $vendorSource = Join-Path $workRoot "vendor-source"
    [void](Invoke-ReleaseCommand -Executable "cargo" -CommandArguments @("vendor", "--frozen", "--versioned-dirs", $vendorSource) -WorkingDirectory $RepoRoot)
    $vendorInventory = Get-DirectoryInventory -LiteralPath $vendorSource
    $vendorInventoryJson = ConvertTo-CanonicalInventoryJson -Inventory $vendorInventory
    Write-NewUtf8File -LiteralPath (Join-Path $evidence "vendor-inventory.json") -Content ($vendorInventoryJson + "`n")

    foreach ($source in @($firstSource, $secondSource)) {
        Copy-Item -LiteralPath $vendorSource -Destination (Join-Path $source "vendor") -Recurse
        $cargoConfig = Join-Path $source ".cargo\config.toml"
        Write-NewUtf8File -LiteralPath $cargoConfig -Content @"
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
"@
    }

    [System.Environment]::SetEnvironmentVariable("CARGO_INCREMENTAL", "0", "Process")
    [System.Environment]::SetEnvironmentVariable("SOURCE_DATE_EPOCH", $sourceDateEpoch, "Process")
    [System.Environment]::SetEnvironmentVariable("RUSTFLAGS", "-C link-arg=/Brepro", "Process")

    $buildArguments = @("build", "--frozen", "--offline", "--locked", "--release", "--workspace", "--bins", "--target", "x86_64-pc-windows-msvc")
    [void](Invoke-ReleaseCommand -Executable "cargo" -CommandArguments $buildArguments -WorkingDirectory $firstSource)
    [void](Invoke-ReleaseCommand -Executable "cargo" -CommandArguments $buildArguments -WorkingDirectory $secondSource)

    $binaryNames = @("approval-ui", "broker", "dashboard", "key-agent", "native-host", "secret-input-ui")
    $payloadRoots = @()
    $buildPairs = @(
        [pscustomobject]@{ Source = $firstSource; Payload = "payload-a" },
        [pscustomobject]@{ Source = $secondSource; Payload = "payload-b" }
    )
    foreach ($pair in $buildPairs) {
        $source = $pair.Source
        $payload = Join-Path $workRoot $pair.Payload
        [void](New-Item -ItemType Directory -Path $payload)
        foreach ($binaryName in $binaryNames) {
            $binary = Join-Path $source "target\x86_64-pc-windows-msvc\release\${binaryName}.exe"
            if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
                throw "Expected release binary was not produced: ${binaryName}.exe"
            }
            Copy-Item -LiteralPath $binary -Destination (Join-Path $payload "${binaryName}.exe")
        }
        [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @((Join-Path $PSScriptRoot "audit-extension.mjs"), "check", "--extension-root", (Join-Path $source "extension")) -WorkingDirectory $source)
        New-DeterministicExtensionZip -ExtensionRoot (Join-Path $source "extension") -OutputPath (Join-Path $payload "extension-package.zip")
        $payloadRoots += $payload
    }

    $firstInventory = Get-DirectoryInventory -LiteralPath $payloadRoots[0]
    $secondInventory = Get-DirectoryInventory -LiteralPath $payloadRoots[1]
    $firstJson = ConvertTo-CanonicalInventoryJson -Inventory $firstInventory
    $secondJson = ConvertTo-CanonicalInventoryJson -Inventory $secondInventory
    if (-not [System.String]::Equals($firstJson, $secondJson, [System.StringComparison]::Ordinal)) {
        throw "Two clean-directory unsigned builds are not byte-for-byte reproducible"
    }
    $unsignedSetSha256 = Get-InventorySha256 -Inventory $firstInventory
    foreach ($payloadFile in Get-ChildItem -LiteralPath $payloadRoots[0] -File) {
        Copy-Item -LiteralPath $payloadFile.FullName -Destination $unsignedOutput
    }

    Copy-Item -LiteralPath (Join-Path $RepoRoot "Cargo.lock") -Destination (Join-Path $evidence "Cargo.lock")
    Copy-Item -LiteralPath (Join-Path $RepoRoot "rust-toolchain.toml") -Destination (Join-Path $evidence "rust-toolchain.toml")
    $rustcVersion = (Invoke-ReleaseCommand -Executable "rustc" -CommandArguments @("-Vv") -WorkingDirectory $RepoRoot).Stdout.Replace("`r`n", "`n").TrimEnd([char[]]"`r`n") + "`n"
    $cargoVersion = (Invoke-ReleaseCommand -Executable "cargo" -CommandArguments @("-Vv") -WorkingDirectory $RepoRoot).Stdout.Replace("`r`n", "`n").TrimEnd([char[]]"`r`n") + "`n"
    Write-NewUtf8File -LiteralPath (Join-Path $evidence "rustc-vv.txt") -Content $rustcVersion
    Write-NewUtf8File -LiteralPath (Join-Path $evidence "cargo-vv.txt") -Content $cargoVersion

    $metadataResult = Invoke-ReleaseCommand -Executable "cargo" -CommandArguments @("metadata", "--frozen", "--offline", "--locked", "--all-features", "--filter-platform", "x86_64-pc-windows-msvc", "--format-version", "1") -WorkingDirectory $firstSource
    $metadataPath = Join-Path $workRoot "cargo-metadata.json"
    Write-NewUtf8File -LiteralPath $metadataPath -Content ($metadataResult.Stdout.Trim() + "`n")
    $cargoLockSha256 = Get-Sha256Lower -LiteralPath (Join-Path $evidence "Cargo.lock")
    [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
        (Join-Path $PSScriptRoot "generate-inventories.mjs"),
        "--metadata", $metadataPath,
        "--source-commit", $commit,
        "--cargo-lock-sha256", $cargoLockSha256,
        "--source-date-epoch", $sourceDateEpoch,
        "--target", "x86_64-pc-windows-msvc",
        "--dependency-output", (Join-Path $evidence "dependencies.json"),
        "--license-output", (Join-Path $evidence "licenses.json"),
        "--sbom-output", (Join-Path $evidence "sbom.spdx.json")
    ) -WorkingDirectory $RepoRoot)

    [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
        (Join-Path $PSScriptRoot "audit-extension.mjs"), "evidence",
        "--extension-root", (Join-Path $firstSource "extension"),
        "--package", (Join-Path $unsignedOutput "extension-package.zip"),
        "--output", (Join-Path $evidence "extension-audit.json")
    ) -WorkingDirectory $RepoRoot)

    $sourceArchiveSha256 = Get-Sha256Lower -LiteralPath (Join-Path $evidence "source.zip")
    $vendorInventorySha256 = Get-Sha256Lower -LiteralPath (Join-Path $evidence "vendor-inventory.json")
    $reproducibility = "{`"firstPayloadSetSha256`":`"${unsignedSetSha256}`",`"result`":`"pass`",`"schema`":`"your-wallet-reproducibility-evidence-v1`",`"secondPayloadSetSha256`":`"${unsignedSetSha256}`",`"sourceCommit`":`"${commit}`",`"sourceTreeSha256`":`"${sourceArchiveSha256}`",`"unsignedArtifactSetSha256`":`"${unsignedSetSha256}`",`"vendorTreeSha256`":`"${vendorInventorySha256}`"}`n"
    Write-NewUtf8File -LiteralPath (Join-Path $evidence "reproducibility.json") -Content $reproducibility

    $preparation = "{`"result`":`"not-release-eligible`",`"schema`":`"your-wallet-unsigned-preparation-v1`",`"sourceCommit`":`"${commit}`",`"unsignedArtifactSetSha256`":`"${unsignedSetSha256}`"}`n"
    Write-NewUtf8File -LiteralPath (Join-Path $staging "preparation.json") -Content $preparation
    Write-NewUtf8File -LiteralPath (Join-Path $staging "INELIGIBLE.txt") -Content "Unsigned preparation only. Platform signing, installer evidence, exact Windows negative tests, independent review, release-manifest signing, and offline verification remain mandatory.`n"

    Move-Item -LiteralPath $staging -Destination $OutputFull
    Write-Output "UNSIGNED_PREPARATION_COMPLETE_NOT_RELEASE_ELIGIBLE"
}
finally {
    [System.Environment]::SetEnvironmentVariable("CARGO_INCREMENTAL", $priorIncremental, "Process")
    [System.Environment]::SetEnvironmentVariable("SOURCE_DATE_EPOCH", $priorSourceDate, "Process")
    [System.Environment]::SetEnvironmentVariable("RUSTFLAGS", $priorRustFlags, "Process")
    if (Test-Path -LiteralPath $safeCleanupRoot) {
        Remove-Item -LiteralPath $safeCleanupRoot -Recurse -Force
    }
}
