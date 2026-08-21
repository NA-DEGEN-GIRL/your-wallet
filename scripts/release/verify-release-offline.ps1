$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-OfflineReleaseVerification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Manifest,
        [Parameter(Mandatory = $true)][string]$Signature,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKey,
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedReleaseKeyIdSha256,
        [Parameter(Mandatory = $true)][ValidatePattern("^[a-p]{32}$", Options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)][string]$ExpectedExtensionId,
        [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedReviewerKeyIdSha256,
        [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedSignerCertificateSha256,
        [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$", Options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)][string]$ExpectedVerifierToolsetSha256,
        [Parameter(Mandatory = $false)][string]$PreviousManifest,
        [Parameter(Mandatory = $false)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedPreviousManifestSha256,
        [Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation
    )

if (-not $OperatorConfirmedNetworkIsolation) {
    throw "Release verification refuses eligibility without an explicit offline-ceremony confirmation"
}
if ($env:OS -ne "Windows_NT") {
    throw "Private Mainnet Canary release verification requires Windows"
}

$hasPreviousManifest = -not [string]::IsNullOrWhiteSpace($PreviousManifest)
$hasPreviousHash = -not [string]::IsNullOrWhiteSpace($ExpectedPreviousManifestSha256)
if ($hasPreviousManifest -ne $hasPreviousHash) {
    throw "PreviousManifest and ExpectedPreviousManifestSha256 must be supplied together from the offline checkpoint"
}

$additionalInputs = @($Manifest, $Signature, $ReleasePublicKey)
if ($hasPreviousManifest) {
    $additionalInputs += $PreviousManifest
}

$toolset = $null
$releaseLocks = $null
try {
    $toolsetRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    $toolset = Open-VerifiedReleaseToolset `
        -ToolsetRoot $toolsetRoot `
        -ExpectedSha256 $ExpectedVerifierToolsetSha256
    $releaseLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $BundleRoot -AdditionalFiles $additionalInputs
    $bundle = $releaseLocks.CanonicalBundleRoot
    Assert-ReleaseTreesDisjoint `
        -LeftCanonicalRoot $toolset.CanonicalVolumeRoot `
        -RightCanonicalRoot $bundle
    $canonicalInputs = @($releaseLocks.CanonicalAdditionalFiles)
    $expectedInputCount = if ($hasPreviousManifest) { 4 } else { 3 }
    if ($canonicalInputs.Count -ne $expectedInputCount) {
        throw "Release verification did not pin the exact external input set"
    }
    $manifestPath = $canonicalInputs[0]
    $signaturePath = $canonicalInputs[1]
    $releasePublicKeyPath = $canonicalInputs[2]
    $previousManifestPath = if ($hasPreviousManifest) { $canonicalInputs[3] } else { $null }
    Assert-NoReparseTree -LiteralPath $bundle
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    $verifyArguments = @(
        "verify",
        "--manifest", $manifestPath,
        "--signature", $signaturePath,
        "--public-key", $releasePublicKeyPath,
        "--bundle-root", $bundle,
        "--expected-release-key-id", $ExpectedReleaseKeyIdSha256,
        "--expected-extension-id", $ExpectedExtensionId,
        "--expected-reviewer-key-id", $ExpectedReviewerKeyIdSha256,
        "--expected-signer-certificate-sha256", $ExpectedSignerCertificateSha256
    )
    if ($hasPreviousManifest) {
        $verifyArguments += @(
            "--previous", $previousManifestPath,
            "--expected-previous-manifest-sha256", $ExpectedPreviousManifestSha256
        )
    }
    $firstPass = Invoke-ReleaseToolsetNode `
        -Toolset $toolset `
        -ScriptRelativePath "scripts/release/release-manifest.mjs" `
        -CommandArguments $verifyArguments
    $expectedVerifierOutput = "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER`n"
    if ($firstPass.ExitCode -ne 0 -or
        -not [string]::Equals($firstPass.Stderr, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($firstPass.Stdout, $expectedVerifierOutput, [System.StringComparison]::Ordinal)) {
        throw "Cryptographic release verification produced an invalid first-pass result"
    }

    $payloadFiles = @(
        "approval-ui.exe",
        "broker.exe",
        "dashboard.exe",
        "key-agent.exe",
        "native-host.exe",
        "secret-input-ui.exe",
        "your-wallet-canary.msi"
    )
    foreach ($fileName in $payloadFiles) {
        $filePath = Join-Path $bundle "payload\$fileName"
        $signatureStatus = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $filePath
        if ($signatureStatus.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signatureStatus.SignerCertificate) {
            throw "Offline Authenticode re-verification failed closed"
        }
        $certificateHasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $certificateBytes = $certificateHasher.ComputeHash($signatureStatus.SignerCertificate.RawData)
        }
        finally {
            $certificateHasher.Dispose()
        }
        $certificateHash = [System.BitConverter]::ToString($certificateBytes).Replace("-", "").ToLowerInvariant()
        if (-not [System.String]::Equals($certificateHash, $ExpectedSignerCertificateSha256, [System.StringComparison]::Ordinal)) {
            throw "Offline Authenticode signer does not match the independently pinned certificate"
        }
    }

    # The held no-write/no-delete file handles bind both verification passes and
    # Authenticode inspection to the same bytes. The second pass also rejects a
    # new unlisted tree entry that appeared during inspection.
    Assert-NoReparseTree -LiteralPath $bundle
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    $secondPass = Invoke-ReleaseToolsetNode `
        -Toolset $toolset `
        -ScriptRelativePath "scripts/release/release-manifest.mjs" `
        -CommandArguments $verifyArguments
    if ($secondPass.ExitCode -ne 0 -or
        -not [string]::Equals($secondPass.Stderr, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($secondPass.Stdout, $expectedVerifierOutput, [System.StringComparison]::Ordinal)) {
        throw "Cryptographic release verification produced an invalid second-pass result"
    }

    [Console]::Out.Write("PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION`n")
}
finally {
    try {
        if ($null -ne $releaseLocks) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $releaseLocks
        }
    }
    finally {
        if ($null -ne $toolset) {
            Close-VerifiedReleaseToolset -Toolset $toolset
        }
    }
}
}

try {
    . (Join-Path $PSScriptRoot "common.ps1")
    $boundArguments = ConvertFrom-ExactNamedArguments `
        -Arguments @($args) `
        -RequiredValueNames @(
            "Manifest",
            "Signature",
            "ReleasePublicKey",
            "BundleRoot",
            "ExpectedReleaseKeyIdSha256",
            "ExpectedExtensionId",
            "ExpectedReviewerKeyIdSha256",
            "ExpectedSignerCertificateSha256",
            "ExpectedVerifierToolsetSha256"
        ) `
        -OptionalValueNames @("PreviousManifest", "ExpectedPreviousManifestSha256") `
        -RequiredSwitchNames @("OperatorConfirmedNetworkIsolation")
    Invoke-OfflineReleaseVerification @boundArguments
}
catch {
    [Console]::Error.WriteLine("RELEASE_VERIFICATION_FAILED: offline release verification failed closed")
    exit 1
}
