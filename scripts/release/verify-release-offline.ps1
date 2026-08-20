[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Manifest,
    [Parameter(Mandatory = $true)][string]$Signature,
    [Parameter(Mandatory = $true)][string]$ReleasePublicKey,
    [Parameter(Mandatory = $true)][string]$BundleRoot,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedReleaseKeyIdSha256,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedReviewerKeyIdSha256,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedSignerCertificateSha256,
    [Parameter(Mandatory = $false)][string]$PreviousManifest,
    [Parameter(Mandatory = $false)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedPreviousManifestSha256,
    [Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "common.ps1")

if (-not $OperatorConfirmedNetworkIsolation) {
    throw "Release verification refuses eligibility without an explicit offline-ceremony confirmation"
}
if ($env:OS -ne "Windows_NT") {
    throw "Private Mainnet Canary release verification requires Windows"
}
foreach ($tool in @("node")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required release verification tool is unavailable: $tool"
    }
}

$hasPreviousManifest = -not [string]::IsNullOrWhiteSpace($PreviousManifest)
$hasPreviousHash = -not [string]::IsNullOrWhiteSpace($ExpectedPreviousManifestSha256)
if ($hasPreviousManifest -ne $hasPreviousHash) {
    throw "PreviousManifest and ExpectedPreviousManifestSha256 must be supplied together from the offline checkpoint"
}

$bundle = (Resolve-Path -LiteralPath $BundleRoot).Path
$manifestPath = (Resolve-Path -LiteralPath $Manifest).Path
$signaturePath = (Resolve-Path -LiteralPath $Signature).Path
$releasePublicKeyPath = (Resolve-Path -LiteralPath $ReleasePublicKey).Path
$previousManifestPath = if ($hasPreviousManifest) { (Resolve-Path -LiteralPath $PreviousManifest).Path } else { $null }
$additionalInputs = @($manifestPath, $signaturePath, $releasePublicKeyPath)
if ($null -ne $previousManifestPath) {
    $additionalInputs += $previousManifestPath
}

Assert-NoReparseTree -LiteralPath $bundle
$releaseLocks = $null
try {
    $releaseLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $bundle -AdditionalFiles $additionalInputs
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    $verifyArguments = @(
        (Join-Path $PSScriptRoot "release-manifest.mjs"), "verify",
        "--manifest", $manifestPath,
        "--signature", $signaturePath,
        "--public-key", $releasePublicKeyPath,
        "--bundle-root", $bundle,
        "--expected-release-key-id", $ExpectedReleaseKeyIdSha256,
        "--expected-reviewer-key-id", $ExpectedReviewerKeyIdSha256,
        "--expected-signer-certificate-sha256", $ExpectedSignerCertificateSha256
    )
    if ($hasPreviousManifest) {
        $verifyArguments += @(
            "--previous", $previousManifestPath,
            "--expected-previous-manifest-sha256", $ExpectedPreviousManifestSha256
        )
    }
    [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments $verifyArguments -WorkingDirectory $bundle)

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
        $signatureStatus = Get-AuthenticodeSignature -LiteralPath $filePath
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
    [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments $verifyArguments -WorkingDirectory $bundle)

    Write-Output "PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION"
}
finally {
    if ($null -ne $releaseLocks) {
        Close-ReadOnlyReleaseTreeLocks -LockSet $releaseLocks
    }
}
