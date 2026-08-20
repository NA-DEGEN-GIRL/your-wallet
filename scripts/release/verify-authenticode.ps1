[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PayloadDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ArtifactSetSha256,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedSignerCertificateSha256,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "common.ps1")

if ($env:OS -ne "Windows_NT") {
    throw "Authenticode verification requires Windows"
}
$payloadRoot = (Resolve-Path -LiteralPath $PayloadDirectory).Path
Assert-NoReparseTree -LiteralPath $payloadRoot
if (Test-Path -LiteralPath $OutputPath) {
    throw "Authenticode evidence output already exists"
}

$requiredFiles = @(
    "approval-ui.exe",
    "broker.exe",
    "dashboard.exe",
    "extension-package.zip",
    "key-agent.exe",
    "native-host.exe",
    "secret-input-ui.exe",
    "your-wallet-canary.msi"
)
$actualEntries = @(Get-ChildItem -LiteralPath $payloadRoot -Force)
$actualFiles = @($actualEntries | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.Name } | Sort-Object)
$expectedFiles = @($requiredFiles | Sort-Object)
if ($actualEntries.Count -ne $requiredFiles.Count -or ($actualFiles -join "`n") -cne ($expectedFiles -join "`n")) {
    throw "Payload directory must contain exactly the reviewed release artifact set"
}

$entries = [System.Collections.Generic.List[object]]::new()
# The fixed array is already in canonical payload-path order. The Node verifier
# compares the report positionally in that same order.
foreach ($fileName in $requiredFiles | Where-Object { $_ -ne "extension-package.zip" }) {
    $filePath = Join-Path $payloadRoot $fileName
    $signature = Get-AuthenticodeSignature -LiteralPath $filePath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed closed for a required payload"
    }
    $certificateHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $certificateBytes = $certificateHasher.ComputeHash($signature.SignerCertificate.RawData)
    }
    finally {
        $certificateHasher.Dispose()
    }
    $certificateHash = [System.BitConverter]::ToString($certificateBytes).Replace("-", "").ToLowerInvariant()
    if (-not [System.String]::Equals($certificateHash, $ExpectedSignerCertificateSha256, [System.StringComparison]::Ordinal)) {
        throw "Authenticode signer certificate does not match the independently pinned release identity"
    }
    $entries.Add([ordered]@{
        path = "payload/$fileName"
        sha256 = Get-Sha256Lower -LiteralPath $filePath
        signerCertificateSha256 = $certificateHash
        status = "valid"
    })
}

$entryJson = foreach ($entry in $entries) {
    "{`"path`":`"$($entry.path)`",`"sha256`":`"$($entry.sha256)`",`"signerCertificateSha256`":`"$($entry.signerCertificateSha256)`",`"status`":`"valid`"}"
}
$report = "{`"artifactSetSha256`":`"${ArtifactSetSha256}`",`"entries`":[$($entryJson -join ',')],`"result`":`"pass`",`"schema`":`"your-wallet-authenticode-evidence-v1`"}`n"
Write-NewUtf8File -LiteralPath $OutputPath -Content $report
Write-Output "AUTHENTICODE_EVIDENCE_WRITTEN"
