[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PayloadDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ArtifactSetSha256,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$ExpectedSignerCertificateSha256,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$PSModuleAutoLoadingPreference = "None"
$ErrorActionPreference = "Stop"
$script:ReleasePowerShellEntryScriptPath = $PSCommandPath
. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))

if ($env:OS -ne "Windows_NT") {
    throw "Authenticode verification requires Windows"
}

function Assert-ExactAuthenticodePayloadInventory {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][string[]]$RequiredFiles
    )

    $actualEntries = @(Get-ChildItem -LiteralPath $PayloadRoot -Force)
    $actualFiles = @(
        $actualEntries |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    $expectedFiles = @($RequiredFiles | Sort-Object)
    if (
        $actualEntries.Count -ne $RequiredFiles.Count -or
        ($actualFiles -join "`n") -cne ($expectedFiles -join "`n")
    ) {
        throw "Payload directory must contain exactly the reviewed release artifact set"
    }
}

function Close-PinnedAuthenticodeFilePath {
    param([Parameter(Mandatory = $false)][AllowNull()][object]$Pin)

    if ($null -eq $Pin) {
        return
    }
    try {
        $Pin.FileHandle.Dispose()
    }
    finally {
        foreach ($handle in $Pin.DirectoryHandles) {
            $handle.Dispose()
        }
    }
}

$outputLeaf = [System.IO.Path]::GetFileName($OutputPath)
if (
    [string]::IsNullOrWhiteSpace($outputLeaf) -or
    $outputLeaf.Length -gt 255 -or
    $outputLeaf.EndsWith(".", [System.StringComparison]::Ordinal) -or
    -not [System.Text.RegularExpressions.Regex]::IsMatch(
        $outputLeaf,
        '^[A-Za-z0-9][A-Za-z0-9._-]*$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
) {
    throw "Authenticode evidence output must use one plain printable-ASCII file name"
}
$outputFull = [System.IO.Path]::GetFullPath($OutputPath)
if (-not [System.String]::Equals(
    [System.IO.Path]::GetFileName($outputFull),
    $outputLeaf,
    [System.StringComparison]::Ordinal
)) {
    throw "Authenticode evidence output file name changed during normalization"
}
$outputParentInput = [System.IO.Path]::GetDirectoryName($outputFull)
if (
    [string]::IsNullOrWhiteSpace($outputParentInput) -or
    [System.String]::Equals(
        $outputParentInput.TrimEnd("\"),
        [System.IO.Path]::GetPathRoot($outputFull).TrimEnd("\"),
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [System.IO.Directory]::Exists($outputParentInput)
) {
    throw "Authenticode evidence output requires one existing non-root parent"
}

$requiredFiles = @(
    "approval-ui.exe",
    "broker.exe",
    "dashboard.exe",
    "extension-package.zip",
    "key-agent-debugger.exe",
    "key-agent.exe",
    "native-host.exe",
    "secret-input-ui.exe",
    "your-wallet-canary.msi"
)
$outputParentPin = $null
$outputFilePin = $null
$payloadLocks = $null
$inspectorPin = $null
try {
    $outputParentPin = Open-PinnedReleaseDirectoryPath -LiteralPath $outputParentInput
    $outputParent = $outputParentPin.CanonicalPath
    if (@(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $outputParent).Count -eq 1) {
        throw "Authenticode evidence output parent must not alias a volume root"
    }
    $OutputPath = [System.IO.Path]::Combine($outputParent, $outputLeaf)
    $existingOutputEntries = @(
        [System.IO.DirectoryInfo]::new($outputParent).GetFileSystemInfos() |
            Where-Object {
                [System.String]::Equals(
                    $_.Name,
                    $outputLeaf,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($existingOutputEntries.Count -ne 0) {
        throw "Authenticode evidence output already exists"
    }

    $payloadLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $PayloadDirectory
    $payloadRoot = $payloadLocks.CanonicalBundleRoot
    Assert-NoReparseTree -LiteralPath $payloadRoot
    $canonicalPayload = $payloadRoot.TrimEnd("\")
    $canonicalOutputParent = $outputParent.TrimEnd("\")
    if (
        [System.String]::Equals(
            $canonicalOutputParent,
            $canonicalPayload,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        $canonicalOutputParent.StartsWith(
            $canonicalPayload + "\",
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Authenticode evidence output must be outside the held payload tree"
    }
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $payloadRoot
    Assert-ExactAuthenticodePayloadInventory `
        -PayloadRoot $payloadRoot `
        -RequiredFiles $requiredFiles

    $entries = [System.Collections.Generic.List[object]]::new()
    $debuggerVersionInspector = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot "assert-key-agent-debugger-version.ps1")
    )
    $inspectorPin = Open-PinnedReleaseFilePath -LiteralPath $debuggerVersionInspector
    $debuggerVersionInspector = $inspectorPin.CanonicalPath
    # The fixed array is already in canonical payload-path order. The Node verifier
    # compares the report positionally in that same order.
    foreach ($fileName in $requiredFiles | Where-Object { $_ -ne "extension-package.zip" }) {
        $filePath = Join-Path $payloadRoot $fileName
        if ([System.String]::Equals(
            $fileName,
            "key-agent-debugger.exe",
            [System.StringComparison]::Ordinal
        )) {
            & $debuggerVersionInspector -ExecutablePath $filePath
        }
        $signature = Get-ReleaseAuthenticodeSignature -LiteralPath $filePath
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
        '{"path":"' + [string]$entry.path +
            '","sha256":"' + [string]$entry.sha256 +
            '","signerCertificateSha256":"' + [string]$entry.signerCertificateSha256 +
            '","status":"valid"}'
    }
    $report = '{"artifactSetSha256":"' + $ArtifactSetSha256 +
        '","entries":[' + ($entryJson -join ',') +
        '],"result":"pass","schema":"your-wallet-authenticode-evidence-v1"}' + "`n"
    Assert-NoReparseTree -LiteralPath $payloadRoot
    Assert-ExactAuthenticodePayloadInventory `
        -PayloadRoot $payloadRoot `
        -RequiredFiles $requiredFiles
    Write-NewUtf8File -LiteralPath $OutputPath -Content $report
    $outputFilePin = Open-PinnedReleaseFilePath -LiteralPath $OutputPath
    if (-not [System.String]::Equals(
        $outputFilePin.CanonicalPath,
        $OutputPath,
        [System.StringComparison]::Ordinal
    )) {
        throw "Authenticode evidence output identity changed after creation"
    }
    $expectedOutputBytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($report)
    $actualOutputBytes = [System.IO.File]::ReadAllBytes($outputFilePin.CanonicalPath)
    if ($actualOutputBytes.Count -ne $expectedOutputBytes.Count) {
        throw "Authenticode evidence output bytes changed after creation"
    }
    for ($byteIndex = 0; $byteIndex -lt $expectedOutputBytes.Count; $byteIndex += 1) {
        if ($actualOutputBytes[$byteIndex] -ne $expectedOutputBytes[$byteIndex]) {
            throw "Authenticode evidence output bytes changed after creation"
        }
    }
    Write-Output "AUTHENTICODE_EVIDENCE_WRITTEN"
}
finally {
    try {
        Close-PinnedAuthenticodeFilePath -Pin $outputFilePin
    }
    finally {
        try {
            Close-PinnedAuthenticodeFilePath -Pin $inspectorPin
        }
        finally {
            try {
                if ($null -ne $payloadLocks) {
                    Close-ReadOnlyReleaseTreeLocks -LockSet $payloadLocks
                }
            }
            finally {
                if ($null -ne $outputParentPin) {
                    foreach ($handle in $outputParentPin.DirectoryHandles) {
                        $handle.Dispose()
                    }
                }
            }
        }
    }
}
