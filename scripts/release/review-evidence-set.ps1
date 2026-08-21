$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-ReviewEvidenceSetCeremony {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation
    )

if (-not $OperatorConfirmedNetworkIsolation) {
    throw "Independent review evidence hashing requires an explicit offline-ceremony confirmation"
}
if ($env:OS -ne "Windows_NT") {
    throw "Independent review evidence hashing requires Windows"
}
if (-not (Get-Command "node" -ErrorAction SilentlyContinue)) {
    throw "Required review evidence tool is unavailable"
}

$releaseLocks = $null
try {
    $releaseLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $BundleRoot
    $bundle = $releaseLocks.CanonicalBundleRoot
    Assert-NoReparseTree -LiteralPath $bundle
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    $result = Invoke-ReleaseCommand `
        -Executable "node" `
        -CommandArguments @(
            (Join-Path $PSScriptRoot "review-evidence-set.mjs"),
            "--bundle-root",
            $bundle
        ) `
        -WorkingDirectory $PSScriptRoot
    if (-not [string]::IsNullOrEmpty($result.Stderr)) {
        throw "Independent review evidence hashing produced unexpected diagnostics"
    }
    $subjectPattern = '^\{"reviewedEvidenceSetSha256":"[0-9a-f]{64}","schema":"your-wallet-reviewed-evidence-set-subject-v1"\}$'
    if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
        $result.Stdout,
        $subjectPattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )) {
        throw "Independent review evidence hashing returned an invalid subject"
    }
    Assert-NoReparseTree -LiteralPath $bundle
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    Write-Output $result.Stdout
}
finally {
    if ($null -ne $releaseLocks) {
        Close-ReadOnlyReleaseTreeLocks -LockSet $releaseLocks
    }
}
}

try {
    . (Join-Path $PSScriptRoot "common.ps1")
    $boundArguments = ConvertFrom-ExactNamedArguments `
        -Arguments @($args) `
        -RequiredValueNames @("BundleRoot") `
        -RequiredSwitchNames @("OperatorConfirmedNetworkIsolation")
    Invoke-ReviewEvidenceSetCeremony @boundArguments
}
catch {
    [Console]::Error.WriteLine("REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed")
    exit 1
}
