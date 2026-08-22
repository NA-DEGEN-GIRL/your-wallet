$PSModuleAutoLoadingPreference = "None"
$ErrorActionPreference = "Stop"
$script:ReleasePowerShellEntryScriptPath = $PSCommandPath

function Invoke-ReviewEvidenceSetCeremony {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$", Options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)][string]$ExpectedVerifierToolsetSha256,
        [Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation
    )

if (-not $OperatorConfirmedNetworkIsolation) {
    throw "Independent review evidence hashing requires an explicit offline-ceremony confirmation"
}
if ($env:OS -ne "Windows_NT") {
    throw "Independent review evidence hashing requires Windows"
}

$toolset = $null
$releaseLocks = $null
try {
    $toolsetRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    $toolset = Open-VerifiedReleaseToolset `
        -ToolsetRoot $toolsetRoot `
        -ExpectedSha256 $ExpectedVerifierToolsetSha256
    $releaseLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $BundleRoot
    $bundle = $releaseLocks.CanonicalBundleRoot
    Assert-ReleaseTreesDisjoint `
        -LeftCanonicalRoot $toolset.CanonicalVolumeRoot `
        -RightCanonicalRoot $bundle
    Assert-NoReparseTree -LiteralPath $bundle
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    $result = Invoke-ReleaseToolsetNode `
        -Toolset $toolset `
        -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
        -CommandArguments @("--bundle-root", $bundle)
    if ($result.ExitCode -ne 0) {
        throw "Independent review evidence hashing failed closed"
    }
    if (-not [string]::Equals($result.Stderr, "", [System.StringComparison]::Ordinal)) {
        throw "Independent review evidence hashing produced unexpected diagnostics"
    }
    $subjectPattern = '\A\{"reviewedEvidenceSetSha256":"[0-9a-f]{64}","schema":"your-wallet-reviewed-evidence-set-subject-v1"\}\n\z'
    if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
        $result.Stdout,
        $subjectPattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )) {
        throw "Independent review evidence hashing returned an invalid subject"
    }
    Assert-NoReparseTree -LiteralPath $bundle
    Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $bundle
    [Console]::Out.Write($result.Stdout)
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
    . ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))
    $boundArguments = ConvertFrom-ExactNamedArguments `
        -Arguments @($args) `
        -RequiredValueNames @("BundleRoot", "ExpectedVerifierToolsetSha256") `
        -RequiredSwitchNames @("OperatorConfirmedNetworkIsolation")
    Invoke-ReviewEvidenceSetCeremony @boundArguments
}
catch {
    [Console]::Error.WriteLine("REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed")
    exit 1
}
