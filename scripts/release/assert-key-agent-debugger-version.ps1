param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$candidate = [System.IO.FileInfo]::new([System.IO.Path]::GetFullPath($ExecutablePath))
if (
    -not $candidate.Exists -or
    ($candidate.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
    ($candidate.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $candidate.Name -cne "key-agent-debugger.exe"
) {
    throw "Key Agent debugger version inspection requires the exact real executable"
}

$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($candidate.FullName)
if (
    $version.FileMajorPart -ne 0 -or
    $version.FileMinorPart -ne 1 -or
    $version.FileBuildPart -ne 0 -or
    $version.FilePrivatePart -ne 0 -or
    $version.ProductMajorPart -ne 0 -or
    $version.ProductMinorPart -ne 1 -or
    $version.ProductBuildPart -ne 0 -or
    $version.ProductPrivatePart -ne 0 -or
    $version.FileDescription -cne "Your Wallet Key Agent Debugger" -or
    $version.FileVersion -cne "0.1.0.0" -or
    $version.InternalName -cne "key-agent-debugger" -or
    $version.OriginalFilename -cne "key-agent-debugger.exe" -or
    $version.ProductName -cne "Your Wallet" -or
    $version.ProductVersion -cne "0.1.0.0"
) {
    throw "Key Agent debugger VERSIONINFO did not match the unsigned release-candidate contract"
}
