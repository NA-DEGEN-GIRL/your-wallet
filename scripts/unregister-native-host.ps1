# scripts/unregister-native-host.ps1 - removes the current user's Chrome native messaging host registration (spec/05 9.2).
# Works on Windows PowerShell 5.1 and PowerShell 7. Never touches the vault or settings (%LOCALAPPDATA%\YourWallet\v3\).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\unregister-native-host.ps1 [-BinDir <dir>] [-RemoveBinaries]
[CmdletBinding()]
param(
    [string]$BinDir = "$env:LOCALAPPDATA\YourWallet\bin",
    [switch]$RemoveBinaries
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = 'com.your_wallet.native'
$RegistryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"

if ([string]::IsNullOrWhiteSpace($BinDir) -or (-not $PSBoundParameters.ContainsKey('BinDir') -and [string]::IsNullOrEmpty($env:LOCALAPPDATA))) {
    [Console]::Error.WriteLine('unregister-native-host: BinDir is empty or LOCALAPPDATA is not set; pass -BinDir explicitly.')
    exit 1
}
$BinDir = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BinDir))
if ($BinDir.Length -gt 3) { $BinDir = $BinDir.TrimEnd('\') }

if (Test-Path -LiteralPath $RegistryKey) {
    Remove-Item -LiteralPath $RegistryKey -Recurse -Force
    Write-Host "Removed registry key $RegistryKey"
} else {
    Write-Host "Registry key not present: $RegistryKey"
}

$manifestPath = Join-Path $BinDir "$HostName.json"
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    Remove-Item -LiteralPath $manifestPath -Force
    Write-Host "Removed $manifestPath"
}

if ($RemoveBinaries) {
    foreach ($name in @('yw-host.exe', 'yw-app.exe')) {
        $binary = Join-Path $BinDir $name
        if (Test-Path -LiteralPath $binary -PathType Leaf) {
            try {
                Remove-Item -LiteralPath $binary -Force
                Write-Host "Removed $binary"
            } catch {
                [Console]::Error.WriteLine("unregister-native-host: could not remove $binary ($($_.Exception.Message)). Close yw-app and Chrome, then run again.")
                exit 1
            }
        }
    }
}
Write-Host 'Done. The vault and settings were not touched.'
