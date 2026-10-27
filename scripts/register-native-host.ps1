# scripts/register-native-host.ps1 - registers the Chrome native messaging host for the current user (spec/05 9.1).
# Works on Windows PowerShell 5.1 and PowerShell 7. HKCU only; no administrator rights.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-native-host.ps1 [-BinDir <dir>] [-BuildProfile release|debug]
[CmdletBinding()]
param(
    [string]$BinDir = "$env:LOCALAPPDATA\YourWallet\bin",
    [ValidateSet('release', 'debug')] [string]$BuildProfile = 'release'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = 'com.your_wallet.native'
$RegistryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Stop-Registration([string]$Message) {
    [Console]::Error.WriteLine("register-native-host: $Message")
    exit 1
}

# 1. The manifest key must produce extension/extension-id.txt.
& node (Join-Path $Root 'scripts\extension-key.mjs') check
if ($LASTEXITCODE -ne 0) { Stop-Registration 'extension ID check failed (node scripts/extension-key.mjs check).' }
$extensionId = ([IO.File]::ReadAllText((Join-Path $Root 'extension\extension-id.txt'))).Trim()
if ($extensionId -cnotmatch '^[a-p]{32}$') { Stop-Registration 'extension/extension-id.txt does not contain a 32-character a-p ID.' }

# 2. Absolute, normalized BinDir without cmd.exe metacharacters (Chrome may launch the host through cmd.exe).
if ([string]::IsNullOrWhiteSpace($BinDir) -or (-not $PSBoundParameters.ContainsKey('BinDir') -and [string]::IsNullOrEmpty($env:LOCALAPPDATA))) {
    Stop-Registration 'BinDir is empty or LOCALAPPDATA is not set; pass -BinDir explicitly.'
}
$BinDir = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BinDir))
if ($BinDir.Length -gt 3) { $BinDir = $BinDir.TrimEnd('\') }
if ($BinDir -match '["%&^|<>!]' -or $BinDir -match '[\x00-\x1f\x7f]') {
    Stop-Registration "BinDir contains a character that is unsafe for cmd.exe: $BinDir"
}

# 3. Copy the built executables.
$targetDir = Join-Path $Root "target\$BuildProfile"
$sourceHost = Join-Path $targetDir 'yw-host.exe'
$sourceApp = Join-Path $targetDir 'yw-app.exe'
if (-not (Test-Path -LiteralPath $sourceHost -PathType Leaf) -or -not (Test-Path -LiteralPath $sourceApp -PathType Leaf)) {
    $buildCommand = 'cargo build -p yw-host -p yw-app'
    if ($BuildProfile -eq 'release') { $buildCommand += ' --release' }
    Stop-Registration "target\$BuildProfile\yw-host.exe or yw-app.exe is missing. Build first: $buildCommand"
}
$hostExe = Join-Path $BinDir 'yw-host.exe'
try {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item -LiteralPath $sourceHost -Destination $hostExe -Force
    Copy-Item -LiteralPath $sourceApp -Destination (Join-Path $BinDir 'yw-app.exe') -Force
} catch {
    Stop-Registration "copying the executables failed ($($_.Exception.Message)). Close yw-app and Chrome, then run this script again."
}

# 4. Native messaging manifest (UTF-8 without BOM).
$manifestPath = Join-Path $BinDir "$HostName.json"
$manifest = [ordered]@{
    name            = $HostName
    description     = 'Your Wallet native messaging host'
    path            = $hostExe
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$extensionId/")
}
$json = ConvertTo-Json -InputObject $manifest -Depth 3
[IO.File]::WriteAllText($manifestPath, $json, [Text.UTF8Encoding]::new($false))

# 5. Validate what was written.
& node (Join-Path $Root 'extension\native-host\validate-manifest.mjs') $manifestPath --expect-id $extensionId
if ($LASTEXITCODE -ne 0) { Stop-Registration "native host manifest validation failed: $manifestPath" }

# 6. Register for the current user and read the value back.
New-Item -Path $RegistryKey -Value $manifestPath -Force | Out-Null
$registered = (Get-Item -LiteralPath $RegistryKey).GetValue('')
if ($registered -ne $manifestPath) { Stop-Registration "registry read-back mismatch at $RegistryKey" }

# 7. Report and next steps (spec/05 9.4).
Write-Host "Extension ID : $extensionId"
Write-Host "Manifest     : $manifestPath"
Write-Host "Registry     : $RegistryKey"
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. chrome://extensions -> Developer mode -> Load unpacked -> select the repository extension folder.'
Write-Host "  2. Confirm the displayed extension ID is $extensionId."
Write-Host '  3. After changing extension sources, reload the extension card and reload open tabs.'
Write-Host "  4. Run yw-app from $BinDir (yw-host starts the yw-app next to itself)."
