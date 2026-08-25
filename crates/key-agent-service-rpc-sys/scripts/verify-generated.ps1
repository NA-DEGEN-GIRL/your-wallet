[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sdkVersion = '10.0.26100.0'
$midlCompilerVersion = '8.01.0628'
$vcToolsVersion = '14.44.35207'
$expectedMidlHash = '57ff0546270ea51e61f87a121f1cc1ea09d100c7ca6e0172a8b3e0b988ab778f'
$expectedMidlcHash = 'b27b8ef9758a7d4b39c622b9fa78ee2f7f8c2601996f1daccbff48c810484915'
$expectedClHash = 'f444d471f7926f50928945f16a53081adb276f599db1dfc3aa2cf4bcf20ece17'
$expectedIdlHash = 'afebe677da4c26a3ca12a56226a9b368a169d7d3f537d62b9eacb5a3d3240074'
$expectedAcfHash = '6159cfe33142e89d14714efbb3801931368b5b549247283295031ae22e265e2b'
$clientPrefix = 'YwkasRpcClient_'
$serverPrefix = 'YwkasRpcServer_'
$artifactNames = @(
    'key_agent_service_rpc.h',
    'key_agent_service_rpc_c.c',
    'key_agent_service_rpc_s.c'
)

$crateRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$idlRelative = 'idl\key_agent_service_rpc.idl'
$acfRelative = 'idl\key_agent_service_rpc.acf'
$checkedGenerated = Join-Path $crateRoot 'generated'
$manifestPath = Join-Path $checkedGenerated 'artifacts.sha256'

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdkBin = Join-Path $kitsRoot "bin\$sdkVersion\x64"
$midl = Join-Path $sdkBin 'midl.exe'
$midlc = Join-Path $sdkBin 'midlc.exe'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

foreach ($required in @($midl, $midlc, $vswhere, $manifestPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required pinned generation input is unavailable: $(Split-Path -Leaf $required)"
    }
}

$vsInstall = (& $vswhere -latest -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($vsInstall)) {
    throw 'Visual Studio C++ x64 tools are unavailable'
}

$cl = Join-Path $vsInstall "VC\Tools\MSVC\$vcToolsVersion\bin\Hostx64\x64\cl.exe"
if (-not (Test-Path -LiteralPath $cl -PathType Leaf)) {
    throw 'Visual Studio x64 C preprocessor is unavailable'
}

function Get-LowerSha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if ((Get-LowerSha256 $midl) -ne $expectedMidlHash -or
    (Get-LowerSha256 $midlc) -ne $expectedMidlcHash -or
    (Get-LowerSha256 $cl) -ne $expectedClHash) {
    throw 'Pinned MIDL/MSVC tool hash mismatch'
}
if ((Get-LowerSha256 (Join-Path $crateRoot $idlRelative)) -ne $expectedIdlHash -or
    (Get-LowerSha256 (Join-Path $crateRoot $acfRelative)) -ne $expectedAcfHash) {
    throw 'Canonical IDL/ACF source hash mismatch'
}

function Assert-ByteEqual(
    [string] $Expected,
    [string] $Actual,
    [string] $Label
) {
    $expectedHash = Get-LowerSha256 $Expected
    $actualHash = Get-LowerSha256 $Actual
    if ($expectedHash -eq $actualHash) {
        return
    }

    $expectedBytes = [IO.File]::ReadAllBytes($Expected)
    $actualBytes = [IO.File]::ReadAllBytes($Actual)
    $limit = [Math]::Min($expectedBytes.Length, $actualBytes.Length)
    $firstDifference = $limit
    for ($index = 0; $index -lt $limit; ++$index) {
        if ($expectedBytes[$index] -ne $actualBytes[$index]) {
            $firstDifference = $index
            break
        }
    }

    throw "$Label differs at byte $firstDifference (expected $expectedHash, actual $actualHash)"
}

function Invoke-PinnedMidl([string] $OutputDirectory) {
    [void][IO.Directory]::CreateDirectory($OutputDirectory)

    $arguments = @(
        '/nologo',
        '/env', 'x64',
        '/Oicf',
        '/robust',
        '/protocol', 'dce',
        '/char', 'signed',
        '/W4',
        '/acf', $acfRelative,
        '/out', $OutputDirectory,
        '/h', 'key_agent_service_rpc.h',
        '/cstub', 'key_agent_service_rpc_c.c',
        '/sstub', 'key_agent_service_rpc_s.c',
        '/client', 'stub',
        '/server', 'stub',
        '/prefix', 'client', $clientPrefix,
        '/prefix', 'server', $serverPrefix,
        $idlRelative
    )

    $oldPath = $env:Path
    $oldPreference = $ErrorActionPreference
    try {
        $env:Path = "$(Split-Path -Parent $cl);$oldPath"
        $ErrorActionPreference = 'Continue'
        Push-Location $crateRoot
        try {
            $messages = @(& $midl @arguments 2>&1 | ForEach-Object { $_.ToString() })
            $exitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:Path = $oldPath
        $ErrorActionPreference = $oldPreference
    }

    if ($exitCode -ne 0) {
        throw "Pinned MIDL failed with exit code ${exitCode}: $($messages -join ' | ')"
    }
    foreach ($name in $artifactNames) {
        if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory $name) -PathType Leaf)) {
            throw "Pinned MIDL omitted expected artifact $name"
        }
    }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ("ywkas-rpc-midl-" + [guid]::NewGuid().ToString('N'))))
$tempPrefix = $tempBase.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $tempRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to create verification directory outside the system temporary directory'
}

$runA = Join-Path $tempRoot 'run-a'
$runB = Join-Path $tempRoot 'run-b'

try {
    Invoke-PinnedMidl $runA
    Invoke-PinnedMidl $runB

    foreach ($name in $artifactNames) {
        Assert-ByteEqual (Join-Path $runA $name) (Join-Path $runB $name) "two-run $name"
        Assert-ByteEqual (Join-Path $checkedGenerated $name) (Join-Path $runA $name) "checked-in $name"
    }

    $header = Get-Content -LiteralPath (Join-Path $runA 'key_agent_service_rpc.h') -Raw
    $client = Get-Content -LiteralPath (Join-Path $runA 'key_agent_service_rpc_c.c') -Raw
    $server = Get-Content -LiteralPath (Join-Path $runA 'key_agent_service_rpc_s.c') -Raw
    $shim = Get-Content -LiteralPath (Join-Path $crateRoot 'native\key_agent_service_rpc_shim.c') -Raw

    if ($header -notmatch "MIDL compiler version $([regex]::Escape($midlCompilerVersion))") {
        throw 'Generated compiler banner does not match the pinned MIDL compiler version'
    }
    if ($header -notmatch 'at Tue Jan 19 12:14:07 2038') {
        throw 'MIDL deterministic 2038 timestamp sentinel is missing'
    }
    if ($header -notmatch 'error_status_t YwkasRpcClient_Exchange\s*\(' -or
        $header -notmatch 'error_status_t YwkasRpcServer_Exchange\s*\(' -or
        $client -notmatch 'RPC_IF_HANDLE YwkasRpcClient_YwkasRpc_v1_0_c_ifspec\s*=' -or
        $server -notmatch 'RPC_IF_HANDLE YwkasRpcServer_YwkasRpc_v1_0_s_ifspec\s*=' -or
        $server -notmatch '\(SERVER_ROUTINE\)YwkasRpcServer_Exchange' -or
        $shim -notmatch 'return YwkasRpcClient_YwkasRpc_v1_0_c_ifspec;' -or
        $shim -notmatch 'return YwkasRpcServer_YwkasRpc_v1_0_s_ifspec;') {
        throw 'Generated or shim symbols do not match the fixed client/server prefixes'
    }
    if ($header -match 'error_status_t Exchange\s*\(' -or
        $client -match 'error_status_t Exchange\s*\(' -or
        $server -match '\(SERVER_ROUTINE\)Exchange') {
        throw 'Bare Exchange symbol would collide in the combined binary'
    }
    $bareIfspec = 'YwkasRpc_v1_0_c_ifspec'
    $bareIfspecPattern = "(?<![A-Za-z0-9_])$bareIfspec(?![A-Za-z0-9_])"
    if ([regex]::Matches($header, $bareIfspecPattern).Count -ne 1 -or
        [regex]::IsMatch("$client`n$server`n$shim", $bareIfspecPattern)) {
        throw 'Unused MIDL compatibility ifspec must be declared once and never defined or referenced'
    }

    $manifestEntries = @{}
    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$') {
            throw "Malformed generated hash manifest line: $line"
        }
        $manifestEntries[$Matches[2]] = $Matches[1]
    }
    if ($manifestEntries.Count -ne $artifactNames.Count) {
        throw 'Generated hash manifest must contain exactly the three MIDL artifacts'
    }
    foreach ($name in $artifactNames) {
        $actual = Get-LowerSha256 (Join-Path $checkedGenerated $name)
        if ($manifestEntries[$name] -ne $actual) {
            throw "Generated hash manifest mismatch for $name"
        }
    }

    Write-Output "SDK $sdkVersion x64; MIDL compiler $midlCompilerVersion; two-run byte diff: zero"
    Write-Output "midl.exe sha256 $(Get-LowerSha256 $midl)"
    Write-Output "midlc.exe sha256 $(Get-LowerSha256 $midlc)"
    Write-Output "cl.exe toolset $vcToolsVersion sha256 $(Get-LowerSha256 $cl)"
    foreach ($name in $artifactNames) {
        Write-Output "$name sha256 $(Get-LowerSha256 (Join-Path $checkedGenerated $name))"
    }
}
finally {
    if ([IO.Directory]::Exists($tempRoot) -and
        (Split-Path -Leaf $tempRoot).StartsWith('ywkas-rpc-midl-', [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
