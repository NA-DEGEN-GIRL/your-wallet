$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "common.ps1")

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("your-wallet-release-" + [System.Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $testRoot)
$safeCleanupRoot = Assert-SafeTemporaryRoot -LiteralPath $testRoot
try {
    $inventory = Get-DirectoryInventory -LiteralPath (Join-Path $RepoRoot "extension\src")
    $firstInventoryHash = Get-InventorySha256 -Inventory $inventory
    $secondInventoryHash = Get-InventorySha256 -Inventory (Get-DirectoryInventory -LiteralPath (Join-Path $RepoRoot "extension\src"))
    if (-not [System.String]::Equals($firstInventoryHash, $secondInventoryHash, [System.StringComparison]::Ordinal)) {
        throw "Directory inventory hash is not deterministic"
    }

    $firstZip = Join-Path $testRoot "first.zip"
    $secondZip = Join-Path $testRoot "second.zip"
    New-DeterministicExtensionZip -ExtensionRoot (Join-Path $RepoRoot "extension") -OutputPath $firstZip
    New-DeterministicExtensionZip -ExtensionRoot (Join-Path $RepoRoot "extension") -OutputPath $secondZip
    if (-not [System.String]::Equals((Get-Sha256Lower -LiteralPath $firstZip), (Get-Sha256Lower -LiteralPath $secondZip), [System.StringComparison]::Ordinal)) {
        throw "Deterministic extension packages differ"
    }

    $lockRoot = Join-Path $testRoot "read-only-lock-test"
    $lockFile = Join-Path $lockRoot "evidence\record.txt"
    Write-NewUtf8File -LiteralPath $lockFile -Content "held release input`n"
    $lockItems = @((Get-Item -LiteralPath $lockRoot -Force)) + @(Get-ChildItem -LiteralPath $lockRoot -Force -Recurse)
    foreach ($item in $lockItems) {
        [System.IO.File]::SetAttributes(
            $item.FullName,
            ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
        )
    }
    $lockSet = $null
    try {
        $lockSet = Open-ReadOnlyReleaseTreeLocks -BundleRoot $lockRoot
        if ($lockSet.FileCount -ne 1) {
            throw "Read-only release lock did not hold the exact file set"
        }
        [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
            "-e",
            "const fs=require('node:fs');fs.realpathSync(process.argv[1]);fs.readdirSync(process.argv[1]);fs.readFileSync(process.argv[2]);",
            $lockRoot,
            $lockFile
        ))
        $writeWasDenied = $false
        try {
            $unexpectedWriter = [System.IO.File]::Open(
                $lockFile,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )
            $unexpectedWriter.Dispose()
        }
        catch [System.IO.IOException] {
            $writeWasDenied = $true
        }
        catch [System.UnauthorizedAccessException] {
            $writeWasDenied = $true
        }
        if (-not $writeWasDenied) {
            throw "Held release input unexpectedly allowed a concurrent writer"
        }
        $writableTreeWasRejected = $false
        try {
            Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $lockRoot
        }
        catch {
            if ($_.Exception.Message -like "*staging tree is writable*") {
                $writableTreeWasRejected = $true
            }
            else {
                throw
            }
        }
        if (-not $writableTreeWasRejected) {
            throw "Mutable staging unexpectedly passed the effective read-only check"
        }
    }
    finally {
        if ($null -ne $lockSet) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $lockSet
        }
        foreach ($item in @((Get-ChildItem -LiteralPath $lockRoot -Force -Recurse)) + @((Get-Item -LiteralPath $lockRoot -Force))) {
            $attributes = [int][System.IO.File]::GetAttributes($item.FullName)
            [System.IO.File]::SetAttributes(
                $item.FullName,
                [System.IO.FileAttributes]($attributes -band (-bnot [int][System.IO.FileAttributes]::ReadOnly))
            )
        }
    }
    Write-Output "POWERSHELL_RELEASE_HELPERS_PASS"
}
finally {
    if (Test-Path -LiteralPath $safeCleanupRoot) {
        Remove-Item -LiteralPath $safeCleanupRoot -Recurse -Force
    }
}
