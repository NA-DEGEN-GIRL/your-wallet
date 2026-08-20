Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-ReleaseCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$CommandArguments,
        [Parameter(Mandatory = $false)][string]$WorkingDirectory = (Get-Location).Path
    )

    $stdoutLines = @()
    $stderr = ""
    $exitCode = -1
    $priorLocation = Get-Location
    $priorPreference = $ErrorActionPreference
    try {
        Set-Location -LiteralPath $WorkingDirectory
        $ErrorActionPreference = "Continue"
        $stderrPath = [System.IO.Path]::GetTempFileName()
        try {
            $stdoutLines = @(& $Executable @CommandArguments 2> $stderrPath)
            $exitCode = $LASTEXITCODE
            $stderr = [System.IO.File]::ReadAllText($stderrPath)
        }
        finally {
            Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        $ErrorActionPreference = $priorPreference
        Set-Location -LiteralPath $priorLocation.Path
    }
    if ($exitCode -ne 0) {
        throw "Release command failed closed with exit code ${exitCode}: $Executable (output withheld; inspect locally with privacy redaction)"
    }
    [pscustomobject]@{ Stdout = ($stdoutLines -join [System.Environment]::NewLine); Stderr = $stderr; ExitCode = $exitCode }
}

function Write-NewUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = Split-Path -Parent $LiteralPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $bytes = $encoding.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Get-Sha256Lower {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Hash target must be a regular file"
    }
    (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
}

function Assert-NoReparseTree {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $root = Get-Item -LiteralPath $LiteralPath -Force
    if (-not $root.PSIsContainer -or ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release tree root must be a real directory"
    }
    foreach ($item in Get-ChildItem -LiteralPath $root.FullName -Force -Recurse) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release tree contains a reparse point"
        }
    }
}

function Initialize-ReleaseDirectoryLockType {
    if ($null -ne ("YourWallet.ReleaseDirectoryLock" -as [type])) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace YourWallet {
    public static class ReleaseDirectoryLock {
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint OpenExisting = 3;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        public static SafeFileHandle Open(string path) {
            SafeFileHandle handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint | FileFlagBackupSemantics,
                IntPtr.Zero
            );
            if (handle.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not hold a no-write/no-delete release directory handle");
            }
            return handle;
        }
    }
}
"@
}

function Open-ReadOnlyReleaseTreeLocks {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $false)][string[]]$AdditionalFiles = @()
    )

    $root = Get-Item -LiteralPath $BundleRoot -Force
    if (-not $root.PSIsContainer -or ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release tree root must be a real directory"
    }
    if (($root.Attributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
        throw "Release verification requires the bundle root and every descendant to be marked read-only"
    }
    Initialize-ReleaseDirectoryLockType
    $directoryHandles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $streams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $directoryHandles.Add([YourWallet.ReleaseDirectoryLock]::Open($root.FullName))
        $pendingDirectories = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
        $pendingDirectories.Enqueue($root)
        while ($pendingDirectories.Count -gt 0) {
            $directory = $pendingDirectories.Dequeue()
            foreach ($item in Get-ChildItem -LiteralPath $directory.FullName -Force | Sort-Object -Property FullName) {
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Release verification refuses a reparse point"
                }
                if (($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
                    throw "Release verification requires the bundle root and every descendant to be marked read-only"
                }
                if ($item.PSIsContainer) {
                    $directoryHandles.Add([YourWallet.ReleaseDirectoryLock]::Open($item.FullName))
                    $pendingDirectories.Enqueue($item)
                }
                else {
                    if (-not $seen.Add($item.FullName)) {
                        throw "Release verification encountered a duplicate Windows file path"
                    }
                    $streams.Add([System.IO.File]::Open(
                        $item.FullName,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read,
                        [System.IO.FileShare]::Read
                    ))
                }
            }
        }
        foreach ($filePath in $AdditionalFiles | Sort-Object) {
            $item = Get-Item -LiteralPath $filePath -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release verification input must be a regular non-reparse file"
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
                throw "Release verification inputs must be marked read-only"
            }
            if (-not $seen.Add($item.FullName)) {
                continue
            }
            $streams.Add([System.IO.File]::Open(
                $item.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            ))
        }
    }
    catch {
        foreach ($stream in $streams) {
            $stream.Dispose()
        }
        foreach ($handle in $directoryHandles) {
            $handle.Dispose()
        }
        throw
    }
    [pscustomobject]@{
        DirectoryHandles = $directoryHandles
        DirectoryCount = $directoryHandles.Count
        Streams = $streams
        FileCount = $streams.Count
    }
}

function Close-ReadOnlyReleaseTreeLocks {
    param([Parameter(Mandatory = $true)][object]$LockSet)
    foreach ($stream in $LockSet.Streams) {
        $stream.Dispose()
    }
    foreach ($handle in $LockSet.DirectoryHandles) {
        $handle.Dispose()
    }
}

function Assert-ReleaseTreeEffectivelyReadOnly {
    param([Parameter(Mandatory = $true)][string]$BundleRoot)

    Assert-NoReparseTree -LiteralPath $BundleRoot
    $root = Get-Item -LiteralPath $BundleRoot -Force
    $directories = @($root) + @(Get-ChildItem -LiteralPath $root.FullName -Force -Directory -Recurse)
    foreach ($directory in $directories) {
        $probePath = Join-Path $directory.FullName (".your-wallet-write-probe-" + [System.Guid]::NewGuid().ToString("N"))
        $probe = $null
        $creationDenied = $false
        try {
            $probe = [System.IO.File]::Open(
                $probePath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
        }
        catch [System.UnauthorizedAccessException] {
            $creationDenied = $true
        }
        catch [System.IO.IOException] {
            $nativeError = $_.Exception.HResult -band 0xFFFF
            if ($nativeError -eq 19) {
                # ERROR_WRITE_PROTECT: the underlying medium is read-only.
                $creationDenied = $true
            }
            else {
                throw "Release verification could not prove that a staging directory is read-only"
            }
        }
        finally {
            if ($null -ne $probe) {
                $probe.Dispose()
            }
        }
        if (-not $creationDenied) {
            Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
            throw "Release verification refuses eligibility because the staging tree is writable by the verifier token"
        }
    }
}

function Get-DirectoryInventory {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    Assert-NoReparseTree -LiteralPath $LiteralPath
    $root = (Resolve-Path -LiteralPath $LiteralPath).Path
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $root -Force -File -Recurse) {
        $rootPrefix = $root.TrimEnd("\") + "\"
        if (-not $file.FullName.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Release inventory path escaped its root"
        }
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace("\", "/")
        $records.Add([ordered]@{
            bytes = $file.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
            path = $relative
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        })
    }
    @($records | Sort-Object -Property @{ Expression = { $_.path }; Ascending = $true })
}

function ConvertTo-CanonicalInventoryJson {
    param([Parameter(Mandatory = $true)][object[]]$Inventory)
    $parts = foreach ($record in $Inventory) {
        foreach ($value in @([string]$record.bytes, [string]$record.path, [string]$record.sha256)) {
            if ($value -match '[^\x20-\x7e]' -or $value.Contains('"') -or $value.Contains('\')) {
                throw "Release inventory refuses a path or value that is not canonical printable ASCII"
            }
        }
        $bytes = '"' + [string]$record.bytes + '"'
        $path = '"' + [string]$record.path + '"'
        $sha256 = '"' + [string]$record.sha256 + '"'
        "{`"bytes`":${bytes},`"path`":${path},`"sha256`":${sha256}}"
    }
    "[" + ($parts -join ",") + "]"
}

function Get-InventorySha256 {
    param([Parameter(Mandatory = $true)][object[]]$Inventory)
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes((ConvertTo-CanonicalInventoryJson -Inventory $Inventory))
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $hasher.ComputeHash($bytes)
    }
    finally {
        $hasher.Dispose()
    }
    ([System.BitConverter]::ToString($hash) -replace "-", "").ToLowerInvariant()
}

function New-DeterministicExtensionZip {
    param(
        [Parameter(Mandatory = $true)][string]$ExtensionRoot,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    $root = (Resolve-Path -LiteralPath $ExtensionRoot).Path
    Assert-NoReparseTree -LiteralPath $root
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    if (Test-Path -LiteralPath $OutputPath) {
        throw "Deterministic extension package output already exists"
    }
    $files = @("manifest.json") + @(Get-ChildItem -LiteralPath (Join-Path $root "src") -File | ForEach-Object { "src/$($_.Name)" } | Sort-Object)
    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    $stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($relative in $files) {
                $source = Join-Path $root $relative.Replace("/", "\")
                $item = Get-Item -LiteralPath $source -Force
                if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Extension package input must be a regular non-reparse file"
                }
                $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::NoCompression)
                $entry.LastWriteTime = [System.DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                $entryStream = $entry.Open()
                try {
                    $sourceStream = [System.IO.File]::OpenRead($item.FullName)
                    try {
                        $sourceStream.CopyTo($entryStream)
                    }
                    finally {
                        $sourceStream.Dispose()
                    }
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-CleanGitRepository {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)
    $status = Invoke-ReleaseCommand -Executable "git" -CommandArguments @("status", "--porcelain=v1", "--untracked-files=all") -WorkingDirectory $RepositoryRoot
    if (-not [string]::IsNullOrWhiteSpace($status.Stdout)) {
        throw "Release preparation requires a completely clean Git worktree, including no untracked files"
    }
}

function Assert-SafeTemporaryRoot {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $resolved = (Resolve-Path -LiteralPath $LiteralPath).Path
    $temporary = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd("\")
    if (-not $resolved.StartsWith("${temporary}\your-wallet-release-", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing cleanup outside the dedicated release temporary root"
    }
    $resolved
}
