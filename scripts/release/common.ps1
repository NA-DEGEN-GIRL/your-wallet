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

function ConvertFrom-ExactNamedArguments {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string[]]$RequiredValueNames,
        [Parameter(Mandatory = $false)][string[]]$OptionalValueNames = @(),
        [Parameter(Mandatory = $true)][string[]]$RequiredSwitchNames
    )

    $valueNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $switchNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @($RequiredValueNames) + @($OptionalValueNames)) {
        if (-not $valueNames.Add($name)) {
            throw "Exact argument schema contains a duplicate value name"
        }
    }
    foreach ($name in $RequiredSwitchNames) {
        if ($valueNames.Contains($name) -or -not $switchNames.Add($name)) {
            throw "Exact argument schema contains a duplicate switch name"
        }
    }

    $bound = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $index = 0
    while ($index -lt $Arguments.Count) {
        $token = $Arguments[$index]
        if (-not $token.StartsWith("-", [System.StringComparison]::Ordinal) -or $token.Length -eq 1) {
            throw "Release command received an unexpected positional argument"
        }
        $name = $token.Substring(1)
        if ($switchNames.Contains($name)) {
            if ($bound.ContainsKey($name)) {
                throw "Release command received a duplicate switch"
            }
            $bound.Add($name, $true)
            $index += 1
            continue
        }
        if (-not $valueNames.Contains($name) -or $index + 1 -ge $Arguments.Count) {
            throw "Release command received an unknown argument or missing value"
        }
        if ($bound.ContainsKey($name)) {
            throw "Release command received a duplicate value argument"
        }
        $bound.Add($name, $Arguments[$index + 1])
        $index += 2
    }

    foreach ($name in @($RequiredValueNames) + @($RequiredSwitchNames)) {
        if (-not $bound.ContainsKey($name)) {
            throw "Release command is missing a required argument"
        }
    }
    Write-Output -NoEnumerate $bound
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
    $root = [System.IO.DirectoryInfo]::new($LiteralPath)
    if (
        -not $root.Exists -or
        ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Release tree root must be a real directory"
    }
    $pending = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
    $pending.Enqueue($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($item in $directory.GetFileSystemInfos()) {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release tree contains a reparse point"
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $pending.Enqueue([System.IO.DirectoryInfo]::new($item.FullName))
            }
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
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace YourWallet {
    public static class ReleaseDirectoryLock {
        private const uint FileReadData = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint OpenExisting = 3;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint VolumeNameGuid = 0x00000001;

        private enum FileInfoByHandleClass {
            FileAttributeTagInfo = 9,
            FileIdInfo = 18
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileAttributeTagInformation {
            internal uint FileAttributes;
            internal uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileId128 {
            internal ulong LowPart;
            internal ulong HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInformation {
            internal ulong VolumeSerialNumber;
            internal FileId128 FileId;
        }

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

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileAttributeTagInformation(
            SafeFileHandle file,
            FileInfoByHandleClass informationClass,
            out FileAttributeTagInformation information,
            uint bufferSize
        );

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileIdInformation(
            SafeFileHandle file,
            FileInfoByHandleClass informationClass,
            out FileIdInformation information,
            uint bufferSize
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags
        );

        private static SafeFileHandle OpenAndValidate(string path, uint desiredAccess, bool expectDirectory) {
            SafeFileHandle handle = CreateFileW(
                path,
                desiredAccess | FileReadAttributes,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint | FileFlagBackupSemantics,
                IntPtr.Zero
            );
            if (handle.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not hold a no-write/no-delete release path handle");
            }
            try {
                FileAttributeTagInformation information;
                if (!GetFileAttributeTagInformation(
                    handle,
                    FileInfoByHandleClass.FileAttributeTagInfo,
                    out information,
                    (uint)Marshal.SizeOf<FileAttributeTagInformation>()
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect a pinned release path");
                }
                bool isDirectory = (information.FileAttributes & FileAttributeDirectory) != 0;
                bool isReparsePoint = (information.FileAttributes & FileAttributeReparsePoint) != 0;
                if (isReparsePoint || isDirectory != expectDirectory) {
                    throw new IOException("Pinned release path has an unsupported type");
                }
                return handle;
            }
            catch {
                handle.Dispose();
                throw;
            }
        }

        private static FileIdInformation Identity(SafeFileHandle handle) {
            FileIdInformation information;
            if (!GetFileIdInformation(
                handle,
                FileInfoByHandleClass.FileIdInfo,
                out information,
                (uint)Marshal.SizeOf<FileIdInformation>()
            )) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not obtain a stable release path identity");
            }
            if (
                information.VolumeSerialNumber == 0 ||
                information.VolumeSerialNumber == UInt64.MaxValue ||
                (information.FileId.LowPart == 0 && information.FileId.HighPart == 0) ||
                (
                    information.FileId.LowPart == UInt64.MaxValue &&
                    information.FileId.HighPart == UInt64.MaxValue
                )
            ) {
                throw new IOException("Release path identity is unsupported");
            }
            return information;
        }

        public static SafeFileHandle OpenDirectory(string path) {
            return OpenAndValidate(path, 0, true);
        }

        public static SafeFileHandle OpenFile(string path) {
            return OpenAndValidate(path, FileReadData, false);
        }

        public static string GetFinalVolumePath(SafeFileHandle handle) {
            StringBuilder path = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, VolumeNameGuid);
            if (length == 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not canonicalize a pinned release path");
            }
            if (length >= path.Capacity) {
                throw new IOException("Pinned release path exceeds the supported canonical path length");
            }
            return path.ToString();
        }

        public static bool SameIdentity(SafeFileHandle left, SafeFileHandle right) {
            FileIdInformation leftIdentity = Identity(left);
            FileIdInformation rightIdentity = Identity(right);
            return
                leftIdentity.VolumeSerialNumber == rightIdentity.VolumeSerialNumber &&
                leftIdentity.FileId.LowPart == rightIdentity.FileId.LowPart &&
                leftIdentity.FileId.HighPart == rightIdentity.FileId.HighPart;
        }

    }
}
"@
}

function Get-CanonicalReleaseDirectoryPaths {
    param([Parameter(Mandatory = $true)][string]$CanonicalDirectory)

    $volumePattern = '^\\\\\?\\Volume\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\'
    $volumeMatch = [System.Text.RegularExpressions.Regex]::Match(
        $CanonicalDirectory,
        $volumePattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $volumeMatch.Success) {
        throw "Release paths must canonicalize to a local volume GUID"
    }
    $volumeRoot = $volumeMatch.Value
    $relative = $CanonicalDirectory.Substring($volumeRoot.Length).Trim("\")
    $paths = [System.Collections.Generic.List[string]]::new()
    $paths.Add($volumeRoot)
    $current = $volumeRoot.TrimEnd("\")
    if (-not [string]::IsNullOrEmpty($relative)) {
        foreach ($segment in $relative.Split(@("\"), [System.StringSplitOptions]::RemoveEmptyEntries)) {
            if ($segment -eq "." -or $segment -eq "..") {
                throw "Canonical release path contains an invalid segment"
            }
            $current = $current + "\" + $segment
            $paths.Add($current)
        }
    }
    $paths.ToArray()
}

function Open-PinnedReleaseDirectoryPath {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    Initialize-ReleaseDirectoryLockType
    $bootstrap = [YourWallet.ReleaseDirectoryLock]::OpenDirectory($LiteralPath)
    $handles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    try {
        $canonical = [YourWallet.ReleaseDirectoryLock]::GetFinalVolumePath($bootstrap)
        foreach ($directoryPath in @(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $canonical)) {
            $handles.Add([YourWallet.ReleaseDirectoryLock]::OpenDirectory($directoryPath))
        }
        if (
            $handles.Count -eq 0 -or
            -not [YourWallet.ReleaseDirectoryLock]::SameIdentity($bootstrap, $handles[$handles.Count - 1])
        ) {
            throw "Release directory identity changed while its canonical path was pinned"
        }
        $confirmed = [YourWallet.ReleaseDirectoryLock]::GetFinalVolumePath($handles[$handles.Count - 1])
        if (-not [System.String]::Equals($canonical, $confirmed, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Release directory canonical path changed while its ancestors were pinned"
        }
        [pscustomobject]@{ CanonicalPath = $confirmed; DirectoryHandles = $handles }
    }
    catch {
        foreach ($handle in $handles) {
            $handle.Dispose()
        }
        throw
    }
    finally {
        $bootstrap.Dispose()
    }
}

function Open-PinnedReleaseFilePath {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    Initialize-ReleaseDirectoryLockType
    $bootstrap = [YourWallet.ReleaseDirectoryLock]::OpenFile($LiteralPath)
    $directoryHandles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $fileHandle = $null
    try {
        $canonical = [YourWallet.ReleaseDirectoryLock]::GetFinalVolumePath($bootstrap)
        $lastSeparator = $canonical.LastIndexOf("\", [System.StringComparison]::Ordinal)
        if ($lastSeparator -lt 0) {
            throw "Pinned release file has no canonical parent"
        }
        $parent = $canonical.Substring(0, $lastSeparator)
        foreach ($directoryPath in @(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $parent)) {
            $directoryHandles.Add([YourWallet.ReleaseDirectoryLock]::OpenDirectory($directoryPath))
        }
        $fileHandle = [YourWallet.ReleaseDirectoryLock]::OpenFile($canonical)
        if (-not [YourWallet.ReleaseDirectoryLock]::SameIdentity($bootstrap, $fileHandle)) {
            throw "Release file identity changed while its canonical path was pinned"
        }
        $confirmed = [YourWallet.ReleaseDirectoryLock]::GetFinalVolumePath($fileHandle)
        if (-not [System.String]::Equals($canonical, $confirmed, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Release file canonical path changed while its ancestors were pinned"
        }
        [pscustomobject]@{
            CanonicalPath = $confirmed
            DirectoryHandles = $directoryHandles
            FileHandle = $fileHandle
        }
    }
    catch {
        if ($null -ne $fileHandle) {
            $fileHandle.Dispose()
        }
        foreach ($handle in $directoryHandles) {
            $handle.Dispose()
        }
        throw
    }
    finally {
        $bootstrap.Dispose()
    }
}

function Open-ReadOnlyReleaseTreeLocks {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $false)][string[]]$AdditionalFiles = @()
    )

    Initialize-ReleaseDirectoryLockType
    $directoryHandles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $fileHandles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $canonicalAdditionalFiles = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $rootPin = Open-PinnedReleaseDirectoryPath -LiteralPath $BundleRoot
        foreach ($handle in $rootPin.DirectoryHandles) {
            $directoryHandles.Add($handle)
        }
        $canonicalRoot = $rootPin.CanonicalPath
        $root = [System.IO.DirectoryInfo]::new($canonicalRoot)
        if (($root.Attributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
            throw "Release verification requires the bundle root and every descendant to be marked read-only"
        }
        $pendingDirectories = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
        $pendingDirectories.Enqueue($root)
        while ($pendingDirectories.Count -gt 0) {
            $directory = $pendingDirectories.Dequeue()
            foreach ($item in @($directory.GetFileSystemInfos() | Sort-Object -Property FullName)) {
                if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                    $directoryHandles.Add([YourWallet.ReleaseDirectoryLock]::OpenDirectory($item.FullName))
                    $stableAttributes = [System.IO.File]::GetAttributes($item.FullName)
                    if (($stableAttributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
                        throw "Release verification requires the bundle root and every descendant to be marked read-only"
                    }
                    $pendingDirectories.Enqueue([System.IO.DirectoryInfo]::new($item.FullName))
                }
                else {
                    if (-not $seen.Add($item.FullName)) {
                        throw "Release verification encountered a duplicate Windows file path"
                    }
                    $fileHandles.Add([YourWallet.ReleaseDirectoryLock]::OpenFile($item.FullName))
                    $stableAttributes = [System.IO.File]::GetAttributes($item.FullName)
                    if (($stableAttributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
                        throw "Release verification requires the bundle root and every descendant to be marked read-only"
                    }
                }
            }
        }
        foreach ($filePath in $AdditionalFiles) {
            $filePin = Open-PinnedReleaseFilePath -LiteralPath $filePath
            foreach ($handle in $filePin.DirectoryHandles) {
                $directoryHandles.Add($handle)
            }
            $fileHandles.Add($filePin.FileHandle)
            $canonicalAdditionalFiles.Add($filePin.CanonicalPath)
            $stableAttributes = [System.IO.File]::GetAttributes($filePin.CanonicalPath)
            if (($stableAttributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0) {
                throw "Release verification inputs must be marked read-only"
            }
        }
    }
    catch {
        foreach ($handle in $fileHandles) {
            $handle.Dispose()
        }
        foreach ($handle in $directoryHandles) {
            $handle.Dispose()
        }
        throw
    }
    [pscustomobject]@{
        CanonicalBundleRoot = $canonicalRoot
        CanonicalAdditionalFiles = $canonicalAdditionalFiles.ToArray()
        DirectoryHandles = $directoryHandles
        DirectoryCount = $directoryHandles.Count
        Streams = $fileHandles
        FileCount = $fileHandles.Count
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
    $pending = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
    $pending.Enqueue([System.IO.DirectoryInfo]::new($BundleRoot))
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        $probePath = [System.IO.Path]::Combine(
            $directory.FullName,
            (".your-wallet-write-probe-" + [System.Guid]::NewGuid().ToString("N"))
        )
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
            [System.IO.File]::Delete($probePath)
            throw "Release verification refuses eligibility because the staging tree is writable by the verifier token"
        }
        foreach ($child in $directory.GetDirectories()) {
            $pending.Enqueue($child)
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
