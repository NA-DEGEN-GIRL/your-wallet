$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "common.ps1")

if ($env:OS -ne "Windows_NT") {
    throw "Verifier toolset tests require Windows"
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "your-wallet-release-verifier-toolset-" + [System.Guid]::NewGuid().ToString("N")
)
[void](New-Item -ItemType Directory -Path $testRoot)
$safeCleanupRoot = Assert-SafeTemporaryRoot -LiteralPath $testRoot

$toolsetDirectories = @(
    "extension",
    "extension/native-host",
    "scripts",
    "scripts/release"
)
$toolsetFiles = @(
    "extension/native-host/validate-manifest.mjs",
    "node.exe",
    "scripts/release/common.ps1",
    "scripts/release/release-manifest.mjs",
    "scripts/release/review-evidence-set.mjs",
    "scripts/release/review-evidence-set.ps1",
    "scripts/release/verify-release-offline.ps1"
)
$activeProtections = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$denyCreateRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $currentSid,
    ([System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Deny
)
$denyCreateFilesOnlyRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $currentSid,
    [System.Security.AccessControl.FileSystemRights]::CreateFiles,
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Deny
)

function Get-TestToolsetSha256 {
    param([Parameter(Mandatory = $true)][string]$Root)

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in $toolsetFiles) {
        $file = Get-Item -LiteralPath (Join-Path $Root $relative.Replace("/", "\")) -Force
        $records.Add([ordered]@{
            bytes = $file.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
            path = $relative
            sha256 = Get-Sha256Lower -LiteralPath $file.FullName
        })
    }
    Get-InventorySha256 -Inventory $records.ToArray()
}

function New-TestToolsetFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$NodeSource,
        [Parameter(Mandatory = $false)][string]$ReviewScriptContent
    )

    foreach ($relativeDirectory in $toolsetDirectories) {
        [void](New-Item -ItemType Directory -Path (Join-Path $Root $relativeDirectory.Replace("/", "\")) -Force)
    }
    foreach ($relativeFile in @(
        "extension/native-host/validate-manifest.mjs",
        "scripts/release/common.ps1",
        "scripts/release/release-manifest.mjs",
        "scripts/release/review-evidence-set.mjs",
        "scripts/release/review-evidence-set.ps1",
        "scripts/release/verify-release-offline.ps1"
    )) {
        Copy-Item `
            -LiteralPath (Join-Path $RepoRoot $relativeFile.Replace("/", "\")) `
            -Destination (Join-Path $Root $relativeFile.Replace("/", "\"))
    }
    Copy-Item -LiteralPath $NodeSource -Destination (Join-Path $Root "node.exe")
    if ($PSBoundParameters.ContainsKey("ReviewScriptContent")) {
        [System.IO.File]::WriteAllText(
            (Join-Path $Root "scripts\release\review-evidence-set.mjs"),
            $ReviewScriptContent,
            [System.Text.UTF8Encoding]::new($false, $true)
        )
    }
    $actualFiles = @(Get-ChildItem -LiteralPath $Root -File -Force -Recurse)
    $actualDirectories = @(Get-ChildItem -LiteralPath $Root -Directory -Force -Recurse)
    if ($actualFiles.Count -ne 7 -or $actualDirectories.Count -ne 4) {
        throw "Test toolset fixture was not the exact seven-file/four-directory shape"
    }
}

function Protect-TestTree {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $false)][switch]$DenyFilesOnly
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    if ($activeProtections.ContainsKey($fullRoot)) {
        throw "Test tree is already protected"
    }
    $acl = Get-Acl -LiteralPath $fullRoot
    $record = [pscustomobject]@{
        Root = $fullRoot
        Sddl = $acl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All
        )
    }
    $activeProtections.Add($fullRoot, $record)
    $denyRule = if ($DenyFilesOnly) { $denyCreateFilesOnlyRule } else { $denyCreateRule }
    [void]$acl.AddAccessRule($denyRule)
    Set-Acl -LiteralPath $fullRoot -AclObject $acl
    foreach ($item in @((Get-Item -LiteralPath $fullRoot -Force)) + @(
        Get-ChildItem -LiteralPath $fullRoot -Force -Recurse
    )) {
        [System.IO.File]::SetAttributes(
            $item.FullName,
            ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
        )
    }
    $record
}

function Unprotect-TestTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    if (-not $activeProtections.ContainsKey($fullRoot)) {
        return
    }
    $record = $activeProtections[$fullRoot]
    if ([System.IO.Directory]::Exists($fullRoot)) {
        $restoredAcl = [System.Security.AccessControl.DirectorySecurity]::new()
        $restoredAcl.SetSecurityDescriptorSddlForm($record.Sddl)
        Set-Acl -LiteralPath $fullRoot -AclObject $restoredAcl
        foreach ($item in @((Get-ChildItem -LiteralPath $fullRoot -Force -Recurse)) + @(
            (Get-Item -LiteralPath $fullRoot -Force)
        )) {
            $attributes = [int][System.IO.File]::GetAttributes($item.FullName)
            [System.IO.File]::SetAttributes(
                $item.FullName,
                [System.IO.FileAttributes]($attributes -band (-bnot [int][System.IO.FileAttributes]::ReadOnly))
            )
        }
    }
    [void]$activeProtections.Remove($fullRoot)
}

function Assert-ToolsetOpenRejected {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $false)][switch]$AlreadyProtected
    )

    if (-not $AlreadyProtected) {
        [void](Protect-TestTree -Root $Root)
    }
    $opened = $null
    $rejected = $false
    try {
        try {
            $opened = Open-VerifiedReleaseToolset -ToolsetRoot $Root -ExpectedSha256 $ExpectedSha256
        }
        catch {
            $rejected = $true
        }
    }
    finally {
        if ($null -ne $opened) {
            Close-VerifiedReleaseToolset -Toolset $opened
        }
        $renameProbe = $Root + "-released-lock-probe"
        $probeMoved = $false
        try {
            [System.IO.Directory]::Move($Root, $renameProbe)
            $probeMoved = $true
            [System.IO.Directory]::Move($renameProbe, $Root)
            $probeMoved = $false
        }
        finally {
            if ($probeMoved -and [System.IO.Directory]::Exists($renameProbe)) {
                [System.IO.Directory]::Move($renameProbe, $Root)
            }
        }
        if (-not $AlreadyProtected) {
            Unprotect-TestTree -Root $Root
        }
    }
    if (-not $rejected) {
        throw "Verifier toolset accepted a rejected fixture: $Label"
    }
}

function Initialize-TestRawProcessType {
    if ($null -ne ("YourWalletVerifierTests.RawProcess" -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace YourWalletVerifierTests {
    public sealed class RawProcessResult {
        public int ExitCode { get; private set; }
        public string Stdout { get; private set; }
        public string Stderr { get; private set; }
        internal RawProcessResult(int exitCode, string stdout, string stderr) {
            ExitCode = exitCode;
            Stdout = stdout;
            Stderr = stderr;
        }
    }

    public static class RawProcess {
        private sealed class CaptureState {
            internal readonly object Sync = new object();
            internal readonly MemoryStream Bytes = new MemoryStream();
            internal readonly int MaximumBytes;
            internal bool Overflow;
            internal Exception Failure;
            internal CaptureState(int maximumBytes) { MaximumBytes = maximumBytes; }
        }

        private static string Quote(string value) {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid argument");
            if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '\r', '\n', '"' }) < 0) return value;
            StringBuilder result = new StringBuilder();
            result.Append('"');
            int backslashes = 0;
            foreach (char current in value) {
                if (current == '\\') { backslashes += 1; continue; }
                if (current == '"') {
                    result.Append('\\', (backslashes * 2) + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }
                result.Append('\\', backslashes);
                backslashes = 0;
                result.Append(current);
            }
            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private static string BuildArguments(string[] arguments) {
            StringBuilder result = new StringBuilder();
            for (int index = 0; index < arguments.Length; index += 1) {
                if (index != 0) result.Append(' ');
                result.Append(Quote(arguments[index]));
            }
            return result.ToString();
        }

        private static void Capture(Stream source, CaptureState state, Process process) {
            try {
                byte[] buffer = new byte[4096];
                while (true) {
                    int count = source.Read(buffer, 0, buffer.Length);
                    if (count == 0) return;
                    lock (state.Sync) {
                        if (state.Bytes.Length > state.MaximumBytes - count) {
                            state.Overflow = true;
                            try { process.Kill(); } catch { }
                            return;
                        }
                        state.Bytes.Write(buffer, 0, count);
                    }
                }
            }
            catch (Exception error) {
                lock (state.Sync) { state.Failure = error; }
                try { process.Kill(); } catch { }
            }
        }

        public static RawProcessResult Run(
            string executable,
            string workingDirectory,
            string[] arguments,
            int timeoutMilliseconds,
            int maximumOutputBytes
        ) {
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = executable;
            start.WorkingDirectory = workingDirectory;
            start.Arguments = BuildArguments(arguments);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.WindowStyle = ProcessWindowStyle.Hidden;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            Process process = new Process();
            process.StartInfo = start;
            CaptureState stdout = new CaptureState(maximumOutputBytes);
            CaptureState stderr = new CaptureState(maximumOutputBytes);
            Thread stdoutThread = null;
            Thread stderrThread = null;
            try {
                if (!process.Start()) throw new IOException("Test process did not start");
                process.StandardInput.Close();
                stdoutThread = new Thread(delegate() { Capture(process.StandardOutput.BaseStream, stdout, process); });
                stderrThread = new Thread(delegate() { Capture(process.StandardError.BaseStream, stderr, process); });
                stdoutThread.IsBackground = true;
                stderrThread.IsBackground = true;
                stdoutThread.Start();
                stderrThread.Start();
                if (!process.WaitForExit(timeoutMilliseconds)) {
                    try { process.Kill(); } catch { }
                    if (!process.WaitForExit(5000)) throw new IOException("Test process could not be terminated");
                    throw new TimeoutException("Test process exceeded its time limit");
                }
                if (!stdoutThread.Join(5000) || !stderrThread.Join(5000)) {
                    throw new IOException("Test output capture did not terminate");
                }
                if (stdout.Overflow || stderr.Overflow) throw new IOException("Test output exceeded its limit");
                if (stdout.Failure != null || stderr.Failure != null) throw new IOException("Test output capture failed");
                UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
                return new RawProcessResult(
                    process.ExitCode,
                    strictUtf8.GetString(stdout.Bytes.ToArray()),
                    strictUtf8.GetString(stderr.Bytes.ToArray())
                );
            }
            finally {
                process.Dispose();
            }
        }
    }
}
'@
}

function Invoke-TestRawProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $false)][int]$TimeoutMilliseconds = 60000
    )

    Initialize-TestRawProcessType
    [YourWalletVerifierTests.RawProcess]::Run(
        $Executable,
        $WorkingDirectory,
        $Arguments,
        $TimeoutMilliseconds,
        1048576
    )
}

function Assert-X86VerifierHostPreflight {
    $x86PowerShell = Join-Path `
        $env:SystemRoot `
        "SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    if (-not [System.IO.File]::Exists($x86PowerShell)) {
        return
    }

    $commonPath = Join-Path $PSScriptRoot "common.ps1"
    $commonPathLiteral = "'" + $commonPath.Replace("'", "''") + "'"
    $probeSource = @'
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (
    -not [System.Environment]::Is64BitOperatingSystem -or
    [System.Environment]::Is64BitProcess
) {
    [Console]::Error.Write("X86_VERIFIER_HOST_PREFLIGHT_ENVIRONMENT_INVALID`n")
    exit 90
}
. __COMMON_PATH_LITERAL__
try {
    [void](Open-VerifiedReleaseToolset `
        -ToolsetRoot "X:\__your_wallet_x86_preflight_must_not_access__" `
        -ExpectedSha256 ("0" * 64))
    [Console]::Error.Write("X86_VERIFIER_HOST_PREFLIGHT_NOT_REJECTED`n")
    exit 91
}
catch {
    if (-not [System.String]::Equals(
        $_.Exception.Message,
        "Verified release toolsets require a 64-bit Windows verifier process",
        [System.StringComparison]::Ordinal
    )) {
        [Console]::Error.Write("X86_VERIFIER_HOST_PREFLIGHT_UNEXPECTED_FAILURE`n")
        exit 92
    }
}
[Console]::Out.Write("X86_VERIFIER_HOST_PREFLIGHT_PASS`n")
'@.Replace("__COMMON_PATH_LITERAL__", $commonPathLiteral)
    $encodedProbe = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($probeSource)
    )
    $result = Invoke-TestRawProcess `
        -Executable $x86PowerShell `
        -WorkingDirectory $RepoRoot `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            $encodedProbe
        ) `
        -TimeoutMilliseconds 30000
    if (
        $result.ExitCode -ne 0 -or
        -not [System.String]::Equals(
            $result.Stdout,
            "X86_VERIFIER_HOST_PREFLIGHT_PASS`n",
            [System.StringComparison]::Ordinal
        ) -or
        -not [System.String]::Equals($result.Stderr, "", [System.StringComparison]::Ordinal)
    ) {
        throw "32-bit Windows PowerShell did not fail closed at the verifier host preflight"
    }
}

function Invoke-ReviewWrapperRaw {
    param(
        [Parameter(Mandatory = $true)][string]$ToolsetRoot,
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    $powershellPath = Join-Path `
        ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)) `
        "WindowsPowerShell\v1.0\powershell.exe"
    Invoke-TestRawProcess `
        -Executable $powershellPath `
        -WorkingDirectory $ToolsetRoot `
        -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            (Join-Path $ToolsetRoot "scripts\release\review-evidence-set.ps1"),
            "-BundleRoot",
            $BundleRoot,
            "-ExpectedVerifierToolsetSha256",
            $ExpectedSha256,
            "-OperatorConfirmedNetworkIsolation"
        ) `
        -TimeoutMilliseconds 60000
}

function Assert-FixedReviewWrapperFailure {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expectedError = "REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed" + `
        [System.Environment]::NewLine
    if ($Result.ExitCode -ne 1 -or
        -not [string]::Equals($Result.Stdout, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($Result.Stderr, $expectedError, [System.StringComparison]::Ordinal)) {
        throw "Review wrapper did not fail with its one path-free line: $Label"
    }
}

function Invoke-InvalidOfflineWrapperRaw {
    param(
        [Parameter(Mandatory = $true)][string]$ToolsetRoot,
        [Parameter(Mandatory = $true)][string]$PrivatePath
    )

    $powershellPath = Join-Path `
        ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)) `
        "WindowsPowerShell\v1.0\powershell.exe"
    Invoke-TestRawProcess `
        -Executable $powershellPath `
        -WorkingDirectory $ToolsetRoot `
        -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            (Join-Path $ToolsetRoot "scripts\release\verify-release-offline.ps1"),
            "-UnknownPrivatePath",
            $PrivatePath
        ) `
        -TimeoutMilliseconds 60000
}

function Invoke-ProxyCompilation {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$OutputAssembly
    )

    $job = Start-Job -ScriptBlock {
        param($CompilationSource, $CompilationOutput)
        Add-Type `
            -TypeDefinition $CompilationSource `
            -OutputAssembly $CompilationOutput `
            -OutputType ConsoleApplication
    } -ArgumentList $Source, $OutputAssembly
    try {
        [void](Wait-Job -Job $job -Timeout 60)
        if ($job.State -ne "Completed") {
            Receive-Job -Job $job -ErrorAction Continue
            throw "Verifier proxy compilation did not complete"
        }
        [void](Receive-Job -Job $job -ErrorAction Stop)
    }
    finally {
        if ($job.State -eq "Running") {
            Stop-Job -Job $job
        }
        Remove-Job -Job $job -Force
    }
    if (-not [System.IO.File]::Exists($OutputAssembly)) {
        throw "Verifier proxy compilation did not produce an executable"
    }
}

try {
    Assert-X86VerifierHostPreflight
    Initialize-ReleaseToolsetProcessType
    $behaviorProxy = Join-Path $testRoot "compiled-behavior-node.exe"
    $canonicalSubject = '{"reviewedEvidenceSetSha256":"0000000000000000000000000000000000000000000000000000000000000000","schema":"your-wallet-reviewed-evidence-set-subject-v1"}'
    $canonicalSubjectLiteral = '"' + $canonicalSubject.Replace('\', '\\').Replace('"', '\"') + '"'
    $behaviorProxyTemplate = @"
using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

public static class VerifierBehaviorNode {
    private static readonly byte[] Canonical = new UTF8Encoding(false, true).GetBytes($canonicalSubjectLiteral + "\n");
    private static readonly string WrapperMode = "__WRAPPER_MODE__";

    private static void Write(Stream stream, byte[] bytes) {
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush();
    }

    private static byte[] Utf8(string value) {
        return new UTF8Encoding(false, true).GetBytes(value);
    }

    private static int RunMode(string mode, string[] arguments, int argumentOffset) {
        if (mode == "contract") {
            Write(Console.OpenStandardOutput(), Utf8("CONTRACT_OK\n"));
            return 0;
        }
        if (mode == "roundtrip") {
            StringBuilder result = new StringBuilder();
            for (int index = argumentOffset; index < arguments.Length; index += 1) {
                result.Append(Convert.ToBase64String(Utf8(arguments[index])));
                result.Append('\n');
            }
            Write(Console.OpenStandardOutput(), Utf8(result.ToString()));
            return 0;
        }
        if (mode == "review-valid") {
            Write(Console.OpenStandardOutput(), Canonical);
            return 0;
        }
        if (mode == "bom") {
            Write(Console.OpenStandardOutput(), new byte[] { 0xef, 0xbb, 0xbf });
            Write(Console.OpenStandardOutput(), Canonical);
            return 0;
        }
        if (mode == "crlf") {
            Write(Console.OpenStandardOutput(), Utf8(Encoding.UTF8.GetString(Canonical).Replace("\n", "\r\n")));
            return 0;
        }
        if (mode == "trailing") {
            Write(Console.OpenStandardOutput(), Canonical);
            Write(Console.OpenStandardOutput(), Utf8("trailing"));
            return 0;
        }
        if (mode == "stderr") {
            Write(Console.OpenStandardOutput(), Canonical);
            Write(Console.OpenStandardError(), Utf8("diagnostic\n"));
            return 0;
        }
        if (mode == "nonzero") {
            Write(Console.OpenStandardOutput(), Canonical);
            return 23;
        }
        if (mode == "invalid-utf8") {
            Write(Console.OpenStandardOutput(), new byte[] { 0xc3, 0x28 });
            return 0;
        }
        if (mode == "oversize") {
            byte[] block = new byte[8192];
            for (int index = 0; index < block.Length; index += 1) {
                block[index] = 0x78;
            }
            int remaining = (1024 * 1024) + 1;
            while (remaining > 0) {
                int count = Math.Min(block.Length, remaining);
                Console.OpenStandardOutput().Write(block, 0, count);
                remaining -= count;
            }
            Console.OpenStandardOutput().Flush();
            return 0;
        }
        if (mode == "sleep") {
            Thread.Sleep(5000);
            return 0;
        }
        Write(Console.OpenStandardError(), Utf8("unknown mode\n"));
        return 97;
    }

    private static int MainCore(string[] arguments) {
        if (arguments.Length == 1 && arguments[0] == "sleep") {
            return RunMode("sleep", arguments, 1);
        }
        if (arguments.Length == 1 && arguments[0] == "raw-contract") {
            Write(Console.OpenStandardOutput(), Utf8("RAW_CONTRACT_OK\n"));
            return 0;
        }
        if (
            arguments.Length < 11 ||
            arguments[0] != "--no-addons" ||
            arguments[1] != "--no-global-search-paths" ||
            arguments[2] != "--no-warnings" ||
            arguments[3] != "--experimental-vm-modules" ||
            arguments[4] != "-e" ||
            arguments[6] != "review" ||
            !Path.IsPathRooted(arguments[7]) ||
            !Path.IsPathRooted(arguments[8]) ||
            !Path.IsPathRooted(arguments[9]) ||
            !arguments[7].EndsWith("\\extension\\native-host\\validate-manifest.mjs", StringComparison.Ordinal) ||
            !arguments[8].EndsWith("\\scripts\\release\\release-manifest.mjs", StringComparison.Ordinal) ||
            !arguments[9].EndsWith("\\scripts\\release\\review-evidence-set.mjs", StringComparison.Ordinal)
        ) {
            return 90;
        }
        string systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (
            !String.Equals(Environment.CurrentDirectory, systemDirectory, StringComparison.OrdinalIgnoreCase) ||
            Console.OpenStandardInput().ReadByte() != -1
        ) {
            return 91;
        }
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables()) {
            string key = (string)entry.Key;
            if (
                !String.Equals(key, "PATH", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(key, "SystemRoot", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(key, "WINDIR", StringComparison.OrdinalIgnoreCase)
            ) {
                return 92;
            }
        }
        string windowsDirectory = Directory.GetParent(systemDirectory).FullName;
        if (
            !String.Equals(Environment.GetEnvironmentVariable("PATH"), systemDirectory, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Environment.GetEnvironmentVariable("SystemRoot"), windowsDirectory, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Environment.GetEnvironmentVariable("WINDIR"), windowsDirectory, StringComparison.OrdinalIgnoreCase)
        ) {
            return 93;
        }
        string mode = arguments[10];
        int offset = 11;
        if (mode == "--bundle-root") {
            mode = WrapperMode;
            offset = arguments.Length;
        }
        return RunMode(mode, arguments, offset);
    }

    public static int Main(string[] arguments) {
        try {
            return MainCore(arguments);
        }
        catch {
            Write(Console.OpenStandardError(), Utf8("proxy failure\n"));
            return 98;
        }
    }
}
"@
    $behaviorProxySource = $behaviorProxyTemplate.Replace("__WRAPPER_MODE__", "review-valid")
    Invoke-ProxyCompilation -Source $behaviorProxySource -OutputAssembly $behaviorProxy

    $preparedToolsetRoot = Join-Path $testRoot "prepared-toolset"
    $preparationScript = Join-Path $RepoRoot "scripts\release\prepare-verifier-toolset.ps1"
    $systemPowerShell = Join-Path `
        ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)) `
        "WindowsPowerShell\v1.0\powershell.exe"
    $preparationArguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $preparationScript,
        "-NodeExecutable",
        $behaviorProxy,
        "-OutputDirectory",
        $preparedToolsetRoot,
        "-OperatorConfirmedPreparationOnly"
    )
    $preparationResult = Invoke-TestRawProcess `
        -Executable $systemPowerShell `
        -WorkingDirectory $RepoRoot `
        -Arguments $preparationArguments
    $preparedToolsetHash = Get-TestToolsetSha256 -Root $preparedToolsetRoot
    $expectedPreparationOutput = "VERIFIER_TOOLSET_SHA256=${preparedToolsetHash}`n" + `
        "VERIFIER_TOOLSET_PREPARED_NOT_RELEASE_ELIGIBLE`n"
    $preparedFiles = @(Get-ChildItem -LiteralPath $preparedToolsetRoot -File -Force -Recurse)
    $preparedDirectories = @(Get-ChildItem -LiteralPath $preparedToolsetRoot -Directory -Force -Recurse)
    $preparedItems = @((Get-Item -LiteralPath $preparedToolsetRoot -Force)) + `
        @($preparedDirectories) + @($preparedFiles)
    if ($preparationResult.ExitCode -ne 0 -or
        -not [string]::Equals($preparationResult.Stdout, $expectedPreparationOutput, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($preparationResult.Stderr, "", [System.StringComparison]::Ordinal) -or
        $preparedFiles.Count -ne 7 -or
        $preparedDirectories.Count -ne 4 -or
        @($preparedItems | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) -eq 0
        }).Count -ne 0) {
        throw "Verifier toolset preparation did not produce the exact non-eligible staged tree"
    }

    $preparedOpened = $null
    $preparedEligibilityRejected = $false
    try {
        $preparedOpened = Open-VerifiedReleaseToolset `
            -ToolsetRoot $preparedToolsetRoot `
            -ExpectedSha256 $preparedToolsetHash
    }
    catch {
        $preparedEligibilityRejected = $true
    }
    finally {
        if ($null -ne $preparedOpened) {
            Close-VerifiedReleaseToolset -Toolset $preparedOpened
        }
    }
    if (-not $preparedEligibilityRejected) {
        throw "Preparation-only output was accepted without effective write protection"
    }

    $expectedPreparationError = "VERIFIER_TOOLSET_PREPARATION_FAILED: preparation failed closed" + `
        [System.Environment]::NewLine
    $existingPreparationResult = Invoke-TestRawProcess `
        -Executable $systemPowerShell `
        -WorkingDirectory $RepoRoot `
        -Arguments $preparationArguments
    if ($existingPreparationResult.ExitCode -ne 1 -or
        -not [string]::Equals($existingPreparationResult.Stdout, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($existingPreparationResult.Stderr, $expectedPreparationError, [System.StringComparison]::Ordinal)) {
        throw "Verifier toolset preparation did not reject an existing output with one fixed line"
    }

    $privatePreparationPath = Join-Path $testRoot "private-preparation-input"
    $invalidPreparationResult = Invoke-TestRawProcess `
        -Executable $systemPowerShell `
        -WorkingDirectory $RepoRoot `
        -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $preparationScript,
            "-UnknownPrivatePath",
            $privatePreparationPath
        )
    if ($invalidPreparationResult.ExitCode -ne 1 -or
        -not [string]::Equals($invalidPreparationResult.Stdout, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($invalidPreparationResult.Stderr, $expectedPreparationError, [System.StringComparison]::Ordinal) -or
        $invalidPreparationResult.Stderr.Contains($privatePreparationPath)) {
        throw "Verifier toolset preparation argument failure disclosed a path or changed its fixed line"
    }

    $wrapperModeProxies = @{}
    foreach ($wrapperMode in @("review-valid", "bom", "crlf", "trailing", "stderr", "nonzero", "invalid-utf8", "oversize")) {
        $wrapperModeProxy = Join-Path $testRoot ("compiled-wrapper-mode-" + $wrapperMode + ".exe")
        Invoke-ProxyCompilation `
            -Source $behaviorProxyTemplate.Replace("__WRAPPER_MODE__", $wrapperMode) `
            -OutputAssembly $wrapperModeProxy
        $wrapperModeProxies[$wrapperMode] = $wrapperModeProxy
    }

    $decoyMarker = Join-Path $testRoot "decoy-node-invoked.marker"
    $decoyMarkerLiteral = '"' + $decoyMarker.Replace('\', '\\').Replace('"', '\"') + '"'
    $decoyNodeDirectory = Join-Path $testRoot "decoy-path"
    [void](New-Item -ItemType Directory -Path $decoyNodeDirectory)
    $decoyNode = Join-Path $decoyNodeDirectory "node.exe"
    $decoySource = @"
using System.IO;
using System.Text;
public static class DecoyNode {
    public static int Main(string[] arguments) {
        File.WriteAllText($decoyMarkerLiteral, "invoked", new UTF8Encoding(false));
        return 99;
    }
    }
"@
    Invoke-ProxyCompilation -Source $decoySource -OutputAssembly $decoyNode

    Initialize-ReleaseDirectoryLockType
    $mappedImageHandle = [YourWallet.ReleaseDirectoryLock]::OpenFile($behaviorProxy)
    try {
        $mappedImageMismatchRejected = $false
        try {
            [void][YourWallet.ReleaseToolsetProcess]::Run(
                $mappedImageHandle,
                $decoyNode,
                [string[]]@("raw-contract"),
                5000,
                1024
            )
        }
        catch {
            $mappedImageMismatchRejected = $true
        }
        if (-not $mappedImageMismatchRejected -or [System.IO.File]::Exists($decoyMarker)) {
            throw "Exact-image runner accepted an executable path that did not match its expected handle"
        }
        $mappedImageRecovery = [YourWallet.ReleaseToolsetProcess]::Run(
            $mappedImageHandle,
            $behaviorProxy,
            [string[]]@("raw-contract"),
            5000,
            1024
        )
        if ($mappedImageRecovery.ExitCode -ne 0 -or
            -not [string]::Equals($mappedImageRecovery.Stdout, "RAW_CONTRACT_OK`n", [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($mappedImageRecovery.Stderr, "", [System.StringComparison]::Ordinal)) {
            throw "Exact-image mismatch cleanup prevented a subsequent matched execution"
        }
    }
    finally {
        $mappedImageHandle.Dispose()
    }

    $proxyFixtureRoot = Join-Path $testRoot "exact-proxy-toolset"
    New-TestToolsetFixture -Root $proxyFixtureRoot -NodeSource $behaviorProxy -ReviewScriptContent "contract"
    $proxyFixtureHash = Get-TestToolsetSha256 -Root $proxyFixtureRoot
    [void](Protect-TestTree -Root $proxyFixtureRoot)
    Assert-ToolsetOpenRejected `
        -Root $proxyFixtureRoot `
        -ExpectedSha256 ("0" * 64) `
        -Label "wrong aggregate hash" `
        -AlreadyProtected
    Assert-ToolsetOpenRejected `
        -Root $proxyFixtureRoot `
        -ExpectedSha256 "ABC" `
        -Label "malformed uppercase hash" `
        -AlreadyProtected

    $proxyToolset = $null
    try {
        function Get-FileHash {
            throw "Ambient Get-FileHash shadow must not be called by the verifier"
        }
        try {
            $proxyToolset = Open-VerifiedReleaseToolset `
                -ToolsetRoot $proxyFixtureRoot `
                -ExpectedSha256 $proxyFixtureHash
        }
        finally {
            Remove-Item -LiteralPath "Function:Get-FileHash" -ErrorAction SilentlyContinue
        }
        if (
            -not [string]::Equals($proxyToolset.Schema, "your-wallet-verified-release-toolset-v1", [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($proxyToolset.InventorySha256, $proxyFixtureHash, [System.StringComparison]::Ordinal) -or
            -not [System.Text.RegularExpressions.Regex]::IsMatch(
                $proxyToolset.CanonicalVolumeRoot,
                '^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\',
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            ) -or
            -not [System.IO.Path]::IsPathRooted($proxyToolset.NodePath)
        ) {
            throw "Exact verifier toolset handle metadata was invalid"
        }

        $originalPath = $env:PATH
        $hadNodeOptions = Test-Path -LiteralPath "Env:NODE_OPTIONS"
        $originalNodeOptions = if ($hadNodeOptions) { $env:NODE_OPTIONS } else { $null }
        $functionMarker = Join-Path $testRoot "function-node-invoked.marker"
        function node {
            [System.IO.File]::WriteAllText($functionMarker, "invoked")
        }
        try {
            $env:PATH = $decoyNodeDirectory
            $env:NODE_OPTIONS = "--require=parent-preload-must-not-run.cjs"
            $contractResult = Invoke-ReleaseToolsetNode `
                -Toolset $proxyToolset `
                -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
                -CommandArguments @("contract")
        }
        finally {
            Remove-Item -LiteralPath "Function:node" -ErrorAction SilentlyContinue
            $env:PATH = $originalPath
            if ($hadNodeOptions) {
                $env:NODE_OPTIONS = $originalNodeOptions
            }
            else {
                Remove-Item -LiteralPath "Env:NODE_OPTIONS" -ErrorAction SilentlyContinue
            }
        }
        if ($contractResult.ExitCode -ne 0 -or
            -not [string]::Equals($contractResult.Stdout, "CONTRACT_OK`n", [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($contractResult.Stderr, "", [System.StringComparison]::Ordinal) -or
            [System.IO.File]::Exists($decoyMarker) -or
            [System.IO.File]::Exists($functionMarker)) {
            throw "Pinned verifier execution used ambient Node state or changed raw output"
        }

        $roundtripValues = @(
            "plain",
            "with space",
            'quote"here',
            "ends-with-\",
            'slash-before-quote\"',
            "tab`tand`nnewline",
            "한글"
        )
        $roundtripResult = Invoke-ReleaseToolsetNode `
            -Toolset $proxyToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments (@("roundtrip") + $roundtripValues)
        $expectedRoundtrip = ""
        foreach ($value in $roundtripValues) {
            $expectedRoundtrip += [System.Convert]::ToBase64String(
                [System.Text.UTF8Encoding]::new($false, $true).GetBytes($value)
            ) + "`n"
        }
        if ($roundtripResult.ExitCode -ne 0 -or
            -not [string]::Equals($roundtripResult.Stdout, $expectedRoundtrip, [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($roundtripResult.Stderr, "", [System.StringComparison]::Ordinal)) {
            throw "Pinned verifier argument quoting did not round-trip exactly"
        }

        $stderrResult = Invoke-ReleaseToolsetNode `
            -Toolset $proxyToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments @("stderr")
        if ($stderrResult.ExitCode -ne 0 -or
            -not [string]::Equals($stderrResult.Stdout, $canonicalSubject + "`n", [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($stderrResult.Stderr, "diagnostic`n", [System.StringComparison]::Ordinal)) {
            throw "Verifier toolset runner changed raw stderr capture"
        }
        $nonzeroResult = Invoke-ReleaseToolsetNode `
            -Toolset $proxyToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments @("nonzero")
        if ($nonzeroResult.ExitCode -ne 23 -or
            -not [string]::Equals($nonzeroResult.Stdout, $canonicalSubject + "`n", [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($nonzeroResult.Stderr, "", [System.StringComparison]::Ordinal)) {
            throw "Verifier toolset runner changed a nonzero child result"
        }
        foreach ($rejectedMode in @("invalid-utf8", "oversize")) {
            $modeRejected = $false
            try {
                [void](Invoke-ReleaseToolsetNode `
                    -Toolset $proxyToolset `
                    -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
                    -CommandArguments @($rejectedMode))
            }
            catch {
                $modeRejected = $true
            }
            if (-not $modeRejected) {
                throw "Verifier toolset runner accepted invalid raw child output"
            }
            $recoveryResult = Invoke-ReleaseToolsetNode `
                -Toolset $proxyToolset `
                -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
                -CommandArguments @("contract")
            if ($recoveryResult.ExitCode -ne 0 -or
                -not [string]::Equals($recoveryResult.Stdout, "CONTRACT_OK`n", [System.StringComparison]::Ordinal) -or
                -not [string]::Equals($recoveryResult.Stderr, "", [System.StringComparison]::Ordinal)) {
                throw "Failed verifier invocation leaked handles or invalidated the sealed toolset"
            }
        }

        foreach ($invalidInvocation in @(
            { [void](Invoke-ReleaseToolsetNode -Toolset $proxyToolset -ScriptRelativePath "Scripts/release/review-evidence-set.mjs" -CommandArguments @()) },
            { [void](Invoke-ReleaseToolsetNode -Toolset $proxyToolset -ScriptRelativePath "scripts/release/common.ps1" -CommandArguments @()) },
            { [void](Invoke-ReleaseToolsetNode -Toolset $proxyToolset -ScriptRelativePath "scripts/release/review-evidence-set.mjs" -CommandArguments @("bad$([char]0)value")) }
        )) {
            $invalidRejected = $false
            try {
                & $invalidInvocation
            }
            catch {
                $invalidRejected = $true
            }
            if (-not $invalidRejected) {
                throw "Verifier toolset invocation accepted an invalid entrypoint or argument"
            }
        }

        $forgedToolset = [pscustomobject]@{ HandleId = $proxyToolset.HandleId }
        $forgedRejected = $false
        try {
            [void](Invoke-ReleaseToolsetNode `
                -Toolset $forgedToolset `
                -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
                -CommandArguments @("contract"))
        }
        catch {
            $forgedRejected = $true
        }
        if (-not $forgedRejected) {
            throw "Verifier toolset accepted a forged public handle"
        }

        $nodeWriteDenied = $false
        try {
            $writer = [System.IO.File]::Open(
                $proxyToolset.NodePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )
            $writer.Dispose()
        }
        catch [System.IO.IOException] {
            $nodeWriteDenied = $true
        }
        catch [System.UnauthorizedAccessException] {
            $nodeWriteDenied = $true
        }
        if (-not $nodeWriteDenied) {
            throw "Held verifier node unexpectedly allowed a concurrent writer"
        }

        $movedProxyRoot = Join-Path $testRoot "exact-proxy-toolset-moved"
        $rootRenameDenied = $false
        try {
            [System.IO.Directory]::Move($proxyFixtureRoot, $movedProxyRoot)
            [System.IO.Directory]::Move($movedProxyRoot, $proxyFixtureRoot)
        }
        catch [System.IO.IOException] {
            $rootRenameDenied = $true
        }
        catch [System.UnauthorizedAccessException] {
            $rootRenameDenied = $true
        }
        if (-not $rootRenameDenied) {
            throw "Held verifier toolset root unexpectedly allowed a concurrent rename"
        }

        $sameRootRejected = $false
        try {
            Assert-ReleaseTreesDisjoint `
                -LeftCanonicalRoot $proxyToolset.CanonicalVolumeRoot `
                -RightCanonicalRoot $proxyToolset.CanonicalVolumeRoot
        }
        catch {
            $sameRootRejected = $true
        }
        if (-not $sameRootRejected) {
            throw "Disjoint-root guard accepted equal verifier and evidence roots"
        }
        $childRootRejected = $false
        try {
            Assert-ReleaseTreesDisjoint `
                -LeftCanonicalRoot $proxyToolset.CanonicalVolumeRoot `
                -RightCanonicalRoot (Join-Path $proxyToolset.CanonicalVolumeRoot "scripts")
        }
        catch {
            $childRootRejected = $true
        }
        if (-not $childRootRejected) {
            throw "Disjoint-root guard accepted a nested verifier/evidence tree"
        }
        $inverseChildRejected = $false
        try {
            Assert-ReleaseTreesDisjoint `
                -LeftCanonicalRoot (Join-Path $proxyToolset.CanonicalVolumeRoot "scripts") `
                -RightCanonicalRoot $proxyToolset.CanonicalVolumeRoot
        }
        catch {
            $inverseChildRejected = $true
        }
        if (-not $inverseChildRejected) {
            throw "Disjoint-root guard accepted inverse verifier/evidence containment"
        }
    }
    finally {
        if ($null -ne $proxyToolset) {
            Close-VerifiedReleaseToolset -Toolset $proxyToolset
            Close-VerifiedReleaseToolset -Toolset $proxyToolset
        }
    }
    $closedRejected = $false
    try {
        [void](Invoke-ReleaseToolsetNode `
            -Toolset $proxyToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments @("contract"))
    }
    catch {
        $closedRejected = $true
    }
    if (-not $closedRejected) {
        throw "Closed verifier toolset handle remained executable"
    }
    Unprotect-TestTree -Root $proxyFixtureRoot
    $movedAfterClose = Join-Path $testRoot "exact-proxy-toolset-after-close"
    [System.IO.Directory]::Move($proxyFixtureRoot, $movedAfterClose)
    [System.IO.Directory]::Move($movedAfterClose, $proxyFixtureRoot)

    $offlineFailure = Invoke-InvalidOfflineWrapperRaw `
        -ToolsetRoot $proxyFixtureRoot `
        -PrivatePath (Join-Path $testRoot "private-release-input")
    $expectedOfflineError = "RELEASE_VERIFICATION_FAILED: offline release verification failed closed" + `
        [System.Environment]::NewLine
    if ($offlineFailure.ExitCode -ne 1 -or
        -not [string]::Equals($offlineFailure.Stdout, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($offlineFailure.Stderr, $expectedOfflineError, [System.StringComparison]::Ordinal)) {
        throw "Final release wrapper did not collapse argument failure to one path-free line"
    }

    foreach ($attack in @(
        [pscustomobject]@{ Name = "extra-file"; Mutate = {
            param($root)
            Write-NewUtf8File -LiteralPath (Join-Path $root "extra.txt") -Content "extra"
        }; Pin = "exact" },
        [pscustomobject]@{ Name = "empty-extra-directory"; Mutate = {
            param($root)
            [void](New-Item -ItemType Directory -Path (Join-Path $root "empty-extra"))
        }; Pin = "exact" },
        [pscustomobject]@{ Name = "missing-file"; Mutate = {
            param($root)
            Remove-Item -LiteralPath (Join-Path $root "extension\native-host\validate-manifest.mjs") -Force
        }; Pin = "zero" },
        [pscustomobject]@{ Name = "case-alias"; Mutate = {
            param($root)
            $source = Join-Path $root "scripts"
            $intermediate = Join-Path $root "scripts-case-intermediate"
            $alias = Join-Path $root "Scripts"
            [System.IO.Directory]::Move($source, $intermediate)
            [System.IO.Directory]::Move($intermediate, $alias)
        }; Pin = "exact" }
    )) {
        $attackRoot = Join-Path $testRoot ("attack-" + $attack.Name)
        New-TestToolsetFixture -Root $attackRoot -NodeSource $behaviorProxy -ReviewScriptContent "contract"
        & $attack.Mutate $attackRoot
        $attackHash = if ($attack.Pin -eq "exact") {
            Get-TestToolsetSha256 -Root $attackRoot
        }
        else {
            "0" * 64
        }
        Assert-ToolsetOpenRejected -Root $attackRoot -ExpectedSha256 $attackHash -Label $attack.Name
    }

    $writableRoot = Join-Path $testRoot "attack-writable"
    New-TestToolsetFixture -Root $writableRoot -NodeSource $behaviorProxy -ReviewScriptContent "contract"
    Assert-ToolsetOpenRejected `
        -Root $writableRoot `
        -ExpectedSha256 (Get-TestToolsetSha256 -Root $writableRoot) `
        -Label "writable tree" `
        -AlreadyProtected

    $directoryWritableRoot = Join-Path $testRoot "attack-directory-writable"
    New-TestToolsetFixture `
        -Root $directoryWritableRoot `
        -NodeSource $behaviorProxy `
        -ReviewScriptContent "contract"
    $directoryWritableHash = Get-TestToolsetSha256 -Root $directoryWritableRoot
    [void](Protect-TestTree -Root $directoryWritableRoot -DenyFilesOnly)
    try {
        Assert-ToolsetOpenRejected `
            -Root $directoryWritableRoot `
            -ExpectedSha256 $directoryWritableHash `
            -Label "directory-writable tree" `
            -AlreadyProtected
    }
    finally {
        Unprotect-TestTree -Root $directoryWritableRoot
    }

    $junctionTarget = Join-Path $testRoot "junction-target"
    [void](New-Item -ItemType Directory -Path $junctionTarget)
    $reparseRoot = Join-Path $testRoot "attack-reparse"
    New-TestToolsetFixture -Root $reparseRoot -NodeSource $behaviorProxy -ReviewScriptContent "contract"
    $reparsePath = Join-Path $reparseRoot "unexpected-junction"
    [void](New-Item -ItemType Junction -Path $reparsePath -Target $junctionTarget)
    try {
        Assert-ToolsetOpenRejected `
            -Root $reparseRoot `
            -ExpectedSha256 (Get-TestToolsetSha256 -Root $reparseRoot) `
            -Label "reparse entry"
    }
    finally {
        if ([System.IO.Directory]::Exists($reparsePath)) {
            [System.IO.Directory]::Delete($reparsePath)
        }
    }

    $hardlinkRoot = Join-Path $testRoot "attack-hardlink"
    New-TestToolsetFixture -Root $hardlinkRoot -NodeSource $behaviorProxy -ReviewScriptContent "contract"
    $hardlinkTarget = Join-Path $testRoot "hardlink-target.mjs"
    Write-NewUtf8File -LiteralPath $hardlinkTarget -Content "hardlink target"
    $hardlinkPath = Join-Path $hardlinkRoot "extension\native-host\validate-manifest.mjs"
    Remove-Item -LiteralPath $hardlinkPath -Force
    [void](New-Item -ItemType HardLink -Path $hardlinkPath -Target $hardlinkTarget)
    Assert-ToolsetOpenRejected `
        -Root $hardlinkRoot `
        -ExpectedSha256 (Get-TestToolsetSha256 -Root $hardlinkRoot) `
        -Label "hard-linked approved file"

    $adsRoot = Join-Path $testRoot "attack-ads"
    New-TestToolsetFixture -Root $adsRoot -NodeSource $behaviorProxy -ReviewScriptContent "contract"
    $adsPath = (Join-Path $adsRoot "extension\native-host\validate-manifest.mjs") + ":unexpected"
    $adsCreated = $false
    try {
        [System.IO.File]::WriteAllText($adsPath, "alternate stream")
        $adsCreated = $true
    }
    catch [System.NotSupportedException] {
    }
    catch [System.IO.IOException] {
    }
    if ($adsCreated) {
        Assert-ToolsetOpenRejected `
            -Root $adsRoot `
            -ExpectedSha256 (Get-TestToolsetSha256 -Root $adsRoot) `
            -Label "alternate data stream"
    }

    $reviewBundleRoot = Join-Path $testRoot "exact-review-bundle"
    $realNode = (Get-Command "node" -CommandType Application -ErrorAction Stop).Source
    [void](Invoke-ReleaseCommand -Executable $realNode -CommandArguments @(
        "--input-type=module",
        "-e",
        "import{mkdir,writeFile}from'node:fs/promises';import path from'node:path';import{REQUIRED_REVIEWED_EVIDENCE_PATHS}from'./scripts/release/release-manifest.mjs';for(const relative of REQUIRED_REVIEWED_EVIDENCE_PATHS){const target=path.join(process.argv[1],...relative.split('/'));await mkdir(path.dirname(target),{recursive:true});await writeFile(target,Buffer.from('sealed verifier review evidence for '+relative+'\n'),{flag:'wx'});}",
        $reviewBundleRoot
    ) -WorkingDirectory $RepoRoot)
    [void](Protect-TestTree -Root $reviewBundleRoot)

    $behaviorFixtureRoot = Join-Path $testRoot "wrapper-behavior-toolset"
    New-TestToolsetFixture `
        -Root $behaviorFixtureRoot `
        -NodeSource $behaviorProxy `
        -ReviewScriptContent "review-valid"
    foreach ($mode in @("review-valid", "bom", "crlf", "trailing", "stderr", "nonzero", "invalid-utf8", "oversize")) {
        Copy-Item `
            -LiteralPath $wrapperModeProxies[$mode] `
            -Destination (Join-Path $behaviorFixtureRoot "node.exe") `
            -Force
        [System.IO.File]::WriteAllText(
            (Join-Path $behaviorFixtureRoot "scripts\release\review-evidence-set.mjs"),
            $mode,
            [System.Text.UTF8Encoding]::new($false, $true)
        )
        $modeHash = Get-TestToolsetSha256 -Root $behaviorFixtureRoot
        [void](Protect-TestTree -Root $behaviorFixtureRoot)
        try {
            if ($mode -eq "review-valid") {
                $directBehaviorToolset = $null
                $directBundleLocks = $null
                try {
                    $directBehaviorToolset = Open-VerifiedReleaseToolset `
                        -ToolsetRoot $behaviorFixtureRoot `
                        -ExpectedSha256 $modeHash
                    $directBundleLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $reviewBundleRoot
                    Assert-ReleaseTreesDisjoint `
                        -LeftCanonicalRoot $directBehaviorToolset.CanonicalVolumeRoot `
                        -RightCanonicalRoot $directBundleLocks.CanonicalBundleRoot
                    $directBehaviorResult = Invoke-ReleaseToolsetNode `
                        -Toolset $directBehaviorToolset `
                        -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
                        -CommandArguments @("--bundle-root", $directBundleLocks.CanonicalBundleRoot)
                    if ($directBehaviorResult.ExitCode -ne 0 -or
                        -not [string]::Equals($directBehaviorResult.Stdout, $canonicalSubject + "`n", [System.StringComparison]::Ordinal) -or
                        -not [string]::Equals($directBehaviorResult.Stderr, "", [System.StringComparison]::Ordinal)) {
                        $directStdoutExact = [string]::Equals(
                            $directBehaviorResult.Stdout,
                            $canonicalSubject + "`n",
                            [System.StringComparison]::Ordinal
                        )
                        $directStderrEmpty = [string]::Equals(
                            $directBehaviorResult.Stderr,
                            "",
                            [System.StringComparison]::Ordinal
                        )
                        throw "Direct exact review behavior fixture failed (exit=$($directBehaviorResult.ExitCode), stdoutExact=$directStdoutExact, stderrEmpty=$directStderrEmpty)"
                    }
                }
                finally {
                    if ($null -ne $directBundleLocks) {
                        Close-ReadOnlyReleaseTreeLocks -LockSet $directBundleLocks
                    }
                    if ($null -ne $directBehaviorToolset) {
                        Close-VerifiedReleaseToolset -Toolset $directBehaviorToolset
                    }
                }
            }
            $wrapperResult = Invoke-ReviewWrapperRaw `
                -ToolsetRoot $behaviorFixtureRoot `
                -BundleRoot $reviewBundleRoot `
                -ExpectedSha256 $modeHash
        }
        finally {
            Unprotect-TestTree -Root $behaviorFixtureRoot
        }
        if ($mode -eq "review-valid") {
            if ($wrapperResult.ExitCode -ne 0 -or
                -not [string]::Equals($wrapperResult.Stdout, $canonicalSubject + "`n", [System.StringComparison]::Ordinal) -or
                -not [string]::Equals($wrapperResult.Stderr, "", [System.StringComparison]::Ordinal)) {
                $stdoutMatches = [string]::Equals(
                    $wrapperResult.Stdout,
                    $canonicalSubject + "`n",
                    [System.StringComparison]::Ordinal
                )
                $stderrEmpty = [string]::Equals(
                    $wrapperResult.Stderr,
                    "",
                    [System.StringComparison]::Ordinal
                )
                throw "Review wrapper rejected an exact raw canonical subject (exit=$($wrapperResult.ExitCode), stdoutExact=$stdoutMatches, stderrEmpty=$stderrEmpty)"
            }
        }
        else {
            Assert-FixedReviewWrapperFailure -Result $wrapperResult -Label $mode
        }
    }

    [void](Protect-TestTree -Root $behaviorFixtureRoot)
    try {
        $wrongPinResult = Invoke-ReviewWrapperRaw `
            -ToolsetRoot $behaviorFixtureRoot `
            -BundleRoot $reviewBundleRoot `
            -ExpectedSha256 ("0" * 64)
    }
    finally {
        Unprotect-TestTree -Root $behaviorFixtureRoot
    }
    Assert-FixedReviewWrapperFailure -Result $wrongPinResult -Label "wrong pinned toolset hash"

    $timeoutRejected = $false
    $timeoutStart = [System.Diagnostics.Stopwatch]::StartNew()
    $timeoutExecutableHandle = $null
    try {
        $timeoutExecutableHandle = [YourWallet.ReleaseDirectoryLock]::OpenFile($behaviorProxy)
        [void][YourWallet.ReleaseToolsetProcess]::Run(
            $timeoutExecutableHandle,
            $behaviorProxy,
            [string[]]@("sleep"),
            50,
            1024
        )
    }
    catch {
        $timeoutRejected = $true
    }
    finally {
        $timeoutStart.Stop()
        if ($null -ne $timeoutExecutableHandle) {
            $timeoutExecutableHandle.Dispose()
        }
    }
    if (-not $timeoutRejected -or $timeoutStart.Elapsed.TotalSeconds -ge 10) {
        throw "Bounded verifier subprocess timeout did not fail closed promptly"
    }

    $realNodeFixtureRoot = Join-Path $testRoot "real-node-toolset"
    $preloadMarker = Join-Path $testRoot "node-options-preload.marker"
    $preloadScript = Join-Path $testRoot "parent-preload.cjs"
    $preloadMarkerForJs = $preloadMarker.Replace("\", "\\").Replace("'", "\'")
    Write-NewUtf8File `
        -LiteralPath $preloadScript `
        -Content ("require('node:fs').writeFileSync('" + $preloadMarkerForJs + "','preloaded');")
    New-TestToolsetFixture `
        -Root $realNodeFixtureRoot `
        -NodeSource $realNode
    $realNodeFixtureHash = Get-TestToolsetSha256 -Root $realNodeFixtureRoot
    [void](Protect-TestTree -Root $realNodeFixtureRoot)
    $realToolset = $null
    $realBundleLocks = $null
    $realReleaseResult = $null
    $hadParentNodeOptions = Test-Path -LiteralPath "Env:NODE_OPTIONS"
    $parentNodeOptions = if ($hadParentNodeOptions) { $env:NODE_OPTIONS } else { $null }
    try {
        $env:NODE_OPTIONS = "--require=$preloadScript"
        $realToolset = Open-VerifiedReleaseToolset `
            -ToolsetRoot $realNodeFixtureRoot `
            -ExpectedSha256 $realNodeFixtureHash
        $realBundleLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $reviewBundleRoot
        Assert-ReleaseTreesDisjoint `
            -LeftCanonicalRoot $realToolset.CanonicalVolumeRoot `
            -RightCanonicalRoot $realBundleLocks.CanonicalBundleRoot
        $realResultFirst = Invoke-ReleaseToolsetNode `
            -Toolset $realToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments @("--bundle-root", $realBundleLocks.CanonicalBundleRoot)
        $realResultSecond = Invoke-ReleaseToolsetNode `
            -Toolset $realToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments @("--bundle-root", $realBundleLocks.CanonicalBundleRoot)
        $realReleaseResult = Invoke-ReleaseToolsetNode `
            -Toolset $realToolset `
            -ScriptRelativePath "scripts/release/release-manifest.mjs" `
            -CommandArguments @()
    }
    finally {
        if ($null -ne $realBundleLocks) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $realBundleLocks
        }
        if ($null -ne $realToolset) {
            Close-VerifiedReleaseToolset -Toolset $realToolset
        }
        if ($hadParentNodeOptions) {
            $env:NODE_OPTIONS = $parentNodeOptions
        }
        else {
            Remove-Item -LiteralPath "Env:NODE_OPTIONS" -ErrorAction SilentlyContinue
        }
        Unprotect-TestTree -Root $realNodeFixtureRoot
    }
    $realSubjectPattern = '\A\{"reviewedEvidenceSetSha256":"[0-9a-f]{64}","schema":"your-wallet-reviewed-evidence-set-subject-v1"\}\n\z'
    $expectedReleaseSmokeError = "RELEASE_INELIGIBLE: usage: release-manifest.mjs key-id|canonicalize|canonicalize-json|validate|verify [arguments]`n"
    if ($realResultFirst.ExitCode -ne 0 -or
        $realResultSecond.ExitCode -ne 0 -or
        -not [string]::Equals($realResultFirst.Stderr, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($realResultSecond.Stderr, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($realResultFirst.Stdout, $realResultSecond.Stdout, [System.StringComparison]::Ordinal) -or
        -not [System.Text.RegularExpressions.Regex]::IsMatch(
            $realResultFirst.Stdout,
            $realSubjectPattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        ) -or
        [System.IO.File]::Exists($preloadMarker)) {
        throw "Sealed real-Node review/release/validate graph was not exact and deterministic"
    }
    if ($realReleaseResult.ExitCode -ne 1 -or
        -not [string]::Equals($realReleaseResult.Stdout, "", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($realReleaseResult.Stderr, $expectedReleaseSmokeError, [System.StringComparison]::Ordinal)) {
        throw "Sealed real-Node release entry did not reach its exact direct-file guard"
    }

    $contextFixtureRoot = Join-Path $testRoot "isolated-vm-context-toolset"
    $canonicalSubjectForJs = $canonicalSubject.Replace("\", "\\").Replace("'", "\'")
    $contextReviewScript = @"
import process from "node:process";
let evalBlocked = false;
let functionBlocked = false;
try { eval("1"); } catch { evalBlocked = true; }
try { Function("return 1"); } catch { functionBlocked = true; }
const isolated =
  typeof globalThis.require === "undefined" &&
  typeof globalThis.module === "undefined" &&
  typeof globalThis.exports === "undefined" &&
  typeof globalThis.process === "undefined" &&
  typeof Buffer === "function" &&
  Buffer.from("ok", "utf8").toString("hex") === "6f6b" &&
  typeof TextDecoder === "function" &&
  new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.of(0x6f, 0x6b)) === "ok" &&
  Object.getPrototypeOf(process) === null &&
  Object.isFrozen(process) &&
  Object.isFrozen(process.argv) &&
  Object.getPrototypeOf(process.stdout) === null &&
  Object.getPrototypeOf(process.stderr) === null &&
  Object.isFrozen(process.stdout) &&
  Object.isFrozen(process.stderr) &&
  Object.keys(process).sort().join(",") === "argv,exitCode,platform,stderr,stdout" &&
  !("env" in process) &&
  !("getBuiltinModule" in process) &&
  !("binding" in process) &&
  !("dlopen" in process) &&
  evalBlocked &&
  functionBlocked;
if (!isolated) {
  process.stderr.write("isolated VM context contract failed\n");
  process.exitCode = 72;
} else {
  process.stdout.write('$canonicalSubjectForJs\n');
}
"@
    New-TestToolsetFixture `
        -Root $contextFixtureRoot `
        -NodeSource $realNode `
        -ReviewScriptContent $contextReviewScript
    $contextFixtureHash = Get-TestToolsetSha256 -Root $contextFixtureRoot
    [void](Protect-TestTree -Root $contextFixtureRoot)
    $contextToolset = $null
    try {
        $contextToolset = Open-VerifiedReleaseToolset `
            -ToolsetRoot $contextFixtureRoot `
            -ExpectedSha256 $contextFixtureHash
        $contextResult = Invoke-ReleaseToolsetNode `
            -Toolset $contextToolset `
            -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
            -CommandArguments @()
    }
    finally {
        if ($null -ne $contextToolset) {
            Close-VerifiedReleaseToolset -Toolset $contextToolset
        }
        Unprotect-TestTree -Root $contextFixtureRoot
    }
    if ($contextResult.ExitCode -ne 0 -or
        -not [string]::Equals($contextResult.Stdout, $canonicalSubject + "`n", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($contextResult.Stderr, "", [System.StringComparison]::Ordinal)) {
        throw "Sealed VM context exposed ambient globals, process capabilities, or string code generation"
    }

    $loaderAttackSources = @(
        [pscustomobject]@{
            Name = "source-bom"
            Bytes = [byte[]]([byte[]]@(0xef, 0xbb, 0xbf) + [System.Text.UTF8Encoding]::new($false, $true).GetBytes("export {};`n"))
        },
        [pscustomobject]@{
            Name = "source-invalid-utf8"
            Bytes = [byte[]]@(0xc3, 0x28)
        },
        [pscustomobject]@{
            Name = "unapproved-static-import"
            Bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes("import 'node:fs';`n")
        },
        [pscustomobject]@{
            Name = "unapproved-dynamic-import"
            Bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes("await import('node:fs/promises');`n")
        }
    )
    foreach ($loaderAttack in $loaderAttackSources) {
        $loaderAttackRoot = Join-Path $testRoot ("loader-attack-" + $loaderAttack.Name)
        New-TestToolsetFixture -Root $loaderAttackRoot -NodeSource $realNode
        [System.IO.File]::WriteAllBytes(
            (Join-Path $loaderAttackRoot "scripts\release\review-evidence-set.mjs"),
            $loaderAttack.Bytes
        )
        $loaderAttackHash = Get-TestToolsetSha256 -Root $loaderAttackRoot
        [void](Protect-TestTree -Root $loaderAttackRoot)
        $loaderAttackToolset = $null
        try {
            $loaderAttackToolset = Open-VerifiedReleaseToolset `
                -ToolsetRoot $loaderAttackRoot `
                -ExpectedSha256 $loaderAttackHash
            $loaderAttackResult = Invoke-ReleaseToolsetNode `
                -Toolset $loaderAttackToolset `
                -ScriptRelativePath "scripts/release/review-evidence-set.mjs" `
                -CommandArguments @()
        }
        finally {
            if ($null -ne $loaderAttackToolset) {
                Close-VerifiedReleaseToolset -Toolset $loaderAttackToolset
            }
            Unprotect-TestTree -Root $loaderAttackRoot
        }
        if ($loaderAttackResult.ExitCode -ne 97 -or
            -not [string]::Equals($loaderAttackResult.Stdout, "", [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($loaderAttackResult.Stderr, "", [System.StringComparison]::Ordinal)) {
            throw "Sealed VM loader accepted a forbidden source or import graph"
        }
    }

    $separateRoot = Join-Path $testRoot "separate-disjoint-tree"
    Write-NewUtf8File -LiteralPath (Join-Path $separateRoot "record.txt") -Content "separate"
    [void](Protect-TestTree -Root $separateRoot)
    $separateLocks = $null
    $separateToolset = $null
    [void](Protect-TestTree -Root $proxyFixtureRoot)
    try {
        $separateToolset = Open-VerifiedReleaseToolset `
            -ToolsetRoot $proxyFixtureRoot `
            -ExpectedSha256 $proxyFixtureHash
        $separateLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $separateRoot
        Assert-ReleaseTreesDisjoint `
            -LeftCanonicalRoot $separateToolset.CanonicalVolumeRoot `
            -RightCanonicalRoot $separateLocks.CanonicalBundleRoot
    }
    finally {
        if ($null -ne $separateLocks) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $separateLocks
        }
        if ($null -ne $separateToolset) {
            Close-VerifiedReleaseToolset -Toolset $separateToolset
        }
        Unprotect-TestTree -Root $proxyFixtureRoot
        Unprotect-TestTree -Root $separateRoot
    }

    Write-Output "POWERSHELL_VERIFIER_TOOLSET_PASS"
}
finally {
    foreach ($protectedRoot in @($activeProtections.Keys)) {
        try {
            Unprotect-TestTree -Root $protectedRoot
        }
        catch {
        }
    }
    $remainingJunction = Join-Path $testRoot "attack-reparse\unexpected-junction"
    if ([System.IO.Directory]::Exists($remainingJunction)) {
        [System.IO.Directory]::Delete($remainingJunction)
    }
    if (Test-Path -LiteralPath $safeCleanupRoot) {
        Remove-Item -LiteralPath $safeCleanupRoot -Recurse -Force
    }
}
