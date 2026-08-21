$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "common.ps1")

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("your-wallet-release-" + [System.Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $testRoot)
$safeCleanupRoot = Assert-SafeTemporaryRoot -LiteralPath $testRoot
try {
    function Test-ExactReviewBinding {
        param(
            [Parameter(Mandatory = $true)][string]$BundleRoot,
            [Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation
        )
        $BundleRoot -eq "ceremony-root" -and $OperatorConfirmedNetworkIsolation
    }
    $exactArguments = ConvertFrom-ExactNamedArguments `
        -Arguments @("-OperatorConfirmedNetworkIsolation", "-BundleRoot", "ceremony-root") `
        -RequiredValueNames @("BundleRoot") `
        -RequiredSwitchNames @("OperatorConfirmedNetworkIsolation")
    if (-not (Test-ExactReviewBinding @exactArguments)) {
        throw "Exact raw argument parsing did not preserve named switch/value binding"
    }
    foreach ($invalidArguments in @(
        (, @("-Unknown", "private-value")),
        (, @("-BundleRoot", "first", "-BundleRoot", "second", "-OperatorConfirmedNetworkIsolation")),
        (, @("-BundleRoot", "missing-switch")),
        (, @("-bundleroot", "wrong-case", "-OperatorConfirmedNetworkIsolation"))
    )) {
        $invalidRejected = $false
        try {
            [void](ConvertFrom-ExactNamedArguments `
                -Arguments $invalidArguments `
                -RequiredValueNames @("BundleRoot") `
                -RequiredSwitchNames @("OperatorConfirmedNetworkIsolation"))
        }
        catch {
            $invalidRejected = $true
        }
        if (-not $invalidRejected) {
            throw "Exact raw argument parser accepted invalid input"
        }
    }

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
            "--input-type=module",
            "-e",
            "import fs from 'node:fs';import{resolveExactReleasePath}from'./scripts/release/release-manifest.mjs';await resolveExactReleasePath(process.argv[1]);fs.lstatSync(process.argv[1]);fs.readdirSync(process.argv[1]);fs.readFileSync(process.argv[2]);",
            $lockSet.CanonicalBundleRoot,
            ([System.IO.Path]::Combine($lockSet.CanonicalBundleRoot, "evidence\record.txt"))
        ))
        $authenticodePathProbe = Get-AuthenticodeSignature -LiteralPath (
            [System.IO.Path]::Combine($lockSet.CanonicalBundleRoot, "evidence\record.txt")
        )
        if ($null -eq $authenticodePathProbe) {
            throw "Authenticode inspection did not accept the canonical volume-GUID path"
        }
        Assert-NoReparseTree -LiteralPath $lockSet.CanonicalBundleRoot
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
        $movedLockRoot = Join-Path $testRoot "read-only-lock-test-moved"
        $rootMoveWasDenied = $false
        try {
            [System.IO.Directory]::Move($lockRoot, $movedLockRoot)
            [System.IO.Directory]::Move($movedLockRoot, $lockRoot)
        }
        catch [System.IO.IOException] {
            $rootMoveWasDenied = $true
        }
        catch [System.UnauthorizedAccessException] {
            $rootMoveWasDenied = $true
        }
        if (-not $rootMoveWasDenied) {
            throw "Held release root unexpectedly allowed a concurrent rename"
        }
        $writableTreeWasRejected = $false
        try {
            Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $lockSet.CanonicalBundleRoot
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

    $aliasTargetA = Join-Path $testRoot "path-pin-a"
    $aliasTargetB = Join-Path $testRoot "path-pin-b"
    $aliasPath = Join-Path $testRoot "mutable-ancestor-alias"
    $aliasBundleA = Join-Path $aliasTargetA "bundle"
    $aliasBundleB = Join-Path $aliasTargetB "bundle"
    $aliasEvidenceA = Join-Path $aliasBundleA "evidence\record.txt"
    $aliasEvidenceB = Join-Path $aliasBundleB "evidence\record.txt"
    $aliasCheckpointA = Join-Path $aliasTargetA "checkpoint.txt"
    $aliasCheckpointB = Join-Path $aliasTargetB "checkpoint.txt"
    Write-NewUtf8File -LiteralPath $aliasEvidenceA -Content "tree-a`n"
    Write-NewUtf8File -LiteralPath $aliasEvidenceB -Content "tree-b`n"
    Write-NewUtf8File -LiteralPath $aliasCheckpointA -Content "checkpoint-a`n"
    Write-NewUtf8File -LiteralPath $aliasCheckpointB -Content "checkpoint-b`n"
    foreach ($rootPath in @($aliasBundleA, $aliasBundleB)) {
        foreach ($item in @((Get-Item -LiteralPath $rootPath -Force)) + @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse)) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
            )
        }
    }
    foreach ($checkpoint in @($aliasCheckpointA, $aliasCheckpointB)) {
        [System.IO.File]::SetAttributes(
            $checkpoint,
            ([System.IO.File]::GetAttributes($checkpoint) -bor [System.IO.FileAttributes]::ReadOnly)
        )
    }
    [void](New-Item -ItemType Junction -Path $aliasPath -Target $aliasTargetA)
    $aliasLockSet = $null
    try {
        $aliasLockSet = Open-ReadOnlyReleaseTreeLocks `
            -BundleRoot (Join-Path $aliasPath "bundle") `
            -AdditionalFiles @((Join-Path $aliasPath "checkpoint.txt"))
        $canonicalPattern = '^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\'
        if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
            $aliasLockSet.CanonicalBundleRoot,
            $canonicalPattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )) {
            throw "Pinned release root did not use a local volume-GUID path"
        }
        if (@($aliasLockSet.CanonicalAdditionalFiles).Count -ne 1) {
            throw "Pinned release external input set was not exact"
        }
        [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
            "-e",
            "const fs=require('node:fs');if(fs.readFileSync(process.argv[1],'utf8')!=='tree-a\n'||fs.readFileSync(process.argv[2],'utf8')!=='checkpoint-a\n')process.exit(7);",
            (Join-Path $aliasLockSet.CanonicalBundleRoot "evidence\record.txt"),
            @($aliasLockSet.CanonicalAdditionalFiles)[0]
        ))

        [System.IO.Directory]::Delete($aliasPath)
        [void](New-Item -ItemType Junction -Path $aliasPath -Target $aliasTargetB)
        if ([System.IO.File]::ReadAllText((Join-Path $aliasPath "bundle\evidence\record.txt")) -ne "tree-b`n") {
            throw "Ancestor alias retarget test did not reach the replacement tree"
        }
        [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
            "-e",
            "const fs=require('node:fs');if(fs.readFileSync(process.argv[1],'utf8')!=='tree-a\n'||fs.readFileSync(process.argv[2],'utf8')!=='checkpoint-a\n')process.exit(8);",
            (Join-Path $aliasLockSet.CanonicalBundleRoot "evidence\record.txt"),
            @($aliasLockSet.CanonicalAdditionalFiles)[0]
        ))
    }
    finally {
        if ($null -ne $aliasLockSet) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $aliasLockSet
        }
        if ([System.IO.Directory]::Exists($aliasPath)) {
            [System.IO.Directory]::Delete($aliasPath)
        }
    }

    $subjectRoot = Join-Path $testRoot "volume-guid-review-subject"
    $subjectReplacementParent = Join-Path $testRoot "review-subject-replacement-parent"
    $subjectReplacementRoot = Join-Path $subjectReplacementParent "volume-guid-review-subject"
    [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
        "--input-type=module",
        "-e",
        "import{mkdir,writeFile}from'node:fs/promises';import path from'node:path';import{REQUIRED_REVIEWED_EVIDENCE_PATHS}from'./scripts/release/release-manifest.mjs';for(const[root,label]of[[process.argv[1],'a'],[process.argv[2],'b']])for(const relative of REQUIRED_REVIEWED_EVIDENCE_PATHS){const target=path.join(root,...relative.split('/'));const body=Buffer.from('volume-guid review evidence '+label+' for '+relative+'\n');await mkdir(path.dirname(target),{recursive:true});await writeFile(target,body,{flag:'wx'});}",
        $subjectRoot,
        $subjectReplacementRoot
    ) -WorkingDirectory $RepoRoot)
    $caseAliasEvidence = Join-Path $subjectRoot "evidence"
    $caseAliasIntermediate = Join-Path $subjectRoot "evidence-case-swap"
    $caseAliasCapitalized = Join-Path $subjectRoot "Evidence"
    $caseAliasLocks = $null
    try {
        [System.IO.Directory]::Move($caseAliasEvidence, $caseAliasIntermediate)
        [System.IO.Directory]::Move($caseAliasIntermediate, $caseAliasCapitalized)
        foreach ($item in @((Get-Item -LiteralPath $subjectRoot -Force)) + @(Get-ChildItem -LiteralPath $subjectRoot -Force -Recurse)) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
            )
        }
        $caseAliasLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $subjectRoot
        [void](Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
            "-e",
            "const{spawnSync}=require('node:child_process');const result=spawnSync(process.execPath,[process.argv[1],'--bundle-root',process.argv[2]],{encoding:'utf8'});if(result.status===0||result.stdout!==''||result.stderr!=='REVIEW_EVIDENCE_SET_FAILED: staged evidence set is not exact\n')process.exit(9);",
            (Join-Path $RepoRoot "scripts\release\review-evidence-set.mjs"),
            $caseAliasLocks.CanonicalBundleRoot
        ) -WorkingDirectory $RepoRoot)
    }
    finally {
        if ($null -ne $caseAliasLocks) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $caseAliasLocks
        }
        if ([System.IO.Directory]::Exists($caseAliasCapitalized)) {
            [System.IO.Directory]::Move($caseAliasCapitalized, $caseAliasIntermediate)
            [System.IO.Directory]::Move($caseAliasIntermediate, $caseAliasEvidence)
        }
        elseif ([System.IO.Directory]::Exists($caseAliasIntermediate)) {
            [System.IO.Directory]::Move($caseAliasIntermediate, $caseAliasEvidence)
        }
    }
    foreach ($reviewRoot in @($subjectRoot, $subjectReplacementRoot)) {
        foreach ($item in @((Get-Item -LiteralPath $reviewRoot -Force)) + @(Get-ChildItem -LiteralPath $reviewRoot -Force -Recurse)) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
            )
        }
    }
    $subjectLocks = $null
    try {
        $subjectLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $subjectRoot
        $subject = Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
            (Join-Path $RepoRoot "scripts\release\review-evidence-set.mjs"),
            "--bundle-root",
            $subjectLocks.CanonicalBundleRoot
        ) -WorkingDirectory $RepoRoot
        if (-not [string]::IsNullOrEmpty($subject.Stderr)) {
            throw "Volume-GUID review subject produced unexpected diagnostics"
        }
        if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
            $subject.Stdout,
            '^\{"reviewedEvidenceSetSha256":"[0-9a-f]{64}","schema":"your-wallet-reviewed-evidence-set-subject-v1"\}$',
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )) {
            throw "Volume-GUID review subject was not canonical"
        }
    }
    finally {
        if ($null -ne $subjectLocks) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $subjectLocks
        }
    }

    $subjectAlias = Join-Path $testRoot "review-subject-ancestor-alias"
    [void](New-Item -ItemType Junction -Path $subjectAlias -Target $testRoot)
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $denyCreateRights = [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor `
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $denyCreateRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        $denyCreateRights,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Deny
    )
    $originalAcls = @{}
    $wrapperJob = $null
    $wrapperToolsetRoot = $null
    $wrapperToolsetOriginalAcl = $null
    try {
        foreach ($reviewRoot in @($subjectRoot, $subjectReplacementRoot)) {
            $acl = Get-Acl -LiteralPath $reviewRoot
            $originalAcls[$reviewRoot] = $acl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::All
            )
            [void]$acl.AddAccessRule($denyCreateRule)
            Set-Acl -LiteralPath $reviewRoot -AclObject $acl
        }
        $subjectMoveProbe = Join-Path $testRoot "volume-guid-review-subject-move-probe"
        $safePrefix = $safeCleanupRoot.TrimEnd("\") + "\"
        foreach ($movePath in @($subjectRoot, $subjectMoveProbe)) {
            $fullMovePath = [System.IO.Path]::GetFullPath($movePath)
            if (-not $fullMovePath.StartsWith($safePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Review wrapper move probe escaped the dedicated test root"
            }
        }
        [System.IO.Directory]::Move($subjectRoot, $subjectMoveProbe)
        [System.IO.Directory]::Move($subjectMoveProbe, $subjectRoot)

        $aliasedSubjectRoot = Join-Path $subjectAlias "volume-guid-review-subject"
        $taskRealNode = (Get-Command "node" -CommandType Application -ErrorAction Stop).Source
        $taskReadyPath = Join-Path $testRoot "review-wrapper-lock-ready.signal"
        $taskContinuePath = Join-Path $testRoot "review-wrapper-continue.signal"
        $wrapperToolsetRoot = Join-Path $testRoot "sealed-review-wrapper-toolset"
        foreach ($relativeDirectory in @("extension\native-host", "scripts\release")) {
            [void](New-Item -ItemType Directory -Path (Join-Path $wrapperToolsetRoot $relativeDirectory) -Force)
        }
        foreach ($relativeFile in @(
            "extension\native-host\validate-manifest.mjs",
            "scripts\release\common.ps1",
            "scripts\release\release-manifest.mjs",
            "scripts\release\review-evidence-set.mjs",
            "scripts\release\review-evidence-set.ps1",
            "scripts\release\verify-release-offline.ps1"
        )) {
            Copy-Item `
                -LiteralPath (Join-Path $RepoRoot $relativeFile) `
                -Destination (Join-Path $wrapperToolsetRoot $relativeFile)
        }
        $realNodeLiteral = '"' + $taskRealNode.Replace('\', '\\').Replace('"', '\"') + '"'
        $readyPathLiteral = '"' + $taskReadyPath.Replace('\', '\\').Replace('"', '\"') + '"'
        $continuePathLiteral = '"' + $taskContinuePath.Replace('\', '\\').Replace('"', '\"') + '"'
        $blockingProxySource = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public static class BlockingReviewNodeProxy {
    private static readonly string RealNode = $realNodeLiteral;
    private static readonly string ReadyPath = $readyPathLiteral;
    private static readonly string ContinuePath = $continuePathLiteral;

    private static string Quote(string value) {
        if (value == null || value.IndexOf('\0') >= 0) {
            throw new ArgumentException("Invalid delegated argument");
        }
        if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '\r', '\n', '"' }) < 0) {
            return value;
        }
        StringBuilder result = new StringBuilder();
        result.Append('"');
        int backslashes = 0;
        foreach (char current in value) {
            if (current == '\\') {
                backslashes += 1;
                continue;
            }
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
        List<string> quoted = new List<string>();
        foreach (string argument in arguments) {
            quoted.Add(Quote(argument));
        }
        return String.Join(" ", quoted.ToArray());
    }

    public static int Main(string[] arguments) {
        File.WriteAllText(ReadyPath, "ready", new UTF8Encoding(false));
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        while (!File.Exists(ContinuePath)) {
            if (DateTime.UtcNow >= deadline) {
                Console.Error.Write("blocking review proxy timed out\n");
                return 124;
            }
            Thread.Sleep(5);
        }
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = RealNode;
        start.Arguments = BuildArguments(arguments);
        start.WorkingDirectory = Environment.CurrentDirectory;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.WindowStyle = ProcessWindowStyle.Hidden;
        start.RedirectStandardInput = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (Process child = Process.Start(start)) {
            child.StandardInput.Close();
            Exception stdoutFailure = null;
            Exception stderrFailure = null;
            Thread stdoutThread = new Thread(delegate() {
                try {
                    child.StandardOutput.BaseStream.CopyTo(Console.OpenStandardOutput());
                    Console.OpenStandardOutput().Flush();
                }
                catch (Exception error) {
                    stdoutFailure = error;
                }
            });
            Thread stderrThread = new Thread(delegate() {
                try {
                    child.StandardError.BaseStream.CopyTo(Console.OpenStandardError());
                    Console.OpenStandardError().Flush();
                }
                catch (Exception error) {
                    stderrFailure = error;
                }
            });
            stdoutThread.IsBackground = true;
            stderrThread.IsBackground = true;
            stdoutThread.Start();
            stderrThread.Start();
            child.WaitForExit();
            if (!stdoutThread.Join(5000) || !stderrThread.Join(5000)) {
                return 125;
            }
            if (stdoutFailure != null || stderrFailure != null) {
                return 126;
            }
            return child.ExitCode;
        }
        }
}
"@
        $proxyNodePath = Join-Path $wrapperToolsetRoot "node.exe"
        $proxyCompileJob = Start-Job -ScriptBlock {
            param($CompilationSource, $CompilationOutput)
            $ErrorActionPreference = "Stop"
            Add-Type `
                -TypeDefinition $CompilationSource `
                -OutputAssembly $CompilationOutput `
                -OutputType ConsoleApplication
        } -ArgumentList $blockingProxySource, $proxyNodePath
        try {
            [void](Wait-Job -Job $proxyCompileJob -Timeout 60)
            if ($proxyCompileJob.State -ne "Completed") {
                throw "Blocking review proxy compilation did not complete"
            }
            [void](Receive-Job -Job $proxyCompileJob -ErrorAction Stop)
            if (-not [System.IO.File]::Exists($proxyNodePath)) {
                throw "Blocking review proxy compilation did not produce an executable"
            }
        }
        finally {
            if ($proxyCompileJob.State -eq "Running") {
                Stop-Job -Job $proxyCompileJob
            }
            Remove-Job -Job $proxyCompileJob -Force
        }
        $wrapperToolsetHash = Get-InventorySha256 -Inventory (
            Get-DirectoryInventory -LiteralPath $wrapperToolsetRoot
        )
        $wrapperToolsetAcl = Get-Acl -LiteralPath $wrapperToolsetRoot
        $wrapperToolsetOriginalAcl = $wrapperToolsetAcl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All
        )
        [void]$wrapperToolsetAcl.AddAccessRule($denyCreateRule)
        Set-Acl -LiteralPath $wrapperToolsetRoot -AclObject $wrapperToolsetAcl
        foreach ($item in @((Get-Item -LiteralPath $wrapperToolsetRoot -Force)) + @(
            Get-ChildItem -LiteralPath $wrapperToolsetRoot -Force -Recurse
        )) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
            )
        }
        $wrapperPath = Join-Path $wrapperToolsetRoot "scripts\release\review-evidence-set.ps1"
        $taskPowerShell = Join-Path `
            ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)) `
            "WindowsPowerShell\v1.0\powershell.exe"
        $rawWrapperRunnerSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace YourWalletTests {
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

    public static class RawWrapperProcess {
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
        $wrapperJob = Start-Job -ScriptBlock {
            param($PowerShellPath, $ToolsetRoot, $ReviewWrapper, $ReviewRoot, $ToolsetHash, $RunnerSource)
            Add-Type -TypeDefinition $RunnerSource
            [YourWalletTests.RawWrapperProcess]::Run(
                $PowerShellPath,
                $ToolsetRoot,
                [string[]]@(
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    $ReviewWrapper,
                    "-BundleRoot",
                    $ReviewRoot,
                    "-ExpectedVerifierToolsetSha256",
                    $ToolsetHash,
                    "-OperatorConfirmedNetworkIsolation"
                ),
                60000,
                1048576
            )
        } -ArgumentList @(
            $taskPowerShell,
            $wrapperToolsetRoot,
            $wrapperPath,
            $aliasedSubjectRoot,
            $wrapperToolsetHash,
            $rawWrapperRunnerSource
        )

        $lockObserved = $false
        for ($attempt = 0; $attempt -lt 6000; $attempt += 1) {
            if ($wrapperJob.State -in @("Completed", "Failed", "Stopped")) {
                break
            }
            if ([System.IO.File]::Exists($taskReadyPath)) {
                $lockObserved = $true
                break
            }
            Start-Sleep -Milliseconds 5
        }
        if (-not $lockObserved) {
            throw "Review wrapper test node was not reached while canonical locks were held"
        }

        $moveSucceeded = $false
        try {
            [System.IO.Directory]::Move($subjectRoot, $subjectMoveProbe)
            $moveSucceeded = $true
        }
        catch [System.IO.IOException] {
            # Expected: the wrapper still denies delete/rename sharing while its child is blocked.
        }
        catch [System.UnauthorizedAccessException] {
            # Expected equivalent on filesystems that report sharing denial as access denial.
        }
        finally {
            if ($moveSucceeded) {
                [System.IO.Directory]::Move($subjectMoveProbe, $subjectRoot)
            }
        }
        if ($moveSucceeded) {
            throw "Review wrapper released canonical locks before its Node child completed"
        }

        [System.IO.Directory]::Delete($subjectAlias)
        [void](New-Item -ItemType Junction -Path $subjectAlias -Target $subjectReplacementParent)
        [System.IO.File]::WriteAllText($taskContinuePath, "continue")
        [void](Wait-Job -Job $wrapperJob -Timeout 60)
        if ($wrapperJob.State -ne "Completed") {
            throw "Review wrapper success test did not complete"
        }
        $wrapperResult = Receive-Job -Job $wrapperJob
        if (@($wrapperResult).Count -ne 1) {
            throw "Review wrapper success test returned an unexpected result count"
        }
        if ($wrapperResult.ExitCode -ne 0) {
            throw "Review wrapper success test failed closed unexpectedly"
        }
        if (-not [string]::Equals($wrapperResult.Stderr, "", [System.StringComparison]::Ordinal)) {
            throw "Review wrapper success test produced unexpected diagnostics"
        }
        if (-not [System.String]::Equals(
            $wrapperResult.Stdout,
            $subject.Stdout + "`n",
            [System.StringComparison]::Ordinal
        )) {
            $replacementSubject = Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
                (Join-Path $RepoRoot "scripts\release\review-evidence-set.mjs"),
                "--bundle-root",
                $subjectReplacementRoot
            ) -WorkingDirectory $RepoRoot
            if ([System.String]::Equals(
                $wrapperResult.Stdout,
                $replacementSubject.Stdout + "`n",
                [System.StringComparison]::Ordinal
            )) {
                throw "Review wrapper followed the replacement ancestor alias"
            }
            throw "Review wrapper success output was not one canonical subject"
        }
    }
    finally {
        if ($null -ne $wrapperJob) {
            if ($wrapperJob.State -eq "Running") {
                Stop-Job -Job $wrapperJob
            }
            Remove-Job -Job $wrapperJob -Force
        }
        if ([System.IO.Directory]::Exists($subjectAlias)) {
            [System.IO.Directory]::Delete($subjectAlias)
        }
        if ($null -ne $wrapperToolsetOriginalAcl -and [System.IO.Directory]::Exists($wrapperToolsetRoot)) {
            $restoredToolsetAcl = [System.Security.AccessControl.DirectorySecurity]::new()
            $restoredToolsetAcl.SetSecurityDescriptorSddlForm($wrapperToolsetOriginalAcl)
            Set-Acl -LiteralPath $wrapperToolsetRoot -AclObject $restoredToolsetAcl
            foreach ($item in @((Get-ChildItem -LiteralPath $wrapperToolsetRoot -Force -Recurse)) + @(
                (Get-Item -LiteralPath $wrapperToolsetRoot -Force)
            )) {
                $attributes = [int][System.IO.File]::GetAttributes($item.FullName)
                [System.IO.File]::SetAttributes(
                    $item.FullName,
                    [System.IO.FileAttributes]($attributes -band (-bnot [int][System.IO.FileAttributes]::ReadOnly))
                )
            }
        }
        foreach ($reviewRoot in @($subjectRoot, $subjectReplacementRoot)) {
            if ($originalAcls.ContainsKey($reviewRoot)) {
                $restoredAcl = [System.Security.AccessControl.DirectorySecurity]::new()
                $restoredAcl.SetSecurityDescriptorSddlForm($originalAcls[$reviewRoot])
                Set-Acl -LiteralPath $reviewRoot -AclObject $restoredAcl
            }
        }
    }
    Write-Output "POWERSHELL_RELEASE_HELPERS_PASS"
}
finally {
    if (Test-Path -LiteralPath $safeCleanupRoot) {
        Remove-Item -LiteralPath $safeCleanupRoot -Recurse -Force
    }
}
