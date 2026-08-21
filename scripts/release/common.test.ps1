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

        $wrapperPath = Join-Path $RepoRoot "scripts\release\review-evidence-set.ps1"
        $aliasedSubjectRoot = Join-Path $subjectAlias "volume-guid-review-subject"
        $taskRealNode = (Get-Command "node" -CommandType Application -ErrorAction Stop).Source
        $taskReadyPath = Join-Path $testRoot "review-wrapper-lock-ready.signal"
        $taskContinuePath = Join-Path $testRoot "review-wrapper-continue.signal"
        $wrapperJob = Start-Job -ScriptBlock {
            param($ReviewWrapper, $ReviewRoot, $TaskRealNode, $TaskReadyPath, $TaskContinuePath)
            function node {
                [System.IO.File]::WriteAllText($TaskReadyPath, "ready")
                $deadline = [System.DateTime]::UtcNow.AddSeconds(30)
                while (-not [System.IO.File]::Exists($TaskContinuePath)) {
                    if ([System.DateTime]::UtcNow -ge $deadline) {
                        throw "Review wrapper test node continuation timed out"
                    }
                    Start-Sleep -Milliseconds 5
                }
                & $TaskRealNode @args
            }
            $output = @(& $ReviewWrapper -BundleRoot $ReviewRoot `
                -OperatorConfirmedNetworkIsolation 2>&1)
            [pscustomobject]@{
                ExitCode = $LASTEXITCODE
                Output = ($output -join [System.Environment]::NewLine)
            }
        } -ArgumentList $wrapperPath, $aliasedSubjectRoot, $taskRealNode, $taskReadyPath, $taskContinuePath

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
        if (-not [System.String]::Equals(
            $wrapperResult.Output.Trim(),
            $subject.Stdout.Trim(),
            [System.StringComparison]::Ordinal
        )) {
            $replacementSubject = Invoke-ReleaseCommand -Executable "node" -CommandArguments @(
                (Join-Path $RepoRoot "scripts\release\review-evidence-set.mjs"),
                "--bundle-root",
                $subjectReplacementRoot
            ) -WorkingDirectory $RepoRoot
            if ([System.String]::Equals(
                $wrapperResult.Output.Trim(),
                $replacementSubject.Stdout.Trim(),
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
