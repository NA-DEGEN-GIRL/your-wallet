[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$UnexpectedArguments
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($null -ne $UnexpectedArguments -and $UnexpectedArguments.Count -ne 0) {
    [System.Console]::Error.WriteLine(
        "WINDOWS_READINESS_NOT_RUN_NOT_RELEASE_EVIDENCE"
    )
    exit 21
}

$script:CaseId = "phase2g-lifecycle-local-fixture-v1"
$script:CommandProfile = "cargo-test-locked-frozen-offline-v1"
$script:EvidenceSchema = "your-wallet-windows-readiness-evidence-v1"
$script:ReleaseEligibility = "not-release-evidence"
$script:ContractSuccessSentinel =
    "WINDOWS_READINESS_CONTRACT_VALID_NOT_RELEASE_EVIDENCE"
$script:PreflightSuccessSentinel =
    "WINDOWS_READINESS_PREFLIGHT_PASS_CURRENT_USER_NON_ELEVATED"
$script:PreflightBlockedSentinel = "WINDOWS_READINESS_PREFLIGHT_BLOCKED"
$script:BlockedSentinel = "WINDOWS_READINESS_BLOCKED_NOT_RELEASE_EVIDENCE"
$script:NotRunSentinel = "WINDOWS_READINESS_NOT_RUN_NOT_RELEASE_EVIDENCE"
$script:BlockedExitCode = 20
$script:NotRunExitCode = 21
$script:NodeApplicationHandle = $null
$script:CargoApplicationHandle = $null
$script:ContractSourceHandle = $null
$script:PreflightSourceHandle = $null
$script:QualifiedTests = @(
    "key_agent_service::windows_lifecycle::tests::clean_startup_active_runtime_clean_release_reaches_normal_stopped",
    "key_agent_service::windows_lifecycle::tests::startup_missing_and_mismatch_require_checked_silent_exit78",
    "key_agent_service::windows_lifecycle::tests::active_ambiguity_reloads_prior_with_fresh_checks_candidate_with_carried_checks_and_partial_terminal",
    "key_agent_service::windows_lifecycle::tests::confirmed_active_reread_failure_never_restores_boot_or_listener_authority",
    "key_agent_service::windows_lifecycle::tests::listener_scm_and_admission_typestates_are_ordered_and_move_only",
    "key_agent_service::windows_lifecycle::tests::effect_authority_is_sealed_move_only_redacted_and_production_unmintable",
    "key_agent_service::windows_lifecycle::tests::effect_backed_startup_is_exactly_ordered_consuming_and_one_shot",
    "key_agent_service::windows_lifecycle::tests::cross_binding_duplicate_and_wrong_purpose_receipts_are_rejected_non_vacuously",
    "key_agent_service::windows_lifecycle::tests::listener_preparation_failure_and_ambiguity_preserve_effects_through_checked_exit",
    "key_agent_service::windows_lifecycle::tests::scm_running_failure_and_ambiguity_preserve_effects_through_checked_exit",
    "key_agent_service::windows_lifecycle::tests::admission_open_failure_and_ambiguity_preserve_effects_through_checked_exit",
    "key_agent_service::windows_lifecycle::tests::admission_close_precedes_stop_reject_and_failure_never_enters_cleanup",
    "key_agent_service::windows_lifecycle::tests::invalidate_then_effect_drain_gates_fixed_remaining_cleanup_without_generic_bypass",
    "key_agent_service::windows_lifecycle::tests::effect_carrier_survives_clean_reload_release_and_every_durable_terminal_class",
    "key_agent_service::windows_lifecycle::tests::post_writer_release_scm_stop_failure_and_ambiguity_are_irreversible_with_both_evidences",
    "key_agent_service::windows_lifecycle::tests::runtime_policy_alone_enforces_work_token_and_quarantine_bounds",
    "key_agent_service::windows_lifecycle::tests::cleanup_requires_exact_order_and_empties_all_runtime_registries_before_clean",
    "key_agent_service::windows_lifecycle::tests::clean_ambiguity_advances_release_policy_for_candidate_only",
    "key_agent_service::windows_lifecycle::tests::release_writer_retained_checks_retirement_and_no_receipt_is_irreversible_exit78",
    "key_agent_service::windows_lifecycle::tests::post_release_logical_failure_is_irreversible_exit78_and_never_stopped",
    "key_agent_service::windows_lifecycle::tests::retirement_fault_preserves_original_lifecycle_and_platform_cleanup_causes",
    "key_agent_service::windows_lifecycle::tests::debug_and_source_surfaces_are_redacted_silent_and_path_handle_free"
)

function Write-FixedSentinel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sentinel
    )

    [System.Console]::Out.WriteLine($Sentinel)
}

function Resolve-FixedApplication {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("cargo", "node")]
        [string]$Name
    )

    $commands = @(
        Get-Command `
            -Name $Name `
            -CommandType Application `
            -ErrorAction Stop
    )
    if ($commands.Count -lt 1) {
        throw "required application is unavailable"
    }

    $source = [System.IO.Path]::GetFullPath([string]$commands[0].Source)
    $expectedFileName = $Name + ".exe"
    if (
        -not [System.String]::Equals(
            [System.IO.Path]::GetFileName($source),
            $expectedFileName,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [System.IO.File]::Exists($source) -or
        ([System.IO.File]::GetAttributes($source) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "required application identity is invalid"
    }

    $hold = [System.IO.File]::Open(
        $source,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    return [pscustomobject]@{
        Executable = $source
        Hold = $hold
    }
}

function Close-ReadinessApplicationHandles {
    if ($null -ne $script:PreflightSourceHandle) {
        $script:PreflightSourceHandle.Dispose()
        $script:PreflightSourceHandle = $null
    }
    if ($null -ne $script:ContractSourceHandle) {
        $script:ContractSourceHandle.Dispose()
        $script:ContractSourceHandle = $null
    }
    if ($null -ne $script:CargoApplicationHandle) {
        $script:CargoApplicationHandle.Dispose()
        $script:CargoApplicationHandle = $null
    }
    if ($null -ne $script:NodeApplicationHandle) {
        $script:NodeApplicationHandle.Dispose()
        $script:NodeApplicationHandle = $null
    }
}

function Open-FixedReadOnlySource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    if (
        -not [System.IO.File]::Exists($fullPath) -or
        ([System.IO.File]::GetAttributes($fullPath) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "fixed readiness source is unavailable"
    }
    return [System.IO.File]::Open(
        $fullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
}

function ConvertTo-FixedProcessArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -gt 4096 -or $Value.IndexOf([char]0) -ge 0) {
        throw "fixed process argument is invalid"
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashes += 1
            continue
        }
        if ($character -eq [char]'"') {
            [void]$builder.Append([char]'\', (($backslashes * 2) + 1))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append([char]'\', $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append([char]'\', ($backslashes * 2))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-FixedOutputLines {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    if ($Text.Length -eq 0) {
        return
    }
    $normalized = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    if ($normalized.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(0, $normalized.Length - 1)
    }
    if ($normalized.Length -eq 0) {
        return
    }
    return [string[]]$normalized.Split([char]"`n")
}

function Stop-ReadinessChildProcess {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process
    )

    if ($Process.HasExited) {
        return
    }
    try {
        $Process.Kill()
    }
    catch {
        if ($Process.HasExited) {
            return
        }
        throw "bounded application could not be terminated"
    }
    if (-not $Process.WaitForExit(5000)) {
        throw "bounded application termination was not observed"
    }
}

function Invoke-BoundedApplication {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1000, 900000)]
        [int]$TimeoutMilliseconds,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 1048576)]
        [int]$MaximumOutputCharacters
    )

    if (
        -not [System.IO.Path]::IsPathRooted($Executable) -or
        -not [System.IO.File]::Exists($Executable) -or
        $Arguments.Count -gt 32
    ) {
        throw "bounded application is unavailable"
    }
    Assert-ExistingDirectoryTreeWithoutReparse -LiteralPath $WorkingDirectory
    $encodedArguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in $Arguments) {
        $encodedArguments.Add((ConvertTo-FixedProcessArgument -Value $argument))
    }
    $encodedArgumentLine = [string]::Join(" ", $encodedArguments.ToArray())
    if ($encodedArgumentLine.Length -gt 30000) {
        throw "fixed process arguments exceed the command-line bound"
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = $encodedArgumentLine
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new(
        $false,
        $true
    )
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new(
        $false,
        $true
    )

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) {
            throw "bounded application did not start"
        }
        $started = $true

        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $stdoutBuilder = [System.Text.StringBuilder]::new()
        $stderrBuilder = [System.Text.StringBuilder]::new()
        $stdoutBuffer = [char[]]::new(4096)
        $stderrBuffer = [char[]]::new(4096)
        $stdoutTask = $null
        $stderrTask = $null
        $stdoutDone = $false
        $stderrDone = $false
        $timedOut = $false
        $overflow = $false
        $terminationDeadline = [long]::MaxValue

        while (-not ($stdoutDone -and $stderrDone)) {
            if (
                -not $timedOut -and
                -not $overflow -and
                $clock.ElapsedMilliseconds -ge $TimeoutMilliseconds
            ) {
                $timedOut = $true
                Stop-ReadinessChildProcess -Process $process
                $terminationDeadline = $clock.ElapsedMilliseconds + 5000
            }
            if (
                ($timedOut -or $overflow) -and
                $clock.ElapsedMilliseconds -ge $terminationDeadline
            ) {
                throw "bounded application output did not close after termination"
            }

            if (-not $stdoutDone -and $null -eq $stdoutTask) {
                $stdoutTask = $process.StandardOutput.ReadAsync(
                    $stdoutBuffer,
                    0,
                    $stdoutBuffer.Length
                )
            }
            if (-not $stderrDone -and $null -eq $stderrTask) {
                $stderrTask = $process.StandardError.ReadAsync(
                    $stderrBuffer,
                    0,
                    $stderrBuffer.Length
                )
            }

            $pendingTasks =
                [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
            $pendingStreams = [System.Collections.Generic.List[string]]::new()
            if ($null -ne $stdoutTask) {
                $pendingTasks.Add($stdoutTask)
                $pendingStreams.Add("stdout")
            }
            if ($null -ne $stderrTask) {
                $pendingTasks.Add($stderrTask)
                $pendingStreams.Add("stderr")
            }
            if ($pendingTasks.Count -eq 0) {
                break
            }

            $remainingMilliseconds = if ($timedOut -or $overflow) {
                $terminationDeadline - $clock.ElapsedMilliseconds
            }
            else {
                [long]$TimeoutMilliseconds - $clock.ElapsedMilliseconds
            }
            $waitMilliseconds = [int][Math]::Max(
                1,
                [Math]::Min(250, $remainingMilliseconds)
            )
            $completedIndex = [System.Threading.Tasks.Task]::WaitAny(
                $pendingTasks.ToArray(),
                $waitMilliseconds
            )
            if ($completedIndex -lt 0) {
                continue
            }

            $streamName = $pendingStreams[$completedIndex]
            if ($streamName -eq "stdout") {
                $readCount = $stdoutTask.GetAwaiter().GetResult()
                $stdoutTask = $null
                if ($readCount -eq 0) {
                    $stdoutDone = $true
                }
                elseif (-not $overflow) {
                    if (
                        ([long]$stdoutBuilder.Length +
                            [long]$stderrBuilder.Length +
                            [long]$readCount) -gt
                            [long]$MaximumOutputCharacters
                    ) {
                        $overflow = $true
                        Stop-ReadinessChildProcess -Process $process
                        $terminationDeadline =
                            $clock.ElapsedMilliseconds + 5000
                    }
                    else {
                        [void]$stdoutBuilder.Append(
                            $stdoutBuffer,
                            0,
                            $readCount
                        )
                    }
                }
            }
            else {
                $readCount = $stderrTask.GetAwaiter().GetResult()
                $stderrTask = $null
                if ($readCount -eq 0) {
                    $stderrDone = $true
                }
                elseif (-not $overflow) {
                    if (
                        ([long]$stdoutBuilder.Length +
                            [long]$stderrBuilder.Length +
                            [long]$readCount) -gt
                            [long]$MaximumOutputCharacters
                    ) {
                        $overflow = $true
                        Stop-ReadinessChildProcess -Process $process
                        $terminationDeadline =
                            $clock.ElapsedMilliseconds + 5000
                    }
                    else {
                        [void]$stderrBuilder.Append(
                            $stderrBuffer,
                            0,
                            $readCount
                        )
                    }
                }
            }
        }

        if (-not $process.HasExited) {
            $remainingMilliseconds =
                [long]$TimeoutMilliseconds - $clock.ElapsedMilliseconds
            if (
                $remainingMilliseconds -le 0 -or
                -not $process.WaitForExit([int]$remainingMilliseconds)
            ) {
                $timedOut = $true
                Stop-ReadinessChildProcess -Process $process
            }
        }

        return [pscustomobject]@{
            ExitCode = if (-not $timedOut -and -not $overflow) {
                $process.ExitCode
            }
            else {
                -1
            }
            TimedOut = $timedOut
            Overflow = $overflow
            StdoutLines = [object[]]@(
                ConvertTo-FixedOutputLines -Text $stdoutBuilder.ToString()
            )
            StderrLines = [object[]]@(
                ConvertTo-FixedOutputLines -Text $stderrBuilder.ToString()
            )
        }
    }
    finally {
        if ($started -and -not $process.HasExited) {
            try {
                Stop-ReadinessChildProcess -Process $process
            }
            catch {
            }
        }
        $process.Dispose()
    }
}

function Test-AmbientCompilerInjection {
    $forbiddenExactNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($name in @(
        "AR",
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "CXX",
        "CXXFLAGS",
        "LD",
        "RANLIB",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_HOME",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN"
    )) {
        [void]$forbiddenExactNames.Add($name)
    }

    $environment = [System.Environment]::GetEnvironmentVariables(
        [System.EnvironmentVariableTarget]::Process
    )
    foreach ($entry in $environment.GetEnumerator()) {
        $name = [string]$entry.Key
        if (
            $forbiddenExactNames.Contains($name) -or
            $name -match
                "^(?:AR|CC|CFLAGS|CPPFLAGS|CXX|CXXFLAGS|LD|RANLIB)_.+$" -or
            $name -match
                "^CARGO_TARGET_.+_(?:LINKER|RUNNER|RUSTFLAGS)$"
        ) {
            return $true
        }
    }

    return $false
}

function Test-AmbientCargoConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $configurationRoots =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    $currentDirectory = [System.IO.DirectoryInfo]::new(
        [System.IO.Path]::GetFullPath($RepositoryRoot)
    )
    while ($null -ne $currentDirectory) {
        [void]$configurationRoots.Add(
            [System.IO.Path]::Combine($currentDirectory.FullName, ".cargo")
        )
        $currentDirectory = $currentDirectory.Parent
    }

    $userProfile = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::UserProfile
    )
    if ([string]::IsNullOrWhiteSpace($userProfile)) {
        return $true
    }
    [void]$configurationRoots.Add(
        [System.IO.Path]::Combine($userProfile, ".cargo")
    )

    foreach ($configurationRoot in $configurationRoots) {
        foreach ($fileName in @("config", "config.toml")) {
            $candidate = [System.IO.Path]::Combine(
                $configurationRoot,
                $fileName
            )
            if ([System.IO.File]::Exists($candidate)) {
                return $true
            }
        }
    }
    return $false
}

function Assert-RegularDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if (-not [System.IO.Directory]::Exists($LiteralPath)) {
        [void][System.IO.Directory]::CreateDirectory($LiteralPath)
    }
    $attributes = [System.IO.File]::GetAttributes($LiteralPath)
    if (
        ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0 -or
        ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "evidence directory is unsafe"
    }
}

function Assert-ExistingDirectoryTreeWithoutReparse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($pathRoot)) {
        throw "directory tree has no fixed root"
    }
    $currentPath = $pathRoot
    $relativePath = $fullPath.Substring($pathRoot.Length)
    $segments = $relativePath.Split(
        [char[]]@(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ),
        [System.StringSplitOptions]::RemoveEmptyEntries
    )
    foreach ($segment in $segments) {
        $currentPath = [System.IO.Path]::Combine($currentPath, $segment)
        if (-not [System.IO.Directory]::Exists($currentPath)) {
            throw "directory tree is incomplete"
        }
        $attributes = [System.IO.File]::GetAttributes($currentPath)
        if (
            ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0 -or
            ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "directory tree contains an unsafe component"
        }
    }
}

function New-EvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    Assert-ExistingDirectoryTreeWithoutReparse -LiteralPath $RepositoryRoot
    $artifactsRoot = [System.IO.Path]::Combine(
        $RepositoryRoot,
        "artifacts"
    )
    Assert-RegularDirectory -LiteralPath $artifactsRoot
    $evidenceRoot = [System.IO.Path]::Combine(
        $artifactsRoot,
        "windows-evidence"
    )
    Assert-RegularDirectory -LiteralPath $evidenceRoot
    $caseRoot = [System.IO.Path]::Combine($evidenceRoot, $script:CaseId)
    Assert-RegularDirectory -LiteralPath $caseRoot

    $runId = [System.Guid]::NewGuid().ToString("N")
    $runRoot = [System.IO.Path]::Combine($caseRoot, $runId)
    if (
        [System.IO.Directory]::Exists($runRoot) -or
        [System.IO.File]::Exists($runRoot)
    ) {
        throw "evidence run already exists"
    }
    [void][System.IO.Directory]::CreateDirectory($runRoot)
    Assert-RegularDirectory -LiteralPath $runRoot

    return [System.IO.Path]::Combine($runRoot, "evidence.json")
}

function Write-CanonicalEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidencePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet("local-fixture", "not-run", "blocked")]
        [string]$Result
    )

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('{"caseId":"')
    [void]$builder.Append($script:CaseId)
    [void]$builder.Append('","commandProfile":"')
    [void]$builder.Append($script:CommandProfile)
    [void]$builder.Append('","qualifiedTests":[')
    for ($index = 0; $index -lt $script:QualifiedTests.Count; $index += 1) {
        if ($index -ne 0) {
            [void]$builder.Append(',')
        }
        [void]$builder.Append('"')
        [void]$builder.Append($script:QualifiedTests[$index])
        [void]$builder.Append('"')
    }
    [void]$builder.Append('],"releaseEligibility":"')
    [void]$builder.Append($script:ReleaseEligibility)
    [void]$builder.Append('","result":"')
    [void]$builder.Append($Result)
    [void]$builder.Append('","schema":"')
    [void]$builder.Append($script:EvidenceSchema)
    [void]$builder.Append('"}')
    [void]$builder.Append("`n")

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($builder.ToString())
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $EvidencePath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        return $stream
    }
    catch {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        throw
    }
}

function Assert-EvidenceContract {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NodeExecutable,
        [Parameter(Mandatory = $true)]
        [string]$ContractPath,
        [Parameter(Mandatory = $true)]
        [string]$EvidencePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet("local-fixture", "not-run", "blocked")]
        [string]$ExpectedResult,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $contractResult = Invoke-BoundedApplication `
        -Executable $NodeExecutable `
        -Arguments @(
            $ContractPath,
            "check",
            "--input",
            $EvidencePath,
            "--expected-result",
            $ExpectedResult
        ) `
        -WorkingDirectory $RepositoryRoot `
        -TimeoutMilliseconds 30000 `
        -MaximumOutputCharacters 4096
    if (
        $contractResult.TimedOut -or
        $contractResult.Overflow -or
        $contractResult.ExitCode -ne 0 -or
        $contractResult.StderrLines.Count -ne 0 -or
        $contractResult.StdoutLines.Count -ne 1 -or
        -not [System.String]::Equals(
            [string]$contractResult.StdoutLines[0],
            $script:ContractSuccessSentinel,
            [System.StringComparison]::Ordinal
        )
    ) {
        throw "evidence contract rejected output"
    }
}

function Complete-EvidenceResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,
        [Parameter(Mandatory = $true)]
        [string]$NodeExecutable,
        [Parameter(Mandatory = $true)]
        [string]$ContractPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet("local-fixture", "not-run", "blocked")]
        [string]$Result,
        [Parameter(Mandatory = $true)]
        [string]$Sentinel,
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    $evidencePath = New-EvidencePath -RepositoryRoot $RepositoryRoot
    $evidenceHandle = $null
    try {
        $evidenceHandle = Write-CanonicalEvidence `
            -EvidencePath $evidencePath `
            -Result $Result
        Assert-EvidenceContract `
            -NodeExecutable $NodeExecutable `
            -ContractPath $ContractPath `
            -EvidencePath $evidencePath `
            -ExpectedResult $Result `
            -RepositoryRoot $RepositoryRoot
        Close-ReadinessApplicationHandles
        if ($ExitCode -eq 0) {
            Write-FixedSentinel -Sentinel $Sentinel
        }
        else {
            [System.Console]::Error.WriteLine($Sentinel)
        }
    }
    finally {
        if ($null -ne $evidenceHandle) {
            $evidenceHandle.Dispose()
        }
        Close-ReadinessApplicationHandles
    }
    exit $ExitCode
}

function Test-ExactSuccessfulCargoOutput {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Output
    )

    $observedTests = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $observedOutcomes = [System.Collections.Generic.List[string]]::new()
    $runningCount = 0
    $summaryCount = 0
    foreach ($outputItem in $Output) {
        $line = [string]$outputItem
        if ([System.String]::Equals(
            $line,
            "running 22 tests",
            [System.StringComparison]::Ordinal
        )) {
            $runningCount += 1
        }
        if ($line -match
            '^test (key_agent_service::windows_lifecycle::tests::[a-z0-9_]+) \.\.\. (ok|FAILED|ignored)$') {
            if (-not $observedTests.Add([string]$Matches[1])) {
                return $false
            }
            [void]$observedOutcomes.Add([string]$Matches[2])
        }
        if ($line -match
            '^test result: ok\. 22 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+$') {
            $summaryCount += 1
        }
    }

    if (
        $runningCount -ne 1 -or
        $summaryCount -ne 1 -or
        $observedTests.Count -ne $script:QualifiedTests.Count -or
        $observedOutcomes.Count -ne $script:QualifiedTests.Count
    ) {
        return $false
    }
    for ($index = 0; $index -lt $script:QualifiedTests.Count; $index += 1) {
        if (
            -not $observedTests.Contains($script:QualifiedTests[$index]) -or
            -not [System.String]::Equals(
                $observedOutcomes[$index],
                "ok",
                [System.StringComparison]::Ordinal
            )
        ) {
            return $false
        }
    }

    return $true
}

try {
    $repositoryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($PSScriptRoot, "..", "..")
    )
    Assert-ExistingDirectoryTreeWithoutReparse -LiteralPath $repositoryRoot
    $contractPath = [System.IO.Path]::Combine(
        $repositoryRoot,
        "scripts",
        "windows-evidence",
        "evidence-contract.mjs"
    )
    if (
        -not [System.IO.File]::Exists($contractPath) -or
        ([System.IO.File]::GetAttributes($contractPath) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "evidence contract is unavailable"
    }
    $script:ContractSourceHandle = Open-FixedReadOnlySource `
        -LiteralPath $contractPath

    Set-Location -LiteralPath $repositoryRoot
    $nodeApplication = Resolve-FixedApplication -Name "node"
    $nodeExecutable = $nodeApplication.Executable
    $script:NodeApplicationHandle = $nodeApplication.Hold

    $systemDirectory = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::System
    )
    $systemPowerShell = [System.IO.Path]::Combine(
        $systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe"
    )
    $preflightPath = [System.IO.Path]::Combine(
        $repositoryRoot,
        "scripts",
        "windows-evidence",
        "preflight.ps1"
    )
    if (
        [string]::IsNullOrWhiteSpace($systemDirectory) -or
        -not [System.IO.File]::Exists($systemPowerShell) -or
        -not [System.IO.File]::Exists($preflightPath) -or
        ([System.IO.File]::GetAttributes($systemPowerShell) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        Complete-EvidenceResult `
            -RepositoryRoot $repositoryRoot `
            -NodeExecutable $nodeExecutable `
            -ContractPath $contractPath `
            -Result "blocked" `
            -Sentinel $script:BlockedSentinel `
            -ExitCode $script:BlockedExitCode
    }
    Assert-ExistingDirectoryTreeWithoutReparse `
        -LiteralPath ([System.IO.Path]::GetDirectoryName($systemPowerShell))
    $script:PreflightSourceHandle = Open-FixedReadOnlySource `
        -LiteralPath $preflightPath

    $preflightResult = Invoke-BoundedApplication `
        -Executable $systemPowerShell `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $preflightPath
        ) `
        -WorkingDirectory $repositoryRoot `
        -TimeoutMilliseconds 30000 `
        -MaximumOutputCharacters 4096
    if (
        -not $preflightResult.TimedOut -and
        -not $preflightResult.Overflow -and
        $preflightResult.ExitCode -eq $script:BlockedExitCode -and
        $preflightResult.StdoutLines.Count -eq 0 -and
        $preflightResult.StderrLines.Count -eq 1 -and
        [System.String]::Equals(
            [string]$preflightResult.StderrLines[0],
            $script:PreflightBlockedSentinel,
            [System.StringComparison]::Ordinal
        )
    ) {
        Complete-EvidenceResult `
            -RepositoryRoot $repositoryRoot `
            -NodeExecutable $nodeExecutable `
            -ContractPath $contractPath `
            -Result "blocked" `
            -Sentinel $script:BlockedSentinel `
            -ExitCode $script:BlockedExitCode
    }
    if (
        $preflightResult.TimedOut -or
        $preflightResult.Overflow -or
        $preflightResult.ExitCode -ne 0 -or
        $preflightResult.StderrLines.Count -ne 0 -or
        $preflightResult.StdoutLines.Count -ne 1 -or
        -not [System.String]::Equals(
            [string]$preflightResult.StdoutLines[0],
            $script:PreflightSuccessSentinel,
            [System.StringComparison]::Ordinal
        )
    ) {
        Complete-EvidenceResult `
            -RepositoryRoot $repositoryRoot `
            -NodeExecutable $nodeExecutable `
            -ContractPath $contractPath `
            -Result "not-run" `
            -Sentinel $script:NotRunSentinel `
            -ExitCode $script:NotRunExitCode
    }

    if (
        (Test-AmbientCompilerInjection) -or
        (Test-AmbientCargoConfiguration -RepositoryRoot $repositoryRoot)
    ) {
        Complete-EvidenceResult `
            -RepositoryRoot $repositoryRoot `
            -NodeExecutable $nodeExecutable `
            -ContractPath $contractPath `
            -Result "blocked" `
            -Sentinel $script:BlockedSentinel `
            -ExitCode $script:BlockedExitCode
    }

    $cargoApplication = Resolve-FixedApplication -Name "cargo"
    $cargoExecutable = $cargoApplication.Executable
    $script:CargoApplicationHandle = $cargoApplication.Hold
    $cargoArguments = @(
        "test",
        "--frozen",
        "--offline",
        "--locked",
        "-p",
        "platform-windows",
        "--lib",
        "key_agent_service::windows_lifecycle::tests::",
        "--",
        "--test-threads=1"
    )
    $previousCargoTargetDirectory = [System.Environment]::GetEnvironmentVariable(
        "CARGO_TARGET_DIR",
        [System.EnvironmentVariableTarget]::Process
    )
    $previousCargoTermColor = [System.Environment]::GetEnvironmentVariable(
        "CARGO_TERM_COLOR",
        [System.EnvironmentVariableTarget]::Process
    )
    $previousNoColor = [System.Environment]::GetEnvironmentVariable(
        "NO_COLOR",
        [System.EnvironmentVariableTarget]::Process
    )
    $targetDirectory = [System.IO.Path]::Combine($repositoryRoot, "target")
    Assert-RegularDirectory -LiteralPath $targetDirectory
    try {
        $env:CARGO_TARGET_DIR = $targetDirectory
        $env:CARGO_TERM_COLOR = "never"
        $env:NO_COLOR = "1"
        $cargoResult = Invoke-BoundedApplication `
            -Executable $cargoExecutable `
            -Arguments $cargoArguments `
            -WorkingDirectory $repositoryRoot `
            -TimeoutMilliseconds 900000 `
            -MaximumOutputCharacters 262144
    }
    finally {
        if ($null -eq $previousCargoTargetDirectory) {
            Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        }
        else {
            $env:CARGO_TARGET_DIR = $previousCargoTargetDirectory
        }
        if ($null -eq $previousCargoTermColor) {
            Remove-Item Env:CARGO_TERM_COLOR -ErrorAction SilentlyContinue
        }
        else {
            $env:CARGO_TERM_COLOR = $previousCargoTermColor
        }
        if ($null -eq $previousNoColor) {
            Remove-Item Env:NO_COLOR -ErrorAction SilentlyContinue
        }
        else {
            $env:NO_COLOR = $previousNoColor
        }
    }

    if (
        $cargoResult.TimedOut -or
        $cargoResult.Overflow -or
        $cargoResult.ExitCode -ne 0 -or
        -not (Test-ExactSuccessfulCargoOutput -Output $cargoResult.StdoutLines)
    ) {
        Complete-EvidenceResult `
            -RepositoryRoot $repositoryRoot `
            -NodeExecutable $nodeExecutable `
            -ContractPath $contractPath `
            -Result "not-run" `
            -Sentinel $script:NotRunSentinel `
            -ExitCode $script:NotRunExitCode
    }

    Complete-EvidenceResult `
        -RepositoryRoot $repositoryRoot `
        -NodeExecutable $nodeExecutable `
        -ContractPath $contractPath `
        -Result "local-fixture" `
        -Sentinel $script:ContractSuccessSentinel `
        -ExitCode 0
}
catch {
    Close-ReadinessApplicationHandles
    [System.Console]::Error.WriteLine($script:NotRunSentinel)
    exit $script:NotRunExitCode
}
