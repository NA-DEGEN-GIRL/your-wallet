$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:ServiceProbePrepareStage = 'INITIALIZE'

function Get-ServiceProbeBuildSpecifications {
    return @(
        [pscustomobject]@{ Name = 'approval-ui.exe'; Package = 'approval-ui'; Binary = 'approval-ui'; Source = 'src/main.rs'; Feature = 'service-helper-rpc-probe-feasibility-test-hook'; Features = @('service-helper-rpc-probe-feasibility-test-hook') },
        [pscustomobject]@{ Name = 'key-agent-service-probe.exe'; Package = 'key-agent-service'; Binary = 'key-agent-service-probe'; Source = 'src/bin/key_agent_service_probe.rs'; Feature = 'desktop-rpc-probe-feasibility-test-hook'; Features = @('desktop-rpc-probe-feasibility-test-hook') },
        [pscustomobject]@{ Name = 'key-agent-service.exe'; Package = 'key-agent-service'; Binary = 'key-agent-service'; Source = 'src/main.rs'; Feature = 'lpac-rpc-probe-feasibility-test-hook'; Features = @('lpac-rpc-probe-feasibility-test-hook', 'rpc-status-feasibility-test-hook', 'scm-feasibility-test-hook', 'service-token-feasibility-test-hook') },
        [pscustomobject]@{ Name = 'secret-input-ui.exe'; Package = 'secret-input-ui'; Binary = 'secret-input-ui'; Source = 'src/main.rs'; Feature = 'service-helper-rpc-probe-feasibility-test-hook'; Features = @('service-helper-rpc-probe-feasibility-test-hook') }
    )
}

function Assert-ServiceProbeBuildEnvironment {
    # A command-line target directory and explicit debug profile are not enough
    # if a wrapper or rustc option silently changes the effective compilation.
    foreach ($name in @('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER', 'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')) {
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, 'Process'))) {
            throw 'SERVICE_PROBE_BUILD_ENVIRONMENT_REJECTED'
        }
    }
}

function Invoke-ServiceProbeCargo {
    param([string[]]$Arguments)

    [YourWallet.ServiceProbe.Harness]::RequireUnelevatedPreparation()
    Assert-ServiceProbeBuildEnvironment
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Keep all native output private. Compiler diagnostics can contain local
        # paths or source text. Only current JSON artifact provenance is used.
        $lines = @(& cargo @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    return [pscustomobject]@{ ExitCode = $code; Lines = $lines }
}

function Test-ServiceProbeExactPath {
    param($Candidate, [string]$Expected)

    if ($Candidate -isnot [string] -or [string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    try {
        if ([IO.Path]::GetPathRoot($Candidate) -cnotmatch '^[A-Za-z]:[\\/]$') { return $false }
        $full = [IO.Path]::GetFullPath($Candidate)
        return [string]::Equals($full, $Expected, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($Candidate) -ceq [IO.Path]::GetFileName($Expected)
    }
    catch { return $false }
}

function Get-ServiceProbeBuiltArtifact {
    param($Result, $Specification, [string]$Workspace, [string]$TargetDirectory)

    if ($null -eq $Result -or $null -eq $Result.PSObject.Properties['ExitCode'] -or
        $Result.ExitCode -isnot [int] -or $Result.ExitCode -ne 0 -or
        $null -eq $Result.PSObject.Properties['Lines']) {
        throw 'SERVICE_PROBE_BUILD_FAILED'
    }
    $expected = [IO.Path]::GetFullPath((Join-Path $TargetDirectory ('x86_64-pc-windows-msvc/debug/' + $Specification.Name)))
    $packageDirectory = Join-Path $Workspace ('crates/' + $Specification.Package)
    $manifest = [IO.Path]::GetFullPath((Join-Path $packageDirectory 'Cargo.toml'))
    $source = [IO.Path]::GetFullPath((Join-Path $packageDirectory $Specification.Source))
    $artifacts = @()
    $finished = @()
    foreach ($line in $Result.Lines) {
        if ($line -isnot [string]) { throw 'SERVICE_PROBE_BUILD_RECORD_REJECTED' }
        try { $message = ConvertFrom-Json -InputObject $line -ErrorAction Stop }
        catch { continue }
        if ($null -eq $message -or $null -eq $message.PSObject.Properties['reason']) { continue }
        if ($message.reason -ceq 'build-finished') { $finished += $message; continue }
        if ($message.reason -cne 'compiler-artifact') { continue }
        if ($null -eq $message.PSObject.Properties['target'] -or $null -eq $message.target -or
            $null -eq $message.target.PSObject.Properties['name']) { continue }
        if ($message.target.name -cne $Specification.Binary) { continue }
        # A matching target is never silently skipped on malformed metadata.
        foreach ($field in @('kind', 'crate_types', 'src_path')) {
            if ($null -eq $message.target.PSObject.Properties[$field]) { throw 'SERVICE_PROBE_BUILD_RECORD_REJECTED' }
        }
        foreach ($field in @('manifest_path', 'executable', 'profile', 'features', 'fresh')) {
            if ($null -eq $message.PSObject.Properties[$field]) { throw 'SERVICE_PROBE_BUILD_RECORD_REJECTED' }
        }
        if (@($message.target.kind).Count -ne 1 -or @($message.target.kind)[0] -cne 'bin' -or
            @($message.target.crate_types).Count -ne 1 -or @($message.target.crate_types)[0] -cne 'bin' -or
            -not (Test-ServiceProbeExactPath $message.manifest_path $manifest) -or
            -not (Test-ServiceProbeExactPath $message.target.src_path $source) -or
            -not (Test-ServiceProbeExactPath $message.executable $expected) -or
            $message.fresh -isnot [bool] -or $null -eq $message.profile) {
            throw 'SERVICE_PROBE_BUILD_RECORD_REJECTED'
        }
        foreach ($field in @('opt_level', 'debug_assertions', 'overflow_checks', 'test')) {
            if ($null -eq $message.profile.PSObject.Properties[$field]) { throw 'SERVICE_PROBE_BUILD_RECORD_REJECTED' }
        }
        if ($message.profile.opt_level -isnot [string] -or $message.profile.opt_level -cne '0' -or
            $message.profile.debug_assertions -isnot [bool] -or -not $message.profile.debug_assertions -or
            $message.profile.overflow_checks -isnot [bool] -or -not $message.profile.overflow_checks -or
            $message.profile.test -isnot [bool] -or $message.profile.test) {
            throw 'SERVICE_PROBE_BUILD_PROFILE_REJECTED'
        }
        $features = @($message.features)
        if ($features.Count -ne $Specification.Features.Count) { throw 'SERVICE_PROBE_BUILD_FEATURES_REJECTED' }
        for ($index = 0; $index -lt $features.Count; $index++) {
            if ($features[$index] -isnot [string] -or $features[$index] -cne $Specification.Features[$index]) {
                throw 'SERVICE_PROBE_BUILD_FEATURES_REJECTED'
            }
        }
        $artifacts += $expected
    }
    if ($artifacts.Count -ne 1 -or $finished.Count -ne 1 -or
        $null -eq $finished[0].PSObject.Properties['success'] -or
        $finished[0].success -isnot [bool] -or -not $finished[0].success) {
        throw 'SERVICE_PROBE_BUILD_PROVENANCE_REJECTED'
    }
    # A cached (fresh=true) artifact is valid only when this exact successful
    # Cargo invocation emits it. There is no fallback to an existing pathname.
    return $artifacts[0]
}

function Get-ServiceProbeHeldFileRecord {
    param([IO.FileStream]$Stream, [string]$Name, [switch]$CargoBuildSource)

    if ($CargoBuildSource) { [YourWallet.ServiceProbe.Harness]::VerifyPreparationBuildFile($Stream) }
    else { [YourWallet.ServiceProbe.Harness]::VerifyPreparationFile($Stream) }
    $length = $Stream.Length
    if ($length -lt 1 -or $length -gt 536870912) { throw 'SERVICE_PROBE_ARTIFACT_SIZE_REJECTED' }
    $Stream.Position = 0
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($hash.ComputeHash($Stream)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    if ($CargoBuildSource) { [YourWallet.ServiceProbe.Harness]::VerifyPreparationBuildFile($Stream) }
    else { [YourWallet.ServiceProbe.Harness]::VerifyPreparationFile($Stream) }
    if ($Stream.Length -ne $length -or $digest -cnotmatch '^[0-9a-f]{64}$') {
        throw 'SERVICE_PROBE_ARTIFACT_CHANGED'
    }
    return [pscustomobject]@{ Name = $Name; Bytes = $length; Sha256 = $digest; Stream = $Stream; CargoBuildSource = $CargoBuildSource.IsPresent }
}

function Get-ServiceProbeCandidateBytes {
    param([object[]]$Records)

    $specifications = @(Get-ServiceProbeBuildSpecifications)
    if ($Records.Count -ne $specifications.Count) { throw 'SERVICE_PROBE_MANIFEST_REJECTED' }
    $rows = @()
    for ($index = 0; $index -lt $Records.Count; $index++) {
        $record = $Records[$index]
        if ($record.Name -cne $specifications[$index].Name -or $record.Bytes -isnot [long] -or
            $record.Bytes -lt 1 -or $record.Bytes -gt 536870912 -or
            $record.Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'SERVICE_PROBE_MANIFEST_REJECTED' }
        $rows += '{"name":"' + $record.Name + '","bytes":' +
            $record.Bytes.ToString([Globalization.CultureInfo]::InvariantCulture) + ',"sha256":"' + $record.Sha256 + '"}'
    }
    $text = '{"schemaVersion":1,"purpose":"service-approval-transport-debug-only","architecture":"x86_64-pc-windows-msvc","artifacts":[' +
        [string]::Join(',', $rows) + "]}`n"
    return ,([Text.Encoding]::ASCII.GetBytes($text))
}

function Copy-ServiceProbeHeldArtifact {
    param($Record, [string]$Destination)

    $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try {
        $Record.Stream.Position = 0
        $Record.Stream.CopyTo($output, 65536)
        $output.Flush($true)
    }
    finally { $output.Dispose() }
    $verified = [YourWallet.ServiceProbe.Harness]::OpenPreparationFile($Destination)
    try {
        $copied = Get-ServiceProbeHeldFileRecord -Stream $verified -Name $Record.Name
        $source = Get-ServiceProbeHeldFileRecord -Stream $Record.Stream -Name $Record.Name -CargoBuildSource:$Record.CargoBuildSource
        if ($copied.Bytes -ne $Record.Bytes -or $copied.Sha256 -cne $Record.Sha256 -or
            $source.Bytes -ne $Record.Bytes -or $source.Sha256 -cne $Record.Sha256) {
            throw 'SERVICE_PROBE_COPY_REJECTED'
        }
    }
    catch { $verified.Dispose(); throw }
    # Retain the read-only output owner through manifest publication. It denies
    # write/delete sharing and rechecks content after the creating writer closed.
    return $verified
}

function Invoke-ServiceProbePrepare {
    param(
        [scriptblock]$RunCargo = { param($arguments) Invoke-ServiceProbeCargo -Arguments $arguments },
        [scriptblock]$Preflight = { [YourWallet.ServiceProbe.Harness]::RequireUnelevatedPreparation() }
    )

    $script:ServiceProbePrepareStage = 'PREFLIGHT'
    . (Join-Path $PSScriptRoot 'common.ps1')
    Import-ServiceProbeNative
    & $Preflight
    Assert-ServiceProbeBuildEnvironment
    $workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $targetDirectory = Join-Path $workspace 'target/service-probe-build'
    $artifactsDirectory = Join-Path $workspace 'artifacts'
    $candidateDirectory = Join-Path $artifactsDirectory 'service-probe-candidate'
    $owners = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    $records = @()
    try {
        $script:ServiceProbePrepareStage = 'SOURCE_ROOT'
        $owners.Add([YourWallet.ServiceProbe.Harness]::HoldPreparationDirectories($workspace))
        if (-not (Test-Path -LiteralPath $artifactsDirectory)) {
            $null = New-Item -ItemType Directory -Path $artifactsDirectory -ErrorAction Stop
        }
        $owners.Add([YourWallet.ServiceProbe.Harness]::HoldPreparationDirectories($artifactsDirectory))
        if ($null -ne (Get-Item -LiteralPath $candidateDirectory -Force -ErrorAction SilentlyContinue)) {
            throw 'SERVICE_PROBE_CANDIDATE_EXISTS'
        }
        Push-Location -LiteralPath $workspace
        try {
            foreach ($specification in @(Get-ServiceProbeBuildSpecifications)) {
                $script:ServiceProbePrepareStage = 'BUILD'
                # Repeat the native non-elevated preflight immediately before
                # every Cargo call; never build through an elevated operator.
                & $Preflight
                Assert-ServiceProbeBuildEnvironment
                $arguments = @('build', '--offline', '--locked', '--no-default-features', '--profile', 'dev',
                    '--target', 'x86_64-pc-windows-msvc', '--target-dir', $targetDirectory,
                    '-p', $specification.Package, '--bin', $specification.Binary,
                    '--features', $specification.Feature, '--message-format=json-render-diagnostics')
                $built = & $RunCargo $arguments
                $script:ServiceProbePrepareStage = 'BUILD_PROVENANCE'
                $source = Get-ServiceProbeBuiltArtifact -Result $built -Specification $specification -Workspace $workspace -TargetDirectory $targetDirectory
                $script:ServiceProbePrepareStage = 'HOLD_ARTIFACT'
                $owners.Add([YourWallet.ServiceProbe.Harness]::HoldPreparationDirectories([IO.Path]::GetDirectoryName($source)))
                # The Cargo-only opener computes the same fixed path itself.
                # It permits Cargo's one deps hardlink while denying writes via
                # either name. Unopened-alias deletion changes the recorded link
                # count and must fail revalidation before manifest publication.
                # Strict candidate/installer opens remain single-link.
                $stream = [YourWallet.ServiceProbe.Harness]::OpenPreparationBuildFile($workspace, $specification.Name)
                $owners.Add($stream)
                $records += Get-ServiceProbeHeldFileRecord -Stream $stream -Name $specification.Name -CargoBuildSource
            }
        }
        finally { Pop-Location }

        $script:ServiceProbePrepareStage = 'STAGE'
        [YourWallet.ServiceProbe.Harness]::CreatePreparationCandidate($workspace)
        $owners.Add([YourWallet.ServiceProbe.Harness]::HoldPreparationDirectories($candidateDirectory))
        foreach ($record in $records) {
            $owners.Add((Copy-ServiceProbeHeldArtifact -Record $record -Destination (Join-Path $candidateDirectory $record.Name)))
        }
        $script:ServiceProbePrepareStage = 'MANIFEST'
        # Recheck every held source after all copies, not only the most recent
        # artifact. An unopened-alias deletion must invalidate its provenance.
        foreach ($record in $records) {
            [YourWallet.ServiceProbe.Harness]::VerifyPreparationBuildFile($record.Stream)
        }
        $bytes = Get-ServiceProbeCandidateBytes -Records $records
        $manifest = [IO.File]::Open((Join-Path $candidateDirectory 'candidate.json'), [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        try {
            $manifest.Write($bytes, 0, $bytes.Length)
            $manifest.Flush($true)
        }
        finally { $manifest.Dispose() }
        $manifest = [YourWallet.ServiceProbe.Harness]::OpenPreparationFile((Join-Path $candidateDirectory 'candidate.json'))
        $owners.Add($manifest)
        & {
            $readback = New-Object byte[] $bytes.Length
            $offset = 0
            while ($offset -lt $readback.Length) {
                $read = $manifest.Read($readback, $offset, $readback.Length - $offset)
                if ($read -le 0) { throw 'SERVICE_PROBE_MANIFEST_READBACK_FAILED' }
                $offset += $read
            }
            if ($manifest.ReadByte() -ne -1 -or
                [Convert]::ToBase64String($readback) -cne [Convert]::ToBase64String($bytes)) {
                throw 'SERVICE_PROBE_MANIFEST_READBACK_FAILED'
            }
            [YourWallet.ServiceProbe.Harness]::VerifyPreparationFile($manifest)
        }
        [string[]]$actualNames = @([IO.Directory]::GetFileSystemEntries($candidateDirectory) | ForEach-Object { [IO.Path]::GetFileName($_) })
        [Array]::Sort($actualNames, [StringComparer]::Ordinal)
        $expectedNames = @('approval-ui.exe', 'candidate.json', 'key-agent-service-probe.exe', 'key-agent-service.exe', 'secret-input-ui.exe')
        if (($actualNames -join ',') -cne ($expectedNames -join ',')) { throw 'SERVICE_PROBE_CANDIDATE_INVENTORY_REJECTED' }
        $script:ServiceProbePrepareStage = 'COMPLETE'
    }
    finally {
        for ($index = $owners.Count - 1; $index -ge 0; $index--) { $owners[$index].Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -ne 0) {
        [Console]::WriteLine('SERVICE_PROBE_PREPARE_ARGUMENT_ERROR')
        [Console]::WriteLine('NOT_RELEASE_EVIDENCE')
        exit 2
    }
    try {
        Invoke-ServiceProbePrepare
        [Console]::WriteLine('SERVICE_PROBE_PREPARE_PASS')
        [Console]::WriteLine('NOT_RELEASE_EVIDENCE')
        exit 0
    }
    catch {
        # Do not print exceptions or captured Cargo output. A partial fresh
        # candidate, if any, is deliberately retained for exact-target review.
        [Console]::WriteLine('SERVICE_PROBE_PREPARE_FAIL')
        [Console]::WriteLine('stage=' + $script:ServiceProbePrepareStage)
        [Console]::WriteLine('NOT_RELEASE_EVIDENCE')
        exit 1
    }
}
