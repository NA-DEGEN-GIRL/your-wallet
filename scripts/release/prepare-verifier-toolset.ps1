$PSModuleAutoLoadingPreference = "None"
$ErrorActionPreference = "Stop"
$script:ReleasePowerShellEntryScriptPath = $PSCommandPath

function Invoke-PrepareVerifierToolset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$NodeExecutable,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][switch]$OperatorConfirmedPreparationOnly
    )

    if (-not $OperatorConfirmedPreparationOnly) {
        throw "Verifier toolset preparation requires an explicit non-eligibility confirmation"
    }
    if ($env:OS -ne "Windows_NT") {
        throw "Verifier toolset preparation requires Windows"
    }

    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    $output = [System.IO.Path]::GetFullPath($OutputDirectory)
    $outputParent = [System.IO.Path]::GetDirectoryName($output)
    if (
        [string]::IsNullOrWhiteSpace($outputParent) -or
        [System.String]::Equals(
            $output.TrimEnd("\"),
            [System.IO.Path]::GetPathRoot($output).TrimEnd("\"),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Verifier toolset output must be one dedicated non-root directory"
    }
    $outputParent = [System.IO.Path]::GetFullPath($outputParent)
    if (-not [System.IO.Directory]::Exists($outputParent)) {
        throw "Verifier toolset output parent must already exist"
    }
    $outputPrefix = $outputParent.TrimEnd("\") + "\"
    if (-not $output.StartsWith($outputPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Verifier toolset output escaped its intended parent"
    }
    if ([System.IO.Directory]::Exists($output) -or [System.IO.File]::Exists($output)) {
        throw "Verifier toolset output must not already exist"
    }

    $nodePath = [System.IO.Path]::GetFullPath($NodeExecutable)
    $sourceFiles = [ordered]@{
        "extension/native-host/validate-manifest.mjs" = Join-Path $repoRoot "extension\native-host\validate-manifest.mjs"
        "node.exe" = $nodePath
        "scripts/release/assert-key-agent-debugger-version.ps1" = Join-Path $repoRoot "scripts\release\assert-key-agent-debugger-version.ps1"
        "scripts/release/common.ps1" = Join-Path $repoRoot "scripts\release\common.ps1"
        "scripts/release/release-manifest.mjs" = Join-Path $repoRoot "scripts\release\release-manifest.mjs"
        "scripts/release/review-evidence-set.mjs" = Join-Path $repoRoot "scripts\release\review-evidence-set.mjs"
        "scripts/release/review-evidence-set.ps1" = Join-Path $repoRoot "scripts\release\review-evidence-set.ps1"
        "scripts/release/verify-release-offline.ps1" = Join-Path $repoRoot "scripts\release\verify-release-offline.ps1"
    }
    $expectedDirectories = @(
        "extension",
        "extension/native-host",
        "scripts",
        "scripts/release"
    )

    $sourcePins = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($source in $sourceFiles.Values) {
            $sourcePins.Add((Open-PinnedReleaseFilePath -LiteralPath $source))
        }

        [void][System.IO.Directory]::CreateDirectory($output)
        foreach ($relative in $expectedDirectories) {
            [void][System.IO.Directory]::CreateDirectory(
                (Join-Path $output $relative.Replace("/", "\"))
            )
        }

        $sourceIndex = 0
        foreach ($relative in $sourceFiles.Keys) {
            $destination = Join-Path $output $relative.Replace("/", "\")
            [System.IO.File]::Copy(
                $sourcePins[$sourceIndex].CanonicalPath,
                $destination,
                $false
            )
            $sourceIndex += 1
        }

        $inventory = [System.Collections.Generic.List[object]]::new()
        foreach ($relative in $sourceFiles.Keys) {
            $file = Get-Item -LiteralPath (Join-Path $output $relative.Replace("/", "\")) -Force
            if (
                $file.PSIsContainer -or
                ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "Prepared verifier toolset contains an unsupported file"
            }
            $inventory.Add([ordered]@{
                bytes = $file.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                path = $relative
                sha256 = Get-Sha256Lower -LiteralPath $file.FullName
            })
        }
        $aggregateSha256 = Get-InventorySha256 -Inventory $inventory.ToArray()

        $items = @(Get-ChildItem -LiteralPath $output -Force -Recurse) + @((Get-Item -LiteralPath $output -Force))
        foreach ($item in $items) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                ([System.IO.File]::GetAttributes($item.FullName) -bor [System.IO.FileAttributes]::ReadOnly)
            )
        }

        [Console]::Out.Write(
            "VERIFIER_TOOLSET_SHA256=${aggregateSha256}`nVERIFIER_TOOLSET_PREPARED_NOT_RELEASE_ELIGIBLE`n"
        )
    }
    catch {
        # A partial output is deliberately left in place. Automatic recursive
        # deletion would be unsafe if an untrusted writer added an unexpected
        # entry while preparation was failing. The exact verifier will reject it.
        throw
    }
    finally {
        foreach ($pin in $sourcePins) {
            if ($null -ne $pin.FileHandle) {
                $pin.FileHandle.Dispose()
            }
            foreach ($handle in $pin.DirectoryHandles) {
                $handle.Dispose()
            }
        }
    }
}

try {
    . ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))
    $boundArguments = ConvertFrom-ExactNamedArguments `
        -Arguments @($args) `
        -RequiredValueNames @("NodeExecutable", "OutputDirectory") `
        -RequiredSwitchNames @("OperatorConfirmedPreparationOnly")
    Invoke-PrepareVerifierToolset @boundArguments
}
catch {
    [Console]::Error.WriteLine("VERIFIER_TOOLSET_PREPARATION_FAILED: preparation failed closed")
    exit 1
}
