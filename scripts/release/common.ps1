$PSModuleAutoLoadingPreference = "None"
$ErrorActionPreference = "Stop"

function Initialize-ReleasePowerShellRuntime {
    if (
        $env:OS -ne "Windows_NT" -or
        -not [System.Environment]::Is64BitOperatingSystem -or
        -not [System.Environment]::Is64BitProcess -or
        -not [System.String]::Equals(
            [string]$PSVersionTable.PSEdition,
            "Desktop",
            [System.StringComparison]::Ordinal
        ) -or
        $PSVersionTable.PSVersion.Major -ne 5 -or
        $PSVersionTable.PSVersion.Minor -ne 1 -or
        $ExecutionContext.SessionState.LanguageMode -ne
            [System.Management.Automation.PSLanguageMode]::FullLanguage -or
        -not [System.String]::Equals(
            [string]$PSModuleAutoLoadingPreference,
            "None",
            [System.StringComparison]::Ordinal
        )
    ) {
        throw "invalid release host"
    }

    $systemDirectory = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::System
    )
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw "invalid release host"
    }
    $expectedPowerShellHome = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($systemDirectory, "WindowsPowerShell", "v1.0")
    )
    $expectedPowerShellImage = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($expectedPowerShellHome, "powershell.exe")
    )
    $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
    try {
        $actualPowerShellImage = [System.IO.Path]::GetFullPath(
            $currentProcess.MainModule.FileName
        )
    }
    finally {
        $currentProcess.Dispose()
    }
    if (
        -not [System.String]::Equals(
            $actualPowerShellImage,
            $expectedPowerShellImage,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [System.String]::Equals(
            [System.IO.Path]::GetFullPath($PSHOME),
            $expectedPowerShellHome,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "invalid release host"
    }

    $commandLine = [System.Environment]::GetCommandLineArgs()
    $expectedHostArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File"
    )
    if ($commandLine.Count -lt 8) {
        throw "invalid release invocation"
    }
    for ($argumentIndex = 0; $argumentIndex -lt $expectedHostArguments.Count; $argumentIndex += 1) {
        if (-not [System.String]::Equals(
            $commandLine[$argumentIndex + 1],
            $expectedHostArguments[$argumentIndex],
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "invalid release invocation"
        }
    }
    if (
        [string]::IsNullOrWhiteSpace([string]$script:ReleasePowerShellEntryScriptPath) -or
        -not [System.String]::Equals(
            [System.IO.Path]::GetFullPath($commandLine[7]),
            [System.IO.Path]::GetFullPath($script:ReleasePowerShellEntryScriptPath),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "invalid release invocation"
    }

    $entryScriptName = [System.IO.Path]::GetFileName(
        [System.IO.Path]::GetFullPath($script:ReleasePowerShellEntryScriptPath)
    )
    $approvedEntryScript = $false
    foreach ($approvedEntryScriptName in @(
        "check.ps1",
        "common.test.ps1",
        "prepare-unsigned.ps1",
        "prepare-verifier-toolset.ps1",
        "review-evidence-set.ps1",
        "verifier-toolset.test.ps1",
        "verify-authenticode.ps1",
        "verify-release-offline.ps1"
    )) {
        if ([System.String]::Equals(
            $entryScriptName,
            $approvedEntryScriptName,
            [System.StringComparison]::Ordinal
        )) {
            $approvedEntryScript = $true
        }
    }
    if (-not $approvedEntryScript) {
        throw "invalid release invocation"
    }

    foreach ($protectedTypeName in @(
        "YourWallet.ReleaseDirectoryLock",
        "YourWallet.ReleaseToolsetProcessResult",
        "YourWallet.ReleaseToolsetProcess"
    )) {
        if ($null -ne ($protectedTypeName -as [type])) {
            throw "pre-existing release runtime type"
        }
    }

    foreach ($visibleAlias in @(
        $ExecutionContext.SessionState.InvokeCommand.GetCommands(
            "*",
            [System.Management.Automation.CommandTypes]::Alias,
            $true
        )
    )) {
        if ($visibleAlias.Name.Contains("-")) {
            throw "release host contains an ambient long-form alias"
        }
    }

    $automationAssembly = [System.Management.Automation.PSObject].Assembly
    $getModuleCommand = $ExecutionContext.SessionState.InvokeCommand.GetCommand(
        "Get-Module",
        [System.Management.Automation.CommandTypes]::Cmdlet
    )
    $importModuleCommand = $ExecutionContext.SessionState.InvokeCommand.GetCommand(
        "Import-Module",
        [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if (
        $null -eq $getModuleCommand -or
        $null -eq $importModuleCommand -or
        $getModuleCommand.CommandType -ne [System.Management.Automation.CommandTypes]::Cmdlet -or
        $importModuleCommand.CommandType -ne [System.Management.Automation.CommandTypes]::Cmdlet -or
        -not [System.String]::Equals(
            $getModuleCommand.ModuleName,
            "Microsoft.PowerShell.Core",
            [System.StringComparison]::Ordinal
        ) -or
        -not [System.String]::Equals(
            $importModuleCommand.ModuleName,
            "Microsoft.PowerShell.Core",
            [System.StringComparison]::Ordinal
        ) -or
        -not [System.String]::Equals(
            $getModuleCommand.ImplementingType.FullName,
            "Microsoft.PowerShell.Commands.GetModuleCommand",
            [System.StringComparison]::Ordinal
        ) -or
        -not [System.String]::Equals(
            $importModuleCommand.ImplementingType.FullName,
            "Microsoft.PowerShell.Commands.ImportModuleCommand",
            [System.StringComparison]::Ordinal
        ) -or
        -not [object]::ReferenceEquals(
            $getModuleCommand.ImplementingType.Assembly,
            $automationAssembly
        ) -or
        -not [object]::ReferenceEquals(
            $importModuleCommand.ImplementingType.Assembly,
            $automationAssembly
        )
    ) {
        throw "invalid release bootstrap commands"
    }
    if (@(& $getModuleCommand -All -ErrorAction Stop).Count -ne 0) {
        throw "release host already contains a loaded module"
    }

    foreach ($coreCommandName in @(
        "ForEach-Object",
        "Get-Command",
        "Get-Module",
        "Import-Module",
        "Set-StrictMode",
        "Where-Object"
    )) {
        $visibleCommands = @(
            $ExecutionContext.SessionState.InvokeCommand.GetCommands(
                $coreCommandName,
                [System.Management.Automation.CommandTypes]::All,
                $true
            )
        )
        if (
            $visibleCommands.Count -ne 1 -or
            $visibleCommands[0].CommandType -ne
                [System.Management.Automation.CommandTypes]::Cmdlet -or
            -not [System.String]::Equals(
                $visibleCommands[0].ModuleName,
                "Microsoft.PowerShell.Core",
                [System.StringComparison]::Ordinal
            ) -or
            -not [object]::ReferenceEquals(
                $visibleCommands[0].ImplementingType.Assembly,
                $automationAssembly
            )
        ) {
            throw "release core command surface is shadowed before module import"
        }
    }
    foreach ($moduleCommandName in @(
        "Add-Type",
        "Copy-Item",
        "Get-AuthenticodeSignature",
        "Get-ChildItem",
        "Get-Item",
        "Get-Location",
        "Get-Variable",
        "Join-Path",
        "Move-Item",
        "New-Item",
        "Remove-Item",
        "Resolve-Path",
        "Set-Location",
        "Sort-Object",
        "Split-Path",
        "Test-Path",
        "Write-Output"
    )) {
        if (@(
            $ExecutionContext.SessionState.InvokeCommand.GetCommands(
                $moduleCommandName,
                [System.Management.Automation.CommandTypes]::All,
                $true
            )
        ).Count -ne 0) {
            throw "release module command surface is shadowed before module import"
        }
    }

    $trustedModules = [System.Collections.Generic.Dictionary[
        string,
        System.Management.Automation.PSModuleInfo
    ]]::new([System.StringComparer]::Ordinal)
    foreach ($moduleName in @(
        "Microsoft.PowerShell.Management",
        "Microsoft.PowerShell.Utility",
        "Microsoft.PowerShell.Security"
    )) {
        $manifestPath = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::Combine(
                $expectedPowerShellHome,
                "Modules",
                $moduleName,
                $moduleName + ".psd1"
            )
        )
        if (
            -not [System.IO.File]::Exists($manifestPath) -or
            ([System.IO.File]::GetAttributes($manifestPath) -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "trusted release module manifest is unavailable"
        }
        $importedModules = @(
            & $importModuleCommand `
                -Name $manifestPath `
                -Force `
                -PassThru `
                -ErrorAction Stop
        )
        if (
            $importedModules.Count -ne 1 -or
            -not [System.String]::Equals(
                $importedModules[0].Name,
                $moduleName,
                [System.StringComparison]::Ordinal
            ) -or
            -not [System.String]::Equals(
                [System.IO.Path]::GetFullPath($importedModules[0].Path),
                $manifestPath,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "trusted release module identity is invalid"
        }
        $trustedModules.Add($moduleName, $importedModules[0])
    }

    $trustedCommands = [System.Collections.Generic.Dictionary[
        string,
        System.Management.Automation.CommandInfo
    ]]::new([System.StringComparer]::Ordinal)
    foreach ($coreCommandName in @(
        "ForEach-Object",
        "Get-Command",
        "Get-Module",
        "Import-Module",
        "Set-StrictMode",
        "Where-Object"
    )) {
        $visibleCommands = @(
            $ExecutionContext.SessionState.InvokeCommand.GetCommands(
                $coreCommandName,
                [System.Management.Automation.CommandTypes]::All,
                $true
            )
        )
        if (
            $visibleCommands.Count -ne 1 -or
            $visibleCommands[0].CommandType -ne
                [System.Management.Automation.CommandTypes]::Cmdlet -or
            -not [System.String]::Equals(
                $visibleCommands[0].ModuleName,
                "Microsoft.PowerShell.Core",
                [System.StringComparison]::Ordinal
            ) -or
            -not [object]::ReferenceEquals(
                $visibleCommands[0].ImplementingType.Assembly,
                $automationAssembly
            )
        ) {
            throw "release core command surface is shadowed"
        }
        $trustedCommands.Add($coreCommandName, $visibleCommands[0])
    }

    $moduleCommandOwners = [ordered]@{
        "Add-Type" = "Microsoft.PowerShell.Utility"
        "Copy-Item" = "Microsoft.PowerShell.Management"
        "Get-AuthenticodeSignature" = "Microsoft.PowerShell.Security"
        "Get-ChildItem" = "Microsoft.PowerShell.Management"
        "Get-Item" = "Microsoft.PowerShell.Management"
        "Get-Location" = "Microsoft.PowerShell.Management"
        "Get-Variable" = "Microsoft.PowerShell.Utility"
        "Join-Path" = "Microsoft.PowerShell.Management"
        "Move-Item" = "Microsoft.PowerShell.Management"
        "New-Item" = "Microsoft.PowerShell.Management"
        "Remove-Item" = "Microsoft.PowerShell.Management"
        "Resolve-Path" = "Microsoft.PowerShell.Management"
        "Set-Location" = "Microsoft.PowerShell.Management"
        "Sort-Object" = "Microsoft.PowerShell.Utility"
        "Split-Path" = "Microsoft.PowerShell.Management"
        "Test-Path" = "Microsoft.PowerShell.Management"
        "Write-Output" = "Microsoft.PowerShell.Utility"
    }
    foreach ($commandName in $moduleCommandOwners.Keys) {
        $moduleName = $moduleCommandOwners[$commandName]
        $expectedCommand = $trustedModules[$moduleName].ExportedCommands[$commandName]
        $visibleCommands = @(
            $ExecutionContext.SessionState.InvokeCommand.GetCommands(
                $commandName,
                [System.Management.Automation.CommandTypes]::All,
                $true
            )
        )
        if (
            $null -eq $expectedCommand -or
            $visibleCommands.Count -ne 1 -or
            $visibleCommands[0].CommandType -ne $expectedCommand.CommandType -or
            -not [System.String]::Equals(
                $visibleCommands[0].ModuleName,
                $moduleName,
                [System.StringComparison]::Ordinal
            ) -or
            -not [System.String]::Equals(
                [System.IO.Path]::GetFullPath($visibleCommands[0].Module.Path),
                [System.IO.Path]::GetFullPath($trustedModules[$moduleName].Path),
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "release module command surface is shadowed"
        }
        if ($visibleCommands[0].CommandType -eq [System.Management.Automation.CommandTypes]::Cmdlet) {
            if (-not [object]::ReferenceEquals(
                $visibleCommands[0].ImplementingType,
                $expectedCommand.ImplementingType
            )) {
                throw "release module cmdlet identity is invalid"
            }
        }
        elseif (-not [System.String]::Equals(
            $visibleCommands[0].Definition,
            $expectedCommand.Definition,
            [System.StringComparison]::Ordinal
        )) {
            throw "release module function identity is invalid"
        }
        $trustedCommands.Add($commandName, $visibleCommands[0])
    }

    $compressionTypes = @(
        & $trustedCommands["Add-Type"] `
            -AssemblyName "System.IO.Compression" `
            -PassThru `
            -ErrorAction Stop
    )
    $zipArchiveType = $null
    $zipArchiveModeType = $null
    foreach ($candidateType in $compressionTypes) {
        if ([System.String]::Equals(
            $candidateType.FullName,
            "System.IO.Compression.ZipArchive",
            [System.StringComparison]::Ordinal
        )) {
            if ($null -ne $zipArchiveType) {
                throw "compression runtime type is duplicated"
            }
            $zipArchiveType = $candidateType
        }
        elseif ([System.String]::Equals(
            $candidateType.FullName,
            "System.IO.Compression.ZipArchiveMode",
            [System.StringComparison]::Ordinal
        )) {
            if ($null -ne $zipArchiveModeType) {
                throw "compression runtime type is duplicated"
            }
            $zipArchiveModeType = $candidateType
        }
    }
    if (
        $null -eq $zipArchiveType -or
        $null -eq $zipArchiveModeType -or
        -not $zipArchiveType.IsPublic -or
        -not $zipArchiveModeType.IsPublic -or
        -not $zipArchiveModeType.IsEnum -or
        -not [object]::ReferenceEquals(
            $zipArchiveType.Assembly,
            $zipArchiveModeType.Assembly
        )
    ) {
        throw "compression runtime types are unavailable"
    }

    $compressionLevelType = $null
    foreach ($candidateMethod in $zipArchiveType.GetMethods(
        [System.Reflection.BindingFlags]::Instance -bor
            [System.Reflection.BindingFlags]::Public
    )) {
        $parameters = $candidateMethod.GetParameters()
        if (
            [System.String]::Equals(
                $candidateMethod.Name,
                "CreateEntry",
                [System.StringComparison]::Ordinal
            ) -and
            $parameters.Count -eq 2 -and
            [object]::ReferenceEquals($parameters[0].ParameterType, [string]) -and
            [System.String]::Equals(
                $parameters[1].ParameterType.FullName,
                "System.IO.Compression.CompressionLevel",
                [System.StringComparison]::Ordinal
            )
        ) {
            if ($null -ne $compressionLevelType) {
                throw "compression level type is ambiguous"
            }
            $compressionLevelType = $parameters[1].ParameterType
        }
    }
    if (
        $null -eq $compressionLevelType -or
        -not $compressionLevelType.IsEnum -or
        -not $compressionLevelType.IsPublic
    ) {
        throw "compression level type is unavailable"
    }

    $expectedFrameworkToken = [byte[]]@(
        0xb7,
        0x7a,
        0x5c,
        0x56,
        0x19,
        0x34,
        0xe0,
        0x89
    )
    $windowsRoot = [System.IO.Path]::GetFullPath(
        [System.Environment]::GetFolderPath(
            [System.Environment+SpecialFolder]::Windows
        )
    ).TrimEnd([char[]]"\/")
    $windowsRootPrefix = $windowsRoot + [System.IO.Path]::DirectorySeparatorChar
    foreach ($frameworkAssembly in @(
        $zipArchiveType.Assembly,
        $compressionLevelType.Assembly
    )) {
        $frameworkAssemblyName = $frameworkAssembly.GetName()
        $expectedAssemblyName = if ([object]::ReferenceEquals(
            $frameworkAssembly,
            $zipArchiveType.Assembly
        )) {
            "System.IO.Compression"
        }
        else {
            "System"
        }
        $actualFrameworkToken = $frameworkAssemblyName.GetPublicKeyToken()
        $frameworkLocation = [System.IO.Path]::GetFullPath(
            $frameworkAssembly.Location
        )
        if (
            $frameworkAssembly.IsDynamic -or
            -not $frameworkAssembly.GlobalAssemblyCache -or
            -not [System.String]::Equals(
                $frameworkAssemblyName.Name,
                $expectedAssemblyName,
                [System.StringComparison]::Ordinal
            ) -or
            -not [System.String]::Equals(
                $frameworkAssemblyName.Version.ToString(),
                "4.0.0.0",
                [System.StringComparison]::Ordinal
            ) -or
            $actualFrameworkToken.Count -ne $expectedFrameworkToken.Count -or
            -not $frameworkLocation.StartsWith(
                $windowsRootPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [System.IO.File]::Exists($frameworkLocation) -or
            ([System.IO.File]::GetAttributes($frameworkLocation) -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "compression framework assembly identity is invalid"
        }
        for (
            $tokenIndex = 0;
            $tokenIndex -lt $expectedFrameworkToken.Count;
            $tokenIndex += 1
        ) {
            if ($actualFrameworkToken[$tokenIndex] -ne
                $expectedFrameworkToken[$tokenIndex]) {
                throw "compression framework assembly identity is invalid"
            }
        }
    }

    $script:ReleaseZipArchiveType = $zipArchiveType
    $script:ReleaseZipArchiveModeType = $zipArchiveModeType
    $script:ReleaseCompressionLevelType = $compressionLevelType
    $script:ReleaseZipArchiveReadMode = [System.Enum]::Parse(
        $zipArchiveModeType,
        "Read",
        $false
    )
    $script:ReleaseZipArchiveCreateMode = [System.Enum]::Parse(
        $zipArchiveModeType,
        "Create",
        $false
    )
    $script:ReleaseNoCompressionLevel = [System.Enum]::Parse(
        $compressionLevelType,
        "NoCompression",
        $false
    )
    $script:ReleaseTrustedCommands = $trustedCommands
    $script:ReleaseDirectoryLockType = $null
    $script:ReleaseToolsetProcessResultType = $null
    $script:ReleaseToolsetProcessType = $null
}

try {
    $initializeRuntimeCommands = @(
        $ExecutionContext.SessionState.InvokeCommand.GetCommands(
            "Initialize-ReleasePowerShellRuntime",
            [System.Management.Automation.CommandTypes]::Function,
            $true
        )
    )
    if ($initializeRuntimeCommands.Count -ne 1) {
        throw "release runtime initializer identity is ambiguous"
    }
    & $initializeRuntimeCommands[0]
    & $script:ReleaseTrustedCommands["Set-StrictMode"] -Version Latest
}
catch {
    throw "Release PowerShell runtime bootstrap failed closed"
}

function Invoke-ReleaseCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$CommandArguments,
        [Parameter(Mandatory = $false)][string]$WorkingDirectory = (Get-Location).Path
    )

    if ([System.IO.Path]::IsPathRooted($Executable)) {
        $applicationPath = [System.IO.Path]::GetFullPath($Executable)
    }
    else {
        $applicationCommand =
            $ExecutionContext.SessionState.InvokeCommand.GetCommand(
                $Executable,
                [System.Management.Automation.CommandTypes]::Application
            )
        if ($null -eq $applicationCommand) {
            throw "Release application is unavailable"
        }
        $applicationPath = [System.IO.Path]::GetFullPath(
            $applicationCommand.Path
        )
    }
    if (
        -not [System.IO.File]::Exists($applicationPath) -or
        ([System.IO.File]::GetAttributes($applicationPath) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Release application identity is invalid"
    }

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
            $stdoutLines = @(& $applicationPath @CommandArguments 2> $stderrPath)
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
        throw "Release command failed closed with exit code ${exitCode} (executable and output withheld; inspect locally with privacy redaction)"
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
    $attributes = [System.IO.File]::GetAttributes($LiteralPath)
    if (
        ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
        ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Hash target must be a regular file"
    }
    $stream = [System.IO.File]::Open(
        $LiteralPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $hasher.ComputeHash($stream)
        }
        finally {
            $hasher.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
    ([System.BitConverter]::ToString($hash) -replace "-", "").ToLowerInvariant()
}

function Get-ReleaseAuthenticodeSignature {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $trustedCommand = $script:ReleaseTrustedCommands["Get-AuthenticodeSignature"]
    $visibleCommands = @(
        $ExecutionContext.SessionState.InvokeCommand.GetCommands(
            "Get-AuthenticodeSignature",
            [System.Management.Automation.CommandTypes]::All,
            $true
        )
    )
    if (
        $visibleCommands.Count -ne 1 -or
        $visibleCommands[0].CommandType -ne $trustedCommand.CommandType -or
        -not [System.String]::Equals(
            $visibleCommands[0].ModuleName,
            $trustedCommand.ModuleName,
            [System.StringComparison]::Ordinal
        ) -or
        -not [System.String]::Equals(
            [System.IO.Path]::GetFullPath($visibleCommands[0].Module.Path),
            [System.IO.Path]::GetFullPath($trustedCommand.Module.Path),
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [object]::ReferenceEquals(
            $visibleCommands[0].ImplementingType,
            $trustedCommand.ImplementingType
        )
    ) {
        throw "Authenticode command identity changed after release bootstrap"
    }
    $signatures = @(& $trustedCommand -LiteralPath $LiteralPath -ErrorAction Stop)
    if ($signatures.Count -ne 1) {
        throw "Authenticode inspection returned an invalid result count"
    }
    $signatures[0]
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
    if ($null -ne $script:ReleaseDirectoryLockType) {
        $resolvedType = "YourWallet.ReleaseDirectoryLock" -as [type]
        if (-not [object]::ReferenceEquals($resolvedType, $script:ReleaseDirectoryLockType)) {
            throw "Release directory lock type identity changed"
        }
        return
    }
    if ($null -ne ("YourWallet.ReleaseDirectoryLock" -as [type])) {
        throw "Release directory lock type was preloaded"
    }
    $addTypeCommand = $script:ReleaseTrustedCommands["Add-Type"]
    $compiledTypes = @(
        & $addTypeCommand -PassThru -TypeDefinition @"
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
        private const uint VolumeNameDos = 0x00000000;
        private const int FindStreamInfoStandard = 0;
        private const int ErrorHandleEof = 38;

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

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime {
            internal uint LowDateTime;
            internal uint HighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation {
            internal uint FileAttributes;
            internal FileTime CreationTime;
            internal FileTime LastAccessTime;
            internal FileTime LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Win32FindStreamData {
            internal long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            internal string StreamName;
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

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstStreamW(
            string fileName,
            int informationLevel,
            out Win32FindStreamData findStreamData,
            uint flags
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStreamW(
            IntPtr findStream,
            out Win32FindStreamData findStreamData
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr findFile);

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

        public static string GetFinalDosPath(SafeFileHandle handle) {
            StringBuilder path = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, VolumeNameDos);
            if (length == 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not obtain a local DOS path for a pinned release path");
            }
            if (length >= path.Capacity) {
                throw new IOException("Pinned release DOS path exceeds the supported path length");
            }
            return path.ToString();
        }

        public static void AssertOnlyDefaultDataStream(string path) {
            Win32FindStreamData stream;
            IntPtr search = FindFirstStreamW(path, FindStreamInfoStandard, out stream, 0);
            if (search == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect release file data streams");
            }
            try {
                int count = 0;
                do {
                    count += 1;
                    if (!String.Equals(stream.StreamName, "::`$DATA", StringComparison.Ordinal)) {
                        throw new IOException("Release toolset files may not contain alternate data streams");
                    }
                } while (FindNextStreamW(search, out stream));
                int error = Marshal.GetLastWin32Error();
                if (error != ErrorHandleEof) {
                    throw new Win32Exception(error, "Could not finish inspecting release file data streams");
                }
                if (count != 1) {
                    throw new IOException("Release toolset file stream inventory is unsupported");
                }
            }
            finally {
                FindClose(search);
            }
        }

        public static void AssertSingleLink(SafeFileHandle handle) {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect release file link count");
            }
            if (information.NumberOfLinks != 1) {
                throw new IOException("Release toolset files must have exactly one hard link");
            }
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
    )
    $compiledType = $null
    foreach ($candidateType in $compiledTypes) {
        if ([System.String]::Equals(
            $candidateType.FullName,
            "YourWallet.ReleaseDirectoryLock",
            [System.StringComparison]::Ordinal
        )) {
            if ($null -ne $compiledType) {
                throw "Release directory lock compilation returned a duplicate type"
            }
            $compiledType = $candidateType
        }
    }
    $resolvedType = "YourWallet.ReleaseDirectoryLock" -as [type]
    if (
        $null -eq $compiledType -or
        -not [object]::ReferenceEquals($resolvedType, $compiledType)
    ) {
        throw "Release directory lock compilation returned an invalid type"
    }
    $script:ReleaseDirectoryLockType = $compiledType
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
    $bootstrap = $script:ReleaseDirectoryLockType::OpenDirectory($LiteralPath)
    $handles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    try {
        $canonical = $script:ReleaseDirectoryLockType::GetFinalVolumePath($bootstrap)
        foreach ($directoryPath in @(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $canonical)) {
            $handles.Add($script:ReleaseDirectoryLockType::OpenDirectory($directoryPath))
        }
        if (
            $handles.Count -eq 0 -or
            -not $script:ReleaseDirectoryLockType::SameIdentity($bootstrap, $handles[$handles.Count - 1])
        ) {
            throw "Release directory identity changed while its canonical path was pinned"
        }
        $confirmed = $script:ReleaseDirectoryLockType::GetFinalVolumePath($handles[$handles.Count - 1])
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
    $bootstrap = $script:ReleaseDirectoryLockType::OpenFile($LiteralPath)
    $directoryHandles = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $fileHandle = $null
    try {
        $canonical = $script:ReleaseDirectoryLockType::GetFinalVolumePath($bootstrap)
        $lastSeparator = $canonical.LastIndexOf("\", [System.StringComparison]::Ordinal)
        if ($lastSeparator -lt 0) {
            throw "Pinned release file has no canonical parent"
        }
        $parent = $canonical.Substring(0, $lastSeparator)
        foreach ($directoryPath in @(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $parent)) {
            $directoryHandles.Add($script:ReleaseDirectoryLockType::OpenDirectory($directoryPath))
        }
        $fileHandle = $script:ReleaseDirectoryLockType::OpenFile($canonical)
        if (-not $script:ReleaseDirectoryLockType::SameIdentity($bootstrap, $fileHandle)) {
            throw "Release file identity changed while its canonical path was pinned"
        }
        $confirmed = $script:ReleaseDirectoryLockType::GetFinalVolumePath($fileHandle)
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
                    $directoryHandles.Add($script:ReleaseDirectoryLockType::OpenDirectory($item.FullName))
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
                    $fileHandles.Add($script:ReleaseDirectoryLockType::OpenFile($item.FullName))
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

function Initialize-ReleaseToolsetProcessType {
    if (
        $null -ne $script:ReleaseToolsetProcessType -or
        $null -ne $script:ReleaseToolsetProcessResultType
    ) {
        $resolvedProcessType = "YourWallet.ReleaseToolsetProcess" -as [type]
        $resolvedResultType = "YourWallet.ReleaseToolsetProcessResult" -as [type]
        if (
            -not [object]::ReferenceEquals(
                $resolvedProcessType,
                $script:ReleaseToolsetProcessType
            ) -or
            -not [object]::ReferenceEquals(
                $resolvedResultType,
                $script:ReleaseToolsetProcessResultType
            )
        ) {
            throw "Release toolset process type identity changed"
        }
        return
    }
    if (
        $null -ne ("YourWallet.ReleaseToolsetProcess" -as [type]) -or
        $null -ne ("YourWallet.ReleaseToolsetProcessResult" -as [type])
    ) {
        throw "Release toolset process type was preloaded"
    }
    $addTypeCommand = $script:ReleaseTrustedCommands["Add-Type"]
    $compiledTypes = @(
        & $addTypeCommand -PassThru -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace YourWallet {
    public sealed class ReleaseToolsetProcessResult {
        public int ExitCode { get; private set; }
        public string Stdout { get; private set; }
        public string Stderr { get; private set; }

        internal ReleaseToolsetProcessResult(int exitCode, string stdout, string stderr) {
            ExitCode = exitCode;
            Stdout = stdout;
            Stderr = stderr;
        }
    }

    public static class ReleaseToolsetProcess {
        private const uint DebugProcess = 0x00000001;
        private const uint DebugOnlyThisProcess = 0x00000002;
        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateDefaultErrorMode = 0x04000000;
        private const uint CreateNoWindow = 0x08000000;
        private const uint StartfUseStdHandles = 0x00000100;
        private const uint HandleFlagInherit = 0x00000001;
        private const long ProcThreadAttributeHandleList = 0x00020002;
        private const long ProcThreadAttributeMitigationPolicy = 0x00020007;
        // DEP, SEHOP, mandatory relocation, heap termination, bottom-up/high-
        // entropy ASLR, strict handle checks, extension-point disable, and the
        // no-remote/no-low-label/prefer-System32 image policies. Dynamic-code
        // and Microsoft-only-image policies are intentionally omitted because
        // the pinned standalone Node/V8 image requires them to remain usable.
        private const long ReleaseProcessMitigationPolicy = 0x1110000101111105;
        private const uint CreateProcessDebugEvent = 3;
        private const uint LoadDllDebugEvent = 6;
        private const uint DbgContinue = 0x00010002;
        private const uint WaitObject0 = 0x00000000;
        private const uint WaitTimeout = 0x00000102;
        private const uint WaitFailed = 0xffffffff;
        private const uint InvalidSuspendCount = 0xffffffff;
        private const uint RejectedProcessExitCode = 0xE0570001;
        private const int CleanupTimeoutMilliseconds = 5000;
        private const int CaptureJoinTimeoutMilliseconds = 5000;
        private const int FileIdInfo = 18;
        private const int ErrorInsufficientBuffer = 122;
        private const int DebugEventBufferBytes = 512;
        private static readonly object ProcessCreationSync = new object();

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes {
            internal uint Length;
            internal IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo {
            internal uint Cb;
            internal IntPtr Reserved;
            internal IntPtr Desktop;
            internal IntPtr Title;
            internal uint X;
            internal uint Y;
            internal uint XSize;
            internal uint YSize;
            internal uint XCountChars;
            internal uint YCountChars;
            internal uint FillAttribute;
            internal uint Flags;
            internal ushort ShowWindow;
            internal ushort Reserved2Count;
            internal IntPtr Reserved2;
            internal IntPtr StdInput;
            internal IntPtr StdOutput;
            internal IntPtr StdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx {
            internal StartupInfo StartupInfo;
            internal IntPtr AttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation {
            internal IntPtr Process;
            internal IntPtr Thread;
            internal uint ProcessId;
            internal uint ThreadId;
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
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref IntPtr size
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize
        );

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out SafeFileHandle readPipe,
            out SafeFileHandle writePipe,
            ref SecurityAttributes pipeAttributes,
            uint size
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(
            SafeFileHandle handle,
            uint mask,
            uint flags
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WaitForDebugEventEx(IntPtr debugEvent, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ContinueDebugEvent(uint processId, uint threadId, uint continueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DebugActiveProcessStop(uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DebugSetProcessKillOnExit([MarshalAs(UnmanagedType.Bool)] bool killOnExit);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(SafeFileHandle thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(SafeFileHandle thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(SafeFileHandle process);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcessId")]
        private static extern uint GetProcessIdFromEvent(IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetThreadId(SafeFileHandle thread);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadId")]
        private static extern uint GetThreadIdFromEvent(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileIdInformation(
            SafeFileHandle file,
            int informationClass,
            out FileIdInformation information,
            uint bufferSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);

        private sealed class CaptureState {
            internal readonly object Sync = new object();
            internal readonly MemoryStream Bytes = new MemoryStream();
            internal readonly int MaximumBytes;
            internal bool Overflow;
            internal Exception Failure;

            internal CaptureState(int maximumBytes) {
                MaximumBytes = maximumBytes;
            }
        }

        private static bool Invalid(SafeFileHandle handle) {
            return handle == null || handle.IsClosed || handle.IsInvalid;
        }

        private static bool Invalid(IntPtr handle) {
            return handle == IntPtr.Zero || handle == new IntPtr(-1);
        }

        private static string QuoteWindowsArgument(string value) {
            if (value == null) {
                throw new ArgumentNullException("value");
            }
            if (value.IndexOf('\0') >= 0) {
                throw new ArgumentException("Process arguments may not contain NUL characters");
            }
            if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '\r', '\n', '"' }) < 0) {
                return value;
            }

            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char current in value) {
                if (current == '\\') {
                    backslashes += 1;
                    continue;
                }
                if (current == '"') {
                    quoted.Append('\\', (backslashes * 2) + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(current);
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static string BuildArguments(IList<string> arguments) {
            StringBuilder commandLine = new StringBuilder();
            for (int index = 0; index < arguments.Count; index += 1) {
                if (index != 0) {
                    commandLine.Append(' ');
                }
                commandLine.Append(QuoteWindowsArgument(arguments[index]));
            }
            return commandLine.ToString();
        }

        private static string GetWindowsDirectoryPath() {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetWindowsDirectoryW(buffer, (uint)buffer.Capacity);
            if (length == 0 || length >= buffer.Capacity || !Path.IsPathRooted(buffer.ToString())) {
                throw new IOException("Could not obtain the trusted Windows directory");
            }
            return buffer.ToString();
        }

        private static string GetSystemDirectoryPath() {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetSystemDirectoryW(buffer, (uint)buffer.Capacity);
            if (length == 0 || length >= buffer.Capacity || !Path.IsPathRooted(buffer.ToString())) {
                throw new IOException("Could not obtain the trusted Windows system directory");
            }
            return buffer.ToString();
        }

        private static IntPtr BuildEnvironmentBlock(string windowsDirectory, string systemDirectory) {
            string[] variables = new string[] {
                "PATH=" + systemDirectory,
                "SystemRoot=" + windowsDirectory,
                "WINDIR=" + windowsDirectory
            };
            string block = String.Join("\0", variables) + "\0\0";
            IntPtr memory = Marshal.AllocHGlobal(checked(block.Length * sizeof(char)));
            Marshal.Copy(block.ToCharArray(), 0, memory, block.Length);
            return memory;
        }

        private static FileIdInformation Identity(SafeFileHandle handle) {
            if (Invalid(handle)) {
                throw new IOException("Expected executable identity handle is invalid");
            }
            FileIdInformation information;
            if (!GetFileIdInformation(
                handle,
                FileIdInfo,
                out information,
                (uint)Marshal.SizeOf(typeof(FileIdInformation))
            )) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not obtain executable file identity");
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
                throw new IOException("Executable file identity is unsupported");
            }
            return information;
        }

        private static bool SameIdentity(FileIdInformation left, FileIdInformation right) {
            return
                left.VolumeSerialNumber == right.VolumeSerialNumber &&
                left.FileId.LowPart == right.FileId.LowPart &&
                left.FileId.HighPart == right.FileId.HighPart;
        }

        private static uint RemainingMilliseconds(Stopwatch timer, int timeoutMilliseconds) {
            long remaining = (long)timeoutMilliseconds - timer.ElapsedMilliseconds;
            if (remaining <= 0) {
                return 0;
            }
            return remaining > UInt32.MaxValue ? UInt32.MaxValue : (uint)remaining;
        }

        private static void TryTerminate(SafeFileHandle process) {
            if (!Invalid(process)) {
                try {
                    TerminateProcess(process, RejectedProcessExitCode);
                }
                catch {
                }
            }
        }

        private static void Capture(Stream stream, CaptureState state, SafeFileHandle process) {
            try {
                byte[] buffer = new byte[4096];
                while (true) {
                    int count = stream.Read(buffer, 0, buffer.Length);
                    if (count == 0) {
                        return;
                    }
                    lock (state.Sync) {
                        if (state.Bytes.Length > state.MaximumBytes - count) {
                            state.Overflow = true;
                            TryTerminate(process);
                            return;
                        }
                        state.Bytes.Write(buffer, 0, count);
                    }
                }
            }
            catch (Exception error) {
                lock (state.Sync) {
                    state.Failure = error;
                }
                TryTerminate(process);
            }
        }

        private static bool JoinCaptureThreads(
            Thread stdoutThread,
            Thread stderrThread,
            Stream stdoutStream,
            Stream stderrStream
        ) {
            bool stdoutStopped = stdoutThread == null || stdoutThread.Join(CaptureJoinTimeoutMilliseconds);
            bool stderrStopped = stderrThread == null || stderrThread.Join(CaptureJoinTimeoutMilliseconds);
            if (stdoutStopped && stderrStopped) {
                return true;
            }
            try {
                if (stdoutStream != null) stdoutStream.Dispose();
            }
            catch {
            }
            try {
                if (stderrStream != null) stderrStream.Dispose();
            }
            catch {
            }
            if (!stdoutStopped && stdoutThread != null) {
                stdoutStopped = stdoutThread.Join(CaptureJoinTimeoutMilliseconds);
            }
            if (!stderrStopped && stderrThread != null) {
                stderrStopped = stderrThread.Join(CaptureJoinTimeoutMilliseconds);
            }
            return stdoutStopped && stderrStopped;
        }

        private static bool TerminateAndReap(
            SafeFileHandle process,
            uint processId,
            bool debuggerAttached,
            bool eventOutstanding,
            bool eventMatchesCreatedIdentity,
            uint eventProcessId,
            uint eventThreadId
        ) {
            if (Invalid(process)) {
                return false;
            }
            bool terminationAccepted = TerminateProcess(process, RejectedProcessExitCode);
            if (!terminationAccepted && WaitForSingleObject(process, 0) != WaitObject0) {
                return false;
            }
            bool eventReleased = !eventOutstanding;
            if (eventOutstanding && eventMatchesCreatedIdentity) {
                eventReleased = ContinueDebugEvent(eventProcessId, eventThreadId, DbgContinue);
            }
            bool detached = !debuggerAttached;
            if (debuggerAttached) {
                detached = DebugActiveProcessStop(processId);
                // A successful detach also releases an outstanding event that
                // was deliberately not continued because its IDs were foreign.
                if (detached) eventReleased = true;
            }
            return
                eventReleased &&
                detached &&
                WaitForSingleObject(process, CleanupTimeoutMilliseconds) == WaitObject0;
        }

        public static ReleaseToolsetProcessResult Run(
            SafeFileHandle expectedExecutableHandle,
            string executable,
            string[] arguments,
            int timeoutMilliseconds,
            int maximumOutputBytes
        ) {
            ReleaseToolsetProcessResult result = null;
            ExceptionDispatchInfo failure = null;
            Thread worker = new Thread(delegate() {
                try {
                    result = RunOnFreshThread(
                        expectedExecutableHandle,
                        executable,
                        arguments,
                        timeoutMilliseconds,
                        maximumOutputBytes
                    );
                }
                catch (Exception error) {
                    failure = ExceptionDispatchInfo.Capture(error);
                }
            });
            // Win32 debugger ownership is thread-affine. A fresh one-shot
            // worker prevents queued events from any caller-owned debuggee
            // from entering this exact-image authentication protocol. Joining
            // synchronously is deliberate: every wait in the worker is bounded,
            // and returning while it still owned a debuggee would defeat the
            // OS kill-on-debugger-thread-exit backstop. Keep the worker in the
            // foreground so host shutdown cannot abandon cleanup in progress.
            worker.Name = "your-wallet-release-toolset";
            worker.IsBackground = false;
            worker.Start();
            worker.Join();
            if (failure != null) {
                failure.Throw();
            }
            if (result == null) {
                throw new IOException("Release toolset process worker returned no result");
            }
            return result;
        }

        private static ReleaseToolsetProcessResult RunOnFreshThread(
            SafeFileHandle expectedExecutableHandle,
            string executable,
            string[] arguments,
            int timeoutMilliseconds,
            int maximumOutputBytes
        ) {
            if (
                Invalid(expectedExecutableHandle) ||
                String.IsNullOrWhiteSpace(executable) ||
                !Path.IsPathRooted(executable) ||
                executable.IndexOf('\0') >= 0 ||
                arguments == null ||
                timeoutMilliseconds <= 0 ||
                maximumOutputBytes <= 0
            ) {
                throw new ArgumentException("Release toolset process configuration is invalid");
            }
            foreach (string argument in arguments) {
                if (argument == null || argument.IndexOf('\0') >= 0) {
                    throw new ArgumentException("Release toolset process arguments are invalid");
                }
            }

            FileIdInformation expectedIdentity = Identity(expectedExecutableHandle);
            string windowsDirectory = GetWindowsDirectoryPath();
            string systemDirectory = GetSystemDirectoryPath();
            List<string> completeArguments = new List<string>();
            completeArguments.Add(executable);
            completeArguments.AddRange(arguments);
            StringBuilder commandLine = new StringBuilder(BuildArguments(completeArguments));

            CaptureState stdout = new CaptureState(maximumOutputBytes);
            CaptureState stderr = new CaptureState(maximumOutputBytes);
            SafeFileHandle stdoutRead = null;
            SafeFileHandle stdoutWrite = null;
            SafeFileHandle stderrRead = null;
            SafeFileHandle stderrWrite = null;
            SafeFileHandle stdinRead = null;
            SafeFileHandle stdinWrite = null;
            SafeFileHandle process = null;
            SafeFileHandle primaryThread = null;
            SafeFileHandle eventFile = null;
            FileStream stdoutStream = null;
            FileStream stderrStream = null;
            Thread stdoutThread = null;
            Thread stderrThread = null;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr inheritedHandles = IntPtr.Zero;
            IntPtr mitigationPolicy = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            IntPtr debugEvent = IntPtr.Zero;
            bool attributeListInitialized = false;
            bool processCreated = false;
            bool debuggerAttached = false;
            bool eventOutstanding = false;
            bool eventMatchesCreatedIdentity = false;
            uint processId = 0;
            uint eventProcessId = 0;
            uint eventThreadId = 0;
            bool timedOut = false;
            Stopwatch timer = Stopwatch.StartNew();
            try {
                SecurityAttributes pipeAttributes = new SecurityAttributes();
                pipeAttributes.Length = (uint)Marshal.SizeOf(typeof(SecurityAttributes));
                pipeAttributes.SecurityDescriptor = IntPtr.Zero;
                pipeAttributes.InheritHandle = true;
                if (
                    !CreatePipe(out stdoutRead, out stdoutWrite, ref pipeAttributes, 0) ||
                    !CreatePipe(out stderrRead, out stderrWrite, ref pipeAttributes, 0) ||
                    !CreatePipe(out stdinRead, out stdinWrite, ref pipeAttributes, 0)
                ) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create isolated release process pipes");
                }
                if (
                    !SetHandleInformation(stdoutRead, HandleFlagInherit, 0) ||
                    !SetHandleInformation(stderrRead, HandleFlagInherit, 0) ||
                    !SetHandleInformation(stdinWrite, HandleFlagInherit, 0)
                ) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not isolate release process pipe inheritance");
                }

                IntPtr attributeBytes = IntPtr.Zero;
                bool sized = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeBytes);
                int sizingError = Marshal.GetLastWin32Error();
                if (sized || sizingError != ErrorInsufficientBuffer || attributeBytes == IntPtr.Zero) {
                    throw new IOException("Could not size the isolated release process attribute list");
                }
                attributeList = Marshal.AllocHGlobal(attributeBytes);
                if (!InitializeProcThreadAttributeList(attributeList, 2, 0, ref attributeBytes)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not initialize isolated release process attributes");
                }
                attributeListInitialized = true;

                inheritedHandles = Marshal.AllocHGlobal(checked(IntPtr.Size * 3));
                Marshal.WriteIntPtr(inheritedHandles, 0, stdinRead.DangerousGetHandle());
                Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size, stdoutWrite.DangerousGetHandle());
                Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size * 2, stderrWrite.DangerousGetHandle());
                if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    new IntPtr(ProcThreadAttributeHandleList),
                    inheritedHandles,
                    new IntPtr(IntPtr.Size * 3),
                    IntPtr.Zero,
                    IntPtr.Zero
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not restrict release process handle inheritance");
                }

                mitigationPolicy = Marshal.AllocHGlobal(sizeof(long));
                Marshal.WriteInt64(mitigationPolicy, ReleaseProcessMitigationPolicy);
                if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    new IntPtr(ProcThreadAttributeMitigationPolicy),
                    mitigationPolicy,
                    new IntPtr(sizeof(long)),
                    IntPtr.Zero,
                    IntPtr.Zero
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not require trusted system image preference");
                }

                StartupInfoEx startup = new StartupInfoEx();
                startup.StartupInfo.Cb = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
                startup.StartupInfo.Flags = StartfUseStdHandles;
                startup.StartupInfo.StdInput = stdinRead.DangerousGetHandle();
                startup.StartupInfo.StdOutput = stdoutWrite.DangerousGetHandle();
                startup.StartupInfo.StdError = stderrWrite.DangerousGetHandle();
                startup.AttributeList = attributeList;
                environment = BuildEnvironmentBlock(windowsDirectory, systemDirectory);

                ProcessInformation information;
                uint creationFlags =
                    DebugProcess |
                    DebugOnlyThisProcess |
                    CreateSuspended |
                    CreateUnicodeEnvironment |
                    ExtendedStartupInfoPresent |
                    CreateDefaultErrorMode |
                    CreateNoWindow;
                lock (ProcessCreationSync) {
                    if (!CreateProcessW(
                        executable,
                        commandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        true,
                        creationFlags,
                        environment,
                        systemDirectory,
                        ref startup,
                        out information
                    )) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Release toolset process could not be created");
                    }
                }
                processCreated = true;
                debuggerAttached = true;
                processId = information.ProcessId;
                process = new SafeFileHandle(information.Process, true);
                primaryThread = new SafeFileHandle(information.Thread, true);
                if (
                    Invalid(process) ||
                    Invalid(primaryThread) ||
                    information.ProcessId == 0 ||
                    information.ThreadId == 0 ||
                    GetProcessId(process) != information.ProcessId ||
                    GetThreadId(primaryThread) != information.ThreadId
                ) {
                    throw new IOException("Release process identity did not match CreateProcessW results");
                }
                // This fresh worker owns exactly this debuggee. If ordinary
                // cleanup cannot run, worker exit is the final OS-enforced
                // guarantee that the still-attached process is terminated.
                if (!DebugSetProcessKillOnExit(true)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not establish fail-closed debugger ownership");
                }

                stdoutWrite.Dispose();
                stdoutWrite = null;
                stderrWrite.Dispose();
                stderrWrite = null;
                stdinRead.Dispose();
                stdinRead = null;
                stdinWrite.Dispose();
                stdinWrite = null;

                uint previousSuspendCount = ResumeThread(primaryThread);
                if (previousSuspendCount != 1) {
                    throw new IOException("Initial release process suspension proof failed");
                }

                debugEvent = Marshal.AllocHGlobal(DebugEventBufferBytes);
                for (int index = 0; index < DebugEventBufferBytes; index += 1) {
                    Marshal.WriteByte(debugEvent, index, 0);
                }
                uint eventWait = RemainingMilliseconds(timer, timeoutMilliseconds);
                if (!WaitForDebugEventEx(debugEvent, eventWait)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Release process create event was not received");
                }
                uint eventCode = unchecked((uint)Marshal.ReadInt32(debugEvent, 0));
                uint observedProcessId = unchecked((uint)Marshal.ReadInt32(debugEvent, 4));
                uint observedThreadId = unchecked((uint)Marshal.ReadInt32(debugEvent, 8));
                eventOutstanding = true;
                eventProcessId = observedProcessId;
                eventThreadId = observedThreadId;
                int unionOffset = IntPtr.Size == 8 ? 16 : 12;
                IntPtr observedFile = IntPtr.Zero;
                if (eventCode == CreateProcessDebugEvent || eventCode == LoadDllDebugEvent) {
                    observedFile = Marshal.ReadIntPtr(debugEvent, unionOffset);
                    if (!Invalid(observedFile)) {
                        eventFile = new SafeFileHandle(observedFile, true);
                    }
                }
                if (
                    observedProcessId != information.ProcessId ||
                    observedThreadId != information.ThreadId
                ) {
                    throw new IOException("Release process create event identity was unexpected");
                }
                eventMatchesCreatedIdentity = true;
                if (eventCode != CreateProcessDebugEvent || Invalid(eventFile)) {
                    throw new IOException("Release process did not provide an authenticatable mapped image");
                }
                IntPtr eventProcess = Marshal.ReadIntPtr(debugEvent, unionOffset + IntPtr.Size);
                IntPtr eventThread = Marshal.ReadIntPtr(debugEvent, unionOffset + (IntPtr.Size * 2));
                if (
                    Invalid(eventProcess) ||
                    Invalid(eventThread) ||
                    GetProcessIdFromEvent(eventProcess) != information.ProcessId ||
                    GetThreadIdFromEvent(eventThread) != information.ThreadId
                ) {
                    throw new IOException("Release process debug handles did not match the created process");
                }
                FileIdInformation mappedIdentity = Identity(eventFile);
                if (!SameIdentity(expectedIdentity, mappedIdentity)) {
                    throw new IOException("Release process mapped executable did not match the pinned node image");
                }
                eventFile.Dispose();
                eventFile = null;

                previousSuspendCount = SuspendThread(primaryThread);
                if (previousSuspendCount != 0) {
                    throw new IOException("Release process pre-detach suspension proof failed");
                }
                if (!ContinueDebugEvent(eventProcessId, eventThreadId, DbgContinue)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not continue authenticated release process event");
                }
                eventOutstanding = false;
                if (!DebugActiveProcessStop(processId)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not detach authenticated release process debugger");
                }
                debuggerAttached = false;

                previousSuspendCount = SuspendThread(primaryThread);
                if (previousSuspendCount != 1) {
                    throw new IOException("Release process post-detach suspension proof failed");
                }
                previousSuspendCount = ResumeThread(primaryThread);
                if (previousSuspendCount != 2) {
                    throw new IOException("Release process post-detach guard restoration failed");
                }

                stdoutStream = new FileStream(stdoutRead, FileAccess.Read, 4096, false);
                stdoutRead = null;
                stderrStream = new FileStream(stderrRead, FileAccess.Read, 4096, false);
                stderrRead = null;
                stdoutThread = new Thread(delegate() { Capture(stdoutStream, stdout, process); });
                stderrThread = new Thread(delegate() { Capture(stderrStream, stderr, process); });
                stdoutThread.IsBackground = true;
                stderrThread.IsBackground = true;
                stdoutThread.Start();
                stderrThread.Start();

                previousSuspendCount = ResumeThread(primaryThread);
                if (previousSuspendCount != 1) {
                    throw new IOException("Release process final suspension proof failed");
                }

                uint processWait = WaitForSingleObject(
                    process,
                    RemainingMilliseconds(timer, timeoutMilliseconds)
                );
                if (processWait == WaitTimeout) {
                    timedOut = true;
                    TryTerminate(process);
                    if (WaitForSingleObject(process, CleanupTimeoutMilliseconds) != WaitObject0) {
                        throw new IOException("Release toolset process could not be terminated within its hard time limit");
                    }
                }
                else if (processWait == WaitFailed) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not wait for release toolset process");
                }
                else if (processWait != WaitObject0) {
                    throw new IOException("Release toolset process wait returned an unsupported result");
                }
                if (!JoinCaptureThreads(stdoutThread, stderrThread, stdoutStream, stderrStream)) {
                    throw new IOException("Release toolset output capture did not terminate");
                }
                if (timedOut) {
                    throw new TimeoutException("Release toolset process exceeded its time limit");
                }
                if (stdout.Overflow || stderr.Overflow) {
                    throw new IOException("Release toolset process exceeded its output limit");
                }
                if (stdout.Failure != null || stderr.Failure != null) {
                    throw new IOException("Release toolset process output was not valid UTF-8");
                }
                UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
                string stdoutText;
                string stderrText;
                try {
                    stdoutText = strictUtf8.GetString(stdout.Bytes.ToArray());
                    stderrText = strictUtf8.GetString(stderr.Bytes.ToArray());
                }
                catch (DecoderFallbackException error) {
                    throw new IOException("Release toolset process output was not valid UTF-8", error);
                }
                uint exitCode;
                if (!GetExitCodeProcess(process, out exitCode)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not obtain release toolset process exit code");
                }
                return new ReleaseToolsetProcessResult(
                    checked((int)exitCode),
                    stdoutText,
                    stderrText
                );
            }
            catch (Exception error) {
                if (eventFile != null) {
                    eventFile.Dispose();
                    eventFile = null;
                }
                bool reaped = !processCreated || TerminateAndReap(
                    process,
                    processId,
                    debuggerAttached,
                    eventOutstanding,
                    eventMatchesCreatedIdentity,
                    eventProcessId,
                    eventThreadId
                );
                bool captureStopped = JoinCaptureThreads(
                    stdoutThread,
                    stderrThread,
                    stdoutStream,
                    stderrStream
                );
                if (!reaped || !captureStopped) {
                    throw new IOException("Release toolset process cleanup failed closed", error);
                }
                throw;
            }
            finally {
                if (eventFile != null) eventFile.Dispose();
                if (stdoutStream != null) stdoutStream.Dispose();
                if (stderrStream != null) stderrStream.Dispose();
                if (stdoutRead != null) stdoutRead.Dispose();
                if (stdoutWrite != null) stdoutWrite.Dispose();
                if (stderrRead != null) stderrRead.Dispose();
                if (stderrWrite != null) stderrWrite.Dispose();
                if (stdinRead != null) stdinRead.Dispose();
                if (stdinWrite != null) stdinWrite.Dispose();
                if (primaryThread != null) primaryThread.Dispose();
                if (process != null) process.Dispose();
                if (attributeListInitialized) DeleteProcThreadAttributeList(attributeList);
                if (attributeList != IntPtr.Zero) Marshal.FreeHGlobal(attributeList);
                if (inheritedHandles != IntPtr.Zero) Marshal.FreeHGlobal(inheritedHandles);
                if (mitigationPolicy != IntPtr.Zero) Marshal.FreeHGlobal(mitigationPolicy);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                if (debugEvent != IntPtr.Zero) Marshal.FreeHGlobal(debugEvent);
                stdout.Bytes.Dispose();
                stderr.Bytes.Dispose();
                GC.KeepAlive(expectedExecutableHandle);
            }
        }
    }
}
"@
    )
    $compiledProcessType = $null
    $compiledResultType = $null
    foreach ($candidateType in $compiledTypes) {
        if ([System.String]::Equals(
            $candidateType.FullName,
            "YourWallet.ReleaseToolsetProcess",
            [System.StringComparison]::Ordinal
        )) {
            if ($null -ne $compiledProcessType) {
                throw "Release toolset process compilation returned a duplicate type"
            }
            $compiledProcessType = $candidateType
        }
        elseif ([System.String]::Equals(
            $candidateType.FullName,
            "YourWallet.ReleaseToolsetProcessResult",
            [System.StringComparison]::Ordinal
        )) {
            if ($null -ne $compiledResultType) {
                throw "Release toolset process compilation returned a duplicate result type"
            }
            $compiledResultType = $candidateType
        }
    }
    $resolvedProcessType = "YourWallet.ReleaseToolsetProcess" -as [type]
    $resolvedResultType = "YourWallet.ReleaseToolsetProcessResult" -as [type]
    if (
        $null -eq $compiledProcessType -or
        $null -eq $compiledResultType -or
        -not [object]::ReferenceEquals($resolvedProcessType, $compiledProcessType) -or
        -not [object]::ReferenceEquals($resolvedResultType, $compiledResultType)
    ) {
        throw "Release toolset process compilation returned an invalid type set"
    }
    $script:ReleaseToolsetProcessType = $compiledProcessType
    $script:ReleaseToolsetProcessResultType = $compiledResultType
}

function Initialize-VerifiedReleaseToolsetRegistry {
    if ($null -eq (Get-Variable -Name VerifiedReleaseToolsetRegistry -Scope Script -ErrorAction SilentlyContinue)) {
        $script:VerifiedReleaseToolsetRegistry = [System.Collections.Generic.Dictionary[System.Guid, object]]::new()
    }
}

function ConvertFrom-CanonicalReleaseDosPath {
    param([Parameter(Mandatory = $true)][string]$CanonicalDosPath)

    if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
        $CanonicalDosPath,
        '^\\\\\?\\[A-Za-z]:\\',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )) {
        throw "Release toolset execution requires an unambiguous local drive path"
    }
    $executionPath = $CanonicalDosPath.Substring(4)
    if (
        $executionPath.StartsWith("\\", [System.StringComparison]::Ordinal) -or
        -not [System.IO.Path]::IsPathRooted($executionPath)
    ) {
        throw "Release toolset execution refuses UNC or unsupported DOS paths"
    }
    $executionPath
}

function Get-VerifiedReleaseToolsetRecord {
    param([Parameter(Mandatory = $true)][object]$Toolset)

    Initialize-VerifiedReleaseToolsetRegistry
    if ($null -eq $Toolset -or $null -eq $Toolset.PSObject.Properties["HandleId"]) {
        throw "Release toolset handle is invalid"
    }
    $handleId = [System.Guid]::Empty
    if (-not [System.Guid]::TryParse([string]$Toolset.HandleId, [ref]$handleId)) {
        throw "Release toolset handle is invalid"
    }
    if (-not $script:VerifiedReleaseToolsetRegistry.ContainsKey($handleId)) {
        throw "Release toolset handle is closed or unknown"
    }
    $record = $script:VerifiedReleaseToolsetRegistry[$handleId]
    if (-not [object]::ReferenceEquals($record.PublicHandle, $Toolset)) {
        throw "Release toolset handle identity is invalid"
    }
    $record
}

function Open-VerifiedReleaseToolset {
    param(
        [Parameter(Mandatory = $true)][string]$ToolsetRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
        $ExpectedSha256,
        '^[0-9a-f]{64}$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )) {
        throw "Release toolset SHA-256 pin must be exactly 64 lowercase hexadecimal characters"
    }
    if ($env:OS -ne "Windows_NT") {
        throw "Verified release toolsets require Windows"
    }
    if (
        -not [System.Environment]::Is64BitOperatingSystem -or
        -not [System.Environment]::Is64BitProcess
    ) {
        throw "Verified release toolsets require a 64-bit Windows verifier process"
    }

    Initialize-ReleaseDirectoryLockType
    Initialize-ReleaseToolsetProcessType
    Initialize-VerifiedReleaseToolsetRegistry

    $expectedDirectories = @(
        "extension",
        "extension/native-host",
        "scripts",
        "scripts/release"
    )
    $expectedFiles = @(
        "extension/native-host/validate-manifest.mjs",
        "node.exe",
        "scripts/release/common.ps1",
        "scripts/release/release-manifest.mjs",
        "scripts/release/review-evidence-set.mjs",
        "scripts/release/review-evidence-set.ps1",
        "scripts/release/verify-release-offline.ps1"
    )

    $treeLocks = $null
    $retainedHandles = [System.Collections.Generic.List[System.IDisposable]]::new()
    try {
        $treeLocks = Open-ReadOnlyReleaseTreeLocks -BundleRoot $ToolsetRoot
        $volumeRoot = $treeLocks.CanonicalBundleRoot
        Assert-NoReparseTree -LiteralPath $volumeRoot
        Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot $volumeRoot

        $actualDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $actualFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $pending = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
        $pending.Enqueue([System.IO.DirectoryInfo]::new($volumeRoot))
        $rootPrefix = $volumeRoot.TrimEnd("\") + "\"
        while ($pending.Count -gt 0) {
            $directory = $pending.Dequeue()
            foreach ($item in $directory.GetFileSystemInfos()) {
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Release toolset contains a reparse point"
                }
                if (-not $item.FullName.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Release toolset inventory escaped its root"
                }
                $relative = $item.FullName.Substring($rootPrefix.Length).Replace("\", "/")
                if (-not [System.Text.RegularExpressions.Regex]::IsMatch(
                    $relative,
                    '^[\x20-\x7e]+$',
                    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
                )) {
                    throw "Release toolset inventory names must be printable ASCII"
                }
                if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                    if (-not $actualDirectories.Add($relative)) {
                        throw "Release toolset contains a duplicate directory identity"
                    }
                    $pending.Enqueue([System.IO.DirectoryInfo]::new($item.FullName))
                }
                else {
                    if (-not $actualFiles.Add($relative)) {
                        throw "Release toolset contains a duplicate file identity"
                    }
                }
            }
        }

        if ($actualDirectories.Count -ne $expectedDirectories.Count -or $actualFiles.Count -ne $expectedFiles.Count) {
            throw "Release toolset inventory is not the exact approved runtime set"
        }
        foreach ($relative in $expectedDirectories) {
            if (-not $actualDirectories.Contains($relative)) {
                throw "Release toolset directory inventory or casing is invalid"
            }
        }
        foreach ($relative in $expectedFiles) {
            if (-not $actualFiles.Contains($relative)) {
                throw "Release toolset file inventory or casing is invalid"
            }
        }

        $inventory = [System.Collections.Generic.List[object]]::new()
        foreach ($relative in $expectedFiles) {
            $canonicalFile = Join-Path $volumeRoot $relative.Replace("/", "\")
            $script:ReleaseDirectoryLockType::AssertOnlyDefaultDataStream($canonicalFile)
            $item = Get-Item -LiteralPath $canonicalFile -Force
            $inventory.Add([ordered]@{
                bytes = $item.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                path = $relative
                sha256 = Get-Sha256Lower -LiteralPath $canonicalFile
            })
        }
        $inventorySha256 = Get-InventorySha256 -Inventory $inventory.ToArray()
        if (-not [System.String]::Equals($inventorySha256, $ExpectedSha256, [System.StringComparison]::Ordinal)) {
            throw "Release toolset does not match the independently pinned aggregate SHA-256"
        }

        $rootPin = Open-PinnedReleaseDirectoryPath -LiteralPath $volumeRoot
        foreach ($handle in $rootPin.DirectoryHandles) {
            $retainedHandles.Add($handle)
        }
        $pinnedRootHandle = $rootPin.DirectoryHandles[$rootPin.DirectoryHandles.Count - 1]
        if (-not [System.String]::Equals($rootPin.CanonicalPath, $volumeRoot, [System.StringComparison]::Ordinal)) {
            throw "Release toolset root identity changed while deriving its execution path"
        }
        $dosRoot = ConvertFrom-CanonicalReleaseDosPath -CanonicalDosPath (
            $script:ReleaseDirectoryLockType::GetFinalDosPath($pinnedRootHandle)
        )
        $dosRootHandle = $script:ReleaseDirectoryLockType::OpenDirectory($dosRoot)
        $retainedHandles.Add($dosRootHandle)
        if (
            -not $script:ReleaseDirectoryLockType::SameIdentity($pinnedRootHandle, $dosRootHandle) -or
            -not [System.String]::Equals(
                $script:ReleaseDirectoryLockType::GetFinalVolumePath($dosRootHandle),
                $volumeRoot,
                [System.StringComparison]::Ordinal
            )
        ) {
            throw "Release toolset DOS root does not identify the pinned canonical root"
        }

        $dosPaths = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
        $volumePaths = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
        $identityHandles = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($relative in $expectedFiles) {
            $volumePath = Join-Path $volumeRoot $relative.Replace("/", "\")
            $expectedDosPath = Join-Path $dosRoot $relative.Replace("/", "\")
            $filePin = Open-PinnedReleaseFilePath -LiteralPath $volumePath
            foreach ($handle in $filePin.DirectoryHandles) {
                $retainedHandles.Add($handle)
            }
            $retainedHandles.Add($filePin.FileHandle)
            $script:ReleaseDirectoryLockType::AssertSingleLink($filePin.FileHandle)
            $finalDosPath = ConvertFrom-CanonicalReleaseDosPath -CanonicalDosPath (
                $script:ReleaseDirectoryLockType::GetFinalDosPath($filePin.FileHandle)
            )
            if (
                -not [System.String]::Equals($filePin.CanonicalPath, $volumePath, [System.StringComparison]::Ordinal) -or
                -not [System.String]::Equals($finalDosPath, $expectedDosPath, [System.StringComparison]::Ordinal)
            ) {
                throw "Release toolset file path or casing changed while it was pinned"
            }
            $dosFileHandle = $script:ReleaseDirectoryLockType::OpenFile($expectedDosPath)
            $retainedHandles.Add($dosFileHandle)
            if (
                -not $script:ReleaseDirectoryLockType::SameIdentity($filePin.FileHandle, $dosFileHandle) -or
                -not [System.String]::Equals(
                    $script:ReleaseDirectoryLockType::GetFinalVolumePath($dosFileHandle),
                    $volumePath,
                    [System.StringComparison]::Ordinal
                )
            ) {
                throw "Release toolset DOS file path does not identify the pinned canonical file"
            }
            $dosPaths.Add($relative, $expectedDosPath)
            $volumePaths.Add($relative, $volumePath)
            $identityHandles.Add($relative, $filePin.FileHandle)
        }

        # CreateProcessW rejects the stable volume-GUID form on supported hosts. The
        # DOS node spelling below is therefore only a process-creation input: the
        # native runner authenticates the mapped image's FILE_ID_INFO before any
        # user-mode instruction is released. JavaScript source is loaded separately
        # from the retained volume-GUID paths through the sealed VM graph loader.
        $handleId = [System.Guid]::NewGuid()
        $publicHandle = [pscustomobject]@{
            Schema = "your-wallet-verified-release-toolset-v1"
            HandleId = $handleId.ToString("D")
            CanonicalVolumeRoot = $volumeRoot
            CanonicalDosRoot = $dosRoot
            NodePath = $dosPaths["node.exe"]
            ReviewEvidenceScriptPath = $dosPaths["scripts/release/review-evidence-set.mjs"]
            ReleaseManifestScriptPath = $dosPaths["scripts/release/release-manifest.mjs"]
            InventorySha256 = $inventorySha256
        }
        $publicHandle.PSObject.TypeNames.Insert(0, "YourWallet.VerifiedReleaseToolset")
        $record = [pscustomobject]@{
            PublicHandle = $publicHandle
            TreeLocks = $treeLocks
            RetainedHandles = $retainedHandles
            CanonicalVolumeRoot = $volumeRoot
            CanonicalDosRoot = $dosRoot
            RootIdentityHandle = $pinnedRootHandle
            DosPaths = $dosPaths
            VolumePaths = $volumePaths
            IdentityHandles = $identityHandles
        }
        $script:VerifiedReleaseToolsetRegistry.Add($handleId, $record)
        $treeLocks = $null
        $retainedHandles = $null
        $publicHandle
    }
    catch {
        if ($null -ne $retainedHandles) {
            foreach ($handle in $retainedHandles) {
                $handle.Dispose()
            }
        }
        if ($null -ne $treeLocks) {
            Close-ReadOnlyReleaseTreeLocks -LockSet $treeLocks
        }
        throw
    }
}

function Invoke-ReleaseToolsetNode {
    param(
        [Parameter(Mandatory = $true)][object]$Toolset,
        [Parameter(Mandatory = $true)][string]$ScriptRelativePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$CommandArguments
    )

    $allowedScripts = @(
        "scripts/release/review-evidence-set.mjs",
        "scripts/release/release-manifest.mjs"
    )
    if ($allowedScripts -cnotcontains $ScriptRelativePath) {
        throw "Release toolset Node invocation refused an unapproved entry script"
    }
    foreach ($argument in $CommandArguments) {
        if ($null -eq $argument -or $argument.Contains([char]0)) {
            throw "Release toolset Node invocation received an invalid argument"
        }
    }

    $record = Get-VerifiedReleaseToolsetRecord -Toolset $Toolset
    $temporaryHandles = [System.Collections.Generic.List[System.IDisposable]]::new()
    try {
        $dosRootHandle = $script:ReleaseDirectoryLockType::OpenDirectory($record.CanonicalDosRoot)
        $temporaryHandles.Add($dosRootHandle)
        if (
            -not $script:ReleaseDirectoryLockType::SameIdentity($record.RootIdentityHandle, $dosRootHandle) -or
            -not [System.String]::Equals(
                $script:ReleaseDirectoryLockType::GetFinalVolumePath($dosRootHandle),
                $record.CanonicalVolumeRoot,
                [System.StringComparison]::Ordinal
            )
        ) {
            throw "Release toolset DOS root identity changed before execution"
        }

        $graphFiles = @(
            "scripts/release/review-evidence-set.mjs",
            "scripts/release/release-manifest.mjs",
            "extension/native-host/validate-manifest.mjs"
        )
        foreach ($relative in @("node.exe") + $graphFiles) {
            $executionPath = if ($relative -ceq "node.exe") {
                $record.DosPaths[$relative]
            }
            else {
                $record.VolumePaths[$relative]
            }
            $candidate = $script:ReleaseDirectoryLockType::OpenFile($executionPath)
            $temporaryHandles.Add($candidate)
            if (
                -not $script:ReleaseDirectoryLockType::SameIdentity($record.IdentityHandles[$relative], $candidate) -or
                -not [System.String]::Equals(
                    $script:ReleaseDirectoryLockType::GetFinalVolumePath($candidate),
                    $record.VolumePaths[$relative],
                    [System.StringComparison]::Ordinal
                )
            ) {
                throw "Release toolset executable graph identity changed before execution"
            }
        }

        $graphLoader = @'
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const { fileURLToPath } = require("node:url");
(async () => {
  const input = process.argv.slice(1);
  if (input.length < 4) throw new Error("sealed loader arguments are incomplete");
  const kind = input[0];
  const diskPaths = { validate: input[1], release: input[2], review: input[3] };
  const cliArguments = input.slice(4);
  const urls = {
    review: "file:///C:/__your_wallet_sealed_toolset__/scripts/release/review-evidence-set.mjs",
    release: "file:///C:/__your_wallet_sealed_toolset__/scripts/release/release-manifest.mjs",
    validate: "file:///C:/__your_wallet_sealed_toolset__/extension/native-host/validate-manifest.mjs",
  };
  const entryName = kind === "review" ? "review" : kind === "release" ? "release" : null;
  if (!entryName) throw new Error("sealed loader entry kind is invalid");
  const sealedArgv = Object.freeze([
    process.execPath,
    fileURLToPath(urls[entryName]),
    ...cliArguments,
  ]);
  const stdoutFacade = Object.create(null);
  Object.defineProperty(stdoutFacade, "write", {
    value: process.stdout.write.bind(process.stdout),
    enumerable: true,
  });
  Object.freeze(stdoutFacade);
  const stderrFacade = Object.create(null);
  Object.defineProperty(stderrFacade, "write", {
    value: process.stderr.write.bind(process.stderr),
    enumerable: true,
  });
  Object.freeze(stderrFacade);
  const processFacade = Object.create(null);
  Object.defineProperties(processFacade, {
    argv: { value: sealedArgv, enumerable: true },
    platform: { value: process.platform, enumerable: true },
    stdout: { value: stdoutFacade, enumerable: true },
    stderr: { value: stderrFacade, enumerable: true },
    exitCode: {
      enumerable: true,
      get() { return process.exitCode; },
      set(value) { process.exitCode = value; },
    },
  });
  Object.freeze(processFacade);
  const sandbox = Object.create(null);
  Object.defineProperty(sandbox, "Buffer", {
    value: Buffer,
    enumerable: true,
  });
  Object.defineProperty(sandbox, "TextDecoder", {
    value: TextDecoder,
    enumerable: true,
  });
  // The distinct context prevents accidental ambient CommonJS/process lookup;
  // it is not a hostile-JavaScript sandbox. The trusted source hashes remain
  // the execution boundary. Buffer and the strict-decoding TextDecoder are the
  // only host globals required by the pinned sources.
  const context = vm.createContext(sandbox, {
    name: "your-wallet-sealed-verifier",
    codeGeneration: { strings: false, wasm: false },
  });
  const decoder = new TextDecoder("utf-8", { fatal: true });
  function readSource(name) {
    const bytes = fs.readFileSync(diskPaths[name]);
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
      throw new Error("sealed loader source must not contain a UTF-8 BOM");
    }
    return decoder.decode(bytes);
  }
  const modules = {};
  for (const name of ["review", "release", "validate"]) {
    modules[name] = new vm.SourceTextModule(readSource(name), {
      context,
      identifier: urls[name],
      initializeImportMeta(meta, module) { meta.url = module.identifier; },
      importModuleDynamically() { throw new Error("dynamic module loading is disabled"); },
    });
  }
  const allowedBuiltins = new Set([
    "node:crypto",
    "node:fs/promises",
    "node:path",
    "node:process",
    "node:url",
  ]);
  const builtins = new Map();
  async function loadBuiltin(specifier) {
    if (!builtins.has(specifier)) {
      let synthetic;
      if (specifier === "node:process") {
        synthetic = new vm.SyntheticModule(["default"], () => {
          synthetic.setExport("default", processFacade);
        }, { context, identifier: specifier });
      } else {
        const namespace = await import(specifier);
        const names = Object.keys(namespace);
        synthetic = new vm.SyntheticModule(names, () => {
          for (const name of names) synthetic.setExport(name, namespace[name]);
        }, { context, identifier: specifier });
      }
      builtins.set(specifier, synthetic);
    }
    return builtins.get(specifier);
  }
  async function linker(specifier, referencingModule) {
    if (allowedBuiltins.has(specifier)) return loadBuiltin(specifier);
    if (
      referencingModule.identifier === urls.review &&
      specifier === "./release-manifest.mjs"
    ) return modules.release;
    if (
      referencingModule.identifier === urls.release &&
      specifier === "../../extension/native-host/validate-manifest.mjs"
    ) return modules.validate;
    throw new Error("sealed loader refused an unapproved module edge");
  }
  const entry = modules[entryName];
  await entry.link(linker);
  await entry.evaluate();
})().catch(() => { process.exitCode = 97; });
'@
        $entryKind = if ($ScriptRelativePath -ceq "scripts/release/review-evidence-set.mjs") {
            "review"
        }
        else {
            "release"
        }
        $arguments = @(
            "--no-addons",
            "--no-global-search-paths",
            "--no-warnings",
            "--experimental-vm-modules",
            "-e",
            $graphLoader,
            $entryKind,
            $record.VolumePaths["extension/native-host/validate-manifest.mjs"],
            $record.VolumePaths["scripts/release/release-manifest.mjs"],
            $record.VolumePaths["scripts/release/review-evidence-set.mjs"]
        ) + @($CommandArguments)
        $script:ReleaseToolsetProcessType::Run(
            $record.IdentityHandles["node.exe"],
            $record.DosPaths["node.exe"],
            [string[]]$arguments,
            120000,
            1048576
        )
    }
    catch {
        throw "Release toolset Node execution failed closed"
    }
    finally {
        foreach ($handle in $temporaryHandles) {
            $handle.Dispose()
        }
    }
}

function Close-VerifiedReleaseToolset {
    param([Parameter(Mandatory = $true)][object]$Toolset)

    Initialize-VerifiedReleaseToolsetRegistry
    if ($null -eq $Toolset -or $null -eq $Toolset.PSObject.Properties["HandleId"]) {
        throw "Release toolset handle is invalid"
    }
    $handleId = [System.Guid]::Empty
    if (-not [System.Guid]::TryParse([string]$Toolset.HandleId, [ref]$handleId)) {
        throw "Release toolset handle is invalid"
    }
    if (-not $script:VerifiedReleaseToolsetRegistry.ContainsKey($handleId)) {
        return
    }
    $record = $script:VerifiedReleaseToolsetRegistry[$handleId]
    if (-not [object]::ReferenceEquals($record.PublicHandle, $Toolset)) {
        throw "Release toolset handle identity is invalid"
    }
    [void]$script:VerifiedReleaseToolsetRegistry.Remove($handleId)
    foreach ($handle in $record.RetainedHandles) {
        $handle.Dispose()
    }
    Close-ReadOnlyReleaseTreeLocks -LockSet $record.TreeLocks
}

function Assert-ReleaseTreesDisjoint {
    param(
        [Parameter(Mandatory = $true)][string]$LeftCanonicalRoot,
        [Parameter(Mandatory = $true)][string]$RightCanonicalRoot
    )

    $leftPaths = @(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $LeftCanonicalRoot)
    $rightPaths = @(Get-CanonicalReleaseDirectoryPaths -CanonicalDirectory $RightCanonicalRoot)
    $left = $leftPaths[$leftPaths.Count - 1].TrimEnd("\")
    $right = $rightPaths[$rightPaths.Count - 1].TrimEnd("\")
    if (
        [System.String]::Equals($left, $right, [System.StringComparison]::OrdinalIgnoreCase) -or
        $left.StartsWith($right + "\", [System.StringComparison]::OrdinalIgnoreCase) -or
        $right.StartsWith($left + "\", [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Release toolset and release evidence trees must be disjoint"
    }
}

function Assert-ReleaseTreeEffectivelyReadOnly {
    param([Parameter(Mandatory = $true)][string]$BundleRoot)

    Assert-NoReparseTree -LiteralPath $BundleRoot
    $pending = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
    $pending.Enqueue([System.IO.DirectoryInfo]::new($BundleRoot))
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        $fileProbePath = [System.IO.Path]::Combine(
            $directory.FullName,
            (".your-wallet-file-write-probe-" + [System.Guid]::NewGuid().ToString("N"))
        )
        $fileProbe = $null
        $fileCreationDenied = $false
        try {
            $fileProbe = [System.IO.File]::Open(
                $fileProbePath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
        }
        catch [System.UnauthorizedAccessException] {
            $fileCreationDenied = $true
        }
        catch [System.IO.IOException] {
            $nativeError = $_.Exception.HResult -band 0xFFFF
            if ($nativeError -eq 19) {
                # ERROR_WRITE_PROTECT: the underlying medium is read-only.
                $fileCreationDenied = $true
            }
            else {
                throw "Release verification could not prove that a staging directory denies file creation"
            }
        }
        catch {
            throw "Release verification could not prove that a staging directory denies file creation"
        }
        finally {
            if ($null -ne $fileProbe) {
                $fileProbe.Dispose()
            }
        }
        if (-not $fileCreationDenied) {
            try {
                [System.IO.File]::Delete($fileProbePath)
            }
            catch {
                throw "Release verification could not safely remove its exact writable-file probe"
            }
            throw "Release verification refuses eligibility because the staging tree is writable by the verifier token"
        }

        $directoryProbePath = [System.IO.Path]::Combine(
            $directory.FullName,
            (".your-wallet-directory-write-probe-" + [System.Guid]::NewGuid().ToString("N"))
        )
        $directoryCreationDenied = $false
        $directoryCreated = $false
        if (
            [System.IO.File]::Exists($directoryProbePath) -or
            [System.IO.Directory]::Exists($directoryProbePath)
        ) {
            throw "Release verification could not establish a unique empty-directory probe"
        }
        try {
            [void][System.IO.Directory]::CreateDirectory($directoryProbePath)
            $directoryCreated = $true
        }
        catch [System.UnauthorizedAccessException] {
            $directoryCreationDenied = $true
        }
        catch [System.IO.IOException] {
            $nativeError = $_.Exception.HResult -band 0xFFFF
            if ($nativeError -eq 19) {
                # ERROR_WRITE_PROTECT: the underlying medium is read-only.
                $directoryCreationDenied = $true
            }
            else {
                throw "Release verification could not prove that a staging directory denies subdirectory creation"
            }
        }
        catch {
            throw "Release verification could not prove that a staging directory denies subdirectory creation"
        }
        if ($directoryCreated) {
            try {
                # Delete only the exact empty probe. Never recurse if another
                # actor populated it between creation and cleanup.
                [System.IO.Directory]::Delete($directoryProbePath, $false)
            }
            catch {
                throw "Release verification could not safely remove its exact empty-directory probe"
            }
            throw "Release verification refuses eligibility because the staging tree permits subdirectory creation by the verifier token"
        }
        if (-not $directoryCreationDenied) {
            throw "Release verification could not prove that a staging directory denies subdirectory creation"
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
            sha256 = Get-Sha256Lower -LiteralPath $file.FullName
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

function Expand-ReleaseZipArchive {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $archivePath = (Resolve-Path -LiteralPath $LiteralPath).Path
    $archiveItem = Get-Item -LiteralPath $archivePath -Force
    if (
        $archiveItem.PSIsContainer -or
        ($archiveItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Release source archive must be a regular non-reparse file"
    }

    $destinationRoot = (Resolve-Path -LiteralPath $DestinationPath).Path
    Assert-NoReparseTree -LiteralPath $destinationRoot
    if (@(Get-ChildItem -LiteralPath $destinationRoot -Force).Count -ne 0) {
        throw "Release source archive destination must be empty"
    }
    $destinationPrefix = $destinationRoot.TrimEnd("\") + "\"
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $deviceNamePattern = "^(?:COM|LPT)[1-9{0}{1}{2}]$" -f `
        ([char]0x00B9), `
        ([char]0x00B2), `
        ([char]0x00B3)

    $archiveStream = [System.IO.File]::Open(
        $archivePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::None
    )
    try {
        $archive = $script:ReleaseZipArchiveType::new(
            $archiveStream,
            $script:ReleaseZipArchiveReadMode,
            $true
        )
        try {
            if ($archive.Entries.Count -eq 0) {
                throw "Release source archive must not be empty"
            }
            foreach ($entry in $archive.Entries) {
                $entryPath = [string]$entry.FullName
                $isDirectory = $entryPath.EndsWith(
                    "/",
                    [System.StringComparison]::Ordinal
                )
                $relativePath = if ($isDirectory) {
                    $entryPath.Substring(0, $entryPath.Length - 1)
                }
                else {
                    $entryPath
                }
                if (
                    [string]::IsNullOrWhiteSpace($relativePath) -or
                    $entryPath.StartsWith(
                        "/",
                        [System.StringComparison]::Ordinal
                    ) -or
                    $entryPath.Contains("\") -or
                    $relativePath.Contains(":") -or
                    -not $seenPaths.Add($relativePath)
                ) {
                    throw "Release source archive contains a noncanonical path"
                }
                foreach ($segment in $relativePath.Split(
                    [char[]]@("/"),
                    [System.StringSplitOptions]::None
                )) {
                    $deviceStem = $segment.Split([char[]]@("."), 2)[0].TrimEnd(
                        [char[]]@(" ", ".")
                    ).ToUpperInvariant()
                    if (
                        [string]::IsNullOrEmpty($segment) -or
                        [System.String]::Equals(
                            $segment,
                            ".",
                            [System.StringComparison]::Ordinal
                        ) -or
                        [System.String]::Equals(
                            $segment,
                            "..",
                            [System.StringComparison]::Ordinal
                        ) -or
                        $segment.EndsWith(
                            ".",
                            [System.StringComparison]::Ordinal
                        ) -or
                        $segment.EndsWith(
                            " ",
                            [System.StringComparison]::Ordinal
                        ) -or
                        $segment.IndexOfAny(
                            [System.IO.Path]::GetInvalidFileNameChars()
                        ) -ge 0 -or
                        $segment.Contains("~") -or
                        $deviceStem -in @(
                            "CON",
                            "PRN",
                            "AUX",
                            "NUL",
                            "CONIN$",
                            "CONOUT$"
                        ) -or
                        $deviceStem -match $deviceNamePattern
                    ) {
                        throw "Release source archive contains a noncanonical path"
                    }
                }

                $unixFileType = ([int64]$entry.ExternalAttributes -shr 16) -band 0xf000
                if ($unixFileType -eq 0xa000) {
                    throw "Release source archive contains a symbolic link"
                }
                $targetPath = [System.IO.Path]::GetFullPath(
                    [System.IO.Path]::Combine(
                        $destinationRoot,
                        $relativePath.Replace("/", "\")
                    )
                )
                if (-not $targetPath.StartsWith(
                    $destinationPrefix,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) {
                    throw "Release source archive path escaped its destination"
                }

                if ($isDirectory) {
                    if ($entry.Length -ne 0) {
                        throw "Release source archive directory entry carries data"
                    }
                    [void][System.IO.Directory]::CreateDirectory($targetPath)
                    continue
                }

                $targetParent = [System.IO.Path]::GetDirectoryName($targetPath)
                [void][System.IO.Directory]::CreateDirectory($targetParent)
                $entryStream = $entry.Open()
                try {
                    $targetStream = [System.IO.File]::Open(
                        $targetPath,
                        [System.IO.FileMode]::CreateNew,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::None
                    )
                    try {
                        $entryStream.CopyTo($targetStream)
                        $targetStream.Flush($true)
                        if ($targetStream.Length -ne $entry.Length) {
                            throw "Release source archive length changed during extraction"
                        }
                    }
                    finally {
                        $targetStream.Dispose()
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
    }
    finally {
        $archiveStream.Dispose()
    }
    Assert-NoReparseTree -LiteralPath $destinationRoot
}

function New-DeterministicExtensionZip {
    param(
        [Parameter(Mandatory = $true)][string]$ExtensionRoot,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    $root = (Resolve-Path -LiteralPath $ExtensionRoot).Path
    Assert-NoReparseTree -LiteralPath $root
    if (Test-Path -LiteralPath $OutputPath) {
        throw "Deterministic extension package output already exists"
    }
    $files = @("manifest.json") + @(Get-ChildItem -LiteralPath (Join-Path $root "src") -File | ForEach-Object { "src/" + $_.Name } | Sort-Object)
    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    $stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $archive = $script:ReleaseZipArchiveType::new(
            $stream,
            $script:ReleaseZipArchiveCreateMode,
            $true
        )
        try {
            foreach ($relative in $files) {
                $source = Join-Path $root $relative.Replace("/", "\")
                $item = Get-Item -LiteralPath $source -Force
                if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Extension package input must be a regular non-reparse file"
                }
                $entry = $archive.CreateEntry(
                    $relative,
                    $script:ReleaseNoCompressionLevel
                )
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
