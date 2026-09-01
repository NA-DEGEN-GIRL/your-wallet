[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$PSModuleAutoLoadingPreference = "None"
Set-StrictMode -Version Latest

$successSentinel = "WINDOWS_READINESS_PREFLIGHT_PASS_CURRENT_USER_NON_ELEVATED"
$blockedSentinel = "WINDOWS_READINESS_PREFLIGHT_BLOCKED"
$blockedExitCode = 20
$identity = $null
$process = $null

try {
    if (
        [System.Environment]::OSVersion.Platform -ne
            [System.PlatformID]::Win32NT -or
        -not [System.Environment]::UserInteractive
    ) {
        throw "blocked"
    }

    $process = [System.Diagnostics.Process]::GetCurrentProcess()
    if ($process.SessionId -eq 0) {
        throw "blocked"
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (
        $null -eq $identity -or
        -not $identity.IsAuthenticated -or
        $null -eq $identity.User -or
        $identity.ImpersonationLevel -ne
            [System.Security.Principal.TokenImpersonationLevel]::None
    ) {
        throw "blocked"
    }

    $userSid = $identity.User.Value
    if (
        [System.String]::Equals(
            $userSid,
            "S-1-5-18",
            [System.StringComparison]::Ordinal
        ) -or
        [System.String]::Equals(
            $userSid,
            "S-1-5-19",
            [System.StringComparison]::Ordinal
        ) -or
        [System.String]::Equals(
            $userSid,
            "S-1-5-20",
            [System.StringComparison]::Ordinal
        ) -or
        $userSid.StartsWith(
            "S-1-5-80-",
            [System.StringComparison]::Ordinal
        )
    ) {
        throw "blocked"
    }

    $groupSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($groupSid in @($identity.Groups)) {
        if ($null -ne $groupSid) {
            [void]$groupSids.Add($groupSid.Value)
        }
    }

    $hasServiceSid = $false
    foreach ($groupSidValue in $groupSids) {
        if ($groupSidValue.StartsWith(
            "S-1-5-80-",
            [System.StringComparison]::Ordinal
        )) {
            $hasServiceSid = $true
        }
    }

    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)

    $systemDirectory = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::System
    )
    $whoamiExecutable = [System.IO.Path]::Combine(
        $systemDirectory,
        "whoami.exe"
    )
    if (
        [string]::IsNullOrWhiteSpace($systemDirectory) -or
        -not [System.IO.File]::Exists($whoamiExecutable) -or
        ([System.IO.File]::GetAttributes($whoamiExecutable) -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "blocked"
    }

    $previousErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $integrityOutput = @(& $whoamiExecutable /groups /fo csv /nh 2>$null)
        $whoamiExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($whoamiExitCode -ne 0) {
        throw "blocked"
    }
    $hasAllowedIntegrity = $false
    $hasForbiddenIntegrity = $false
    foreach ($integrityLine in $integrityOutput) {
        $line = [string]$integrityLine
        if ($line -match "(?<![0-9-])S-1-16-(?:8192|8448)(?![0-9-])") {
            $hasAllowedIntegrity = $true
        }
        if ($line -match
            "(?<![0-9-])S-1-16-(?:12288|16384|20480|28672)(?![0-9-])") {
            $hasForbiddenIntegrity = $true
        }
    }

    if (
        -not $groupSids.Contains("S-1-5-4") -or
        -not $hasAllowedIntegrity -or
        $hasForbiddenIntegrity -or
        $groupSids.Contains("S-1-5-3") -or
        $groupSids.Contains("S-1-5-6") -or
        $hasServiceSid -or
        $groupSids.Contains("S-1-5-32-544") -or
        $groupSids.Contains("S-1-16-12288") -or
        $groupSids.Contains("S-1-16-16384") -or
        $groupSids.Contains("S-1-16-20480") -or
        $groupSids.Contains("S-1-16-28672") -or
        $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    ) {
        throw "blocked"
    }

    [System.Console]::Out.WriteLine($successSentinel)
    exit 0
}
catch {
    [System.Console]::Error.WriteLine($blockedSentinel)
    exit $blockedExitCode
}
finally {
    if ($null -ne $identity) {
        $identity.Dispose()
    }
    if ($null -ne $process) {
        $process.Dispose()
    }
}
