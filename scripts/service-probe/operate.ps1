$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try {
    if ($args.Count -ne 2 -or $args[0] -cne '-Action' -or
        $args[1] -cnotin @('Install', 'Readback', 'Start', 'Stop', 'Remove')) {
        Write-Output 'SERVICE_PROBE_ARGUMENT_ERROR'
        exit 2
    }
    $Action = [string]$args[1]
    . (Join-Path $PSScriptRoot 'common.ps1')
    Import-ServiceProbeNative
    $workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $result = [YourWallet.ServiceProbe.Harness]::Run($Action, $workspace)
    Write-Output $result
    if ($result -ceq ('SERVICE_PROBE_' + $Action.ToUpperInvariant() + '_PASS_NOT_RELEASE_EVIDENCE')) {
        exit 0
    }
    exit 20
}
catch {
    Write-Output 'SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW'
    exit 20
}
