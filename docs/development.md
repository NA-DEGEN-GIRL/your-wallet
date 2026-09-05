# Local development checks

The repository gate remains:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 check
```

CI also requires the separate, check-only release-policy gate. Run both before
calling the CI checks complete; neither authorizes a production release:

```powershell
$systemPowerShell = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System), 'WindowsPowerShell', 'v1.0', 'powershell.exe')
$nodeExecutable = $ExecutionContext.SessionState.InvokeCommand.GetCommand('node', [System.Management.Automation.CommandTypes]::Application).Path
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/check.ps1 all -NodeExecutable $nodeExecutable
```

For a library test or module, use the focused runner. It obtains the actual
Key Agent executable from Cargo's build output and supplies the same
`YW_TEST_KEY_AGENT_EXECUTABLE` fixture required by the full gate. Running
`cargo test` directly without that fixture can produce `OperatingSystem`
errors in Windows activation tests.
Both runners share one artifact parser: missing or duplicate matches, relative
paths (including Windows drive-relative and root-relative paths), non-string
paths, wrong executable names, and missing files are rejected.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-focused.ps1 -Package platform-windows -Filter secret_input_lifecycle::tests:: -ExpectedCount 10
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-focused.ps1 -Package platform-windows -Filter secret_input_lifecycle::tests:: -ExpectedCount 10 -Features key-agent-service-lpac-launch-feasibility-test-hook
```

Use `-Exact` with a fully qualified test name to select a single test. Discovery
must select at least one test. `-ExpectedCount` additionally detects missing or
unexpected tests. A successful run requires every discovered test to pass;
ignored tests, zero-test runs, inventory mismatches, and command failures fail
the runner. The prior helper environment value is restored even on failure.

Progress, counts, and restricted failing-test identifiers are printed without
raw child output or local paths. No raw logs or wallet data are written by this
runner. Cargo still writes its ordinary build artifacts and local caches.
This is a development aid, not release evidence or a replacement for the full
repository gate.

The full gate prints each tool's start and elapsed time. The architecture scan
also emits fixed count/time progress after every 32 verified checks. Its scan
includes the repository-wide security checks and mutation controls, so it is
appropriate for integration milestones. Focused test success does not imply
that those checks have run.

PowerShell files use CRLF as specified by `.gitattributes`. Normalize new and
edited PowerShell files before updating their raw-byte architecture inventory
hashes; mixed line endings can otherwise pass locally and fail after checkout.

The privacy scan checks tracked files plus non-ignored new source files.
Ignored build output and dependencies are outside that source inventory.
The gate also runs the focused-runner and privacy-scanner regression tests.
