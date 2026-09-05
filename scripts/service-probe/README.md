# Local service Approval transport probe

This is an **unsigned, debug-only operator harness**, not a production installer
or release approval. It has no wallet, mnemonic, private-key, vault, transaction,
or signing operation. A transport success is not evidence that real-asset use is
safe. The installed/restricted SCM and native UI path still needs an actual
operator run; automated checks do not claim that evidence.

The operator explicitly trusts the reviewed local workspace, the fixed native
interop source, and the four locally prepared debug executables. `Add-Type`
compiles only that fixed interop source; the elevated entry does not invoke Cargo,
project build scripts, package restore, candidate executables, or UAC. Use a new
64-bit Windows PowerShell process with `-NoProfile` as shown below. Do not
dot-source the operator script into an arbitrary existing elevated session.

## Prepare without elevation

From the repository root, use a normal Medium-integrity interactive desktop:

```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/prepare.ps1
```

Preparation must produce the fresh fixed `artifacts/service-probe-candidate`
directory. It contains exactly `approval-ui.exe`, `key-agent-service-probe.exe`,
`key-agent-service.exe`, `secret-input-ui.exe`, and `candidate.json`. The manifest
is canonical ASCII, no BOM, one final LF, and no paths or identities:

```json
{"schemaVersion":1,"purpose":"service-approval-transport-debug-only","architecture":"x86_64-pc-windows-msvc","artifacts":[{"name":"approval-ui.exe","bytes":1,"sha256":"<lowercase SHA-256>"},{"name":"key-agent-service-probe.exe","bytes":1,"sha256":"<lowercase SHA-256>"},{"name":"key-agent-service.exe","bytes":1,"sha256":"<lowercase SHA-256>"},{"name":"secret-input-ui.exe","bytes":1,"sha256":"<lowercase SHA-256>"}]}
```

The above illustrates the field order only; its placeholder hashes are invalid.
The actual manifest uses each exact held artifact's positive byte length, bounded
to 512 MiB, and lowercase 64-digit SHA-256. Preparation owns generation; never
hand-edit a candidate into apparent validity.

Cargo normally gives a reported executable one hardlink in its `deps` directory.
A separate non-elevated build-only opener accepts one or two links for the four
fixed, provenance-checked build paths and retains the file's identity, size and
link count. Its read-only handle blocks writes through either name and deletion
of the held name. Windows can still allow deletion of the unopened alias; any
observed link-count change is rejected on revalidation before manifest creation.
The fresh copied candidate and every installer input must still be single-link.
Preparation never removes Cargo aliases or searches for arbitrary link paths.

## Explicit elevated operator steps

Review the source and candidate, then open an elevated 64-bit PowerShell yourself
and change to the same repository root. No command below is executed by automated
tests. The only accepted syntax is the exact two arguments `-Action <operation>`:

```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/operate.ps1 -Action Install
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/operate.ps1 -Action Readback
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/operate.ps1 -Action Start
```

Install refuses an existing `YourWalletKeyAgent` service or an existing
machine-Program-Files `YourWalletServiceProbe` leaf. It does not adopt, repair,
overwrite, or stop an unrelated service. The new directory and files have
protected ACLs and Administrators ownership from creation; neither the desktop
user nor the service can rewrite the executables or ownership journal. Source
files are held read-only without write/delete sharing, reparse points and
multiple hardlinks are rejected, and copied hashes and exact ACLs are read back.

The service is fixed to `NT SERVICE\YourWalletKeyAgent`, own process,
noninteractive, demand start, one quoted binary path, and no arguments. There is
no LocalSystem fallback. The protected service DACL grants only SYSTEM and
Administrators full control. The service SID and both fixed helper package SIDs
are obtained from Windows; each helper file grants read/execute only to its
corresponding package SID in addition to the service and trusted administrators.

Run the desktop client from the **prepared workspace candidate** in a separate
normal, non-elevated interactive PowerShell, not from the protected Program Files
copy and never from the elevated operator shell:

```powershell
& .\artifacts\service-probe-candidate\key-agent-service-probe.exe
```

The Program Files client copy intentionally has no general desktop-user execute
grant. The native Approval window is explicitly a non-signing transport test and
uses the existing original five-second service deadline. A client failure or an
expired window is not approval and does not enable signing. This harness does not
change machine policy to make an unsuccessful probe appear successful.

The client executable also has an independent 25-second process watchdog around
the RPC work and output/flush. Windows ignores `RPC_C_OPT_CALL_TIMEOUT` for local
RPC, so the library's before/after deadline checks alone cannot stop a stuck
call. The watchdog exits only this non-signing diagnostic process with code 78;
it does not cancel another process, retry the command, or claim remote cleanup
completed. Successful output is valid only with exit code 0. The service retains
its own original helper deadline and cleanup obligations. See the official
[local-RPC timeout limitation](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetoption).

After the probe, use the elevated operator shell:

```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/operate.ps1 -Action Stop
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/operate.ps1 -Action Remove
```

Remove requires the exact stopped configuration, protected ownership journal,
directory identity, file inventory, hashes, ACLs, and expected account rights.
It removes only the known file leaves using identity-held deletion and then the
same empty directory. It never recursively deletes a directory. Successful
removal does not remove the workspace candidate or any wallet/user storage.

## Privileges and retained failure state

The required-privilege filter is exactly `SeAssignPrimaryTokenPrivilege`,
`SeChangeNotifyPrivilege`, `SeImpersonatePrivilege`, and
`SeIncreaseQuotaPrivilege`. That filter does not grant missing rights. This
harness records the exact service SID's existing direct LSA rights, refuses any
outside the four selected privileges plus `SeServiceLogonRight`, writes a
protected journal of the missing subset, grants only that subset, and reads it
back. It never grants Debug, Tcb, Backup, Restore, or LoadDriver privileges and
never edits group/domain policy. Microsoft documents that the required-privilege
list filters the initial token and that ChangeNotify remains present for
compatibility. See [required privileges](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow).

Cleanup removes only the explicitly journaled subset with
`LsaRemoveAccountRights(AllRights=false)`, preserving all observed preexisting
rights. The baseline is observed **after** service creation, so it can include
an SCM-created service-logon right; successful cleanup does not claim that this
remaining LSA account record was created independently or deleted. See
[account-right enumeration](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights)
and [selective right removal](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights).

Errors after first directory creation retain the protected partial fixture and
emit `SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW`. There is no automatic
repair or speculative rollback. A partially configured service, incomplete
grant, interrupted removal, extra file, or altered manifest can deliberately
block `Remove`; inspect that precise fixture as an administrator before deciding
what to repair or remove. Do not retry Install by force, broaden permissions, or
claim full rollback. Successful actions end in `PASS_NOT_RELEASE_EVIDENCE`;
unelevated operation is rejected before native mutation with exit 20.

## Read-only diagnosis after an operator failure

Do not repeat Install, Start or Remove after a retained-state failure. The same
generic category covers failures both before and after creation; it does not
identify the failed check or prove what was changed. Run this **single line** in
the elevated 64-bit PowerShell, using this workspace's actual location:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File 'D:\#Programming\your-wallet\scripts\service-probe\operate.ps1' -Action Inspect
```

Inspect is a separate read-only dispatcher. It requests only SCM connect and
service query-configuration, query-status and READ_CONTROL rights. File handles
are read-only; account-right enumeration does not grant or remove rights.
It never starts, stops, installs, removes or repairs a service, changes ACLs,
replaces candidates, runs a candidate executable, or builds project code.

Output contains only fixed stage names and PASS/FAIL/UNAVAILABLE categories,
not exception text, native error payloads, paths, SIDs, hashes or file contents.
The service-status stage instead reports STOPPED, RUNNING, START_PENDING, OTHER
or UNAVAILABLE, without sending a control command.
The service security owner/group, exact ACE bytes and protection bit are checked
separately, as are service configuration and the retained files. An unavailable
query is not evidence of absence. A completed inspection is **not ownership,
installation-success, transport or release evidence**; failed independent
checks remain failed. Share the fixed output before deciding on a precise repair.

An ordinary user's service list can omit a service when its query permission is
denied. Do not interpret such omission as permission to reinstall. See Microsoft's
[service query access contract](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

## Verification boundaries

```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/service-probe/native.test.ps1
node --test scripts/service-probe/operate.test.mjs
node --test scripts/service-probe/prepare.test.mjs
```

The 139 native self-checks retain the original 30 interop, manifest and fake
operator checks, adding the 33-stage inspection dispatcher, fixed-output error
cases and independent security-shape checks. These include preflight rejection
before execution and propagation of a failed explicit native cleanup.
Failed SCM/LSA/native-allocation cleanup prevents a
successful operator result; finalizers do not throw. CLI tests use owned temporary
copies, a forced-denied preflight, and a poisoned native execution boundary;
they do not install, start, stop, delete, or configure a real service, modify LSA,
or open a native Approval UI. They do not simulate every native installation
failure edge and are not a substitute for installed Windows evidence.
The six operator CLI tests include poisoned inspection adapters with fixed
successful and mixed-failure results. They do not perform an actual elevated
inspection of the retained fixture.

Additional official contracts used by this harness:

- [Virtual account service creation](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
- [Restricted service SID](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Optional configuration readback, including NULL or empty group/dependencies](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw)
- [Security descriptor at directory creation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
- [OS-derived helper package SID](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deriveappcontainersidfromappcontainername)
- [Identity-held file disposition requires DELETE access](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
