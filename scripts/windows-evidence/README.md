# Windows evidence readiness

This directory contains a non-elevated, current-user readiness fixture for the
Phase 2G Windows lifecycle contract. It is deliberately separate from
`scripts/release/` and never produces release evidence.

The fixture rejects Administrator, elevated, SYSTEM, service, and
non-interactive identities. It does not elevate itself or install/control a
service. It does not change policy, ACLs, the registry, firewall state, TPM
state, signatures, or reboot state.

The runner accepts one fixed case and executes one locked test profile:

```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/windows-evidence/run-current-user.ps1
```

Dependencies must already be available locally because Cargo runs with
`--locked --frozen --offline`. The runner itself creates only ordinary Cargo
artifacts under `target/` and a canonical result under the ignored
`artifacts/windows-evidence/` directory. Cargo, rustc, and the operating system
may still use their preconfigured local caches or temporary facilities; those
ambient tool writes are not evidence produced by this harness. The result
contains no username, SID, computer name, absolute path, environment dump, raw
log, transcript, timestamp, or free-form reason.

The runner rejects caller arguments, compiler/toolchain environment overrides,
and Cargo configuration files discoverable from the workspace, its ancestors,
or the default user Cargo directory. Its fixed Node, preflight, and Cargo child
profiles have deadlines and live combined-output character caps. A timeout or
overflow terminates the selected leaf process and records only a fixed
readiness result; descendant-process cleanup remains part of the trusted local
tool boundary.

`local-fixture` means that the exact 22 local lifecycle tests passed under the
fixed profile. `blocked` and `not-run` exit nonzero. Every result carries
`releaseEligibility: "not-release-evidence"`; equality from the build-inventory
comparator has the same limitation.

Actual elevated SCM and installer evidence, service-SID and ProgramData ACL
evidence, reboot and power-loss evidence, TPM-backed evidence, signing evidence,
and release-machine reproducibility remain separate STOP-SHIP gates.

This local fixture trusts the PATH-selected local Cargo and Node applications,
the fixed system PowerShell executable, the default Rustup installation and
caches, and the workspace and parent directories against malicious same-user
replacement before or during the run. It holds the selected Cargo and Node
leaf files, the two harness source files, and generated evidence without
write/delete sharing while they are used. It does not pin parent-directory
handles, so those explicit same-user and descendant-process trust boundaries
remain. Neither that boundary nor a successful fixture result is release
evidence.
