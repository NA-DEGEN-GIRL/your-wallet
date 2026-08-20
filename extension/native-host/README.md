# Native-host manifest boundary

`com.your_wallet.native.json.template` is deliberately not installable. Both
the executable path and Chrome extension ID are release placeholders, and
`validateReleaseNativeManifest` rejects either placeholder.

A release process must render a separate concrete manifest and validate it
before registration. The validator requires exactly one
`chrome-extension://<32 lowercase a-p characters>/` origin, the exact host name,
`stdio`, and an absolute Windows `.exe` path. It does not install or register
anything and does not prove path ACLs, Authenticode identity, artifact hashes,
or endpoint DACLs. Those remain separate release-attestation requirements.

There is intentionally no development origin, wildcard origin, relative path,
environment-variable expansion, registry writer, or installer fallback here.

## Current headless bridge state

The MV3 background worker opens the exact host name through Chrome Native
Messaging. The default native executable now keeps that bounded stdio stream
alive for multiple exact request/cancellation frames. Every valid request still
receives provider error `4900`, cancellation has no response, and EOF or the
first terminal protocol error ends the process with code 78. The executable
constructs only a disabled release attestation, so the Broker endpoint and
downstream executor remain unreachable.

An explicit development-only hook is gated by both the
`broker-ipc-contract-test-hook` Cargo feature and Rust debug assertions. It
derives only the regular-file `broker` sibling beside its own executable and
starts that child with hidden, cleared-environment, bounded stdio. A private
drop guard kills and waits the exact child even if the contract driver unwinds.
After an exact two-nonce/role handshake, Broker may return only its local Sepolia
`eth_chainId`. Every other allowlisted request is represented internally only by
a closed method enum and the exact session/sequence/activation/request
correlation; raw parameters, message bytes, accounts, addresses, and origins do
not cross this unavailable-completion command. Broker records that request as
complete before the host emits 4900. A later exact cancellation is consumed as
already completed, receives no Chrome response, and cannot shift the next
request sequence. The hello is outside Broker's independent lifetime count:
4,096 post-handshake commands may be dispatched and the next complete frame
fails before dispatch.

The real headless process tests cover all of the following without opening a
browser or GUI and without performing a wallet network request:

- multiple chain-ID and stable-unavailable responses over one native-host and
  one Broker subprocess;
- a response-free late cancellation followed by another successful chain-ID
  request on the same pair;
- old-process exit 78, a newly sampled extension session, sequence reset, and a
  successful request after reconnect; and
- a release build with all features enabled, proving the hook is still absent,
  the Broker exits 78, and the native host stays on the 4900/exit-78 path.

A second Windows-only development hook is gated by both
`windows-broker-channel-contract-test-hook` and debug assertions. It does not
use Broker stdio. The platform supervisor holds the sibling `broker.exe`
without write/delete sharing, launches it hidden and suspended on a fresh
debugger thread, and compares the first pre-user-mode
`CREATE_PROCESS_DEBUG_EVENT.hFile` with that held artifact by volume serial and
all 128 `FILE_ID_INFO` bits. Its exact `HANDLE_LIST` is `[restricted parent
process, shared read/write NUL]`; `STARTF_USESTDHANDLES` assigns that same NUL
handle to stdin, stdout, and stderr. Its exact `JOB_LIST` is `[job]`, naming the
retained one-process kill-on-close Job, and its environment has only two
variables. The process, Job, and held artifact remain owned until the channel
closes; a hung child is terminated and reaped.

That private named pipe has one protected current-logon DACL entry, rejects
remote clients and second instances, and binds both ends to retained process
objects plus pipe-reported process/session identity. It never reopens a PID.
The Windows channel is the sole owner of its four-byte big-endian prefix and
8,192-byte JSON payload ceiling. Broker IPC consumes payloads only; the legacy
stdio adapter remains a separate single framing owner. The same closed typed
state permits only chain ID, correlation-only unavailable completion, and exact
cancellation. It still cannot represent accounts, wallet RPC, network access,
signing, or a Key Agent operation.

The Windows process test builds the two real debug binaries in one isolated
target directory, reaches chain ID and typed unavailable over the exact hidden
channel, then observes native-host exit 78. Platform subprocess tests separately
cover the exact 8,192-byte boundary, mapped-file mismatch before user mode,
partial/deadline closure, and hung-child Job cleanup. Release with all features
still proves both hooks absent.

This is protocol-path evidence only. It proves the launched Broker child, not
the already-running native host that Chrome started. An immutable signed
installation, protected native-messaging registration, stable release extension
ID, and end-to-end signed-artifact evidence remain stop-ship. The debug artifact
hold is not Authenticode release attestation.
