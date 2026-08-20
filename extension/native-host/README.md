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

This is protocol-path evidence only. The handshake nonces are not process
authentication, and the same-build sibling path is not trusted bootstrap.
Authenticated Windows Broker IPC, exact executable identity, SID/DACL and
remote-client rejection, signed installation/registration evidence, and the
release-attested downstream composition remain stop-ship requirements.
