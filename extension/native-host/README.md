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

The headless process test drives two real `BackgroundRouter` requests through
one native-host subprocess and checks the two independent native response
sequences plus final exit 78. It starts no browser or GUI and performs no wallet
network request. This is protocol-path evidence only; authenticated Broker IPC,
signed installation/registration evidence, and the release-attested downstream
composition remain stop-ship requirements.
