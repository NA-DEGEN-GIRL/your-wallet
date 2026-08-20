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
