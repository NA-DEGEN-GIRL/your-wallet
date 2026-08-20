# Security policy

This project is pre-release and explicitly **STOP-SHIP**. No version is
currently supported for storing value, signing live transactions, installation,
or distribution.

## Reporting a finding

Do not include real seed phrases, private keys, passwords, signed transactions,
RPC credentials, private URLs, wallet addresses, or identifying browser data in
a report. Reproduce with synthetic fixtures and describe:

- the affected commit and component;
- the trust boundary or invariant that fails;
- a minimal synthetic reproduction;
- whether the issue can expose secrets, misrepresent an approval, create an
  unauthorized signature, reuse a nonce, bypass chain policy, or compromise an
  update; and
- any suspected active exploitation.

Until a private disclosure channel is published, keep high-impact findings
local and contact the repository owner through the same private channel by which
you received access. Do not open a public issue containing exploit details or
sensitive artifacts.

## Response rules

A suspected secret, authorization, signing, nonce, release-key, or update
compromise freezes release work. The response must preserve evidence without
copying secret payloads into logs, revoke affected artifacts/keys, invalidate
pending approvals and sessions, quarantine potentially signed nonces, and
publish a reviewed recovery plan before signing is re-enabled.

Security fixes do not silently weaken a fail-closed behavior. Any exception to
the frozen decisions in [security-decisions.md](docs/security-decisions.md)
requires a written decision record, new negative tests, and independent review.
