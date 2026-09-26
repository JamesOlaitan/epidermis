# `epidermis-core`

This crate contains the local protocol objects and verification rules for issuer-backed credentials and exact-action authorization. It's the library used by the issuer, wallet, and verifier layers (it doesn't run a service or own persistent application state).

## Responsibilities and boundaries

| Module | Owns | Called by |
| --- | --- | --- |
| `crypto.rs` | SLH-DSA-SHA2-128s keys and signatures, SHA-256 hashes, and the length-prefixed signing encoder | Issuer and wallet key adapters. The model and verifier |
| `model.rs` | Claims, credentials, actions, challenges, presentations, and their signed byte representations | Issuer, wallet, and verifier services |
| `verify.rs` | Issuer claim permissions, credential and presentation checks, approval policy, revocation lookup, and one-time challenge consumption | Verifier service |

The issuer service is responsible for enrollment, mapping one person to an issuer-scoped `subject_id`, protecting issuer signing keys, and publishing trust and revocation data. A wallet protects holder keys, displays the exact `Action` fields, and obtains user approval before calling `Presentation::sign`. A verifier service selects the action schema and `Policy`, issues and registers challenges, supplies trusted issuer and revocation data, and persists verification/audit outcomes. This crate checks the signed data it receives (it can't establish that enrollment or the wallet display was trustworthy).

The `InMemoryTrustRegistry` and `InMemoryReplayStore` are development implementations. Production implementations of `TrustRegistry` and `ReplayStore` must use authenticated, current trust data and shared, atomic challenge state. The replay store must recognize only challenges issued by the relying party and consume each successfully verified challenge once. The current `TrustRegistry::is_revoked` returns only a boolean, so the interface must be extended to represent unavailable or stale status before production use.

## Integration contract

1. Construct `CredentialBody` with sorted, unique claim kinds and an issuer-scoped `subject_id`. sign it with `Credential::issue`.
2. Construct an `Action` with sorted, unique field names. Include every value whose change would alter the user's decision. The wallet must display these same values.
3. Construct a short-lived `Challenge` for the relying party's audience and action. Register its exact bytes before sending it to the wallet.
4. The holder signs a `Presentation` with the private key named in the credential.
5. Call `Verifier::verify` with the expected audience, action, challenge, presentations, policy, current time, trust registry, and replay store. Treat any `VerifyError` as a denied authorization.

`Verifier::verify` is the crate's facade. `TrustRegistry` and `ReplayStore` are adapter points for the hosting service. The verifier composes a fixed sequence of checks: structural validity, challenge binding and time, issuer authority, credential signature and revocation, policy claims, holder signature, distinct approvers, then atomic challenge consumption. Keep this order so invalid requests do not consume valid challenges. The current code does not implement a configurable strategy or chain of responsibility. They'll be added when multiple verification methods require them.

## Rules for changes

- Treat `signing_bytes()` as a protocol format. Changing field order, encoding, domain strings, or signature algorithm invalidates existing signatures. Make such changes under a new protocol version with test vectors and a migration plan.
- Keep claim authorization separate from signature validity: a valid issuer signature is insufficient when the issuer is not trusted to assert that claim kind.
- Preserve distinctness checks for both holder keys and `(issuer, subject_id)`. The issuer must deduplicate its own people; distinct references from different issuers do not prove distinct humans.
- Keep policy and action schema decisions outside this crate. So, bank, video-call, or social-network-specific verification don't belong here.
- The current credential exposes a stable issuer-scoped subject reference. It does not provide L1 unique-human proofs or cross-service unlinkability.
- This crate does not own enrollment, passkeys, device attestation, recovery, a trusted display, network transport, durable storage, or audit retention.

Run `cargo test --locked` and `cargo clippy --all-targets -- -D warnings` from the repository root after changing protocol or verification behavior. `tests/authorization.rs` covers action tampering, approval thresholds, duplicate approvers, replay, revocation, audience binding, and credential tampering.
