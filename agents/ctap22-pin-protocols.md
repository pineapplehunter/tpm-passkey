# CTAP audit resumed: PIN protocols and truthful UV

Normative source: CTAP 2.2 (2025-07-14), §§5, 6.1.2, 6.2.2, 6.4, 6.5.1,
6.5.5–6.5.7. Refetched via web tools, stored response mvrswt4x6j1s11.

Integrated/reviewed the earlier PIN worker's crypto changes without overwriting
PCR opt-in or the project rename. Parent changes use existing typed CBOR helpers,
reject unsupported UV before required-parameter checks, prefer protocols [2,1],
and distinguish missing, wrong-type, and out-of-range ClientPIN fields.

Protocol 1: SHA256(ECDH), zero-IV CBC with no prefix, HMAC truncated to 16 bytes.
Protocol 2: existing independent HKDF keys, random-IV prefix, 32-byte HMAC.
Active tokens are protocol-tagged; a valid full-length MAC cannot repurpose a
Protocol 1 token as Protocol 2. Issuance replaces all prior active tokens, matching
§6.5.5.7's reset-all-protocols steps. ChangePIN/reset also invalidate token state.

Polkit/terminal approval is UP only, never built-in UV. UV subcommands 6/7 return
INVALID_COMMAND; effective uv=true options return INVALID_OPTION. PIN tokens
alone establish UV and never cache presence. With no configured PIN, rk=true
registration may proceed with UP only; after PIN setup it requires a token.

VM compliance flow now sets a real PIN, tests P1 legacy token registration and
P2 permissioned assertion/credential management, verifies UP/UV flags, rejects
fake built-in UV, and keeps testing PIN change/reboot/reset through libfido2.

Remaining known gaps: client-only credProps currently appears as an authenticator
extension; PIN load failures silently downgrade protection; approval is blocking;
PIN verifier/retries have no TPM-equivalent storage protection. These are not
hidden behind a full-compliance claim. No migrations or credential-policy edits.

Validated: nix fmt, cargo check, cargo test (91), daemon dry run, and full
nix flake check (Pueue task 10). Both host-system software-TPM VM checks passed,
including real Protocol 1 enrollment and Protocol 2 authenticated operations.
