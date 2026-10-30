# Remaining CTAP audit follow-up

Normative reference: CTAP 2.2 PS, 2025-07-14, linked from AGENTS.md.

## Persistent assertion order (§6.2.2)

Without an allowList, multiple credentials must be ordered newest first. The
assertion path reverses its in-memory candidate list, but persistent reloads
previously sorted by RP and random credential ID. Load in ascending persistent
local_id order instead. The IDs are preserved for existing records on full-store
rewrites and assigned in registration order for new credentials. This avoids
second-resolution timestamp ties. The store regression deliberately reverses ID
and RP ordering and rewrites the input vector; the CTAP VM checks ordered user
handles before and after a daemon restart.

## Security blockers retained explicitly

§6.5.1 requires PIN storage assurances at least equivalent to private keys.
SQLite verifier/retry state plus a colocated HMAC key is not equivalent to
TPM-bound private keys. A partial sealing-only fix would leave rollback of retry
state. No TPM NV/reset lifecycle redesign is slipped into this wire audit.

Current credential MAC covers only identity/user metadata. A complete-record MAC
would also need to bind keys, policy, counters and creation-order metadata and be
updated by signing/migration paths. Existing unsigned fields cannot be safely
upgraded just by computing a new MAC at load time. A versioned transition and a
TPM-backed rollback strategy remain necessary, rather than silently trusting old
records or invalidating all existing passkeys without a migration decision.

§9: no FIDO_2_2 advertisement. hmac-secret and credProtect remain unimplemented;
PIN support counts as UV support for the latter requirement. NFC/BLE/hybrid/U2F
are not implemented, and U2F absence is correctly signaled with NMSG.

## Integrated command-family corrections

- §§6.1.2/6.2.2: distinguish missing required fields from wrong CBOR types;
  protocol-only input does not invent a missing authentication requirement.
- §6.1.2 step 12: exclusion returns CREDENTIAL_EXCLUDED after UP or timeout,
  without consuming token permissions/cached UP or being hidden by a full store;
  explicit CTAPHID cancellation remains KEEPALIVE_CANCEL.
- §§6.1.3/6.2: return discoverable user handles even for allow-list assertions;
  omit identifying names and retain no enumeration state for allow lists.
- §§6.5.5–6.5.7 and §8.1: initialized/stable key agreement, regenerated on wrong
  PIN/decryption error; unsupported ClientPIN subcommands return 0x3e; unsigned
  nonzero permissions accept unknown high bits without granting them. Check
  blocked state before cryptography; persist an attempt before PIN-hash
  decryption; correct PIN resets retries before replacement-PIN validation.
  Uncertain persistent writes latch live PIN handling closed.
- §§11.2.5.4/11.2.9: empty CBOR transport length error, idle INIT discards state,
  invalid INIT does not allocate/abort, spurious continuations ignored, CANCEL
  never gets a direct response. Keepalive is sent on status change at the next
  UHID poll as well as at 100 ms. Remove no-op WINK advertising/support.

The immediate status-change keepalive exposed another cancellation-test race:
its event file may not exist before the first agent message. Treat that as no
messages yet, keeping the existing bounded wait. An initial VM snapshot also
caught a test-fixture field mistake; corrected before final validation.

## Validation

Initial `nix fmt`, `cargo check --workspace`, `cargo test --workspace`: passed.
`nix build --no-link .#checks.x86_64-linux.nixos-ctap-credentials
.#checks.x86_64-linux.nixos-state-integrity`: passed, including the daemon-restart
assertion-order check. Transport VM passed before the final PIN integration.
Final `nix fmt`, `cargo check --workspace`, and `cargo test --workspace` passed
(170 tests passed, 8 ignored, no failures). Complete
`nix flake check --keep-going` passed for x86_64-linux, including all 15 NixOS VM
checks, binary separation, formatting, and approval-options checks. Incompatible
aarch64-linux/aarch64-darwin systems were skipped by Nix; not claimed tested.
