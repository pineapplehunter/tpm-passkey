# Single-user simplification

The supported model is one daemon/store for one user on a single-user machine.
This supersedes the multi-user/session-isolation tasks in earlier agent plans.

- Removed session identity checks and session-bound CTAP state.
- Removed management peer-UID discovery and owner-filtered store queries.
- Kept logind discovery only for polkit prompt routing, plus existing approval,
  PIN/UV, cancellation, device/socket permissions, and TPM policies.
- Retained legacy owner metadata in storage/MACs and existing TPM policyRefs to
  avoid invalidating existing credentials. New credentials have no owner UID.
- Updated README and the current architecture/security/protocol documentation.

Validation passed: `nix fmt`, SQLx offline metadata regeneration,
`cargo check`, `cargo test` (70 tests), and `cargo run -- daemon --dry-run`.
The NixOS VM integration test was not rerun.
