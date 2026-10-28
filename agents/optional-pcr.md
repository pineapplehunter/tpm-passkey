# Optional PCR binding

Requested behavior: TPM-bound keys remain non-exportable, with no PCR dependency
unless explicitly selected. Recovery phrase setup alone must not enable PCRs.
Existing per-credential policies and explicitly saved default selections remain
unchanged; disabling clears only the future-registration default.

Implementation:
- Unbound registration creates a key with no authPolicy and userWithAuth=true
  (empty auth), keeping fixedTPM/fixedParent/sensitiveDataOrigin=true. This is
  distinct from an empty PCR selection, and fixes the previously unusable
  no-policy key template (userWithAuth=false with no policy).
- Bound registration requires configured/unlocked recovery and always creates
  an authority and signed policy. Global defaults never determine how old keys
  sign. Policy updates still require the supplied recovery phrase.
- `config set default-pcr-policy --disable` removes the configuration row.
  Missing/default-disabled is shown as `none` (wire config uses CBOR null).
  Existing saved selections are neither deleted nor interpreted as missing.
- No new or modified migrations are needed for this feature.

Checks passed: SQLx metadata refresh, nix fmt, cargo check, cargo test (85),
and daemon dry run. The new software-TPM/UHID VM regression covers default keys
across PCR changes, phrase-only behavior, locked/missing recovery gates, explicit
binding, recovery phrase enforcement, future-only disable, and old-key policy
snapshots. Full `nix flake check -L` passed (Pueue task 8), including both
software-TPM VM checks; only the host system was checked.

The broad CTAP audit is paused for this request. Its committed fixes remain;
Protocol 1 and bounded-approval worker changes have not been integrated.
After this PCR change, the user requested a full rename to `tpm-passkey`, with
existing encrypted recovery records still readable.
