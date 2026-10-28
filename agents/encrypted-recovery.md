# Encrypted recovery authorization

The user permits breaking changes, including credential deletion, but requires
new SQL migrations rather than editing old migrations.

Design:
- Each credential has a TPM-generated recovery authority and a random 32-byte
  authorization value, independent of the passphrase.
- Argon2id (64 MiB, t=3, p=1) derives a wrapping key; AES-256-GCM protects each
  authorization value with a fresh nonce and credential/key/policyRef AAD.
- Stored TPM key types cannot contain authorization values. No plaintext
  passphrase hash, derived wrapping key, or equivalent is persisted.
- An encrypted known configuration marker validates the passphrase. Setup and
  explicit `config unlock-recovery` keep only a zeroizing wrapping key in the
  authenticator worker for creating recovery-enabled credentials. Restart locks
  enrollment, not ordinary signing. Policy updates always decrypt using the
  provided phrase, rather than implicitly using the enrollment unlock cache.
- Rotation rewraps all secrets and configuration in a single SQL transaction;
  no change to TPM objects or registered passkeys is needed.
- A new breaking migration deletes insecure old credentials and passphrase
  configuration; it cannot erase old backups/snapshots or securely wipe media.

Validation passed: SQLx offline metadata regeneration, `nix fmt`, `cargo check`,
`cargo test` (70 tests), and the daemon dry run. Tests cover wrong phrases,
AEAD tampering/slot swaps, enrollment unlock/restart, rotation and rollback of
failed SQL writes, and upgrading a pre-change database through the destructive
migration. A focused independent source review found no introduced bugs.

Follow-ups: migration `20261028070000` removes legacy owner metadata/indexes
and discards owner-dependent MAC records. Migration `20261028080000` adds
`last_used` and `used_count` per recovery token. Successful policy persistence
and usage increments share one SQL transaction; failures, normal signing,
unlock, and phrase rotation do not count. Usage survives full saves/rotation.
All 70 tests still pass after these changes.

The first NixOS VM run (task 1) passed real TPM registration, assertions, PCR
recovery, and phrase rotation, then failed because a new test searched for a
literal backslash-t rather than tab/whitespace in CLI output. The assertion was
corrected. The expanded VM test checks token usage, old-phrase rejection despite
an unlocked enrollment cache, and locked/unlocked registration after restart.
The updated NixOS VM check passed (Pueue task 2): real software-TPM registration,
assertions, PCR recovery, phrase rotation, token usage tracking, reboot
persistence, locked/unlocked enrollment, credential management, and reset.
Command: `nix build --no-link -L .#checks.x86_64-linux.nixos-polkit`.
