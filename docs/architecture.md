# Architecture

`tpm-passkey-daemon` owns the TPM, virtual HID authenticator, SQLite store, and
system-bus service. `tpm-passkey` is an unprivileged management CLI and the GTK
approval agent is a separate, unprivileged process. The shared protocol crate
contains wire types and transport only; it does not depend on TPM, SQLite, or
GTK.

## Runtime and serialization

The daemon's authenticator worker owns the sole TPM context and TPM command
channel. CTAPHID requests are bounded, parsed into CTAP operations, and submitted
to the worker. TPM private objects are generated and used on the original TPM;
the store holds blobs, public keys, metadata, PCR policy packages, and per-key
migration-authority envelopes.

A process-wide credential mutation guard serializes registration against
management configuration changes and bulk migration. Registration uses a
nonblocking acquisition and fails closed if management already owns the guard;
management owns the guard while it snapshots the current credential set and
updates selected credentials. No client-side list is used as a bulk-operation
snapshot. Each credential update can succeed or fail independently. The global
PCR default commits only after every selected update succeeds; successful
per-credential changes remain committed on partial failure.

System-bus management requests are authorized against the actual caller before
deserializing the sealed bounded memfd. Migration, migration-passphrase, and
settings actions have distinct polkit treatment. Secret-bearing request types
use zeroizing values and the protocol transport uses guarded buffers. The
unprivileged CLI invokes one daemon bulk request for `migrate` and one for
`config policy`; it does not issue a list request followed by racing mutation
requests.

## Migration key and credentials

Mandatory `setup` creates the passphrase-protected P-256 migration key pair and
sets the initial PCR policy. The SQLite daemon-config entry stores the encrypted
private scalar and public key under an integrity MAC keyed by the local
integrity key. Setup writes the config and default policy in one database
transaction. It is one-time and rejects setup if credentials already exist.

Registration needs only the migration public key. It creates a TPM migration
authority and encrypts the authority authorization secret independently for
that credential using ephemeral P-256 ECDH, HKDF, and AES-256-GCM. Authenticated
data binds the envelope to the credential and authority. The migration private
key is not unlocked during enrollment. Every new credential is migration-
authorized even when its PCR selection is disabled; disabled policies use an
authorized baseline rather than bypassing authorization.

PCR-policy migration decrypts the per-credential authority secret with the
supplied phrase, then asks the same TPM authority to sign a new `PolicyAuthorize`
state. The registered passkey key/blob is unchanged. `migrate --yes` selects all
credentials on the daemon and skips PCR-disabled keys. `config policy` visits
all credentials, including PCR-disabled keys, and applies its default-policy
change only on full success. Passphrase rotation rewraps the same private key
and preserves the public key and authorization envelopes.

## Persistent state and destructive upgrade

SQLite migrations are append-only. The redesign migration is deliberately
lossy: it removes old credentials and previous migration/default-policy config
that cannot be transformed safely, while preserving the separate client PIN
state. The credential metadata and migration config are MACed; ciphertext
envelopes authenticate their own context. These controls do not provide
full-store rollback protection, secure erasure, or protection against root or
simultaneous replacement of database and integrity key.

The `store` layer owns SQLx persistence and integrity validation. PIN verifier
and retry state are separate from migration-key state. Use `fido2-manage` for
PIN management; the management CLI exposes no PIN API. CTAP reset atomically
clears credentials and PIN state, but is separate from schema-upgrade behavior.

## Source map

- `src/ctap2.rs`, `src/ctaphid.rs`, `src/hid.rs`: CTAP and virtual HID.
- `src/tpm.rs`: TPM policy/key commands and sole TPM implementation.
- `src/migration_crypto.rs`: migration key encryption and per-credential envelopes.
- `src/store.rs`, `migrations/`: database schema, persistence, MACs, and PIN state.
- `src/management/`: serialized management dispatch and bulk results.
- `src/bus.rs`, `src/polkit.rs`: system-bus authorization and approval-agent lifecycle.
- `crates/protocol/`: shared bus protocol and sealed-FD transport.
- `crates/cli/`: unprivileged table/JSON management interface.
- `crates/approval-gtk/`: separate user-presence frontend.
- `nix/`, `nix/tests/`: NixOS packaging and software-TPM integration tests.
