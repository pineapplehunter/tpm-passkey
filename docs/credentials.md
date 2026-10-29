# Credential Storage and Migration

## Compatibility and persistent state

This experimental authenticator stores TPM-generated P-256 WebAuthn passkeys. All
schema changes are new migrations. Migration `20261029090000` is deliberately
breaking: it deletes credentials and old migration/default-policy configuration
that cannot be safely transformed to the migration-key format. It preserves
`client_pin_state`. Users must register replacement passkeys with relying parties;
deleting local rows does not revoke website registrations. Old backups must not
be reused.

The store contains `credentials.sqlite` and `integrity.hmac-key`. SQLite stores
credential metadata, TPM object blobs, PCR-policy packages, migration-key config,
encrypted migration-authority values, and client PIN state. The integrity key
MACs the migration configuration and credential metadata. Credential loading
fails closed on missing or invalid integrity state. A client PIN is separate from
the migration passphrase; use `fido2-manage` to manage PINs.

`credential_metadata` stores RP/user fields and counters; `credential_keyslots`
stores the primary and migration authority TPM objects and policy packages;
`credential_tokens` stores encrypted authority values and use counters;
`daemon_config` stores the migration-key configuration and default PCR selection.
TPM private blobs are bound to the original TPM and are not raw private scalars.

## Migration key and enrollment

`tpm-passkey setup` is mandatory before registration.
Setup interactively selects the PCR default and creates a confirmed migration
passphrase. The private migration key is passphrase-protected. Its public-key
integrity is protected by the local config MAC. Per-credential authority secrets
are encrypted to the configured public key using P-256 ECDH, HKDF, and AES-GCM;
credential identity and authority data are authenticated as associated data.
Fresh ephemeral keys, salts, and nonces prevent deterministic envelopes.

Every new credential, including one with PCR binding disabled, is authorized by
the migration key. Enrollment uses the public key and does not unlock or prompt
for the migration passphrase. The PCR default only determines whether the
credential's authorized policy also binds use to selected PCRs. An unbound
credential therefore remains TPM-bound and migration-authorized; it is not an
ordinary TPM auth-value-only key.

## PCR policy operations

`config policy PCR... --yes` updates all existing credentials, including those
whose PCR binding was disabled, and then changes the default for future
registrations. `config policy --disable --yes` updates every existing credential
to the authorized PCR-disabled baseline and clears the default. Both are one
serialized daemon bulk request. Each credential can succeed or fail
independently; results report partial success, and the default changes only if
every selected update succeeds. A zero-credential operation is explicitly
reported and can still change the default after migration-passphrase
verification.

`migrate --yes` targets the daemon's current credential set in one bulk request.
It updates PCR-bound credentials and skips PCR-disabled credentials. It reports
per-credential outcomes; successful updates are not rolled back if another
credential fails. Passphrase rotation authenticates and re-encrypts migration
material atomically without changing passkeys. Registration, configuration
mutation, and migration serialize against one another; the TPM worker remains
the sole TPM command channel.

Policy changes require the supplied migration passphrase. Credential state and
policy/token-use metadata are committed atomically per successful update; a
failed update does not update its token-use history. The global default is stored
only after full bulk success. Setup writes the authenticated config and initial
default policy transactionally. PIN state survives the destructive schema
migration and is unaffected by migration operations.

## PCR security and limits

A PCR-bound credential's fixed TPM policy trusts its signed policy authority via
`PolicyAuthorize`, restricting use to `TPM2_Sign`. Migration approves a new PCR
state on the original TPM while keeping the registered passkey key/blob intact.
It cannot recover from TPM loss, replacement, clearing, or loss of credential
blobs. Users must decide whether a newly measured boot state is trustworthy.

Database disclosure permits offline passphrase guessing; use a strong phrase.
The metadata/config MAC key is stored beside the database and does not protect
against root or full-store rollback. Old snapshots may retain migration
material. Deleting rows is not secure erasure of SQLite free pages, WAL files,
SSDs, or backups. The NixOS service restricts its state directory; direct
development deployments must secure files and devices themselves.
