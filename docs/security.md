# Security Model

`tpm-passkey` is experimental and makes no FIDO certification or production
security claim. This document describes the implemented model and explicit
limitations, not guarantees against a privileged live system adversary.

## Components and trust boundaries

- **Daemon:** privileged CTAP/HID, TPM, SQLite, and system-bus service. GTK is
  not linked into it.
- **Management CLI:** unprivileged program that collects migration passphrases
  and sends bounded system-bus requests.
- **Approval agent:** separate unprivileged GTK process for transaction-specific
  user presence (UP). It is not secure attention and same-user malware may
  impersonate or compromise it.
- **TPM:** generates and uses non-exportable P-256 credential keys on the
  original TPM.
- **Store:** one SQLite namespace, local integrity-key file, TPM blobs, PIN
  state, PCR policies, and migration-key envelopes.

One daemon/store serves one user. The daemon cannot identify the sender of UHID
requests, and does not isolate credentials by user or login session. Do not use
this design as a multi-user authenticator. Device permissions, system-bus policy,
polkit, and a graphical approval agent restrict ordinary access but do not
replace isolation.

## Migration authorization and PCR policies

Mandatory `tpm-passkey setup` creates a passphrase-protected P-256 migration key
pair and initial PCR default. Setup is one-time. The private scalar is encrypted
under a passphrase-derived key; the config, including the public key, has a
same-host integrity MAC. The MAC detects config-only edits while the integrity
key remains trusted; it does not protect against root or simultaneous database
and key replacement.

For every new credential, enrollment uses the public migration key to encrypt
its random TPM authority authorization secret. The envelope uses ephemeral
P-256 ECDH, HKDF-SHA256, and AES-256-GCM. Associated data binds it to the
canonical credential ID, authority public blob, and policyRef. Authorization
plaintext is exactly 32 bytes (48 bytes including the GCM tag); encoded public
keys are length-bounded before hex decoding/allocation. Enrollment does not unlock or prompt for the migration passphrase.
Credentials remain migration-authorized even with PCR binding disabled; the
TPM uses an authorized baseline rather than an auth-value bypass.

PCR-bound keys use `PolicyAuthorize` with a credential-specific policy
reference. Migration can approve another PCR state on the original TPM while
keeping the registered passkey key/blob unchanged. It cannot recover from TPM
loss, replacement, clearing, or lost/corrupt TPM blobs. A PCR selection is a
measurement, not a trust verdict; firmware, Secure Boot keys, kernel, or
bootloader updates may require an informed migration. PCR-disabled credentials
trade measured-boot restriction for convenience while remaining TPM-bound and
migration-authorized.

`migrate --yes` snapshots current credentials inside one serialized daemon
request, updates PCR-bound credentials, and skips PCR-disabled credentials.
`config policy` updates every credential including PCR-disabled keys and changes
the default only if all selected updates succeed. Per-credential successes are
not rolled back when another target fails. Passphrase rotation re-encrypts the
same private key under a new KDF salt/nonce and preserves its public key and
credential envelopes. Setup and config/default writes are transactional; policy
and token-use state are committed atomically per successful credential. PIN
state is separate and survives the destructive schema migration.

Database disclosure permits offline passphrase guessing. Use a strong phrase.
Old database snapshots may retain usable migration envelopes. SQLite deletion is
not secure erasure of free pages, WAL files, backups, or SSD blocks.

## TPM keys and client PIN

Credential private keys are TPM-generated and their private blobs are bound to
the original TPM hierarchy. Non-extractability does not mean a privileged
attacker cannot cause the TPM to use a key. The client PIN is distinct from the
migration passphrase and is managed with `fido2-manage`. PIN verifier and retry
state currently live in SQLite with a local MAC and PBKDF2; this is weaker than
TPM-backed PIN storage, permits rollback/offline guessing, and remains a
conformance/security limitation. Invalid PIN state fails closed rather than
silently disabling PIN enforcement.

## Management and secrets

System-bus management authorizes the actual unique sender with operation-specific
polkit actions before decoding requests. The CLI sends secret-bearing operations
in bounded sealed memfds, not D-Bus string bodies. Serialization of registration,
configuration changes, and bulk migration uses one mutation guard; registration
fails closed instead of blocking the TPM worker while management is waiting on
it. Management lock acquisition and worker reply waits share the original request
deadline; expired queued work cannot begin a later mutation. A timeout after TPM
work has begun can have an unknown per-credential outcome: inspect current state
before retrying. The default is not changed on partial failure or timeout.
Management errors use fixed nonsecret diagnostics for setup, authentication,
integrity, invalid selection, service availability and deadline failures rather
than forwarding database/TPM/crypto reports. TPM work runs on its sole owner
thread. This avoids stale client-side bulk snapshots and conflicting writes,
but does not eliminate kernel/library copies,
swap, crash dumps, or observation by root, the bus broker, or a compromised
same-user process.

Host approval is UP, not built-in CTAP UV. The approval agent displays untrusted
RP/account values and does not independently verify browser origin. Desktop
locking does not guarantee cancellation of a pending approval. Missing agent,
Deny, timeout, cancellation, malformed response, or disconnection fail closed.
The GTK agent is not a polkit/PAM re-authentication ceremony.

## Destructive schema migration and rollback

Migration `20261029090000` deletes credentials and old policy/config state that
cannot be safely converted, while preserving client PIN state. Website
registrations are not revoked; affected passkeys must be registered again. The
change is intentionally lossy and old backups must not be mixed with the new
store format.

Full-store rollback resistance is not implemented. Restoring an older valid
snapshot may restore deleted records, prior counters, or prior configuration.
The local integrity key is stored beside the database, and metadata MACs do not
cover every store property or prevent whole-store replacement.

## Out of scope and remaining limitations

Physical TPM attacks, TPM firmware compromise, kernel compromise, hardware/firmware
supply-chain compromise, CPU/TPM side channels, and denial of service by root
are out of scope. The daemon does not monitor desktop lock/session state or
secure browser origin. State deletion is not secure erasure. The project remains
experimental and requires independent security review before production use.
