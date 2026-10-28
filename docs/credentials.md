# Credential Storage and Recovery

## Scope and compatibility

This experimental authenticator stores TPM-generated P-256 WebAuthn passkeys.
There is no U2F or software passkey-signing fallback. One daemon and SQLite
store serve a single-user machine, with no caller-UID filtering.

Every commit/release may invalidate existing credentials. All schema changes
are recorded in new `migrations/` files; existing migrations must not be edited.
A migration may deliberately discard credentials. Migration `20261028060000`
deletes the old credentials and plaintext-equivalent recovery configuration.
Migration `20261028070000` removes the legacy owner column/indexes and discards
records using the old owner-dependent metadata MAC. The user must register
replacement passkeys with their relying parties.
Deleting local records does not revoke old website registrations; remove those
registrations if old recovery material may have been exposed.

## Files and schema

The default store is `.linux-tpm-fido2-store/`, overridden by `daemon --store-dir`.
The NixOS service uses `/var/lib/linux-tpm-fido2`. The directory contains:

- `credentials.sqlite`: metadata, TPM object blobs, policies, encrypted recovery
  authorization values, Client PIN state, and daemon configuration.
- `integrity.hmac-key`: the current development metadata-MAC key. This is not
  the recovery encryption key and cannot decrypt recovery authorization values.

The schema is defined by the complete migration history. Current tables are:

- `credential_metadata`: credential/RP/user information and signature counters.
- `credential_keyslots`: primary and recovery TPM blobs, public keys, and primary
  PCR-policy authorization packages.
- `credential_tokens`: an `encrypted_auth` CBOR envelope for each recovery slot,
  plus nullable `last_used` and nonnegative `used_count` (default zero).
- `client_pin_state`: PIN verifier and retry state.
- `daemon_config`: default PCR selection and an encrypted recovery unlock check.

No local owner UID is stored in credential metadata. All credentials belong to
the single shared namespace. WebAuthn user handles are still required and are
not local user IDs.

Stored TPM key blobs contain only the TPM private/public representations. Their
Rust storage type has no authorization-value field. A TPM private blob is
protected under a storage parent on the original TPM, not a raw private scalar.
The daemon recreates a transient owner-hierarchy parent as needed and loads and
flushes credential objects for signing.

## Recovery policy

For each recovery-enabled credential:

1. The TPM creates a separate recovery authority with a random 32-byte auth value.
2. The authority approves a PCR policy using a credential-specific `policyRef`.
3. The primary key's fixed policy trusts that authority through `PolicyAuthorize`
   and restricts use to `TPM2_Sign`.
4. The daemon password-encrypts the authority's auth value before persistence.

Normal assertions verify the existing signed approval against the current PCR
state. They do not decrypt the auth value or require the recovery phrase.

After a boot-state change, the management command decrypts the auth value using
its supplied phrase. The original TPM uses the recovery authority to approve
its current measurements. The passkey and its public key do not change. This
recovers from PCR changes, not a lost/replaced/cleared TPM or lost object blobs.
The user is responsible for deciding whether the new boot state is trustworthy.

## Password encryption

Format version 1 uses:

- Argon2id v1.3, 64 MiB memory, three passes, one lane, 32-byte output.
- A random 32-byte salt per encryption configuration.
- AES-256-GCM with a fresh random 12-byte nonce per encrypted value and its
  authentication tag appended to the ciphertext.
- Associated data binding each authorization value to its credential ID,
  recovery key's TPM public blob, and credential-specific `policyRef`.

The envelope records its version, KDF parameters, salt, nonce, and ciphertext.
Version 1 accepts only its defined KDF parameters, bounding work for untrusted
stored input. Swapping slots or changing authenticated data fails decryption.

The daemon configuration contains an encrypted known check value in a separate
AAD domain. It does not contain the phrase, Argon2 output, wrapping key, or an
unencrypted TPM authorization value. The configuration and slots share the
phrase-derived wrapping key, but each credential has an independent random TPM
authorization secret and each encryption has an independent nonce.

## Enrollment, unlock, and rotation

Configure recovery before creating credentials that need it:

```sh
linux-tpm-fido2 config set recovery-passphrase
```

This retains a zeroizing wrapping key only in the authenticator worker's memory
for creating recovery-enabled credentials. After a daemon restart, enrollment
is locked. Unlock it explicitly with:

```sh
linux-tpm-fido2 config unlock-recovery
```

While configured but locked, registration fails rather than silently creating a
credential without recovery. Existing credentials can still authenticate. If no
recovery configuration exists, registration creates PCR-bound credentials
without recovery; setting a phrase later does not retrofit their fixed policy.

Policy-update requests always require their supplied phrase and do not use the
enrollment unlock cache. Failed decryption happens before any TPM policy update.
Each successful policy update atomically records `last_used = CURRENT_TIMESTAMP`
and increments the recovery token's `used_count` with the new policy. Before its
first use, `last_used` is NULL and `used_count` is zero. Normal passkey assertions,
enrollment unlock, and passphrase rotation do not count as token uses. Full
credential saves and rotation preserve the usage history. Failed updates do not
change it.

Setting a new phrase requires the old phrase when configured. The worker first
authenticates and decrypts all slots, re-encrypts them under a new salt/key with
fresh nonces, and atomically commits all ciphertexts and the configuration in
one SQLite transaction. TPM auth values and keys do not change. Wrong phrases,
corrupt slots, or failed writes leave the old configuration intact.

## Remaining security limits

- Database disclosure permits offline phrase guessing; use a strong phrase.
- A live privileged attacker can capture a phrase or the in-memory unlock key.
- Rotation does not revoke recovery material in old snapshots. Database rollback
  protection is not implemented.
- Deleting records is not secure erasure of SQLite free pages, WAL files, SSD
  storage, or backups. Old insecure stores/backups must not be reused.
- The current metadata MAC does not authenticate the complete credential record
  and its key is stored beside the database. Recovery AEAD protects its own
  authorization value and bindings, not all database metadata.
- Direct development deployment still depends on file/device permissions; the
  NixOS service restricts its state directory to `0700`.
