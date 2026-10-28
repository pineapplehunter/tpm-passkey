# Security Audit

Historical snapshot, not a current security guarantee. The encrypted recovery
refactor replaces the plaintext recovery auth/hash format described in findings
1 and 4, and adds a destructive migration. See `agents/encrypted-recovery.md`
and `docs/credentials.md` for the current design and validation. Other findings
remain relevant unless independently resolved.

## Scope

Static review of credential storage, TPM operations, CTAP2 handling, management transport, session/polkit integration, systemd configuration, and database migrations.

Validation performed:

- Inspected actual development-store permissions.
- `cargo check`: passed.
- `cargo test`: 70 tests passed.
- Dependency vulnerability scanning was not completed because `cargo-audit` is unavailable in the development shell.

## Conclusion

Raw WebAuthn private keys do not appear extractable from the credential store. They are generated inside the TPM with `fixedTPM`, `fixedParent`, and `sensitiveDataOrigin`; the database contains TPM-wrapped blobs rather than P-256 private scalars.

The store nevertheless exposes other sensitive material that weakens recovery and PIN protection. It should not be considered secure outside the systemd-managed deployment.

## Findings

### 1. High: recovery passphrase authorization secret is stored in the database

The Argon2id result is used as the TPM recovery key's authorization value:

- `src/tpm.rs:214`
- `src/tpm.rs:274`

That authorization value is serialized into `TpmKeyBlob` and persisted:

- `src/store.rs:117-132`
- `src/store.rs:830`
- `src/store.rs:853`

Anyone who obtains the store therefore gets the TPM authorization secret without knowing or cracking the passphrase. With access to the original TPM, an attacker can use the recovery authority directly to approve a new PCR state.

This does not reveal the registered WebAuthn private scalar, but it defeats the intended passphrase protection and may make the credential operationally usable in an attacker-controlled boot state.

**Recommendation:** Never persist `auth_value`. Derive it transiently from the supplied passphrase and set it only on the loaded TPM object. If software passphrase validation is necessary, use a separate, domain-separated verifier or validate by attempting TPM authorization.

### 2. High in development/custom deployments: credential files are world-readable

Store creation relies on the ambient umask:

- `src/store.rs:969`
- `src/store.rs:1011-1013`

The development store inspected during this audit had these permissions:

```text
755 .linux-tpm-fido2-store
644 credentials.sqlite
644 integrity.hmac-key
```

These files disclose:

- RP IDs and usernames
- User handles and credential IDs
- TPM object blobs
- Recovery and daemon passphrase verifiers
- Recovery TPM authorization values
- Client PIN verifier
- Integrity HMAC key

The NixOS service mitigates this through `StateDirectoryMode=0700`, but direct daemon use and arbitrary `--store-dir` paths remain unsafe.

**Recommendation:** Explicitly create the directory as `0700` and database/key files as `0600`. Reject unexpected owners, symlinks, and permissive existing files. Use atomic exclusive creation for the HMAC key.

### 3. Medium: integrity protection is incomplete and effectively forgeable

The credential MAC covers only selected metadata:

- `src/store.rs:1019-1040`

It omits important fields including:

- TPM public/private blobs
- Authorization values
- PCR and recovery policies
- Recovery KDF data
- Public key
- Signature counter

Additionally:

- The HMAC key is stored beside the database.
- Credentials without a MAC are accepted.
- Failure to read the HMAC key causes credential verification to fail open (`src/store.rs:588-593`).
- Save-time HMAC-key failures can produce records without a MAC (`src/store.rs:637-645`).

Anyone able to modify the store can generally also read the HMAC key and forge protected metadata.

**Recommendation:** MAC a canonical encoding of the complete security-sensitive record, fail closed on missing or invalid MACs, and protect the MAC key with the TPM or another boundary separate from the database. Add rollback protection separately.

### 4. Medium: offline PIN and passphrase guessing

The database contains offline-verifiable values:

- Client PIN verifier: `src/ctap2.rs:1897`
- Recovery passphrase PHC value: `src/store.rs:148-171`
- Daemon passphrase verifier: `src/store.rs:376-431`

Recovery passphrases use reasonable Argon2id defaults. The Client PIN accepts four-character PINs and uses PBKDF2-100,000, so weak PINs can be tested offline after store disclosure, bypassing TPM/CTAP retry counters.

Because of finding 1, the recovery passphrase does not need to be guessed to recover its TPM authorization value.

**Recommendation:** First remove the persisted recovery authorization value. Protect PIN state with a TPM-backed secret or equivalent mechanism so database disclosure does not permit offline verification. Consider a stronger minimum PIN policy where compatible.

### 5. Low: credential metadata is written to logs

Info-level approval and credential logs include RP IDs and sometimes user-facing names:

- `src/approval.rs:23-31`
- `src/ctap2.rs:467`
- `src/ctap2.rs:586-590`
- `src/ctap2.rs:723-727`

Users with journal access may learn which services have credentials and when they are used. Raw CTAP payloads are not logged, which is good.

**Recommendation:** Put RP/user details behind debug logging or redact/hash them in normal logs.

### 6. Low: secrets are not consistently cleared from memory

Some derived values use `zeroize`, but passphrase request strings, decoded PINs, PIN hashes, tokens, and cloned TPM authorization values generally remain in ordinary heap allocations until overwritten.

A root-readable core dump or memory disclosure could expose them. The service does not explicitly disable core dumps.

**Recommendation:** Use `Zeroizing<String>` and `Zeroizing<Vec<u8>>` throughout secret-handling paths, clear serialized management-request buffers, and configure `LimitCORE=0` or appropriate systemd coredump restrictions.

## Positive Observations

- TPM credentials use non-exportable TPM object attributes.
- There is no software private-key fallback.
- CTAPHID debug logging records packet metadata rather than packet contents.
- The management socket is root-only (`0700`).
- The production NixOS state directory is `0700`.
- Recovery uses Argon2id with 64 MiB memory and three iterations.
- PIN and credential state have some integrity checking and constant-time comparisons.

## Remediation Priority

1. Stop persisting the recovery TPM `auth_value`.
2. Enforce secure store-directory and file permissions in application code.
3. Authenticate the complete credential record with a separately protected key and fail closed.
4. Prevent offline PIN verification after store disclosure.
5. Reduce metadata logging and improve in-memory secret handling.
