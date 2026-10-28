# Linux TPM Fido2

Linux TPM Fido2 is an experimental Linux TPM-backed FIDO2/WebAuthn authenticator.

It exposes a browser-usable virtual HID authenticator, which uses the TPM for signing.
Its goal is convenient, TPM-bound passkey storage on a single-user machine,
not multi-user credential isolation.

## What It Does

- Presents a virtual FIDO2 HID authenticator to browsers.
- Creates TPM-backed P-256 credentials for registration and assertion.
- Keeps credentials TPM-bound, with optional, explicit PCR boot-state binding.
- Supports recovery material unlocked by a passphrase and kept TPM-bound.
- Checks user acknowledgement through polkit.

## System assumptions

- A single-user machine: one daemon instance and credential store serve one user.
  All stored credentials share one namespace. The daemon does not identify HID
  request senders, check their UID, or bind operations to a login session.
  Multiple users, fast user switching, and multi-seat isolation are unsupported.
- Linux
- Systemd enabled
- TPM2 on system
- Secureboot Enabled (Recommended)

Keep device and store access restricted. Single-user operation does not make
requests from other processes trustworthy: transaction approval and CTAP PIN/UV
checks still apply. Logind is used only to route polkit prompts to the desktop,
not to identify the caller or select credentials.

## Usage

Daemon:

```sh
linux-tpm-fido2 daemon --store-dir .linux-tpm-fido2-store --tpm-path /dev/tpmrm0 --uhid-path /dev/uhid
```

Management examples:

```sh
linux-tpm-fido2 list-credentials
linux-tpm-fido2 config show
```

`list-credentials` prints the base64 credential ID accepted by
`fido2-manage -credential`, followed by tab-separated RP ID, user name,
registration time, last-use time, and bound PCR indices (`none` when unbound).
`config show` prints `default_pcr_policy\tnone` when no selection is configured,
or the explicit indices, such as `1,7`.

### Optional PCR binding

**New credentials have no PCR binding by default.** They remain non-exportable
TPM keys, but can sign on the original TPM after boot measurements change.
This trades boot-state restrictions for convenience; someone with sufficient
access to the original TPM can use an unbound key regardless of boot state.

Opt in before registering credentials that should be PCR-bound:

```sh
linux-tpm-fido2 config set recovery-passphrase
linux-tpm-fido2 config set default-pcr-policy 1 7
# After a daemon restart, unlock before registering new PCR-bound credentials:
linux-tpm-fido2 config unlock-recovery
```

A passphrase alone does **not** enable PCR binding. Enabling requires configured
recovery, and new PCR-bound enrollment also requires it to be unlocked. Every
new PCR-bound credential gets its own recovery authority. Unbound enrollment
never requires a recovery unlock, even when a phrase is configured.

Disable binding for future registrations explicitly:

```sh
linux-tpm-fido2 config set default-pcr-policy --disable
```

These settings affect **future registrations only**. Existing credentials are
not retrofitted or relaxed. Existing explicitly saved PCR selections are
preserved across upgrades/restarts; only an absent default configuration means
no binding. Previously created PCR-bound keys without recovery are not upgraded
by setting a phrase. Existing PCR-policy updates still require the phrase.

Recovery approves new PCR states on the **same TPM**. It cannot recover from
TPM loss, replacement, clearing, or loss of the necessary credential blobs.

Each PCR-bound credential has its own TPM recovery authority with a random authorization
secret. Argon2id (64 MiB, three passes) and AES-256-GCM encrypt that secret; the
database stores neither plaintext authorization values nor derived encryption
keys. Policy updates require the supplied passphrase, even when registration is
unlocked. Passphrase rotation atomically re-encrypts all recovery slots without
changing the passkeys. `update-passphrase` remains an alias for setting/rotating
the phrase. Recovery tokens track `last_used` and `used_count` for successful
PCR-policy updates; ordinary assertions and phrase rotation do not count.
See [`docs/credentials.md`](docs/credentials.md).

Useful flags:

- `--dry-run` on the daemon prints the resolved configuration without opening devices.
- `--store-dir` selects the SQLite store and UI settings directory.

## Features

- TPM-backed signing keys and PCR policy bindings.
- Recovery slots stored separately from the primary credential metadata.
- Sign counter persistence.

## Protocol Compliance

The maintained CTAP 2.2 wire-format checklist and audit status are in
[`docs/ctap2-compliance.md`](docs/ctap2-compliance.md).

## Future Work

- Expand CTAP2 compatibility for additional browser request shapes.
- Harden transaction approval through polkit.
- Further security review

## Current Limits

- Experimental only. Every commit/release may break credential compatibility.
  Schema changes use new SQL migrations and may delete keys. In particular,
  migration `20261028060000` deletes old credentials and insecure recovery
  configuration, and `20261028070000` deletes records using the legacy owner
  format while removing the owner field. Websites will need new credentials
  registered.
- Deleted database records are not a secure erase of old files or backups, nor
  do they revoke old registrations at websites. Remove old website credentials
  if their insecure recovery material may have been exposed. Passphrase rotation
  does not provide protection against database rollback.
- No FIDO certification claims.
- No production security claims for the development store.
