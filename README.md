# Linux TPM Fido2

Linux TPM Fido2 is an experimental Linux TPM-backed FIDO2/WebAuthn authenticator.

It exposes a browser-usable virtual HID authenticator, which uses the TPM for signing.
Its goal is convenient, TPM-bound passkey storage on a single-user machine,
not multi-user credential isolation.

## What It Does

- Presents a virtual FIDO2 HID authenticator to browsers.
- Creates TPM-backed P-256 credentials for registration and assertion.
- Supports secure-boot PCR-bound credentials.
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
linux-tpm-fido2 config set default-pcr-policy 1 7
linux-tpm-fido2 config set recovery-passphrase
# After restarting the daemon, before registering recovery-enabled credentials:
linux-tpm-fido2 config unlock-recovery
```

`list-credentials` prints the base64 credential ID accepted by
`fido2-manage -credential`, followed by tab-separated RP ID, user name,
registration time, last-use time, and bound PCR indices. `config show` reports
the effective default PCR policy and whether recovery passphrase material is
configured. Configure recovery before creating credentials that need it.
Setting the recovery passphrase unlocks recovery-enabled registration for the
current daemon process; after a restart, run `config unlock-recovery` to unlock
registration again. Existing credentials can still authenticate while enrollment
is locked. Credentials created before recovery is configured have no recovery
slot and cannot gain one just by setting a passphrase.

Each credential has its own TPM recovery authority with a random authorization
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
