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
```

`list-credentials` prints the base64 credential ID accepted by
`fido2-manage -credential`, followed by tab-separated RP ID, user name,
registration time, last-use time, and bound PCR indices. `config show` reports
the effective default PCR policy and whether recovery passphrase material is
configured. Setting the recovery passphrase also updates each credential's
recovery slot; the existing `update-passphrase` command remains as a compatible
alias.

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

- Experimental only.
- No FIDO certification claims.
- No production security claims for the development store.
