# Linux TPM Fido2

Linux TPM Fido2 is an experimental Linux TPM-backed FIDO2/WebAuthn authenticator.

It exposes a browser-usable virtual HID authenticator, which uses the TPM for signing.

## What It Does

- Presents a virtual FIDO2 HID authenticator to browsers.
- Creates TPM-backed P-256 credentials for registration and assertion.
- Supports secure-boot PCR-bound credentials.
- Supports recovery material unlocked by a passphrase and kept TPM-bound.
- Checks user acknowledgement through polkit.

## System assumptions

- Linux
- Systemd enabled
- TPM2 on system
- Secureboot Enabled (Recommended)

## Usage

Daemon:

```sh
linux-tpm-fido2 daemon --store-dir .linux-tpm-fido2-store --tpm-path /dev/tpmrm0 --uhid-path /dev/uhid
```

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
- Harden polkit and session-switch handling.
- Further security review

## Current Limits

- Experimental only.
- No FIDO certification claims.
- No production security claims for the development store.
