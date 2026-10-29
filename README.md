# tpm-passkey

`tpm-passkey` is an experimental Linux TPM-backed FIDO2/WebAuthn authenticator.

It exposes a browser-usable virtual HID authenticator, which uses the TPM for signing.
Its goal is convenient, TPM-bound passkey storage on a single-user machine,
not multi-user credential isolation.

## What It Does

- Presents a virtual FIDO2 HID authenticator to browsers.
- Creates TPM-backed P-256 credentials for registration and assertion.
- Keeps credentials TPM-bound, with optional, explicit PCR boot-state binding.
- Supports recovery material unlocked by a passphrase and kept TPM-bound.
- Collects transaction-specific user presence through an unprivileged GTK Allow/Deny agent.
- Runs management commands as the user, with daemon-side polkit authorization.

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
checks still apply. The daemon does not monitor desktop lock or login sessions;
the desktop is responsible for preventing interaction while locked.

## Usage

Daemon (as root; prefer the NixOS service setup below):

```sh
sudo tpm-passkey-daemon --store-dir .tpm-passkey-store --tpm-path /dev/tpmrm0 --uhid-path /dev/uhid
```

There are three separate Cargo packages/binaries:

- `tpm-passkey-daemon`: privileged CTAP/TPM/store service, without GTK.
- `tpm-passkey`: unprivileged management CLI, without GTK or TPM implementation.
- `tpm-passkey-approval-gtk`: unprivileged GTK4/libadwaita confirmation agent.

Direct daemon deployment also requires the supplied system-bus/polkit assets and
an administrator-selected authorization policy. Management CLI commands below run
as the ordinary user, without `sudo`.

Both public interfaces use the system bus, at
`io.github.pineapplehunter.TpmPasskey1`. The former management Unix socket and
`tpm-passkey daemon` command are retired. The systemd unit remains
`tpm-passkey.service`; state remains `/var/lib/tpm-passkey`. No migration changes
credentials, recovery formats or PIN requirements for this binary/API split.

### Desktop setup (NixOS)

The overlay supplies all three packages. For example, replacing `alice` with your
desktop account:

```nix
services.tpm-passkey = {
  enable = true;
  # Approval is enabled automatically with the daemon.
  # Default: "systemd". Alternatives: "xdg-autostart" or "manual".
  approval.startup = "systemd";
};
users.users.alice.extraGroups = [ "tpm-passkey" ];
```

Log out/in after changing group membership. No user lingering is enabled.
The default `approval.startup = "systemd"` requires correctly integrated
`graphical-session.target` and display environment. Choose `"xdg-autostart"` for
desktops using XDG autostart, or `"manual"` and launch `tpm-passkey-approval-gtk`
from the compositor's session configuration. `approval.enable = false` disables
agent installation/startup for an independently managed frontend. The root daemon
never starts GTK, scrapes display environment variables, or connects to a user's
session bus.

The option group is toolkit-independent: `approval.package` defaults to the GTK
agent but can select another compatible frontend. Configurations using the old
`approvalGtk` option group must rename it to `approval`.

The configurable `accessGroup` (default `tpm-passkey`) gates ordinary callers.
Members may read metadata and register an agent without a password prompt.
Management mutations require administrator authentication by default;
`managementAuthentication = "self"` instead delegates them to members after
own-password authentication. Authorization is not retained. Root remains trusted.
Group access is to one shared store, not separate per-user stores.

GTK approval is user presence, not a polkit/PAM re-authentication ceremony or
built-in UV. Missing GUI/agent, close, Deny, cancellation or expiry fail closed
without a fallback prompt. Same-user malware can impersonate the helper; this is
not secure attention. Wayland does not guarantee automatic foreground focus.

Flake packages are `daemon`, `cli` (also `default`), `approval-gtk`, and an optional
`bundle`. Install the components separately to keep GTK outside the daemon's
runtime closure. `cargo run -p tpm-passkey-daemon -- --dry-run` checks daemon
configuration without opening devices.

Existing state directories are **not moved automatically**. Stop the previously
installed daemon before moving its complete state directory (database and
supporting key files) to the new service path, preserving restrictive permissions.
For development, `--store-dir` can point directly to an existing directory.
The rename does not change existing keys, policies, or encrypted recovery formats.

Management examples:

```sh
tpm-passkey list-credentials
tpm-passkey config show
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
tpm-passkey config set recovery-passphrase
tpm-passkey config set default-pcr-policy 1 7
# After a daemon restart, unlock before registering new PCR-bound credentials:
tpm-passkey config unlock-recovery
```

A passphrase alone does **not** enable PCR binding. Enabling requires configured
recovery, and new PCR-bound enrollment also requires it to be unlocked. Every
new PCR-bound credential gets its own recovery authority. Unbound enrollment
never requires a recovery unlock, even when a phrase is configured.

Disable binding for future registrations explicitly:

```sh
tpm-passkey config set default-pcr-policy --disable
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

Host approval supplies user presence, not built-in user verification. FIDO
client PINs (Protocols 2 and 1) provide PIN verification and are separate from
the PCR recovery phrase. Without a PIN, discoverable enrollment can use presence
alone; after PIN setup, it requires a valid PIN token. PIN-state storage still
needs TPM-equivalent protection before a full conformance claim is possible.

## Future Work

- Expand CTAP2 compatibility for additional browser request shapes.
- Manually validate Firefox and approval UX on target Wayland desktops.
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
