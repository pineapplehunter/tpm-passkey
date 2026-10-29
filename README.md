# tpm-passkey

`tpm-passkey` is an experimental Linux TPM-backed FIDO2/WebAuthn authenticator.

It exposes a browser-usable virtual HID authenticator, which uses the TPM for signing.
Its goal is convenient, TPM-bound passkey storage on a single-user machine,
not multi-user credential isolation.

## What It Does

- Presents a virtual FIDO2 HID authenticator to browsers.
- Creates TPM-backed P-256 credentials for registration and assertion.
- Keeps credentials TPM-bound, with optional, explicit PCR boot-state binding.
- Authorizes migration of PCR policies through a passphrase-protected, TPM-bound migration key.
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
`tpm-passkey.service`; state remains `/var/lib/tpm-passkey`. The migration-key redesign is a breaking database migration: it deletes stored credentials and prior migration/default-policy configuration, while preserving client PIN state.

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
Existing state uses the migration-redesign schema; older credentials are intentionally removed by the breaking migration.

Management commands (run as the ordinary user):

```sh
tpm-passkey setup
tpm-passkey list                 # use --json for machine-readable output
tpm-passkey info 17               # local numeric ID; use --json for JSON
tpm-passkey migrate              # asks for confirmation; --yes skips it
tpm-passkey config show
tpm-passkey config policy         # show the default policy without scanning credentials
tpm-passkey config policy 1 7     # asks for confirmation
tpm-passkey config policy --disable --yes
tpm-passkey config passphrase
```

Setup interactively selects the PCR binding default (empty selection disables
binding) and creates a confirmed migration passphrase. Every new credential is
authorized by the migration key regardless of whether PCR binding is enabled;
enrollment does not require unlocking it. `list` and `info` use sharp tables by
default, and emit JSON with `--json`. The list has ID, site, account and creation
date columns; JSON retains the full creation timestamp. IDs are local integer IDs. Use
`fido2-manage` for PIN management; this CLI has no PIN API.

`migrate` confirms the current affected count and trusted boot state, then sends
one daemon-side bulk request (`--yes` skips confirmation). With no PCR-bound
credentials it exits without asking for a passphrase. It migrates all PCR-bound
credentials, skips PCR-disabled credentials, reports per-credential results,
and permits partial success. `config policy` updates every existing credential
(including PCR-disabled ones) and the future-enrollment default in one serialized
request; the default changes only if every credential update succeeds. `--disable`
clears PCR binding for existing credentials and the default. With zero credentials,
the default change is still applied and reported explicitly.

Migration policy authorizes a new PCR state on the same TPM; it cannot recover
from TPM loss, replacement, clearing, or loss of necessary credential blobs.
The migration private key is passphrase-protected; config integrity is MACed.
Passphrase changes preserve credentials and are committed atomically. See
[`docs/credentials.md`](docs/credentials.md).

Useful flags:

- `--dry-run` on the daemon prints the resolved configuration without opening devices.
- `--store-dir` selects the SQLite store and UI settings directory.

## Features

- TPM-backed signing keys and PCR policy bindings.
- Per-credential TPM migration authorities stored separately from primary key material.
- Sign counter persistence.

## Protocol Compliance

The maintained CTAP 2.2 wire-format checklist and audit status are in
[`docs/ctap2-compliance.md`](docs/ctap2-compliance.md).

Host approval supplies user presence, not built-in user verification. FIDO
client PINs (Protocols 2 and 1) provide PIN verification and are separate from
the migration passphrase. Without a PIN, discoverable enrollment can use presence
alone; after PIN setup, it requires a valid PIN token. PIN-state storage still
needs TPM-equivalent protection before a full conformance claim is possible.

## Future Work

- Expand CTAP2 compatibility for additional browser request shapes.
- Manually validate Firefox and approval UX on target Wayland desktops.
- Further security review

## Current Limits

- Experimental only. Every commit/release may break credential compatibility.
  Schema changes use new SQL migrations and may delete keys. In particular,
  migration `20261029090000` deletes old credentials and old migration/default-policy
  configuration that cannot safely be converted, while preserving client PIN
  state. Websites will need replacement credentials registered.
- Deleted database records are not a secure erase of old files or backups, nor
  do they revoke old registrations at websites. Remove old website credentials
  if old credential material may have been exposed. Passphrase rotation
  does not provide protection against database rollback.
- No FIDO certification claims.
- No production security claims for the development store.
