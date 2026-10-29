# Architecture

## Overview

`tpm-passkey` is a blocking system daemon that exposes a virtual FIDO2
authenticator through Linux UHID. The daemon owns the CTAPHID channels, CTAP2
state machines, TPM context, one single-user credential store, and transaction
approval coordination. Multi-user credential isolation is unsupported.

The separate `tpm-passkey` CLI and `tpm-passkey-approval-gtk` GUI depend only on a
small shared protocol crate, never the daemon library. GTK is not linked into
the daemon or CLI, and separate Nix packages keep it out of their runtime closures.

The daemon relies on the desktop lock and does not monitor login sessions. It does
not identify HID requester UIDs, scope credentials by UID, or bind PIN tokens to
login sessions. D-Bus management and registration authenticate their own senders.
File and device permissions remain in place. Credential compatibility across
commits is not guaranteed; new SQL migrations may deliberately discard keys.

## Runtime Request Flow

1. The browser writes 64-byte reports to the UHID device.
2. `ctaphid` validates global transaction arbitration, channels, packet
   sequence, and timeout, then assembles complete requests.
3. Complete CBOR requests are sent to a persistent authenticator worker. The
   UHID thread remains responsive for keepalives, cancellation, and competing
   channels while approval or TPM work blocks.
4. `ctap2::Authenticator` on the worker decodes the CTAP command and coordinates
   its state machine.
5. The command handler uses the shared credential namespace, obtains approval
   through `approval::UserApproval`, and asks `tpm` to create or use keys.
6. `store` persists credential, PIN, policy, and recovery state in SQLite.
7. The worker result is fragmented by `ctaphid` and sent to the browser through
   UHID.

Management requests use the root-owned system-bus API and daemon-side polkit
authorization of the actual sender. Request bodies travel through bounded sealed
memfds, not secret-bearing D-Bus arguments. Storage work runs outside the bus
handler's event loop; TPM operations are queued to the same authenticator worker.
This preserves one owner for the TPM context because the NixOS test TPM exposes
only one usable `/dev/tpm0` opener. Recovery setup, unlock, rotation, and policy
updates also run on this worker, so enrollment cannot race passphrase rotation.
Rotation re-encrypts all recovery authorization values and atomically stores them
with the new configuration. Normal signing uses existing policy signatures and
requires no phrase. Policy updates must decrypt authorization using their own
request's phrase, never the enrollment cache.

## Source Boundaries

```text
src/
├── main.rs                 standalone daemon lifecycle and UHID loop
├── hid.rs                  HID descriptor and virtual-device identity
├── ctaphid.rs              CTAPHID channels, framing, and transport errors
├── ctap2.rs                authenticator facade and command orchestration
├── ctap2/
│   ├── protocol.rs         CTAP commands, status values, and command names
│   ├── cbor_codec.rs       CBOR decoding, lookup, and canonical encoding
│   ├── authenticator_data.rs
│   │                       authenticatorData and COSE encoding
│   └── tests.rs            protocol-level unit tests
├── credential.rs           runtime credential model and store conversion
├── store.rs                SQLite schema access and integrity metadata
├── tpm.rs                  TPM object, PCR policy, and signing operations
├── recovery.rs             Argon2id/AES-GCM encryption of recovery authorization
├── approval.rs             injectable, controlled transaction-presence boundary
├── bus.rs                  persistent bus endpoint, agent registry and consent
├── management.rs           management dispatch boundary (no Unix listener)
├── management/
│   └── service.rs          management operations and TPM command dispatch
└── polkit.rs               management/registration authorization, not CTAP UP
```

## State Ownership

The persistent authenticator worker owns `ctap2::Authenticator` and its TPM
context. `ctap2::Authenticator` owns state that must survive across CTAP
commands:

- loaded credentials and signature counters;
- pending `getNextAssertion` enumeration;
- credential-management enumeration state;
- Client PIN verifier and retry state;
- ephemeral key agreement and PIN/UV token state;
- transaction UV state;
- a zeroizing recovery-enrollment wrapping key, only after setup or explicit
  unlock; it is never serialized and is forgotten at restart;
- the lazily opened TPM context.

`ctaphid::PacketHandler` remains on the UHID thread and owns transport state:

- allocated channel IDs;
- the one globally active incomplete or processing transaction;
- expected continuation sequence and transaction timeout;
- keepalive timing, progress status, and cancellation flag;
- the next channel ID to allocate;
- command and result channels for the authenticator worker.

Persistent state belongs to `store`; TPM handles and policy sessions belong to
`tpm` and are flushed by their guards.

## Effect Boundaries

Interactive authorization is injected through `approval::UserApproval`.
Production explicitly installs `BusApproval`; `SystemApproval` is a fail-closed
library default. Protocol tests provide an explicit fake provider. This avoids making production behavior depend on `cfg(test)`.
`approve_controlled` receives the transaction cancellation flag and an absolute
30-second deadline. Production directs a structured request to a registered
unprivileged agent on the system bus. Its unique connection/object path, fresh
request ID and remaining lifetime bind exactly one decision to one transaction.
The daemon explicitly cancels the remote dialog; dropping a local future alone
is not sufficient. The helper tombstones authenticated cancellation IDs even
when Cancel overtakes Request authentication. The agent registers when the daemon
appears and retries failures; desktop lock or session changes do not revoke it.
There is no automatic terminal or polkit fallback for presence.

`crates/protocol` contains toolkit/TPM-independent wire types and sealed-FD
management transport. `crates/cli` contains one-shot management commands.
`crates/approval-gtk` owns the GTK main loop, D-Bus lifecycle and native libadwaita
AlertDialog, using plain-text labels and a Deny default. libadwaita is not a
daemon/CLI dependency.
GTK runs only in the desktop user's own environment. Desktop startup may use
a correctly integrated graphical-session.target (the default), XDG autostart,
or a compositor's own startup mechanism. The generic `approval` options enable
the agent with the daemon by default; `approval.enable = false` opts out.
Root does not scrape environment variables or access a
user session bus. No lingering is enabled.

The runtime credential model is distinct from the SQLite representation.
Conversions live in `credential.rs`, preventing CTAP handlers from depending on
storage encoding details.

TPM and store access are not yet injected interfaces. They remain the next
useful seams if protocol tests need deterministic signing, failure injection,
or an in-memory repository.

## Logging

Logs use consistent `key=value` context and avoid raw CTAP payloads:

- `info`: daemon/UHID lifecycle, complete CTAP commands, approvals, and credential outcomes;
- `debug`: CTAPHID packet flow, command options, ClientPIN subcommands, status codes, and TPM policy diagnostics;
- `trace`: individual UHID report writes.

For focused diagnostics, use:

```sh
RUST_LOG=tpm_passkey=debug,sqlx=warn,zbus=warn
```

## Testing Layers

- Unit tests cover CTAP parsing, state transitions, authenticator data,
  Client PIN, CTAPHID framing, storage, and PCR selection.
- Independent NixOS tests under `nix/tests/<case>/` exercise focused UHID,
  protocol, management, PIN, reset, integrity, approval, PCR and recovery cases.
  Each directory has its Nix test, reason and case-specific assets. Shared
  machine configuration, driver helpers and credential fixtures stay directly
  in `nix/tests/`; see its [test index](../nix/tests/README.md).
  Protocol cases use an explicitly test-only auto-answering system-bus agent
  and a controlled desktop fixture, not production bypasses. Fault cases hold a
  dialog pending and verify directed cancellation identity.
  A separate test runs the real unprivileged GTK binary on headless X11; this
  is not evidence of manual Firefox/Wayland usability or automatic focus.

The NixOS VM uses `/dev/tpm0`, so all management TPM operations must pass
through the daemon-owned TPM command channel.

## Remaining Architectural Work

- Introduce repository and signer interfaces when tests require deterministic
  persistence or TPM failures.
- Keep splitting CTAP command families only when they can expose narrow inputs
  and outputs; moving large `impl Authenticator` blocks without reducing
  coupling would provide little benefit.
- Give the SQLite store a long-lived connection/runtime rather than opening a
  pool and checking migrations for individual operations.
