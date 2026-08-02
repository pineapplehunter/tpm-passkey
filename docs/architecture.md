# Architecture

## Overview

`linux-tpm-fido2` is a blocking system daemon that exposes a virtual FIDO2
authenticator through Linux UHID. The daemon owns the CTAPHID channels, CTAP2
state machines, TPM context, credential store, active-session identity, and
transaction approval flow.

## Runtime Request Flow

1. The browser writes 64-byte reports to the UHID device.
2. `ctaphid` validates the channel and packet sequence, assembles the request,
   and dispatches complete commands.
3. `ctap2::Authenticator` decodes the CTAP command and coordinates its state
   machine.
4. The command handler scopes credentials to the active UID, obtains approval
   through `approval::UserApproval`, and asks `tpm` to create or use keys.
5. `store` persists credential, PIN, policy, and recovery state in SQLite.
6. The CTAP response is encoded canonically, fragmented by `ctaphid`, and sent
   to the browser through UHID.

Management requests use a Unix socket. Socket threads perform validation and
storage work, while TPM operations are sent to the daemon thread because the
NixOS test TPM exposes only one usable `/dev/tpm0` opener.

## Source Boundaries

```text
src/
├── main.rs                 daemon lifecycle, UHID loop, and CLI
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
├── approval.rs             injectable approval boundary and polkit fallback
├── management.rs           management socket server and client transport
├── management/
│   ├── protocol.rs         serialized management API
│   └── service.rs          management operations and TPM command dispatch
├── session.rs              captured daemon session identity
├── systemd_logind.rs       active-session discovery
└── polkit.rs               polkit authorization request
```

## State Ownership

`ctap2::Authenticator` owns state that must survive across CTAP commands:

- loaded credentials and signature counters;
- pending `getNextAssertion` enumeration;
- credential-management enumeration state;
- Client PIN verifier and retry state;
- ephemeral key agreement and PIN/UV token state;
- transaction UV state;
- the lazily opened TPM context.

`ctaphid::PacketHandler` owns transport state independently:

- allocated channel IDs;
- incomplete messages and expected sequence numbers;
- the next channel ID to allocate.

Persistent state belongs to `store`; TPM handles and policy sessions belong to
`tpm` and are flushed by their guards.

## Effect Boundaries

Interactive authorization is injected through `approval::UserApproval`.
Production uses `SystemApproval`, while protocol tests provide an explicit fake
provider. This avoids making production behavior depend on `cfg(test)`.

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
RUST_LOG=linux_tpm_fido2=debug,sqlx=warn,zbus=warn
```

## Testing Layers

- Unit tests cover CTAP parsing, state transitions, authenticator data,
  Client PIN, CTAPHID framing, storage, and PCR selection.
- The NixOS VM test exercises UHID discovery, polkit approval, a software TPM,
  credential creation/assertion, PIN management, PCR recovery, reboot
  persistence, and CTAP compliance through `python-fido2`.

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
- Move daemon lifecycle and session-change handling out of `main.rs` when UHID
  device recreation is implemented.
