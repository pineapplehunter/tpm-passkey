# System-bus interfaces

The root daemon owns `io.github.pineapplehunter.TpmPasskey1`, exporting
`/io/github/pineapplehunter/TpmPasskey1` with an interface of the same name.
Only root may own that name. The management CLI and graphical agent connect as
their ordinary user; neither needs the daemon library. No root session-bus or
display access is involved.

## Caller authorization

The daemon obtains the actual unique sender from the incoming message header.
Polkit subjects are `system-bus-name` subjects referring to that connection,
not client-supplied usernames/PIDs or logind session leaders. The NixOS module
creates a configurable `tpm-passkey` access group and installs site policy:

| Action suffix | Ordinary group members | Others |
| --- | --- | --- |
| `register-agent` | Noninteractive eligibility to register | Denied |
| `read` | Read configuration/credential metadata | Denied |
| `manage-migration` | Authenticate as administrator (or explicitly configured self) | Denied |
| `manage-settings` | Authenticate as administrator (or explicitly configured self) | Denied |

All action IDs start with `io.github.pineapplehunter.tpm-passkey.`. There is no
retained authorization. Root is trusted regardless of group membership. Migration-key operations still require the appropriate phrase; polkit cannot replace it.
This is access to one shared store, not per-user credential isolation.

## Agent registration

- `RegisterAgent(o path) -> ()`
- `UnregisterAgent(o path) -> ()`

The path is `/io/github/pineapplehunter/TpmPasskey1/ApprovalAgent`. A registration
is bound to its unique sender and object path. Run one frontend at a time. A live
agent is not silently replaced; a pending approval cannot be replaced, queued,
or resurrected by re-registration. Agents register when the daemon appears
and retry failures. The daemon does not monitor session or lock state: the
desktop is responsible for preventing interaction while locked. This does not
identify the browser or enforce credential ownership.

## Toolkit-independent approval interface

The agent exports `io.github.pineapplehunter.TpmPasskey1.ApprovalAgent` on its
unique connection:

- `Request(s id, (sssssu) context, u timeout_ms) -> b allow`
- `Cancel(s id) -> ()`

Context fields, in order: operation (`register`, `login`, `selection`, `reset`),
RP ID, optional RP name, optional account name, optional account ID, and candidate
count. Empty strings mean absent. Login consent does not select an account.
Strings are untrusted plain text: bound them, escape misleading controls, do not
interpret markup, and show the full RP ID. Reset must explicitly warn that it
deletes all passkeys and clears the FIDO PIN.

Before handling either call, authenticate the actual sender as the current
root-owned daemon name owner. Keep one pending dialog, bind its decision to the
exact connection/request ID, and accept a matching answer only once before its
deadline. Remember authenticated Cancel IDs even if Cancel overtakes Request's
asynchronous authentication. Close/Escape, invalid requests, missing display,
expiry and failures deny. Daemon disconnection clears all consent. Never transfer
selection approval to a later operation or reuse a recent Allow.

The daemon owns the absolute 30-second CTAP approval budget. `timeout_ms` is its
remaining lifetime, at most 30000. It explicitly cancels the remote dialog on
abort, with at most 100 ms of cleanup allowance; dropping a local future alone
is insufficient. No polkit/PAM re-authentication or terminal fallback supplies UP.
PIN token verification remains separate. Wayland does not guarantee focus.

## Management and secrets

`Manage(s operation, h request_fd) -> ay response`

The public operation selects a polkit action **before** the daemon inspects or
reads the FD. The decoded request must name exactly that operation. The FD must
be a nonempty regular anonymous-memory file, at most 16 KiB, sealed against
write/grow/shrink. Check irreversible seals before reading metadata, and read at
an explicit offset rather than trusting a shared seek position. Queued TPM work
expires before execution; already-running TPM commands/commits cannot be
asynchronously preempted.

The FD contains a CBOR externally tagged `ManagementRequest`: a string for unit
operations (for example `"show-config"`), or a one-entry map from operation name
to its parameter map. See `crates/protocol/src/management.rs` for exact variants.
The reply is CBOR `ManagementResponse` (`ok`, optional `error`, optional `result`),
at most 1 MiB. There is no legacy Unix-socket bypass.

Secrets must not occur in D-Bus arguments, signals, logs, errors, argv or environment
variables. The CLI uses bounded zeroizing encoding storage; secret fields and
decoder scratch have zeroizing guards, including partial failures. This is
best-effort memory hygiene, not universal erasure. Sealed pages cannot be wiped,
may be swapped, and may remain referenced by another holder. The bus broker
handles FDs and privileged observers remain trusted: this is not end-to-end
secret protection against root, the broker or kernel.
