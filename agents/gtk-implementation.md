# GTK approval / unprivileged management implementation

User approved implementation after discussion. Existing baseline is 52b21c5;
leave unrelated agents/* notes alone. Parent integrates independent workers.

## Updated decisions (supersede original task account/subcommand assumptions)
- Three binaries and separate Cargo packages: root tpm-passkey-daemon (library
  crate name tpm_passkey retained), crates/cli tpm-passkey, crates/approval-gtk
  tpm-passkey-approval-gtk. GTK/libadwaita must not be in daemon OR CLI dependency graphs.
  User later requested native libadwaita for the popup; use AlertDialog with Deny
  default, plain text, explicit destructive reset and no Enter-to-Allow.
- Shared crates/protocol is TPM/storage/GTK independent. Parent has supplied
  compile-checked wire types and sealed-FD/client transport. Do not rename them.
- No configured approval username. Registration actual D-Bus sender's UID must
  match the sole eligible active, unlocked, local graphical logind session.
  Reject ambiguity, session loss and changes, with fail-closed pending consent.
  User-service PID need not be inside graphical session scope. Not browser UID
  authentication or credential ownership; single-user store remains unchanged.
- Configurable tpm-passkey group gate through polkit. Members register without
  interaction, then daemon applies session guard. Management reads/mutations
  use distinct polkit actions; defaults no retained authorization. NixOS parent
  chooses AUTH_ADMIN for mutations, YES for group reads/register; nonmembers NO.
- CLI management moves to system bus, no public/legacy Unix socket bypass.
  Secrets only via bounded sealed memfd, never plain D-Bus arguments or errors.
- Production UP is GTK Allow/Deny, never polkit/PAM or built-in UV. No fallback.

## Fixed wire contract
crates/protocol/src/lib.rs defines names and ApprovalContext. Root exports
DAEMON_PATH/DAEMON_IFACE on BUS_NAME. Methods:
- RegisterAgent(path: object-path) -> ()
- UnregisterAgent(path: object-path) -> ()
- Manage(operation: string, request: UNIX_FD) -> byte array (CBOR ManagementResponse)
  Authorize operation BEFORE reading secret FD; reject mismatched decoded op.
Agent exports AGENT_PATH/AGENT_IFACE on its unique connection, methods:
- Request(id: string, context: ApprovalContext, timeout_ms: u32) -> bool
- Cancel(id: string) -> ()
Fresh random request ID, one pending, exact request binding, no queued consent.
Agent validates actual caller against root-owned BUS_NAME unique owner. Deny
stale requests/cancels and missing display, invalid context, malformed responses.

## Backend job
Own only src/* (except CLI moved output handled by GUI job), root main becomes
standalone daemon CLI preserving dry-run and UHID normalize tests. Implement
root persistent bus service, polkit actual system-bus-name caller checks with
bounded auth/cancellation, sender ownership/lifetime, registration, managed
approval state, structured context wired through CTAP including accurate RP,
registration account, login candidate count (never invent account selection),
reset/selection. Keep existing UserApproval fakes compatible if practical using
new context-controlled default adapter; production never parses human prompts.
Keep same 30s absolute control scope for bus/logind/agent waits, remote Cancel
with <=100ms cleanup, CTAPHID keepalives and errors unchanged. Observe session
loss/lock and agent disconnect during pending operation; final eligibility check
must catch session switches and disconnection. Abort future consent on observed
loss even if session later recovers. No replacing live registration while pending.
No polkit UP/fallback; retain terminal code only as explicit development provider.
Management dispatch stays existing code and recovery/PCR invariants. Dispatch
blocking DB/TPM work outside async bus handlers, authorize first, abort if caller
vanishes while awaiting authorization. Avoid unbounded worker reply waits.
Root Cargo already renamed and protocol dependency added; parent owns root
manifest/lock final integration. Report needed dependencies, do not edit Nix,
assets, docs or crates/*; request contract changes explicitly in report.
Add focused independent tests incl registry races, caller failures, context and
session gating, cancellation/deadlines, management authorization. Check/test root
as possible (old main cannot compile until replacement due removed rpassword).

## GUI/CLI job
Own only crates/cli/**, crates/approval-gtk/**. Create their manifests and CLI/GTK
implementation, root workspace modifications ONLY in private copy to validate;
parent will integrate root Cargo changes. CLI derives from current src/main.rs
management commands/tests, uses tpm_passkey_protocol as management alias and
send_request. Drop daemon command; no daemon lib dependency, no TPM libs. CLI
PCR input can do simple numeric sanity checking; daemon remains authoritative.
Zeroize discarded password inputs too (empty old, confirmation etc). Keep output
and management command compatibility. Shared protocol transport already works.
GUI GTK4 native Rust main thread; asynchronous zbus handling background runtime
and main-loop event channel, never block GTK. Fail closed on display init/errors,
window close/Escape, daemon disconnect/restart, timeouts, invalid/stale ids. Exactly
one pending dialog. Caller must be current root-owned BUS_NAME owner, do not
trust supplied UID/name. Cancel verifies caller and ID. Registration reconnect
never reuses consent, clears/dismisses dialogs on daemon loss. Reconnect without
requiring daemon to autostart/root launch desktop process. Default focus Deny,
no initial default Allow or Enter activation; buttons single-use, show full RP ID
with plain text, bounded/sanitized control/bidi text. Accurate operation wording,
reset explicitly deletes all passkeys and clears FIDO PIN. UI pending lifetime
must not exceed passed remaining timeout. No standalone CLI approval subcommand.
Nix parent will add gtk4 to devShell. In private shell can use nix develop with
private manifest/shell changes to add gtk4; report any changes needed. Prefer
cargo add dependencies. Add focused GUI logic tests and GTK smoke if possible;
report what was not manually exercised. No production auto-allow/test mode.

## Parent job
Shared protocol tests/review, manifests/lock integration, Nix package graph and
GTK wrapping, group/polkit/system bus policy, service/startup assets, docs and
adapt NixOS scenarios. Need separate focused real-GTK smoke (not claim Firefox
Wayland manual testing without host display). Preserve the 12 separate test dirs.
Final nix fmt/check/test all workspace, dry run, flake checks through Pueue. Do
not claim completed manual desktop/Firefox tests in sandbox. Review workers and
request security fixes before committing.
