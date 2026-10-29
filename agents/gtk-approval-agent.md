---
title: Replace polkit presence checks with a GTK system-bus approval agent
created: 2026-10-28 18:53:59
status: blocked
priority: P2
base: 52b21c5
tag: user-presence
---

## Description

Replace polkit/PAM re-authentication for CTAP user presence (UP) with a simple GTK Allow/Deny dialog displayed by an unprivileged graphical-session agent. The root daemon must not launch GTK, inherit desktop credentials, or connect directly to the user's session bus.

Recorded user feedback:

> I think a simple gtk dialog for simple confirmation would be enough, though in that case the problem is how to spawn a wayland window from the root running daemon. workshop this in the subagent.

After research recommended a registered system-bus agent, the user approved creating this task:

> Seems good. Create a task file in the agents directory.

Implementation was requested after the design discussion. The updated decisions
in `agents/gtk-implementation.md` supersede the original account/subcommand
assumptions below. Do not overwrite unrelated work running in parallel; inspect the current source and changes from the baseline before implementing.

### Selected architecture

```text
Graphical login starts unprivileged approval-agent
    -> exports an approval object on the system bus
    -> registers its object path with the root daemon

Firefox -> UHID -> root daemon
    -> directed D-Bus approval call to registered unique sender/object
    -> agent creates GTK window in its own graphical environment
    -> Allow/Deny response for exactly that transaction
```

Use separate Cargo packages/binaries: `tpm-passkey-daemon`, the management CLI
`tpm-passkey`, and the resident `tpm-passkey-approval-gtk`. The daemon and CLI must
not link GTK; the CLI/GUI must not depend on the daemon's TPM/store library.
A toolkit-independent shared protocol permits another frontend, such as Qt.
A registered agent needs no well-known name. Derive identity from the actual
D-Bus sender, never a caller-supplied UID or bus name.

No hard-coded approval account is required. Match the registered sender UID to
the sole eligible graphical session, and gate ordinary callers through the
configurable `tpm-passkey` group and polkit. Registration is noninteractive;
management mutations require separate polkit authentication. Management also
moves to the system bus, with bounded sealed-memfd requests for secret material;
retain all existing cryptographic recovery checks. Start the helper through XDG
autostart, a correctly integrated graphical-session.target, or explicitly from
the compositor. No lingering or root display access. Target-desktop behavior is
verification work, not a prerequisite to toolkit-independent implementation.

Keep the existing `UserApproval`/`ApprovalControl` boundary and one absolute approval deadline. Keep TPM ownership and command execution in the daemon; do not block the UHID loop or GTK main loop.

### Boundaries and non-goals

- GTK approval replaces the polkit/PAM UP ceremony; it is not an additional prompt.
- FIDO PIN/token verification remains independent and unchanged. GTK consent is UP, never built-in UV.
- No direct root access to `/run/user/UID/bus`, session-bus policy changes, root GTK, or display-environment scraping. Keep `ProtectHome`, management/store permissions and unrelated daemon hardening intact.
- Do not introduce a second on-demand GUI service/bridge initially. A user-side D-Bus-activated child is an optional future footprint optimization, not required here.
- No authorization caching, recent-unlock shortcuts, selection-to-operation approval transfer, or unconditional allow rules.
- No multi-user/multi-seat isolation redesign. Same-user malware may impersonate or compromise the helper; this is not a secure-attention mechanism.

## Checklist

- [x] Inspect current approval, CTAP, service and packaging code; compare against the baseline and preserve intervening work. Use automatic graphical-session UID eligibility and configurable group authorization; provide explicit session-startup mechanisms.
- [x] Define a small system-bus registration/approval/cancellation API with narrow bus policy. Authenticate the helper's actual sender UID against eligible graphical-session identity and polkit/group policy; bind registration to its unique connection/object path. Do not replace a live registration during a pending approval. The helper must validate the daemon caller/name owner before displaying requests.
- [x] Carry structured approval context: operation, actual RP ID, optional RP name and accurate account information. Use bounded input and a fresh per-request ID; permit exactly one pending approval. Accept a matching answer once, only from the bound connection and before cancellation/deadline. Ignore stale/duplicate answers.
- [x] Preserve the existing 30-second absolute action budget, cancellation/error mapping and keepalives. Provide explicit remote dialog cancellation: dropping a local D-Bus future alone is insufficient. Helper disappearance, daemon disappearance, missing helper/display, malformed responses, GUI failure, timeout and window close must fail closed. Restart/re-registration cannot resurrect pending consent; do not queue requests for a later login.
- [x] Use logind only as a graphical-session eligibility guard, not HID caller authentication or credential ownership. Define the minimal supported single-session policy, reject ambiguity, and cancel pending approval on observed lock/logout/session switch. Recheck eligibility before accepting Allow. Document that `LockedHint` depends on desktop cooperation; a user-service PID need not belong to the graphical session scope.
- [x] Implement a minimal GTK4/libadwaita AlertDialog on the main thread with asynchronous D-Bus handling. Show registration/login/selection/reset-specific wording and prominent full RP ID where supplied. Treat all RP/account text as untrusted plain text; bound text and handle misleading control characters. Do not invent an account selection when approval covers multiple candidate credentials.
- [x] Default to Deny/Cancel; Escape and window close deny. Prevent accidental Allow through initial keyboard focus/default activation and disable repeated responses. Make reset explicitly say it deletes all passkeys and clears the FIDO PIN. Preserve existing reset admission and selection semantics.
- [x] Add graphical-session startup, daemon/helper reconnect handling and required Nix/system-bus policy assets. Keep management execution privileged, but expose the API to authenticated system-bus clients with daemon-side polkit checks. Use sealed FDs for secrets. Add GTK dependencies/wrapping only to the separate GUI package; keep daemon/CLI runtime closures GTK-free.
- [x] Retire production polkit approval integration and update affected service dependencies, policy installation and tests. An explicitly selected terminal development provider may remain, but denial/cancel/timeout must not fall through to another provider.
- [x] Update `README.md`, `docs/architecture.md` and `docs/security.md`: GTK UI replaces the former no-GUI/polkit assumptions, host re-authentication assurance is removed, same-user helper trust is explicit, and Wayland foreground focus is not guaranteed.
- [x] Test registration/authenticated callers, Allow/Deny, absent/busy helper, stale/duplicate replies, cancellation races, deadlines, helper/daemon restart and session loss. Preserve PIN-required flows, `up=false`, selection-followed-by-operation and reset behavior. Adapt auto-allow polkit VM tests; they are not evidence of real GTK UX.
- [x] Run `nix fmt`, `cargo check` and `cargo test` in the project dev shell after Rust changes; validate flake changes with `nix flake check` and exercise relevant VM checks. Record outcomes and remaining limitations.
- [ ] Manually test Firefox on the target Wayland desktop, including activation/environment, polkit management authentication, lock behavior and a window that is not automatically focused. **Unavailable in this sandbox; remains required deployment verification.**

### Likely integration points

- `src/approval.rs`, `src/ctap2.rs`: structured context and replacement provider, preserving cancellation and PIN/UP semantics.
- `src/main.rs`, new agent/protocol modules: CLI mode, bus registration, connection lifecycle and GTK handling.
- `src/systemd_logind.rs`: eligibility checks rather than polkit process-subject routing.
- `src/polkit.rs`, `assets/tpm-passkey.policy`: retire production approval use as appropriate.
- `Cargo.toml`, `Cargo.lock`, `nix/package.nix`, `flake.nix`: GTK dependencies, build/runtime environment and wrapping.
- `nix/nixos-module.nix`, `assets/tpm-passkey.service`, new user-unit/autostart and D-Bus policy assets: configured account and deployment.
- Relevant protocol/provider tests, NixOS tests and documentation. Reinspect paths because test organization may have changed since research.

### Research precedents and cautions

Research was performed by two `openai-codex/gpt-6.1-sol` subagents with high thinking, using web searches and upstream source inspection. No target desktop prototype was tested.

- **BlueZ/Blueman:** the closest system-daemon-to-confirmation-agent pattern. Desktop helper registers on the system bus; daemon calls its unique sender/object and supports cancellation. Borrow the topology, not BlueZ's global default-agent selection policy. [Agent API](https://github.com/bluez/bluez/blob/master/doc/org.bluez.Agent.rst), [Blueman agent implementation](https://github.com/blueman-project/blueman/blob/ec7c9d20c3a15c80854aa9f4f10a36f381894618/blueman/main/applet/BluezAgent.py).
- **NetworkManager:** authenticated sender/UID-based registration and directed agent calls on the system bus. [Agent manager implementation](https://github.com/NetworkManager/NetworkManager/blob/main/src/core/settings/nm-agent-manager.c).
- **GCR 3 SystemPrompter:** verified session-bus activation of a GTK confirmation service with 10-second idle exit. Its verified callers are user-session processes, not root daemons; its internal wire protocol is not a public API. This is a future lifecycle reference, not a dependency recommendation. [GTK prompter source](https://github.com/GNOME/gcr/blob/4efdfccd68fc0f44c5004bccc1a93047ef988b71/ui/gcr-prompter-tool.c).
- Root is not automatically admitted to standard user buses; changing the bus address does not change EXTERNAL credentials. [D-Bus connection policy](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).
- `ProtectHome=yes` hides `/run/user`; system-bus registration avoids needing to expose it. [systemd execution sandbox](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ProtectHome=).
- GTK presentation is not guaranteed foreground focus on Wayland, and the HID request supplies no activation-token channel. [GTK window presentation](https://docs.gtk.org/gtk4/method.Window.present.html).

## Completion notes

Implementation and automated verification are complete with three binaries and
toolkit-independent D-Bus interfaces. The popup uses native libadwaita. The task
is blocked only on the unchecked manual deployment verification above.

Whole-workspace checks, 142 distinct Rust/native tests (including private D-Bus
and real libadwaita/Xvfb cases), dry run, and full flake checks passed. All 15
x86_64-linux VM checks and dependency-closure separation passed. Evidence:
`/tmp/gtk-final-rust-v3.log`, `/tmp/gtk-final-flake-v3.log`. `docs/dbus.md` describes the wire
contract; `agents/gtk-verification.md` records reviews and automated evidence.
No configured username/desktop assumption is required; deployment selects group
membership and a startup mechanism. Manual Firefox/Wayland, real desktop startup,
lock publication and polkit authentication UX remain explicitly unverified.
