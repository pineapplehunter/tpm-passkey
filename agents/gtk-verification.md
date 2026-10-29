# GTK/system-bus integration verification (in progress)

Baseline: 52b21c5. Updated design is in gtk-implementation.md and docs/dbus.md.
No migration, private-key format, recovery AAD or PIN/UV policy changed.

## Reviews and selected fixes

Frontend/protocol/Nix review b6d105fe-c83c-40ef-b971-2e6c3bbd99b1 found:
- Missing polkit action installation: daemon package now in systemPackages, plus
  VM pkaction assertions. Merely listing it in dbus/udev packages was insufficient.
- Cancel-before-Request-authentication race: authenticated cancellation IDs now
  become owner-scoped tombstones, with a regression test.
- Secret retention: fixed-size guarded encoding; externally tagged direct field
  decoding; zeroizing secret fields including partial failures; borrowed-string
  visitors and full-message guarded scratch avoid Ciborium owned-string growth.
  This is best-effort hygiene, not universal allocator/library/crash-dump erasure.
- Terminal injection in metadata: CLI escapes controls, Unicode format and
  non-ordinary whitespace; GUI also escapes invisible formatting characters.
- Seal/size race: irreversible seals checked before the size snapshot.

Backend review 73c66e43-7f06-423c-a724-6cb7f3a61392 found:
- Disconnect could overtake registration commit: in-flight sender counts now
  participate in owner-loss generation invalidation, with a regression test.
- Post-consent cancellation: registration rechecks after TPM creation and before
  persistence; reset checks before deletion. An already-started kernel/TPM/SQLite
  operation is not preemptible, and cancellation racing a commit cannot promise
  rollback. No stronger guarantee is claimed.

Integration also checks ceil-rounded remote lifetimes, conservative graphical
ambiguity (including inactive sessions), and periodic re-registration after
session revocation even when the daemon's bus owner is unchanged.

## Evidence so far

Old Pueue queue tasks 5/6: backend and GUI/CLI implementation reports; selected
files reviewed and integrated, not wholesale workspace copies. Task 8: first
independent review. Task 9: preliminary whole-workspace check/test/dry run passed.
Queue reset after harness/environment update; subsequent IDs start at zero.

New queue task 0 passed whole-workspace checks/tests and all six private-bus
backend tests, plus dry run. /tmp/gtk-final-rust.log. This predates the final
registration-race fix and libadwaita request; rerun required.

New queue task 1: first full flake check built packages, including backend private
bus tests, but all 15 VM scenarios stopped at the shared readiness assertion:
fido2-manage -list does not provide the grepped /dev/hidraw stdout format. Replaced
with real Python CTAP GetInfo readiness. Binary closure check also overreached:
GTK's native dependencies can include platform TPM support, despite no frontend
Cargo dependency on the daemon/TPM implementation. The check now rejects GTK and
libadwaita from daemon/CLI closures, and TPM support from the CLI closure.
Evidence: /tmp/gtk-first-flake.log.

User subsequently requested libadwaita: native AlertDialog with Deny default,
explicit destructive reset response, no Enter-to-Allow, and plain text. Added
only to GUI Cargo/Nix dependencies; targeted check and default tests passed.
Native GTK/libadwaita environmental tests and targeted VM retries passed.
The initial native test re-emitted a disabled private response after the dialog
was closed; this caused a libadwaita critical, not a production consent failure.
It now checks disabled response state and injects duplicate decisions at the
consent-model boundary. Presentation tracking also makes delayed dismissals
idempotent. The native test passes with G_DEBUG=fatal-criticals.

## Final evidence

- /tmp/gtk-final-rust-v3.log: whole-workspace check/test, all six private-bus
  tests, both environmental GTK/libadwaita tests (fatal criticals), and dry run
  passed. 142 distinct tests: daemon library 113, daemon binary 4, CLI 7,
  GUI 12, protocol 6. Temporary NSS/Xvfb/private-bus setup is sandbox-only.
- /tmp/gtk-second-targeted.log: real group/polkit access, sealed FD rejection,
  operation substitution and dependency-closure separation passed.
- /tmp/gtk-third-targeted.log: management, cancellation, session lifecycle and
  actual unprivileged libadwaita dialog VM tests passed.
- /tmp/gtk-final-flake.log: all 15 x86_64-linux VM cases, binary separation and
  treefmt passed. This predates only the final native-test correction.
- A harness restart interrupted the subsequent redundant full-check process
  (/tmp/gtk-final-flake-v2.log) during compilation and reset the private queue.
  Current queue task 0 passed exact final sources: /tmp/gtk-final-flake-v3.log.
  All 15 x86_64-linux VM cases (16–38 seconds each), binary dependency-closure
  separation and treefmt passed. Other advertised systems were not built.

## Remaining deployment verification

Manual Firefox/Wayland/session-activation/lock/focus and positive interactive
polkit management authentication are unavailable in this sandbox. They remain
explicitly unverified; the automated headless X11 smoke is not a substitute.
