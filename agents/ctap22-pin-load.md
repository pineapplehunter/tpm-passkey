# Fail-closed PIN loading and atomic reset

After c67de52 (PIN protocols/UV) and e6dbc79 (client-only extensions), fixed the
startup path that logged a PIN load error and silently continued as unconfigured.

A load-error flag gates all credential/PIN commands with INTEGRITY_FAILURE.
GetInfo conservatively reports PIN protection, allowing ordinary discovery/reset.
Selection and explicit factory reset retain their original approval/time gates.
The flag is sticky until successful reset or a fresh, successful startup load.
PIN loads require bounded fields and a present/valid MAC, and never generate a
replacement integrity key. No automatic record rewrites or destructive migrations.

Reset previously deleted PIN first, then credentials individually; a later write
failure could leave credentials persisted but PIN protection gone. Reset now
deletes all credential rows and PIN in one SQLite transaction, independent of
which rows the daemon loaded, and clears memory/throttles only after commit.
Custom PCR/recovery enrollment settings remain unchanged.

Tests: damaged/missing MACs, correctly MACed malformed fields, missing integrity
key (no implicit regeneration), blocked requests/reported protection, denied reset,
backup repair/restart, and successful reset. An injected SQLite trigger forces
reset rollback and proves both credentials and PIN survive. A privileged VM fault
script corrupts/removes the PIN MAC, restarts, checks rejection, then restores the
original state and verifies PIN/credential preservation. This is not TPM-grade
PIN protection; offline guessing and rollback remain explicit gaps.

Passed SQLx all-target preparation, nix fmt, cargo check, cargo test (95).
Offline-mode cargo check/test and daemon dry run also passed. Full nix flake
check passed (task 0 in the new private queue, 2026-10-28); both software-TPM VM
checks passed, including the PIN corruption/repair fault script. Evidence is in
/tmp/ctap22-pin-load-flake.log.
