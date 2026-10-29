# Focused pre-integration review

Read agents/gtk-implementation.md and original task. This is an independent copy
of parent WIP. Do not edit or commit. Backend src/* is still baseline and is being
implemented separately: do NOT review baseline backend as if integrated.

Review crates/protocol, crates/cli, crates/approval-gtk, assets/tpm-passkey*.conf,
assets/tpm-passkey.policy/service, nix/nixos-module.nix, nix/package.nix and flake
package graph. Find concrete security/correctness issues in FD validation/secret
handling, operation/authorization binding assumptions, caller/name ownership,
reconnect/cancel/replay handling, GTK main-loop/focus/text behavior, group policy,
startup and package separation. Focus on bugs not speculative abstractions.
Parent built/tested the three new packages (20 default tests pass, 2 environmental
GUI tests ignored by default; GUI worker separately ran both). Root is not yet
compile-ready, so do not run whole-workspace checks. Can run targeted checks.
Report file/line, triggering case, impact, minimal fix, and tests/limits. No
implementation changes. Explicitly note any failure that blocks integration.
